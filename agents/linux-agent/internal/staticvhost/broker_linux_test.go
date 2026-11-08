//go:build linux

package staticvhost

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBrokerRejectsUnexpectedPeerUIDBeforeEnvelopeValidation(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "broker.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil { t.Fatal(err) }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	allowedUID := uint32(os.Getuid()) + 1
	trust := BrokerTrust{Issuer:"trusted-issuer", Audience:"static-deployments", KeyID:"key-1", PublicKey:&rsa.PublicKey{N:big.NewInt(17), E:65537}}
	go func() { done <- Serve(ctx, listener, allowedUID, "/etc/nginx/conf.d", trust) }()
	requestCtx, requestCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer requestCancel()
	if err := RequestInstall(requestCtx, socketPath, "not-a-valid-jws"); err == nil {
		t.Fatal("broker accepted a peer with an unexpected UID")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil { t.Fatal(err) }
	case <-time.After(2*time.Second):
		t.Fatal("broker did not stop after cancellation")
	}
}

func TestRequestInstallRejectsEmptyOrOversizedEnvelope(t *testing.T) {
	ctx := context.Background()
	if err := RequestInstall(ctx, "/unused/socket", ""); err == nil {
		t.Fatal("accepted an empty deployment envelope")
	}
	if err := RequestInstall(ctx, "/unused/socket", strings.Repeat("x", maxBrokerRequest)); err == nil {
		t.Fatal("accepted an oversized deployment envelope")
	}
}

func TestReadRootOwnedFileRejectsRelativePath(t *testing.T) {
	if _, err := readRootOwnedFile("relative.json", 4096); err == nil {
		t.Fatal("accepted a relative trust-file path")
	}
}

func TestReadRootOwnedFileRejectsSymlink(t *testing.T) {
	if os.Geteuid() != 0 { t.Skip("root-owned trust file test requires root") }
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "trust.json")
	if err := os.WriteFile(target, []byte("secret"), 0600); err != nil { t.Fatal(err) }
	if err := os.Symlink(target, link); err != nil { t.Fatal(err) }
	if _, err := readRootOwnedFile(link, 4096); err == nil {
		t.Fatal("followed a symlinked trust file")
	}
}

func TestReadRootOwnedFileRejectsGroupWritableFile(t *testing.T) {
	if os.Geteuid() != 0 { t.Skip("root-owned trust file test requires root") }
	path := filepath.Join(t.TempDir(), "trust.json")
	if err := os.WriteFile(path, []byte("trusted"), 0600); err != nil { t.Fatal(err) }
	if err := os.Chmod(path, 0660); err != nil { t.Fatal(err) }
	if _, err := readRootOwnedFile(path, 4096); err == nil {
		t.Fatal("accepted a group-writable trust file")
	}
}


func TestBrokerRejectsInvalidEnvelopeFromAuthorizedPublisher(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "broker.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name:socketPath, Net:"unix"})
	if err != nil { t.Fatal(err) }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	trust := BrokerTrust{Issuer:"trusted-issuer", Audience:"static-deployments", KeyID:"key-1", PublicKey:&rsa.PublicKey{N:big.NewInt(17), E:65537}}
	go func() { done <- Serve(ctx, listener, uint32(os.Getuid()), "/etc/nginx/conf.d", trust) }()
	requestCtx, requestCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer requestCancel()
	err = RequestInstall(requestCtx, socketPath, "not.a.valid.signature")
	if err == nil || !strings.Contains(err.Error(), "invalid or expired") {
		t.Fatalf("expected signed-envelope rejection, got %v", err)
	}
	cancel()
	select {
	case serveErr := <-done:
		if serveErr != nil { t.Fatal(serveErr) }
	case <-time.After(2*time.Second):
		t.Fatal("broker did not stop after cancellation")
	}
}


func makeBrokerEnvelope(t *testing.T, key *rsa.PrivateKey, now time.Time) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg":"RS256","typ":"JWT","kid":"broker-test"})
	if err != nil { t.Fatal(err) }
	claims, err := json.Marshal(map[string]any{
		"iss":"trusted-issuer", "aud":"static-deployments",
		"organization_id":"org_test", "project_id":"project_test",
		"deployment_id":"deployment_test", "hosting_account_id":"hosting_test",
		"domain_id":"domain_test", "hostname":"www.example.test",
		"repository_id":"123456789", "commit_sha":"0123456789abcdef0123456789abcdef01234567",
		"artifact_sha256":strings.Repeat("a",64), "artifact_bytes":128,
		"jti":"0123456789abcdef0123456789abcdef",
		"iat":now.Unix(), "exp":now.Add(4*time.Minute).Unix(),
	})
	if err != nil { t.Fatal(err) }
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(header)+"."+enc.EncodeToString(claims)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader,key,crypto.SHA256,digest[:])
	if err != nil { t.Fatal(err) }
	return input+"."+enc.EncodeToString(signature)
}

func TestBrokerInstallsOnlyBindingFromVerifiedEnvelope(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil { t.Fatal(err) }
	now := time.Now().UTC().Truncate(time.Second)
	token := makeBrokerEnvelope(t,key,now)
	socketPath := filepath.Join(t.TempDir(),"broker.sock")
	listener, err := net.ListenUnix("unix",&net.UnixAddr{Name:socketPath,Net:"unix"})
	if err != nil { t.Fatal(err) }
	trust := BrokerTrust{Issuer:"trusted-issuer",Audience:"static-deployments",KeyID:"broker-test",PublicKey:&key.PublicKey}
	called := make(chan Binding,1)
	serverDone := make(chan struct{})
	go func(){
		defer close(serverDone)
		conn, acceptErr := listener.AcceptUnix()
		if acceptErr != nil { return }
		handleBrokerRequestWithInstaller(context.Background(),conn,uint32(os.Getuid()),"/etc/nginx/conf.d",trust,
			func(configDir string,binding Binding) error {
				if configDir != "/etc/nginx/conf.d" { t.Errorf("unexpected config dir: %s",configDir) }
				called <- binding
				return nil
			})
	}()
	ctx,cancel := context.WithTimeout(context.Background(),3*time.Second)
	defer cancel()
	if err := RequestInstall(ctx,socketPath,token); err != nil { t.Fatal(err) }
	select {
	case binding := <-called:
		if binding.DomainID != "domain_test" || binding.Hostname != "www.example.test" || binding.HostingAccountID != "hosting_test" {
			t.Fatalf("broker derived unexpected binding from signed claims: %+v",binding)
		}
	case <-time.After(time.Second):
		t.Fatal("verified binding was not passed to installer")
	}
	_ = listener.Close()
	<-serverDone
}

func TestBrokerRejectsExpiredEnvelopeWithoutInstalling(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader,2048)
	if err != nil { t.Fatal(err) }
	now := time.Now().UTC().Add(-10*time.Minute).Truncate(time.Second)
	token := makeBrokerEnvelope(t,key,now)
	socketPath := filepath.Join(t.TempDir(),"broker.sock")
	listener, err := net.ListenUnix("unix",&net.UnixAddr{Name:socketPath,Net:"unix"})
	if err != nil { t.Fatal(err) }
	trust := BrokerTrust{Issuer:"trusted-issuer",Audience:"static-deployments",KeyID:"broker-test",PublicKey:&key.PublicKey}
	called := false
	serverDone := make(chan struct{})
	go func(){
		defer close(serverDone)
		conn, acceptErr := listener.AcceptUnix()
		if acceptErr != nil { return }
		handleBrokerRequestWithInstaller(context.Background(),conn,uint32(os.Getuid()),"/etc/nginx/conf.d",trust,
			func(_ string,_ Binding) error { called=true; return nil })
	}()
	ctx,cancel := context.WithTimeout(context.Background(),3*time.Second)
	defer cancel()
	if err := RequestInstall(ctx,socketPath,token); err == nil || !strings.Contains(err.Error(),"invalid or expired") {
		t.Fatalf("expected expired envelope rejection, got %v",err)
	}
	_ = listener.Close()
	<-serverDone
	if called { t.Fatal("expired envelope reached the installer") }
}
