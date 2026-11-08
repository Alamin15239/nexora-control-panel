//go:build linux

package staticvhost

import (
	"context"
	"crypto/rsa"
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
