package artifactdelivery

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/appnodeauth"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/artifactclient"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/artifactreceiver"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/deployenvelope"
)

func releaseArchive(t *testing.T) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	tw := tar.NewWriter(gz)
	content := []byte("<h1>Published by Nexora</h1>")
	if err := tw.WriteHeader(&tar.Header{Name: "public/index.html", Mode: 0644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil { t.Fatal(err) }
	if err := tw.Close(); err != nil { t.Fatal(err) }
	if err := gz.Close(); err != nil { t.Fatal(err) }
	return buffer.Bytes()
}

func envelopeFor(t *testing.T, key *rsa.PrivateKey, expected deployenvelope.Expected, artifact []byte, now time.Time) string {
	t.Helper()
	digest := sha256.Sum256(artifact)
	header, err := json.Marshal(map[string]string{"alg":"RS256","typ":"JWT","kid":"nexora-test"})
	if err != nil { t.Fatal(err) }
	claims, err := json.Marshal(map[string]any{
		"iss": expected.Issuer,
		"aud": expected.Audience,
		"organization_id": expected.OrganizationID,
		"project_id": expected.ProjectID,
		"deployment_id": expected.DeploymentID,
		"hosting_account_id": expected.HostingAccountID,
		"repository_id": expected.RepositoryID,
		"commit_sha": expected.CommitSHA,
		"artifact_sha256": hex.EncodeToString(digest[:]),
		"artifact_bytes": len(artifact),
		"jti": "0123456789abcdef0123456789abcdef",
		"iat": now.Unix(),
		"exp": now.Add(5*time.Minute).Unix(),
	})
	if err != nil { t.Fatal(err) }
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(header)+"."+enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil { t.Fatal(err) }
	return input+"."+enc.EncodeToString(signature)
}

func TestFetchAndPublishPerformsAuthenticatedDownloadAndAtomicActivation(t *testing.T) {
	nodePublic, nodePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil { t.Fatal(err) }
	now := time.Now().UTC().Truncate(time.Second)
	expected := deployenvelope.Expected{
		Issuer: "https://api.nexoraedge.digital",
		Audience: "nexora-runtime",
		OrganizationID: "org_test",
		ProjectID: "project_test",
		DeploymentID: "deployment_test",
		HostingAccountID: "hosting_test",
		RepositoryID: "123456789",
		CommitSHA: "0123456789abcdef0123456789abcdef01234567",
	}
	artifact := releaseArchive(t)
	token := envelopeFor(t, signingKey, expected, artifact, now)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost ||
			(r.URL.Path != artifactclient.ArtifactRequestPath && r.URL.Path != artifactclient.ArtifactValidationReportPath) {
			t.Errorf("unexpected request target: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil { t.Errorf("read request body: %v", readErr); w.WriteHeader(http.StatusBadRequest); return }
		proof := appnodeauth.Proof{
			Timestamp: r.Header.Get("X-Nexora-Node-Timestamp"),
			Nonce: r.Header.Get("X-Nexora-Node-Nonce"),
			Signature: r.Header.Get("X-Nexora-Node-Signature"),
		}
		issuedAt, parseErr := strconv.ParseInt(proof.Timestamp, 10, 64)
		if parseErr != nil { t.Errorf("parse signed timestamp: %v", parseErr); w.WriteHeader(http.StatusUnauthorized); return }
		if verifyErr := appnodeauth.Verify(nodePublic, r.Header.Get("X-Nexora-Node-Identity"),
			r.Method, r.URL.Path, body, proof, time.Unix(issuedAt, 0)); verifyErr != nil {
			t.Errorf("verify node proof: %v", verifyErr)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == artifactclient.ArtifactValidationReportPath {
			var report artifactclient.ValidationReport
			if err := json.Unmarshal(body, &report); err != nil { t.Errorf("decode validation report: %v", err); w.WriteHeader(http.StatusBadRequest); return }
			digest := sha256.Sum256(artifact)
			if report.DeploymentID != expected.DeploymentID || report.ArtifactSHA256 != hex.EncodeToString(digest[:]) ||
				report.ArchiveEntries != 1 || report.ArchiveFiles != 1 || report.ArchiveBytes != int64(len("<h1>Published by Nexora</h1>")) {
				t.Errorf("unexpected archive validation report: %+v", report)
				w.WriteHeader(http.StatusConflict)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{\"accepted\":true}"))
			return
		}
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Nexora-Deployment-Envelope", token)
		digest := sha256.Sum256(artifact)
		w.Header().Set("X-Nexora-Artifact-SHA256", hex.EncodeToString(digest[:]))
		_, _ = w.Write(artifact)
	}))
	defer server.Close()

	base := filepath.Join(t.TempDir(), "publisher")
	replayDir := filepath.Join(t.TempDir(), "replay")
	for _, directory := range []string{base, filepath.Join(base,"staging"), filepath.Join(base,"releases"), replayDir} {
		if err := os.Mkdir(directory, 0700); err != nil { t.Fatal(err) }
	}
	config := Config{
		HTTPClient: server.Client(),
		ArtifactClient: artifactclient.Config{
			ControlPlaneURL: server.URL,
			NodeIdentity: "runtime-test-node",
			PrivateKey: nodePrivate,
		},
		Expected: expected,
		TrustedSigningKeys: map[string]*rsa.PublicKey{"nexora-test": &signingKey.PublicKey},
		BaseDir: base,
		ReplayGuard: artifactreceiver.FileReplayGuard{Directory: replayDir},
	}
	result, err := FetchAndPublish(context.Background(), config, expected.DeploymentID)
	if err != nil { t.Fatal(err) }
	if result.ReleaseID != expected.DeploymentID || result.ArtifactSHA256 != deployenvelope.DigestHex(artifact) {
		t.Fatalf("unexpected publication result: %+v", result)
	}
	published, err := os.ReadFile(filepath.Join(base,"releases",expected.DeploymentID,"public","index.html"))
	if err != nil { t.Fatal(err) }
	if string(published) != "<h1>Published by Nexora</h1>" { t.Fatalf("unexpected content: %q", published) }
	link, err := os.Readlink(filepath.Join(base,"current"))
	if err != nil { t.Fatal(err) }
	if link != filepath.Join("releases",expected.DeploymentID) { t.Fatalf("unexpected active link: %q", link) }

	_, err = FetchAndPublish(context.Background(), config, expected.DeploymentID)
	if err == nil || !strings.Contains(err.Error(), "already been consumed") {
		t.Fatalf("expected persistent envelope replay rejection, got %v", err)
	}
}

func TestFetchAndPublishRejectsMismatchedRequestedDeployment(t *testing.T) {
	config := Config{Expected: deployenvelope.Expected{DeploymentID:"expected-deployment"}}
	_, err := FetchAndPublish(context.Background(), config, "other-deployment")
	if err == nil { t.Fatal("expected trusted assignment mismatch rejection") }
}

func TestFetchAndPublishRejectsInvalidEnvelopeBeforePublishing(t *testing.T) {
	_, nodePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil { t.Fatal(err) }
	now := time.Now().UTC().Truncate(time.Second)
	expected := deployenvelope.Expected{
		Issuer:"https://api.nexoraedge.digital", Audience:"nexora-runtime",
		OrganizationID:"org_test", ProjectID:"project_test", DeploymentID:"deployment_test",
		HostingAccountID:"hosting_test", RepositoryID:"123456789",
		CommitSHA:"0123456789abcdef0123456789abcdef01234567",
	}
	artifact := releaseArchive(t)
	token := envelopeFor(t, signingKey, expected, artifact, now)
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(parts[2]) < 2 {
		t.Fatal("test JWT must be a compact three-part token")
	}
	replacement := "A"
	if parts[2][:1] == replacement { replacement = "B" }
	parts[2] = replacement + parts[2][1:]
	token = strings.Join(parts, ".")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type","application/gzip")
		w.Header().Set("Cache-Control","no-store")
		w.Header().Set("X-Content-Type-Options","nosniff")
		w.Header().Set("X-Nexora-Deployment-Envelope",token)
		digest := sha256.Sum256(artifact)
		w.Header().Set("X-Nexora-Artifact-SHA256",hex.EncodeToString(digest[:]))
		_,_ = w.Write(artifact)
	}))
	defer server.Close()
	base := filepath.Join(t.TempDir(),"publisher")
	replayDir := filepath.Join(t.TempDir(),"replay")
	for _, directory := range []string{base,filepath.Join(base,"staging"),filepath.Join(base,"releases"),replayDir} {
		if err := os.Mkdir(directory,0700); err != nil { t.Fatal(err) }
	}
	config := Config{
		HTTPClient:server.Client(),
		ArtifactClient:artifactclient.Config{ControlPlaneURL:server.URL,NodeIdentity:"runtime-test-node",PrivateKey:nodePrivate},
		Expected:expected, TrustedSigningKeys:map[string]*rsa.PublicKey{"nexora-test":&signingKey.PublicKey},
		BaseDir:base, ReplayGuard:artifactreceiver.FileReplayGuard{Directory:replayDir},
	}
	_, err = FetchAndPublish(context.Background(),config,expected.DeploymentID)
	if err == nil { t.Fatal("expected invalid envelope rejection") }
	entries, readErr := os.ReadDir(filepath.Join(base,"staging"))
	if readErr != nil { t.Fatal(readErr) }
	if len(entries) != 0 { t.Fatalf("invalid envelope created staging directories: %v",entries) }
}
