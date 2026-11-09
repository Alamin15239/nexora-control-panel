package artifactreceiver

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"strings"

	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/deployenvelope"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/releasepublisher"
)

type memoryReplayGuard struct {
	mu sync.Mutex
	seen map[string]bool
}

func (g *memoryReplayGuard) Consume(_ context.Context, jti string, _ time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen[jti] {
		return errors.New("replayed token")
	}
	g.seen[jti] = true
	return nil
}

type fixture struct {
	request Request
	privateKey *rsa.PrivateKey
	jti string
}

func makeArchive(t *testing.T) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	body := []byte("<h1>Nexora test release</h1>")
	if err := tw.WriteHeader(&tar.Header{Name: "public/index.html", Mode: 0644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil { t.Fatal(err) }
	if err := tw.Close(); err != nil { t.Fatal(err) }
	if err := gz.Close(); err != nil { t.Fatal(err) }
	return out.Bytes()
}

func signEnvelope(t *testing.T, key *rsa.PrivateKey, now time.Time, expected deployenvelope.Expected, artifact []byte, jti string) string {
	t.Helper()
	digest := sha256.Sum256(artifact)
	header, _ := json.Marshal(map[string]string{"alg":"RS256", "typ":"JWT", "kid":"test-key"})
	claims, _ := json.Marshal(map[string]any{
		"iss":"https://api.nexoraedge.digital",
		"aud":"nexora-builder",
		"organization_id":expected.OrganizationID,
		"project_id":expected.ProjectID,
		"deployment_id":expected.DeploymentID,
		"hosting_account_id":expected.HostingAccountID,
		"domain_id":expected.DomainID,
		"hostname":expected.Hostname,
		"repository_id":expected.RepositoryID,
		"commit_sha":expected.CommitSHA,
		"artifact_sha256":hex.EncodeToString(digest[:]),
		"artifact_bytes":len(artifact),
		"jti":jti,
		"iat":now.Unix(),
		"exp":now.Add(5*time.Minute).Unix(),
	})
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil { t.Fatal(err) }
	return input + "." + enc.EncodeToString(signature)
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil { t.Fatal(err) }
	now := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	expected := deployenvelope.Expected{
		Issuer:"https://api.nexoraedge.digital",
		Audience:"nexora-builder",
		OrganizationID:"org_test",
		ProjectID:"project_test",
		DeploymentID:"deploy_test_001",
		HostingAccountID:"hosting_test",
		DomainID:"domain_test",
		Hostname:"www.example.test",
		RepositoryID:"123456789",
		CommitSHA:"0123456789abcdef0123456789abcdef01234567",
	}
	artifact := makeArchive(t)
	jti := "00112233445566778899aabbccddeeff"
	token := signEnvelope(t, key, now, expected, artifact, jti)
	base := filepath.Join(t.TempDir(), "publisher")
	for _, dir := range []string{base, filepath.Join(base,"staging"), filepath.Join(base,"releases")} {
		if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
	}
	return fixture{
		privateKey:key,
		jti:jti,
		request:Request{
			Token:token, Artifact:artifact, Expected:expected,
			Keys:map[string]*rsa.PublicKey{"test-key":&key.PublicKey},
			BaseDir:base, Now:now, Replay:&memoryReplayGuard{seen:map[string]bool{}},
		},
	}
}

func TestReceiveVerifiesAndStoresImmutableReleaseWithoutActivation(t *testing.T) {
	f := newFixture(t)
	result, err := Receive(context.Background(), f.request)
	if err != nil { t.Fatal(err) }
	if result.ReleaseID != f.request.Expected.DeploymentID || result.Archive.Files != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	releaseFile := filepath.Join(f.request.BaseDir,"releases",result.ReleaseID,"public","index.html")
	got, err := os.ReadFile(releaseFile)
	if err != nil { t.Fatal(err) }
	if string(got) != "<h1>Nexora test release</h1>" { t.Fatalf("unexpected release content: %q", got) }
	fileInfo, err := os.Stat(releaseFile)
	if err != nil { t.Fatal(err) }
	if fileInfo.Mode().Perm() != 0644 { t.Fatalf("published static file mode = %o, want 0644", fileInfo.Mode().Perm()) }
	releaseInfo, err := os.Stat(filepath.Join(f.request.BaseDir, "releases", result.ReleaseID))
	if err != nil { t.Fatal(err) }
	if releaseInfo.Mode().Perm() != 0750 { t.Fatalf("published release root mode = %o, want 0750", releaseInfo.Mode().Perm()) }
	if _, err := os.Lstat(filepath.Join(f.request.BaseDir, "current")); !os.IsNotExist(err) {
		t.Fatalf("artifact receipt unexpectedly activated release: %v", err)
	}
}

func TestReceiveRejectsArtifactDigestMismatchBeforeStaging(t *testing.T) {
	f := newFixture(t)
	f.request.Artifact = append([]byte(nil), f.request.Artifact...)
	f.request.Artifact[len(f.request.Artifact)-1] ^= 0xff
	if _, err := Receive(context.Background(), f.request); err == nil {
		t.Fatal("expected artifact digest mismatch")
	}
	entries, err := os.ReadDir(filepath.Join(f.request.BaseDir,"staging"))
	if err != nil { t.Fatal(err) }
	if len(entries) != 0 { t.Fatalf("unexpected staging entries: %v", entries) }
}

func TestReceiveRejectsCrossProjectEnvelope(t *testing.T) {
	f := newFixture(t)
	f.request.Expected.ProjectID = "another_project"
	if _, err := Receive(context.Background(), f.request); err == nil {
		t.Fatal("expected project identity mismatch")
	}
}

func TestReceiveRejectsReplayedEnvelope(t *testing.T) {
	f := newFixture(t)
	guard := f.request.Replay.(*memoryReplayGuard)
	guard.seen[f.jti] = true
	if _, err := Receive(context.Background(), f.request); err == nil {
		t.Fatal("expected replay rejection")
	}
	entries, err := os.ReadDir(filepath.Join(f.request.BaseDir,"staging"))
	if err != nil { t.Fatal(err) }
	if len(entries) != 0 { t.Fatalf("unexpected staging entries: %v", entries) }
}


func TestReceiveRetryRecognizesStoredReleaseWithoutReactivatingRollbackTarget(t *testing.T) {
	f := newFixture(t)
	first, err := Receive(context.Background(), f.request)
	if err != nil { t.Fatal(err) }
	if first.AlreadyPublished { t.Fatal("first publication was incorrectly marked as a retry") }

	otherRelease := filepath.Join(f.request.BaseDir, "releases", "previous-release")
	if err := os.Mkdir(otherRelease, 0700); err != nil { t.Fatal(err) }
	if err := releasepublisher.Activate(f.request.BaseDir, "previous-release"); err != nil { t.Fatal(err) }

	retry := f.request
	retry.Token = signEnvelope(t, f.privateKey, f.request.Now, f.request.Expected, f.request.Artifact,
		"11112222333344445555666677778888")
	result, err := Receive(context.Background(), retry)
	if err != nil { t.Fatal(err) }
	if !result.AlreadyPublished { t.Fatal("retry was not recognized as already published") }
	target, err := os.Readlink(filepath.Join(f.request.BaseDir, "current"))
	if err != nil { t.Fatal(err) }
	if target != filepath.Join("releases", "previous-release") {
		t.Fatalf("retry changed the active rollback target: %q", target)
	}
	entries, err := os.ReadDir(filepath.Join(f.request.BaseDir, "staging"))
	if err != nil { t.Fatal(err) }
	if len(entries) != 0 { t.Fatalf("retry unexpectedly extracted another staging release: %v", entries) }
}

func TestReceiveRefusesExistingReleaseWithMismatchedManifest(t *testing.T) {
	f := newFixture(t)
	if _, err := Receive(context.Background(), f.request); err != nil { t.Fatal(err) }
	manifestPath := filepath.Join(f.request.BaseDir, "releases", f.request.Expected.DeploymentID, releaseManifestName)
	if err := os.Chmod(manifestPath, 0600); err != nil { t.Fatal(err) }
	if err := os.WriteFile(manifestPath, []byte("{\"version\":1,\"releaseId\":\"deploy_test_001\",\"artifactSha256\":\""+strings.Repeat("f",64)+"\",\"artifactBytes\":1}"), 0600); err != nil { t.Fatal(err) }

	retry := f.request
	retry.Token = signEnvelope(t, f.privateKey, f.request.Now, f.request.Expected, f.request.Artifact,
		"99992222333344445555666677778888")
	if _, err := Receive(context.Background(), retry); err == nil {
		t.Fatal("mismatched existing release manifest was accepted")
	}
}
