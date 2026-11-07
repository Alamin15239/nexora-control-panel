package artifactclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"strconv"
	"time"

	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/appnodeauth"
)

func testIdentity(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	return publicKey, privateKey
}

func TestFetchAuthenticatesAndVerifiesArtifactTransport(t *testing.T) {
	publicKey, privateKey := testIdentity(t)
	artifact := []byte("synthetic-gzip-artifact")
	digest := sha256.Sum256(artifact)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != ArtifactRequestPath {
			t.Fatalf("unexpected request target: %s %s", r.Method, r.URL.Path)
		}
		body := make([]byte, r.ContentLength)
		if _, err := r.Body.Read(body); err != nil { t.Fatal(err) }
		proof := appnodeauth.Proof{
			Timestamp: r.Header.Get("X-Nexora-Node-Timestamp"),
			Nonce: r.Header.Get("X-Nexora-Node-Nonce"),
			Signature: r.Header.Get("X-Nexora-Node-Signature"),
		}
		if err := appnodeauth.Verify(publicKey, r.Header.Get("X-Nexora-Node-Identity"),
			r.Method, r.URL.Path, body, proof, nowFromTimestamp(t, proof.Timestamp)); err != nil {
			t.Fatalf("request signature invalid: %v", err)
		}
		var payload struct { DeploymentID string `json:"deploymentId"` }
		if err := json.Unmarshal(body, &payload); err != nil { t.Fatal(err) }
		if payload.DeploymentID != "deployment-a" { t.Fatalf("unexpected request: %+v", payload) }
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Nexora-Deployment-Envelope", "signed-envelope-test")
		w.Header().Set("X-Nexora-Artifact-SHA256", hex.EncodeToString(digest[:]))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(artifact)
	}))
	defer server.Close()

	result, err := Fetch(t.Context(), server.Client(), Config{
		ControlPlaneURL: server.URL,
		NodeIdentity: "runtime-a",
		PrivateKey: privateKey,
	}, "deployment-a")
	if err != nil { t.Fatal(err) }
	if result.Envelope != "signed-envelope-test" || result.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("unexpected download metadata: %+v", result)
	}
	if string(result.Artifact) != string(artifact) { t.Fatalf("unexpected artifact: %q", result.Artifact) }
}

func TestFetchRejectsDigestMismatch(t *testing.T) {
	_, privateKey := testIdentity(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Nexora-Deployment-Envelope", "signed-envelope-test")
		w.Header().Set("X-Nexora-Artifact-SHA256", hex.EncodeToString(make([]byte, 32)))
		_, _ = w.Write([]byte("tampered"))
	}))
	defer server.Close()
	_, err := Fetch(t.Context(), server.Client(), Config{
		ControlPlaneURL: server.URL, NodeIdentity: "runtime-a", PrivateKey: privateKey,
	}, "deployment-a")
	if err == nil { t.Fatal("expected SHA-256 mismatch") }
}

func TestFetchDoesNotFollowRedirects(t *testing.T) {
	_, privateKey := testIdentity(t)
	redirectTargetCalled := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectTargetCalled = true
	}))
	defer target.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	_, err := Fetch(t.Context(), server.Client(), Config{
		ControlPlaneURL: server.URL, NodeIdentity: "runtime-a", PrivateKey: privateKey,
	}, "deployment-a")
	if err == nil { t.Fatal("expected redirect response to be rejected") }
	if redirectTargetCalled { t.Fatal("request proof was forwarded to redirect target") }
}

func nowFromTimestamp(t *testing.T, value string) time.Time {
	t.Helper()
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil { t.Fatal(err) }
	return time.Unix(seconds, 0)
}
