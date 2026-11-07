package artifactclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"context"
	"io"
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
		body, err := io.ReadAll(r.Body)
		if err != nil { t.Fatal(err) }
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

	result, err := Fetch(context.Background(), server.Client(), Config{
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
	_, err := Fetch(context.Background(), server.Client(), Config{
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
	_, err := Fetch(context.Background(), server.Client(), Config{
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


func TestReportHealthCheckSignsNodeBoundReport(t *testing.T) {
	publicKey, privateKey := testIdentity(t)
	digest := sha256.Sum256([]byte("artifact"))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != ArtifactHealthCheckReportPath {
			t.Fatalf("unexpected health report target: %s %s", r.Method, r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil { t.Fatal(err) }
		proof := appnodeauth.Proof{
			Timestamp: r.Header.Get("X-Nexora-Node-Timestamp"),
			Nonce: r.Header.Get("X-Nexora-Node-Nonce"),
			Signature: r.Header.Get("X-Nexora-Node-Signature"),
		}
		if err := appnodeauth.Verify(publicKey, r.Header.Get("X-Nexora-Node-Identity"),
			r.Method, r.URL.Path, body, proof, nowFromTimestamp(t, proof.Timestamp)); err != nil {
			t.Fatalf("health report signature invalid: %v", err)
		}
		var report map[string]any
		if err := json.Unmarshal(body, &report); err != nil { t.Fatal(err) }
		if report["deploymentId"] != "deployment-a" || report["probePath"] != "/ready" ||
			report["healthStatus"] != "healthy" || report["httpStatus"] != float64(204) {
			t.Fatalf("unexpected health report: %+v", report)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{\"accepted\":true,\"duplicate\":false,\"deploymentId\":\"deployment-a\",\"releaseState\":\"succeeded\",\"workloadHealth\":\"healthy\",\"rollbackRequired\":false,\"rollbackTargetDeploymentId\":null}"))
	}))
	defer server.Close()

	ack, err := ReportHealthCheck(context.Background(), server.Client(), Config{
		ControlPlaneURL: server.URL, NodeIdentity: "runtime-a", PrivateKey: privateKey,
	}, HealthCheckReport{
		DeploymentID: "deployment-a",
		ArtifactSHA256: hex.EncodeToString(digest[:]),
		ProbePath: "/ready",
		HealthStatus: "healthy",
		HTTPStatus: 204,
		DurationMs: 19,
	})
	if err != nil { t.Fatal(err) }
	if !ack.Accepted || ack.ReleaseState != "succeeded" || ack.WorkloadHealth != "healthy" || ack.RollbackRequired {
		t.Fatalf("unexpected health acknowledgement: %+v", ack)
	}
}

func TestReportHealthCheckRejectsInconsistentOrUntrustedResults(t *testing.T) {
	_, privateKey := testIdentity(t)
	config := Config{
		ControlPlaneURL: "https://api.example.test",
		NodeIdentity: "runtime-a",
		PrivateKey: privateKey,
	}
	digest := hex.EncodeToString(make([]byte, 32))
	for _, report := range []HealthCheckReport{
		{DeploymentID:"deployment-a",ArtifactSHA256:digest,ProbePath:"/ready",HealthStatus:"healthy",HTTPStatus:503},
		{DeploymentID:"deployment-a",ArtifactSHA256:digest,ProbePath:"/ready",HealthStatus:"unhealthy",HTTPStatus:503,FailureCode:"arbitrary"},
		{DeploymentID:"deployment-a",ArtifactSHA256:digest,ProbePath:"/ready",HealthStatus:"unhealthy",HTTPStatus:204,FailureCode:"timeout"},
		{DeploymentID:"deployment-a",ArtifactSHA256:digest,ProbePath:"/ready?token=secret",HealthStatus:"healthy",HTTPStatus:200},
	} {
		if _, err := ReportHealthCheck(context.Background(), nil, config, report); err == nil {
			t.Fatalf("expected invalid health report rejection: %+v", report)
		}
	}
}


func TestReportHealthCheckReturnsRollbackTargetForUnhealthyRelease(t *testing.T) {
	_, privateKey := testIdentity(t)
	digest := sha256.Sum256([]byte("artifact"))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"accepted\":true,\"duplicate\":false,\"deploymentId\":\"deployment-a\",\"releaseState\":\"failed\",\"workloadHealth\":\"unhealthy\",\"rollbackRequired\":true,\"rollbackTargetDeploymentId\":\"previous-deployment\"}"))
	}))
	defer server.Close()
	ack, err := ReportHealthCheck(context.Background(), server.Client(), Config{
		ControlPlaneURL:server.URL, NodeIdentity:"runtime-a", PrivateKey:privateKey,
	}, HealthCheckReport{
		DeploymentID:"deployment-a",
		ArtifactSHA256:hex.EncodeToString(digest[:]),
		ProbePath:"/ready",
		HealthStatus:"unhealthy",
		HTTPStatus:503,
		DurationMs:100,
		FailureCode:"http_5xx",
	})
	if err != nil { t.Fatal(err) }
	if !ack.RollbackRequired || ack.RollbackTargetDeploymentID == nil ||
		*ack.RollbackTargetDeploymentID != "previous-deployment" || ack.ReleaseState != "failed" {
		t.Fatalf("unexpected rollback acknowledgement: %+v", ack)
	}
}

func TestReportHealthCheckRejectsContradictoryAcknowledgement(t *testing.T) {
	_, privateKey := testIdentity(t)
	digest := sha256.Sum256([]byte("artifact"))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{\"accepted\":true,\"duplicate\":false,\"deploymentId\":\"deployment-a\",\"releaseState\":\"succeeded\",\"workloadHealth\":\"healthy\",\"rollbackRequired\":true,\"rollbackTargetDeploymentId\":\"previous-deployment\"}"))
	}))
	defer server.Close()
	_, err := ReportHealthCheck(context.Background(), server.Client(), Config{
		ControlPlaneURL:server.URL, NodeIdentity:"runtime-a", PrivateKey:privateKey,
	}, HealthCheckReport{
		DeploymentID:"deployment-a", ArtifactSHA256:hex.EncodeToString(digest[:]),
		ProbePath:"/ready", HealthStatus:"healthy", HTTPStatus:200, DurationMs:1,
	})
	if err == nil { t.Fatal("expected contradictory acknowledgement to be rejected") }
}
