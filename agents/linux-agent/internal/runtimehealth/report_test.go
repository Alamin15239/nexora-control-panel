package runtimehealth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/appnodeauth"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/artifactclient"
)

func testNodeKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	return publicKey, privateKey
}

func localPort(t *testing.T, server *httptest.Server) int {
	t.Helper()
	host, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil { t.Fatal(err) }
	if host != "127.0.0.1" { t.Fatalf("workload test server is not bound to loopback: %s", host) }
	port, err := strconv.Atoi(portText)
	if err != nil { t.Fatal(err) }
	return port
}

func TestProbeAndReportSubmitsVerifiedHealthyResult(t *testing.T) {
	nodePublic, nodePrivate := testNodeKeys(t)
	workload := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ready" { w.WriteHeader(http.StatusNotFound); return }
		w.WriteHeader(http.StatusNoContent)
	}))
	defer workload.Close()
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil { t.Fatal(err) }
		proof := appnodeauth.Proof{
			Timestamp: r.Header.Get("X-Nexora-Node-Timestamp"),
			Nonce: r.Header.Get("X-Nexora-Node-Nonce"),
			Signature: r.Header.Get("X-Nexora-Node-Signature"),
		}
		issuedAt, err := strconv.ParseInt(proof.Timestamp, 10, 64)
		if err != nil { t.Fatal(err) }
		if err := appnodeauth.Verify(nodePublic, r.Header.Get("X-Nexora-Node-Identity"),
			r.Method, r.URL.Path, body, proof, time.Unix(issuedAt, 0)); err != nil {
			t.Fatalf("invalid signed node report: %v", err)
		}
		var report map[string]any
		if err := json.Unmarshal(body, &report); err != nil { t.Fatal(err) }
		if report["deploymentId"] != "deployment-a" || report["probePath"] != "/ready" ||
			report["healthStatus"] != "healthy" || report["httpStatus"] != float64(http.StatusNoContent) {
			t.Fatalf("unexpected health report: %+v", report)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"accepted\":true,\"duplicate\":false,\"deploymentId\":\"deployment-a\",\"releaseState\":\"succeeded\",\"workloadHealth\":\"healthy\",\"rollbackRequired\":false,\"rollbackTargetDeploymentId\":null}"))
	}))
	defer api.Close()
	digest := hex.EncodeToString(make([]byte, 32))
	result, ack, err := ProbeAndReport(context.Background(), api.Client(), artifactclient.Config{
		ControlPlaneURL: api.URL,
		NodeIdentity: "runtime-a",
		PrivateKey: nodePrivate,
	}, "deployment-a", digest, localPort(t, workload), "/ready", time.Second)
	if err != nil { t.Fatal(err) }
	if result.Status != Healthy || result.HTTPStatus != http.StatusNoContent {
		t.Fatalf("unexpected probe result: %+v", result)
	}
	if !ack.Accepted || ack.ReleaseState != "succeeded" || ack.WorkloadHealth != "healthy" {
		t.Fatalf("unexpected API acknowledgement: %+v", ack)
	}
}

func TestProbeAndReportReturnsRollbackGuidanceForUnhealthyWorkload(t *testing.T) {
	_, nodePrivate := testNodeKeys(t)
	workload := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer workload.Close()
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !json.Valid(body) { t.Fatal("health report is not valid JSON") }
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"accepted\":true,\"duplicate\":false,\"deploymentId\":\"deployment-a\",\"releaseState\":\"failed\",\"workloadHealth\":\"unhealthy\",\"rollbackRequired\":true,\"rollbackTargetDeploymentId\":\"previous-deployment\"}"))
	}))
	defer api.Close()
	digest := hex.EncodeToString(make([]byte, 32))
	result, ack, err := ProbeAndReport(context.Background(), api.Client(), artifactclient.Config{
		ControlPlaneURL: api.URL,
		NodeIdentity: "runtime-a",
		PrivateKey: nodePrivate,
	}, "deployment-a", digest, localPort(t, workload), "/ready", time.Second)
	if err != nil { t.Fatal(err) }
	if result.Status != Unhealthy || result.FailureCode != "http_5xx" {
		t.Fatalf("unexpected unhealthy probe result: %+v", result)
	}
	if !ack.RollbackRequired || ack.RollbackTargetDeploymentID == nil ||
		*ack.RollbackTargetDeploymentID != "previous-deployment" {
		t.Fatalf("missing rollback guidance: %+v", ack)
	}
}
