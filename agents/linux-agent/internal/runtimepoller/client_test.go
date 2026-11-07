package runtimepoller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/appnodeauth"
)

func stringPtr(value string) *string { return &value }
func intPtr(value int) *int { return &value }

func testSnapshot() Snapshot {
	return Snapshot{
		NodeIdentity: "runtime-a", PolledAt: time.Now().UTC(), ExecutionEnabled: false,
		CommandsIncluded: false, SecretsIncluded: false,
		Workloads: []Workload{{
			WorkloadID: "workload-a", ProjectID: "project-a", WorkloadKind: "web",
			WorkloadStatus: "healthy", DesiredReplicas: 1, ObservedReplicas: 1,
			ReleaseID: "release-a", ReleaseState: "succeeded", ReleaseSpecVersion: 2,
			ImageDigest: stringPtr("registry.nexoraedge.digital/org/app@sha256:" + strings.Repeat("a", 64)), ListenPort: intPtr(3000),
			SettingsSpecVersion: 2, RuntimeProfileID: "runtime-nodejs-v1",
			RuntimeProfileKey: "nodejs-v1", RuntimeFamily: "nodejs", ExecutionKind: "oci",
			CPUMillis: 500, MemoryMiB: 512, DiskMiB: 2048, ProcessLimit: 128,
			DesiredState: "running",
		}},
	}
}

func testClient(t *testing.T, handler http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	_ = public
	server := httptest.NewServer(handler)
	client := &Client{
		BaseURL: server.URL, NodeIdentity: "runtime-a", PrivateKey: private,
		HTTPClient: server.Client(), Now: func() time.Time { return time.Now().UTC() },
	}
	return client, server
}

func TestPollSignsExactGETAndDecodesReadOnlySnapshot(t *testing.T) {
	expected := testSnapshot()
	client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != desiredStatePath { t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path) }
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil || len(body) != 0 { t.Errorf("poll request unexpectedly has a body: %q (%v)", body, readErr) }
		proof := appnodeauth.Proof{
			Timestamp: r.Header.Get("X-Nexora-Node-Timestamp"),
			Nonce: r.Header.Get("X-Nexora-Node-Nonce"),
			Signature: r.Header.Get("X-Nexora-Node-Signature"),
		}
		if proof.Nonce == "" || proof.Signature == "" { t.Error("request proof headers are missing") }
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(expected)
	}))
	defer server.Close()
	got, err := client.Poll(context.Background())
	if err != nil { t.Fatal(err) }
	if got.NodeIdentity != expected.NodeIdentity || len(got.Workloads) != 1 ||
		got.Workloads[0].WorkloadID != "workload-a" || got.ExecutionEnabled {
		t.Fatalf("unexpected snapshot: %+v", got)
	}
}

func TestPollRejectsExecutionEnabledOrSecretsInResponse(t *testing.T) {
	for _, mutate := range []func(*Snapshot){
		func(s *Snapshot) { s.ExecutionEnabled = true },
		func(s *Snapshot) { s.SecretsIncluded = true },
		func(s *Snapshot) { s.CommandsIncluded = true },
	} {
		snapshot := testSnapshot()
		mutate(&snapshot)
		client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(snapshot)
		}))
		_, err := client.Poll(context.Background())
		server.Close()
		if err == nil { t.Fatal("unsafe polling response was accepted") }
	}
}

func TestPollRejectsInvalidWorkloadAndDuplicateIDs(t *testing.T) {
	for _, mutate := range []func(*Snapshot){
		func(s *Snapshot) { s.Workloads[0].ReleaseState = "building" },
		func(s *Snapshot) { s.Workloads[0].CPUMillis = 9000 },
		func(s *Snapshot) { s.Workloads[0].RuntimeProfileKey = "container-v1" },
		func(s *Snapshot) { s.Workloads[0].ImageDigest = stringPtr("registry.example/app:latest") },
		func(s *Snapshot) { s.Workloads[0].ListenPort = intPtr(8080) },
		func(s *Snapshot) { s.Workloads[0].DesiredReplicas = 2 },
		func(s *Snapshot) { s.Workloads = append(s.Workloads, s.Workloads[0]) },
	} {
		snapshot := testSnapshot()
		mutate(&snapshot)
		client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(snapshot)
		}))
		_, err := client.Poll(context.Background())
		server.Close()
		if err == nil { t.Fatal("invalid workload metadata was accepted") }
	}
}

func TestPollRejectsOversizedAndUnknownResponseFields(t *testing.T) {
	for _, body := range []string{
		strings.Repeat("x", maxResponseBytes+1),
		`{"nodeIdentity":"runtime-a","polledAt":"2026-11-07T00:00:00Z","executionEnabled":false,"workloads":[],"commandsIncluded":false,"secretsIncluded":false,"unexpected":true}`,
	} {
		client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		_, err := client.Poll(context.Background())
		server.Close()
		if err == nil { t.Fatal("invalid response was accepted") }
	}
}

func TestPollRequiresHTTPSOutsideLoopback(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	client := &Client{BaseURL: "http://control.example.test", NodeIdentity: "runtime-a", PrivateKey: private}
	if _, err := client.Poll(context.Background()); err == nil {
		t.Fatal("non-loopback HTTP control-plane URL was accepted")
	}
}

func TestPollProofVerifiesAgainstNodePublicKey(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	now := time.Now().UTC()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proof := appnodeauth.Proof{
			Timestamp: r.Header.Get("X-Nexora-Node-Timestamp"),
			Nonce: r.Header.Get("X-Nexora-Node-Nonce"),
			Signature: r.Header.Get("X-Nexora-Node-Signature"),
		}
		if err := appnodeauth.Verify(public, "runtime-a", http.MethodGet, desiredStatePath, nil, proof, now); err != nil {
			t.Errorf("request signature verification failed: %v", err)
		}
		_ = json.NewEncoder(w).Encode(testSnapshot())
	}))
	defer server.Close()
	client := &Client{
		BaseURL: server.URL, NodeIdentity: "runtime-a", PrivateKey: private,
		HTTPClient: server.Client(), Now: func() time.Time { return now },
	}
	if _, err := client.Poll(context.Background()); err != nil { t.Fatal(err) }
}
