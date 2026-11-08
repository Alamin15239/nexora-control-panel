package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/appnodeauth"
)

func TestFetchPendingPreservesConfiguredHealthCheckPath(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		if r.Method != http.MethodGet || r.URL.Path != pendingPath { t.Errorf("unexpected request: %s %s",r.Method,r.URL.Path) }
		proof := appnodeauth.Proof{
			Timestamp:r.Header.Get("X-Nexora-Node-Timestamp"),
			Nonce:r.Header.Get("X-Nexora-Node-Nonce"),
			Signature:r.Header.Get("X-Nexora-Node-Signature"),
		}
		issuedAt, parseErr := time.Parse(time.RFC3339, time.Unix(0,0).Format(time.RFC3339))
		_ = issuedAt
		if parseErr != nil { t.Fatal(parseErr) }
		var timestamp int64
		if _, scanErr := fmt.Sscan(proof.Timestamp,&timestamp); scanErr != nil { t.Errorf("invalid signed timestamp: %v",scanErr) }
		if verifyErr := appnodeauth.Verify(publicKey,r.Header.Get("X-Nexora-Node-Identity"),r.Method,r.URL.Path,nil,proof,time.Unix(timestamp,0)); verifyErr != nil {
			t.Errorf("request proof invalid: %v",verifyErr)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type","application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"nodeIdentity":"runtime-node-test",
			"polledAt":time.Now().UTC(),
			"releases":[]any{map[string]any{
				"deploymentId":"deployment_test","organizationId":"org_test","projectId":"project_test",
				"hostingAccountId":"hosting_test","domainId":"domain_test","hostname":"www.example.test",
				"repositoryId":"123456789","commitSha":"0123456789abcdef0123456789abcdef01234567",
				"healthCheckPath":"/healthz",
			}},
		})
	}))
	defer server.Close()
	cfg := Config{ControlPlaneURL:server.URL,NodeIdentity:"runtime-node-test"}
	releases, err := fetchPending(context.Background(),server.Client(),cfg,privateKey)
	if err != nil { t.Fatal(err) }
	if len(releases)!=1 || releases[0].HealthCheckPath!="/healthz" {
		t.Fatalf("configured health-check path was not preserved: %+v",releases)
	}
}
