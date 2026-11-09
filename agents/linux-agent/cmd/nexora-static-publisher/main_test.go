package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/appnodeauth"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/runtimehealth"
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
		timestamp, parseErr := strconv.ParseInt(proof.Timestamp,10,64)
		if parseErr != nil { t.Errorf("invalid signed timestamp: %v",parseErr) }
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
			"rollbacks":[]any{map[string]any{
				"failedDeploymentId":"deployment_failed","targetDeploymentId":"deployment_previous",
				"failedReleaseId":"release_failed","targetReleaseId":"release_previous",
				"organizationId":"org_test","projectId":"project_test","hostingAccountId":"hosting_test",
				"hostname":"www.example.test","healthCheckPath":"/healthz",
				"targetArtifactSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			}},
		})
	}))
	defer server.Close()
	cfg := Config{ControlPlaneURL:server.URL,NodeIdentity:"runtime-node-test"}
	pending, err := fetchPending(context.Background(),server.Client(),cfg,privateKey)
	if err != nil { t.Fatal(err) }
	if len(pending.Rollbacks)!=1 || pending.Rollbacks[0].TargetDeploymentID!="deployment_previous" || pending.Rollbacks[0].FailedReleaseID!="release_failed" || pending.Rollbacks[0].TargetReleaseID!="release_previous" || pending.Rollbacks[0].TargetArtifactSHA256!="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("pending rollback was not preserved: %+v",pending.Rollbacks)
	}
	if len(pending.Releases)!=1 || pending.Releases[0].HealthCheckPath!="/healthz" {
		t.Fatalf("configured health-check path was not preserved: %+v",pending.Releases)
	}
}


func rollbackTestLayout(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	for _, name := range []string{"staging", "releases"} {
		if err := os.Mkdir(filepath.Join(base, name), 0700); err != nil { t.Fatal(err) }
	}
	for _, id := range []string{"release_old", "release_new", "release_latest"} {
		if err := os.Mkdir(filepath.Join(base, "releases", id), 0700); err != nil { t.Fatal(err) }
	}
	if err := os.Symlink(filepath.Join("releases", "release_new"), filepath.Join(base, "current")); err != nil { t.Fatal(err) }
	return base
}

func TestRollbackStaticReleaseRestoresPreviousAndVerifiesServing(t *testing.T) {
	base := rollbackTestLayout(t)
	target, node := "release_old", "runtime-node-test"
	probed := false
	result, err := rollbackStaticRelease(base, "release_new", &target, &node, node, func() runtimehealth.Result {
		probed = true
		return runtimehealth.Result{Status:runtimehealth.Healthy,HTTPStatus:http.StatusOK}
	})
	if err != nil { t.Fatal(err) }
	if !probed || result.Status != runtimehealth.Healthy { t.Fatalf("rollback serving probe did not pass: %+v",result) }
	active, err := os.Readlink(filepath.Join(base,"current"))
	if err != nil { t.Fatal(err) }
	if active != filepath.Join("releases","release_old") { t.Fatalf("active release = %q",active) }
}

func TestRollbackStaticReleaseRejectsOtherNodeAndLeavesActiveUntouched(t *testing.T) {
	base := rollbackTestLayout(t)
	target, targetNode := "release_old", "different-node"
	_, err := rollbackStaticRelease(base,"release_new",&target,&targetNode,"runtime-node-test",func() runtimehealth.Result {
		t.Fatal("probe must not run for a cross-node rollback")
		return runtimehealth.Result{}
	})
	if err == nil { t.Fatal("accepted rollback target on another node") }
	active, readErr := os.Readlink(filepath.Join(base,"current"))
	if readErr != nil { t.Fatal(readErr) }
	if active != filepath.Join("releases","release_new") { t.Fatalf("active release changed: %q",active) }
}

func TestRollbackStaticReleaseRefusesStaleTargetAfterNewerActivation(t *testing.T) {
	base := rollbackTestLayout(t)
	if err := os.Remove(filepath.Join(base,"current")); err != nil { t.Fatal(err) }
	if err := os.Symlink(filepath.Join("releases","release_latest"),filepath.Join(base,"current")); err != nil { t.Fatal(err) }
	target, node := "release_old", "runtime-node-test"
	_, err := rollbackStaticRelease(base,"release_new",&target,&node,node,func() runtimehealth.Result {
		t.Fatal("probe must not run after stale compare-and-switch refusal")
		return runtimehealth.Result{}
	})
	if err == nil { t.Fatal("stale rollback overwrote a newer active release") }
	active, readErr := os.Readlink(filepath.Join(base,"current"))
	if readErr != nil { t.Fatal(readErr) }
	if active != filepath.Join("releases","release_latest") { t.Fatalf("newer release was overwritten: %q",active) }
}

func TestRollbackStaticReleaseRequiresHealthyRestoredProbe(t *testing.T) {
	base := rollbackTestLayout(t)
	target, node := "release_old", "runtime-node-test"
	result, err := rollbackStaticRelease(base,"release_new",&target,&node,node,func() runtimehealth.Result {
		return runtimehealth.Result{Status:runtimehealth.Unhealthy,HTTPStatus:http.StatusServiceUnavailable,FailureCode:"http_5xx"}
	})
	if err == nil || result.FailureCode != "http_5xx" { t.Fatalf("expected unhealthy restored probe, got %+v, %v",result,err) }
	active, readErr := os.Readlink(filepath.Join(base,"current"))
	if readErr != nil { t.Fatal(readErr) }
	if active != filepath.Join("releases","release_old") { t.Fatalf("rollback target was not activated: %q",active) }
}

func TestRollbackIntentFromPendingBindsAccountAndProbeMetadata(t *testing.T) {
	pending := PendingRollback{
		FailedDeploymentID: "deployment-failed",
		TargetDeploymentID: "deployment-previous",
		FailedReleaseID: "release-failed",
		TargetReleaseID: "release-previous",
		OrganizationID: "org-test",
		ProjectID: "project-test",
		HostingAccountID: "hosting-test",
		Hostname: "www.example.test",
		HealthCheckPath: "/healthz",
		TargetArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	op := rollbackIntentFromPending(pending, "runtime-node-test")
	if op.ID != "rollback-deployment-failed" || op.NodeID != "runtime-node-test" ||
		op.FailedDeploymentID != pending.FailedDeploymentID || op.TargetDeploymentID != pending.TargetDeploymentID ||
		op.FailedReleaseID != pending.FailedReleaseID || op.TargetReleaseID != pending.TargetReleaseID ||
		op.ExpectedActiveReleaseID != pending.FailedReleaseID ||
		op.HostingAccountID != pending.HostingAccountID || op.Hostname != pending.Hostname ||
		op.HealthCheckPath != pending.HealthCheckPath || op.ArtifactSHA256 != pending.TargetArtifactSHA256 {
		t.Fatalf("rollback intent lost its trusted assignment: %+v", op)
	}
}
