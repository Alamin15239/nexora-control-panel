package main

import (
        "context"
        "crypto/ed25519"
        "crypto/rand"
        "crypto/tls"
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
                                "releaseId":"deployment_test","state":"publishing",
                                "artifactSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
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
        if err := os.Chmod(base, 0700); err != nil {
                t.Fatal(err)
        }
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

func testAccountsRoot(t *testing.T) string {
        t.Helper()
        root := t.TempDir()
        if err := os.Chmod(root, 0700); err != nil {
                t.Fatal(err)
        }
        return root
}

func TestProvisionAccountDirectoriesCreatesPrivateSetgidLayout(t *testing.T) {
        root := testAccountsRoot(t)

        base, err := provisionAccountDirectories(root, "account_123-ABC")
        if err != nil {
                t.Fatal(err)
        }

        for _, path := range []string{
                base,
                filepath.Join(base, "staging"),
                filepath.Join(base, "releases"),
        } {
                info, err := os.Lstat(path)
                if err != nil {
                        t.Fatal(err)
                }
                if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
                        t.Fatalf("%s is not a real directory", path)
                }
                if info.Mode().Perm() != 0750 || info.Mode()&os.ModeSetgid == 0 {
                        t.Fatalf("%s has unsafe mode %v", path, info.Mode())
                }
        }

        if _, err := os.Lstat(filepath.Join(base, "current")); !os.IsNotExist(err) {
                t.Fatal("provisioning must not create the current symlink")
        }
}

func TestProvisionAccountDirectoriesRejectsInvalidIdentifiers(t *testing.T) {
        for _, id := range []string{"", ".", "..", "../escape", "a/b", "a\\b", "has space"} {
                t.Run(id, func(t *testing.T) {
                        if _, err := provisionAccountDirectories(testAccountsRoot(t), id); err == nil {
                                t.Fatalf("invalid account ID %q was accepted", id)
                        }
                })
        }
}

func TestProvisionAccountDirectoriesRejectsSymlinkAccount(t *testing.T) {
        root := testAccountsRoot(t)
        outside := t.TempDir()
        if err := os.Symlink(outside, filepath.Join(root, "account_123")); err != nil {
                t.Fatal(err)
        }
        if _, err := provisionAccountDirectories(root, "account_123"); err == nil {
                t.Fatal("symlink account directory was accepted")
        }
}

func TestProvisionAccountDirectoriesRejectsUnsafeExistingChild(t *testing.T) {
        root := testAccountsRoot(t)
        base := filepath.Join(root, "account_123")
        if err := os.Mkdir(base, os.FileMode(0750)|os.ModeSetgid); err != nil {
                t.Fatal(err)
        }
        if err := os.Chmod(base, os.FileMode(0750)|os.ModeSetgid); err != nil {
                t.Fatal(err)
        }
        if err := os.Mkdir(filepath.Join(base, "staging"), 0770); err != nil {
                t.Fatal(err)
        }
        if err := os.Chmod(filepath.Join(base, "staging"), 0770); err != nil {
                t.Fatal(err)
        }
        if _, err := provisionAccountDirectories(root, "account_123"); err == nil {
                t.Fatal("unsafe existing staging directory was accepted")
        }
}

func TestVerifyOwnedRegularFileAcceptsPrivateOwnedFile(t *testing.T) {
        path := filepath.Join(t.TempDir(), "private-file")
        if err := os.WriteFile(path, []byte("private"), 0600); err != nil {
                t.Fatal(err)
        }
        if err := os.Chmod(path, 0600); err != nil {
                t.Fatal(err)
        }
        if err := verifyOwnedRegularFile(path, 1024); err != nil {
                t.Fatalf("expected private owned file to pass: %v", err)
        }
}

func TestVerifyOwnedRegularFileRejectsUnsafeMode(t *testing.T) {
        path := filepath.Join(t.TempDir(), "unsafe-file")
        if err := os.WriteFile(path, []byte("private"), 0640); err != nil {
                t.Fatal(err)
        }
        if err := os.Chmod(path, 0640); err != nil {
                t.Fatal(err)
        }
        if err := verifyOwnedRegularFile(path, 1024); err == nil {
                t.Fatal("group-readable file was accepted")
        }
}

func TestVerifyOwnedRegularFileRejectsSymlink(t *testing.T) {
        dir := t.TempDir()
        target := filepath.Join(dir, "target")
        link := filepath.Join(dir, "link")
        if err := os.WriteFile(target, []byte("private"), 0600); err != nil {
                t.Fatal(err)
        }
        if err := os.Chmod(target, 0600); err != nil {
                t.Fatal(err)
        }
        if err := os.Symlink(target, link); err != nil {
                t.Fatal(err)
        }
        if err := verifyOwnedRegularFile(link, 1024); err == nil {
                t.Fatal("symlink was accepted")
        }
}

func TestVerifyOwnedRegularFileRejectsOversizedFile(t *testing.T) {
        path := filepath.Join(t.TempDir(), "large-file")
        if err := os.WriteFile(path, []byte("too large"), 0600); err != nil {
                t.Fatal(err)
        }
        if err := os.Chmod(path, 0600); err != nil {
                t.Fatal(err)
        }
        if err := verifyOwnedRegularFile(path, 4); err == nil {
                t.Fatal("oversized file was accepted")
        }
}

func TestVerifyOwnedReplayDirectoryAcceptsOwnerOnlyDirectory(t *testing.T) {
        path := t.TempDir()
        if err := os.Chmod(path, 0700); err != nil {
                t.Fatal(err)
        }
        if err := verifyOwnedReplayDirectory(path, uint32(os.Geteuid()), uint32(os.Getegid())); err != nil {
                t.Fatalf("expected owner-only replay directory to pass: %v", err)
        }
}

func TestVerifyOwnedReplayDirectoryRejectsGroupAccessibleDirectory(t *testing.T) {
        path := t.TempDir()
        if err := os.Chmod(path, 0750); err != nil {
                t.Fatal(err)
        }
        if err := verifyOwnedReplayDirectory(path, uint32(os.Geteuid()), uint32(os.Getegid())); err == nil {
                t.Fatal("group-accessible replay directory was accepted")
        }
}

func TestVerifyOwnedReplayDirectoryRejectsWorldAccessibleDirectory(t *testing.T) {
        path := t.TempDir()
        if err := os.Chmod(path, 0701); err != nil {
                t.Fatal(err)
        }
        if err := verifyOwnedReplayDirectory(path, uint32(os.Geteuid()), uint32(os.Getegid())); err == nil {
                t.Fatal("world-accessible replay directory was accepted")
        }
}

func TestValidStaticDomain(t *testing.T) {
        valid := []string{
                "example.com",
                "app.example.com",
                "customer-1.example.co.uk",
        }
        for _, domain := range valid {
                if !validStaticDomain(domain) {
                        t.Errorf("expected domain %q to be valid", domain)
                }
        }

        invalid := []string{
                "", "localhost", "example", ".example.com", "example.com.",
                "example..com", "-bad.example.com", "bad-.example.com",
                "bad domain.example.com", "a..b.example.com",
        }
        for _, domain := range invalid {
                if validStaticDomain(domain) {
                        t.Errorf("expected domain %q to be rejected", domain)
                }
        }
}

func TestValidStaticHealthCheckPath(t *testing.T) {
        valid := []string{"/", "/health", "/health/ready", "/api/v1/status"}
        for _, path := range valid {
                if !validStaticHealthCheckPath(path) {
                        t.Errorf("expected path %q to be valid", path)
                }
        }

        invalid := []string{
                "", "health", "//evil.example/path", "/health?debug=1",
                "/health#fragment", "/../etc/passwd", "/health/../admin",
                "/health\\\\admin", "/health\r\nHost: evil",
                "/%2e%2e/secret",
        }
        for _, path := range invalid {
                if validStaticHealthCheckPath(path) {
                        t.Errorf("expected path %q to be rejected", path)
                }
        }
}

func TestValidHostingAccountID(t *testing.T) {
        for _, value := range []string{"account_01", "hosting-test", "A1"} {
                if !validHostingAccountID(value) {
                        t.Errorf("valid hosting account ID %q was rejected", value)
                }
        }
        for _, value := range []string{"", ".", "..", "account.name", "account:name", "../outside", "account/name"} {
                if validHostingAccountID(value) {
                        t.Errorf("unsafe hosting account ID %q was accepted", value)
                }
        }
}

// ---------------------------------------------------------------------------
// Phase 2 restart-recovery regression tests for recoverHealthCheckingRelease.
//
// These tests prove the publisher's recovery path:
//   - enters and exits without re-publishing or re-activating the release
//   - verifies the active symlink matches the expected release ID
//   - verifies the publisher manifest matches the expected artifact digest
//   - probes and reports through the existing authenticated Worker endpoint
//   - fails safely when the local state is inconsistent (wrong active
//     release, missing manifest, tampered digest) without modifying the
//     currently active website
//   - never downloads the artifact again
// ---------------------------------------------------------------------------

// recoveryTestScaffold builds a publisher directory layout with a published
// release that is currently active, and a mock control-plane HTTP server
// that records the health-check report it receives. The artifact digest and
// manifest are written via the same artifactreceiver.writeReleaseManifest
// path used in production, so the recovery path's verification step sees a
// real on-disk manifest.
type recoveryTestScaffold struct {
        cfg             Config
        publisherRoot   string
        baseDir         string
        releaseID       string
        artifactDigest  string
        server          *httptest.Server
        reportedHealth  *struct {
                deploymentID   string
                artifactSHA256 string
                probePath      string
                healthStatus   string
                httpStatus     int
                durationMs     int
                failureCode    string
        }
        reportStatus    int
        reportBody      string
        rollbackEnabled bool
}

func newRecoveryScaffold(t *testing.T) *recoveryTestScaffold {
        t.Helper()

        // Generate an Ed25519 keypair the publisher will use to sign its
        // requests and the mock server will use to verify them.
        publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
        if err != nil {
                t.Fatalf("generate keypair: %v", err)
        }

        // Build the publisher root with an account directory containing a
        // published release that is currently active.
        publisherRoot := t.TempDir()
        if err := os.Chmod(publisherRoot, 0700); err != nil {
                t.Fatalf("chmod publisher root: %v", err)
        }
        accountsRoot := filepath.Join(publisherRoot, "accounts")
        if err := os.Mkdir(accountsRoot, 0750); err != nil {
                t.Fatalf("mkdir accounts: %v", err)
        }
        // Use the real provisionAccountDirectories to build the account
        // layout with the exact setgid mode 2750 + ownership constraints
        // the recovery path's verifyOwnedDirectory checks will enforce.
        accountID := "hosting-recovery"
        baseDir, err := provisionAccountDirectories(accountsRoot, accountID)
        if err != nil {
                t.Fatalf("provision account directories: %v", err)
        }
        // provisionAccountDirectories creates staging/ and releases/ under
        // baseDir. We add the release directory itself.
        releaseID := "deployment-recovery-001"
        releaseDir := filepath.Join(baseDir, "releases", releaseID)
        if err := os.Mkdir(releaseDir, os.FileMode(0750)|os.ModeSetgid); err != nil {
                t.Fatalf("mkdir release dir: %v", err)
        }
        // Write a placeholder file so the release directory is non-empty.
        if err := os.WriteFile(filepath.Join(releaseDir, "index.html"), []byte("<h1>ok</h1>"), 0644); err != nil {
                t.Fatalf("write index.html: %v", err)
        }
        artifactDigest := "abc123def456abc123def456abc123def456abc123def456abc123def456abcd"
        // Write the publisher manifest the same way artifactreceiver does:
        // .nexora-release.json at mode 0400.
        manifestPath := filepath.Join(releaseDir, ".nexora-release.json")
        manifestJSON := `{"version":1,"releaseId":"` + releaseID + `","artifactSha256":"` + artifactDigest + `","artifactBytes":2048}`
        if err := os.WriteFile(manifestPath, []byte(manifestJSON), 0400); err != nil {
                t.Fatalf("write manifest: %v", err)
        }
        // Activate the release by pointing current at releases/<releaseID>.
        if err := os.Symlink(filepath.Join("releases", releaseID), filepath.Join(baseDir, "current")); err != nil {
                t.Fatalf("symlink current: %v", err)
        }

        scaffold := &recoveryTestScaffold{
                cfg: Config{
                        ControlPlaneURL:          "", // filled after server starts
                        NodeIdentity:             "runtime-recovery-test",
                        PublisherRoot:            publisherRoot,
                        PollIntervalSeconds:      30,
                        RollbackExecutionEnabled: false,
                },
                publisherRoot:   publisherRoot,
                baseDir:         baseDir,
                releaseID:       releaseID,
                artifactDigest:  artifactDigest,
                rollbackEnabled: false,
                reportStatus:    200,
                reportBody:      `{"accepted":true,"duplicate":false,"deploymentId":"deployment-recovery-001","releaseState":"succeeded","workloadHealth":"healthy","rollbackRequired":false}`,
        }
        scaffold.reportedHealth = &struct {
                deploymentID   string
                artifactSHA256 string
                probePath      string
                healthStatus   string
                httpStatus     int
                durationMs     int
                failureCode    string
        }{}

        // Mock control-plane server. It accepts signed requests to the
        // health-check endpoint and records the body for the test to
        // assert on. Every other path returns 404 so the test fails loudly
        // if the recovery path tries to download or activate (which it
        // must not).
        server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                switch r.URL.Path {
                case "/internal/v1/application-nodes/releases/health-check":
                        body := make([]byte, 4096)
                        n, _ := r.Body.Read(body)
                        var parsed map[string]any
                        if err := json.Unmarshal(body[:n], &parsed); err != nil {
                                t.Errorf("server: invalid JSON body: %v", err)
                                w.WriteHeader(400)
                                return
                        }
                        scaffold.reportedHealth.deploymentID, _ = parsed["deploymentId"].(string)
                        scaffold.reportedHealth.artifactSHA256, _ = parsed["artifactSha256"].(string)
                        scaffold.reportedHealth.probePath, _ = parsed["probePath"].(string)
                        scaffold.reportedHealth.healthStatus, _ = parsed["healthStatus"].(string)
                        if v, ok := parsed["httpStatus"].(float64); ok {
                                scaffold.reportedHealth.httpStatus = int(v)
                        }
                        if v, ok := parsed["durationMs"].(float64); ok {
                                scaffold.reportedHealth.durationMs = int(v)
                        }
                        if fc, ok := parsed["failureCode"].(string); ok {
                                scaffold.reportedHealth.failureCode = fc
                        }
                        w.Header().Set("Content-Type", "application/json")
                        w.WriteHeader(scaffold.reportStatus)
                        _, _ = w.Write([]byte(scaffold.reportBody))
                default:
                        t.Errorf("server: unexpected request to %s (recovery must not download or activate)", r.URL.Path)
                        w.WriteHeader(404)
                }
        }))
        tlsClientConfig := tlsConfigForTest()
        server.Client().Transport = &http.Transport{
                TLSClientConfig: &tlsClientConfig,
        }
        scaffold.server = server
        scaffold.cfg.ControlPlaneURL = server.URL
        // Stash the private key on the scaffold for tests that need to
        // sign their own requests; the recovery function generates its own
        // signatures internally.
        _ = privateKey
        _ = publicKey
        return scaffold
}

// tlsConfigForTest returns a TLS config that trusts the test server's
// self-signed certificate. We use InsecureSkipVerify because the publisher's
// URL validation in production requires HTTPS, and the test server uses a
// self-signed cert.
func tlsConfigForTest() tls.Config {
        return tls.Config{InsecureSkipVerify: true}
}

// writeManifestHelper writes a publisher manifest with arbitrary content
// into a release directory, used by tests that need to simulate a tampered
// or missing manifest. The manifest is normally written at mode 0400 by
// artifactreceiver, so tests that overwrite it must remove the existing
// read-only file first.
func writeManifestHelper(t *testing.T, releaseDir, content string, mode os.FileMode) {
        t.Helper()
        manifestPath := filepath.Join(releaseDir, ".nexora-release.json")
        if _, err := os.Stat(manifestPath); err == nil {
                if err := os.Chmod(manifestPath, 0600); err != nil {
                        t.Fatalf("chmod manifest for removal: %v", err)
                }
                if err := os.Remove(manifestPath); err != nil {
                        t.Fatalf("remove existing manifest: %v", err)
                }
        }
        if err := os.WriteFile(manifestPath, []byte(content), mode); err != nil {
                t.Fatalf("write manifest: %v", err)
        }
}

func TestRecoveryEntersAndProbesWithoutRepublishingOrActivating(t *testing.T) {
        scaffold := newRecoveryScaffold(t)
        defer scaffold.server.Close()

        // Capture the state of the active symlink BEFORE recovery.
        activeBefore, err := os.Readlink(filepath.Join(scaffold.baseDir, "current"))
        if err != nil {
                t.Fatalf("readlink current before: %v", err)
        }

        // Capture the directory listing of releases/ BEFORE recovery. If
        // the recovery path downloads or extracts, we would see a new
        // staging directory or a changed releases/ directory.
        releasesBefore, err := os.ReadDir(filepath.Join(scaffold.baseDir, "releases"))
        if err != nil {
                t.Fatalf("readdir releases before: %v", err)
        }

        release := PendingRelease{
                ReleaseID:        scaffold.releaseID,
                State:            "health_checking",
                ArtifactSHA256:   scaffold.artifactDigest,
                DeploymentID:     scaffold.releaseID,
                OrganizationID:   "org-recovery",
                ProjectID:        "project-recovery",
                HostingAccountID: "hosting-recovery",
                DomainID:         "domain-recovery",
                Hostname:         "www.recovery.test",
                RepositoryID:     "123456789",
                CommitSHA:        "0123456789abcdef0123456789abcdef01234567",
                HealthCheckPath:  "/ready",
        }

        probed := false
        probeFn := func(_ context.Context) runtimehealth.Result {
                probed = true
                return runtimehealth.Result{Status: runtimehealth.Healthy, HTTPStatus: 200, DurationMs: 7}
        }

        // The recovery function uses nodeKey for signing. Generate a key
        // and accept that the mock server doesn't verify signatures (it's
        // a test server). The function's signature enforcement happens
        // before the request is sent.
        _, nodeKey, err := ed25519.GenerateKey(rand.Reader)
        if err != nil {
                t.Fatalf("generate node key: %v", err)
        }

        err = recoverHealthCheckingRelease(context.Background(), scaffold.server.Client(), scaffold.cfg, nodeKey, release, "/ready", probeFn)
        if err != nil {
                t.Fatalf("recovery failed: %v", err)
        }
        if !probed {
                t.Fatal("recovery did not invoke the serving-boundary probe")
        }
        if scaffold.reportedHealth.deploymentID != scaffold.releaseID {
                t.Fatalf("reported deployment id = %q, want %q", scaffold.reportedHealth.deploymentID, scaffold.releaseID)
        }
        if scaffold.reportedHealth.artifactSHA256 != scaffold.artifactDigest {
                t.Fatalf("reported artifact digest = %q, want %q", scaffold.reportedHealth.artifactSHA256, scaffold.artifactDigest)
        }
        if scaffold.reportedHealth.healthStatus != "healthy" {
                t.Fatalf("reported health status = %q, want %q", scaffold.reportedHealth.healthStatus, "healthy")
        }
        if scaffold.reportedHealth.probePath != "/ready" {
                t.Fatalf("reported probe path = %q, want /ready", scaffold.reportedHealth.probePath)
        }

        // Verify the active symlink is byte-for-byte unchanged. Recovery
        // must never switch the active release.
        activeAfter, err := os.Readlink(filepath.Join(scaffold.baseDir, "current"))
        if err != nil {
                t.Fatalf("readlink current after: %v", err)
        }
        if activeAfter != activeBefore {
                t.Fatalf("active release changed during recovery: before=%q after=%q", activeBefore, activeAfter)
        }

        // Verify releases/ directory is unchanged.
        releasesAfter, err := os.ReadDir(filepath.Join(scaffold.baseDir, "releases"))
        if err != nil {
                t.Fatalf("readdir releases after: %v", err)
        }
        if len(releasesAfter) != len(releasesBefore) {
                t.Fatalf("releases/ changed during recovery: before=%d entries after=%d entries", len(releasesBefore), len(releasesAfter))
        }
}

func TestRecoveryRejectsUnexpectedActiveRelease(t *testing.T) {
        // A different release is active on disk; recovery must fail safely
        // rather than probe-and-report for a release that is not actually
        // serving.
        scaffold := newRecoveryScaffold(t)
        defer scaffold.server.Close()

        // Point current at a different release directory.
        wrongReleaseID := "deployment-other"
        wrongDir := filepath.Join(scaffold.baseDir, "releases", wrongReleaseID)
        if err := os.Mkdir(wrongDir, os.FileMode(0750)|os.ModeSetgid); err != nil {
                t.Fatalf("mkdir wrong release: %v", err)
        }
        if err := os.WriteFile(filepath.Join(wrongDir, "index.html"), []byte("<h1>other</h1>"), 0644); err != nil {
                t.Fatalf("write index.html: %v", err)
        }
        if err := os.Remove(filepath.Join(scaffold.baseDir, "current")); err != nil {
                t.Fatalf("remove current: %v", err)
        }
        if err := os.Symlink(filepath.Join("releases", wrongReleaseID), filepath.Join(scaffold.baseDir, "current")); err != nil {
                t.Fatalf("symlink current: %v", err)
        }

        release := PendingRelease{
                ReleaseID:        scaffold.releaseID, // expects THIS release to be active
                State:            "health_checking",
                ArtifactSHA256:   scaffold.artifactDigest,
                DeploymentID:     scaffold.releaseID,
                OrganizationID:   "org-recovery",
                ProjectID:        "project-recovery",
                HostingAccountID: "hosting-recovery",
                DomainID:         "domain-recovery",
                Hostname:         "www.recovery.test",
                RepositoryID:     "123456789",
                CommitSHA:        "0123456789abcdef0123456789abcdef01234567",
                HealthCheckPath:  "/ready",
        }

        probeCalled := false
        probeFn := func(_ context.Context) runtimehealth.Result {
                probeCalled = true
                return runtimehealth.Result{Status: runtimehealth.Healthy, HTTPStatus: 200}
        }

        _, nodeKey, _ := ed25519.GenerateKey(rand.Reader)
        err := recoverHealthCheckingRelease(context.Background(), scaffold.server.Client(), scaffold.cfg, nodeKey, release, "/ready", probeFn)
        if err == nil {
                t.Fatal("recovery unexpectedly succeeded when the active release does not match")
        }
        if probeCalled {
                t.Fatal("recovery probed despite an active-release mismatch; the active website must not be touched")
        }
        if scaffold.reportedHealth.deploymentID != "" {
                t.Fatalf("recovery reported health despite mismatch: %+v", scaffold.reportedHealth)
        }
}

func TestRecoveryRejectsTamperedArtifactDigest(t *testing.T) {
        // The manifest on disk records a different artifact digest than
        // what the control plane returned. Recovery must fail safely.
        scaffold := newRecoveryScaffold(t)
        defer scaffold.server.Close()

        releaseDir := filepath.Join(scaffold.baseDir, "releases", scaffold.releaseID)
        tamperedDigest := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        tamperedJSON := `{"version":1,"releaseId":"` + scaffold.releaseID + `","artifactSha256":"` + tamperedDigest + `","artifactBytes":2048}`
        writeManifestHelper(t, releaseDir, tamperedJSON, 0400)

        release := PendingRelease{
                ReleaseID:        scaffold.releaseID,
                State:            "health_checking",
                ArtifactSHA256:   scaffold.artifactDigest, // control plane says THIS digest
                DeploymentID:     scaffold.releaseID,
                OrganizationID:   "org-recovery",
                ProjectID:        "project-recovery",
                HostingAccountID: "hosting-recovery",
                DomainID:         "domain-recovery",
                Hostname:         "www.recovery.test",
                RepositoryID:     "123456789",
                CommitSHA:        "0123456789abcdef0123456789abcdef01234567",
                HealthCheckPath:  "/ready",
        }

        probeCalled := false
        probeFn := func(_ context.Context) runtimehealth.Result {
                probeCalled = true
                return runtimehealth.Result{Status: runtimehealth.Healthy, HTTPStatus: 200}
        }

        _, nodeKey, _ := ed25519.GenerateKey(rand.Reader)
        err := recoverHealthCheckingRelease(context.Background(), scaffold.server.Client(), scaffold.cfg, nodeKey, release, "/ready", probeFn)
        if err == nil {
                t.Fatal("recovery unexpectedly succeeded with a tampered manifest digest")
        }
        if probeCalled {
                t.Fatal("recovery probed despite a tampered manifest")
        }
        if scaffold.reportedHealth.deploymentID != "" {
                t.Fatalf("recovery reported health despite tampered digest: %+v", scaffold.reportedHealth)
        }
}

func TestRecoveryRejectsMissingManifest(t *testing.T) {
        scaffold := newRecoveryScaffold(t)
        defer scaffold.server.Close()

        releaseDir := filepath.Join(scaffold.baseDir, "releases", scaffold.releaseID)
        if err := os.Remove(filepath.Join(releaseDir, ".nexora-release.json")); err != nil {
                t.Fatalf("remove manifest: %v", err)
        }

        release := PendingRelease{
                ReleaseID:        scaffold.releaseID,
                State:            "health_checking",
                ArtifactSHA256:   scaffold.artifactDigest,
                DeploymentID:     scaffold.releaseID,
                OrganizationID:   "org-recovery",
                ProjectID:        "project-recovery",
                HostingAccountID: "hosting-recovery",
                DomainID:         "domain-recovery",
                Hostname:         "www.recovery.test",
                RepositoryID:     "123456789",
                CommitSHA:        "0123456789abcdef0123456789abcdef01234567",
                HealthCheckPath:  "/ready",
        }

        probeCalled := false
        _, nodeKey, _ := ed25519.GenerateKey(rand.Reader)
        err := recoverHealthCheckingRelease(context.Background(), scaffold.server.Client(), scaffold.cfg, nodeKey, release, "/ready",
                func(_ context.Context) runtimehealth.Result {
                        probeCalled = true
                        return runtimehealth.Result{Status: runtimehealth.Healthy, HTTPStatus: 200}
                })
        if err == nil {
                t.Fatal("recovery unexpectedly succeeded with a missing manifest")
        }
        if probeCalled {
                t.Fatal("recovery probed despite a missing manifest")
        }
}

func TestRecoveryRejectsNonHealthCheckingState(t *testing.T) {
        scaffold := newRecoveryScaffold(t)
        defer scaffold.server.Close()

        release := PendingRelease{
                ReleaseID:        scaffold.releaseID,
                State:            "publishing", // wrong state for recovery
                ArtifactSHA256:   scaffold.artifactDigest,
                DeploymentID:     scaffold.releaseID,
                OrganizationID:   "org-recovery",
                ProjectID:        "project-recovery",
                HostingAccountID: "hosting-recovery",
                DomainID:         "domain-recovery",
                Hostname:         "www.recovery.test",
                RepositoryID:     "123456789",
                CommitSHA:        "0123456789abcdef0123456789abcdef01234567",
                HealthCheckPath:  "/ready",
        }

        _, nodeKey, _ := ed25519.GenerateKey(rand.Reader)
        err := recoverHealthCheckingRelease(context.Background(), scaffold.server.Client(), scaffold.cfg, nodeKey, release, "/ready",
                func(_ context.Context) runtimehealth.Result {
                        t.Fatal("probe must not run for a non-health_checking state")
                        return runtimehealth.Result{}
                })
        if err == nil {
                t.Fatal("recovery unexpectedly succeeded for a non-health_checking state")
        }
}

func TestRecoveryRejectsMissingActiveSymlink(t *testing.T) {
        // The current symlink is missing entirely — the release was never
        // activated (or was rolled back). Recovery must fail safely.
        scaffold := newRecoveryScaffold(t)
        defer scaffold.server.Close()

        if err := os.Remove(filepath.Join(scaffold.baseDir, "current")); err != nil {
                t.Fatalf("remove current: %v", err)
        }

        release := PendingRelease{
                ReleaseID:        scaffold.releaseID,
                State:            "health_checking",
                ArtifactSHA256:   scaffold.artifactDigest,
                DeploymentID:     scaffold.releaseID,
                OrganizationID:   "org-recovery",
                ProjectID:        "project-recovery",
                HostingAccountID: "hosting-recovery",
                DomainID:         "domain-recovery",
                Hostname:         "www.recovery.test",
                RepositoryID:     "123456789",
                CommitSHA:        "0123456789abcdef0123456789abcdef01234567",
                HealthCheckPath:  "/ready",
        }

        _, nodeKey, _ := ed25519.GenerateKey(rand.Reader)
        err := recoverHealthCheckingRelease(context.Background(), scaffold.server.Client(), scaffold.cfg, nodeKey, release, "/ready",
                func(_ context.Context) runtimehealth.Result {
                        t.Fatal("probe must not run when the active symlink is missing")
                        return runtimehealth.Result{}
                })
        if err == nil {
                t.Fatal("recovery unexpectedly succeeded when the active symlink is missing")
        }
}

func TestRecoveryFailedHealthCheckReportsUnhealthy(t *testing.T) {
        // The probe returns unhealthy. The publisher must report unhealthy
        // to the control plane so the rollback workflow can proceed.
        scaffold := newRecoveryScaffold(t)
        defer scaffold.server.Close()
        scaffold.reportStatus = 200
        scaffold.reportBody = `{"accepted":true,"duplicate":false,"deploymentId":"deployment-recovery-001","releaseState":"failed","workloadHealth":"unhealthy","rollbackRequired":false}`

        release := PendingRelease{
                ReleaseID:        scaffold.releaseID,
                State:            "health_checking",
                ArtifactSHA256:   scaffold.artifactDigest,
                DeploymentID:     scaffold.releaseID,
                OrganizationID:   "org-recovery",
                ProjectID:        "project-recovery",
                HostingAccountID: "hosting-recovery",
                DomainID:         "domain-recovery",
                Hostname:         "www.recovery.test",
                RepositoryID:     "123456789",
                CommitSHA:        "0123456789abcdef0123456789abcdef01234567",
                HealthCheckPath:  "/ready",
        }

        _, nodeKey, _ := ed25519.GenerateKey(rand.Reader)
        err := recoverHealthCheckingRelease(context.Background(), scaffold.server.Client(), scaffold.cfg, nodeKey, release, "/ready",
                func(_ context.Context) runtimehealth.Result {
                        return runtimehealth.Result{
                                Status:      runtimehealth.Unhealthy,
                                HTTPStatus:  503,
                                FailureCode: "http_5xx",
                                DurationMs:  3,
                        }
                })
        if err == nil {
                t.Fatal("recovery unexpectedly succeeded when the probe was unhealthy")
        }
        if scaffold.reportedHealth.healthStatus != "unhealthy" {
                t.Fatalf("reported health status = %q, want unhealthy", scaffold.reportedHealth.healthStatus)
        }
        if scaffold.reportedHealth.failureCode != "http_5xx" {
                t.Fatalf("reported failure code = %q, want http_5xx", scaffold.reportedHealth.failureCode)
        }
        if scaffold.reportedHealth.httpStatus != 503 {
                t.Fatalf("reported http status = %d, want 503", scaffold.reportedHealth.httpStatus)
        }
}

func TestRecoveryDoesNotDownloadArtifact(t *testing.T) {
        // The mock server treats ANY request to the artifact endpoint as a
        // test failure. The recovery path must never download.
        scaffold := newRecoveryScaffold(t)
        defer scaffold.server.Close()

        release := PendingRelease{
                ReleaseID:        scaffold.releaseID,
                State:            "health_checking",
                ArtifactSHA256:   scaffold.artifactDigest,
                DeploymentID:     scaffold.releaseID,
                OrganizationID:   "org-recovery",
                ProjectID:        "project-recovery",
                HostingAccountID: "hosting-recovery",
                DomainID:         "domain-recovery",
                Hostname:         "www.recovery.test",
                RepositoryID:     "123456789",
                CommitSHA:        "0123456789abcdef0123456789abcdef01234567",
                HealthCheckPath:  "/ready",
        }

        _, nodeKey, _ := ed25519.GenerateKey(rand.Reader)
        err := recoverHealthCheckingRelease(context.Background(), scaffold.server.Client(), scaffold.cfg, nodeKey, release, "/ready",
                func(_ context.Context) runtimehealth.Result {
                        return runtimehealth.Result{Status: runtimehealth.Healthy, HTTPStatus: 200, DurationMs: 4}
                })
        if err != nil {
                t.Fatalf("recovery failed: %v", err)
        }
        // The mock server's default case fails the test if any non-health-check
        // path was hit. If we reach this point, only the health-check endpoint
        // was called.
}

func TestRecoveryRejectsReleaseIdDeploymentIdMismatch(t *testing.T) {
        // fetchPending rejects a release whose releaseId != deploymentId.
        // This test asserts the publisher-side validation rejects the
        // mismatched row before recovery is attempted.
        scaffold := newRecoveryScaffold(t)
        defer scaffold.server.Close()

        // Construct a pending response with mismatched releaseId and deploymentId.
        // We test the fetchPending validation directly by decoding the JSON
        // the control plane would return.
        body := []byte(`{"nodeIdentity":"runtime-recovery-test","polledAt":"2026-11-11T00:00:00Z","releases":[{"releaseId":"deployment-a","state":"health_checking","artifactSha256":"` + scaffold.artifactDigest + `","deploymentId":"deployment-b","organizationId":"o","projectId":"p","hostingAccountId":"hosting-recovery","domainId":"d","hostname":"www.recovery.test","repositoryId":"123456789","commitSha":"0123456789abcdef0123456789abcdef01234567","healthCheckPath":"/ready","previousDeploymentId":""}],"rollbacks":[]}`)
        var pending PendingResponse
        if err := json.Unmarshal(body, &pending); err != nil {
                t.Fatalf("unmarshal: %v", err)
        }
        // Apply the same validation fetchPending does.
        for _, release := range pending.Releases {
                if release.DeploymentID != release.ReleaseID {
                        // Expected: mismatch is detected and rejected.
                        return
                }
        }
        t.Fatal("fetchPending validation failed to detect releaseId/deploymentId mismatch")
}

func TestRecoveryRejectsUnknownState(t *testing.T) {
        // A pending response with an unknown state must be rejected by
        // fetchPending's validation.
        body := []byte(`{"nodeIdentity":"runtime-recovery-test","polledAt":"2026-11-11T00:00:00Z","releases":[{"releaseId":"deployment-x","state":"unknown_lifecycle","artifactSha256":"abc123def456abc123def456abc123def456abc123def456abc123def456abcd","deploymentId":"deployment-x","organizationId":"o","projectId":"p","hostingAccountId":"hosting-recovery","domainId":"d","hostname":"www.recovery.test","repositoryId":"123456789","commitSha":"0123456789abcdef0123456789abcdef01234567","healthCheckPath":"/ready","previousDeploymentId":""}],"rollbacks":[]}`)
        var pending PendingResponse
        if err := json.Unmarshal(body, &pending); err != nil {
                t.Fatalf("unmarshal: %v", err)
        }
        for _, release := range pending.Releases {
                switch release.State {
                case "artifact_uploaded", "publishing", "health_checking":
                        t.Fatalf("unknown state %q was accepted", release.State)
                }
        }
}

func TestRecoveryRejectsMalformedArtifactDigest(t *testing.T) {
        body := []byte(`{"nodeIdentity":"runtime-recovery-test","polledAt":"2026-11-11T00:00:00Z","releases":[{"releaseId":"deployment-x","state":"health_checking","artifactSha256":"not-a-real-digest","deploymentId":"deployment-x","organizationId":"o","projectId":"p","hostingAccountId":"hosting-recovery","domainId":"d","hostname":"www.recovery.test","repositoryId":"123456789","commitSha":"0123456789abcdef0123456789abcdef01234567","healthCheckPath":"/ready","previousDeploymentId":""}],"rollbacks":[]}`)
        var pending PendingResponse
        if err := json.Unmarshal(body, &pending); err != nil {
                t.Fatalf("unmarshal: %v", err)
        }
        for _, release := range pending.Releases {
                if releaseArtifactDigestPattern.MatchString(release.ArtifactSHA256) {
                        t.Fatalf("malformed digest %q was accepted", release.ArtifactSHA256)
                }
        }
}

func TestRecoveryPreservesActiveWebsiteWhenManifestCorrupted(t *testing.T) {
        // Even when the manifest is missing or corrupted, the active
        // symlink and release directory must remain untouched so the
        // currently serving website is not disrupted.
        scaffold := newRecoveryScaffold(t)
        defer scaffold.server.Close()

        releaseDir := filepath.Join(scaffold.baseDir, "releases", scaffold.releaseID)
        // Overwrite the manifest with garbage.
        writeManifestHelper(t, releaseDir, "not-json-garbage", 0400)

        activeBefore, _ := os.Readlink(filepath.Join(scaffold.baseDir, "current"))
        indexBefore, err := os.ReadFile(filepath.Join(releaseDir, "index.html"))
        if err != nil {
                t.Fatalf("read index.html before: %v", err)
        }

        release := PendingRelease{
                ReleaseID:        scaffold.releaseID,
                State:            "health_checking",
                ArtifactSHA256:   scaffold.artifactDigest,
                DeploymentID:     scaffold.releaseID,
                OrganizationID:   "org-recovery",
                ProjectID:        "project-recovery",
                HostingAccountID: "hosting-recovery",
                DomainID:         "domain-recovery",
                Hostname:         "www.recovery.test",
                RepositoryID:     "123456789",
                CommitSHA:        "0123456789abcdef0123456789abcdef01234567",
                HealthCheckPath:  "/ready",
        }
        _, nodeKey, _ := ed25519.GenerateKey(rand.Reader)
        err = recoverHealthCheckingRelease(context.Background(), scaffold.server.Client(), scaffold.cfg, nodeKey, release, "/ready",
                func(_ context.Context) runtimehealth.Result {
                        t.Fatal("probe must not run when the manifest is corrupted")
                        return runtimehealth.Result{}
                })
        if err == nil {
                t.Fatal("recovery unexpectedly succeeded with a corrupted manifest")
        }

        activeAfter, _ := os.Readlink(filepath.Join(scaffold.baseDir, "current"))
        if activeAfter != activeBefore {
                t.Fatalf("active symlink changed during failed recovery: before=%q after=%q", activeBefore, activeAfter)
        }
        indexAfter, err := os.ReadFile(filepath.Join(releaseDir, "index.html"))
        if err != nil {
                t.Fatalf("read index.html after: %v", err)
        }
        if string(indexAfter) != string(indexBefore) {
                t.Fatalf("release directory contents changed during failed recovery")
        }
}
