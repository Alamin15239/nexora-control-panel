package rollbackexecutor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/rollbackoutbox"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/runtimehealth"
)

type fixedProbe struct {
	result runtimehealth.Result
	calls int
}
func (p *fixedProbe) Probe(context.Context, rollbackoutbox.Operation) runtimehealth.Result {
	p.calls++
	return p.result
}

type fixedReporter struct {
	err error
	calls int
}
func (r *fixedReporter) Report(context.Context, rollbackoutbox.Operation, runtimehealth.Result) error {
	r.calls++
	return r.err
}

func setup(t *testing.T) (*rollbackoutbox.Store, string, rollbackoutbox.Operation) {
	t.Helper()
	outboxDir := filepath.Join(t.TempDir(), "outbox")
	if err := os.Mkdir(outboxDir, 0700); err != nil { t.Fatal(err) }
	store, err := rollbackoutbox.Open(filepath.Join(outboxDir, "rollback.json"))
	if err != nil { t.Fatal(err) }
	base := t.TempDir()
	for _, dir := range []string{"staging", "releases"} {
		if err := os.Mkdir(filepath.Join(base, dir), 0700); err != nil { t.Fatal(err) }
	}
	for _, release := range []string{"release-old", "release-failed"} {
		if err := os.Mkdir(filepath.Join(base, "releases", release), 0700); err != nil { t.Fatal(err) }
	}
	if err := os.Symlink(filepath.Join("releases", "release-failed"), filepath.Join(base, "current")); err != nil { t.Fatal(err) }
	intent := rollbackoutbox.Operation{
		ID: "rollback-op-001", FailedDeploymentID: "deploy-failed-001",
		FailedReleaseID: "release-failed", TargetDeploymentID: "deploy-old-001",
		TargetReleaseID: "release-old", ProjectID: "project-001",
		OrganizationID: "org-001", NodeID: "node-001",
		ExpectedActiveReleaseID: "release-failed",
		ArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	return store, base, intent
}

func healthyProbe() runtimehealth.Result {
	return runtimehealth.Result{Status: runtimehealth.Healthy, HTTPStatus: 200, DurationMs: 12}
}

func TestExecutePersistsSwitchesVerifiesAndReports(t *testing.T) {
	store, base, intent := setup(t)
	probe := &fixedProbe{result: healthyProbe()}
	reporter := &fixedReporter{}
	executor := Executor{Enabled: true, Store: store, Publisher: RealPublisher{}, Prober: probe, Reporter: reporter}

	op, err := executor.Execute(context.Background(), base, intent)
	if err != nil { t.Fatal(err) }
	if op.State != "reported" { t.Fatalf("state = %q, want reported", op.State) }
	target, err := os.Readlink(filepath.Join(base, "current"))
	if err != nil { t.Fatal(err) }
	if target != filepath.Join("releases", "release-old") { t.Fatalf("active release = %q", target) }
	if probe.calls != 2 { t.Fatalf("probe calls = %d, want initial verification and pre-report recheck", probe.calls) }
	if reporter.calls != 1 { t.Fatalf("report calls = %d, want 1", reporter.calls) }

	// An identical retry is terminal and must not switch or report again.
	op, err = executor.Execute(context.Background(), base, intent)
	if err != nil { t.Fatal(err) }
	if op.State != "reported" || reporter.calls != 1 { t.Fatal("reported retry was not idempotent") }
}

func TestExecuteIsInertWhenDisabled(t *testing.T) {
	store, base, intent := setup(t)
	executor := Executor{Store: store, Publisher: RealPublisher{}}
	if _, err := executor.Execute(context.Background(), base, intent); err == nil {
		t.Fatal("disabled executor accepted execution")
	}
	target, err := os.Readlink(filepath.Join(base, "current"))
	if err != nil { t.Fatal(err) }
	if target != filepath.Join("releases", "release-failed") { t.Fatal("disabled executor changed active release") }
	ops, err := store.List()
	if err != nil { t.Fatal(err) }
	if len(ops) != 0 { t.Fatal("disabled executor persisted an operation") }
}

func TestExecuteBlocksUnhealthyRestoredWorkload(t *testing.T) {
	store, base, intent := setup(t)
	probe := &fixedProbe{result: runtimehealth.Result{Status: runtimehealth.Unhealthy, HTTPStatus: 503, FailureCode: "http_5xx"}}
	reporter := &fixedReporter{}
	executor := Executor{Enabled: true, Store: store, Publisher: RealPublisher{}, Prober: probe, Reporter: reporter}
	op, err := executor.Execute(context.Background(), base, intent)
	if err == nil { t.Fatal("unhealthy restored workload was accepted") }
	if op.State != "blocked" || reporter.calls != 0 { t.Fatalf("state=%q reports=%d", op.State, reporter.calls) }
	target, readErr := os.Readlink(filepath.Join(base, "current"))
	if readErr != nil { t.Fatal(readErr) }
	if target != filepath.Join("releases", "release-old") { t.Fatal("health failure unexpectedly switched back to failed release") }
}

func TestExecuteLeavesVerifiedOperationRetryableWhenReporterFails(t *testing.T) {
	store, base, intent := setup(t)
	probe := &fixedProbe{result: healthyProbe()}
	reporter := &fixedReporter{err: errors.New("control plane unavailable")}
	executor := Executor{Enabled: true, Store: store, Publisher: RealPublisher{}, Prober: probe, Reporter: reporter}
	op, err := executor.Execute(context.Background(), base, intent)
	if err == nil { t.Fatal("reporter failure was hidden") }
	if op.State != "verified" { t.Fatalf("state = %q, want verified", op.State) }

	reporter.err = nil
	op, err = executor.Execute(context.Background(), base, intent)
	if err != nil { t.Fatal(err) }
	if op.State != "reported" || reporter.calls != 2 { t.Fatalf("state=%q reports=%d", op.State, reporter.calls) }
}

func TestExecuteRefusesStaleRollbackAndPersistsBlockedState(t *testing.T) {
	store, base, intent := setup(t)
	if err := os.Remove(filepath.Join(base, "current")); err != nil { t.Fatal(err) }
	if err := os.Symlink(filepath.Join("releases", "release-newer"), filepath.Join(base, "current")); err != nil { t.Fatal(err) }
	if err := os.Mkdir(filepath.Join(base, "releases", "release-newer"), 0700); err != nil { t.Fatal(err) }
	executor := Executor{Enabled: true, Store: store, Publisher: RealPublisher{}, Prober: &fixedProbe{result: healthyProbe()}, Reporter: &fixedReporter{}}
	op, err := executor.Execute(context.Background(), base, intent)
	if err == nil { t.Fatal("stale rollback was accepted") }
	if op.State != "blocked" { t.Fatalf("state = %q, want blocked", op.State) }
	target, readErr := os.Readlink(filepath.Join(base, "current"))
	if readErr != nil { t.Fatal(readErr) }
	if target != filepath.Join("releases", "release-newer") { t.Fatal("stale rollback overwrote newer release") }
}
