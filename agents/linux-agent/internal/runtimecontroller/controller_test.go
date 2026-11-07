package runtimecontroller

import (
	"context"
	"errors"
	"testing"

	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/ocisupervisor"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/supervisorstate"
)

type fakeBackend struct {
	workload ocisupervisor.Workload
	startID string
	startCalls int
	inspectErr error
}
func (f *fakeBackend) Start(_ context.Context, _ ocisupervisor.Spec) (string, error) {
	f.startCalls++
	return f.startID, nil
}
func (f *fakeBackend) Inspect(_ context.Context, _ string) (ocisupervisor.Workload, error) {
	return f.workload, f.inspectErr
}
func (f *fakeBackend) Restart(context.Context, string) error { return nil }
func (f *fakeBackend) StopManaged(context.Context, string) error { return nil }

type fakeStore struct {
	items map[string]supervisorstate.WorkloadState
	upsertErr error
	deleteErr error
}
func (f *fakeStore) Upsert(item supervisorstate.WorkloadState) error {
	if f.upsertErr != nil { return f.upsertErr }
	if f.items == nil { f.items = make(map[string]supervisorstate.WorkloadState) }
	f.items[item.WorkloadID] = item
	return nil
}
func (f *fakeStore) Load() ([]supervisorstate.WorkloadState, error) {
	out := make([]supervisorstate.WorkloadState, 0, len(f.items))
	for _, item := range f.items { out = append(out, item) }
	return out, nil
}
func (f *fakeStore) Delete(id string) error {
	if f.deleteErr != nil { return f.deleteErr }
	delete(f.items, id)
	return nil
}
func desired(running bool, containerID string) ocisupervisor.DesiredState {
	return ocisupervisor.DesiredState{
		WorkloadID: "workload-001", ReleaseID: "release-001", Running: running, ContainerID: containerID,
		Spec: ocisupervisor.Spec{WorkloadID: "workload-001", ReleaseID: "release-001"},
	}
}

func TestConvergePersistsBackendObservedState(t *testing.T) {
	backend := &fakeBackend{
		startID: "0123456789abcdef0123456789abcdef",
		workload: ocisupervisor.Workload{
			ContainerID: "0123456789abcdef0123456789abcdef",
			WorkloadID: "workload-001", ReleaseID: "release-001", State: ocisupervisor.StateRunning,
		},
	}
	store := &fakeStore{}
	result, err := (Controller{Backend: backend, State: store}).Converge(context.Background(), desired(true, ""))
	if err != nil { t.Fatal(err) }
	if result.Action != "started" || result.ObservedState != ocisupervisor.StateRunning {
		t.Fatalf("unexpected reconcile result: %+v", result)
	}
	if got := store.items["workload-001"]; got.ContainerID != backend.startID || got.State != "running" {
		t.Fatalf("unexpected durable state: %+v", got)
	}
}

func TestConvergeDeletesStateWhenWorkloadShouldNotExist(t *testing.T) {
	store := &fakeStore{items: map[string]supervisorstate.WorkloadState{
		"workload-001": {WorkloadID: "workload-001", ReleaseID: "release-001", ContainerID: "0123456789abcdef", State: "stopped"},
	}}
	result, err := (Controller{Backend: &fakeBackend{}, State: store}).Converge(context.Background(), desired(false, ""))
	if err != nil { t.Fatal(err) }
	if result.Action != "already_stopped" { t.Fatalf("unexpected result: %+v", result) }
	if _, exists := store.items["workload-001"]; exists { t.Fatal("stale durable state was not deleted") }
}

func TestConvergeDoesNotPersistUnverifiedBackendState(t *testing.T) {
	backend := &fakeBackend{
		startID: "0123456789abcdef0123456789abcdef",
		inspectErr: errors.New("inspect unavailable"),
	}
	store := &fakeStore{}
	_, err := (Controller{Backend: backend, State: store}).Converge(context.Background(), desired(true, ""))
	if err == nil { t.Fatal("inspection failure was ignored") }
	if len(store.items) != 0 { t.Fatal("unverified state was persisted") }
}

func TestConvergeRejectsObservedIdentityMismatch(t *testing.T) {
	backend := &fakeBackend{
		startID: "0123456789abcdef0123456789abcdef",
		workload: ocisupervisor.Workload{
			ContainerID: "0123456789abcdef0123456789abcdef",
			WorkloadID: "another-workload", ReleaseID: "release-001", State: ocisupervisor.StateRunning,
		},
	}
	store := &fakeStore{}
	_, err := (Controller{Backend: backend, State: store}).Converge(context.Background(), desired(true, ""))
	if err == nil { t.Fatal("mismatched workload identity was accepted") }
	if len(store.items) != 0 { t.Fatal("mismatched state was persisted") }
}

func TestConvergeReportsPersistenceFailure(t *testing.T) {
	backend := &fakeBackend{
		startID: "0123456789abcdef0123456789abcdef",
		workload: ocisupervisor.Workload{
			ContainerID: "0123456789abcdef0123456789abcdef",
			WorkloadID: "workload-001", ReleaseID: "release-001", State: ocisupervisor.StateRunning,
		},
	}
	store := &fakeStore{upsertErr: errors.New("disk full")}
	_, err := (Controller{Backend: backend, State: store}).Converge(context.Background(), desired(true, ""))
	if err == nil { t.Fatal("persistence failure was ignored") }
}

func TestRecoverVerifiesAndRefreshesPersistedState(t *testing.T) {
	id := "0123456789abcdef0123456789abcdef"
	store := &fakeStore{items: map[string]supervisorstate.WorkloadState{
		"workload-001": {WorkloadID: "workload-001", ReleaseID: "release-001", ContainerID: id, State: "exited"},
	}}
	backend := &fakeBackend{workload: ocisupervisor.Workload{
		ContainerID: id, WorkloadID: "workload-001", ReleaseID: "release-001", State: ocisupervisor.StateRunning,
	}}
	report, err := (Controller{Backend: backend, State: store}).Recover(context.Background())
	if err != nil { t.Fatal(err) }
	if report.Checked != 1 || report.Reconciled != 1 || len(report.Workloads) != 1 {
		t.Fatalf("unexpected recovery report: %+v", report)
	}
	if store.items["workload-001"].State != "running" { t.Fatal("recovered observed state was not persisted") }
}

func TestRecoverFailsClosedOnOwnershipMismatch(t *testing.T) {
	id := "0123456789abcdef0123456789abcdef"
	store := &fakeStore{items: map[string]supervisorstate.WorkloadState{
		"workload-001": {WorkloadID: "workload-001", ReleaseID: "release-001", ContainerID: id, State: "running"},
	}}
	backend := &fakeBackend{workload: ocisupervisor.Workload{
		ContainerID: id, WorkloadID: "other-workload", ReleaseID: "release-001", State: ocisupervisor.StateRunning,
	}}
	if _, err := (Controller{Backend: backend, State: store}).Recover(context.Background()); err == nil {
		t.Fatal("recovery accepted a container with mismatched ownership")
	}
}

func TestRecoverFailsClosedWhenContainerCannotBeInspected(t *testing.T) {
	id := "0123456789abcdef0123456789abcdef"
	store := &fakeStore{items: map[string]supervisorstate.WorkloadState{
		"workload-001": {WorkloadID: "workload-001", ReleaseID: "release-001", ContainerID: id, State: "running"},
	}}
	backend := &fakeBackend{inspectErr: errors.New("container not found")}
	if _, err := (Controller{Backend: backend, State: store}).Recover(context.Background()); err == nil {
		t.Fatal("recovery accepted an uninspectable persisted container")
	}
}
