package ocisupervisor

import (
	"context"
	"errors"
	"testing"
)

type fakeLifecycle struct {
	workload Workload
	startID string
	startErr error
	restartErr error
	stopErr error
	startCalls int
	restartCalls int
	stopCalls int
	inspectCalls int
}

func (f *fakeLifecycle) Start(_ context.Context, _ Spec) (string, error) {
	f.startCalls++
	return f.startID, f.startErr
}
func (f *fakeLifecycle) Inspect(_ context.Context, _ string) (Workload, error) {
	f.inspectCalls++
	return f.workload, nil
}
func (f *fakeLifecycle) Restart(_ context.Context, _ string) error {
	f.restartCalls++
	return f.restartErr
}
func (f *fakeLifecycle) StopManaged(_ context.Context, _ string) error {
	f.stopCalls++
	return f.stopErr
}

func desiredForTest(running bool, containerID string) DesiredState {
	return DesiredState{
		WorkloadID: "workload-123",
		ReleaseID: "release-123",
		Running: running,
		ContainerID: containerID,
		Spec: Spec{WorkloadID:"workload-123", ReleaseID:"release-123"},
	}
}

func TestReconcileStartsMissingDesiredWorkload(t *testing.T) {
	backend := &fakeLifecycle{startID:"abcdef0123456789"}
	result, err := ReconcileOne(context.Background(), backend, desiredForTest(true, ""))
	if err != nil { t.Fatal(err) }
	if result.Action != "started" || result.ContainerID != backend.startID || backend.startCalls != 1 {
		t.Fatalf("unexpected reconcile result: %+v backend=%+v", result, backend)
	}
}

func TestReconcileDoesNotStartWhenStoppedAndMissing(t *testing.T) {
	backend := &fakeLifecycle{}
	result, err := ReconcileOne(context.Background(), backend, desiredForTest(false, ""))
	if err != nil { t.Fatal(err) }
	if result.Action != "already_stopped" || backend.startCalls != 0 {
		t.Fatalf("unexpected reconcile result: %+v", result)
	}
}

func TestReconcileRunningWorkloadIsNoop(t *testing.T) {
	id := "abcdef0123456789"
	backend := &fakeLifecycle{workload:Workload{ContainerID:id,WorkloadID:"workload-123",ReleaseID:"release-123",State:StateRunning}}
	result, err := ReconcileOne(context.Background(), backend, desiredForTest(true,id))
	if err != nil { t.Fatal(err) }
	if result.Action != "no_op" || backend.restartCalls != 0 { t.Fatalf("unexpected result: %+v", result) }
}

func TestReconcileRestartsExitedWorkload(t *testing.T) {
	id := "abcdef0123456789"
	backend := &fakeLifecycle{workload:Workload{ContainerID:id,WorkloadID:"workload-123",ReleaseID:"release-123",State:StateExited}}
	result, err := ReconcileOne(context.Background(), backend, desiredForTest(true,id))
	if err != nil { t.Fatal(err) }
	if result.Action != "restarted" || backend.restartCalls != 1 { t.Fatalf("unexpected result: %+v", result) }
}

func TestReconcileStopsUndesiredWorkload(t *testing.T) {
	id := "abcdef0123456789"
	backend := &fakeLifecycle{workload:Workload{ContainerID:id,WorkloadID:"workload-123",ReleaseID:"release-123",State:StateRunning}}
	result, err := ReconcileOne(context.Background(), backend, desiredForTest(false,id))
	if err != nil { t.Fatal(err) }
	if result.Action != "stopped" || backend.stopCalls != 1 { t.Fatalf("unexpected result: %+v", result) }
}

func TestReconcileRejectsReleaseOrOwnershipMismatch(t *testing.T) {
	id := "abcdef0123456789"
	tests := []struct{name string; observed Workload}{
		{"workload mismatch",Workload{ContainerID:id,WorkloadID:"other-workload",ReleaseID:"release-123",State:StateRunning}},
		{"release mismatch",Workload{ContainerID:id,WorkloadID:"workload-123",ReleaseID:"other-release",State:StateRunning}},
		{"container mismatch",Workload{ContainerID:"1234567890ab",WorkloadID:"workload-123",ReleaseID:"release-123",State:StateRunning}},
	}
	for _, tc := range tests {
		t.Run(tc.name,func(t *testing.T){
			backend:=&fakeLifecycle{workload:tc.observed}
			if _,err:=ReconcileOne(context.Background(),backend,desiredForTest(true,id));err==nil{
				t.Fatal("expected identity mismatch rejection")
			}
			if backend.restartCalls!=0 || backend.stopCalls!=0 {t.Fatal("mismatched workload was mutated")}
		})
	}
}

func TestReconcileRejectsInvalidBackendContainerID(t *testing.T) {
	backend:=&fakeLifecycle{startID:"not-a-container-id"}
	if _,err:=ReconcileOne(context.Background(),backend,desiredForTest(true,""));err==nil{
		t.Fatal("expected invalid backend identifier rejection")
	}
}

func TestReconcilePropagatesLifecycleErrors(t *testing.T) {
	id:="abcdef0123456789"
	backend:=&fakeLifecycle{workload:Workload{ContainerID:id,WorkloadID:"workload-123",ReleaseID:"release-123",State:StateExited},restartErr:errors.New("engine error")}
	if _,err:=ReconcileOne(context.Background(),backend,desiredForTest(true,id));err==nil{
		t.Fatal("expected restart failure")
	}
}
