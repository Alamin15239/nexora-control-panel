package ocisupervisor

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type inspectRunner struct {
	calls [][]string
	output []byte
	err error
}

func (r *inspectRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string(nil), args...))
	if r.err != nil {
		return nil, r.err
	}
	if len(args) > 0 && args[0] == "inspect" {
		return r.output, nil
	}
	return []byte("ok"), nil
}

func inspectionJSON(id, managed, workload, release, state string) []byte {
	return []byte(`[{"Id":"` + id + `","State":{"Status":"` + state + `"},"Config":{"Labels":{"io.nexora.managed":"` + managed + `","io.nexora.workload":"` + workload + `","io.nexora.release":"` + release + `"}}}]`)
}

func TestInspectRequiresNexoraOwnershipLabels(t *testing.T) {
	id := strings.Repeat("a", 32)
	runner := &inspectRunner{output: inspectionJSON(id, "true", "workload-123", "release-123", "running")}
	workload, err := (Podman{Runner: runner}).Inspect(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if workload.ContainerID != id || workload.WorkloadID != "workload-123" ||
		workload.ReleaseID != "release-123" || workload.State != StateRunning {
		t.Fatalf("unexpected workload inspection: %+v", workload)
	}
	if len(runner.calls) != 1 || strings.Join(runner.calls[0], " ") != "inspect --type container --format json "+id {
		t.Fatalf("unexpected Podman inspect invocation: %+v", runner.calls)
	}
}

func TestInspectRejectsUnmanagedOrMalformedContainers(t *testing.T) {
	id := strings.Repeat("b", 32)
	tests := map[string][]byte{
		"unmanaged": inspectionJSON(id, "false", "workload-123", "release-123", "running"),
		"invalid workload label": inspectionJSON(id, "true", "../escape", "release-123", "running"),
		"unknown state": inspectionJSON(id, "true", "workload-123", "release-123", "mystery"),
		"wrong container id": inspectionJSON(strings.Repeat("c", 32), "true", "workload-123", "release-123", "running"),
		"invalid json": []byte("{"),
	}
	for name, output := range tests {
		t.Run(name, func(t *testing.T) {
			runner := &inspectRunner{output: output}
			if _, err := (Podman{Runner: runner}).Inspect(context.Background(), id); err == nil {
				t.Fatal("expected invalid or unmanaged container to be rejected")
			}
			if len(runner.calls) != 1 {
				t.Fatalf("expected inspect only, got %+v", runner.calls)
			}
		})
	}
}

func TestRestartVerifiesOwnershipBeforeRestart(t *testing.T) {
	id := strings.Repeat("d", 32)
	runner := &inspectRunner{output: inspectionJSON(id, "true", "workload-123", "release-123", "running")}
	if err := (Podman{Runner: runner}).Restart(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 || runner.calls[1][0] != "restart" {
		t.Fatalf("expected inspect followed by restart: %+v", runner.calls)
	}
}

func TestRestartRejectsDeadWorkload(t *testing.T) {
	id := strings.Repeat("e", 32)
	runner := &inspectRunner{output: inspectionJSON(id, "true", "workload-123", "release-123", "dead")}
	if err := (Podman{Runner: runner}).Restart(context.Background(), id); err == nil {
		t.Fatal("expected dead workload restart to be rejected")
	}
	if len(runner.calls) != 1 {
		t.Fatalf("restart invoked for dead workload: %+v", runner.calls)
	}
}

func TestManagedRemovalRequiresStoppedContainer(t *testing.T) {
	id := strings.Repeat("f", 32)
	runner := &inspectRunner{output: inspectionJSON(id, "true", "workload-123", "release-123", "running")}
	if err := (Podman{Runner: runner}).RemoveManaged(context.Background(), id); err == nil {
		t.Fatal("expected running workload removal to be rejected")
	}
	if len(runner.calls) != 1 {
		t.Fatalf("remove invoked for running workload: %+v", runner.calls)
	}
}

func TestInspectPropagatesPodmanFailure(t *testing.T) {
	id := strings.Repeat("1", 32)
	runner := &inspectRunner{err: errors.New("engine unavailable")}
	if _, err := (Podman{Runner: runner}).Inspect(context.Background(), id); err == nil {
		t.Fatal("expected Podman failure")
	}
}
