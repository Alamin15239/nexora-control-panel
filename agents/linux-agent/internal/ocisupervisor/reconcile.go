package ocisupervisor

import (
	"context"
	"errors"
	"fmt"
)

// DesiredState is a validated control-plane snapshot after node identity,
// signature, nonce, release assignment and tenant authorization have succeeded.
// The caller must not construct it from unauthenticated input.
type DesiredState struct {
	WorkloadID string
	ReleaseID string
	Running bool
	ContainerID string
	Spec Spec
}

type LifecycleBackend interface {
	Start(context.Context, Spec) (string, error)
	Inspect(context.Context, string) (Workload, error)
	Restart(context.Context, string) error
	StopManaged(context.Context, string) error
}

type ReconcileResult struct {
	ContainerID string
	Action string
	ObservedState WorkloadState
}

// ReconcileOne converges one already-authorized desired workload snapshot.
// It deliberately does not poll the control plane, persist node state, choose
// releases, or accept raw HTTP payloads. Those responsibilities belong to the
// authenticated node service and durable supervisor state store.
func ReconcileOne(ctx context.Context, backend LifecycleBackend, desired DesiredState) (ReconcileResult, error) {
	var result ReconcileResult
	if backend == nil {
		return result, errors.New("runtime lifecycle backend is required")
	}
	if !idPattern.MatchString(desired.WorkloadID) || !idPattern.MatchString(desired.ReleaseID) ||
		desired.Spec.WorkloadID != desired.WorkloadID || desired.Spec.ReleaseID != desired.ReleaseID {
		return result, errors.New("desired workload identity does not match its immutable runtime specification")
	}
	if desired.ContainerID != "" && !containerIDPattern.MatchString(desired.ContainerID) {
		return result, errors.New("desired workload contains an invalid container identifier")
	}
	if desired.ContainerID == "" {
		if !desired.Running {
			return ReconcileResult{Action: "already_stopped"}, nil
		}
		id, err := backend.Start(ctx, desired.Spec)
		if err != nil {
			return result, fmt.Errorf("start desired workload: %w", err)
		}
		if !containerIDPattern.MatchString(id) {
			return result, errors.New("runtime backend returned an invalid container identifier")
		}
		return ReconcileResult{ContainerID: id, Action: "started"}, nil
	}

	observed, err := backend.Inspect(ctx, desired.ContainerID)
	if err != nil {
		return result, fmt.Errorf("inspect desired workload: %w", err)
	}
	if observed.ContainerID != desired.ContainerID || observed.WorkloadID != desired.WorkloadID {
		return result, errors.New("observed container ownership does not match desired workload")
	}
	if observed.ReleaseID != desired.ReleaseID {
		return result, errors.New("observed container release does not match the assigned desired release")
	}
	result.ContainerID = desired.ContainerID
	result.ObservedState = observed.State

	if desired.Running {
		switch observed.State {
		case StateRunning:
			result.Action = "no_op"
			return result, nil
		case StateCreated, StateExited, StateStopped:
			if err := backend.Restart(ctx, desired.ContainerID); err != nil {
				return result, fmt.Errorf("restart desired workload: %w", err)
			}
			result.Action = "restarted"
			return result, nil
		default:
			return result, fmt.Errorf("cannot converge desired running state from observed state %q", observed.State)
		}
	}

	switch observed.State {
	case StateStopped, StateExited, StateDead:
		result.Action = "already_stopped"
		return result, nil
	case StateCreated, StateRunning, StatePaused:
		if err := backend.StopManaged(ctx, desired.ContainerID); err != nil {
			return result, fmt.Errorf("stop workload no longer desired: %w", err)
		}
		result.Action = "stopped"
		return result, nil
	default:
		return result, fmt.Errorf("cannot converge desired stopped state from observed state %q", observed.State)
	}
}
