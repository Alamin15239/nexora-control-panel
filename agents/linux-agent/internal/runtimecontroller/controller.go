package runtimecontroller

import (
	"context"
	"errors"
	"fmt"

	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/ocisupervisor"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/supervisorstate"
)

// StateStore is the durable metadata interface required by the controller.
type StateStore interface {
	Upsert(supervisorstate.WorkloadState) error
	Delete(string) error
}

// Controller combines one authenticated desired-state snapshot with the
// lifecycle backend and durable state store. Authentication and assignment
// checks must happen before this method is called.
type Controller struct {
	Backend ocisupervisor.LifecycleBackend
	State   StateStore
}

// Converge changes one workload and persists the backend-observed state.
// It never accepts untrusted HTTP input or chooses a release.
func (c Controller) Converge(ctx context.Context, desired ocisupervisor.DesiredState) (ocisupervisor.ReconcileResult, error) {
	var empty ocisupervisor.ReconcileResult
	if c.Backend == nil || c.State == nil {
		return empty, errors.New("runtime backend and durable state store are required")
	}
	result, err := ocisupervisor.ReconcileOne(ctx, c.Backend, desired)
	if err != nil {
		return result, err
	}
	if result.ContainerID == "" {
		if desired.Running {
			return result, errors.New("running workload reconciliation returned no container identifier")
		}
		if err := c.State.Delete(desired.WorkloadID); err != nil {
			return result, fmt.Errorf("remove stopped workload from durable state: %w", err)
		}
		return result, nil
	}

	observed, err := c.Backend.Inspect(ctx, result.ContainerID)
	if err != nil {
		return result, fmt.Errorf("confirm workload state before persistence: %w", err)
	}
	if observed.ContainerID != result.ContainerID ||
		observed.WorkloadID != desired.WorkloadID ||
		observed.ReleaseID != desired.ReleaseID {
		return result, errors.New("observed workload identity changed before durable persistence")
	}
	switch observed.State {
	case ocisupervisor.StateCreated, ocisupervisor.StateRunning, ocisupervisor.StatePaused,
		ocisupervisor.StateExited, ocisupervisor.StateStopped, ocisupervisor.StateDead:
	default:
		return result, fmt.Errorf("cannot persist unsupported observed workload state %q", observed.State)
	}
	if err := c.State.Upsert(supervisorstate.WorkloadState{
		WorkloadID: observed.WorkloadID,
		ReleaseID: observed.ReleaseID,
		ContainerID: observed.ContainerID,
		State: string(observed.State),
	}); err != nil {
		return result, fmt.Errorf("persist observed workload state: %w", err)
	}
	result.ObservedState = observed.State
	return result, nil
}
