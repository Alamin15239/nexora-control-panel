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

// RecoveryStore is the load capability required for startup reconciliation.
type RecoveryStore interface {
	StateStore
	Load() ([]supervisorstate.WorkloadState, error)
}

type RecoveryReport struct {
	Checked int
	Reconciled int
	Workloads []supervisorstate.WorkloadState
}

// Recover verifies every persisted container against Podman before the node
// may use the local snapshot. It refreshes changed observed states but fails
// closed on missing containers or ownership mismatches.
func (c Controller) Recover(ctx context.Context) (RecoveryReport, error) {
	var report RecoveryReport
	if c.Backend == nil {
		return report, errors.New("runtime backend is required for recovery")
	}
	store, ok := c.State.(RecoveryStore)
	if !ok || store == nil {
		return report, errors.New("durable state store does not support recovery loads")
	}
	items, err := store.Load()
	if err != nil {
		return report, fmt.Errorf("load durable runtime state: %w", err)
	}
	report.Workloads = make([]supervisorstate.WorkloadState, 0, len(items))
	for _, item := range items {
		report.Checked++
		observed, err := c.Backend.Inspect(ctx, item.ContainerID)
		if err != nil {
			return report, fmt.Errorf("verify persisted workload %q during recovery: %w", item.WorkloadID, err)
		}
		if observed.ContainerID != item.ContainerID || observed.WorkloadID != item.WorkloadID ||
			observed.ReleaseID != item.ReleaseID {
			return report, fmt.Errorf("persisted workload %q does not match backend ownership metadata", item.WorkloadID)
		}
		switch observed.State {
		case ocisupervisor.StateCreated, ocisupervisor.StateRunning, ocisupervisor.StatePaused,
			ocisupervisor.StateExited, ocisupervisor.StateStopped, ocisupervisor.StateDead:
		default:
			return report, fmt.Errorf("persisted workload %q has unsupported backend state %q", item.WorkloadID, observed.State)
		}
		if string(observed.State) != item.State {
			item.State = string(observed.State)
			if err := store.Upsert(item); err != nil {
				return report, fmt.Errorf("refresh recovered workload %q state: %w", item.WorkloadID, err)
			}
			report.Reconciled++
		}
		item.State = string(observed.State)
		report.Workloads = append(report.Workloads, item)
	}
	return report, nil
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
