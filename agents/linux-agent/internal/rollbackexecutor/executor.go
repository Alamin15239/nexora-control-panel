// Package rollbackexecutor coordinates a crash-recoverable local rollback.
// It is intentionally inert unless explicitly enabled by an operator. Callers
// must authenticate and authorize the rollback intent before invoking Execute;
// this package does not accept or verify control-plane signatures.
package rollbackexecutor

import (
	"context"
	"errors"
	"fmt"

	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/releasepublisher"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/rollbackoutbox"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/runtimehealth"
)

// Publisher is the narrow, compare-and-switch release operation required here.
type Publisher interface {
	Rollback(baseDir, failedReleaseID, previousReleaseID string) error
}

// Prober must probe only the workload's trusted, locally assigned loopback
// endpoint. The operation's metadata must not be used to choose an arbitrary
// network destination.
type Prober interface {
	Probe(context.Context, rollbackoutbox.Operation) runtimehealth.Result
}

// Reporter must submit a signed, replay-protected acknowledgement bound to the
// exact operation and return nil only after receiving a valid server response.
type Reporter interface {
	Report(context.Context, rollbackoutbox.Operation, runtimehealth.Result) error
}

type Executor struct {
	Enabled bool
	Store *rollbackoutbox.Store
	Publisher Publisher
	Prober Prober
	Reporter Reporter
}

// Execute persists intent before switching, uses compare-and-switch rollback,
// verifies the restored workload, and reports only a successful local probe.
// Re-running the same operation is safe after a crash at any stage.
func (e *Executor) Execute(ctx context.Context, baseDir string, intent rollbackoutbox.Operation) (rollbackoutbox.Operation, error) {
	if !e.Enabled {
		return rollbackoutbox.Operation{}, errors.New("rollback execution is disabled")
	}
	if e.Store == nil || e.Publisher == nil || e.Prober == nil || e.Reporter == nil {
		return rollbackoutbox.Operation{}, errors.New("rollback executor dependencies are incomplete")
	}
	if err := ctx.Err(); err != nil {
		return rollbackoutbox.Operation{}, err
	}
	op, err := e.Store.Enqueue(intent)
	if err != nil {
		return rollbackoutbox.Operation{}, fmt.Errorf("persist rollback intent: %w", err)
	}
	if op.State == "reported" {
		return op, nil
	}
	if op.State == "blocked" {
		return op, errors.New("rollback operation is blocked")
	}

	if op.State == "pending" {
		if err := e.Publisher.Rollback(baseDir, op.FailedReleaseID, op.TargetReleaseID); err != nil {
			if ctx.Err() != nil {
				return op, ctx.Err()
			}
			blocked, transitionErr := e.Store.Transition(op.ID, "blocked", "rollback_switch_failed", 0, 0)
			if transitionErr != nil {
				return op, fmt.Errorf("rollback switch failed (%v) and could not persist blocked state: %w", err, transitionErr)
			}
			return blocked, fmt.Errorf("rollback switch failed: %w", err)
		}
		op, err = e.Store.Transition(op.ID, "switched", "", 0, 0)
		if err != nil {
			return op, fmt.Errorf("rollback switched but progress could not be persisted; retry is safe: %w", err)
		}
	}
	if op.State == "switched" {
		if err := ctx.Err(); err != nil {
			return op, err
		}
		result := e.Prober.Probe(ctx, op)
		if result.Status != runtimehealth.Healthy || result.HTTPStatus < 200 || result.HTTPStatus > 299 ||
			result.FailureCode != "" || result.DurationMs < 0 || result.DurationMs > 30000 {
			code := result.FailureCode
			if code == "" {
				code = "rollback_health_check_failed"
			}
			blocked, transitionErr := e.Store.Transition(op.ID, "blocked", code, result.HTTPStatus, result.DurationMs)
			if transitionErr != nil {
				return op, fmt.Errorf("restored workload did not pass health check and blocked state could not be persisted: %w", transitionErr)
			}
			return blocked, errors.New("restored workload failed its local health check")
		}
		op, err = e.Store.Transition(op.ID, "verified", "", result.HTTPStatus, result.DurationMs)
		if err != nil {
			return op, fmt.Errorf("health check passed but verification could not be persisted: %w", err)
		}
	}
	if op.State == "verified" {
		if err := ctx.Err(); err != nil {
			return op, err
		}
		// A reporter error is retryable. Keep the durable operation verified;
		// do not claim completion or switch releases again.
		result := e.Prober.Probe(ctx, op)
		if result.Status != runtimehealth.Healthy || result.HTTPStatus < 200 || result.HTTPStatus > 299 || result.FailureCode != "" {
			return op, errors.New("verified rollback health state changed before acknowledgement")
		}
		if err := e.Reporter.Report(ctx, op, result); err != nil {
			return op, fmt.Errorf("report verified rollback: %w", err)
		}
		op, err = e.Store.Transition(op.ID, "reported", "", result.HTTPStatus, result.DurationMs)
		if err != nil {
			return op, fmt.Errorf("rollback acknowledgement sent but reported state could not be persisted; retry must be idempotent: %w", err)
		}
	}
	return op, nil
}

// RealPublisher adapts the production compare-and-switch implementation.
type RealPublisher struct{}

func (RealPublisher) Rollback(baseDir, failedReleaseID, previousReleaseID string) error {
	return releasepublisher.Rollback(baseDir, failedReleaseID, previousReleaseID)
}
