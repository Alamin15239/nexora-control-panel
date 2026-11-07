package ocisupervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// WorkloadState is the observed state reported by the rootless OCI engine.
type WorkloadState string

const (
	StateCreated  WorkloadState = "created"
	StateRunning  WorkloadState = "running"
	StatePaused   WorkloadState = "paused"
	StateExited   WorkloadState = "exited"
	StateStopped  WorkloadState = "stopped"
	StateRemoving WorkloadState = "removing"
	StateDead     WorkloadState = "dead"
)

type Workload struct {
	ContainerID string
	WorkloadID  string
	ReleaseID   string
	State       WorkloadState
}

type inspectRecord struct {
	ID    string `json:"Id"`
	State struct {
		Status string `json:"Status"`
	} `json:"State"`
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

var containerIDPattern = regexp.MustCompile(`^[a-f0-9]{12,64}$`)

func (p Podman) Inspect(ctx context.Context, containerID string) (Workload, error) {
	var result Workload
	if !containerIDPattern.MatchString(containerID) {
		return result, errors.New("invalid container identifier")
	}
	output, err := p.runner().Run(ctx, "inspect", "--type", "container", "--format", "json", containerID)
	if err != nil {
		return result, fmt.Errorf("inspect workload container: %w", err)
	}
	var records []inspectRecord
	decoderErr := json.Unmarshal(output, &records)
	if decoderErr != nil || len(records) != 1 {
		return result, errors.New("Podman returned an invalid container inspection response")
	}
	record := records[0]
	if record.ID != containerID {
		return result, errors.New("Podman inspection returned a different container identifier")
	}
	labels := record.Config.Labels
	if labels["io.nexora.managed"] != "true" ||
		!idPattern.MatchString(labels["io.nexora.workload"]) ||
		!idPattern.MatchString(labels["io.nexora.release"]) {
		return result, errors.New("container is not a Nexora-managed workload")
	}
	state := WorkloadState(record.State.Status)
	switch state {
	case StateCreated, StateRunning, StatePaused, StateExited, StateStopped, StateRemoving, StateDead:
	default:
		return result, errors.New("Podman returned an unknown workload state")
	}
	return Workload{
		ContainerID: record.ID,
		WorkloadID: labels["io.nexora.workload"],
		ReleaseID: labels["io.nexora.release"],
		State: state,
	}, nil
}

// Restart only operates on a container whose immutable Nexora ownership labels
// have been verified by Inspect. It never accepts a container name or shell input.
func (p Podman) Restart(ctx context.Context, containerID string) error {
	workload, err := p.Inspect(ctx, containerID)
	if err != nil {
		return err
	}
	if workload.State == StateRemoving || workload.State == StateDead {
		return errors.New("workload cannot be restarted from its current state")
	}
	if _, err := p.runner().Run(ctx, "restart", "--time", "10", workload.ContainerID); err != nil {
		return fmt.Errorf("restart Nexora workload: %w", err)
	}
	return nil
}

// StopManaged and RemoveManaged verify Nexora ownership before changing a
// container. The lower-level Stop/Remove methods remain for compatibility but
// the supervisor must use these guarded variants.
func (p Podman) StopManaged(ctx context.Context, containerID string) error {
	workload, err := p.Inspect(ctx, containerID)
	if err != nil {
		return err
	}
	if workload.State == StateStopped || workload.State == StateExited || workload.State == StateDead {
		return nil
	}
	if _, err := p.runner().Run(ctx, "stop", "--time", "10", workload.ContainerID); err != nil {
		return fmt.Errorf("stop Nexora workload: %w", err)
	}
	return nil
}

func (p Podman) RemoveManaged(ctx context.Context, containerID string) error {
	workload, err := p.Inspect(ctx, containerID)
	if err != nil {
		return err
	}
	if workload.State == StateRunning || workload.State == StatePaused {
		return errors.New("running workload must be stopped before removal")
	}
	if _, err := p.runner().Run(ctx, "rm", workload.ContainerID); err != nil {
		return fmt.Errorf("remove Nexora workload: %w", err)
	}
	return nil
}

// ParseInspection is kept private to make the accepted JSON shape explicit.
func parseInspection(output []byte) ([]inspectRecord, error) {
	var records []inspectRecord
	if err := json.Unmarshal(output, &records); err != nil {
		return nil, err
	}
	if len(records) != 1 || strings.TrimSpace(records[0].ID) == "" {
		return nil, errors.New("expected exactly one inspected container")
	}
	return records, nil
}
