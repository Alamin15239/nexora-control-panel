package runtimehealth

import (
	"context"
	"net/http"
	"time"

	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/artifactclient"
)

// ProbeAndReport probes the assigned workload on loopback and submits the
// result through the signed application-node API client. The caller must only
// invoke this after starting the workload inside its enforced isolation boundary.
func ProbeAndReport(
	ctx context.Context,
	httpClient *http.Client,
	nodeConfig artifactclient.Config,
	deploymentID string,
	artifactSHA256 string,
	assignedPort int,
	configuredPath string,
	timeout time.Duration,
) (Result, artifactclient.HealthCheckAcknowledgement, error) {
	result := Probe(ctx, assignedPort, configuredPath, timeout)
	report := artifactclient.HealthCheckReport{
		DeploymentID: deploymentID,
		ArtifactSHA256: artifactSHA256,
		ProbePath: configuredPath,
		HealthStatus: string(result.Status),
		HTTPStatus: result.HTTPStatus,
		DurationMs: result.DurationMs,
		FailureCode: result.FailureCode,
	}
	acknowledgement, err := artifactclient.ReportHealthCheck(ctx, httpClient, nodeConfig, report)
	return result, acknowledgement, err
}
