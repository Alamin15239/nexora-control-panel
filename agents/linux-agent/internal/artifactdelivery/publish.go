// Package artifactdelivery composes authenticated artifact download with verified
// local publication. It is an internal primitive, not a background service.
package artifactdelivery

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/artifactclient"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/artifactreceiver"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/deployarchive"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/deployenvelope"
)

type Config struct {
	HTTPClient *http.Client
	ArtifactClient artifactclient.Config
	Expected deployenvelope.Expected
	TrustedSigningKeys map[string]*rsa.PublicKey
	BaseDir string
	ReplayGuard artifactreceiver.ReplayGuard
	ArchiveLimits deployarchive.Limits
}

// FetchAndPublish requests the deployment artifact as an authenticated runtime
// node, then verifies its signed deployment identity and digest before extraction
// and atomic release activation. Expected identity must come from trusted node
// assignment data, not user-controlled workload input.
func FetchAndPublish(ctx context.Context, config Config, deploymentID string) (artifactreceiver.Result, error) {
	var empty artifactreceiver.Result
	if deploymentID == "" || config.Expected.DeploymentID != deploymentID {
		return empty, errors.New("requested deployment does not match the trusted node assignment")
	}
	if config.Expected.Issuer == "" || config.Expected.Audience == "" {
		return empty, errors.New("trusted deployment envelope issuer and audience are required")
	}
	if config.ReplayGuard == nil {
		return empty, errors.New("durable envelope replay protection is required")
	}
	download, err := artifactclient.Fetch(ctx, config.HTTPClient, config.ArtifactClient, deploymentID)
	if err != nil {
		return empty, fmt.Errorf("download authorized deployment artifact: %w", err)
	}
	return artifactreceiver.Receive(ctx, artifactreceiver.Request{
		Token: download.Envelope,
		Artifact: download.Artifact,
		Expected: config.Expected,
		Keys: config.TrustedSigningKeys,
		BaseDir: config.BaseDir,
		Now: time.Now().UTC(),
		Limits: config.ArchiveLimits,
		Replay: config.ReplayGuard,
	})
}
