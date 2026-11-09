package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/appnodeauth"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/artifactclient"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/artifactdelivery"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/artifactreceiver"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/deployarchive"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/deployenvelope"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/staticvhost"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/runtimehealth"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/releasepublisher"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/rollbackoutbox"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/rollbackexecutor"
)

const pendingPath = "/internal/v1/application-nodes/pending-static-releases"
var identityPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$`)

type Config struct {
	ControlPlaneURL string `json:"control_plane_url"`
	NodeIdentity string `json:"node_identity"`
	PrivateKeyFile string `json:"private_key_file"`
	DeploymentSigningPublicKeyFile string `json:"deployment_signing_public_key_file"`
	DeploymentSigningKeyID string `json:"deployment_signing_key_id"`
	DeploymentEnvelopeIssuer string `json:"deployment_envelope_issuer"`
	DeploymentEnvelopeAudience string `json:"deployment_envelope_audience"`
	PublisherRoot string `json:"publisher_root"`
	ReplayDirectory string `json:"replay_directory"`
	PollIntervalSeconds int `json:"poll_interval_seconds"`
	RollbackExecutionEnabled bool `json:"rollback_execution_enabled"`
}

type PendingRelease struct {
	DeploymentID string `json:"deploymentId"`
	OrganizationID string `json:"organizationId"`
	ProjectID string `json:"projectId"`
	HostingAccountID string `json:"hostingAccountId"`
	DomainID string `json:"domainId"`
	Hostname string `json:"hostname"`
	RepositoryID string `json:"repositoryId"`
	CommitSHA string `json:"commitSha"`
	HealthCheckPath string `json:"healthCheckPath"`
}
type PendingResponse struct {
	NodeIdentity string `json:"nodeIdentity"`
	PolledAt time.Time `json:"polledAt"`
	Releases []PendingRelease `json:"releases"`
}

func main() {
	configPath := flag.String("config", "/etc/nexora-static-publisher/node.json", "static publisher config")
	flag.Parse()
	if err := run(*configPath); err != nil {
		fmt.Fprintln(os.Stderr, "nexora-static-publisher:", err)
		os.Exit(1)
	}
}

func loadConfig(path string) (Config, error) {
	var cfg Config
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return cfg, errors.New("config path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil { return cfg, err }
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return cfg, errors.New("config must be a regular owner-only file")
	}
	raw, err := os.ReadFile(path)
	if err != nil { return cfg, err }
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil { return cfg, fmt.Errorf("decode config: %w", err) }
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF { return cfg, errors.New("config contains trailing JSON data") }
	u, err := url.Parse(cfg.ControlPlaneURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return cfg, errors.New("control_plane_url must be an HTTPS origin")
	}
	if !identityPattern.MatchString(cfg.NodeIdentity) { return cfg, errors.New("node_identity is invalid") }
	for name, value := range map[string]string{
		"private_key_file": cfg.PrivateKeyFile,
		"deployment_signing_public_key_file": cfg.DeploymentSigningPublicKeyFile,
		"publisher_root": cfg.PublisherRoot,
		"replay_directory": cfg.ReplayDirectory,
	} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value { return cfg, fmt.Errorf("%s must be an absolute clean path", name) }
	}
	if !regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`).MatchString(cfg.DeploymentSigningKeyID) ||
		cfg.DeploymentEnvelopeIssuer == "" || cfg.DeploymentEnvelopeAudience == "" {
		return cfg, errors.New("deployment envelope key ID, issuer and audience are required")
	}
	if cfg.PollIntervalSeconds < 15 || cfg.PollIntervalSeconds > 600 {
		return cfg, errors.New("poll_interval_seconds must be between 15 and 600")
	}
	return cfg, nil
}

func loadNodeKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err != nil { return nil, err }
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 || info.Size() > 256 {
		return nil, errors.New("node key must be a small regular owner-only file")
	}
	raw, err := os.ReadFile(path)
	if err != nil { return nil, err }
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != ed25519.PrivateKeySize { return nil, errors.New("node key must contain a 64-byte Ed25519 private key in hex") }
	return ed25519.PrivateKey(key), nil
}

func loadSigningKey(path string) (*rsa.PublicKey, error) {
	info, err := os.Lstat(path)
	if err != nil { return nil, err }
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0027 != 0 || info.Size() > 16<<10 {
		return nil, errors.New("deployment signing public key must be a regular, non-world-readable file")
	}
	raw, err := os.ReadFile(path)
	if err != nil { return nil, err }
	block, _ := pem.Decode(raw)
	if block == nil { return nil, errors.New("deployment signing public key is not PEM encoded") }
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		if key, pkcs1Err := x509.ParsePKCS1PublicKey(block.Bytes); pkcs1Err == nil { parsed = key } else { return nil, errors.New("unable to parse deployment signing public key") }
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok || key.N == nil || key.N.BitLen() < 2048 || key.E < 3 {
		return nil, errors.New("deployment signing public key must be RSA-2048 or stronger")
	}
	return key, nil
}

func verifyPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil { return fmt.Errorf("inspect %s: %w", filepath.Base(path), err) }
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("%s must be a real directory not writable by group or others", filepath.Base(path))
	}
	return nil
}

func fetchPending(ctx context.Context, client *http.Client, cfg Config, key ed25519.PrivateKey) ([]PendingRelease, error) {
	body := []byte{}
	proof, err := appnodeauth.Sign(key, cfg.NodeIdentity, http.MethodGet, pendingPath, body, time.Now().UTC())
	if err != nil { return nil, fmt.Errorf("sign pending-release request: %w", err) }
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(cfg.ControlPlaneURL, "/")+pendingPath, nil)
	if err != nil { return nil, err }
	if err := proof.Apply(req, cfg.NodeIdentity); err != nil { return nil, err }
	safeClient := *client
	safeClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := safeClient.Do(req)
	if err != nil { return nil, fmt.Errorf("poll pending static releases: %w", err) }
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil { return nil, err }
	if len(data) > 1<<20 { return nil, errors.New("pending-release response exceeds 1 MiB") }
	if resp.StatusCode != http.StatusOK { return nil, fmt.Errorf("pending-release API returned HTTP %d", resp.StatusCode) }
	var result PendingResponse
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil { return nil, fmt.Errorf("decode pending releases: %w", err) }
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF { return nil, errors.New("pending-release response contains trailing JSON") }
	if result.NodeIdentity != cfg.NodeIdentity || result.PolledAt.IsZero() || len(result.Releases) > 10 {
		return nil, errors.New("pending-release response violates the node assignment contract")
	}
	return result.Releases, nil
}

func run(configPath string) error {
	cfg, err := loadConfig(configPath)
	if err != nil { return err }
	nodeKey, err := loadNodeKey(cfg.PrivateKeyFile)
	if err != nil { return fmt.Errorf("load node signing key: %w", err) }
	signingKey, err := loadSigningKey(cfg.DeploymentSigningPublicKeyFile)
	if err != nil { return fmt.Errorf("load deployment trust key: %w", err) }
	for _, dir := range []string{cfg.PublisherRoot, filepath.Join(cfg.PublisherRoot, "accounts"), cfg.ReplayDirectory} {
		if err := verifyPrivateDirectory(dir); err != nil { return err }
	}
	var rollbackStore *rollbackoutbox.Store
	if cfg.RollbackExecutionEnabled {
		rollbackStateDir := filepath.Join(cfg.ReplayDirectory, "rollback-outbox")
		if err := os.Mkdir(rollbackStateDir, 0700); err != nil && !os.IsExist(err) {
			return fmt.Errorf("create rollback outbox directory: %w", err)
		}
		rollbackStore, err = rollbackoutbox.Open(filepath.Join(rollbackStateDir, "operations.json"))
		if err != nil { return fmt.Errorf("open rollback outbox: %w", err) }
	}
	httpClient := &http.Client{Timeout: 2 * time.Minute}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	poll := func() {
		releases, err := fetchPending(ctx, httpClient, cfg, nodeKey)
		if err != nil {
			fmt.Fprintln(os.Stderr, "pending-release poll:", err)
			return
		}
		for _, release := range releases {
			if ctx.Err() != nil { return }
			if !identityPattern.MatchString(release.HostingAccountID) {
				fmt.Fprintf(os.Stderr, "skip deployment %s: invalid hosting account identifier\n", release.DeploymentID)
				continue
			}
			baseDir := filepath.Join(cfg.PublisherRoot, "accounts", release.HostingAccountID)
			if err := verifyPrivateDirectory(baseDir); err != nil {
				fmt.Fprintf(os.Stderr, "deployment %s: %v\n", release.DeploymentID, err)
				continue
			}
			expected := deployenvelope.Expected{
				Issuer: cfg.DeploymentEnvelopeIssuer, Audience: cfg.DeploymentEnvelopeAudience,
				OrganizationID: release.OrganizationID, ProjectID: release.ProjectID,
				DeploymentID: release.DeploymentID, HostingAccountID: release.HostingAccountID,
				DomainID: release.DomainID, Hostname: release.Hostname,
				RepositoryID: release.RepositoryID, CommitSHA: strings.ToLower(release.CommitSHA),
			}
			nodeArtifactConfig := artifactclient.Config{
				ControlPlaneURL: cfg.ControlPlaneURL, NodeIdentity: cfg.NodeIdentity,
				PrivateKey: nodeKey, Purpose: "validate",
			}
			result, publishErr := artifactdelivery.FetchAndPublish(ctx, artifactdelivery.Config{
				HTTPClient: httpClient,
				ArtifactClient: nodeArtifactConfig,
				Expected: expected,
				TrustedSigningKeys: map[string]*rsa.PublicKey{cfg.DeploymentSigningKeyID: signingKey},
				BaseDir: baseDir,
				ReplayGuard: artifactreceiver.FileReplayGuard{Directory: cfg.ReplayDirectory},
				ArchiveLimits: deployarchive.Limits{},
			}, release.DeploymentID)
			if publishErr != nil {
				fmt.Fprintf(os.Stderr, "deployment %s publication failed: %v\n", release.DeploymentID, publishErr)
				continue
			}
			if err := staticvhost.RequestInstall(ctx, "", result.SignedEnvelope); err != nil {
				fmt.Fprintf(os.Stderr, "deployment %s release is staged but vhost installation failed: %v\n", release.DeploymentID, err)
				continue
			}
			if err := artifactclient.ReportActivated(ctx, httpClient, nodeArtifactConfig, artifactclient.ActivationReport{
				DeploymentID: result.DeploymentID,
				ReleaseID: result.ReleaseID,
				ArtifactSHA256: result.ArtifactSHA256,
			}); err != nil {
				fmt.Fprintf(os.Stderr, "deployment %s is routed by Nginx but activation acknowledgement failed: %v\n", release.DeploymentID, err)
				continue
			}
			healthCheckPath := release.HealthCheckPath
			if healthCheckPath == "" { healthCheckPath = "/" }
			probe := staticvhost.ProbeHTTP(ctx, release.Hostname, healthCheckPath, 5*time.Second)
			healthAck, healthErr := artifactclient.ReportHealthCheck(ctx, httpClient, nodeArtifactConfig, artifactclient.HealthCheckReport{
				DeploymentID: result.DeploymentID,
				ArtifactSHA256: result.ArtifactSHA256,
				ProbePath: healthCheckPath,
				HealthStatus: string(probe.Status),
				HTTPStatus: probe.HTTPStatus,
				DurationMs: probe.DurationMs,
				FailureCode: probe.FailureCode,
			})
			if healthErr != nil {
				fmt.Fprintf(os.Stderr, "deployment %s health report failed: %v\n", release.DeploymentID, healthErr)
				continue
			}
			if healthAck.RollbackRequired {
				if !cfg.RollbackExecutionEnabled {
					fmt.Fprintf(os.Stderr, "deployment %s failed; rollback to %v is required but rollback execution is disabled\n",
						release.DeploymentID, healthAck.RollbackTargetDeploymentID)
					continue
				}
				if healthAck.RollbackTargetDeploymentID == nil || healthAck.RollbackTargetNodeIdentity == nil ||
					healthAck.RollbackTargetArtifactSHA256 == nil || *healthAck.RollbackTargetNodeIdentity != cfg.NodeIdentity {
					fmt.Fprintf(os.Stderr, "deployment %s rollback target is incomplete or belongs to another node\n", release.DeploymentID)
					continue
				}
				intent := rollbackoutbox.Operation{
					ID: "rollback-" + result.DeploymentID,
					FailedDeploymentID: result.DeploymentID,
					FailedReleaseID: result.ReleaseID,
					TargetDeploymentID: *healthAck.RollbackTargetDeploymentID,
					TargetReleaseID: *healthAck.RollbackTargetDeploymentID,
					ProjectID: release.ProjectID,
					OrganizationID: release.OrganizationID,
					NodeID: cfg.NodeIdentity,
					ExpectedActiveReleaseID: result.ReleaseID,
					ArtifactSHA256: *healthAck.RollbackTargetArtifactSHA256,
				}
				executor := rollbackexecutor.Executor{
					Enabled: true,
					Store: rollbackStore,
					Publisher: rollbackexecutor.RealPublisher{},
					Prober: staticRollbackProber{hostname: release.Hostname, path: healthCheckPath},
					Reporter: staticRollbackReporter{client: httpClient, config: nodeArtifactConfig},
				}
				rollbackOp, rollbackErr := executor.Execute(ctx, baseDir, intent)
				if rollbackErr != nil {
					fmt.Fprintf(os.Stderr, "deployment %s automatic rollback did not complete safely (state=%s): %v\n",
						release.DeploymentID, rollbackOp.State, rollbackErr)
					continue
				}
				fmt.Fprintf(os.Stderr, "deployment %s automatically rolled back; previous release is serving and acknowledged (operation=%s)\n",
					release.DeploymentID, rollbackOp.ID)
				continue
			}
			if probe.Status != runtimehealth.Healthy {
				fmt.Fprintf(os.Stderr, "deployment %s failed HTTP health check: status=%d failure=%s\n",
					release.DeploymentID, probe.HTTPStatus, probe.FailureCode)
				continue
			}
			fmt.Printf("static release healthy and serving: deployment=%s release=%s sha256=%s bytes=%d probe_ms=%d already_published=%t\n",
				result.DeploymentID, result.ReleaseID, result.ArtifactSHA256, result.ArtifactBytes, probe.DurationMs, result.AlreadyPublished)		}
	}
	poll()
	ticker := time.NewTicker(time.Duration(cfg.PollIntervalSeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done(): return nil
		case <-ticker.C: poll()
		}
	}
}



type staticRollbackProber struct {
	hostname string
	path string
}

func (p staticRollbackProber) Probe(ctx context.Context, _ rollbackoutbox.Operation) runtimehealth.Result {
	return staticvhost.ProbeHTTP(ctx, p.hostname, p.path, 5*time.Second)
}

type staticRollbackReporter struct {
	client *http.Client
	config artifactclient.Config
}

func (r staticRollbackReporter) Report(ctx context.Context, op rollbackoutbox.Operation, result runtimehealth.Result) error {
	_, err := artifactclient.ReportRollbackCompleted(ctx, r.client, r.config, artifactclient.RollbackCompletionReport{
		OperationID: op.ID,
		FailedDeploymentID: op.FailedDeploymentID,
		TargetDeploymentID: op.TargetDeploymentID,
		TargetArtifactSHA256: op.ArtifactSHA256,
		HTTPStatus: result.HTTPStatus,
		DurationMs: result.DurationMs,
	})
	return err
}

// rollbackStaticRelease performs a compare-and-switch rollback only when the
// control plane's target belongs to this node. It verifies the restored release
// through an injected serving-boundary probe before reporting success.
func rollbackStaticRelease(baseDir, failedReleaseID string, targetDeploymentID, targetNodeID *string,
	nodeIdentity string, probe func() runtimehealth.Result) (runtimehealth.Result, error) {
	var empty runtimehealth.Result
	if targetDeploymentID == nil || targetNodeID == nil {
		return empty, errors.New("control plane rollback guidance is incomplete")
	}
	if nodeIdentity == "" || *targetNodeID != nodeIdentity {
		return empty, errors.New("rollback target belongs to a different runtime node")
	}
	if !releasepublisher.IsReleaseID(*targetDeploymentID) || !releasepublisher.IsReleaseID(failedReleaseID) {
		return empty, errors.New("rollback release identifier is invalid")
	}
	if probe == nil {
		return empty, errors.New("rollback serving-boundary probe is required")
	}
	if err := releasepublisher.Rollback(baseDir, failedReleaseID, *targetDeploymentID); err != nil {
		return empty, err
	}
	result := probe()
	if result.Status != runtimehealth.Healthy || result.HTTPStatus < 200 || result.HTTPStatus > 299 || result.FailureCode != "" {
		return result, fmt.Errorf("restored release failed HTTP verification: status=%d failure=%s", result.HTTPStatus, result.FailureCode)
	}
	return result, nil
}
