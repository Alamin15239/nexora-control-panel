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
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/releasepublisher"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/rollbackexecutor"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/rollbackoutbox"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/runtimehealth"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/staticvhost"
)

const pendingPath = "/internal/v1/application-nodes/pending-static-releases"

var identityPattern = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
var accountIDPattern = regexp.MustCompile("^[A-Za-z0-9_-]{1,128}$")

func validHostingAccountID(value string) bool {
	return accountIDPattern.MatchString(value)
}

type Config struct {
	ControlPlaneURL                string `json:"control_plane_url"`
	NodeIdentity                   string `json:"node_identity"`
	PrivateKeyFile                 string `json:"private_key_file"`
	DeploymentSigningPublicKeyFile string `json:"deployment_signing_public_key_file"`
	DeploymentSigningKeyID         string `json:"deployment_signing_key_id"`
	DeploymentEnvelopeIssuer       string `json:"deployment_envelope_issuer"`
	DeploymentEnvelopeAudience     string `json:"deployment_envelope_audience"`
	PublisherRoot                  string `json:"publisher_root"`
	ReplayDirectory                string `json:"replay_directory"`
	PollIntervalSeconds            int    `json:"poll_interval_seconds"`
	RollbackExecutionEnabled       bool   `json:"rollback_execution_enabled"`
}

type PendingRelease struct {
	DeploymentID         string `json:"deploymentId"`
	OrganizationID       string `json:"organizationId"`
	ProjectID            string `json:"projectId"`
	HostingAccountID     string `json:"hostingAccountId"`
	DomainID             string `json:"domainId"`
	Hostname             string `json:"hostname"`
	RepositoryID         string `json:"repositoryId"`
	CommitSHA            string `json:"commitSha"`
	HealthCheckPath      string `json:"healthCheckPath"`
	PreviousDeploymentID string `json:"previousDeploymentId"`
}
type PendingRollback struct {
	FailedDeploymentID   string `json:"failedDeploymentId"`
	TargetDeploymentID   string `json:"targetDeploymentId"`
	FailedReleaseID      string `json:"failedReleaseId"`
	TargetReleaseID      string `json:"targetReleaseId"`
	OrganizationID       string `json:"organizationId"`
	ProjectID            string `json:"projectId"`
	HostingAccountID     string `json:"hostingAccountId"`
	Hostname             string `json:"hostname"`
	HealthCheckPath      string `json:"healthCheckPath"`
	TargetArtifactSHA256 string `json:"targetArtifactSha256"`
}

type PendingResponse struct {
	NodeIdentity string            `json:"nodeIdentity"`
	PolledAt     time.Time         `json:"polledAt"`
	Releases     []PendingRelease  `json:"releases"`
	Rollbacks    []PendingRollback `json:"rollbacks"`
}

func main() {
	configPath := flag.String("config", "/etc/nexora-static-publisher/node.json", "static publisher config")
	flag.Parse()
	if err := run(*configPath); err != nil {
		fmt.Fprintln(os.Stderr, "nexora-static-publisher:", err)
		os.Exit(1)
	}
}

func verifyOwnedRegularFile(path string, maxSize int64) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("must be a regular non-symlink file")
	}
	if info.Mode().Perm() != 0600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("must have exact owner-only mode 0600")
	}
	if info.Size() > maxSize {
		return fmt.Errorf("file exceeds maximum size of %d bytes", maxSize)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) {
		return errors.New("file has unexpected owner or group")
	}
	return nil
}

func verifyOwnedDirectory(path string, uid, gid uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect directory %s: %w", filepath.Base(path), err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s must be a real directory", filepath.Base(path))
	}
	if info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("%s is writable by group or others", filepath.Base(path))
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || stat.Gid != gid {
		return fmt.Errorf("%s has unexpected ownership", filepath.Base(path))
	}
	return nil
}

func verifyOwnedReplayDirectory(path string, uid, gid uint32) error {
	if err := verifyOwnedDirectory(path, uid, gid); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0700 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("replay directory must have exact owner-only mode 0700")
	}
	return nil
}

func ensurePrivateChild(path string, uid, gid uint32) error {
	err := os.Mkdir(path, os.FileMode(0750)|os.ModeSetgid)
	created := err == nil
	if err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create %s: %w", filepath.Base(path), err)
	}
	if created {
		if err := os.Chmod(path, os.FileMode(0750)|os.ModeSetgid); err != nil {
			return fmt.Errorf("set permissions on %s: %w", filepath.Base(path), err)
		}
	}
	if err := verifyOwnedDirectory(path, uid, gid); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0750 || info.Mode()&os.ModeSetgid == 0 {
		return fmt.Errorf("%s must have setgid mode 2750", filepath.Base(path))
	}
	return nil
}

func provisionAccountDirectories(accountsRoot, accountID string) (string, error) {
	if !validHostingAccountID(accountID) {
		return "", errors.New("hosting account identifier is invalid")
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if err := verifyOwnedDirectory(accountsRoot, uid, gid); err != nil {
		return "", fmt.Errorf("accounts root: %w", err)
	}
	base := filepath.Join(accountsRoot, accountID)
	if err := ensurePrivateChild(base, uid, gid); err != nil {
		return "", fmt.Errorf("account directory: %w", err)
	}
	for _, name := range []string{"staging", "releases"} {
		if err := ensurePrivateChild(filepath.Join(base, name), uid, gid); err != nil {
			return "", fmt.Errorf("%s directory: %w", name, err)
		}
	}
	return base, nil
}

func validStaticDomain(domain string) bool {
	if len(domain) < 3 || len(domain) > 253 || strings.Contains(domain, "..") ||
		strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || !strings.Contains(domain, ".") {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 ||
			!regexp.MustCompile("(?i)^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$").MatchString(label) {
			return false
		}
	}
	return true
}

func validStaticHealthCheckPath(path string) bool {
	if len(path) == 0 || len(path) > 512 || !strings.HasPrefix(path, "/") ||
		strings.HasPrefix(path, "//") || strings.ContainsAny(path, "?#\\") {
		return false
	}
	for _, r := range path {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	decoded, err := url.PathUnescape(path)
	if err != nil || strings.ContainsAny(decoded, "\\?#") {
		return false
	}
	for _, r := range decoded {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	if !strings.HasPrefix(decoded, "/") || strings.HasPrefix(decoded, "//") {
		return false
	}
	for _, segment := range strings.Split(decoded, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func loadConfig(path string) (Config, error) {
	var cfg Config
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return cfg, errors.New("config path must be absolute and clean")
	}
	if err := verifyOwnedRegularFile(path, 64<<10); err != nil {
		return cfg, fmt.Errorf("config file security check: %w", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("decode config: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return cfg, errors.New("config contains trailing JSON data")
	}
	u, err := url.Parse(cfg.ControlPlaneURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return cfg, errors.New("control_plane_url must be an HTTPS origin")
	}
	if !identityPattern.MatchString(cfg.NodeIdentity) {
		return cfg, errors.New("node_identity is invalid")
	}
	for name, value := range map[string]string{
		"private_key_file":                   cfg.PrivateKeyFile,
		"deployment_signing_public_key_file": cfg.DeploymentSigningPublicKeyFile,
		"publisher_root":                     cfg.PublisherRoot,
		"replay_directory":                   cfg.ReplayDirectory,
	} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return cfg, fmt.Errorf("%s must be an absolute clean path", name)
		}
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
	if err := verifyOwnedRegularFile(path, 256); err != nil {
		return nil, fmt.Errorf("node key security check: %w", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("node key must contain a 64-byte Ed25519 private key in hex")
	}
	return ed25519.PrivateKey(key), nil
}

func loadSigningKey(path string) (*rsa.PublicKey, error) {
	if err := verifyOwnedRegularFile(path, 16<<10); err != nil {
		return nil, fmt.Errorf("deployment signing public key security check: %w", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("deployment signing public key is not PEM encoded")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		if key, pkcs1Err := x509.ParsePKCS1PublicKey(block.Bytes); pkcs1Err == nil {
			parsed = key
		} else {
			return nil, errors.New("unable to parse deployment signing public key")
		}
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok || key.N == nil || key.N.BitLen() < 2048 || key.E < 3 {
		return nil, errors.New("deployment signing public key must be RSA-2048 or stronger")
	}
	return key, nil
}

func verifyPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", filepath.Base(path), err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("%s must be a real directory not writable by group or others", filepath.Base(path))
	}
	return nil
}

func fetchPending(ctx context.Context, client *http.Client, cfg Config, key ed25519.PrivateKey) (PendingResponse, error) {
	var empty PendingResponse
	body := []byte{}
	proof, err := appnodeauth.Sign(key, cfg.NodeIdentity, http.MethodGet, pendingPath, body, time.Now().UTC())
	if err != nil {
		return empty, fmt.Errorf("sign pending-release request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(cfg.ControlPlaneURL, "/")+pendingPath, nil)
	if err != nil {
		return empty, err
	}
	if err := proof.Apply(req, cfg.NodeIdentity); err != nil {
		return empty, err
	}
	safeClient := *client
	safeClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := safeClient.Do(req)
	if err != nil {
		return empty, fmt.Errorf("poll pending static releases: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return empty, err
	}
	if len(data) > 1<<20 {
		return empty, errors.New("pending-release response exceeds 1 MiB")
	}
	if resp.StatusCode != http.StatusOK {
		return empty, fmt.Errorf("pending-release API returned HTTP %d", resp.StatusCode)
	}
	var result PendingResponse
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return empty, fmt.Errorf("decode pending releases: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return empty, errors.New("pending-release response contains trailing JSON")
	}
	if result.NodeIdentity != cfg.NodeIdentity || result.PolledAt.IsZero() || len(result.Releases) > 10 || len(result.Rollbacks) > 10 {
		return empty, errors.New("pending-release response violates the node assignment contract")
	}
	for _, release := range result.Releases {
		if !validStaticDomain(release.Hostname) || !validStaticHealthCheckPath(release.HealthCheckPath) {
			return empty, fmt.Errorf("deployment %q has an invalid hostname or health-check path", release.DeploymentID)
		}
	}
	for _, rollback := range result.Rollbacks {
		if !validStaticDomain(rollback.Hostname) || !validStaticHealthCheckPath(rollback.HealthCheckPath) {
			return empty, fmt.Errorf("rollback %q has an invalid hostname or health-check path", rollback.FailedDeploymentID)
		}
	}
	return result, nil
}

func run(configPath string) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	nodeKey, err := loadNodeKey(cfg.PrivateKeyFile)
	if err != nil {
		return fmt.Errorf("load node signing key: %w", err)
	}
	signingKey, err := loadSigningKey(cfg.DeploymentSigningPublicKeyFile)
	if err != nil {
		return fmt.Errorf("load deployment trust key: %w", err)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	for _, dir := range []string{cfg.PublisherRoot, filepath.Join(cfg.PublisherRoot, "accounts")} {
		if err := verifyOwnedDirectory(dir, uid, gid); err != nil {
			return fmt.Errorf("publisher directory ownership/security check: %w", err)
		}
	}
	if err := verifyOwnedReplayDirectory(cfg.ReplayDirectory, uid, gid); err != nil {
		return fmt.Errorf("replay directory ownership/security check: %w", err)
	}
	var rollbackStore *rollbackoutbox.Store
	if cfg.RollbackExecutionEnabled {
		rollbackStateDir := filepath.Join(cfg.ReplayDirectory, "rollback-outbox")
		if err := os.Mkdir(rollbackStateDir, 0700); err != nil && !os.IsExist(err) {
			return fmt.Errorf("create rollback outbox directory: %w", err)
		}
		rollbackStore, err = rollbackoutbox.Open(filepath.Join(rollbackStateDir, "operations.json"))
		if err != nil {
			return fmt.Errorf("open rollback outbox: %w", err)
		}
	}
	httpClient := &http.Client{Timeout: 2 * time.Minute}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	poll := func() {
		if cfg.RollbackExecutionEnabled {
			if err := resumeLocalRollbackOutbox(ctx, httpClient, cfg, rollbackStore, nodeKey); err != nil && ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "rollback outbox recovery:", err)
			}
		}
		pending, err := fetchPending(ctx, httpClient, cfg, nodeKey)
		if err != nil {
			fmt.Fprintln(os.Stderr, "pending-release poll:", err)
			return
		}
		for _, release := range pending.Releases {
			if ctx.Err() != nil {
				return
			}
			baseDir, provisionErr := provisionAccountDirectories(
				filepath.Join(cfg.PublisherRoot, "accounts"), release.HostingAccountID,
			)
			if provisionErr != nil {
				fmt.Fprintf(os.Stderr, "deployment %s: account provisioning rejected: %v\n", release.DeploymentID, provisionErr)
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
				HTTPClient:         httpClient,
				ArtifactClient:     nodeArtifactConfig,
				Expected:           expected,
				TrustedSigningKeys: map[string]*rsa.PublicKey{cfg.DeploymentSigningKeyID: signingKey},
				BaseDir:            baseDir,
				ReplayGuard:        artifactreceiver.FileReplayGuard{Directory: cfg.ReplayDirectory},
				ArchiveLimits:      deployarchive.Limits{},
			}, release.DeploymentID)
			if publishErr != nil {
				fmt.Fprintf(os.Stderr, "deployment %s publication failed: %v\n", release.DeploymentID, publishErr)
				continue
			}
			if err := staticvhost.RequestInstall(ctx, "", result.SignedEnvelope); err != nil {
				fmt.Fprintf(os.Stderr, "deployment %s release is stored but vhost installation failed: %v\n", release.DeploymentID, err)
				continue
			}
			// The privileged broker installs and validates the Nginx vhost first.
			// Only then may the unprivileged publisher switch the active release.
			if err := releasepublisher.ActivateIfCurrent(baseDir, release.PreviousDeploymentID, result.ReleaseID); err != nil {
				fmt.Fprintf(os.Stderr, "deployment %s vhost is installed but release activation failed: %v\n", release.DeploymentID, err)
				continue
			}
			if err := artifactclient.ReportActivated(ctx, httpClient, nodeArtifactConfig, artifactclient.ActivationReport{
				DeploymentID:   result.DeploymentID,
				ReleaseID:      result.ReleaseID,
				ArtifactSHA256: result.ArtifactSHA256,
			}); err != nil {
				fmt.Fprintf(os.Stderr, "deployment %s is routed by Nginx but activation acknowledgement failed: %v\n", release.DeploymentID, err)
				continue
			}
			healthCheckPath := release.HealthCheckPath
			if healthCheckPath == "" {
				healthCheckPath = "/"
			}
			probe := staticvhost.ProbeHTTP(ctx, release.Hostname, healthCheckPath, 5*time.Second)
			healthAck, healthErr := artifactclient.ReportHealthCheck(ctx, httpClient, nodeArtifactConfig, artifactclient.HealthCheckReport{
				DeploymentID:   result.DeploymentID,
				ArtifactSHA256: result.ArtifactSHA256,
				ProbePath:      healthCheckPath,
				HealthStatus:   string(probe.Status),
				HTTPStatus:     probe.HTTPStatus,
				DurationMs:     probe.DurationMs,
				FailureCode:    probe.FailureCode,
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
				if healthAck.RollbackTargetDeploymentID == nil || healthAck.RollbackTargetReleaseID == nil || healthAck.RollbackTargetNodeIdentity == nil ||
					healthAck.RollbackTargetArtifactSHA256 == nil || *healthAck.RollbackTargetNodeIdentity != cfg.NodeIdentity {
					fmt.Fprintf(os.Stderr, "deployment %s rollback target is incomplete or belongs to another node\n", release.DeploymentID)
					continue
				}
				intent := rollbackoutbox.Operation{
					ID:                      "rollback-" + result.DeploymentID,
					FailedDeploymentID:      result.DeploymentID,
					FailedReleaseID:         result.ReleaseID,
					TargetDeploymentID:      *healthAck.RollbackTargetDeploymentID,
					TargetReleaseID:         *healthAck.RollbackTargetReleaseID,
					ProjectID:               release.ProjectID,
					OrganizationID:          release.OrganizationID,
					NodeID:                  cfg.NodeIdentity,
					HostingAccountID:        release.HostingAccountID,
					Hostname:                release.Hostname,
					HealthCheckPath:         healthCheckPath,
					ExpectedActiveReleaseID: result.ReleaseID,
					ArtifactSHA256:          *healthAck.RollbackTargetArtifactSHA256,
				}
				executor := rollbackexecutor.Executor{
					Enabled:   true,
					Store:     rollbackStore,
					Publisher: rollbackexecutor.RealPublisher{},
					Prober:    staticRollbackProber{hostname: release.Hostname, path: healthCheckPath},
					Reporter:  staticRollbackReporter{client: httpClient, config: nodeArtifactConfig},
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
				result.DeploymentID, result.ReleaseID, result.ArtifactSHA256, result.ArtifactBytes, probe.DurationMs, result.AlreadyPublished)
		}
		for _, pendingRollback := range pending.Rollbacks {
			if !cfg.RollbackExecutionEnabled {
				fmt.Fprintf(os.Stderr, "rollback required for failed deployment %s but execution is disabled\n", pendingRollback.FailedDeploymentID)
				continue
			}
			if !validHostingAccountID(pendingRollback.HostingAccountID) {
				fmt.Fprintf(os.Stderr, "skip rollback %s: invalid hosting account identifier\n", pendingRollback.FailedDeploymentID)
				continue
			}
			baseDir := filepath.Join(cfg.PublisherRoot, "accounts", pendingRollback.HostingAccountID)
			if err := verifyPrivateDirectory(baseDir); err != nil {
				fmt.Fprintf(os.Stderr, "rollback %s: %v\n", pendingRollback.FailedDeploymentID, err)
				continue
			}
			operationID := "rollback-" + pendingRollback.FailedDeploymentID
			exists, existsErr := localRollbackOperationExists(rollbackStore, operationID)
			if existsErr != nil {
				fmt.Fprintf(os.Stderr, "rollback %s: inspect local outbox: %v\n", pendingRollback.FailedDeploymentID, existsErr)
				continue
			}
			if exists {
				continue
			} // Existing operation was already resumed at the start of this poll.
			intent := rollbackIntentFromPending(pendingRollback, cfg.NodeIdentity)
			rollbackOp, err := executeRollbackOperation(ctx, httpClient, cfg, rollbackStore, baseDir, intent, nodeKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "pending rollback %s did not complete safely (state=%s): %v\n",
					pendingRollback.FailedDeploymentID, rollbackOp.State, err)
				continue
			}
			fmt.Fprintf(os.Stderr, "pending rollback %s completed and acknowledged (operation=%s)\n",
				pendingRollback.FailedDeploymentID, rollbackOp.ID)
		}
	}
	poll()
	ticker := time.NewTicker(time.Duration(cfg.PollIntervalSeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			poll()
		}
	}
}

func rollbackIntentFromPending(p PendingRollback, nodeIdentity string) rollbackoutbox.Operation {
	return rollbackoutbox.Operation{
		ID:                      "rollback-" + p.FailedDeploymentID,
		FailedDeploymentID:      p.FailedDeploymentID,
		FailedReleaseID:         p.FailedReleaseID,
		TargetDeploymentID:      p.TargetDeploymentID,
		TargetReleaseID:         p.TargetReleaseID,
		ProjectID:               p.ProjectID,
		OrganizationID:          p.OrganizationID,
		NodeID:                  nodeIdentity,
		HostingAccountID:        p.HostingAccountID,
		Hostname:                p.Hostname,
		HealthCheckPath:         p.HealthCheckPath,
		ExpectedActiveReleaseID: p.FailedReleaseID,
		ArtifactSHA256:          p.TargetArtifactSHA256,
	}
}

func executeRollbackOperation(ctx context.Context, client *http.Client, cfg Config, store *rollbackoutbox.Store,
	baseDir string, op rollbackoutbox.Operation, nodeKey ed25519.PrivateKey) (rollbackoutbox.Operation, error) {
	executor := rollbackexecutor.Executor{
		Enabled:   true,
		Store:     store,
		Publisher: rollbackexecutor.RealPublisher{},
		Prober:    staticRollbackProber{hostname: op.Hostname, path: op.HealthCheckPath},
		Reporter: staticRollbackReporter{client: client, config: artifactclient.Config{
			ControlPlaneURL: cfg.ControlPlaneURL, NodeIdentity: cfg.NodeIdentity, PrivateKey: nodeKey,
		}},
	}
	return executor.Execute(ctx, baseDir, op)
}

func localRollbackOperationExists(store *rollbackoutbox.Store, operationID string) (bool, error) {
	operations, err := store.List()
	if err != nil {
		return false, err
	}
	for _, operation := range operations {
		if operation.ID == operationID {
			return true, nil
		}
	}
	return false, nil
}

func resumeLocalRollbackOutbox(ctx context.Context, client *http.Client, cfg Config,
	store *rollbackoutbox.Store, nodeKey ed25519.PrivateKey) error {
	operations, err := store.List()
	if err != nil {
		return fmt.Errorf("list durable rollback operations: %w", err)
	}
	for _, op := range operations {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if op.State == "reported" || op.State == "blocked" {
			continue
		}
		if op.NodeID != cfg.NodeIdentity {
			return fmt.Errorf("rollback operation %s belongs to another node identity", op.ID)
		}
		baseDir := filepath.Join(cfg.PublisherRoot, "accounts", op.HostingAccountID)
		if err := verifyPrivateDirectory(baseDir); err != nil {
			fmt.Fprintf(os.Stderr, "rollback operation %s: %v\n", op.ID, err)
			continue
		}
		if _, err := executeRollbackOperation(ctx, client, cfg, store, baseDir, op, nodeKey); err != nil {
			fmt.Fprintf(os.Stderr, "resume rollback operation %s (state=%s): %v\n", op.ID, op.State, err)
		}
	}
	return nil
}

type staticRollbackProber struct {
	hostname string
	path     string
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
		OperationID:          op.ID,
		FailedDeploymentID:   op.FailedDeploymentID,
		TargetDeploymentID:   op.TargetDeploymentID,
		TargetArtifactSHA256: op.ArtifactSHA256,
		HTTPStatus:           result.HTTPStatus,
		DurationMs:           result.DurationMs,
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
