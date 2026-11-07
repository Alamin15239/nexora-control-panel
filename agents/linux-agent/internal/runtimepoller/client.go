package runtimepoller

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/appnodeauth"
)

const desiredStatePath = "/internal/v1/application-nodes/desired-state"
const maxResponseBytes = 1 << 20

type Workload struct {
	WorkloadID string `json:"workloadId"`
	ProjectID string `json:"projectId"`
	WorkloadKind string `json:"workloadKind"`
	WorkloadStatus string `json:"workloadStatus"`
	DesiredReplicas int `json:"desiredReplicas"`
	ObservedReplicas int `json:"observedReplicas"`
	ReleaseID string `json:"releaseId"`
	ReleaseState string `json:"releaseState"`
	ReleaseSpecVersion int `json:"releaseSpecVersion"`
	ImageDigest *string `json:"imageDigest"`
	ArtifactDigest *string `json:"artifactDigest"`
	SettingsSpecVersion int `json:"settingsSpecVersion"`
	RuntimeProfileID string `json:"runtimeProfileId"`
	RuntimeProfileKey string `json:"runtimeProfileKey"`
	RuntimeFamily string `json:"runtimeFamily"`
	ExecutionKind string `json:"executionKind"`
	ListenPort *int `json:"listenPort"`
	CPUMillis int `json:"cpuMillis"`
	MemoryMiB int `json:"memoryMiB"`
	DiskMiB int `json:"diskMiB"`
	ProcessLimit int `json:"processLimit"`
	DesiredState string `json:"desiredState"`
}

type Snapshot struct {
	NodeIdentity string `json:"nodeIdentity"`
	PolledAt time.Time `json:"polledAt"`
	ExecutionEnabled bool `json:"executionEnabled"`
	Workloads []Workload `json:"workloads"`
	CommandsIncluded bool `json:"commandsIncluded"`
	SecretsIncluded bool `json:"secretsIncluded"`
}

type Client struct {
	BaseURL string
	NodeIdentity string
	PrivateKey ed25519.PrivateKey
	HTTPClient *http.Client
	Now func() time.Time
}

func (c *Client) Poll(ctx context.Context) (Snapshot, error) {
	var empty Snapshot
	if len(c.PrivateKey) != ed25519.PrivateKeySize {
		return empty, errors.New("valid application-node Ed25519 private key is required")
	}
	if c.NodeIdentity == "" {
		return empty, errors.New("application-node identity is required")
	}
	base, err := url.Parse(c.BaseURL)
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" ||
		(base.Path != "" && base.Path != "/") {
		return empty, errors.New("control-plane base URL must be an origin without credentials, path, query or fragment")
	}
	if base.Scheme != "https" && !(base.Scheme == "http" && isLoopback(base.Hostname())) {
		return empty, errors.New("control-plane URL must use HTTPS (HTTP is permitted only for loopback tests)")
	}
	now := time.Now()
	if c.Now != nil { now = c.Now() }
	if now.IsZero() { return empty, errors.New("request clock is required") }
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.BaseURL, "/")+desiredStatePath, nil)
	if err != nil { return empty, fmt.Errorf("create desired-state request: %w", err) }
	proof, err := appnodeauth.Sign(c.PrivateKey, c.NodeIdentity, http.MethodGet, desiredStatePath, nil, now)
	if err != nil { return empty, fmt.Errorf("sign desired-state request: %w", err) }
	if err := proof.Apply(req, c.NodeIdentity); err != nil { return empty, err }
	client := c.HTTPClient
	if client == nil { client = &http.Client{Timeout: 15 * time.Second} }
	response, err := client.Do(req)
	if err != nil { return empty, fmt.Errorf("poll runtime desired state: %w", err) }
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil { return empty, fmt.Errorf("read desired-state response: %w", err) }
	if len(body) > maxResponseBytes { return empty, errors.New("desired-state response exceeds the 1 MiB limit") }
	if response.StatusCode != http.StatusOK {
		return empty, fmt.Errorf("desired-state API returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var snapshot Snapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return empty, fmt.Errorf("decode desired-state response: %w", err)
	}
	if snapshot.NodeIdentity != c.NodeIdentity || snapshot.PolledAt.IsZero() ||
		snapshot.ExecutionEnabled || snapshot.CommandsIncluded || snapshot.SecretsIncluded ||
		len(snapshot.Workloads) > 100 {
		return empty, errors.New("desired-state response violates the read-only polling contract")
	}
	seen := make(map[string]struct{}, len(snapshot.Workloads))
	for _, workload := range snapshot.Workloads {
		if workload.WorkloadID == "" || workload.ReleaseID == "" ||
			workload.ReleaseState != "succeeded" ||
			(workload.DesiredState != "running" && workload.DesiredState != "stopped") ||
			workload.DesiredReplicas < 0 || workload.DesiredReplicas > 1 ||
			workload.ObservedReplicas < 0 || workload.ObservedReplicas > 1 ||
			workload.CPUMillis < 100 || workload.CPUMillis > 8000 ||
			workload.MemoryMiB < 128 || workload.MemoryMiB > 16384 ||
			workload.DiskMiB < 128 || workload.DiskMiB > 65536 ||
			workload.ProcessLimit < 16 || workload.ProcessLimit > 512 {
			return empty, errors.New("desired-state workload metadata is outside permitted bounds")
		}
		// Only the first Node.js web profile is admitted. Execution is still
		// disabled by the control plane and enforced as read-only by this client.
		if workload.RuntimeProfileKey != "nodejs-v1" ||
			workload.RuntimeFamily != "nodejs" ||
			workload.ExecutionKind != "oci" ||
			workload.WorkloadKind != "web" ||
			workload.ListenPort == nil || *workload.ListenPort != 3000 ||
			workload.ImageDigest == nil || !validImmutableOCIImage(*workload.ImageDigest) ||
			workload.ReleaseSpecVersion < 1 || workload.SettingsSpecVersion < 1 {
			return empty, errors.New("workload does not satisfy the nodejs-v1 immutable web-image contract")
		}
		if _, exists := seen[workload.WorkloadID]; exists {
			return empty, errors.New("desired-state response contains duplicate workload identifiers")
		}
		seen[workload.WorkloadID] = struct{}{}
	}
	return snapshot, nil
}

// validImmutableOCIImage accepts a registry-qualified, digest-pinned image
// reference. Mutable tags and malformed digest suffixes are never admitted.
func validImmutableOCIImage(ref string) bool {
	parts := strings.Split(ref, "@sha256:")
	if len(parts) != 2 || len(parts[1]) != 64 || strings.ToLower(parts[1]) != parts[1] {
		return false
	}
	for _, ch := range parts[1] {
		if !(ch >= '0' && ch <= '9') && !(ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	name := parts[0]
	slash := strings.IndexByte(name, '/')
	if slash <= 0 || slash == len(name)-1 || strings.ContainsAny(name, " \t\r\n@") {
		return false
	}
	registry := name[:slash]
	if strings.ContainsAny(registry, "?#") || strings.HasPrefix(registry, ".") || strings.HasSuffix(registry, ".") {
		return false
	}
	for _, segment := range strings.Split(name[slash+1:], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") { return true }
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
