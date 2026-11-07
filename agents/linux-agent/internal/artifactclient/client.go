// Package artifactclient downloads a deployment artifact using per-node Ed25519 authentication.
package artifactclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/appnodeauth"
)

const (
	ArtifactRequestPath = "/internal/v1/application-nodes/artifact"
	ArtifactValidationReportPath = "/internal/v1/application-nodes/releases/validated"
	ArtifactActivationReportPath = "/internal/v1/application-nodes/releases/activated"
	DefaultMaxArtifactBytes int64 = 100 << 20
	maxEnvelopeBytes = 8 << 10
)

type Config struct {
	ControlPlaneURL string
	NodeIdentity string
	PrivateKey ed25519.PrivateKey
	MaxArtifactBytes int64
	Purpose string
}

type Download struct {
	Envelope string
	Artifact []byte
	SHA256 string
}

// Fetch authenticates a runtime node request, downloads only its assigned release
// from the control plane, and validates the transport digest. The returned
// envelope must still be verified by artifactreceiver.Receive before extraction.
func Fetch(ctx context.Context, client *http.Client, cfg Config, deploymentID string) (Download, error) {
	var result Download
	if len(cfg.PrivateKey) != ed25519.PrivateKeySize {
		return result, errors.New("application-node Ed25519 private key is invalid")
	}
	if cfg.NodeIdentity == "" || deploymentID == "" || len(deploymentID) > 128 {
		return result, errors.New("node identity and deployment ID are required")
	}
	base, err := url.Parse(strings.TrimRight(cfg.ControlPlaneURL, "/"))
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil ||
		base.RawQuery != "" || base.Fragment != "" || base.Path != "" {
		return result, errors.New("control plane URL must be an HTTPS origin without a path")
	}
	maxBytes := cfg.MaxArtifactBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxArtifactBytes
	}
	if maxBytes > DefaultMaxArtifactBytes {
		return result, errors.New("configured artifact size limit exceeds the platform maximum")
	}

	if cfg.Purpose != "" && cfg.Purpose != "validate" && cfg.Purpose != "publish" {
		return result, errors.New("artifact request purpose must be validate or publish")
	}
	body, err := json.Marshal(struct {
		DeploymentID string `json:"deploymentId"`
		Purpose string `json:"purpose,omitempty"`
	}{DeploymentID: deploymentID, Purpose: cfg.Purpose})
	if err != nil {
		return result, fmt.Errorf("encode artifact request: %w", err)
	}
	proof, err := appnodeauth.Sign(cfg.PrivateKey, cfg.NodeIdentity, http.MethodPost,
		ArtifactRequestPath, body, time.Now().UTC())
	if err != nil {
		return result, fmt.Errorf("sign artifact request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String()+ArtifactRequestPath, bytes.NewReader(body))
	if err != nil {
		return result, fmt.Errorf("create artifact request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if err := proof.Apply(request, cfg.NodeIdentity); err != nil {
		return result, fmt.Errorf("apply node proof: %w", err)
	}

	activeClient := client
	if activeClient == nil {
		activeClient = &http.Client{Timeout: 2 * time.Minute}
	}
	safeClient := *activeClient
	// Never forward node credentials to a redirect target.
	safeClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := safeClient.Do(request)
	if err != nil {
		return result, fmt.Errorf("request deployment artifact: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return result, fmt.Errorf("artifact endpoint returned %s: %s", response.Status,
			strings.TrimSpace(string(message)))
	}

	envelope := response.Header.Get("X-Nexora-Deployment-Envelope")
	if envelope == "" || len(envelope) > maxEnvelopeBytes {
		return result, errors.New("artifact response has no valid deployment envelope")
	}
	expectedDigest := response.Header.Get("X-Nexora-Artifact-SHA256")
	if len(expectedDigest) != 64 || strings.ToLower(expectedDigest) != expectedDigest {
		return result, errors.New("artifact response has no valid SHA-256 header")
	}
	if _, err := hex.DecodeString(expectedDigest); err != nil {
		return result, errors.New("artifact response SHA-256 header is malformed")
	}
	if response.ContentLength >= 0 && response.ContentLength > maxBytes {
		return result, errors.New("artifact response exceeds the configured size limit")
	}
	if response.ContentLength >= 0 && response.ContentLength < 1 {
		return result, errors.New("artifact response is empty")
	}
	artifact, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return result, fmt.Errorf("read deployment artifact: %w", err)
	}
	if len(artifact) == 0 || int64(len(artifact)) > maxBytes {
		return result, errors.New("artifact response is empty or exceeds the configured size limit")
	}
	if response.ContentLength >= 0 && int64(len(artifact)) != response.ContentLength {
		return result, errors.New("artifact response length does not match Content-Length")
	}
	digest := sha256.Sum256(artifact)
	actualDigest := hex.EncodeToString(digest[:])
	if actualDigest != expectedDigest {
		return result, errors.New("artifact response SHA-256 does not match its header")
	}
	if response.Header.Get("Content-Type") != "application/gzip" {
		return result, errors.New("artifact response has an unexpected content type")
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		return result, errors.New("artifact response must disable caching")
	}
	if response.Header.Get("X-Content-Type-Options") != "nosniff" {
		return result, errors.New("artifact response must disable MIME sniffing")
	}
	if rawLength := response.Header.Get("Content-Length"); rawLength != "" {
		declared, parseErr := strconv.ParseInt(rawLength, 10, 64)
		if parseErr != nil || declared != int64(len(artifact)) {
			return result, errors.New("artifact response Content-Length is invalid")
		}
	}
	result = Download{Envelope: envelope, Artifact: artifact, SHA256: actualDigest}
	return result, nil
}


type ValidationReport struct {
	DeploymentID string
	ArtifactSHA256 string
	ArchiveEntries int
	ArchiveFiles int
	ArchiveBytes int64
}

// ReportValidated sends a signed, replay-protected report after the local receiver
// has independently validated the envelope, artifact digest, and archive.
func ReportValidated(ctx context.Context, client *http.Client, cfg Config, report ValidationReport) error {
	if len(cfg.PrivateKey) != ed25519.PrivateKeySize {
		return errors.New("application-node Ed25519 private key is invalid")
	}
	if cfg.NodeIdentity == "" || report.DeploymentID == "" ||
		len(report.DeploymentID) > 128 ||
		len(report.ArtifactSHA256) != 64 ||
		strings.ToLower(report.ArtifactSHA256) != report.ArtifactSHA256 ||
		report.ArchiveEntries < 1 || report.ArchiveEntries > 10000 ||
		report.ArchiveFiles < 0 || report.ArchiveFiles > report.ArchiveEntries ||
		report.ArchiveBytes < 0 || report.ArchiveBytes > 500<<20 {
		return errors.New("deployment archive validation report is outside permitted bounds")
	}
	if _, err := hex.DecodeString(report.ArtifactSHA256); err != nil {
		return errors.New("deployment archive validation digest is malformed")
	}
	base, err := url.Parse(strings.TrimRight(cfg.ControlPlaneURL, "/"))
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil ||
		base.RawQuery != "" || base.Fragment != "" || base.Path != "" {
		return errors.New("control plane URL must be an HTTPS origin without a path")
	}
	body, err := json.Marshal(struct {
		DeploymentID string `json:"deploymentId"`
		ArtifactSHA256 string `json:"artifactSha256"`
		ArchiveEntries int `json:"archiveEntries"`
		ArchiveFiles int `json:"archiveFiles"`
		ArchiveBytes int64 `json:"archiveBytes"`
	}{
		DeploymentID: report.DeploymentID,
		ArtifactSHA256: report.ArtifactSHA256,
		ArchiveEntries: report.ArchiveEntries,
		ArchiveFiles: report.ArchiveFiles,
		ArchiveBytes: report.ArchiveBytes,
	})
	if err != nil {
		return fmt.Errorf("encode archive validation report: %w", err)
	}
	proof, err := appnodeauth.Sign(cfg.PrivateKey, cfg.NodeIdentity, http.MethodPost,
		ArtifactValidationReportPath, body, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("sign archive validation report: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		base.String()+ArtifactValidationReportPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create archive validation report request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if err := proof.Apply(request, cfg.NodeIdentity); err != nil {
		return fmt.Errorf("apply node request proof: %w", err)
	}
	activeClient := client
	if activeClient == nil {
		activeClient = &http.Client{Timeout: 30 * time.Second}
	}
	safeClient := *activeClient
	safeClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := safeClient.Do(request)
	if err != nil {
		return fmt.Errorf("submit archive validation report: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("archive validation endpoint returned %s: %s", response.Status,
			strings.TrimSpace(string(message)))
	}
	return nil
}


type ActivationReport struct {
	DeploymentID string
	ReleaseID string
	ArtifactSHA256 string
}

// ReportActivated acknowledges that the verified release directory has been
// atomically activated. It does not claim that the customer process is running
// or healthy; the control plane moves the release only to health_checking.
func ReportActivated(ctx context.Context, client *http.Client, cfg Config, report ActivationReport) error {
	if len(cfg.PrivateKey) != ed25519.PrivateKeySize {
		return errors.New("application-node Ed25519 private key is invalid")
	}
	if cfg.NodeIdentity == "" || !regexpID(report.DeploymentID) || !regexpID(report.ReleaseID) ||
		report.DeploymentID != report.ReleaseID ||
		len(report.ArtifactSHA256) != 64 || strings.ToLower(report.ArtifactSHA256) != report.ArtifactSHA256 {
		return errors.New("release activation report is outside permitted bounds")
	}
	if _, err := hex.DecodeString(report.ArtifactSHA256); err != nil {
		return errors.New("release activation SHA-256 is malformed")
	}
	base, err := url.Parse(strings.TrimRight(cfg.ControlPlaneURL, "/"))
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil ||
		base.RawQuery != "" || base.Fragment != "" || base.Path != "" {
		return errors.New("control plane URL must be an HTTPS origin without a path")
	}
	body, err := json.Marshal(struct {
		DeploymentID string `json:"deploymentId"`
		ReleaseID string `json:"releaseId"`
		ArtifactSHA256 string `json:"artifactSha256"`
	}{
		DeploymentID: report.DeploymentID,
		ReleaseID: report.ReleaseID,
		ArtifactSHA256: report.ArtifactSHA256,
	})
	if err != nil {
		return fmt.Errorf("encode release activation report: %w", err)
	}
	proof, err := appnodeauth.Sign(cfg.PrivateKey, cfg.NodeIdentity, http.MethodPost,
		ArtifactActivationReportPath, body, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("sign release activation report: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		base.String()+ArtifactActivationReportPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create release activation report request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if err := proof.Apply(request, cfg.NodeIdentity); err != nil {
		return fmt.Errorf("apply node request proof: %w", err)
	}
	activeClient := client
	if activeClient == nil {
		activeClient = &http.Client{Timeout: 30 * time.Second}
	}
	safeClient := *activeClient
	safeClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	response, err := safeClient.Do(request)
	if err != nil {
		return fmt.Errorf("submit release activation report: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("release activation endpoint returned %s: %s", response.Status,
			strings.TrimSpace(string(message)))
	}
	return nil
}

func regexpID(value string) bool {
	if value == "" || len(value) > 128 { return false }
	for _, char := range value {
		if !(char >= 'a' && char <= 'z') && !(char >= 'A' && char <= 'Z') &&
			!(char >= '0' && char <= '9') && char != '_' && char != '-' {
			return false
		}
	}
	return true
}
