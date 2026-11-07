// Package artifactreceiver composes deployment authorization, artifact integrity,
// archive validation, private extraction, and atomic release activation.
//
// This is an offline publisher primitive, not a network service. A future receiver
// must authenticate the node, independently load deployment ownership from the
// control plane, and provide a durable one-time JTI store before calling Receive.
// It never executes customer code.
package artifactreceiver

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/deployarchive"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/deployenvelope"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/releasepublisher"
)

type ReplayGuard interface {
	// Consume must atomically persist jti until expiresAt and reject an existing value.
	Consume(ctx context.Context, jti string, expiresAt time.Time) error
}

type Request struct {
	Token    string
	Artifact []byte
	Expected deployenvelope.Expected
	Keys     map[string]*rsa.PublicKey
	BaseDir  string
	Now      time.Time
	Limits   deployarchive.Limits
	Replay      ReplayGuard
	OnValidated func(context.Context, deployenvelope.Claims, deployarchive.Result) error
}

type Result struct {
	DeploymentID string
	ReleaseID    string
	ArtifactSHA256 string
	ArtifactBytes int64
	Archive      deployarchive.Result
}

// Receive verifies a short-lived signed envelope against independently supplied
// deployment identity, verifies the complete artifact digest and archive, consumes
// the envelope JTI, extracts into a new private staging directory, and publishes
// an immutable release. BaseDir and all its parents must be operator-owned and
// inaccessible to untrusted local users. The caller owns durable replay storage.
func Receive(ctx context.Context, request Request) (Result, error) {
	var result Result
	if request.Replay == nil {
		return result, errors.New("durable deployment replay guard is required")
	}
	if request.Now.IsZero() {
		return result, errors.New("verification time must be supplied explicitly")
	}
	if len(request.Artifact) == 0 || int64(len(request.Artifact)) > 100<<20 {
		return result, errors.New("artifact size is outside the permitted range")
	}
	if !releasepublisher.IsReleaseID(request.Expected.DeploymentID) {
		return result, errors.New("deployment identifier cannot be used as a release identifier")
	}

	claims, err := deployenvelope.Verify(request.Token, request.Keys, request.Expected, request.Now)
	if err != nil {
		return result, fmt.Errorf("verify deployment authorization: %w", err)
	}
	if int64(len(request.Artifact)) != claims.ArtifactBytes {
		return result, errors.New("artifact byte count does not match signed deployment envelope")
	}
	digest := sha256.Sum256(request.Artifact)
	digestHex := hex.EncodeToString(digest[:])
	if digestHex != claims.ArtifactSHA256 {
		return result, errors.New("artifact SHA-256 does not match signed deployment envelope")
	}

	archiveResult, err := deployarchive.ValidateGzipTar(bytes.NewReader(request.Artifact), request.Limits)
	if err != nil {
		return result, fmt.Errorf("validate deployment archive: %w", err)
	}

	if !filepath.IsAbs(request.BaseDir) {
		return result, errors.New("publisher base directory must be absolute")
	}
	baseInfo, err := os.Lstat(request.BaseDir)
	if err != nil || !baseInfo.IsDir() || baseInfo.Mode()&os.ModeSymlink != 0 || baseInfo.Mode().Perm()&0022 != 0 {
		return result, errors.New("publisher base directory must be a real, private operator-owned directory")
	}
	stagingRoot := filepath.Join(request.BaseDir, "staging")
	stagingInfo, err := os.Lstat(stagingRoot)
	if err != nil || !stagingInfo.IsDir() || stagingInfo.Mode()&os.ModeSymlink != 0 || stagingInfo.Mode().Perm()&0022 != 0 {
		return result, errors.New("publisher staging directory must be a real, non-writable-by-others directory")
	}
	releasesRoot := filepath.Join(request.BaseDir, "releases")
	releasesInfo, err := os.Lstat(releasesRoot)
	if err != nil || !releasesInfo.IsDir() || releasesInfo.Mode()&os.ModeSymlink != 0 || releasesInfo.Mode().Perm()&0022 != 0 {
		return result, errors.New("publisher releases directory must be a real, non-writable-by-others directory")
	}
	if request.OnValidated != nil {
		if err := request.OnValidated(ctx, claims, archiveResult); err != nil {
			return result, fmt.Errorf("report validated deployment archive: %w", err)
		}
	}

	if err := request.Replay.Consume(ctx, claims.JWTID, time.Unix(claims.ExpiresAt, 0)); err != nil {
		return result, fmt.Errorf("consume deployment authorization: %w", err)
	}

	stageIDBytes := make([]byte, 16)
	if _, err := rand.Read(stageIDBytes); err != nil {
		return result, fmt.Errorf("generate private staging identifier: %w", err)
	}
	stageID := "artifact-" + hex.EncodeToString(stageIDBytes)
	stagePath := filepath.Join(stagingRoot, stageID)
	if err := os.Mkdir(stagePath, 0700); err != nil {
		return result, fmt.Errorf("create private staging directory: %w", err)
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(stagePath)
		}
	}()

	extracted, err := deployarchive.ExtractGzipTar(bytes.NewReader(request.Artifact), stagePath, request.Limits)
	if err != nil {
		return result, fmt.Errorf("extract validated deployment archive: %w", err)
	}
	if extracted != archiveResult {
		return result, errors.New("archive extraction result differs from pre-publication validation")
	}
	if err := releasepublisher.Publish(request.BaseDir, stageID, request.Expected.DeploymentID); err != nil {
		return result, fmt.Errorf("publish immutable release: %w", err)
	}
	published = true
	return Result{
		DeploymentID: claims.DeploymentID,
		ReleaseID: claims.DeploymentID,
		ArtifactSHA256: digestHex,
		ArtifactBytes: claims.ArtifactBytes,
		Archive: extracted,
	}, nil
}
