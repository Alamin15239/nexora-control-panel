// Package artifactreceiver composes deployment authorization, artifact integrity,
// archive validation, private extraction, and immutable release storage.
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
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	ReleaseID string
	ArtifactSHA256 string
	ArtifactBytes int64
	Archive deployarchive.Result
	AlreadyPublished bool
	// SignedEnvelope is retained only in memory so the privileged vhost broker
	// can independently verify the exact control-plane authorization.
	SignedEnvelope string
}

const releaseManifestName = ".nexora-release.json"

type releaseManifest struct {
	Version int `json:"version"`
	ReleaseID string `json:"releaseId"`
	ArtifactSHA256 string `json:"artifactSha256"`
	ArtifactBytes int64 `json:"artifactBytes"`
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
	if err := request.Replay.Consume(ctx, claims.JWTID, time.Unix(claims.ExpiresAt, 0)); err != nil {
		return result, fmt.Errorf("consume deployment authorization: %w", err)
	}
	if request.OnValidated != nil {
		if err := request.OnValidated(ctx, claims, archiveResult); err != nil {
			return result, fmt.Errorf("report validated deployment archive: %w", err)
		}
	}

	alreadyPublished, err := reconcilePublishedRelease(
		request.BaseDir, claims.DeploymentID, digestHex, claims.ArtifactBytes,
	)
	if err != nil {
		return result, err
	}
	if alreadyPublished {
		// A retry verifies the immutable release only. It must never reactivate
		// a release that may have failed health checks and been rolled back.
		return Result{
			DeploymentID: claims.DeploymentID,
			ReleaseID: claims.DeploymentID,
			ArtifactSHA256: digestHex,
			ArtifactBytes: claims.ArtifactBytes,
			Archive: archiveResult,
			AlreadyPublished: true,
			SignedEnvelope: request.Token,
		}, nil
	}

	stageIDBytes := make([]byte, 16)
	if _, err := rand.Read(stageIDBytes); err != nil {
		return result, fmt.Errorf("generate private staging identifier: %w", err)
	}
	stageID := "artifact-" + hex.EncodeToString(stageIDBytes)
	stagePath := filepath.Join(stagingRoot, stageID)
	// The parent staging directory must be setgid and group-owned by the web-server read group.
	// This keeps the release readable by the static origin without granting it write access.
	if err := os.Mkdir(stagePath, 0750); err != nil {
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
	if err := prepareStaticTree(stagePath); err != nil {
		return result, fmt.Errorf("prepare static files for read-only web serving: %w", err)
	}
	if err := writeReleaseManifest(stagePath, claims.DeploymentID, digestHex, claims.ArtifactBytes); err != nil {
		return result, fmt.Errorf("write publisher release manifest: %w", err)
	}
	if err := releasepublisher.Store(request.BaseDir, stageID, request.Expected.DeploymentID); err != nil {
		return result, fmt.Errorf("store immutable release: %w", err)
	}
	published = true
	return Result{
		DeploymentID: claims.DeploymentID,
		ReleaseID: claims.DeploymentID,
		ArtifactSHA256: digestHex,
		ArtifactBytes: claims.ArtifactBytes,
		Archive: extracted,
		SignedEnvelope: request.Token,
	}, nil
}



 // prepareStaticTree exposes only validated regular website files to the
 // configured read-only web-server group. It never follows links or preserves
 // permissions supplied by the archive.
func prepareStaticTree(root string) error {
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil { return walkErr }
		info, err := os.Lstat(path)
		if err != nil { return err }
		if info.Mode()&os.ModeSymlink != 0 { return errors.New("symbolic link appeared in validated staging tree") }
		if entry.IsDir() {
			if path == root { return nil }
			return os.Chmod(path, 0755)
		}
		if !info.Mode().IsRegular() || path == filepath.Join(root, releaseManifestName) {
			if path == filepath.Join(root, releaseManifestName) { return nil }
			return errors.New("staging tree contains a non-regular file")
		}
		return os.Chmod(path, 0644)
	}); err != nil { return err }
	return os.Chmod(root, 02750)
}

func writeReleaseManifest(stagePath, releaseID, digest string, artifactBytes int64) error {
	manifest := releaseManifest{Version: 1, ReleaseID: releaseID, ArtifactSHA256: digest, ArtifactBytes: artifactBytes}
	data, err := json.Marshal(manifest)
	if err != nil { return fmt.Errorf("encode release manifest: %w", err) }
	path := filepath.Join(stagePath, releaseManifestName)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil { return fmt.Errorf("create release manifest: %w", err) }
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write release manifest: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync release manifest: %w", err)
	}
	if err := file.Close(); err != nil { return fmt.Errorf("close release manifest: %w", err) }
	dir, err := os.Open(stagePath)
	if err != nil { return fmt.Errorf("open staging release directory: %w", err) }
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil { return fmt.Errorf("sync staging release directory: %w", syncErr) }
	if closeErr != nil { return fmt.Errorf("close staging release directory: %w", closeErr) }
	return nil
}

// reconcilePublishedRelease permits a retry only when the existing immutable
// release contains a publisher-owned manifest matching the exact verified artifact.
// If a previous attempt moved the release but failed before activation, retrying
// completes that activation without overwriting the release contents.
func reconcilePublishedRelease(baseDir, releaseID, digest string, artifactBytes int64) (bool, error) {
	releasePath := filepath.Join(baseDir, "releases", releaseID)
	info, err := os.Lstat(releasePath)
	if errors.Is(err, os.ErrNotExist) { return false, nil }
	if err != nil { return false, fmt.Errorf("inspect existing immutable release: %w", err) }
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return false, errors.New("existing release path is not a private real directory")
	}
	manifestPath := filepath.Join(releasePath, releaseManifestName)
	manifestInfo, err := os.Lstat(manifestPath)
	if err != nil {
		return false, errors.New("existing release has no trusted publisher manifest; refusing overwrite")
	}
	if !manifestInfo.Mode().IsRegular() || manifestInfo.Mode()&os.ModeSymlink != 0 || manifestInfo.Mode().Perm()&0077 != 0 {
		return false, errors.New("existing release manifest is not a private regular file")
	}
	data, err := os.ReadFile(manifestPath)
	if err != nil { return false, fmt.Errorf("read existing release manifest: %w", err) }
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest releaseManifest
	if err := decoder.Decode(&manifest); err != nil { return false, fmt.Errorf("decode existing release manifest: %w", err) }
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return false, errors.New("existing release manifest contains trailing data")
	}
	if manifest.Version != 1 || manifest.ReleaseID != releaseID ||
		manifest.ArtifactSHA256 != digest || manifest.ArtifactBytes != artifactBytes {
		return false, errors.New("existing release manifest does not match the verified deployment artifact")
	}
	// Existing immutable content is recognized without changing the active release.
	return true, nil
}
