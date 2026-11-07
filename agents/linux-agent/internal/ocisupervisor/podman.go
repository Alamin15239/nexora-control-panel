// Package ocisupervisor provides a rootless Podman backend for immutable OCI
// application releases. It is not wired into the agent service yet.
package ocisupervisor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	idPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{2,63}$`)
	imagePattern = regexp.MustCompile(`^[A-Za-z0-9.-]+(?::[0-9]{1,5})?/[A-Za-z0-9._/-]+@sha256:[a-f0-9]{64}$`)
	secretNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	containerIDPattern = regexp.MustCompile(`^[a-f0-9]{12,64}$`)
)

type Spec struct {
	WorkloadID string
	ReleaseID string
	ImageDigest string
	ReleaseDir string
	PersistentDataDir string
	SecretDir string
	HostPort int
	ContainerPort int
	CPUMillis int
	MemoryMiB int
	ProcessLimit int
}

type Runner interface { Run(context.Context, ...string) ([]byte, error) }
type OSRunner struct { Binary string }

func (r OSRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	binary := r.Binary
	if binary == "" { binary = "podman" }
	output, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("podman %s: %w: %s", args[0], err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

type Podman struct { Runner Runner; AllowedRegistries []string }
func (p Podman) runner() Runner { if p.Runner != nil { return p.Runner }; return OSRunner{} }

func validatePersistentDataDir(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path { return errors.New("persistent data directory must be an absolute clean path") }
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("persistent data directory must be a real directory not writable by group or others")
	}
	return nil
}

func validateSecretDir(path string) error {
	if path == "" { return nil }
	if !filepath.IsAbs(path) || filepath.Clean(path) != path { return errors.New("secret directory must be an absolute clean path") }
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return errors.New("secret directory must be a real owner-only directory")
	}
	entries, err := os.ReadDir(path)
	if err != nil { return err }
	if len(entries) > 64 { return errors.New("secret directory contains too many entries") }
	for _, entry := range entries {
		if !secretNamePattern.MatchString(entry.Name()) || entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return errors.New("secret directory contains an unsafe entry")
		}
		fileInfo, err := entry.Info()
		if err != nil || fileInfo.Mode().Perm() != 0400 || fileInfo.Size() == 0 || fileInfo.Size() > 64<<10 {
			return errors.New("secret file must be a non-empty owner-read-only regular file within size limits")
		}
	}
	return nil
}

func validateSpec(spec Spec) error {
	if !idPattern.MatchString(spec.WorkloadID) || !idPattern.MatchString(spec.ReleaseID) { return errors.New("workload and release IDs must be opaque platform identifiers") }
	if !imagePattern.MatchString(spec.ImageDigest) || strings.Contains(spec.ImageDigest, "..") { return errors.New("OCI image must be pinned to a valid sha256 digest") }
	if !filepath.IsAbs(spec.ReleaseDir) || filepath.Clean(spec.ReleaseDir) != spec.ReleaseDir { return errors.New("release directory must be an absolute clean path") }
	info, err := os.Lstat(spec.ReleaseDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 { return errors.New("release directory must be a real directory not writable by group or others") }
	if err := validatePersistentDataDir(spec.PersistentDataDir); err != nil { return err }
	if err := validateSecretDir(spec.SecretDir); err != nil { return err }
	if spec.HostPort < 1024 || spec.HostPort > 65535 || spec.ContainerPort < 1 || spec.ContainerPort > 65535 { return errors.New("assigned host and container ports are outside permitted ranges") }
	if spec.CPUMillis < 100 || spec.CPUMillis > 8000 || spec.MemoryMiB < 128 || spec.MemoryMiB > 16384 || spec.ProcessLimit < 16 || spec.ProcessLimit > 512 {
		return errors.New("runtime resource limits are outside platform bounds")
	}
	return nil
}

func (p Podman) EnsureRootless(ctx context.Context) error {
	output, err := p.runner().Run(ctx, "info", "--format", "{{.Host.Security.Rootless}}")
	if err != nil { return fmt.Errorf("inspect Podman security mode: %w", err) }
	if strings.TrimSpace(string(output)) != "true" { return errors.New("Nexora runtime requires rootless Podman; refusing privileged container execution") }
	return nil
}

// Start creates and starts a constrained container with immutable release,
// per-workload writable data, and optional read-only secret-file mounts.
func (p Podman) Start(ctx context.Context, spec Spec) (string, error) {
	if err := validateSpec(spec); err != nil { return "", err }
	registry := strings.SplitN(spec.ImageDigest, "/", 2)[0]
	allowed := false
	for _, candidate := range p.AllowedRegistries { if candidate == registry { allowed = true; break } }
	if !allowed { return "", errors.New("OCI image registry is not in the operator allowlist") }
	if err := p.EnsureRootless(ctx); err != nil { return "", err }
	name := "nxr-" + spec.WorkloadID
	cpu := fmt.Sprintf("%.3f", float64(spec.CPUMillis)/1000)
	memory := strconv.Itoa(spec.MemoryMiB) + "m"
	args := []string{
		"create", "--name", name,
		"--label", "io.nexora.managed=true",
		"--label", "io.nexora.workload=" + spec.WorkloadID,
		"--label", "io.nexora.release=" + spec.ReleaseID,
		"--network", "slirp4netns",
		"--publish", fmt.Sprintf("127.0.0.1:%d:%d", spec.HostPort, spec.ContainerPort),
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--userns", "keep-id:uid=10001,gid=10001", "--user", "10001:10001",
		"--pids-limit", strconv.Itoa(spec.ProcessLimit),
		"--memory", memory, "--memory-swap", memory, "--cpus", cpu,
		"--init", "--log-driver", "k8s-file", "--log-opt", "max-size=10mb",
		"--ipc", "private", "--pid", "private",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
		"--mount", "type=bind,src=" + spec.ReleaseDir + ",dst=/app,ro=true",
		"--mount", "type=bind,src=" + spec.PersistentDataDir + ",dst=/var/lib/nexora,rw=true",
	}
	if spec.SecretDir != "" { args = append(args, "--mount", "type=bind,src="+spec.SecretDir+",dst=/run/secrets,ro=true") }
	args = append(args, "--workdir", "/app", spec.ImageDigest)
	created, err := p.runner().Run(ctx, args...)
	if err != nil { return "", fmt.Errorf("create constrained workload: %w", err) }
	containerID := strings.TrimSpace(string(created))
	if !containerIDPattern.MatchString(containerID) { return "", errors.New("Podman returned an invalid container identifier; refusing follow-up commands") }
	if _, err := p.runner().Run(ctx, "start", containerID); err != nil {
		_, _ = p.runner().Run(context.Background(), "rm", "--force", containerID)
		return "", fmt.Errorf("start constrained workload: %w", err)
	}
	return containerID, nil
}

func (p Podman) Stop(ctx context.Context, containerID string) error {
	if !containerIDPattern.MatchString(containerID) { return errors.New("invalid container identifier") }
	_, err := p.runner().Run(ctx, "stop", "--time", "10", containerID)
	return err
}
func (p Podman) Remove(ctx context.Context, containerID string) error {
	if !containerIDPattern.MatchString(containerID) { return errors.New("invalid container identifier") }
	_, err := p.runner().Run(ctx, "rm", containerID)
	return err
}
