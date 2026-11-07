package ocisupervisor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRunner struct {
	calls [][]string
	rootless string
	failStart bool
	createOutput string
}

func (f *fakeRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	copied := append([]string(nil), args...)
	f.calls = append(f.calls, copied)
	if len(args) >= 1 && args[0] == "info" {
		return []byte(f.rootless), nil
	}
	if len(args) >= 1 && args[0] == "create" {
		if f.createOutput != "" { return []byte(f.createOutput), nil }
		return []byte("0123456789abcdef0123456789abcdef"), nil
	}
	if len(args) >= 1 && args[0] == "start" && f.failStart {
		return nil, errors.New("synthetic start failure")
	}
	return []byte("ok"), nil
}

func validSpec(t *testing.T) Spec {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "release")
	if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
	return Spec{
		WorkloadID: "workload-123",
		ReleaseID: "release-123",
		ImageDigest: "registry.example.com/nexora/app@sha256:" + strings.Repeat("a", 64),
		ReleaseDir: dir,
		HostPort: 18080,
		ContainerPort: 8080,
		CPUMillis: 500,
		MemoryMiB: 512,
		ProcessLimit: 128,
	}
}

func TestStartUsesRootlessConstrainedPodman(t *testing.T) {
	runner := &fakeRunner{rootless:"true"}
	podman := Podman{Runner:runner, AllowedRegistries:[]string{"registry.example.com"}}
	spec := validSpec(t)
	id, err := podman.Start(context.Background(), spec)
	if err != nil { t.Fatal(err) }
	if id != "0123456789abcdef0123456789abcdef" { t.Fatalf("unexpected container ID %q", id) }
	if len(runner.calls) != 3 { t.Fatalf("expected info/create/start calls, got %d", len(runner.calls)) }
	create := strings.Join(runner.calls[1], " ")
	for _, required := range []string{
		"--read-only", "--cap-drop ALL", "--security-opt no-new-privileges",
		"--userns keep-id:uid=10001,gid=10001", "--user 10001:10001", "--pids-limit 128", "--memory 512m",
		"--memory-swap 512m", "--cpus 0.500", "--network slirp4netns",
		"--publish 127.0.0.1:18080:8080", "--ipc private", "--pid private",
		"--log-driver k8s-file", "--log-opt max-size=10mb",
		"dst=/app,ro=true", spec.ImageDigest,
	} {
		if !strings.Contains(create, required) { t.Errorf("create command missing %q: %s", required, create) }
	}
	if strings.Contains(create, "sh -c") || strings.Contains(create, "--privileged") {
		t.Fatalf("unsafe execution option found: %s", create)
	}
}

func TestStartRefusesRootfulPodman(t *testing.T) {
	runner := &fakeRunner{rootless:"false"}
	_, err := (Podman{Runner:runner, AllowedRegistries:[]string{"registry.example.com"}}).Start(context.Background(), validSpec(t))
	if err == nil { t.Fatal("expected rootful Podman to be rejected") }
	if len(runner.calls) != 1 { t.Fatalf("container command ran despite rootful mode: %+v", runner.calls) }
}

func TestStartCleansUpIfContainerFailsToStart(t *testing.T) {
	runner := &fakeRunner{rootless:"true", failStart:true}
	_, err := (Podman{Runner:runner, AllowedRegistries:[]string{"registry.example.com"}}).Start(context.Background(), validSpec(t))
	if err == nil { t.Fatal("expected synthetic start failure") }
	if len(runner.calls) != 4 || runner.calls[3][0] != "rm" {
		t.Fatalf("expected failed container cleanup, got %+v", runner.calls)
	}
}

func TestStartRejectsUnsafeSpecs(t *testing.T) {
	tests := map[string]func(*Spec){
		"tagged image": func(s *Spec) { s.ImageDigest = "registry.example.com/app:latest" },
		"non-loopback host bind": func(s *Spec) { s.HostPort = 80 },
		"excessive memory": func(s *Spec) { s.MemoryMiB = 32768 },
		"invalid CPU": func(s *Spec) { s.CPUMillis = 9000 },
		"invalid process limit": func(s *Spec) { s.ProcessLimit = 1024 },
		"path traversal": func(s *Spec) { s.ReleaseDir = "/tmp/../etc" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			runner := &fakeRunner{rootless:"true"}
			spec := validSpec(t)
			mutate(&spec)
			if _, err := (Podman{Runner:runner, AllowedRegistries:[]string{"registry.example.com"}}).Start(context.Background(), spec); err == nil {
				t.Fatal("expected invalid workload specification to be rejected")
			}
			if len(runner.calls) != 0 { t.Fatalf("Podman invoked for invalid spec: %+v", runner.calls) }
		})
	}
}

func TestStartRejectsSymlinkAndWritableReleaseDirectories(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0700); err != nil { t.Fatal(err) }
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil { t.Fatal(err) }
	runner := &fakeRunner{rootless:"true"}
	spec := validSpec(t)
	spec.ReleaseDir = link
	if _, err := (Podman{Runner:runner, AllowedRegistries:[]string{"registry.example.com"}}).Start(context.Background(), spec); err == nil {
		t.Fatal("expected release symlink rejection")
	}
	if err := os.Chmod(real, 0770); err != nil { t.Fatal(err) }
	spec.ReleaseDir = real
	if _, err := (Podman{Runner:runner, AllowedRegistries:[]string{"registry.example.com"}}).Start(context.Background(), spec); err == nil {
		t.Fatal("expected group-writable release directory rejection")
	}
	if len(runner.calls) != 0 { t.Fatalf("Podman invoked for unsafe release directory: %+v", runner.calls) }
}

func TestStopAndRemoveRequireOpaqueContainerIDs(t *testing.T) {
	runner := &fakeRunner{}
	p := Podman{Runner:runner, AllowedRegistries:[]string{"registry.example.com"}}
	if err := p.Stop(context.Background(), "not-a-container"); err == nil { t.Fatal("expected invalid ID rejection") }
	if err := p.Remove(context.Background(), "not-a-container"); err == nil { t.Fatal("expected invalid ID rejection") }
	if len(runner.calls) != 0 { t.Fatalf("Podman invoked for invalid ID: %+v", runner.calls) }
}


func TestStartRejectsNonAllowlistedRegistryBeforePodmanInvocation(t *testing.T) {
	runner := &fakeRunner{rootless:"true"}
	spec := validSpec(t)
	spec.ImageDigest = "untrusted.example.net/nexora/app@sha256:" + strings.Repeat("b", 64)
	p := Podman{Runner:runner, AllowedRegistries:[]string{"registry.example.com"}}
	if _, err := p.Start(context.Background(), spec); err == nil {
		t.Fatal("expected non-allowlisted image registry rejection")
	}
	if len(runner.calls) != 0 { t.Fatalf("Podman invoked for untrusted image registry: %+v", runner.calls) }
}

func TestStartRejectsMalformedContainerIDBeforeStarting(t *testing.T) {
	runner := &fakeRunner{rootless: "true", createOutput: "not-a-container-id"}
	p := Podman{Runner: runner, AllowedRegistries: []string{"registry.example.com"}}
	if _, err := p.Start(context.Background(), validSpec(t)); err == nil {
		t.Fatal("malformed Podman container ID was accepted")
	}
	if len(runner.calls) != 2 || runner.calls[1][0] != "create" {
		t.Fatalf("unexpected lifecycle commands after malformed ID: %+v", runner.calls)
	}
}
