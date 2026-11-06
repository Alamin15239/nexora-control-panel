package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestInstallNginxConfigAtCreatesConfigAndLink(t *testing.T) {
	available := t.TempDir()
	enabled := t.TempDir()
	availableFD := openTestDirectory(t, available)
	enabledFD := openTestDirectory(t, enabled)

	name := "nexora-example_test"
	target := filepath.Join(available, name)
	content := "server_name example.test;\nroot /home/test/public_html;\n"

	if err := installNginxConfigForTest(availableFD, enabledFD, name, target, content); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(target)
	if err != nil || string(got) != content {
		t.Fatalf("configuration mismatch: %q, %v", got, err)
	}

	link, err := os.Readlink(filepath.Join(enabled, name))
	if err != nil || link != target {
		t.Fatalf("unexpected enabled link: %q, %v", link, err)
	}

	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0644 {
		t.Fatalf("unexpected config mode: %v, %v", info, err)
	}
}

func TestInstallNginxConfigAtIsIdempotent(t *testing.T) {
	available := t.TempDir()
	enabled := t.TempDir()
	availableFD := openTestDirectory(t, available)
	enabledFD := openTestDirectory(t, enabled)

	name := "nexora-example_test"
	target := filepath.Join(available, name)
	content := "server_name example.test;\n"

	for i := 0; i < 2; i++ {
		if err := installNginxConfigForTest(availableFD, enabledFD, name, target, content); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
}

func TestInstallNginxConfigAtPreservesDifferentConfig(t *testing.T) {
	available := t.TempDir()
	enabled := t.TempDir()
	availableFD := openTestDirectory(t, available)
	enabledFD := openTestDirectory(t, enabled)

	name := "nexora-example_test"
	path := filepath.Join(available, name)
	original := "customer-owned configuration\n"
	if err := os.WriteFile(path, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}

	err := installNginxConfigForTest(
		availableFD,
		enabledFD,
		name,
		path,
		"server_name example.test;\n",
	)
	if err == nil {
		t.Fatal("expected different existing configuration to be rejected")
	}

	got, readErr := os.ReadFile(path)
	if readErr != nil || string(got) != original {
		t.Fatalf("existing configuration was changed: %q, %v", got, readErr)
	}
}

func TestInstallNginxConfigAtRejectsWrongEnabledLink(t *testing.T) {
	available := t.TempDir()
	enabled := t.TempDir()
	availableFD := openTestDirectory(t, available)
	enabledFD := openTestDirectory(t, enabled)

	name := "nexora-example_test"
	target := filepath.Join(available, name)
	if err := os.WriteFile(target, []byte("server_name example.test;\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/some/other/site", filepath.Join(enabled, name)); err != nil {
		t.Fatal(err)
	}

	if err := installNginxConfigForTest(availableFD, enabledFD, name, target, "server_name example.test;\n"); err == nil {
		t.Fatal("expected conflicting enabled link to be rejected")
	}
}

func TestInstallNginxConfigAtRejectsRegularEnabledPath(t *testing.T) {
	available := t.TempDir()
	enabled := t.TempDir()
	availableFD := openTestDirectory(t, available)
	enabledFD := openTestDirectory(t, enabled)

	name := "nexora-example_test"
	target := filepath.Join(available, name)
	if err := os.WriteFile(filepath.Join(enabled, name), []byte("preserve me"), 0644); err != nil {
		t.Fatal(err)
	}

	err := installNginxConfigForTest(availableFD, enabledFD, name, target, "server_name example.test;\n")
	if err == nil {
		t.Fatal("expected regular enabled path to be rejected")
	}

	got, readErr := os.ReadFile(filepath.Join(enabled, name))
	if readErr != nil || string(got) != "preserve me" {
		t.Fatalf("existing enabled file changed: %q, %v", got, readErr)
	}
}

func TestReadlinkAtReportsMissingLink(t *testing.T) {
	dir := t.TempDir()
	fd := openTestDirectory(t, dir)

	_, err := readlinkAt(fd, "missing")
	if err == nil || !errorsIsENOENT(err) {
		t.Fatalf("expected ENOENT, got %v", err)
	}
}

func errorsIsENOENT(err error) bool {
	return err == syscall.ENOENT
}

// Tests use the current process owner; production explicitly uses root.
func installNginxConfigForTest(
	availableFD, enabledFD int,
	configName, target, content string,
) error {
	_, err := installNginxConfigAt(
		availableFD,
		enabledFD,
		configName,
		target,
		content,
		os.Getuid(),
		os.Getgid(),
	)
	return err
}

func TestRollbackNginxInstallRemovesCreatedFiles(t *testing.T) {
	available := t.TempDir()
	enabled := t.TempDir()
	availableFD := openTestDirectory(t, available)
	enabledFD := openTestDirectory(t, enabled)

	name := "nexora-rollback_test"
	target := filepath.Join(available, name)

	state, err := installNginxConfigAt(
		availableFD, enabledFD, name, target,
		"server_name rollback.test;\n", os.Getuid(), os.Getgid(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !state.configCreated || !state.linkCreated {
		t.Fatalf("expected both objects to be newly created: %+v", state)
	}

	if err := rollbackNginxInstallAt(
		availableFD, enabledFD, name, target, state,
	); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}

	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("configuration still exists after rollback: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(enabled, name)); !os.IsNotExist(err) {
		t.Fatalf("enabled link still exists after rollback: %v", err)
	}
}

func TestRollbackNginxInstallPreservesPreexistingFiles(t *testing.T) {
	available := t.TempDir()
	enabled := t.TempDir()
	availableFD := openTestDirectory(t, available)
	enabledFD := openTestDirectory(t, enabled)

	name := "nexora-preserve_test"
	target := filepath.Join(available, name)
	content := "server_name preserve.test;\n"

	firstState, err := installNginxConfigAt(
		availableFD, enabledFD, name, target,
		content, os.Getuid(), os.Getgid(),
	)
	if err != nil {
		t.Fatal(err)
	}

	// A second installation sees the config and matching link as pre-existing.
	secondState, err := installNginxConfigAt(
		availableFD, enabledFD, name, target,
		content, os.Getuid(), os.Getgid(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if secondState.configCreated || !secondState.linkPreexisting {
		t.Fatalf("unexpected second-install state: %+v", secondState)
	}

	if err := rollbackNginxInstallAt(
		availableFD, enabledFD, name, target, secondState,
	); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil || string(got) != content {
		t.Fatalf("pre-existing configuration was not preserved: %q, %v", got, err)
	}

	link, err := os.Readlink(filepath.Join(enabled, name))
	if err != nil || link != target {
		t.Fatalf("pre-existing enabled link was not preserved: %q, %v", link, err)
	}

	// The first invocation created these files; clean them up for test hygiene.
	if err := rollbackNginxInstallAt(
		availableFD, enabledFD, name, target, firstState,
	); err != nil {
		t.Fatalf("initial installation cleanup failed: %v", err)
	}
}

func TestRollbackNginxInstallPreservesChangedLinkAndConfig(t *testing.T) {
	available := t.TempDir()
	enabled := t.TempDir()
	availableFD := openTestDirectory(t, available)
	enabledFD := openTestDirectory(t, enabled)

	name := "nexora-changed-link_test"
	target := filepath.Join(available, name)
	content := "server_name changed.test;\n"

	state, err := installNginxConfigAt(
		availableFD, enabledFD, name, target,
		content, os.Getuid(), os.Getgid(),
	)
	if err != nil {
		t.Fatal(err)
	}

	linkPath := filepath.Join(enabled, name)
	if err := os.Remove(linkPath); err != nil {
		t.Fatal(err)
	}

	changedTarget := "/some/other/site"
	if err := os.Symlink(changedTarget, linkPath); err != nil {
		t.Fatal(err)
	}

	if err := rollbackNginxInstallAt(
		availableFD, enabledFD, name, target, state,
	); err == nil {
		t.Fatal("expected rollback to refuse a changed link")
	}

	link, err := os.Readlink(linkPath)
	if err != nil || link != changedTarget {
		t.Fatalf("changed link was not preserved: %q, %v", link, err)
	}

	got, err := os.ReadFile(target)
	if err != nil || string(got) != content {
		t.Fatalf("configuration referenced by changed link was removed: %q, %v", got, err)
	}
}

func TestInstallNginxConfigAtRemovesNewConfigOnEnabledPathConflict(t *testing.T) {
	available := t.TempDir()
	enabled := t.TempDir()
	availableFD := openTestDirectory(t, available)
	enabledFD := openTestDirectory(t, enabled)

	name := "nexora-conflict_test"
	target := filepath.Join(available, name)

	// A regular enabled path is a conflict and must remain untouched.
	enabledPath := filepath.Join(enabled, name)
	if err := os.WriteFile(enabledPath, []byte("preserve me"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := installNginxConfigAt(
		availableFD, enabledFD, name, target,
		"server_name conflict.test;\n", os.Getuid(), os.Getgid(),
	)
	if err == nil {
		t.Fatal("expected enabled path conflict")
	}

	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("new config was not rolled back after conflict: %v", err)
	}

	got, err := os.ReadFile(enabledPath)
	if err != nil || string(got) != "preserve me" {
		t.Fatalf("conflicting enabled file was changed: %q, %v", got, err)
	}
}
