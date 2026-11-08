package releasepublisher

import (
	"os"
	"path/filepath"
	"testing"
)

func testLayout(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	for _, name := range []string{"staging", "releases"} {
		if err := os.Mkdir(filepath.Join(base, name), 0700); err != nil { t.Fatal(err) }
	}
	return base
}

func writeStage(t *testing.T, base, id string) {
	t.Helper()
	stage := filepath.Join(base, "staging", id)
	if err := os.Mkdir(stage, 0700); err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(stage, "index.html"), []byte("safe"), 0600); err != nil { t.Fatal(err) }
}

func TestPublishMovesImmutableReleaseAndActivatesAtomically(t *testing.T) {
	base := testLayout(t)
	writeStage(t, base, "stage-1")
	if err := Publish(base, "stage-1", "release-1"); err != nil { t.Fatal(err) }
	active := filepath.Join(base, "current")
	target, err := os.Readlink(active)
	if err != nil { t.Fatal(err) }
	if target != filepath.Join("releases", "release-1") { t.Fatalf("unexpected active target %q", target) }
	if _, err := os.Stat(filepath.Join(base, "releases", "release-1", "index.html")); err != nil { t.Fatal(err) }
	if _, err := os.Lstat(filepath.Join(base, "staging", "stage-1")); !os.IsNotExist(err) { t.Fatal("staging directory was not moved") }
}

func TestPublishRejectsExistingReleaseWithoutOverwriting(t *testing.T) {
	base := testLayout(t)
	writeStage(t, base, "stage-1")
	if err := os.Mkdir(filepath.Join(base, "releases", "release-1"), 0700); err != nil { t.Fatal(err) }
	if err := Publish(base, "stage-1", "release-1"); err == nil { t.Fatal("existing release was overwritten") }
	if _, err := os.Stat(filepath.Join(base, "staging", "stage-1", "index.html")); err != nil { t.Fatal("staging release was lost") }
}

func TestActivateSupportsRollbackToPreviousRelease(t *testing.T) {
	base := testLayout(t)
	for _, id := range []string{"release-old", "release-new"} {
		if err := os.Mkdir(filepath.Join(base, "releases", id), 0700); err != nil { t.Fatal(err) }
	}
	if err := Activate(base, "release-new"); err != nil { t.Fatal(err) }
	if err := Activate(base, "release-old"); err != nil { t.Fatal(err) }
	target, err := os.Readlink(filepath.Join(base, "current"))
	if err != nil { t.Fatal(err) }
	if target != filepath.Join("releases", "release-old") { t.Fatalf("rollback target = %q", target) }
}

func TestActivateRejectsNonSymlinkCurrentAndSymlinkRelease(t *testing.T) {
	t.Run("regular current path", func(t *testing.T) {
		base := testLayout(t)
		if err := os.WriteFile(filepath.Join(base, "current"), []byte("not a link"), 0600); err != nil { t.Fatal(err) }
		if err := os.Mkdir(filepath.Join(base, "releases", "release-1"), 0700); err != nil { t.Fatal(err) }
		if err := Activate(base, "release-1"); err == nil { t.Fatal("regular current path was replaced") }
	})
	t.Run("symlink release", func(t *testing.T) {
		base := testLayout(t)
		outside := t.TempDir()
		if err := os.Symlink(outside, filepath.Join(base, "releases", "release-1")); err != nil { t.Fatal(err) }
		if err := Activate(base, "release-1"); err == nil { t.Fatal("symlink release target was activated") }
	})
}

func TestPublishRejectsUnsafeIdentifiersAndWritableStaging(t *testing.T) {
	base := testLayout(t)
	writeStage(t, base, "stage-1")
	if err := Publish(base, "../escape", "release-1"); err == nil { t.Fatal("path traversal release ID was accepted") }
	if err := os.Chmod(filepath.Join(base, "staging", "stage-1"), 0770); err != nil { t.Fatal(err) }
	if err := Publish(base, "stage-1", "release-1"); err == nil { t.Fatal("group-writable staging directory was accepted") }
}

func TestActivateRejectsWritableReleaseDirectory(t *testing.T) {
	for _, mode := range []os.FileMode{0770, 0707} {
		t.Run(mode.String(), func(t *testing.T) {
			base := testLayout(t)
			release := filepath.Join(base, "releases", "release-unsafe")
			if err := os.Mkdir(release, 0700); err != nil { t.Fatal(err) }
			if err := os.Chmod(release, mode); err != nil { t.Fatal(err) }
			if err := Activate(base, "release-unsafe"); err == nil {
				t.Fatal("group/world-writable release directory was activated")
			}
			if _, err := os.Lstat(filepath.Join(base, "current")); !os.IsNotExist(err) {
				t.Fatal("unsafe release unexpectedly changed active symlink")
			}
		})
	}
}

func TestRollbackOnlySwitchesExpectedFailedReleaseAndIsIdempotent(t *testing.T) {
	base := testLayout(t)
	for _, id := range []string{"release-old", "release-failed", "release-newer"} {
		if err := os.Mkdir(filepath.Join(base, "releases", id), 0700); err != nil { t.Fatal(err) }
	}
	if err := Activate(base, "release-failed"); err != nil { t.Fatal(err) }
	if err := Rollback(base, "release-failed", "release-old"); err != nil { t.Fatal(err) }
	target, err := os.Readlink(filepath.Join(base, "current"))
	if err != nil { t.Fatal(err) }
	if target != filepath.Join("releases", "release-old") { t.Fatalf("rollback target = %q", target) }
	if err := Rollback(base, "release-failed", "release-old"); err != nil {
		t.Fatalf("retry of completed rollback should be idempotent: %v", err)
	}
}

func TestRollbackRefusesToOverwriteANewerDeployment(t *testing.T) {
	base := testLayout(t)
	for _, id := range []string{"release-old", "release-failed", "release-newer"} {
		if err := os.Mkdir(filepath.Join(base, "releases", id), 0700); err != nil { t.Fatal(err) }
	}
	if err := Activate(base, "release-newer"); err != nil { t.Fatal(err) }
	if err := Rollback(base, "release-failed", "release-old"); err == nil {
		t.Fatal("stale rollback unexpectedly replaced a newer active release")
	}
	target, err := os.Readlink(filepath.Join(base, "current"))
	if err != nil { t.Fatal(err) }
	if target != filepath.Join("releases", "release-newer") {
		t.Fatalf("stale rollback changed active target to %q", target)
	}
}

func TestRollbackRejectsUnsafeActivationLock(t *testing.T) {
	base := testLayout(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(base, ".activation.lock")); err != nil { t.Fatal(err) }
	if err := Rollback(base, "release-failed", "release-old"); err == nil {
		t.Fatal("symlink activation lock was accepted")
	}
}
