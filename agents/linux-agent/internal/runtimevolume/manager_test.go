package runtimevolume

import (
	"os"
	"path/filepath"
	"testing"
)

func newManager(t *testing.T) (*Manager, string) {
	t.Helper()
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0700); err != nil { t.Fatal(err) }
	if err := os.Chmod(parent, 0700); err != nil { t.Fatal(err) }
	manager, err := Open(filepath.Join(parent, "volumes"))
	if err != nil { t.Fatal(err) }
	return manager, parent
}

func TestProvisionCreatesStablePrivateWorkloadVolume(t *testing.T) {
	manager, _ := newManager(t)
	first, err := manager.Provision("workload-123")
	if err != nil { t.Fatal(err) }
	second, err := manager.Provision("workload-123")
	if err != nil { t.Fatal(err) }
	if first != second { t.Fatalf("volume path changed: %q != %q", first, second) }
	info, err := os.Lstat(first)
	if err != nil { t.Fatal(err) }
	if info.Mode().Perm() != 0700 { t.Fatalf("volume mode = %o, want 700", info.Mode().Perm()) }
	if err := manager.Validate("workload-123", first); err != nil { t.Fatal(err) }
}

func TestProvisionRejectsInvalidWorkloadID(t *testing.T) {
	manager, _ := newManager(t)
	for _, id := range []string{"../escape", "ab", "workload/a", ""} {
		if _, err := manager.Provision(id); err == nil { t.Errorf("accepted invalid workload ID %q", id) }
	}
}

func TestOpenRejectsUnsafeParentAndRootSymlink(t *testing.T) {
	root := t.TempDir()
	unsafe := filepath.Join(root, "unsafe")
	if err := os.Mkdir(unsafe, 0777); err != nil { t.Fatal(err) }
	if err := os.Chmod(unsafe, 0777); err != nil { t.Fatal(err) }
	if _, err := Open(filepath.Join(unsafe, "volumes")); err == nil { t.Fatal("unsafe parent accepted") }

	parent := filepath.Join(root, "private")
	if err := os.Mkdir(parent, 0700); err != nil { t.Fatal(err) }
	real := filepath.Join(parent, "real")
	if err := os.Mkdir(real, 0700); err != nil { t.Fatal(err) }
	link := filepath.Join(parent, "volumes")
	if err := os.Symlink(real, link); err != nil { t.Fatal(err) }
	if _, err := Open(link); err == nil { t.Fatal("volume root symlink accepted") }
}

func TestValidateRejectsPathTraversalAndSymlink(t *testing.T) {
	manager, parent := newManager(t)
	if err := manager.Validate("workload-123", filepath.Join(parent, "other")); err == nil {
		t.Fatal("unassigned data path accepted")
	}
	real := filepath.Join(manager.root, "real")
	if err := os.Mkdir(real, 0700); err != nil { t.Fatal(err) }
	link := filepath.Join(manager.root, "workload-123")
	if err := os.Symlink(real, link); err != nil { t.Fatal(err) }
	if err := manager.Validate("workload-123", link); err == nil { t.Fatal("symlink workload volume accepted") }
}

func TestRemoveEmptyNeverRecursivelyDeletesCustomerData(t *testing.T) {
	manager, _ := newManager(t)
	path, err := manager.Provision("workload-123")
	if err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(path, "keep.txt"), []byte("customer data"), 0600); err != nil { t.Fatal(err) }
	if err := manager.RemoveEmpty("workload-123"); err == nil { t.Fatal("non-empty customer volume was removed") }
	if _, err := os.Stat(filepath.Join(path, "keep.txt")); err != nil { t.Fatal("customer data was deleted") }
	if err := os.Remove(filepath.Join(path, "keep.txt")); err != nil { t.Fatal(err) }
	if err := manager.RemoveEmpty("workload-123"); err != nil { t.Fatal(err) }
	if _, err := os.Lstat(path); !os.IsNotExist(err) { t.Fatalf("empty volume still exists: %v", err) }
}
