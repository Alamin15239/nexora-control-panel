package main

import (
	"os"
	"path/filepath"
	"testing"
)

func testRegistryOwner(t *testing.T) (uint32, uint32) {
	t.Helper()
	return uint32(os.Getuid()), uint32(os.Getgid())
}

func testRegistryPath(t *testing.T) string {
	t.Helper()
	parent := filepath.Join(t.TempDir(), "secure-parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(parent, "registry")
}

func TestRegisterAndReadManagedAccount(t *testing.T) {
	uid, gid := testRegistryOwner(t)
	path := testRegistryPath(t)

	if err := registerManagedAccountAt(path, "client01", 1101, uid, gid); err != nil {
		t.Fatal(err)
	}
	accounts, err := readManagedAccountsAt(path, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 || accounts[0].Username != "client01" || accounts[0].UID != 1101 {
		t.Fatalf("unexpected registered accounts: %#v", accounts)
	}
}

func TestRegisterManagedAccountIsIdempotent(t *testing.T) {
	uid, gid := testRegistryOwner(t)
	path := testRegistryPath(t)

	for i := 0; i < 2; i++ {
		if err := registerManagedAccountAt(path, "client01", 1101, uid, gid); err != nil {
			t.Fatalf("registration %d failed: %v", i, err)
		}
	}
}

func TestRegisterManagedAccountRejectsUIDChange(t *testing.T) {
	uid, gid := testRegistryOwner(t)
	path := testRegistryPath(t)

	if err := registerManagedAccountAt(path, "client01", 1101, uid, gid); err != nil {
		t.Fatal(err)
	}
	if err := registerManagedAccountAt(path, "client01", 1102, uid, gid); err == nil {
		t.Fatal("expected changed UID to be rejected")
	}
}

func TestRegisterManagedAccountRejectsInvalidIdentity(t *testing.T) {
	uid, gid := testRegistryOwner(t)
	path := testRegistryPath(t)

	tests := []struct {
		username   string
		accountUID int
	}{
		{"Invalid!", 1101},
		{"client01", 999},
		{"", 1101},
	}
	for _, tt := range tests {
		if err := registerManagedAccountAt(path, tt.username, tt.accountUID, uid, gid); err == nil {
			t.Errorf("expected invalid identity to be rejected: %#v", tt)
		}
	}
}

func TestReadManagedAccountsRejectsSymlinkMarker(t *testing.T) {
	uid, gid := testRegistryOwner(t)
	path := testRegistryPath(t)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte(`{"version":1,"username":"client01","uid":1101}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(path, "client01.json")); err != nil {
		t.Fatal(err)
	}

	if _, err := readManagedAccountsAt(path, uid, gid); err == nil {
		t.Fatal("expected symlink marker to be rejected")
	}
}

func TestReadManagedAccountsRejectsInvalidMarker(t *testing.T) {
	uid, gid := testRegistryOwner(t)
	path := testRegistryPath(t)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}

	marker := filepath.Join(path, "client01.json")
	if err := os.WriteFile(marker, []byte(`{"version":1,"username":"other01","uid":1101}`), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := readManagedAccountsAt(path, uid, gid); err == nil {
		t.Fatal("expected marker identity mismatch to be rejected")
	}
}

func TestReadManagedAccountsRejectsInsecureDirectory(t *testing.T) {
	uid, gid := testRegistryOwner(t)
	path := testRegistryPath(t)
	if err := os.Mkdir(path, 0755); err != nil {
		t.Fatal(err)
	}

	if _, err := readManagedAccountsAt(path, uid, gid); err == nil {
		t.Fatal("expected insecure directory permissions to be rejected")
	}
}

func TestRegisterManagedAccountRejectsRegistrySymlinkWithoutChangingTarget(t *testing.T) {
	uid, gid := testRegistryOwner(t)
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0755); err != nil {
		t.Fatal(err)
	}
	link := testRegistryPath(t)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	err := registerManagedAccountAt(link, "client01", 1101, uid, gid)
	if err == nil {
		t.Fatal("expected registry symlink to be rejected")
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Fatalf("symlink target permissions changed: %o", info.Mode().Perm())
	}
}

func TestRegisterManagedAccountRejectsInsecureParent(t *testing.T) {
	uid, gid := testRegistryOwner(t)
	parent := filepath.Join(t.TempDir(), "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "registry")

	if err := registerManagedAccountAt(path, "client01", 1101, uid, gid); err == nil {
		t.Fatal("expected insecure parent directory to be rejected")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("registry should not have been created; stat error: %v", err)
	}
}
