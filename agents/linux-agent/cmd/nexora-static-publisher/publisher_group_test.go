package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The systemd unit sets www-data as the publisher's primary group. Account
// directories must inherit that GID so Nginx can traverse the active release
// tree without granting the web server write access.
func TestProvisionedReleaseDirectoriesUsePublisherPrimaryGroup(t *testing.T) {
	root := testAccountsRoot(t)
	base, err := provisionAccountDirectories(root, "account_group_test")
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{
		base,
		filepath.Join(base, "staging"),
		filepath.Join(base, "releases"),
	} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatalf("%s has no Unix ownership metadata", path)
		}
		if stat.Gid != uint32(os.Getegid()) {
			t.Errorf("%s group ID = %d, want publisher primary GID %d", path, stat.Gid, os.Getegid())
		}
		if info.Mode().Perm()&0050 != 0050 {
			t.Errorf("%s does not grant its owning group read/traverse access: %v", path, info.Mode())
		}
		if info.Mode().Perm()&0020 != 0 {
			t.Errorf("%s is group-writable: %v", path, info.Mode())
		}
	}
}
