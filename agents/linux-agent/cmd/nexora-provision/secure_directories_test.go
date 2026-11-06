package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func openTestDirectory(t *testing.T, path string) int {
	t.Helper()

	fd, err := syscall.Open(
		path,
		syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	return fd
}

func TestEnsureDirectoryChainAtCreatesOwnedDirectories(t *testing.T) {
	root := t.TempDir()
	rootFD := openTestDirectory(t, root)
	defer syscall.Close(rootFD)

	owner := directoryOwner{uid: os.Getuid(), gid: os.Getgid()}
	err := ensureDirectoryChainAt(
		rootFD,
		[]string{"account", "public_html"},
		[]directoryOwner{owner, owner},
	)
	if err != nil {
		t.Fatalf("expected secure directory creation: %v", err)
	}

	for _, path := range []string{
		filepath.Join(root, "account"),
		filepath.Join(root, "account", "public_html"),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatal("expected syscall.Stat_t")
		}
		if int(stat.Uid) != owner.uid || int(stat.Gid) != owner.gid {
			t.Fatalf("unexpected ownership for %s: %d:%d", path, stat.Uid, stat.Gid)
		}
		if info.Mode().Perm() != 0750 {
			t.Fatalf("unexpected permissions for %s: %o", path, info.Mode().Perm())
		}
	}
}

func TestEnsureDirectoryChainAtRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}

	rootFD := openTestDirectory(t, root)
	defer syscall.Close(rootFD)

	owner := directoryOwner{uid: os.Getuid(), gid: os.Getgid()}
	err := ensureDirectoryChainAt(
		rootFD,
		[]string{"linked", "child"},
		[]directoryOwner{owner, owner},
	)
	if err == nil {
		t.Fatal("expected symlink component to be rejected")
	}
	if _, err := os.Lstat(filepath.Join(target, "child")); !os.IsNotExist(err) {
		t.Fatalf("symlink target was unexpectedly modified: %v", err)
	}
}

func TestEnsureDirectoryChainAtRejectsUnexpectedOwnership(t *testing.T) {
	root := t.TempDir()
	rootFD := openTestDirectory(t, root)
	defer syscall.Close(rootFD)

	owner := directoryOwner{uid: os.Getuid() + 1, gid: os.Getgid()}
	err := ensureDirectoryChainAt(
		rootFD,
		[]string{"account"},
		[]directoryOwner{owner},
	)
	if err == nil {
		t.Fatal("expected unexpected directory ownership to be rejected")
	}
}

func TestEnsureDirectoryChainAtRejectsWritableDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "writable"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "writable"), 0777); err != nil {
		t.Fatal(err)
	}

	rootFD := openTestDirectory(t, root)
	defer syscall.Close(rootFD)

	owner := directoryOwner{uid: os.Getuid(), gid: os.Getgid()}
	err := ensureDirectoryChainAt(
		rootFD,
		[]string{"writable"},
		[]directoryOwner{owner},
	)
	if err == nil {
		t.Fatal("expected group/world-writable directory to be rejected")
	}
}
