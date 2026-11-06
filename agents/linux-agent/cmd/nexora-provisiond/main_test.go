//go:build linux

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestListenProvisionSocketSetsOwnerAndMode(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "provision.sock")
	uid, gid := os.Getuid(), os.Getgid()

	listener, err := listenProvisionSocket(socketPath, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	info, err := os.Lstat(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket path is not a Unix socket: %v", info.Mode())
	}
	if got := info.Mode().Perm(); got != 0660 {
		t.Fatalf("socket mode = %04o, want 0660", got)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("socket stat does not expose Unix ownership")
	}
	if stat.Uid != uint32(uid) || stat.Gid != uint32(gid) {
		t.Fatalf("socket owner = %d:%d, want %d:%d", stat.Uid, stat.Gid, uid, gid)
	}
}

func TestListenProvisionSocketRefusesExistingPath(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(socketPath, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if listener, err := listenProvisionSocket(socketPath, os.Getuid(), os.Getgid()); err == nil {
		if listener != nil {
			_ = listener.Close()
		}
		t.Fatal("expected existing path to be rejected")
	}
	data, err := os.ReadFile(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "keep" {
		t.Fatalf("existing path was modified: %q", data)
	}
}
