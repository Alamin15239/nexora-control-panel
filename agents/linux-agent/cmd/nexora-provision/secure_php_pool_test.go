package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteConfigFileAtCreatesSecureFile(t *testing.T) {
	dir := t.TempDir()
	fd := openTestDirectory(t, dir)

	content := "[test]\nuser = test\n"
	if err := writeConfigFileAt(fd, "pool.conf", content, 0640, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(dir, "pool.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0640 {
		t.Fatalf("unexpected file metadata: %v", info.Mode())
	}

	got, err := os.ReadFile(filepath.Join(dir, "pool.conf"))
	if err != nil || string(got) != content {
		t.Fatalf("unexpected file content: %q, error: %v", got, err)
	}
}

func TestWriteConfigFileAtIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	fd := openTestDirectory(t, dir)
	content := "[test]\nuser = test\n"

	if err := writeConfigFileAt(fd, "pool.conf", content, 0640, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	if err := writeConfigFileAt(fd, "pool.conf", content, 0640, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("identical existing configuration should be accepted: %v", err)
	}
}

func TestWriteConfigFileAtRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	fd := openTestDirectory(t, dir)

	if err := os.WriteFile(filepath.Join(dir, "pool.conf"), []byte("customer data"), 0640); err != nil {
		t.Fatal(err)
	}

	err := writeConfigFileAt(fd, "pool.conf", "[test]\n", 0640, os.Getuid(), os.Getgid())
	if err == nil {
		t.Fatal("expected existing different content to be rejected")
	}

	got, err := os.ReadFile(filepath.Join(dir, "pool.conf"))
	if err != nil || string(got) != "customer data" {
		t.Fatalf("existing content changed: %q, error: %v", got, err)
	}
}

func TestWriteConfigFileAtRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	fd := openTestDirectory(t, dir)

	target := filepath.Join(dir, "customer.conf")
	if err := os.WriteFile(target, []byte("customer data"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "pool.conf")); err != nil {
		t.Fatal(err)
	}

	if err := writeConfigFileAt(fd, "pool.conf", "[test]\n", 0640, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("expected symlink to be rejected")
	}
}

func TestWriteConfigFileAtRejectsInvalidNames(t *testing.T) {
	fd := openTestDirectory(t, t.TempDir())

	for _, name := range []string{"", ".", "..", "../pool.conf", "subdir/pool.conf"} {
		if err := writeConfigFileAt(fd, name, "data", 0640, os.Getuid(), os.Getgid()); err == nil {
			t.Errorf("expected invalid filename %q to be rejected", name)
		}
	}
}
