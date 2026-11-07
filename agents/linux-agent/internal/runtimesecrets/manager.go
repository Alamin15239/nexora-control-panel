// Package runtimesecrets materializes immutable per-release secret bundles as
// owner-only files. Secret values are never placed in environment variables or
// process command-line arguments.
package runtimesecrets

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"syscall"
)

var workloadIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$`)
var bundleIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$`)
var secretNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

const maxSecretValueBytes = 64 << 10
const maxSecretBundleBytes = 256 << 10
const maxSecretCount = 64

type Manager struct { root string }

func Open(root string) (*Manager, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("secret root must be an absolute clean path")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0077 != 0 || !ownedByCurrentUser(info) {
		return nil, errors.New("secret root must be a real owner-only directory owned by the runtime service")
	}
	return &Manager{root: root}, nil
}

// Materialize writes a new immutable bundle directory and returns its path.
// Existing bundle IDs are never overwritten. The caller must obtain the map
// only from an authenticated, authorized secret-delivery channel.
func (m *Manager) Materialize(workloadID, bundleID string, secrets map[string][]byte) (string, error) {
	if m == nil || !workloadIDPattern.MatchString(workloadID) || !bundleIDPattern.MatchString(bundleID) {
		return "", errors.New("invalid workload or secret bundle identifier")
	}
	if len(secrets) == 0 || len(secrets) > maxSecretCount {
		return "", errors.New("secret bundle must contain between 1 and 64 entries")
	}
	total := 0
	names := make([]string, 0, len(secrets))
	for name, value := range secrets {
		if !secretNamePattern.MatchString(name) || len(value) == 0 || len(value) > maxSecretValueBytes {
			return "", errors.New("secret bundle contains an invalid name or value size")
		}
		total += len(value)
		if total > maxSecretBundleBytes { return "", errors.New("secret bundle exceeds 256 KiB") }
		names = append(names, name)
	}
	sort.Strings(names)

	workloadDir := filepath.Join(m.root, workloadID)
	if err := os.Mkdir(workloadDir, 0700); err != nil && !os.IsExist(err) {
		return "", fmt.Errorf("create workload secret directory: %w", err)
	}
	if err := validatePrivateDir(workloadDir); err != nil { return "", err }

	finalDir := filepath.Join(workloadDir, bundleID)
	if _, err := os.Lstat(finalDir); err == nil {
		return "", errors.New("secret bundle identifier already exists")
	} else if !os.IsNotExist(err) {
		return "", err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil { return "", fmt.Errorf("generate secret staging name: %w", err) }
	staging := filepath.Join(workloadDir, ".staging-"+hex.EncodeToString(nonce))
	if err := os.Mkdir(staging, 0700); err != nil { return "", err }
	committed := false
	defer func() { if !committed { _ = os.RemoveAll(staging) } }()

	for _, name := range names {
		path := filepath.Join(staging, name)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
		if err != nil { return "", fmt.Errorf("create secret file %q: %w", name, err) }
		if _, err := file.Write(secrets[name]); err != nil { _ = file.Close(); return "", fmt.Errorf("write secret file %q: %w", name, err) }
		if err := file.Sync(); err != nil { _ = file.Close(); return "", fmt.Errorf("sync secret file %q: %w", name, err) }
		if err := file.Close(); err != nil { return "", fmt.Errorf("close secret file %q: %w", name, err) }
	}
	dir, err := os.Open(staging)
	if err != nil { return "", err }
	err = dir.Sync()
	closeErr := dir.Close()
	if err != nil { return "", err }
	if closeErr != nil { return "", closeErr }
	if err := os.Rename(staging, finalDir); err != nil { return "", fmt.Errorf("publish immutable secret bundle: %w", err) }
	parent, err := os.Open(workloadDir)
	if err != nil { return "", err }
	err = parent.Sync()
	closeErr = parent.Close()
	if err != nil { return "", err }
	if closeErr != nil { return "", closeErr }
	committed = true
	return finalDir, nil
}

func (m *Manager) Validate(workloadID, bundleID, path string) error {
	if m == nil || !workloadIDPattern.MatchString(workloadID) || !bundleIDPattern.MatchString(bundleID) ||
		path != filepath.Join(m.root, workloadID, bundleID) {
		return errors.New("secret directory is not assigned to this workload bundle")
	}
	if err := validatePrivateDir(path); err != nil { return err }
	entries, err := os.ReadDir(path)
	if err != nil { return err }
	if len(entries) == 0 || len(entries) > maxSecretCount { return errors.New("secret bundle has an invalid entry count") }
	for _, entry := range entries {
		if !secretNamePattern.MatchString(entry.Name()) || entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return errors.New("secret bundle contains an unsafe file entry")
		}
		info, err := entry.Info()
		if err != nil || info.Mode().Perm() != 0400 || info.Size() == 0 || info.Size() > maxSecretValueBytes {
			return errors.New("secret bundle file permissions or size are invalid")
		}
	}
	return nil
}

func validatePrivateDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0077 != 0 || !ownedByCurrentUser(info) {
		return errors.New("secret directory must be a real owner-only directory owned by the runtime service")
	}
	return nil
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
