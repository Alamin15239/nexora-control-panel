// Package runtimevolume manages per-workload persistent data directories.
package runtimevolume

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
)

var workloadIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$`)

// Manager owns a private root containing one persistent data directory per workload.
type Manager struct { root string }

func Open(root string) (*Manager, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("volume root must be an absolute clean path")
	}
	parent := filepath.Dir(root)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 ||
		parentInfo.Mode().Perm()&0077 != 0 || !ownedByCurrentUser(parentInfo) {
		return nil, errors.New("volume root parent must be a private real directory owned by the runtime service")
	}
	if err := os.Mkdir(root, 0700); err != nil && !os.IsExist(err) {
		return nil, fmt.Errorf("create volume root: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0077 != 0 || !ownedByCurrentUser(info) {
		return nil, errors.New("volume root must be a real owner-only directory owned by the runtime service")
	}
	return &Manager{root: root}, nil
}

// Provision creates or validates the stable data directory for one workload.
// Disk-space quotas are intentionally not claimed here; a platform quota backend
// must be installed before customer workloads can be enabled.
func (m *Manager) Provision(workloadID string) (string, error) {
	if m == nil || !workloadIDPattern.MatchString(workloadID) {
		return "", errors.New("invalid workload identifier or volume manager")
	}
	path := filepath.Join(m.root, workloadID)
	if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
		return "", fmt.Errorf("create workload data directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0077 != 0 || !ownedByCurrentUser(info) {
		return "", errors.New("workload data directory must be a real owner-only directory owned by the runtime service")
	}
	return path, nil
}

// Validate rejects paths that are not the exact manager-owned workload directory.
func (m *Manager) Validate(workloadID, path string) error {
	if m == nil || !workloadIDPattern.MatchString(workloadID) ||
		path != filepath.Join(m.root, workloadID) {
		return errors.New("persistent data path is not assigned to this workload")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0077 != 0 || !ownedByCurrentUser(info) {
		return errors.New("persistent data directory failed ownership or permission validation")
	}
	return nil
}

// RemoveEmpty removes only an empty workload directory. It never recursively
// deletes customer data; non-empty directories require a separate retention flow.
func (m *Manager) RemoveEmpty(workloadID string) error {
	if m == nil || !workloadIDPattern.MatchString(workloadID) {
		return errors.New("invalid workload identifier or volume manager")
	}
	path := filepath.Join(m.root, workloadID)
	if err := m.Validate(workloadID, path); err != nil {
		if os.IsNotExist(err) { return nil }
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove empty workload volume: %w", err)
	}
	return nil
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
