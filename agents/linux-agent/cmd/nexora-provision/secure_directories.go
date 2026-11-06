package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
)

type directoryOwner struct {
	uid int
	gid int
}

// ensureDirectoryChainAt creates and verifies directories relative to an
// already-open directory. Symlinks are never followed.
func ensureDirectoryChainAt(rootFD int, parts []string, owners []directoryOwner) error {
	if len(parts) == 0 || len(parts) != len(owners) {
		return fmt.Errorf("invalid directory chain")
	}

	currentFD, err := syscall.Dup(rootFD)
	if err != nil {
		return fmt.Errorf("unable to duplicate directory descriptor")
	}
	syscall.CloseOnExec(currentFD)
	defer func() {
		_ = syscall.Close(currentFD)
	}()

	for i, part := range parts {
		if part == "" || part == "." || part == ".." ||
			strings.Contains(part, string(filepath.Separator)) {
			return fmt.Errorf("invalid directory component")
		}

		flags := syscall.O_RDONLY | syscall.O_DIRECTORY |
			syscall.O_NOFOLLOW | syscall.O_CLOEXEC

		nextFD, openErr := syscall.Openat(currentFD, part, flags, 0)
		created := false

		if errors.Is(openErr, syscall.ENOENT) {
			mkdirErr := syscall.Mkdirat(currentFD, part, 0750)
			if mkdirErr != nil && !errors.Is(mkdirErr, syscall.EEXIST) {
				return fmt.Errorf("unable to create directory component")
			}
			created = mkdirErr == nil

			nextFD, openErr = syscall.Openat(currentFD, part, flags, 0)
		}

		if openErr != nil {
			return fmt.Errorf("directory component is missing or unsafe")
		}

		if created {
			if err := syscall.Fchown(nextFD, owners[i].uid, owners[i].gid); err != nil {
				_ = syscall.Close(nextFD)
				return fmt.Errorf("unable to set new directory ownership")
			}
			if err := syscall.Fchmod(nextFD, 0750); err != nil {
				_ = syscall.Close(nextFD)
				return fmt.Errorf("unable to set new directory permissions")
			}
		}

		var stat syscall.Stat_t
		if err := syscall.Fstat(nextFD, &stat); err != nil {
			_ = syscall.Close(nextFD)
			return fmt.Errorf("unable to verify directory component")
		}

		if stat.Mode&syscall.S_IFMT != syscall.S_IFDIR ||
			int(stat.Uid) != owners[i].uid ||
			int(stat.Gid) != owners[i].gid ||
			stat.Mode&0022 != 0 {
			_ = syscall.Close(nextFD)
			return fmt.Errorf("directory has unexpected type, ownership, or permissions")
		}

		_ = syscall.Close(currentFD)
		currentFD = nextFD
	}

	return nil
}

// ensureSafeDirectory securely creates a document root beneath one hosting
// account's home. /home must be root-owned and not group/world writable.
func ensureSafeDirectory(home, target string, uid, gid int) error {
	if uid < 1000 || gid < 0 ||
		filepath.Clean(home) != home ||
		filepath.Clean(target) != target ||
		!filepath.IsAbs(target) {
		return fmt.Errorf("PATH_CONFLICT: invalid hosting directory path or identity")
	}

	username := filepath.Base(home)
	if home != filepath.Join("/home", username) ||
		!usernamePattern.MatchString(username) {
		return fmt.Errorf("PATH_CONFLICT: invalid hosting home path")
	}

	rel, err := filepath.Rel(home, target)
	if err != nil || rel == ".." ||
		strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("INVALID_DOCUMENT_ROOT: document root must remain inside the account home")
	}

	parts := []string{"home", username}
	owners := []directoryOwner{
		{uid: 0, gid: 0},
		{uid: uid, gid: gid},
	}

	if rel != "." {
		for _, part := range strings.Split(rel, string(filepath.Separator)) {
			if part == "" || part == "." || part == ".." {
				return fmt.Errorf("PATH_CONFLICT: invalid document-root component")
			}
			parts = append(parts, part)
			owners = append(owners, directoryOwner{uid: uid, gid: gid})
		}
	}

	rootFD, err := syscall.Open(
		"/",
		syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
		0,
	)
	if err != nil {
		return fmt.Errorf("PATH_CONFLICT: unable to open filesystem root")
	}
	defer syscall.Close(rootFD)

	if err := ensureDirectoryChainAt(rootFD, parts, owners); err != nil {
		return fmt.Errorf("PATH_CONFLICT: hosting directory is unsafe or has unexpected ownership or permissions")
	}

	return nil
}
