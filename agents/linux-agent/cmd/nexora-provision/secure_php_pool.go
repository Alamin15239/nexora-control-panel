package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

func openRootOwnedDirectory(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, fmt.Errorf("invalid configuration directory path")
	}

	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}

	check := func(fd int) error {
		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil {
			return err
		}
		if st.Mode&syscall.S_IFMT != syscall.S_IFDIR ||
			st.Uid != 0 || st.Gid != 0 || st.Mode&0022 != 0 {
			return fmt.Errorf("unsafe configuration directory")
		}
		return nil
	}

	if err := check(fd); err != nil {
		syscall.Close(fd)
		return -1, err
	}

	trimmed := strings.TrimPrefix(path, "/")
	if trimmed == "" {
		return fd, nil
	}

	for _, part := range strings.Split(trimmed, "/") {
		if part == "" || part == "." || part == ".." {
			syscall.Close(fd)
			return -1, fmt.Errorf("invalid directory component")
		}

		next, err := syscall.Openat(fd, part,
			syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if err != nil {
			return -1, err
		}
		fd = next

		if err := check(fd); err != nil {
			syscall.Close(fd)
			return -1, err
		}
	}

	return fd, nil
}

func linkAt(oldDirFD int, oldName string, newDirFD int, newName string) error {
	oldPtr, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	newPtr, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}

	_, _, errno := syscall.Syscall6(
		syscall.SYS_LINKAT,
		uintptr(oldDirFD),
		uintptr(unsafe.Pointer(oldPtr)),
		uintptr(newDirFD),
		uintptr(unsafe.Pointer(newPtr)),
		0,
		0,
	)
	runtime.KeepAlive(oldPtr)
	runtime.KeepAlive(newPtr)
	if errno != 0 {
		return errno
	}
	return nil
}

// renameAt wraps the renameat(2) syscall. It atomically renames oldName
// (in oldDirFD) to newName (in newDirFD). When old and new live in the same
// directory and newName already exists, the rename atomically replaces it.
func renameAt(oldDirFD int, oldName string, newDirFD int, newName string) error {
	oldPtr, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	newPtr, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(
		syscall.SYS_RENAMEAT,
		uintptr(oldDirFD),
		uintptr(unsafe.Pointer(oldPtr)),
		uintptr(newDirFD),
		uintptr(unsafe.Pointer(newPtr)),
		0,
		0,
	)
	runtime.KeepAlive(oldPtr)
	runtime.KeepAlive(newPtr)
	if errno != 0 {
		return errno
	}
	return nil
}

func writeConfigFileAt(dirFD int, name, content string, mode uint32, uid, gid int) error {
	_, err := writeConfigFileAtTracked(dirFD, name, content, mode, uid, gid)
	return err
}

// writeConfigFileAtTracked reports whether this call published a new file.
// Existing exact files are never reported as newly created.
func writeConfigFileAtTracked(dirFD int, name, content string, mode uint32, uid, gid int) (bool, error) {
	if name == "" || name == "." || name == ".." ||
		len(name) > 255 || strings.Contains(name, "/") {
		return false, fmt.Errorf("invalid configuration filename")
	}
	if mode&^0777 != 0 || uid < 0 || gid < 0 {
		return false, fmt.Errorf("invalid configuration metadata")
	}
	if len(content) > 1024*1024 {
		return false, fmt.Errorf("configuration exceeds maximum size")
	}

	fd, err := syscall.Openat(dirFD, name,
		syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)

	if err == nil {
		file := os.NewFile(uintptr(fd), name)
		defer file.Close()

		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil {
			return false, err
		}
		if st.Mode&syscall.S_IFMT != syscall.S_IFREG ||
			int(st.Uid) != uid || int(st.Gid) != gid ||
			st.Mode&0777 != mode || st.Size > 1024*1024 {
			return false, fmt.Errorf("existing configuration file has unexpected metadata")
		}

		data, err := io.ReadAll(io.LimitReader(file, 1024*1024+1))
		if err != nil {
			return false, err
		}
		if len(data) > 1024*1024 {
			return false, fmt.Errorf("existing configuration exceeds maximum size")
		}
		if string(data) != content {
			return false, fmt.Errorf("existing configuration differs; refusing overwrite")
		}
		return false, nil
	}

	if !errors.Is(err, syscall.ENOENT) {
		return false, fmt.Errorf("unable to safely inspect configuration file")
	}

	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return false, fmt.Errorf("unable to generate temporary filename")
	}
	tmpName := fmt.Sprintf(".nexora-config-%x", token[:])

	tmpFD, err := syscall.Openat(dirFD, tmpName,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|
			syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return false, fmt.Errorf("unable to create temporary configuration")
	}

	tmp := os.NewFile(uintptr(tmpFD), tmpName)
	defer func() {
		_ = tmp.Close()
		_ = syscall.Unlinkat(dirFD, tmpName)
	}()

	if err := tmp.Chown(uid, gid); err != nil {
		return false, fmt.Errorf("unable to set configuration ownership")
	}
	if err := tmp.Chmod(os.FileMode(mode)); err != nil {
		return false, fmt.Errorf("unable to set configuration permissions")
	}
	if _, err := io.WriteString(tmp, content); err != nil {
		return false, fmt.Errorf("unable to write configuration")
	}
	if err := tmp.Sync(); err != nil {
		return false, fmt.Errorf("unable to sync configuration")
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("unable to close configuration")
	}

	// Publish atomically without replacing an existing file.
	if err := linkAt(dirFD, tmpName, dirFD, name); err != nil {
		if errors.Is(err, syscall.EEXIST) {
			return false, fmt.Errorf("configuration appeared concurrently; refusing overwrite")
		}
		return false, fmt.Errorf("unable to publish configuration atomically")
	}

	// The destination now belongs to this invocation, even if a later
	// durability operation fails. The caller can safely roll it back.
	if err := syscall.Unlinkat(dirFD, tmpName); err != nil {
		return true, fmt.Errorf("configuration published but temporary cleanup failed")
	}
	if err := syscall.Fsync(dirFD); err != nil {
		return true, fmt.Errorf("configuration published but directory sync failed")
	}
	return true, nil
}

func writeRootConfigFile(path, content string, mode uint32) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("invalid configuration file path")
	}

	dirFD, err := openRootOwnedDirectory(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("configuration directory is missing or unsafe")
	}
	defer syscall.Close(dirFD)

	return writeConfigFileAt(dirFD, filepath.Base(path), content, mode, 0, 0)
}

// overwriteConfigFileAt atomically replaces an existing configuration file
// (or creates one if none exists) with the new content. It writes the new
// content to a fresh temp file, syncs it, then renames it over the target.
// The rename is atomic on POSIX filesystems, so readers never observe a
// partial write. If the target already existed, the caller may capture the
// prior content beforehand and pass it to restoreConfigFileAt on rollback.
//
// Unlike writeConfigFileAt (which refuses to overwrite an existing file),
// this function is intended for the update path where overwriting is the
// explicit goal — for example, rewriting an existing PHP-FPM pool config.
// The same hardening rules apply: O_NOFOLLOW on every openat, root-only
// ownership of every directory traversed, O_CREAT|O_EXCL for the temp file,
// and an explicit fsync of the directory after the rename.
func overwriteConfigFileAt(dirFD int, name, content string, mode uint32, uid, gid int) error {
	if name == "" || name == "." || name == ".." ||
		len(name) > 255 || strings.Contains(name, "/") {
		return fmt.Errorf("invalid configuration filename")
	}
	if mode&^0777 != 0 || uid < 0 || gid < 0 {
		return fmt.Errorf("invalid configuration metadata")
	}
	if len(content) > 1024*1024 {
		return fmt.Errorf("configuration exceeds maximum size")
	}

	// Reject if the target is a symlink — we never follow symlinks when
	// rewriting configuration owned by root.
	fd, err := syscall.Openat(dirFD, name,
		syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err == nil {
		var st syscall.Stat_t
		if ferr := syscall.Fstat(fd, &st); ferr != nil {
			syscall.Close(fd)
			return fmt.Errorf("unable to inspect existing configuration: %s", ferr.Error())
		}
		if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
			syscall.Close(fd)
			return fmt.Errorf("existing configuration is not a regular file")
		}
		if int(st.Uid) != uid || int(st.Gid) != gid || st.Mode&0777 != mode {
			syscall.Close(fd)
			return fmt.Errorf("existing configuration has unexpected metadata")
		}
		syscall.Close(fd)
	} else if !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("unable to safely inspect configuration file")
	}

	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return fmt.Errorf("unable to generate temporary filename")
	}
	tmpName := fmt.Sprintf(".nexora-config-%x", token[:])

	tmpFD, err := syscall.Openat(dirFD, tmpName,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|
			syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return fmt.Errorf("unable to create temporary configuration: %s", err.Error())
	}
	tmp := os.NewFile(uintptr(tmpFD), tmpName)
	defer func() {
		_ = tmp.Close()
		// Best-effort cleanup of the temp file if the rename never happened.
		_ = syscall.Unlinkat(dirFD, tmpName)
	}()

	if err := tmp.Chown(uid, gid); err != nil {
		return fmt.Errorf("unable to set configuration ownership: %s", err.Error())
	}
	if err := tmp.Chmod(os.FileMode(mode)); err != nil {
		return fmt.Errorf("unable to set configuration permissions: %s", err.Error())
	}
	if _, err := io.WriteString(tmp, content); err != nil {
		return fmt.Errorf("unable to write configuration: %s", err.Error())
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("unable to sync configuration: %s", err.Error())
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("unable to close configuration: %s", err.Error())
	}

	// Atomically replace the target. renameat(2) is atomic on POSIX
	// filesystems: either the new file fully replaces the old, or the
	// old file remains intact.
	if err := renameAt(dirFD, tmpName, dirFD, name); err != nil {
		return fmt.Errorf("unable to publish configuration atomically: %s", err.Error())
	}
	if err := syscall.Fsync(dirFD); err != nil {
		return fmt.Errorf("configuration published but directory sync failed: %s", err.Error())
	}
	return nil
}

// restoreConfigFileAt writes the supplied backup content back to the named
// file using the same atomic-rename strategy as overwriteConfigFileAt. It is
// intended for rollback paths: if a freshly-applied configuration fails
// validation or reload, the caller restores the previously captured content
// so the on-disk state matches the last known-good service state.
func restoreConfigFileAt(dirFD int, name, content string, mode uint32, uid, gid int) error {
	if content == "" {
		// Nothing to restore — caller had no prior file.
		return nil
	}
	return overwriteConfigFileAt(dirFD, name, content, mode, uid, gid)
}

// overwriteRootConfigFile is the root-owned wrapper around
// overwriteConfigFileAt. It returns the prior file content (if any) so the
// caller can pass it to restoreRootConfigFile on rollback.
func overwriteRootConfigFile(path, content string, mode uint32) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("invalid configuration file path")
	}
	dirFD, err := openRootOwnedDirectory(filepath.Dir(path))
	if err != nil {
		return "", fmt.Errorf("configuration directory is missing or unsafe")
	}
	defer syscall.Close(dirFD)

	// Capture the prior content for rollback. If the file does not exist,
	// priorContent stays empty and restoreRootConfigFile will treat that
	// as "delete the new file" semantics on rollback.
	priorContent, _ := os.ReadFile(path)

	if err := overwriteConfigFileAt(dirFD, filepath.Base(path), content, mode, 0, 0); err != nil {
		return "", err
	}
	return string(priorContent), nil
}

// restoreRootConfigFile writes the supplied backup content back to the named
// path. Used for rollback after a failed validation or reload.
func restoreRootConfigFile(path, backupContent string, mode uint32) error {
	if backupContent == "" {
		return nil
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("invalid configuration file path")
	}
	dirFD, err := openRootOwnedDirectory(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("configuration directory is missing or unsafe")
	}
	defer syscall.Close(dirFD)
	return restoreConfigFileAt(dirFD, filepath.Base(path), backupContent, mode, 0, 0)
}
