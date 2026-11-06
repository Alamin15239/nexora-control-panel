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
