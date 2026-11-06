package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	fmAtRemovedir     = 0x200
	fmRenameNoReplace = 1
)

func fmParts(path string, allowRoot bool) ([]string, error) {
	if path == "" && allowRoot {
		return nil, nil
	}
	if path == "" || len(path) > 1024 || strings.HasPrefix(path, "/") || strings.Contains(path, "\\") {
		return nil, fmt.Errorf("INVALID_PATH: file path is invalid")
	}
	parts := strings.Split(path, "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || len(p) > 128 {
			return nil, fmt.Errorf("INVALID_PATH: file path contains an invalid component")
		}
		for _, r := range p {
			if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' ||
				r >= '0' && r <= '9' || strings.ContainsRune("._ -", r)) {
				return nil, fmt.Errorf("INVALID_PATH: file path contains an invalid component")
			}
		}
	}
	return parts, nil
}

func fmOpenDir(rootFD int, parts []string) (int, error) {
	fd, err := syscall.Dup(rootFD)
	if err != nil {
		return -1, err
	}
	syscall.CloseOnExec(fd)

	for _, part := range parts {
		next, e := syscall.Openat(fd, part,
			syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		_ = syscall.Close(fd)
		if e != nil {
			return -1, e
		}
		fd = next
	}
	return fd, nil
}

func fmParent(rootFD int, path string) (int, string, error) {
	parts, err := fmParts(path, false)
	if err != nil {
		return -1, "", err
	}
	fd, err := fmOpenDir(rootFD, parts[:len(parts)-1])
	if err != nil {
		return -1, "", fmt.Errorf("INVALID_PATH: parent directory does not exist")
	}
	return fd, parts[len(parts)-1], nil
}

func fmInspect(parentFD int, name string) (*syscall.Stat_t, error) {
	fd, err := syscall.Openat(parentFD, name,
		linuxOPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func fmRenameat2(oldFD int, oldName string, newFD int, newName string, flags uintptr) error {
	var number uintptr
	switch runtime.GOARCH {
	case "amd64":
		number = 316
	case "arm64":
		number = 276
	default:
		return fmt.Errorf("renameat2 is unsupported on this architecture")
	}

	oldPtr, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	newPtr, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(number,
		uintptr(oldFD), uintptr(unsafe.Pointer(oldPtr)),
		uintptr(newFD), uintptr(unsafe.Pointer(newPtr)),
		flags, 0)
	runtime.KeepAlive(oldPtr)
	runtime.KeepAlive(newPtr)
	if errno != 0 {
		return errno
	}
	return nil
}

func fmUnlinkat(dirFD int, name string, flags uintptr) error {
	var number uintptr
	switch runtime.GOARCH {
	case "amd64":
		number = 263
	case "arm64":
		number = 35
	default:
		return fmt.Errorf("unlinkat is unsupported on this architecture")
	}

	ptr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(number,
		uintptr(dirFD), uintptr(unsafe.Pointer(ptr)), flags, 0, 0, 0)
	runtime.KeepAlive(ptr)
	if errno != 0 {
		return errno
	}
	return nil
}

func secureFileManagerOperation(input request, root string, quarantineFD int, writeResult func(any) error) error {
	rootFD, err := syscall.Open(root,
		syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("FILE_ROOT_UNAVAILABLE: document root is unavailable")
	}
	defer syscall.Close(rootFD)

	switch input.FileOperation {
	case "LIST_FILES":
		parts, err := fmParts(input.Path, true)
		if err != nil {
			return err
		}
		fd, err := fmOpenDir(rootFD, parts)
		if err != nil {
			return fmt.Errorf("NOT_A_DIRECTORY: selected path is not a directory")
		}
		dir := os.NewFile(uintptr(fd), "file-manager-list")
		items, err := dir.ReadDir(-1)
		_ = dir.Close()
		if err != nil {
			return fmt.Errorf("DIRECTORY_READ_FAILED: unable to read directory")
		}

		entries := make([]managedFileEntry, 0, 1000)
		for _, item := range items {
			st, e := fmInspectEntry(rootFD, parts, item.Name())
			if e != nil || st.Mode&syscall.S_IFMT == syscall.S_IFLNK {
				continue
			}
			kind := st.Mode & syscall.S_IFMT
			if kind != syscall.S_IFREG && kind != syscall.S_IFDIR {
				continue
			}
			entries = append(entries, managedFileEntry{
				Name: item.Name(), IsDir: kind == syscall.S_IFDIR,
				Size:       st.Size,
				ModifiedAt: time.Unix(st.Mtim.Sec, st.Mtim.Nsec).UTC().Format(time.RFC3339),
			})
			if len(entries) == 1000 {
				break
			}
		}
		return writeResult(map[string]any{"path": input.Path, "entries": entries})

	case "READ_FILE":
		parent, name, err := fmParent(rootFD, input.Path)
		if err != nil {
			return err
		}
		defer syscall.Close(parent)

		fd, err := syscall.Openat(parent, name,
			syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("FILE_READ_FAILED: unable to read selected file")
		}
		file := os.NewFile(uintptr(fd), "file-manager-read")
		defer file.Close()

		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
			return fmt.Errorf("NOT_A_FILE: selected path is not a regular file")
		}
		if st.Size > maxManagedFileBytes {
			return fmt.Errorf("FILE_TOO_LARGE: files larger than 256 KiB cannot be opened in the editor")
		}
		data, err := io.ReadAll(io.LimitReader(file, maxManagedFileBytes+1))
		if err != nil {
			return fmt.Errorf("FILE_READ_FAILED: unable to read selected file")
		}
		if len(data) > maxManagedFileBytes {
			return fmt.Errorf("FILE_TOO_LARGE: files larger than 256 KiB cannot be opened in the editor")
		}
		return writeResult(map[string]any{
			"path": input.Path, "contentBase64": base64.StdEncoding.EncodeToString(data), "size": len(data),
		})

	case "WRITE_FILE":
		data, err := base64.StdEncoding.DecodeString(input.ContentBase64)
		if err != nil || len(data) > maxManagedFileBytes {
			return fmt.Errorf("INVALID_FILE_CONTENT: file content is invalid or exceeds 256 KiB")
		}
		parent, name, err := fmParent(rootFD, input.Path)
		if err != nil {
			return err
		}
		defer syscall.Close(parent)

		if st, e := fmInspect(parent, name); e == nil {
			if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
				return fmt.Errorf("NOT_A_FILE: only regular files can be edited")
			}
		} else if !errors.Is(e, syscall.ENOENT) {
			return fmt.Errorf("FILE_WRITE_FAILED: unable to inspect destination")
		}

		random := make([]byte, 12)
		if _, err := rand.Read(random); err != nil {
			return fmt.Errorf("FILE_WRITE_FAILED: unable to create temporary file")
		}
		tmpName := ".nexora-file-" + hex.EncodeToString(random)
		fd, err := syscall.Openat(parent, tmpName,
			syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
		if err != nil {
			return fmt.Errorf("FILE_WRITE_FAILED: unable to create temporary file")
		}
		tmp := os.NewFile(uintptr(fd), "file-manager-temp")
		defer fmUnlinkat(parent, tmpName, 0)

		if _, err := tmp.Write(data); err != nil {
			_ = tmp.Close()
			return fmt.Errorf("FILE_WRITE_FAILED: unable to write file content")
		}
		if err := tmp.Chmod(0640); err != nil {
			_ = tmp.Close()
			return fmt.Errorf("FILE_WRITE_FAILED: unable to set file permissions")
		}
		if err := tmp.Sync(); err != nil {
			_ = tmp.Close()
			return fmt.Errorf("FILE_WRITE_FAILED: unable to sync file content")
		}
		if err := tmp.Close(); err != nil {
			return fmt.Errorf("FILE_WRITE_FAILED: unable to close file")
		}
		if err := fmRenameat2(parent, tmpName, parent, name, 0); err != nil {
			return fmt.Errorf("FILE_WRITE_FAILED: unable to replace file")
		}
		return writeResult(map[string]any{"success": true, "path": input.Path, "size": len(data)})

	case "CREATE_DIRECTORY":
		parent, name, err := fmParent(rootFD, input.Path)
		if err != nil {
			return err
		}
		defer syscall.Close(parent)
		if _, err := fmInspect(parent, name); err == nil {
			return fmt.Errorf("PATH_EXISTS: a file or directory already exists at this path")
		} else if !errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("DIRECTORY_CREATE_FAILED: unable to inspect destination")
		}
		if err := syscall.Mkdirat(parent, name, 0750); err != nil {
			return fmt.Errorf("DIRECTORY_CREATE_FAILED: unable to create directory")
		}
		return writeResult(map[string]any{"success": true, "path": input.Path})

	case "RENAME_PATH":
		oldParent, oldName, err := fmParent(rootFD, input.Path)
		if err != nil {
			return err
		}
		defer syscall.Close(oldParent)
		newParent, newName, err := fmParent(rootFD, input.NewPath)
		if err != nil {
			return err
		}
		defer syscall.Close(newParent)

		st, err := fmInspect(oldParent, oldName)
		if errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("FILE_NOT_FOUND: source does not exist")
		}
		if err != nil || st.Mode&syscall.S_IFMT == syscall.S_IFLNK ||
			(st.Mode&syscall.S_IFMT != syscall.S_IFREG && st.Mode&syscall.S_IFMT != syscall.S_IFDIR) {
			return fmt.Errorf("RENAME_FAILED: unable to safely inspect selected item")
		}
		if _, err := fmInspect(newParent, newName); err == nil {
			return fmt.Errorf("PATH_EXISTS: destination already exists")
		} else if !errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("RENAME_FAILED: unable to inspect destination")
		}
		if err := fmRenameat2(oldParent, oldName, newParent, newName, fmRenameNoReplace); err != nil {
			if errors.Is(err, syscall.EEXIST) {
				return fmt.Errorf("PATH_EXISTS: destination already exists")
			}
			return fmt.Errorf("RENAME_FAILED: unable to rename selected item")
		}
		return writeResult(map[string]any{"success": true, "path": input.NewPath})

	case "DELETE_PATH":
		if err := secureFileManagerDelete(rootFD, quarantineFD, input.Path); err != nil {
			return err
		}
		return writeResult(map[string]any{"success": true, "path": input.Path})

	default:
		return fmt.Errorf("INVALID_FILE_OPERATION: unsupported file manager operation")
	}
}

func fmInspectEntry(rootFD int, parts []string, name string) (*syscall.Stat_t, error) {
	fd, err := fmOpenDir(rootFD, parts)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)
	return fmInspect(fd, name)
}
