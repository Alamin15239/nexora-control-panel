package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func openDocumentDirectory(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, fmt.Errorf("invalid document directory")
	}

	if path == "/" {
		return syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	}

	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return -1, fmt.Errorf("invalid document directory component")
		}
	}

	return openDirectoryChain("/", parts...)
}

func writeIndexDescriptor(fd int, name string, uid, gid int) error {
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = syscall.Close(fd)
		return fmt.Errorf("unable to wrap index descriptor")
	}

	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()

	if _, err := file.WriteString(defaultIndexHTML); err != nil {
		return fmt.Errorf("unable to write index page")
	}
	if err := file.Chown(uid, gid); err != nil {
		return fmt.Errorf("unable to set index ownership")
	}
	if err := file.Chmod(0640); err != nil {
		return fmt.Errorf("unable to set index permissions")
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("unable to sync index page")
	}
	if err := file.Close(); err != nil {
		closed = true
		return fmt.Errorf("unable to close index page")
	}
	closed = true
	return nil
}

// createDefaultIndexAt creates index.html without following symlinks and
// without replacing an existing customer file.
func createDefaultIndexAt(dirFD int, uid, gid int) error {
	fd, err := syscall.Openat(
		dirFD,
		"index.html",
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|
			syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
		0640,
	)
	if errors.Is(err, syscall.EEXIST) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("unable to create index page")
	}

	if err := writeIndexDescriptor(fd, "index.html", uid, gid); err != nil {
		// Do not unlink by name: another process may have replaced this entry.
		return err
	}
	return nil
}

func upgradeLegacyDefaultIndex(documentRoot string, uid, gid int) error {
	// Legacy pages are deliberately not replaced automatically. This check
	// only verifies that an existing index is a regular file and not a symlink.
	dirFD, err := openDocumentDirectory(documentRoot)
	if err != nil {
		return fmt.Errorf("DEFAULT_PAGE_CHECK_FAILED: unable to securely open the document root")
	}
	defer syscall.Close(dirFD)

	indexFD, err := syscall.Openat(
		dirFD,
		"index.html",
		syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC,
		0,
	)
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("DEFAULT_PAGE_CHECK_FAILED: unable to securely open index.html")
	}
	defer syscall.Close(indexFD)

	var stat syscall.Stat_t
	if err := syscall.Fstat(indexFD, &stat); err != nil {
		return fmt.Errorf("DEFAULT_PAGE_CHECK_FAILED: unable to inspect index.html")
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return fmt.Errorf("DEFAULT_PAGE_CONFLICT: refusing a non-regular index.html")
	}

	// Keep the parameters for compatibility with existing callers.
	_, _ = uid, gid
	return nil
}

// createDefaultIndexForEmptyDomain creates a starter homepage only when the
// opened document root is empty. Existing customer files are never overwritten.
func createDefaultIndexForEmptyDomain(documentRoot string, uid, gid int) error {
	dirFD, err := openDocumentDirectory(documentRoot)
	if err != nil {
		return fmt.Errorf("DEFAULT_PAGE_CHECK_FAILED: unable to securely open the document root")
	}
	defer syscall.Close(dirFD)

	// Open "." relative to dirFD to obtain a fresh directory stream.
	readFD, err := syscall.Openat(
		dirFD,
		".",
		syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
		0,
	)
	if err != nil {
		return fmt.Errorf("DEFAULT_PAGE_CHECK_FAILED: unable to inspect the document root")
	}

	dirFile := os.NewFile(uintptr(readFD), documentRoot)
	if dirFile == nil {
		_ = syscall.Close(readFD)
		return fmt.Errorf("DEFAULT_PAGE_CHECK_FAILED: unable to inspect the document root")
	}
	entries, readErr := dirFile.ReadDir(-1)
	closeErr := dirFile.Close()
	if readErr != nil || closeErr != nil {
		return fmt.Errorf("DEFAULT_PAGE_CHECK_FAILED: unable to inspect the document root")
	}
	if len(entries) != 0 {
		return nil
	}

	if err := createDefaultIndexAt(dirFD, uid, gid); err != nil {
		return fmt.Errorf("DEFAULT_PAGE_FAILED: unable to create the initial domain homepage")
	}
	return nil
}
