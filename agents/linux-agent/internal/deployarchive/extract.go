package deployarchive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ExtractGzipTar extracts a previously validated gzip tar into an existing,
// empty, private staging directory. It deliberately does not preserve archive
// ownership, permissions, links, timestamps, or special files.
//
// The caller must create destination exclusively (0700, owned by the publisher)
// and must not expose it to untrusted local processes while extraction runs.
// A separate activation step must publish the completed directory atomically.
func ExtractGzipTar(input io.ReadSeeker, destination string, limits Limits) (Result, error) {
	validationDigest := sha256.New()
	validated, err := ValidateGzipTar(io.TeeReader(input, validationDigest), limits)
	if err != nil {
		return Result{}, fmt.Errorf("validate archive before extraction: %w", err)
	}
	validatedHash := validationDigest.Sum(nil)
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return Result{}, fmt.Errorf("rewind validated archive: %w", err)
	}

	info, err := os.Lstat(destination)
	if err != nil {
		return Result{}, fmt.Errorf("inspect staging directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return Result{}, errors.New("staging destination must be a private, non-symlink directory")
	}
	entries, err := os.ReadDir(destination)
	if err != nil {
		return Result{}, fmt.Errorf("inspect staging directory contents: %w", err)
	}
	if len(entries) != 0 {
		return Result{}, errors.New("staging destination must be empty")
	}

	extractionDigest := sha256.New()
	gz, err := gzip.NewReader(io.TeeReader(input, extractionDigest))
	if err != nil {
		return Result{}, fmt.Errorf("open gzip archive for extraction: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	result := Result{}
	for {
		header, nextErr := tr.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return Result{}, fmt.Errorf("read archive during extraction: %w", nextErr)
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA && header.Typeflag != tar.TypeDir {
			return Result{}, fmt.Errorf("archive entry %q has prohibited type %d", header.Name, header.Typeflag)
		}
		name, rootDirectory, pathErr := normalizeArchivePath(header.Name, header.Typeflag)
		if pathErr != nil {
			return Result{}, pathErr
		}
		if rootDirectory {
			continue
		}
		if header.Size < 0 || header.Size > limitsOrDefault(limits).MaxFileBytes {
			return Result{}, fmt.Errorf("archive entry %q exceeds the per-file size limit", header.Name)
		}

		target := filepath.Join(destination, filepath.FromSlash(name))
		relative, relErr := filepath.Rel(destination, target)
		if relErr != nil || relative == "." || relative == ".." ||
			strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
			return Result{}, fmt.Errorf("archive entry %q escapes staging directory", header.Name)
		}
		parent := filepath.Dir(target)
		if err := os.MkdirAll(parent, 0700); err != nil {
			return Result{}, fmt.Errorf("create staging parent for %q: %w", header.Name, err)
		}
		if err := verifyPrivateDirectoryChain(destination, parent); err != nil {
			return Result{}, err
		}

		result.Entries++
		if result.Entries > limitsOrDefault(limits).MaxEntries {
			return Result{}, errors.New("archive contains too many entries")
		}
		if header.Typeflag == tar.TypeDir {
			if header.Size != 0 {
				return Result{}, fmt.Errorf("directory entry %q has a non-zero size", header.Name)
			}
			if err := os.MkdirAll(target, 0700); err != nil {
				return Result{}, fmt.Errorf("create staging directory %q: %w", header.Name, err)
			}
			continue
		}
		if result.Bytes > limitsOrDefault(limits).MaxTotalBytes-header.Size {
			return Result{}, errors.New("archive exceeds the total expanded size limit")
		}
		file, openErr := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if openErr != nil {
			return Result{}, fmt.Errorf("create staged file %q: %w", header.Name, openErr)
		}
		written, copyErr := io.CopyN(file, tr, header.Size)
		closeErr := file.Close()
		if copyErr != nil {
			return Result{}, fmt.Errorf("extract staged file %q: %w", header.Name, copyErr)
		}
		if closeErr != nil {
			return Result{}, fmt.Errorf("close staged file %q: %w", header.Name, closeErr)
		}
		if written != header.Size {
			return Result{}, fmt.Errorf("staged file %q has an unexpected byte count", header.Name)
		}
		result.Bytes += written
		result.Files++
	}

	buffer := make([]byte, 32*1024)
	for {
		n, readErr := gz.Read(buffer)
		for _, value := range buffer[:n] {
			if value != 0 {
				return Result{}, errors.New("archive contains non-zero data after the tar end marker")
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return Result{}, fmt.Errorf("verify gzip trailer after extraction: %w", readErr)
		}
	}
	if result != validated {
		return Result{}, errors.New("archive contents changed between validation and extraction")
	}
	if !bytes.Equal(validatedHash, extractionDigest.Sum(nil)) {
		return Result{}, errors.New("archive bytes changed between validation and extraction")
	}
	return result, nil
}

func limitsOrDefault(limits Limits) Limits {
	if limits.MaxEntries <= 0 { limits.MaxEntries = DefaultMaxEntries }
	if limits.MaxFileBytes <= 0 { limits.MaxFileBytes = DefaultMaxFileBytes }
	if limits.MaxTotalBytes <= 0 { limits.MaxTotalBytes = DefaultMaxTotalBytes }
	return limits
}

func verifyPrivateDirectoryChain(root, directory string) error {
	relative, err := filepath.Rel(root, directory)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return errors.New("staging path escaped its root")
	}
	current := root
	rootInfo, err := os.Lstat(current)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("staging root changed during extraction")
	}
	if relative == "." {
		return nil
	}
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("staging parent %q is not a real directory", current)
		}
	}
	return nil
}
