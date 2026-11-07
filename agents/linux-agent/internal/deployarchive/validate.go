package deployarchive

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

const (
	DefaultMaxEntries = 10_000
	DefaultMaxFileBytes = int64(100 << 20)
	DefaultMaxTotalBytes = int64(500 << 20)
)

type Limits struct {
	MaxEntries int
	MaxFileBytes int64
	MaxTotalBytes int64
}

type Result struct {
	Entries int
	Files int
	Bytes int64
}

type entryKind uint8

const (
	entryDirectory entryKind = iota + 1
	entryFile
)

func normalizeArchivePath(name string, kind byte) (string, bool, error) {
	if name == "" || strings.ContainsRune(name, 0) || strings.Contains(name, "\\") {
		return "", false, errors.New("archive contains an empty or invalid path")
	}
	if strings.HasPrefix(name, "/") {
		return "", false, fmt.Errorf("absolute archive path is not allowed: %q", name)
	}
	parts := strings.Split(name, "/")
	firstComponent := ""
	for _, part := range parts {
		if part == ".." {
			return "", false, fmt.Errorf("path traversal is not allowed: %q", name)
		}
		if part != "" && part != "." && firstComponent == "" {
			firstComponent = part
		}
	}
	// Ignore leading "./" components before checking for a drive/volume prefix.
	// Otherwise "./C:/site/index.html" would bypass the volume-qualified check.
	if strings.Contains(firstComponent, ":") {
		return "", false, fmt.Errorf("volume-qualified path is not allowed: %q", name)
	}
	clean := path.Clean(name)
	if clean == "." {
		if kind == tar.TypeDir {
			return "", true, nil
		}
		return "", false, fmt.Errorf("archive file path resolves to root: %q", name)
	}
	if clean == ".." || strings.HasPrefix(clean, "../") || path.IsAbs(clean) {
		return "", false, fmt.Errorf("path escapes archive root: %q", name)
	}
	return clean, false, nil
}

// ValidateGzipTar validates a gzip-compressed tar archive without extracting it.
// Only regular files and directories are accepted. Links and special files are rejected.
func ValidateGzipTar(input io.Reader, limits Limits) (Result, error) {
	if limits.MaxEntries <= 0 { limits.MaxEntries = DefaultMaxEntries }
	if limits.MaxFileBytes <= 0 { limits.MaxFileBytes = DefaultMaxFileBytes }
	if limits.MaxTotalBytes <= 0 { limits.MaxTotalBytes = DefaultMaxTotalBytes }

	gz, err := gzip.NewReader(input)
	if err != nil { return Result{}, fmt.Errorf("open gzip archive: %w", err) }
	defer gz.Close()

	tr := tar.NewReader(gz)
	entries := make(map[string]entryKind)
	result := Result{}
	for {
		header, nextErr := tr.Next()
		if nextErr == io.EOF { break }
		if nextErr != nil { return Result{}, fmt.Errorf("read tar header: %w", nextErr) }
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA && header.Typeflag != tar.TypeDir {
			return Result{}, fmt.Errorf("archive entry %q has prohibited type %d", header.Name, header.Typeflag)
		}
		name, rootDirectory, pathErr := normalizeArchivePath(header.Name, header.Typeflag)
		if pathErr != nil { return Result{}, pathErr }
		if rootDirectory { continue }
		if name == ".nexora-release.json" {
			return Result{}, errors.New("archive path is reserved for publisher release metadata")
		}
		if header.Size < 0 || header.Size > limits.MaxFileBytes {
			return Result{}, fmt.Errorf("archive entry %q exceeds the per-file size limit", header.Name)
		}

		kind := entryFile
		if header.Typeflag == tar.TypeDir {
			kind = entryDirectory
			if header.Size != 0 { return Result{}, fmt.Errorf("directory entry %q has a non-zero size", header.Name) }
		}
		if _, exists := entries[name]; exists { return Result{}, fmt.Errorf("duplicate archive path: %q", name) }
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if entries[parent] == entryFile { return Result{}, fmt.Errorf("archive path %q is nested below a regular file", name) }
		}
		if kind == entryFile {
			prefix := name + "/"
			for existing := range entries {
				if strings.HasPrefix(existing, prefix) { return Result{}, fmt.Errorf("regular file %q conflicts with an existing directory entry", name) }
			}
		}

		result.Entries++
		if result.Entries > limits.MaxEntries { return Result{}, errors.New("archive contains too many entries") }
		entries[name] = kind
		if kind == entryFile {
			if result.Bytes > limits.MaxTotalBytes-header.Size { return Result{}, errors.New("archive exceeds the total expanded size limit") }
			result.Bytes += header.Size
			result.Files++
			if _, copyErr := io.CopyN(io.Discard, tr, header.Size); copyErr != nil {
				return Result{}, fmt.Errorf("read archive file %q: %w", name, copyErr)
			}
		}
	}

	// Consume the remainder so gzip's checksum is verified; only tar zero-padding is valid.
	buffer := make([]byte, 32*1024)
	for {
		n, readErr := gz.Read(buffer)
		for _, value := range buffer[:n] {
			if value != 0 { return Result{}, errors.New("archive contains non-zero data after the tar end marker") }
		}
		if readErr == io.EOF { break }
		if readErr != nil { return Result{}, fmt.Errorf("verify gzip trailer: %w", readErr) }
	}
	return result, nil
}
