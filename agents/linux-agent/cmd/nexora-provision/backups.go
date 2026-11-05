package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const backupStorageRoot = "/var/lib/nexora/backups"
const restoreStagingRoot = "/var/lib/nexora/restore-staging"

// Bound decompression and extraction work even if an archive is highly compressed.
const maxBackupArchiveUncompressedBytes int64 = 20 << 30

var backupIDPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

type backupResult struct {
	BackupID      string   `json:"backupId"`
	ArchiveName   string   `json:"archiveName,omitempty"`
	SizeBytes     int64    `json:"sizeBytes,omitempty"`
	SHA256        string   `json:"sha256,omitempty"`
	DatabaseNames []string `json:"databaseNames,omitempty"`
	CreatedAt     string   `json:"createdAt,omitempty"`
	StagingPath   string   `json:"stagingPath,omitempty"`
	Success       bool     `json:"success"`
}

func validateBackupID(value string) error {
	if !backupIDPattern.MatchString(value) {
		return fmt.Errorf("INVALID_BACKUP_ID: backup identifier is invalid")
	}
	return nil
}

func ensurePrivateDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("INVALID_STORAGE_PATH: backup storage path is invalid")
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(path, current), current) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("UNSAFE_STORAGE_PATH: backup storage contains an unsafe path component")
		}
		if current == "/var/lib/nexora" || strings.HasPrefix(current, "/var/lib/nexora"+string(filepath.Separator)) {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != 0 {
				return fmt.Errorf("UNSAFE_STORAGE_OWNER: backup storage directories must be root-owned")
			}
			if info.Mode().Perm()&0022 != 0 {
				return fmt.Errorf("UNSAFE_STORAGE_MODE: backup storage directories must not be group- or world-writable")
			}
		}
	}
	if err := os.Chown(path, 0, 0); err != nil {
		return err
	}
	return os.Chmod(path, 0700)
}

func accountBackupDirectory(username string) (string, error) {
	if !usernamePattern.MatchString(username) {
		return "", fmt.Errorf("INVALID_USERNAME: hosting username is invalid")
	}
	if err := ensurePrivateDirectory(backupStorageRoot); err != nil {
		return "", err
	}
	path := filepath.Join(backupStorageRoot, username)
	if err := ensurePrivateDirectory(path); err != nil {
		return "", err
	}
	return path, nil
}

// Linux O_PATH lets us inspect an entry without opening a FIFO, device, or
// other special file. O_NOFOLLOW makes a symlink itself inspectable so it can
// be rejected rather than traversed.
const linuxOPath = 0x200000

func sameInode(a, b *syscall.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode&syscall.S_IFMT == b.Mode&syscall.S_IFMT
}

// snapshotBackupDirectory consumes sourceFD and copies only regular files and
// directories. Every lookup is relative to a pinned directory descriptor, and
// every opened child is checked against the inode inspected with O_PATH.
func snapshotBackupDirectory(sourceFD int, destination string) error {
	source := os.NewFile(uintptr(sourceFD), "backup-source-directory")
	if source == nil {
		_ = syscall.Close(sourceFD)
		return fmt.Errorf("BACKUP_SOURCE_UNAVAILABLE: unable to open document root")
	}
	defer source.Close()

	entries, err := source.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("BACKUP_SOURCE_READ_FAILED: unable to enumerate document root")
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == "" || name == "." || name == ".." || strings.Contains(name, "/") {
			return fmt.Errorf("UNSAFE_BACKUP_CONTENT: invalid directory entry")
		}
		pathFD, err := syscall.Openat(sourceFD, name, linuxOPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("BACKUP_SOURCE_CHANGED: unable to safely inspect a document")
		}
		var inspected syscall.Stat_t
		statErr := syscall.Fstat(pathFD, &inspected)
		_ = syscall.Close(pathFD)
		if statErr != nil {
			return fmt.Errorf("BACKUP_SOURCE_READ_FAILED: unable to inspect a document")
		}

		target := filepath.Join(destination, name)
		switch inspected.Mode & syscall.S_IFMT {
		case syscall.S_IFDIR:
			childFD, openErr := syscall.Openat(sourceFD, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
			if openErr != nil {
				return fmt.Errorf("BACKUP_SOURCE_CHANGED: directory changed during snapshot")
			}
			var opened syscall.Stat_t
			if err := syscall.Fstat(childFD, &opened); err != nil || !sameInode(&inspected, &opened) {
				_ = syscall.Close(childFD)
				return fmt.Errorf("BACKUP_SOURCE_CHANGED: directory changed during snapshot")
			}
			if err := os.Mkdir(target, 0700); err != nil {
				_ = syscall.Close(childFD)
				return fmt.Errorf("BACKUP_SNAPSHOT_FAILED: unable to create snapshot directory")
			}
			if err := snapshotBackupDirectory(childFD, target); err != nil {
				return err
			}
			if err := os.Chmod(target, os.FileMode(inspected.Mode).Perm()&0755); err != nil {
				return fmt.Errorf("BACKUP_SNAPSHOT_FAILED: unable to set snapshot directory mode")
			}
		case syscall.S_IFREG:
			fileFD, openErr := syscall.Openat(sourceFD, name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
			if openErr != nil {
				return fmt.Errorf("BACKUP_SOURCE_CHANGED: file changed during snapshot")
			}
			var opened syscall.Stat_t
			if err := syscall.Fstat(fileFD, &opened); err != nil || !sameInode(&inspected, &opened) || opened.Mode&syscall.S_IFMT != syscall.S_IFREG {
				_ = syscall.Close(fileFD)
				return fmt.Errorf("BACKUP_SOURCE_CHANGED: file changed during snapshot")
			}
			input := os.NewFile(uintptr(fileFD), "backup-source-file")
			output, createErr := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if createErr != nil {
				_ = input.Close()
				return fmt.Errorf("BACKUP_SNAPSHOT_FAILED: unable to create snapshot file")
			}
			_, copyErr := io.Copy(output, input)
			inputCloseErr := input.Close()
			modeErr := output.Chmod(os.FileMode(inspected.Mode).Perm() & 0755)
			outputCloseErr := output.Close()
			if copyErr != nil || inputCloseErr != nil || modeErr != nil || outputCloseErr != nil {
				return fmt.Errorf("BACKUP_SNAPSHOT_FAILED: unable to copy document safely")
			}
		default:
			return fmt.Errorf("UNSAFE_BACKUP_CONTENT: symbolic links and special files are not included in backups")
		}
	}
	return nil
}

func validateBackupArchive(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gz.Close()
	limited := &io.LimitedReader{R: gz, N: maxBackupArchiveUncompressedBytes + 1}
	reader := tar.NewReader(limited)
	seen := make(map[string]bool)
	regularFiles := make(map[string]bool)
	descendantCounts := make(map[string]int)
	hasPublicHTML := false
	hasDatabases := false
	entries := 0
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			if !hasPublicHTML || !hasDatabases || entries == 0 {
				return fmt.Errorf("backup archive is missing required top-level directories")
			}
			// tar.Reader stops at the tar end markers before necessarily
			// consuming the gzip trailer. Drain the gzip stream so its CRC and
			// uncompressed-size trailer are verified before accepting the archive.
			if _, err := io.Copy(io.Discard, limited); err != nil {
				return fmt.Errorf("backup archive gzip integrity check failed: %w", err)
			}
			if limited.N == 0 {
				return fmt.Errorf("backup archive exceeds the uncompressed size limit")
			}
			return nil
		}
		if nextErr != nil {
			return nextErr
		}
		entries++
		if entries > 1_000_000 {
			return fmt.Errorf("backup archive contains too many entries")
		}
		if strings.Contains(header.Name, "\\") {
			return fmt.Errorf("unsafe archive path separator")
		}
		rawName := header.Name
		if header.Typeflag == tar.TypeDir {
			rawName = strings.TrimSuffix(rawName, "/")
		}
		name := filepath.Clean(filepath.FromSlash(rawName))
		if name == "." || name != rawName || filepath.IsAbs(name) || name == ".." ||
			strings.HasPrefix(name, ".."+string(filepath.Separator)) ||
			!(name == "public_html" || strings.HasPrefix(name, "public_html"+string(filepath.Separator)) ||
				name == "databases" || strings.HasPrefix(name, "databases"+string(filepath.Separator))) ||
			(header.Typeflag != tar.TypeDir && header.Typeflag != tar.TypeReg) || header.Size < 0 {
			return fmt.Errorf("unsafe archive path or file type")
		}
		if header.Size > maxBackupArchiveUncompressedBytes {
			return fmt.Errorf("backup archive exceeds the uncompressed size limit")
		}
		// Reject file/directory hierarchy conflicts in either archive order.
		// Otherwise extraction could place a child beneath a regular file, or
		// replace a directory that already contains validated members.
		for parent := filepath.Dir(name); parent != "."; parent = filepath.Dir(parent) {
			if regularFiles[parent] {
				return fmt.Errorf("backup archive contains a member beneath a regular file")
			}
		}
		if header.Typeflag == tar.TypeReg && descendantCounts[name] > 0 {
			return fmt.Errorf("backup archive replaces a directory containing members")
		}
		if seen[name] {
			return fmt.Errorf("backup archive contains duplicate paths")
		}
		seen[name] = true
		if header.Typeflag == tar.TypeReg {
			regularFiles[name] = true
		}
		for parent := filepath.Dir(name); parent != "."; parent = filepath.Dir(parent) {
			descendantCounts[parent]++
		}
		if name == "public_html" && header.Typeflag == tar.TypeDir {
			hasPublicHTML = true
		}
		if name == "databases" && header.Typeflag == tar.TypeDir {
			hasDatabases = true
		}
	}
}

func createAccountBackup(username, backupID string, databaseNames []string) error {
	if err := validateBackupID(backupID); err != nil {
		return err
	}
	account, _, err := verifiedAccount(username)
	if err != nil {
		return err
	}
	rootFD, err := openDirectoryChain("/", "home", username, "public_html")
	if err != nil {
		return fmt.Errorf("BACKUP_SOURCE_UNAVAILABLE: document root is missing or unsafe")
	}
	rootFDOpen := true
	defer func() {
		if rootFDOpen {
			_ = syscall.Close(rootFD)
		}
	}()
	if len(databaseNames) > 20 {
		return fmt.Errorf("INVALID_DATABASE_LIST: too many databases requested")
	}
	seen := make(map[string]bool, len(databaseNames))
	for _, name := range databaseNames {
		if err := validateManagedDatabaseName(name, username); err != nil || seen[name] {
			return fmt.Errorf("INVALID_DATABASE_LIST: database does not belong to the hosting account")
		}
		seen[name] = true
	}
	storage, err := accountBackupDirectory(username)
	if err != nil {
		return err
	}
	archiveName := backupID + ".tar.gz"
	archivePath := filepath.Join(storage, archiveName)
	if _, err := os.Lstat(archivePath); err == nil {
		return fmt.Errorf("BACKUP_EXISTS: backup already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	work, err := os.MkdirTemp(storage, ".work-")
	if err != nil {
		return fmt.Errorf("BACKUP_TEMP_FAILED: unable to create secure backup workspace")
	}
	defer os.RemoveAll(work)
	if err := os.Chmod(work, 0700); err != nil {
		return err
	}
	dbDir := filepath.Join(work, "databases")
	if err := os.Mkdir(dbDir, 0700); err != nil {
		return err
	}
	snapshotDir := filepath.Join(work, "public_html")
	if err := os.Mkdir(snapshotDir, 0700); err != nil {
		return err
	}
	if err := snapshotBackupDirectory(rootFD, snapshotDir); err != nil {
		rootFDOpen = false
		return err
	}
	rootFDOpen = false

	for _, name := range databaseNames {
		dumpPath := filepath.Join(dbDir, name+".sql")
		dump, err := os.OpenFile(dumpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return fmt.Errorf("DATABASE_DUMP_FAILED: unable to create database dump")
		}
		cmd := exec.Command("/usr/bin/mariadb-dump", "--single-transaction", "--routines", "--triggers", "--hex-blob", "--databases", name)
		cmd.Stdout = dump
		cmd.Stderr = io.Discard
		if err := cmd.Run(); err != nil {
			dump.Close()
			return fmt.Errorf("DATABASE_DUMP_FAILED: database dump did not complete")
		}
		if err := dump.Close(); err != nil {
			return fmt.Errorf("DATABASE_DUMP_FAILED: database dump could not be closed")
		}
	}

	placeholder, err := os.OpenFile(archivePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("BACKUP_CREATE_FAILED: unable to reserve backup archive")
	}
	if err := placeholder.Close(); err != nil {
		os.Remove(archivePath)
		return err
	}
	cmd := exec.Command("/usr/bin/tar", "-czf", archivePath, "-C", work, "public_html", "databases")
	if output, err := cmd.CombinedOutput(); err != nil {
		_ = os.Remove(archivePath)
		return fmt.Errorf("BACKUP_ARCHIVE_FAILED: %s", safeOutput(string(output)))
	}
	file, err := os.Open(archivePath)
	if err != nil {
		_ = os.Remove(archivePath)
		return err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		_ = os.Remove(archivePath)
		return err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(archivePath)
		return fmt.Errorf("BACKUP_VERIFY_FAILED: archive could not be read for verification")
	}
	result := backupResult{BackupID: backupID, ArchiveName: archiveName, SizeBytes: info.Size(), SHA256: hex.EncodeToString(hash.Sum(nil)), DatabaseNames: databaseNames, CreatedAt: time.Now().UTC().Format(time.RFC3339), Success: true}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return err
	}
	return nil
}

func deleteAccountBackup(username, backupID string) error {
	if err := validateBackupID(backupID); err != nil {
		return err
	}
	storage, err := accountBackupDirectory(username)
	if err != nil {
		return err
	}
	path := filepath.Join(storage, backupID+".tar.gz")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("BACKUP_NOT_FOUND: backup archive does not exist")
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("UNSAFE_BACKUP_FILE: refusing to delete an unsafe backup path")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("BACKUP_DELETE_FAILED: unable to delete backup archive")
	}
	return json.NewEncoder(os.Stdout).Encode(backupResult{BackupID: backupID, Success: true})
}

func verifyBackupDigest(path, expected string) error {
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(expected) {
		return fmt.Errorf("BACKUP_DIGEST_INVALID: expected archive digest is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("BACKUP_VERIFY_FAILED: archive could not be hashed")
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
		return fmt.Errorf("BACKUP_INTEGRITY_FAILED: archive checksum does not match the recorded digest")
	}
	return nil
}

func stageAccountBackupRestore(username, backupID, expectedSHA256 string) error {
	if err := validateBackupID(backupID); err != nil {
		return err
	}
	storage, err := accountBackupDirectory(username)
	if err != nil {
		return err
	}
	archivePath := filepath.Join(storage, backupID+".tar.gz")
	info, err := os.Lstat(archivePath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("BACKUP_NOT_FOUND: verified backup archive is unavailable")
	}
	accountStage := filepath.Join(restoreStagingRoot, username)
	if err := ensurePrivateDirectory(restoreStagingRoot); err != nil {
		return err
	}
	if err := ensurePrivateDirectory(accountStage); err != nil {
		return err
	}
	stage := filepath.Join(accountStage, backupID)
	if _, err := os.Lstat(stage); err == nil {
		return fmt.Errorf("RESTORE_STAGE_EXISTS: staging directory already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Mkdir(stage, 0700); err != nil {
		return fmt.Errorf("RESTORE_STAGE_FAILED: unable to create restore staging directory")
	}
	if err := verifyBackupDigest(archivePath, expectedSHA256); err != nil {
		_ = os.RemoveAll(stage)
		return err
	}
	if err := validateBackupArchive(archivePath); err != nil {
		_ = os.RemoveAll(stage)
		return fmt.Errorf("BACKUP_VERIFY_FAILED: archive contains an unsafe or invalid member")
	}
	cmd := exec.Command("/usr/bin/tar", "--extract", "--gzip", "--file", archivePath, "--directory", stage, "--no-same-owner", "--no-same-permissions")
	if output, err := cmd.CombinedOutput(); err != nil {
		_ = os.RemoveAll(stage)
		return fmt.Errorf("RESTORE_STAGE_FAILED: %s", safeOutput(string(output)))
	}
	_ = os.Chmod(stage, 0700)
	return json.NewEncoder(os.Stdout).Encode(backupResult{BackupID: backupID, StagingPath: stage, Success: true})
}
