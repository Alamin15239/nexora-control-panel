package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"archive/tar"
	"compress/gzip"
	"syscall"
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
	"time"
)

const backupStorageRoot = "/var/lib/nexora/backups"
const restoreStagingRoot = "/var/lib/nexora/restore-staging"

var backupIDPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

type backupResult struct {
	BackupID     string   `json:"backupId"`
	ArchiveName  string   `json:"archiveName,omitempty"`
	SizeBytes    int64    `json:"sizeBytes,omitempty"`
	SHA256       string   `json:"sha256,omitempty"`
	DatabaseNames []string `json:"databaseNames,omitempty"`
	CreatedAt    string   `json:"createdAt,omitempty"`
	StagingPath  string   `json:"stagingPath,omitempty"`
	Success      bool     `json:"success"`
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
	if err := os.MkdirAll(path, 0700); err != nil { return err }
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(path, current), current) {
		if part == "" { continue }
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("UNSAFE_STORAGE_PATH: backup storage contains an unsafe path component")
		}
		if strings.HasPrefix(current, "/var/lib/nexora") {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != 0 {
				return fmt.Errorf("UNSAFE_STORAGE_OWNER: backup storage directories must be root-owned")
			}
		}
	}
	if err := os.Chown(path, 0, 0); err != nil { return err }
	return os.Chmod(path, 0700)
}

func accountBackupDirectory(username string) (string, error) {
	if !usernamePattern.MatchString(username) { return "", fmt.Errorf("INVALID_USERNAME: hosting username is invalid") }
	if err := ensurePrivateDirectory(backupStorageRoot); err != nil { return "", err }
	path := filepath.Join(backupStorageRoot, username)
	if err := ensurePrivateDirectory(path); err != nil { return "", err }
	return path, nil
}


func validateBackupTree(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil { return walkErr }
		info, err := os.Lstat(path)
		if err != nil { return err }
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("UNSAFE_BACKUP_CONTENT: symbolic links and special files are not included in backups")
		}
		return nil
	})
}

func validateBackupArchive(path string) error {
	file, err := os.Open(path)
	if err != nil { return err }
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil { return err }
	defer gz.Close()
	reader := tar.NewReader(gz)
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) { return nil }
		if nextErr != nil { return nextErr }
		name := filepath.Clean(filepath.FromSlash(header.Name))
		if name == "." || filepath.IsAbs(name) || name == ".." ||
			strings.HasPrefix(name, ".."+string(filepath.Separator)) ||
			!(name == "public_html" || strings.HasPrefix(name, "public_html"+string(filepath.Separator)) ||
				name == "databases" || strings.HasPrefix(name, "databases"+string(filepath.Separator))) ||
			(header.Typeflag != tar.TypeDir && header.Typeflag != tar.TypeReg) {
			return fmt.Errorf("unsafe archive path or file type")
		}
	}
}

func createAccountBackup(username, backupID string, databaseNames []string) error {
	if err := validateBackupID(backupID); err != nil { return err }
	account, _, err := verifiedAccount(username)
	if err != nil { return err }
	publicHTML := filepath.Join(account.HomeDir, "public_html")
	rootFD, err := openDirectoryChain("/", "home", username, "public_html")
	if err != nil { return fmt.Errorf("BACKUP_SOURCE_UNAVAILABLE: document root is missing or unsafe") }
	_ = syscall.Close(rootFD)
	if err := validateBackupTree(publicHTML); err != nil { return err }
	if len(databaseNames) > 20 { return fmt.Errorf("INVALID_DATABASE_LIST: too many databases requested") }
	seen := make(map[string]bool, len(databaseNames))
	for _, name := range databaseNames {
		if err := validateManagedDatabaseName(name, username); err != nil || seen[name] {
			return fmt.Errorf("INVALID_DATABASE_LIST: database does not belong to the hosting account")
		}
		seen[name] = true
	}
	storage, err := accountBackupDirectory(username)
	if err != nil { return err }
	archiveName := backupID + ".tar.gz"
	archivePath := filepath.Join(storage, archiveName)
	if _, err := os.Lstat(archivePath); err == nil { return fmt.Errorf("BACKUP_EXISTS: backup already exists") } else if !errors.Is(err, os.ErrNotExist) { return err }

	work, err := os.MkdirTemp(storage, ".work-")
	if err != nil { return fmt.Errorf("BACKUP_TEMP_FAILED: unable to create secure backup workspace") }
	defer os.RemoveAll(work)
	if err := os.Chmod(work, 0700); err != nil { return err }
	dbDir := filepath.Join(work, "databases")
	if err := os.Mkdir(dbDir, 0700); err != nil { return err }

	for _, name := range databaseNames {
		dumpPath := filepath.Join(dbDir, name+".sql")
		dump, err := os.OpenFile(dumpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil { return fmt.Errorf("DATABASE_DUMP_FAILED: unable to create database dump") }
		cmd := exec.Command("/usr/bin/mariadb-dump", "--single-transaction", "--routines", "--triggers", "--hex-blob", "--databases", name)
		cmd.Stdout = dump
		cmd.Stderr = io.Discard
		if err := cmd.Run(); err != nil { dump.Close(); return fmt.Errorf("DATABASE_DUMP_FAILED: database dump did not complete") }
		if err := dump.Close(); err != nil { return fmt.Errorf("DATABASE_DUMP_FAILED: database dump could not be closed") }
	}

	placeholder, err := os.OpenFile(archivePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil { return fmt.Errorf("BACKUP_CREATE_FAILED: unable to reserve backup archive") }
	if err := placeholder.Close(); err != nil { os.Remove(archivePath); return err }
	cmd := exec.Command("/usr/bin/tar", "-czf", archivePath, "-C", account.HomeDir, "public_html", "-C", work, "databases")
	if output, err := cmd.CombinedOutput(); err != nil {
		_ = os.Remove(archivePath)
		return fmt.Errorf("BACKUP_ARCHIVE_FAILED: %s", safeOutput(string(output)))
	}
	file, err := os.Open(archivePath)
	if err != nil { _ = os.Remove(archivePath); return err }
	info, err := file.Stat()
	if err != nil { file.Close(); _ = os.Remove(archivePath); return err }
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil { _ = os.Remove(archivePath); return fmt.Errorf("BACKUP_VERIFY_FAILED: archive could not be read for verification") }
	result := backupResult{BackupID: backupID, ArchiveName: archiveName, SizeBytes: info.Size(), SHA256: hex.EncodeToString(hash.Sum(nil)), DatabaseNames: databaseNames, CreatedAt: time.Now().UTC().Format(time.RFC3339), Success: true}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil { return err }
	return nil
}

func deleteAccountBackup(username, backupID string) error {
	if err := validateBackupID(backupID); err != nil { return err }
	storage, err := accountBackupDirectory(username)
	if err != nil { return err }
	path := filepath.Join(storage, backupID+".tar.gz")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) { return fmt.Errorf("BACKUP_NOT_FOUND: backup archive does not exist") }
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("UNSAFE_BACKUP_FILE: refusing to delete an unsafe backup path")
	}
	if err := os.Remove(path); err != nil { return fmt.Errorf("BACKUP_DELETE_FAILED: unable to delete backup archive") }
	return json.NewEncoder(os.Stdout).Encode(backupResult{BackupID: backupID, Success: true})
}

func verifyBackupDigest(path, expected string) error {
	if !regexp.MustCompile(`^[a-f0-9]{64}package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"archive/tar"
	"compress/gzip"
	"syscall"
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
	"time"
)

const backupStorageRoot = "/var/lib/nexora/backups"
const restoreStagingRoot = "/var/lib/nexora/restore-staging"

var backupIDPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

type backupResult struct {
	BackupID     string   `json:"backupId"`
	ArchiveName  string   `json:"archiveName,omitempty"`
	SizeBytes    int64    `json:"sizeBytes,omitempty"`
	SHA256       string   `json:"sha256,omitempty"`
	DatabaseNames []string `json:"databaseNames,omitempty"`
	CreatedAt    string   `json:"createdAt,omitempty"`
	StagingPath  string   `json:"stagingPath,omitempty"`
	Success      bool     `json:"success"`
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
	if err := os.MkdirAll(path, 0700); err != nil { return err }
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(path, current), current) {
		if part == "" { continue }
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("UNSAFE_STORAGE_PATH: backup storage contains an unsafe path component")
		}
		if strings.HasPrefix(current, "/var/lib/nexora") {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != 0 {
				return fmt.Errorf("UNSAFE_STORAGE_OWNER: backup storage directories must be root-owned")
			}
		}
	}
	if err := os.Chown(path, 0, 0); err != nil { return err }
	return os.Chmod(path, 0700)
}

func accountBackupDirectory(username string) (string, error) {
	if !usernamePattern.MatchString(username) { return "", fmt.Errorf("INVALID_USERNAME: hosting username is invalid") }
	if err := ensurePrivateDirectory(backupStorageRoot); err != nil { return "", err }
	path := filepath.Join(backupStorageRoot, username)
	if err := ensurePrivateDirectory(path); err != nil { return "", err }
	return path, nil
}


func validateBackupTree(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil { return walkErr }
		info, err := os.Lstat(path)
		if err != nil { return err }
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("UNSAFE_BACKUP_CONTENT: symbolic links and special files are not included in backups")
		}
		return nil
	})
}

func validateBackupArchive(path string) error {
	file, err := os.Open(path)
	if err != nil { return err }
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil { return err }
	defer gz.Close()
	reader := tar.NewReader(gz)
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) { return nil }
		if nextErr != nil { return nextErr }
		name := filepath.Clean(filepath.FromSlash(header.Name))
		if name == "." || filepath.IsAbs(name) || name == ".." ||
			strings.HasPrefix(name, ".."+string(filepath.Separator)) ||
			!(name == "public_html" || strings.HasPrefix(name, "public_html"+string(filepath.Separator)) ||
				name == "databases" || strings.HasPrefix(name, "databases"+string(filepath.Separator))) ||
			(header.Typeflag != tar.TypeDir && header.Typeflag != tar.TypeReg) {
			return fmt.Errorf("unsafe archive path or file type")
		}
	}
}

func createAccountBackup(username, backupID string, databaseNames []string) error {
	if err := validateBackupID(backupID); err != nil { return err }
	account, _, err := verifiedAccount(username)
	if err != nil { return err }
	publicHTML := filepath.Join(account.HomeDir, "public_html")
	rootFD, err := openDirectoryChain("/", "home", username, "public_html")
	if err != nil { return fmt.Errorf("BACKUP_SOURCE_UNAVAILABLE: document root is missing or unsafe") }
	_ = syscall.Close(rootFD)
	if err := validateBackupTree(publicHTML); err != nil { return err }
	if len(databaseNames) > 20 { return fmt.Errorf("INVALID_DATABASE_LIST: too many databases requested") }
	seen := make(map[string]bool, len(databaseNames))
	for _, name := range databaseNames {
		if err := validateManagedDatabaseName(name, username); err != nil || seen[name] {
			return fmt.Errorf("INVALID_DATABASE_LIST: database does not belong to the hosting account")
		}
		seen[name] = true
	}
	storage, err := accountBackupDirectory(username)
	if err != nil { return err }
	archiveName := backupID + ".tar.gz"
	archivePath := filepath.Join(storage, archiveName)
	if _, err := os.Lstat(archivePath); err == nil { return fmt.Errorf("BACKUP_EXISTS: backup already exists") } else if !errors.Is(err, os.ErrNotExist) { return err }

	work, err := os.MkdirTemp(storage, ".work-")
	if err != nil { return fmt.Errorf("BACKUP_TEMP_FAILED: unable to create secure backup workspace") }
	defer os.RemoveAll(work)
	if err := os.Chmod(work, 0700); err != nil { return err }
	dbDir := filepath.Join(work, "databases")
	if err := os.Mkdir(dbDir, 0700); err != nil { return err }

	for _, name := range databaseNames {
		dumpPath := filepath.Join(dbDir, name+".sql")
		dump, err := os.OpenFile(dumpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil { return fmt.Errorf("DATABASE_DUMP_FAILED: unable to create database dump") }
		cmd := exec.Command("/usr/bin/mariadb-dump", "--single-transaction", "--routines", "--triggers", "--hex-blob", "--databases", name)
		cmd.Stdout = dump
		cmd.Stderr = io.Discard
		if err := cmd.Run(); err != nil { dump.Close(); return fmt.Errorf("DATABASE_DUMP_FAILED: database dump did not complete") }
		if err := dump.Close(); err != nil { return fmt.Errorf("DATABASE_DUMP_FAILED: database dump could not be closed") }
	}

	placeholder, err := os.OpenFile(archivePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil { return fmt.Errorf("BACKUP_CREATE_FAILED: unable to reserve backup archive") }
	if err := placeholder.Close(); err != nil { os.Remove(archivePath); return err }
	cmd := exec.Command("/usr/bin/tar", "-czf", archivePath, "-C", account.HomeDir, "public_html", "-C", work, "databases")
	if output, err := cmd.CombinedOutput(); err != nil {
		_ = os.Remove(archivePath)
		return fmt.Errorf("BACKUP_ARCHIVE_FAILED: %s", safeOutput(string(output)))
	}
	file, err := os.Open(archivePath)
	if err != nil { _ = os.Remove(archivePath); return err }
	info, err := file.Stat()
	if err != nil { file.Close(); _ = os.Remove(archivePath); return err }
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil { _ = os.Remove(archivePath); return fmt.Errorf("BACKUP_VERIFY_FAILED: archive could not be read for verification") }
	result := backupResult{BackupID: backupID, ArchiveName: archiveName, SizeBytes: info.Size(), SHA256: hex.EncodeToString(hash.Sum(nil)), DatabaseNames: databaseNames, CreatedAt: time.Now().UTC().Format(time.RFC3339), Success: true}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil { return err }
	return nil
}

func deleteAccountBackup(username, backupID string) error {
	if err := validateBackupID(backupID); err != nil { return err }
	storage, err := accountBackupDirectory(username)
	if err != nil { return err }
	path := filepath.Join(storage, backupID+".tar.gz")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) { return fmt.Errorf("BACKUP_NOT_FOUND: backup archive does not exist") }
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("UNSAFE_BACKUP_FILE: refusing to delete an unsafe backup path")
	}
	if err := os.Remove(path); err != nil { return fmt.Errorf("BACKUP_DELETE_FAILED: unable to delete backup archive") }
	return json.NewEncoder(os.Stdout).Encode(backupResult{BackupID: backupID, Success: true})
}

).MatchString(expected) {
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
	if err := validateBackupID(backupID); err != nil { return err }
	storage, err := accountBackupDirectory(username)
	if err != nil { return err }
	archivePath := filepath.Join(storage, backupID+".tar.gz")
	info, err := os.Lstat(archivePath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("BACKUP_NOT_FOUND: verified backup archive is unavailable")
	}
	accountStage := filepath.Join(restoreStagingRoot, username)
	if err := ensurePrivateDirectory(restoreStagingRoot); err != nil { return err }
	if err := ensurePrivateDirectory(accountStage); err != nil { return err }
	stage := filepath.Join(accountStage, backupID)
	if _, err := os.Lstat(stage); err == nil { return fmt.Errorf("RESTORE_STAGE_EXISTS: staging directory already exists") } else if !errors.Is(err, os.ErrNotExist) { return err }
	if err := os.Mkdir(stage, 0700); err != nil { return fmt.Errorf("RESTORE_STAGE_FAILED: unable to create restore staging directory") }

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

