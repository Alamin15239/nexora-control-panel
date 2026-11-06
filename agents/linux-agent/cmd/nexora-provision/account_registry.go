package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"
)

const hostingAccountRegistry = "/etc/nexora-hosting-accounts"

type managedAccountMarker struct {
	Version  int    `json:"version"`
	Username string `json:"username"`
	UID      int    `json:"uid"`
}

type managedAccount struct {
	Username string
	UID      int
}

func registryOwnership(info os.FileInfo, uid, gid uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid && stat.Gid == gid
}

func verifyRegistryDirectory(path string, ownerUID, ownerGID uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("account registry directory is unavailable")
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0700 ||
		!registryOwnership(info, ownerUID, ownerGID) {
		return fmt.Errorf("account registry directory failed security checks")
	}
	return nil
}

func verifyRegistryMarker(path, username string, ownerUID, ownerGID uint32) (managedAccount, error) {
	var result managedAccount

	if !usernamePattern.MatchString(username) {
		return result, fmt.Errorf("invalid registered account name")
	}

	info, err := os.Lstat(path)
	if err != nil {
		return result, fmt.Errorf("account registry marker is unavailable")
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0600 ||
		!registryOwnership(info, ownerUID, ownerGID) ||
		info.Size() > 4096 {
		return result, fmt.Errorf("account registry marker failed security checks")
	}

	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return result, fmt.Errorf("account registry marker cannot be opened safely")
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()

	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() ||
		!os.SameFile(info, openedInfo) ||
		openedInfo.Mode().Perm() != 0600 ||
		!registryOwnership(openedInfo, ownerUID, ownerGID) ||
		openedInfo.Size() > 4096 {
		return result, fmt.Errorf("account registry marker changed during verification")
	}

	data, err := io.ReadAll(file)
	if err != nil {
		return result, fmt.Errorf("account registry marker cannot be read")
	}

	var marker managedAccountMarker
	if err := json.Unmarshal(data, &marker); err != nil {
		return result, fmt.Errorf("account registry marker is invalid")
	}
	if marker.Version != 1 || marker.Username != username || marker.UID < 1000 {
		return result, fmt.Errorf("account registry marker identity is invalid")
	}

	return managedAccount{Username: marker.Username, UID: marker.UID}, nil
}

func verifyRegistryParent(path string, ownerUID, ownerGID uint32) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		!registryOwnership(info, ownerUID, ownerGID) ||
		info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("account registry parent failed security checks")
	}
	return nil
}

func ensureRegistryDirectory(path string, ownerUID, ownerGID uint32) error {
	parent := filepath.Dir(path)

	if err := verifyRegistryParent(parent, ownerUID, ownerGID); err != nil {
		return err
	}

	if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("cannot create account registry directory")
	}

	return verifyRegistryDirectory(path, ownerUID, ownerGID)
}

func registerManagedAccountAt(path, username string, uid int, ownerUID, ownerGID uint32) error {
	if !usernamePattern.MatchString(username) || uid < 1000 {
		return fmt.Errorf("invalid hosting account identity")
	}

	if err := ensureRegistryDirectory(path, ownerUID, ownerGID); err != nil {
		return err
	}

	markerPath := filepath.Join(path, username+".json")
	if existing, err := verifyRegistryMarker(markerPath, username, ownerUID, ownerGID); err == nil {
		if existing.UID != uid {
			return fmt.Errorf("registered account UID does not match")
		}
		return nil
	} else if _, statErr := os.Lstat(markerPath); statErr == nil {
		return fmt.Errorf("existing account registry marker is invalid; refusing to replace it")
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("cannot inspect existing account registry marker")
	}

	data, err := json.Marshal(managedAccountMarker{
		Version: 1, Username: username, UID: uid,
	})
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(path, ".nexora-account-*")
	if err != nil {
		return fmt.Errorf("cannot create account registry marker")
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return fmt.Errorf("cannot secure account registry marker")
	}
	if err := tmp.Chown(int(ownerUID), int(ownerGID)); err != nil {
		tmp.Close()
		return fmt.Errorf("cannot secure account registry ownership")
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("cannot write account registry marker")
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("cannot sync account registry marker")
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("cannot close account registry marker")
	}
	if err := os.Link(tmpPath, markerPath); err != nil {
		return fmt.Errorf("cannot publish account registry marker")
	}

	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot open account registry directory")
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("cannot sync account registry directory")
	}
	return nil
}

func readManagedAccountsAt(path string, ownerUID, ownerGID uint32) ([]managedAccount, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return []managedAccount{}, nil
	} else if err != nil {
		return nil, fmt.Errorf("cannot inspect account registry directory")
	}

	if err := verifyRegistryDirectory(path, ownerUID, ownerGID); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read account registry")
	}

	accounts := make([]managedAccount, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if len(name) <= len(".json") || filepath.Ext(name) != ".json" {
			return nil, fmt.Errorf("unexpected entry in account registry")
		}
		username := name[:len(name)-len(".json")]
		account, err := verifyRegistryMarker(filepath.Join(path, name), username, ownerUID, ownerGID)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}

	sort.Slice(accounts, func(i, j int) bool {
		return accounts[i].Username < accounts[j].Username
	})
	return accounts, nil
}

func registerManagedAccount(username string, uid int) error {
	return registerManagedAccountAt(hostingAccountRegistry, username, uid, 0, 0)
}

func readManagedAccounts() ([]managedAccount, error) {
	return readManagedAccountsAt(hostingAccountRegistry, 0, 0)
}

func verifiedNexoraAccounts() ([]managedAccount, error) {
	registered, err := readManagedAccounts()
	if err != nil {
		return nil, err
	}

	verified := make([]managedAccount, 0, len(registered))
	for _, marker := range registered {
		account, _, err := verifiedAccount(marker.Username)
		if err != nil {
			return nil, fmt.Errorf("registered hosting account failed identity verification")
		}
		uid, err := strconv.Atoi(account.Uid)
		if err != nil || uid != marker.UID {
			return nil, fmt.Errorf("registered hosting account UID does not match")
		}
		verified = append(verified, marker)
	}
	return verified, nil
}
