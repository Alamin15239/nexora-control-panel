package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type request struct {
	Operation string `json:"operation"`
	Username  string `json:"username"`
}

var usernamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{2,15}$`)

func main() {
	if os.Geteuid() != 0 {
		fail("ROOT_REQUIRED", "The Nexora provisioning helper must run as root.")
	}
	reader := bufio.NewReader(os.Stdin)
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var input request
	if err := decoder.Decode(&input); err != nil {
		fail("INVALID_REQUEST", "The provisioning request is invalid.")
	}
	if input.Operation != "CREATE_HOSTING_ACCOUNT" {
		fail("UNSUPPORTED_OPERATION", "This provisioning operation is not supported.")
	}
	if !usernamePattern.MatchString(input.Username) {
		fail("INVALID_USERNAME", "The hosting username is invalid.")
	}
	if err := provisionAccount(input.Username); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	fmt.Printf("Provisioned Linux hosting identity %s and its public_html directory.\n", input.Username)
}

func fail(code, message string) {
	fmt.Fprintf(os.Stderr, "%s: %s\n", code, message)
	os.Exit(1)
}

func provisionAccount(username string) error {
	home := filepath.Join("/home", username)
	publicHTML := filepath.Join(home, "public_html")

	account, lookupErr := user.Lookup(username)
	if lookupErr != nil {
		var unknown user.UnknownUserError
		if !errors.As(lookupErr, &unknown) {
			return fmt.Errorf("USER_LOOKUP_FAILED: unable to verify the Linux account")
		}
		args := []string{"--create-home", "--home-dir", home, "--shell", "/usr/sbin/nologin"}
		if _, err := user.LookupGroup(username); err == nil {
			args = append(args, "--gid", username)
		} else {
			args = append(args, "--user-group")
		}
		args = append(args, username)
		if output, err := exec.Command("/usr/sbin/useradd", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("USER_CREATE_FAILED: %s", safeOutput(string(output)))
		}
		account, lookupErr = user.Lookup(username)
		if lookupErr != nil {
			return fmt.Errorf("USER_LOOKUP_FAILED: account was created but could not be verified")
		}
	}

	if filepath.Clean(account.HomeDir) != home {
		return fmt.Errorf("ACCOUNT_CONFLICT: existing Linux user does not have the expected home directory")
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid < 1000 {
		return fmt.Errorf("ACCOUNT_CONFLICT: existing Linux user is not a regular hosting account")
	}
	group, err := user.LookupGroupId(account.Gid)
	if err != nil {
		return fmt.Errorf("GROUP_LOOKUP_FAILED: unable to verify the account group")
	}
	passwd, err := exec.Command("/usr/bin/getent", "passwd", username).Output()
	if err != nil {
		return fmt.Errorf("ACCOUNT_VERIFY_FAILED: unable to verify the account login shell")
	}
	fields := strings.Split(strings.TrimSpace(string(passwd)), ":")
	if len(fields) != 7 || fields[6] != "/usr/sbin/nologin" {
		return fmt.Errorf("ACCOUNT_CONFLICT: hosting users must use /usr/sbin/nologin")
	}

	for _, path := range []string{"/home", home, publicHTML} {
		if info, statErr := os.Lstat(path); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("PATH_CONFLICT: refusing to use a symbolic link in the hosting home path")
		} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("PATH_CHECK_FAILED: unable to verify hosting directory")
		}
	}
	if err := os.MkdirAll(home, 0750); err != nil {
		return fmt.Errorf("HOME_CREATE_FAILED: unable to create the account home directory")
	}
	if err := os.Chown(home, uid, mustGID(group.Gid)); err != nil {
		return fmt.Errorf("HOME_PERMISSION_FAILED: unable to set account ownership")
	}
	if err := os.Chmod(home, 0750); err != nil {
		return fmt.Errorf("HOME_PERMISSION_FAILED: unable to set account permissions")
	}
	if err := os.MkdirAll(publicHTML, 0750); err != nil {
		return fmt.Errorf("DOCUMENT_ROOT_CREATE_FAILED: unable to create public_html")
	}
	if err := os.Chown(publicHTML, uid, mustGID(group.Gid)); err != nil {
		return fmt.Errorf("DOCUMENT_ROOT_PERMISSION_FAILED: unable to set document root ownership")
	}
	if err := os.Chmod(publicHTML, 0750); err != nil {
		return fmt.Errorf("DOCUMENT_ROOT_PERMISSION_FAILED: unable to set document root permissions")
	}
	index := filepath.Join(publicHTML, "index.html")
	file, err := os.OpenFile(index, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if err == nil {
		_, writeErr := file.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>Hosting account ready</title></head><body><h1>Hosting account provisioned</h1><p>Website service configuration is not enabled yet.</p></body></html>\n")
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			return fmt.Errorf("DEFAULT_PAGE_FAILED: unable to write the initial index page")
		}
		if err := os.Chown(index, uid, mustGID(group.Gid)); err != nil {
			return fmt.Errorf("DEFAULT_PAGE_PERMISSION_FAILED: unable to set initial page ownership")
		}
	} else if !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("DEFAULT_PAGE_FAILED: unable to create the initial index page")
	}
	return nil
}

func mustGID(value string) int {
	gid, _ := strconv.Atoi(value)
	return gid
}

func safeOutput(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 240 {
		value = value[:240]
	}
	if value == "" {
		return "system user creation failed"
	}
	return value
}
