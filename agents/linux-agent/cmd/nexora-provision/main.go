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
	Operation    string `json:"operation"`
	Username     string `json:"username"`
	Domain       string `json:"domain,omitempty"`
	DocumentRoot string `json:"documentRoot,omitempty"`
}

var (
	usernamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{2,15}$`)
	domainPattern = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+$`)
)

func main() {
	if os.Geteuid() != 0 { fail("ROOT_REQUIRED", "The Nexora provisioning helper must run as root.") }
	decoder := json.NewDecoder(bufio.NewReader(os.Stdin))
	decoder.DisallowUnknownFields()
	var input request
	if err := decoder.Decode(&input); err != nil { fail("INVALID_REQUEST", "The provisioning request is invalid.") }
	if !usernamePattern.MatchString(input.Username) { fail("INVALID_USERNAME", "The hosting username is invalid.") }
	var err error
	switch input.Operation {
	case "CREATE_HOSTING_ACCOUNT":
		err = provisionAccount(input.Username)
	case "ADD_DOMAIN":
		err = addDomain(input.Username, input.Domain, input.DocumentRoot)
	default:
		fail("UNSUPPORTED_OPERATION", "This provisioning operation is not supported.")
	}
	if err != nil { fmt.Fprintln(os.Stderr, err.Error()); os.Exit(1) }
	fmt.Printf("Nexora operation %s completed for %s.\n", input.Operation, input.Username)
}

func fail(code, message string) { fmt.Fprintf(os.Stderr, "%s: %s\n", code, message); os.Exit(1) }

func verifiedAccount(username string) (*user.User, *user.Group, error) {
	home := filepath.Join("/home", username)
	account, err := user.Lookup(username)
	if err != nil { return nil, nil, fmt.Errorf("ACCOUNT_NOT_FOUND: hosting account does not exist") }
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid < 1000 || filepath.Clean(account.HomeDir) != home {
		return nil, nil, fmt.Errorf("ACCOUNT_CONFLICT: existing Linux user is not a verified hosting account")
	}
	group, err := user.LookupGroupId(account.Gid)
	if err != nil { return nil, nil, fmt.Errorf("GROUP_LOOKUP_FAILED: unable to verify account group") }
	passwd, err := exec.Command("/usr/bin/getent", "passwd", username).Output()
	if err != nil { return nil, nil, fmt.Errorf("ACCOUNT_VERIFY_FAILED: unable to verify account login shell") }
	fields := strings.Split(strings.TrimSpace(string(passwd)), ":")
	if len(fields) != 7 || fields[6] != "/usr/sbin/nologin" {
		return nil, nil, fmt.Errorf("ACCOUNT_CONFLICT: hosting users must use /usr/sbin/nologin")
	}
	return account, group, nil
}

func provisionAccount(username string) error {
	home := filepath.Join("/home", username)
	account, lookupErr := user.Lookup(username)
	if lookupErr != nil {
		var unknown user.UnknownUserError
		if !errors.As(lookupErr, &unknown) { return fmt.Errorf("USER_LOOKUP_FAILED: unable to verify Linux account") }
		args := []string{"--create-home", "--home-dir", home, "--shell", "/usr/sbin/nologin"}
		if _, err := user.LookupGroup(username); err == nil { args = append(args, "--gid", username) } else { args = append(args, "--user-group") }
		args = append(args, username)
		if output, err := exec.Command("/usr/sbin/useradd", args...).CombinedOutput(); err != nil { return fmt.Errorf("USER_CREATE_FAILED: %s", safeOutput(string(output))) }
		account, lookupErr = user.Lookup(username)
		if lookupErr != nil { return fmt.Errorf("USER_LOOKUP_FAILED: account was created but could not be verified") }
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid < 1000 || filepath.Clean(account.HomeDir) != home { return fmt.Errorf("ACCOUNT_CONFLICT: existing Linux user does not have the expected hosting identity") }
	group, err := user.LookupGroupId(account.Gid)
	if err != nil { return fmt.Errorf("GROUP_LOOKUP_FAILED: unable to verify account group") }
	passwd, err := exec.Command("/usr/bin/getent", "passwd", username).Output()
	if err != nil { return fmt.Errorf("ACCOUNT_VERIFY_FAILED: unable to verify account login shell") }
	fields := strings.Split(strings.TrimSpace(string(passwd)), ":")
	if len(fields) != 7 || fields[6] != "/usr/sbin/nologin" { return fmt.Errorf("ACCOUNT_CONFLICT: hosting users must use /usr/sbin/nologin") }
	for _, path := range []string{"/home", home, filepath.Join(home, "public_html")} {
		if info, e := os.Lstat(path); e == nil && info.Mode()&os.ModeSymlink != 0 { return fmt.Errorf("PATH_CONFLICT: refusing symbolic link in hosting home path") } else if e != nil && !errors.Is(e, os.ErrNotExist) { return fmt.Errorf("PATH_CHECK_FAILED: unable to verify hosting directory") }
	}
	if err := os.MkdirAll(home, 0750); err != nil { return fmt.Errorf("HOME_CREATE_FAILED: unable to create account home") }
	if err := os.Chown(home, uid, mustGID(group.Gid)); err != nil { return fmt.Errorf("HOME_PERMISSION_FAILED: unable to set account ownership") }
	if err := os.Chmod(home, 0750); err != nil { return fmt.Errorf("HOME_PERMISSION_FAILED: unable to set account permissions") }
	publicHTML := filepath.Join(home, "public_html")
	if err := os.MkdirAll(publicHTML, 0750); err != nil { return fmt.Errorf("DOCUMENT_ROOT_CREATE_FAILED: unable to create public_html") }
	if err := os.Chown(publicHTML, uid, mustGID(group.Gid)); err != nil { return fmt.Errorf("DOCUMENT_ROOT_PERMISSION_FAILED: unable to set document root ownership") }
	if err := os.Chmod(publicHTML, 0750); err != nil { return fmt.Errorf("DOCUMENT_ROOT_PERMISSION_FAILED: unable to set document root permissions") }
	index := filepath.Join(publicHTML, "index.html")
	file, err := os.OpenFile(index, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if err == nil {
		_, writeErr := file.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>Hosting account ready</title></head><body><h1>Hosting account provisioned</h1><p>Website service configuration is not enabled yet.</p></body></html>\n")
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil { return fmt.Errorf("DEFAULT_PAGE_FAILED: unable to write initial index page") }
		if err := os.Chown(index, uid, mustGID(group.Gid)); err != nil { return fmt.Errorf("DEFAULT_PAGE_PERMISSION_FAILED: unable to set initial page ownership") }
	} else if !errors.Is(err, os.ErrExist) { return fmt.Errorf("DEFAULT_PAGE_FAILED: unable to create initial index page") }
	return nil
}

func addDomain(username, domain, documentRoot string) error {
	if !domainPattern.MatchString(domain) || len(domain) > 253 { return fmt.Errorf("INVALID_DOMAIN: domain name is invalid") }
	home := filepath.Join("/home", username)
	if documentRoot == "" { documentRoot = filepath.Join(home, "public_html") }
	if !filepath.IsAbs(documentRoot) || filepath.Clean(documentRoot) != documentRoot {
		return fmt.Errorf("INVALID_DOCUMENT_ROOT: document root must be a clean absolute path")
	}
	rel, err := filepath.Rel(home, documentRoot)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("INVALID_DOCUMENT_ROOT: document root must be inside the hosting account home")
	}
	account, group, err := verifiedAccount(username)
	if err != nil { return err }
	uid, _ := strconv.Atoi(account.Uid)
	gid := mustGID(group.Gid)
	if err := ensureSafeDirectory(home, documentRoot, uid, gid); err != nil { return err }
	if err := runFixed("/usr/bin/setfacl", "-m", "u:www-data:--x", home); err != nil { return fmt.Errorf("ACL_FAILED: unable to grant web server home traversal") }
	if err := runFixed("/usr/bin/setfacl", "-R", "-m", "u:www-data:rX", documentRoot); err != nil { return fmt.Errorf("ACL_FAILED: unable to grant web server document access") }
	if err := runFixed("/usr/bin/setfacl", "-m", "d:u:www-data:rX", documentRoot); err != nil { return fmt.Errorf("ACL_FAILED: unable to set default web server access") }
	if err := configureNginx(username, domain, documentRoot); err != nil { return err }
	return nil
}

func ensureSafeDirectory(home, target string, uid, gid int) error {
	for _, p := range []string{"/home", home} {
		info, err := os.Lstat(p)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() { return fmt.Errorf("PATH_CONFLICT: hosting home path is missing, unsafe, or not a directory") }
	}
	rel, _ := filepath.Rel(home, target)
	current := home
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0750); err != nil { return fmt.Errorf("DOCUMENT_ROOT_CREATE_FAILED: unable to create document root") }
			if err := os.Chown(current, uid, gid); err != nil { return fmt.Errorf("DOCUMENT_ROOT_PERMISSION_FAILED: unable to set ownership") }
			info, err = os.Lstat(current)
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() { return fmt.Errorf("PATH_CONFLICT: refusing symlink or non-directory in document root path") }
	}
	return nil
}

func configureNginx(username, domain, root string) error {
	if _, err := os.Stat("/usr/sbin/nginx"); err != nil { return fmt.Errorf("NGINX_NOT_INSTALLED: install and start Nginx before adding a domain") }
	if _, err := os.Stat("/usr/bin/setfacl"); err != nil { return fmt.Errorf("ACL_TOOL_MISSING: install the acl package before adding a domain") }
	// One deterministic vhost per domain; the domain has already passed strict DNS-label validation.
	fileKey := strings.ReplaceAll(domain, ".", "_")
	available := filepath.Join("/etc/nginx/sites-available", "nexora-"+fileKey)
	enabled := filepath.Join("/etc/nginx/sites-enabled", "nexora-"+fileKey)
	content := fmt.Sprintf("server {\n    listen 80;\n    server_name %s;\n\n    root %s;\n    index index.html index.htm;\n\n    access_log /var/log/nginx/nexora-%s.access.log;\n    error_log /var/log/nginx/nexora-%s.error.log;\n\n    location / {\n        try_files $uri $uri/ =404;\n    }\n\n    location ~ /\\. {\n        deny all;\n    }\n}\n", domain, root, fileKey, fileKey)
	if err := os.MkdirAll("/etc/nginx/sites-available", 0755); err != nil { return fmt.Errorf("NGINX_CONFIG_FAILED: unable to access Nginx configuration directory") }
	if err := os.MkdirAll("/etc/nginx/sites-enabled", 0755); err != nil { return fmt.Errorf("NGINX_CONFIG_FAILED: unable to access Nginx enabled directory") }
	tmp, err := os.CreateTemp("/etc/nginx/sites-available", ".nexora-domain-*")
	if err != nil { return fmt.Errorf("NGINX_CONFIG_FAILED: unable to create temporary configuration") }
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(content); err != nil { tmp.Close(); return fmt.Errorf("NGINX_CONFIG_FAILED: unable to write configuration") }
	if err := tmp.Chmod(0644); err != nil { tmp.Close(); return fmt.Errorf("NGINX_CONFIG_FAILED: unable to set configuration permissions") }
	if err := tmp.Close(); err != nil { return fmt.Errorf("NGINX_CONFIG_FAILED: unable to close configuration") }
	backup := available + ".nexora-backup"
	_, oldErr := os.Lstat(available)
	if oldErr == nil {
		_ = os.Remove(backup)
		if err := os.Rename(available, backup); err != nil { return fmt.Errorf("NGINX_CONFIG_FAILED: unable to preserve previous configuration") }
	} else if !errors.Is(oldErr, os.ErrNotExist) { return fmt.Errorf("NGINX_CONFIG_FAILED: unable to inspect previous configuration") }
	rollback := func() {
		_ = os.Remove(available)
		if oldErr == nil { _ = os.Rename(backup, available) }
	}
	if err := os.Rename(tmpName, available); err != nil { rollback(); return fmt.Errorf("NGINX_CONFIG_FAILED: unable to install configuration") }
	linkInfo, linkErr := os.Lstat(enabled)
	if linkErr == nil && (linkInfo.Mode()&os.ModeSymlink == 0 || filepath.Clean(mustReadlink(enabled)) != available) {
		rollback()
		return fmt.Errorf("NGINX_CONFIG_CONFLICT: enabled site path already belongs to another configuration")
	}
	if errors.Is(linkErr, os.ErrNotExist) {
		if err := os.Symlink(available, enabled); err != nil { rollback(); return fmt.Errorf("NGINX_CONFIG_FAILED: unable to enable site") }
	} else if linkErr != nil { rollback(); return fmt.Errorf("NGINX_CONFIG_FAILED: unable to inspect enabled site") }
	if err := runFixed("/usr/sbin/nginx", "-t"); err != nil {
		if errors.Is(linkErr, os.ErrNotExist) { _ = os.Remove(enabled) }
		rollback()
		return fmt.Errorf("NGINX_TEST_FAILED: Nginx rejected the new configuration")
	}
	if err := runFixed("/usr/bin/systemctl", "reload", "nginx"); err != nil {
		if errors.Is(linkErr, os.ErrNotExist) { _ = os.Remove(enabled) }
		rollback()
		_ = runFixed("/usr/sbin/nginx", "-t")
		return fmt.Errorf("NGINX_RELOAD_FAILED: Nginx configuration was restored; reload failed")
	}
	_ = os.Remove(backup)
	_ = username
	return nil
}

func mustReadlink(path string) string { target, _ := os.Readlink(path); return target }
func runFixed(path string, args ...string) error {
	cmd := exec.Command(path, args...)
	if output, err := cmd.CombinedOutput(); err != nil { return fmt.Errorf("%s", safeOutput(string(output))) }
	return nil
}
func mustGID(value string) int { gid, _ := strconv.Atoi(value); return gid }
func safeOutput(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 240 { value = value[:240] }
	if value == "" { return "system command failed" }
	return value
}
