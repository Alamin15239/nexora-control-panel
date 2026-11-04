package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	legacyDefaultIndexHTML = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Hosting account ready</title></head><body><h1>Hosting account provisioned</h1><p>Website service configuration is not enabled yet.</p></body></html>\n"
	defaultIndexHTML = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Website ready</title></head><body><main><h1>Your website is ready</h1><p>Your hosting account has been created successfully.</p><p>Upload your website files to this domain using Nexora File Manager. Replace this index.html file with your own website homepage.</p></main></body></html>\n"
)

type request struct {
	Operation    string `json:"operation"`
	Username     string `json:"username"`
	Domain       string `json:"domain,omitempty"`
	DocumentRoot string `json:"documentRoot,omitempty"`
	Path string `json:"path,omitempty"`
	NewPath string `json:"newPath,omitempty"`
	ContentBase64 string `json:"contentBase64,omitempty"`
	FileOperation string `json:"fileOperation,omitempty"`
	DatabaseName string `json:"databaseName,omitempty"`
}

var (
	usernamePattern = regexp.MustCompile("^[a-z][a-z0-9_]{2,15}$")
	domainPattern = regexp.MustCompile("^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\\.(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+$")
	documentRootPattern = regexp.MustCompile("^/home/[a-z][a-z0-9_]{2,15}/public_html(?:/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$")
	databaseNamePattern = regexp.MustCompile("^[a-z][a-z0-9_]{1,63}$")
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
	case "FILE_MANAGER":
		err = fileManager(input)
		if err != nil { fmt.Fprintln(os.Stderr, err.Error()); os.Exit(1) }
		return
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
	if err := configurePHPFPM(username); err != nil { return err }
	index := filepath.Join(publicHTML, "index.html")
	file, err := os.OpenFile(index, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if err == nil {
		_, writeErr := file.WriteString(defaultIndexHTML)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil { return fmt.Errorf("DEFAULT_PAGE_FAILED: unable to write initial index page") }
		if err := os.Chown(index, uid, mustGID(group.Gid)); err != nil { return fmt.Errorf("DEFAULT_PAGE_PERMISSION_FAILED: unable to set initial page ownership") }
	} else if !errors.Is(err, os.ErrExist) { return fmt.Errorf("DEFAULT_PAGE_FAILED: unable to create initial index page") }
	return nil
}


func upgradeLegacyDefaultIndex(documentRoot string, uid, gid int) error {
	index := filepath.Join(documentRoot, "index.html")
	info, err := os.Lstat(index)
	if errors.Is(err, os.ErrNotExist) { return nil }
	if err != nil { return fmt.Errorf("DEFAULT_PAGE_CHECK_FAILED: unable to inspect the default index page") }
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("DEFAULT_PAGE_CONFLICT: refusing to replace a non-regular index.html")
	}
	if info.Size() > 4096 { return nil }
	data, err := os.ReadFile(index)
	if err != nil { return fmt.Errorf("DEFAULT_PAGE_CHECK_FAILED: unable to read the default index page") }
	if string(data) != legacyDefaultIndexHTML { return nil }

	tmp, err := os.CreateTemp(documentRoot, ".nexora-index-*")
	if err != nil { return fmt.Errorf("DEFAULT_PAGE_UPDATE_FAILED: unable to create a replacement index page") }
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(defaultIndexHTML); err != nil { tmp.Close(); return fmt.Errorf("DEFAULT_PAGE_UPDATE_FAILED: unable to write replacement index page") }
	if err := tmp.Chmod(0640); err != nil { tmp.Close(); return fmt.Errorf("DEFAULT_PAGE_UPDATE_FAILED: unable to set index page permissions") }
	if err := tmp.Chown(uid, gid); err != nil { tmp.Close(); return fmt.Errorf("DEFAULT_PAGE_UPDATE_FAILED: unable to set index page ownership") }
	if err := tmp.Close(); err != nil { return fmt.Errorf("DEFAULT_PAGE_UPDATE_FAILED: unable to close replacement index page") }
	if err := os.Rename(tmpName, index); err != nil { return fmt.Errorf("DEFAULT_PAGE_UPDATE_FAILED: unable to activate replacement index page") }
	return nil
}

// createDefaultIndexForEmptyDomain creates a starter homepage only when the
// newly provisioned document root is completely empty. Existing customer files
// and index pages are never overwritten.
func createDefaultIndexForEmptyDomain(documentRoot string, uid, gid int) error {
	entries, err := os.ReadDir(documentRoot)
	if err != nil {
		return fmt.Errorf("DEFAULT_PAGE_CHECK_FAILED: unable to inspect the document root")
	}
	if len(entries) != 0 {
		return nil
	}

	index := filepath.Join(documentRoot, "index.html")
	file, err := os.OpenFile(index, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("DEFAULT_PAGE_FAILED: unable to create the initial domain homepage")
	}
	_, writeErr := file.WriteString(defaultIndexHTML)
	chmodErr := file.Chmod(0640)
	chownErr := file.Chown(uid, gid)
	closeErr := file.Close()
	if writeErr != nil || chmodErr != nil || chownErr != nil || closeErr != nil {
		_ = os.Remove(index)
		return fmt.Errorf("DEFAULT_PAGE_FAILED: unable to write or secure the initial domain homepage")
	}
	return nil
}

func addDomain(username, domain, documentRoot string) error {
	if !domainPattern.MatchString(domain) || len(domain) > 253 { return fmt.Errorf("INVALID_DOMAIN: domain name is invalid") }
	home := filepath.Join("/home", username)
	if documentRoot == "" { documentRoot = filepath.Join(home, "public_html") }
	if !validDocumentRoot(documentRoot) {
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
	if err := upgradeLegacyDefaultIndex(documentRoot, uid, gid); err != nil { return err }
	if err := createDefaultIndexForEmptyDomain(documentRoot, uid, gid); err != nil { return err }
	if err := runFixed("/usr/bin/setfacl", "-m", "u:www-data:--x", home); err != nil { return fmt.Errorf("ACL_FAILED: unable to grant web server home traversal") }
	if err := runFixed("/usr/bin/setfacl", "-R", "-m", "u:www-data:rX", documentRoot); err != nil { return fmt.Errorf("ACL_FAILED: unable to grant web server document access") }
	if err := runFixed("/usr/bin/setfacl", "-m", "d:u:www-data:rX", documentRoot); err != nil { return fmt.Errorf("ACL_FAILED: unable to set default web server access") }
	if err := configureNginx(username, domain, documentRoot); err != nil { return err }
	return nil
}


const maxManagedFileBytes = 256 * 1024

type managedFileEntry struct {
 Name string `json:"name"`
 IsDir bool `json:"isDir"`
 Size int64 `json:"size"`
 ModifiedAt string `json:"modifiedAt"`
}


// openDirectoryChain opens each path component relative to the previously
// opened directory. O_NOFOLLOW prevents symlink traversal at every level.
func openDirectoryChain(root string, parts ...string) (int, error) {
 fd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
 if err != nil { return -1, err }
 for _, part := range parts {
  if part == "" || part == "." || part == ".." || strings.Contains(part, string(filepath.Separator)) {
   _ = syscall.Close(fd)
   return -1, fmt.Errorf("invalid directory component")
  }
  nextFD, openErr := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
  _ = syscall.Close(fd)
  if openErr != nil { return -1, openErr }
  fd = nextFD
 }
 return fd, nil
}

func fileManager(input request) error {
 account, group, err := verifiedAccount(input.Username)
 if err != nil { return err }
 uid, _ := strconv.Atoi(account.Uid)
 gid := mustGID(group.Gid)
 rootFD, err := openDirectoryChain("/", "home", input.Username, "public_html")
 if err != nil { return fmt.Errorf("FILE_ROOT_UNAVAILABLE: hosting document root is missing or unsafe") }
 runtime.LockOSThread()
 if err := syscall.Fchdir(rootFD); err != nil {
  _ = syscall.Close(rootFD)
  return fmt.Errorf("FILE_SANDBOX_FAILED: unable to enter the hosting document root")
 }
 _ = syscall.Close(rootFD)
 // Chroot to the already-open directory descriptor's working directory.
 // This prevents a path replacement between validation and chroot.
 if err := syscall.Chroot("."); err != nil { return fmt.Errorf("FILE_SANDBOX_FAILED: unable to enter the hosting document root") }
 if err := os.Chdir("/"); err != nil { return fmt.Errorf("FILE_SANDBOX_FAILED: unable to enter the hosting document root") }
 if err := syscall.Setgroups([]int{gid}); err != nil { return fmt.Errorf("FILE_SANDBOX_FAILED: unable to set account groups") }
 if err := syscall.Setgid(gid); err != nil { return fmt.Errorf("FILE_SANDBOX_FAILED: unable to drop group privileges") }
 if err := syscall.Setuid(uid); err != nil { return fmt.Errorf("FILE_SANDBOX_FAILED: unable to drop user privileges") }
 writeResult := func(value any) error { return json.NewEncoder(os.Stdout).Encode(value) }
 return fileManagerOperation(input, "/", writeResult)
}

func managedParentPath(value string) string {
 parent := filepath.ToSlash(filepath.Dir(value))
 if parent == "." { return "" }
 return parent
}

func safeManagedPath(root, relative string, allowRoot bool) (string, os.FileInfo, error) {
 if relative == "" {
  if allowRoot { info, err := os.Lstat(root); return root, info, err }
  return "", nil, fmt.Errorf("INVALID_PATH: a file path is required")
 }
 if len(relative) > 1024 || strings.Contains(relative, "\\") || filepath.IsAbs(relative) {
  return "", nil, fmt.Errorf("INVALID_PATH: file path is invalid")
 }
 parts := strings.Split(relative, "/")
 current := root
 for i, part := range parts {
  if part == "" || part == "." || part == ".." || len(part) > 128 || !regexp.MustCompile("^[A-Za-z0-9._ -]+$").MatchString(part) {
   return "", nil, fmt.Errorf("INVALID_PATH: file path contains an invalid component")
  }
  current = filepath.Join(current, part)
  info, err := os.Lstat(current)
  if errors.Is(err, os.ErrNotExist) && i == len(parts)-1 { return current, nil, nil }
  if err != nil { return "", nil, fmt.Errorf("FILE_NOT_FOUND: file or directory does not exist") }
  if info.Mode()&os.ModeSymlink != 0 { return "", nil, fmt.Errorf("UNSAFE_PATH: symbolic links are not allowed in the File Manager") }
  if i < len(parts)-1 && !info.IsDir() { return "", nil, fmt.Errorf("INVALID_PATH: a parent path is not a directory") }
  if i == len(parts)-1 { return current, info, nil }
 }
 return "", nil, fmt.Errorf("INVALID_PATH: file path is invalid")
}

func fileManagerOperation(input request, root string, writeResult func(any) error) error {
 switch input.FileOperation {
 case "LIST_FILES":
  path, info, err := safeManagedPath(root, input.Path, true)
  if err != nil { return err }
  if info == nil || !info.IsDir() { return fmt.Errorf("NOT_A_DIRECTORY: selected path is not a directory") }
  items, err := os.ReadDir(path)
  if err != nil { return fmt.Errorf("DIRECTORY_READ_FAILED: unable to read directory") }
  entries := make([]managedFileEntry, 0, len(items))
  for _, item := range items {
   entryInfo, err := item.Info()
   if err != nil || item.Type()&os.ModeSymlink != 0 { continue }
   entries = append(entries, managedFileEntry{Name:item.Name(), IsDir:entryInfo.IsDir(), Size:entryInfo.Size(), ModifiedAt:entryInfo.ModTime().UTC().Format(time.RFC3339)})
   if len(entries) >= 1000 { break }
  }
  return writeResult(map[string]any{"path":input.Path,"entries":entries})
 case "READ_FILE":
  path, info, err := safeManagedPath(root, input.Path, false)
  if err != nil { return err }
  if info == nil || !info.Mode().IsRegular() { return fmt.Errorf("NOT_A_FILE: selected path is not a regular file") }
  if info.Size() > maxManagedFileBytes { return fmt.Errorf("FILE_TOO_LARGE: files larger than 256 KiB cannot be opened in the editor") }
  data, err := os.ReadFile(path)
  if err != nil { return fmt.Errorf("FILE_READ_FAILED: unable to read selected file") }
  return writeResult(map[string]any{"path":input.Path,"contentBase64":base64.StdEncoding.EncodeToString(data),"size":len(data)})
 case "WRITE_FILE":
  data, err := base64.StdEncoding.DecodeString(input.ContentBase64)
  if err != nil || len(data) > maxManagedFileBytes { return fmt.Errorf("INVALID_FILE_CONTENT: file content is invalid or exceeds 256 KiB") }
  path, info, err := safeManagedPath(root, input.Path, false)
  if err != nil { return err }
  if info != nil && !info.Mode().IsRegular() { return fmt.Errorf("NOT_A_FILE: only regular files can be edited") }
  if info == nil {
   _, parentInfo, e := safeManagedPath(root, managedParentPath(input.Path), true)
   if e != nil || parentInfo == nil || !parentInfo.IsDir() { return fmt.Errorf("INVALID_PATH: parent directory does not exist") }
  }
  tmp, err := os.CreateTemp(filepath.Dir(path), ".nexora-file-*")
  if err != nil { return fmt.Errorf("FILE_WRITE_FAILED: unable to create temporary file") }
  tmpName := tmp.Name()
  defer os.Remove(tmpName)
  if _, err = tmp.Write(data); err != nil { tmp.Close(); return fmt.Errorf("FILE_WRITE_FAILED: unable to write file content") }
  if err = tmp.Chmod(0640); err != nil { tmp.Close(); return fmt.Errorf("FILE_WRITE_FAILED: unable to set file permissions") }
  if err = tmp.Close(); err != nil { return fmt.Errorf("FILE_WRITE_FAILED: unable to close file") }
  if err = os.Rename(tmpName, path); err != nil { return fmt.Errorf("FILE_WRITE_FAILED: unable to replace file") }
  return writeResult(map[string]any{"success":true,"path":input.Path,"size":len(data)})
 case "CREATE_DIRECTORY":
  path, info, err := safeManagedPath(root, input.Path, false)
  if err != nil { return err }
  if info != nil { return fmt.Errorf("PATH_EXISTS: a file or directory already exists at this path") }
  _, parentInfo, err := safeManagedPath(root, managedParentPath(input.Path), true)
  if err != nil || parentInfo == nil || !parentInfo.IsDir() { return fmt.Errorf("INVALID_PATH: parent directory does not exist") }
  if err := os.Mkdir(path, 0750); err != nil { return fmt.Errorf("DIRECTORY_CREATE_FAILED: unable to create directory") }
  return writeResult(map[string]any{"success":true,"path":input.Path})
 case "RENAME_PATH":
  if input.Path == "" || input.NewPath == "" { return fmt.Errorf("INVALID_PATH: the document root cannot be renamed") }
  oldPath, oldInfo, err := safeManagedPath(root, input.Path, false)
  if err != nil { return err }
  if oldInfo == nil { return fmt.Errorf("FILE_NOT_FOUND: source does not exist") }
  newPath, newInfo, err := safeManagedPath(root, input.NewPath, false)
  if err != nil { return err }
  if newInfo != nil { return fmt.Errorf("PATH_EXISTS: destination already exists") }
  _, parentInfo, err := safeManagedPath(root, managedParentPath(input.NewPath), true)
  if err != nil || parentInfo == nil || !parentInfo.IsDir() { return fmt.Errorf("INVALID_PATH: destination directory does not exist") }
  if err := os.Rename(oldPath, newPath); err != nil { return fmt.Errorf("RENAME_FAILED: unable to rename selected item") }
  return writeResult(map[string]any{"success":true,"path":input.NewPath})
 case "DELETE_PATH":
  if input.Path == "" { return fmt.Errorf("INVALID_PATH: the document root cannot be deleted") }
  path, info, err := safeManagedPath(root, input.Path, false)
  if err != nil { return err }
  if info == nil { return fmt.Errorf("FILE_NOT_FOUND: selected item does not exist") }
  if err := os.RemoveAll(path); err != nil { return fmt.Errorf("DELETE_FAILED: unable to delete selected item") }
  return writeResult(map[string]any{"success":true,"path":input.Path})
 default:
  return fmt.Errorf("INVALID_FILE_OPERATION: unsupported file manager operation")
 }
}

func validDocumentRoot(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && documentRootPattern.MatchString(path)
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
	content := fmt.Sprintf("server {\n    listen 80;\n    server_name %s;\n\n    root %s;\n    index index.php index.html index.htm;\n\n    access_log /var/log/nginx/nexora-%s.access.log;\n    error_log /var/log/nginx/nexora-%s.error.log;\n\n    location / {\n        try_files $uri $uri/ =404;\n    }\n\n    location ~ [.]php$ {\n        try_files $uri =404;\n        include fastcgi_params;\n        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n        fastcgi_pass unix:/run/php/nexora-%s.sock;\n    }\n\n    location ~ /[.] {\n        deny all;\n    }\n}\n", domain, root, fileKey, fileKey, username)
	if err := os.MkdirAll("/etc/nginx/sites-available", 0755); err != nil { return fmt.Errorf("NGINX_CONFIG_FAILED: unable to access Nginx configuration directory") }
	if err := os.MkdirAll("/etc/nginx/sites-enabled", 0755); err != nil { return fmt.Errorf("NGINX_CONFIG_FAILED: unable to access Nginx enabled directory") }
	duplicates, err := findDuplicateNexoraVhosts("/etc/nginx/sites-enabled", "/etc/nginx/sites-available", enabled, domain, root)
	if err != nil { return fmt.Errorf("NGINX_CONFIG_CONFLICT: %s", safeOutput(err.Error())) }
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
	removedDuplicates := make([]duplicateVhost, 0, len(duplicates))
	for _, duplicate := range duplicates {
		if err := os.Remove(duplicate.link); err != nil {
			for _, removed := range removedDuplicates { _ = os.Symlink(removed.target, removed.link) }
			if errors.Is(linkErr, os.ErrNotExist) { _ = os.Remove(enabled) }
			rollback()
			return fmt.Errorf("NGINX_CONFIG_FAILED: unable to disable duplicate Nexora site")
		}
		removedDuplicates = append(removedDuplicates, duplicate)
	}
	restoreDuplicates := func() {
		for _, removed := range removedDuplicates { _ = os.Symlink(removed.target, removed.link) }
	}
	if err := runFixed("/usr/sbin/nginx", "-t"); err != nil {
		restoreDuplicates()
		if errors.Is(linkErr, os.ErrNotExist) { _ = os.Remove(enabled) }
		rollback()
		return fmt.Errorf("NGINX_TEST_FAILED: %s", safeOutput(err.Error()))
	}
	if err := runFixed("/usr/bin/systemctl", "reload", "nginx"); err != nil {
		restoreDuplicates()
		if errors.Is(linkErr, os.ErrNotExist) { _ = os.Remove(enabled) }
		rollback()
		// The running Nginx master keeps its last valid configuration when a
		// reload fails. Verify that the restored on-disk configuration is valid
		// and retain both diagnostics for the agent's provisioning-job record.
		if testErr := runFixed("/usr/sbin/nginx", "-t"); testErr != nil {
			return fmt.Errorf("NGINX_RELOAD_FAILED: %s; restored configuration test also failed: %s", safeOutput(err.Error()), safeOutput(testErr.Error()))
		}
		return fmt.Errorf("NGINX_RELOAD_FAILED: %s; previous configuration restored", safeOutput(err.Error()))
	}
	_ = os.Remove(backup)
	_ = username
	return nil
}

type duplicateVhost struct {
	link string
	target string
}

func findDuplicateNexoraVhosts(enabledDir, availableDir, keepLink, domain, root string) ([]duplicateVhost, error) {
	entries, err := os.ReadDir(enabledDir)
	if err != nil { return nil, err }
	var duplicates []duplicateVhost
	for _, entry := range entries {
		link := filepath.Join(enabledDir, entry.Name())
		if link == keepLink { continue }
		info, err := os.Lstat(link)
		if err != nil { return nil, err }
		if info.Mode()&os.ModeSymlink == 0 { continue }
		target, err := filepath.EvalSymlinks(link)
		if err != nil { continue }
		rel, err := filepath.Rel(availableDir, target)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || !strings.HasPrefix(filepath.Base(target), "nexora-") { continue }
		data, err := os.ReadFile(target)
		if err != nil { continue }
		if nginxConfigMatchesDomainRoot(string(data), domain, root) {
			duplicates = append(duplicates, duplicateVhost{link: link, target: target})
		}
	}
	return duplicates, nil
}

func nginxConfigMatchesDomainRoot(content, domain, root string) bool {
	foundDomain, foundRoot := false, false
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 { continue }
		if fields[0] == "server_name" {
			for _, name := range fields[1:] {
				if strings.TrimSuffix(name, ";") == domain { foundDomain = true }
			}
		}
		if fields[0] == "root" && strings.TrimSuffix(fields[1], ";") == root { foundRoot = true }
	}
	return foundDomain && foundRoot
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


const phpFPMDisabledFunctions = "exec,shell_exec,system,passthru,proc_open,popen,pcntl_exec"

// phpFPMPoolConfig keeps account-specific PHP restrictions in the dedicated
// FPM pool rather than changing the server-wide PHP configuration.
func phpFPMPoolConfig(username string) string {
	return fmt.Sprintf(`[nexora-%s]
user = %s
group = %s
listen = /run/php/nexora-%s.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = ondemand
pm.max_children = 5
pm.process_idle_timeout = 10s
pm.max_requests = 500
chdir = /
clear_env = yes
security.limit_extensions = .php
php_admin_flag[allow_url_include] = off
php_admin_value[disable_functions] = %s
php_admin_value[open_basedir] = /home/%s:/tmp:/usr/share/php
`, username, username, username, username, phpFPMDisabledFunctions, username)
}

func configurePHPFPM(username string) error {
	if _, err := os.Stat("/usr/bin/php"); err != nil {
		if err := runFixed("/usr/bin/apt-get", "update"); err != nil { return fmt.Errorf("PHP_PACKAGE_INDEX_FAILED: %s", safeOutput(err.Error())) }
		if err := runFixed("/usr/bin/apt-get", "install", "-y", "php-fpm", "php-cli"); err != nil { return fmt.Errorf("PHP_INSTALL_FAILED: %s", safeOutput(err.Error())) }
	}
	versionOutput, err := exec.Command("/usr/bin/php", "-r", "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;").Output()
	if err != nil { return fmt.Errorf("PHP_VERSION_FAILED: unable to detect installed PHP version") }
	version := strings.TrimSpace(string(versionOutput))
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+$`).MatchString(version) { return fmt.Errorf("PHP_VERSION_FAILED: detected PHP version is invalid") }
	poolDir := filepath.Join("/etc/php", version, "fpm", "pool.d")
	if info, err := os.Stat(poolDir); err != nil || !info.IsDir() { return fmt.Errorf("PHP_POOL_DIRECTORY_MISSING: PHP-FPM pool directory is unavailable") }
	poolPath := filepath.Join(poolDir, "nexora-"+username+".conf")
	pool := phpFPMPoolConfig(username)
	if err := writeAtomicRootFile(poolPath, pool, 0640); err != nil { return fmt.Errorf("PHP_POOL_CONFIG_FAILED: %s", safeOutput(err.Error())) }
	service := "php" + version + "-fpm"
	if err := runFixed("/usr/bin/systemctl", "enable", "--now", service); err != nil { return fmt.Errorf("PHP_FPM_SERVICE_FAILED: %s", safeOutput(err.Error())) }
	if err := runFixed("/usr/bin/systemctl", "restart", service); err != nil { return fmt.Errorf("PHP_FPM_RESTART_FAILED: %s", safeOutput(err.Error())) }
	if _, err := os.Stat("/run/php/nexora-"+username+".sock"); err != nil { return fmt.Errorf("PHP_POOL_SOCKET_MISSING: dedicated PHP-FPM socket did not appear") }
	return nil
}

func writeAtomicRootFile(path, content string, mode os.FileMode) error {
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) { return fmt.Errorf("refusing to replace non-regular configuration file") } else if err != nil && !errors.Is(err, os.ErrNotExist) { return err }
	tmp, err := os.CreateTemp(filepath.Dir(path), ".nexora-php-*")
	if err != nil { return err }
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.WriteString(content); err != nil { tmp.Close(); return err }
	if err := tmp.Chmod(mode); err != nil { tmp.Close(); return err }
	if err := tmp.Close(); err != nil { return err }
	return os.Rename(tmpPath, path)
}
