package main

import (
        "crypto/rand"
        "encoding/base64"
        "encoding/json"
        "errors"
        "fmt"
        "io"
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
        defaultIndexHTML       = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Website ready</title></head><body><main><h1>Your website is ready</h1><p>Your hosting account has been created successfully.</p><p>Upload your website files to this domain using Nexora File Manager. Replace this index.html file with your own website homepage.</p></main></body></html>\n"
)

type request struct {
        Operation         string   `json:"operation"`
        Username          string   `json:"username"`
        Domain            string   `json:"domain,omitempty"`
        DocumentRoot      string   `json:"documentRoot,omitempty"`
        Path              string   `json:"path,omitempty"`
        NewPath           string   `json:"newPath,omitempty"`
        ContentBase64     string   `json:"contentBase64,omitempty"`
        FileOperation     string   `json:"fileOperation,omitempty"`
        DatabaseName      string   `json:"databaseName,omitempty"`
        DatabaseUserName  string   `json:"databaseUserName,omitempty"`
        DatabaseUserNames []string `json:"databaseUserNames,omitempty"`
        Privileges        []string `json:"privileges,omitempty"`
        BackupID          string   `json:"backupId,omitempty"`
        ExpectedSHA256    string   `json:"sha256,omitempty"`
        DatabaseNames     []string `json:"databaseNames,omitempty"`
        PhpVersion        string   `json:"phpVersion,omitempty"`
        MemoryLimitMib    int      `json:"memoryLimitMib,omitempty"`
        MaxExecutionTime  int      `json:"maxExecutionTimeSeconds,omitempty"`
        UploadMaxFilesize int      `json:"uploadMaxFilesizeMib,omitempty"`
        MaxInputVars      int      `json:"maxInputVars,omitempty"`
        DisplayErrors     int      `json:"displayErrors,omitempty"`
}

var (
        usernamePattern     = regexp.MustCompile("^[a-z][a-z0-9_]{2,15}$")
        domainPattern       = regexp.MustCompile("^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\\.(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+$")
        documentRootPattern = regexp.MustCompile("^/home/[a-z][a-z0-9_]{2,15}/public_html(?:/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$")
        databaseNamePattern = regexp.MustCompile("^[a-z][a-z0-9_]{1,63}$")
)

func decodeRequest(reader io.Reader) (request, error) {
        const maxRequestBytes = 1 << 20

        rawRequest, err := io.ReadAll(io.LimitReader(reader, maxRequestBytes+1))
        if err != nil {
                return request{}, err
        }
        if len(rawRequest) > maxRequestBytes {
                return request{}, fmt.Errorf("request exceeds %d bytes", maxRequestBytes)
        }

        decoder := json.NewDecoder(strings.NewReader(string(rawRequest)))
        decoder.DisallowUnknownFields()

        var input request
        if err := decoder.Decode(&input); err != nil {
                return request{}, err
        }

        var trailing any
        if err := decoder.Decode(&trailing); err != io.EOF {
                if err == nil {
                        return request{}, fmt.Errorf("multiple JSON documents")
                }
                return request{}, err
        }

        return input, nil
}

func main() {
        if os.Geteuid() != 0 {
                fail("ROOT_REQUIRED", "The Nexora provisioning helper must run as root.")
        }
        input, requestErr := decodeRequest(os.Stdin)
        if requestErr != nil {
                fail("INVALID_REQUEST", "The provisioning request is invalid.")
        }
        if input.Operation == "DATABASE_USAGE" {
                if err := databaseUsage(); err != nil {
                        fail("DATABASE_USAGE_FAILED", "Unable to collect MariaDB database usage.")
                }
                return
        }
        if !usernamePattern.MatchString(input.Username) {
                fail("INVALID_USERNAME", "The hosting username is invalid.")
        }
        var err error
        switch input.Operation {
        case "CREATE_HOSTING_ACCOUNT":
                err = provisionAccount(input.Username)
        case "ADD_DOMAIN":
                err = addDomain(input.Username, input.Domain, input.DocumentRoot)
        case "FILE_MANAGER":
                err = fileManager(input)
                if err != nil {
                        fmt.Fprintln(os.Stderr, err.Error())
                        os.Exit(1)
                }
                return
        case "CREATE_DATABASE":
                err = createDatabase(input.DatabaseName, input.Username)
        case "CREATE_DATABASE_USER":
                if err := createDatabaseUser(input.DatabaseName, input.Username, input.DatabaseUserName, input.Privileges); err != nil {
                        fail("DATABASE_USER_CREATE_FAILED", "The MariaDB user could not be created.")
                }
                return
        case "REVOKE_DATABASE_USER":
                err = revokeDatabaseUser(input.Username, input.DatabaseUserName, input.DatabaseName)
        case "DELETE_DATABASE":
                err = deleteDatabase(input.Username, input.DatabaseName, input.DatabaseUserNames)
        case "CREATE_BACKUP":
                err = createAccountBackup(input.Username, input.BackupID, input.DatabaseNames)
                if err != nil {
                        fail("BACKUP_CREATE_FAILED", "The hosting account backup could not be created.")
                }
                return
        case "RESTORE_BACKUP":
                err = stageAccountBackupRestore(input.Username, input.BackupID, input.ExpectedSHA256)
                if err != nil {
                        fail("BACKUP_RESTORE_STAGE_FAILED", "The backup could not be staged for restore.")
                }
                return
        case "DELETE_BACKUP":
                err = deleteAccountBackup(input.Username, input.BackupID)
                if err != nil {
                        fail("BACKUP_DELETE_FAILED", "The backup archive could not be deleted.")
                }
                return
        case "UPDATE_PHP_POOL":
                settings := phpPoolSettings{
                        MemoryLimitMib: input.MemoryLimitMib, MaxExecutionTime: input.MaxExecutionTime,
                        UploadMaxFilesize: input.UploadMaxFilesize, MaxInputVars: input.MaxInputVars,
                        DisplayErrors: input.DisplayErrors,
                }
                err = updatePhpPool(input.Username, input.PhpVersion, settings)
                if err != nil { fail("PHP_POOL_UPDATE_FAILED", safeOutput(err.Error())) }
                return
        case "SUSPEND_HOSTING_ACCOUNT":
                err = suspendHostingAccount(input.Username)
        case "REACTIVATE_HOSTING_ACCOUNT":
                err = reactivateHostingAccount(input.Username)
        case "REMOVE_DOMAIN":
                err = removeDomain(input.Username, input.Domain)
        default:
                fail("UNSUPPORTED_OPERATION", "This provisioning operation is not supported.")
        }
        if err != nil {
                fmt.Fprintln(os.Stderr, err.Error())
                os.Exit(1)
        }
        fmt.Printf("Nexora operation %s completed for %s.\n", input.Operation, input.Username)
}

func fail(code, message string) { fmt.Fprintf(os.Stderr, "%s: %s\n", code, message); os.Exit(1) }

type databaseUsageEntry struct {
        Name      string `json:"name"`
        UsedBytes uint64 `json:"usedBytes"`
}

func databaseUsage() error {
        accounts, err := verifiedNexoraAccounts()
        if err != nil {
                return fmt.Errorf("managed account registry verification failed")
        }

        entries := make([]databaseUsageEntry, 0)
        if len(accounts) > 0 {
                prefixConditions := make([]string, 0, len(accounts))
                for _, account := range accounts {
                        prefix := account.Username + "_"
                        prefixConditions = append(prefixConditions,
                                fmt.Sprintf("LEFT(s.schema_name, %d) = %s", len(prefix), sqlString(prefix)))
                }

                statement := "SELECT s.schema_name, COALESCE(SUM(t.data_length + t.index_length), 0) " +
                        "FROM information_schema.schemata s " +
                        "LEFT JOIN information_schema.tables t ON t.table_schema = s.schema_name " +
                        "WHERE (" + strings.Join(prefixConditions, " OR ") + ") " +
                        "GROUP BY s.schema_name ORDER BY s.schema_name"

                output, err := exec.Command(
                        "/usr/bin/mariadb",
                        "--batch",
                        "--skip-column-names",
                        "-e",
                        statement,
                ).Output()
                if err != nil {
                        return fmt.Errorf("MariaDB usage query failed: %s", safeOutput(string(output)))
                }

                for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
                        if line == "" {
                                continue
                        }
                        fields := strings.Split(line, "\t")
                        if len(fields) != 2 || !databaseNamePattern.MatchString(fields[0]) {
                                return fmt.Errorf("MariaDB returned an invalid database usage row")
                        }

                        managed := false
                        for _, account := range accounts {
                                if validateManagedDatabaseName(fields[0], account.Username) == nil {
                                        managed = true
                                        break
                                }
                        }
                        if !managed {
                                return fmt.Errorf("MariaDB returned a database outside the managed account registry")
                        }

                        usedBytes, err := strconv.ParseUint(fields[1], 10, 64)
                        if err != nil {
                                return fmt.Errorf("MariaDB returned an invalid database size")
                        }
                        entries = append(entries, databaseUsageEntry{
                                Name: fields[0], UsedBytes: usedBytes,
                        })
                        if len(entries) > 100 {
                                return fmt.Errorf("database usage result exceeds the allowed limit")
                        }
                }
        }

        result, err := json.Marshal(map[string]any{"databases": entries})
        if err != nil {
                return err
        }
        _, err = os.Stdout.Write(append(result, '\n'))
        return err
}

func validateManagedDatabaseName(databaseName, accountName string) error {
        if !usernamePattern.MatchString(accountName) ||
                !databaseNamePattern.MatchString(databaseName) ||
                len(databaseName) > 64 ||
                !strings.HasPrefix(databaseName, accountName+"_") ||
                len(databaseName) <= len(accountName)+1 {
                return fmt.Errorf("INVALID_DATABASE_NAME: database does not belong to the hosting account")
        }
        return nil
}

func createDatabase(name, accountName string) error {
        if err := validateManagedDatabaseName(name, accountName); err != nil {
                return err
        }
        statement := "CREATE DATABASE IF NOT EXISTS `" + name + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
        output, err := exec.Command("/usr/bin/mariadb", "--batch", "--skip-column-names", "-e", statement).CombinedOutput()
        if err != nil {
                return fmt.Errorf("DATABASE_CREATE_FAILED: %s", safeOutput(string(output)))
        }
        return nil
}

var allowedDatabasePrivileges = map[string]bool{
        "SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": true,
        "CREATE": true, "ALTER": true, "INDEX": true,
}

func sqlString(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }

func normalizeDatabaseUserSuffix(accountName, requestedUser string) string {
        prefix := accountName + "_"
        for strings.HasPrefix(requestedUser, prefix) {
                requestedUser = strings.TrimPrefix(requestedUser, prefix)
        }
        return requestedUser
}

func createDatabaseUser(databaseName, accountName, requestedUser string, privileges []string) error {
        requestedUser = normalizeDatabaseUserSuffix(accountName, requestedUser)
        if validateManagedDatabaseName(databaseName, accountName) != nil ||
                !databaseNamePattern.MatchString(requestedUser) ||
                len(privileges) == 0 ||
                len(privileges) > len(allowedDatabasePrivileges) {
                return fmt.Errorf("INVALID_DATABASE_USER: database user request is invalid")
        }
        seen := map[string]bool{}
        for _, privilege := range privileges {
                if !allowedDatabasePrivileges[privilege] || seen[privilege] {
                        return fmt.Errorf("INVALID_DATABASE_PRIVILEGE: requested database privilege is not allowed")
                }
                seen[privilege] = true
        }
        physicalUser := accountName + "_" + requestedUser
        if len(physicalUser) > 80 {
                return fmt.Errorf("INVALID_DATABASE_USER: database username is too long")
        }
        secret := make([]byte, 32)
        if _, err := rand.Read(secret); err != nil {
                return fmt.Errorf("PASSWORD_GENERATION_FAILED: secure random source unavailable")
        }
        password := base64.RawURLEncoding.EncodeToString(secret)
        quotedUser := sqlString(physicalUser)
        account := quotedUser + "@'localhost'"
        quotedDB := "`" + strings.ReplaceAll(databaseName, "`", "``") + "`"
        grants := strings.Join(privileges, ", ")
        sql := "CREATE USER " + account + " IDENTIFIED BY " + sqlString(password) + "; GRANT " + grants + " ON " + quotedDB + ".* TO " + account + ";"
        command := exec.Command("/usr/bin/mariadb", "--batch", "--skip-column-names")
        command.Stdin = strings.NewReader(sql)
        output, err := command.CombinedOutput()
        if err != nil {
                cleanup := exec.Command("/usr/bin/mariadb", "--batch", "--skip-column-names", "-e", "DROP USER IF EXISTS "+account)
                _, _ = cleanup.CombinedOutput()
                return fmt.Errorf("DATABASE_USER_CREATE_FAILED: %s", safeOutput(string(output)))
        }
        result, _ := json.Marshal(map[string]string{"username": physicalUser, "password": password})
        _, err = os.Stdout.Write(append(result, '\n'))
        return err
}

func revokeDatabaseUser(accountName, requestedUser, databaseName string) error {
        if err := validateManagedDatabaseName(databaseName, accountName); err != nil {
                return err
        }
        requestedUser = normalizeDatabaseUserSuffix(accountName, requestedUser)
        if !usernamePattern.MatchString(accountName) || !databaseNamePattern.MatchString(requestedUser) {
                return fmt.Errorf("INVALID_DATABASE_USER: database username is invalid")
        }
        physicalUser := accountName + "_" + requestedUser
        if len(physicalUser) > 80 {
                return fmt.Errorf("INVALID_DATABASE_USER: database username is too long")
        }
        statement := "DROP USER IF EXISTS " + sqlString(physicalUser) + "@'localhost'"
        output, err := exec.Command("/usr/bin/mariadb", "--batch", "--skip-column-names", "-e", statement).CombinedOutput()
        if err != nil {
                return fmt.Errorf("DATABASE_USER_REVOKE_FAILED: %s", safeOutput(string(output)))
        }
        return nil
}

func validateDatabaseDeletionUsers(accountName string, databaseUserNames []string) ([]string, error) {
        if !usernamePattern.MatchString(accountName) {
                return nil, fmt.Errorf("INVALID_USERNAME: hosting account name is invalid")
        }
        if len(databaseUserNames) > 100 {
                return nil, fmt.Errorf("INVALID_DATABASE_USERS: too many database users")
        }
        prefix := accountName + "_"
        seen := make(map[string]bool, len(databaseUserNames))
        for _, fullName := range databaseUserNames {
                if !strings.HasPrefix(fullName, prefix) || len(fullName) > 80 {
                        return nil, fmt.Errorf("INVALID_DATABASE_USER: database username does not belong to the hosting account")
                }
                suffix := strings.TrimPrefix(fullName, prefix)
                if !databaseNamePattern.MatchString(suffix) || seen[fullName] {
                        return nil, fmt.Errorf("INVALID_DATABASE_USER: database username is invalid or duplicated")
                }
                seen[fullName] = true
        }
        return append([]string(nil), databaseUserNames...), nil
}

func deleteDatabase(accountName, databaseName string, databaseUserNames []string) error {
        if err := validateManagedDatabaseName(databaseName, accountName); err != nil {
                return err
        }
        users, err := validateDatabaseDeletionUsers(accountName, databaseUserNames)
        if err != nil {
                return err
        }
        statements := make([]string, 0, len(users)+1)
        for _, fullName := range users {
                statements = append(statements, "DROP USER IF EXISTS "+sqlString(fullName)+"@'localhost'")
        }
        statements = append(statements, "DROP DATABASE IF EXISTS `"+databaseName+"`")
        command := exec.Command("/usr/bin/mariadb", "--batch", "--skip-column-names")
        command.Stdin = strings.NewReader(strings.Join(statements, "; ") + ";")
        output, err := command.CombinedOutput()
        if err != nil {
                return fmt.Errorf("DATABASE_DELETE_FAILED: %s", safeOutput(string(output)))
        }
        return nil
}

func verifiedAccount(username string) (*user.User, *user.Group, error) {
        home := filepath.Join("/home", username)
        account, err := user.Lookup(username)
        if err != nil {
                return nil, nil, fmt.Errorf("ACCOUNT_NOT_FOUND: hosting account does not exist")
        }
        uid, err := strconv.Atoi(account.Uid)
        if err != nil || uid < 1000 || filepath.Clean(account.HomeDir) != home {
                return nil, nil, fmt.Errorf("ACCOUNT_CONFLICT: existing Linux user is not a verified hosting account")
        }
        group, err := user.LookupGroupId(account.Gid)
        if err != nil {
                return nil, nil, fmt.Errorf("GROUP_LOOKUP_FAILED: unable to verify account group")
        }
        passwd, err := exec.Command("/usr/bin/getent", "passwd", username).Output()
        if err != nil {
                return nil, nil, fmt.Errorf("ACCOUNT_VERIFY_FAILED: unable to verify account login shell")
        }
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
                if !errors.As(lookupErr, &unknown) {
                        return fmt.Errorf("USER_LOOKUP_FAILED: unable to verify Linux account")
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
        uid, err := strconv.Atoi(account.Uid)
        if err != nil || uid < 1000 || filepath.Clean(account.HomeDir) != home {
                return fmt.Errorf("ACCOUNT_CONFLICT: existing Linux user does not have the expected hosting identity")
        }
        group, err := user.LookupGroupId(account.Gid)
        if err != nil {
                return fmt.Errorf("GROUP_LOOKUP_FAILED: unable to verify account group")
        }
        passwd, err := exec.Command("/usr/bin/getent", "passwd", username).Output()
        if err != nil {
                return fmt.Errorf("ACCOUNT_VERIFY_FAILED: unable to verify account login shell")
        }
        fields := strings.Split(strings.TrimSpace(string(passwd)), ":")
        if len(fields) != 7 || fields[6] != "/usr/sbin/nologin" {
                return fmt.Errorf("ACCOUNT_CONFLICT: hosting users must use /usr/sbin/nologin")
        }
        publicHTML := filepath.Join(home, "public_html")
        if err := ensureSafeDirectory(home, publicHTML, uid, mustGID(group.Gid)); err != nil {
                return fmt.Errorf("ACCOUNT_DIRECTORY_FAILED: unable to securely prepare hosting directories")
        }
        if err := configurePHPFPM(username); err != nil {
                return err
        }
        dirFD, err := openDocumentDirectory(publicHTML)
        if err != nil {
                return fmt.Errorf("DEFAULT_PAGE_FAILED: unable to securely open the hosting document root")
        }
        pageErr := createDefaultIndexAt(dirFD, uid, mustGID(group.Gid))
        _ = syscall.Close(dirFD)
        if pageErr != nil {
                return fmt.Errorf("DEFAULT_PAGE_FAILED: unable to create initial index page")
        }
        if err := registerManagedAccount(username, uid); err != nil {
                return fmt.Errorf("ACCOUNT_REGISTRY_FAILED: hosting account could not be registered securely")
        }
        return nil
}

func addDomain(username, domain, documentRoot string) error {
        if !domainPattern.MatchString(domain) || len(domain) > 253 {
                return fmt.Errorf("INVALID_DOMAIN: domain name is invalid")
        }
        home := filepath.Join("/home", username)
        if documentRoot == "" {
                documentRoot = filepath.Join(home, "public_html")
        }
        if !validDocumentRoot(documentRoot) {
                return fmt.Errorf("INVALID_DOCUMENT_ROOT: document root must be a clean absolute path")
        }
        rel, err := filepath.Rel(home, documentRoot)
        if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
                return fmt.Errorf("INVALID_DOCUMENT_ROOT: document root must be inside the hosting account home")
        }
        account, group, err := verifiedAccount(username)
        if err != nil {
                return err
        }
        uid, _ := strconv.Atoi(account.Uid)
        gid := mustGID(group.Gid)
        if err := ensureSafeDirectory(home, documentRoot, uid, gid); err != nil {
                return err
        }
        if err := upgradeLegacyDefaultIndex(documentRoot, uid, gid); err != nil {
                return err
        }
        if err := createDefaultIndexForEmptyDomain(documentRoot, uid, gid); err != nil {
                return err
        }
        if err := runFixed("/usr/bin/setfacl", "-m", "u:www-data:--x", home); err != nil {
                return fmt.Errorf("ACL_FAILED: unable to grant web server home traversal")
        }
        if err := runFixed("/usr/bin/setfacl", "-R", "-P", "-m", "u:www-data:rX", documentRoot); err != nil {
                return fmt.Errorf("ACL_FAILED: unable to grant web server document access")
        }
        if err := runFixed("/usr/bin/setfacl", "-m", "d:u:www-data:rX", documentRoot); err != nil {
                return fmt.Errorf("ACL_FAILED: unable to set default web server access")
        }
        if err := configureNginx(username, domain, documentRoot); err != nil {
                return err
        }
        return nil
}

const maxManagedFileBytes = 256 * 1024

type managedFileEntry struct {
        Name       string `json:"name"`
        IsDir      bool   `json:"isDir"`
        Size       int64  `json:"size"`
        ModifiedAt string `json:"modifiedAt"`
}

// openDirectoryChain opens each path component relative to the previously
// opened directory. O_NOFOLLOW prevents symlink traversal at every level.
func openDirectoryChain(root string, parts ...string) (int, error) {
        fd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
        if err != nil {
                return -1, err
        }
        for _, part := range parts {
                if part == "" || part == "." || part == ".." || strings.Contains(part, string(filepath.Separator)) {
                        _ = syscall.Close(fd)
                        return -1, fmt.Errorf("invalid directory component")
                }
                nextFD, openErr := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
                _ = syscall.Close(fd)
                if openErr != nil {
                        return -1, openErr
                }
                fd = nextFD
        }
        return fd, nil
}

func fileManager(input request) error {
        account, group, err := verifiedAccount(input.Username)
        if err != nil {
                return err
        }

        uid, _ := strconv.Atoi(account.Uid)
        gid := mustGID(group.Gid)

        rootFD, err := openDirectoryChain("/", "home", input.Username, "public_html")
        if err != nil {
                return fmt.Errorf("FILE_ROOT_UNAVAILABLE: hosting document root is missing or unsafe")
        }
        defer syscall.Close(rootFD)

        writeResult := func(value any) error {
                return json.NewEncoder(os.Stdout).Encode(value)
        }

        // DELETE must happen before dropping privileges. The document-root
        // descriptor remains anchored to the verified directory.
        if input.FileOperation == "DELETE_PATH" {
                quarantineFD, err := openFileManagerQuarantine(input.Username)
                if err != nil {
                        return fmt.Errorf("DELETE_FAILED: protected quarantine is unavailable")
                }
                defer syscall.Close(quarantineFD)

                if err := secureFileManagerDelete(rootFD, quarantineFD, input.Path); err != nil {
                        return err
                }

                return writeResult(map[string]any{
                        "success": true,
                        "path":    input.Path,
                })
        }

        runtime.LockOSThread()

        if err := syscall.Fchdir(rootFD); err != nil {
                return fmt.Errorf("FILE_SANDBOX_FAILED: unable to enter the hosting document root")
        }

        // The working directory is anchored to the verified document root.
        if err := syscall.Chroot("."); err != nil {
                return fmt.Errorf("FILE_SANDBOX_FAILED: unable to enter the hosting document root")
        }

        if err := os.Chdir("/"); err != nil {
                return fmt.Errorf("FILE_SANDBOX_FAILED: unable to enter the hosting document root")
        }

        if err := syscall.Setgroups([]int{gid}); err != nil {
                return fmt.Errorf("FILE_SANDBOX_FAILED: unable to set account groups")
        }
        if err := syscall.Setgid(gid); err != nil {
                return fmt.Errorf("FILE_SANDBOX_FAILED: unable to drop group privileges")
        }
        if err := syscall.Setuid(uid); err != nil {
                return fmt.Errorf("FILE_SANDBOX_FAILED: unable to drop user privileges")
        }

        return secureFileManagerOperation(input, "/", -1, writeResult)
}

func managedParentPath(value string) string {
        parent := filepath.ToSlash(filepath.Dir(value))
        if parent == "." {
                return ""
        }
        return parent
}

func safeManagedPath(root, relative string, allowRoot bool) (string, os.FileInfo, error) {
        if relative == "" {
                if allowRoot {
                        info, err := os.Lstat(root)
                        return root, info, err
                }
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
                if errors.Is(err, os.ErrNotExist) && i == len(parts)-1 {
                        return current, nil, nil
                }
                if err != nil {
                        return "", nil, fmt.Errorf("FILE_NOT_FOUND: file or directory does not exist")
                }
                if info.Mode()&os.ModeSymlink != 0 {
                        return "", nil, fmt.Errorf("UNSAFE_PATH: symbolic links are not allowed in the File Manager")
                }
                if i < len(parts)-1 && !info.IsDir() {
                        return "", nil, fmt.Errorf("INVALID_PATH: a parent path is not a directory")
                }
                if i == len(parts)-1 {
                        return current, info, nil
                }
        }
        return "", nil, fmt.Errorf("INVALID_PATH: file path is invalid")
}

func fileManagerOperation(input request, root string, writeResult func(any) error) error {
        switch input.FileOperation {
        case "LIST_FILES":
                path, info, err := safeManagedPath(root, input.Path, true)
                if err != nil {
                        return err
                }
                if info == nil || !info.IsDir() {
                        return fmt.Errorf("NOT_A_DIRECTORY: selected path is not a directory")
                }
                items, err := os.ReadDir(path)
                if err != nil {
                        return fmt.Errorf("DIRECTORY_READ_FAILED: unable to read directory")
                }
                entries := make([]managedFileEntry, 0, len(items))
                for _, item := range items {
                        entryInfo, err := item.Info()
                        if err != nil || item.Type()&os.ModeSymlink != 0 {
                                continue
                        }
                        entries = append(entries, managedFileEntry{Name: item.Name(), IsDir: entryInfo.IsDir(), Size: entryInfo.Size(), ModifiedAt: entryInfo.ModTime().UTC().Format(time.RFC3339)})
                        if len(entries) >= 1000 {
                                break
                        }
                }
                return writeResult(map[string]any{"path": input.Path, "entries": entries})
        case "READ_FILE":
                path, info, err := safeManagedPath(root, input.Path, false)
                if err != nil {
                        return err
                }
                if info == nil || !info.Mode().IsRegular() {
                        return fmt.Errorf("NOT_A_FILE: selected path is not a regular file")
                }
                if info.Size() > maxManagedFileBytes {
                        return fmt.Errorf("FILE_TOO_LARGE: files larger than 256 KiB cannot be opened in the editor")
                }
                data, err := os.ReadFile(path)
                if err != nil {
                        return fmt.Errorf("FILE_READ_FAILED: unable to read selected file")
                }
                return writeResult(map[string]any{"path": input.Path, "contentBase64": base64.StdEncoding.EncodeToString(data), "size": len(data)})
        case "WRITE_FILE":
                data, err := base64.StdEncoding.DecodeString(input.ContentBase64)
                if err != nil || len(data) > maxManagedFileBytes {
                        return fmt.Errorf("INVALID_FILE_CONTENT: file content is invalid or exceeds 256 KiB")
                }
                path, info, err := safeManagedPath(root, input.Path, false)
                if err != nil {
                        return err
                }
                if info != nil && !info.Mode().IsRegular() {
                        return fmt.Errorf("NOT_A_FILE: only regular files can be edited")
                }
                if info == nil {
                        _, parentInfo, e := safeManagedPath(root, managedParentPath(input.Path), true)
                        if e != nil || parentInfo == nil || !parentInfo.IsDir() {
                                return fmt.Errorf("INVALID_PATH: parent directory does not exist")
                        }
                }
                tmp, err := os.CreateTemp(filepath.Dir(path), ".nexora-file-*")
                if err != nil {
                        return fmt.Errorf("FILE_WRITE_FAILED: unable to create temporary file")
                }
                tmpName := tmp.Name()
                defer os.Remove(tmpName)
                if _, err = tmp.Write(data); err != nil {
                        tmp.Close()
                        return fmt.Errorf("FILE_WRITE_FAILED: unable to write file content")
                }
                if err = tmp.Chmod(0640); err != nil {
                        tmp.Close()
                        return fmt.Errorf("FILE_WRITE_FAILED: unable to set file permissions")
                }
                if err = tmp.Close(); err != nil {
                        return fmt.Errorf("FILE_WRITE_FAILED: unable to close file")
                }
                if err = os.Rename(tmpName, path); err != nil {
                        return fmt.Errorf("FILE_WRITE_FAILED: unable to replace file")
                }
                return writeResult(map[string]any{"success": true, "path": input.Path, "size": len(data)})
        case "CREATE_DIRECTORY":
                path, info, err := safeManagedPath(root, input.Path, false)
                if err != nil {
                        return err
                }
                if info != nil {
                        return fmt.Errorf("PATH_EXISTS: a file or directory already exists at this path")
                }
                _, parentInfo, err := safeManagedPath(root, managedParentPath(input.Path), true)
                if err != nil || parentInfo == nil || !parentInfo.IsDir() {
                        return fmt.Errorf("INVALID_PATH: parent directory does not exist")
                }
                if err := os.Mkdir(path, 0750); err != nil {
                        return fmt.Errorf("DIRECTORY_CREATE_FAILED: unable to create directory")
                }
                return writeResult(map[string]any{"success": true, "path": input.Path})
        case "RENAME_PATH":
                if input.Path == "" || input.NewPath == "" {
                        return fmt.Errorf("INVALID_PATH: the document root cannot be renamed")
                }
                oldPath, oldInfo, err := safeManagedPath(root, input.Path, false)
                if err != nil {
                        return err
                }
                if oldInfo == nil {
                        return fmt.Errorf("FILE_NOT_FOUND: source does not exist")
                }
                newPath, newInfo, err := safeManagedPath(root, input.NewPath, false)
                if err != nil {
                        return err
                }
                if newInfo != nil {
                        return fmt.Errorf("PATH_EXISTS: destination already exists")
                }
                _, parentInfo, err := safeManagedPath(root, managedParentPath(input.NewPath), true)
                if err != nil || parentInfo == nil || !parentInfo.IsDir() {
                        return fmt.Errorf("INVALID_PATH: destination directory does not exist")
                }
                if err := os.Rename(oldPath, newPath); err != nil {
                        return fmt.Errorf("RENAME_FAILED: unable to rename selected item")
                }
                return writeResult(map[string]any{"success": true, "path": input.NewPath})
        case "DELETE_PATH":
                if input.Path == "" {
                        return fmt.Errorf("INVALID_PATH: the document root cannot be deleted")
                }
                path, info, err := safeManagedPath(root, input.Path, false)
                if err != nil {
                        return err
                }
                if info == nil {
                        return fmt.Errorf("FILE_NOT_FOUND: selected item does not exist")
                }
                if err := os.RemoveAll(path); err != nil {
                        return fmt.Errorf("DELETE_FAILED: unable to delete selected item")
                }
                return writeResult(map[string]any{"success": true, "path": input.Path})
        default:
                return fmt.Errorf("INVALID_FILE_OPERATION: unsupported file manager operation")
        }
}

func validDocumentRoot(path string) bool {
        return filepath.IsAbs(path) && filepath.Clean(path) == path && documentRootPattern.MatchString(path)
}

func configureNginx(username, domain, root string) error {
        if !usernamePattern.MatchString(username) ||
                !domainPattern.MatchString(domain) ||
                len(domain) > 253 ||
                !validDocumentRoot(root) {
                return fmt.Errorf("NGINX_CONFIG_FAILED: invalid site configuration input")
        }

        if _, err := os.Stat("/usr/sbin/nginx"); err != nil {
                return fmt.Errorf("NGINX_NOT_INSTALLED: install Nginx before adding a domain")
        }
        if _, err := os.Stat("/usr/bin/setfacl"); err != nil {
                return fmt.Errorf("ACL_TOOL_MISSING: install the acl package before adding a domain")
        }

        fileKey := strings.ReplaceAll(domain, ".", "_")
        configName := "nexora-" + fileKey
        if len(configName) > 255 {
                return fmt.Errorf("NGINX_CONFIG_FAILED: domain is too long for a configuration filename")
        }

        availableFD, err := openRootOwnedDirectory("/etc/nginx/sites-available")
        if err != nil {
                return fmt.Errorf("NGINX_CONFIG_FAILED: sites-available directory is missing or unsafe")
        }
        defer syscall.Close(availableFD)

        enabledFD, err := openRootOwnedDirectory("/etc/nginx/sites-enabled")
        if err != nil {
                return fmt.Errorf("NGINX_CONFIG_FAILED: sites-enabled directory is missing or unsafe")
        }
        defer syscall.Close(enabledFD)

        content := fmt.Sprintf(`server {
    listen 80;
    server_name %s;

    root %s;
    index index.php index.html index.htm;

    access_log /var/log/nginx/nexora-%s.access.log;
    error_log /var/log/nginx/nexora-%s.error.log;

    location / {
        try_files $uri $uri/ =404;
    }

    location ~ [.]php$ {
        try_files $uri =404;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_pass unix:/run/php/nexora-%s.sock;
    }

    location ~ /[.] {
        deny all;
    }
}
`, domain, root, fileKey, fileKey, username)

        target := "/etc/nginx/sites-available/" + configName
        installState, err := installNginxConfigAt(
                availableFD,
                enabledFD,
                configName,
                target,
                content,
                0,
                0,
        )
        if err != nil {
                return err
        }

        // Validate the complete on-disk configuration before considering a reload.
        if err := runFixed("/usr/sbin/nginx", "-t"); err != nil {
                testErr := fmt.Errorf("NGINX_TEST_FAILED: %s", safeOutput(err.Error()))
                rollbackErr := rollbackNginxInstallAt(
                        availableFD, enabledFD, configName, target, installState,
                )
                if rollbackErr != nil {
                        return fmt.Errorf("%v; NGINX_ROLLBACK_FAILED: %w", testErr, rollbackErr)
                }
                return testErr
        }

        // Never start or enable Nginx as a side effect of adding a domain.
        if err := runFixed("/usr/bin/systemctl", "is-active", "--quiet", "nginx"); err != nil {
                return fmt.Errorf("NGINX_INACTIVE: configuration is installed and validated; Nginx was not started")
        }

        if err := runFixed("/usr/bin/systemctl", "reload", "nginx"); err != nil {
                return fmt.Errorf("NGINX_RELOAD_FAILED: %s; validated configuration remains installed", safeOutput(err.Error()))
        }

        return nil
}

func runFixed(path string, args ...string) error {
        cmd := exec.Command(path, args...)
        if output, err := cmd.CombinedOutput(); err != nil {
                return fmt.Errorf("%s", safeOutput(string(output)))
        }
        return nil
}
func mustGID(value string) int { gid, _ := strconv.Atoi(value); return gid }
func safeOutput(value string) string {
        value = strings.TrimSpace(value)
        if len(value) > 240 {
                value = value[:240]
        }
        if value == "" {
                return "system command failed"
        }
        return value
}

const phpFPMDisabledFunctions = "exec,shell_exec,system,passthru,proc_open,popen,pcntl_exec"

// phpFPMPoolConfig keeps account-specific PHP restrictions in the dedicated
// FPM pool rather than changing the server-wide PHP configuration.
func phpFPMPoolConfig(username string) string {
        if !usernamePattern.MatchString(username) {
                return ""
        }
        return phpFPMPoolConfigWithSettings(username, phpPoolSettings{
                MemoryLimitMib: 256, MaxExecutionTime: 30, UploadMaxFilesize: 64,
                MaxInputVars: 1000, DisplayErrors: 0,
        })
}

type phpPoolSettings struct {
        MemoryLimitMib    int
        MaxExecutionTime  int
        UploadMaxFilesize int
        MaxInputVars      int
        DisplayErrors     int
}

func phpFPMPoolConfigWithSettings(username string, s phpPoolSettings) string {
        if !usernamePattern.MatchString(username) {
                return ""
        }
        if s.MemoryLimitMib <= 0 { s.MemoryLimitMib = 256 }
        if s.MaxExecutionTime <= 0 { s.MaxExecutionTime = 30 }
        if s.UploadMaxFilesize <= 0 { s.UploadMaxFilesize = 64 }
        if s.MaxInputVars <= 0 { s.MaxInputVars = 1000 }
        displayFlag := "off"
        if s.DisplayErrors != 0 { displayFlag = "on" }
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
php_admin_flag[display_errors] = %s
php_admin_value[memory_limit] = %dM
php_admin_value[max_execution_time] = %d
php_admin_value[upload_max_filesize] = %dM
php_admin_value[max_input_vars] = %d
php_admin_value[disable_functions] = %s
php_admin_value[open_basedir] = /home/%s:/tmp:/usr/share/php
`, username, username, username, username, displayFlag,
                s.MemoryLimitMib, s.MaxExecutionTime, s.UploadMaxFilesize, s.MaxInputVars,
                phpFPMDisabledFunctions, username)
}

func configurePHPFPM(username string) error {
        if !usernamePattern.MatchString(username) {
                return fmt.Errorf("PHP_POOL_CONFIG_FAILED: invalid hosting username")
        }

        phpCLI := "/usr/bin/php"
        if info, err := os.Stat(phpCLI); err != nil || !info.Mode().IsRegular() {
                return fmt.Errorf("PHP_NOT_INSTALLED: PHP CLI must be installed before provisioning")
        }

        versionOutput, err := exec.Command(phpCLI, "-r",
                "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;").Output()
        if err != nil {
                return fmt.Errorf("PHP_VERSION_FAILED: unable to detect installed PHP version")
        }

        version := strings.TrimSpace(string(versionOutput))
        if !regexp.MustCompile(`^[0-9]+\.[0-9]+$`).MatchString(version) {
                return fmt.Errorf("PHP_VERSION_FAILED: detected PHP version is invalid")
        }

        poolDir := filepath.Join("/etc/php", version, "fpm", "pool.d")
        poolPath := filepath.Join(poolDir, "nexora-"+username+".conf")
        pool := phpFPMPoolConfig(username)
        if pool == "" {
                return fmt.Errorf("PHP_POOL_CONFIG_FAILED: unable to generate pool configuration")
        }

        if err := writeRootConfigFile(poolPath, pool, 0640); err != nil {
                return fmt.Errorf("PHP_POOL_CONFIG_FAILED: %s", safeOutput(err.Error()))
        }

        // Validate the complete configuration before touching the running service.
        fpmBinary := filepath.Join("/usr/sbin", "php-fpm"+version)
        if info, err := os.Stat(fpmBinary); err != nil || !info.Mode().IsRegular() {
                return fmt.Errorf("PHP_FPM_BINARY_MISSING: PHP-FPM validation binary is unavailable")
        }
        if err := runFixed(fpmBinary, "-tt"); err != nil {
                return fmt.Errorf("PHP_FPM_CONFIG_INVALID: %s", safeOutput(err.Error()))
        }

        service := "php" + version + "-fpm"

        // Never enable, start, or restart PHP-FPM as part of account provisioning.
        // Reload only when the service is already active.
        if err := runFixed("/usr/bin/systemctl", "is-active", "--quiet", service); err != nil {
                return fmt.Errorf("PHP_FPM_INACTIVE: configuration is valid, but PHP-FPM is not active; no service state was changed")
        }
        if err := runFixed("/usr/bin/systemctl", "reload", service); err != nil {
                return fmt.Errorf("PHP_FPM_RELOAD_FAILED: %s", safeOutput(err.Error()))
        }

        if _, err := os.Stat("/run/php/nexora-" + username + ".sock"); err != nil {
                return fmt.Errorf("PHP_POOL_SOCKET_MISSING: dedicated PHP-FPM socket did not appear after reload")
        }
        return nil
}

// updatePhpPool rewrites an existing PHP-FPM pool configuration with the
// supplied settings, using a strict phased approach so a malformed or
// incompatible configuration can never leave the running service in a
// broken state:
//
//  1. Validate inputs (username, version, generated config content).
//  2. Confirm a pool config already exists on disk. We never create a
//     pool via the UPDATE path — initial creation belongs to provisionAccount.
//  3. Capture the existing pool content as a backup, then atomically swap
//     the new content into place (overwriteRootConfigFile uses a temp file
//     + rename, so readers never observe a partial write).
//  4. Validate the *complete* PHP-FPM configuration with `php-fpm -tt`.
//     If validation fails, restore the backup and fail the operation.
//  5. Confirm the service is already active (we never start or restart
//     PHP-FPM). If it is not active, restore the backup and fail without
//     attempting a reload — no service state is changed.
//  6. Reload PHP-FPM. If reload fails, restore the backup and reload again
//     so the running service is back to its prior configuration.
//  7. Runtime verification: confirm the account's dedicated socket has
//     appeared. If it has not, restore the backup, reload, and fail.
//
// The net effect is that a successful return guarantees the new config is
// on disk, syntactically valid, accepted by the running service, and the
// per-account socket is live. A failed return guarantees the on-disk and
// running state match the pre-call state (best effort — if a backup
// restore also fails, the error message will indicate the restore failure).
func updatePhpPool(username, phpVersion string, settings phpPoolSettings) error {
        if !usernamePattern.MatchString(username) {
                return fmt.Errorf("PHP_POOL_UPDATE_FAILED: invalid hosting username")
        }
        version := phpVersion
        if version == "" {
                versionOutput, err := exec.Command("/usr/bin/php", "-r", "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;").Output()
                if err != nil {
                        return fmt.Errorf("PHP_VERSION_FAILED: unable to detect PHP version")
                }
                version = strings.TrimSpace(string(versionOutput))
        }
        if !regexp.MustCompile(`^[0-9]+\.[0-9]+$`).MatchString(version) {
                return fmt.Errorf("PHP_POOL_UPDATE_FAILED: invalid PHP version %q", version)
        }
        poolPath := filepath.Join("/etc/php", version, "fpm", "pool.d", "nexora-"+username+".conf")
        if _, err := os.Stat(poolPath); err != nil {
                return fmt.Errorf("PHP_POOL_NOT_FOUND: no existing PHP-FPM pool for account %s", username)
        }

        // Phase 1 — generate the new config content in memory only.
        pool := phpFPMPoolConfigWithSettings(username, settings)
        if pool == "" {
                return fmt.Errorf("PHP_POOL_UPDATE_FAILED: unable to generate pool configuration")
        }

        // Phase 2 — capture backup and atomically swap the new content in.
        backup, err := overwriteRootConfigFile(poolPath, pool, 0640)
        if err != nil {
                return fmt.Errorf("PHP_POOL_UPDATE_FAILED: %s", safeOutput(err.Error()))
        }

        // Phase 3 — validate the full PHP-FPM configuration. The -tt flag
        // parses every pool.d/*.conf file (including the new one) without
        // touching the running service.
        fpmBinary := filepath.Join("/usr/sbin", "php-fpm"+version)
        if info, statErr := os.Stat(fpmBinary); statErr != nil || !info.Mode().IsRegular() {
                _ = restoreRootConfigFile(poolPath, backup, 0640)
                return fmt.Errorf("PHP_FPM_BINARY_MISSING: PHP-FPM validation binary is unavailable")
        }
        if err := runFixed(fpmBinary, "-tt"); err != nil {
                // Restore the prior configuration so on-disk state matches the
                // running service's last known-good config.
                if restoreErr := restoreRootConfigFile(poolPath, backup, 0640); restoreErr != nil {
                        return fmt.Errorf("PHP_FPM_CONFIG_INVALID: %s (restore failed: %s)", safeOutput(err.Error()), safeOutput(restoreErr.Error()))
                }
                return fmt.Errorf("PHP_FPM_CONFIG_INVALID: %s", safeOutput(err.Error()))
        }

        service := "php" + version + "-fpm"

        // Phase 4 — confirm the service is already active. We never start or
        // restart PHP-FPM as part of an update.
        if err := runFixed("/usr/bin/systemctl", "is-active", "--quiet", service); err != nil {
                _ = restoreRootConfigFile(poolPath, backup, 0640)
                return fmt.Errorf("PHP_FPM_INACTIVE: configuration is valid, but PHP-FPM is not active; no service state was changed")
        }

        // Phase 5 — reload PHP-FPM so the new pool config takes effect.
        if err := runFixed("/usr/bin/systemctl", "reload", service); err != nil {
                // Restore the backup and reload again so the running service
                // matches the on-disk backup state.
                if restoreErr := restoreRootConfigFile(poolPath, backup, 0640); restoreErr != nil {
                        return fmt.Errorf("PHP_FPM_RELOAD_FAILED: %s (restore failed: %s)", safeOutput(err.Error()), safeOutput(restoreErr.Error()))
                }
                // Best-effort reload of the restored config.
                _ = runFixed("/usr/bin/systemctl", "reload", service)
                return fmt.Errorf("PHP_FPM_RELOAD_FAILED: %s", safeOutput(err.Error()))
        }

        // Phase 6 — runtime verification: confirm the account's dedicated
        // socket is live. This proves the pool actually loaded and bound.
        socketPath := "/run/php/nexora-" + username + ".sock"
        if _, err := os.Stat(socketPath); err != nil {
                // Restore the backup, reload, and report the socket-missing error.
                if restoreErr := restoreRootConfigFile(poolPath, backup, 0640); restoreErr != nil {
                        return fmt.Errorf("PHP_POOL_SOCKET_MISSING: dedicated PHP-FPM socket did not appear after reload (restore failed: %s)", safeOutput(restoreErr.Error()))
                }
                _ = runFixed("/usr/bin/systemctl", "reload", service)
                return fmt.Errorf("PHP_POOL_SOCKET_MISSING: dedicated PHP-FPM socket did not appear after reload")
        }

        return nil
}

func suspendHostingAccount(username string) error {
        if !usernamePattern.MatchString(username) { return fmt.Errorf("SUSPEND_FAILED: invalid hosting username") }
        vhostPath := filepath.Join("/etc/nginx/sites-available", "nexora-"+username+".conf")
        suspendedPath := vhostPath + ".suspended"
        if _, err := os.Stat(suspendedPath); err == nil { return fmt.Errorf("SUSPEND_FAILED: already suspended") }
        if err := os.Rename(vhostPath, suspendedPath); err != nil {
                return fmt.Errorf("SUSPEND_FAILED: %s", safeOutput(err.Error()))
        }
        suspendedConfig := "server {\n    listen 80;\n    listen [::]:80;\n    server_name _;\n    return 503;\n}\n"
        if err := writeRootConfigFile(vhostPath, suspendedConfig, 0640); err != nil {
                _ = os.Rename(suspendedPath, vhostPath)
                return fmt.Errorf("SUSPEND_FAILED: %s", safeOutput(err.Error()))
        }
        if err := runFixed("/usr/sbin/nginx", "-t"); err != nil {
                _ = os.Rename(suspendedPath, vhostPath)
                return fmt.Errorf("NGINX_CONFIG_INVALID: %s", safeOutput(err.Error()))
        }
        if err := runFixed("/usr/bin/systemctl", "reload", "nginx"); err != nil {
                _ = os.Rename(suspendedPath, vhostPath)
                return fmt.Errorf("NGINX_RELOAD_FAILED: %s", safeOutput(err.Error()))
        }
        return nil
}

func reactivateHostingAccount(username string) error {
        if !usernamePattern.MatchString(username) { return fmt.Errorf("REACTIVATE_FAILED: invalid hosting username") }
        vhostPath := filepath.Join("/etc/nginx/sites-available", "nexora-"+username+".conf")
        suspendedPath := vhostPath + ".suspended"
        if _, err := os.Stat(suspendedPath); err != nil { return fmt.Errorf("REACTIVATE_FAILED: not suspended") }
        _ = os.Remove(vhostPath)
        if err := os.Rename(suspendedPath, vhostPath); err != nil {
                return fmt.Errorf("REACTIVATE_FAILED: %s", safeOutput(err.Error()))
        }
        if err := runFixed("/usr/sbin/nginx", "-t"); err != nil { return fmt.Errorf("NGINX_CONFIG_INVALID: %s", safeOutput(err.Error())) }
        if err := runFixed("/usr/bin/systemctl", "reload", "nginx"); err != nil { return fmt.Errorf("NGINX_RELOAD_FAILED: %s", safeOutput(err.Error())) }
        return nil
}

// removeDomain removes only the server block for the requested domain from
// the account's Nginx configuration. Other domains served by the same
// account are preserved. The approach:
//   1. Read the full vhost config file.
//   2. Split it into server blocks (each starts with "server {" at the
//      beginning of a line and ends with the matching "}" at the same
//      nesting depth).
//   3. For each block, check whether it contains "server_name <domain>"
//      (exact match on the domain token). If it does, skip it.
//   4. Write the remaining blocks back atomically.
//   5. Validate and reload only if the resulting config is valid.
//   6. Restore the original config if any step fails.
//
// Website files, database records, and other domains' DNS records are
// untouched.
func removeDomain(username, domain string) error {
        if !usernamePattern.MatchString(username) {
                return fmt.Errorf("REMOVE_DOMAIN_FAILED: invalid hosting username")
        }
        if !domainPattern.MatchString(domain) {
                return fmt.Errorf("REMOVE_DOMAIN_FAILED: invalid domain")
        }
        vhostPath := filepath.Join("/etc/nginx/sites-available", "nexora-"+username+".conf")

        original, err := os.ReadFile(vhostPath)
        if err != nil {
                return fmt.Errorf("REMOVE_DOMAIN_FAILED: unable to read vhost config: %s", safeOutput(err.Error()))
        }

        filtered := removeServerBlockByDomain(string(original), domain)
        if filtered == string(original) {
                // No matching server block was removed — the domain may not
                // be configured in this account's vhost.
                return fmt.Errorf("REMOVE_DOMAIN_FAILED: domain %s not found in the vhost configuration", domain)
        }

        // Write the filtered config atomically: write to a temp file in the
        // same directory, then rename over the original. If validation
        // fails, restore the original.
        backup := vhostPath + ".remove-domain-backup"
        if err := writeRootConfigFile(backup, string(original), 0640); err != nil {
                return fmt.Errorf("REMOVE_DOMAIN_FAILED: unable to create backup: %s", safeOutput(err.Error()))
        }
        if err := writeRootConfigFile(vhostPath, filtered, 0640); err != nil {
                _ = os.Remove(backup)
                return fmt.Errorf("REMOVE_DOMAIN_FAILED: %s", safeOutput(err.Error()))
        }
        if err := runFixed("/usr/sbin/nginx", "-t"); err != nil {
                _ = os.Rename(backup, vhostPath)
                return fmt.Errorf("NGINX_CONFIG_INVALID: %s", safeOutput(err.Error()))
        }
        if err := runFixed("/usr/bin/systemctl", "reload", "nginx"); err != nil {
                _ = os.Rename(backup, vhostPath)
                return fmt.Errorf("NGINX_RELOAD_FAILED: %s", safeOutput(err.Error()))
        }
        _ = os.Remove(backup)
        return nil
}

// removeServerBlockByDomain returns the config with the server block that
// matches the given domain removed. Returns the input unchanged if no
// match is found.
func removeServerBlockByDomain(config, domain string) string {
        lines := strings.Split(config, "\n")
        var result []string
        i := 0
        removed := false
        for i < len(lines) {
                line := strings.TrimSpace(lines[i])
                if strings.HasPrefix(line, "server {") || strings.HasPrefix(line, "server{") {
                        // Find the end of this server block by tracking brace depth.
                        blockStart := i
                        depth := 0
                        blockEnd := -1
                        for j := i; j < len(lines); j++ {
                                for _, ch := range lines[j] {
                                        if ch == '{' { depth++ }
                                        if ch == '}' { depth-- }
                                }
                                if depth == 0 && j > i {
                                        blockEnd = j
                                        break
                                }
                        }
                        if blockEnd == -1 {
                                // Unbalanced braces — keep everything from here.
                                result = append(result, lines[i:]...)
                                break
                        }
                        // Check if this block matches the domain.
                        block := strings.Join(lines[blockStart:blockEnd+1], "\n")
                        if serverBlockMatchesDomain(block, domain) && !removed {
                                // Skip this block (remove it).
                                removed = true
                                i = blockEnd + 1
                                continue
                        }
                        result = append(result, lines[blockStart:blockEnd+1]...)
                        i = blockEnd + 1
                        continue
                }
                result = append(result, lines[i])
                i++
        }
        return strings.Join(result, "\n")
}

// serverBlockMatchesDomain reports whether the server block's server_name
// directive includes the given domain as an exact token match.
func serverBlockMatchesDomain(block, domain string) bool {
        for _, line := range strings.Split(block, "\n") {
                trimmed := strings.TrimSpace(line)
                if !strings.HasPrefix(trimmed, "server_name ") { continue }
                // server_name can list multiple domains: "server_name a.com b.com;"
                names := strings.Fields(strings.TrimSuffix(strings.TrimPrefix(trimmed, "server_name "), ";"))
                for _, name := range names {
                        if strings.EqualFold(name, domain) { return true }
                        // Wildcard matches: *.domain.com or .domain.com
                        if strings.HasPrefix(name, "*.") && strings.EqualFold(name[2:], domain) { return true }
                        if strings.HasPrefix(name, ".") && strings.EqualFold(name[1:], domain) { return true }
                }
        }
        return false
}
