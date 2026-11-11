package main

import (
        "os"
        "path/filepath"
        "strings"
        "syscall"
        "testing"
)

func TestUsernamePattern(t *testing.T) {
        valid := []string{"web001", "client_01", "abc"}
        for _, value := range valid {
                if !usernamePattern.MatchString(value) {
                        t.Errorf("expected %q to be accepted", value)
                }
        }
        invalid := []string{"ab", "1client", "Client01", "client-name", "client.name", "client;id", "sixteen_char_name"}
        for _, value := range invalid {
                if usernamePattern.MatchString(value) {
                        t.Errorf("expected %q to be rejected", value)
                }
        }
}

func TestDatabaseNamePattern(t *testing.T) {
        valid := []string{"client01_app", "store_db2", "ab"}
        for _, value := range valid {
                if !databaseNamePattern.MatchString(value) {
                        t.Errorf("expected database name %q to be accepted", value)
                }
        }
        invalid := []string{"", "1database", "UpperCase", "db-name", "db.name", "db;drop", "a"}
        for _, value := range invalid {
                if databaseNamePattern.MatchString(value) {
                        t.Errorf("expected database name %q to be rejected", value)
                }
        }
}

func TestDomainPattern(t *testing.T) {
        valid := []string{"example.com", "sub.example.co.uk", "nxoratest01.test", "a1.example-domain.com"}
        for _, value := range valid {
                if !domainPattern.MatchString(value) {
                        t.Errorf("expected domain %q to be accepted", value)
                }
        }
        invalid := []string{"", "localhost", "-bad.example.com", "bad-.example.com", "bad..example.com", "bad;domain.com", "example.com/path", "example .com", "example.com\n"}
        for _, value := range invalid {
                if domainPattern.MatchString(value) {
                        t.Errorf("expected domain %q to be rejected", value)
                }
        }
}

func TestDocumentRootPattern(t *testing.T) {
        valid := []string{"/home/client01/public_html", "/home/client_01/public_html/example.com"}
        for _, value := range valid {
                if !validDocumentRoot(value) {
                        t.Errorf("expected document root %q to be accepted", value)
                }
        }
        invalid := []string{"/home/client01/public_html;include", "/home/client01/public_html with spaces", "/home/client01/../other", "/tmp/site", "/home/client01/.ssh", "/home/client01/public_html/.private", "/home/client01/public_html\\n"}
        for _, value := range invalid {
                if validDocumentRoot(value) {
                        t.Errorf("expected document root %q to be rejected", value)
                }
        }
}

func TestSafeManagedPathRejectsTraversalAndSymlinks(t *testing.T) {
        root := t.TempDir()
        if err := os.Mkdir(filepath.Join(root, "assets"), 0750); err != nil {
                t.Fatal(err)
        }
        if err := os.WriteFile(filepath.Join(root, "assets", "site.css"), []byte("body{}"), 0640); err != nil {
                t.Fatal(err)
        }
        if _, info, err := safeManagedPath(root, "assets/site.css", false); err != nil || info == nil || !info.Mode().IsRegular() {
                t.Fatalf("expected a regular file, got info=%v err=%v", info, err)
        }
        for _, value := range []string{"../etc/passwd", "/etc/passwd", "assets/../../etc/passwd", "assets\\\\site.css"} {
                if _, _, err := safeManagedPath(root, value, false); err == nil {
                        t.Errorf("expected unsafe path %q to be rejected", value)
                }
        }
        if err := os.Symlink("/etc/passwd", filepath.Join(root, "assets", "escape")); err != nil {
                t.Fatal(err)
        }
        if _, _, err := safeManagedPath(root, "assets/escape", false); err == nil {
                t.Fatal("expected symbolic link to be rejected")
        }
}

func TestManagedParentPath(t *testing.T) {
        if got := managedParentPath("index.html"); got != "" {
                t.Fatalf("root-level parent = %q, want empty", got)
        }
        if got := managedParentPath("assets/site.css"); got != "assets" {
                t.Fatalf("nested parent = %q, want assets", got)
        }
}

func TestUpgradeLegacyDefaultIndexPreservesExistingPages(t *testing.T) {
        root := t.TempDir()
        index := filepath.Join(root, "index.html")

        legacy := []byte(legacyDefaultIndexHTML)
        if err := os.WriteFile(index, legacy, 0640); err != nil {
                t.Fatal(err)
        }

        if err := upgradeLegacyDefaultIndex(root, os.Getuid(), os.Getgid()); err != nil {
                t.Fatal(err)
        }

        got, err := os.ReadFile(index)
        if err != nil {
                t.Fatal(err)
        }
        if string(got) != string(legacy) {
                t.Fatal("legacy index page was unexpectedly replaced")
        }

        custom := []byte("<h1>Customer website</h1>")
        if err := os.WriteFile(index, custom, 0640); err != nil {
                t.Fatal(err)
        }
        if err := upgradeLegacyDefaultIndex(root, os.Getuid(), os.Getgid()); err != nil {
                t.Fatal(err)
        }

        got, err = os.ReadFile(index)
        if err != nil {
                t.Fatal(err)
        }
        if string(got) != string(custom) {
                t.Fatal("customer index page was modified")
        }
}

func TestUpgradeLegacyDefaultIndexDoesNotFollowSymlinks(t *testing.T) {
        root := t.TempDir()
        target := filepath.Join(root, "customer.html")
        if err := os.WriteFile(target, []byte(legacyDefaultIndexHTML), 0640); err != nil {
                t.Fatal(err)
        }
        index := filepath.Join(root, "index.html")
        if err := os.Symlink(target, index); err != nil {
                t.Fatal(err)
        }
        if err := upgradeLegacyDefaultIndex(root, os.Getuid(), os.Getgid()); err == nil {
                t.Fatal("expected symlink index.html to be rejected")
        }
        got, err := os.ReadFile(target)
        if err != nil {
                t.Fatal(err)
        }
        if string(got) != legacyDefaultIndexHTML {
                t.Fatal("symlink target was modified")
        }
}

func TestOpenDirectoryChainRejectsSymlinkComponents(t *testing.T) {
        root := t.TempDir()
        real := filepath.Join(root, "real")
        if err := os.Mkdir(real, 0750); err != nil {
                t.Fatal(err)
        }
        if err := os.Symlink(real, filepath.Join(root, "linked")); err != nil {
                t.Fatal(err)
        }
        fd, err := openDirectoryChain(root, "real")
        if err != nil {
                t.Fatalf("expected real directory to open: %v", err)
        }
        _ = syscall.Close(fd)
        if fd, err := openDirectoryChain(root, "linked"); err == nil {
                _ = syscall.Close(fd)
                t.Fatal("expected symlink directory component to be rejected")
        }
}

func TestCreateDefaultIndexForEmptyDomainRoot(t *testing.T) {
        root := t.TempDir()
        if err := createDefaultIndexForEmptyDomain(root, os.Getuid(), os.Getgid()); err != nil {
                t.Fatal(err)
        }
        got, err := os.ReadFile(filepath.Join(root, "index.html"))
        if err != nil {
                t.Fatal(err)
        }
        if string(got) != defaultIndexHTML {
                t.Fatalf("unexpected starter homepage: %q", string(got))
        }
}

func TestCreateDefaultIndexPreservesExistingCustomerFiles(t *testing.T) {
        root := t.TempDir()
        customFile := filepath.Join(root, "app.php")
        if err := os.WriteFile(customFile, []byte("<?php echo 'customer';"), 0640); err != nil {
                t.Fatal(err)
        }
        if err := createDefaultIndexForEmptyDomain(root, os.Getuid(), os.Getgid()); err != nil {
                t.Fatal(err)
        }
        if _, err := os.Lstat(filepath.Join(root, "index.html")); !os.IsNotExist(err) {
                t.Fatalf("starter homepage should not be created in a non-empty document root; stat error=%v", err)
        }
        got, err := os.ReadFile(customFile)
        if err != nil || string(got) != "<?php echo 'customer';" {
                t.Fatalf("customer file was changed: %q err=%v", string(got), err)
        }
}

func TestCreateDefaultIndexDoesNotOverwriteExistingHomepage(t *testing.T) {
        root := t.TempDir()
        index := filepath.Join(root, "index.html")
        custom := []byte("<h1>Existing customer homepage</h1>")
        if err := os.WriteFile(index, custom, 0640); err != nil {
                t.Fatal(err)
        }
        if err := createDefaultIndexForEmptyDomain(root, os.Getuid(), os.Getgid()); err != nil {
                t.Fatal(err)
        }
        got, err := os.ReadFile(index)
        if err != nil || string(got) != string(custom) {
                t.Fatalf("existing homepage was changed: %q err=%v", string(got), err)
        }
}

func TestPHPFPMPoolConfigEnforcesAccountIsolation(t *testing.T) {
        config := phpFPMPoolConfig("client01")
        required := []string{
                "[nexora-client01]",
                "user = client01",
                "group = client01",
                "listen = /run/php/nexora-client01.sock",
                "listen.mode = 0660",
                "pm = ondemand",
                "clear_env = yes",
                "security.limit_extensions = .php",
                "php_admin_flag[allow_url_include] = off",
                "php_admin_value[disable_functions] = " + phpFPMDisabledFunctions,
                "php_admin_value[open_basedir] = /home/client01:/tmp:/usr/share/php",
        }
        for _, directive := range required {
                if !strings.Contains(config, directive) {
                        t.Errorf("PHP-FPM pool config is missing %q", directive)
                }
        }
        if strings.Contains(config, "/home/other-account") {
                t.Fatal("PHP-FPM pool config contains another account's home path")
        }
}

func TestValidateManagedDatabaseName(t *testing.T) {
        tests := []struct {
                name         string
                databaseName string
                accountName  string
                wantErr      bool
        }{
                {"valid account database", "nxoratest01_testdb", "nxoratest01", false},
                {"valid second database", "client01_store", "client01", false},
                {"another account database", "otheracct_store", "nxoratest01", true},
                {"account prefix without separator", "nxoratest01store", "nxoratest01", true},
                {"prefix confusion", "nxoratest0101_store", "nxoratest01", true},
                {"empty suffix", "nxoratest01_", "nxoratest01", true},
                {"invalid database name", "nxoratest01_bad-name", "nxoratest01", true},
                {"invalid account name", "nxoratest01_store", "Invalid!", true},
                {"empty database name", "", "nxoratest01", true},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        err := validateManagedDatabaseName(tt.databaseName, tt.accountName)
                        if (err != nil) != tt.wantErr {
                                t.Fatalf("validateManagedDatabaseName(%q, %q) error = %v, wantErr %v",
                                        tt.databaseName, tt.accountName, err, tt.wantErr)
                        }
                })
        }
}

func TestValidateDatabaseDeletionUsers(t *testing.T) {
        tests := []struct {
                name    string
                account string
                users   []string
                wantErr bool
        }{
                {"valid users", "nxoratest01", []string{"nxoratest01_app", "nxoratest01_readonly"}, false},
                {"empty user list", "nxoratest01", nil, false},
                {"foreign account user", "nxoratest01", []string{"otheracct_app"}, true},
                {"missing suffix", "nxoratest01", []string{"nxoratest01_"}, true},
                {"invalid suffix", "nxoratest01", []string{"nxoratest01_bad-name"}, true},
                {"duplicate user", "nxoratest01", []string{"nxoratest01_app", "nxoratest01_app"}, true},
                {"invalid account", "Invalid!", []string{"nxoratest01_app"}, true},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got, err := validateDatabaseDeletionUsers(tt.account, tt.users)
                        if (err != nil) != tt.wantErr {
                                t.Fatalf("validateDatabaseDeletionUsers() error = %v, wantErr %v", err, tt.wantErr)
                        }
                        if err == nil && len(got) != len(tt.users) {
                                t.Fatalf("got %d names, want %d", len(got), len(tt.users))
                        }
                })
        }
}

func TestPHPFPMPoolConfigWithSettingsAppliesCustomLimits(t *testing.T) {
        config := phpFPMPoolConfigWithSettings("client01", phpPoolSettings{MemoryLimitMib: 512, MaxExecutionTime: 60, UploadMaxFilesize: 128, MaxInputVars: 2000, DisplayErrors: 1})
        for _, d := range []string{"php_admin_value[memory_limit] = 512M", "php_admin_value[max_execution_time] = 60", "php_admin_value[upload_max_filesize] = 128M", "php_admin_value[max_input_vars] = 2000", "php_admin_flag[display_errors] = on"} {
                if !strings.Contains(config, d) { t.Errorf("missing %q", d) }
        }
}

func TestPHPFPMPoolConfigWithSettingsUsesDefaultsForZeroValues(t *testing.T) {
        config := phpFPMPoolConfigWithSettings("client01", phpPoolSettings{})
        if !strings.Contains(config, "php_admin_value[memory_limit] = 256M") { t.Error("expected default 256M") }
        if !strings.Contains(config, "php_admin_flag[display_errors] = off") { t.Error("expected display_errors off") }
}

func TestPHPFPMPoolConfigWithSettingsRejectsInvalidUsername(t *testing.T) {
        if phpFPMPoolConfigWithSettings("../etc", phpPoolSettings{}) != "" { t.Fatal("expected empty") }
}

func TestPHPFPMPoolConfigBackwardCompatibility(t *testing.T) {
        if phpFPMPoolConfig("client01") != phpFPMPoolConfigWithSettings("client01", phpPoolSettings{MemoryLimitMib:256,MaxExecutionTime:30,UploadMaxFilesize:64,MaxInputVars:1000,DisplayErrors:0}) { t.Fatal("mismatch") }
}

func TestRequestDecodesPhpSettings(t *testing.T) {
        req, err := decodeRequest(strings.NewReader(`{"operation":"UPDATE_PHP_POOL","username":"client01","phpVersion":"8.3","memoryLimitMib":512,"maxExecutionTimeSeconds":60,"uploadMaxFilesizeMib":128,"maxInputVars":2000,"displayErrors":1}`))
        if err != nil { t.Fatalf("decode: %v", err) }
        if req.PhpVersion != "8.3" { t.Errorf("version=%q", req.PhpVersion) }
        if req.MemoryLimitMib != 512 { t.Errorf("mem=%d", req.MemoryLimitMib) }
}

func TestRemoveServerBlockByDomainRemovesMatchingBlock(t *testing.T) {
        config := `# Account vhost
server {
    listen 80;
    server_name example.com www.example.com;
    root /home/client01/public_html;
}
server {
    listen 80;
    server_name addon.example.com;
    root /home/client01/addon;
}
`
        result := removeServerBlockByDomain(config, "example.com")
        if strings.Contains(result, "/home/client01/public_html") {
                t.Fatal("the matching server block was not removed (public_html root still present)")
        }
        if !strings.Contains(result, "/home/client01/addon") {
                t.Fatal("the non-matching server block was removed")
        }
}

func TestRemoveServerBlockByDomainPreservesOtherBlocks(t *testing.T) {
        config := `server {
    server_name a.example.com;
    root /a;
}
server {
    server_name b.example.com;
    root /b;
}
server {
    server_name c.example.com;
    root /c;
}
`
        result := removeServerBlockByDomain(config, "b.example.com")
        if strings.Contains(result, "b.example.com") {
                t.Fatal("matched block not removed")
        }
        if !strings.Contains(result, "a.example.com") || !strings.Contains(result, "c.example.com") {
                t.Fatal("unrelated blocks were removed")
        }
}

func TestRemoveServerBlockByDomainNoMatch(t *testing.T) {
        config := "server {\n    server_name a.com;\n}\n"
        result := removeServerBlockByDomain(config, "notthere.com")
        if result != config {
                t.Fatal("config should be unchanged when domain does not match")
        }
}

func TestServerBlockMatchesDomainExact(t *testing.T) {
        block := "server {\n    server_name example.com;\n}\n"
        if !serverBlockMatchesDomain(block, "example.com") { t.Fatal("expected match") }
        if serverBlockMatchesDomain(block, "other.com") { t.Fatal("unexpected match") }
}

func TestServerBlockMatchesDomainMultiple(t *testing.T) {
        block := "server {\n    server_name a.com b.com c.com;\n}\n"
        if !serverBlockMatchesDomain(block, "b.com") { t.Fatal("expected match for b.com") }
        if !serverBlockMatchesDomain(block, "c.com") { t.Fatal("expected match for c.com") }
}

func TestServerBlockMatchesDomainCaseInsensitive(t *testing.T) {
        block := "server {\n    server_name Example.COM;\n}\n"
        if !serverBlockMatchesDomain(block, "example.com") { t.Fatal("expected case-insensitive match") }
}

// TestOverwriteConfigFileAtAtomicallyReplacesExistingFile verifies that
// overwriteConfigFileAt can rewrite an existing file with new content —
// the behavior that the writeConfigFileAt helper deliberately refuses.
// This is the foundation of Fix 4: PHP pool updates must be able to
// replace an existing pool config.
func TestOverwriteConfigFileAtAtomicallyReplacesExistingFile(t *testing.T) {
        dir := t.TempDir()
        fd := openTestDirectory(t, dir)

        original := "[client01]\nuser = client01\nmemory_limit = 256M\n"
        if err := os.WriteFile(filepath.Join(dir, "pool.conf"), []byte(original), 0640); err != nil {
                t.Fatal(err)
        }

        updated := "[client01]\nuser = client01\nmemory_limit = 512M\n"
        if err := overwriteConfigFileAt(fd, "pool.conf", updated, 0640, os.Getuid(), os.Getgid()); err != nil {
                t.Fatalf("overwrite failed: %v", err)
        }

        got, err := os.ReadFile(filepath.Join(dir, "pool.conf"))
        if err != nil {
                t.Fatal(err)
        }
        if string(got) != updated {
                t.Fatalf("file content was not replaced: got %q, want %q", got, updated)
        }

        // Confirm the file metadata is preserved.
        info, err := os.Stat(filepath.Join(dir, "pool.conf"))
        if err != nil {
                t.Fatal(err)
        }
        if info.Mode().Perm() != 0640 {
                t.Fatalf("file mode changed: %v", info.Mode().Perm())
        }
}

// TestOverwriteConfigFileAtCreatesWhenMissing verifies the same helper
// can also create a new file when none exists. This lets the update path
// handle both initial creation and modification uniformly.
func TestOverwriteConfigFileAtCreatesWhenMissing(t *testing.T) {
        dir := t.TempDir()
        fd := openTestDirectory(t, dir)

        content := "[client01]\nuser = client01\n"
        if err := overwriteConfigFileAt(fd, "pool.conf", content, 0640, os.Getuid(), os.Getgid()); err != nil {
                t.Fatalf("create-via-overwrite failed: %v", err)
        }
        got, err := os.ReadFile(filepath.Join(dir, "pool.conf"))
        if err != nil || string(got) != content {
                t.Fatalf("file content mismatch: %q, err: %v", got, err)
        }
}

// TestOverwriteConfigFileAtRejectsSymlink verifies the update path refuses
// to follow symlinks — a symlink planted at the pool path must not let an
// attacker redirect the write to an unrelated root-owned file.
func TestOverwriteConfigFileAtRejectsSymlink(t *testing.T) {
        dir := t.TempDir()
        fd := openTestDirectory(t, dir)

        target := filepath.Join(dir, "outside.conf")
        if err := os.WriteFile(target, []byte("sensitive data"), 0640); err != nil {
                t.Fatal(err)
        }
        if err := os.Symlink(target, filepath.Join(dir, "pool.conf")); err != nil {
                t.Fatal(err)
        }

        if err := overwriteConfigFileAt(fd, "pool.conf", "[test]\n", 0640, os.Getuid(), os.Getgid()); err == nil {
                t.Fatal("expected symlink target to be rejected")
        }

        // The target file must be untouched.
        got, err := os.ReadFile(target)
        if err != nil || string(got) != "sensitive data" {
                t.Fatalf("symlink target was modified: %q", got)
        }
}

// TestRestoreConfigFileAtRewritesBackup verifies that a restore after a
// failed reload puts the prior content back on disk — the rollback path
// that makes the phased PHP update safe.
func TestRestoreConfigFileAtRewritesBackup(t *testing.T) {
        dir := t.TempDir()
        fd := openTestDirectory(t, dir)

        original := "[client01]\nuser = client01\nmemory_limit = 256M\n"
        if err := os.WriteFile(filepath.Join(dir, "pool.conf"), []byte(original), 0640); err != nil {
                t.Fatal(err)
        }

        // Simulate a failed update: overwrite with new content, then restore.
        newContent := "[client01]\nuser = client01\nmemory_limit = 99999M\n"
        if err := overwriteConfigFileAt(fd, "pool.conf", newContent, 0640, os.Getuid(), os.Getgid()); err != nil {
                t.Fatal(err)
        }
        if err := restoreConfigFileAt(fd, "pool.conf", original, 0640, os.Getuid(), os.Getgid()); err != nil {
                t.Fatalf("restore failed: %v", err)
        }

        got, err := os.ReadFile(filepath.Join(dir, "pool.conf"))
        if err != nil {
                t.Fatal(err)
        }
        if string(got) != original {
                t.Fatalf("restore did not put original content back: got %q", got)
        }
}

// TestRestoreConfigFileAtHandlesEmptyBackup verifies the restore helper
// is a no-op when there was no prior file to restore from. This keeps
// rollback calls safe even on the initial-creation path.
func TestRestoreConfigFileAtHandlesEmptyBackup(t *testing.T) {
        dir := t.TempDir()
        fd := openTestDirectory(t, dir)
        if err := restoreConfigFileAt(fd, "pool.conf", "", 0640, os.Getuid(), os.Getgid()); err != nil {
                t.Fatalf("empty backup restore should be a no-op: %v", err)
        }
        if _, err := os.Stat(filepath.Join(dir, "pool.conf")); !os.IsNotExist(err) {
                t.Fatalf("no file should exist after empty restore, got: %v", err)
        }
}
