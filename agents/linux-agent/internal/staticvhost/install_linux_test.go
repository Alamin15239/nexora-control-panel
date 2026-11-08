//go:build linux

package staticvhost

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRunner struct { calls []string; failAt string }
func (f *fakeRunner) Run(name string, args ...string) error {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if f.failAt == call { return errors.New("injected command failure") }
	return nil
}
func testConfigDir(t *testing.T) (string,uint32) {
	t.Helper()
	dir:=t.TempDir()
	if err:=os.Chmod(dir,0700);err!=nil{t.Fatal(err)}
	return dir,uint32(os.Getuid())
}
func validName() string { return "nexora-static-0123456789abcdef0123456789abcdef.conf" }
func config(body string) string { return "# Managed by Nexora. Do not edit.\nserver {\n"+body+"\n}\n" }

func TestInstallValidatesBeforeReload(t *testing.T) {
	dir,uid:=testConfigDir(t); runner:=&fakeRunner{}
	if err:=Install(dir,validName(),config("    server_name example.test;"),uid,runner);err!=nil{t.Fatal(err)}
	if len(runner.calls)!=2 || runner.calls[0]!="/usr/sbin/nginx -t" || runner.calls[1]!="/usr/bin/systemctl reload nginx"{t.Fatalf("unexpected command sequence: %#v",runner.calls)}
	got,err:=os.ReadFile(filepath.Join(dir,validName()));if err!=nil{t.Fatal(err)}
	if string(got)!=config("    server_name example.test;"){t.Fatalf("installed content mismatch: %q",got)}
}
func TestInstallRestoresPreviousConfigWhenValidationFails(t *testing.T) {
	dir,uid:=testConfigDir(t); path:=filepath.Join(dir,validName()); old:=config("    server_name old.example.test;")
	if err:=os.WriteFile(path,[]byte(old),0644);err!=nil{t.Fatal(err)}
	runner:=&fakeRunner{failAt:"/usr/sbin/nginx -t"}
	if err:=Install(dir,validName(),config("    server_name new.example.test;"),uid,runner);err==nil{t.Fatal("expected validation failure")}
	got,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
	if string(got)!=old{t.Fatalf("previous config not restored: %q",got)}
}
func TestInstallRemovesNewConfigWhenValidationFails(t *testing.T) {
	dir,uid:=testConfigDir(t);runner:=&fakeRunner{failAt:"/usr/sbin/nginx -t"}
	if err:=Install(dir,validName(),config("    server_name example.test;"),uid,runner);err==nil{t.Fatal("expected validation failure")}
	if _,err:=os.Lstat(filepath.Join(dir,validName()));!os.IsNotExist(err){t.Fatalf("new config remains after failed validation: %v",err)}
}
func TestInstallRestoresPreviousConfigWhenReloadFails(t *testing.T) {
	dir,uid:=testConfigDir(t);path:=filepath.Join(dir,validName());old:=config("    server_name old.example.test;")
	if err:=os.WriteFile(path,[]byte(old),0644);err!=nil{t.Fatal(err)}
	runner:=&fakeRunner{failAt:"/usr/bin/systemctl reload nginx"}
	if err:=Install(dir,validName(),config("    server_name new.example.test;"),uid,runner);err==nil{t.Fatal("expected reload failure")}
	got,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
	if string(got)!=old{t.Fatalf("previous config not restored: %q",got)}
	if len(runner.calls)!=4{t.Fatalf("expected validation, failed reload, recovery validation and reload; got %#v",runner.calls)}
}
func TestInstallRejectsUnsafeFilenameAndUntrustedDirectory(t *testing.T) {
	dir,uid:=testConfigDir(t);runner:=&fakeRunner{}
	if err:=Install(dir,"../../nginx.conf",config(""),uid,runner);err==nil{t.Fatal("accepted unsafe filename")}
	if err:=os.Chmod(dir,0777);err!=nil{t.Fatal(err)}
	if err:=Install(dir,validName(),config(""),uid,runner);err==nil{t.Fatal("accepted writable config directory")}
	if len(runner.calls)!=0{t.Fatalf("commands ran for rejected input: %#v",runner.calls)}
}
func TestInstallRejectsSymlinkTarget(t *testing.T) {
	dir,uid:=testConfigDir(t);target:=filepath.Join(t.TempDir(),"target")
	if err:=os.WriteFile(target,[]byte("keep"),0600);err!=nil{t.Fatal(err)}
	if err:=os.Symlink(target,filepath.Join(dir,validName()));err!=nil{t.Fatal(err)}
	runner:=&fakeRunner{}
	if err:=Install(dir,validName(),config(""),uid,runner);err==nil{t.Fatal("accepted symlink target")}
	got,err:=os.ReadFile(target);if err!=nil{t.Fatal(err)}
	if string(got)!="keep"{t.Fatalf("symlink target modified: %q",got)}
}
