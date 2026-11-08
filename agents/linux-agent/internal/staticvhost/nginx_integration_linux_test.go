//go:build linux

package staticvhost

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestNginxServesAtomicReleaseSwitch is an opt-in disposable-node integration
// test. It starts an isolated Nginx master on loopback and never edits system
// configuration. Enable with NEXORA_NGINX_INTEGRATION=1 on a host with nginx.
func TestNginxServesAtomicReleaseSwitch(t *testing.T) {
	if os.Getenv("NEXORA_NGINX_INTEGRATION") != "1" {
		t.Skip("set NEXORA_NGINX_INTEGRATION=1 on a disposable host with nginx")
	}
	nginx, err := exec.LookPath("nginx")
	if err != nil { t.Skip("nginx binary is not installed") }
	tmp := t.TempDir()
	for _, id := range []string{"release-a", "release-b"} {
		root := filepath.Join(tmp, "releases", id)
		if err := os.MkdirAll(root, 0755); err != nil { t.Fatal(err) }
		if err := os.WriteFile(filepath.Join(root, "index.html"), []byte(id), 0644); err != nil { t.Fatal(err) }
	}
	current := filepath.Join(tmp, "current")
	if err := os.Symlink(filepath.Join("releases","release-a"), current); err != nil { t.Fatal(err) }
	listener, err := net.Listen("tcp4","127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	binding := Binding{DomainID:"integration_domain",HostingAccountID:"integration_account",Hostname:"integration.example.test"}
	serverBlock, err := Render(binding)
	if err != nil { t.Fatal(err) }
	serverBlock = strings.Replace(serverBlock,"listen 80;","listen 127.0.0.1:"+strconv.Itoa(port)+";",1)
	serverBlock = strings.Replace(serverBlock,"/var/lib/nexora-static/accounts/integration_account/current",current,1)
	sitePath := filepath.Join(tmp,"site.conf")
	if err := os.WriteFile(sitePath,[]byte(serverBlock),0600); err != nil { t.Fatal(err) }
	config := fmt.Sprintf("worker_processes 1;\npid %s;\nerror_log %s;\nevents { worker_connections 32; }\nhttp { access_log off; include %s; }\n",
		filepath.Join(tmp,"nginx.pid"),filepath.Join(tmp,"error.log"),sitePath)
	configPath := filepath.Join(tmp,"nginx.conf")
	if err := os.WriteFile(configPath,[]byte(config),0600); err != nil { t.Fatal(err) }
	if output, err := exec.Command(nginx,"-t","-p",tmp+"/","-c",configPath).CombinedOutput(); err != nil {
		t.Fatalf("isolated nginx config validation failed: %v: %s",err,output)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx,nginx,"-g","daemon off; master_process off;","-p",tmp+"/","-c",configPath)
	output := &strings.Builder{}
	cmd.Stdout,cmd.Stderr = output,output
	if err := cmd.Start(); err != nil { t.Fatalf("start isolated nginx: %v",err) }
	defer func(){ cancel(); _ = cmd.Wait() }()

	client := &http.Client{Timeout:time.Second,CheckRedirect:func(_ *http.Request,_ []*http.Request) error{return http.ErrUseLastResponse}}
	fetch := func() string {
		t.Helper()
		deadline := time.Now().Add(5*time.Second)
		for time.Now().Before(deadline) {
			req,_ := http.NewRequest(http.MethodGet,fmt.Sprintf("http://127.0.0.1:%d/",port),nil)
			req.Host = binding.Hostname
			resp,requestErr := client.Do(req)
			if requestErr == nil {
				body,_ := io.ReadAll(io.LimitReader(resp.Body,1024))
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK { return string(body) }
			}
			time.Sleep(50*time.Millisecond)
		}
		t.Fatalf("isolated nginx did not serve a healthy response: %s",output.String())
		return ""
	}
	if got := fetch(); got != "release-a" { t.Fatalf("initial release body = %q",got) }
	next := filepath.Join(tmp,"current.next")
	if err := os.Symlink(filepath.Join("releases","release-b"),next); err != nil { t.Fatal(err) }
	if err := os.Rename(next,current); err != nil { t.Fatal(err) }
	if got := fetch(); got != "release-b" { t.Fatalf("switched release body = %q",got) }

	req,_ := http.NewRequest(http.MethodGet,fmt.Sprintf("http://127.0.0.1:%d/index.php",port),nil)
	req.Host = binding.Hostname
	resp,err := client.Do(req)
	if err != nil { t.Fatal(err) }
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound { t.Fatalf("PHP path status = %d, want 404",resp.StatusCode) }
}
