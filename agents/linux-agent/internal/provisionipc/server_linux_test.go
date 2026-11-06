//go:build linux

package provisionipc

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func startTestServer(t *testing.T, allowedUID uint32, helper string) (string, context.CancelFunc) {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "provision.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	server := &Server{AllowedUID: allowedUID, HelperPath: helper}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(ctx, listener)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("IPC server did not stop")
		}
	})
	return socketPath, cancel
}

func TestServerClientRoundTrip(t *testing.T) {
	uid := uint32(os.Getuid())
	socketPath, _ := startTestServer(t, uid, "/usr/bin/cat")
	request := []byte(`{"operation":"DATABASE_USAGE"}`)
	result, err := Run(context.Background(), socketPath, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("helper exit code = %d, stderr = %q", result.ExitCode, result.Stderr)
	}
	if string(result.Stdout) != string(request) {
		t.Fatalf("stdout = %q, want %q", result.Stdout, request)
	}
}

func TestServerRejectsWrongPeerUID(t *testing.T) {
	uid := uint32(os.Getuid())
	socketPath, _ := startTestServer(t, uid+1, "/usr/bin/cat")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := Run(ctx, socketPath, []byte("request")); err == nil {
		t.Fatal("expected unauthorized peer to be disconnected")
	}
}

func TestServerRejectsTrailingRequestData(t *testing.T) {
	uid := uint32(os.Getuid())
	socketPath, _ := startTestServer(t, uid, "/usr/bin/cat")
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := writeFrame(conn, []byte("request"), MaxRequestBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("unexpected")); err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var response [1]byte
	if n, err := conn.Read(response[:]); n != 0 || !(errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET)) {
		t.Fatalf("expected EOF for trailing bytes, read=%d err=%v", n, err)
	}
}

func TestResultExitCodeIsPreserved(t *testing.T) {
	result := Result{ExitCode: 23, Stdout: []byte("out"), Stderr: []byte("err")}
	payload, err := marshalResult(result)
	if err != nil {
		t.Fatal(err)
	}
	got, err := unmarshalResult(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got.ExitCode != 23 || string(got.Stdout) != "out" || string(got.Stderr) != "err" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestServerCancellationKillsHelperProcessGroup(t *testing.T) {
	uid := uint32(os.Getuid())
	dir := t.TempDir()
	helper := filepath.Join(dir, "helper.sh")
	pidFile := filepath.Join(dir, "child.pid")

	quotedPIDFile := "'" + strings.ReplaceAll(pidFile, "'", "'\\''") + "'"
	script := "#!/bin/sh\n/bin/sleep 30 &\necho $! > " + quotedPIDFile + "\nwait\n"

	if err := os.WriteFile(helper, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}

	socketPath, cancelServer := startTestServer(t, uid, helper)

	type runResult struct {
		result Result
		err    error
	}
	resultCh := make(chan runResult, 1)

	go func() {
		result, err := Run(context.Background(), socketPath, []byte(`{"operation":"DATABASE_USAGE"}`))
		resultCh <- runResult{result: result, err: err}
	}()

	deadline := time.Now().Add(3 * time.Second)
	var childPID int

	for time.Now().Before(deadline) {
		data, err := os.ReadFile(pidFile)
		if err == nil {
			childPID, err = strconv.Atoi(strings.TrimSpace(string(data)))
			if err == nil && childPID > 0 {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}

	if childPID <= 0 {
		cancelServer()
		t.Fatal("helper did not start its child process")
	}

	defer func() {
		// Safety cleanup if the regression under test fails.
		_ = syscall.Kill(childPID, syscall.SIGKILL)
	}()

	cancelServer()

	select {
	case <-resultCh:
	case <-time.After(4 * time.Second):
		t.Fatal("IPC request did not finish after server cancellation")
	}

	// A killed process may briefly remain as a zombie until reaped.
	terminated := false
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile("/proc/" + strconv.Itoa(childPID) + "/stat")
		if errors.Is(err, os.ErrNotExist) {
			terminated = true
			break
		}
		if err == nil {
			closeParen := strings.LastIndex(string(data), ")")
			if closeParen >= 0 {
				fields := strings.Fields(string(data)[closeParen+1:])
				if len(fields) > 0 && fields[0] == "Z" {
					terminated = true
					break
				}
			}
		}
		time.Sleep(25 * time.Millisecond)
	}

	if !terminated {
		t.Fatalf("helper child process %d survived server cancellation", childPID)
	}
}


func TestClientDisconnectCancelsHelperProcessGroup(t *testing.T) {
	uid := uint32(os.Getuid())
	dir := t.TempDir()
	helper := filepath.Join(dir, "helper.sh")
	pidFile := filepath.Join(dir, "child.pid")
	quotedPIDFile := "'" + strings.ReplaceAll(pidFile, "'", "'\\''") + "'"
	script := "#!/bin/sh\n/bin/sleep 30 &\necho $! > " + quotedPIDFile + "\nwait\n"
	if err := os.WriteFile(helper, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}

	socketPath, _ := startTestServer(t, uid, helper)
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(conn, []byte("request"), MaxRequestBytes); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	var childPID int
	for time.Now().Before(deadline) {
		data, readErr := os.ReadFile(pidFile)
		if readErr == nil {
			childPID, readErr = strconv.Atoi(strings.TrimSpace(string(data)))
			if readErr == nil && childPID > 0 {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if childPID <= 0 {
		_ = conn.Close()
		t.Fatal("helper did not start its child process")
	}
	defer func() { _ = syscall.Kill(childPID, syscall.SIGKILL) }()

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		data, readErr := os.ReadFile("/proc/" + strconv.Itoa(childPID) + "/stat")
		if errors.Is(readErr, os.ErrNotExist) {
			return
		}
		if readErr == nil {
			closeParen := strings.LastIndex(string(data), ")")
			if closeParen >= 0 {
				fields := strings.Fields(string(data)[closeParen+1:])
				if len(fields) > 0 && fields[0] == "Z" {
					return
				}
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("helper child process %d survived client disconnect", childPID)
}

func TestServerKeepsEncodedResponseWithinFrameLimit(t *testing.T) {
	uid := uint32(os.Getuid())
	dir := t.TempDir()
	helper := filepath.Join(dir, "helper.sh")
	script := "#!/bin/sh\n/usr/bin/head -c 6291456 /dev/zero\n"
	if err := os.WriteFile(helper, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	socketPath, _ := startTestServer(t, uid, helper)
	result, err := Run(context.Background(), socketPath, []byte("request"))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Stdout) > maxCapturedStreamBytes || len(result.Stderr) > maxCapturedStreamBytes {
		t.Fatalf("captured output exceeded per-stream cap: stdout=%d stderr=%d", len(result.Stdout), len(result.Stderr))
	}
	if !result.OutputTruncated {
		t.Fatal("expected response to report truncated helper output")
	}
	payload, err := marshalResult(result)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) > MaxResponseBytes {
		t.Fatalf("encoded response is %d bytes, limit is %d", len(payload), MaxResponseBytes)
	}
}


func TestServerEnforcesConcurrentRequestLimit(t *testing.T) {
	uid := uint32(os.Getuid())
	dir := t.TempDir()
	helper := filepath.Join(dir, "helper.sh")
	markerDir := filepath.Join(dir, "active")
	if err := os.Mkdir(markerDir, 0700); err != nil {
		t.Fatal(err)
	}
	quotedDir := "'" + strings.ReplaceAll(markerDir, "'", "'\\''") + "'"
	script := "#!/bin/sh\\ntouch " + quotedDir + "/$$\\nsleep 3\\nrm -f " + quotedDir + "/$$\\n"
	if err := os.WriteFile(helper, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}

	socketPath, _ := startTestServer(t, uid, helper)
	type outcome struct {
		err error
	}
	results := make(chan outcome, maxConcurrentRequests)
	for i := 0; i < maxConcurrentRequests; i++ {
		go func() {
			_, err := Run(context.Background(), socketPath, []byte("request"))
			results <- outcome{err: err}
		}()
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir(markerDir)
		if err == nil && len(entries) == maxConcurrentRequests {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	entries, err := os.ReadDir(markerDir)
	if err != nil || len(entries) != maxConcurrentRequests {
		t.Fatalf("expected %d active helpers, found %d (err=%v)", maxConcurrentRequests, len(entries), err)
	}

	// All worker slots are occupied. The next accepted connection must be
	// closed without starting a fifth privileged helper.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := Run(ctx, socketPath, []byte("overflow")); err == nil {
		t.Fatal("expected request beyond concurrency limit to be rejected")
	}

	for i := 0; i < maxConcurrentRequests; i++ {
		select {
		case got := <-results:
			if got.err != nil {
				t.Fatalf("active request %d failed: %v", i+1, got.err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for active helper requests")
		}
	}
}
