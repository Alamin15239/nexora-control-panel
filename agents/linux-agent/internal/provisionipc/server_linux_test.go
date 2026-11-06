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
