package runtimehealth

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func loopbackPort(t *testing.T, server *httptest.Server) int {
	t.Helper()
	host, rawPort, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil { t.Fatal(err) }
	if host != "127.0.0.1" { t.Fatalf("test server is not loopback-bound: %s", host) }
	port, err := strconv.Atoi(rawPort)
	if err != nil { t.Fatal(err) }
	return port
}

func TestProbeReportsHealthyLocalApplication(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/ready" {
			t.Fatalf("unexpected probe request: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	result := Probe(context.Background(), loopbackPort(t, server), "/ready", time.Second)
	if result.Status != Healthy || result.HTTPStatus != http.StatusNoContent || result.FailureCode != "" {
		t.Fatalf("unexpected health result: %+v", result)
	}
}

func TestProbeClassifiesHTTPFailuresWithoutFollowingRedirects(t *testing.T) {
	cases := []struct {
		name string
		status int
		failure string
	}{
		{name:"redirect",status:http.StatusFound,failure:"invalid_response"},
		{name:"client error",status:http.StatusServiceUnavailable-400,failure:"http_4xx"},
		{name:"server error",status:http.StatusServiceUnavailable,failure:"http_5xx"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			redirectTargetCalled := false
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				redirectTargetCalled = true
				w.WriteHeader(http.StatusOK)
			}))
			defer target.Close()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if testCase.status == http.StatusFound {
					http.Redirect(w, r, target.URL, http.StatusFound)
					return
				}
				w.WriteHeader(testCase.status)
			}))
			defer server.Close()
			result := Probe(context.Background(), loopbackPort(t, server), "/ready", time.Second)
			if result.Status != Unhealthy || result.FailureCode != testCase.failure {
				t.Fatalf("unexpected health result: %+v", result)
			}
			if redirectTargetCalled { t.Fatal("health probe followed an external redirect") }
		})
	}
}

func TestProbeClassifiesConnectionRefusedAndTimeout(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil { t.Fatal(err) }
	refused := Probe(context.Background(), port, "/ready", 200*time.Millisecond)
	if refused.FailureCode != "connection_refused" {
		t.Fatalf("expected connection_refused, got %+v", refused)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	timeout := Probe(context.Background(), loopbackPort(t, server), "/ready", 20*time.Millisecond)
	if timeout.FailureCode != "timeout" || timeout.DurationMs > 100 {
		t.Fatalf("expected bounded timeout, got %+v", timeout)
	}
}

func TestProbeRejectsInvalidPortAndUnsafePaths(t *testing.T) {
	for _, tc := range []struct{ port int; path string }{
		{port:0,path:"/ready"},
		{port:65536,path:"/ready"},
		{port:1234,path:"https://example.com/ready"},
		{port:1234,path:"/ready?token=secret"},
		{port:1234,path:"/ready#fragment"},
		{port:1234,path:"/ready\r\nHost: evil"},
	} {
		result := Probe(context.Background(), tc.port, tc.path, time.Second)
		if result.Status != Unhealthy || result.FailureCode != "probe_error" {
			t.Fatalf("expected invalid probe input rejection for %+v, got %+v", tc, result)
		}
	}
}

func TestProbeHonorsCallerCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100*time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := Probe(ctx, loopbackPort(t, server), "/ready", time.Second)
	if result.Status != Unhealthy || result.FailureCode != "probe_error" {
		t.Fatalf("unexpected cancelled probe result: %+v", result)
	}
}
