//go:build linux

package staticvhost

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/runtimehealth"
)

func loopbackAddress(t *testing.T, server *httptest.Server) string {
	t.Helper()
	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil { t.Fatal(err) }
	if host != "127.0.0.1" { t.Fatalf("test server did not bind loopback: %s",host) }
	return net.JoinHostPort(host,port)
}

func TestStaticProbeUsesLoopbackAndExpectedHostHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		if r.Host != "www.example.test" { t.Errorf("Host = %q",r.Host) }
		if r.URL.Path != "/healthz" { t.Errorf("path = %q",r.URL.Path) }
		w.WriteHeader(http.StatusOK)
		_,_ = w.Write([]byte("static release"))
	}))
	defer server.Close()
	result := probeHTTPAt(context.Background(),"www.example.test","/healthz",loopbackAddress(t,server),time.Second)
	if result.Status != runtimehealth.Healthy || result.HTTPStatus != http.StatusOK || result.FailureCode != "" {
		t.Fatalf("unexpected healthy probe result: %+v",result)
	}
}

func TestStaticProbeClassifiesHTTPFailuresWithoutFollowingRedirects(t *testing.T) {
	redirectTargetCalled := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,_ *http.Request){
		redirectTargetCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,req *http.Request){
		http.Redirect(w,req,target.URL,http.StatusFound)
	}))
	defer redirect.Close()
	result := probeHTTPAt(context.Background(),"www.example.test","/",loopbackAddress(t,redirect),time.Second)
	if result.Status != runtimehealth.Unhealthy || result.HTTPStatus != http.StatusFound || result.FailureCode != "invalid_response" {
		t.Fatalf("unexpected redirect result: %+v",result)
	}
	if redirectTargetCalled { t.Fatal("health probe followed an external redirect") }

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,_ *http.Request){ w.WriteHeader(http.StatusServiceUnavailable) }))
	defer server.Close()
	result = probeHTTPAt(context.Background(),"www.example.test","/",loopbackAddress(t,server),time.Second)
	if result.FailureCode != "http_5xx" || result.HTTPStatus != http.StatusServiceUnavailable {
		t.Fatalf("unexpected 5xx result: %+v",result)
	}
}

func TestStaticProbeRejectsInvalidHostnameAndNonLoopbackDestination(t *testing.T) {
	for _,tc := range []struct{hostname,path,address string}{
		{"www.example.test; return 200","/","127.0.0.1:80"},
		{"www.example.test","/health?token=1","127.0.0.1:80"},
		{"www.example.test","example.com:80","127.0.0.1:80"},
		{"www.example.test","/","[::1]:80"},
		{"www.example.test","/","127.0.0.1:0"},
	} {
		result := probeHTTPAt(context.Background(),tc.hostname,tc.path,tc.address,time.Second)
		if result.Status != runtimehealth.Unhealthy || result.FailureCode != "probe_error" {
			t.Fatalf("accepted invalid probe input %+v: %+v",tc,result)
		}
	}
}

func TestStaticProbeReportsConnectionRefused(t *testing.T) {
	listener, err := net.Listen("tcp4","127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	_,portText,err := net.SplitHostPort(listener.Addr().String())
	if err != nil { t.Fatal(err) }
	_ = listener.Close()
	port,err := strconv.Atoi(portText)
	if err != nil { t.Fatal(err) }
	result := probeHTTPAt(context.Background(),"www.example.test","/",net.JoinHostPort("127.0.0.1",strconv.Itoa(port)),time.Second)
	if result.Status != runtimehealth.Unhealthy || result.FailureCode != "connection_refused" {
		t.Fatalf("unexpected refused result: %+v",result)
	}
}
