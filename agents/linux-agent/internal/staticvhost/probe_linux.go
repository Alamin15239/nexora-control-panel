//go:build linux

package staticvhost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/runtimehealth"
)

const staticProbeTimeout = 5 * time.Second

// ProbeHTTP checks the activated static hostname through the local Nginx
// listener. It never resolves or connects to a customer-controlled address.
func ProbeHTTP(ctx context.Context, hostname string, timeout time.Duration) runtimehealth.Result {
	return probeHTTPAt(ctx, hostname, "127.0.0.1:80", timeout)
}

// probeHTTPAt keeps the destination injectable for tests. Production callers
// use ProbeHTTP, whose destination is always the local IPv4 loopback listener.
func probeHTTPAt(ctx context.Context, hostname, address string, timeout time.Duration) runtimehealth.Result {
	started := time.Now()
	result := runtimehealth.Result{Status: runtimehealth.Unhealthy}
	finish := func() runtimehealth.Result {
		result.DurationMs = time.Since(started).Milliseconds()
		if result.DurationMs < 0 { result.DurationMs = 0 }
		if result.DurationMs > 30000 { result.DurationMs = 30000 }
		return result
	}
	if _, err := Render(Binding{DomainID:"probe", HostingAccountID:"probe", Hostname:hostname}); err != nil {
		result.FailureCode = "probe_error"
		return finish()
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" {
		result.FailureCode = "probe_error"
		return finish()
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		result.FailureCode = "probe_error"
		return finish()
	}
	if timeout <= 0 { timeout = staticProbeTimeout }
	if timeout > 30*time.Second { timeout = 30*time.Second }
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	target := "http://" + net.JoinHostPort("127.0.0.1", portText) + "/"
	parsed, err := url.Parse(target)
	if err != nil || parsed.Hostname() != "127.0.0.1" || parsed.Port() != portText {
		result.FailureCode = "probe_error"
		return finish()
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(dialCtx context.Context, network, dialAddress string) (net.Conn, error) {
			dialHost, dialPort, splitErr := net.SplitHostPort(dialAddress)
			if splitErr != nil || dialHost != "127.0.0.1" || dialPort != portText {
				return nil, errors.New("static health probe attempted a non-loopback destination")
			}
			return (&net.Dialer{Timeout:timeout, KeepAlive:-1}).DialContext(dialCtx,"tcp4",net.JoinHostPort("127.0.0.1",portText))
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport:transport,
		Timeout:timeout,
		CheckRedirect:func(_ *http.Request,_ []*http.Request) error { return http.ErrUseLastResponse },
	}
	request, err := http.NewRequestWithContext(probeCtx,http.MethodGet,target,nil)
	if err != nil {
		result.FailureCode = "probe_error"
		return finish()
	}
	request.Host = hostname
	request.Header.Set("User-Agent","Nexora-Static-HealthCheck/1")
	response, err := client.Do(request)
	if err != nil {
		switch {
		case errors.Is(err,context.DeadlineExceeded):
			result.FailureCode = "timeout"
		default:
			var netErr net.Error
			var opErr *net.OpError
			if errors.As(err,&netErr) && netErr.Timeout() {
				result.FailureCode = "timeout"
			} else if errors.As(err,&opErr) && strings.Contains(strings.ToLower(opErr.Err.Error()),"refused") {
				result.FailureCode = "connection_refused"
			} else {
				result.FailureCode = "probe_error"
			}
		}
		return finish()
	}
	defer response.Body.Close()
	result.HTTPStatus = response.StatusCode
	_, _ = io.Copy(io.Discard,io.LimitReader(response.Body,4096))
	if response.StatusCode >= 200 && response.StatusCode <= 299 {
		result.Status = runtimehealth.Healthy
		result.FailureCode = ""
		return finish()
	}
	switch {
	case response.StatusCode >= 300 && response.StatusCode <= 399:
		result.FailureCode = "invalid_response"
	case response.StatusCode >= 400 && response.StatusCode <= 499:
		result.FailureCode = "http_4xx"
	case response.StatusCode >= 500 && response.StatusCode <= 599:
		result.FailureCode = "http_5xx"
	default:
		result.FailureCode = "invalid_response"
	}
	_ = fmt.Sprintf("%d",result.HTTPStatus)
	return finish()
}
