// Package runtimehealth probes a workload only through an explicitly assigned
// loopback port. It never follows redirects or connects to external hosts.
package runtimehealth

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
)

const (
	DefaultTimeout = 5 * time.Second
	MaxTimeout = 30 * time.Second
	MaxResponseBytes = 4096
)

type Status string

const (
	Healthy Status = "healthy"
	Unhealthy Status = "unhealthy"
)

type Result struct {
	Status Status
	HTTPStatus int
	DurationMs int64
	FailureCode string
}

// Probe performs a bounded GET to http://127.0.0.1:<port><path>.
// The caller must obtain port/path from trusted runtime assignment/configuration.
// Redirects are reported as unhealthy and never followed.
func Probe(ctx context.Context, port int, path string, timeout time.Duration) Result {
	started := time.Now()
	result := Result{Status: Unhealthy}
	finish := func() Result {
		result.DurationMs = time.Since(started).Milliseconds()
		if result.DurationMs < 0 { result.DurationMs = 0 }
		if result.DurationMs > MaxTimeout.Milliseconds() { result.DurationMs = MaxTimeout.Milliseconds() }
		return result
	}

	if port < 1 || port > 65535 {
		result.FailureCode = "probe_error"
		return finish()
	}
	if err := validatePath(path); err != nil {
		result.FailureCode = "probe_error"
		return finish()
	}
	if timeout <= 0 { timeout = DefaultTimeout }
	if timeout > MaxTimeout { timeout = MaxTimeout }

	probeContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	target := "http://127.0.0.1:" + strconv.Itoa(port) + path
	parsed, err := url.Parse(target)
	if err != nil || parsed.Hostname() != "127.0.0.1" || parsed.Port() == "" {
		result.FailureCode = "probe_error"
		return finish()
	}

	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			host, dialPort, splitErr := net.SplitHostPort(address)
			if splitErr != nil || host != "127.0.0.1" || dialPort != strconv.Itoa(port) {
				return nil, errors.New("health probe attempted a non-assigned loopback destination")
			}
			dialer := &net.Dialer{Timeout: timeout, KeepAlive: -1}
			return dialer.DialContext(dialCtx, "tcp4", net.JoinHostPort("127.0.0.1", dialPort))
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequestWithContext(probeContext, http.MethodGet, target, nil)
	if err != nil {
		result.FailureCode = "probe_error"
		return finish()
	}
	request.Header.Set("User-Agent", "Nexora-Runtime-HealthCheck/1")

	response, err := client.Do(request)
	if err != nil {
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			result.FailureCode = "timeout"
		default:
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				result.FailureCode = "timeout"
			} else {
				var opErr *net.OpError
				if errors.As(err, &opErr) && strings.Contains(strings.ToLower(opErr.Err.Error()), "refused") {
					result.FailureCode = "connection_refused"
				} else {
					result.FailureCode = "probe_error"
				}
			}
		}
		return finish()
	}
	defer response.Body.Close()
	result.HTTPStatus = response.StatusCode
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, MaxResponseBytes))
	if response.StatusCode >= 200 && response.StatusCode <= 299 {
		result.Status = Healthy
		result.FailureCode = ""
		return finish()
	}
	if response.StatusCode >= 300 && response.StatusCode <= 399 {
		result.FailureCode = "invalid_response"
	} else if response.StatusCode >= 400 && response.StatusCode <= 499 {
		result.FailureCode = "http_4xx"
	} else if response.StatusCode >= 500 && response.StatusCode <= 599 {
		result.FailureCode = "http_5xx"
	} else {
		result.FailureCode = "invalid_response"
	}
	return finish()
}

func validatePath(path string) error {
	if path == "" || len(path) > 512 || !strings.HasPrefix(path, "/") ||
		strings.ContainsAny(path, "?#\r\n") {
		return fmt.Errorf("health-check path must be a local absolute path without query or fragment")
	}
	for _, r := range path {
		if r < 0x20 || r == 0x7f {
			return errors.New("health-check path contains a control character")
		}
	}
	return nil
}
