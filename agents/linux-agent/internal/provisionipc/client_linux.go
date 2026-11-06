//go:build linux

package provisionipc

import (
	"context"
	"fmt"
	"net"
	"time"
)

const defaultSocketPath = "/run/nexora/provision.sock"

// Run sends exactly one provisioner JSON request and receives exactly one
// bounded response. Helper failures are represented by Result.ExitCode;
// transport and protocol failures are returned as errors.
func Run(ctx context.Context, socketPath string, request []byte) (Result, error) {
	if len(request) == 0 || len(request) > MaxRequestBytes {
		return Result{}, fmt.Errorf("provisioning request exceeds the IPC size limit")
	}
	if socketPath == "" {
		socketPath = defaultSocketPath
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return Result{}, fmt.Errorf("connect to provisioning service: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(2 * time.Minute)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return Result{}, err
	}
	if err := writeFrame(conn, request, MaxRequestBytes); err != nil {
		return Result{}, fmt.Errorf("send provisioning request: %w", err)
	}
	response, err := readFrame(conn, MaxResponseBytes)
	if err != nil {
		return Result{}, fmt.Errorf("receive provisioning response: %w", err)
	}
	result, err := unmarshalResult(response)
	if err != nil {
		return Result{}, fmt.Errorf("decode provisioning response: %w", err)
	}
	return result, nil
}
