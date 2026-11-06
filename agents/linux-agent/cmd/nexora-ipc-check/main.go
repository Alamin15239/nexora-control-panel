//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/provisionipc"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	request := []byte(`{"operation":"DATABASE_USAGE"}`)
	result, err := provisionipc.Run(ctx, "", request)
	if err != nil {
		fail("IPC connection or protocol failed: %v", err)
	}
	if result.ExitCode != 0 {
		fail("privileged helper returned exit code %d: %s",
			result.ExitCode, string(result.Stderr))
	}
	if len(result.Stdout) == 0 || len(result.Stdout) > 64*1024 {
		fail("database usage response is empty or exceeds 64 KiB")
	}

	var response struct {
		Databases []struct {
			Name      string `json:"name"`
			UsedBytes uint64 `json:"usedBytes"`
		} `json:"databases"`
	}

	decoder := json.NewDecoder(bytes.NewReader(result.Stdout))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		fail("invalid database usage JSON: %v", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		fail("unexpected trailing data in database usage response")
	}
	if response.Databases == nil || len(response.Databases) > 100 {
		fail("database usage response has an invalid database list")
	}

	fmt.Printf("IPC smoke test PASSED: authenticated socket request succeeded; %d database records returned.\n",
		len(response.Databases))
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "IPC smoke test FAILED: "+format+"\n", args...)
	os.Exit(1)
}
