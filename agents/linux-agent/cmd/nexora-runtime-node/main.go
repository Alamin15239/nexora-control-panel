package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/ocisupervisor"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/runtimecontroller"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/runtimepoller"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/supervisorstate"
)

var runtimeNodeIdentityPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/ocisupervisor"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/runtimecontroller"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/runtimepoller"
	"github.com/alamin15239/nexora-control-panel/agents/linux-agent/internal/supervisorstate"
)

)

type Config struct {
	ControlPlaneURL string `json:"control_plane_url"`
	NodeIdentity string `json:"node_identity"`
	PrivateKeyFile string `json:"private_key_file"`
	StateFile string `json:"state_file"`
	AllowedRegistries []string `json:"allowed_registries"`
	PollIntervalSeconds int `json:"poll_interval_seconds"`
}

func main() {
	configPath := flag.String("config", "/etc/nexora-runtime/node.json", "runtime node config")
	flag.Parse()
	if err := run(*configPath); err != nil {
		fmt.Fprintln(os.Stderr, "nexora-runtime-node:", err)
		os.Exit(1)
	}
}

func loadConfig(path string) (Config, error) {
	var cfg Config
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return cfg, errors.New("config path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil { return cfg, err }
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return cfg, errors.New("runtime config must be a regular owner-only file")
	}
	raw, err := os.ReadFile(path)
	if err != nil { return cfg, err }
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil { return cfg, fmt.Errorf("decode runtime config: %w", err) }
	var extra any
	if err := decoder.Decode(&extra); err == nil { return cfg, errors.New("runtime config contains trailing JSON data") }
	u, err := url.Parse(cfg.ControlPlaneURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return cfg, errors.New("control_plane_url must be an HTTPS origin without credentials, path, query or fragment")
	}
	if !runtimeNodeIdentityPattern.MatchString(cfg.NodeIdentity) {
		return cfg, errors.New("node_identity is invalid")
	}
	if !filepath.IsAbs(cfg.PrivateKeyFile) || filepath.Clean(cfg.PrivateKeyFile) != cfg.PrivateKeyFile {
		return cfg, errors.New("private_key_file must be an absolute clean path")
	}
	if !filepath.IsAbs(cfg.StateFile) || filepath.Clean(cfg.StateFile) != cfg.StateFile {
		return cfg, errors.New("state_file must be an absolute clean path")
	}
	if cfg.PollIntervalSeconds < 15 || cfg.PollIntervalSeconds > 600 {
		return cfg, errors.New("poll_interval_seconds must be between 15 and 600")
	}
	if len(cfg.AllowedRegistries) == 0 {
		return cfg, errors.New("at least one operator-approved OCI registry is required")
	}
	for _, registry := range cfg.AllowedRegistries {
		if strings.ContainsAny(registry, "/:@ \t\r\n") || registry == "" {
			return cfg, errors.New("allowed registry entries must be hostnames only")
		}
	}
	return cfg, nil
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err != nil { return nil, err }
	if info.Size() > 256 { return nil, errors.New("Ed25519 private key file exceeds size limit") }
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("Ed25519 private key file must be regular and owner-only")
	}
	raw, err := os.ReadFile(path)
	if err != nil { return nil, err }
	encoded := strings.TrimSpace(string(raw))
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, errors.New("private key file must contain a 64-byte Ed25519 private key in hex")
	}
	return ed25519.PrivateKey(decoded), nil
}

func run(configPath string) error {
	cfg, err := loadConfig(configPath)
	if err != nil { return err }
	key, err := loadPrivateKey(cfg.PrivateKeyFile)
	if err != nil { return fmt.Errorf("load node signing key: %w", err) }
	store, err := supervisorstate.Open(cfg.StateFile)
	if err != nil { return fmt.Errorf("open durable supervisor state: %w", err) }

	// Startup recovery verifies every previously recorded container before the
	// polling loop is allowed to start. No workload is started or changed.
	podman := ocisupervisor.Podman{AllowedRegistries: cfg.AllowedRegistries}
	recovery, err := (runtimecontroller.Controller{Backend: podman, State: store}).Recover(context.Background())
	if err != nil { return fmt.Errorf("fail-closed runtime startup recovery: %w", err) }
	fmt.Printf("runtime recovery verified %d persisted workloads; refreshed %d states\n", recovery.Checked, recovery.Reconciled)

	client := &runtimepoller.Client{BaseURL: cfg.ControlPlaneURL, NodeIdentity: cfg.NodeIdentity, PrivateKey: key}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	poll := func() error {
		snapshot, err := client.Poll(ctx)
		if err != nil { return err }
		// Execution is deliberately disabled in the control-plane contract.
		if snapshot.ExecutionEnabled || snapshot.CommandsIncluded || snapshot.SecretsIncluded {
			return errors.New("control plane attempted to enable workload execution or deliver commands/secrets")
		}
		fmt.Printf("desired-state poll accepted: %d assigned workload records; execution disabled\n", len(snapshot.Workloads))
		return nil
	}
	if err := poll(); err != nil { fmt.Fprintln(os.Stderr, "initial desired-state poll:", err) }
	ticker := time.NewTicker(time.Duration(cfg.PollIntervalSeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := poll(); err != nil && ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "desired-state poll:", err)
			}
		}
	}
}
