package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
)

type Config struct {
	NodeID       string `json:"node_id"`
	ControlPlane string `json:"control_plane_url"`
	CACert       string `json:"ca_cert_file"`
	ClientCert   string `json:"client_cert_file"`
	ClientKey    string `json:"client_key_file"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "version":
		fmt.Println("nexora-agent 0.2.0")
	case "validate-config":
		fs := flag.NewFlagSet("validate-config", flag.ExitOnError)
		configPath := fs.String("config", "/etc/nexora/agent.json", "path to agent JSON configuration")
		_ = fs.Parse(os.Args[2:])
		if err := validate(*configPath); err != nil {
			fmt.Fprintln(os.Stderr, "configuration invalid:", err)
			os.Exit(1)
		}
		fmt.Println("configuration valid; no server operations were executed")
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: nexora-agent <version|validate-config> [options]")
}

func validate(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("parse JSON: %w", err)
	}
	if strings.TrimSpace(cfg.NodeID) == "" {
		return fmt.Errorf("node_id is required")
	}
	parsed, err := url.Parse(cfg.ControlPlane)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return fmt.Errorf("control_plane_url must be a valid HTTPS URL without embedded credentials")
	}
	if cfg.CACert == "" || cfg.ClientCert == "" || cfg.ClientKey == "" {
		return fmt.Errorf("CA certificate and client certificate/key paths are required")
	}

	caPEM, err := os.ReadFile(cfg.CACert)
	if err != nil {
		return fmt.Errorf("read CA certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM(caPEM); !ok {
		return fmt.Errorf("CA file contains no valid PEM certificates")
	}

	cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
	if err != nil {
		return fmt.Errorf("load client mTLS identity: %w", err)
	}
	if len(cert.Certificate) == 0 {
		return fmt.Errorf("client certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse client certificate: %w", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("client certificate is not trusted for client authentication by configured CA: %w", err)
	}
	return nil
}
