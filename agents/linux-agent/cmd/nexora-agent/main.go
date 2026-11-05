package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const version = "0.8.0"

type Config struct {
	NodeID       string `json:"node_id"`
	Secret       string `json:"secret"`
	ControlPlane string `json:"control_plane_url"`
	ServerID     string `json:"server_id,omitempty"`
}

type serviceCheck struct {
	Key         string `json:"key"`
	DisplayName string `json:"displayName"`
	Status      string `json:"status"`
	CheckedAt   string `json:"checkedAt"`
}

type databaseUsageMeasurement struct {
	Name        string `json:"name"`
	UsedBytes   uint64 `json:"usedBytes"`
	CollectedAt string `json:"collectedAt"`
}

type telemetry struct {
	AgentVersion  string                     `json:"agentVersion"`
	CPUUsage      float64                    `json:"cpuUsagePercent"`
	MemoryTotal   uint64                     `json:"memoryTotalBytes"`
	MemoryUsed    uint64                     `json:"memoryUsedBytes"`
	DiskTotal     uint64                     `json:"diskTotalBytes"`
	DiskUsed      uint64                     `json:"diskUsedBytes"`
	Load1         float64                    `json:"loadAverage1m"`
	CollectedAt   string                     `json:"collectedAt"`
	Services      []serviceCheck             `json:"services,omitempty"`
	DatabaseUsage []databaseUsageMeasurement `json:"databaseUsage,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Println("nexora-agent " + version)
	case "enroll":
		fs := flag.NewFlagSet("enroll", flag.ExitOnError)
		api := fs.String("api", "", "Nexora API base URL")
		serverID := fs.String("server-id", "", "registered Nexora server ID")
		configPath := fs.String("config", "/etc/nexora/agent.json", "agent config output path")
		tokenStdin := fs.Bool("token-stdin", false, "read one-time enrollment token from stdin")
		_ = fs.Parse(os.Args[2:])
		if !*tokenStdin || *api == "" || *serverID == "" {
			fs.Usage()
			os.Exit(2)
		}
		if err := enroll(*api, *serverID, *configPath); err != nil {
			fmt.Fprintln(os.Stderr, "enrollment failed:", err)
			os.Exit(1)
		}
		fmt.Println("Node enrolled. Credential saved with owner-only permissions.")
	case "run":
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		configPath := fs.String("config", "/etc/nexora/agent.json", "agent config path")
		interval := fs.Duration("interval", 60*time.Second, "heartbeat interval")
		_ = fs.Parse(os.Args[2:])
		if *interval < 15*time.Second || *interval > 10*time.Minute {
			fmt.Fprintln(os.Stderr, "interval must be between 15s and 10m")
			os.Exit(2)
		}
		if err := run(*configPath, *interval); err != nil {
			fmt.Fprintln(os.Stderr, "agent stopped:", err)
			os.Exit(1)
		}
	case "validate-config":
		fs := flag.NewFlagSet("validate-config", flag.ExitOnError)
		configPath := fs.String("config", "/etc/nexora/agent.json", "agent config path")
		_ = fs.Parse(os.Args[2:])
		if _, err := loadConfig(*configPath); err != nil {
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
	fmt.Fprintln(os.Stderr, "Usage: nexora-agent <version|enroll|run|validate-config> [options]")
}

func loadConfig(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse JSON: %w", err)
	}
	if cfg.NodeID == "" || len(cfg.Secret) != 64 {
		return Config{}, fmt.Errorf("node_id and 32-byte hex secret are required")
	}
	if _, err := hex.DecodeString(cfg.Secret); err != nil {
		return Config{}, fmt.Errorf("secret must be hexadecimal")
	}
	u, err := url.Parse(cfg.ControlPlane)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return Config{}, fmt.Errorf("control_plane_url must be a valid HTTPS URL")
	}
	return cfg, nil
}

func apiBase(value string) (string, error) {
	u, err := url.Parse(strings.TrimRight(value, "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("API URL must use HTTPS")
	}
	return strings.TrimRight(value, "/"), nil
}

func enroll(api, serverID, configPath string) error {
	base, err := apiBase(api)
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stderr, "Paste the one-time enrollment token, then press Enter: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && len(line) == 0 {
		return err
	}
	token := strings.TrimSpace(line)
	if len(token) != 64 {
		return fmt.Errorf("enrollment token must be 32-byte hex")
	}
	if _, err := hex.DecodeString(token); err != nil {
		return fmt.Errorf("invalid enrollment token")
	}
	body, _ := json.Marshal(map[string]string{"serverId": serverID, "enrollmentToken": token})
	req, err := http.NewRequest(http.MethodPost, base+"/v1/agent/enroll", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("control plane returned %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	var result struct {
		NodeID string `json:"nodeId"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}
	if result.NodeID == "" || len(result.Secret) != 64 {
		return fmt.Errorf("control plane returned invalid node credentials")
	}
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		return err
	}
	cfg := Config{NodeID: result.NodeID, Secret: result.Secret, ControlPlane: base, ServerID: serverID}
	encoded, _ := json.MarshalIndent(cfg, "", "  ")
	tmp := configPath + ".tmp"
	if err := os.WriteFile(tmp, encoded, 0600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, configPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

const jobPollInterval = 15 * time.Second
const serviceCheckEvery = 5

func run(configPath string, interval time.Duration) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client := &http.Client{Timeout: 15 * time.Second}
	var previousTotal, previousIdle uint64
	heartbeatCount := 0

	sendTelemetry := func() {
		heartbeatCount++
		includeServices := heartbeatCount == 1 || heartbeatCount%serviceCheckEvery == 0
		sample, total, idle, collectErr := collect(previousTotal, previousIdle, includeServices)
		if collectErr != nil {
			fmt.Fprintln(os.Stderr, "telemetry:", collectErr)
			return
		}
		previousTotal, previousIdle = total, idle

		if includeServices {
			databaseUsage, usageErr := collectDatabaseUsage(ctx)
			if usageErr != nil {
				fmt.Fprintln(os.Stderr, "database usage:", usageErr)
			} else {
				sample.DatabaseUsage = databaseUsage
			}
		}

		if heartbeatErr := sendHeartbeat(ctx, client, cfg, sample); heartbeatErr != nil {
			fmt.Fprintln(os.Stderr, "heartbeat:", heartbeatErr)
		}
	}
	pollJobs := func() {
		if jobErr := processNextJob(ctx, client, cfg); jobErr != nil && ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, "provisioning:", jobErr)
		}
	}

	// Send an initial heartbeat and check for queued work immediately at startup.
	sendTelemetry()
	pollJobs()

	heartbeatTicker := time.NewTicker(interval)
	defer heartbeatTicker.Stop()
	jobTicker := time.NewTicker(jobPollInterval)
	defer jobTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-heartbeatTicker.C:
			sendTelemetry()
		case <-jobTicker.C:
			pollJobs()
		}
	}
}

func collect(previousTotal, previousIdle uint64, includeServices bool) (telemetry, uint64, uint64, error) {
	cpu, total, idle, err := cpuUsage(previousTotal, previousIdle)
	if err != nil {
		return telemetry{}, total, idle, err
	}

	memTotal, memUsed, err := memoryUsage()
	if err != nil {
		return telemetry{}, total, idle, err
	}

	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return telemetry{}, total, idle, err
	}

	diskTotal := stat.Blocks * uint64(stat.Bsize)
	diskFree := stat.Bavail * uint64(stat.Bsize)

	loadRaw, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return telemetry{}, total, idle, err
	}

	fields := strings.Fields(string(loadRaw))
	if len(fields) == 0 {
		return telemetry{}, total, idle, fmt.Errorf("invalid load average")
	}

	load, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return telemetry{}, total, idle, err
	}

	sample := telemetry{
		AgentVersion: version,
		CPUUsage:     cpu,
		MemoryTotal:  memTotal,
		MemoryUsed:   memUsed,
		DiskTotal:    diskTotal,
		DiskUsed:     diskTotal - diskFree,
		Load1:        load,
		CollectedAt:  time.Now().UTC().Format(time.RFC3339),
	}

	if includeServices {
		sample.Services = collectServiceChecks()
	}

	return sample, total, idle, nil
}

func serviceStatus(loadState, activeState string) string {
	switch {
	case loadState == "not-found":
		return "NOT_INSTALLED"
	case loadState != "loaded":
		return "UNKNOWN"
	case activeState == "active":
		return "ACTIVE"
	case activeState == "inactive":
		return "INACTIVE"
	case activeState == "failed":
		return "FAILED"
	default:
		return "UNKNOWN"
	}
}

// Only these fixed systemd units are inspected. No user-provided command or unit is executed.
func collectServiceChecks() []serviceCheck {
	services := []struct {
		key  string
		name string
		unit string
	}{
		{"nginx", "Nginx", "nginx.service"},
		{"php_fpm", "PHP 8.5-FPM", "php8.5-fpm.service"},
		{"mariadb", "MariaDB", "mariadb.service"},
		{"ssh", "SSH", "ssh.service"},
		{"nexora_agent", "Nexora Agent", "nexora-agent.service"},
		{"cloudflared", "Cloudflare Tunnel", "cloudflared.service"},
	}

	checkedAt := time.Now().UTC().Format(time.RFC3339)
	results := make([]serviceCheck, 0, len(services))

	for _, service := range services {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		output, err := exec.CommandContext(
			ctx,
			"/usr/bin/systemctl",
			"show",
			service.unit,
			"--property=LoadState",
			"--property=ActiveState",
			"--value",
		).Output()
		cancel()

		status := "UNKNOWN"
		if err == nil {
			fields := strings.Fields(string(output))
			if len(fields) >= 2 {
				status = serviceStatus(fields[0], fields[1])
			}
		}

		results = append(results, serviceCheck{
			Key:         service.key,
			DisplayName: service.name,
			Status:      status,
			CheckedAt:   checkedAt,
		})
	}

	return results
}

func cpuUsage(previousTotal, previousIdle uint64) (float64, uint64, uint64, error) {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, 0, err
	}
	fields := strings.Fields(strings.SplitN(string(raw), "\n", 2)[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, 0, fmt.Errorf("invalid /proc/stat")
	}
	var values []uint64
	for _, f := range fields[1:] {
		n, e := strconv.ParseUint(f, 10, 64)
		if e != nil {
			return 0, 0, 0, e
		}
		values = append(values, n)
	}
	var total uint64
	for _, n := range values {
		total += n
	}
	idle := values[3]
	if len(values) > 4 {
		idle += values[4]
	}
	if previousTotal == 0 || total <= previousTotal || idle < previousIdle {
		return 0, total, idle, nil
	}
	dt, di := total-previousTotal, idle-previousIdle
	return 100 * float64(dt-di) / float64(dt), total, idle, nil
}

func memoryUsage() (uint64, uint64, error) {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	var total, available uint64
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		n, e := strconv.ParseUint(f[1], 10, 64)
		if e != nil {
			continue
		}
		switch strings.TrimSuffix(f[0], ":") {
		case "MemTotal":
			total = n * 1024
		case "MemAvailable":
			available = n * 1024
		}
	}
	if total == 0 || available > total {
		return 0, 0, fmt.Errorf("invalid memory counters")
	}
	return total, total - available, nil
}

type provisionJob struct {
	DatabaseName string `json:"databaseName,omitempty"`
	ID           string `json:"id"`
	Operation    string `json:"operation"`
	Account      struct {
		AccountID      string `json:"accountId"`
		Username       string `json:"username"`
		PrimaryDomain  string `json:"primaryDomain"`
		DiskLimitBytes uint64 `json:"diskLimitBytes"`
		Domain         string `json:"domain"`
		DocumentRoot   string `json:"documentRoot"`
	} `json:"account"`
	RequestPayload json.RawMessage `json:"requestPayload"`
}

func signedRequest(ctx context.Context, client *http.Client, cfg Config, method, path string, body []byte) (*http.Response, error) {
	if body == nil {
		body = []byte{}
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := randomHexString(16)
	bodyHash := sha256.Sum256(body)
	canonical := timestamp + "\n" + nonce + "\n" + method + "\n" + path + "\n" + hex.EncodeToString(bodyHash[:])
	derived := sha256.Sum256([]byte(cfg.Secret))
	mac := hmac.New(sha256.New, []byte(hex.EncodeToString(derived[:])))
	_, _ = mac.Write([]byte(canonical))
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(cfg.ControlPlane, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Nexora-Node", cfg.NodeID)
	req.Header.Set("X-Nexora-Timestamp", timestamp)
	req.Header.Set("X-Nexora-Nonce", nonce)
	req.Header.Set("X-Nexora-Signature", hex.EncodeToString(mac.Sum(nil)))
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
	}
	return client.Do(req)
}

func sendHeartbeat(ctx context.Context, client *http.Client, cfg Config, sample telemetry) error {
	body, err := json.Marshal(sample)
	if err != nil {
		return err
	}
	resp, err := signedRequest(ctx, client, cfg, http.MethodPost, "/v1/agent/heartbeat", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("control plane returned %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}

func collectDatabaseUsage(ctx context.Context) ([]databaseUsageMeasurement, error) {
	requestBody, err := json.Marshal(map[string]string{"operation": "DATABASE_USAGE"})
	if err != nil {
		return nil, err
	}

	command := exec.CommandContext(ctx, "sudo", "-n", "/usr/local/libexec/nexora-provision")
	command.Stdin = bytes.NewReader(requestBody)

	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("provisioning helper could not collect database usage")
	}
	if len(output) == 0 || len(output) > 64*1024 {
		return nil, fmt.Errorf("database usage response exceeded its size limit")
	}

	var result struct {
		Databases []struct {
			Name      string `json:"name"`
			UsedBytes uint64 `json:"usedBytes"`
		} `json:"databases"`
	}

	decoder := json.NewDecoder(io.LimitReader(bytes.NewReader(output), 64*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("provisioning helper returned invalid database usage data")
	}
	if result.Databases == nil {
		return nil, fmt.Errorf("provisioning helper omitted the database usage array")
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("provisioning helper returned unexpected trailing data")
	}
	if len(result.Databases) > 100 {
		return nil, fmt.Errorf("database usage response exceeded the database limit")
	}

	collectedAt := time.Now().UTC().Format(time.RFC3339)
	measurements := make([]databaseUsageMeasurement, 0, len(result.Databases))
	seen := make(map[string]bool, len(result.Databases))

	for _, database := range result.Databases {
		name := database.Name
		if len(name) < 2 || len(name) > 64 ||
			name[0] < 'a' || name[0] > 'z' || seen[name] {
			return nil, fmt.Errorf("provisioning helper returned an invalid database name")
		}
		for _, char := range name[1:] {
			if !((char >= 'a' && char <= 'z') ||
				(char >= '0' && char <= '9') || char == '_') {
				return nil, fmt.Errorf("provisioning helper returned an invalid database name")
			}
		}

		seen[name] = true
		measurements = append(measurements, databaseUsageMeasurement{
			Name: name, UsedBytes: database.UsedBytes, CollectedAt: collectedAt,
		})
	}
	return measurements, nil
}

func processNextJob(ctx context.Context, client *http.Client, cfg Config) error {
	resp, err := signedRequest(ctx, client, cfg, http.MethodGet, "/v1/agent/jobs/next", nil)
	if err != nil {
		return err
	}
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if readErr != nil {
		return readErr
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("job poll returned %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	var envelope struct {
		Job *provisionJob `json:"job"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("invalid job response: %w", err)
	}
	if envelope.Job == nil {
		return nil
	}

	job := envelope.Job
	success := false
	errorCode := ""
	errorMessage := ""
	var resultPayload json.RawMessage
	if job.Operation == "CREATE_DATABASE" {
		var payload struct {
			DatabaseName string `json:"databaseName"`
		}
		if len(job.RequestPayload) == 0 || json.Unmarshal(job.RequestPayload, &payload) != nil || payload.DatabaseName == "" {
			errorCode = "INVALID_JOB_PAYLOAD"
			errorMessage = "The database job payload is invalid"
		} else {
			encoded, _ := json.Marshal(map[string]string{"operation": "CREATE_DATABASE", "username": job.Account.Username, "databaseName": payload.DatabaseName})
			command := exec.CommandContext(ctx, "sudo", "-n", "/usr/local/libexec/nexora-provision")
			command.Stdin = bytes.NewReader(encoded)
			output, commandErr := command.CombinedOutput()
			if commandErr == nil {
				success = true
				fmt.Printf("Provisioning job %s (CREATE_DATABASE) completed for account %s\\n", job.ID, job.Account.Username)
			} else {
				errorCode = "DATABASE_PROVISION_FAILED"
				errorMessage = strings.TrimSpace(string(output))
				if errorMessage == "" {
					errorMessage = "The MariaDB database could not be created"
				}
				if len(errorMessage) > 400 {
					errorMessage = errorMessage[:400]
				}
			}
		}
	} else if job.Operation == "CREATE_DATABASE_USER" {
		var payload struct {
			DatabaseName     string   `json:"databaseName"`
			DatabaseUserName string   `json:"databaseUserName"`
			Privileges       []string `json:"privileges"`
		}
		if len(job.RequestPayload) == 0 || json.Unmarshal(job.RequestPayload, &payload) != nil || payload.DatabaseName == "" || payload.DatabaseUserName == "" {
			errorCode = "INVALID_JOB_PAYLOAD"
			errorMessage = "The database-user job payload is invalid"
		} else {
			encoded, _ := json.Marshal(map[string]any{"operation": "CREATE_DATABASE_USER", "username": job.Account.Username, "databaseName": payload.DatabaseName, "databaseUserName": payload.DatabaseUserName, "privileges": payload.Privileges})
			command := exec.CommandContext(ctx, "sudo", "-n", "/usr/local/libexec/nexora-provision")
			command.Stdin = bytes.NewReader(encoded)
			output, commandErr := command.CombinedOutput()
			if commandErr == nil && json.Valid(bytes.TrimSpace(output)) {
				success = true
				resultPayload = append(json.RawMessage(nil), bytes.TrimSpace(output)...)
				fmt.Printf("Provisioning job %s (CREATE_DATABASE_USER) completed for account %s\\n", job.ID, job.Account.Username)
			} else {
				errorCode = "DATABASE_USER_PROVISION_FAILED"
				errorMessage = "The MariaDB database user could not be created"
			}
		}
	} else if job.Operation == "REVOKE_DATABASE_USER" {
		var payload struct {
			DatabaseUserName string `json:"databaseUserName"`
			DatabaseName     string `json:"databaseName"`
		}
		if len(job.RequestPayload) == 0 || json.Unmarshal(job.RequestPayload, &payload) != nil || payload.DatabaseUserName == "" || payload.DatabaseName == "" {
			errorCode = "INVALID_JOB_PAYLOAD"
			errorMessage = "The database-user revocation payload is invalid"
		} else {
			encoded, _ := json.Marshal(map[string]string{"operation": "REVOKE_DATABASE_USER", "username": job.Account.Username, "databaseUserName": payload.DatabaseUserName, "databaseName": payload.DatabaseName})
			command := exec.CommandContext(ctx, "sudo", "-n", "/usr/local/libexec/nexora-provision")
			command.Stdin = bytes.NewReader(encoded)
			_, commandErr := command.CombinedOutput()
			if commandErr == nil {
				success = true
			} else {
				errorCode = "DATABASE_USER_REVOKE_FAILED"
				errorMessage = "The MariaDB database user could not be revoked"
			}
		}
	} else if job.Operation == "DELETE_DATABASE" {
		var payload struct {
			DatabaseName      string   `json:"databaseName"`
			DatabaseUserNames []string `json:"databaseUserNames"`
		}
		if len(job.RequestPayload) == 0 || json.Unmarshal(job.RequestPayload, &payload) != nil ||
			payload.DatabaseName == "" || len(payload.DatabaseUserNames) > 100 {
			errorCode = "INVALID_JOB_PAYLOAD"
			errorMessage = "The database deletion payload is invalid"
		} else {
			encoded, _ := json.Marshal(map[string]any{
				"operation": "DELETE_DATABASE", "username": job.Account.Username,
				"databaseName": payload.DatabaseName, "databaseUserNames": payload.DatabaseUserNames,
			})
			command := exec.CommandContext(ctx, "sudo", "-n", "/usr/local/libexec/nexora-provision")
			command.Stdin = bytes.NewReader(encoded)
			output, commandErr := command.CombinedOutput()
			if commandErr == nil {
				success = true
			} else {
				errorCode = "DATABASE_DELETE_FAILED"
				errorMessage = strings.TrimSpace(string(output))
				if errorMessage == "" {
					errorMessage = "The MariaDB database could not be deleted"
				}
				if len(errorMessage) > 400 {
					errorMessage = errorMessage[:400]
				}
			}
		}
	} else if job.Operation == "FILE_MANAGER" {
		var payload map[string]any
		if len(job.RequestPayload) == 0 || json.Unmarshal(job.RequestPayload, &payload) != nil {
			errorCode = "INVALID_JOB_PAYLOAD"
			errorMessage = "The file manager job payload is invalid"
		} else {
			payload["operation"] = "FILE_MANAGER"
			payload["username"] = job.Account.Username
			encoded, _ := json.Marshal(payload)
			command := exec.CommandContext(ctx, "sudo", "-n", "/usr/local/libexec/nexora-provision")
			command.Stdin = bytes.NewReader(encoded)
			output, commandErr := command.CombinedOutput()
			if commandErr == nil && json.Valid(bytes.TrimSpace(output)) {
				success = true
				resultPayload = append(json.RawMessage(nil), bytes.TrimSpace(output)...)
			} else {
				errorCode = "FILE_MANAGER_FAILED"
				errorMessage = strings.TrimSpace(string(output))
				if commandErr == nil {
					errorMessage = "The file manager returned an invalid result"
				}
				if errorMessage == "" {
					errorMessage = "The restricted file manager operation failed"
				}
				if len(errorMessage) > 400 {
					errorMessage = errorMessage[:400]
				}
			}
		}
	} else if job.Operation != "CREATE_HOSTING_ACCOUNT" && job.Operation != "ADD_DOMAIN" {
		errorCode = "UNSUPPORTED_OPERATION"
		errorMessage = "This agent version does not support the requested operation"
	} else {
		payload := map[string]string{"operation": job.Operation, "username": job.Account.Username}
		if job.Operation == "ADD_DOMAIN" {
			if job.Account.Domain == "" || job.Account.DocumentRoot == "" {
				errorCode = "INVALID_JOB_PAYLOAD"
				errorMessage = "The domain job is missing its domain name or document root"
			} else {
				payload["domain"] = job.Account.Domain
				payload["documentRoot"] = job.Account.DocumentRoot
			}
		}
		if errorCode == "" {
			encoded, _ := json.Marshal(payload)
			command := exec.CommandContext(ctx, "sudo", "-n", "/usr/local/libexec/nexora-provision")
			command.Stdin = bytes.NewReader(encoded)
			output, commandErr := command.CombinedOutput()
			if commandErr == nil {
				success = true
				fmt.Printf("Provisioning job %s (%s) completed for account %s\\n", job.ID, job.Operation, job.Account.Username)
			} else {
				errorCode = "PROVISIONER_FAILED"
				errorMessage = strings.TrimSpace(string(output))
				if errorMessage == "" {
					errorMessage = "The restricted Linux provisioning helper failed"
				}
				if len(errorMessage) > 400 {
					errorMessage = errorMessage[:400]
				}
			}
		}
	}
	result, _ := json.Marshal(map[string]any{
		"success":      success,
		"errorCode":    errorCode,
		"errorMessage": errorMessage,
		"result":       resultPayload,
	})
	resultPath := "/v1/agent/jobs/" + url.PathEscape(job.ID) + "/result"
	resultResp, err := signedRequest(ctx, client, cfg, http.MethodPost, resultPath, result)
	if err != nil {
		return err
	}
	defer resultResp.Body.Close()
	if resultResp.StatusCode != http.StatusOK {
		resultBody, _ := io.ReadAll(io.LimitReader(resultResp.Body, 4096))
		return fmt.Errorf("job result was rejected: %s: %s", resultResp.Status, strings.TrimSpace(string(resultBody)))
	}
	return nil
}

func randomHexString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("secure random source unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}
