# Nexora Linux Agent

Restricted Linux node agent for Nexora Control. Version 0.3.0 adds one-time enrollment and authenticated, read-only telemetry.

## Security model

- Enrollment token is one-time and expires after 15 minutes.
- The control plane stores only a SHA-256 hash of the per-node secret; the secret is returned once and stored locally with mode 0600.
- Heartbeats use HMAC-SHA256 over timestamp, nonce, HTTP method, path, and body hash.
- Requests outside the five-minute clock window and replayed nonces are rejected.
- The agent validates HTTPS URLs and uses the platform TLS trust store.
- The agent only reads Linux telemetry (/proc and filesystem statistics). It does not execute provisioning jobs, shell commands, or customer code.

## Commands

```sh
nexora-agent version
nexora-agent enroll --api https://YOUR-NEXORA-API.workers.dev --server-id YOUR_SERVER_UUID --token-stdin
nexora-agent run --config /etc/nexora/agent.json --interval 60s
nexora-agent validate-config --config /etc/nexora/agent.json
```

For enrollment, paste the one-time token at the prompt; it is read from standard input rather than a command-line argument. Keep the config file private. The enrollment command writes it with owner-only permissions.

## Build and test

```sh
go test ./...
go vet ./...
go build -trimpath -o dist/nexora-agent ./cmd/nexora-agent
```

GitHub Actions builds Linux amd64 and arm64 binaries and uploads them as a workflow artifact.

## Current limitations

The first agent release supports identity and monitoring only. Hosting account, database, DNS, SSL, email, backup and other provisioning operations remain disabled until narrowly scoped privileged helpers and signed job envelopes are independently implemented and audited. Do not run this agent as root for routine monitoring.
