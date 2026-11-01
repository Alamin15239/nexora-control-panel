# Nexora Linux Agent

The Linux agent is the restricted node-side component for managed hosting servers.

## Current implementation

Version `0.1.0` provides a Go CLI with:

- `nexora-agent version`
- `nexora-agent validate-config --config /path/to/agent.json`
- HTTPS-only control-plane URL validation
- CA PEM parsing and client certificate/private-key pair validation for the future mTLS connection

It does **not** connect to the control plane, collect telemetry, or execute server operations yet. No privileged actions are implemented. This is intentional: the first network-enabled release must establish and verify node identity before exposing even read-only telemetry.

## Build and test

From this directory:

```sh
go test ./...
go build -o dist/nexora-agent ./cmd/nexora-agent
./dist/nexora-agent version
./dist/nexora-agent validate-config --config ./config.example.json
```

The example configuration contains placeholder paths and is not expected to validate until real certificates are provisioned.

## Configuration

See [config.example.json](./config.example.json). Keep private keys outside the repository, owned by root or the dedicated agent service account, with restrictive permissions (normally `0600`). Never commit node credentials.

## Security contract for future releases

- Unique, revocable node identity and mutual TLS.
- Short-lived signed operation envelopes with expiry, nonce/replay protection and idempotency keys.
- Strict allowlist and schema validation for each operation.
- Bounded timeouts, output limits and resource limits.
- No arbitrary shell command endpoint and no customer-controlled root commands.
- Structured audit events; never log credentials or customer file contents.
- Read-only health telemetry before any mutating provisioning feature is enabled.

The agent must run with the least privilege possible. Any privileged helper must be a separate, narrowly scoped component with its own review and audit trail.
