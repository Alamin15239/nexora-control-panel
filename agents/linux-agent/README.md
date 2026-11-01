# Nexora Linux Agent

The Linux agent is the trusted, restricted execution component installed on each managed hosting node.

## Security requirements

- Written in Go and distributed as a signed release.
- Runs under a dedicated service identity wherever possible.
- Privileged helpers are narrowly scoped and separately audited.
- Uses mutual TLS with a unique node identity.
- Accepts only signed, expiring operation envelopes.
- Enforces an allowlist of operation names and strict schemas.
- Implements replay protection, idempotency and bounded execution time.
- Never accepts arbitrary shell commands from the API or customer.
- Emits structured logs without secrets or customer file contents.

## Initial implementation status

This directory documents the agent contract. The executable is not implemented yet. The first agent release will support identity registration and read-only health telemetry before any mutating provisioning operation is enabled.
