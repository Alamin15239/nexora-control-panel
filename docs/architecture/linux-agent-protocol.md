# Linux agent protocol design

## Trust boundary

The agent initiates outbound connections to the control plane. The control plane must never open an inbound management port on a customer node. Each node receives a unique certificate from a Nexora-controlled CA during an authenticated enrollment flow.

## Enrollment (not implemented)

1. An administrator creates a one-time enrollment token scoped to one organization and one pending node.
2. The token is displayed once, stored hashed server-side, and expires quickly.
3. The node generates its private key locally; the private key never leaves the node.
4. The node submits a certificate-signing request over HTTPS using the one-time token.
5. The control plane validates token scope, expiry and one-time use, then issues a short-lived client certificate.
6. The token is invalidated and the issued certificate is associated with the organization and node record.
7. Administrators can revoke the node certificate immediately.

Do not accept a caller-supplied organization ID as proof of tenant ownership. Tenant identity must be derived from the verified certificate record.

## Agent request requirements

- TLS 1.3 with mutual certificate authentication.
- Certificate identity maps to exactly one node and organization.
- Every request has a timestamp, unique request ID and bounded body size.
- Reject stale timestamps and replayed request IDs.
- Rate-limit per node and organization.
- Return only the minimum data required by the authenticated node.
- Redact credentials and sensitive values from logs.

## Operation envelope (future mutating operations)

A job must be an explicit typed operation, never a shell command. The signed envelope must include:

- immutable job ID and idempotency key;
- node ID and organization scope;
- allowlisted operation name and validated structured arguments;
- issued-at and expires-at timestamps;
- nonce and schema version;
- signature verified against a pinned Nexora control-plane signing key.

The agent independently checks node scope, expiry, nonce, signature, operation allowlist and argument schema. Unknown operation names fail closed. Jobs have strict execution time, output and resource limits. Mutating operations remain disabled until audit logging, replay protection, idempotency and rollback behavior are implemented and tested.

## Initial telemetry scope

The first network-enabled agent release should be read-only: agent version, OS/kernel metadata, CPU and memory totals/usage, filesystem capacity, service health and last-seen time. Do not collect customer file contents, process command lines, environment variables, passwords or unrelated user data.

## Implementation status

This document is a design contract, not a claim that enrollment, mTLS transport, telemetry or remote operations are implemented. The current agent only validates local configuration and certificate files.
