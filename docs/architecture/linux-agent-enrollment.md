# Nexora Control — Linux agent enrollment protocol (Phase 1)

## Status

The repository currently provides a **secure enrollment-token primitive and configuration validator**. This document specifies the next integration contract. It is not a claim that certificate issuance or a live agent connection is already deployed.

## Architecture decision

The control-plane API must run on infrastructure that supports:
- TLS termination with client-certificate validation (mTLS), or a trusted private ingress that forwards verified certificate identity;
- durable PostgreSQL access;
- a private CA signer (preferably an external CA such as Smallstep step-ca).

A serverless frontend proxy is not the agent control plane. Do not expose CA private keys in the Next.js application, browser, repository, or ordinary environment logs.

## Enrollment lifecycle

1. An organization OWNER/ADMIN creates a pending server record and requests a short-lived one-time enrollment token.
2. API stores only SHA-256(token), bound to the organization and server, with expiry (recommended 15 minutes).
3. Administrator runs the install/enroll command over SSH. Token is provided through stdin or a protected environment variable and is never printed.
4. Agent creates a private key locally (ECDSA P-256 or RSA 3072), generates a CSR, and sends token + CSR + metadata over verified HTTPS.
5. Control plane atomically consumes the token. Replays, expired tokens, wrong org/server, malformed CSR, and already-consumed tokens are rejected.
6. A configured CA signs the CSR with a short-lived client certificate containing a server identity. The private key never leaves the server.
7. Agent stores key/certificate with root-only permissions and starts as a systemd service.
8. Agent sends heartbeat and telemetry over mTLS. Control plane verifies certificate identity, not a client-provided node ID.

## Required endpoint contract (to implement)

- `POST /v1/servers` — authenticated OWNER/ADMIN; create server metadata.
- `POST /v1/servers/:serverId/enrollment-token` — authenticated OWNER/ADMIN; issue one-time token.
- `POST /v1/agent/enroll` — public HTTPS; token + CSR; atomic consume and CA issuance.
- `POST /v1/agent/heartbeat` — mTLS; server identity derived from validated client certificate.
- `POST /v1/agent/telemetry` — mTLS; validated payload, bounded values, timestamps, replay/idempotency controls.

## Operational safeguards

- Token: 256-bit entropy, hash at rest, single use, short TTL, rate-limited, never logged.
- CSR: validate subject/SAN policy; do not accept arbitrary certificate extensions.
- CA: separate signer service/key; rotation and revocation procedures documented.
- Agent: least privilege; no arbitrary shell command executor; operations must be typed, allowlisted, signed, and auditable.
- Telemetry: reject NaN/infinite/negative/oversized values; timestamp skew bound; rate limit; retention policy.
- Organization isolation: all management reads/writes scoped by the authenticated membership organization.
- Audit: record token issue/consume, server create/update, enrollment success/failure, certificate rotation/revocation.

## Agent config after successful enrollment

The example config is intentionally not a credential. Actual config should reference:
- immutable node/server identifier issued by control plane;
- HTTPS control-plane URL;
- control-plane CA bundle;
- client certificate and private key stored root-only.

Never use `curl | sudo bash` as an installation pattern. Provide a signed package and checksum, inspectable install script, and a systemd unit.
