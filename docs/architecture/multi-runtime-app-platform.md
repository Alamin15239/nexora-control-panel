# Multi-runtime application hosting architecture

Status: proposed architecture only. This document does not enable customer deployments or change production infrastructure.

## Goal

Nexora must host applications independently of framework or language. Cloudflare remains the public edge and control plane; isolated Linux compute nodes provide general-purpose execution. Cloudflare Workers are not a universal Linux runtime.

Customer code must never execute inside the Nexora API Worker, monitoring agent, privileged provisioner, or host operating-system namespace.

## Target architecture

1. Control plane: Cloudflare Workers + D1 for organizations, projects, deployments, domains, quotas, audit events and desired state. Use Queues/Workflows for idempotent build, publish, health-check and rollback orchestration. KV is cache only; R2 is private object storage.
2. Build plane: ephemeral isolated builders. GitHub OIDC validates repository, workflow and immutable commit identity. Builds run in disposable sandboxes or microVMs with CPU, memory, disk, process, time and network-egress limits. Produce immutable OCI images or static artifacts with digest, SBOM and provenance. Never run customer builds on the API Worker, privileged agent or production application node.
3. Artifact plane: retain the private R2 staging bucket and one-time upload capability. Validate archive size, digest, path traversal, symlinks, file types and metadata. Promote only verified artifacts to private runtime storage. Preserve active and rollback artifacts; garbage-collect only terminal, unreferenced artifacts after retention.
4. Compute plane: a separate Linux application-node pool using an OCI-compatible runtime such as containerd. Workloads run non-root with read-only root filesystems where possible, dropped capabilities, seccomp, AppArmor, cgroup v2 limits, PID limits, filesystem quotas and explicit network policy. Use microVM or equivalent stronger isolation for mutually untrusted tenants and build execution. Ordinary containers alone are not a complete security boundary.
5. Node receiver: accept only signed, short-lived, replay-resistant deployment instructions. Verify signature, audience, expiry, nonce, tenant/project/deployment binding, artifact digest and allowed operation. Never accept arbitrary shell commands, host paths, systemd units, privileged flags or Docker socket access.
6. Edge and ingress: Cloudflare DNS, proxy, TLS, WAF and rate limiting provide public ingress. A controlled reverse-proxy tier routes verified hostnames to workloads. Customer containers never bind directly to public host ports. Keep management endpoints private and origin ingress restricted to trusted edge paths.
7. Data services: support external or managed PostgreSQL first. Add MySQL/MariaDB and Redis only after tenant isolation, quotas, backup, restore and monitoring exist. Encrypt credentials at rest and inject them at runtime; never bake secrets into images or logs. Persistent volumes must be declared, tenant-scoped, quota-controlled and backed up.
8. Operations: health checks, logs, metrics, usage metering, alerts, audit trails, immutable releases, atomic traffic switching and automatic rollback. Independently manage web processes, background workers, scheduled jobs, databases and persistent storage.

## Runtime support matrix

| Workload | Examples | Execution model |
|---|---|---|
| Static | HTML/CSS/JS, Vite, React SPA, Vue, Angular, Svelte export | Immutable static files on edge/static origin |
| JavaScript server | Node.js, Express, Fastify, NestJS, Next.js SSR, Nuxt, Remix, SvelteKit | OCI image or managed Node profile |
| PHP | Laravel, Symfony, WordPress, Drupal | PHP-FPM + web server in isolated workload |
| Python | Django, Flask, FastAPI, Starlette | WSGI/ASGI process in isolated workload |
| Go | Go HTTP services and binaries | Reproducible build + minimal runtime image |
| Java | Spring Boot, Quarkus, Micronaut | OCI image/JRE profile with memory-aware limits |
| .NET | ASP.NET Core | OCI image/runtime profile |
| Ruby | Rails, Sinatra | Ruby/Bundler profile |
| Custom containers | Dockerfile; constrained Compose | OCI image; no privileged mode, host mounts or host networking |

This is the target matrix, not a claim that these runtimes are implemented today. Runtime availability must be explicit per node pool and plan. Unsupported projects must fail with a clear explanation, never silently deploy as static content.

## Versioned deployment contract

Every project must resolve to a validated deployment specification containing source repository, immutable commit SHA, trusted workflow identity, build method, build context, build command, output directory, runtime profile, start command, listening port, health-check policy, CPU/memory/process/disk limits, secret references, persistent-volume declarations, internal ports, egress policy, domains and routing policy. User-provided values are data, never shell fragments.

## Deployment state machine

QUEUED -> AUTHORIZED -> BUILDING -> ARTIFACT_UPLOADED -> VALIDATING -> READY_TO_PUBLISH -> PUBLISHING -> HEALTH_CHECKING -> SUCCEEDED

Error paths: FAILED, CANCELLED and ROLLED_BACK. Transitions must be conditional and idempotent. Only the publisher may activate a validated release. Failed health checks leave the previous release serving traffic.

## Security invariants

- No customer build or runtime code in Workers, the Nexora agent, provisioner or host namespace.
- No privileged Docker socket, host namespace mount, shared writable tenant filesystem or arbitrary root execution.
- No untrusted Dockerfile execution on the production application node.
- No public artifact bucket or long-lived upload capability.
- No secrets in source archives, image layers, logs, telemetry or browser code.
- No deployment without repository/workflow identity, artifact digest verification and signed authorization.
- Enforce tenant isolation and object-level authorization on every API and node operation.

## Rollout and acceptance gates

### Phase 0 — Inventory and contracts
- Inventory current API, D1 schema, R2 endpoints, GitHub App/OIDC code, Linux agent, IPC daemon, provisioner, Nginx and legacy hosting behavior.
- Separate legacy PHP/shared-hosting operations from the new application-container compute plane.
- Define workload schemas, node enrollment, trust roots, quotas and failure semantics. Customer publishing stays disabled.

### Phase 1 — Control-plane contracts
- Add versioned runtime profiles and deployment specifications.
- Add node-pool, workload, release, health-check and usage records with reviewed D1 migrations.
- Add tenant-isolation and authorization tests. Keep execution disabled.

### Phase 2 — Isolated build service
- Implement strict GitHub OIDC validation and trusted-workflow pinning.
- Run ephemeral isolated builds with resource and network limits.
- Generate SBOM/provenance and immutable artifacts.
- Test malicious archives, Dockerfile abuse and build escape cases.

### Phase 3 — Application nodes
- Provision a dedicated non-production node pool, separate from the current control-plane VM and legacy hosting agent.
- Implement signed node commands, workload lifecycle, ingress, quotas and runtime secret injection.
- Prove tenant isolation, host escape resistance, resource-exhaustion controls and node recovery.

### Phase 4 — Atomic publisher
- Implement immutable releases, atomic route switching, health checks and rollback.
- Test interrupted deployment, corrupted artifacts, unavailable nodes, unhealthy apps, duplicate events and rollback failures.

### Phase 5 — Runtime profiles and services
- Deliver static and Node.js first; then PHP, Python and Go; then Java, .NET, Ruby and constrained custom containers.
- Add databases, persistent volumes, backup/restore, workers and cron only with independent security and recovery tests.

### Phase 6 — Controlled pilot
- Enable only after all prior gates, runbooks, alerts, incident response, backups, restore drills, usage enforcement and support processes are ready.
- Start with an allowlisted pilot and expand only against measured capacity.

## Per-node builder identity and usage report authentication

Builder nodes use independent Ed25519 key pairs. A node generates its private key locally; only its 32-byte raw public key (lowercase/uppercase hex accepted, stored lowercase) is registered with the control plane. The private key must remain on that node, be readable only by the dedicated builder service account, and must never be sent to the API or committed to source control.

An operator provisions a pending `application_nodes` row in a `ready` node pool with a one-time enrollment token hash in `enrollment_key_hash`. Generate a 32-byte random token (64 hex characters), store only its SHA-256 hex digest, and deliver the raw token to the node through a protected provisioning channel. The node submits `nodeIdentity`, `enrollmentToken`, `publicKey` (64 hex characters), and `agentVersion` to `POST /internal/v1/application-nodes/enroll`. The API hashes the token, atomically consumes it once, and only enrolls a pending node whose pool is ready. A successful enrollment moves the node to `online`; the raw enrollment token is never stored or returned by the API.

Usage reports are signed with the node's Ed25519 private key. Required headers are `x-nexora-node-identity`, `x-nexora-node-timestamp` (Unix seconds), `x-nexora-node-nonce` (32–128 hex characters), and `x-nexora-node-signature` (128 hex characters). The signature covers the UTF-8 bytes of `timestamp + "." + nonce + "." + rawBody`. Reports older than five minutes, invalid signatures, unknown/offline/revoked nodes, and nodes whose pools are not ready are rejected. A per-node nonce table prevents replay; duplicate deployment reports remain idempotent and do not increment usage twice. Usage events record the reporting node ID.

Node revocation is immediate at the database authorization boundary: set `application_nodes.status = 'revoked'`; subsequent signatures are rejected. Re-enrollment requires a newly provisioned pending node record and a fresh one-time token. Node public-key replacement is not accepted through the enrollment endpoint. Expired nonce rows may be pruned after their `expires_at` timestamp; they are retained long enough to prevent replay within the accepted clock-skew window.

This protocol authenticates a node but does not itself assign build jobs to nodes. A future dispatch/assignment layer must bind each job to a specific node before any builder is trusted with customer source. This endpoint records metering only; it does not authorize a build, alter deployment status, publish artifacts, or enforce quota at dispatch. Customer execution remains disabled.

## Monthly build-minute accounting

Hosting plans carry an explicit monthly application build-minute allowance (default 300 minutes; administrators may configure 0–100,000 minutes). The period is the UTC calendar month. Usage is stored as integer build seconds to avoid rounding each short build upward; API responses expose both seconds and fractional minutes.

The control plane now has a tenant-scoped usage-period aggregate and an immutable per-deployment usage-event ledger. The ledger enforces one event per project/deployment, validates that the project, organization, deployment, and period agree, and restricts event source to the future isolated builder. The project usage read endpoint reports the current UTC period and allowance.

**Important implementation boundary:** the isolated builder does not yet exist, so no trusted metering writer is connected. The endpoint therefore reports `meteringStatus: not_connected`, and the control plane does not claim that usage is being measured. Build dispatch quota enforcement remains disabled until a signed, authenticated builder can submit idempotent completion records and the platform has tested retry, timeout, partial-build, and duplicate-delivery behavior. Customer builds remain disabled.

## Hosting-plan runtime ceilings

The control plane now stores application CPU (millicores), memory (MiB), storage (MiB) and process ceilings on each hosting plan. Project runtime settings are checked against the plan attached to the project's hosting account. Effective application storage is the lower of the app storage ceiling and the account's existing disk quota. The API exposes the effective limits to the dashboard and rejects settings that exceed them.

These are admission-control limits for configuration metadata. They do not reserve physical capacity or enforce cgroups at runtime. Runtime execution remains disabled until the isolated compute plane can enforce the same limits and report measured usage.

## Current constraints

- The API Worker, D1 and private R2 bucket are a control-plane foundation, not a general-purpose application runtime.
- The current Ubuntu VirtualBox VM is a development/test node, not a production multi-tenant compute cluster.
- The Linux agent and provisioner implement restricted legacy hosting operations; they are not a container orchestrator and must never execute customer build commands.
- The GitHub deployment pipeline is incomplete. Customer publishing remains disabled until OIDC, isolated build, secure receiver, artifact validation, atomic publication, health checks and rollback are implemented and tested.
- A single static output directory is not appropriate for all applications.

## Definition of ready

A workload class is ready only when its build profile, runtime image, isolation policy, resource limits, ingress, secret injection, logs, health checks, rollback, backups (where stateful), metering and automated security tests are implemented and documented. A runtime appearing in the dashboard is not evidence that it is production-ready.