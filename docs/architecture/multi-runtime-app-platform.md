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

Nodes send signed heartbeats to `POST /internal/v1/application-nodes/heartbeat` using the same identity, timestamp, nonce and signature headers; the signed JSON body currently permits only `agentVersion`. Heartbeats update `last_heartbeat_at` and `last_signature_at`; draining nodes may continue reporting while their pool remains ready. The endpoint cannot change a node's lifecycle status or pool assignment.

Node revocation is immediate at the database authorization boundary: set `application_nodes.status = 'revoked'`; subsequent signatures are rejected. Re-enrollment requires a newly provisioned pending node record and a fresh one-time token. Node public-key replacement is not accepted through the enrollment endpoint. Expired nonce rows may be pruned after their `expires_at` timestamp; they are retained long enough to prevent replay within the accepted clock-skew window.

This protocol authenticates a node but does not itself assign build jobs to nodes. A future dispatch/assignment layer must bind each job to a specific node before any builder is trusted with customer source. This endpoint records metering only; it does not authorize a build, alter deployment status, publish artifacts, or enforce quota at dispatch. Customer execution remains disabled.

## Node operator controls, revocation, and signing-key rotation

Node lifecycle administration is separate from customer workspace roles. The operator endpoints require the dedicated `APPLICATION_NODE_OPERATOR_TOKEN` Worker secret (minimum 32 characters); they fail closed with HTTP 503 when it is not configured and reject missing or invalid bearer credentials with HTTP 401. Do not reuse a customer session token or expose this credential to a node.

- Revoke: `POST /internal/v1/operator/application-nodes/:nodeId/revoke`. Revocation is terminal, invalidates the enrollment-token hash, clears any outstanding rotation challenge, and records an optional bounded reason. The database trigger prevents a revoked node from being reactivated or having its signing key/enrollment hash changed. A replacement must be provisioned as a new node record with a fresh one-time enrollment token.
- Begin key rotation: `POST /internal/v1/operator/application-nodes/:nodeId/key-rotation-challenge`. The operator receives a one-time random 256-bit challenge; only its SHA-256 digest and a ten-minute expiry are stored. Deliver the challenge to the node through a protected operator channel.
- Complete key rotation: the node posts `newPublicKey` and `challenge` to `POST /internal/v1/application-nodes/rotate-key`, signed over the exact request body with its current private key and the normal timestamp/nonce headers. The old key proves possession; the challenge is single-use and expires after ten minutes. The D1 batch changes the active key and records old/new key history atomically. Key-history public keys are immutable and retirement can be recorded only once.

The operator credential is not configured by this change. Configure it separately as a Cloudflare Worker secret before using these endpoints; do not put it in source control, D1, logs, or customer-facing settings. No node is revoked or rotated as part of this code change. Node roles now default to `runtime`; a trusted operator must explicitly assign `builder`, and the pool must independently be classified `rootless` or `microvm` before the usage-report gate admits it. These labels are admission controls, not evidence of actual host isolation.

## Static-publisher admission on a non-isolated host

The dedicated static publisher is a separate capability from general application execution. The initial single-node static host may use a pool with `runtime_engine='static'` and `isolation_level='untrusted'`; this does not assert rootless or microVM isolation. The operator enrollment route admits this exact combination, while the general runtime-pool assignment, desired-state API and builder usage path continue to require `rootless` or `microvm`.

A static-publisher node can authenticate for static release polling, artifact delivery, archive validation, activation, health reporting and same-node rollback only. Every release lookup in that path is constrained to an enabled `static-v1` profile with `build_method='static'`. A static pool cannot be assigned as a general application runtime pool, and its node cannot report builder usage. Do not run customer build commands, OCI workloads, server-side application processes or arbitrary customer code on this host. Static artifacts must be built in a separately trusted workflow and published as immutable files.

The static pool should remain `provisioning` until host installation, local trust configuration, account/domain bindings and preflight have been reviewed. Mark it `ready` only when the operator is ready to issue the one-time node enrollment. The node's runtime role is a shared identity schema value; the static runtime-engine classification and endpoint-specific static profile checks are the actual capability boundary.

## Monthly build-minute accounting

Hosting plans carry an explicit monthly application build-minute allowance (default 300 minutes; administrators may configure 0–100,000 minutes). The period is the UTC calendar month. Usage is stored as integer build seconds to avoid rounding each short build upward; API responses expose both seconds and fractional minutes.

The control plane now has a tenant-scoped usage-period aggregate and an immutable per-deployment usage-event ledger. The ledger enforces one event per project/deployment, validates that the project, organization, deployment, and period agree, and restricts event source to the future isolated builder. The project usage read endpoint reports the current UTC period and allowance.

**Important implementation boundary:** the isolated builder does not yet exist, so no trusted metering writer is connected. The endpoint therefore reports `meteringStatus: not_connected`, and the control plane does not claim that usage is being measured. Build dispatch quota enforcement remains disabled until a signed, authenticated builder can submit idempotent completion records and the platform has tested retry, timeout, partial-build, and duplicate-delivery behavior. Customer builds remain disabled.

## Hosting-plan runtime ceilings

The control plane now stores application CPU (millicores), memory (MiB), storage (MiB) and process ceilings on each hosting plan. Project runtime settings are checked against the plan attached to the project's hosting account. Effective application storage is the lower of the app storage ceiling and the account's existing disk quota. The API exposes the effective limits to the dashboard and rejects settings that exceed them.

These are admission-control limits for configuration metadata. They do not reserve physical capacity or enforce cgroups at runtime. Runtime execution remains disabled until the isolated compute plane can enforce the same limits and report measured usage.

## Atomic release activation primitive

The Linux agent repository now contains a standalone `internal/releasepublisher` filesystem primitive. It accepts only operator-prepared private staging directories, moves a release into a non-overwritable release store, and atomically switches a `current` symlink. The same activation operation can point back to a previous immutable release for rollback. It rejects unsafe identifiers, symlinked release directories, group/world-writable staging and release directories, and a non-symlink active path. Directory metadata is synced after the rename operations. If the atomic activation step fails after the staging rename, the immutable release remains stored but inactive so an operator can inspect or retry activation.

The `releasepublisher` package itself remains a filesystem-only primitive: it does not download from R2, authenticate an envelope, authorize a project, verify a digest, or run a health check. It is now composed by the separate `artifactdelivery` package after node-authenticated download and signed-envelope/archive validation. It is not connected to the legacy privileged provisioner or a long-running customer runtime service. Its parent directories must be operator-owned and inaccessible to untrusted local users. Customer execution remains disabled.

## Current constraints

- The API Worker, D1 and private R2 bucket are a control-plane foundation, not a general-purpose application runtime.
- The current Ubuntu VirtualBox VM is a development/test node, not a production multi-tenant compute cluster.
- The Linux agent and provisioner implement restricted legacy hosting operations; they are not a container orchestrator and must never execute customer build commands.
- The GitHub deployment pipeline is incomplete. Customer publishing remains disabled until OIDC, isolated build, secure receiver, artifact validation, atomic publication, health checks and rollback are implemented and tested.
- A single static output directory is not appropriate for all applications.

## Definition of ready

A workload class is ready only when its build profile, runtime image, isolation policy, resource limits, ingress, secret injection, logs, health checks, rollback, backups (where stateful), metering and automated security tests are implemented and documented. A runtime appearing in the dashboard is not evidence that it is production-ready.

## Builder node isolation classification

Node pools default to `isolation_level=untrusted`. A pool must be explicitly classified as `rootless` or `microvm` before a builder node from that pool can submit build-usage reports. Nodes carry a control-plane-assigned `node_role` (`builder` or `runtime`); runtime nodes cannot report builder usage. The API checks both attributes before accepting a report, and a D1 insert trigger independently enforces the same rule. This classification is an admission gate, not proof that the host is actually hardened: pool operators must separately validate rootless isolation or microVM boundaries before changing the classification. Existing pools remain untrusted by default, and customer execution stays disabled.


## Offline verified artifact receiver primitive

The Linux agent now contains a verified receiver used by `internal/artifactdelivery`. It verifies the RS256 deployment envelope against independently supplied deployment identity, checks exact artifact byte count and SHA-256, validates the gzip TAR before extraction, consumes the envelope JTI using a private filesystem replay guard, creates a private staging directory, extracts the archive, and invokes atomic release activation. The receiver can send a signed archive-validation report through its callback before extraction/publication proceeds. Tests cover successful publication, cross-project identity mismatch, digest tampering, replay rejection, and local activation.

The receiver package is not a network listener or daemon. The `artifactdelivery` composition currently calls the control-plane artifact client and receiver as a library; it still needs a trusted long-running node service to supply operator-provisioned node credentials, trusted RSA public keys, independently resolved deployment assignment, lifecycle/retry handling, and health-check coordination. Its base directory and parents must be operator-owned and inaccessible to untrusted local users. A failed publish can leave an immutable release stored but inactive if final activation fails; the caller must reconcile before retrying. Customer execution remains disabled.


## Authenticated runtime artifact delivery primitives

The control plane exposes internal `POST /internal/v1/application-nodes/artifact`, `POST /internal/v1/application-nodes/releases/validated`, `POST /internal/v1/application-nodes/releases/activated`, and `POST /internal/v1/application-nodes/releases/health-check` routes. Ed25519 request proofs bind node identity, timestamp, one-time nonce, HTTP method, exact path, and SHA-256 of the raw body. Artifact delivery accepts only online, non-revoked runtime nodes in ready `rootless` or `microvm` pools and only releases assigned to that same pool. The artifact route has a validation purpose for `artifact_uploaded`/validation states and a publish purpose for `ready_to_publish`/publishing states. It checks release/deployment digest and size, R2 object size and tenant metadata, signs a short-lived RS256 deployment envelope, and responds with `no-store` and `nosniff`. The validation-report route checks the signed node identity and report digest/size against D1 before recording the archive-validation event and advancing the release to `publishing`. After the receiver atomically switches the local `current` symlink, its activation callback sends a second Ed25519-signed acknowledgement; the API verifies that same runtime node/pool and artifact digest, records `release_files_activated`, and moves `publishing -> health_checking`. Duplicate acknowledgements are idempotent only when the original event details match. The health-check route accepts only an Ed25519-signed report from an online runtime node in the assigned isolated pool, checks the artifact digest and configured health path, and records `health_checking -> succeeded|failed`; the matching GitHub deployment status is finalized in the same D1 batch. A failed report preserves the previous active release reference and returns both the prior deployment ID and the exact node ID that owns it; it does not itself perform filesystem rollback. A rollback coordinator must send the activation request to that previous node, not assume the newly assigned node has the old release files. A separate signed health-check report route accepts only the configured local probe path and a bounded HTTP outcome; it can move `health_checking -> succeeded` or `failed`, record a workload observation, and return the previous active deployment as rollback guidance. This route is a reporting contract—the real runtime supervisor must perform the local probe before it can safely submit a result.

The Linux agent repository now includes:
- `internal/appnodeauth`: canonical Ed25519 request signing and verification.
- `internal/artifactclient`: HTTPS-only artifact download, no redirect forwarding, response size/content-type/cache checks, and SHA-256 verification.
- `internal/artifactreceiver`: signed envelope identity verification, artifact digest/size checks, archive validation, private extraction, durable one-time JTI replay records, and atomic release activation.
- `internal/artifactdelivery`: a composition function that joins the authenticated download and verified local publication primitives.

Synthetic Go tests exercise the download-to-publication flow, replay rejection, invalid envelope rejection, and atomic active-release link. API integration tests exercise runtime identity/pool checks, nonce replay protection, R2 metadata consistency, and fail-closed behavior.

These are code-level primitives and route tests, not a running application-node service or a verified customer deployment path. When a project has an operator-assigned runtime pool and enabled runtime profile, manual GitHub deployment dispatch now creates a tenant-bound `application_releases` row with the selected pool/profile. The GitHub OIDC runner claim advances that release through `queued -> authorized -> building`; accepted R2 artifact upload advances it to `artifact_uploaded`; an enrolled runtime node downloads the artifact for validation, verifies it locally, and submits a signed report that advances it through `validating -> ready_to_publish -> publishing`. The assignment and release-creation steps are covered by metadata/admission tests; node delivery and report endpoints have synthetic integration tests; Go composition has local synthetic tests.

Still missing: a scheduler/dispatch service for assigned runtime nodes, a long-running node daemon that invokes `artifactdelivery`, publish failure reconciliation, runtime process supervision, post-activation health checks, automatic rollback coordination, cgroup/container/microVM enforcement, ingress/domain routing, and production node provisioning. The `health_checking` state means only that the node reported the files active; it must remain pending until a future runtime supervisor starts the configured application and reports a verified health check. The control plane must not mark the deployment `succeeded` based only on the activation acknowledgement.

Runtime profiles remain disabled by default and customer execution remains disabled.


## Operator-controlled project runtime pool assignment

Migration `0028_application_project_node_pool_assignment.sql` adds an optional runtime pool assignment to project settings. D1 insert/update triggers reject assignments unless the target pool is ready, explicitly classified as `rootless` or `microvm`, and contains an enrolled, online, non-revoked runtime node with a signing key. The internal operator API lists eligible pools and assigns a project only when its runtime profile is enabled; it refuses assignment while the project has a starting or healthy workload. The operator token is required, and the response explicitly states that assignment neither enables execution nor allocates capacity.

The assignment workflow is metadata and admission control only; it does not reserve CPU/memory/disk or start workloads. When a project has an enabled runtime profile and valid assignment, the manual GitHub deployment-dispatch path now creates a release row bound to that pool. The OIDC claim, artifact-upload, and signed runtime archive-validation routes advance the release state. No runtime process is started by these transitions.


## Current release lifecycle integration boundary

For a project with an enabled runtime profile and operator-assigned isolated runtime pool, the metadata lifecycle is now connected in the control plane:

`queued -> authorized -> building -> artifact_uploaded -> validating -> ready_to_publish -> publishing -> health_checking`.

The GitHub OIDC exchange advances the application release when the pinned workflow claims the deployment. The upload endpoint stores the verified R2 artifact reference and digest metadata in both the GitHub deployment and application release. The runtime artifact endpoint only serves the release to an online runtime node in its assigned pool. The node downloads over HTTPS with an Ed25519 request proof, verifies the RS256 deployment envelope and artifact digest, validates the archive, consumes the envelope JTI locally, and posts a signed validation report. The receiver then extracts to private staging, writes the publisher-owned release manifest, and atomically switches the release symlink. It sends a second signed activation acknowledgement, moving the control-plane release to `health_checking`.

The publisher writes a private, reserved `.nexora-release.json` manifest containing release ID, artifact SHA-256, byte count, and manifest version. Customer archives cannot provide that path. On retry, the receiver verifies this publisher-owned manifest and the release directory before treating the release as already published; if the release directory was moved but the active symlink switch did not complete, it safely retries the atomic activation without overwriting the release. A reused envelope JTI is still rejected; a retry must obtain a fresh short-lived envelope.

The current implementation has a local loopback-only health-probe primitive and a signed health-result API contract. It still does not launch the application's process or prove that the assigned loopback port belongs to a sandboxed workload. The API health route must only be called by a trusted supervisor after a real local probe; the probe primitive itself does not create or supervise a process. There is also no long-running node daemon, durable work scheduler, automatic retry reconciler, or operator UI for the full lifecycle. Consequently the state `publishing` is not proof that a customer application is live. Do not enable runtime profiles, apply migrations to production, deploy the receiver, or enable customer publishing until the runtime supervisor, failure reporting, health-check/rollback, host isolation, and end-to-end acceptance gates are complete.


## Loopback runtime health probe primitive

The Go agent now contains `internal/runtimehealth`, a bounded health probe that connects only to `127.0.0.1` on an explicitly assigned port and configured absolute path. It disables proxy use, rejects query/fragment/control-character/backslash paths, never follows redirects, caps the response body read, and classifies connection refusal, timeouts, HTTP 4xx/5xx, and redirects. Tests use local loopback HTTP servers and verify that redirects are not followed.

This is a probe primitive only. It does not start a process, select a port, prove that the port belongs to a sandboxed workload, or establish host isolation. A future node supervisor must obtain the port from the trusted workload assignment, apply cgroup/container/microVM limits, start the process inside the isolation boundary, call this probe, and then use the signed health-check report client. The API's `succeeded` state must only be reachable through that trusted supervisor path; no general-purpose customer-accessible health-report endpoint exists.


## Per-release runtime node binding

Migration `0029_application_release_node_assignment.sql` adds `application_releases.assigned_node_id`. A runtime release with a runtime profile cannot be created without an enrolled, online, non-revoked runtime node that belongs to the assigned isolated pool and has an Ed25519 signing key. Manual GitHub deployment dispatch selects one eligible node from the operator-assigned pool and stores that exact node ID with the release. The artifact-download, archive-validation, activation, and health-check routes all require the authenticated node ID to match `assigned_node_id`; knowing a deployment ID or belonging to the same pool is not sufficient. If the assigned node becomes unavailable, delivery fails closed until an explicit rescheduler/reassignment workflow is implemented.


## Rootless OCI supervisor backend foundation

The Linux agent now contains an isolated `internal/ocisupervisor` Podman backend. It refuses to start unless Podman reports `Host.Security.Rootless=true`, accepts only immutable SHA-256 image references from an explicit operator-configured registry allowlist, validates operator-owned release directories, binds the published application port to host loopback only, and applies read-only root filesystem, dropped Linux capabilities, no-new-privileges, non-root container UID, private PID/IPC namespaces, explicit rootless UID mapping to a non-root container user, CPU/memory/PID ceilings, a bounded temporary filesystem, and bounded k8s-file container logs. It never accepts a customer shell command, arbitrary mount list, privileged mode, or host-network mode.

This is a backend primitive with fake-runner tests; it is **not yet connected to the application-node polling loop, workload database reconciliation, domain proxy, health-check lifecycle, secret delivery, persistent writable data volumes, log retention, storage quota enforcement, or production node service**. Rootless Podman networking currently uses `slirp4netns`; outbound egress policy still requires a separate network policy layer. Do not enable customer workloads until those controls and the complete lifecycle are implemented and reviewed.


## Durable runtime supervisor state foundation

The Linux runtime supervisor now has a local metadata-only state store in
`agents/linux-agent/internal/supervisorstate`. It persists workload, release,
container identity, observed state and update timestamps using a versioned JSON
snapshot, owner-only file permissions, a service-private parent directory,
strict schema decoding, bounded file size, atomic replacement, file and
directory fsync, and in-process serialization. It rejects symlinks, unsafe
permissions, unknown fields, malformed identifiers, unsupported states and
trailing JSON data. The store intentionally excludes customer secrets,
environment variables, build commands and payload data.

This is a persistence primitive, not yet the node supervisor service. It is
single-process and is not safe for multiple writers or hostile processes with
the same service UID. The service must own a parent directory with mode 0700
(or stricter), run as a dedicated unprivileged account, and be the sole writer.
Crash recovery, reconciliation against Podman, control-plane polling,
authenticated desired-state ingestion and lifecycle orchestration remain
separate integration gates. No customer workload execution is enabled by this
package.


### Durable runtime reconciliation integration

The Linux runtime controller now composes the existing desired-state reconciliation primitive with the owner-only durable supervisor state store. A caller must authenticate the runtime node, validate its signature and nonce, and verify the exact release/node assignment before constructing a desired-state value and invoking the controller.

The controller performs one lifecycle convergence, re-inspects the backend-owned container, verifies the observed container/workload/release identities, and only then persists the observed metadata snapshot. When a workload is no longer desired and no container remains, its stale metadata entry is deleted. Backend inspection or persistence errors are returned and are not silently treated as success.

This remains a single-process local state foundation. The controller also exposes a fail-closed startup recovery primitive that loads the snapshot, inspects each exact container ID, verifies immutable workload/release ownership, and refreshes observed states. It does not yet wire that recovery call into the running agent's systemd startup path, implement inter-process locking or full container discovery when the snapshot is missing, or authorize customer workload execution. It does not enable customer execution. Runtime execution remains disabled until the full node service, isolation, storage, egress, ingress, secret delivery, recovery, and end-to-end acceptance gates are complete.


### Authenticated desired-state polling contract

Runtime nodes may poll `GET /internal/v1/application-nodes/desired-state` using the established Ed25519 canonical request proof. The proof binds node identity, timestamp, one-time nonce, HTTP method, exact path, and SHA-256 of the empty request body. The API rejects stale proofs, reused nonces, revoked/offline nodes, builder-role nodes, non-ready pools, and pools that are not classified as rootless or microVM isolated.

The query is constrained to workloads whose `node_id` equals the authenticated node and whose active release belongs to the same project and organization, is assigned to that exact node, and is in the successful state. The response is capped at 100 workload records and uses `Cache-Control: no-store`. It contains only workload/release identity, desired replica count, runtime profile metadata, and bounded resource metadata. Build/start commands, arbitrary `spec_json`, environment variables, and secrets are never returned.

The endpoint always returns `executionEnabled: false`, `commandsIncluded: false`, and `secretsIncluded: false`. It is a read-only protocol foundation, not authorization to start customer workloads.

The Linux runtime polling client signs GET requests with the node's Ed25519 key, requires HTTPS except for loopback tests, bounds response size, rejects unknown fields, duplicate workload IDs, invalid release states and out-of-range resource values, and fails closed if the API ever indicates execution or secret/command delivery is enabled. The client does not invoke the OCI supervisor.


## Runtime node service: read-only polling phase

The Linux agent repository now contains a separate `cmd/nexora-runtime-node` binary and `systemd/nexora-runtime-node.service`. It runs as a dedicated unprivileged `nexora-runtime` account, reads an owner-only configuration and Ed25519 key file, performs fail-closed verification of the persisted supervisor snapshot at startup, and polls the authenticated desired-state endpoint. The service rejects any response that advertises execution, command delivery, or secret delivery. It does not call workload convergence and does not start, stop, restart, or publish customer code.

The service is a control-plane polling client only. It is not installed or enabled on the development VM by this change. A real runtime node still requires operator-managed account/key/config provisioning, rootless Podman setup, storage and network policy, service health/rollback integration, and end-to-end acceptance tests.

## Per-workload persistent data directories

The Linux agent now contains `internal/runtimevolume`, which creates stable per-workload directories beneath a private service-owned volume root. It validates workload IDs, ownership, directory type, symlink exclusion, and owner-only permissions. Its removal operation only removes an empty directory; it never recursively deletes customer data. The rootless OCI backend accepts the exact operator-provided persistent-data path and mounts it read/write at `/var/lib/nexora` while keeping the application release mount read-only.

This is **not disk quota enforcement**. A directory and bind mount do not impose a hard byte or inode limit. Filesystem project quotas, XFS/ext4 quota configuration, per-node capacity admission, usage accounting, and quota-exhaustion tests remain mandatory before customer workloads can be enabled. The volume manager is a tested primitive and is not yet called by the node polling service or a production lifecycle reconciler.

## Immutable runtime secret bundles

The Linux agent now contains `internal/runtimesecrets`, a local primitive for materializing a new immutable secret bundle under a private workload directory. It validates identifier and key formats, limits each value to 64 KiB and the aggregate bundle to 256 KiB, writes each value to a mode-0400 file, fsyncs files/directories, and refuses to overwrite an existing bundle ID. The OCI backend validates the directory and file permissions and can bind it read-only at `/run/secrets`. Secret values are not passed through container environment variables or command-line arguments.

This does **not** implement secret retrieval, API authorization, encryption at rest, key management, rotation/revocation, bundle garbage collection, or end-to-end delivery. The materializer must only receive values from a future authenticated and narrowly scoped secret-delivery channel. No secret-delivery API exists in this slice, and the runtime polling contract continues to reject secret delivery. Do not pass customer secrets to this primitive from an untrusted source or enable customer workloads on this basis.
