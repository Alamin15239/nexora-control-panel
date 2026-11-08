# Nexora static deployment execution architecture

## Design decision

Nexora does not run customer build scripts on the Cloudflare Worker, the hosting VM, the Nexora Linux agent, or the privileged provisioning daemon.

The first release uses two separate execution boundaries:

1. **Build boundary — GitHub-hosted Actions runner.** A disposable GitHub-hosted runner checks out one immutable commit, executes the fixed static-site build profile, packages the output, and uploads it with a short-lived, single-deployment capability.
2. **Publication boundary — enrolled Nexora static publisher.** A separate unprivileged service on an explicitly approved isolated runtime node downloads a signed artifact, validates the archive, extracts it into private staging, and atomically activates a versioned static release. It never executes customer code.

This separation is intentional. The term *build worker* must not be interpreted as permission to execute customer code on the existing hosting server.

## Trust boundaries

| Component | Trusted input | Must never do |
|---|---|---|
| Cloudflare API Worker | Authenticated user, GitHub App, signed OIDC claims, D1 state | Execute package scripts, shell commands, or customer source |
| GitHub-hosted runner | One project, one workflow revision, one commit | Receive Nexora server credentials, GitHub App private key, SSH key, or deployment secrets |
| R2 artifact bucket | API-generated object key and bounded upload stream | Accept a customer-selected object key or public artifact URL |
| Static publisher | Exact node assignment, signed deployment envelope, validated archive | Run npm, shell, customer commands, or write outside the target account |
| Hosting account document root | Publisher-created immutable release and activation pointer | Be writable by the build runner or customer-controlled workflow |

The existing nexora-agent and nexora-provisiond are hosting control-plane components. They are not build executors and must not receive arbitrary build commands.

## Required workflow contract

The customer repository contains .github/workflows/nexora-deploy.yml, reviewed and pinned by a platform administrator. The supplied template at docs/templates/nexora-deploy.yml is intentionally limited to npm projects with package-lock.json and a dist/ output directory.

- Trigger only through workflow_dispatch; automatic push deployment is not part of this phase.
- Use GitHub-hosted ubuntu-latest, never self-hosted runners.
- Pin every third-party action to a full immutable commit SHA.
- Grant only contents: read and id-token: write; disable checkout credential persistence.
- Check out the exact SHA supplied by Nexora and compare it to git rev-parse HEAD before executing build scripts.
- Do not pass repository secrets or Nexora credentials to build steps.
- Use the fixed npm ci / npm run build profile; customer-controlled shell commands are not accepted.
- Reject symlinks and special files in the output and cap the compressed archive at 100 MiB.
- Request a GitHub OIDC token only for the Nexora audience, then exchange it for a five-minute, one-time upload capability scoped to the deployment.
- Upload only to the deployment-specific API endpoint. The API chooses the private R2 key and verifies the stream length and SHA-256 digest.

Build scripts are untrusted and may attempt to request the job's OIDC token. Therefore the capability is deliberately limited to one deployment and cannot read artifacts, publish releases, access another project, or access a hosting server. Workflow SHA pinning is a separate administrator approval gate.

## Artifact publication contract

The publication path is:

queued → building → artifact_uploaded → validating → ready_to_publish → publishing → health_checking → succeeded

The authenticated publisher must:

1. Poll only releases assigned to its exact enrolled node identity.
2. Verify the deployment envelope signature and the organization, project, deployment, hosting account, repository ID, commit SHA, and artifact digest.
3. Download the artifact through the node-authenticated API endpoint.
4. Validate the entire gzip/tar archive before filesystem changes; reject traversal, absolute paths, duplicate paths, links, special files, excessive entry counts, and expanded-size violations.
5. Extract into a new private staging directory with normalized permissions.
6. Activate an immutable versioned release through an atomic pointer switch. Failed validation or extraction must leave the active release untouched.
7. Install or validate the deterministic Nginx vhost through the dedicated root broker, which independently verifies the signed deployment envelope. Only after Nginx validation and reload succeed does the publisher send the node-signed activation acknowledgement. A successful activation is not the same as a successful HTTP health check.

Rollback must switch to a previously verified immutable release and must be audited. Retention and deletion must never remove the currently active release.

## Current repository implementation

The repository already contains these building blocks:

- GitHub App installation-token and workflow-dispatch code.
- Administrator-pinned workflow SHA and strict GitHub OIDC signature/claim verification.
- A single-use, expiring upload capability bound to project, deployment, repository, branch, commit, and workflow run.
- Private R2 staging with a generated object key, bounded streaming upload, and SHA-256 verification.
- Application release/node assignment schema and tenant-integrity triggers.
- Go archive validation/extraction, signed deployment-envelope verification, node request authentication, and static release activation packages.
- The nexora-static-publisher binary and restrictive systemd unit.

These components are not proof that a production publisher node is enrolled, online, correctly isolated, or safely mapped to a real hosting account. Runtime profiles are seeded disabled. A customer-facing successful deployment must not be reported until the end-to-end publication and health-check path is enabled and verified.

## Explicit operational gates

Before enabling customer deployments:

- Pin the reviewed workflow revision for each project and verify that the actual workflow content matches the review.
- Provision a separate publisher node or approved isolated node pool; do not repurpose the current Nexora development VM as a multi-tenant executor.
- Enroll its Ed25519 node identity and install the publisher trust public key/configuration with owner-only permissions.
- Verify systemd confinement, service account, writable paths, account directory ownership, and Nginx/static-site serving behavior.
- Confirm the node can retrieve only releases assigned to its exact node ID.
- Exercise valid and malicious archives, interrupted downloads, replayed envelopes, checksum mismatches, failed activation, concurrent deployment attempts, health-check failure, and rollback.
- Verify organization and hosting-account membership isolation through HTTP integration tests.
- Confirm artifact retention and cleanup policies, quotas, rate limits, audit records, and bounded logs.
- Keep automatic push webhooks disabled until signature verification, replay protection, queue idempotency, and end-to-end tests are complete.

**Current safety posture:** building and artifact staging are separate from publication. Do not merge a workflow change into production, enable runtime profiles, enroll the current VM as a publisher, or advertise production deployment availability until these gates pass.

## Health-check and rollback integration status

The health-check API contract and the Go loopback probe/report primitives exist, and the release publisher can atomically activate a previously verified immutable release by release ID. These pieces are not yet wired into one operational lifecycle:

- `nexora-static-publisher` downloads, validates, and activates an artifact, installs the Nginx vhost through the privileged broker, and only then reports activation. The pending-release API supplies the project's configured `health_check_path` (default `/`); the publisher probes that path through `127.0.0.1:80` with the assigned hostname as the HTTP Host header and submits the node-signed health report. Redirects are not followed and the probe cannot connect to external destinations.
- `nexora-runtime-node` currently heartbeats and polls desired state while explicitly rejecting execution-enabled snapshots. It does not start workloads, call `runtimehealth.ProbeAndReport`, or consume rollback guidance.
- An unhealthy health-check report marks the release failed and returns the previous deployment/node as rollback guidance. The static publisher now accepts that guidance only when the target node equals its own node identity, validates the target release identifier, and invokes the compare-and-switch `releasepublisher.Rollback` primitive. It then probes the restored hostname again and reports success locally only when the prior release returns a healthy 2xx response.
- This is a guarded same-node static rollback, not yet an independent signed rollback command/acknowledgement protocol. The control plane does not yet receive a durable rollback-completed event, and OCI workload rollback remains a separate unimplemented lifecycle.

Consequently, do not treat `health_checking` as a completed deployment until the serving probe passes. The opt-in `NEXORA_NGINX_INTEGRATION=1` test starts an isolated Nginx instance on loopback, verifies the initial release response, atomically switches the current symlink, verifies the new response, and confirms PHP paths return 404. Run it on a disposable node with Nginx installed; ordinary CI skips it unless explicitly enabled. Customer deployment execution remains disabled until this test, rollback acknowledgement/auditing, account/domain trust mapping, and production node enrollment are verified.
## Rollback protocol implementation boundary

Rollback must be implemented for the actual serving runtime, not by calling the static publisher from the OCI runtime process. Nexora currently has two distinct mechanisms:

- **Static hosting release:** the publisher owns a versioned document-root tree and `current` symlink. Its local `releasepublisher.Rollback(baseDir, failedReleaseID, previousReleaseID)` compare-and-switch primitive is appropriate only for this filesystem-backed release layout.
- **OCI application workload:** the runtime supervisor owns a container identified by workload ID and release ID. Rolling it back means reconciling that workload to the previously approved immutable release/image digest through the OCI lifecycle backend; changing a static symlink cannot roll back a container.

The control-plane protocol must therefore carry an explicit target kind and bind every command to the exact node identity, project, deployment/release, workload (when OCI), expected currently-active failed release, previous successful release, and a unique command ID. The node must reject unknown fields, stale expected-release values, cross-node commands, expired commands, duplicate command IDs, and targets that do not match its durable local ownership state. A command is acknowledged only after the serving backend has been inspected and confirms the target release is active. The acknowledgement must be signed by the node and idempotently recorded by the API; a timeout must permit safe retry without replaying an unrelated rollback.

The API must issue rollback work only after an authenticated unhealthy health-check report has been matched to the exact assigned release and a verified previous successful release. It must not infer the rollback target from client-supplied values. The command queue, one-time delivery/claim semantics, expiry, retry policy, signed acknowledgement endpoint, database state transitions, and audit events must be designed and integration-tested together. Until then, `rollbackRequired` is advisory guidance only and must never be presented as an executed rollback.

The current runtime node intentionally rejects command-bearing desired-state responses. Do not remove that guard or add command delivery until both the server-side command lifecycle and the node-side consumer are implemented and tested end to end.


## Verified serving-path gap (2026-11-08)

A source review confirms that the current hosting vhost and the static publisher do not share a serving path:

- The hosting provisioner accepts document roots only under `/home/<username>/public_html` and generates the Nginx `root` directive from that path.
- The static publisher is configured with `publisher_root=/var/lib/nexora-static` and publishes each hosting account beneath `/var/lib/nexora-static/accounts/<hostingAccountId>`, activating its `current` symlink there.
- No reviewed code maps the publisher's `current` path into the Nginx document root, creates a dedicated Nginx vhost for that path, or otherwise proves that an HTTP request serves the activated static release.

Therefore the existing `releasepublisher.Rollback` primitive currently switches the publisher's local pointer, but repository inspection does not establish that it switches the content customers receive over HTTP. It would be unsafe to implement or advertise operational automatic rollback on that assumption.

### Required next integration decision

Before adding rollback commands, implement and verify one explicit serving integration for static deployments. The preferred direction is a dedicated deployment vhost whose document root resolves to the publisher-owned account `current` path, with strict account-to-hostname mapping and no customer write access to publisher storage. The integration must define how static deployments coexist with the existing PHP hosting vhosts and must be exercised through Nginx configuration tests plus an HTTP test that proves a release activation changes the served response.

Only after that serving contract is proven should the signed static rollback command/acknowledgement lifecycle be connected. OCI workload rollback remains a separate runtime-controller operation.

## Nginx serving integration contract

The existing database already has a canonical domain-to-account relationship: `domains.hosting_account_id` identifies the hosting account that owns `domains.name`. The static deployment project is also bound to exactly one `github_projects.hosting_account_id`. A deployment hostname must therefore be resolved server-side by joining those records; it must never be accepted as a free-form hostname supplied by a customer build, artifact, or node request.

The static publisher service is deliberately unprivileged. Its systemd unit runs as `nexora-runtime:nexora-static`, has `NoNewPrivileges=true` and `ProtectSystem=strict`, and declares only `/var/lib/nexora-static` writable. It cannot safely install files under `/etc/nginx/sites-available`, enable a site, test the global Nginx configuration, or reload Nginx. Giving it general root access or broad write access to Nginx configuration would defeat the publication trust boundary.

The implementation must use a narrowly scoped privileged operation rather than weakening the publisher service:

1. The control plane resolves one eligible active domain from the project's hosting account and includes its immutable domain ID and normalized hostname in the signed deployment envelope. The hostname is derived from the `domains` row, not from artifact contents. If no eligible domain exists, publication must fail closed.
2. The publisher verifies the signed envelope and the account/domain binding before requesting serving configuration. It passes only opaque account/domain IDs and the signed hostname claim to a dedicated, narrowly authorized privileged broker operation. It must not pass arbitrary Nginx text, filesystem paths, shell commands, or customer-controlled configuration.
3. The privileged helper independently validates the hostname syntax, confirms the local hosting account identity using a root-owned account registry, constructs the document root as `/var/lib/nexora-static/accounts/<hostingAccountId>/current`, and rejects any path outside that exact managed tree. The helper must not accept a caller-selected document root.
4. Nginx access to the publisher-owned release tree must be granted explicitly and minimally (read/traverse only). The publisher's supplementary `www-data` group membership does not grant the Nginx worker access in the reverse direction. Verify every parent directory and the active symlink target; do not recursively grant access outside the account release tree.
5. Install a static-only vhost with no PHP/FastCGI handler, no directory listing, a defined index/404 policy, and the existing TLS/custom-hostname termination model. The static vhost must not replace or mutate the hosting account's PHP vhost. Domain ownership conflicts and duplicate server names must fail closed.
6. The privileged helper writes config atomically, runs `nginx -t`, reloads only an already-active Nginx service, and records enough ownership metadata to remove or repair only the exact config it created. Failed validation must preserve the prior working config and active release.
7. Add integration tests using a disposable Nginx instance or isolated config root. The test must request the configured hostname, verify release A content, activate release B, and verify the same HTTP request returns release B. Also verify a PHP hosting vhost remains unchanged and a domain cannot be rebound across accounts.

### Privileged-broker boundary

The existing provisioning IPC server authorizes the `nexora-agent` UID and invokes a fixed helper. The static publisher runs under a different UID. Do not simply add the publisher to a broad privileged group or allow it to invoke arbitrary provisioning operations. Introduce a distinct authorization rule for the one static-serving operation (or a separate broker socket), bind it to the publisher's OS identity, and keep all other provisioning operations unavailable to that identity. The helper must re-derive and validate all security-sensitive values; the broker's caller identity is not a substitute for domain/account validation.

### Serving-readiness gate

The static publisher must not report a deployment as customer-visible or successful merely because the release symlink switched. The deployment remains nonterminal until the configured hostname returns the expected release identity/content through the real Nginx serving path and the signed health report is accepted by the control plane. A failed HTTP probe leaves the deployment failed and triggers no automatic rollback until the separate signed rollback command/acknowledgement lifecycle is complete.



## Canonical static-domain binding and renderer (2026-11-08)

The control plane now resolves the static deployment hostname from the hosting account's canonical `domains` rows. It selects the primary domain first, then the lexicographically first domain as a deterministic fallback. Both the pending-release assignment and artifact-delivery lookup require an ACTIVE hosting account and an existing domain; a release without either is not offered to the publisher.

The five-minute RS256 deployment envelope now binds `domain_id` and the canonical lowercase `hostname` in addition to the existing project/account/repository/commit/artifact claims. The Linux publisher carries the same domain identity from its signed pending assignment into `deployenvelope.Expected`; the Go verifier rejects domain-ID or hostname rebinding and malformed hostnames. The artifact-delivery integration fixture asserts these claims.

A new pure Go package, `internal/staticvhost`, renders a constrained static-only Nginx server block. It derives the document root from the validated hosting-account ID, hashes the immutable domain ID for a stable config filename, rejects hostname injection, disables directory listing, denies hidden files and PHP paths, and emits no FastCGI, proxy, include, alias, or customer-provided directives.

**Important implementation boundary:** the renderer is not yet connected to the privileged provisioning IPC, does not install or atomically replace Nginx files, does not run `nginx -t` or reload Nginx, and does not establish Nginx read/traverse permissions for publisher releases. No live HTTP test has yet proved that activation changes the customer-visible response. Those are still mandatory gates; static publishing and customer deployment dispatch remain disabled until the privileged broker and end-to-end serving test are complete.


### Atomic Nginx vhost installation implementation

The Linux agent's `internal/staticvhost` package now contains an atomic installer for
renderer-produced static vhosts. It accepts only the deterministic
`nexora-static-<32 hex chars>.conf` filename, requires the effective UID to match
the expected config owner, verifies the config directory and any existing target,
and serializes updates with a root-owned, no-follow lock file.

The installer stages a same-directory temporary file, fsyncs it, atomically renames
it into place, validates the complete Nginx configuration with `nginx -t`, and
reloads Nginx only after validation succeeds. A validation or reload failure
restores the previous file (or removes a newly introduced file); after a failed
reload it makes a best-effort validation and reload of the restored configuration.
Unit tests cover successful ordering, failed validation, failed reload, restoration,
unsafe filenames/directories, symlink targets, and symlinked lock files.

This package is not yet wired to the publisher or a dedicated privileged IPC
endpoint. The existing provisioning socket authorizes only `nexora-agent`, while
the static publisher runs as `nexora-runtime`; granting the publisher access to
the general-purpose provisioning helper would be an unacceptable privilege
expansion. A separate narrow broker/helper and root-owned domain/account registry
must be completed before this installer is invoked in production.


## Static vhost installer trust boundary update

The Linux static-vhost installer now enforces a binding-only API:
- `installBinding` derives the Nginx filename from the domain ID and renders the complete server block through the trusted `staticvhost.Render` function.
- `InstallAsRoot` accepts a `Binding`, not raw Nginx text or a caller-selected filename. It still requires the caller to authenticate its IPC peer and resolve the binding from root-owned account/domain state.
- The filesystem installer is package-private. It continues to enforce the managed filename pattern, directory ownership and write permissions, lock-file no-follow semantics, atomic replacement, `nginx -t`, reload, and restoration on failure.
- Tests verify the installed bytes exactly match renderer output and reject an invalid hostname before invoking Nginx or systemd.

This change closes the raw-configuration injection surface at the installer API, but it does **not** complete the privileged broker. No unprivileged publisher may call the root installer directly. The separate broker, peer-credential policy for `nexora-runtime`, root-owned immutable hosting-account/domain registry, fixed Nginx config directory, and disposable-VM HTTP integration test remain required before enabling static serving.


## Dedicated privileged static-vhost broker

The publisher does not write Nginx configuration or invoke systemctl. After it verifies and activates an artifact, it sends the exact signed deployment envelope to a dedicated Unix socket. The root broker independently verifies the same RS256 envelope before installing the vhost.

- Runs as root in `nexora-static-vhostd.service`, separate from the general provisioning daemon.
- Authorizes the publisher using kernel `SO_PEERCRED` and the UID resolved for `nexora-runtime`.
- Accepts one bounded JSON request containing only `deploymentEnvelope`; unknown fields are rejected.
- Loads issuer, audience and key ID from the root-owned `/etc/nexora-static-vhost/trust.json` and a pinned RSA public key at `/etc/nexora-static-vhost/deployment-envelope-public.pem`. Both files and their parent directory must be root-owned and not group/world writable; symlink opens are rejected.
- Verifies the RS256 signature, key ID, issuer, audience, claim schema and expiry independently using the deployment-envelope verifier. It derives domain ID, canonical hostname and hosting-account ID only from verified signed claims.
- Installs only the deterministic managed config under `/etc/nginx/conf.d`, then validates and reloads Nginx through fixed executable paths.
- Limits concurrent broker requests, command execution time, request/response size and connection time.

The root-owned trust config schema is:

```json
{
  "issuer": "configured-deployment-envelope-issuer",
  "audience": "configured-deployment-envelope-audience",
  "keyId": "active-signing-key-id"
}
```

The matching public key is installed at the fixed path above. The signing private key remains in the Cloudflare Worker secret store. Because the broker verifies the short-lived deployment envelope itself, no separately mutable domain registry or registry synchronization process is required. The Worker must continue issuing envelopes only for deployments assigned to the authenticated runtime node and the verified project/domain/account relationship.

The publisher connects through `/run/nexora-static-vhost/vhost.sock`; the broker unit runs with primary group `nexora-static`, so systemd creates the runtime directory with that group and the daemon creates a `0660` socket without `chown` or `CAP_CHOWN`. The broker independently verifies the publisher UID. The publisher passes the original envelope only in memory; it is not written to logs.

**Integration status:** broker code, daemon unit, publisher-to-broker request path, pinned trust-file validation, independent signed-envelope verification, and CI build/unit coverage are in the branch. Package installation/upgrade wiring, provisioning the root trust files from the active deployment signing key, and disposable-VM end-to-end HTTP verification remain required. Do not enable the broker or customer static deployments on production until those are complete.
