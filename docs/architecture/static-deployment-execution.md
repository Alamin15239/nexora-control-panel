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
7. Report activation using the node's signed identity. A successful activation is not the same as a successful HTTP health check.

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

- `nexora-static-publisher` currently downloads, validates, and activates an artifact, then reports activation. It does not execute a post-activation HTTP health probe or submit a health-check report.
- `nexora-runtime-node` currently heartbeats and polls desired state while explicitly rejecting execution-enabled snapshots. It does not start workloads, call `runtimehealth.ProbeAndReport`, or consume rollback guidance.
- An unhealthy health-check report marks the release failed and returns the previous deployment/node as rollback guidance. The API does not issue a rollback command, and the runtime node does not perform a rollback. The workload row is metadata; updating it is not proof that the serving release was switched back.
- `releasepublisher.Activate` is only a local atomic symlink-switch primitive. It is not yet connected to a signed, idempotent rollback request or an acknowledgement/audit lifecycle.

Consequently, do not treat `health_checking` as a completed deployment, do not claim automatic rollback, and do not enable customer deployment execution. The next implementation phase must define and test the static-site HTTP probe target and the signed rollback command/acknowledgement protocol before wiring either into the publisher or runtime supervisor.
