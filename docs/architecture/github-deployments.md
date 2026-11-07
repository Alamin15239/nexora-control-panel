# Nexora GitHub Deployments

## Product behavior

A customer connects a GitHub account, chooses a repository and production branch, attaches it to one Nexora hosting account, and configures a framework/build profile. Each deployment targets an immutable commit SHA. The first supported release is **static output deployment**: plain HTML, Vite/React, Vue, and static Astro. Next.js is supported only when configured for static export. Server-rendered Node.js applications are a later runtime feature; never silently treat SSR output as static content.

The dashboard/API milestone supports GitHub App connection, repository listing, and linking a repository to an active hosting account. It does not yet execute or publish builds. Automatic deployment remains disabled until the build workflow and publish protocol are implemented and tested.

## Control-plane data

Migration `0012_github_deployments.sql` stores:
- one encrypted GitHub connection per organization;
- single-use, expiring OAuth state hashes scoped to an organization and user;
- repository-to-hosting-account project configuration;
- immutable commit-specific deployment records and bounded log excerpts.

The API implements GitHub App OAuth connect/callback/disconnect, organization-scoped token encryption and refresh-token rotation, installation repository listing, and project-to-hosting-account configuration. It verifies a selected repository against the chosen installation before saving it. Disconnect attempts to revoke the GitHub grant and always removes local credentials; linked project configuration is removed by the foreign-key cascade, while published website files are untouched. Access and refresh tokens are encrypted with AES-GCM using the dedicated `GITHUB_TOKEN_ENCRYPTION_KEY` secret (32-byte hex key), separate from database credential encryption. Never return tokens to the dashboard, logs, webhook responses, or deployment records.

OAuth state is random, SHA-256 hashed at rest, expires after 10 minutes, and is consumed once. Validate it against the authenticated organization and user on callback. Refresh-token rotation uses compare-and-swap so concurrent requests cannot overwrite a newer token pair.

## Build-execution architecture

**Security boundary:** customer source code, package lifecycle scripts, compiler plugins, and configured build commands are untrusted. They must never execute inside the Cloudflare API Worker, the hosting VM, the Nexora Agent, or the privileged provisioning daemon. Do not send arbitrary build commands over the existing authenticated agent job channel.

The initial build executor will be a **GitHub-hosted Actions runner** in the customer's repository. This avoids running hostile build code on the hosting server and provides an ephemeral hosted runner for each job. Nexora's API remains the control plane; the hosting server is only a constrained publisher of already-built static artifacts.

Required workflow contract:
1. A customer adds the Nexora deployment workflow to the repository's default branch. It accepts a deployment ID and runs only for a Nexora-dispatched `workflow_dispatch` event. It must use a GitHub-hosted runner, never a self-hosted runner.
2. Nexora dispatches the workflow at the exact configured branch/ref and commit. The workflow checks out that ref and verifies `git rev-parse HEAD` equals the requested commit SHA before running any build command.
3. The job grants only `contents: read` and `id-token: write`. Do not expose GitHub App private keys, installation tokens, repository secrets, hosting credentials, SSH keys, or long-lived Nexora secrets to build steps. Set the workflow's default `GITHUB_TOKEN` permissions to read-only.
4. The runner requests a GitHub OIDC token with a Nexora-specific audience. Nexora validates the JWT signature against GitHub's published keys and validates issuer, exact audience, repository ID, ref, commit SHA, workflow identity, event name, and run identity. Reject tokens from self-hosted workflows and unexpected workflow paths/refs.
5. After validation, the API issues a one-time, short-lived artifact-upload capability bound to the organization, project, deployment ID, repository ID, branch, and commit SHA. The capability permits only one upload, has a strict byte limit, and cannot read artifacts or modify any other deployment. The API must atomically consume it.
6. The workflow packages only the configured output directory. The API streams the archive into a private R2 staging object (or equivalent private object storage), enforces size and content limits, and records a digest. Do not accept customer-supplied object keys or callback URLs.
7. A separate publish operation validates the archive and manifest, rejects absolute paths, traversal, hard links, symlinks, special files, duplicate paths, and excessive file counts/sizes, then stages files under the target hosting account. The privileged publisher receives only a validated artifact reference and a server-generated target account ID—not a shell command or customer build command.
8. Publication uses immutable versioned release directories and an atomic activation switch. A failed upload, validation, extraction, or publish leaves the active release untouched. Keep the prior release for rollback according to plan retention policy.
9. The workflow reports only bounded status and log excerpts. Store full logs only with explicit retention limits and redact known secrets. Never log OIDC JWTs, upload capabilities, GitHub tokens, or private keys.

### GitHub App permissions for this model

- Repository permissions: **Contents: Read-only**, **Metadata: Read-only**, and **Actions: Read & write** (required to dispatch the workflow).
- Add **Webhooks: Read & write** only when push-webhook automation is implemented.
- Subscribe to the `push` event only when webhook automation is implemented.
- Do not request Contents write merely to install a workflow file; the customer adds and reviews the workflow.
- The GitHub App private key stays in a server-side secret store and is used only by the control plane to mint short-lived installation tokens for repository reads and workflow dispatch. It is never sent to the runner.

### Runner and workflow constraints

- Require GitHub-hosted runners for the first release; reject self-hosted runner labels and user-selected runner groups.
- Use a fixed, reviewed workflow template and pinned action versions (full commit SHAs), with minimal permissions and no deployment secrets.
- Enforce an overall job timeout, build output size limit, log limit, and allowed framework/package-manager matrix.
- Treat package installation and build scripts as arbitrary code. They may access the job's OIDC request endpoint; therefore the upload capability must be short-lived, single-use, and scoped to that exact project/commit. A build job must never receive a cross-project credential.
- Do not allow arbitrary install/build shell commands from API input in the first release. Use a fixed command profile per supported framework, with customer settings limited to validated root/output directories and documented build options.
- Do not enable automatic push deployments until signed webhook verification, replay protection, queue idempotency, and end-to-end tests are complete.

## Deployment state machine

`queued -> dispatched -> building -> artifact_received -> validating -> publishing -> succeeded`

Any nonterminal state may transition to `failed` or `cancelled` under explicit, audited rules. State transitions must be conditional database updates so duplicate webhook deliveries, repeated OIDC exchanges, and concurrent worker callbacks cannot publish twice. Record the exact commit SHA and GitHub Actions run ID/attempt for every deployment.

## Webhooks

When automatic deployment is implemented, register a repository push webhook using a per-project random secret. Verify `X-Hub-Signature-256` with constant-time HMAC-SHA256 comparison over the raw request body. Validate repository ID, installation/connection, event type, branch, and commit SHA. Reject replays/duplicates through an idempotency key. Never accept arbitrary callback URLs or arbitrary repository clone URLs from customers.

## GitHub App configuration

Create a GitHub App (not a broad OAuth App) and configure:
- Repository permissions listed above; do not grant more permissions than the current milestone requires.
- OAuth callback URL: the API endpoint `/v1/github/callback` on the production API origin.
- Do not request broad OAuth scopes; repository access is granted by installing the GitHub App on selected repositories.

Required Worker secrets/vars:
- `GITHUB_APP_CLIENT_ID`
- `GITHUB_APP_CLIENT_SECRET`
- `GITHUB_OAUTH_CALLBACK_URL` (exact HTTPS callback URL configured in the GitHub App)
- `GITHUB_TOKEN_ENCRYPTION_KEY` (32-byte hex key)
- `DASHBOARD_URL` (HTTPS dashboard origin used for OAuth completion redirect)
- Future server-side dispatch only: `GITHUB_APP_ID` and `GITHUB_APP_PRIVATE_KEY`; keep the private key out of the dashboard, browser, build runner, logs, and API responses.
- A private artifact staging bucket (for example, an R2 bucket) and a narrowly scoped publish protocol.
- A server-side GitHub OIDC verifier using GitHub's published signing keys and strict claim validation.

The OAuth configuration must be added to the Worker before the Connect GitHub action can succeed. The current dashboard only provides GitHub connection, repository selection, and project configuration. Actual builds remain disabled until workflow dispatch, OIDC exchange, private artifact staging, and safe publication are implemented.

## Release gates

- OAuth state/CSRF, token encryption, organization isolation, refresh-token rotation, disconnect/revocation.
- Workflow dispatch restricted to the selected installation, repository, branch, and exact commit SHA.
- GitHub OIDC signature and claim validation; one-time, scoped upload capability and replay protection.
- GitHub-hosted ephemeral runner only; no self-hosted runner, privileged host access, or deployment secrets.
- Strict artifact size, file-count, path, symlink, hard-link, and special-file validation.
- Publisher cannot execute customer commands and cannot write outside the target account's release directory.
- Atomic publish/rollback; failed builds never replace the live release.
- End-to-end tests on a disposable hosting account, including malicious archive fixtures and cross-tenant authorization tests, before customer rollout.


## Current dispatch API milestone

The API now exposes `POST /v1/github/projects/:projectId/deployments` for an administrator-triggered workflow dispatch and `GET /v1/github/projects/:projectId/deployments` for organization-scoped deployment history. Dispatch resolves the configured production branch to an immutable 40-character commit SHA, mints a short-lived installation token scoped to that repository with Actions write and Contents read, and dispatches `.github/workflows/nexora-deploy.yml` with a generated deployment ID and commit SHA. The GitHub App private key supports both PKCS#8 and GitHub's downloaded RSA PKCS#1 PEM format and is used only inside the Worker to sign a short-lived App JWT.

Migration `0015_github_deployment_concurrency.sql` adds a partial unique index so a project cannot have two queued or active deployment records concurrently. The deployment record is inserted before dispatch; a rejected dispatch is recorded as failed rather than leaving an invisible attempt. A successful GitHub dispatch is recorded as `queued`, not `succeeded`.

**This is still not a completed deploy pipeline.** GitHub OIDC verification and a one-time artifact-upload capability/streaming endpoint are implemented, but the capability is withheld until a private R2 bucket is bound as `ARTIFACTS`. Archive validation, publishing, and a reviewed workflow template do not exist yet. The dashboard deliberately keeps the Deploy action disabled. A queued record means only that GitHub accepted the workflow-dispatch request; it does not mean the build started, passed, or changed the live website.


## GitHub Actions OIDC verification milestone

The API now exposes `POST /v1/github/deployments/:deploymentId/oidc/exchange`. It accepts a GitHub Actions OIDC JWT as a bearer token, verifies the RS256 signature against GitHub's published JWKS, and checks the issuer, configured audience, expiry/issued-at window, repository name and immutable repository ID, exact branch ref, exact dispatched commit SHA, `workflow_dispatch` event, exact `.github/workflows/nexora-deploy.yml` workflow ref, and `runner_environment=github-hosted`. The workflow must request the audience `https://api.nexoraedge.digital/github-deployments` (or the exact `GITHUB_OIDC_AUDIENCE` Worker variable) when requesting its OIDC token. It rejects self-hosted runners and any run that does not match the queued deployment.

The exchange creates a random 256-bit upload capability, stores only its SHA-256 hash, binds it to one organization/project/deployment/repository/branch/commit and GitHub run ID/attempt, and expires it after five minutes. A unique deployment constraint and conditional state transition allow only one runner claim. The capability is withheld unless a private R2 bucket is bound as `ARTIFACTS`; no bucket binding is currently configured, so the exchange returns HTTP 503 rather than issuing a credential that cannot be used. Migration `0016_github_oidc_artifact_capabilities.sql` adds the capability table and verified run identity columns.

The artifact PUT endpoint and streaming size enforcement are implemented. The private R2 bucket `nexora-deployment-artifacts` is declared as the `ARTIFACTS` binding in `apps/cloudflare-api/wrangler.toml`; this repository configuration does not by itself prove that the deployed Worker has the binding or that production credentials/configuration are correct. The standalone archive validator exists in the Linux agent, but it is not yet wired into the upload lifecycle or a publisher. The publisher is not implemented. Artifact staging is not equivalent to a deploy, and customer production publishing must remain disabled until validation, safe extraction, atomic activation, health checks and rollback are implemented and tested.


## Private artifact upload endpoint

After a verified runner receives its one-time capability, it can upload a gzip-compressed tar stream to `PUT /v1/github/deployments/:deploymentId/artifact`. The API requires the capability as a bearer token, requires a declared `Content-Length`, enforces a 100 MiB maximum while streaming, checks the actual byte count against the declared length, and atomically consumes the capability before accepting the body. The object key is generated by the API under an organization/project/deployment-scoped staging prefix; clients cannot choose an object key. R2 object metadata binds the object to the organization, project, deployment, and commit. The private object key and byte count are recorded in the deployment row and are not returned by the API.

The endpoint requires an R2 bucket binding named `ARTIFACTS`, which is declared in `wrangler.toml` for the `nexora-deployment-artifacts` private bucket. The OIDC exchange still fails closed with HTTP 503 if the deployed Worker does not receive that binding. Migration `0017_github_deployment_artifact_storage.sql` adds the private staging object reference and byte count. This endpoint only stages bytes: it does not extract, inspect, or publish the archive. Archive validation and the isolated publisher remain mandatory release gates.


## Experimental GitHub Actions workflow template

A static-only artifact-staging example is provided at `docs/templates/nexora-deploy.yml`. It checks out the immutable commit supplied by the control plane, builds on a GitHub-hosted runner, rejects symlinks and special files in `dist/`, obtains a short-lived OIDC-bound upload capability only after the build, and uploads a checksum-bound archive to private R2.

This is an integration test scaffold, not a customer-ready deployment workflow:
- It assumes an npm project with `package-lock.json` and static `dist/` output.
- It runs repository-controlled npm lifecycle/build scripts on an ephemeral GitHub-hosted runner.
- It stages an archive only. It does not validate/extract it, publish a release, route traffic, run health checks, or roll back.
- Before use, review the exact workflow source and pin its immutable workflow commit SHA through the administrator trust endpoint. Do not expose deployment credentials or repository secrets to build steps.

## Administrator-pinned workflow trust

OIDC exchange additionally requires `github_projects.trusted_workflow_sha` to be set to a full 40-character commit SHA. It compares the signed `workflow_sha` claim to this exact approved value; a workflow edit therefore blocks runner credential issuance until an organization OWNER/ADMIN reviews the changed workflow revision and explicitly updates the pin through `PUT /v1/github/projects/:projectId/workflow-trust` with `{"workflowSha":"<reviewed-40-character-commit-sha>"}`. The API records an audit event for each pin change. The field is intentionally NULL by default, so existing projects cannot obtain build credentials until an administrator approves a workflow revision. This approval is a security-critical manual review step; the API does not claim to inspect or certify workflow source code automatically.


Deployment dispatch now also refuses to start a GitHub Actions run unless the project has a full, administrator-approved workflow SHA. The approval endpoint is organization-scoped, OWNER/ADMIN-only, validates the 40-character SHA format, and writes an audit event. The OIDC exchange compares the signed `workflow_sha` claim to that pin. This binds upload credential issuance to the exact workflow revision an administrator reviewed, rather than trusting only a mutable workflow path. A changed workflow file requires a new review and pin before dispatch resumes.


## Static archive validator foundation

The Linux agent now contains a standalone `internal/deployarchive` validator for gzip-compressed tar archives. It parses without extracting and enforces entry-count, per-file, and total expanded-size limits; rejects absolute paths, traversal components, backslashes, volume-qualified paths, duplicate normalized paths, file/directory collisions, symlinks, hard links, and non-regular special file types; and drains the gzip stream to verify the trailer/checksum and zero-only tar padding. Unit tests cover valid static-site archives, unsafe entry types, traversal, duplicates/collisions, and size/count limits.

This package is not yet wired into the privileged publisher or the Worker upload lifecycle. No archive is extracted or published by this milestone. The publisher must call this validator (and retain independent safe extraction/path checks) before any filesystem changes.
