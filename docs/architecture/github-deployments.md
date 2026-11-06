# Nexora GitHub Deployments

## Product behavior

A customer connects a GitHub account, chooses a repository and production branch, attaches it to one Nexora hosting account, and configures a framework/build profile. A deployment is created for a specific commit SHA. Push webhooks enqueue deployments only when the pushed branch matches the configured production branch. Manual deploys use the selected branch's current commit.

The first supported release is **static output deployment**: plain HTML, Vite/React, Vue, and static Astro. Next.js is supported only when configured for static export. Current dashboard/API milestone supports GitHub connection, listing repositories available through installed GitHub App installations, and linking a repository to one active hosting account; it does not yet execute a build. Server-rendered Node.js applications are a later runtime feature; do not silently treat SSR output as static content.

## Control-plane data

Migration `0012_github_deployments.sql` stores:
- one encrypted GitHub OAuth connection per organization;
- single-use, expiring OAuth state hashes scoped to an organization and user;
- a repository-to-hosting-account project configuration;
- immutable commit-specific deployment records and bounded log excerpts.

The API now implements GitHub App OAuth connect/callback/disconnect, organization-scoped token encryption and refresh-token rotation, installation repository listing, and project-to-hosting-account configuration. The API verifies a selected repository against the chosen installation before saving it. Disconnect attempts to revoke the GitHub grant and always removes local credentials; linked project configuration is removed by the foreign-key cascade, while published website files are untouched. Access and refresh tokens are encrypted with AES-GCM using the dedicated `GITHUB_TOKEN_ENCRYPTION_KEY` secret (32-byte hex key), separate from database credential encryption. When GitHub token expiration is enabled, the API refreshes tokens shortly before expiry and atomically stores the rotated access/refresh token pair. OAuth state is random, SHA-256 hashed at rest, expires after 10 minutes, and is consumed once. Never return tokens to the dashboard, logs, webhook responses, or deployment records. OAuth state must be random, hashed at rest, short-lived, single-use, and validated against the authenticated organization/user on callback.

## Deployment pipeline

1. API validates organization membership, hosting-account ownership, quota, project configuration, and branch.
2. API records a queued deployment and delivers a job to the assigned server/build worker using the existing authenticated agent job channel.
3. A dedicated unprivileged build worker checks out the exact commit SHA into a per-job temporary workspace.
4. Build runs in an ephemeral rootless container with CPU, memory, process, disk, and wall-clock limits; no host socket, host PID namespace, privileged mode, or root credentials.
5. The worker detects/uses an allowlisted package manager, runs the configured install/build commands, and validates the output directory. Build commands are untrusted customer code.
6. The output is scanned for unsafe paths/symlinks and published to a versioned release directory owned by the hosting account. A safe atomic activation switches the live release only after a successful build.
7. Failed builds leave the currently active release untouched. Old releases are retained according to plan policy and can be rolled back.
8. Worker reports bounded status/log excerpts. Full logs must have a retention limit and must redact known secret values.

## Webhooks

Register a repository push webhook using a per-project random secret. Verify `X-Hub-Signature-256` with constant-time HMAC-SHA256 comparison over the raw request body. Validate repository ID, installation/connection, event type, branch, and commit SHA. Reject replays/duplicates through an idempotency key. Do not accept arbitrary callback URLs or arbitrary repository clone URLs from customers.

## GitHub App configuration

Create a GitHub App (not a broad OAuth App) and configure:
- Repository permissions: **Contents: Read-only**, **Metadata: Read-only**. Add **Webhooks: Read & write** only when webhook automation is implemented.
- Subscribe to the `push` event when webhook automation is implemented.
- Set the OAuth callback URL to the API endpoint `/v1/github/callback` on the production API origin.
- Do not request broad OAuth scopes; repository access is granted by installing the GitHub App on selected repositories.

Required Worker secrets/vars:
- `GITHUB_APP_CLIENT_ID`
- `GITHUB_APP_CLIENT_SECRET`
- `GITHUB_OAUTH_CALLBACK_URL` (exact HTTPS callback URL configured in the GitHub App)
- `GITHUB_TOKEN_ENCRYPTION_KEY` (32-byte hex key)
- `DASHBOARD_URL` (HTTPS dashboard origin used for the OAuth completion redirect)
- For the future build worker only: `GITHUB_APP_ID` and `GITHUB_APP_PRIVATE_KEY`, used to mint short-lived installation access tokens. Keep the private key off the dashboard and out of browser/API responses.
- A dedicated build-worker runtime and authenticated job/result protocol

The dashboard currently provides GitHub connection, repository selection, and project configuration. Actual builds remain disabled until the isolated build worker is implemented and deployed. The OAuth configuration must be added to the Worker before the Connect GitHub action can succeed.

## Release gates

- OAuth state/CSRF, token encryption, organization isolation, disconnect/revocation.
- Private repository access only through the customer's granted GitHub permissions.
- Webhook signature, replay, and branch validation.
- Rootless isolated build execution and strict resource limits.
- No symlink/path traversal escape from checkout or artifact output.
- Atomic publish/rollback; failed build never replaces the live release.
- End-to-end tests on a disposable hosting account before customer rollout.
