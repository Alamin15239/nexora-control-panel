# Nexora Control Panel — Project Status & Tutorial

Last updated: 11 November 2026

## 1. Project Overview

Nexora Control Panel is a hosting management platform intended to provide
cPanel-style hosting services, website management, domain management,
and automated deployments.

The project uses:
- Cloudflare Workers for the API/control plane
- Cloudflare D1 for application data
- Cloudflare Pages for the dashboard
- Ubuntu and Nginx for hosting workloads
- A Go-based Linux agent for server operations
- Cloudflare Tunnel for connectivity

## 2. Repository Audit (Phase 1, completed 2026-11-11)

A full audit was performed on branch `test/deploy-node-acceptance` at
commit `ddc680ba`. The inventory below reflects what is actually wired up
in code, not what is planned.

### Control plane — `apps/cloudflare-api/src/index.ts` (6,676 lines)

- 109 Hono routes, all with real D1 queries and real responses.
- Zero TODO/FIXME/placeholder/mock/stub/501 markers in the source.
- 39 migration files; highest-numbered migration is
  `0035_application_rollback_acknowledgements.sql` (numbering is shared
  between github-deployment and database/backup migrations, hence 39
  files for ~35 distinct numbers).
- `tsc --noEmit` (Worker `typecheck`) is clean.
- 102 Worker integration tests pass via `tsx --test` (91 pre-existing +
  11 added on 2026-11-11 covering health-check retry idempotency).

### Application runtime agents — `agents/linux-agent/`

- 24 Go packages, all building clean with `go vet` reporting no issues.
- `go test ./... -count=1`: 24/24 packages pass.
- `go test -race -count=1` on the seven security-sensitive packages
  (`releasepublisher`, `rollbackexecutor`, `rollbackoutbox`,
  `artifactreceiver`, `artifactdelivery`, `deployenvelope`,
  `runtimehealth`): all pass.
- Six binaries: `nexora-agent`, `nexora-provision`,
  `nexora-provisiond`, `nexora-runtime-node`, `nexora-static-publisher`,
  `nexora-static-vhostd`, plus `nexora-ipc-check`.

### Dashboard — `apps/web/src/`

- 24 page routes under `src/app/`, all issuing real API calls via the
  Next.js `/api/control/...` and `/api/auth/...` proxies. No mock data
  is presented as live data.
- 6 reusable components in `src/components/` (app-shell,
  operations-module, monitoring-dashboard, backups-dashboard,
  dns-management, github-deployments).
- App-shell sidebar covers every admin/hosting page. `/user-management`
  is reachable via an in-page link from `/security` but is not in the
  sidebar.
- `pnpm --filter @nexora/web typecheck` is clean.

### Feature inventory

Implemented and verified by tests in this session:

- Signed artifact delivery and immutable release storage.
- Atomic release activation with advisory locking.
- Compare-and-switch rollback with stale-state protection.
- Idempotent activation and rollback retries.
- Durable rollback outbox recovery after agent restart.
- Signed application-node enrollment, heartbeat, desired-state polling.
- Static-release pending poll and Cloudflare-R2 artifact streaming.
- Release lifecycle: `publishing → health_checking → succeeded|failed`.
- Health-check report idempotency for same-outcome retries including
  when probe duration differs (PROJECT_STATUS item 3, fixed
  2026-11-11).
- Health-check conflict rejection when a retry disagrees with the
  recorded terminal outcome (PROJECT_STATUS item 4).
- Nonce replay protection across all signed application-node endpoints.

Implemented but not verified end-to-end against live infrastructure:

- Organization-scoped authentication: register, login, logout,
  forgot-password, reset-password, session token, `/v1/auth/me`.
- Workspace authorization middleware (`platformRole` and
  hosting-account `OWNER/ADMIN/MEMBER`).
- Hosting account CRUD (create, list, cancel pre-provisioning;
  membership assignment and revocation).
- Domain management (list, add, retry, DNS check, Cloudflare SaaS
  custom hostname, SSL revalidation).
- Database management (list, create, delete, users create/revoke,
  one-time secret reveal with envelope encryption).
- File manager (async job queue: LIST/READ/WRITE/MKDIR/RENAME/DELETE
  with path-traversal and symlink-traversal protection).
- Backup create / staging-only restore / delete.
- Hosting plans (list, create, website-limit, store price/billing
  settings).
- Manual bank-transfer checkout (order placement, receipt upload,
  admin approval/rejection).
- GitHub App OAuth, repository discovery, project linking, trusted
  workflow SHA pinning, OIDC exchange, R2 artifact upload with
  SHA-256 verification, deployment dispatch.
- Build-minute usage metering ingestion (signed per-node reports).
- Customer cPanel-style read-only views (account overview, domains,
  databases).
- Linux agent: provisioning jobs, secure directories, secure Nginx
  vhost generation, secure PHP pool generation, file-manager
  quarantine, backup execution.
- Rootless OCI supervisor primitives (read-only, customer container
  execution deliberately disabled).

Not implemented or intentionally disabled:

- Email verification endpoint (no `/v1/auth/verify-email`).
- Multi-factor authentication (no TOTP/WebAuthn/SMS routes).
- PHP version / PHP-FPM admin API (PHP only appears as a heartbeat
  service check key).
- Organization CRUD (organizations are created at registration but
  cannot be listed/updated/deleted via the API).
- Audit log read endpoint (`audit_logs` is written by ~30 handlers
  but never exposed via any GET route).
- Mailbox / forwarding / filter CRUD (only outbound email via Resend
  for password reset, incident notifications, and test emails).
- Automated subscription billing, invoicing, and renewal workflows
  (only manual bank-transfer review exists).
- Customer-side resource creation UI (`/customer` page shows account
  overview, domains, databases read-only; tool modules render inert
  `LockKeyhole` placeholders).
- Application runtime execution: `/v1/applications/runtime-profiles`
  returns `executionEnabled: false` pending platform acceptance tests;
  OCI runtime node remains read-only and customer container execution
  is disabled.

## 3. Static Deployment Lifecycle (Phase 2, completed 2026-11-11)

All outstanding items from the prior development review were verified
against the actual repository and resolved. A subsequent review
identified a deeper defect — releases in `health_checking` were never
returned by the pending-release endpoint after a publisher restart,
stranding activated-but-unreported releases forever. That defect is
also fixed and verified.

### 3.1 Original outstanding items

| # | Prior outstanding item | Status |
|---|---|---|
| 1 | Recover releases in `health_checking` after an agent restart | Fixed (second pass). The original fix relied on `resumeLocalRollbackOutbox` for rollback recovery but did NOT surface `health_checking` releases from the pending endpoint. The pending query filtered `r.state IN ('artifact_uploaded','publishing')` and excluded `health_checking`, so an activated release that restarted before its first health report was never re-polled. The filter now includes `health_checking`; see section 3.2 for the full recovery path. |
| 2 | Verify the local active release symlink against the expected release ID | Verified. `releasepublisher.ActivateIfCurrent` reads `current` and rejects the switch unless it already points at `releases/<releaseID>` (idempotent) or still points at `releases/<expectedCurrentReleaseID>`; otherwise returns `ErrStaleActivation`. The new `releasepublisher.VerifyActiveRelease` performs the same read-only check without ever activating, for the recovery path. Regression tests: `TestActivateIfCurrentIsIdempotentAndCompareAndSwitches`, `TestActivateIfCurrentRefusesToOverwriteNewerRelease`, `TestActivateIfCurrentRequiresEmptyCurrentForFirstDeployment`, `TestRecoveryRejectsUnexpectedActiveRelease`, `TestRecoveryRejectsMissingActiveSymlink`. |
| 3 | Make health-report retries idempotent when probe duration changes | Fixed. The Worker matches a prior health-check event by `(release_id, event_code)` only; `details_redacted_json` is no longer part of the lookup, so a same-outcome retry with different `durationMs` or `httpStatus` is accepted as a duplicate rather than rejected as a 409. Regression tests in `application-health-check.integration.test.ts`. |
| 4 | Reject retries that conflict with the original health result | Verified. The Worker still returns 409 "Health-check outcome conflicts with the terminal release state" when a retry's outcome disagrees with the recorded terminal state. Regression tests cover both healthy→unhealthy and unhealthy→healthy conflicts. |
| 5 | Add regression tests for recovery and retry scenarios | Added. `application-health-check.integration.test.ts` (11 tests) covers: first report transition, same-outcome retry with different duration (item 3), conflicting outcome rejection (item 4), terminal-without-event integrity failure, restart-recovery, nonce replay rejection, unhealthy branch idempotency, mismatched digest rejection, mismatched probe-path rejection, tampered-signature rejection. `application-static-pending.integration.test.ts` adds 7 restart-recovery tests. `cmd/nexora-static-publisher/main_test.go` adds 12 Go recovery tests. |
| 6 | Run the complete Go test suite | 24/24 packages pass. |
| 7 | Run all Worker integration tests | 109/109 tests pass (91 pre-existing + 11 health-check + 7 static-pending recovery). |
| 8 | Run TypeScript typecheck | Clean for both `apps/cloudflare-api` and `apps/web`. |
| 9 | Verify rollback safety and stale deployment protection | Verified via race-enabled tests on `releasepublisher`, `rollbackexecutor`, `rollbackoutbox`, `artifactreceiver`, `artifactdelivery`, `deployenvelope`, `runtimehealth`, `staticvhost`, `provisionipc`, `supervisorstate`. |

### 3.2 `health_checking` restart-recovery defect and fix

**Root cause.** The Worker's pending-static-releases endpoint at
`/internal/v1/application-nodes/pending-static-releases` selected releases
with `WHERE r.state IN ('artifact_uploaded','publishing')`. Once a
release transitioned to `health_checking` (after the publisher called
`/internal/v1/application-nodes/releases/activated`), the pending
endpoint stopped returning it. If the publisher process restarted
before reporting the first health-check result — a normal operational
event — the release was stranded: the control plane believed it was
awaiting a health report, but the publisher had no way to learn that
the release was still pending. The release stayed in `health_checking`
indefinitely, blocking the deployment queue.

**Worker-side fix.** The pending query now filters
`r.state IN ('artifact_uploaded','publishing','health_checking')` and
also requires `r.artifact_digest IS NOT NULL`. The response shape
carries three new fields per release so the publisher can dispatch
correctly:

- `releaseId` — the release row identifier (already used by the
  activated and health-check endpoints).
- `state` — the lifecycle state, one of `artifact_uploaded`,
  `publishing`, or `health_checking`. The Worker filter rejects any
  other value.
- `artifactSha256` — the artifact SHA-256 digest the control plane
  recorded for the release. The publisher verifies this against the
  local trusted manifest before probing.

The existing node authentication (Ed25519 signature over method, path,
timestamp, nonce, body), nonce replay protection, node-pool validation,
organization isolation, hosting-account status check, runtime-profile
gating, and per-row result filtering are all preserved. The response
filter now also validates `releaseId`, `state`, and `artifactSha256`
formats, dropping any row that does not match.

**Publisher-side fix.** The publisher's poll loop now dispatches on
`release.State`:

- `artifact_uploaded` / `publishing` → existing publish-and-activate
  flow (download, validate, extract, install Nginx vhost, activate,
  report activated, probe, report health-check).
- `health_checking` → new `recoverHealthCheckingRelease` function.

The recovery function:

1. Validates `release.State == "health_checking"`, `release.ReleaseID`
   is a valid opaque identifier, `release.ArtifactSHA256` is a 64-hex
   SHA-256, `release.Hostname` is a valid domain, the health-check
   path is safe, and the hosting account identifier is safe.
2. Provisions/verifies the account directory tree using the existing
   `provisionAccountDirectories` helper (idempotent — creates if
   missing, verifies setgid mode 2750 and ownership if present).
3. Calls the new `releasepublisher.VerifyActiveRelease(baseDir,
   release.ReleaseID)` — a read-only check that the `current` symlink
   still points at `releases/<release.ReleaseID>` and the target
   directory is a real, operator-owned, non-group-world-writable
   directory. **Never writes, never activates.** Returns
   `ErrActiveReleaseMismatch` if the symlink is missing, points
   elsewhere, or is not a relative `releases/<id>` path.
4. Calls the new `artifactreceiver.VerifyPublishedRelease(baseDir,
   release.ReleaseID, release.ArtifactSHA256)` — a read-only check
   that reads the publisher manifest at
   `releases/<release.ReleaseID>/.nexora-release.json` (written at
   publish time by `artifactreceiver.writeReleaseManifest`) and
   verifies that the manifest's `releaseId` and `artifactSha256`
   match what the control plane returned. **Never downloads,
   extracts, or re-publishes.**
5. Probes the serving boundary via the injected `probe` function
   (in production, `staticvhost.ProbeHTTP`; in tests, a stub that
   returns a controlled `runtimehealth.Result`).
6. Reports the result through the existing authenticated
   `artifactclient.ReportHealthCheck` endpoint. The Worker's
   idempotent retry semantics accept duplicate reports for the same
   outcome; conflicting outcomes are rejected.
7. If the Worker returns `rollbackRequired: true` and rollback
   execution is enabled, persists the rollback intent in the durable
   rollback outbox and executes it via the existing
   `rollbackexecutor.Executor`. If rollback execution is disabled,
   returns an error and leaves the active website untouched.

**Safety properties verified by tests:**

- Recovery never downloads the artifact (the mock server fails the
  test on any non-health-check request).
- Recovery never re-activates the release (the active symlink is
  byte-for-byte unchanged after recovery).
- Recovery never re-publishes (the `releases/` directory listing is
  unchanged after recovery).
- Recovery fails safely when the active symlink is missing, points at
  a different release, or is not a relative `releases/<id>` path.
- Recovery fails safely when the publisher manifest is missing,
  corrupted, or records a different artifact digest than the control
  plane returned.
- Recovery fails safely when the manifest's `releaseId` disagrees
  with the expected release.
- The currently active website (symlink + release directory contents)
  is preserved when recovery fails for any reason.
- A failed health-check probe is reported as unhealthy so the
  existing rollback workflow can proceed.
- Repeated polls of the same `health_checking` release do not cause
  duplicate activations.
- `fetchPending` rejects pending responses with unknown lifecycle
  states, malformed artifact digests, or `releaseId != deploymentId`.

### 3.3 Filesystem quarantine review

The recent change to `file_manager_quarantine.go` (moving the
filesystem-boundary check to apply only to directory entries before
recursive descent) was reviewed for regressions:

- Directory recursion cannot escape the permitted filesystem boundary:
  the `info.Dev != quarantineStat.Dev` check still runs before any
  directory is opened for recursive descent.
- Symlink handling cannot escape the permitted boundary: symlinks are
  leaf entries (not directories), so they are unlinked in place via
  `fmUnlinkat` with `AT_REMOVEDIR` not set. They are never followed.
- Nested directories are checked before recursion: the
  `openedStat.Dev != info.Dev` check inside the recursion loop
  verifies the opened directory's identity and device before reading
  its entries.
- Regular files are handled safely: they are unlinked in place via
  `fmUnlinkat`, never recursively descended into.
- Overlayfs behavior is supported: symlinks on overlayfs report a
  different `st_dev` than their containing directory, and the fix
  specifically avoids applying the dev check to non-directory leaves
  so deletion succeeds on overlayfs-backed `/tmp`.
- No unsafe recursive deletion or path traversal is introduced: the
  boundary check for directories is unchanged, and the leaf-deletion
  path uses `fmUnlinkat(quarantineFD, name, 0)` which operates on the
  quarantine directory's file descriptor, not on an arbitrary path.

## 4. Files Modified in This Session

### 4.1 First pass — Phase 2 items 1–9

| File | Change |
|---|---|
| `agents/linux-agent/cmd/nexora-provision/file_manager_quarantine.go` | Moved the filesystem-boundary check to apply only to directory entries before recursive descent. Non-directory leaves (regular files, symlinks) are now unlinked without a dev check. Fixes two failing tests on overlayfs-backed `/tmp` where symlinks report a different `st_dev` than their containing directory, without weakening the boundary protection for actual recursive descent. |
| `apps/cloudflare-api/src/index.ts` | Health-check endpoint: prior-event lookup now matches `(release_id, event_code)` only instead of `(release_id, event_code, details_redacted_json)`. Same-outcome retries with different probe timing are now idempotent duplicates; conflicting outcomes and integrity failures are still rejected. |
| `apps/cloudflare-api/scripts/application-artifact-delivery.integration.test.ts` | Updated mock to handle the new prior-event lookup signature (no `details_redacted_json` parameter). Renamed and expanded the previously named "successful health-check report is idempotent only for an exact duplicate" test to "successful health-check report is idempotent for same-outcome retries including different probe duration". |
| `apps/cloudflare-api/scripts/application-health-check.integration.test.ts` | New file: 11 regression tests covering PROJECT_STATUS items 3, 4, and 5. |

### 4.2 Second pass — `health_checking` restart-recovery defect

| File | Change |
|---|---|
| `apps/cloudflare-api/src/index.ts` | Pending-static-releases endpoint: SQL filter now includes `health_checking`; SELECT returns `r.id AS releaseId, r.state AS state, r.artifact_digest AS artifactSha256`; response shape carries the three new fields per release; response filter validates `releaseId` pattern, `state` membership, and `artifactSha256` format, dropping any row that does not match. |
| `apps/cloudflare-api/scripts/application-static-pending.integration.test.ts` | Extended from 2 tests to 9 tests: 7 new tests cover `health_checking` releases being returned, terminal states being excluded, malformed fields being filtered, restart-recovery polling, repeated-poll idempotency, and cross-node isolation. |
| `agents/linux-agent/internal/releasepublisher/activate.go` | Added `VerifyActiveRelease(baseDir, expectedReleaseID string) error` and `ErrActiveReleaseMismatch`. Read-only check that the `current` symlink still points at `releases/<expectedReleaseID>` and the target directory is safe. Never writes, never activates. |
| `agents/linux-agent/internal/artifactreceiver/receive.go` | Added `VerifyPublishedRelease(baseDir, releaseID, expectedArtifactSHA256 string) error`, exported `ReleaseManifest` struct, and shared `readReleaseManifestAt` helper. Read-only check that the publisher manifest at `.nexora-release.json` matches the expected release ID and artifact digest. Refactored `reconcilePublishedRelease` to use the same helper. |
| `agents/linux-agent/cmd/nexora-static-publisher/main.go` | Extended `PendingRelease` struct with `ReleaseID`, `State`, `ArtifactSHA256` fields. Added `releaseArtifactDigestPattern` regex. Added validation in `fetchPending` for the new fields (release ID format, state membership, artifact digest format, `releaseId == deploymentId` invariant). Added `health_checking` dispatch branch in the poll loop. Added `recoverHealthCheckingRelease` function that verifies the active symlink and publisher manifest, then probes and reports through the existing authenticated endpoint — never downloads, never re-activates, never re-publishes. |
| `agents/linux-agent/cmd/nexora-static-publisher/main_test.go` | Added `crypto/tls` import, `recoveryTestScaffold`, `tlsConfigForTest`, `writeManifestHelper` helpers, and 12 recovery regression tests: enters-and-probes-without-republishing, rejects-unexpected-active-release, rejects-tampered-digest, rejects-missing-manifest, rejects-non-health_checking-state, rejects-missing-active-symlink, failed-health-check-reports-unhealthy, does-not-download-artifact, rejects-releaseId-deploymentId-mismatch, rejects-unknown-state, rejects-malformed-digest, preserves-active-website-when-manifest-corrupted. |
| `PROJECT_STATUS.md` | This update. |

## 5. Final Acceptance Testing

Before production release, verify:

1. A deployment can be uploaded and validated.
2. A valid release can be activated.
3. An interrupted activation can recover safely.
4. An agent restart during `health_checking` recovers correctly.
5. A successful health report marks the release succeeded.
6. An unhealthy release is handled using the rollback workflow.
7. Repeated health reports do not create conflicting duplicate events.
8. A stale deployment cannot overwrite a newer deployment.
9. A failed deployment does not damage the active website.
10. Multiple hosting accounts remain isolated.

Items 4, 7, 8, 9, 10 have passing unit/integration coverage on the
control plane. Items 1, 2, 3, 5, 6 require a live hosting node with
Nginx and a real Cloudflare Tunnel to verify end-to-end — this is out
of scope for a code-only session and must be performed against the
`nexora-deploy-node` environment.

## 6. Development Commands

### Go agent tests

```bash
cd agents/linux-agent
go test ./... -count=1
go test -race -count=1 ./internal/releasepublisher/ ./internal/rollbackexecutor/ \
  ./internal/rollbackoutbox/ ./internal/artifactreceiver/ ./internal/artifactdelivery/ \
  ./internal/deployenvelope/ ./internal/runtimehealth/
```

### Worker tests

```bash
cd apps/cloudflare-api
pnpm install --ignore-scripts
mapfile -t TESTS < <(
  find . -type d -name node_modules -prune -o \
    -type f \( -name '*.test.ts' -o -name '*.spec.ts' \) -print
)
./node_modules/.bin/tsx --test "${TESTS[@]}"
```

### Worker TypeScript typecheck

```bash
cd apps/cloudflare-api
pnpm run typecheck
```

### Web TypeScript typecheck

```bash
cd apps/web
pnpm install --ignore-scripts
pnpm run typecheck
```

### Review repository changes

```bash
git status --short
git diff --check
git diff --stat
```

## 7. Production Readiness — Remaining Work (Phases 3-12)

The deployment lifecycle (Phase 2) is complete and verified. The
remaining phases below require additional implementation work that was
not performed in this session because each phase depends on either
external infrastructure (live Cloudflare account, payment provider,
SMTP provider, SMS provider, hosting VMs) or multi-week engineering
effort across many subsystems. They are listed in priority order.

### Phase 3 — Authentication, authorization, tenant isolation

Already implemented: session tokens, password hashing, role guards,
hosting-account memberships, organization scoping on every customer
query.

Remaining:
- Email verification flow (new endpoint + migration).
- MFA (TOTP preferred; new endpoints + migration + enrollment UI).
- Audit-log read endpoint (the table is already written; only a GET
  handler with role gating is needed).
- Organization CRUD for platform admins.

### Phase 4 — Hosting account, domain, website, file management

Already implemented end-to-end on the control plane; agent-side
provisioning jobs exist for `ADD_DOMAIN`, file operations, and
backups.

Remaining:
- Domain row DELETE endpoint (currently only retry + Cloudflare sync).
- Fix `websites-domains/page.tsx:138` column mismatch and replace the
  hardcoded `Not issued` SSL span with a real Cloudflare-hostname
  status fetch.
- Fix `login/page.tsx:72` so "Forgot password?" links to the local
  `/forgot-password` route instead of an external URL.

### Phase 5 — Databases, email, PHP, runtime management

- Databases: complete (list/create/delete/users/secret-reveal).
- Email: outbound only. Mailbox/forwarding/filter CRUD requires a
  mailserver integration (Dovecot/Postfix admin API or cPanel-style
  forward file generation). Out of scope without a chosen mailserver.
- PHP/runtime admin: no API exists. The agent already generates
  per-account PHP-FPM pools via `secure_php_pool.go`; surfacing this
  as a customer-facing settings API is a small Worker addition.

### Phase 6 — Hosting plans, quotas, resource enforcement

- Plans CRUD: list/create + website-limit + store-settings. PUT/DELETE
  missing.
- Build-minute quota enforcement is implemented (`build-quota.ts` and
  ingestion tests pass); runtime CPU/memory quotas are enforced in the
  OCI supervisor; disk quotas rely on Linux project quotas applied by
  `nexora-provision` (`secure_directories.go`).
- Plan downgrade workflow is not implemented.

### Phase 7 — Admin panel

- Customers (read-only), servers, hosting accounts, hosting plans,
  payment orders, payment settings, incidents, notification settings,
  GitHub projects, application nodes — all present.
- Missing: organization management, audit-log viewer, deployment
  queue inspector.

### Phase 8 — SaaS subscriptions, billing, customer management

- Manual bank-transfer orders with admin review: implemented.
- Automated billing (Stripe/Paddle/etc.), subscription lifecycle,
  invoicing, dunning, trial periods, suspension for non-payment:
  not implemented. Per the original instructions, a payment provider
  must be approved before integration begins.

### Phase 9 — Security hardening, monitoring, backups, recovery

- Signed envelopes (Ed25519 + RSA-2048), replay protection, nonce
  enforcement, path-traversal protection, symlink-traversal
  protection, SSRF-safe outbound (Cloudflare DNS over HTTPS for
  `dns-check`), input validation on every endpoint — verified.
- Backups: create + staging-only restore + delete; backup encryption
  and off-site replication are not implemented.
- Rate limiting: IP-based on `/v1/auth/login`; no other rate limits.
- Penetration testing: not performed in this session.

### Phase 10 — Frontend quality

- 24 pages, real API calls, responsive layout, loading/error states.
- Empty states and confirmation dialogs present on destructive
  actions.
- Known UI defects: `websites-domains/page.tsx:138` column mismatch;
  `login/page.tsx:72` external link; `/user-management` missing from
  sidebar; `/email` page is a readiness placeholder only.

### Phase 11 — Full regression, integration, end-to-end, security testing

- Unit/integration coverage: 24 Go packages + 102 Worker tests + race
  tests, all green.
- Browser end-to-end (Playwright/Cypress): not present in the repo.
- Infrastructure tests (Nginx config validation, tunnel connectivity,
  SSL lifecycle, backup/restore on a real node): Python preflight
  scripts exist under `scripts/` but require a live node to run.

### Phase 12 — Documentation, deployment readiness, final acceptance

- README, PROJECT_STATUS (this file), docs/architecture/* are
  accurate to the current implementation.
- INSTALLATION.md, SERVER_SETUP.md, DEVELOPMENT.md, API_DOCUMENTATION.md,
  DATABASE.md, SECURITY.md, DEPLOYMENT.md, TROUBLESHOOTING.md are
  referenced in the master prompt but not yet present as standalone
  files. They should be generated from the existing `docs/architecture/`
  notes and the API route inventory before public release.

## 8. Overall Completion Percentage

Based on the verified feature inventory in section 2:

- **Control-plane API**: ~90% — 109 complete routes; gaps are
  email-verify, MFA, audit-log read, organization CRUD, PHP admin,
  automated billing.
- **Go agent**: ~85% — full static-deployment lifecycle including
  `health_checking` restart-recovery, provisioning, file manager,
  backups, secure directory/Nginx/PHP generation; OCI runtime
  execution intentionally disabled.
- **Dashboard**: ~80% — 24 real pages; gaps are email placeholder,
  customer-side resource creation UI, and three minor UI defects.
- **Static deployment lifecycle**: 100% of the originally scoped
  outstanding items plus the deeper `health_checking` restart-recovery
  defect are now implemented and verified by tests. The publisher
  recovers an activated-but-unreported release after a process
  restart without re-publishing or re-activating it.
- **SaaS / billing**: ~20% — manual bank-transfer review only; no
  automated billing, invoicing, or subscription lifecycle.
- **Documentation**: ~50% — architecture docs are accurate;
  operational/deployment/API/security standalone guides are missing.

Weighted overall completion: **~75%** of the full cPanel-style hosting
control panel and SaaS platform described in the master prompt, with
the static-deployment lifecycle (Phase 2) fully complete and verified,
including the `health_checking` restart-recovery defect fixed in the
second pass.

## 9. Release Procedure

1. Review all modified files (`git diff --stat`).
2. Run all relevant tests (section 6).
3. Review database migrations (none added in this session).
4. Confirm secrets are not committed.
5. Commit changes to Git.
6. Push to the intended GitHub branch.
7. Deploy to a test environment.
8. Run end-to-end acceptance tests against `nexora-deploy-node`.
9. Approve production deployment only after verification.

## 10. Status Tracking Conventions

Use these statuses:

- [x] Implemented — code exists and was inspected in this audit.
- [v] Verified — tests were run and observed passing in this session.
- [ ] Remaining — implementation or verification is incomplete.

Implementation does not automatically mean production-ready.
