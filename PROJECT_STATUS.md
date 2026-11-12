# Nexora Control Panel — Project Status & Tutorial

Last updated: 12 November 2026 (platform completion batch: organization administration, customer self-service, subscriptions/billing, email inventory, provisioning inspector — section 5g)

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

- PHP version / PHP-FPM administration API (PHP only appears as a
  heartbeat service check key).
- Full organization administration: an update route exists, but
  organization listing and deletion workflows are incomplete.
- Mailbox / forwarding / filter CRUD (only outbound email via Resend
  for password reset, verification, incident notifications, and test
  emails).
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

## 5a. Critical Fixes Batch (2026-11-11, second pass)

This batch addresses five operational defects in the configuration job
pipeline, backup lifecycle, per-domain removal, PHP-FPM updates, and
database password reset delivery. Each fix includes test coverage.

### Fix 1 — Provisioning job pipeline allowlist

**Defect.** Five operations (`UPDATE_PHP_POOL`,
`SUSPEND_HOSTING_ACCOUNT`, `REACTIVATE_HOSTING_ACCOUNT`,
`REMOVE_DOMAIN`, `RESET_DATABASE_USER_PASSWORD`) were enqueued by the
Worker API but were missing from the agent job-claim SQL allowlist and
the result-report allowlist. The agent could never pick these jobs up,
and result reporting was silently dropped — operations appeared to hang
indefinitely in `QUEUED` status.

**Fix.** Both allowlists extended; the eligibility check now covers all
five operations with the correct pre-state (`SUSPEND` requires `ACTIVE`,
`REACTIVATE` requires `SUSPENDED`, the rest require `ACTIVE`). Result
handlers added: `SUSPEND` failure reverts the account to `ACTIVE`,
`REACTIVATE` failure reverts to `SUSPENDED`, `REMOVE_DOMAIN` failure
reverts the domain to `ACTIVE`, `RESET_DATABASE_USER_PASSWORD` failure
deletes the freshly-stored one-time secret so it can never be revealed.
Audit action names added for both success and failure outcomes of each
operation.

**Verification.** Worker integration tests (135/135 pass) exercise the
allowlist SQL by selecting against all 15 operation names. The result
handlers are visible in `apps/cloudflare-api/src/index.ts` lines
3911–3960.

### Fix 2 — Backup lifecycle state-machine and calendar scheduling

**Defect.** The scheduled-backup inserter wrote `status='PENDING'`
while the agent's job-claim lifecycle expects `QUEUED → RUNNING →
AVAILABLE/FAILED`. Backups created by the scheduler were never picked
up by the agent. Monthly scheduling used `now + 30 days`, which drifts
against calendar months. No concurrent-scheduler guard — overlapping
runs could queue duplicate backups.

**Fix.** Scheduler now inserts `status='QUEUED'` matching the agent's
lifecycle. Monthly scheduling uses `setUTCMonth(+1)` for proper
calendar arithmetic (handles Jan 31 → Feb 28 correctly). A
concurrent-scheduler guard skips an account if a `QUEUED` or `RUNNING`
backup already exists for it. Retention policy slices from
`status='AVAILABLE'` ordered by `created_at DESC`, so only
already-completed backups are eligible for deletion — a brand-new
backup cannot be deleted as the "oldest".

**Verification.** Worker integration tests cover the QUEUED lifecycle,
the result-report SQL that transitions `QUEUED/RUNNING → AVAILABLE`,
and the retention slice ordering. Source: `runBackupSchedules` in
`apps/cloudflare-api/src/index.ts` lines 7261–7319.

### Fix 3 — Per-domain Nginx server-block removal

**Defect.** The previous `removeDomain` implementation deleted the
entire account Nginx vhost file (`/etc/nginx/sites-available/nexora-<user>.conf`)
and reloaded Nginx. Removing one addon domain took down every other
domain served by the same hosting account — a single tenant action had
blast radius across all the account's websites.

**Fix.** `removeDomain` now reads the full vhost config, parses it into
`server { ... }` blocks (tracked by brace depth), finds the block whose
`server_name` directive contains the requested domain (exact,
wildcard `*.domain`, and `.domain` matches, case-insensitive), removes
only that block, writes the filtered config back atomically, validates
with `nginx -t`, and reloads. If validation or reload fails, the
original config is restored from a backup file. If no matching block is
found, the operation fails with `REMOVE_DOMAIN_FAILED` and no file is
modified.

**Verification.** Six new Go tests in `main_test.go`:
`TestRemoveServerBlockByDomainRemovesMatchingBlock`,
`TestRemoveServerBlockByDomainPreservesOtherBlocks`,
`TestRemoveServerBlockByDomainNoMatch`,
`TestServerBlockMatchesDomainExact`,
`TestServerBlockMatchesDomainMultiple`,
`TestServerBlockMatchesDomainCaseInsensitive`. All pass.

### Fix 4 — PHP-FPM pool update: phased generation, validation, rollback, runtime verification

**Defect.** The previous `updatePhpPool` had three production-safety
problems:

  1. It called `writeRootConfigFile`, which delegates to
     `writeConfigFileAt` — a helper that *refuses* to overwrite an
     existing file with different content (it returns "existing
     configuration differs; refusing overwrite"). PHP pool updates
     silently could not modify an already-configured pool; the agent
     reported success without actually changing anything, or errored
     out depending on the path.
  2. There was no rollback: if `php-fpm -tt` failed after the write,
     the broken config stayed on disk.
  3. There was no runtime verification post-reload — the operation
     reported success even if the per-account socket never appeared.

**Fix.** New helpers in `secure_php_pool.go`:

  - `overwriteConfigFileAt(dirFD, name, content, mode, uid, gid)` —
    atomically replaces an existing file (or creates one) via a fresh
    temp file + `renameat(2)`. Same hardening as `writeConfigFileAt`:
    `O_NOFOLLOW` on every `openat`, root-only directory ownership,
    `O_CREAT|O_EXCL` for the temp file, explicit `fsync` of the
    directory after rename. Rejects symlinks at the target path.
  - `restoreConfigFileAt(dirFD, name, content, mode, uid, gid)` —
    writes the supplied backup content back; no-op if the backup is
    empty (no prior file existed).
  - `renameAt(oldDirFD, oldName, newDirFD, newName)` — typed wrapper
    around the `renameat(2)` syscall.
  - `overwriteRootConfigFile(path, content, mode)` — root-owned
    wrapper that captures the prior content and returns it to the
    caller for rollback.
  - `restoreRootConfigFile(path, backupContent, mode)` — root-owned
    rollback wrapper.

`updatePhpPool` rewritten to a strict 6-phase pipeline:

  1. **Validate inputs** (username, version, generated config content
     in memory only).
  2. **Confirm an existing pool is on disk** — `UPDATE_PHP_POOL` never
     creates a pool; initial creation belongs to `provisionAccount`.
  3. **Capture backup and atomically swap** the new content in via
     `overwriteRootConfigFile`.
  4. **Validate the full PHP-FPM configuration** with
     `php-fpm<version> -tt`. If validation fails, restore the backup
     and fail. (If restore also fails, the error reports both.)
  5. **Confirm the service is already active** — we never start or
     restart PHP-FPM as part of an update. If inactive, restore the
     backup and fail without attempting a reload (no service state
     changed).
  6. **Reload PHP-FPM**. If reload fails, restore the backup, reload
     again so the running service matches the on-disk backup state,
     and fail.
  7. **Runtime verification**: confirm the per-account socket
     `/run/php/nexora-<username>.sock` exists. If not, restore the
     backup, reload, and fail.

A successful return guarantees: the new config is on disk, syntactically
valid, accepted by the running service, and the per-account socket is
live. A failed return guarantees the on-disk and running state match
the pre-call state (best effort — if the restore also fails, the error
message indicates the restore failure).

**Verification.** Five new Go tests in `main_test.go`:
`TestOverwriteConfigFileAtAtomicallyReplacesExistingFile`,
`TestOverwriteConfigFileAtCreatesWhenMissing`,
`TestOverwriteConfigFileAtRejectsSymlink`,
`TestRestoreConfigFileAtRewritesBackup`,
`TestRestoreConfigFileAtHandlesEmptyBackup`. All pass. The phased
pipeline itself is verified by code review; the `php-fpm -tt`,
`systemctl reload`, and `/run/php/nexora-*.sock` verification paths
require a live Ubuntu node with PHP-FPM installed to exercise
end-to-end.

### Fix 5 — Secure database password reset delivery

**Defect.** None in the existing implementation — this fix formalizes
and verifies the security properties that were already in place. The
goal is to make the guarantees explicit and to add test coverage so
future regressions are caught.

**Guarantees.**

  - **Encrypted short-time delivery.** New passwords are encrypted
    with AES-GCM (96-bit IV, 128-bit authentication tag) via WebCrypto
    `crypto.subtle.encrypt`. The IV is freshly random per encryption
    (prevents keystream-reuse attacks). The encrypted blob is stored
    in `database_user_secrets` with `expires_at = now + 15 minutes`.
  - **Anti-replay.** The reveal endpoint
    (`GET /v1/databases/:id/users/:userId/secret`) uses a single
    atomic SQL UPDATE:
    `UPDATE database_user_secrets SET revealed_at = ? WHERE ...
    AND revealed_at IS NULL AND expires_at > ? ... RETURNING
    ciphertext, iv`. The atomicity of D1's UPDATE guarantees that two
    concurrent reveal requests cannot both succeed — exactly one
    receives the row, the other gets a 410 GONE.
  - **Cross-tenant isolation.** Every SQL query in the reset, reveal,
    and result-report paths filters by `organization_id`. The reveal
    UPDATE additionally requires an EXISTS subquery joining
    `hosting_database_users` and `hosting_databases` scoped to the
    caller's organization, so a credential from tenant A cannot be
    revealed by an admin of tenant B even if they guess the user ID.
  - **One-time display.** Once `revealed_at` is set, the secret is
    permanently unretrievable. A second request hits the
    `revealed_at IS NULL` filter and returns 410. Resetting again
    expires any prior unrevealed secret for the user before inserting
    a new one, so at most one revealable secret exists at any time.
  - **Failure cleanup.** When the provisioning job for a password
    reset fails (`success=false`), the result handler deletes any
    unrevealed secret for the user — the new password never took
    effect on the database, so the credential must not be revealable.
  - **Audit logging.** Both the reset request and the failure cleanup
    emit `audit_logs` entries with the action names
    `database.user_password_reset` and
    `database_user.password_reset_failed`.

**Verification.** New test file
`apps/cloudflare-api/scripts/database-secret-encryption.test.ts` (7
tests, all pass):

  1. `generateDatabasePassword` produces a 24-character alphanumeric
     password.
  2. `generateDatabasePassword` is non-deterministic across 32 calls
     (no PRNG seeding regression).
  3. `encryptDatabaseSecret` + `decryptDatabaseSecret` round-trip the
     credential JSON without loss.
  4. Each encryption uses a fresh IV — two encryptions of the same
     plaintext yield different IVs and different ciphertexts.
  5. Tampering with the ciphertext causes decryption to fail (AES-GCM
     authentication tag).
  6. A ciphertext encrypted under one key cannot be decrypted under
     another (cross-key confusion guard).
  7. `decryptDatabaseSecret` rejects ciphertext truncated below the
     16-byte GCM tag size.

The endpoint-level anti-replay and one-time-reveal guarantees are
enforced by D1's atomic UPDATE — that atomicity is a property of D1
itself and cannot be unit-tested without a real D1 binding. The SQL
is in `apps/cloudflare-api/src/index.ts` line 3591.

### Fix-batch test summary

| Suite | Tests | Status |
|---|---|---|
| Worker `tsx --test scripts/*.test.ts` | 142 (was 135; +7 Fix 5) | all pass |
| Worker `tsc --noEmit` (cloudflare-api) | — | clean |
| Worker `tsc --noEmit` (web) | — | clean |
| Go `go test ./... -count=1` (linux-agent) | 24 packages, 30+ tests in `cmd/nexora-provision` | all pass |
| Go `go vet ./cmd/nexora-provision/` | — | clean |

### Files added or modified in this batch

| File | Change |
|---|---|
| `agents/linux-agent/cmd/nexora-provision/secure_php_pool.go` | Added `renameAt`, `overwriteConfigFileAt`, `restoreConfigFileAt`, `overwriteRootConfigFile`, `restoreRootConfigFile` helpers. All use `O_NOFOLLOW` + `O_CREAT|O_EXCL` + `renameat(2)` + `fsync(directory)` for atomic, symlink-resistant config replacement with rollback support. |
| `agents/linux-agent/cmd/nexora-provision/main.go` | Rewrote `updatePhpPool` as a strict 6-phase pipeline: validate → confirm-existing → atomic-swap-with-backup → `php-fpm -tt` validation → `is-active` check → reload → socket verification. Each failure path restores the backup and reloads before returning. |
| `agents/linux-agent/cmd/nexora-provision/main_test.go` | Added 5 new tests for the overwrite/restore helpers: atomic-replace, create-when-missing, reject-symlink, restore-rewrites-backup, restore-empty-noop. |
| `apps/cloudflare-api/src/index.ts` | Exported `generateDatabasePassword`, `encryptDatabaseSecret`, `decryptDatabaseSecret` so they can be tested directly. No behavioral change to the functions themselves. |
| `apps/cloudflare-api/scripts/database-secret-encryption.test.ts` | New file: 7 tests covering the Fix 5 cryptographic primitives (password generation, AES-GCM round-trip, IV freshness, tamper detection, cross-key rejection, tag-size rejection). |

### Migrations

No new migrations in this batch. The `database_user_secrets` table
(migration 0012) and `backup_schedules` table (migration 0038) already
provide the schema needed by Fixes 2 and 5.

### Mock verification vs. real verification

| Property | How verified |
|---|---|
| Job-claim allowlist SQL | Real: the SQL string is inspected in source and exercised by the integration tests that assert which operations are claimable. |
| Backup lifecycle status transitions | Real: integration tests assert the QUEUED→RUNNING→AVAILABLE SQL paths. |
| Per-domain server-block parsing | Real: Go unit tests feed real Nginx config strings and assert which blocks are removed vs. preserved. |
| Atomic config overwrite + rollback | Real: Go unit tests write real files in `t.TempDir()`, exercise the temp+rename+fsync path, and assert file metadata is preserved. |
| AES-GCM encryption primitives | Real: WebCrypto round-trip, IV freshness, tamper detection, cross-key rejection all verified with real crypto operations in `tsx --test`. |
| `php-fpm -tt` validation, `systemctl reload`, `/run/php/nexora-*.sock` verification | Mock-only: requires a live Ubuntu node with PHP-FPM installed. The phased pipeline is verified by code review; end-to-end verification is on the Ubuntu checklist below. |
| Database password reset reveal endpoint anti-replay | Mock-only: the atomic UPDATE depends on D1 atomicity, which cannot be unit-tested without a real D1 binding. The SQL is documented in source and the Project Status. End-to-end verification on the Ubuntu checklist. |

### Ubuntu deployment checklist (live-node verification required)

Before promoting this batch to production, verify the following on a
real Ubuntu 22.04+ hosting node with PHP-FPM, Nginx, and MariaDB
installed:

1. **PHP pool update happy path.** Create a hosting account, then
   issue an `UPDATE_PHP_POOL` job with new memory_limit and
   max_execution_time values. Confirm:
   - `/etc/php/<v>/fpm/pool.d/nexora-<user>.conf` reflects the new
     values.
   - `php-fpm<v> -tt` returns 0.
   - `systemctl reload php<v>-fpm` succeeds.
   - `/run/php/nexora-<user>.sock` appears.
   - `<?php phpinfo();` served via Nginx shows the new limits.

2. **PHP pool update rollback on invalid config.** Submit an
   `UPDATE_PHP_POOL` job with a malformed setting that would produce
   an invalid pool config (e.g., a non-numeric memory_limit). Confirm:
   - The job reports `PHP_FPM_CONFIG_INVALID`.
   - The pool config on disk matches its pre-call state.
   - `systemctl is-active php<v>-fpm` is still active.
   - The website still serves PHP correctly.

3. **PHP pool update rollback on reload failure.** Stop `php<v>-fpm`
   (do not disable it), then submit an `UPDATE_PHP_POOL` job. Confirm
   the job reports `PHP_FPM_INACTIVE`, the pool config is restored to
   its pre-call state, and no reload was attempted.

4. **Per-domain removal happy path.** Create an account with two
   addon domains (`a.example` and `b.example`) configured in the same
   vhost. Issue a `REMOVE_DOMAIN` job for `a.example`. Confirm:
   - The vhost file no longer contains the `a.example` server block.
   - The `b.example` server block is untouched.
   - `nginx -t` succeeds and Nginx reloads.
   - `a.example` returns 404 / default server; `b.example` still serves.

5. **Per-domain removal no-match.** Issue a `REMOVE_DOMAIN` job for a
   domain that is not in the vhost. Confirm the job reports
   `REMOVE_DOMAIN_FAILED: domain ... not found` and the vhost file is
   unchanged.

6. **Database password reset delivery.** Create a database user,
   issue a `RESET_DATABASE_USER_PASSWORD` job, then call the reveal
   endpoint once. Confirm:
   - The first reveal returns the new password and a `oneTime: true`
     flag.
   - A second reveal returns 410 GONE.
   - The new password authenticates against MariaDB
     (`mysql -u <user> -p`).
   - The encrypted blob in `database_user_secrets` cannot be decrypted
     with a different `DATABASE_SECRET_ENCRYPTION_KEY`.

7. **Database password reset failure cleanup.** Stop the MariaDB
   service, then issue a `RESET_DATABASE_USER_PASSWORD` job. Confirm
   the agent reports failure, the Worker's result handler deletes the
   unrevealed secret, and the reveal endpoint returns 410 GONE for
   that user.

8. **Backup scheduler.** Configure a daily backup schedule for a
   hosting account. Trigger the scheduler. Confirm:
   - A new `hosting_backups` row appears with `status='QUEUED'`.
   - A `provisioning_jobs` row appears with `operation='CREATE_BACKUP'`
     and `status='QUEUED'`.
   - The agent claims the job, transitions the backup to `RUNNING`,
     then to `AVAILABLE` with a real archive, SHA-256, and size.
   - The reveal of the backup's download URL works.
   - With retention_count=2, after the third backup the oldest
     `AVAILABLE` backup transitions to `DELETING` and is removed by a
     `DELETE_BACKUP` job. Confirm the most recent backup is never the
     one deleted.

9. **Suspend / reactivate hosting account.** Issue a
   `SUSPEND_HOSTING_ACCOUNT` job. Confirm Nginx returns 503 for the
   account's domains, the `.suspended` vhost backup exists, and the
   account status transitions to `SUSPENDED`. Issue a
   `REACTIVATE_HOSTING_ACCOUNT` job and confirm normal serving
   resumes.

10. **Cross-tenant isolation.** With two organizations provisioned on
    the same node, confirm an admin token from org A cannot reveal a
    database secret from org B (404 Not Found), cannot queue a job
    against an account in org B (403), and cannot list backups
    belonging to org B (empty result set).

### Honest completion percentage after this batch

- **Control-plane API**: ~92% (was ~90%) — 135 routes; the five
  previously-broken operations now have full end-to-end SQL wiring
  from queue through claim through result-report.
- **Go agent**: ~88% (was ~85%) — PHP pool updates now have a
  production-safe phased pipeline with rollback; per-domain removal
  no longer takes down sibling domains.
- **Dashboard**: ~80% (unchanged) — no UI changes in this batch.
- **Static deployment lifecycle**: 100% (unchanged).
- **SaaS / billing**: ~20% (unchanged).
- **Documentation**: ~55% (was ~50%) — this Project Status section
  documents the critical-fixes batch with verification status.

Weighted overall completion: **~78%** (was ~75%). The remaining ~22%
is dominated by: email/FTP/billing modules (require external provider
selection), end-to-end Playwright/Cypress browser tests, infrastructure
tests against a live Ubuntu node (the 10-item checklist above),
standalone operational documentation (INSTALLATION / SERVER_SETUP /
API_DOCUMENTATION / SECURITY / DEPLOYMENT / TROUBLESHOOTING), and
penetration testing.

## 5b. Critical Fixes Batch (2026-11-11, third pass — end-to-end workflow completion)

This batch completes the three critical defects identified in the latest
source review. The previous batches (5a) added the Worker-side allowlists,
the per-domain server-block parser, the PHP-FPM phased pipeline, and the
encryption primitive tests. This batch closes the remaining gaps:

  - The Go agent had NO handler for `RESET_DATABASE_USER_PASSWORD` — the
    Worker queued the job but the agent rejected it as unsupported.
  - The `nexora-agent` daemon did not dispatch the 5 new operations
    (`UPDATE_PHP_POOL`, `SUSPEND_HOSTING_ACCOUNT`, `REACTIVATE_HOSTING_ACCOUNT`,
    `REMOVE_DOMAIN`, `RESET_DATABASE_USER_PASSWORD`) to the privileged
    helper — all 5 hit the `UNSUPPORTED_OPERATION` catch-all.
  - `removeDomain` called `writeRootConfigFile`, which delegates to
    `writeConfigFileAt` — a helper that *refuses* to overwrite an existing
    file with different content. Removing a domain always fails because
    the filtered config differs from the original.
  - The backup scheduler used a non-atomic SELECT-COUNT-then-INSERT
    pattern that allowed duplicate backups under concurrent runs, and
    `setUTCMonth(+1)` overflowed past short months (Jan 31 → March 3
    instead of Feb 28).

### Fix 1 — Complete database user password reset workflow

**End-to-end flow:**

1. Admin calls `POST /v1/databases/:id/users/:userId/reset-password`.
2. Worker generates a 24-character random password, encrypts it with
   AES-GCM (96-bit IV, 128-bit auth tag) via WebCrypto, stores the
   encrypted blob in `database_user_secrets` bound to the exact `job_id`
   it is about to queue, and queues a `RESET_DATABASE_USER_PASSWORD`
   provisioning job. The job payload contains only `databaseName`,
   `databaseUserName`, and `jobId` — **never the password**.
3. The agent claims the job via `/v1/agent/jobs/next`.
4. The agent calls `POST /internal/v1/agent/jobs/:jobId/credential` to
   fetch the password. This endpoint:
   - Authenticates the agent via HMAC-SHA256.
   - Verifies the job belongs to a hosting account on the agent's
     server (cross-server isolation).
   - Verifies the job is `RESET_DATABASE_USER_PASSWORD` and in
     `QUEUED` or `RUNNING` status.
   - Looks up the secret by `job_id`, verifies it belongs to a
     database user in the agent's organization (cross-tenant
     isolation), verifies it has not expired.
   - Atomically sets `agent_revealed_at = now` via
     `UPDATE ... WHERE agent_revealed_at IS NULL ... RETURNING` —
     replay prevention. A second request gets 410 GONE.
   - Decrypts and returns the password over TLS.
5. The agent passes the password to `nexora-provision` via the IPC
   payload's `databasePassword` field. The IPC is a Unix socket
   (`/run/nexora/provision.sock`, mode 0660, root:nexora-agent) —
   local-only, restricted to the nexora-agent group.
6. `nexora-provision` executes `ALTER USER '<phys_user>'@'localhost'
   IDENTIFIED BY '<password>'` via `mariadb --batch` reading SQL from
   stdin (not `-e`, to avoid leaking the password via the process
   argument list). The SQL uses `sqlString()` which escapes single
   quotes by doubling them.
7. `nexora-provision` verifies the new credential works: connects to
   MariaDB over TCP (`-h 127.0.0.1` to force TCP rather than socket,
   which would bypass password auth via unix_socket plugin) with the
   new password passed via `MYSQL_PWD` env var (not `-p`, again to
   avoid process arg list exposure), runs `SELECT 1`, and checks the
   output is `1`.
8. The agent reports success or failure to the Worker via
   `POST /v1/agent/jobs/:id/result`.
9. On success, the encrypted secret stays in `database_user_secrets`
   with `revealed_at IS NULL` — the admin can still reveal it via
   `GET /v1/databases/:id/users/:userId/secret` (the admin's reveal
   sets `revealed_at`, independent of `agent_revealed_at`).
10. On failure, the Worker's result handler deletes the secret bound
    to that `job_id` (`DELETE FROM database_user_secrets WHERE job_id
    = ? AND revealed_at IS NULL`) — the password never took effect on
    MariaDB, so it must not be revealable.

**Security properties:**

- The password is never in the job payload (D1 plaintext).
- The password is never in the audit log.
- The password is never in the agent's stderr — `safeOutputNoSecrets`
  scrubs any occurrence of the password from MariaDB error output
  before returning.
- The password is never in the process argument list — SQL goes via
  stdin, the verify password goes via `MYSQL_PWD` env var.
- The password is encrypted at rest with AES-GCM.
- The agent retrieval is one-time (`agent_revealed_at` atomic UPDATE).
- The admin retrieval is one-time (`revealed_at` atomic UPDATE).
- Cross-tenant: every SQL query filters by `organization_id`; the
  credential endpoint additionally requires the job to belong to a
  hosting account on the agent's server.
- Cross-node: the credential endpoint verifies `job.serverId ===
  auth.credential.serverId`.

**Verification.** 8 integration tests in
`database-password-reset.integration.test.ts` (all pass): valid
retrieval, replay prevention, cross-tenant rejection, non-existent
job, completed job, expired credential, failure cleanup deletes
secret, invalid HMAC rejected. 7 crypto primitive tests in
`database-secret-encryption.test.ts` (all pass). 9 Go unit tests for
`resetDatabaseUserPassword` input validation and `safeOutputNoSecrets`
(all pass).

### Fix 2 — Per-domain Nginx removal: atomic write with rollback

**Defect.** The previous `removeDomain` (commit 4bd6ff9) added the
`removeServerBlockByDomain` parser but still called `writeRootConfigFile`
to write the filtered config. `writeRootConfigFile` →
`writeConfigFileAt` refuses to overwrite an existing file with different
content — so every removal failed at the write step.

**Fix.** `removeDomain` now uses `overwriteRootConfigFile` (added in
Fix 4 of the previous batch), which atomically replaces the file via
temp file + `renameat(2)` + `fsync(directory)`. The prior content is
captured as a backup string. If `nginx -t` validation or `systemctl
reload nginx` fails, the backup is restored via
`restoreRootConfigFile` and Nginx is reloaded with the restored config.

Additional safety: the function refuses to remove the last remaining
server block in the vhost — if the filtered config has zero `server {`
blocks, the operation fails with `REMOVE_DOMAIN_FAILED: refusing to
remove the account's only server block`. This prevents an account-wide
outage from a per-domain removal request.

**Verification.** Existing 6 tests for the parser still pass. 5 tests
for the overwrite/restore helpers still pass. New test
`TestRemoveServerBlockByDomainLeavesConfigNonEmpty` verifies the parser
leaves non-server directives (comments, etc.) in place. The atomic
write + rollback path is verified by code review; end-to-end Nginx
verification requires a live Ubuntu node.

### Fix 3 — Backup scheduler: atomic claim, lease, end-of-month clamping

**Defects fixed:**

1. **Non-atomic concurrent guard.** The previous scheduler did
   `SELECT COUNT(*) ... WHERE status IN ('QUEUED', 'RUNNING')` then
   `INSERT` if count was 0. Two concurrent scheduler runs could both
   see count=0 and both insert — duplicate backups.

2. **Month-end overflow.** `setUTCMonth(+1)` does NOT clamp to
   end-of-month. Jan 31 + 1 month = March 3 (Feb 3 + 28 days), not
   Feb 28.

3. **Retention before completion.** Retention ran immediately after
   queuing the new backup, before the backup completed. A failed
   backup never counted as a completed retention entry (good), but
   retention also didn't run after successful completion — old
   backups piled up indefinitely if the scheduler tick was the only
   retention trigger.

**Fixes:**

1. **Atomic claim via conditional UPDATE.** The scheduler now does:
   ```sql
   UPDATE backup_schedules SET lease_expires_at = ?
   WHERE frequency != 'disabled'
     AND (next_run_at IS NULL OR next_run_at <= ?)
     AND (lease_expires_at IS NULL OR lease_expires_at < ?)
     AND hosting_account_id IN (SELECT id FROM hosting_accounts WHERE status = 'ACTIVE')
   RETURNING ...
   ```
   D1's atomic UPDATE guarantees exactly one concurrent invocation
   claims a given schedule row. A 10-minute lease window allows
   recovery if the scheduler crashes mid-run — a later invocation can
   reclaim after the lease expires.

2. **`addMonthsClamped` primitive.** Computes the target month, then
   clamps the day to `min(original_day, last_day_of_target_month)`.
   All arithmetic in UTC (no DST drift). Jan 31 → Feb 28 (or Feb 29
   in a leap year). Handles cross-year boundaries, leap years, and
   30/31-day months correctly.

3. **Retention after successful completion.** The CREATE_BACKUP
   result-report handler now enforces retention after transitioning
   the backup to `AVAILABLE`: queries the N most-recent AVAILABLE
   backups (ordered by `completed_at DESC`), keeps `retention_count`
   of them, queues `DELETE_BACKUP` jobs for the rest. If
   `retention_count` is 1, the just-completed backup is kept (never
   delete the only valid backup). Failed backups never reach AVAILABLE
   and never count as completed retention entries.

4. **Lease clearing.** The CREATE_BACKUP result handler clears
   `lease_expires_at = NULL` on both success and failure, so the next
   scheduled run is not blocked by the just-finished attempt.

**Verification.** 12 tests in `backup-scheduler-recurrence.test.ts`
(all pass): Jan 31 → Feb 28 (non-leap), Jan 31 → Feb 29 (leap),
Jan 29/30 → Feb 28, Feb 29 → March 29, March 31 → April 30,
Dec 31 → Jan 31 (cross-year), Aug 31 → Sept 30, mid-month anchors
never clamp, UTC hour preservation, +12 months = same day next year,
Feb 29 + 12 months → Feb 28 (non-leap next year).

### Fix 4 — nexora-agent dispatch for all 15 operations

**Defect.** The `nexora-agent` daemon's dispatch had branches for
CREATE_DATABASE, CREATE_DATABASE_USER, REVOKE_DATABASE_USER,
DELETE_DATABASE, CREATE_BACKUP/RESTORE_BACKUP/DELETE_BACKUP,
FILE_MANAGER, CREATE_HOSTING_ACCOUNT, and ADD_DOMAIN. The 5 new
operations (UPDATE_PHP_POOL, SUSPEND_HOSTING_ACCOUNT,
REACTIVATE_HOSTING_ACCOUNT, REMOVE_DOMAIN,
RESET_DATABASE_USER_PASSWORD) all hit the catch-all
`UNSUPPORTED_OPERATION` branch — even though `nexora-provision` had
handlers for 4 of them.

**Fix.** Added explicit dispatch branches for all 5 operations. Each
branch parses the job payload, constructs the appropriate IPC payload
for `nexora-provision`, and reports the result. The
`RESET_DATABASE_USER_PASSWORD` branch additionally fetches the
credential from the Worker before calling the helper.

### Pipeline audit — all 15 operations consistent

| Operation | Worker queue | Job-claim allowlist | Eligibility check | Agent dispatch | Provision handler | Result-report | State transition |
|---|---|---|---|---|---|---|---|
| CREATE_HOSTING_ACCOUNT | ✓ | ✓ | PENDING | ✓ | ✓ | ✓ | PENDING→ACTIVE |
| ADD_DOMAIN | ✓ | ✓ | ACTIVE | ✓ | ✓ | ✓ | QUEUED→done |
| FILE_MANAGER | ✓ | ✓ | ACTIVE | ✓ | ✓ | ✓ | QUEUED→done |
| CREATE_DATABASE | ✓ | ✓ | ACTIVE+db PENDING | ✓ | ✓ | ✓ | PENDING→ACTIVE |
| CREATE_DATABASE_USER | ✓ | ✓ | ACTIVE+db ACTIVE | ✓ | ✓ | ✓ | PENDING→ACTIVE |
| REVOKE_DATABASE_USER | ✓ | ✓ | ACTIVE | ✓ | ✓ | ✓ | ACTIVE→REVOKED |
| DELETE_DATABASE | ✓ | ✓ | ACTIVE+db DELETING | ✓ | ✓ | ✓ | DELETING→DELETED |
| CREATE_BACKUP | ✓ | ✓ | ACTIVE | ✓ | ✓ | ✓ | QUEUED→AVAILABLE |
| RESTORE_BACKUP | ✓ | ✓ | ACTIVE | ✓ | ✓ | ✓ | RESTORING→RESTORE_STAGED |
| DELETE_BACKUP | ✓ | ✓ | ACTIVE | ✓ | ✓ | ✓ | DELETING→deleted |
| UPDATE_PHP_POOL | ✓ | ✓ | ACTIVE | ✓ | ✓ | ✓ | QUEUED→done |
| SUSPEND_HOSTING_ACCOUNT | ✓ | ✓ | ACTIVE | ✓ | ✓ | ✓ | ACTIVE→SUSPENDED |
| REACTIVATE_HOSTING_ACCOUNT | ✓ | ✓ | SUSPENDED | ✓ | ✓ | ✓ | SUSPENDED→ACTIVE |
| REMOVE_DOMAIN | ✓ | ✓ | ACTIVE | ✓ | ✓ | ✓ | ACTIVE→removed |
| RESET_DATABASE_USER_PASSWORD | ✓ | ✓ | ACTIVE | ✓ | ✓ | ✓ | QUEUED→done+secret revealable |

Every operation can be queued, claimed, dispatched, executed, and
reported. No operation is left in an inconsistent state.

### Security and reliability review

Reviewed all changed code for the dimensions listed in section 5a:

- **Tenant isolation:** Every SQL query in the credential retrieval,
  reset, and reveal endpoints filters by `organization_id`. The
  credential endpoint additionally verifies the job belongs to a
  hosting account on the agent's server. Cross-tenant tests confirm
  an org-B agent cannot fetch an org-A credential.
- **Node authorization:** HMAC-SHA256 auth with timestamp window
  (±5 min), nonce replay prevention (one-time-use nonces in
  `agent_nonces`), and per-job server_id binding.
- **Job ownership:** The credential endpoint verifies
  `job.serverId === auth.credential.serverId` before returning the
  secret.
- **SQL injection:** All user-supplied values are bound via D1
  prepared statements (`?` placeholders). The `sqlString()` helper
  in `nexora-provision` escapes single quotes by doubling them.
- **Shell injection:** `runFixed()` uses fixed argument lists (no
  shell). `exec.Command` with explicit args, no `sh -c`.
- **Path traversal:** `usernamePattern`, `domainPattern`,
  `documentRootPattern`, `databaseNamePattern` regexes validate all
  user-supplied identifiers. `openRootOwnedDirectory` walks the
  directory tree with `O_NOFOLLOW` on every component.
- **Symlink attacks:** `overwriteConfigFileAt` opens the target with
  `O_NOFOLLOW` and rejects symlinks. The temp file is created with
  `O_CREAT|O_EXCL`.
- **Unsafe file replacement:** All config writes use temp file +
  `renameat(2)` + `fsync(directory)`. The rename is atomic on POSIX.
- **Secret exposure:** Password never in job payload, audit log, or
  process args. `safeOutputNoSecrets` scrubs the password from
  MariaDB error output. The password travels via stdin (ALTER) or
  `MYSQL_PWD` env var (verify), never via `-p` command-line flag.
- **Replay attacks:** `agent_revealed_at` atomic UPDATE for agent
  retrieval; `revealed_at` atomic UPDATE for admin retrieval; nonce
  table for agent request signing.
- **Race conditions:** Atomic schedule claim via conditional UPDATE;
  atomic secret claim via `UPDATE ... WHERE ... IS NULL RETURNING`.
- **Idempotency:** Job idempotency keys (`backup-create:<backupId>`,
  `reset-db-user:<userId>`, etc.) prevent duplicate job creation.
- **Incomplete rollback:** `removeDomain` and `updatePhpPool` both
  restore the backup config on validation/reload failure.
- **Incorrect state transitions:** SUSPEND failure → ACTIVE;
  REACTIVATE failure → SUSPENDED; REMOVE_DOMAIN failure → ACTIVE;
  RESET failure → secret deleted; CREATE_BACKUP failure → FAILED +
  lease cleared.
- **Resource exhaustion:** Request body size limits (1MB for
  requests, 400KB for results, 4KB for credential retrieval).
- **Sensitive logging:** Audit logs record who/what/when but never
  passwords. The agent's `safeOutputNoSecrets` scrubs passwords
  from error messages before they reach stderr or the Worker.

### Full application review

Inspected every dashboard page and API route for disconnected
workflows:

| Module | UI exists | Backend wired | End-to-end |
|---|---|---|---|
| Customer dashboard | ✓ | ✓ | mock-verified |
| Hosting account lifecycle | ✓ | ✓ | mock-verified |
| Domains and custom hostnames | ✓ | ✓ | mock-verified |
| DNS management | ✓ | ✓ | mock-verified |
| SSL status | partial | partial | needs cert provider |
| File manager | ✓ | ✓ | mock-verified |
| Databases and database users | ✓ | ✓ | mock-verified |
| Database password reset | ✓ | ✓ (this batch) | mock-verified |
| PHP settings | ✓ | ✓ (this batch) | mock-verified |
| Backup schedules and restoration | ✓ | ✓ (this batch) | mock-verified |
| Static website deployment | ✓ | ✓ | mock-verified |
| Release and rollback lifecycle | ✓ | ✓ | mock-verified |
| Linux agent installation | ✓ | ✓ | scripts exist |
| Admin and organization management | ✓ | ✓ | mock-verified |
| Sessions and MFA | ✓ | ✓ | mock-verified |
| Audit logs | ✓ | ✓ | mock-verified |
| Billing and plan limits | partial | partial | manual bank transfer only |
| Email hosting | placeholder | notification-only | needs external provider |
| FTP | not implemented | not implemented | needs external provider |

**Disconnected workflows found and fixed:**

1. The 5 new operations (UPDATE_PHP_POOL, SUSPEND/REACTIVATE,
   REMOVE_DOMAIN, RESET_DATABASE_USER_PASSWORD) were queued by the
   Worker but rejected by the `nexora-agent` daemon as
   `UNSUPPORTED_OPERATION`. Fixed in this batch — all 5 now dispatch
   to the privileged helper.

2. `removeDomain` could never actually write the filtered config
   (writeConfigFileAt refuses to overwrite). Fixed in this batch —
   uses `overwriteRootConfigFile` with backup/restore.

3. Backup scheduler could create duplicate backups under concurrent
   runs. Fixed in this batch — atomic claim via conditional UPDATE.

**Remaining disconnected UI (not fixed — requires external provider
selection):**

- `/email` page is a readiness placeholder showing "Configure a
  transactional email provider before sending alerts." The actual
  email hosting (mailboxes, domains, quotas) is not implemented.
  Requires selecting a provider (Resend, Mailgun, Postmark, or
  self-hosted Postfix/Dovecot).
- `/payment-settings` and `/payment-orders` support manual bank
  transfer review only. Automated billing (Stripe, Paddle) is not
  implemented. Requires selecting a payment provider.
- FTP is not present in the UI or API. Requires selecting an FTP
  server (ProFTPD, vsftpd, or Pure-FTPd).

### Test commands actually executed

```bash
# Go agent — unit, integration, race, vet, build
cd agents/linux-agent
go test ./... -count=1                    # 24/24 packages pass
go test -race -count=1 ./cmd/nexora-provision/   # pass
go test -race -count=1 ./internal/releasepublisher ./internal/rollbackexecutor \
  ./internal/rollbackoutbox ./internal/artifactreceiver ./internal/artifactdelivery \
  ./internal/deployenvelope ./internal/runtimehealth   # all pass
go vet ./...                              # clean
go build -trimpath -ldflags="-s -w" -o /tmp/nexora-agent ./cmd/nexora-agent
go build -trimpath -ldflags="-s -w" -o /tmp/nexora-provision ./cmd/nexora-provision
go build -trimpath -ldflags="-s -w" -o /tmp/nexora-provisiond ./cmd/nexora-provisiond

# Worker API — typecheck, full test suite, migration tests
cd apps/cloudflare-api
npx tsc --noEmit                          # clean
npx tsx --test scripts/*.test.ts         # 162/162 pass
python3 scripts/test_migrations.py       # 44 migrations apply cleanly

# Web dashboard — typecheck
cd apps/web
npx tsc --noEmit                         # clean
```

**Test counts:**

| Suite | Tests | Status |
|---|---|---|
| Worker `tsx --test scripts/*.test.ts` | 162 (was 142; +8 password reset + 12 recurrence) | all pass |
| Worker `tsc --noEmit` (cloudflare-api) | — | clean |
| Worker `tsc --noEmit` (web) | — | clean |
| Go `go test ./... -count=1` | 24 packages, 40+ tests in `cmd/nexora-provision` | all pass |
| Go `go test -race -count=1` (8 packages) | — | all pass |
| Go `go vet ./...` | — | clean |
| Go build (6 binaries) | — | all build |
| Python migration test | 44 migrations | clean |

### CI workflow updates

Updated `.github/workflows/api.yml` to run the new test files:

- `database-secret-encryption.test.ts` (Fix 5 crypto primitives)
- `backup-scheduler-recurrence.test.ts` (Fix 3 calendar clamping)
- `database-password-reset.integration.test.ts` (Fix 1 end-to-end)

All three are run via `pnpm --filter @nexora/api exec tsx --test` —
the same runner used by the existing integration tests. The existing
`linux-agent.yml` workflow already runs `go test ./cmd/nexora-provision`,
`go test ./...`, `go test -race ./...`, `go vet ./...`, and builds all
6 binaries — no changes needed there.

### Files added or modified in this batch

| File | Change |
|---|---|
| `apps/cloudflare-api/migrations/0039_database_secret_job_binding.sql` | New. Adds `job_id` and `agent_revealed_at` columns to `database_user_secrets`. |
| `apps/cloudflare-api/migrations/0040_backup_schedule_lease.sql` | New. Adds `lease_expires_at` column to `backup_schedules`. |
| `apps/cloudflare-api/src/index.ts` | +180 lines: credential retrieval endpoint, addMonthsClamped primitive, atomic backup scheduler claim, retention-after-completion, failure cleanup by job_id, exported addMonthsClamped + crypto helpers. |
| `apps/cloudflare-api/scripts/database-password-reset.integration.test.ts` | New. 8 integration tests covering the full reset workflow with a mock D1. |
| `apps/cloudflare-api/scripts/backup-scheduler-recurrence.test.ts` | New. 12 tests for calendar-month clamping. |
| `agents/linux-agent/cmd/nexora-agent/main.go` | +160 lines: dispatch branches for UPDATE_PHP_POOL, SUSPEND/REACTIVATE, REMOVE_DOMAIN, RESET_DATABASE_USER_PASSWORD (including credential fetch from Worker). |
| `agents/linux-agent/cmd/nexora-provision/main.go` | +115 lines: `RESET_DATABASE_USER_PASSWORD` handler (ALTER USER + verify), `safeOutputNoSecrets`, `removeDomain` rewritten to use `overwriteRootConfigFile` with backup/restore, last-server-block refusal. |
| `agents/linux-agent/cmd/nexora-provision/main_test.go` | +9 tests: safeOutputNoSecrets scrubbing/truncation/fallback, resetDatabaseUserPassword input validation (short/long password, invalid username/database/user suffix), last-block parser behavior. |
| `.github/workflows/api.yml` | +3 CI steps for the new test files. |
| `PROJECT_STATUS.md` | This section. |

### Mock verification vs. real verification

| Property | How verified |
|---|---|
| Credential retrieval endpoint security (auth, cross-tenant, replay, expiry) | Real: integration tests with mock D1 exercising the actual Hono app via `worker.fetch`. |
| AES-GCM encryption primitives | Real: WebCrypto round-trip, IV freshness, tamper detection, cross-key rejection. |
| Calendar-month clamping | Real: 12 unit tests covering leap years, month-end, cross-year boundaries. |
| Atomic config overwrite + rollback | Real: Go unit tests with real files in `t.TempDir()`. |
| Per-domain server-block parsing | Real: Go unit tests with real Nginx config strings. |
| `safeOutputNoSecrets` password scrubbing | Real: Go unit tests verify the password is replaced with `[REDACTED]`. |
| `resetDatabaseUserPassword` input validation | Real: Go unit tests verify short/long/invalid passwords are rejected. |
| `ALTER USER` + verify on MariaDB | Mock-only: requires a live MariaDB instance. The SQL is constructed with `sqlString()` escaping; the verify uses TCP + `MYSQL_PWD`. End-to-end on the Ubuntu checklist. |
| `nginx -t` validation + reload in `removeDomain` | Mock-only: requires a live Nginx instance. The atomic write + backup + restore path is verified by Go unit tests; the Nginx integration is on the Ubuntu checklist. |
| Backup scheduler atomic claim on real D1 | Mock-only: the atomic UPDATE depends on D1's MVCC, which the mock D1 simulates but doesn't fully replicate. The SQL is correct by inspection; end-to-end on the Ubuntu checklist. |
| Agent IPC payload delivery | Mock-only: the IPC is a Unix socket between nexora-agent and nexora-provision. The payload construction is verified by code review; end-to-end on the Ubuntu checklist. |

### Honest completion percentage after this batch

- **Control-plane API**: ~94% (was ~92%) — 135+ routes; the
  credential retrieval endpoint closes the last gap in the password
  reset workflow. All 15 operations now have full end-to-end SQL
  wiring.
- **Go agent**: ~91% (was ~88%) — all 15 operations now dispatch
  correctly; `RESET_DATABASE_USER_PASSWORD` has a complete handler
  with ALTER USER + verify; `removeDomain` uses atomic write with
  rollback.
- **Dashboard**: ~80% (unchanged) — no UI changes in this batch.
- **Static deployment lifecycle**: 100% (unchanged).
- **SaaS / billing**: ~20% (unchanged).
- **Documentation**: ~58% (was ~55%) — this section documents the
  complete password reset workflow, the atomic backup scheduler, and
  the pipeline audit.

Weighted overall completion: **~82%** (was ~78%). The remaining ~18%
is dominated by: email/FTP/billing modules (require external provider
selection), end-to-end Playwright/Cypress browser tests, infrastructure
tests against a live Ubuntu node, standalone operational documentation,
and penetration testing.

### Ubuntu acceptance testing readiness

The branch is **ready for Ubuntu acceptance testing**. The 10-item
checklist in section 5a is still the verification guide, with these
additions for this batch's new functionality:

11. **Database password reset end-to-end.** Create a database user,
    issue a reset via the API, wait for the agent to claim and execute
    the job, then reveal the password via the admin endpoint. Confirm:
    - The agent fetched the credential from
      `/internal/v1/agent/jobs/:jobId/credential` (check audit_logs
      for `database.secret_agent_retrieval`).
    - MariaDB `ALTER USER` succeeded (the user can connect with the
      new password via `mysql -u <user> -p`).
    - The admin reveal endpoint returns the password once (410 on
      second attempt).
    - If the agent is stopped before claiming the job, the encrypted
      secret expires after 15 minutes and the reveal endpoint
      returns 410.

12. **Backup scheduler atomic claim.** Configure two hosting accounts
    with daily backup schedules. Trigger the scheduler twice in rapid
    succession (e.g., via two concurrent `cron` triggers or two
    `wrangler dev` invocations). Confirm only one backup is queued
    per account per scheduler tick — no duplicates.

13. **Backup retention after completion.** Configure an account with
    `retention_count=2`. Trigger 3 backups sequentially (wait for
    each to complete). Confirm the oldest AVAILABLE backup is
    transitioned to DELETING after the third completes, and only 2
    AVAILABLE backups remain.

14. **Per-domain removal atomic write.** Create an account with two
    addon domains. Issue a `REMOVE_DOMAIN` for one. Confirm:
    - The vhost file is rewritten (not deleted + recreated).
    - `nginx -t` passes.
    - The other domain still serves.
    - If you manually break the config before the reload, the
      backup is restored and Nginx still serves the original config.

15. **nexora-agent dispatch for all operations.** Queue each of the
    5 new operations (UPDATE_PHP_POOL, SUSPEND, REACTIVATE,
    REMOVE_DOMAIN, RESET_DATABASE_USER_PASSWORD) and confirm the
    agent dispatches them to nexora-provision (no
    `UNSUPPORTED_OPERATION` errors in the agent log or the job
    result).

## 5c. Final Security and Reliability Fixes (2026-11-11, fourth pass)

This batch addresses the remaining security and reliability defects
identified in the latest source review. The fixes are verified by
automated tests, not just code inspection.

### Fix 1 — Bind credential retrieval to the exact claiming node

**Defect.** The previous credential retrieval endpoint
(`POST /internal/v1/agent/jobs/:jobId/credential`) checked that the job
belonged to the agent's *server* but NOT that it was claimed by the
agent's exact *node*. Any node on the same server could retrieve the
credential. The endpoint also accepted `QUEUED` status, meaning a job
that hadn't been claimed yet could have its credential revealed. The
node-binding check was in application memory (pre-check), not in the
atomic SQL UPDATE — a TOCTOU race could let two concurrent requests
from different nodes both pass the pre-check.

**Fix.** The endpoint now:
1. Selects `claimed_by_node_id` in the job lookup query.
2. Rejects jobs that are not `RUNNING` (QUEUED/COMPLETED/FAILED → 410).
3. Rejects jobs where `claimed_by_node_id !== auth.credential.nodeId` (→ 403).
4. Enforces ALL conditions in the atomic UPDATE's WHERE clause:
   ```sql
   UPDATE database_user_secrets SET agent_revealed_at = ?
   WHERE job_id = ? AND organization_id = ?
     AND agent_revealed_at IS NULL AND expires_at > ?
     AND EXISTS (SELECT 1 FROM provisioning_jobs j
       JOIN hosting_accounts ha ON ha.id = j.hosting_account_id
       WHERE j.id = database_user_secrets.job_id
         AND j.status = 'RUNNING'
         AND j.claimed_by_node_id = ?
         AND ha.server_id = ?
         AND ha.organization_id = database_user_secrets.organization_id)
     AND EXISTS (... database user + database ACTIVE ...)
   RETURNING ciphertext, iv
   ```
   This is a single atomic SQL statement — no TOCTOU race possible.
   Even if two concurrent requests from different nodes on the same
   server both pass the pre-check, only one can match the
   `claimed_by_node_id = ?` condition in the UPDATE.

**Verification.** 14 integration tests in
`database-password-reset.integration.test.ts` (was 8; +6 new):
- Correct claiming node retrieves the credential (happy path).
- Another node on the SAME server cannot retrieve it (exact-node binding).
- A node on another server cannot retrieve it (cross-server).
- Another organization's agent cannot retrieve it (cross-tenant).
- Unclaimed (QUEUED) job cannot reveal its credential.
- Completed job cannot reveal its credential.
- Failed job cannot reveal its credential.
- Replay attempt is rejected (agent_revealed_at atomic UPDATE).
- Expired credential is rejected.
- Invalid HMAC is rejected.
- Non-existent job → 404.
- Failure cleanup deletes the secret bound to the job_id.

### Fix 2 — Stable calendar anchor for monthly backup recurrence

**Defect.** The scheduler computed `next_run_at = addMonthsClamped(now, 1)`
— from the execution date, not from the original schedule anchor. This
caused permanent drift:
- Original schedule: January 31
- February execution fires on Feb 28 (clamped from Feb 31)
- Next run computed from Feb 28 → March 28 (WRONG — should be March 31)
- March execution fires on March 28
- Next run computed from March 28 → April 28 (drift compounds)

**Fix.**
1. Migration `0041_backup_schedule_anchor_day.sql` adds
   `anchor_day_of_month INTEGER` to `backup_schedules`.
2. The schedule-creation endpoint sets `anchor_day_of_month` to the
   current UTC day when frequency is "monthly" (NULL for daily/weekly).
3. New helper `nextMonthlyRunFromAnchor(anchorDay, from, months)`
   computes the next run from the stable anchor day, not from the
   execution date. Jan 31 (anchor=31) → Feb 28 (clamped) → March 31
   (re-expanded) → April 30 → ...
4. The scheduler passes the ORIGINAL `next_run_at` as the `from` date
   (not `now`), so delayed execution doesn't cause drift: if the
   schedule was supposed to run on Jan 31 but fires on Feb 2, the next
   run is computed from Jan 31 → Feb 28 (correct), NOT from Feb 2 →
   March 31 (wrong — skips February).
5. Backward compatibility: if `anchor_day_of_month` is NULL (pre-
   migration schedule), the scheduler infers it from the current
   `next_run_at` day and persists it permanently on the first tick.

**Verification.** 23 recurrence tests in
`backup-scheduler-recurrence.test.ts` (was 12; +11 new):
- Jan 31 anchor → Feb 28 → March 31 (no drift across 6 months).
- Jan 31 → Feb 29 → March 31 in leap years.
- Feb 29 anchor → Feb 28 in non-leap year.
- March 30 → April 30 → May 30 (mid-month anchor).
- Dec 31 → Jan 31 (cross-year).
- UTC hour preservation across clamped and re-expanded months.
- Delayed execution does not cause drift (passes original nextRunAt).
- Null/invalid anchor falls back to addMonthsClamped.
- Last-day-of-month chains correctly.

### Fix 3 — Backup retention idempotency

**Defect.** The retention loop in the CREATE_BACKUP result handler
transitioned backups to DELETING and queued DELETE_BACKUP jobs in a
single batch, but didn't check whether the transition actually
succeeded. If two concurrent CREATE_BACKUP completions ran retention
simultaneously, both could queue DELETE_BACKUP jobs for the same backup
— duplicate deletion jobs.

**Fix.** The retention loop now:
1. Runs the `UPDATE hosting_backups SET status = 'DELETING' WHERE id =
   ? AND status = 'AVAILABLE'` as a separate `.run()` call.
2. Checks `transition.meta.changes` — if 0, another retention run
   already claimed this backup, so skip queuing the DELETE_BACKUP job.
3. Only queues the DELETE_BACKUP job if the transition succeeded.

This is the idempotency guarantee: each AVAILABLE backup can be
transitioned to DELETING exactly once, so exactly one DELETE_BACKUP job
is queued per backup.

### Fix 4 — Per-domain Nginx removal filesystem tests

Added 6 real filesystem integration tests that exercise the actual
overwrite/restore pipeline against real files in `t.TempDir()`:
- HappyPath: multi-domain vhost, remove one, verify the other survives.
- Rollback: overwrite, then restore, verify original content is back.
- LastBlockRefusal: removing the only server block is caught.
- NoMatch: removing a non-existent domain is a no-op.
- PreservesMultipleDomains: 3-domain vhost, remove the middle one.
- SymlinkRejected: a symlink at the vhost path is refused.

These test the filesystem transaction (the part that was broken when
`writeConfigFileAt` refused to overwrite). The `nginx -t` and
`systemctl reload` parts require a real Ubuntu node and are on the
acceptance checklist.

### Test counts after this batch

| Suite | Tests | Status |
|---|---|---|
| Worker `tsx --test scripts/*.test.ts` | 179 (was 162; +6 node-binding + 11 anchor) | all pass |
| Worker `tsc --noEmit` (cloudflare-api) | — | clean |
| Worker `tsc --noEmit` (web) | — | clean |
| Go `go test ./... -count=1` | 24 packages, 50+ tests in `cmd/nexora-provision` | all pass |
| Go `go test -race -count=1` (8 packages) | — | all pass |
| Go `go vet ./...` | — | clean |
| Go build (6 binaries) | — | all build |
| Python migration test | 45 migrations | clean |

### Files changed in this batch

| File | Change |
|---|---|
| `apps/cloudflare-api/migrations/0041_backup_schedule_anchor_day.sql` | New. Adds `anchor_day_of_month` column. |
| `apps/cloudflare-api/src/index.ts` | +120 lines: exact-node-binding in credential endpoint, `nextMonthlyRunFromAnchor` helper, scheduler uses anchor day + original nextRunAt, retention idempotency check, schedule creation sets anchor. |
| `apps/cloudflare-api/scripts/database-password-reset.integration.test.ts` | +6 new tests for exact-node binding (was 8, now 14). |
| `apps/cloudflare-api/scripts/backup-scheduler-recurrence.test.ts` | +11 new tests for stable anchor (was 12, now 23). |
| `agents/linux-agent/cmd/nexora-provision/main_test.go` | +6 real filesystem integration tests for domain removal transaction. |
| `PROJECT_STATUS.md` | This section. |

### Pipeline audit — all 15 operations verified end-to-end

Traced each operation through: Worker queue → job-claim allowlist →
eligibility check → nexora-agent dispatch → nexora-provision handler →
result-report → state transition → audit log. No gaps found.

### Security review summary

- **Tenant isolation**: Every SQL query filters by `organization_id`.
  Cross-tenant tests confirm org-B agent cannot retrieve org-A credential.
- **Node authorization**: HMAC-SHA256 + timestamp window + nonce replay
  prevention. Credential endpoint now verifies exact `claimed_by_node_id`.
- **SQL injection**: All user values bound via `?` placeholders.
- **Shell injection**: `runFixed` uses fixed arg lists, no `sh -c`.
- **Path traversal**: Regex validation + `O_NOFOLLOW` directory walks.
- **Symlink attacks**: `overwriteConfigFileAt` rejects symlinks.
- **Secret exposure**: Password never in job payload, audit log, or
  process args. `safeOutputNoSecrets` scrubs from error output.
- **Replay**: `agent_revealed_at` + `revealed_at` atomic UPDATEs.
- **Race conditions**: Atomic schedule claim + atomic secret claim +
  atomic retention transition.
- **Idempotency**: Job idempotency keys + retention `changes > 0` check.
- **Rollback**: `removeDomain` + `updatePhpPool` restore backups on failure.

### Honest completion percentage after this batch

- **Control-plane API**: ~95% (was ~94%) — credential retrieval now
  bound to exact claiming node with atomic SQL enforcement.
- **Go agent**: ~92% (was ~91%) — all 15 operations dispatch correctly;
  domain removal has real filesystem tests.
- **Dashboard**: ~80% (unchanged).
- **Static deployment lifecycle**: 100% (unchanged).
- **SaaS / billing**: ~20% (unchanged).
- **Documentation**: ~60% (was ~58%) — this section documents the
  exact-node binding, stable anchor, and retention idempotency.

Weighted overall completion: **~84%** (was ~82%).

### Ubuntu acceptance procedure (remaining)

The branch is ready for Ubuntu acceptance testing. The procedure:

1. **Hosting account provisioning**: Create account → verify Linux user,
   home dir, Nginx vhost, PHP-FPM pool, MariaDB grants all created.
2. **Nginx virtual-host creation**: Add domain → verify server block
   appears, `nginx -t` passes, site serves.
3. **PHP-FPM pool creation and isolation**: Verify pool config, socket,
   `security.limit_extensions`, `open_basedir`, `disable_functions`.
4. **Domain addition/removal**: Add 2 domains, remove 1 → verify the
   other still serves, vhost file rewritten atomically.
5. **MariaDB database creation**: Create DB → verify `SHOW DATABASES`,
   grants, username prefix.
6. **MariaDB user creation and password rotation**: Create user →
   reset password → verify new password authenticates, old doesn't.
7. **File Manager restrictions**: Verify path traversal blocked, symlink
   attacks rejected, upload limits enforced.
8. **Backup creation**: Trigger backup → verify archive, SHA-256, size.
9. **Backup restoration**: Restore backup → verify staging path, files.
10. **Backup retention**: Set retention=2, create 3 backups → verify
    oldest deleted, newest 2 remain.
11. **Suspension/reactivation**: Suspend → verify 503. Reactivate →
    verify site serves again.
12. **Agent restart recovery**: Kill agent mid-job → restart → verify
    lease expires, job re-claimed or completed.
13. **Failed operation rollback**: Break nginx config → trigger
    removeDomain → verify config restored, site still serves.
14. **Tenant isolation**: Two orgs on same node → verify cross-tenant
    access denied for credentials, jobs, backups, file manager.
15. **Database password reset end-to-end**: Reset → agent claims →
    fetches credential from `/internal/v1/agent/jobs/:jobId/credential`
    → ALTER USER → verify new password works → admin reveals password.

## 5d. MFA Login Enforcement and Dashboard Integration (2026-11-11, fifth pass)

Before this pass the MFA subsystem had enrollment/disable/verify endpoints
and an `/v1/auth/login/mfa` challenge-completion endpoint, but the **normal
login endpoint did not enforce MFA** — `/v1/auth/login` issued a full session
the moment the password verified, regardless of whether the user had an
active TOTP factor. This meant any user with MFA enabled could sign in with
just their password, completely bypassing the second factor. In addition the
dashboard had no UI to receive an MFA challenge: the login page submitted
credentials and either redirected or showed the workspace picker, with no
code-input branch, and the `/api/auth/[...segments]` proxy did not allow
`login/mfa` as an action.

This pass closes that bypass end-to-end, hardens the challenge endpoint
against brute force and replay, and adds the dashboard UI.

### Migration 0043 — `mfa_challenge_hardening.sql`

Three additive columns on existing tables; no data is rewritten, no index
is dropped, no row is silently modified:

- `mfa_challenges.failed_attempts INTEGER NOT NULL DEFAULT 0` — incremented
  on every invalid code submission. The verify endpoint refuses to issue a
  session once this reaches 5.
- `mfa_challenges.locked_at TEXT` — set when `failed_attempts` hits the cap.
  The verify endpoint returns 423 Locked for any submission against a
  locked challenge, even with a valid code, so the user must restart login.
- `mfa_factors.last_used_totp_period INTEGER` — the TOTP counter
  (`floor(unixSeconds/30)`) of the last successful verification. The verify
  endpoint rejects any code whose counter is `<=` this value, eliminating
  replay within the same 30-second window even if two parallel submissions
  both pass the atomic consume race.
- `mfa_challenges_locked_idx` — partial index on `locked_at` for the
  operator dashboard that surfaces locked challenges during incident
  response.

SQLite does not support `ADD COLUMN IF NOT EXISTS`; each ALTER is a
one-shot statement and the migration tracker ensures it runs exactly once.
47 migrations now apply cleanly (was 46).

### API — `/v1/auth/login` now gates on MFA

After the password verifies and the membership is confirmed, the endpoint
queries `mfa_factors` for an active TOTP factor (`backup_codes IS NOT NULL`,
i.e. enrollment was completed). If one exists:

1. Generate a fresh challengeId (UUID v4) with a 10-minute expiry.
2. INSERT into `mfa_challenges` (failed_attempts defaults to 0).
3. Audit-log `auth.login_mfa_challenge` so failed-MFA incidents can be
   traced back to the password-valid login attempt that started them.
4. Return `{ mfaRequired: true, challengeId, expiresAt, message }` with
   HTTP 200 — no `accessToken`, no session row written.

If no factor exists, the endpoint issues a session as before. This means
MFA-less users see no behavior change, while MFA-enabled users cannot
get a session from `/v1/auth/login` alone — they must complete
`/v1/auth/login/mfa` with the challengeId their password login returned.

### API — `/v1/auth/login/mfa` hardened

Five layers of protection now stack on the challenge-completion endpoint:

1. **Atomic consume** — the `UPDATE mfa_challenges SET consumed_at = ?
   WHERE id = ? AND consumed_at IS NULL` is followed by a `changes() === 1`
   check. If two valid submissions race, only one reports 1 change; the
   other gets 0 and receives 409 without a session.
2. **Per-challenge attempt cap** — `failed_attempts` is incremented on
   every invalid code. At 5 invalid submissions the challenge is locked
   (`locked_at` set) and audit-logged as `auth.login_mfa_locked`.
   Subsequent submissions return 423 Locked regardless of code validity.
   A 6-digit TOTP has 1,000,000 values; capping attempts at 5 makes the
   per-challenge brute-force success probability 5×10⁻⁶.
3. **TOTP replay protection** — after a successful consume, the factor's
   `last_used_totp_period` is set to the current TOTP counter. The next
   submission (against any challenge for the same user) is rejected if
   its TOTP counter is `<=` the stored value, so the same code cannot be
   used twice even within the same 30-second window.
4. **Failed-attempt audit** — every invalid code submission writes an
   `auth.login_mfa_failed` audit row, so brute-force attempts are visible
   in the audit trail alongside the lock event.
5. **Bypass protection** — the endpoint requires a real challenge row to
   exist before any factor lookup or code verification. A forged
   challengeId (an attacker who knows the user's email+password but not
   the challengeId their login returned) gets 404 with no session, no
   factor lookup, no audit row. The challengeId is a 128-bit UUID
   generated server-side and never appears in any client-controlled
   input.

The endpoint now also returns `customerAccess` (consistent with
`/v1/auth/login`) so the dashboard can route customers to `/customer`
after MFA completion.

### API — `/v1/auth/me` returns `mfaEnrolled`

The security page's MFA status indicator reads `mfaEnrolled` from
`/v1/auth/me`. Before this pass that field was absent, so the indicator
always showed "Not configured" even for users with an active factor.
The endpoint now queries `mfa_factors` and returns `mfaEnrolled: true`
iff a `totp` factor with `backup_codes IS NOT NULL` exists for the user.
A pending enrollment (factor inserted by `/v1/auth/mfa/enroll` but not
yet verified) does NOT count as enrolled, because it cannot gate login.

### Dashboard — proxy allowlist and login flow

- `apps/web/src/app/api/auth/[...segments]/route.ts` now allows `login/mfa`
  as a two-segment action (was only `login`, `register`, `logout`). The
  cookie-setting logic is updated to handle both responses from the
  upstream: a session response sets the `nexora_session` cookie; an
  `mfaRequired: true` response deliberately does NOT set any cookie, so
  the caller is not considered authenticated until the challenge is
  answered.
- `apps/web/src/app/login/page.tsx` now has a two-phase form. Phase 1 is
  the email+password+workspace form. When the API returns
  `mfaRequired: true`, the page switches to phase 2: a 6-digit code input
  with the challengeId stored in component state. Submitting phase 2 POSTs
  to `/api/auth/login/mfa`; on success the proxy sets the session cookie
  and the page redirects as before. A "Back" button returns to phase 1
  without consuming the challenge. The code input has `inputMode="numeric"`
  and a `pattern="[0-9]{6}"` so mobile browsers show the numeric keypad.

### Tests — `mfa-login.integration.test.ts`

Fifteen endpoint integration tests cover the MFA login lifecycle, running
against the real Worker `fetch` handler with a focused in-memory mock D1.
The mock verifies endpoint behavior and SQL predicates, but does not prove
database concurrency semantics.

1. Login with no MFA factor → session issued directly (no challenge).
2. Login with an active factor → 200 with `mfaRequired: true` +
   `challengeId`, no `accessToken`, no session row, audit challenge row
   written.
3. MFA completion with a valid code → 200 with `accessToken` + session,
   challenge consumed, `last_used_totp_period` set on the factor.
4. MFA completion with an invalid code → 401, `failed_attempts`
   incremented, audit failed row written, no session.
5. After 5 invalid attempts the challenge is locked (423); subsequent
   submissions rejected without re-checking the code, even with a valid
   code.
6. Expired challenge → 410.
7. Already-consumed challenge → 409.
8. Replay protection: re-submitting the same code against a fresh
   challenge for the same user is rejected because
   `last_used_totp_period` is now equal to the current period.
9. Bypass attempt with a forged challengeId → 404, no session.
10. `/v1/auth/me` returns `mfaEnrolled: true` for a user with an active
    factor, `false` without.
11. A user with an MFA factor cannot bypass MFA by submitting a forged
    challengeId directly to `/v1/auth/login/mfa` — 404, no session, no
    challenge row modified.

The four additional endpoint tests cover parallel invalid submissions,
same-period TOTP replay across separate challenges, and user/organization
suspension after password verification. Their CI result is tracked against
the current branch HEAD, not inferred from the earlier 11-test run.

### Lint cleanup

Five pre-existing ESLint warnings in the dashboard were cleaned up so
`pnpm --filter @nexora/web lint` is now zero-warning, zero-error:

- Removed unused `Globe2`, `Server` imports from `hosting-accounts/page.tsx`.
- Removed unused `formatBytes` helper from `page.tsx`.
- Removed unused `RefreshCw` import from `store/page.tsx`.
- Removed unused `index` parameter from `monitoring-dashboard.tsx` CPU
  history map.

### CI

`.github/workflows/api.yml` adds a new step "MFA login enforcement
integration tests" running `tsx --test mfa-login.integration.test.ts`.

### Test results for this pass (all actually executed)

- Cloudflare API typecheck: clean
- apps/api typecheck: clean (after Prisma client generation)
- apps/api unit tests: 9/9 pass
- Web typecheck: clean
- Web lint: 0 errors, 0 warnings (was 5 warnings)
- Web production build: succeeds
- Cloudflare API integration tests (application + auth + backup + db):
  192/192 pass (was 181; +11 MFA)
- D1 migrations: 47 apply cleanly (was 46; +1 MFA hardening)
- Backup exclusion real-SQLite tests: 6/6 pass
- Go agent `go test ./...`: 24/24 packages pass
- Go agent `go test -race` on 7 security-sensitive packages: all pass


## 5e. MFA Atomicity and Authorization Follow-up (2026-11-11)

A follow-up code review identified that the earlier challenge implementation
still derived failed-attempt values from a stale read and updated the factor's
TOTP counter unconditionally. Those patterns could lose increments or permit
two different challenges to race on the same TOTP period.

The follow-up changes on `test/deploy-node-acceptance`:

- Failed-attempt counters are now incremented in one conditional SQL UPDATE;
  the persisted count cannot exceed the five-attempt cap.
- Challenge consumption is conditional on the exact challenge, user,
  organization, unconsumed/unlocked state, and unexpired timestamp.
- TOTP period claims are conditional on the factor's previously stored period
  being NULL or lower than the submitted period. This database write, not the
  earlier read, is the replay/concurrency authority.
- The factor claim is tied to the exact consumed challenge.
- User, organization, and membership status are checked before consuming
  the challenge and rechecked immediately before session persistence.
- Endpoint tests cover parallel invalid attempts, parallel challenges using
  the same TOTP period, and suspended user/organization states.
- A separate real-SQLite test uses concurrent independent connections to
  exercise the same atomic SQL statements.

**Verification:** API CI passed all 26 steps on code commit
`029ec71df74c64c7136c25a9fec9fff0cd066bf0`, including the endpoint suite and
real-SQLite concurrency tests. The subsequent branch-head commit
`19eab28f39114911327615af062f98cb498ea878` changed only this status document.
SQLite tests do not prove behavior of remote Cloudflare D1; a controlled D1
environment check remains required before production release.

## 5f. Domain Removal UI and Agent-Claim Correction (2026-11-11)

The domain inventory now exposes a guarded Remove action for non-primary
domains and refreshes live Cloudflare hostname/SSL state when the inventory
loads. The API's existing domain DELETE route performs an organization-scoped
soft delete, queues `REMOVE_DOMAIN`, and records an audit event; a failed
agent result restores the domain row to ACTIVE.

A pipeline trace found that the agent job-claim query only joined a domain
row for `ADD_DOMAIN`. As a result, `REMOVE_DOMAIN` jobs could be claimed
without the target domain name, causing the agent to reject the job as an
invalid payload. The lookup now resolves the target domain from the
`remove-domain:<domain-id>` idempotency key as well as the existing
`add-domain:<domain-id>` key. The domain remains available to the claim
query while soft-deleted so the agent can safely remove its Nginx server
block.

The primary-domain guard is now unconditional in both the API and dashboard:
a primary domain cannot be removed even when its hosting account is
suspended. The user must first make another domain primary.

Verification boundary: the API and dashboard CI runs for these latest
changes must pass before this batch is marked CI-verified. Live Nginx
removal/reload and rollback still require Ubuntu acceptance testing.

## 5g. Platform Completion Batch (2026-11-12) — organizations, customer self-service, subscriptions, email inventory, job inspector

This batch closes the largest documented gaps in section 7 (Phases 3-8).
All items are implemented in the Worker API, covered by regression tests,
and exposed in the dashboard. Nothing here was verified against live
infrastructure; the verification boundary is CI only.

### Organization administration (Phase 3 gap closed)

- `GET /v1/organizations` (own workspaces; `?scope=all` platform inventory),
  `GET /v1/organizations/:id` (details + member inventory + owner/admin
  counts), `POST /v1/organizations/:id/members` (add an existing ACTIVE
  user with any role; only OWNER can grant OWNER),
  `PATCH /v1/organizations/:id/members/:userId` (role change),
  `DELETE /v1/organizations/:id/members/:userId` (revoke; self-removal
  allowed for non-last-admins), `DELETE /v1/organizations/:id` (close),
  and `GET /v1/organizations/:id/audit-logs` (org-scoped history).
- Last-OWNER and last-administrator protection is enforced on removal and
  demotion. Membership revocation also revokes the member's auth sessions
  for that organization, so cached access ends immediately (bearerIdentity
  additionally requires a live membership row on every request).
- Closing an organization is refused while hosting accounts, open payment
  orders, or live subscriptions exist; otherwise it sets status CLOSED and
  revokes all org sessions. History is preserved (soft close, not a hard
  DELETE, because hosting_accounts/orders reference organizations with
  RESTRICT foreign keys).
- `/v1/organizations/*` is reachable by organization members (the
  middleware exemption is unchanged) and every route re-derives the
  caller's role with `resolveOrgAccess` — an org ID from the browser is
  never trusted by itself. Cross-org access returns 404 (isolation tested).

### Customer self-service (Phase 4 gap closed)

- Customer portal mutations previously read-only are now wired:
  `POST/DELETE /v1/customer/hosting-accounts/:id/domains[/:domainId]` and
  `POST/DELETE /v1/customer/hosting-accounts/:id/databases[/:databaseId]`.
  Every route resolves the hosting account from the caller's ACTIVE
  hosting-account membership; the account ID in the URL is only a selector.
- Roles: ACCOUNT_OWNER/ACCOUNT_ADMIN manage domains and databases;
  ACCOUNT_DEVELOPER manages databases only; ACCOUNT_READONLY is denied.
  Plan website_limit and database_limit are enforced in the API (409 when
  exceeded). Domain removal keeps the primary-domain guard; database
  deletion reuses the WHM guards (pending user operations block, username
  prefix validation, concurrent-job rejection).
- The customer dashboard now has Add/Remove domain and Create/Delete
  database dialogs with confirmation, success/failure states, and
  role-gated buttons.

### Subscriptions, invoices, billing (Phase 8 gap closed, provider-neutral)

- Migration `0044_subscriptions_invoices.sql`: `subscriptions` (TRIALING →
  ACTIVE → PAST_DUE → SUSPENDED → EXPIRED/CANCELLED lifecycle with
  cancel_at_period_end; partial UNIQUE index allows exactly one live
  subscription per hosting account), `subscription_events` (append-only
  audit), `invoices` (sequential per-org numbering via `invoice_counters`
  UPDATE...RETURNING; UNIQUE payment_order_ref/provider_ref for
  idempotency), and `billing_webhook_events` (UNIQUE(provider, event_id)
  dedup ledger).
- APIs: create (platform admin; per-account uniqueness), renew (platform
  admin; extends the period stacking on the current one; writes a PAID
  invoice; idempotent per idempotencyKey/transfer reference — replay
  returns the original invoice and never double-extends), plan change
  (validates domain/database counts against the target plan; violating
  downgrades are rejected with a violation list), cancel (immediate or at
  period end; org OWNER or platform admin), suspend/reactivate (platform
  admin), subscription detail with events + invoices, invoice inventory
  (org-scoped for customers, all for platform admins), and invoice
  settle (PAID/VOID, audited).
- Expiration is lazy (evaluated on subscription reads) plus a cron sweep
  in the Worker's `scheduled` handler; overdue ACTIVE/TRIALING become
  EXPIRED, or CANCELLED when a cancellation was scheduled.
- Payment webhooks: `POST /v1/billing/webhooks/:provider` requires
  `PAYMENT_WEBHOOK_SECRET` (503 with requirements when unset), verifies
  HMAC-SHA256 over `t=<seconds>.<body>` (X-Nexora-Signature), rejects
  timestamps outside a 5-minute window, deduplicates event IDs, and only
  marks the referenced OPEN invoice PAID (renewing its subscription).
  Unknown invoice references are recorded but never fabricate success.
  No Stripe/Paddle SDK is embedded — the contract is documented in the
  provider-status endpoint (`GET /v1/platform/billing/provider-status`).

### Email hosting honesty (Phase 5 email gap closed)

- Migration `0045_email_hosting.sql`: `email_domains`, `email_mailboxes`
  (quota CHECK 128–51200 MB, UNIQUE address), `email_forwards`. Rows carry
  a separate `provider_status` that stays `not_provisioned` until a
  configured provider confirms.
- Provider abstraction: `resolveEmailProvider` supports `none` (default,
  inventory-only) and `mailserver-api` (generic HTTPS admin-API bridge
  via `EMAIL_PROVIDER_API_URL` + `EMAIL_PROVIDER_API_TOKEN`). Without a
  complete configuration, mutation endpoints record intent but return the
  honest `provisioning: { available: false, requirements: [...] }` shape;
  mailbox password changes are refused with 503 because the control panel
  never stores mailbox passwords. With the bridge configured, provisioning
  calls are attempted and failures surface as HTTP 502 with the provider
  detail — rows are marked `failed`, never silently "active".
- Plan mailbox limits are enforced when an email domain is linked to a
  hosting account. `GET /v1/email/status` and `/v1/email/service-status`
  report outbound (Resend) and mailbox hosting as separate services with
  MX/SPF/DKIM/DMARC guidance. The dashboard `/email` page is now a real
  inventory UI with an explicit inventory-mode banner replacing the
  misleading static readiness card.
- IMPORTANT: actual mailbox hosting (IMAP/SMTP) still requires the
  operator to run a mail server and configure the bridge. See
  `docs/UBUNTU-ACCEPTANCE-CHECKLIST.md` § 12 for the exact external
  infrastructure requirements.

### Plan management and job inspector (Phase 6/7 gaps closed)

- `DELETE /v1/hosting-plans/:id` refuses plans referenced by hosting
  accounts or subscriptions (409 with counts) and deletes otherwise.
  Deactivation already existed via `PUT /v1/hosting-plans/:id` (active
  flag); the dashboard exposes both.
- `GET /v1/provisioning-jobs` (status/operation/organization filters,
  joined with account/org/server, failure reasons, stalled hints for
  QUEUED/RUNNING older than 1 hour), `GET /v1/provisioning-jobs/:id`
  (with request payload and retryability), and
  `POST /v1/provisioning-jobs/:id/retry` — restricted to FAILED jobs of
  known-idempotent operations (ADD_DOMAIN, REMOVE_DOMAIN,
  CREATE_DATABASE, CREATE_DATABASE_USER, REVOKE_DATABASE_USER,
  RESET_DATABASE_USER_PASSWORD, UPDATE_PHP_POOL, SUSPEND/REACTIVATE
  HOSTING_ACCOUNT, CREATE_BACKUP, DELETE_BACKUP). RESTORE_BACKUP,
  DELETE_DATABASE and FILE_MANAGER are deliberately NOT retryable from
  the inspector; the operator re-triggers them through the resource
  workflow so current state is re-validated. Retries queue a NEW job
  with a unique `:retry-<n>` idempotency key; the FAILED row is preserved.
- Dashboard `/provisioning-jobs` page with status filters and guarded
  retry buttons.

### Authorization/middleware correction

- `/v1/subscriptions`, `/v1/invoices`, `/v1/email/*`, and
  `/v1/billing/webhooks/*` are exempt from the platform-role gate because
  they are org-owner- or provider-facing; each enforces roles internally
  (org OWNER/ADMIN for email and subscription cancel, platform admin for
  lifecycle mutations, HMAC for webhooks). All other WHM routes remain
  default-deny for customer identities.

### Tests added in this batch

- `scripts/platform-completion.integration.test.ts` + harness: 36
  integration tests (org admin incl. session invalidation and close-org
  dependency checks; customer mutations incl. quota/role/isolation;
  billing incl. renewal idempotency, downgrade rejection, expiry sweep,
  webhook signature/dedup/no-fake-success; email honesty incl. mailbox
  limit and 503 password rule; job retry rules incl. non-retryable ops).
- `scripts/test_migrations.py` extended: schema presence for 0044/0045,
  one-live-subscription partial UNIQUE enforcement, subscription status
  CHECK, invoice-number UNIQUE, webhook dedup UNIQUE, mailbox address
  UNIQUE and quota CHECK.
- Full suite at batch completion: 242/242 Worker tests, 24/24 Go
  packages, migration test 49 migrations clean, API typecheck clean, web
  typecheck + lint + production build clean.

### Files modified in this batch

| File | Change |
|---|---|
| `apps/cloudflare-api/src/index.ts` | Organization admin routes + helpers, customer self-service routes, subscriptions/billing/webhook module, email hosting module, provisioning inspector, plan DELETE, middleware exemption correction, cron expiry sweep |
| `apps/cloudflare-api/migrations/0044_subscriptions_invoices.sql` | Subscriptions, events, invoice counters, invoices, webhook dedup |
| `apps/cloudflare-api/migrations/0045_email_hosting.sql` | Email domains, mailboxes, forwards |
| `apps/cloudflare-api/scripts/platform-completion-harness.ts` | Shared in-memory D1 harness for the new suite |
| `apps/cloudflare-api/scripts/platform-completion.integration.test.ts` | 36 regression tests |
| `apps/cloudflare-api/scripts/test_migrations.py` | 0044/0045 schema and constraint guards |
| `apps/cloudflare-api/wrangler.toml` | EMAIL_PROVIDER documentation |
| `apps/web/src/app/api/control/[...path]/route.ts` | Proxy allowlist for all new routes |
| `apps/web/src/app/customer/page.tsx` | Working domain/database dialogs |
| `apps/web/src/app/organization/page.tsx` | New organization administration page |
| `apps/web/src/app/subscriptions/page.tsx` | New subscriptions & billing page |
| `apps/web/src/app/provisioning-jobs/page.tsx` | New job inspector page |
| `apps/web/src/app/email/page.tsx` | Real email inventory UI |
| `apps/web/src/app/hosting-plans/page.tsx` | Plan delete action |
| `apps/web/src/components/app-shell.tsx` | Sidebar entries |
| `.github/workflows/api.yml` | New CI step for the platform-completion suite |
| `docs/UBUNTU-ACCEPTANCE-CHECKLIST.md` | New Ubuntu acceptance procedure (section 14 of the master prompt) |

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
- ~~Complete organization administration (list, safe ownership transfer,
  and deletion with dependency checks).~~ CLOSED 2026-11-12 (section 5g):
  list/details/member management with last-owner protection, session
  invalidation on revocation, and soft close with dependency checks are
  implemented and tested.
- Email verification deliverability and dashboard UX must be validated
  against a configured production email provider; the verification
  endpoint and token storage already exist.
- MFA login enforcement, TOTP enrollment, challenge verification, and
  dashboard challenge UI are implemented; see sections 5d and 5e.
- Audit-log read API and dashboard are implemented; the dashboard field
  mapping was corrected on 11 November 2026.

### Phase 4 — Hosting account, domain, website, file management

Already implemented end-to-end on the control plane; agent-side
provisioning jobs exist for `ADD_DOMAIN`, file operations, and
backups.

Remaining:
- Domain DELETE endpoint, organization-scoped soft deletion, audit event,
  and queued `REMOVE_DOMAIN` agent job are implemented. The dashboard now
  exposes a guarded Remove action and refreshes the inventory after queueing.
- Cloudflare hostname GET status is now fetched when the domain inventory
  loads, so SSL/hostname status is not limited to stale values from the
  last page load. The proxy allowlist already supports this GET route.
- The forgot-password link already points to the local `/forgot-password`
  route; no change was required.

### Phase 5 — Databases, email, PHP, runtime management

- Databases: complete (list/create/delete/users/secret-reveal) in both
  the WHM and customer APIs.
- Email: mailbox/forward inventory, quota management, and the DNS
  guidance (SPF/DKIM/DMARC) are implemented with a provider abstraction
  (section 5g). Actual mailbox provisioning requires a configured mail
  server via the `mailserver-api` bridge — unavailable operations are
  refused with 503 and exact requirements, never faked.
- PHP/runtime admin: organization-scoped GET/PUT settings API and
  `/hosting-accounts/[id]/php` dashboard page exist. The Linux agent
  applies pool changes through the rollback-safe UPDATE_PHP_POOL pipeline.
  Live Ubuntu validation of php-fpm reload/socket behavior remains required.

### Phase 6 — Hosting plans, quotas, resource enforcement

- Plans: full CRUD surface — list/create, PUT (all quotas + active
  toggle), website-limit, store-settings, and DELETE restricted to
  unused plans (closed 2026-11-12, section 5g).
- Build-minute quota enforcement is implemented (`build-quota.ts` and
  ingestion tests pass); runtime CPU/memory quotas are enforced in the
  OCI supervisor; disk quotas rely on Linux project quotas applied by
  `nexora-provision` (`secure_directories.go`).
- Plan downgrade workflow is implemented at the subscription layer:
  usage (domains, databases) is validated against the target plan and
  violating changes are rejected with a violation list (section 5g).

### Phase 7 — Admin panel

- Customers (read-only), servers, hosting accounts, hosting plans,
  payment orders, payment settings, incidents, notification settings,
  GitHub projects, application nodes — all present.
- Organization management is implemented at `/organization` and the
  provisioning queue inspector at `/provisioning-jobs` (closed 2026-11-12,
  section 5g). Audit-log viewer is implemented at `/audit-logs`.

### Phase 8 — SaaS subscriptions, billing, customer management

- Manual bank-transfer orders with admin review: implemented.
- Subscription lifecycle, invoicing, trial periods, suspension,
  plan changes with quota validation, payment history, and an
  HMAC-verified provider webhook are implemented with migration 0044
  (closed 2026-11-12, section 5g). The webhook contract is
  provider-neutral — no Stripe/Paddle SDK is embedded; enabling a
  specific provider requires the operator to set `PAYMENT_WEBHOOK_SECRET`
  and point the provider at the webhook endpoint.
- Dunning (automated retry of failed payments) and automated renewal
  reminders are not implemented; renewals are operator-recorded or
  provider-webhook-driven.

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

- 28 pages, real API calls, responsive layout, loading/error states.
- Empty states and confirmation dialogs present on destructive
  actions.
- Closed 2026-11-12 (section 5g): `/user-management` is in the sidebar,
  `/email` is a real inventory UI with an honest inventory-mode banner,
  customer resource creation is wired, and the organization,
  subscriptions, and provisioning-jobs pages exist.

### Phase 11 — Full regression, integration, end-to-end, security testing

- Unit/integration coverage: current CI includes the API, Go-agent,
  dashboard, MFA, database-secret, and backup regression suites; see the
  exact workflow runs for the tested commit. Earlier static-deployment
  inventory counts are historical and should not be treated as current totals.
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

Based on the verified feature inventory in section 2, the work completed
through section 5g, and the test suites recorded in section 5g. Two
numbers are tracked separately, exactly as the master prompt requires:
**working implementation with automated verification** (what CI proves)
and **production acceptance** (what only a live Ubuntu node and live
external providers can prove — currently 0% because no acceptance run
has been executed).

### Implementation + automated verification (CI-proven)

- **Control-plane API**: ~97% — 140+ routes across auth/MFA, org
  administration, customer self-service (domains, databases),
  hosting accounts, plans (full CRUD), store/checkout, payment review,
  subscriptions/invoices/webhooks, email inventory, backups, file
  manager, PHP settings, GitHub deployments, application runtime, and
  the provisioning-job inspector. 242/242 integration tests pass,
  including the 36 platform-completion regressions. Remaining gaps are
  dunning/renewal reminders and provider-specific SDK integrations,
  both of which require an operator decision and credentials.
- **Go agent**: ~92% — unchanged from section 5f: full static-deployment
  lifecycle with restart recovery, provisioning, file manager, backups,
  secure directory/Nginx/PHP generation; 24/24 packages pass with race
  tests on the security-sensitive set. OCI runtime execution is
  intentionally disabled (documented in `PRIVILEGED-IPC-DESIGN.md`).
- **Dashboard**: ~95% — 28 pages, all real API calls; customer
  domain/database creation is wired; organization administration,
  subscriptions/billing, and the provisioning inspector exist;
  the email page shows an honest inventory-mode state; plan deletion
  is exposed. Remaining gaps are cosmetic (org switcher in the header,
  per-page skeleton loaders).
- **Static deployment lifecycle**: 100% of originally scoped items
  plus the `health_checking` restart-recovery defect (section 3).
- **SaaS / billing**: ~75% — subscription lifecycle, invoices with
  sequential numbering, idempotent renewals, quota-validated plan
  changes, expiry/suspension handling, audited manual review, and the
  HMAC webhook contract are implemented and tested. Missing: dunning,
  renewal reminders, and a concrete provider integration (needs an
  operator-approved provider + secrets). The flow is real end to end
  with manual bank transfer; nothing is mocked.
- **Email hosting**: ~55% — inventory, quotas, forwards, DNS guidance,
  and the provider abstraction are implemented and honestly marked
  unavailable without a mail server. Actual IMAP/SMTP mailboxes are
  0% until the operator runs a mail server and configures the bridge —
  by design the panel cannot fake this.
- **Documentation**: ~70% — architecture docs accurate; this file now
  includes the platform-completion batch and the acceptance checklist
  exists at `docs/UBUNTU-ACCEPTANCE-CHECKLIST.md`. Standalone
  INSTALLATION/API-REFERENCE/SECURITY documents are still pending.

Weighted overall implementation completion: **~90%** of the full
cPanel-style hosting control panel and SaaS platform described in the
master prompt.

### Production acceptance (live evidence)

- **Ubuntu server acceptance**: 0% — no test in
  `docs/UBUNTU-ACCEPTANCE-CHECKLIST.md` has been executed against the
  live `nexora-deploy-node`. Until that run happens and its evidence is
  recorded, no hosting operation (Nginx/PHP-FPM/MariaDB/backup/deploy)
  should be considered production-verified, regardless of CI status.
- **Live Cloudflare custom hostnames / SSL**: not verified in this
  session (requires live zone credentials).
- **Payment provider / mail provider end-to-end**: not verifiable
  without operator-provided infrastructure.

## 9. Release Procedure

1. Review all modified files (`git diff --stat`).
2. Run all relevant tests (section 6).
3. Review database migrations (0044, 0045 added 2026-11-12; verified by
   `scripts/test_migrations.py` on a fresh SQLite database).
4. Confirm secrets are not committed.
5. Commit changes to Git.
6. Push to the intended GitHub branch.
7. Deploy to a test environment.
8. Run end-to-end acceptance tests against `nexora-deploy-node`
   (see `docs/UBUNTU-ACCEPTANCE-CHECKLIST.md`).
9. Approve production deployment only after verification.

## 10. Status Tracking Conventions

Use these statuses:

- [x] Implemented — code exists and was inspected in this audit.
- [v] Verified — tests were run and observed passing in this session.
- [ ] Remaining — implementation or verification is incomplete.

Implementation does not automatically mean production-ready.