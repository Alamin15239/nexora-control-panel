# Nexora Control Panel — Operations Runbook

This runbook covers installation, upgrade, rollback, backup, and recovery
procedures for the Nexora Control Panel production deployment. It is
intended for platform operators who have already completed the
[Ubuntu static-deployment-node setup](./static-deployment-node-setup.md)
and the [Cloudflare Tunnel node setup](../cloudflare-tunnel-node.md).

## 1. Architecture recap

| Layer | Technology | Deployment target |
|---|---|---|
| Control-plane API | Cloudflare Workers + Hono | Cloudflare Workers (single worker) |
| Application database | Cloudflare D1 | Cloudflare edge (region-replicated) |
| Artifact storage | Cloudflare R2 | Cloudflare edge |
| Dashboard | Next.js 16 on Cloudflare Pages | Cloudflare Pages |
| Hosting workloads | Ubuntu 22.04 + Nginx + PHP-FPM + MariaDB | Operator-managed VMs |
| Linux agent | Go binaries (nexora-agent, nexora-provision, nexora-provisiond, nexora-static-publisher, nexora-static-vhostd, nexora-runtime-node, nexora-ipc-check) | Operator-managed VMs |
| Connectivity | Cloudflare Tunnel | Operator-managed VMs |

The control plane (API + D1 + R2 + dashboard) is entirely on
Cloudflare's managed edge. The hosting workloads run on operator VMs and
are managed by the Go agent, which connects to the API over Cloudflare
Tunnel. There is no direct inbound network path to any hosting VM — all
traffic flows through Cloudflare.

## 2. Installation

### 2.1 Control plane (one-time)

```bash
# From the repository root.
cd apps/cloudflare-api

# 1. Install dependencies.
pnpm install --frozen-lockfile

# 2. Create the D1 database (one-time).
npx wrangler d1 create nexora-production
# Copy the database_id from the output into wrangler.toml.

# 3. Apply migrations to the production D1.
npx wrangler d1 migrations apply nexora-production --remote

# 4. Set the required secrets.
npx wrangler secret put DATABASE_SECRET_ENCRYPTION_KEY  # 32-byte hex
npx wrangler secret put MFA_ENCRYPTION_KEY               # 32-byte hex
npx wrangler secret put SESSION_SECRET                   # random 64+ chars
# Plus any of the optional secrets listed in .env.example.

# 5. Deploy the Worker.
npx wrangler deploy

# 6. Note the deployed Worker URL. Configure the dashboard to use it
#    via the NEXORA_API_URL environment variable (or the NEXORA_API
#    service binding if deploying the dashboard to the same Cloudflare
#    account).
```

### 2.2 Dashboard (one-time)

```bash
cd apps/web

# The dashboard reads NEXORA_API_URL at build time for the fallback API
# base URL. In production the /api/control/[...path] proxy prefers the
# NEXORA_API service binding, so NEXORA_API_URL is only used for
# local development.
NEXORA_API_URL="https://api.nexoraedge.digital" pnpm build

# Deploy to Cloudflare Pages via the dashboard or wrangler.
npx wrangler pages deploy . --project-name nexora-dashboard
```

### 2.3 Hosting VM (per server)

Follow the full procedure in
[`docs/operations/static-deployment-node-setup.md`](./static-deployment-node-setup.md).
In summary:

1. Provision an Ubuntu 22.04 VM with SSH access.
2. Install Nginx, PHP-FPM, MariaDB, and the Go agent binaries.
3. Generate an Ed25519 keypair for the agent and register the public key
   with the control plane via `POST /v1/servers` +
   `POST /v1/servers/:id/enrollment-token` + agent enrollment.
4. Configure the Cloudflare Tunnel.
5. Start `nexora-agent`, `nexora-provisiond`, `nexora-static-publisher`,
   `nexora-static-vhostd` as systemd services.

## 3. Upgrade

### 3.1 Control-plane API upgrade

```bash
cd apps/cloudflare-api

# 1. Pull the new code.
git pull --ff-only origin test/deploy-node-acceptance

# 2. Apply any new migrations. D1 migrations are forward-only; each
#    migration is wrapped in its own transaction and the migration
#    tracker records applied migrations, so re-running is safe.
npx wrangler d1 migrations apply nexora-production --remote

# 3. Deploy the Worker. Cloudflare Workers deployment is atomic — the
#    new version becomes active within seconds and old in-flight
#    requests drain gracefully.
npx wrangler deploy

# 4. Verify the health endpoints.
curl https://api.nexoraedge.digital/v1/health
curl https://api.nexoraedge.digital/v1/health/ready
curl https://api.nexoraedge.digital/v1/health/schema
```

If any migration fails, the worker is NOT deployed (the
`migrations apply` command exits non-zero and the deployment script
halts). The database is left in its pre-migration state for the failing
migration only; previously applied migrations remain applied.

### 3.2 Dashboard upgrade

```bash
cd apps/web
git pull --ff-only origin test/deploy-node-acceptance
pnpm install --frozen-lockfile
NEXORA_API_URL="https://api.nexoraedge.digital" pnpm build
npx wrangler pages deploy . --project-name nexora-dashboard
```

Cloudflare Pages deployment is atomic via immutable deployment
candidates. The previous deployment remains reachable until the new one
is promoted, so there is no downtime.

### 3.3 Hosting VM agent upgrade

```bash
# On each hosting VM, as the nexora service user:
cd /opt/nexora/linux-agent
git pull --ff-only origin test/deploy-node-acceptance

# Build the new binaries (or download the pre-built release artifacts).
go build -o /usr/local/bin/nexora-agent        ./cmd/nexora-agent
go build -o /usr/local/bin/nexora-provision    ./cmd/nexora-provision
go build -o /usr/local/bin/nexora-provisiond   ./cmd/nexora-provisiond
go build -o /usr/local/bin/nexora-static-publisher ./cmd/nexora-static-publisher
go build -o /usr/local/bin/nexora-static-vhostd    ./cmd/nexora-static-vhostd

# Restart the systemd services. The agent drains in-flight requests
# before exiting; provisiond checkpoints its rollback outbox so pending
# rollbacks resume after restart.
sudo systemctl restart nexora-agent nexora-provisiond \
                     nexora-static-publisher nexora-static-vhostd

# Verify enrollment is still valid (heartbeat reaches the API).
curl -s http://localhost:9100/healthz
```

For a rolling upgrade across multiple hosting VMs, upgrade one VM at a
time and verify the next heartbeat reaches `/v1/agent/heartbeat` before
proceeding to the next VM.

## 4. Rollback

### 4.1 Control-plane API rollback

Cloudflare Workers supports instant rollback to the previous deployment
via the dashboard or wrangler:

```bash
# List recent deployments.
npx wrangler deployments list

# Roll back to the previous version.
npx wrangler deployments rollback
```

**Database rollback is NOT supported.** D1 migrations are forward-only
by design. Every migration in `apps/cloudflare-api/migrations/` is
additive (CREATE TABLE, ALTER TABLE ADD COLUMN, CREATE INDEX) and never
destroys data, so a forward roll is always safe. If a migration is
defective, the fix is a new forward migration that corrects the schema,
not a rollback.

### 4.2 Dashboard rollback

Cloudflare Pages retains all previous deployments. From the Pages
dashboard in the Cloudflare UI, select the previous deployment and
promote it. The switch is atomic.

### 4.3 Hosting VM agent rollback

```bash
cd /opt/nexora/linux-agent
git checkout <previous-commit-sha>
go build -o /usr/local/bin/nexora-agent ./cmd/nexora-agent
# (rebuild the other binaries as needed)
sudo systemctl restart nexora-agent
```

If a release was activated with a bad artifact, use the platform's
compare-and-switch rollback from the dashboard or API:
`POST /v1/applications/releases/:id/rollback`. The rollback executor on
the agent restores the previous release atomically with advisory locking
and stale-state protection; the rollback outbox persists the intent so
the rollback completes even if the agent restarts mid-rollback.

## 5. Backup

### 5.1 Application database (D1)

D1 is region-replicated and snapshot-backed by Cloudflare. To take an
on-demand backup:

```bash
# Export the database to a local SQLite file.
npx wrangler d1 export nexora-production --remote --output=nexora-$(date +%Y%m%d-%H%M%S).sql

# Store the export in R2 or any durable storage.
npx wrangler r2 object put nexora-backups/nexora-$(date +%Y%m%d-%H%M%S).sql \
  --file=nexora-$(date +%Y%m%d-%H%M%S).sql
```

Schedule this via cron on any operator machine with wrangler
credentials. A daily backup is recommended; the export is a full
logical dump (no incremental backups).

### 5.2 Hosting account backups

Each hosting account has an automated backup schedule managed by the
control plane. The scheduler runs every minute as a cron trigger on the
Worker, claims due schedules with an atomic lease, and queues a
`CREATE_BACKUP` provisioning job on the assigned hosting VM.

The schedule is configurable per hosting account via
`PUT /v1/hosting-accounts/:id/backup-schedule` with:
- `enabled: boolean`
- `frequency: 'daily' | 'weekly' | 'monthly'`
- `anchorDayOfMonth: number` (1–28, for monthly schedules; stable
  calendar anchor prevents drift — Jan 31 → Feb 28 → Mar 31, not Mar 28)
- `retentionDays: number` (1–90)
- `hourOfDay: number` (0–23, UTC)

Backups are stored on the hosting VM under
`/var/backups/nexora/<username>/` and are subject to the retention
policy: when a new backup completes, backups older than
`retentionDays` are queued for `DELETE_BACKUP` deletion. The deletion is
idempotent — the retention sweeper first transitions the row to
`DELETING` with an atomic `UPDATE ... WHERE status='AVAILABLE'` and only
queues the delete job if `changes > 0`, so concurrent sweeps cannot
delete the same backup twice.

### 5.3 Restore

Restoring a hosting account from a backup is a control-plane operation:

```bash
# 1. List backups for the account.
curl -H "Authorization: Bearer $TOKEN" \
  https://api.nexoraedge.digital/v1/hosting-accounts/$ACCOUNT_ID/backups

# 2. Trigger a restore. This queues a RESTORE_BACKUP provisioning job.
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://api.nexoraedge.digital/v1/backups/$BACKUP_ID/restore

# 3. Monitor the job status.
curl -H "Authorization: Bearer $TOKEN" \
  https://api.nexoraedge.digital/v1/agent/jobs/$JOB_ID/result
```

The restore job extracts the backup tarball into the hosting account's
home directory with path-traversal and symlink-traversal protection,
replaces the live document root atomically, and reports success/failure
back to the control plane. Restores are staging-only by default — the
operator must verify the restore on a staging URL before promoting it.

### 5.4 Artifact storage (R2)

R2 bucket lifecycle policies handle artifact retention automatically.
See [`docs/operations/r2-artifact-retention.md`](./r2-artifact-retention.md)
for the retention configuration.

## 6. Recovery

### 6.1 Control-plane API failure

Cloudflare Workers has a 100% uptime SLA. If the Worker is unreachable:

1. Check `https://status.cloudflare.com` for a platform incident.
2. Check the Worker's health endpoints:
   - `GET /v1/health` — liveness
   - `GET /v1/health/ready` — readiness (DB + bindings)
   - `GET /v1/health/schema` — schema integrity (all required tables
     present)
3. If the Worker is deployed but returning 5xx, roll back to the
   previous deployment (section 4.1).
4. If D1 is unreachable, the Worker will return 503 from `/v1/health/ready`.
   Cloudflare D1 has its own status page; recovery is automatic.

### 6.2 Hosting VM failure

If a hosting VM becomes unreachable:

1. The agent's heartbeat stops reaching `/v1/agent/heartbeat`. After 3
   minutes the server's `status` flips from `ONLINE` to `OFFLINE` and
   an incident is auto-created.
2. Existing hosting accounts on that VM continue to serve traffic via
   Nginx (which does not depend on the agent), but no provisioning
   operations can run.
3. To migrate accounts to a new VM:
   a. Provision a new VM per section 2.3.
   b. Restore each account's most recent backup on the new VM per
      section 5.3.
   c. Update DNS records to point to the new VM (or rely on Cloudflare
      SaaS custom hostname revalidation).
4. The old VM's agent credential is revoked via
   `POST /internal/v1/operator/application-nodes/:nodeId/revoke` (for
   application runtime nodes) or by revoking the agent credential row
   in D1.

### 6.3 Database corruption

D1 corruption is extremely unlikely (Cloudflare manages durability), but
if it happens:

1. Stop the Worker (set `enabled = false` in the dashboard, or roll
   back to a known-good deployment).
2. Restore from the most recent D1 export (section 5.1):
   ```bash
   npx wrangler d1 execute nexora-production --remote \
     --file=nexora-YYYYMMDD-HHMMSS.sql
   ```
3. Re-apply migrations to ensure the schema is at the latest version:
   ```bash
   npx wrangler d1 migrations apply nexora-production --remote
   ```
4. Re-enable the Worker.

### 6.4 Compromised agent credential

If an agent's Ed25519 private key is compromised:

1. Revoke the credential:
   ```bash
   curl -X POST -H "Authorization: Bearer $TOKEN" \
     https://api.nexoraedge.digital/internal/v1/operator/application-nodes/$NODE_ID/revoke
   ```
2. Generate a new keypair on the hosting VM and enroll the new
   credential. The old credential's signed requests are rejected
   (`agent_credentials.revoked_at IS NOT NULL`).
3. Rotate any database user secrets that were revealed to the
   compromised agent via
   `POST /v1/databases/:id/users/:userId/reset-password`.

### 6.5 MFA lockout

If a user is locked out of their account because their MFA challenge was
locked (5 invalid attempts):

1. The lock is per-challenge, not per-user. The user can immediately
   sign in again with their email+password to receive a fresh
   challengeId — there is no admin action required.
2. If the user has lost their TOTP device entirely, an admin can disable
   MFA on their behalf by directly deleting the `mfa_factors` row in D1:
   ```sql
   DELETE FROM mfa_factors WHERE user_id = '<user-id>';
   ```
   This is the only MFA bypass path and it requires D1 write access.
   Audit-log the action manually.

## 7. Monitoring

### 7.1 Control plane

- `GET /v1/overview` — counts of servers, hosting accounts, domains,
  plans, databases; check flags for api/database/schema/agent/server
  readiness.
- `GET /v1/incidents` — recent incidents with acknowledgment state.
- `GET /v1/servers/:id/telemetry` — CPU/memory/disk history for a
  hosting VM.
- `GET /v1/servers/:id/services` — Nginx/PHP-FPM/MariaDB service status.
- `GET /v1/audit-logs?action=auth.login_mfa_failed` — failed MFA
  attempts (potential brute force).
- `GET /v1/audit-logs?action=auth.login_mfa_locked` — locked MFA
  challenges (definitive brute force signal).

### 7.2 Hosting VMs

The agent exposes a local health endpoint on each VM:

```bash
curl http://localhost:9100/healthz
```

For deeper inspection, the systemd journal is the primary log source:

```bash
sudo journalctl -u nexora-agent -u nexora-provisiond \
                -u nexora-static-publisher -u nexora-static-vhostd \
                --since="1 hour ago"
```

## 8. Security checklist

- [ ] `DATABASE_SECRET_ENCRYPTION_KEY` and `MFA_ENCRYPTION_KEY` are
      set as Worker secrets (not in plaintext env vars).
- [ ] The dashboard's `/api/auth/[...segments]` proxy enforces
      same-origin on all non-GET requests.
- [ ] The `/api/control/[...path]` proxy enforces same-origin on all
      non-GET requests and only allows the routes in its allowlist.
- [ ] All hosting VM agent credentials are Ed25519 keypairs (no
      passwords).
- [ ] MFA is enforced on `/v1/auth/login` (verified by
      `mfa-login.integration.test.ts`).
- [ ] TOTP replay protection is active (verified by the replay test).
- [ ] Per-challenge attempt cap is active (verified by the lock test).
- [ ] All hosting account backups are subject to retention policy.
- [ ] The D1 database has at least one daily export configured.
- [ ] The Cloudflare Tunnel on each hosting VM is configured to reject
      any inbound traffic that does not originate from Cloudflare.
