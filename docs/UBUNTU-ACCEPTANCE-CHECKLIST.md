# Ubuntu Acceptance Checklist — Nexora Control Panel

Status: **not executed**. No item below has been verified against the
live `nexora-deploy-node`. This document separates automated CI
verification (already green at the branch HEAD) from real server
acceptance, which requires the operator to run these steps and record
the evidence column. An item is only "passed" when the actual command
output was captured on the server.

Target: Ubuntu 22.04/24.04 LTS host running the Nexora Linux agent,
Nginx + PHP-FPM, MariaDB, and `cloudflared`. Run all commands as a
sudo-capable operator unless stated otherwise.

Legend: `[ ]` pending · `[x]` passed (fill in date + evidence) ·
`[!]` failed (fill in defect reference).

---

## 1. Agent service and identity

| # | Check | Command | Expected result | Evidence |
|---|---|---|---|---|
| 1.1 | Agent binary present | `nexora-agent --version 2>/dev/null || systemctl cat nexora-agent` | Service unit exists and points at the built binary | |
| 1.2 | Service active | `systemctl status nexora-agent --no-pager` | `active (running)`, no restart loops in the last hour | |
| 1.3 | Enrollment intact | `ls -l /etc/nexora/agent/` and confirm key files are `root:`-owned, mode 0600 | Ed25519 identity + enrollment files exist, not world-readable | |
| 1.4 | Agent log clean | `journalctl -u nexora-agent -n 100 --no-pager` | No repeated claim/auth failures, no signature rejections | |

## 2. Heartbeat and control-plane connectivity

| # | Check | Command | Expected result | Evidence |
|---|---|---|---|---|
| 2.1 | Heartbeat reported | In dashboard `/servers`: server row shows `ONLINE` with `last heartbeat < 2 min` | Agent heartbeat accepted by Worker | |
| 2.2 | Telemetry stored | Dashboard `/servers` → server detail → telemetry graph | Recent CPU/memory/disk points | |
| 2.3 | Tunnel up | `systemctl status cloudflared --no-pager` and `cloudflared tunnel info <tunnel>` | Active connections ≥ 1 | |

## 3. Job claiming and idempotency

| # | Check | Command | Expected result | Evidence |
|---|---|---|---|---|
| 3.1 | Claim loop running | `journalctl -u nexora-agent -n 200 --no-pager | grep -i claim` | Periodic poll attempts, 2xx outcomes | |
| 3.2 | Lease safety | Trigger two rapid domain adds for the same account; confirm only distinct jobs are claimed and no job is processed twice | No duplicate Nginx blocks | |
| 3.3 | Nonce replay rejected | Attempt to re-send a captured signed request (if testing with a harness) | Worker returns 4xx; agent log shows rejection | |

## 4. Hosting account lifecycle

| # | Check | Command | Expected result | Evidence |
|---|---|---|---|---|
| 4.1 | Account created | WHM → Hosting accounts → create; then on the node: `ls -ld /home/<user>` | Directory exists with setgid 2750, correct ownership | |
| 4.2 | PHP-FPM pool generated | `systemctl status php-fpm-<user>.service` (or pool name from job payload) | Pool active; `ls -l /run/php/<user>.sock` exists | |
| 4.3 | Account suspended | WHM → suspend account; then `systemctl status php-fpm-<user>` | Pool stopped or web root disabled per design; job SUCCEEDED | |
| 4.4 | Account reactivated | WHM → reactivate | Pool active again | |

## 5. Domains and Nginx

| # | Check | Command | Expected result | Evidence |
|---|---|---|---|---|
| 5.1 | Domain add job succeeds | WHM or customer portal → add domain; then `provisioning-jobs` shows SUCCEEDED | Job SUCCEEDED with no error_code | |
| 5.2 | Vhost written | `nginx -T 2>/dev/null | grep -A3 "server_name <domain>"` | Server block present, document root inside `/home/<user>/public_html` | |
| 5.3 | Config validation | `nginx -t` | `syntax is ok` / `test is successful` | |
| 5.4 | Reload without downtime | `systemctl reload nginx` and curl the domain | HTTP 200/expected response; no dropped connections in error log | |
| 5.5 | Domain removal | Remove a non-primary domain; `nginx -T | grep "server_name <domain>"` | Block gone; job SUCCEEDED; site for other domains still serving | |
| 5.6 | Primary-domain guard | Attempt to remove the primary domain via API | 409 "primary domain cannot be removed" | |

## 6. PHP execution and runtime settings

| # | Check | Command | Expected result | Evidence |
|---|---|---|---|---|
| 6.1 | PHP page executes | `echo '<?php phpinfo();' > /home/<user>/public_html/info.php` then `curl -s http://<domain>/info.php | head -5` | PHP version banner returned via FPM | |
| 6.2 | Pool isolation | `ps -o user,cmd -C php-fpm` | Pool worker runs as the account user, not root | |
| 6.3 | PHP settings applied | Change PHP memory limit in WHM; after job, `curl -s http://<domain>/info.php | grep memory_limit` | New limit visible; `php-fpm` reload clean in journal | |
| 6.4 | Remove test file | `rm /home/<user>/public_html/info.php` | — | |

## 7. MariaDB databases

| # | Check | Command | Expected result | Evidence |
|---|---|---|---|---|
| 7.1 | Database created | Portal → create database; then `sudo mysql -e "SHOW DATABASES LIKE '<db>'"` | Database listed | |
| 7.2 | User created | Portal → create database user; `sudo mysql -e "SELECT user,host FROM mysql.user WHERE user LIKE '<prefix>%'"` | User exists, host-scoped | |
| 7.3 | Connectivity | `mysql -u <dbuser> -p<secret> -h 127.0.0.1 <db> -e "CREATE TABLE t1(id INT); DROP TABLE t1;"` | Success; user cannot see other tenants' databases (`SHOW DATABASES`) | |
| 7.4 | Privileges scoped | `sudo mysql -e "SHOW GRANTS FOR '<dbuser>'@'localhost'"` | Grants limited to `<db>`.* only | |
| 7.5 | Password reset | Portal → reset user password; retry 7.3 with the new secret | Old secret rejected, new works | |
| 7.6 | User revoked | Portal → revoke; `SHOW GRANTS` | No grants remain | |
| 7.7 | Database deleted | Portal → delete database; `SHOW DATABASES LIKE '<db>'` | Gone; job SUCCEEDED | |

## 8. Backups

| # | Check | Command | Expected result | Evidence |
|---|---|---|---|---|
| 8.1 | Backup created | WHM → backups → create; inspect staging path from job payload | Archive exists with expected sha256 recorded in the API | |
| 8.2 | Backup listed | WHM → backups list | Row with size/sha256/status SUCCEEDED | |
| 8.3 | Restore (staging) | WHM → restore; verify staging output and confirm the restore is STAGING-ONLY per current design | Restore job SUCCEEDED; restored files verified in the staging directory before promotion | |
| 8.4 | Scheduled backup | Configure a daily schedule; wait for the cron tick (or run the sweep manually) | Backup auto-created; next_run_at advanced; anchor day preserved | |
| 8.5 | Backup delete | Delete the backup | Archive removed from disk; row removed | |

## 9. Deployment publishing and rollback

| # | Check | Command | Expected result | Evidence |
|---|---|---|---|---|
| 9.1 | Static publish | Trigger a GitHub deployment for a linked project | Release transitions publishing → health_checking → succeeded | |
| 9.2 | Release active | `readlink /home/<user>/public_html/../releases/current` (or per design path) | Points at the new release ID | |
| 9.3 | Health check recorded | Release detail in dashboard | Health report stored; outcome healthy | |
| 9.4 | Rollback | Roll back to the previous release | `current` symlink switches back; site serves the old artifact; rollback ack recorded | |
| 9.5 | Publisher restart recovery | Restart `nexora-static-publisher` while a release is in `health_checking` | Release is re-polled and completes without re-publishing | |

## 10. Cloudflare custom hostnames and SSL

| # | Check | Command | Expected result | Evidence |
|---|---|---|---|---|
| 10.1 | Custom hostname created | WHM → domains → register Cloudflare hostname | API returns hostname id; status pending | |
| 10.2 | Ownership verification | Add the returned TXT/CNAME records in DNS | Hostname status → active | |
| 10.3 | SSL active | `curl -sv https://<custom-domain> 2>&1 | grep -E "subject|SSL certificate verify"` | Certificate valid for the custom hostname; ssl status active | |
| 10.4 | Revalidate | WHM → revalidate SSL | Status refreshed from the Cloudflare API | |

## 11. Resource isolation and permission boundaries

| # | Check | Command | Expected result | Evidence |
|---|---|---|---|---|
| 11.1 | Filesystem boundary | As a tenant DB user / FPM pool, attempt `open_basedir` escape or symlink traversal | Blocked; agent file-manager quarantines out-of-boundary paths | |
| 11.2 | Tenant DB isolation | As tenant A DB user: `SHOW DATABASES` | Only tenant A databases visible | |
| 11.3 | API org isolation | As customer of org A, request org B resources via API (curl with org-B IDs) | 404, never 200 | |
| 11.4 | Agent cannot be invoked externally | Attempt an unauthenticated call to the agent IPC socket | Permission denied / auth required | |

## 12. External infrastructure required for full SaaS operation

These capabilities cannot be accepted on the node alone; they require
operator-provided infrastructure and secrets. Record each decision and
the verification run.

1. **Mailbox hosting (IMAP/SMTP).** Required: a mail server (self-hosted
   Postfix+Dovecot, Mailcow, Stalwart, or equivalent) with a stable
   admin API reachable over HTTPS from the Worker; DNS: MX, SPF, DKIM,
   DMARC records per domain; secrets: `EMAIL_PROVIDER=mailserver-api`,
   `EMAIL_PROVIDER_API_URL`, `EMAIL_PROVIDER_API_TOKEN`. Until then the
   email module stays in inventory mode and reports
   `provider_status: not_provisioned` honestly.
2. **Automated payment provider.** Required: an approved provider
   (Stripe/Paddle/local gateway); secrets: `PAYMENT_WEBHOOK_SECRET`
   (32+ chars) for the generic HMAC webhook, or a provider-specific
   integration; provider webhook configured to POST
   `{eventId, invoiceRef, outcome}` with
   `X-Nexora-Signature: t=<seconds>,v1=<hmac>`. Renewals are otherwise
   recorded manually (audited bank-transfer flow).
3. **Outbound notification email.** Required: `RESEND_API_KEY` and a
   verified `EMAIL_FROM` domain for password resets and incident
   alerts. This is transactional email only — not mailbox hosting.
4. **Off-site backup replication / encryption at rest** (currently
   staging-only restore): object storage bucket + KMS decision.
5. **Live Cloudflare zone credentials** for custom-hostname acceptance
   (`CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ZONE_ID`).

## 13. CI vs. live acceptance separation

Automated CI (no live node required) — must stay green on the branch:

- API typecheck, web typecheck/lint/build
- 242 Worker integration tests (`apps/cloudflare-api/scripts/*.test.ts`)
- 24/24 Go packages, `go vet`, race tests on security-sensitive packages
- Migration test: all 49 migrations apply to a fresh SQLite database
  with constraint guards

Live acceptance (this document) — requires the node and external
services; none of it is covered by CI. Do not mark the platform
"production accepted" until every applicable row above has captured
evidence.
