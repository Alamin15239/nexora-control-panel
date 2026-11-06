# Privileged IPC disposable-VM integration test plan

Status: **planned; not yet executed**. This plan is for a disposable Ubuntu VM snapshot, never the live Nexora VM.

## Safety gate

- Create a fresh VM snapshot or clone. Do not run this plan against a production host.
- Confirm the clone has no customer data, production DNS, public ingress, or live Cloudflare tunnel credentials.
- Use a dedicated test domain under a reserved test zone and a disposable MariaDB instance.
- Record the VM image/version, package versions, service unit hashes, and initial filesystem/database state.
- Keep a console session available. Do not weaken systemd protections to make a test pass.
- After testing, export logs and destroy/revert the clone.

## Test topology

Install the candidate `nexora-provisiond`, root-owned `nexora-provision` helper, and `nexora-agent` on the clone. Start the daemon with the committed `nexora-provisiond.service`; invoke operations only through the Unix socket as the configured `nexora-agent` UID. Do not invoke the helper directly for acceptance tests.

For every request, capture: request operation (redact secrets), client exit status, IPC result/exit code, daemon journal, helper process exit/reaping, and before/after filesystem or database state.

## Operation coverage matrix

| Operation | Positive path | Negative/security path | Required postcondition |
|---|---|---|---|
| `DATABASE_USAGE` | Empty registry returns an empty database list; registered test account returns only its prefixed schemas | Corrupt registry marker; oversized/truncated IPC output | Agent rejects incomplete output; no unrelated schema is disclosed |
| `CREATE_HOSTING_ACCOUNT` | Create a unique test account | Existing unmanaged user, invalid username, conflicting home/registry entry | Correct UID/GID, nologin shell, verified registry marker, secure home/public_html ownership and modes |
| `ADD_DOMAIN` | Add test hostname and document root | Invalid hostname, traversal/out-of-home document root, pre-existing conflicting Nginx config/link | Config and enabled link are correct; `nginx -t` succeeds; no existing file is overwritten |
| `FILE_MANAGER` | LIST, READ, WRITE, UPLOAD, CREATE_DIRECTORY, RENAME_PATH, DELETE_PATH | Traversal, symlink swap, symlink target, cross-account path, mount boundary, oversized transfer, quarantine unavailable | All operations remain inside account root; no symlink escape; delete quarantine remains root-owned |
| `CREATE_DATABASE` | Create account-prefixed schema | Foreign prefix, malformed name, SQL metacharacters | Only the account-owned schema exists |
| `CREATE_DATABASE_USER` | Create user with allowed privileges | Unsupported privilege, foreign schema/user, invalid username | Grants are limited to the requested managed schema and allowed privilege set |
| `REVOKE_DATABASE_USER` | Revoke the test user's grants | Foreign account/schema/user | Only the requested managed grant is revoked |
| `DELETE_DATABASE` | Delete disposable schema and explicitly supplied managed users | Foreign schema/user, malformed user list | Only the test account's schema and authorized users are removed |
| `CREATE_BACKUP` | Archive website snapshot and selected test DB dump | Invalid UUID, symlinked storage path, insufficient free space, concurrent lock | Root-owned private storage; archive hash and metadata verify |
| `RESTORE_BACKUP` | Stage restore using the exact archive SHA-256 | Wrong hash, malformed archive, traversal/symlink/hardlink archive entries | Restore is staged only; original live content is unchanged |
| `DELETE_BACKUP` | Delete the selected test archive | Invalid ID, foreign account archive, symlink/path substitution | Only the selected account's validated archive is removed |

File Manager's operation names are part of the nested `fileOperation` field; exercise each operation through the outer `FILE_MANAGER` IPC request.

## IPC and daemon behavior

- Correct agent UID can connect; an unrelated UID is disconnected.
- Socket owner/group/mode are root, agent group, and `0660`; runtime directory is root:agent-group `0750`.
- Existing socket path, regular file, or symlink is never replaced on daemon startup.
- Idle client is disconnected at the configured request-read deadline.
- Malformed, oversized, truncated, or trailing request data is rejected.
- Four concurrent requests are accepted; a fifth is rejected without launching another helper.
- Client disconnect and daemon shutdown cancel and reap the complete helper process group.
- Helper timeout cancels and reaps the process group.
- Unexpected listener failure exits non-zero so systemd can restart the daemon.
- Oversized helper output is drained without unbounded memory growth, marked truncated, and rejected by agent consumers that require complete output.

## systemd sandbox audit

Run each positive operation under the actual committed unit, not a manually relaxed shell. For each operation, verify all required paths are writable only where intended and that unrelated paths remain protected.

| Area | Expected access / dependency to verify |
|---|---|
| Account identity | `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow` updates via supported system account tools |
| Hosting data | `/home/<account>` creation, ownership, File Manager chroot and credential drop |
| Nginx | `/etc/nginx/sites-available`, `/etc/nginx/sites-enabled`; `nginx -t` |
| PHP-FPM | `/etc/php/<version>/fpm/pool.d`; PHP-FPM config validation/reload path |
| MariaDB | Unix socket access and `/usr/bin/mariadb`; no network socket dependency |
| Backups | `/var/lib/nexora/backups`, `/var/lib/nexora/restore-staging`; private ownership/modes and free-space checks |
| Runtime | `/run/nexora/provision.sock`; root-owned runtime directory and agent-group socket |
| Temporary files | `PrivateTmp=true` behavior for helper tools and backup staging |
| Capabilities | Only the declared CHOWN, DAC_OVERRIDE, FOWNER, FSETID, SETGID, SETUID, SYS_CHROOT set; confirm no operation requires an undeclared capability |

Do not remove `NoNewPrivileges`, widen `CapabilityBoundingSet`, disable `ProtectSystem`, or relax filesystem protections as a test workaround. If an operation fails, identify the exact syscall/path and decide whether the implementation or unit is wrong before changing policy.

## Exit criteria

The IPC migration is not ready for VM rollout until every row has recorded positive and negative results, the full Go/race/vet/build CI remains green, systemd runs with the committed restrictions, and no unrelated account, file, database, or configuration is modified. Attach the sanitized test report to the pull request.