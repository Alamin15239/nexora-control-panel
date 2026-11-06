# Nexora Linux Agent

Restricted Linux node agent for Nexora Control. The Linux agent provides authenticated node monitoring and allowlisted hosting operations. Privileged operations are delegated through a local authenticated IPC service; the agent itself remains unprivileged.

## Security model

- Enrollment tokens are one-time and expire after 15 minutes.
- The control plane stores only a SHA-256 hash of the per-node secret; the secret is returned once and stored locally with mode 0600.
- Heartbeats and job requests use HMAC-SHA256 over timestamp, nonce, HTTP method, path, and body hash.
- Requests outside the five-minute clock window and replayed nonces are rejected.
- The agent validates HTTPS URLs and uses the platform TLS trust store.
- The monitoring agent runs as the unprivileged `nexora-agent` user.
- The agent does not execute commands or scripts supplied by the control plane.
- Privileged operations are sent to `/run/nexora/provision.sock`. The root-owned `nexora-provisiond` verifies the connecting UID using Unix socket peer credentials, enforces bounded length-prefixed messages, and launches the fixed root-owned `/usr/local/libexec/nexora-provision` helper as a separate one-request child process.
- The helper retains the operation allowlist, strict JSON decoding, account/domain/database/backup validation, and secure filesystem operations. File Manager work runs in a child process because it chroots and drops to the hosting account UID/GID; this cannot affect the IPC daemon or subsequent requests.
- The IPC daemon accepts only the configured `nexora-agent` UID. Its socket directory is root-owned and the socket is accessible only to root and the agent group. The helper and daemon executables must be root-owned and not writable by the agent.
- Supported privileged operations include hosting-account creation, domain configuration, database usage and management, account backups/restores, and restricted File Manager operations. The helper rejects unknown operations and does not expose arbitrary command execution.
- Nginx configuration changes are tested with `nginx -t` and reloaded only after a successful test; failed changes are rolled back. PHP-FPM pool changes are validated before reloading an already-active service. The agent does not automatically enable or start PHP-FPM.
- Domain provisioning configures HTTP Nginx virtual hosts only. DNS, TLS, mail, quota enforcement, suspension, and deletion policies remain separate capabilities.

## Commands

```sh
nexora-agent version
nexora-agent enroll --api https://YOUR-NEXORA-API.workers.dev --server-id YOUR_SERVER_UUID --token-stdin
nexora-agent run --config /etc/nexora/agent.json --interval 60s
nexora-agent validate-config --config /etc/nexora/agent.json
```

## Build

From `agents/linux-agent`:

```sh
go test ./...
go test -race ./...
go vet ./...
go build -trimpath -ldflags="-s -w" -o /tmp/nexora-agent ./cmd/nexora-agent
go build -trimpath -ldflags="-s -w" -o /tmp/nexora-provision ./cmd/nexora-provision
go build -trimpath -ldflags="-s -w" -o /tmp/nexora-provisiond ./cmd/nexora-provisiond
```

## IPC service installation files

- Daemon binary destination: `/usr/local/sbin/nexora-provisiond`
- Privileged helper destination: `/usr/local/libexec/nexora-provision`
- Unit file: `systemd/nexora-provisiond.service`
- Socket: `/run/nexora/provision.sock` (created by the daemon at startup)
- Runtime account: `nexora-agent` (must exist before starting the IPC daemon)

The daemon unit runs as root with a reduced capability bounding set and systemd protections. `ProtectSystem=full` is an intentional interim boundary: the helper still needs to update system account databases, dynamic customer home directories, Nginx/PHP configuration, and backup storage. Do not change it to `strict` or enable `ProtectHome=true` until all operations have been tested with a complete filesystem exception list on the target Ubuntu version.

## Migration warning

**Do not install the new agent binary on an existing server until the IPC daemon has been installed, started, and verified.** The new agent no longer invokes sudo; it requires the socket above. An existing server may still have the legacy sudoers rule and systemd drop-ins. Keep those in place during the staged migration so rollback remains possible.

The safe migration order is:

1. Build and install the root-owned helper and daemon binaries; install the daemon unit file.
2. Reload systemd, start the daemon, and verify that `/run/nexora/provision.sock` is a root-owned socket with group `nexora-agent` and mode `0660`.
3. Verify peer-credential rejection for an unauthorized UID and run a harmless/read-only database-usage request through the socket.
4. Install the IPC-capable agent binary and verify heartbeat plus every operation used by the node.
5. Only after successful end-to-end verification, remove the legacy sudoers rule and the agent drop-ins that weakened `NoNewPrivileges`, `ProtectSystem`, `ProtectHome`, and the capability bounding set. Restore the main agent unit's restrictive settings.
6. Keep the previous binaries and configuration available until the migration is confirmed; if IPC fails, restore the previous agent binary and its previous service configuration.

Do not apply this migration to the production VM until the full operation integration tests and target-host sandbox checks pass. No live service, sudoers file, or systemd drop-in is changed by building or testing this repository.

## CI

GitHub Actions runs provisioner tests, the complete Go test suite, race tests, `go vet`, builds the agent/helper/daemon, and validates the provisioning systemd unit. The control-plane API must have the required D1 migrations applied before job delivery is available.
