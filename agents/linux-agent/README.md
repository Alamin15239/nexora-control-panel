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


## Isolated application runtime node (read-only polling phase)

The separate `nexora-runtime-node` binary is a dedicated runtime-node control client. It does not replace the legacy hosting agent and does not run inside the privileged provisioner.

Build and test it:

```sh
go test ./...
go test -race ./...
go build -trimpath -ldflags="-s -w" -o /tmp/nexora-runtime-node ./cmd/nexora-runtime-node
```

The example configuration is `config.runtime-node.example.json`. Install it as `/etc/nexora-runtime/node.json`, owned by `nexora-runtime:nexora-runtime`, mode `0600`. Store the raw Ed25519 private key as 128 hexadecimal characters in the separate owner-only file configured by `private_key_file`. The state file parent must be a real directory owned by the runtime service account with mode `0700`.

The service unit is `systemd/nexora-runtime-node.service`. It runs under a dedicated unprivileged `nexora-runtime` account, uses systemd filesystem/kernel restrictions, and writes only to `/var/lib/nexora-runtime`. Installation requires operator-created account, config and key files; do not install or enable it on the current development VM as part of CI work.

At startup the process loads and validates the durable supervisor snapshot, then verifies every recorded container through Podman and fails closed on an ownership mismatch or missing container. An absent snapshot is treated as an empty first-boot state. It then performs signed Ed25519 desired-state polling at the configured interval.

**Execution remains disabled.** The client rejects any response that enables execution or includes commands/secrets. It does not call `Controller.Converge`, start/stop/restart containers, create volumes, or deliver secrets. Rootless Podman service/storage integration, actual runtime activation, and host network policy remain separate acceptance gates. The example registry allowlist is configuration only and is not a claim that an image build or deployment pipeline exists.

## Isolated static artifact publisher (activation milestone)

The separate `nexora-static-publisher` service consumes only static releases explicitly assigned to its enrolled runtime node. It does not run npm, shell commands, customer processes, OCI containers or build scripts. It:

1. Polls an authenticated, nonce-protected control-plane endpoint for releases assigned to its exact node.
2. Accepts only the enabled `static-v1` profile and projects configured with the `static` build method.
3. Downloads the artifact only through the node-authenticated artifact endpoint.
4. Verifies the short-lived RS256 deployment envelope against an operator-installed public key and checks organization, project, deployment, hosting account, repository ID and immutable commit identity.
5. Verifies the SHA-256 digest and bounded gzip/tar archive, rejects links/traversal/special files, extracts into a private staging directory, and atomically switches the account's `current` symlink.
6. Reports archive validation and release activation to the control plane using signed node requests. Activation moves the release to `health_checking`; it does **not** claim that the website is reachable or healthy.

Build and test:

```sh
go test ./...
go test -race ./...
go vet ./...
go build -trimpath -ldflags="-s -w" -o /tmp/nexora-static-publisher ./cmd/nexora-static-publisher
```

### Operator preparation (not performed by CI)

The service is not enabled by default. Before installing it, the operator must:

- Enroll a dedicated runtime node in a ready `rootless` or `microvm` pool and configure its owner-only Ed25519 private-key file.
- Install the matching RSA deployment-envelope public key, key ID, issuer and audience. The private signing key remains only in the Cloudflare Worker secret store.
- Create `/var/lib/nexora-static`, `accounts`, and each assigned account directory as real, non-symlink directories. The account ID directory must be provisioned out-of-band from the trusted hosting-account mapping.
- Make the publisher's `staging` and `releases` directories operator-owned and setgid with the dedicated read-only static-origin group (for example `www-data`). The publisher base and these directories must not be group/world writable. Setgid on the account, staging and release directories ensures extracted files inherit the web-server read group; do not clear that group inheritance during setup. Create the replay directory mode `0700`.
- Configure the web server's document root for each account as `/var/lib/nexora-static/accounts/<hosting-account-id>/current`. The service makes validated regular files readable (0644), directories traversable (0755), and the release root 2750 (setgid). The web-server group receives read/traverse access only; it must not be able to modify releases.
- Verify Nginx can read a manually staged test release, and test rollback by switching the `current` symlink to a previous immutable release before enabling the service.

Example config: `config.static-publisher.example.json`. Install a completed, owner-only configuration at `/etc/nexora-static-publisher/node.json`, and place the node key and public trust key in the configured paths. Install `systemd/nexora-static-publisher.service`, then use `systemd-analyze verify` before enabling the unit.

**Do not enable this service on the existing VirtualBox development VM or any customer node yet.** The publisher is a controlled static-file activation component, not a complete production release service. External HTTP health probes, rollback orchestration, web-server routing, account quota enforcement, production tenant-isolation tests, and live Cloudflare/D1/R2 configuration verification remain release gates. The runtime OCI execution loop remains disabled.
