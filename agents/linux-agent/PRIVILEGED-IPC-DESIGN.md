# Privileged Provisioning IPC Design

Status: IPC daemon, client, helper isolation, and agent call-site migration are implemented in the repository. A harmless authenticated socket smoke test passed on the development VM. GitHub CI passed provisioner tests, the full Go test suite, race tests, vet, build, CLI verification, systemd-unit verification, and Cloudflare Tunnel installer syntax validation on commit 6c8c14e7181de58059dcdcc10b68e4533e3be663. Full operation-by-operation validation and final systemd hardening/rollout remain pending; do not treat this document as deployment approval.

## Objective

Remove the agent's sudo elevation path and broad systemd exceptions currently required by the one-shot provisioning helper. Keep the monitoring/control-plane agent unprivileged, and isolate privileged operations behind a local authenticated Unix-domain socket.

The existing provisioner remains the policy enforcement point: it owns the operation allowlist, request decoding, account/domain/database/backup validation, secure filesystem operations, and File Manager privilege drop.

## Current constraints discovered in the code

The agent routes privileged operations through the shared provisionipc client. Database usage and queued provisioning jobs use the authenticated Unix socket; the daemon starts the fixed /usr/local/libexec/nexora-provision helper as a separate child. The provisioner remains the validation boundary.

The helper is a one-request executable. Its File Manager operation opens the validated document-root directory, calls chroot, then setgroups, setgid, and setuid. These operations permanently change the process security context. Therefore, a persistent server must not execute File Manager work in its own request-serving process.

The privileged helper accesses these system resources:

- Customer home trees under /home/<username> (directory creation, ownership, ACLs, website snapshots, File Manager chroot).
- Account identity databases through useradd, NSS/getent, and the system account databases.
- Nginx configuration under /etc/nginx/sites-available and /etc/nginx/sites-enabled; validates with nginx -t and reloads an already-active Nginx service.
- PHP-FPM pool configuration under /etc/php/<version>/fpm/pool.d; validates the detected FPM binary and reloads only an already-active service.
- Nexora backup and restore workspaces under /var/lib/nexora/backups and /var/lib/nexora/restore-staging.
- MariaDB through its fixed CLI binaries and local service socket.
- systemd control operations for Nginx and PHP-FPM.
- ACL changes through the fixed setfacl executable.

Do not derive a final ReadWritePaths list from this summary alone. It must be checked against every helper operation and the actual target OS layout, including the exact account database files modified by the installed useradd implementation and the MariaDB socket path.

## Proposed process architecture

1. nexora-agent connects to the root-owned Unix socket at /run/nexora/provision.sock.
2. The separate root-owned nexora-provisiond accepts one request per connection.
3. Before reading a request, the daemon obtains peer credentials with SO_PEERCRED and accepts only the configured nexora-agent UID. Socket ownership/mode should be root:nexora-agent and 0660. The socket directory must be root-owned and not writable by the agent.
4. The daemon applies a 1 MiB request limit, a 12 MiB framed response limit, a 10-second request-read deadline, a two-minute helper deadline, and a four-worker concurrency limit. It does not accept operation names as command names, executable paths, environment variables, or filesystem paths.
5. For each accepted connection, the daemon starts the fixed root-owned /usr/local/libexec/nexora-provision executable as a separate child process, passes the request bytes on stdin, captures stdout/stderr separately, and returns a framed response containing the child exit status and bounded output.
6. The one-shot helper continues to call its existing decodeRequest, enforce DisallowUnknownFields, validate the operation and inputs, and execute the existing implementation. The helper child exits after every request. A File Manager child can therefore chroot and drop UID/GID without affecting the daemon or later requests.
7. The agent uses one shared IPC client function in place of every sudo call. The IPC response must preserve the existing semantics: stdout is used for successful JSON results, while non-zero exit status and captured output are treated as operation failure. The database-usage call must continue to parse stdout only and enforce its existing response limit.

The daemon currently uses the fixed helper path /usr/local/libexec/nexora-provision with no client-controlled arguments. It must not invoke a shell, accept client-supplied executable arguments, or trust client-supplied environment variables. It must not run the helper with exec.Command in the same process.

## Request/response protocol requirements

- One request and one response per socket connection; no persistent multiplexed sessions.
- Length-prefixed or otherwise unambiguously framed messages; never rely on a single Read call to return a complete message.
- Maximum request size: no greater than the helper's existing 1 MiB limit.
- Implemented response cap: stdout and stderr are each retained up to one quarter of the 12 MiB frame budget, leaving room for base64 expansion and JSON framing. Excess output is drained without being retained (avoiding SIGPIPE), and `outputTruncated` is set in the response. The encoded frame is checked again before transmission.
- Response includes exit status, stdout bytes, and stderr bytes. Use base64 or a binary frame for arbitrary bytes; do not concatenate streams because the database-usage path relies on stdout-only parsing.
- Apply connection and child-process deadlines. The helper child is bounded to two minutes and is killed as a process group on timeout, daemon shutdown, or client disconnect. The client keeps its write side open while waiting so the daemon can distinguish a live request from a disconnected client; trailing bytes are rejected.
- Reject extra/trailing frame data and malformed lengths.
- Never log request bodies, database credentials, or File Manager file contents.

## systemd isolation targets

### Unprivileged agent

After the IPC migration is installed and verified, restore a restrictive agent unit: NoNewPrivileges=true, ProtectSystem=strict, ProtectHome=true, empty capability bounding set, and only the network address families and runtime paths actually needed by the agent. Remove all legacy override drop-ins that weaken the unit only as part of the explicit migration, not before the IPC service is ready.

### Privileged IPC daemon

Run as root in a separate unit. The current repository unit uses NoNewPrivileges=true, ProtectSystem=full, PrivateTmp=true, kernel/control-group protections, AF_UNIX-only networking, and a capability bounding set limited to the helper's observed account/filesystem/chroot operations. `RestrictSUIDSGID=false` is required because the File Manager helper explicitly calls setgroups/setgid/setuid after chroot. The current ProtectSystem=full exception model is intentionally not claimed to be final least-privilege hardening; tighten it only after disposable-VM operation tests.

The daemon and its helper children need access to dynamic customer homes, account databases, Nginx/PHP configuration, backup storage, the MariaDB socket, and the systemd control interface. The final filesystem exceptions and capability set must be derived from the complete operation inventory and verified on the actual Ubuntu installation. In particular, ProtectHome=true cannot be applied blindly to the privileged helper because it must access customer home directories.

The daemon must not run with a writable socket path outside its root-owned runtime directory. Use systemd runtime-directory management where practical. The agent must not be able to replace the daemon executable, helper executable, unit files, socket directory, or configuration.

## Required tests before VM migration

- Unit tests cover peer-credential authorization, wrong UID rejection, framing, truncated/oversized frames, capped output and truncation signaling, daemon cancellation/reaping, client-disconnect cancellation, encoded response size, and the four-worker concurrency limit. Remaining gaps: request-read deadline coverage, daemon socket ownership/mode integration test, and operation-by-operation helper integration tests.
- Integration tests for every currently supported operation through the socket, including File Manager chroot/drop-privilege behavior and JSON stdout results.
- Verify a File Manager request does not affect the daemon's UID/GID, root directory, or ability to serve the next request.
- The daemon validates that the helper exists, is a regular file, is root-owned, and is not group/world writable.
- Confirm no remaining sudo invocation exists in the agent code path and audit all privileged process execution.
- Run gofmt, go test ./..., go test -race ./..., and go vet ./...; add CI coverage for the IPC package and provisioner integration tests.
- On a disposable test VM, validate the service units with systemd-analyze verify, inspect systemd-analyze security, and test every operation with the final filesystem/capability sandbox. A security score is not a substitute for operation tests.

## Migration and rollback

Do not edit the live VM's unit files, drop-ins, sudoers rule, or binaries during development. The repository implementation and a harmless socket smoke test do not establish that every privileged operation is safe under the final systemd sandbox.

Migration must be staged: install the daemon and its unit/socket; validate the socket and helper with a harmless/read-only request; switch the agent to IPC; verify heartbeat plus each operation; then restore agent hardening and remove the obsolete sudoers rule/drop-ins. Keep the previous binaries and configuration available for rollback until all tests pass. Do not stop or restart the currently healthy agent as part of an unverified rollout.

## Explicit non-goals

- No arbitrary command execution or client-supplied executable path.
- No broad root API or generic filesystem proxy.
- No change to existing account/database/backup business rules as part of the IPC refactor.
- No automatic service start/enable/restart behavior. Preserve existing Nginx/PHP-FPM validate-before-reload and active-only reload rules.