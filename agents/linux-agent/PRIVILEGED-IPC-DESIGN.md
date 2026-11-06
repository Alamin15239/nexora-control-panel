# Privileged Provisioning IPC Design

Status: design approved for implementation planning; not yet deployed.

## Objective

Remove the agent's sudo elevation path and broad systemd exceptions currently required by the one-shot provisioning helper. Keep the monitoring/control-plane agent unprivileged, and isolate privileged operations behind a local authenticated Unix-domain socket.

The existing provisioner remains the policy enforcement point: it owns the operation allowlist, request decoding, account/domain/database/backup validation, secure filesystem operations, and File Manager privilege drop.

## Current constraints discovered in the code

The agent currently invokes /usr/local/libexec/nexora-provision through sudo -n in eight code paths: database usage, create database, create database user, revoke database user, delete database, backup operations, File Manager, and account/domain provisioning.

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

1. nexora-agent connects to a root-owned Unix socket, proposed path /run/nexora/provision.sock.
2. A separate root-owned nexora-provisiond accepts one request per connection.
3. Before reading a request, the daemon obtains peer credentials with SO_PEERCRED and accepts only the configured nexora-agent UID. Socket ownership/mode should be root:nexora-agent and 0660. The socket directory must be root-owned and not writable by the agent.
4. The daemon applies a strict request byte limit, a bounded response byte limit, a request deadline, and a small concurrency limit. It does not accept operation names as command names, executable paths, environment variables, or filesystem paths.
5. For each accepted connection, the daemon starts the fixed root-owned /usr/local/libexec/nexora-provision executable as a separate child process, passes the request bytes on stdin, captures stdout/stderr separately, and returns a framed response containing the child exit status and bounded output.
6. The one-shot helper continues to call its existing decodeRequest, enforce DisallowUnknownFields, validate the operation and inputs, and execute the existing implementation. The helper child exits after every request. A File Manager child can therefore chroot and drop UID/GID without affecting the daemon or later requests.
7. The agent uses one shared IPC client function in place of every sudo call. The IPC response must preserve the existing semantics: stdout is used for successful JSON results, while non-zero exit status and captured output are treated as operation failure. The database-usage call must continue to parse stdout only and enforce its existing response limit.

The daemon must use a fixed executable path and a fixed argument vector. It must not invoke a shell, accept client-supplied executable arguments, or trust client-supplied environment variables. It must not run the helper with exec.Command in the same process.

## Request/response protocol requirements

- One request and one response per socket connection; no persistent multiplexed sessions.
- Length-prefixed or otherwise unambiguously framed messages; never rely on a single Read call to return a complete message.
- Maximum request size: no greater than the helper's existing 1 MiB limit.
- Explicit maximum response size; select a value that safely accommodates the largest legitimate File Manager listing and backup metadata response, and enforce it while reading child output to avoid unbounded memory growth.
- Response includes exit status, stdout bytes, and stderr bytes. Use base64 or a binary frame for arbitrary bytes; do not concatenate streams because the database-usage path relies on stdout-only parsing.
- Apply connection and child-process deadlines. The current implementation bounds each helper child to two minutes and reaps it on timeout or daemon shutdown. Immediate cancellation on client disconnect remains a follow-up hardening requirement.
- Reject extra/trailing frame data and malformed lengths.
- Never log request bodies, database credentials, or File Manager file contents.

## systemd isolation targets

### Unprivileged agent

After the IPC migration is installed and verified, restore a restrictive agent unit: NoNewPrivileges=true, ProtectSystem=strict, ProtectHome=true, empty capability bounding set, and only the network address families and runtime paths actually needed by the agent. Remove all legacy override drop-ins that weaken the unit only as part of the explicit migration, not before the IPC service is ready.

### Privileged IPC daemon

Run as root in a separate unit with a restrictive baseline such as NoNewPrivileges=true, ProtectSystem=strict, PrivateTmp=true, kernel/control-group protections, and a deliberately minimized capability bounding set. Do not copy the current agent's broad capability list into this unit.

The daemon and its helper children need access to dynamic customer homes, account databases, Nginx/PHP configuration, backup storage, the MariaDB socket, and the systemd control interface. The final filesystem exceptions and capability set must be derived from the complete operation inventory and verified on the actual Ubuntu installation. In particular, ProtectHome=true cannot be applied blindly to the privileged helper because it must access customer home directories.

The daemon must not run with a writable socket path outside its root-owned runtime directory. Use systemd runtime-directory management where practical. The agent must not be able to replace the daemon executable, helper executable, unit files, socket directory, or configuration.

## Required tests before VM migration

- Unit tests for peer-credential authorization, wrong UID rejection, socket permissions, framing, truncated frames, oversized requests/responses, deadlines, child cancellation/reaping, and concurrent-request limits.
- Integration tests for every currently supported operation through the socket, including File Manager chroot/drop-privilege behavior and JSON stdout results.
- Verify a File Manager request does not affect the daemon's UID/GID, root directory, or ability to serve the next request.
- Verify helper executable ownership/mode and reject a missing, non-regular, or non-root-owned helper binary.
- Confirm no remaining sudo invocation exists in the agent code.
- Run gofmt, go test ./..., go test -race ./..., and go vet ./...; add CI coverage for the IPC package and provisioner integration tests.
- On a disposable test VM, validate the service units with systemd-analyze verify, inspect systemd-analyze security, and test every operation with the final filesystem/capability sandbox. A security score is not a substitute for operation tests.

## Migration and rollback

Do not edit the live VM's unit files, drop-ins, sudoers rule, or binaries during development.

Migration must be staged: install the daemon and its unit/socket; validate the socket and helper with a harmless/read-only request; switch the agent to IPC; verify heartbeat plus each operation; then restore agent hardening and remove the obsolete sudoers rule/drop-ins. Keep the previous binaries and configuration available for rollback until all tests pass. Do not stop or restart the currently healthy agent as part of an unverified rollout.

## Explicit non-goals

- No arbitrary command execution or client-supplied executable path.
- No broad root API or generic filesystem proxy.
- No change to existing account/database/backup business rules as part of the IPC refactor.
- No automatic service start/enable/restart behavior. Preserve existing Nginx/PHP-FPM validate-before-reload and active-only reload rules.