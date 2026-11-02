# Nexora Linux Agent

Restricted Linux node agent for Nexora Control. Version 0.6.0 supports authenticated hosting-account provisioning, Nginx domain configuration, and sandboxed hosting File Manager jobs.

## Security model

- Enrollment token is one-time and expires after 15 minutes.
- The control plane stores only a SHA-256 hash of the per-node secret; the secret is returned once and stored locally with mode 0600.
- Heartbeats and job requests use HMAC-SHA256 over timestamp, nonce, HTTP method, path, and body hash.
- Requests outside the five-minute clock window and replayed nonces are rejected.
- The agent validates HTTPS URLs and uses the platform TLS trust store.
- The monitoring agent runs as the unprivileged `nexora-agent` user.
- The agent accepts only the allowlisted `CREATE_HOSTING_ACCOUNT`, `ADD_DOMAIN`, and `FILE_MANAGER` job types. It does not execute commands or scripts supplied by the control plane.
- Privileged account creation is delegated to a separate root-owned helper at `/usr/local/libexec/nexora-provision`, permitted through one exact sudoers command.
- The helper validates account identities and domain names, creates non-login hosting users, and creates document roots with restrictive ownership and permissions. For `ADD_DOMAIN`, it rejects unsafe paths and symlinks, applies a read-only Nginx ACL, writes an Nginx virtual host, runs `nginx -t`, and reloads Nginx only after a successful test. The configuration update is rolled back if validation or reload fails. File Manager operations run in a chroot rooted at the account's `public_html`, then drop to the account UID/GID. They reject symlink traversal and support bounded list, read, write, create-directory, rename and delete operations; each file transfer is limited to 256 KiB.
- Domain provisioning configures HTTP Nginx virtual hosts only. It does not configure DNS, TLS, PHP, mail, databases, backups, or enforce plan quotas. Public reachability still requires correct DNS and firewall/network configuration.

## Commands

```sh
nexora-agent version
nexora-agent enroll --api https://YOUR-NEXORA-API.workers.dev --server-id YOUR_SERVER_UUID --token-stdin
nexora-agent run --config /etc/nexora/agent.json --interval 60s
nexora-agent validate-config --config /etc/nexora/agent.json
```

## Build and install

From `agents/linux-agent`:

```sh
go test ./...
go vet ./...
go build -trimpath -ldflags="-s -w" -o /tmp/nexora-agent ./cmd/nexora-agent
go build -trimpath -ldflags="-s -w" -o /tmp/nexora-provision ./cmd/nexora-provision
sudo install -o root -g root -m 0755 /tmp/nexora-agent /usr/local/bin/nexora-agent
sudo install -o root -g root -m 0755 /tmp/nexora-provision /usr/local/libexec/nexora-provision
```

Install the single-command sudo rule and validate it:

```sh
echo 'nexora-agent ALL=(root) NOPASSWD: /usr/local/libexec/nexora-provision ""' | sudo tee /etc/sudoers.d/nexora-agent >/dev/null
sudo chown root:root /etc/sudoers.d/nexora-agent
sudo chmod 0440 /etc/sudoers.d/nexora-agent
sudo visudo -cf /etc/sudoers.d/nexora-agent
```

The helper binary and sudoers rule must remain owned by root and must not be writable by the agent account.

For the systemd service, retain the unprivileged service user but permit only the capability set needed by the fixed root helper. Create `/etc/systemd/system/nexora-agent.service.d/override.conf` with:

```ini
[Service]
ProtectSystem=false
ProtectHome=false
NoNewPrivileges=false
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_FSETID CAP_SETGID CAP_SETUID CAP_SETFCAP CAP_AUDIT_WRITE
```

Then run `sudo systemctl daemon-reload && sudo systemctl restart nexora-agent`. The agent itself runs without effective root privileges; the exact sudoers rule is the only intended elevation path.

## Build and test

GitHub Actions runs `go test ./...` and builds both Linux binaries. The control-plane API must have the latest D1 migrations applied before job delivery is available.

## Current limitations

The first provisioning operation creates a restricted Linux account and document-root directory only. Web-server virtual hosts, PHP runtimes, database engines, TLS, DNS, mail, backups, quota enforcement, suspension, and deletion require separate, narrowly scoped helpers and integration tests. Never replace this allowlist with arbitrary shell execution.
