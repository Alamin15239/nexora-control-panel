# Static deployment node trust and filesystem setup

This is an operator runbook for a **non-production, explicitly approved static publisher test node**. The normal path is a disposable VM. The user-selected `nexora-server` may use the narrowly scoped `development-test` install path below, but this does not make it a production node or authorize customer deployments. Complete the architecture acceptance gates before starting either service.

## 0. Install reviewed binaries on an approved disposable node

The repository includes `scripts/install-static-deployment-node.sh`. It defaults to
a read-only plan and accepts only a directory containing these four reviewed
artifacts:

- `nexora-static-vhostd`
- `nexora-static-publisher`
- `nexora-static-vhostd.service`
- `nexora-static-publisher.service`

First inspect the plan without changing the node:

```sh
bash scripts/install-static-deployment-node.sh --artifact-dir /path/to/reviewed-artifacts --plan
```

Applying requires all of the following: an explicitly disposable test node, a
root-owned approval file with mode `0600`, an exact node identity match, and
the explicit `--apply` flag. For a disposable test VM, the approval file schema is exactly:

```json
{
  "environment": "disposable-test",
  "node_identity": "YOUR_APPROVED_NODE_ID",
  "allow_static_publisher_install": true
}
```

The selected `nexora-server` has a separate, explicit development-test approval
shape. Create it only through the authenticated operator process after confirming
the exact node identity and that the purpose is a controlled test—not production:

```json
{
  "environment": "development-test",
  "node_identity": "YOUR_NEXORA_SERVER_NODE_ID",
  "allow_static_publisher_install": true,
  "allow_development_host_install": true
}
```

This exception is restricted to the exact hostname `nexora-server` and requires
both the `--development-test` command-line flag and the root-owned approval file.
It does not enable services, enroll the node, change runtime-pool admission, enable
`static-v1`, or authorize customer workloads. Never use this approval shape on a
production host.

For a disposable VM, use:

```sh
sudo bash scripts/install-static-deployment-node.sh \
  --artifact-dir /path/to/reviewed-artifacts \
  --node-id YOUR_APPROVED_NODE_ID --apply
```

For the explicitly selected `nexora-server` development-test install only, use:

```sh
sudo bash scripts/install-static-deployment-node.sh \
  --artifact-dir /path/to/reviewed-artifacts \
  --node-id YOUR_NEXORA_SERVER_NODE_ID --development-test --apply
```

The installer creates/verifies the dedicated service identity and data
directories, then installs root-owned binaries and unit files. It refuses to
overwrite existing binary/unit targets. It does **not** install private keys,
trust JSON, account/domain bindings, or publisher configuration. It does not
run `systemctl daemon-reload`, start, enable, or reload either service.
Complete the remaining operator trust/configuration steps below, then run the
read-only preflight. Service activation remains a separate, explicit
acceptance decision and is not authorized by a successful install or preflight.

## 1. Create the deployment-envelope signing key pair

Generate a dedicated RSA key pair on a trusted operator workstation. Keep the private key outside the repository and outside every hosting node.

```sh
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out nexora-deployment-envelope-private.pem
openssl pkey -in nexora-deployment-envelope-private.pem -pubout \
  -out nexora-deployment-envelope-public.pem
openssl pkey -pubin -in nexora-deployment-envelope-public.pem -text -noout
```

Choose a stable key ID matching `^[A-Za-z0-9._-]{1,64}$`. Configure the Cloudflare Worker secrets with the matching private key and metadata:

- `GITHUB_DEPLOYMENT_ENVELOPE_PRIVATE_KEY`: complete PKCS#8 private PEM.
- `GITHUB_DEPLOYMENT_ENVELOPE_KEY_ID`: the chosen key ID.
- `GITHUB_DEPLOYMENT_ENVELOPE_ISSUER`: the exact issuer string used by the publisher.
- `GITHUB_DEPLOYMENT_ENVELOPE_AUDIENCE`: the exact audience string used by the publisher.

Use the correct Worker environment when setting secrets. Never commit the private PEM, paste it into source files, or install it on a runtime node. The Worker signs five-minute RS256 envelopes; the nodes receive only the public key.

## 2. Install the root broker trust

Transfer the public PEM, trust JSON, and account/domain registry over an authenticated operator channel. Create the root broker trust directory and install the files:

```sh
sudo install -d -o root -g root -m 0750 /etc/nexora-static-vhost
sudo install -o root -g root -m 0600 trust.json \
  /etc/nexora-static-vhost/trust.json
sudo install -o root -g root -m 0644 nexora-deployment-envelope-public.pem \
  /etc/nexora-static-vhost/deployment-envelope-public.pem
sudo install -o root -g root -m 0600 bindings.json \
  /etc/nexora-static-vhost/bindings.json
```

The trust JSON must use the exact Worker values:

```json
{
  "issuer": "YOUR_CONFIGURED_ISSUER",
  "audience": "YOUR_CONFIGURED_AUDIENCE",
  "keyId": "YOUR_ACTIVE_KEY_ID"
}
```

The broker also requires a separate root-owned `bindings.json` registry. Start from `agents/linux-agent/config.static-vhost-bindings.example.json`, but replace every example value using the authoritative hosting-account and domain records on the node. Each hosting account maps to exactly one existing non-system Linux username and UID (UID 1000 or greater); each domain maps to exactly one hosting-account ID and its canonical lowercase hostname. Do not copy values from a deployment request or customer artifact. Keep account IDs, domain IDs, hostnames, usernames, and UIDs unique. At broker startup, each configured Linux username must resolve through the host's NSS account database to the exact UID recorded in the registry. The broker rejects missing, duplicate, unknown, stale, or mismatched mappings and will not install a vhost when the signed envelope does not exactly match this file.

The file is deliberately a local operator-managed trust anchor. Provision and update it only through an authenticated root-level configuration-management process; do not expose a customer API for editing it. After changing it, verify ownership and permissions and restart the broker during a controlled maintenance window.

## 3. Establish the publisher and Nginx group boundary

The publisher runs as `nexora-runtime:www-data`. This is intentional: its account directories are created with the process's primary group, and Nginx workers need read/traverse access through `www-data`. The publisher receives `nexora-static` only as a supplementary group so it can connect to the root broker's Unix socket. Do not reverse these groups: doing so creates release directories that Nginx cannot traverse.

Create the publisher account and group membership through the host's normal account-management process. Before installing the service, provision the publisher-owned paths with the exact owner/group expected by the daemon:

```sh
sudo install -d -o nexora-runtime -g www-data -m 0750 /var/lib/nexora-static
sudo install -d -o nexora-runtime -g www-data -m 0750 /var/lib/nexora-static/accounts
sudo install -d -o nexora-runtime -g www-data -m 0700 /var/lib/nexora-static/replay
sudo install -d -o nexora-runtime -g www-data -m 0700 /etc/nexora-static-publisher
```

Install the publisher's public verification key, node private key, and JSON config as publisher-owned files with exact mode `0600` and group `www-data`, because the daemon verifies both UID and primary GID:

```sh
sudo install -o nexora-runtime -g www-data -m 0600 \
  nexora-deployment-envelope-public.pem \
  /etc/nexora-static-publisher/deployment-envelope-public.pem
sudo install -o nexora-runtime -g www-data -m 0600 node-ed25519.key \
  /etc/nexora-static-publisher/node-ed25519.key
sudo install -o nexora-runtime -g www-data -m 0600 node.json \
  /etc/nexora-static-publisher/node.json
```

The publisher's public-key copy is used for its own full deployment-identity verification. The broker independently loads its root-owned copy. The private deployment-signing key never leaves the Worker.

For each provisioned account, the expected shape is:

- Account root: owner `nexora-runtime`, group `www-data`, mode `0750`.
- `staging` and `releases`: owner `nexora-runtime`, group `www-data`, mode `2750` (setgid).
- Activated release directories: group `www-data`, readable/traversable by that group, not group-writable.
- Website files: mode `0644`; directories: mode `0755`; active pointer: publisher-managed symlink named `current`.

All parent directories from `/var/lib` through the account root must be traversable by `www-data`. Do not make release directories or files writable by `www-data`. The publisher normalizes extracted file and directory modes; the setgid serving directories preserve the read group.

## 4. Install and verify services without enabling them

Build the Linux binaries from the reviewed branch and install the broker binary and unit only after its trust files and service accounts exist. The broker unit runs as root with primary group `nexora-static`; systemd creates `/run/nexora-static-vhost` with that group. The daemon creates a `0660` socket. The publisher's supplementary `nexora-static` membership grants access to that socket without granting it general root or provisioning privileges.

Before starting either service:

```sh
sudo systemd-analyze verify /etc/systemd/system/nexora-static-vhostd.service
sudo systemd-analyze verify /etc/systemd/system/nexora-static-publisher.service
sudo stat -c '%U:%G:%a %n' \
  /etc/nexora-static-vhost \
  /etc/nexora-static-vhost/trust.json \
  /etc/nexora-static-vhost/deployment-envelope-public.pem \
  /etc/nexora-static-vhost/bindings.json \
  /var/lib/nexora-static \
  /var/lib/nexora-static/accounts \
  /var/lib/nexora-static/replay \
  /etc/nexora-static-publisher/node.json \
  /etc/nexora-static-publisher/node-ed25519.key \
  /etc/nexora-static-publisher/deployment-envelope-public.pem
```

Expected broker trust permissions are root-owned, directory `750` or stricter, trust JSON and binding registry `600`, and public PEM `644` or stricter. Publisher config/key files must be owned by `nexora-runtime:www-data` with mode `600`; publisher root/accounts directories must be `nexora-runtime:www-data` mode `750`, and replay storage `nexora-runtime:www-data` mode `700`. The broker refuses symlinked or group/world-writable trust files and rejects a missing or inconsistent account/domain registry.

Run the repository's read-only preflight after installing the reviewed binaries, units, trust files, publisher config and directory layout. From the reviewed checkout:

```sh
sudo bash scripts/preflight-static-deployment-node.sh
```

The preflight checks service identities and group membership, exact file ownership/modes, both copies of the deployment public key, matching issuer/audience/key ID, NSS UID mappings, unique account/domain bindings, Nginx traversal, `nginx -t`, and systemd unit validity. It does not create or modify files and never starts, stops, enables, or reloads services. A non-zero exit means the node is not ready; correct the issue through the approved operator process and rerun it. A successful preflight is necessary but does not replace the disposable-hostname deployment, health, rollback, or Cloudflare-path acceptance tests.

Do not enable the services until all of the following are true:

- The signing key ID, issuer, audience, and public key match the deployed Worker environment.
- The enrolled node identity and publisher configuration are verified.
- The node is explicitly approved for static publishing and has the required filesystem layout.
- The broker socket peer-UID test, signed-envelope tests, race tests, and full Linux-agent CI pass.
- A disposable-VM test proves the exact hostname returns the expected release over HTTP and that a failed Nginx reload restores the previous config.
- Health reporting and rollback orchestration are tested end to end.

## 5. Key rotation

For rotation, generate a new key pair and a new key ID. Deploy the new public key and trust metadata to every approved publisher node before switching the Worker to sign with the new key. During a controlled overlap, the broker currently trusts one configured key ID at a time, so coordinate the cutover: update node trust files and restart the broker, then switch Worker signing. Retain the old private key offline only for the defined incident-recovery window, then destroy it according to the operator key-retention policy.

Never silently replace a public key under the same key ID. Record the key ID, issuer, audience, deployment date, and approving operator in the change log.
