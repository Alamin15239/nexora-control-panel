# Static deployment node trust and filesystem setup

This is an operator runbook for a **disposable, explicitly approved static publisher node**. It does not authorize enrolling the existing development VM or enabling production deployments. Complete the architecture acceptance gates before running these commands.

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

## 2. Install the public trust on the node

Transfer only the public PEM and trust JSON over an authenticated operator channel. Create the root broker trust directory and install the public key:

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

The broker also requires a separate root-owned `bindings.json` registry. Start from `agents/linux-agent/config.static-vhost-bindings.example.json`, but replace every example value using the authoritative hosting-account and domain records on the node. Each hosting account maps to exactly one existing non-system Linux username and UID (UID 1000 or greater); each domain maps to exactly one hosting-account ID and its canonical lowercase hostname. Do not copy values from a deployment request or customer artifact. Keep account IDs, domain IDs, usernames, and UIDs unique. The broker rejects missing, duplicate, unknown, or mismatched mappings and will not install a vhost when the signed envelope does not exactly match this file.

The file is deliberately a local operator-managed trust anchor. Provision and update it only through an authenticated root-level configuration-management process; do not expose a customer API for editing it. After changing it, verify ownership and permissions and restart the broker during a controlled maintenance window.

The publisher also needs the same public key. Install a read-only copy at the path in `config.static-publisher.example.json`:

```sh
sudo install -o root -g nexora-static -m 0640 \
  nexora-deployment-envelope-public.pem \
  /etc/nexora-static-publisher/deployment-envelope-public.pem
```

The broker independently loads its root-owned copy. The publisher's copy is used for its own full deployment-identity verification. The private signing key never leaves the Worker.

## 3. Prepare serving permissions

The publisher service runs as `nexora-runtime`, primary group `nexora-static`, with `www-data` as a supplementary read group. Keep the publisher write boundary separate from Nginx's read boundary.

For each provisioned account, the expected shape is:

- Account root: owner `nexora-runtime`, group `www-data`, mode `0750`.
- `staging` and `releases`: owner `nexora-runtime`, group `www-data`, mode `2750` (setgid).
- Activated release directories: group `www-data`, readable/traversable by that group, not group-writable.
- Website files: mode `0644`; directories: mode `0755`; active pointer: publisher-managed symlink named `current`.

All parent directories from `/var/lib` through the account root must be traversable by `www-data`. Do not make release directories or files writable by `www-data`. The static publisher normalizes extracted file and directory modes; the setgid serving directories preserve the read group.

## 4. Install and verify services without enabling them

Build the Linux binaries from the reviewed branch and install the broker binary and unit only after its trust files and service accounts exist. The broker unit runs as root with primary group `nexora-static`; systemd creates `/run/nexora-static-vhost` with that group. The daemon creates a `0660` socket and does not require `CAP_CHOWN`.

Before starting either service:

```sh
sudo systemd-analyze verify /etc/systemd/system/nexora-static-vhostd.service
sudo systemd-analyze verify /etc/systemd/system/nexora-static-publisher.service
sudo stat -c '%U:%G:%a %n' \
  /etc/nexora-static-vhost \
  /etc/nexora-static-vhost/trust.json \
  /etc/nexora-static-vhost/deployment-envelope-public.pem \
  /etc/nexora-static-vhost/bindings.json
```

Expected trust permissions are root-owned, directory `750` or stricter, trust JSON `600`, and public PEM `644` or stricter. The broker refuses symlinked or group/world-writable trust files.

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
