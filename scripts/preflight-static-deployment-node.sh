#!/usr/bin/env bash
# Read-only acceptance preflight for a dedicated Nexora static publisher node.
# This script never creates files, changes permissions, reloads services, or
# enables/starts units. Run it as root after operator provisioning.
set -Eeuo pipefail

failures=0
checks=0

pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1" >&2; failures=$((failures + 1)); }
check() {
  local description="$1"; shift
  checks=$((checks + 1))
  if "$@"; then pass "$description"; else fail "$description"; fi
}
expect_owner_mode() {
  local path="$1" owner="$2" group="$3" mode="$4"
  [[ -e "$path" && ! -L "$path" ]] || return 1
  [[ "$(stat -c '%U:%G:%a' -- "$path")" == "$owner:$group:$mode" ]]
}
is_executable_regular() { [[ -f "$1" && ! -L "$1" && -x "$1" ]]; }
has_group() {
  local user="$1" group="$2"
  id -nG "$user" | tr ' ' '\n' | grep -Fxq "$group"
}

if [[ "${EUID}" -ne 0 ]]; then
  printf 'Run this read-only preflight as root: sudo %s\n' "$0" >&2
  exit 2
fi

printf 'Nexora static publisher node preflight (read-only)\n'
printf 'No services will be started, stopped, enabled, or reloaded.\n\n'

check "publisher service account exists" getent passwd nexora-runtime
check "publisher primary group is www-data" bash -c '[[ "$(id -gn nexora-runtime 2>/dev/null)" == "www-data" ]]'
check "publisher has supplementary broker IPC group" has_group nexora-runtime nexora-static
check "Nginx serving group exists" getent group www-data
check "broker IPC group exists" getent group nexora-static

check "broker binary installed" is_executable_regular /usr/local/sbin/nexora-static-vhostd
check "publisher binary installed" is_executable_regular /usr/local/bin/nexora-static-publisher
check "broker unit installed" test -f /etc/systemd/system/nexora-static-vhostd.service
check "publisher unit installed" test -f /etc/systemd/system/nexora-static-publisher.service

check "broker trust directory is root:root 750" expect_owner_mode /etc/nexora-static-vhost root root 750
check "broker trust JSON is root:root 600" expect_owner_mode /etc/nexora-static-vhost/trust.json root root 600
check "broker public key is root:root 644" expect_owner_mode /etc/nexora-static-vhost/deployment-envelope-public.pem root root 644
check "broker bindings registry is root:root 600" expect_owner_mode /etc/nexora-static-vhost/bindings.json root root 600

check "publisher config directory is runtime:www-data 700" expect_owner_mode /etc/nexora-static-publisher nexora-runtime www-data 700
check "publisher node config is runtime:www-data 600" expect_owner_mode /etc/nexora-static-publisher/node.json nexora-runtime www-data 600
check "publisher node private key is runtime:www-data 600" expect_owner_mode /etc/nexora-static-publisher/node-ed25519.key nexora-runtime www-data 600
check "publisher deployment public key is runtime:www-data 600" expect_owner_mode /etc/nexora-static-publisher/deployment-envelope-public.pem nexora-runtime www-data 600

check "publisher data root is runtime:www-data 750" expect_owner_mode /var/lib/nexora-static nexora-runtime www-data 750
check "publisher accounts root is runtime:www-data 750" expect_owner_mode /var/lib/nexora-static/accounts nexora-runtime www-data 750
check "publisher replay directory is runtime:www-data 700" expect_owner_mode /var/lib/nexora-static/replay nexora-runtime www-data 700
check "Nginx config directory exists" test -d /etc/nginx/conf.d
check "Nginx can traverse publisher data root" runuser -u www-data -- test -x /var/lib/nexora-static/accounts
check "Nginx configuration validates" nginx -t
check "systemd units validate" systemd-analyze verify /etc/systemd/system/nexora-static-vhostd.service /etc/systemd/system/nexora-static-publisher.service

if command -v openssl >/dev/null 2>&1; then
  broker_fp="$(openssl pkey -pubin -in /etc/nexora-static-vhost/deployment-envelope-public.pem -outform DER 2>/dev/null | sha256sum | awk '{print $1}')" || broker_fp=""
  publisher_fp="$(openssl pkey -pubin -in /etc/nexora-static-publisher/deployment-envelope-public.pem -outform DER 2>/dev/null | sha256sum | awk '{print $1}')" || publisher_fp=""
  check "broker and publisher deployment public keys match" test -n "$broker_fp" -a "$broker_fp" = "$publisher_fp"
else
  fail "openssl is installed for deployment-key comparison"
fi

if command -v python3 >/dev/null 2>&1; then
  if python3 - <<'PY'
import json, re, subprocess, sys
from pathlib import Path

base = Path("/etc/nexora-static-vhost")
pub = Path("/etc/nexora-static-publisher")
try:
    trust = json.loads((base / "trust.json").read_text())
    bindings = json.loads((base / "bindings.json").read_text())
    config = json.loads((pub / "node.json").read_text())
except Exception as exc:
    print(f"configuration JSON cannot be read: {exc}", file=sys.stderr)
    sys.exit(1)

required = {"issuer", "audience", "keyId"}
if not required.issubset(trust) or not all(isinstance(trust[k], str) and trust[k] for k in required):
    print("broker trust JSON is missing issuer, audience, or keyId", file=sys.stderr)
    sys.exit(1)
if (config.get("deployment_envelope_issuer") != trust["issuer"] or
    config.get("deployment_envelope_audience") != trust["audience"] or
    config.get("deployment_signing_key_id") != trust["keyId"]):
    print("publisher envelope trust settings do not match broker trust", file=sys.stderr)
    sys.exit(1)
if config.get("publisher_root") != "/var/lib/nexora-static" or config.get("replay_directory") != "/var/lib/nexora-static/replay":
    print("publisher storage paths do not match the provisioned layout", file=sys.stderr)
    sys.exit(1)
if not isinstance(bindings.get("accounts"), list) or not bindings["accounts"] or not isinstance(bindings.get("domains"), list) or not bindings["domains"]:
    print("bindings registry must contain at least one account and one domain", file=sys.stderr)
    sys.exit(1)

account_ids, usernames, uids = set(), set(), set()
for account in bindings["accounts"]:
    aid, username, uid = account.get("hostingAccountId"), account.get("linuxUsername"), account.get("linuxUid")
    if not isinstance(aid, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", aid):
        raise SystemExit("invalid hosting account ID in bindings registry")
    if not isinstance(username, str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", username):
        raise SystemExit("invalid Linux username in bindings registry")
    if not isinstance(uid, int) or uid < 1000:
        raise SystemExit("invalid Linux UID in bindings registry")
    if aid in account_ids or username in usernames or uid in uids:
        raise SystemExit("duplicate account ID, username, or UID in bindings registry")
    account_ids.add(aid); usernames.add(username); uids.add(uid)
    try:
        actual = subprocess.check_output(["id", "-u", username], text=True).strip()
    except Exception:
        raise SystemExit(f"Linux account {username} is missing from NSS")
    if actual != str(uid):
        raise SystemExit(f"Linux UID mismatch for hosting account {aid}")

domain_ids, hostnames = set(), set()
for domain in bindings["domains"]:
    did, aid, hostname = domain.get("domainId"), domain.get("hostingAccountId"), domain.get("hostname")
    if not isinstance(did, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", did):
        raise SystemExit("invalid domain ID in bindings registry")
    if aid not in account_ids:
        raise SystemExit("domain references an unknown hosting account")
    if not isinstance(hostname, str) or hostname != hostname.lower() or len(hostname) > 253:
        raise SystemExit("hostname must be canonical lowercase DNS text")
    labels = hostname.split(".")
    if len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        raise SystemExit("invalid hostname in bindings registry")
    if did in domain_ids or hostname in hostnames:
        raise SystemExit("duplicate domain ID or hostname in bindings registry")
    domain_ids.add(did); hostnames.add(hostname)
print(f"validated {len(account_ids)} account and {len(domain_ids)} domain bindings")
PY
  then
    pass "publisher and broker trust metadata plus account/domain registry agree"
  else
    fail "publisher and broker trust metadata plus account/domain registry validate"
  fi
else
  fail "python3 is installed for registry validation"
fi

printf '\nChecks: %d; failures: %d\n' "$checks" "$failures"
if (( failures > 0 )); then
  printf 'Preflight failed. Do not start or enable either service.\n' >&2
  exit 1
fi
printf 'Preflight passed. This does not authorize service activation or production use.\n'
