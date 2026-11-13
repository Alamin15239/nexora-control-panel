#!/usr/bin/env python3
"""Build the static-vhost trust registry from Wrangler D1 JSON and host NSS."""
import argparse, json, os, pwd, re, sys, tempfile
from pathlib import Path

ACCOUNT_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
DOMAIN_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
USERNAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
FIELDS = {"account_id", "username", "domain_id", "hostname"}

def find_rows(value, found):
    if isinstance(value, dict):
        if FIELDS.issubset(value):
            found.append(value)
        for child in value.values():
            find_rows(child, found)
    elif isinstance(value, list):
        for child in value:
            find_rows(child, found)

def valid_host(host):
    if not isinstance(host, str) or host != host.lower() or len(host) > 253 or host.endswith("."):
        return False
    labels = host.split(".")
    return len(labels) >= 2 and all(1 <= len(x) <= 63 and LABEL.fullmatch(x) for x in labels)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Wrangler D1 --json output")
    ap.add_argument("--output", required=True)
    ap.add_argument("--account", action="append", default=[], help="Limit to exact Linux username; repeatable")
    args = ap.parse_args()
    try:
        payload = json.loads(Path(args.input).read_text())
    except Exception as exc:
        raise SystemExit(f"Cannot parse Wrangler JSON: {exc}")
    rows = []
    find_rows(payload, rows)
    if not rows:
        raise SystemExit("No D1 account/domain rows found; refusing to create an empty trust registry")
    allowed = set(args.account)
    accounts, domains = {}, {}
    for row in rows:
        aid, user, did, host = (row.get(k) for k in ("account_id","username","domain_id","hostname"))
        if not all(isinstance(x, str) and x for x in (aid,user,did,host)):
            raise SystemExit("D1 row contains an empty or non-string identity")
        if allowed and user not in allowed:
            continue
        if not ACCOUNT_ID.fullmatch(aid) or not DOMAIN_ID.fullmatch(did) or not USERNAME.fullmatch(user):
            raise SystemExit(f"Invalid account/domain/Linux username in D1 row: {user!r}")
        if not valid_host(host):
            raise SystemExit(f"Non-canonical hostname in D1: {host!r}")
        try:
            entry = pwd.getpwnam(user)
        except KeyError:
            raise SystemExit(f"Linux user {user!r} from D1 does not exist in NSS; provision it first")
        if entry.pw_uid < 1000 or user in {"root","nobody","nexora-runtime","nexora-agent"}:
            raise SystemExit(f"Refusing system/reserved Linux user {user!r}")
        account = {"hostingAccountId": aid, "linuxUsername": user, "linuxUid": entry.pw_uid}
        previous = accounts.get(aid)
        if previous and previous != account:
            raise SystemExit(f"Conflicting D1 account mapping for {aid}")
        accounts[aid] = account
        domain = {"domainId": did, "hostingAccountId": aid, "hostname": host}
        if did in domains and domains[did] != domain:
            raise SystemExit(f"Conflicting D1 domain mapping for {did}")
        domains[did] = domain
    if not accounts or not domains:
        raise SystemExit("No matching D1 accounts/domains after filtering; refusing empty registry")
    if allowed and set(a["linuxUsername"] for a in accounts.values()) != allowed:
        missing = sorted(allowed - {a["linuxUsername"] for a in accounts.values()})
        raise SystemExit("Requested account(s) absent from eligible D1 rows: " + ", ".join(missing))
    hostnames = [d["hostname"] for d in domains.values()]
    if len(hostnames) != len(set(hostnames)):
        raise SystemExit("Duplicate hostname in D1 bindings")
    result = {"accounts": sorted(accounts.values(), key=lambda x:x["hostingAccountId"]),
              "domains": sorted(domains.values(), key=lambda x:x["domainId"])}
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".bindings-", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(result, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
    print(f"Generated {len(accounts)} account(s), {len(domains)} domain(s): {target}")
    for account in result["accounts"]:
        print(f"  {account['linuxUsername']} uid={account['linuxUid']} account={account['hostingAccountId']}")

if __name__ == "__main__":
    main()
