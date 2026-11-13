#!/usr/bin/env bash
# Plan-first installer for an explicitly approved disposable static node.
# It never installs secrets and never starts, enables, or reloads services.
set -Eeuo pipefail
MODE=plan
ARTIFACT_DIR=""
NODE_ID=""
DEVELOPMENT_TEST=0
APPROVAL_FILE="/etc/nexora-static-node/approval.json"
usage() {
  cat <<'EOF'
Usage: install-static-deployment-node.sh --artifact-dir DIR [--node-id ID] [--plan]
       install-static-deployment-node.sh --artifact-dir DIR --node-id ID --apply
       install-static-deployment-node.sh --artifact-dir DIR --node-id ID --development-test --apply
Default is a read-only plan. Disposable-node apply requires a root:root 0600 approval JSON:
{"environment":"disposable-test","node_identity":"NODE_ID","allow_static_publisher_install":true}
The explicitly selected nexora-server development-test path additionally requires:
{"environment":"development-test","node_identity":"NODE_ID","allow_static_publisher_install":true,"allow_development_host_install":true}
The installer only installs binaries and disabled unit files. It never starts,
enables, or reloads services and never installs keys, trust, bindings, or config.
Development-test installation does not authorize node enrollment, runtime admission,
customer deployments, or production use.
EOF
}
while (($#)); do
  case "$1" in
    --plan) MODE=plan; shift ;;
    --apply) MODE=apply; shift ;;
    --artifact-dir) [[ $# -ge 2 ]] || { echo "Missing --artifact-dir value" >&2; exit 2; }; ARTIFACT_DIR=$2; shift 2 ;;
    --node-id) [[ $# -ge 2 ]] || { echo "Missing --node-id value" >&2; exit 2; }; NODE_ID=$2; shift 2 ;;
    --development-test) DEVELOPMENT_TEST=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
[[ -n "$ARTIFACT_DIR" ]] || { echo "--artifact-dir is required" >&2; exit 2; }
[[ -d "$ARTIFACT_DIR" && ! -L "$ARTIFACT_DIR" ]] || { echo "Artifact directory must be a real directory" >&2; exit 2; }
for file in nexora-static-vhostd nexora-static-publisher nexora-static-vhostd.service nexora-static-publisher.service; do
  [[ -f "$ARTIFACT_DIR/$file" && ! -L "$ARTIFACT_DIR/$file" ]] || { echo "Missing regular artifact: $file" >&2; exit 2; }
done
for file in nexora-static-vhostd nexora-static-publisher; do
  [[ -x "$ARTIFACT_DIR/$file" ]] || { echo "Artifact is not executable: $file" >&2; exit 2; }
done
grep -Fxq 'User=root' "$ARTIFACT_DIR/nexora-static-vhostd.service"
grep -Fxq 'Group=nexora-static' "$ARTIFACT_DIR/nexora-static-vhostd.service"
grep -Fxq 'User=nexora-runtime' "$ARTIFACT_DIR/nexora-static-publisher.service"
grep -Fxq 'Group=www-data' "$ARTIFACT_DIR/nexora-static-publisher.service"
grep -Fxq 'SupplementaryGroups=nexora-static' "$ARTIFACT_DIR/nexora-static-publisher.service"
TARGETS=(/usr/local/sbin/nexora-static-vhostd /usr/local/bin/nexora-static-publisher /etc/systemd/system/nexora-static-vhostd.service /etc/systemd/system/nexora-static-publisher.service)
# Tests may redirect plan-only target inspection into a disposable root. Apply
# mode deliberately ignores this variable and always uses the real system paths.
if [[ "$MODE" == "plan" && -n "${NEXORA_STATIC_PLAN_ROOT:-}" ]]; then
  [[ "$NEXORA_STATIC_PLAN_ROOT" == /* && "$NEXORA_STATIC_PLAN_ROOT" != "/" ]] || {
    echo "NEXORA_STATIC_PLAN_ROOT must be a non-root absolute path" >&2; exit 2;
  }
  for i in "${!TARGETS[@]}"; do TARGETS[$i]="$NEXORA_STATIC_PLAN_ROOT${TARGETS[$i]}"; done
fi
if [[ "$MODE" == "plan" ]]; then
  printf 'PLAN ONLY: no machine changes will be made.\n'
  printf 'Artifact directory: %s\n' "$ARTIFACT_DIR"
  printf 'Would create/verify nexora-static group and nexora-runtime:www-data service account.\n'
  printf 'Would install binaries root:root 0755 and units root:root 0644.\n'
  if [[ "$DEVELOPMENT_TEST" == "1" ]]; then printf 'Mode: explicit development-test only; no node enrollment or customer runtime admission.\n'; fi
  printf 'Would leave both services stopped and disabled; no secrets/config installed.\n'
  for target in "${TARGETS[@]}"; do
    if [[ -e "$target" || -L "$target" ]]; then printf 'CONFLICT: target already exists: %s\n' "$target" >&2; exit 3; fi
    printf '  %s\n' "$target"
  done
  exit 0
fi
[[ "${EUID}" -eq 0 ]] || { echo "--apply must run as root" >&2; exit 2; }
[[ -n "$NODE_ID" && "$NODE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$ ]] || { echo "--apply requires a valid --node-id" >&2; exit 2; }
host="$(hostname -s)"
if [[ "$host" == "nexora-server" ]]; then
  [[ "$DEVELOPMENT_TEST" == "1" ]] || { echo "Refusing nexora-server install without explicit --development-test approval" >&2; exit 4; }
elif [[ "$DEVELOPMENT_TEST" == "1" ]]; then
  echo "--development-test is restricted to the exact host nexora-server" >&2
  exit 4
fi
[[ -f "$APPROVAL_FILE" && ! -L "$APPROVAL_FILE" ]] || { echo "Missing operator approval file: $APPROVAL_FILE" >&2; exit 4; }
[[ "$(stat -c '%U:%G:%a' "$APPROVAL_FILE")" == "root:root:600" ]] || { echo "Approval file must be root:root mode 0600" >&2; exit 4; }
python3 - "$APPROVAL_FILE" "$NODE_ID" "$DEVELOPMENT_TEST" <<'PY'
import json, sys
from pathlib import Path
try:
    approval = json.loads(Path(sys.argv[1]).read_text())
except Exception as exc:
    raise SystemExit(f"Invalid approval JSON: {exc}")
common = {"node_identity", "allow_static_publisher_install"}
if sys.argv[3] == "1":
    expected = common | {"environment", "allow_development_host_install"}
    valid = (isinstance(approval, dict) and set(approval) == expected and
             approval.get("environment") == "development-test" and
             approval.get("node_identity") == sys.argv[2] and
             approval.get("allow_static_publisher_install") is True and
             approval.get("allow_development_host_install") is True)
    if not valid:
        raise SystemExit("Approval must explicitly authorize this exact nexora-server development-test node")
else:
    expected = common | {"environment"}
    valid = (isinstance(approval, dict) and set(approval) == expected and
             approval.get("environment") == "disposable-test" and
             approval.get("node_identity") == sys.argv[2] and
             approval.get("allow_static_publisher_install") is True)
    if not valid:
        raise SystemExit("Approval must explicitly authorize this disposable test node identity")
PY
for target in "${TARGETS[@]}"; do
  [[ ! -e "$target" && ! -L "$target" ]] || { echo "Refusing to overwrite existing target: $target" >&2; exit 4; }
done
getent group www-data >/dev/null || { echo "Required Nginx group www-data is missing" >&2; exit 5; }
getent group nexora-static >/dev/null || groupadd --system nexora-static
if ! getent passwd nexora-runtime >/dev/null; then
  useradd --system --home-dir /var/lib/nexora-static --no-create-home --shell /usr/sbin/nologin --gid www-data --groups nexora-static nexora-runtime
else
  # passwd fields are name:password:uid:gid:gecos:home:shell; retain GECOS so HOME and SHELL are read correctly.
  IFS=: read -r runtime_name _ runtime_uid runtime_gid runtime_gecos runtime_home runtime_shell < <(getent passwd nexora-runtime)
  [[ "$runtime_name" == "nexora-runtime" && "$runtime_uid" -lt 1000 ]] || { echo "Existing nexora-runtime account is not a system account" >&2; exit 5; }
  [[ "$runtime_home" == "/var/lib/nexora-static" ]] || { echo "Existing nexora-runtime home is not /var/lib/nexora-static" >&2; exit 5; }
  [[ "$runtime_shell" == "/usr/sbin/nologin" ]] || { echo "Existing nexora-runtime shell is not /usr/sbin/nologin" >&2; exit 5; }
  [[ "$(id -gn nexora-runtime)" == "www-data" ]] || { echo "Existing nexora-runtime primary group is not www-data" >&2; exit 5; }
  id -nG nexora-runtime | tr ' ' '\n' | grep -Fxq nexora-static || usermod -a -G nexora-static nexora-runtime
fi
install -d -o nexora-runtime -g www-data -m 0750 /var/lib/nexora-static /var/lib/nexora-static/accounts
install -d -o nexora-runtime -g www-data -m 0700 /var/lib/nexora-static/replay
install -D -o root -g root -m 0755 "$ARTIFACT_DIR/nexora-static-vhostd" /usr/local/sbin/nexora-static-vhostd
install -D -o root -g root -m 0755 "$ARTIFACT_DIR/nexora-static-publisher" /usr/local/bin/nexora-static-publisher
install -D -o root -g root -m 0644 "$ARTIFACT_DIR/nexora-static-vhostd.service" /etc/systemd/system/nexora-static-vhostd.service
install -D -o root -g root -m 0644 "$ARTIFACT_DIR/nexora-static-publisher.service" /etc/systemd/system/nexora-static-publisher.service
printf 'Installed on approved disposable node %s. Services remain stopped and disabled.\n' "$NODE_ID"
