#!/usr/bin/env bash
# Stage B: install trust/configuration only. Does not install binaries or activate services.
set -Eeuo pipefail
D1_JSON="" PUBLIC_PEM="" ISSUER="" AUDIENCE="" KEY_ID="" NODE_ID="nexora-server-static-01"
ACCOUNT=""
usage(){ cat <<'EOF'
Usage:
  sudo bash scripts/prepare-static-deployment-node.sh \
    --d1-json /tmp/nexora-hosting-bindings.json \
    --public-key /path/to/deployment-envelope-public.pem \
    --issuer https://api.nexoraedge.digital \
    --audience nexora-static-node-v1 \
    --key-id YOUR_WORKER_KEY_ID \
    [--account nxoratest01] [--node-id nexora-server-static-01]

This installs trust/config files only. It never installs binaries, enrolls the node,
changes pool admission, starts/enables services, or handles a private RSA key.
EOF
}
while (($#)); do
 case "$1" in
  --d1-json) D1_JSON="$2"; shift 2;;
  --public-key) PUBLIC_PEM="$2"; shift 2;;
  --issuer) ISSUER="$2"; shift 2;;
  --audience) AUDIENCE="$2"; shift 2;;
  --key-id) KEY_ID="$2"; shift 2;;
  --node-id) NODE_ID="$2"; shift 2;;
  --account) ACCOUNT="$2"; shift 2;;
  -h|--help) usage; exit 0;;
  *) echo "Unknown argument: $1" >&2; usage >&2; exit 2;;
 esac
done
[[ $EUID -eq 0 ]] || { echo "Run with sudo" >&2; exit 2; }
[[ "$(hostname -s)" == "nexora-server" ]] || { echo "Refusing host $(hostname -s); expected nexora-server" >&2; exit 3; }
[[ -f "$D1_JSON" && ! -L "$D1_JSON" ]] || { echo "D1 JSON file missing or symlinked" >&2; exit 2; }
[[ -f "$PUBLIC_PEM" && ! -L "$PUBLIC_PEM" ]] || { echo "Public PEM missing or symlinked" >&2; exit 2; }
[[ -n "$ISSUER" && ${#ISSUER} -le 256 && -n "$AUDIENCE" && ${#AUDIENCE} -le 256 ]] || { echo "Issuer and audience are required (max 256 chars)" >&2; exit 2; }
[[ "$KEY_ID" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || { echo "Invalid key ID" >&2; exit 2; }
[[ "$NODE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$ ]] || { echo "Invalid node identity" >&2; exit 2; }
getent passwd nexora-runtime >/dev/null || { echo "nexora-runtime account missing; run Stage A first" >&2; exit 4; }
[[ "$(id -gn nexora-runtime)" == "www-data" ]] || { echo "nexora-runtime primary group must be www-data" >&2; exit 4; }
getent group nexora-static >/dev/null || { echo "nexora-static group missing; run Stage A first" >&2; exit 4; }
command -v openssl >/dev/null
command -v go >/dev/null
command -v python3 >/dev/null
openssl rsa -pubin -in "$PUBLIC_PEM" -noout >/dev/null 2>&1 || { echo "Public PEM must be an RSA public key" >&2; exit 5; }
BITS="$(openssl rsa -pubin -in "$PUBLIC_PEM" -text -noout 2>/dev/null | sed -n 's/.*(\([0-9][0-9]*\) bit).*/\1/p' | head -1)"
[[ "${BITS:-0}" -ge 2048 ]] || { echo "RSA public key must be at least 2048 bits" >&2; exit 5; }
for p in /etc/nexora-static-vhost /etc/nexora-static-publisher; do
 [[ ! -e "$p" && ! -L "$p" ]] || { echo "Refusing to overwrite existing path: $p" >&2; exit 6; }
done
TMP="$(mktemp -d /tmp/nexora-stage-b.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
GEN="$(dirname "$0")/generate-static-vhost-bindings.py"
[[ -f "$GEN" ]] || { echo "Missing bindings generator: $GEN" >&2; exit 7; }
GEN_ARGS=(--input "$D1_JSON" --output "$TMP/bindings.json")
if [[ -n "$ACCOUNT" ]]; then GEN_ARGS+=(--account "$ACCOUNT"); fi
python3 "$GEN" "${GEN_ARGS[@]}"
# Go's standard library generates the exact 64-byte ed25519.PrivateKey format
# consumed by nexora-static-publisher. Private key bytes never enter stdout.
cat >"$TMP/keygen.go" <<'GO'
package main
import("crypto/ed25519";"crypto/rand";"encoding/hex";"fmt";"os")
func main(){pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{panic(err)}
if err=os.WriteFile(os.Args[1],[]byte(hex.EncodeToString(priv)+"\n"),0600);err!=nil{panic(err)}
fmt.Println(hex.EncodeToString(pub))}
GO
NODE_PUBLIC="$(go run "$TMP/keygen.go" "$TMP/node-ed25519.key")"
[[ "$NODE_PUBLIC" =~ ^[0-9a-f]{64}$ ]] || { echo "Ed25519 key generation failed" >&2; exit 8; }
python3 - "$TMP" "$ISSUER" "$AUDIENCE" "$KEY_ID" "$NODE_ID" <<'PY'
import json, pathlib, sys
d=pathlib.Path(sys.argv[1]); issuer,audience,key_id,node_id=sys.argv[2:]
(d/"trust.json").write_text(json.dumps({"issuer":issuer,"audience":audience,"keyId":key_id},indent=2)+"\n")
config={
 "control_plane_url":"https://api.nexoraedge.digital",
 "node_identity":node_id,
 "private_key_file":"/etc/nexora-static-publisher/node-ed25519.key",
 "deployment_signing_public_key_file":"/etc/nexora-static-publisher/deployment-envelope-public.pem",
 "deployment_signing_key_id":key_id,
 "deployment_envelope_issuer":issuer,
 "deployment_envelope_audience":audience,
 "publisher_root":"/var/lib/nexora-static",
 "replay_directory":"/var/lib/nexora-static/replay",
 "poll_interval_seconds":30,
 "rollback_execution_enabled":False
}
(d/"node.json").write_text(json.dumps(config,indent=2)+"\n")
PY
install -d -o root -g root -m 0750 /etc/nexora-static-vhost
install -o root -g root -m 0600 "$TMP/trust.json" /etc/nexora-static-vhost/trust.json
install -o root -g root -m 0644 "$PUBLIC_PEM" /etc/nexora-static-vhost/deployment-envelope-public.pem
install -o root -g root -m 0600 "$TMP/bindings.json" /etc/nexora-static-vhost/bindings.json
install -d -o nexora-runtime -g www-data -m 0700 /etc/nexora-static-publisher
install -o nexora-runtime -g www-data -m 0600 "$TMP/node.json" /etc/nexora-static-publisher/node.json
install -o nexora-runtime -g www-data -m 0600 "$TMP/node-ed25519.key" /etc/nexora-static-publisher/node-ed25519.key
install -o nexora-runtime -g www-data -m 0600 "$PUBLIC_PEM" /etc/nexora-static-publisher/deployment-envelope-public.pem
echo
echo "STAGE B FILES INSTALLED. SERVICES REMAIN UNTOUCHED."
echo "Node identity: $NODE_ID"
echo "Deployment envelope key ID: $KEY_ID"
echo "Node Ed25519 public key (save for the operator enrollment step):"
echo "$NODE_PUBLIC"
echo
echo "Next: run the read-only preflight only after Stage A binaries, units, and data directories are installed."
echo "No enrollment, pool admission, or service activation was performed."
