#!/usr/bin/env bash
set -Eeuo pipefail

# Install Cloudflare's signed cloudflared package and register a remotely-managed
# tunnel as a systemd service. The tunnel token is read silently and never
# written to this script, shell history, or command output.

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this script with sudo: sudo bash scripts/setup-cloudflare-tunnel.sh" >&2
  exit 1
fi

if [[ ! -r /etc/os-release ]]; then
  echo "Cannot identify this Linux distribution." >&2
  exit 1
fi
# shellcheck disable=SC1091
source /etc/os-release
if [[ "${ID:-}" != "ubuntu" && "${ID_LIKE:-}" != *"debian"* ]]; then
  echo "This installer currently supports Ubuntu and Debian only." >&2
  exit 1
fi

if ! systemctl is-active --quiet nginx; then
  echo "Nginx must be running before the tunnel is installed." >&2
  exit 1
fi

if systemctl cat cloudflared.service >/dev/null 2>&1; then
  echo "A cloudflared systemd service already exists. Refusing to overwrite it." >&2
  exit 1
fi

echo "Installing cloudflared from Cloudflare's signed APT repository..."
install -d -m 0755 /usr/share/keyrings
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
  -o /usr/share/keyrings/cloudflare-main.gpg
chmod 0644 /usr/share/keyrings/cloudflare-main.gpg
printf '%s\n' \
  "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" \
  > /etc/apt/sources.list.d/cloudflared.list
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y cloudflared

echo
echo "In Cloudflare Zero Trust, create a remotely-managed tunnel and copy its install token."
echo "The token will be read without displaying it. Do not paste it into chat."
read -r -s -p "Cloudflare Tunnel token: " TUNNEL_TOKEN
printf '\n'
if [[ ! "${TUNNEL_TOKEN}" =~ ^[A-Za-z0-9._-]{80,}$ ]]; then
  unset TUNNEL_TOKEN
  echo "The token format does not look valid. No tunnel service was installed." >&2
  exit 1
fi

echo "Registering the tunnel service..."
if ! cloudflared service install "${TUNNEL_TOKEN}"; then
  unset TUNNEL_TOKEN
  echo "Cloudflare rejected the service installation. Check the tunnel token in Cloudflare." >&2
  exit 1
fi
unset TUNNEL_TOKEN

systemctl enable --now cloudflared.service
sleep 2

if ! systemctl is-active --quiet cloudflared.service; then
  systemctl --no-pager --full status cloudflared.service || true
  echo "cloudflared did not become active. Review the service logs before retrying." >&2
  exit 1
fi

echo
echo "cloudflared service is active."
echo "Next: in Cloudflare Tunnel > Public Hostnames, route your real hostname to http://localhost:80."
echo "Do not use the reserved .test hostname for public DNS or TLS."
echo "Verify tunnel health in Cloudflare before testing the public hostname."
