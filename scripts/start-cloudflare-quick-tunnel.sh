#!/usr/bin/env bash
set -Eeuo pipefail

# Start a temporary, unauthenticated Cloudflare Quick Tunnel to the local Nginx
# origin. Cloudflare assigns a random trycloudflare.com hostname. The tunnel
# exists only while this foreground process is running.

if ! command -v cloudflared >/dev/null 2>&1; then
  if [[ "${EUID}" -eq 0 ]]; then SUDO=""; else SUDO="sudo"; fi
  echo "Installing cloudflared from Cloudflare's signed APT repository..."
  $SUDO install -d -m 0755 /usr/share/keyrings
  $SUDO curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg
  $SUDO chmod 0644 /usr/share/keyrings/cloudflare-main.gpg
  printf '%s\n' \
    "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" \
    | $SUDO tee /etc/apt/sources.list.d/cloudflared.list >/dev/null
  $SUDO apt-get update
  $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y cloudflared
fi

if ! curl --fail --silent --show-error --max-time 3 http://127.0.0.1/ >/dev/null; then
  echo "Nginx is not responding on http://127.0.0.1:80. Start Nginx before opening the tunnel." >&2
  exit 1
fi

echo
echo "Starting a temporary Cloudflare Quick Tunnel to http://127.0.0.1:80"
echo "Wait for the https://....trycloudflare.com URL below."
echo "Keep this terminal open. Press Ctrl+C to stop the tunnel."
echo "Quick Tunnels are for testing only; the public URL changes when restarted."
echo

exec cloudflared tunnel --no-autoupdate --url http://127.0.0.1:80
