#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "Run this script from inside the Nexora Control repository." >&2
  exit 1
}
cd "$ROOT_DIR"

BRANCH="$(git branch --show-current)"
if [[ "$BRANCH" != "main" ]]; then
  echo "Refusing to update from branch '$BRANCH'; switch to main first." >&2
  exit 1
fi
if [[ -n "$(git status --porcelain)" ]]; then
  echo "Refusing to overwrite local changes. Commit or stash them first." >&2
  exit 1
fi

command -v go >/dev/null || {
  echo "Go is required to build the Linux agent. Install the Go 1.23 toolchain first." >&2
  exit 1
}
command -v sudo >/dev/null
command -v systemctl >/dev/null

echo "Updating Nexora Control source..."
git pull --ff-only origin main

echo "Running Linux agent tests..."
(
  cd "$ROOT_DIR/agents/linux-agent"
  go test ./...
  go test -race ./...
  go vet ./...
)

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

echo "Building agent, helper, and IPC daemon..."
(
  cd "$ROOT_DIR/agents/linux-agent"
  go build -trimpath -ldflags="-s -w" -o "$BUILD_DIR/nexora-agent" ./cmd/nexora-agent
  go build -trimpath -ldflags="-s -w" -o "$BUILD_DIR/nexora-provision" ./cmd/nexora-provision
  go build -trimpath -ldflags="-s -w" -o "$BUILD_DIR/nexora-provisiond" ./cmd/nexora-provisiond
)

echo "Installing root-owned helper and IPC daemon..."
sudo install -D -o root -g root -m 0755 "$BUILD_DIR/nexora-provision" /usr/local/libexec/nexora-provision
sudo install -D -o root -g root -m 0755 "$BUILD_DIR/nexora-provisiond" /usr/local/sbin/nexora-provisiond
sudo install -D -o root -g root -m 0644 "$ROOT_DIR/agents/linux-agent/systemd/nexora-provisiond.service" /etc/systemd/system/nexora-provisiond.service

echo "Starting the privileged IPC service before changing the agent..."
sudo systemctl daemon-reload
sudo systemctl enable --now nexora-provisiond.service
sudo systemctl is-active --quiet nexora-provisiond.service

SOCKET_PATH="/run/nexora/provision.sock"
for _ in {1..10}; do
  [[ -S "$SOCKET_PATH" ]] && break
  sleep 1
done
if [[ ! -S "$SOCKET_PATH" ]]; then
  echo "Provisioning IPC socket was not created; leaving the existing agent binary untouched." >&2
  sudo systemctl --no-pager --full status nexora-provisiond.service || true
  exit 1
fi
SOCKET_META="$(stat -c '%U:%G:%a' "$SOCKET_PATH")"
if [[ "$SOCKET_META" != "root:nexora-agent:660" ]]; then
  echo "Unexpected provisioning socket ownership or mode: $SOCKET_META" >&2
  exit 1
fi

BACKUP_DIR="/var/backups/nexora-agent-ipc-$(date -u +%Y%m%dT%H%M%SZ)"
sudo install -d -o root -g root -m 0700 "$BACKUP_DIR"
HAD_PREVIOUS_AGENT=0
if [[ -x /usr/local/bin/nexora-agent ]]; then
  sudo cp -a /usr/local/bin/nexora-agent "$BACKUP_DIR/nexora-agent.previous"
  HAD_PREVIOUS_AGENT=1
fi

echo "Installing the IPC-capable agent..."
sudo install -o root -g root -m 0755 "$BUILD_DIR/nexora-agent" /usr/local/bin/nexora-agent
if ! sudo systemctl restart nexora-agent || ! sudo systemctl is-active --quiet nexora-agent; then
  echo "New agent failed to start; attempting to restore the previous agent binary." >&2
  if [[ "$HAD_PREVIOUS_AGENT" -eq 1 ]]; then
    sudo install -o root -g root -m 0755 "$BACKUP_DIR/nexora-agent.previous" /usr/local/bin/nexora-agent
    sudo systemctl restart nexora-agent || true
  fi
  echo "Legacy sudoers and systemd drop-ins were not removed. Backup: $BACKUP_DIR" >&2
  exit 1
fi

echo
echo "Nexora IPC migration binaries installed and agent restarted."
echo "Previous agent backup: $BACKUP_DIR"
echo "Legacy sudoers and agent drop-ins were intentionally retained for rollback."
nexora-agent version
sudo systemctl --no-pager --full status nexora-provisiond.service | sed -n '1,12p'
sudo systemctl --no-pager --full status nexora-agent.service | sed -n '1,12p'
