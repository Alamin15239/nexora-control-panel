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
)

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

echo "Building agent and privileged helper..."
(
  cd "$ROOT_DIR/agents/linux-agent"
  go build -trimpath -ldflags="-s -w" -o "$BUILD_DIR/nexora-agent" ./cmd/nexora-agent
  go build -trimpath -ldflags="-s -w" -o "$BUILD_DIR/nexora-provision" ./cmd/nexora-provision
)

echo "Installing root-owned binaries..."
sudo install -o root -g root -m 0755 "$BUILD_DIR/nexora-agent" /usr/local/bin/nexora-agent
sudo install -o root -g root -m 0755 "$BUILD_DIR/nexora-provision" /usr/local/libexec/nexora-provision

echo "Restarting the agent service..."
sudo systemctl restart nexora-agent
sudo systemctl is-active --quiet nexora-agent

echo
echo "Nexora Linux agent update completed."
nexora-agent version
sudo systemctl --no-pager --full status nexora-agent | sed -n '1,12p'
