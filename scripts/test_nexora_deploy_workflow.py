#!/usr/bin/env python3
"""Static security-contract tests for the customer-facing Nexora build workflow."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "docs/templates/nexora-deploy.yml").read_text(encoding="utf-8")

def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")

checkout = re.search(r"(?m)^\s*uses:\s*actions/checkout@([0-9a-f]{40})(?:\s+#.*)?$", source)
require(checkout is not None, "actions/checkout must be pinned to a full 40-character commit SHA")
require(checkout.group(1) == "11bd71901bbe5b1630ceea73d27597364c9af683",
        "checkout pin must match the reviewed v4.2.2 revision")

require(re.search(r"(?m)^on:\s*$", source) is not None, "workflow must declare triggers")
require(re.search(r"(?m)^\s{2}workflow_dispatch:\s*$", source) is not None,
        "workflow_dispatch trigger is required")
require("push:" not in source and "pull_request:" not in source,
        "automatic push/PR triggers are not enabled in this milestone")

require(re.search(r"(?m)^\s{4}runs-on:\s*ubuntu-latest\s*$", source) is not None,
        "build job must use GitHub-hosted ubuntu-latest")
require("self-hosted" not in source.lower(), "self-hosted runners are prohibited")
require(re.search(r"(?m)^permissions:\n  contents: read\n  id-token: write$", source) is not None,
        "top-level permissions must be contents:read and id-token:write only")
require(re.search(r"(?m)^\s{4}permissions:\n\s{6}contents: read\n\s{6}id-token: write$", source) is not None,
        "job permissions must be contents:read and id-token:write only")
require("persist-credentials: false" in source, "checkout must not persist the repository token")
require("secrets." not in source, "workflow must not expose repository or Nexora secrets")

require("ref: ${{ inputs.commit_sha }}" in source, "checkout must use the requested commit SHA")
require("git rev-parse HEAD" in source and 'actual" == "$EXPECTED_COMMIT"' in source,
        "workflow must verify the checked-out commit before building")

require("npm ci" in source and "npm run build" in source, "static npm build profile is incomplete")
require("test -d dist" in source, "the initial artifact output must be dist/")
require("build_command" not in source and "install_command" not in source,
        "customer-provided commands must not be interpolated into the workflow")

require("find dist -type l" in source, "symlink rejection is required")
require("find dist ! -type d ! -type f" in source, "special-file rejection is required")
require("bytes > 104857600" in source, "compressed artifact must be capped at 100 MiB")
require('sha256sum "$artifact"' in source, "artifact SHA-256 must be calculated")
require("OIDC_AUDIENCE" in source and "/oidc/exchange" in source,
        "workflow must exchange a GitHub OIDC token for a scoped upload capability")
require('/v1/github/deployments/$DEPLOYMENT_ID/artifact"' in source,
        "workflow must upload only to the deployment-scoped artifact endpoint")

print("PASS: Nexora static deployment workflow security contract")
