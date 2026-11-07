#!/usr/bin/env python3
"""Static security-contract regression checks for application settings routes.

These checks complement (but do not replace) Worker/D1 request integration tests.
They pin the route's authorization, tenant scoping, validation, and metadata-only
execution invariants until a Miniflare-backed integration harness is introduced.
"""
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "src" / "index.ts"
source = SOURCE.read_text(encoding="utf-8")

def route(method: str, path: str) -> str:
    marker = f'app.{method}("{path}"'
    start = source.find(marker)
    assert start >= 0, f"missing route: {method.upper()} {path}"
    next_route = source.find("\napp.", start + len(marker))
    return source[start:] if next_route < 0 else source[start:next_route]

put = route("put", "/v1/applications/projects/:projectId/settings")
get = route("get", "/v1/applications/projects/:projectId/settings")
catalog = route("get", "/v1/applications/runtime-profiles")

# Authentication and authorization must precede project lookup and all writes.
auth = put.find("await bearerIdentity")
role = put.find("canManageServers(identity.role)")
project = put.find("FROM github_projects WHERE id = ? AND organization_id = ?")
write = put.find("INSERT INTO application_project_settings")
assert 0 <= auth < role < project < write, "PUT authorization/tenant checks must precede writes"
assert 'return c.json({ message: "Not authenticated" }, 401)' in put
assert 'return c.json({ message: "Administrator access required" }, 403)' in put
assert 'return c.json({ message: "GitHub project not found." }, 404)' in put

# Runtime profile metadata must be resolved from the platform catalog.
assert "FROM application_runtime_profiles WHERE id = ? LIMIT 1" in put
assert "Unknown runtime profile." in put
assert "Static websites must use the static build method." in put
assert "Custom OCI profiles must use the Dockerfile build method." in put

# Paths and commands are data only and must be bounded before persistence.
assert "buildContext must be a safe relative path." in put
assert "outputDirectory must be null or a safe relative path." in put
assert 'raw.includes("\\\\")' in put
assert 'raw.split("/").some((part) => part === ".."' in put
assert "buildCommand, 1000" in put and "startCommand, 1000" in put
assert "healthCheckPath, 200" in put
assert "Resource values are outside the permitted platform bounds." in put
for lower, upper in [("100", "8000"), ("128", "16384"), ("128", "65536"), ("16", "512")]:
    assert lower in put and upper in put, f"missing resource bound {lower}..{upper}"

# This phase is explicitly metadata-only: no dispatch or process execution.
assert "executionEnabled: false" in put
assert "planQuotasEnforced: false" in put
assert "Customer builds and runtime execution remain disabled." in put
assert "fetch(" not in put and "spawn(" not in put and "exec(" not in put

# GET must be organization-scoped and return no settings for an unknown project.
assert "WHERE p.id = ? AND p.organization_id = ?" in get
assert "LEFT JOIN application_project_settings s" in get
assert "executionEnabled: false" in get

# Catalog access is authenticated and exposes disabled profiles as non-selectable.
assert "await bearerIdentity" in catalog
assert "selectable: profile.enabled === 1" in catalog
assert "executionEnabled: false" in catalog

print("Application settings security-contract checks passed.")
print("Note: these are source-contract checks, not live Hono/D1 integration tests.")
