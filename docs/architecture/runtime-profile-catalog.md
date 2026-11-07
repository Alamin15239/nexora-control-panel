# Runtime profile catalog and deployment specification

This document describes the first control-plane schema slice for the multi-runtime platform. It is not an enablement switch for customer workloads.

## Migration

`0021_multi_runtime_application_platform.sql` adds:

- `application_runtime_profiles`: versioned runtime catalog. All seeded profiles are disabled.
- `application_node_pools` and `application_nodes`: future compute inventory and enrollment state; no node enrollment endpoint is enabled.
- `application_project_settings`: organization-scoped runtime/build/resource settings linked to an existing GitHub project.
- `application_releases` and `application_release_events`: release state machine and redacted append-only event history.
- `application_workloads`: desired/observed web, worker and scheduled workload state.

Organization/project consistency is enforced by database triggers for project settings, releases and workloads. Runtime catalog entries are metadata only. The migration does not create a node, execute a build, publish a release, or enable a runtime.

## Runtime profile policy

| Profile key | Family | Execution kind | Default port | Initial state |
|---|---|---|---:|---|
| `static-v1` | static | static | — | disabled |
| `nodejs-v1` | nodejs | OCI | 3000 | disabled |
| `php-v1` | php | OCI | 8080 | disabled |
| `python-v1` | python | OCI | 8000 | disabled |
| `go-v1` | go | OCI | 8080 | disabled |
| `java-v1` | java | OCI | 8080 | disabled |
| `dotnet-v1` | dotnet | OCI | 8080 | disabled |
| `ruby-v1` | ruby | OCI | 3000 | disabled |
| `container-v1` | container | OCI | 8080 | disabled |

These defaults are starting metadata, not a promise that a runtime is supported. A profile may be enabled only after its build image, runtime policy, ingress, resource enforcement, secret injection, logs, health checks, rollback and security tests pass.

## Deployment specification rules

1. Store structured, versioned configuration; do not store arbitrary shell fragments as trusted commands.
2. Validate build context and output paths as relative paths and reject traversal, absolute paths, symlinks and unsupported archive entries.
3. Restrict ports to the assigned internal workload port; do not expose host ports.
4. Enforce plan ceilings server-side for CPU, memory, disk and process count. Never trust dashboard-provided limits.
5. Store secret references only. Resolve secret values at runtime through a scoped secret-injection mechanism; never include values in the deployment spec or logs.
6. Bind every settings, release, workload and event query to the authenticated organization. IDs are not authorization.
7. Make release transitions conditional and idempotent; only a signed publisher may activate a validated release.

## Next implementation gates

- Add authenticated API routes for listing runtime profiles and reading/updating project settings; validate membership role, organization/project ownership and plan ceilings.
- Add schema-health checks and automated migration tests against SQLite/D1.
- Add a JSON Schema or equivalent runtime validator and unit tests for malformed commands, paths, ports, resource overages and secret leakage.
- Keep node enrollment, build execution, publisher actions and profile enablement disabled until their separate security gates are complete.

## Operational warning

The existing VirtualBox Ubuntu VM is a development/test machine. Do not register it as a production multi-tenant node. The current legacy hosting agent must not be repurposed to execute customer builds or arbitrary container commands.