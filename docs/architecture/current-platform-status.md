# Nexora platform status and source-of-truth architecture

**Status snapshot: 2026-11-10**

This document reconciles the current repository implementation with older architecture notes. It describes code and configuration present in the repository; it does not assert that every binding, secret, migration, service, or workflow is installed in the live Cloudflare account or on a production host.

## Selected architecture

Nexora uses a Cloudflare control plane with a separate, isolated application-compute plane:

- **Dashboard:** Next.js 15 / React 19, configured for Cloudflare Workers through OpenNext in `apps/web`.
- **Control-plane API:** Hono Worker in `apps/cloudflare-api`.
- **Transactional metadata:** Cloudflare D1, with checked-in SQL migrations in `apps/cloudflare-api/migrations`.
- **Private artifacts:** Cloudflare R2 through the `ARTIFACTS` binding. The bucket declaration in Wrangler configuration must still be verified against the deployed Worker.
- **Edge, DNS and TLS:** Cloudflare DNS, proxying and supported custom-hostname/Worker routing.
- **Application compute:** a separate Linux node pool using a constrained rootless OCI runtime or stronger microVM isolation. This is not the same thing as the Cloudflare Worker control plane.
- **Legacy API foundation:** `apps/api` (NestJS/Prisma) remains in the repository as a separate foundation. It is not the selected production control-plane API described above.
- **Linux agents:** legacy hosting-agent functionality and the newer application-runtime-node foundation are distinct. Do not reuse a privileged hosting/provisioning agent to run customer source code.

Cloudflare Workers are not general-purpose Linux VPS instances. A Workers-only design does not provide unrestricted SSH, PHP-FPM, arbitrary processes or arbitrary Docker workloads.

## Implemented foundations in the repository

- Organization-scoped authentication and control-plane API foundations.
- GitHub App connection, repository discovery and repository-to-hosting-account project configuration.
- Manual deployment-dispatch API. It resolves the configured branch to an immutable commit SHA and requires an administrator-approved full SHA for the trusted workflow revision.
- GitHub Actions OIDC verification, including repository identity, branch, commit, workflow, event and hosted-runner claims.
- Short-lived, one-time artifact-upload capability and bounded private R2 artifact upload endpoint.
- D1 schema for projects, deployment/release records, runtime profiles, node pools, node identities, quotas and build-usage events.
- Authenticated application-node enrollment, heartbeat, signed desired-state polling, artifact delivery and release/health-check protocol foundations.
- Dedicated static artifact publisher daemon: assigned-node polling, trusted RS256 envelope verification, durable replay protection, SHA-256 verification, archive validation, private account-directory provisioning, immutable releases and atomic activation.
- The publisher service now runs with `www-data` as its primary group for Nginx read/traverse access, while `nexora-static` remains supplementary for broker-socket access. CI checks the systemd group contract and verifies provisioned account directories inherit the publisher primary GID without group-write permission.
- Static publishing installs and validates the Nginx vhost through the privileged broker before switching the active release; it then reports activation to the API.
- The publisher performs a bounded local HTTP origin probe and submits a signed health result. Same-node automatic rollback uses a durable outbox, compare-and-switch semantics, a second serving probe and a signed, idempotent API acknowledgement. Cross-node previous workloads are preserved rather than incorrectly rolled back by the new node.
- GitHub Actions currently verifies the Linux agent with full Go tests, race tests, real Nginx release-switching/PHP-isolation integration, vet, binary builds and systemd unit validation. Cloudflare API CI verifies TypeScript, all D1 migrations, tenant constraints, runtime admission and application integration contracts.
- Linux-side archive validation/extraction primitives, rootless Podman supervisor primitives, workload-volume and secret-bundle primitives, and durable supervisor metadata.
- R2 artifact retention logic for eligible terminal artifacts.
- Dashboard UI for GitHub connection, repository linking and runtime metadata configuration.

These are foundations and integration components. A code path or Wrangler binding in Git does not prove that the corresponding production secret, binding, service, host configuration or end-to-end flow is active.

## Deployment status: not production-enabled

The repository does **not** yet provide a complete customer-facing build-to-live deployment path.

1. The sample workflow at `docs/templates/nexora-deploy.yml` remains a static-only artifact-staging scaffold. It is not installed as `.github/workflows/nexora-deploy.yml` in every customer repository and assumes npm, `package-lock.json` and `dist/`.
2. The control plane can dispatch the named workflow only when GitHub App credentials/permissions are configured and the project has an administrator-reviewed workflow SHA.
3. The static publisher is implemented and CI-tested, but is not installed or enabled on a runtime node. Its `static-v1` profile remains disabled by default.
4. Static activation requires operator-provisioned account release directories, a dedicated read-only web-server group, Nginx document-root routing, a node signing key and the matching deployment-envelope public key. These live prerequisites have not been verified.
5. The publisher and API now implement activation acknowledgement, a bounded local HTTP origin probe, health-state transitions and same-node rollback acknowledgement. These are CI-tested code paths, not proof that the live node, Cloudflare ingress or customer traffic path has passed end-to-end acceptance.
6. The application runtime-node service remains read-only for OCI workloads. It rejects execution, command delivery and secret delivery; it does not start or stop customer containers.
7. Customer-facing automatic push deployment, complete deployment logs, customer rollback UI, production ingress routing and live end-to-end release acceptance remain incomplete.
8. Build-usage reporting exists, but build-dispatch quota enforcement is explicitly not enabled.

The dashboard must continue to describe a project as configured—not deployed—until the complete flow has passed acceptance tests. Never report a deployment as successful merely because GitHub accepted a workflow-dispatch request or an artifact reached R2.

## Next engineering sequence

### Gate 1 — Complete and verify static publishing
- Install and pin a reviewed workflow template in a disposable test repository.
- Keep the runner GitHub-hosted and ephemeral; never run customer build scripts on the Nexora VM, API Worker, privileged agent or production application node.
- Verify GitHub OIDC trust, exact workflow SHA, repository/branch/commit binding, one-time upload capability and R2 checksum.
- Install the static publisher only on a dedicated non-production node after operator provisioning of its keys, replay store, account directories and web-server group.
- Configure Nginx document roots and verify the actual HTTP origin, not just the release symlink.
- Install the publisher only after its service account, signing keys, replay store, account directories, web-server group and Nginx broker are provisioned.
- Verify the actual Cloudflare-to-origin traffic path in addition to the local origin probe; test failed health checks, same-node rollback, cross-node preservation, interrupted publishing and durable outbox recovery.
- Add bounded redacted deployment logs and customer-visible rollback history before exposing a Deploy action.

### Gate 2 — Support server-rendered applications
- Implement a dedicated isolated build plane and a separate application-node pool.
- Complete rootless OCI lifecycle integration, cgroup/resource limits, filesystem quotas, network egress policy, secret retrieval/rotation, persistent storage, ingress, logs, health checks, recovery and rollback.
- Start with one explicitly supported Node.js profile. Add Next.js SSR only after its build and runtime contract is tested. Static Next.js export is a separate profile.
- Do not set `dist` as a universal output directory. Vite commonly uses `dist`; Next.js static export commonly uses `out`; Next.js SSR requires a Node runtime rather than copying `.next` as static files.

### Gate 3 — Production readiness
- Use a dedicated non-production test pool first; the current VirtualBox Ubuntu VM is a development/test machine, not a multi-tenant production node.
- Verify tenant isolation, malicious archives, build isolation, host boundary, resource exhaustion, secret leakage, node revocation, node loss, failed health checks, interrupted publishing and rollback.
- Verify live Cloudflare D1 migrations, R2 binding, Worker secrets, GitHub App permissions, DNS/TLS and monitoring independently of repository configuration.
- Publish a supported-runtime matrix, per-plan quotas, retention and pricing only after measured acceptance.

## Operational rule

Keep customer build execution, customer application execution, privileged host provisioning and the Cloudflare control plane as separate trust domains. Fail closed when an approval, identity, digest, node assignment, quota or health check is missing.