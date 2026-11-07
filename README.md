# Nexora Control

Nexora is a multi-tenant hosting control plane and application-deployment platform. Its selected architecture uses Cloudflare for the dashboard, API, metadata and edge services, with a separate isolated compute plane for workloads that need a conventional application runtime.

**Current implementation status:** substantial control-plane and runtime foundations exist, but Nexora is not yet a production-complete cPanel replacement or a customer-ready build-to-live application host. See [the current platform status](docs/architecture/current-platform-status.md) before enabling workloads or onboarding customers.

## Selected architecture

- **Dashboard:** Next.js 15, React 19, TypeScript and Tailwind CSS; configured for Cloudflare Workers using OpenNext in `apps/web`.
- **Control-plane API:** Hono on Cloudflare Workers in `apps/cloudflare-api`.
- **Database:** Cloudflare D1 with reviewed SQL migrations in `apps/cloudflare-api/migrations`.
- **Artifact storage:** private Cloudflare R2 through the API's `ARTIFACTS` binding.
- **Edge and domains:** Cloudflare DNS, proxy, TLS and supported custom-hostname routing.
- **Application compute:** separate Linux application-node pools using constrained rootless OCI or stronger microVM isolation.
- **Legacy foundation:** `apps/api` (NestJS/Prisma) and legacy Linux hosting-agent code remain in the repository; they are not interchangeable with the selected Cloudflare control plane or the new application runtime-node service.

Cloudflare Workers are not general-purpose Linux VPS instances. Conventional PHP-FPM, arbitrary processes and unrestricted containers require a separately implemented and secured compute environment.

## Implemented foundations

- Organization-scoped authentication and control-plane API.
- GitHub App connection, repository discovery and hosting-account project linking.
- Manual deployment dispatch, immutable commit binding, trusted workflow SHA approval and GitHub Actions OIDC verification.
- One-time artifact upload capabilities and private R2 artifact staging.
- D1 project, release, runtime-profile, node-pool, node-identity and usage schema.
- Authenticated application-node enrollment/heartbeat and signed read-only desired-state polling.
- A dedicated static artifact publisher with assigned-node polling, signed deployment-envelope verification, durable replay protection, archive validation, immutable release storage and atomic activation.
- Linux rootless Podman, release-delivery, volume, secret-bundle and durable supervisor primitives.
- Runtime settings and build-usage metadata in the dashboard.

These components are not proof that the full release lifecycle is enabled in production. The static publisher is not installed or enabled on a node; its runtime profile remains disabled by default. Static activation also needs operator-provisioned account directories, Nginx routing and a real HTTP health probe. The OCI runtime node remains read-only and customer container execution remains disabled.

## What is not production-ready yet

- Installing and verifying the static publisher on a dedicated non-production node, including account-directory permissions and Nginx document-root routing.
- External HTTP health checks, automated rollback orchestration and end-to-end static deployment acceptance.
- A production build workflow installed and approved in customer repositories.
- An isolated builder with enforced resource and egress policies.
- A complete application-node lifecycle connected to rootless OCI execution.
- Runtime secret delivery/rotation, persistent-volume quotas, ingress routing and recovery.
- Automatic push deployments, complete deployment logs and customer rollback controls.
- Production acceptance tests for tenant isolation and hostile build/artifact inputs.

The sample workflow in `docs/templates/nexora-deploy.yml` is an artifact-staging scaffold, not a working production deployment. Do not interpret a queued workflow or uploaded artifact as a live website.

## Development

Requirements vary by package. The root workspace uses pnpm 9.

```sh
pnpm install
pnpm --filter @nexora/web dev
```

Run the Cloudflare API locally in a separate terminal:

```sh
pnpm --filter @nexora/cloudflare-api dev
```

Useful validation commands:

```sh
pnpm --filter @nexora/web typecheck
pnpm --filter @nexora/cloudflare-api typecheck
```

Configure local bindings and secrets using Wrangler's local development mechanisms. Never commit API tokens, GitHub App private keys, encryption keys, session secrets or customer credentials.

## Security principles

- Bind every customer-owned row and object to the authenticated organization.
- Enforce object-level authorization; opaque IDs are not authorization.
- Keep customer builds and runtime processes out of the API Worker and privileged host agents.
- Use ephemeral, least-privilege credentials and one-time, scoped artifact capabilities.
- Verify immutable source identity, trusted workflow identity and artifact digests.
- Enforce CPU, memory, process, disk, network and time limits server-side.
- Keep secrets out of source archives, images, logs, telemetry and browser code.
- Use immutable releases, health checks and failure-safe rollback.
- Audit privileged operations and fail closed when trust or capacity checks fail.

## License

Proprietary. All rights reserved. Third-party dependencies retain their respective licenses.
