# Cloudflare control-plane architecture

Nexora uses Cloudflare for its dashboard, control-plane API, transactional metadata, private artifact storage and public edge. Customer application execution is a separate compute-plane responsibility; a Cloudflare Worker is not a general-purpose Linux VPS.

## Core architecture

- **Dashboard:** Next.js 15 deployed as the `nexora-dashboard` Worker using OpenNext. Configuration is in `apps/web/open-next.config.ts` and `apps/web/wrangler.toml`.
- **API:** Hono Worker named `nexora-api`, implemented in `apps/cloudflare-api/src/index.ts`.
- **Database:** D1 database `nexora-production`, with SQL migrations in `apps/cloudflare-api/migrations`.
- **Object storage:** private R2 bucket `nexora-deployment-artifacts`, declared as the API's `ARTIFACTS` binding. Verify the deployed binding independently; a Wrangler declaration alone does not prove production configuration.
- **Edge and domains:** Cloudflare DNS, proxy, TLS, Workers and supported custom-hostname routing.
- **Background work:** Cron Triggers currently handle scheduled maintenance tasks. Queues/Workflows should be introduced for asynchronous deployment orchestration where durable retry and ordering are required.
- **Application execution:** separate isolated Linux node pools using rootless OCI or microVM isolation. Do not execute customer source code in the API Worker or the legacy privileged hosting agent.
- **Legacy API:** `apps/api` contains the separate NestJS/Prisma foundation. It is not the Hono/D1 API deployed as the Cloudflare control plane.

## Workload boundaries

Cloudflare Workers can execute supported JavaScript/TypeScript and WebAssembly workloads and serve static assets. They do not provide unrestricted SSH, arbitrary root processes, PHP-FPM, general Docker, or a conventional writable Linux filesystem.

Nexora's supported workload matrix must be explicit. Static websites, server-rendered Node.js, PHP, Python and custom OCI workloads require different build/runtime profiles. Do not silently treat a server-rendered application as static output.

## Security requirements

- Scope every tenant-owned row and object to the authenticated organization.
- Keep Cloudflare account credentials in narrowly scoped server-side secrets.
- Treat repository source, package lifecycle scripts, Dockerfiles and build output as untrusted.
- Build on ephemeral isolated builders; never run customer build scripts on the control-plane Worker, privileged provisioner or production application node.
- Verify GitHub OIDC issuer, audience, repository ID, branch, immutable commit, workflow identity and hosted-runner status.
- Issue one-time, short-lived upload capabilities scoped to a single deployment.
- Keep artifacts private; validate archive paths, types, size and digest before extraction or publication.
- Use signed node requests, replay protection, node revocation and explicit node/release assignment.
- Enforce tenant quotas, resource limits, network policy and secret isolation at the compute boundary.
- Use immutable releases, health checks, atomic traffic switching and rollback.

## Current implementation status

The repository contains the Hono/D1 control-plane API, GitHub App and OIDC foundations, R2 artifact staging, runtime-node contracts, a dedicated static artifact publisher, and Linux rootless OCI/supervisor primitives. The static publisher can validate and atomically activate static releases assigned to an enrolled node, but it is not installed or enabled on a live node and does not prove that Nginx serves the new release. It reports activation as `health_checking` until an actual HTTP origin probe succeeds.

The OCI runtime-node service still performs read-only desired-state polling and refuses container execution, command delivery and secret delivery. The sample GitHub Actions workflow stages static artifacts only; the reviewed workflow must be installed in the customer repository. The current VirtualBox Ubuntu VM is a development/test machine and must not be treated as a production multi-tenant application node.

See [current platform status and rollout gates](architecture/current-platform-status.md) for the authoritative implementation inventory and next steps.

## Development and operations

- Dashboard Worker: `apps/web/wrangler.toml`.
- API Worker: `apps/cloudflare-api/wrangler.toml`.
- D1 migrations: `apps/cloudflare-api/migrations`.
- Private artifact bucket: `ARTIFACTS` binding in the API Worker.

Before release, verify the live Cloudflare Worker versions, D1 migration state, R2 binding, Worker secrets, GitHub App permissions, DNS/TLS and production smoke tests. Repository configuration is not evidence that live infrastructure is correctly provisioned.

## Official references

- Workers limits: https://developers.cloudflare.com/workers/platform/limits/
- Workers pricing: https://developers.cloudflare.com/workers/platform/pricing/
- D1 pricing and limits: https://developers.cloudflare.com/d1/platform/pricing/
- Workers Static Assets: https://developers.cloudflare.com/workers/static-assets/
- Custom Domains: https://developers.cloudflare.com/workers/configuration/routing/custom-domains/
- Containers: https://developers.cloudflare.com/containers/
