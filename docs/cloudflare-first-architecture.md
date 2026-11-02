# Cloudflare-first deployment architecture

Nexora's primary infrastructure platform is Cloudflare. The product will be designed as a Cloudflare-native hosting and application platform, not as a traditional VPS/cPanel manager.

## Core architecture

- **Web application:** Keep the current Vercel deployment while migrating the Next.js frontend to Cloudflare Workers with Static Assets/OpenNext only after compatibility testing. Cloudflare Workers Static Assets is the preferred target for static assets and supported full-stack Worker deployments.
- **API:** Move suitable API routes to Cloudflare Workers. Prefer a Worker-native API (for example, Hono) for new endpoints. Do not assume the existing NestJS + Prisma + PostgreSQL API can be deployed unchanged to Workers.
- **Database:** Cloudflare D1 for tenant metadata and relational application data. Design schema and migrations for SQLite/D1 compatibility; replace Prisma/PostgreSQL-specific assumptions where necessary.
- **Object storage:** Cloudflare R2 for customer uploads, website assets where suitable, backups and export files.
- **Caching/configuration:** Workers KV for non-authoritative cache/configuration; never use KV as the source of truth for transactional data.
- **Stateful coordination:** Durable Objects for per-tenant coordination, locks, live state or websocket coordination where required.
- **Background jobs:** Cloudflare Queues and Workers Cron Triggers for provisioning workflows, notifications, cleanup and scheduled tasks.
- **Domains and TLS:** Cloudflare DNS and Worker Custom Domains for routing and managed certificates.
- **Secrets:** Worker secrets and Cloudflare-managed environment bindings; never commit API tokens or secrets.
- **Containers:** Cloudflare Containers may be evaluated for workloads requiring a container runtime, but they are not part of the free Workers plan. Current documentation lists Containers as included with the $5/month Workers Paid plan and metered usage thereafter.

## What this platform can host

Cloudflare Workers can run supported JavaScript/TypeScript and WebAssembly workloads at the edge. Workers Static Assets can serve static websites. With appropriate runtime adaptation, Nexora can offer deployment for supported web applications.

Cloudflare Workers are not general-purpose Linux VPS instances. A Workers-only design does not provide customers with unrestricted SSH, a conventional Linux filesystem, arbitrary root processes, standard PHP-FPM hosting, arbitrary Docker workloads, or a traditional cPanel environment. Those capabilities require a container product or a separate compute provider and must be explicitly designed and priced.

Do not advertise Nexora as offering unrestricted PHP/Linux shared hosting unless a compatible, supported execution environment is implemented and tested.

## Free-tier constraints

Cloudflare's Workers Free plan currently documents 100,000 requests per day and 10 ms CPU time per invocation. D1 has free-tier daily read/write and storage limits. These limits are suitable for development and early prototypes, not a promise of unlimited free hosting. Usage limits and prices can change; review the official pricing and limits before onboarding customers.

Workers Paid is currently listed at a minimum of $5 USD/month. Cloudflare Containers are not available on the Workers Free plan according to the Containers pricing documentation.

## Migration from the existing codebase

1. Keep the existing Vercel deployment stable while developing the Cloudflare-native backend in a separate package.
2. Inventory existing NestJS controllers, auth flows, tenant scoping, audit logs and Prisma schema.
3. Define a D1-compatible schema and reviewed migrations; preserve organization isolation and role checks.
4. Implement Worker API authentication, session revocation, rate limiting and audit logging before migrating privileged endpoints.
5. Move server-management features to Cloudflare-native concepts: Worker deployments, custom domains, bindings, D1 databases, R2 buckets and usage metrics.
6. Add Queues/Workflows for idempotent asynchronous deployments and rollbacks.
7. Add per-tenant quotas, abuse prevention, usage metering and cost controls.
8. Migrate the dashboard only after API compatibility and production smoke tests pass.

## Security requirements

- Scope every tenant-owned record and object to the authenticated organization.
- Use least-privilege Cloudflare API tokens, separated by environment and responsibility.
- Never expose account-wide API tokens to browsers or customer code.
- Treat customer deployment source as untrusted; build and execute it in isolated supported environments.
- Add deployment approvals, immutable audit events, quotas, rollback and abuse controls.
- Keep secrets out of logs and deployment artifacts.
- Test tenant isolation, authorization boundaries and resource cleanup automatically.

## Current implementation status

This is the target architecture, not evidence that the application has already migrated to Cloudflare. The existing project currently has a Next.js frontend, NestJS/Prisma/PostgreSQL API foundation and a Go Linux agent foundation. The API and Linux agent are not yet a Cloudflare-native hosting platform. The old Google Cloud plan is retained only as a historical alternative and is not the selected provider.

## Official references

- Workers limits: https://developers.cloudflare.com/workers/platform/limits/
- Workers pricing: https://developers.cloudflare.com/workers/platform/pricing/
- D1 pricing and limits: https://developers.cloudflare.com/d1/platform/pricing/
- Workers Static Assets: https://developers.cloudflare.com/workers/static-assets/
- Custom Domains: https://developers.cloudflare.com/workers/configuration/routing/custom-domains/
- Containers pricing: https://developers.cloudflare.com/containers/platform/pricing/