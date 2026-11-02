# Nexora Control

A multi-tenant hosting and application deployment platform built around Cloudflare's serverless and edge infrastructure. Nexora's selected direction is a Cloudflare-native alternative for supported web workloads, not a traditional unrestricted Linux VPS/cPanel service.

## Current architecture

- Web: Next.js 15, React 19, TypeScript and Tailwind CSS, deployed to Cloudflare Workers using the OpenNext adapter.
- API: NestJS with Prisma and PostgreSQL.
- Current API foundation: NestJS, Prisma and PostgreSQL (migration to Cloudflare Workers and D1 is planned, not yet completed).
- Existing Go Linux agent: validation-only foundation; it is not the selected execution model for Cloudflare-native hosting.
- Target infrastructure: Workers, D1, R2, KV, Durable Objects, Queues, Cron Triggers and Cloudflare DNS/Custom Domains.

Nexora's target model is Cloudflare-native deployment and resource orchestration. Cloudflare Workers are not general-purpose Linux VPS instances and do not provide unrestricted SSH, arbitrary root processes or standard PHP-FPM hosting.

## Current implemented functionality

- Responsive Nexora dashboard shell.
- Sign-in and workspace registration interface.
- Next.js authentication proxy that stores the bearer session in an HttpOnly, SameSite=Lax cookie rather than browser local storage.
- API registration (creates user, organization and OWNER membership), login, logout and current-user endpoints.
- Scrypt password hashing, short-lived signed sessions, persisted token hashes, database-backed session revocation and active membership checks.
- Persistent failed-login attempt tracking.
- Go agent CLI for version reporting and local agent configuration validation.

Dashboard metric cards and infrastructure status are still setup placeholders. The web interface does not yet provision or manage real hosting resources.

## Cloudflare deployment

Cloudflare is the selected deployment provider for both the dashboard and API. The dashboard is configured as the `nexora-dashboard` Worker using `apps/web/wrangler.toml` and the OpenNext adapter. The API is deployed separately as `nexora-api` and uses the `nexora-production` D1 database. Vercel is not required. See [the Cloudflare-first architecture](docs/cloudflare-first-architecture.md) for deployment details, free-tier constraints and supported hosting model. The Google Cloud document is retained only as a historical alternative.

## Development setup

Requirements: Node.js 20+, pnpm 9+, Go 1.23+ and PostgreSQL.

```sh
pnpm install
pnpm --filter @nexora/database db:generate
pnpm --filter @nexora/api dev
```

In a separate terminal:

```sh
pnpm --filter @nexora/web dev
```

Configure the environment variables below before using authentication.

## Environment

API:
- `DATABASE_URL`: PostgreSQL connection string.
- `SESSION_SECRET`: at least 32 random bytes.
- `ALLOW_PUBLIC_REGISTRATION`: `true` to enable self-service registration; otherwise registration is disabled.

Web:
- `NEXORA_API_URL`: base URL of the Cloudflare Worker API. Production is configured in `apps/web/wrangler.toml`; local development can use `.env.local`.

Generate a session secret using `openssl rand -base64 48`. Keep all real credentials in deployment secret settings, never in Git.

The Prisma schema has changed to include persistent auth sessions and login-attempt tracking. Update the development database using `pnpm --filter @nexora/database exec prisma db push`. For production, create and review a checked-in migration before applying changes; do not use unreviewed `db push` as a production migration strategy.

## Security and release status

The authentication slice is an initial implementation, not a production-complete identity system. Email verification, password reset, MFA challenge flows, refresh-token rotation, registration abuse protection, robust distributed rate limiting, session/device management and security monitoring remain outstanding. Configure TLS, strict CORS, request limits, trusted proxy behavior and security headers at the deployment boundary.

All business controllers must explicitly apply authentication and role guards. Every tenant-scoped query must use the authenticated organization scope and object-level authorization.

The Go agent does not yet connect to the control plane, send telemetry or execute provisioning operations. Hosting account provisioning, websites, databases, DNS, SSL, FTP, mail, backups, reseller functions and billing are not yet implemented. Do not market the current build as a complete cPanel replacement until those functions are implemented, integrated and tested.

## Security principles

- Tenant isolation for every customer-owned resource.
- MFA for privileged accounts.
- Short-lived, revocable credentials.
- Mutual TLS between control plane and server agents.
- Explicit allowlists for privileged server operations.
- Auditable changes and privileged actions.
- Encrypted, independently stored backups.
- No arbitrary root shell execution.

## License

Proprietary. All rights reserved. Third-party dependencies retain their respective licenses.
