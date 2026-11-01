# Nexora Control

An independently developed hosting control plane and Linux server management platform. The long-term objective is a self-hosted alternative to cPanel/WHM, with a multi-tenant SaaS control plane and customer workload nodes.

## Current architecture

- Web: Next.js 15, React 19, TypeScript and Tailwind CSS.
- API: NestJS with Prisma and PostgreSQL.
- Linux agent: Go CLI foundation.
- Database schema: users, organizations, memberships, servers, agent enrollment, telemetry, hosting plans/accounts, domains, provisioning jobs, audit logs, persisted sessions and login-attempt tracking.
- Planned infrastructure: Redis/BullMQ, Nginx, PHP-FPM, DNS, mail, SSL automation and encrypted backups.

The control plane is separate from customer workload servers. Privileged operations must use authenticated, allowlisted server-agent operations. Never execute arbitrary user-supplied shell commands as root.

## Current implemented functionality

- Responsive Nexora dashboard shell.
- Sign-in and workspace registration interface.
- Next.js authentication proxy that stores the bearer session in an HttpOnly, SameSite=Lax cookie rather than browser local storage.
- API registration (creates user, organization and OWNER membership), login, logout and current-user endpoints.
- Scrypt password hashing, short-lived signed sessions, persisted token hashes, database-backed session revocation and active membership checks.
- Persistent failed-login attempt tracking.
- Go agent CLI for version reporting and local agent configuration validation.

Dashboard metric cards and infrastructure status are still setup placeholders. The web interface does not yet provision or manage real hosting resources.

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
- `NEXORA_API_URL`: internal/reachable base URL of the NestJS API, for example `http://localhost:4000`.

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
