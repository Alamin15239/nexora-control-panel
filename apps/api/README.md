# Nexora Control API

NestJS control-plane API. The global route prefix is `/v1`.

## Implemented endpoints

- `GET /v1/health`: process liveness.
- `GET /v1/health/ready`: PostgreSQL readiness.
- `POST /v1/auth/register`: creates a user, organization and OWNER membership, then issues a session. Disabled unless `ALLOW_PUBLIC_REGISTRATION=true`.
- `POST /v1/auth/login`: verifies credentials and organization membership, applies a persistent per-email/IP failed-login threshold, and issues a session.
- `POST /v1/auth/logout`: revokes the current persisted session.
- `GET /v1/auth/me`: returns the current active user, organization and role.

All auth routes use JSON request/response bodies. Login requires `email`, `password` and `organizationId`. Registration requires `email`, `password`, `name` and `organizationName`.

## Security components

- Passwords use Node.js scrypt with per-password random salts and constant-time verification.
- Access tokens are short-lived HS256 tokens (15 minutes) with issuer, audience, expiry and unique session ID.
- The raw bearer token is never stored; the database stores its SHA-256 hash.
- Protected requests check the persisted session, user status, organization status and current membership role in PostgreSQL.
- Logout revokes the matching session. Membership changes and account/organization suspension invalidate access on the next guarded request.
- Login failures are tracked in PostgreSQL using an email/IP-derived bucket key.
- Organization creation, membership creation and registration audit record are committed transactionally.

## Required environment

- `DATABASE_URL`: PostgreSQL connection string.
- `SESSION_SECRET`: at least 32 cryptographically random bytes; store in the hosting provider's secret manager.
- `ALLOW_PUBLIC_REGISTRATION`: set to `true` only when public self-service signup is intended. It defaults to disabled.

Generate a secret with `openssl rand -base64 48`. Never commit real secrets.

## Database setup

The Prisma schema is the source of truth. The new `AuthSession` and `LoginAttempt` models require the database schema to be updated before the new authentication endpoints can run. In a controlled development environment, run:

```sh
pnpm --filter @nexora/database db:generate
pnpm --filter @nexora/database exec prisma db push
```

For production, establish and review a checked-in Prisma migration before applying schema changes. Do not use `db push` as an unreviewed production migration strategy.

## Development

```sh
pnpm install
pnpm --filter @nexora/database db:generate
pnpm --filter @nexora/api typecheck
pnpm --filter @nexora/api test
pnpm --filter @nexora/api build
```

## Production release gates still outstanding

This is an initial authentication slice, not a production-complete identity system. Before public launch, add email verification, password reset, MFA enrollment/challenge, refresh-token rotation, account recovery, registration abuse protection, stronger distributed rate limiting (including proxy-aware trusted IP configuration), session/device management, and operational alerting. Add CSRF protection if authentication moves to cookies. Configure TLS, strict CORS allowlists, request-size limits, reverse-proxy trust settings and security headers at the deployment boundary.

The role guard is available for controller methods, but business controllers must explicitly apply it. Every tenant-scoped query must scope by the authenticated organization. Add object-level authorization for resources and audit sensitive changes.

The Linux agent remains a configuration-validation CLI only. It does not yet connect, send telemetry, or execute provisioning operations. Hosting account provisioning, DNS, SSL, mail, backups and customer billing are not yet implemented. Do not represent the product as a complete cPanel replacement until those capabilities are built, integrated and tested.
