# Nexora Control API

NestJS control-plane API. The global route prefix is `/v1`.

## Current endpoints and components

- `GET /v1/health`: process-level liveness response.
- `GET /v1/health/ready`: database readiness check.
- `src/servers/enrollment-token.ts`: cryptographically secure enrollment token generation, SHA-256 storage hashing and constant-time verification primitives.
- `src/auth/session-token.ts`: short-lived HS256 session token signing and verification, including organization and membership-role claims, issuer/audience checks, expiry checks and constant-time signature comparison.

Session-token primitives are not yet wired to login, refresh, logout or HTTP route guards. Do not treat the presence of these helpers as a complete authentication system. Production authentication still requires secure password verification, persisted users and memberships, secret management, rate limiting, session revocation/rotation, CSRF protections if cookie-based, and authorization checks on every tenant-scoped operation.

The enrollment token functions are not yet exposed as HTTP endpoints and do not persist enrollment records. A production enrollment flow must additionally enforce authenticated organization-admin authorization, short expiry, one-time atomic consumption, rate limits, certificate signing, audit events and revocation.

## Development

```sh
pnpm --filter @nexora/api dev
pnpm --filter @nexora/api typecheck
pnpm --filter @nexora/api test
```
