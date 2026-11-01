# Nexora Control API

NestJS control-plane API. The global route prefix is `/v1`.

## Current endpoints and components

- `GET /v1/health`: process-level liveness response.
- `GET /v1/health/ready`: database readiness check.
- `src/servers/enrollment-token.ts`: cryptographically secure enrollment token generation, SHA-256 storage hashing and constant-time verification primitives.
- `src/auth/session-token.ts`: short-lived HS256 session token signing and verification, including organization and membership-role claims, issuer/audience checks, expiry checks and constant-time signature comparison.
- `src/auth/password-hash.ts`: Node.js scrypt password hashing with per-password random salts and constant-time verification.
- `src/auth/auth.guard.ts`: bearer-session guard; verifies a signed token and attaches verified claims to the request.
- `src/auth/roles.guard.ts`: method/controller role metadata and exact organization membership-role authorization.
- `@RequireRoles("OWNER", "ADMIN")`: decorator to restrict a controller route to the listed membership roles when used with `@UseGuards(SessionAuthGuard, MembershipRolesGuard)`.

The auth module is registered in the API application. Guards are available for route-level use; they are not globally enforced, and no login or registration routes exist yet.

## Production authentication release gates

Authentication primitives are not a complete account system. Before exposing login, implement persistent users and memberships, secure registration and email verification, password reset, persistent brute-force controls, session revocation/rotation, audit events, and CSRF protections if cookie-based. A verified token's organization and role must be revalidated against current database membership before sensitive operations; do not trust stale role claims as the only authorization source. Every tenant-scoped query must include the verified organization scope.

Passwords must never be logged. Session secrets must be at least 32 random bytes and supplied through the deployment secret manager, never committed to source control.

The enrollment token functions are not yet exposed as HTTP endpoints and do not persist enrollment records. A production enrollment flow must additionally enforce authenticated organization-admin authorization, short expiry, one-time atomic consumption, rate limits, certificate signing, audit events and revocation.

## Development

```sh
pnpm --filter @nexora/api dev
pnpm --filter @nexora/api typecheck
pnpm --filter @nexora/api test
```
