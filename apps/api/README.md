# Nexora Control API

NestJS control-plane API. The global route prefix is `/v1`.

## Current endpoints and components

- `GET /v1/health`: process-level liveness response.
- `GET /v1/health/ready`: database readiness check.
- `src/servers/enrollment-token.ts`: cryptographically secure enrollment token generation, SHA-256 storage hashing and constant-time verification primitives.
- `src/auth/session-token.ts`: short-lived HS256 session token signing and verification, including organization and membership-role claims, issuer/audience checks, expiry checks and constant-time signature comparison.
- `src/auth/password-hash.ts`: Node.js scrypt password hashing with per-password random salts, fixed resource parameters and constant-time verification.

Password hashes use the format `scrypt$N$r$p$salt$key`. Passwords must be 12–128 characters. Do not log plaintext passwords, hashes, tokens or authorization headers.

## Not yet production authentication

The authentication files are security primitives only. They are not wired to login, registration, password reset, refresh, logout or HTTP route guards. No public credential endpoint is enabled yet. Before exposing login, implement persistent brute-force controls (prefer shared Redis or equivalent, not process-local counters), account lockout policy, secure session revocation/rotation, CSRF protections if cookie-based, email verification and audit events. Every tenant-scoped operation must derive organization access from a verified membership, never from a caller-supplied organization ID alone.

The enrollment token functions are not yet exposed as HTTP endpoints and do not persist enrollment records. A production enrollment flow must additionally enforce authenticated organization-admin authorization, short expiry, one-time atomic consumption, rate limits, certificate signing, audit events and revocation.

## Development

```sh
pnpm --filter @nexora/api dev
pnpm --filter @nexora/api typecheck
pnpm --filter @nexora/api test
```
