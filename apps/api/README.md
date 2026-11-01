# Nexora Control API

NestJS control-plane API. The global route prefix is `/v1`.

## Current endpoints and components

- `GET /v1/health`: process-level health response.
- `src/servers/enrollment-token.ts`: cryptographically secure enrollment token generation, SHA-256 storage hashing and constant-time verification primitives.

The enrollment token functions are not yet exposed as HTTP endpoints and do not persist enrollment records. A production enrollment flow must additionally enforce authenticated organization-admin authorization, short expiry, one-time atomic consumption, rate limits, certificate signing, audit events and revocation.

## Development

```sh
pnpm --filter @nexora/api dev
pnpm --filter @nexora/api typecheck
pnpm --filter @nexora/api test
```
