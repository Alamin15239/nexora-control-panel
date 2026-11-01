# Nexora Control API

NestJS control-plane API foundation.

## Current endpoint

- GET /v1/health — process health only; it does not yet verify database, queue or server-agent connectivity.

## Development

From the repository root:

    pnpm install
    pnpm --filter @nexora/api dev

Authentication, tenant authorization, database access and provisioning routes must be added before exposing customer or administrative operations.
