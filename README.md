# Nexora Control

An independently owned hosting control plane and Linux server management platform.

## Architecture
- Web application: Next.js, React, TypeScript
- API: NestJS (planned)
- Linux server agent: Go (planned)
- Control-plane database: PostgreSQL + Prisma
- Background jobs: Redis + BullMQ (planned)
- Hosting nodes: Linux, Nginx, PHP-FPM and database/mail services

The control plane is separate from customer workload servers. Privileged operations must use authenticated, allowlisted server-agent operations. Never execute arbitrary user-supplied shell commands as root.

## Development
Requirements: Node.js 20+ and pnpm 9+.

Run `pnpm install` and then `pnpm dev`.

## Security principles
- Tenant isolation for all customer-owned resources
- MFA for privileged accounts
- Short-lived, scoped credentials
- Mutual TLS between control plane and server agents
- Allowlisted server operations
- Append-only audit events for privileged actions
- Encrypted, independently stored backups

## Status
Repository foundation and initial web dashboard/API scaffolding are committed. The Linux agent now has a Go CLI for version reporting and local mTLS certificate/configuration validation, with Go test/build CI. Agent enrollment, live telemetry, remote operations, hosting provisioning, billing and production deployment are not implemented yet. See [agent protocol design](docs/architecture/linux-agent-protocol.md).

## License
Proprietary. All rights reserved. Third-party dependencies retain their respective licenses.
