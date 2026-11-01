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
Initial repository bootstrap. The first milestone is the web control-plane shell, followed by API, database and secure server-agent foundations.

## License
Proprietary. All rights reserved. Third-party dependencies retain their respective licenses.
