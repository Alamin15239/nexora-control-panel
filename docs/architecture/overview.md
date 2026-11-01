# Architecture Overview

## Control plane and data plane

Nexora Control uses a control-plane/data-plane architecture.

- The **control plane** provides identity, tenant management, plans, billing, orchestration, audit events and the web interfaces.
- The **data plane** consists of Linux hosting nodes that run customer websites, databases, DNS and mail services.
- A **server agent** on each managed node receives authenticated, narrowly scoped operations from the control plane.

Existing customer workloads must continue to run if the web interface or control-plane API is temporarily unavailable.

## Trust boundaries

1. Browser to API: TLS, secure sessions, CSRF protection and authorization checks.
2. API to workers: authenticated internal service identity and durable job records.
3. Control plane to agent: mutually authenticated TLS and signed, expiring operation envelopes.
4. Agent to operating system: allowlisted operations with strict input schemas and least privilege.
5. Tenant to tenant: organization-scoped authorization and database constraints.

## Provisioning lifecycle

Every mutating operation is represented by a durable job with an idempotency key, explicit state, attempt count and sanitized error information. Retries must be safe. The agent must reject unknown operation names, expired requests, replayed nonces and invalid signatures.

## Initial deployment topology

- Web application
- API service
- Background worker
- PostgreSQL control database
- Redis job broker
- One isolated Linux test node
- Independent encrypted backup destination

Production must add monitoring, alerting, restore drills, redundant DNS and a tested recovery process before accepting paying customers.

## Explicit non-goals for the first milestone

- No arbitrary root shell endpoint
- No public customer registration before authentication and abuse controls are ready
- No automatic production server modification from the dashboard
- No claim that placeholder metrics are live telemetry
