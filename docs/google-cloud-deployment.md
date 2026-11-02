# Google Cloud deployment plan

Nexora will use Google Cloud Platform (GCP) as its infrastructure provider. The first supported provider will be Google Compute Engine (GCE), while the control plane remains provider-neutral so other providers can be added later.

## Target architecture

- **Web dashboard:** Next.js on Vercel (existing deployment).
- **Control-plane API:** NestJS deployed to a dedicated Google Compute Engine VM for the first production-like deployment. Keep it separate from customer workload VMs.
- **Database:** Cloud SQL for PostgreSQL in production. A local PostgreSQL instance is acceptable only for isolated development.
- **Workload nodes:** Separate Ubuntu 24.04 LTS Compute Engine VMs, one Nexora Linux Agent per node.
- **Agent channel:** HTTPS with mutual TLS, short-lived one-time enrollment tokens, certificate rotation and replay protection.
- **Provisioning:** A queue-backed control-plane worker calls the Compute Engine API for VM lifecycle operations. The agent performs a fixed set of allowlisted local operations; it must never execute arbitrary customer-provided shell commands as root.
- **Secrets:** Secret Manager for production secrets. Attach a dedicated service account to the API VM; do not download or commit service-account JSON keys.

## GCP project preparation

1. Create a dedicated GCP project for Nexora (separate from personal or unrelated workloads).
2. Enable billing and set a budget alert before creating resources. Budget alerts notify; they do not automatically cap spend.
3. Enable the Compute Engine API. Enable Cloud SQL and Secret Manager APIs when those services are introduced.
4. Choose one region close to the intended first customers and keep the API, database and workload VMs geographically close where practical.
5. Create separate service accounts for the control plane and workload VMs. Grant only the permissions each component needs.
6. Use OS Login and IAP TCP forwarding for administrative SSH. Do not expose SSH (port 22) to the public internet.
7. Create firewall rules narrowly: public web traffic only where needed; agent-to-control-plane traffic restricted to the required endpoint and port.

## Initial development environment

For the first integration test, create:
- One small Ubuntu 24.04 LTS Compute Engine VM for the Nexora API.
- One separate Ubuntu 24.04 LTS Compute Engine VM as a disposable agent/workload node.
- PostgreSQL in a private network or a temporary development database.

Do not use the API VM as a customer hosting node. Do not place the production database on a public IP. Start with modest VM sizes and monitor CPU, memory, disk, network egress and persistent-disk usage before scaling.

## Production security boundaries

- The API's GCP service account should have only the Compute Engine permissions needed for the selected provisioning workflow, plus iam.serviceAccounts.actAs only on the specific workload service account if required.
- Never grant broad Project Editor or Owner roles to the application service account.
- Keep the database on private IP where supported; require TLS and strong database credentials.
- Store DATABASE_URL, session secrets, agent CA material and provider credentials in Secret Manager or the deployment's secret facility, not Git.
- Use a dedicated CA (for example, step-ca or an equivalent managed PKI workflow) for agent client certificates. An enrollment token is a bootstrap credential, not a replacement for mTLS.
- Record every VM lifecycle action in the audit log. Scope every server and hosting resource query to the authenticated organization.
- Use queue-backed, idempotent provisioning jobs with retries and explicit states. Never run long provisioning work inside a user-facing HTTP request.
- Configure snapshots and independent backups; test restoration before onboarding paying customers.

## Implementation sequence

1. Finish API and agent CI and add automated tenant-isolation tests.
2. Complete the server registration and one-time enrollment workflow.
3. Deploy the API to the dedicated GCP control-plane VM and connect a PostgreSQL database.
4. Implement agent mTLS enrollment, heartbeat and telemetry.
5. Add a GCP provider adapter for creating, inspecting, stopping and deleting Compute Engine VMs.
6. Add a safe provisioning worker and an agent operation allowlist.
7. Build dashboard screens for servers, health, provisioning jobs and audit history.
8. Add website provisioning (Nginx, PHP-FPM, users, quotas, domains and automated TLS) only after the server lifecycle and isolation controls are tested.

## Important status

This document is the deployment plan, not evidence that GCP resources have been created. Nexora does not yet provision Compute Engine VMs, issue agent certificates, install websites or provide production hosting. Those capabilities require implementation, deployment and end-to-end testing.