# Nexora hosting panel: cPanel and WHM product structure

## Product split

Nexora should have two distinct user experiences backed by one control plane:

- **WHM / Platform Admin** manages infrastructure and customers: servers and runtime nodes, hosting packages, customer hosting accounts, service health, global DNS/SSL policy, billing/quotas, audit and platform settings.
- **cPanel / Customer Account** manages only the hosting account(s) explicitly assigned to the signed-in customer: websites, domains, document roots, file manager, databases and database users, mailboxes, DNS (only when delegated), SSL status, backups, application deployments and usage.

Do not expose the WHM navigation or organization-wide APIs to a customer login. A customer must never be able to select an arbitrary hosting account ID and gain access to it.

## Current repository state

The current Next.js app is an organization-scoped administrator console. Login establishes an organization membership role (OWNER, ADMIN, BILLING, SUPPORT, MEMBER). Most provisioning and account operations still use the organization-level OWNER/ADMIN authorization check. There is no customer-to-hosting-account assignment relation yet.

The redesigned navigation therefore explicitly labels the existing app WHM / Administrator. The cPanel-style tiles on its overview are operator shortcuts, not a claim that the customer portal or account-level authorization is already implemented.

## Proposed navigation

### WHM / Administrator

- Overview
- Servers & nodes
- Hosting packages
- Customer accounts
- Monitoring and incidents
- Global DNS and hostname management
- Runtime pools and application workloads
- Security, audit and platform settings

### cPanel / Customer account

- Home / account summary
- Websites & domains
- File Manager
- Databases and database users
- Email accounts and forwarding
- DNS zone editor (only if delegated)
- SSL/TLS status and certificate actions
- Backups and restore
- Git / application deployments
- Resource usage and logs
- Account preferences and access

Customer navigation must be account-contextual. When a customer has multiple assigned hosting accounts, the account selector may switch only among server-authorized assignments.

## Authorization model required before customer portal

Add a relation such as hosting_account_memberships with:
- id, hosting_account_id, user_id, role, status, created_at
- unique (hosting_account_id, user_id)
- constrained roles such as ACCOUNT_OWNER, ACCOUNT_ADMIN, ACCOUNT_DEVELOPER, ACCOUNT_READONLY

Every customer endpoint must:
1. Authenticate the session and resolve the organization membership.
2. Resolve the hosting account from the route, then prove the signed-in user has an active account assignment.
3. Apply action-level permission checks (read, file write, database create, mailbox manage, backup restore, deployment).
4. Query all resources with both hosting_account_id and organization_id predicates.
5. Record security-sensitive changes in the audit log with actor, account, action and resource.
6. Return no cross-account existence details for unauthorized IDs.

Do not rely on hidden navigation, client-side role checks, a selected account dropdown, or a caller-supplied organization/account ID as authorization.

## Suggested delivery order

1. Complete the current WHM information architecture and visual consistency.
2. Add the hosting-account membership schema, invitation/assignment workflows and authorization helpers.
3. Add account-scoped customer API routes and cross-tenant negative tests.
4. Build the cPanel customer shell and account home using only those scoped routes.
5. Add individual cPanel modules (files, databases, email, DNS, SSL, backups, deployments and usage).
6. Add organization/customer role-based access, audit coverage and end-to-end isolation tests.

## Design principles

- Familiar cPanel information architecture, but Nexora branding and a cleaner responsive layout.
- Account context always visible in the customer portal.
- Resource usage and plan limits visible near the top of the account home.
- Frequent actions are quick-launch tiles; detailed management lives in dedicated modules.
- Clear queued/running/succeeded/failed job states for operations performed by the Linux agent.
- No fake controls: every visible action must be backed by an implemented and authorized API operation.
- Distinguish a real server or service health signal from an unverified/configured state.