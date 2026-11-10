# Nexora Control Panel — Project Status & Tutorial

Last updated: 10 November 2026

## 1. Project Overview

Nexora Control Panel is a hosting management platform intended to provide
cPanel-style hosting services, website management, domain management,
and automated deployments.

The project uses:
- Cloudflare Workers for the API/control plane
- Cloudflare D1 for application data
- Cloudflare Pages for the dashboard
- Ubuntu and Nginx for hosting workloads
- A Go-based Linux agent for server operations
- Cloudflare Tunnel for connectivity

## 2. Completed Work

The following items have been implemented during development.
They should still undergo final acceptance testing before production use.

### Control Plane and Infrastructure
- Cloudflare Worker API and D1 integration.
- Dashboard and login application.
- Cloudflare API credentials configured for the API.
- Cloudflare Tunnel connectivity configured.
- Custom hostname and fallback-origin configuration.
- Hosting account and domain provisioning foundations.

### Hosting Server
- Ubuntu hosting environment.
- Nginx web server.
- PHP-FPM integration.
- Hosting account directory isolation.
- Account-specific public_html file management.
- Basic website publishing and HTTP testing.
- Linux agent installation and heartbeat reporting.

### Static Deployment Lifecycle
- Pending static deployment retrieval.
- Signed deployment artifact validation.
- Artifact delivery and archive validation.
- Release staging and activation.
- Protection against stale releases replacing newer releases.
- Idempotent activation and rollback foundations.
- Activation acknowledgement and health-check workflow.

## 3. Outstanding Deployment Lifecycle Work

These items were still outstanding at the last development review.

- Recover releases in health_checking after an agent restart.
- Verify that the local active release symlink matches the expected release ID.
- Make health-report retries idempotent when probe duration changes.
- Reject retries that conflict with the original health outcome.
- Add regression tests for these recovery scenarios.
- Run the complete Go test suite.
- Run all Worker integration tests.
- Run the TypeScript typecheck.
- Review the final changes for security and concurrency issues.

Do not mark these complete until implementation and tests have been verified.

## 4. Final Acceptance Testing

Before production release, verify:

1. A deployment can be uploaded and validated.
2. A valid release can be activated.
3. An interrupted activation can recover safely.
4. An agent restart during health_checking recovers correctly.
5. A successful health report marks the release succeeded.
6. An unhealthy release is handled using the rollback workflow.
7. Repeated health reports do not create conflicting duplicate events.
8. A stale deployment cannot overwrite a newer deployment.
9. A failed deployment does not damage the active website.
10. Multiple hosting accounts remain isolated.

## 5. Development Commands

### Go agent tests

```bash
cd agents/linux-agent
go test ./... -count=1
```

### Worker tests

```bash
cd apps/cloudflare-api

mapfile -t TESTS < <(
  find . -type d -name node_modules -prune -o \
    -type f \( -name '*.test.ts' -o -name '*.spec.ts' \) -print
)

./node_modules/.bin/tsx --test "${TESTS[@]}"
```

### Worker TypeScript typecheck

```bash
cd apps/cloudflare-api
npm run typecheck
```

### Review repository changes

```bash
git status --short
git diff --check
git diff --stat
```

## 6. Production Readiness — Remaining Areas to Audit

The following areas require a repository-wide audit and must not be assumed
complete simply because the deployment lifecycle is implemented.

- Authentication and session security.
- Role-based access control and organization isolation.
- Hosting plan enforcement and quotas.
- Website, database, email and domain management.
- Custom hostname provisioning and SSL lifecycle.
- Billing, subscriptions and payment integration.
- Backup, restore and disaster recovery.
- Monitoring, logging and alerting.
- Rate limiting and abuse protection.
- Agent upgrade and recovery procedures.
- Security hardening and penetration testing.
- Production deployment and rollback procedures.
- Documentation and operational support procedures.

## 7. Release Procedure

1. Review all modified files.
2. Run all relevant tests.
3. Review database migrations.
4. Confirm secrets are not committed.
5. Commit changes to Git.
6. Push to the intended GitHub branch.
7. Deploy to a test environment.
8. Run end-to-end acceptance tests.
9. Approve production deployment only after verification.

## 8. Progress Tracking

Update this document whenever a feature is implemented and verified.

Use these statuses:

- [x] Implemented — code exists.
- [ ] Remaining — implementation or verification is incomplete.
- [ ] Verified — tests and acceptance checks passed.

Implementation does not automatically mean production-ready.

## 9. Current Overall Status

The project has substantial hosting infrastructure, control-plane,
and static deployment foundations.

The static deployment lifecycle still needs the outstanding recovery,
idempotency, and regression-test work described above.

The complete product's percentage of completion is not yet established.
A repository-wide feature audit is required before assigning a reliable
overall completion percentage.
