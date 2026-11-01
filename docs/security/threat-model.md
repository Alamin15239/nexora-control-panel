# Initial Threat Model

## Assets

- Customer website files and databases
- Email content and credentials
- Server identity keys
- Control-plane database and session secrets
- DNS and TLS configuration
- Backup encryption keys
- Billing and subscription records

## Threats

- Cross-tenant authorization bypass
- Compromised administrator session
- Server-agent impersonation
- Replay of privileged operations
- Arbitrary command execution
- Malicious or compromised customer website
- Credential theft and secret leakage
- Backup deletion or ransomware
- Email abuse and outbound spam

## Required mitigations

- MFA for privileged users
- Organization-scoped authorization on every request
- PostgreSQL row-level security where appropriate
- Mutual TLS and signed operation envelopes
- Agent allowlists and strict input validation
- Linux account isolation and resource quotas
- Secret manager; never commit credentials
- Immutable/offsite encrypted backups
- Rate limits, abuse detection and audit trails
- Security review and restore drills before production

This is an initial engineering checklist, not a completed security certification.
