#!/usr/bin/env python3
"""Apply all D1 migrations to SQLite and exercise multi-runtime tenant guards."""
from pathlib import Path
import sqlite3

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "migrations"
db = sqlite3.connect(":memory:")
db.execute("PRAGMA foreign_keys = ON")

for migration in sorted(MIGRATIONS.glob("*.sql")):
    try:
        db.executescript(migration.read_text(encoding="utf-8"))
    except sqlite3.Error as exc:
        raise SystemExit(f"Migration failed: {migration.name}: {exc}") from exc

required = {
    "application_runtime_profiles", "application_node_pools", "application_nodes",
    "application_project_settings", "application_releases",
    "application_release_events", "application_workloads",
    "application_usage_periods", "application_usage_events", "application_node_request_nonces",
    "application_node_signing_key_history",
}
actual = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
missing = required - actual
assert not missing, f"Missing application tables: {sorted(missing)}"

# Minimal, valid project/deployment fixture in two separate tenants.
db.execute("INSERT INTO organizations(id,name,slug) VALUES ('org-a','Org A','org-a'),('org-b','Org B','org-b')")
db.execute("INSERT INTO users(id,email,status) VALUES ('user-a','a@example.test','ACTIVE')")
db.execute("INSERT INTO hosting_plans(id,organization_id,name,disk_limit_bytes) VALUES ('plan-a','org-a','Plan A',1000000)")
plan_limits = db.execute(
    """SELECT app_cpu_millis, app_memory_mib, app_disk_mib, app_process_limit, app_build_minutes_month
       FROM hosting_plans WHERE id='plan-a'"""
).fetchone()
assert plan_limits == (500, 512, 2048, 128, 300), f"Unexpected default runtime plan quotas: {plan_limits}"
must_reject_plan_quota = False
try:
    db.execute("UPDATE hosting_plans SET app_memory_mib=16385 WHERE id='plan-a'")
except sqlite3.IntegrityError:
    must_reject_plan_quota = True
assert must_reject_plan_quota, "Hosting plan memory quota CHECK constraint was not enforced"
db.execute("INSERT INTO servers(id,organization_id,hostname,primary_ip) VALUES ('server-a','org-a','node-a','192.0.2.10')")
db.execute("INSERT INTO hosting_accounts(id,organization_id,server_id,plan_id,username) VALUES ('account-a','org-a','server-a','plan-a','tenant-a')")
db.execute("""INSERT INTO github_connections
(id,organization_id,github_user_id,github_login,encrypted_access_token,access_token_iv)
VALUES ('connection-a','org-a','1','test','ciphertext','iv')""")
db.execute("""INSERT INTO github_projects
(id,organization_id,hosting_account_id,github_connection_id,github_repository_id,repository_full_name)
VALUES ('project-a','org-a','account-a','connection-a','repo-1','owner/repo')""")
db.execute("""INSERT INTO github_deployments
(id,organization_id,project_id,commit_sha,branch,trigger_type)
VALUES ('deployment-a','org-a','project-a',?,'main','manual')""", ("a" * 40,))
db.execute("""INSERT INTO hosting_accounts
(id,organization_id,server_id,plan_id,username)
VALUES ('account-other','org-a','server-a','plan-a','tenant-other')""")
db.execute("""INSERT INTO github_projects
(id,organization_id,hosting_account_id,github_connection_id,github_repository_id,repository_full_name)
VALUES ('project-b','org-a','account-other','connection-a','repo-2','owner/other-repo')""")
db.execute("""INSERT INTO github_deployments
(id,organization_id,project_id,commit_sha,branch,trigger_type)
VALUES ('deployment-b','org-a','project-b',?,'main','manual')""", ("b" * 40,))
def must_reject(label, sql, args):
    try:
        db.execute(sql, args)
    except sqlite3.IntegrityError:
        return
    raise AssertionError(f"Tenant guard did not reject: {label}")

db.execute("""INSERT INTO application_node_pools
(id,name,environment,region,runtime_engine,status)
VALUES ('pool-a','Test builder pool','staging','test-region','containerd','ready')""")
assert db.execute("SELECT isolation_level FROM application_node_pools WHERE id='pool-a'").fetchone()[0] == "untrusted"
db.execute("UPDATE application_node_pools SET isolation_level='rootless' WHERE id='pool-a'")
db.execute("""INSERT INTO application_nodes
(id,node_pool_id,node_identity,enrollment_key_hash,node_role,status,signing_public_key,enrollment_consumed_at)
VALUES ('builder-a','pool-a','builder-a','hash-a','builder','online',?,datetime('now'))""", ("a" * 64,))
db.execute("""INSERT INTO application_node_pools
(id,name,environment,region,runtime_engine,status,isolation_level)
VALUES ('pool-untrusted','Untrusted pool','staging','test-region','containerd','ready','untrusted')""")
db.execute("""INSERT INTO application_nodes
(id,node_pool_id,node_identity,enrollment_key_hash,node_role,status,signing_public_key,enrollment_consumed_at)
VALUES ('builder-untrusted','pool-untrusted','builder-untrusted','hash-untrusted','builder','online',?,datetime('now'))""", ("b" * 64,))
db.execute("""INSERT INTO application_node_pools
(id,name,environment,region,runtime_engine,status,isolation_level)
VALUES ('pool-runtime','Runtime pool','production','test-region','microvm','ready','microvm')""")
db.execute("""INSERT INTO application_nodes
(id,node_pool_id,node_identity,enrollment_key_hash,node_role,status,signing_public_key,enrollment_consumed_at)
VALUES ('runtime-a','pool-runtime','runtime-a','hash-runtime','runtime','online',?,datetime('now'))""", ("c" * 64,))

# Project runtime pool assignment is restricted to online runtime nodes in isolated ready pools.
must_reject(
    "builder-only pool cannot host runtime projects",
    """INSERT INTO application_project_settings
    (id,organization_id,project_id,runtime_profile_id,node_pool_id)
    VALUES ('settings-builder','org-a','project-a','runtime-nodejs-v1','pool-a')""",
    (),
)
must_reject(
    "untrusted pool cannot host runtime projects",
    """INSERT INTO application_project_settings
    (id,organization_id,project_id,runtime_profile_id,node_pool_id)
    VALUES ('settings-untrusted','org-a','project-a','runtime-nodejs-v1','pool-untrusted')""",
    (),
)
db.execute("""INSERT INTO application_project_settings
(id,organization_id,project_id,runtime_profile_id,node_pool_id)
VALUES ('settings-runtime','org-a','project-a','runtime-nodejs-v1','pool-runtime')""")
assert db.execute(
    "SELECT node_pool_id FROM application_project_settings WHERE id='settings-runtime'"
).fetchone()[0] == "pool-runtime"
must_reject(
    "project runtime pool reassignment to builder-only pool",
    "UPDATE application_project_settings SET node_pool_id='pool-a' WHERE id='settings-runtime'",
    (),
)

db.execute("""INSERT INTO application_usage_periods
(id,organization_id,project_id,period_start,build_minutes_limit)
VALUES ('usage-a','org-a','project-a','2026-11-01',300)""")

# Node identity and pool isolation are explicit security gates.
assert db.execute("SELECT node_role FROM application_nodes WHERE id='builder-a'").fetchone()[0] == "builder"
for node_id in ("builder-untrusted", "runtime-a"):
    rejected = False
    try:
        db.execute("""INSERT INTO application_usage_events
        (id,organization_id,project_id,deployment_id,period_start,build_seconds,source,build_result,node_id)
        VALUES (?,?,?,?,?,?,'isolated_builder','succeeded',?)""",
        ("evt-" + node_id, "org-a", "project-a", "deployment-a", "2026-11-01", 30, node_id))
    except sqlite3.IntegrityError:
        rejected = True
    assert rejected, f"Untrusted or runtime node was allowed to report builder usage: {node_id}"
db.execute("""INSERT INTO application_nodes
(id,node_pool_id,node_identity,enrollment_key_hash,status)
VALUES ('node-a','pool-a','node-a',?,'pending')""", ("b" * 64,))
assert db.execute("SELECT node_role FROM application_nodes WHERE id='node-a'").fetchone()[0] == "runtime", "New nodes must default to runtime, not builder"
must_reject(
    "invalid Ed25519 public key encoding",
    "UPDATE application_nodes SET signing_public_key='not-a-public-key' WHERE id='node-a'",
    (),
)
db.execute("UPDATE application_nodes SET signing_public_key=? WHERE id='node-a'", ("c" * 64,))
db.execute("""INSERT INTO application_node_request_nonces(node_id,nonce,expires_at)
VALUES ('node-a',?,'2026-11-07 00:10:00')""", ("d" * 32,))
db.execute("""INSERT INTO application_node_signing_key_history (id,node_id,public_key)
VALUES ('key-history-runtime','runtime-a',?)""", ("c" * 64,))
must_reject(
    "signing key history deletion",
    "DELETE FROM application_node_signing_key_history WHERE id='key-history-runtime'",
    (),
)
must_reject(
    "signing key history mutation",
    "UPDATE application_node_signing_key_history SET public_key=? WHERE id='key-history-runtime'",
    ("d" * 64,),
)
db.execute("UPDATE application_node_signing_key_history SET retired_at=datetime('now') WHERE id='key-history-runtime'")

db.execute("""INSERT OR IGNORE INTO application_node_pools
(id,name,environment,region,runtime_engine,status,isolation_level)
VALUES ('pool-runtime','Dedicated Runtime Pool','staging','test-region','microvm','ready','microvm')""")
db.execute("UPDATE application_node_pools SET status='ready', isolation_level='microvm' WHERE id='pool-runtime'")
db.execute("""INSERT INTO application_nodes
(id,node_pool_id,node_identity,enrollment_key_hash,status,agent_version,signing_public_key,enrollment_consumed_at,last_heartbeat_at)
VALUES ('runtime-node-b','pool-runtime','runtime-b',?,'online','0.4.0',?,datetime('now'),datetime('now'))""",
    ("e" * 64, "d" * 64))
db.execute("""INSERT INTO application_releases
(id,organization_id,project_id,deployment_id,node_pool_id,runtime_profile_id,assigned_node_id,spec_version,source_commit_sha)
VALUES ('release-a','org-a','project-a','deployment-a','pool-runtime','runtime-nodejs-v1','runtime-node-b',1,?)""", ("a" * 40,))
assert db.execute(
    "SELECT assigned_node_id FROM application_releases WHERE id='release-a'"
).fetchone()[0] == "runtime-node-b"
must_reject(
    "release cannot be assigned to a builder node",
    "UPDATE application_releases SET assigned_node_id='builder-a' WHERE id='release-a'",
    (),
)
must_reject(
    "release cannot lose its individual runtime node assignment",
    "UPDATE application_releases SET assigned_node_id=NULL WHERE id='release-a'",
    (),
)
db.execute("""INSERT INTO application_nodes
(id,node_pool_id,node_identity,enrollment_key_hash,node_role,status,signing_public_key,enrollment_consumed_at,last_heartbeat_at)
VALUES ('runtime-node-c','pool-runtime','runtime-c',?,'runtime','online',?,datetime('now'),datetime('now'))""",
    ("f" * 64, "e" * 64))
must_reject(
    "release cannot be reassigned to another otherwise eligible runtime node",
    "UPDATE application_releases SET assigned_node_id='runtime-node-c' WHERE id='release-a'",
    (),
)
must_reject(
    "release execution tenant and project binding is immutable",
    "UPDATE application_releases SET project_id='project-b', deployment_id='deployment-b' WHERE id='release-a'",
    (),
)
must_reject(
    "release source commit is immutable",
    "UPDATE application_releases SET source_commit_sha=? WHERE id='release-a'",
    ("b" * 40,),
)
db.execute("UPDATE application_releases SET artifact_digest=?, artifact_bytes=128 WHERE id='release-a'",
           ("c" * 64,))
must_reject(
    "release artifact digest cannot be replaced",
    "UPDATE application_releases SET artifact_digest=? WHERE id='release-a'",
    ("d" * 64,),
)
must_reject(
    "release artifact size cannot be changed after acceptance",
    "UPDATE application_releases SET artifact_bytes=256 WHERE id='release-a'",
    (),
)

must_reject(
    "signing key retirement cannot be changed twice",
    "UPDATE application_node_signing_key_history SET retired_at=datetime('now','+1 minute') WHERE id='key-history-runtime'",
    (),
)
db.execute("UPDATE application_nodes SET status='revoked', revoked_at=datetime('now') WHERE id='runtime-a'")
must_reject(
    "revoked node reactivation",
    "UPDATE application_nodes SET status='online' WHERE id='runtime-a'",
    (),
)
must_reject(
    "revoked node signing key mutation",
    "UPDATE application_nodes SET signing_public_key=? WHERE id='runtime-a'",
    ("e" * 64,),
)

must_reject(
    "duplicate per-node request nonce",
    """INSERT INTO application_node_request_nonces(node_id,nonce,expires_at)
    VALUES ('node-a',?,'2026-11-07 00:10:00')""",
    ("d" * 32,),
)



must_reject(
    "settings organization mismatch",
    """INSERT INTO application_project_settings
    (id,organization_id,project_id,runtime_profile_id) VALUES ('settings-b','org-b','project-a','runtime-nodejs-v1')""",
    (),
)
must_reject(
    "release organization mismatch",
    """INSERT INTO application_releases
    (id,organization_id,project_id,deployment_id,spec_version,source_commit_sha)
    VALUES ('release-b','org-b','project-a','deployment-a',1,?)""",
    ("a" * 40,),
)

must_reject(
    "invalid release state jump",
    "UPDATE application_releases SET state='succeeded' WHERE id='release-a'",
    (),
)
for state in ("authorized", "building", "artifact_uploaded", "validating",
              "ready_to_publish", "publishing", "health_checking", "succeeded"):
    db.execute("UPDATE application_releases SET state=? WHERE id='release-a'", (state,))
db.execute("UPDATE application_releases SET state='rolled_back' WHERE id='release-a'")

must_reject(
    "workload cross-tenant release",
    """INSERT INTO application_workloads
    (id,organization_id,project_id,active_release_id,workload_kind)
    VALUES ('workload-b','org-b','project-a','release-a','web')""",
    (),
)

violations = list(db.execute("PRAGMA foreign_key_check"))
# Usage periods are tenant-bound; aggregation and event marking are idempotent.
db.execute("""INSERT INTO application_usage_events
(id,organization_id,project_id,deployment_id,period_start,build_seconds,source,node_id)
VALUES ('usage-event-a','org-a','project-a','deployment-a','2026-11-01',120,'isolated_builder','builder-a')""")
db.execute("""UPDATE application_usage_periods SET build_seconds_used = build_seconds_used + (
  SELECT COALESCE(SUM(build_seconds),0) FROM application_usage_events
  WHERE organization_id='org-a' AND project_id='project-a'
    AND period_start='2026-11-01' AND aggregated_at IS NULL
) WHERE organization_id='org-a' AND project_id='project-a' AND period_start='2026-11-01'""")
db.execute("UPDATE application_usage_events SET aggregated_at=? WHERE id=?", ("2026-11-07 00:00:00","usage-event-a"))
assert db.execute("SELECT build_seconds_used FROM application_usage_periods WHERE id=?", ("usage-a",)).fetchone()[0] == 120
must_reject(
    "duplicate usage event for deployment",
    """INSERT INTO application_usage_events
    (id,organization_id,project_id,deployment_id,period_start,build_seconds,source)
    VALUES ('usage-event-b','org-a','project-a','deployment-a','2026-11-01',120,'isolated_builder')""",
    (),
)
db.execute("""INSERT OR IGNORE INTO application_usage_events
(id,organization_id,project_id,deployment_id,period_start,build_seconds,source)
VALUES ('usage-event-replay','org-a','project-a','deployment-a','2026-11-01',120,'isolated_builder')""")
db.execute("""UPDATE application_usage_periods SET build_seconds_used = build_seconds_used + (
  SELECT COALESCE(SUM(build_seconds),0) FROM application_usage_events
  WHERE organization_id='org-a' AND project_id='project-a'
    AND period_start='2026-11-01' AND aggregated_at IS NULL
) WHERE organization_id='org-a' AND project_id='project-a' AND period_start='2026-11-01'""")
assert db.execute("SELECT build_seconds_used FROM application_usage_periods WHERE id=?", ("usage-a",)).fetchone()[0] == 120, "Duplicate report changed aggregate usage"
must_reject(
    "usage period cross-tenant write",
    """INSERT INTO application_usage_periods
    (id,organization_id,project_id,period_start,build_minutes_limit)
    VALUES ('usage-b','org-b','project-a','2026-11-01',300)""",
    (),
)
must_reject(
    "usage event node attribution is immutable",
    "UPDATE application_usage_events SET node_id=NULL WHERE id='usage-event-a'",
    (),
)
must_reject(
    "aggregated usage event payload mutation",
    "UPDATE application_usage_events SET build_seconds=999 WHERE id='usage-event-a'",
    (),
)
must_reject(
    "usage event aggregate marker cannot be reset",
    "UPDATE application_usage_events SET aggregated_at=NULL WHERE id='usage-event-a'",
    (),
)
must_reject(
    "invalid usage source",
    """INSERT INTO application_usage_events
    (id,organization_id,project_id,deployment_id,period_start,build_seconds,source)
    VALUES ('usage-event-invalid','org-a','project-a','deployment-b','2026-11-01',120,'client')""",
    (),
)
# Customer cPanel membership is explicit, role-constrained, and tenant-bound.
db.execute("""INSERT INTO hosting_account_memberships
(id,hosting_account_id,organization_id,user_id,role)
VALUES ('account-member-a','account-a','org-a','user-a','ACCOUNT_OWNER')""")
assert db.execute(
    """SELECT role FROM hosting_account_memberships
       WHERE hosting_account_id='account-a' AND organization_id='org-a'
         AND user_id='user-a' AND status='ACTIVE'"""
).fetchone()[0] == "ACCOUNT_OWNER"
must_reject(
    "account membership cannot cross organization boundary",
    """INSERT INTO hosting_account_memberships
    (id,hosting_account_id,organization_id,user_id,role)
    VALUES ('account-member-cross','account-a','org-b','user-a','ACCOUNT_ADMIN')""",
    (),
)
must_reject(
    "account membership role must be recognized",
    """INSERT INTO hosting_account_memberships
    (id,hosting_account_id,organization_id,user_id,role)
    VALUES ('account-member-invalid','account-a','org-a','user-a','OWNER')""",
    (),
)
db.execute(
    "UPDATE hosting_account_memberships SET status='REVOKED' WHERE id='account-member-a'"
)
assert db.execute(
    "SELECT status FROM hosting_account_memberships WHERE id='account-member-a'"
).fetchone()[0] == "REVOKED"


# Customer resource inventory queries must remain scoped to the selected active membership.
db.execute("INSERT INTO users(id,email,status) VALUES ('user-b','b@example.test','ACTIVE')")
db.execute("INSERT INTO memberships(id,user_id,organization_id,role) VALUES ('org-member-b','user-b','org-b','MEMBER')")
db.execute("INSERT INTO hosting_plans(id,organization_id,name,disk_limit_bytes) VALUES ('plan-b','org-b','Plan B',1000000)")
db.execute("INSERT INTO servers(id,organization_id,hostname,primary_ip) VALUES ('server-b','org-b','node-b','192.0.2.11')")
db.execute("INSERT INTO hosting_accounts(id,organization_id,server_id,plan_id,username,status) VALUES ('account-b','org-b','server-b','plan-b','tenant-b','ACTIVE')")
db.execute("UPDATE hosting_accounts SET status='ACTIVE' WHERE id='account-a'")
db.execute("INSERT INTO domains(id,hosting_account_id,name,document_root,is_primary) VALUES ('domain-a','account-a','a.example.test','/home/tenant-a/public_html',1)")
db.execute("INSERT INTO domains(id,hosting_account_id,name,document_root) VALUES ('domain-b','account-b','b.example.test','/home/tenant-b/public_html')")
db.execute("INSERT INTO hosting_databases(id,organization_id,hosting_account_id,name,engine,status) VALUES ('db-a','org-a','account-a','tenant_a_app','MARIADB','ACTIVE')")
db.execute("INSERT INTO hosting_databases(id,organization_id,hosting_account_id,name,engine,status) VALUES ('db-b','org-b','account-b','tenant_b_app','MARIADB','ACTIVE')")
db.execute("""INSERT INTO hosting_account_memberships
(id,hosting_account_id,organization_id,user_id,role)
VALUES ('account-member-b','account-b','org-b','user-b','ACCOUNT_OWNER')""")
db.execute("UPDATE hosting_account_memberships SET status='ACTIVE' WHERE id='account-member-a'")
customer_membership_query = """SELECT a.id FROM hosting_account_memberships m
JOIN hosting_accounts a ON a.id=m.hosting_account_id AND a.organization_id=m.organization_id
WHERE a.id=? AND a.organization_id=? AND m.user_id=?
AND m.status='ACTIVE' AND a.status='ACTIVE' LIMIT 1"""
assert db.execute(customer_membership_query, ("account-a","org-a","user-a")).fetchone() == ("account-a",)
assert db.execute(customer_membership_query, ("account-b","org-a","user-a")).fetchone() is None
assert db.execute(customer_membership_query, ("account-a","org-b","user-b")).fetchone() is None
customer_domains = db.execute(
    "SELECT id,name FROM domains WHERE hosting_account_id=? ORDER BY is_primary DESC,created_at ASC",
    ("account-a",),
).fetchall()
assert customer_domains == [("domain-a","a.example.test")], f"Customer domains escaped account scope: {customer_domains}"
customer_databases = db.execute(
    "SELECT id,name FROM hosting_databases WHERE hosting_account_id=? AND organization_id=? AND status!='DELETED' ORDER BY created_at DESC",
    ("account-a","org-a"),
).fetchall()
assert customer_databases == [("db-a","tenant_a_app")], f"Customer databases escaped account scope: {customer_databases}"
db.execute("UPDATE hosting_account_memberships SET status='REVOKED' WHERE id='account-member-a'")
assert db.execute(customer_membership_query, ("account-a","org-a","user-a")).fetchone() is None, "Revoked membership retained customer resource access"

# --- Subscription / invoice / email schema guards (0044, 0045) ---
subscriptions_actual = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
for table in ("subscriptions", "subscription_events", "invoice_counters", "invoices",
              "billing_webhook_events", "email_domains", "email_mailboxes", "email_forwards"):
    assert table in subscriptions_actual, f"Missing billing/email table: {table}"

# One live subscription per hosting account (partial UNIQUE index).
db.execute("""INSERT INTO subscriptions(id,organization_id,hosting_account_id,plan_id,status,billing_period,
              current_period_start,current_period_end)
              VALUES ('sub-a','org-a','account-a','plan-a','ACTIVE','monthly',datetime('now'),datetime('now','+1 month'))""")
try:
    db.execute("""INSERT INTO subscriptions(id,organization_id,hosting_account_id,plan_id,status,billing_period,
                  current_period_start,current_period_end)
                  VALUES ('sub-a2','org-a','account-a','plan-a','ACTIVE','monthly',datetime('now'),datetime('now','+1 month'))""")
    raise SystemExit("Partial UNIQUE index failed: two live subscriptions for one hosting account were allowed")
except sqlite3.IntegrityError:
    pass
# A second subscription is allowed once the first is terminal.
db.execute("UPDATE subscriptions SET status='CANCELLED', cancelled_at=datetime('now') WHERE id='sub-a'")
db.execute("""INSERT INTO subscriptions(id,organization_id,hosting_account_id,plan_id,status,billing_period,
              current_period_start,current_period_end)
              VALUES ('sub-a3','org-a','account-a','plan-a','ACTIVE','monthly',datetime('now'),datetime('now','+1 month'))""")
# Subscription status CHECK constraint.
try:
    db.execute("UPDATE subscriptions SET status='INVALID' WHERE id='sub-a3'")
    raise SystemExit("subscriptions.status CHECK constraint was not enforced")
except sqlite3.IntegrityError:
    pass
# Invoices: unique sequential numbers per organization.
db.execute("INSERT INTO invoice_counters(organization_id,last_number) VALUES ('org-a',0)")
db.execute("""INSERT INTO invoices(id,organization_id,subscription_id,invoice_number,amount_sar_minor,status,billing_period)
              VALUES ('inv-a','org-a','sub-a3','INV-2026-000001',1500,'OPEN','monthly')""")
try:
    db.execute("""INSERT INTO invoices(id,organization_id,subscription_id,invoice_number,amount_sar_minor,status,billing_period)
                  VALUES ('inv-a-dup','org-a','sub-a3','INV-2026-000001',1500,'OPEN','monthly')""")
    raise SystemExit("invoices.invoice_number UNIQUE constraint was not enforced")
except sqlite3.IntegrityError:
    pass
# Webhook dedup ledger.
db.execute("INSERT INTO billing_webhook_events(id,provider,event_id) VALUES ('wh-a','stripe','evt-1')")
try:
    db.execute("INSERT INTO billing_webhook_events(id,provider,event_id) VALUES ('wh-a2','stripe','evt-1')")
    raise SystemExit("billing_webhook_events UNIQUE(provider, event_id) was not enforced")
except sqlite3.IntegrityError:
    pass
# Email hosting: unique mailbox addresses and per-org domain uniqueness.
db.execute("INSERT INTO email_domains(id,organization_id,hosting_account_id,domain) VALUES ('ed-a','org-a','account-a','mail.example.test')")
db.execute("INSERT INTO email_mailboxes(id,organization_id,email_domain_id,address,quota_mb) VALUES ('em-a','org-a','ed-a','hello@mail.example.test',1024)")
try:
    db.execute("INSERT INTO email_mailboxes(id,organization_id,email_domain_id,address,quota_mb) VALUES ('em-a2','org-a','ed-a','hello@mail.example.test',1024)")
    raise SystemExit("email_mailboxes.address UNIQUE constraint was not enforced")
except sqlite3.IntegrityError:
    pass
try:
    db.execute("INSERT INTO email_mailboxes(id,organization_id,email_domain_id,address,quota_mb) VALUES ('em-a3','org-a','ed-a','tiny@mail.example.test',64)")
    raise SystemExit("email_mailboxes.quota_mb CHECK constraint was not enforced")
except sqlite3.IntegrityError:
    pass

violations = list(db.execute("PRAGMA foreign_key_check"))
assert not violations, f"Foreign-key violations: {violations}"
print(f"PASS: {len(list(MIGRATIONS.glob('*.sql')))} migrations applied; runtime schema, plan quota defaults/checks, per-node Ed25519 key/nonce constraints, usage ledger idempotency/tenant guards/immutable aggregation, customer account membership role and tenant constraints, release transitions, and foreign keys verified.")
