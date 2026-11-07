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

db.execute("""INSERT INTO application_usage_periods
(id,organization_id,project_id,period_start,build_minutes_limit)
VALUES ('usage-period-a','org-a','project-a','2026-11-01',300)""")

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
must_reject(
    "invalid Ed25519 public key encoding",
    "UPDATE application_nodes SET signing_public_key='not-a-public-key' WHERE id='node-a'",
    (),
)
db.execute("UPDATE application_nodes SET signing_public_key=? WHERE id='node-a'", ("c" * 64,))
db.execute("""INSERT INTO application_node_request_nonces(node_id,nonce,expires_at)
VALUES ('node-a',?,'2026-11-07 00:10:00')""", ("d" * 32,))
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

db.execute("""INSERT INTO application_releases
(id,organization_id,project_id,deployment_id,spec_version,source_commit_sha)
VALUES ('release-a','org-a','project-a','deployment-a',1,?)""", ("a" * 40,))
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
db.execute("""INSERT INTO application_usage_periods
(id,organization_id,project_id,period_start,build_seconds_used,build_minutes_limit)
VALUES ('usage-a','org-a','project-a','2026-11-01',0,300)""")
db.execute("""INSERT INTO application_usage_events
(id,organization_id,project_id,deployment_id,period_start,build_seconds,source,node_id)
VALUES ('usage-event-a','org-a','project-a','deployment-a','2026-11-01',120,'isolated_builder','node-a')""")
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
violations = list(db.execute("PRAGMA foreign_key_check"))
assert not violations, f"Foreign-key violations: {violations}"
print(f"PASS: {len(list(MIGRATIONS.glob('*.sql')))} migrations applied; runtime schema, plan quota defaults/checks, per-node Ed25519 key/nonce constraints, usage ledger idempotency/tenant guards/immutable aggregation, release transitions, and foreign keys verified.")
