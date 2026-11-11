#!/usr/bin/env python3
"""Real-SQLite concurrency tests for the MFA SQL atomicity guards.

This exercises the same conditional UPDATE statements used by the Worker,
against a real SQLite database with independent concurrent connections.
It does not claim to emulate Cloudflare's remote D1 service; D1 acceptance
remains a deployment-environment check.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
import tempfile
import threading
from datetime import datetime, timedelta, timezone

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = sorted((ROOT / "migrations").glob("*.sql"))

FAILED_INCREMENT = """
UPDATE mfa_challenges
SET failed_attempts = failed_attempts + 1,
    locked_at = CASE WHEN failed_attempts + 1 >= ? THEN ? ELSE locked_at END
WHERE id = ? AND consumed_at IS NULL AND locked_at IS NULL
  AND expires_at > ? AND failed_attempts < ?
"""
CONSUME_CHALLENGE = """
UPDATE mfa_challenges SET consumed_at = ?
WHERE id = ? AND user_id = ? AND organization_id = ?
  AND consumed_at IS NULL AND locked_at IS NULL AND expires_at > ?
"""
CLAIM_TOTP_PERIOD = """
UPDATE mfa_factors SET last_used_totp_period = ?
WHERE id = ? AND (last_used_totp_period IS NULL OR last_used_totp_period < ?)
  AND EXISTS (
    SELECT 1 FROM mfa_challenges
    WHERE id = ? AND user_id = ? AND organization_id = ? AND consumed_at = ?
  )
"""


def connect(path: str) -> sqlite3.Connection:
    db = sqlite3.connect(path, timeout=15, isolation_level=None)
    db.execute("PRAGMA busy_timeout = 15000")
    return db


def initialize(path: str) -> None:
    db = connect(path)
    db.execute("PRAGMA foreign_keys = ON")
    for migration in MIGRATIONS:
        db.executescript(migration.read_text(encoding="utf-8"))
    db.execute("INSERT INTO organizations(id,name,slug,status) VALUES ('org-a','Org A','org-a','ACTIVE')")
    db.execute("INSERT INTO users(id,email,status) VALUES ('user-a','a@example.test','ACTIVE')")
    db.execute("INSERT INTO memberships(id,user_id,organization_id,role) VALUES ('membership-a','user-a','org-a','ADMIN')")
    db.execute(
        "INSERT INTO mfa_factors(id,user_id,kind,encrypted_secret,backup_codes,last_used_totp_period) "
        "VALUES ('factor-a','user-a','totp','encrypted','activated',NULL)"
    )
    db.close()


def add_challenge(path: str, challenge_id: str) -> None:
    expires = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
    db = connect(path)
    db.execute(
        "INSERT INTO mfa_challenges(id,user_id,organization_id,expires_at) VALUES (?,?,?,?)",
        (challenge_id, "user-a", "org-a", expires),
    )
    db.close()


def test_failed_attempts_are_atomic_under_concurrency(path: str) -> None:
    add_challenge(path, "failed-challenge")
    cap = 5
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    def attempt(_: int) -> int:
        db = connect(path)
        try:
            return db.execute(FAILED_INCREMENT, (cap, now, "failed-challenge", now, cap)).rowcount
        finally:
            db.close()

    with ThreadPoolExecutor(max_workers=12) as pool:
        changes = list(pool.map(attempt, range(12)))

    db = connect(path)
    attempts, locked = db.execute(
        "SELECT failed_attempts, locked_at FROM mfa_challenges WHERE id='failed-challenge'"
    ).fetchone()
    db.close()
    assert sum(changes) == cap, f"expected exactly {cap} successful increments, got {sum(changes)}"
    assert attempts == cap, f"counter exceeded or missed cap: {attempts}"
    assert locked is not None, "challenge must lock exactly at the configured cap"
    print("PASS: concurrent invalid attempts increment exactly to five and lock")


def test_totp_period_can_be_claimed_once_across_challenges(path: str) -> None:
    add_challenge(path, "totp-challenge-a")
    add_challenge(path, "totp-challenge-b")
    period = 60000000
    barrier = threading.Barrier(2)

    def complete(challenge_id: str) -> int:
        db = connect(path)
        try:
            now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            consumed = db.execute(
                CONSUME_CHALLENGE,
                (now, challenge_id, "user-a", "org-a", now),
            )
            assert consumed.rowcount == 1
            barrier.wait(timeout=10)
            claimed = db.execute(
                CLAIM_TOTP_PERIOD,
                (period, "factor-a", period, challenge_id, "user-a", "org-a", now),
            )
            return claimed.rowcount
        finally:
            db.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(pool.map(complete, ["totp-challenge-a", "totp-challenge-b"]))

    db = connect(path)
    stored_period = db.execute(
        "SELECT last_used_totp_period FROM mfa_factors WHERE id='factor-a'"
    ).fetchone()[0]
    db.close()
    assert sum(claims) == 1, f"one TOTP period must be claimable once, got {claims}"
    assert stored_period == period
    print("PASS: concurrent challenges can claim one TOTP period only once")


def test_authorization_query_rejects_inactive_user_and_org(path: str) -> None:
    db = connect(path)
    query = """
    SELECT m.role
    FROM memberships m
    JOIN users u ON u.id = m.user_id AND u.status = 'ACTIVE'
    JOIN organizations o ON o.id = m.organization_id AND o.status = 'ACTIVE'
    WHERE m.user_id = ? AND m.organization_id = ? LIMIT 1
    """
    assert db.execute(query, ("user-a", "org-a")).fetchone() is not None
    db.execute("UPDATE users SET status='SUSPENDED' WHERE id='user-a'")
    assert db.execute(query, ("user-a", "org-a")).fetchone() is None
    db.execute("UPDATE users SET status='ACTIVE' WHERE id='user-a'")
    db.execute("UPDATE organizations SET status='SUSPENDED' WHERE id='org-a'")
    assert db.execute(query, ("user-a", "org-a")).fetchone() is None
    db.close()
    print("PASS: final session authorization query rejects inactive user or organization")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="nexora-mfa-") as temp:
        path = str(Path(temp) / "mfa.sqlite")
        initialize(path)
        test_failed_attempts_are_atomic_under_concurrency(path)
        test_totp_period_can_be_claimed_once_across_challenges(path)
        test_authorization_query_rejects_inactive_user_and_org(path)
    print("ALL MFA ATOMICITY TESTS PASSED")


if __name__ == "__main__":
    main()
