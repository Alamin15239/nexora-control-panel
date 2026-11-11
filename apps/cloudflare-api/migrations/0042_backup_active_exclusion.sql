-- Atomic backup exclusion: at most one active backup per hosting account.
--
-- Defect: The previous scheduler used a non-atomic SELECT-COUNT-then-INSERT
-- to check for existing QUEUED/RUNNING backups. The manual backup endpoint
-- (POST /v1/hosting-accounts/:id/backups) did no check at all. A manual
-- backup could be inserted between the scheduler's count check and its
-- insert, producing duplicate active backups for the same account.
--
-- Fix: a partial UNIQUE index on hosting_backups(hosting_account_id) where
-- status is QUEUED or RUNNING. SQLite/D1 enforces this at the storage level
-- — a second INSERT with the same hosting_account_id while an active backup
-- exists fails with SQLITE_CONSTRAINT_UNIQUE, regardless of the isolation
-- level or the order of concurrent requests.
--
-- The index automatically excludes backups in terminal states (AVAILABLE,
-- FAILED, DELETED, RESTORING, RESTORE_STAGED). When a backup transitions
-- to a terminal state, the row is removed from the index and the exclusion
-- is released — the next backup can be created immediately.
--
-- Before creating the index, mark any stuck QUEUED/RUNNING backups as
-- FAILED. These are orphaned from crashed scheduler/agent runs where the
-- lease has expired (10 minutes for the scheduler, 5 minutes for the job).
-- We do NOT delete them — they remain in the backup history with status
-- FAILED so the admin can see what happened. This is a data correction,
-- not a deletion. Without this step, the CREATE UNIQUE INDEX would fail
-- if any account already had duplicate active backups from the race.
UPDATE hosting_backups SET status = 'FAILED', error_message = 'Marked as failed during migration 0042: stale active backup from a pre-exclusion race'
WHERE status IN ('QUEUED', 'RUNNING')
  AND created_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-30 minutes');

CREATE UNIQUE INDEX IF NOT EXISTS idx_hosting_backups_active_exclusion
ON hosting_backups(hosting_account_id)
WHERE status IN ('QUEUED', 'RUNNING');
