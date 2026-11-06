-- Efficiently find expired artifacts without scanning deployment history.
-- Successful artifacts are intentionally excluded from automatic deletion.
CREATE INDEX IF NOT EXISTS idx_github_deployments_failed_artifact_retention
ON github_deployments(finished_at)
WHERE artifact_key IS NOT NULL AND status IN ('failed', 'cancelled');

-- Deployment history is append-only: retries and rollbacks create new rows.
-- This also prevents a terminal artifact from becoming active while GC deletes it.
CREATE TRIGGER IF NOT EXISTS github_deployments_terminal_status_immutable
BEFORE UPDATE OF status ON github_deployments
WHEN OLD.status IN ('succeeded', 'failed', 'cancelled')
 AND NEW.status <> OLD.status
BEGIN
  SELECT RAISE(ABORT, 'terminal deployment status is immutable');
END;
