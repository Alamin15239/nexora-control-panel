-- Efficiently find expired artifacts without scanning deployment history.
-- Successful artifacts are intentionally excluded from automatic deletion.
CREATE INDEX IF NOT EXISTS idx_github_deployments_failed_artifact_retention
ON github_deployments(finished_at)
WHERE artifact_key IS NOT NULL AND status IN ('failed', 'cancelled');
