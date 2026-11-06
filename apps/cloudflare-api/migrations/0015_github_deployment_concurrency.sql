-- A project may have only one queued or active deployment at a time.
-- Terminal states are intentionally excluded so deployment history remains append-only.
CREATE UNIQUE INDEX IF NOT EXISTS idx_github_deployments_one_active_per_project
ON github_deployments(project_id)
WHERE status IN ('queued', 'cloning', 'installing', 'building', 'publishing');
