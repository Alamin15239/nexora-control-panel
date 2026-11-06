ALTER TABLE github_projects ADD COLUMN github_installation_id TEXT;
CREATE INDEX IF NOT EXISTS idx_github_projects_installation ON github_projects(github_installation_id);
