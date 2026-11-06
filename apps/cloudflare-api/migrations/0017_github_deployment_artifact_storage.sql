-- Persist the private staging object reference without exposing it to customers.
ALTER TABLE github_deployments ADD COLUMN artifact_key TEXT;
ALTER TABLE github_deployments ADD COLUMN artifact_bytes INTEGER;
