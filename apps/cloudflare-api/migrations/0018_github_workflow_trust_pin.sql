-- Require an administrator-approved immutable workflow revision before issuing build credentials.
ALTER TABLE github_projects ADD COLUMN trusted_workflow_sha TEXT;
