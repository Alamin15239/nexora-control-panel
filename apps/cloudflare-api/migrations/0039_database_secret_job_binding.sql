-- Bind database user secrets to the exact provisioning job that will
-- consume them, and track one-time retrieval by the agent.
--
-- job_id: the provisioning_jobs.id of the RESET_DATABASE_USER_PASSWORD
--   job that will use this secret. The agent fetches the credential via
--   /internal/v1/agent/jobs/:jobId/credential, so the secret must be
--   bound to the specific job the agent is executing — not just the
--   database user. This prevents an agent from fetching a secret for
--   a different job on the same user.
--
-- agent_revealed_at: timestamp of the one-time agent retrieval. Once
--   set, the agent cannot retrieve the same secret again (replay
--   prevention). This is separate from revealed_at, which tracks the
--   admin's one-time reveal via /v1/databases/:id/users/:userId/secret.
--   Both can be set independently — the agent retrieves to apply the
--   password to MariaDB, the admin retrieves to give it to the customer.
ALTER TABLE database_user_secrets ADD COLUMN job_id TEXT;
ALTER TABLE database_user_secrets ADD COLUMN agent_revealed_at TEXT;
CREATE INDEX idx_database_user_secrets_job_id ON database_user_secrets(job_id);
