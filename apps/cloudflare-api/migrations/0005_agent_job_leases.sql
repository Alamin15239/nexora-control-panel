ALTER TABLE provisioning_jobs ADD COLUMN lease_expires_at TEXT;
ALTER TABLE provisioning_jobs ADD COLUMN claimed_by_node_id TEXT;

CREATE INDEX provisioning_jobs_server_lease_idx
ON provisioning_jobs(status, lease_expires_at, requested_at);
