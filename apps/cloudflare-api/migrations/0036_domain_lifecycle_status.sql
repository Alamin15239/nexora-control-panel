-- Domain lifecycle status.
ALTER TABLE domains ADD COLUMN status TEXT NOT NULL DEFAULT 'ACTIVE'
  CHECK (status IN ('ACTIVE', 'PENDING', 'DELETED'));
CREATE INDEX domains_account_status_idx ON domains(hosting_account_id, status);
