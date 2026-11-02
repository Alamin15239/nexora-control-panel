ALTER TABLE auth_sessions
  ADD COLUMN organization_id TEXT REFERENCES organizations(id) ON DELETE CASCADE;

CREATE INDEX auth_sessions_org_state_idx
  ON auth_sessions(organization_id, revoked_at, expires_at);
