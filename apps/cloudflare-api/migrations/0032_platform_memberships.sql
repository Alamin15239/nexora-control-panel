-- Platform-wide privileges are independent of organization memberships.
-- Existing customer OWNER/ADMIN roles are deliberately not promoted.
CREATE TABLE IF NOT EXISTS platform_memberships (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('PLATFORM_OWNER', 'PLATFORM_ADMIN')),
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'SUSPENDED')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_platform_memberships_role_status
  ON platform_memberships(role, status);
