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

-- Grant platform ownership only to the explicitly designated Nexora operator.
-- This does not change the user's organization membership role.
INSERT INTO platform_memberships (user_id, role, status)
SELECT id, 'PLATFORM_OWNER', 'ACTIVE'
FROM users
WHERE lower(email) = lower('alaminkhan.xiaomi@gmail.com')
  AND status = 'ACTIVE'
ON CONFLICT(user_id) DO UPDATE SET
  role = 'PLATFORM_OWNER',
  status = 'ACTIVE',
  updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now');
