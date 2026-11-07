PRAGMA foreign_keys = ON;

CREATE TABLE hosting_account_memberships (
  id TEXT PRIMARY KEY NOT NULL,
  hosting_account_id TEXT NOT NULL REFERENCES hosting_accounts(id) ON DELETE CASCADE,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('ACCOUNT_OWNER', 'ACCOUNT_ADMIN', 'ACCOUNT_DEVELOPER', 'ACCOUNT_READONLY')),
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REVOKED')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE (hosting_account_id, user_id),
  FOREIGN KEY (hosting_account_id, organization_id)
    REFERENCES hosting_accounts(id, organization_id) ON DELETE CASCADE
);

CREATE INDEX hosting_account_memberships_user_status_idx
  ON hosting_account_memberships(user_id, status, hosting_account_id);

CREATE INDEX hosting_account_memberships_org_account_idx
  ON hosting_account_memberships(organization_id, hosting_account_id, status);
