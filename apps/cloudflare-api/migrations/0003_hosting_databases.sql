CREATE TABLE hosting_databases (
  id TEXT PRIMARY KEY NOT NULL,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  hosting_account_id TEXT NOT NULL REFERENCES hosting_accounts(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  engine TEXT NOT NULL DEFAULT 'MYSQL' CHECK (engine IN ('MYSQL', 'MARIADB', 'POSTGRESQL')),
  status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'ACTIVE', 'FAILED', 'DELETING', 'DELETED')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE (hosting_account_id, name)
);
CREATE INDEX hosting_databases_org_idx ON hosting_databases(organization_id, created_at);
CREATE INDEX hosting_databases_account_idx ON hosting_databases(hosting_account_id, status);

CREATE TABLE hosting_database_users (
  id TEXT PRIMARY KEY NOT NULL,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  database_id TEXT NOT NULL REFERENCES hosting_databases(id) ON DELETE CASCADE,
  username TEXT NOT NULL,
  privileges TEXT NOT NULL CHECK (json_valid(privileges)),
  status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'ACTIVE', 'FAILED', 'REVOKED')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE (database_id, username)
);
CREATE INDEX hosting_database_users_org_idx ON hosting_database_users(organization_id, database_id);
