PRAGMA foreign_keys = ON;

CREATE TABLE password_reset_tokens (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX password_reset_tokens_user_created_idx
  ON password_reset_tokens(user_id, created_at DESC);

CREATE INDEX password_reset_tokens_expiry_idx
  ON password_reset_tokens(expires_at, used_at);
