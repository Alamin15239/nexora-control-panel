ALTER TABLE github_connections ADD COLUMN encrypted_refresh_token TEXT;
ALTER TABLE github_connections ADD COLUMN refresh_token_iv TEXT;
ALTER TABLE github_connections ADD COLUMN token_expires_at TEXT;
ALTER TABLE github_connections ADD COLUMN refresh_token_expires_at TEXT;
