-- PHP settings, organization updates, backup schedules.
--
-- hosting_account_php_settings stores per-account PHP version and
-- resource limits. The agent reads these when generating the PHP-FPM
-- pool configuration. Changing a setting queues an UPDATE_PHP_POOL
-- provisioning job so the agent rewrites the pool and reloads PHP-FPM.
CREATE TABLE hosting_account_php_settings (
  hosting_account_id TEXT PRIMARY KEY NOT NULL REFERENCES hosting_accounts(id) ON DELETE CASCADE,
  php_version TEXT NOT NULL DEFAULT '8.3',
  memory_limit_mib INTEGER NOT NULL DEFAULT 256,
  max_execution_time_seconds INTEGER NOT NULL DEFAULT 30,
  upload_max_filesize_mib INTEGER NOT NULL DEFAULT 64,
  max_input_vars INTEGER NOT NULL DEFAULT 1000,
  display_errors INTEGER NOT NULL DEFAULT 0 CHECK (display_errors IN (0, 1)),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- backup_schedules stores per-account backup automation. The agent
-- reads the schedule and creates backups at the specified interval.
CREATE TABLE backup_schedules (
  hosting_account_id TEXT PRIMARY KEY NOT NULL REFERENCES hosting_accounts(id) ON DELETE CASCADE,
  frequency TEXT NOT NULL DEFAULT 'weekly' CHECK (frequency IN ('daily', 'weekly', 'monthly', 'disabled')),
  retention_count INTEGER NOT NULL DEFAULT 4 CHECK (retention_count BETWEEN 1 AND 52),
  next_run_at TEXT,
  last_run_at TEXT,
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
