-- Runtime limits inherited from the hosting plan assigned to each project account.
-- These are admission ceilings; they do not themselves allocate host resources.
ALTER TABLE hosting_plans
  ADD COLUMN app_cpu_millis INTEGER NOT NULL DEFAULT 500
  CHECK (app_cpu_millis BETWEEN 100 AND 8000);

ALTER TABLE hosting_plans
  ADD COLUMN app_memory_mib INTEGER NOT NULL DEFAULT 512
  CHECK (app_memory_mib BETWEEN 128 AND 16384);

ALTER TABLE hosting_plans
  ADD COLUMN app_disk_mib INTEGER NOT NULL DEFAULT 2048
  CHECK (app_disk_mib BETWEEN 128 AND 65536);

ALTER TABLE hosting_plans
  ADD COLUMN app_process_limit INTEGER NOT NULL DEFAULT 128
  CHECK (app_process_limit BETWEEN 16 AND 512);
