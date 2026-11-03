ALTER TABLE domains ADD COLUMN cloudflare_custom_hostname_id TEXT;
ALTER TABLE domains ADD COLUMN cloudflare_hostname_status TEXT;
ALTER TABLE domains ADD COLUMN cloudflare_ssl_status TEXT;
ALTER TABLE domains ADD COLUMN cloudflare_validation_records TEXT
  CHECK (cloudflare_validation_records IS NULL OR json_valid(cloudflare_validation_records));
ALTER TABLE domains ADD COLUMN cloudflare_cname_target TEXT;
ALTER TABLE domains ADD COLUMN cloudflare_last_checked_at TEXT;
ALTER TABLE domains ADD COLUMN cloudflare_error TEXT;

CREATE UNIQUE INDEX domains_cloudflare_hostname_id_idx
  ON domains(cloudflare_custom_hostname_id)
  WHERE cloudflare_custom_hostname_id IS NOT NULL;
