-- Store the checksum that R2 verified against the streamed artifact body.
ALTER TABLE github_deployments ADD COLUMN artifact_sha256 TEXT;
