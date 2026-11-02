ALTER TABLE provisioning_jobs ADD COLUMN request_payload TEXT CHECK (request_payload IS NULL OR json_valid(request_payload));
ALTER TABLE provisioning_jobs ADD COLUMN result_payload TEXT CHECK (result_payload IS NULL OR json_valid(result_payload));
