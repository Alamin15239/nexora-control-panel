-- Rate-limit manual test emails per workspace.
ALTER TABLE incident_notification_settings
ADD COLUMN last_test_at TEXT;
