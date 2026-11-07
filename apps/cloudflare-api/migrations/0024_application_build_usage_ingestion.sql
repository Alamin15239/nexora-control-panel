-- Builder-reported build outcomes are immutable. Only the aggregate marker may transition once.
ALTER TABLE application_usage_events
  ADD COLUMN build_result TEXT NOT NULL DEFAULT 'succeeded'
  CHECK (build_result IN ('succeeded', 'failed', 'cancelled'));

ALTER TABLE application_usage_events
  ADD COLUMN aggregated_at TEXT;

DROP TRIGGER IF EXISTS application_usage_event_immutable_update;

CREATE TRIGGER application_usage_event_immutable_update
BEFORE UPDATE ON application_usage_events
WHEN OLD.aggregated_at IS NOT NULL
  OR NEW.aggregated_at IS NULL
  OR NEW.id != OLD.id
  OR NEW.organization_id != OLD.organization_id
  OR NEW.project_id != OLD.project_id
  OR NEW.deployment_id != OLD.deployment_id
  OR NEW.period_start != OLD.period_start
  OR NEW.build_seconds != OLD.build_seconds
  OR NEW.source != OLD.source
  OR NEW.build_result != OLD.build_result
  OR NEW.recorded_at != OLD.recorded_at
BEGIN
  SELECT RAISE(ABORT, 'application usage events are immutable');
END;

CREATE INDEX application_usage_events_pending_idx
  ON application_usage_events(organization_id, project_id, period_start, aggregated_at);
