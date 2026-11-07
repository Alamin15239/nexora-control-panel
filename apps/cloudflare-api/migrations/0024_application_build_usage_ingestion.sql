-- Builder-reported build outcomes are immutable. Only the aggregate marker may transition once.
ALTER TABLE application_usage_events
  ADD COLUMN build_result TEXT NOT NULL DEFAULT 'succeeded'
  CHECK (build_result IN ('succeeded', 'failed', 'cancelled'));

ALTER TABLE application_usage_events
  ADD COLUMN aggregated_at TEXT;

DROP TRIGGER IF EXISTS application_usage_event_immutable_update;

CREATE TRIGGER application_usage_event_immutable_update
BEFORE UPDATE OF id, organization_id, project_id, deployment_id, period_start,
                 build_seconds, source, build_result, recorded_at
ON application_usage_events
BEGIN
  SELECT RAISE(ABORT, 'application usage events are immutable');
END;

CREATE TRIGGER application_usage_event_aggregate_marker_once
BEFORE UPDATE OF aggregated_at ON application_usage_events
WHEN OLD.aggregated_at IS NOT NULL OR NEW.aggregated_at IS NULL
BEGIN
  SELECT RAISE(ABORT, 'application usage event aggregate marker is immutable');
END;

CREATE INDEX application_usage_events_pending_idx
  ON application_usage_events(organization_id, project_id, period_start, aggregated_at);
