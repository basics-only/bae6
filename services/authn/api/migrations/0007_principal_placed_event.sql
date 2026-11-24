ALTER TABLE principal_events DROP CONSTRAINT principal_events_type_check;
ALTER TABLE principal_events ADD CONSTRAINT principal_events_type_check
  CHECK (type IN ('created', 'linked', 'disabled', 'enabled', 'deprovisioned', 'placed'));
