ALTER TABLE provider_connections
  ADD COLUMN jit_provisioning boolean NOT NULL DEFAULT false,
  ADD COLUMN group_claim text CHECK (group_claim ~ '^[A-Za-z_][A-Za-z0-9_.:/-]{0,255}$');

ALTER TABLE principals ADD CONSTRAINT principals_tenant_id_type UNIQUE (tenant_id, id, type);

CREATE TABLE group_mappings (
  tenant_id text NOT NULL,
  provider_connection_id text NOT NULL,
  external_group text NOT NULL CHECK (length(external_group) BETWEEN 1 AND 256),
  group_principal_id text NOT NULL,
  group_type text NOT NULL DEFAULT 'group' CHECK (group_type = 'group'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, provider_connection_id, external_group),
  FOREIGN KEY (tenant_id, provider_connection_id) REFERENCES provider_connections (tenant_id, id),
  FOREIGN KEY (tenant_id, group_principal_id, group_type) REFERENCES principals (tenant_id, id, type)
);
CREATE INDEX group_mappings_group ON group_mappings (tenant_id, group_principal_id);

-- Readers page by (xact_id, id) below pg_snapshot_xmin(pg_current_snapshot()) so late commits are never skipped.
CREATE TABLE principal_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  xact_id xid8 NOT NULL DEFAULT pg_current_xact_id(),
  tenant_id text NOT NULL,
  principal_id text NOT NULL,
  type text NOT NULL CHECK (type IN ('created', 'linked', 'disabled', 'enabled', 'deprovisioned')),
  actor text NOT NULL CHECK (length(actor) BETWEEN 1 AND 128),
  detail jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(detail) = 'object' AND pg_column_size(detail) <= 4096),
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, principal_id) REFERENCES principals (tenant_id, id)
);
CREATE INDEX principal_events_outbox ON principal_events (xact_id, id);
CREATE INDEX principal_events_principal ON principal_events (tenant_id, principal_id, id);

CREATE FUNCTION principal_events_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'principal_events is append-only';
END $$;
CREATE TRIGGER principal_events_append_only BEFORE UPDATE OR DELETE ON principal_events
  FOR EACH ROW EXECUTE FUNCTION principal_events_append_only();
