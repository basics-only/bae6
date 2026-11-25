CREATE TABLE tenant_resources (
  organization_id text NOT NULL,
  resource text NOT NULL,
  unit text NOT NULL,
  PRIMARY KEY (organization_id, resource)
);

CREATE TABLE tenant_resource_outbox (
  organization_id text NOT NULL,
  resource text NOT NULL,
  due_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, resource),
  FOREIGN KEY (organization_id, resource)
    REFERENCES tenant_resources (organization_id, resource) ON DELETE CASCADE
);

CREATE INDEX tenant_resource_outbox_due
  ON tenant_resource_outbox (organization_id, due_at, resource);
