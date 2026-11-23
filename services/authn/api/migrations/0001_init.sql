CREATE TABLE provider_connections (
  tenant_id text NOT NULL CHECK (tenant_id ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
  id text NOT NULL CHECK (id ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
  kind text NOT NULL CHECK (kind IN ('pingfederate', 'entra', 'okta', 'oidc')),
  issuer text NOT NULL CHECK (issuer ~ '^https://' AND length(issuer) <= 512),
  client_id text NOT NULL CHECK (length(client_id) BETWEEN 1 AND 256),
  -- Name of the secret holding the client credential; the credential itself is never stored here.
  client_secret_ref text NOT NULL CHECK (length(client_secret_ref) BETWEEN 1 AND 256),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id)
);

CREATE TABLE principals (
  id text PRIMARY KEY CHECK (id ~ '^prn_[0-9a-f]{32}$'),
  tenant_id text NOT NULL CHECK (tenant_id ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
  type text NOT NULL CHECK (type IN ('user', 'group', 'service', 'application', 'agent')),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'deprovisioned')),
  owner_application_id text CHECK (owner_application_id ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (type <> 'agent' OR owner_application_id IS NOT NULL),
  UNIQUE (tenant_id, id)
);

CREATE TABLE external_identities (
  id text PRIMARY KEY CHECK (id ~ '^xid_[0-9a-f]{32}$'),
  tenant_id text NOT NULL,
  principal_id text NOT NULL,
  provider_connection_id text NOT NULL,
  -- Not tied to the connection's issuer: multitenant issuers such as Entra embed the provider tenant.
  issuer text NOT NULL CHECK (issuer ~ '^https://' AND length(issuer) <= 512),
  subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 256),
  external_tenant_id text CHECK (length(external_tenant_id) BETWEEN 1 AND 128),
  external_object_id text CHECK (length(external_object_id) BETWEEN 1 AND 256),
  last_verified_at timestamptz NOT NULL,
  FOREIGN KEY (tenant_id, principal_id) REFERENCES principals (tenant_id, id),
  FOREIGN KEY (tenant_id, provider_connection_id) REFERENCES provider_connections (tenant_id, id),
  UNIQUE NULLS NOT DISTINCT (tenant_id, provider_connection_id, issuer, subject, external_tenant_id)
);
CREATE INDEX external_identities_principal ON external_identities (tenant_id, principal_id);

CREATE TABLE sessions (
  id text PRIMARY KEY CHECK (id ~ '^ses_[0-9a-f]{32}$'),
  tenant_id text NOT NULL,
  principal_id text NOT NULL,
  -- SHA-256 of the cookie secret and the CSRF token; neither is stored in the clear.
  secret_hash bytea NOT NULL CHECK (length(secret_hash) = 32),
  csrf_hash bytea NOT NULL CHECK (length(csrf_hash) = 32),
  provider_connection_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '24 hours'),
  FOREIGN KEY (tenant_id, principal_id) REFERENCES principals (tenant_id, id),
  FOREIGN KEY (tenant_id, provider_connection_id) REFERENCES provider_connections (tenant_id, id)
);
CREATE INDEX sessions_principal ON sessions (tenant_id, principal_id) WHERE revoked_at IS NULL;
CREATE INDEX sessions_expires ON sessions (expires_at);

-- The 24-hour cap is only meaningful if writers cannot choose created_at.
CREATE FUNCTION sessions_pin_created_at() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.created_at := CASE WHEN TG_OP = 'INSERT' THEN now() ELSE OLD.created_at END;
  RETURN NEW;
END $$;
CREATE TRIGGER sessions_pin_created_at BEFORE INSERT OR UPDATE ON sessions
  FOR EACH ROW EXECUTE FUNCTION sessions_pin_created_at();

-- Public halves only. Private keys live in the signer (KMS or a mounted secret).
CREATE TABLE signing_keys (
  kid text PRIMARY KEY CHECK (kid ~ '^[A-Za-z0-9_-]{1,64}$'),
  alg text NOT NULL CHECK (alg IN ('ES256', 'EdDSA')),
  public_jwk jsonb NOT NULL CHECK (
    jsonb_typeof(public_jwk) = 'object' AND NOT public_jwk ? 'd'
    AND public_jwk->>'kid' = kid AND public_jwk->>'alg' = alg
  ),
  status text NOT NULL CHECK (status IN ('next', 'active', 'retired')),
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz,
  CHECK ((status = 'retired') = (retired_at IS NOT NULL))
);
CREATE UNIQUE INDEX signing_keys_one_active ON signing_keys (status) WHERE status = 'active';
