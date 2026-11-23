ALTER TABLE principals ADD COLUMN org_path text[];

CREATE FUNCTION principals_default_org_path() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.org_path := COALESCE(NEW.org_path, ARRAY[NEW.tenant_id]);
  RETURN NEW;
END $$;
CREATE TRIGGER principals_default_org_path BEFORE INSERT ON principals
  FOR EACH ROW EXECUTE FUNCTION principals_default_org_path();

UPDATE principals SET org_path = ARRAY[tenant_id];
ALTER TABLE principals
  ALTER COLUMN org_path SET NOT NULL,
  ADD CONSTRAINT principals_org_path CHECK (
    array_ndims(org_path) = 1 AND array_position(org_path, NULL) IS NULL
    AND cardinality(org_path) BETWEEN 1 AND 32 AND org_path[1] = tenant_id
    AND array_to_string(org_path, ',') ~ '^[a-z0-9][a-z0-9-]{0,62}(,[a-z0-9][a-z0-9-]{0,62})*$'
    AND cardinality(string_to_array(array_to_string(org_path, ','), ',')) = cardinality(org_path)
  );

CREATE UNIQUE INDEX signing_keys_one_next ON signing_keys (status) WHERE status = 'next';
