ALTER TABLE signing_keys
  DROP CONSTRAINT signing_keys_status_check,
  ADD CONSTRAINT signing_keys_status_check CHECK (status IN ('next', 'active', 'retired', 'revoked'));
