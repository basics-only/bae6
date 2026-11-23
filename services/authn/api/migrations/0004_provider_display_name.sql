ALTER TABLE provider_connections
  ADD COLUMN display_name text CHECK (length(display_name) BETWEEN 1 AND 128 AND display_name !~ '[[:cntrl:]]');
