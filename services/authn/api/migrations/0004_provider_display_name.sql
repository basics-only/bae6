ALTER TABLE provider_connections
  ADD COLUMN display_name text
  CONSTRAINT provider_connections_display_name_check CHECK (
    length(display_name) BETWEEN 1 AND 128
    AND btrim(display_name) <> ''
    AND display_name !~ '[\u0001-\u001f\u007f-\u009f­؜᠎​-‏ -‮⁠-⁩﻿]'
  );
