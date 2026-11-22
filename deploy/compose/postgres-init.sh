#!/bin/sh
set -eu

for entry in \
  "openfga:$OPENFGA_DB_PASSWORD" \
  "authz:$AUTHZ_DB_PASSWORD" \
  "ai:$AI_DB_PASSWORD" \
  "embed:$EMBED_DB_PASSWORD" \
  "mcp:$MCP_DB_PASSWORD"; do
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" \
    -v name="${entry%%:*}" -v pw="${entry#*:}" <<'SQL'
CREATE ROLE :"name" LOGIN PASSWORD :'pw';
CREATE DATABASE :"name" OWNER :"name";
REVOKE CONNECT ON DATABASE :"name" FROM PUBLIC;
SQL
done

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" -d embed -c 'CREATE EXTENSION vector'
