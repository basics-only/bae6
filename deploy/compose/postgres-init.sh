#!/bin/sh
set -eu
POSTGRES_USER=${POSTGRES_USER:-postgres}

for entry in \
  "openfga:$OPENFGA_DB_PASSWORD" \
  "authn:$AUTHN_DB_PASSWORD" \
  "authz:$AUTHZ_DB_PASSWORD" \
  "ai:$AI_DB_PASSWORD" \
  "embed:$EMBED_DB_PASSWORD" \
  "mcp:$MCP_DB_PASSWORD" \
  "agents:$AGENT_DB_PASSWORD" \
  "evals:$EVAL_DB_PASSWORD"; do
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" \
    -v name="${entry%%:*}" -v pw="${entry#*:}" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN', :'name')
 WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'name') \gexec
SELECT format('ALTER ROLE %I PASSWORD %L', :'name', :'pw') \gexec
SELECT format('CREATE DATABASE %I OWNER %I', :'name', :'name')
 WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = :'name') \gexec
SELECT format('REVOKE CONNECT ON DATABASE %I FROM PUBLIC', :'name') \gexec
SQL
done

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" -d embed -c 'CREATE EXTENSION IF NOT EXISTS vector'
