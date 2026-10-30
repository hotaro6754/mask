#!/bin/sh
# Runs once, when the production database volume is first initialised (official postgres image entrypoint).
# Creates the gateway's read-only login. Tables belong to the owner account (POSTGRES_USER), never to the gateway;
# MaskGuard refuses to start in production if its account can write, create objects or owns a table.
set -eu
: "${MASKGUARD_GATEWAY_DB_PASSWORD:?MASKGUARD_GATEWAY_DB_PASSWORD is required}"
psql -v ON_ERROR_STOP=1 -v gw_password="$MASKGUARD_GATEWAY_DB_PASSWORD" \
     --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
CREATE ROLE maskguard_gateway LOGIN PASSWORD :'gw_password'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO maskguard_gateway;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO maskguard_gateway;
-- tables the owner creates later are readable (only readable) by the gateway as well
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO maskguard_gateway;
SQL
