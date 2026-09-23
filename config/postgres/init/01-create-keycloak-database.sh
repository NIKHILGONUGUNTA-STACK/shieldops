#!/bin/sh
set -eu

# Executed only during first PostgreSQL volume initialization by the official image.
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=keycloak_db="$POSTGRES_KEYCLOAK_DB" <<'SQL'
SELECT format('CREATE DATABASE %I', :'keycloak_db')
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = :'keycloak_db')\gexec
SQL
