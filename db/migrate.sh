#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Aegis CTI — apply all migrations in order against $DATABASE_URL
# Usage:
#   DATABASE_URL=postgres://aegis:pass@localhost:5432/aegis ./db/migrate.sh
# Requires: psql on PATH.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

: "${DATABASE_URL:?Set DATABASE_URL, e.g. postgres://aegis:pass@localhost:5432/aegis}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/migrations"

echo "▶ Applying migrations from $DIR"
# Track applied migrations in a table so re-runs are idempotent.
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -q <<'SQL'
CREATE SCHEMA IF NOT EXISTS aegis;
CREATE TABLE IF NOT EXISTS aegis.schema_migrations(
  filename text PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
);
SQL

for f in "$DIR"/*.sql; do
  base="$(basename "$f")"
  already=$(psql "$DATABASE_URL" -tA -c \
    "SELECT 1 FROM aegis.schema_migrations WHERE filename='$base'")
  if [ "$already" = "1" ]; then
    echo "  ↷ skip  $base (already applied)"
    continue
  fi
  echo "  ▸ apply $base"
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -q -f "$f"
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -q -c \
    "INSERT INTO aegis.schema_migrations(filename) VALUES ('$base')"
done

echo "✔ All migrations applied."
