-- ═════════════════════════════════════════════════════════════════════════════
-- Aegis CTI — Migration 0001: extensions, enums, core helpers
-- Idempotent: safe to re-run. Requires PostgreSQL 15+.
-- ═════════════════════════════════════════════════════════════════════════════

-- ── Extensions ───────────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "pgcrypto";     -- gen_random_uuid(), digest()
CREATE EXTENSION IF NOT EXISTS "pg_trgm";      -- trigram indexes for fuzzy search
CREATE EXTENSION IF NOT EXISTS "citext";       -- case-insensitive text (emails)
CREATE EXTENSION IF NOT EXISTS "btree_gin";    -- GIN over scalar + jsonb combos

-- ── Dedicated schema ─────────────────────────────────────────────────────────
CREATE SCHEMA IF NOT EXISTS aegis;
SET search_path TO aegis, public;

-- ── Enum types ───────────────────────────────────────────────────────────────
DO $$ BEGIN
  CREATE TYPE aegis.ioc_type AS ENUM (
    'ipv4','ipv6','domain','url','md5','sha1','sha256','sha512',
    'email','cidr','asn','file_path','registry_key','mutex','user_agent','ja3'
  );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE aegis.tlp AS ENUM ('clear','green','amber','amber_strict','red');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE aegis.severity AS ENUM ('info','low','medium','high','critical');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE aegis.confidence AS ENUM ('low','medium','high','confirmed');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE aegis.scan_status AS ENUM ('queued','running','completed','failed','cancelled');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE aegis.alert_status AS ENUM ('open','acknowledged','resolved','suppressed');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE aegis.job_status AS ENUM ('pending','claimed','running','succeeded','failed','dead');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ── Generic updated_at trigger function ──────────────────────────────────────
CREATE OR REPLACE FUNCTION aegis.set_updated_at()
RETURNS trigger AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Helper to attach the trigger to any table with an updated_at column.
-- Trigger names are scoped per-table in PostgreSQL, so a fixed name is safe
-- and avoids fragile parsing of the (search_path-dependent) relation name.
CREATE OR REPLACE FUNCTION aegis.attach_updated_at(tbl regclass)
RETURNS void AS $$
BEGIN
  EXECUTE format(
    'DROP TRIGGER IF EXISTS trg_set_updated_at ON %s;
     CREATE TRIGGER trg_set_updated_at BEFORE UPDATE ON %s
       FOR EACH ROW EXECUTE FUNCTION aegis.set_updated_at();',
    tbl, tbl);
END;
$$ LANGUAGE plpgsql;
