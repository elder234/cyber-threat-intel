-- ═════════════════════════════════════════════════════════════════════════════
-- Aegis CTI — Migration 0004: IOCs, detection rules, enrichment
-- ═════════════════════════════════════════════════════════════════════════════
SET search_path TO aegis, public;

-- ── Indicators of Compromise ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS aegis.iocs (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  type         aegis.ioc_type NOT NULL,
  value        text NOT NULL,                          -- normalized (lowercase, defanged->refanged)
  value_norm   text GENERATED ALWAYS AS (lower(value)) STORED,
  description  text NOT NULL DEFAULT '',
  severity     aegis.severity NOT NULL DEFAULT 'medium',
  confidence   aegis.confidence NOT NULL DEFAULT 'medium',
  tlp          aegis.tlp NOT NULL DEFAULT 'amber',
  score        int NOT NULL DEFAULT 50,                -- 0..100 risk score
  is_active    boolean NOT NULL DEFAULT true,
  tags         text[] NOT NULL DEFAULT '{}',
  actor_ids    uuid[] NOT NULL DEFAULT '{}',
  malware_ids  uuid[] NOT NULL DEFAULT '{}',
  technique_ids text[] NOT NULL DEFAULT '{}',
  source       text NOT NULL DEFAULT 'manual',         -- feed name / 'manual'
  first_seen   timestamptz NOT NULL DEFAULT now(),
  last_seen    timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz,                            -- auto-decay
  enrichment   jsonb NOT NULL DEFAULT '{}'::jsonb,     -- OSINT lookups cache
  created_by   uuid REFERENCES aegis.users(id) ON DELETE SET NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (type, value_norm)
);
CREATE INDEX IF NOT EXISTS idx_iocs_type        ON aegis.iocs(type);
CREATE INDEX IF NOT EXISTS idx_iocs_value_norm  ON aegis.iocs(value_norm);
CREATE INDEX IF NOT EXISTS idx_iocs_value_trgm  ON aegis.iocs USING gin(value_norm gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_iocs_tags        ON aegis.iocs USING gin(tags);
CREATE INDEX IF NOT EXISTS idx_iocs_active_sev  ON aegis.iocs(is_active, severity) WHERE is_active;
CREATE INDEX IF NOT EXISTS idx_iocs_last_seen   ON aegis.iocs(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_iocs_source      ON aegis.iocs(source);

-- Sightings — where/when an IOC was observed
CREATE TABLE IF NOT EXISTS aegis.ioc_sightings (
  id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ioc_id     uuid NOT NULL REFERENCES aegis.iocs(id) ON DELETE CASCADE,
  source     text NOT NULL,
  context    jsonb NOT NULL DEFAULT '{}'::jsonb,
  observed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sightings_ioc ON aegis.ioc_sightings(ioc_id, observed_at DESC);

-- Relationships between IOCs (e.g. domain -> resolves_to -> ip)
CREATE TABLE IF NOT EXISTS aegis.ioc_relations (
  src_id   uuid NOT NULL REFERENCES aegis.iocs(id) ON DELETE CASCADE,
  dst_id   uuid NOT NULL REFERENCES aegis.iocs(id) ON DELETE CASCADE,
  relation text NOT NULL,                              -- 'resolves_to','communicates_with'
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (src_id, dst_id, relation),
  CHECK (src_id <> dst_id)
);

-- ── Detection rules: YARA / Sigma ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS aegis.detection_rules (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  format       text NOT NULL CHECK (format IN ('yara','sigma')),
  name         text NOT NULL,
  rule_id_ext  text,                                   -- author-assigned id (sigma)
  content      text NOT NULL,                          -- raw rule source
  description  text NOT NULL DEFAULT '',
  author       text,
  severity     aegis.severity NOT NULL DEFAULT 'medium',
  status       text NOT NULL DEFAULT 'experimental',   -- stable/test/experimental/deprecated
  tags         text[] NOT NULL DEFAULT '{}',
  technique_ids text[] NOT NULL DEFAULT '{}',
  is_enabled   boolean NOT NULL DEFAULT true,
  is_valid     boolean,                                -- last compile/parse result
  validation_error text,
  created_by   uuid REFERENCES aegis.users(id) ON DELETE SET NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (format, name)
);
CREATE INDEX IF NOT EXISTS idx_rules_format  ON aegis.detection_rules(format);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON aegis.detection_rules(is_enabled) WHERE is_enabled;
CREATE INDEX IF NOT EXISTS idx_rules_tags    ON aegis.detection_rules USING gin(tags);

SELECT aegis.attach_updated_at('aegis.iocs');
SELECT aegis.attach_updated_at('aegis.detection_rules');
