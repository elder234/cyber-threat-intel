-- ═════════════════════════════════════════════════════════════════════════════
-- Aegis CTI — Migration 0003: threat intelligence core
--   CVEs, CISA KEV, EPSS, MITRE ATT&CK, threat actors, malware families
-- ═════════════════════════════════════════════════════════════════════════════
SET search_path TO aegis, public;

-- ── CVE / vulnerability catalog (NVD) ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS aegis.cves (
  cve_id            text PRIMARY KEY,                 -- 'CVE-2024-3094'
  description        text NOT NULL DEFAULT '',
  published_at      timestamptz,
  last_modified_at  timestamptz,
  -- CVSS (store both v3.1 and v4.0 where present)
  cvss_v31_score    numeric(3,1),
  cvss_v31_vector   text,
  cvss_v31_severity aegis.severity,
  cvss_v40_score    numeric(3,1),
  cvss_v40_vector   text,
  -- EPSS (exploit prediction) — updated daily
  epss_score        numeric(6,5),                     -- 0.00000 .. 1.00000
  epss_percentile   numeric(6,5),
  epss_updated_at   timestamptz,
  -- CISA Known Exploited Vulnerabilities
  kev               boolean NOT NULL DEFAULT false,
  kev_added_at      date,
  kev_due_date      date,
  kev_ransomware    boolean NOT NULL DEFAULT false,
  -- Affected products as CPE match strings + references
  cpes              text[] NOT NULL DEFAULT '{}',
  cwe_ids           text[] NOT NULL DEFAULT '{}',
  references         jsonb NOT NULL DEFAULT '[]'::jsonb,
  source            text NOT NULL DEFAULT 'nvd',
  raw               jsonb,                             -- original record for re-parse
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_cves_published   ON aegis.cves(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_cves_kev         ON aegis.cves(kev) WHERE kev;
CREATE INDEX IF NOT EXISTS idx_cves_cvss31      ON aegis.cves(cvss_v31_score DESC);
CREATE INDEX IF NOT EXISTS idx_cves_epss        ON aegis.cves(epss_score DESC);
CREATE INDEX IF NOT EXISTS idx_cves_cpes_gin    ON aegis.cves USING gin(cpes);
CREATE INDEX IF NOT EXISTS idx_cves_desc_trgm   ON aegis.cves USING gin(description gin_trgm_ops);

-- ── MITRE ATT&CK ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS aegis.mitre_tactics (
  id          text PRIMARY KEY,                        -- 'TA0001'
  name        text NOT NULL,                           -- 'Initial Access'
  shortname   text NOT NULL,                           -- 'initial-access'
  description text NOT NULL DEFAULT '',
  url         text,
  sort_order  int NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS aegis.mitre_techniques (
  id             text PRIMARY KEY,                     -- 'T1566' / 'T1566.001'
  name           text NOT NULL,
  description    text NOT NULL DEFAULT '',
  is_subtechnique boolean NOT NULL DEFAULT false,
  parent_id      text REFERENCES aegis.mitre_techniques(id) ON DELETE CASCADE,
  tactic_ids     text[] NOT NULL DEFAULT '{}',         -- may map to several tactics
  platforms      text[] NOT NULL DEFAULT '{}',
  detection      text,
  url            text,
  deprecated     boolean NOT NULL DEFAULT false,
  raw            jsonb,
  updated_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_mitre_tech_parent  ON aegis.mitre_techniques(parent_id);
CREATE INDEX IF NOT EXISTS idx_mitre_tech_tactics ON aegis.mitre_techniques USING gin(tactic_ids);
CREATE INDEX IF NOT EXISTS idx_mitre_tech_name_trgm ON aegis.mitre_techniques USING gin(name gin_trgm_ops);

-- ── Threat actors (intrusion sets) ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS aegis.threat_actors (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name         text NOT NULL UNIQUE,                   -- 'APT29'
  aliases      text[] NOT NULL DEFAULT '{}',           -- 'Cozy Bear','Nobelium'
  description  text NOT NULL DEFAULT '',
  country      text,                                   -- suspected origin (ISO code)
  motivation   text[] NOT NULL DEFAULT '{}',           -- 'espionage','financial'
  technique_ids text[] NOT NULL DEFAULT '{}',          -- MITRE techniques used
  first_seen   date,
  last_seen    date,
  external_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_actors_aliases ON aegis.threat_actors USING gin(aliases);
CREATE INDEX IF NOT EXISTS idx_actors_name_trgm ON aegis.threat_actors USING gin(name gin_trgm_ops);

-- ── Malware families ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS aegis.malware_families (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name         text NOT NULL UNIQUE,                   -- 'Emotet'
  aliases      text[] NOT NULL DEFAULT '{}',
  category     text,                                   -- 'trojan','ransomware', ...
  description  text NOT NULL DEFAULT '',
  platforms    text[] NOT NULL DEFAULT '{}',
  actor_ids    uuid[] NOT NULL DEFAULT '{}',
  technique_ids text[] NOT NULL DEFAULT '{}',
  external_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_malware_aliases ON aegis.malware_families USING gin(aliases);

-- ── Triggers ─────────────────────────────────────────────────────────────────
SELECT aegis.attach_updated_at('aegis.cves');
SELECT aegis.attach_updated_at('aegis.threat_actors');
SELECT aegis.attach_updated_at('aegis.malware_families');
