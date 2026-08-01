-- ═════════════════════════════════════════════════════════════════════════════
-- Aegis CTI — Migration 0014: web inspection (deep DAST) support
-- ═════════════════════════════════════════════════════════════════════════════
-- Feature F-DAST. Adds the 'web' scan type and a probe-policy table, and seeds
-- the web:scan permission. Web inspection output reuses aegis.findings — no
-- parallel findings table — with these category conventions:
--
--   category            evidence jsonb shape (all under findings.evidence)
--   ──────────────────  ────────────────────────────────────────────────────────
--   fingerprint         { server, framework, cms, technologies[], confidence }
--   version_cve         { product, version, cpe, source } + findings.cve_id set
--   http_header         { header, issue }                (from http_headers::analyze)
--   cookie              { name, flags_missing[] }
--   xss                 { method, url, param, marker, reflected, confidence }
--   sqli                { method, url, param, marker, db_error_signature, confidence }
--   path_traversal      { method, url, param, payload, marker, confidence }
--   open_redirect       { method, url, param, redirect_to, confidence }
--
-- scan_type is free text on aegis.scans (0005_assets_scans.sql:28) — 'web' needs
-- no enum change, only this documented convention.
-- ═════════════════════════════════════════════════════════════════════════════
SET search_path TO aegis, public;

-- ── Probe policy ─────────────────────────────────────────────────────────────
-- Records which active-DAST probe classes a scan is permitted to send. A scan
-- references a policy so its findings are auditable against what it was allowed
-- to do. `active_enabled=false` restricts a scan to the passive fingerprint +
-- version→CVE pass (no attack traffic). Active probes ALSO require the target
-- asset to have is_authorized=true — enforced in the scanner, not here.
CREATE TABLE IF NOT EXISTS aegis.web_probe_policies (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name           text NOT NULL UNIQUE,
  description    text NOT NULL DEFAULT '',
  active_enabled boolean NOT NULL DEFAULT false,   -- false = passive-only
  -- Which benign, non-destructive probe classes are allowed.
  probe_classes  text[] NOT NULL DEFAULT '{}',     -- subset of xss,sqli,path_traversal,open_redirect
  max_payloads_per_param int NOT NULL DEFAULT 4 CHECK (max_payloads_per_param BETWEEN 1 AND 64),
  catalog_version text NOT NULL DEFAULT 'v1',      -- payload catalog the scanner used
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);

SELECT aegis.attach_updated_at('aegis.web_probe_policies');

-- Two built-in policies: a safe default (passive only) and a full active profile.
INSERT INTO aegis.web_probe_policies(name, description, active_enabled, probe_classes, catalog_version)
VALUES
  ('passive-only',
   'Fingerprint + header/cookie analysis + version→CVE correlation. No attack traffic.',
   false, '{}', 'v1'),
  ('active-standard',
   'Passive pass plus benign, non-destructive DAST markers. Requires an authorized asset.',
   true, ARRAY['xss','sqli','path_traversal','open_redirect'], 'v1')
ON CONFLICT (name) DO NOTHING;

-- Helpful partial index: findings produced by web scans, by category.
CREATE INDEX IF NOT EXISTS idx_findings_category ON aegis.findings(category);

-- ── Permission ───────────────────────────────────────────────────────────────
-- Separate web DAST from port scanning so an operator can grant one without the
-- other. web:scan is required to launch a 'web' scan (in addition to the target
-- asset being authorized for active probes).
INSERT INTO aegis.permissions(code, description) VALUES
  ('web:scan','Launch web application (DAST) inspection scans')
ON CONFLICT (code) DO NOTHING;

INSERT INTO aegis.role_permissions(role_id, permission_id)
SELECT r.id, p.id FROM aegis.roles r JOIN aegis.permissions p ON true
WHERE r.name = 'admin' AND p.code = 'web:scan'
ON CONFLICT DO NOTHING;

INSERT INTO aegis.role_permissions(role_id, permission_id)
SELECT r.id, p.id FROM aegis.roles r JOIN aegis.permissions p ON true
WHERE r.name = 'analyst' AND p.code = 'web:scan'
ON CONFLICT DO NOTHING;

-- viewer intentionally does not get web:scan (it launches active traffic).
