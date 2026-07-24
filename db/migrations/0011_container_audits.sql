-- ═════════════════════════════════════════════════════════════════════════════
-- Aegis CTI — Migration 0011: container security audits (Module 6)
-- Stores Dockerfile / image-config / Trivy-report audits and their findings.
-- The Rust aegis-container crate performs the analysis in the worker; the API
-- creates an audit row + enqueues a 'container.audit' job.
-- ═════════════════════════════════════════════════════════════════════════════
SET search_path TO aegis, public;

DO $$ BEGIN
  CREATE TYPE aegis.container_audit_kind AS ENUM ('dockerfile','image_config','trivy');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE aegis.container_finding_category AS ENUM
    ('dockerfile','image_config','vulnerability','secret','compose');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS aegis.container_audits (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL,                            -- image ref or filename
  kind        aegis.container_audit_kind NOT NULL,
  -- Raw input to analyze (Dockerfile text or scanner JSON). Kept so a re-run is
  -- reproducible; capped by the API's body limit.
  input       text NOT NULL DEFAULT '',
  status      text NOT NULL DEFAULT 'queued',           -- queued/running/completed/failed
  score       int,                                      -- 0–100 risk score
  summary     jsonb NOT NULL DEFAULT '{}'::jsonb,       -- RiskSummary counts
  error       text,
  requested_by uuid REFERENCES aegis.users(id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_container_audits_created ON aegis.container_audits(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_container_audits_status  ON aegis.container_audits(status);

CREATE TABLE IF NOT EXISTS aegis.container_findings (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  audit_id    uuid NOT NULL REFERENCES aegis.container_audits(id) ON DELETE CASCADE,
  rule_id     text NOT NULL,                            -- e.g. 'DKR-USER-ROOT' or a CVE id
  category    aegis.container_finding_category NOT NULL,
  severity    aegis.severity NOT NULL,
  title       text NOT NULL,
  remediation text NOT NULL DEFAULT '',
  location    text,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_container_findings_audit ON aegis.container_findings(audit_id);
CREATE INDEX IF NOT EXISTS idx_container_findings_sev   ON aegis.container_findings(severity);

SELECT aegis.attach_updated_at('aegis.container_audits');

-- ── Permissions ───────────────────────────────────────────────────────────────
INSERT INTO aegis.permissions(code, description) VALUES
  ('container:read','View container security audits'),
  ('container:run','Run container security audits')
ON CONFLICT (code) DO NOTHING;

-- admin already gets everything via the CROSS JOIN seed; ensure it covers the
-- new codes (idempotent).
INSERT INTO aegis.role_permissions(role_id, permission_id)
SELECT r.id, p.id FROM aegis.roles r JOIN aegis.permissions p ON true
WHERE r.name = 'admin' AND p.code IN ('container:read','container:run')
ON CONFLICT DO NOTHING;

-- analyst → read + run
INSERT INTO aegis.role_permissions(role_id, permission_id)
SELECT r.id, p.id FROM aegis.roles r JOIN aegis.permissions p ON true
WHERE r.name = 'analyst' AND p.code IN ('container:read','container:run')
ON CONFLICT DO NOTHING;

-- viewer → read only
INSERT INTO aegis.role_permissions(role_id, permission_id)
SELECT r.id, p.id FROM aegis.roles r JOIN aegis.permissions p ON true
WHERE r.name = 'viewer' AND p.code = 'container:read'
ON CONFLICT DO NOTHING;
