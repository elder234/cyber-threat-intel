-- ═════════════════════════════════════════════════════════════════════════════
-- Aegis CTI — Migration 0005: assets, scans, findings
-- ═════════════════════════════════════════════════════════════════════════════
SET search_path TO aegis, public;

-- ── Assets under management (scan targets) ───────────────────────────────────
CREATE TABLE IF NOT EXISTS aegis.assets (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind        text NOT NULL CHECK (kind IN ('host','domain','cidr','url','asn')),
  value       text NOT NULL,
  label       text,
  tags        text[] NOT NULL DEFAULT '{}',
  owner_id    uuid REFERENCES aegis.users(id) ON DELETE SET NULL,
  is_authorized boolean NOT NULL DEFAULT false,       -- MUST be true to scan
  criticality aegis.severity NOT NULL DEFAULT 'medium',
  metadata    jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (kind, value)
);
CREATE INDEX IF NOT EXISTS idx_assets_tags ON aegis.assets USING gin(tags);

-- ── Scans ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS aegis.scans (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id     uuid REFERENCES aegis.assets(id) ON DELETE SET NULL,
  target       text NOT NULL,                          -- resolved target string
  scan_type    text NOT NULL,                          -- 'port','tls','http','subdomain','full'
  profile      jsonb NOT NULL DEFAULT '{}'::jsonb,     -- ports, timeouts, options
  status       aegis.scan_status NOT NULL DEFAULT 'queued',
  progress     int NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
  requested_by uuid REFERENCES aegis.users(id) ON DELETE SET NULL,
  scheduled_id uuid,                                   -- FK added in 0006
  error        text,
  started_at   timestamptz,
  finished_at  timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_scans_status  ON aegis.scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_asset   ON aegis.scans(asset_id);
CREATE INDEX IF NOT EXISTS idx_scans_created ON aegis.scans(created_at DESC);

-- Open ports / services discovered
CREATE TABLE IF NOT EXISTS aegis.scan_ports (
  id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  scan_id    uuid NOT NULL REFERENCES aegis.scans(id) ON DELETE CASCADE,
  ip         inet NOT NULL,
  port       int NOT NULL CHECK (port BETWEEN 1 AND 65535),
  protocol   text NOT NULL DEFAULT 'tcp',
  state      text NOT NULL DEFAULT 'open',
  service    text,
  product    text,
  version    text,
  banner     text,
  cpe        text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_scan_ports_scan ON aegis.scan_ports(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_ports_ipport ON aegis.scan_ports(ip, port);

-- TLS / certificate inspection results
CREATE TABLE IF NOT EXISTS aegis.scan_tls (
  id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  scan_id       uuid NOT NULL REFERENCES aegis.scans(id) ON DELETE CASCADE,
  host          text NOT NULL,
  port          int NOT NULL DEFAULT 443,
  tls_versions  text[] NOT NULL DEFAULT '{}',
  cipher_suites text[] NOT NULL DEFAULT '{}',
  cert_subject  text,
  cert_issuer   text,
  cert_serial   text,
  san           text[] NOT NULL DEFAULT '{}',
  not_before    timestamptz,
  not_after     timestamptz,
  is_expired    boolean,
  is_self_signed boolean,
  sha256_fp     text,
  weak_findings text[] NOT NULL DEFAULT '{}',
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_scan_tls_scan ON aegis.scan_tls(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_tls_expiry ON aegis.scan_tls(not_after);

-- Generic findings (CVE matches, missing headers, misconfigs)
CREATE TABLE IF NOT EXISTS aegis.findings (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id     uuid REFERENCES aegis.scans(id) ON DELETE CASCADE,
  asset_id    uuid REFERENCES aegis.assets(id) ON DELETE SET NULL,
  category    text NOT NULL,                           -- 'cve','http_header','tls','misconfig'
  title       text NOT NULL,
  description text NOT NULL DEFAULT '',
  severity    aegis.severity NOT NULL DEFAULT 'medium',
  cve_id      text REFERENCES aegis.cves(cve_id) ON DELETE SET NULL,
  evidence    jsonb NOT NULL DEFAULT '{}'::jsonb,
  remediation text,
  status      text NOT NULL DEFAULT 'open',            -- open/accepted/false_positive/fixed
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_findings_scan     ON aegis.findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON aegis.findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_cve      ON aegis.findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_findings_status   ON aegis.findings(status);

SELECT aegis.attach_updated_at('aegis.assets');
SELECT aegis.attach_updated_at('aegis.scans');
SELECT aegis.attach_updated_at('aegis.findings');
