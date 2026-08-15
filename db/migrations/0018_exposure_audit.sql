SET search_path TO aegis, public;
CREATE TABLE IF NOT EXISTS aegis.exposure_audits (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), asset_id uuid NOT NULL REFERENCES aegis.assets(id) ON DELETE CASCADE,
  scan_id uuid REFERENCES aegis.scans(id) ON DELETE SET NULL, proxy_http boolean NOT NULL DEFAULT false,
  proxy_socks boolean NOT NULL DEFAULT false, smtp_open_relay boolean NOT NULL DEFAULT false,
  dns_open_resolver boolean NOT NULL DEFAULT false, weak_auth_services jsonb NOT NULL DEFAULT '[]',
  ioc_overlap jsonb NOT NULL DEFAULT '[]', beacon_flows jsonb NOT NULL DEFAULT '[]',
  score int NOT NULL DEFAULT 0 CHECK (score BETWEEN 0 AND 100), status text NOT NULL DEFAULT 'queued',
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_exposure_asset ON aegis.exposure_audits(asset_id, created_at DESC);
SELECT aegis.attach_updated_at('aegis.exposure_audits');
INSERT INTO aegis.permissions(code, description) VALUES
 ('exposure:read','View defensive exposure audits'), ('exposure:run','Run defensive exposure audits')
ON CONFLICT (code) DO NOTHING;
INSERT INTO aegis.role_permissions(role_id, permission_id)
SELECT r.id,p.id FROM aegis.roles r JOIN aegis.permissions p ON true
WHERE (r.name IN ('admin','analyst') AND p.code IN ('exposure:read','exposure:run'))
   OR (r.name='viewer' AND p.code='exposure:read') ON CONFLICT DO NOTHING;
