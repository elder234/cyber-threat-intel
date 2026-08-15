SET search_path TO aegis, public;

CREATE TABLE IF NOT EXISTS aegis.pcap_analyses (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), sha256 text NOT NULL UNIQUE,
  size_bytes bigint NOT NULL, format text NOT NULL, packet_count bigint NOT NULL DEFAULT 0,
  duration_ms bigint NOT NULL DEFAULT 0, interface_count int NOT NULL DEFAULT 0,
  top_talkers jsonb NOT NULL DEFAULT '[]', protocol_mix jsonb NOT NULL DEFAULT '{}',
  dns_queries jsonb NOT NULL DEFAULT '[]', tls_snis text[] NOT NULL DEFAULT '{}',
  http_hosts text[] NOT NULL DEFAULT '{}', suspicious jsonb NOT NULL DEFAULT '[]',
  ioc_matches jsonb NOT NULL DEFAULT '[]', score int NOT NULL DEFAULT 0 CHECK (score BETWEEN 0 AND 100),
  summary text NOT NULL DEFAULT '', requested_by uuid REFERENCES aegis.users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS aegis.pcap_findings (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  analysis_id uuid NOT NULL REFERENCES aegis.pcap_analyses(id) ON DELETE CASCADE,
  finding_id text NOT NULL, severity aegis.severity NOT NULL, title text NOT NULL,
  detail text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pcap_created ON aegis.pcap_analyses(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pcap_findings_analysis ON aegis.pcap_findings(analysis_id);
SELECT aegis.attach_updated_at('aegis.pcap_analyses');

INSERT INTO aegis.permissions(code, description) VALUES
 ('pcap:read','View packet capture analysis'), ('pcap:run','Analyze packet captures')
ON CONFLICT (code) DO NOTHING;
INSERT INTO aegis.role_permissions(role_id, permission_id)
SELECT r.id,p.id FROM aegis.roles r JOIN aegis.permissions p ON true
WHERE (r.name IN ('admin','analyst') AND p.code IN ('pcap:read','pcap:run'))
   OR (r.name='viewer' AND p.code='pcap:read') ON CONFLICT DO NOTHING;
