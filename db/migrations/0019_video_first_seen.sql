SET search_path TO aegis, public;
CREATE TABLE IF NOT EXISTS aegis.video_fingerprints (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), sha256 text NOT NULL UNIQUE, md5 text NOT NULL,
  size_bytes bigint NOT NULL, duration_ms bigint, width int, height int, fps double precision,
  codec text, encoder text, creation_time timestamptz, gps text, file_type text,
  perceptual_frame_hashes text[] NOT NULL DEFAULT '{}', status text NOT NULL DEFAULT 'completed',
  summary text NOT NULL DEFAULT '', requested_by uuid REFERENCES aegis.users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS aegis.video_sources (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL UNIQUE,
  kind text NOT NULL CHECK (kind IN ('telegram','x','facebook','snapchat','manual')),
  config jsonb NOT NULL DEFAULT '{}', enabled boolean NOT NULL DEFAULT false,
  poll_interval_secs int NOT NULL DEFAULT 900 CHECK (poll_interval_secs >= 60),
  last_polled_at timestamptz, health text NOT NULL DEFAULT 'unknown', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS aegis.video_sightings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), fingerprint_id uuid NOT NULL REFERENCES aegis.video_fingerprints(id) ON DELETE CASCADE,
  source_id uuid NOT NULL REFERENCES aegis.video_sources(id) ON DELETE CASCADE, url text NOT NULL,
  author text, snippet text, observed_at timestamptz NOT NULL DEFAULT now(),
  matched_via text NOT NULL CHECK (matched_via IN ('perceptual','exact','manual')),
  confidence numeric(5,4) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
  alert_id uuid REFERENCES aegis.alerts(id) ON DELETE SET NULL, status text NOT NULL DEFAULT 'new',
  created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(source_id,url)
);
SELECT aegis.attach_updated_at('aegis.video_fingerprints');
INSERT INTO aegis.permissions(code, description) VALUES
 ('video:read','View video fingerprints and sightings'), ('video:run','Register video fingerprints and sightings')
ON CONFLICT (code) DO NOTHING;
INSERT INTO aegis.role_permissions(role_id, permission_id)
SELECT r.id,p.id FROM aegis.roles r JOIN aegis.permissions p ON true
WHERE (r.name IN ('admin','analyst') AND p.code IN ('video:read','video:run'))
   OR (r.name='viewer' AND p.code='video:read') ON CONFLICT DO NOTHING;
INSERT INTO aegis.alert_rules(name,description,event_type,conditions,severity,channels)
SELECT 'Video sighting','A registered video was observed on a monitored source.','video.sighting','{}'::jsonb,'high'::aegis.severity,'{}'::text[]
WHERE NOT EXISTS (SELECT 1 FROM aegis.alert_rules WHERE name='Video sighting');
