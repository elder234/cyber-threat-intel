-- ═════════════════════════════════════════════════════════════════════════════
-- Aegis CTI — Migration 0013: align DB output names to the frontend contract
-- ─────────────────────────────────────────────────────────────────────────────
-- Decision (P2): the SQL layer is renamed to match the UI types in
-- web/src/lib/types.ts, applied uniformly. dashboard_stats() additionally gains
-- real aggregates for risk_score / by_severity / ingest_24h, which previously
-- had no source at all. Also seeds the `dashboard:read` permission (P4).
-- ═════════════════════════════════════════════════════════════════════════════
SET search_path TO aegis, public;

-- ─────────────────────────────────────────────────────────────────────────────
-- unified_search: entity_type / entity_id / label / sub_label / rank / severity
-- (renamed from title/subtitle/score; severity is now produced for ioc + cve).
-- The RETURNS TABLE shape changes, so DROP first: CREATE OR REPLACE FUNCTION
-- forbids changing a function's result type.
-- ─────────────────────────────────────────────────────────────────────────────
DROP FUNCTION IF EXISTS aegis.unified_search(p_q text, p_limit int);
CREATE OR REPLACE FUNCTION aegis.unified_search(p_q text, p_limit int DEFAULT 25)
RETURNS TABLE(
  entity_type text, entity_id text, label text, sub_label text, rank real,
  severity aegis.severity
) AS $$
  SELECT 'ioc'::text AS entity_type, i.id::text AS entity_id, i.value AS label,
         i.type::text AS sub_label,
         similarity(i.value_norm, lower(p_q))::real AS rank,
         i.severity AS severity
    FROM aegis.iocs i
   WHERE i.value_norm % lower(p_q) OR i.value_norm ILIKE '%'||lower(p_q)||'%'
  UNION ALL
  SELECT 'cve', c.cve_id, c.cve_id, left(c.description, 120),
         GREATEST(similarity(c.cve_id, p_q), similarity(c.description, p_q))::real,
         c.cvss_v31_severity
    FROM aegis.cves c
   WHERE c.cve_id ILIKE '%'||p_q||'%' OR c.description % p_q
  UNION ALL
  SELECT 'threat_actor', a.id::text, a.name, array_to_string(a.aliases, ', '),
         similarity(a.name, p_q)::real, NULL
    FROM aegis.threat_actors a
   WHERE a.name % p_q OR p_q = ANY(a.aliases)
  UNION ALL
  SELECT 'malware', m.id::text, m.name, m.category,
         similarity(m.name, p_q)::real, NULL
    FROM aegis.malware_families m
   WHERE m.name % p_q OR p_q = ANY(m.aliases)
  ORDER BY rank DESC NULLS LAST
  LIMIT p_limit;
$$ LANGUAGE sql STABLE;

-- ─────────────────────────────────────────────────────────────────────────────
-- dashboard_stats: exactly the keys DashboardStats (types.ts) renders.
-- risk_score is a weighted composite across active IOC scores, open alerts,
-- and KEV exposure; by_severity is a full 5-bucket count; ingest_24h counts
-- IOCs first seen in the last 24 hours.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION aegis.dashboard_stats()
RETURNS jsonb AS $$
  SELECT jsonb_build_object(
    'iocs_total',   (SELECT count(*) FROM aegis.iocs),
    'iocs_active',  (SELECT count(*) FROM aegis.iocs WHERE is_active),
    'cves_kev',     (SELECT count(*) FROM aegis.cves WHERE kev),
    'alerts_open',  (SELECT count(*) FROM aegis.alerts WHERE status='open'),
    'scans_running',(SELECT count(*) FROM aegis.scans WHERE status='running'),
    'feeds_healthy',(SELECT count(*) FROM aegis.feeds
                      WHERE enabled AND COALESCE(last_status,'succeeded') = 'succeeded'),
    'feeds_total',  (SELECT count(*) FROM aegis.feeds WHERE enabled),
    'risk_score',   (
      SELECT LEAST(100, GREATEST(0, round(
               COALESCE((SELECT avg(aegis.compute_ioc_score(severity, confidence, last_seen))
                           FROM aegis.iocs WHERE is_active), 0) * 0.6
             + LEAST(100, (SELECT count(*) FROM aegis.alerts WHERE status='open') * 8) * 0.25
             + LEAST(100, (SELECT count(*) FROM aegis.cves WHERE kev) * 3) * 0.15
           )))::int
    ),
    'by_severity',  (
      SELECT jsonb_object_agg(sev, c) FROM (
        SELECT sev, count(i.id) AS c
          FROM unnest(ARRAY['critical','high','medium','low','info']::text[]) AS sev(sev)
          LEFT JOIN aegis.iocs i ON i.severity::text = sev AND i.is_active
         GROUP BY sev
      ) s
    ),
    'ingest_24h',   (SELECT count(*) FROM aegis.iocs
                      WHERE first_seen >= now() - interval '24 hours')
  );
$$ LANGUAGE sql STABLE;

-- ─────────────────────────────────────────────────────────────────────────────
-- v_attack_stats: tactic / count (UI names; tactic-level aggregation only).
-- Column names change, so DROP first: CREATE OR REPLACE VIEW forbids renaming
-- or removing view columns.
-- ─────────────────────────────────────────────────────────────────────────────
DROP VIEW IF EXISTS aegis.v_attack_stats;
CREATE OR REPLACE VIEW aegis.v_attack_stats AS
  SELECT t.name AS tactic, count(DISTINCT i.id) AS count
    FROM aegis.mitre_tactics t
    LEFT JOIN aegis.mitre_techniques mt ON t.id = ANY(mt.tactic_ids)
    LEFT JOIN aegis.iocs i ON mt.id = ANY(i.technique_ids) AND i.is_active
   GROUP BY t.id, t.name, t.sort_order
   ORDER BY t.sort_order;

-- ─────────────────────────────────────────────────────────────────────────────
-- v_top_sources: source / count / high_sev (UI names).
-- ─────────────────────────────────────────────────────────────────────────────
DROP VIEW IF EXISTS aegis.v_top_sources;
CREATE OR REPLACE VIEW aegis.v_top_sources AS
  SELECT source, count(*) AS count,
         count(*) FILTER (WHERE severity IN ('high','critical')) AS high_sev
    FROM aegis.iocs
   WHERE is_active
   GROUP BY source
   ORDER BY count DESC;

-- ─────────────────────────────────────────────────────────────────────────────
-- v_recent_kev: widen to the full Cve shape the frontend consumes.
-- ─────────────────────────────────────────────────────────────────────────────
DROP VIEW IF EXISTS aegis.v_recent_kev;
CREATE OR REPLACE VIEW aegis.v_recent_kev AS
  SELECT cve_id, description, cvss_v31_score, cvss_v31_severity, epss_score,
         epss_percentile, kev, kev_ransomware, published_at, kev_added_at
    FROM aegis.cves
   WHERE kev
   ORDER BY kev_added_at DESC NULLS LAST
   LIMIT 100;

-- ─────────────────────────────────────────────────────────────────────────────
-- P4: dashboard:read permission, granted to every role (read-only aggregate).
-- ─────────────────────────────────────────────────────────────────────────────
INSERT INTO aegis.permissions(code, description) VALUES
  ('dashboard:read','View dashboard aggregates and threat timeline')
ON CONFLICT (code) DO NOTHING;

INSERT INTO aegis.role_permissions(role_id, permission_id)
SELECT r.id, p.id FROM aegis.roles r JOIN aegis.permissions p ON true
WHERE r.name IN ('admin','analyst','viewer') AND p.code = 'dashboard:read'
ON CONFLICT DO NOTHING;
