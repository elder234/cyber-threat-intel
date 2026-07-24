-- ═════════════════════════════════════════════════════════════════════════════
-- Aegis CTI — Migration 0008: dashboard views (timeline, geo, top lists)
-- ═════════════════════════════════════════════════════════════════════════════
SET search_path TO aegis, public;

-- Threat timeline: alerts + KEV additions + new critical IOCs, last 30 days
CREATE OR REPLACE VIEW aegis.v_threat_timeline AS
  SELECT created_at AS ts, 'alert'::text AS kind, severity::text AS severity, title
    FROM aegis.alerts
   WHERE created_at > now() - interval '30 days'
  UNION ALL
  SELECT first_seen, 'ioc', severity::text, value
    FROM aegis.iocs
   WHERE first_seen > now() - interval '30 days' AND severity IN ('high','critical')
  UNION ALL
  SELECT (kev_added_at)::timestamptz, 'kev', 'critical', cve_id
    FROM aegis.cves
   WHERE kev AND kev_added_at > (now() - interval '30 days')::date;

-- Attack statistics by MITRE tactic (from IOC technique mappings)
CREATE OR REPLACE VIEW aegis.v_attack_stats AS
  SELECT t.id AS tactic_id, t.name AS tactic_name, count(DISTINCT i.id) AS ioc_count
    FROM aegis.mitre_tactics t
    LEFT JOIN aegis.mitre_techniques mt ON t.id = ANY(mt.tactic_ids)
    LEFT JOIN aegis.iocs i ON mt.id = ANY(i.technique_ids) AND i.is_active
   GROUP BY t.id, t.name, t.sort_order
   ORDER BY t.sort_order;

-- Top IOC sources
CREATE OR REPLACE VIEW aegis.v_top_sources AS
  SELECT source, count(*) AS total,
         count(*) FILTER (WHERE severity IN ('high','critical')) AS high_sev
    FROM aegis.iocs
   WHERE is_active
   GROUP BY source
   ORDER BY total DESC;

-- Recent KEV CVEs (for dashboard widget)
CREATE OR REPLACE VIEW aegis.v_recent_kev AS
  SELECT cve_id, cvss_v31_score, epss_score, kev_added_at, kev_ransomware,
         left(description, 160) AS summary
    FROM aegis.cves
   WHERE kev
   ORDER BY kev_added_at DESC NULLS LAST
   LIMIT 100;

-- Certificate expiry watch (from TLS scans)
CREATE OR REPLACE VIEW aegis.v_cert_expiry AS
  SELECT DISTINCT ON (host, port) host, port, cert_subject, not_after,
         (not_after - now()) AS time_left, is_expired
    FROM aegis.scan_tls
   WHERE not_after IS NOT NULL
   ORDER BY host, port, created_at DESC;
