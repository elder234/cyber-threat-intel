-- ═════════════════════════════════════════════════════════════════════════════
-- Aegis CTI — Migration 0007: stored procedures & functions
-- ═════════════════════════════════════════════════════════════════════════════
SET search_path TO aegis, public;

-- ─────────────────────────────────────────────────────────────────────────────
-- dequeue_jobs: atomically claim N pending jobs (SKIP LOCKED). Used by Rust workers.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION aegis.dequeue_jobs(
  p_queue text,
  p_worker text,
  p_limit int DEFAULT 1
)
RETURNS SETOF aegis.jobs AS $$
  WITH claimed AS (
    SELECT id
    FROM aegis.jobs
    WHERE status = 'pending'
      AND queue = p_queue
      AND run_after <= now()
    ORDER BY priority ASC, run_after ASC
    FOR UPDATE SKIP LOCKED
    LIMIT p_limit
  )
  UPDATE aegis.jobs j
     SET status = 'running',
         claimed_by = p_worker,
         claimed_at = now(),
         attempts = j.attempts + 1,
         updated_at = now()
    FROM claimed
   WHERE j.id = claimed.id
   RETURNING j.*;
$$ LANGUAGE sql;

-- complete_job / fail_job with retry+backoff
CREATE OR REPLACE FUNCTION aegis.complete_job(p_id bigint)
RETURNS void AS $$
  UPDATE aegis.jobs
     SET status = 'succeeded', updated_at = now()
   WHERE id = p_id;
$$ LANGUAGE sql;

CREATE OR REPLACE FUNCTION aegis.fail_job(p_id bigint, p_error text)
RETURNS void AS $$
  UPDATE aegis.jobs
     SET status = CASE WHEN attempts >= max_attempts THEN 'dead'::aegis.job_status
                       ELSE 'pending'::aegis.job_status END,
         last_error = p_error,
         run_after = now() + (interval '10 seconds' * power(2, least(attempts, 8))),
         claimed_by = NULL,
         updated_at = now()
   WHERE id = p_id;
$$ LANGUAGE sql;

CREATE OR REPLACE FUNCTION aegis.enqueue_job(
  p_kind text,
  p_payload jsonb DEFAULT '{}'::jsonb,
  p_queue text DEFAULT 'default',
  p_priority int DEFAULT 5,
  p_run_after timestamptz DEFAULT now()
)
RETURNS bigint AS $$
  INSERT INTO aegis.jobs(kind, payload, queue, priority, run_after)
  VALUES (p_kind, p_payload, p_queue, p_priority, p_run_after)
  RETURNING id;
$$ LANGUAGE sql;

-- ─────────────────────────────────────────────────────────────────────────────
-- compute_ioc_score: deterministic 0..100 risk score from severity/confidence/age
-- ─────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION aegis.compute_ioc_score(
  p_severity aegis.severity,
  p_confidence aegis.confidence,
  p_last_seen timestamptz
)
RETURNS int AS $$
DECLARE
  sev_w   int := CASE p_severity
                   WHEN 'critical' THEN 100 WHEN 'high' THEN 80
                   WHEN 'medium' THEN 55 WHEN 'low' THEN 30 ELSE 10 END;
  conf_m  numeric := CASE p_confidence
                   WHEN 'confirmed' THEN 1.0 WHEN 'high' THEN 0.9
                   WHEN 'medium' THEN 0.75 ELSE 0.5 END;
  age_days numeric := GREATEST(0, EXTRACT(EPOCH FROM (now() - p_last_seen)) / 86400.0);
  decay   numeric := GREATEST(0.4, 1.0 - (age_days / 365.0));  -- floor at 0.4
BEGIN
  RETURN LEAST(100, GREATEST(0, round(sev_w * conf_m * decay)))::int;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ─────────────────────────────────────────────────────────────────────────────
-- upsert_ioc: insert-or-merge an IOC, bump last_seen, recompute score
-- ─────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION aegis.upsert_ioc(
  p_type aegis.ioc_type,
  p_value text,
  p_severity aegis.severity DEFAULT 'medium',
  p_confidence aegis.confidence DEFAULT 'medium',
  p_source text DEFAULT 'manual',
  p_tags text[] DEFAULT '{}',
  p_tlp aegis.tlp DEFAULT 'amber'
)
RETURNS uuid AS $$
DECLARE
  v_id uuid;
BEGIN
  INSERT INTO aegis.iocs(type, value, severity, confidence, source, tags, tlp, score, last_seen)
  VALUES (p_type, p_value, p_severity, p_confidence, p_source, p_tags, p_tlp,
          aegis.compute_ioc_score(p_severity, p_confidence, now()), now())
  ON CONFLICT (type, value_norm) DO UPDATE
    SET last_seen  = now(),
        severity   = GREATEST(aegis.iocs.severity, EXCLUDED.severity),
        confidence = GREATEST(aegis.iocs.confidence, EXCLUDED.confidence),
        tags       = ARRAY(SELECT DISTINCT unnest(aegis.iocs.tags || EXCLUDED.tags)),
        is_active  = true,
        score      = aegis.compute_ioc_score(
                       GREATEST(aegis.iocs.severity, EXCLUDED.severity),
                       GREATEST(aegis.iocs.confidence, EXCLUDED.confidence), now()),
        updated_at = now()
  RETURNING id INTO v_id;

  INSERT INTO aegis.ioc_sightings(ioc_id, source) VALUES (v_id, p_source);
  RETURN v_id;
END;
$$ LANGUAGE plpgsql;

-- ─────────────────────────────────────────────────────────────────────────────
-- write_audit: convenience insert used by API + triggers
-- ─────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION aegis.write_audit(
  p_actor uuid, p_email citext, p_action text,
  p_resource text, p_resource_id text, p_ip inet,
  p_ua text, p_meta jsonb DEFAULT '{}'::jsonb
)
RETURNS bigint AS $$
  INSERT INTO aegis.audit_log(actor_id, actor_email, action, resource, resource_id, ip, user_agent, metadata)
  VALUES (p_actor, p_email, p_action, p_resource, p_resource_id, p_ip, p_ua, p_meta)
  RETURNING id;
$$ LANGUAGE sql;

-- ─────────────────────────────────────────────────────────────────────────────
-- user_permissions: flattened permission codes for a user (RBAC resolution)
-- ─────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION aegis.user_permissions(p_user uuid)
RETURNS TABLE(code text) AS $$
  SELECT DISTINCT p.code
  FROM aegis.user_roles ur
  JOIN aegis.role_permissions rp ON rp.role_id = ur.role_id
  JOIN aegis.permissions p ON p.id = rp.permission_id
  WHERE ur.user_id = p_user;
$$ LANGUAGE sql STABLE;

-- ─────────────────────────────────────────────────────────────────────────────
-- unified_search: search across IOCs, CVEs, actors, malware (Module 12 DB side)
-- Returns a uniform result shape ranked by relevance.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION aegis.unified_search(p_q text, p_limit int DEFAULT 25)
RETURNS TABLE(
  entity_type text, entity_id text, title text, subtitle text, score real
) AS $$
  SELECT 'ioc', i.id::text, i.value, i.type::text,
         similarity(i.value_norm, lower(p_q))::real
    FROM aegis.iocs i
   WHERE i.value_norm % lower(p_q) OR i.value_norm ILIKE '%'||lower(p_q)||'%'
  UNION ALL
  SELECT 'cve', c.cve_id, c.cve_id, left(c.description, 120),
         GREATEST(similarity(c.cve_id, p_q), similarity(c.description, p_q))::real
    FROM aegis.cves c
   WHERE c.cve_id ILIKE '%'||p_q||'%' OR c.description % p_q
  UNION ALL
  SELECT 'threat_actor', a.id::text, a.name, array_to_string(a.aliases, ', '),
         similarity(a.name, p_q)::real
    FROM aegis.threat_actors a
   WHERE a.name % p_q OR p_q = ANY(a.aliases)
  UNION ALL
  SELECT 'malware', m.id::text, m.name, m.category,
         similarity(m.name, p_q)::real
    FROM aegis.malware_families m
   WHERE m.name % p_q OR p_q = ANY(m.aliases)
  ORDER BY 4 DESC NULLS LAST
  LIMIT p_limit;
$$ LANGUAGE sql STABLE;

-- ─────────────────────────────────────────────────────────────────────────────
-- dashboard_stats: single-call aggregate for the SOC dashboard header
-- ─────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION aegis.dashboard_stats()
RETURNS jsonb AS $$
  SELECT jsonb_build_object(
    'iocs_active',      (SELECT count(*) FROM aegis.iocs WHERE is_active),
    'iocs_critical',    (SELECT count(*) FROM aegis.iocs WHERE is_active AND severity='critical'),
    'cves_total',       (SELECT count(*) FROM aegis.cves),
    'cves_kev',         (SELECT count(*) FROM aegis.cves WHERE kev),
    'alerts_open',      (SELECT count(*) FROM aegis.alerts WHERE status='open'),
    'alerts_critical',  (SELECT count(*) FROM aegis.alerts WHERE status='open' AND severity='critical'),
    'scans_running',    (SELECT count(*) FROM aegis.scans WHERE status='running'),
    'findings_open',    (SELECT count(*) FROM aegis.findings WHERE status='open'),
    'feeds_enabled',    (SELECT count(*) FROM aegis.feeds WHERE enabled),
    'jobs_pending',     (SELECT count(*) FROM aegis.jobs WHERE status='pending')
  );
$$ LANGUAGE sql STABLE;
