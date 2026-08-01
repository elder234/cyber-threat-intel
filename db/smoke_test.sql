-- ═════════════════════════════════════════════════════════════════════════════
-- Aegis CTI — DB smoke test. Run AFTER migrate.sh:
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f db/smoke_test.sql
-- Exits non-zero (via ASSERT) if any invariant fails.
-- ═════════════════════════════════════════════════════════════════════════════
SET search_path TO aegis, public;
\set ON_ERROR_STOP on

DO $$
DECLARE
  v_ioc uuid;
  v_job bigint;
  v_score int;
  v_perm_count int;
  v_claimed int;
  v_stats jsonb;
BEGIN
  -- 1. RBAC seeded correctly: admin must hold every permission.
  SELECT count(*) INTO v_perm_count FROM aegis.user_permissions(
    (SELECT u.id FROM aegis.users u LIMIT 1))
  WHERE true;
  -- (user may not exist yet in a fresh DB; check role instead)
  ASSERT (SELECT count(*) FROM aegis.role_permissions rp
          JOIN aegis.roles r ON r.id=rp.role_id WHERE r.name='admin')
         = (SELECT count(*) FROM aegis.permissions),
         'admin role must map to all permissions';

  -- 2. Risk scoring is deterministic and bounded.
  v_score := aegis.compute_ioc_score('critical','confirmed', now());
  ASSERT v_score BETWEEN 0 AND 100, 'score must be in [0,100]';
  ASSERT v_score = 100, format('fresh critical/confirmed should be 100, got %s', v_score);

  -- 3. IOC upsert + merge behaviour.
  v_ioc := aegis.upsert_ioc('ipv4','203.0.113.5','high','high','unit-test', ARRAY['test']);
  ASSERT v_ioc IS NOT NULL, 'upsert_ioc must return an id';
  -- re-upsert with higher severity merges upward
  PERFORM aegis.upsert_ioc('ipv4','203.0.113.5','critical','confirmed','unit-test-2');
  ASSERT (SELECT severity FROM aegis.iocs WHERE id=v_ioc) = 'critical',
         'severity must merge upward';
  ASSERT (SELECT count(*) FROM aegis.ioc_sightings WHERE ioc_id=v_ioc) = 2,
         'two sightings expected';

  -- 4. Job queue: enqueue + atomic dequeue.
  v_job := aegis.enqueue_job('unit.test', '{"x":1}'::jsonb, 'default', 1);
  ASSERT v_job IS NOT NULL, 'enqueue must return id';
  SELECT count(*) INTO v_claimed FROM aegis.dequeue_jobs('default','worker-1',10);
  ASSERT v_claimed >= 1, 'dequeue must claim the pending job';
  PERFORM aegis.complete_job(v_job);
  ASSERT (SELECT status FROM aegis.jobs WHERE id=v_job) = 'succeeded',
         'job must be marked succeeded';

  -- 5. Unified search finds the IOC we inserted.
  ASSERT (SELECT count(*) FROM aegis.unified_search('203.0.113.5')) >= 1,
         'unified_search must find the test IOC';

  -- 6. Dashboard stats returns every key the frontend DashboardStats consumes.
  v_stats := aegis.dashboard_stats();
  ASSERT (SELECT bool_and(v_stats ? k) FROM unnest(ARRAY[
           'iocs_total','iocs_active','cves_kev','alerts_open','scans_running',
           'feeds_healthy','feeds_total','risk_score','by_severity','ingest_24h'
         ]) AS k), 'dashboard_stats missing keys';
  ASSERT v_stats->>'risk_score' ~ '^\d+$', 'risk_score must be an int';
  ASSERT (v_stats->'by_severity'->'critical') IS NOT NULL, 'by_severity must be bucketed';

  -- cleanup test rows
  DELETE FROM aegis.iocs WHERE source LIKE 'unit-test%';
  DELETE FROM aegis.jobs WHERE kind='unit.test';

  RAISE NOTICE '✔ All smoke tests passed (score=%, claimed=%)', v_score, v_claimed;
END $$;
