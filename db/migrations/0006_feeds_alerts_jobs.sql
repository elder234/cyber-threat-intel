-- ═════════════════════════════════════════════════════════════════════════════
-- Aegis CTI — Migration 0006: feeds, alerts, notifications, job queue, schedules
-- ═════════════════════════════════════════════════════════════════════════════
SET search_path TO aegis, public;

-- ── Threat feeds (MISP, OTX, abuse.ch, CISA, ...) ────────────────────────────
CREATE TABLE IF NOT EXISTS aegis.feeds (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name          text NOT NULL UNIQUE,
  provider      text NOT NULL,                         -- 'misp','otx','urlhaus','cisa_kev'
  url           text,
  format        text NOT NULL DEFAULT 'json',          -- 'json','csv','stix','taxii','misp'
  enabled       boolean NOT NULL DEFAULT true,
  interval_secs int NOT NULL DEFAULT 3600,
  default_tlp   aegis.tlp NOT NULL DEFAULT 'amber',
  default_confidence aegis.confidence NOT NULL DEFAULT 'medium',
  config        jsonb NOT NULL DEFAULT '{}'::jsonb,    -- auth headers, api key refs
  last_run_at   timestamptz,
  last_status   text,
  last_error    text,
  last_item_count int NOT NULL DEFAULT 0,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS aegis.feed_runs (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  feed_id     uuid NOT NULL REFERENCES aegis.feeds(id) ON DELETE CASCADE,
  status      text NOT NULL,
  items_new   int NOT NULL DEFAULT 0,
  items_updated int NOT NULL DEFAULT 0,
  error       text,
  started_at  timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_feed_runs_feed ON aegis.feed_runs(feed_id, started_at DESC);

-- ── Alert rules + alerts ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS aegis.alert_rules (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL,
  description text NOT NULL DEFAULT '',
  enabled     boolean NOT NULL DEFAULT true,
  -- match spec: which events trigger this rule
  event_type  text NOT NULL,                           -- 'ioc.new','cve.kev','scan.finding'
  conditions  jsonb NOT NULL DEFAULT '{}'::jsonb,      -- e.g. {"min_severity":"high"}
  severity    aegis.severity NOT NULL DEFAULT 'medium',
  channels    text[] NOT NULL DEFAULT '{}',            -- 'email','slack','discord','telegram','webhook'
  throttle_secs int NOT NULL DEFAULT 0,
  created_by  uuid REFERENCES aegis.users(id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS aegis.alerts (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  rule_id     uuid REFERENCES aegis.alert_rules(id) ON DELETE SET NULL,
  title       text NOT NULL,
  body        text NOT NULL DEFAULT '',
  severity    aegis.severity NOT NULL DEFAULT 'medium',
  status      aegis.alert_status NOT NULL DEFAULT 'open',
  source      text,
  entity_type text,                                    -- 'ioc','cve','scan',...
  entity_id   text,
  dedupe_key  text,                                    -- collapse duplicates
  metadata    jsonb NOT NULL DEFAULT '{}'::jsonb,
  acknowledged_by uuid REFERENCES aegis.users(id) ON DELETE SET NULL,
  acknowledged_at timestamptz,
  resolved_at timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_alerts_status   ON aegis.alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON aegis.alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_created  ON aegis.alerts(created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS uq_alerts_dedupe
  ON aegis.alerts(dedupe_key) WHERE dedupe_key IS NOT NULL AND status = 'open';

-- Notification delivery attempts (per channel)
CREATE TABLE IF NOT EXISTS aegis.notifications (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  alert_id    uuid REFERENCES aegis.alerts(id) ON DELETE CASCADE,
  channel     text NOT NULL,
  status      text NOT NULL DEFAULT 'pending',         -- pending/sent/failed
  attempts    int NOT NULL DEFAULT 0,
  error       text,
  sent_at     timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_notifications_alert ON aegis.notifications(alert_id);

-- ── Scheduled scans ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS aegis.scheduled_scans (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id    uuid REFERENCES aegis.assets(id) ON DELETE CASCADE,
  scan_type   text NOT NULL,
  profile     jsonb NOT NULL DEFAULT '{}'::jsonb,
  cron        text NOT NULL,                           -- cron expression
  enabled     boolean NOT NULL DEFAULT true,
  next_run_at timestamptz,
  last_run_at timestamptz,
  created_by  uuid REFERENCES aegis.users(id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
-- late FK from scans -> scheduled_scans
ALTER TABLE aegis.scans
  DROP CONSTRAINT IF EXISTS fk_scans_scheduled;
ALTER TABLE aegis.scans
  ADD CONSTRAINT fk_scans_scheduled
  FOREIGN KEY (scheduled_id) REFERENCES aegis.scheduled_scans(id) ON DELETE SET NULL;

-- ── Durable job queue (SKIP LOCKED pattern for Rust workers) ─────────────────
CREATE TABLE IF NOT EXISTS aegis.jobs (
  id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  queue        text NOT NULL DEFAULT 'default',
  kind         text NOT NULL,                          -- 'scan.port','feed.pull','ioc.enrich'
  payload      jsonb NOT NULL DEFAULT '{}'::jsonb,
  status       aegis.job_status NOT NULL DEFAULT 'pending',
  priority     int NOT NULL DEFAULT 5,                 -- lower = higher priority
  attempts     int NOT NULL DEFAULT 0,
  max_attempts int NOT NULL DEFAULT 5,
  run_after    timestamptz NOT NULL DEFAULT now(),
  claimed_by   text,
  claimed_at   timestamptz,
  last_error   text,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_jobs_dequeue
  ON aegis.jobs(queue, priority, run_after)
  WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_jobs_status ON aegis.jobs(status);

SELECT aegis.attach_updated_at('aegis.feeds');
SELECT aegis.attach_updated_at('aegis.alert_rules');
SELECT aegis.attach_updated_at('aegis.alerts');
SELECT aegis.attach_updated_at('aegis.scheduled_scans');
SELECT aegis.attach_updated_at('aegis.jobs');
