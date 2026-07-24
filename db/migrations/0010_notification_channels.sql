-- ═════════════════════════════════════════════════════════════════════════════
-- Aegis CTI — Migration 0010: notification channels (Module 11)
-- Stores per-destination delivery config for the alert engine. Secrets (webhook
-- URLs, bot tokens, SMTP passwords) live here encrypted-at-rest by the DB; the
-- API never returns secret fields in list responses.
-- ═════════════════════════════════════════════════════════════════════════════
SET search_path TO aegis, public;

-- Channel types the dispatcher understands.
DO $$ BEGIN
  CREATE TYPE aegis.channel_type AS ENUM ('email','slack','discord','telegram','webhook');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS aegis.notification_channels (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL UNIQUE,                    -- referenced by alert_rules.channels
  type        aegis.channel_type NOT NULL,
  enabled     boolean NOT NULL DEFAULT true,
  -- Delivery config. Shape depends on `type`:
  --   slack/discord/webhook: { "url": "https://..." }
  --   telegram:              { "bot_token": "...", "chat_id": "..." }
  --   email:                 { "to": ["a@x"], "from": "aegis@x" }  (SMTP transport from env)
  config      jsonb NOT NULL DEFAULT '{}'::jsonb,
  -- Only forward alerts at/above this severity through this channel.
  min_severity aegis.severity NOT NULL DEFAULT 'low',
  last_ok_at  timestamptz,
  last_error  text,
  created_by  uuid REFERENCES aegis.users(id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_notif_channels_enabled
  ON aegis.notification_channels(enabled) WHERE enabled;

-- Link a notification delivery row back to the channel that handled it, so the
-- UI can show per-channel delivery history. (notifications.channel is the name.)
CREATE INDEX IF NOT EXISTS idx_notifications_channel ON aegis.notifications(channel);
CREATE INDEX IF NOT EXISTS idx_notifications_status  ON aegis.notifications(status);

SELECT aegis.attach_updated_at('aegis.notification_channels');

-- ── raise_alert(): dedupe-aware alert insertion used by the alert engine ──────
-- Returns the alert id (existing open one on dedupe hit, else the new row).
CREATE OR REPLACE FUNCTION aegis.raise_alert(
  p_rule_id     uuid,
  p_title       text,
  p_body        text,
  p_severity    aegis.severity,
  p_source      text,
  p_entity_type text,
  p_entity_id   text,
  p_dedupe_key  text,
  p_metadata    jsonb DEFAULT '{}'::jsonb
) RETURNS TABLE(id uuid, is_new boolean) AS $$
DECLARE
  v_id uuid;
BEGIN
  -- Reuse an open alert with the same dedupe key if present.
  IF p_dedupe_key IS NOT NULL THEN
    SELECT a.id INTO v_id
      FROM aegis.alerts a
     WHERE a.dedupe_key = p_dedupe_key AND a.status = 'open'
     LIMIT 1;
    IF v_id IS NOT NULL THEN
      RETURN QUERY SELECT v_id, false;
      RETURN;
    END IF;
  END IF;

  INSERT INTO aegis.alerts(rule_id, title, body, severity, source,
                           entity_type, entity_id, dedupe_key, metadata)
  VALUES (p_rule_id, p_title, p_body, p_severity, p_source,
          p_entity_type, p_entity_id, p_dedupe_key, COALESCE(p_metadata, '{}'::jsonb))
  RETURNING alerts.id INTO v_id;

  RETURN QUERY SELECT v_id, true;
END;
$$ LANGUAGE plpgsql;

-- ── Default alert rules ───────────────────────────────────────────────────────
-- Seeded with no channels attached, so they raise in-console alerts immediately
-- and an operator can wire channels later via /api/alert-rules. Idempotent by name
-- (alert_rules.name has no unique constraint, so we guard with NOT EXISTS).
INSERT INTO aegis.alert_rules (name, description, event_type, conditions, severity, channels)
SELECT v.name, v.description, v.event_type, v.conditions::jsonb, v.severity::aegis.severity, '{}'::text[]
  FROM (VALUES
    ('KEV-listed vulnerability',
     'A CVE observed in CISA''s Known Exploited Vulnerabilities catalog.',
     'cve.kev', '{}', 'critical'),
    ('High-severity indicator',
     'A new indicator scored high or critical by enrichment.',
     'ioc.new', '{"min_severity":"high"}', 'high'),
    ('Scan finding',
     'A vulnerability scan surfaced a finding.',
     'scan.finding', '{}', 'medium')
  ) AS v(name, description, event_type, conditions, severity)
 WHERE NOT EXISTS (
   SELECT 1 FROM aegis.alert_rules r WHERE r.name = v.name
 );


