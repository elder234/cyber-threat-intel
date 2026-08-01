-- ═════════════════════════════════════════════════════════════════════════════
-- Aegis CTI — Migration 0015: dark-web monitor (Tor-routed, read-only)
-- ═════════════════════════════════════════════════════════════════════════════
-- Feature F-DARKWEB. A watchlist-driven monitor that polls curated public
-- leak/paste/forum sources EXCLUSIVELY over the Tor SOCKS proxy and raises an
-- alert when a page mentions something on the operator's watchlist.
--
-- Scope & safety (mirrors AGENTS.md Ground rules):
--   * Read-only: fetch + parse public pages only. Never authenticate, post,
--     purchase, or interact. No illicit-market/transaction sources are seeded —
--     the scope is brand/victim/credential EXPOSURE on public leak/paste pages.
--   * Fail-closed Tor: the collector refuses to run if TOR_SOCKS_PROXY is unset
--     or unreachable (enforced in Rust, not here).
--   * Redact on the way in: snippets are truncated and credential/PII-masked by
--     the collector before they ever reach `darkweb_hits.snippet`.
-- ═════════════════════════════════════════════════════════════════════════════
SET search_path TO aegis, public;

-- ── Watchlist ────────────────────────────────────────────────────────────────
-- What the operator wants to be alerted about if it surfaces on a dark-web source.
CREATE TABLE IF NOT EXISTS aegis.watchlist (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind        text NOT NULL CHECK (kind IN ('domain','email','keyword','brand','bin')),
  value       text NOT NULL,
  label       text,
  severity    aegis.severity NOT NULL DEFAULT 'high',
  enabled     boolean NOT NULL DEFAULT true,
  created_by  uuid REFERENCES aegis.users(id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (kind, value)
);
CREATE INDEX IF NOT EXISTS idx_watchlist_enabled ON aegis.watchlist(enabled) WHERE enabled;
SELECT aegis.attach_updated_at('aegis.watchlist');

-- ── Sources ──────────────────────────────────────────────────────────────────
-- Curated public leak/paste/forum indexes to poll. onion_url is typically a
-- .onion address reached only through Tor; is_onion drives the fail-closed check.
CREATE TABLE IF NOT EXISTS aegis.darkweb_sources (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name           text NOT NULL UNIQUE,
  kind           text NOT NULL CHECK (kind IN ('leak_site','paste','forum')),
  onion_url      text NOT NULL,
  is_onion       boolean NOT NULL DEFAULT true,   -- true = MUST route via Tor
  enabled        boolean NOT NULL DEFAULT true,
  poll_interval_secs int NOT NULL DEFAULT 3600 CHECK (poll_interval_secs BETWEEN 300 AND 86400),
  last_polled_at timestamptz,
  health         text NOT NULL DEFAULT 'unknown', -- unknown|ok|unreachable|error
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_darkweb_sources_enabled ON aegis.darkweb_sources(enabled) WHERE enabled;
SELECT aegis.attach_updated_at('aegis.darkweb_sources');

-- ── Hits ─────────────────────────────────────────────────────────────────────
-- One row per (source, url, matched value). snippet is already redacted/truncated.
CREATE TABLE IF NOT EXISTS aegis.darkweb_hits (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_id     uuid NOT NULL REFERENCES aegis.darkweb_sources(id) ON DELETE CASCADE,
  watchlist_id  uuid REFERENCES aegis.watchlist(id) ON DELETE SET NULL,
  url           text NOT NULL,
  matched_value text NOT NULL,
  snippet       text NOT NULL DEFAULT '',         -- redacted + truncated context
  severity      aegis.severity NOT NULL DEFAULT 'high',
  observed_at   timestamptz NOT NULL DEFAULT now(),
  alert_id      uuid REFERENCES aegis.alerts(id) ON DELETE SET NULL,
  status        text NOT NULL DEFAULT 'new',       -- new|reviewed|false_positive|actioned
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (source_id, url, matched_value)
);
CREATE INDEX IF NOT EXISTS idx_darkweb_hits_observed  ON aegis.darkweb_hits(observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_darkweb_hits_severity  ON aegis.darkweb_hits(severity);
CREATE INDEX IF NOT EXISTS idx_darkweb_hits_status    ON aegis.darkweb_hits(status);
CREATE INDEX IF NOT EXISTS idx_darkweb_hits_watchlist ON aegis.darkweb_hits(watchlist_id);
SELECT aegis.attach_updated_at('aegis.darkweb_hits');

-- ── Seed sources ─────────────────────────────────────────────────────────────
-- A small curated set of well-known ransomware leak indexes / paste sites, kept
-- DISABLED by default so no Tor traffic happens until an operator opts in and
-- confirms an onion address. Addresses rotate frequently, so onion_url is a
-- documented placeholder the operator updates before enabling. We intentionally
-- seed NO illicit-market/transaction URLs — leak-site/brand-exposure only.
INSERT INTO aegis.darkweb_sources(name, kind, onion_url, is_onion, enabled, poll_interval_secs)
VALUES
  ('LockBit leak index',  'leak_site', 'http://REPLACE-WITH-CURRENT.onion/', true, false, 7200),
  ('ALPHV/BlackCat leak', 'leak_site', 'http://REPLACE-WITH-CURRENT.onion/', true, false, 7200),
  ('Cl0p leak site',      'leak_site', 'http://REPLACE-WITH-CURRENT.onion/', true, false, 7200),
  ('Generic paste mirror','paste',     'http://REPLACE-WITH-CURRENT.onion/', true, false, 3600)
ON CONFLICT (name) DO NOTHING;

-- ── Alert rule ───────────────────────────────────────────────────────────────
-- In-console rule (no channels attached) so dark-web hits surface on the live
-- feed. Matches the existing seed pattern in 0010_notification_channels.sql.
INSERT INTO aegis.alert_rules (name, description, event_type, conditions, severity, channels)
SELECT v.name, v.description, v.event_type, v.conditions::jsonb, v.severity::aegis.severity, '{}'::text[]
  FROM (VALUES
    ('Dark-web exposure',
     'A watchlisted brand, domain, email or keyword surfaced on a monitored dark-web source.',
     'darkweb.hit', '{}', 'high')
  ) AS v(name, description, event_type, conditions, severity)
 WHERE NOT EXISTS (
   SELECT 1 FROM aegis.alert_rules r WHERE r.name = v.name
 );

-- ── Permissions ──────────────────────────────────────────────────────────────
-- watchlist:write  — manage the watchlist (admin + analyst).
-- darkweb:read     — view sources + hits (admin + analyst; viewer too, read-only).
INSERT INTO aegis.permissions(code, description) VALUES
  ('watchlist:write','Create/update/delete dark-web watchlist entries'),
  ('darkweb:read','View dark-web sources and hits')
ON CONFLICT (code) DO NOTHING;

-- watchlist:write → admin, analyst
INSERT INTO aegis.role_permissions(role_id, permission_id)
SELECT r.id, p.id FROM aegis.roles r JOIN aegis.permissions p ON true
WHERE r.name IN ('admin','analyst') AND p.code = 'watchlist:write'
ON CONFLICT DO NOTHING;

-- darkweb:read → admin, analyst, viewer
INSERT INTO aegis.role_permissions(role_id, permission_id)
SELECT r.id, p.id FROM aegis.roles r JOIN aegis.permissions p ON true
WHERE r.name IN ('admin','analyst','viewer') AND p.code = 'darkweb:read'
ON CONFLICT DO NOTHING;
