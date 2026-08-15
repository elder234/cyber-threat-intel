-- ═════════════════════════════════════════════════════════════════════════════
-- Aegis CTI — Migration 0016: clearnet dark-web sources + structured parsing
-- ═════════════════════════════════════════════════════════════════════════════
-- Extends 0015's dark-web monitor so it can also poll public CLEARNET indexers
-- (aggregator APIs and leak-site mirrors) in addition to onion sources:
--
--   * `onion_url` is renamed to `url` — a source may now be a clearnet HTTP(S)
--     URL (is_onion = false) or an onion address (is_onion = true, still the
--     fail-closed Tor path).
--   * `format` selects how the collector interprets the response:
--       'html' — raw page text (default; existing behaviour)
--       'json' — parse structured JSON records and match each record's text,
--                storing the record's own URL so every victim dedupes.
--
-- Safety posture is unchanged: onion sources still refuse to run without Tor,
-- and the two seeded clearnet sources are public defensive indexers
-- (ransomware.live's victim API, WikiLeaks V2's mirror). No illicit-market or
-- transaction URLs are added.
-- ═════════════════════════════════════════════════════════════════════════════
SET search_path TO aegis, public;

-- A source is now a generic URL, not necessarily an onion.
ALTER TABLE aegis.darkweb_sources RENAME COLUMN onion_url TO url;

COMMENT ON COLUMN aegis.darkweb_sources.url IS
  'URL to poll — clearnet HTTP(S) when is_onion=false, .onion when true.';

-- How to interpret the fetched body. Existing rows default to 'html'.
ALTER TABLE aegis.darkweb_sources
  ADD COLUMN format text NOT NULL DEFAULT 'html'
  CONSTRAINT ck_darkweb_sources_format CHECK (format IN ('html','json'));

COMMENT ON COLUMN aegis.darkweb_sources.format IS
  'html = raw page text matching; json = parse records and match each one.';

-- ── Seed clearnet sources ────────────────────────────────────────────────────
-- Enabled: clearnet public indexers, and poll_all short-circuits on an empty
-- watchlist anyway, so no traffic happens until the operator adds watch entries.
INSERT INTO aegis.darkweb_sources(name, kind, url, is_onion, enabled, poll_interval_secs, format)
VALUES
  ('ransomware.live victims', 'leak_site', 'https://api.ransomware.live/v2/recentvictims', false, true, 3600, 'json'),
  ('WikiLeaks V2 mirror',     'leak_site', 'https://wikileaks2.com/',                   false, true, 3600, 'html')
ON CONFLICT (name) DO NOTHING;
