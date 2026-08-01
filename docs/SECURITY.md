# Security Model & Controls

This document describes the controls that keep Aegis CTI's more powerful
features — active web inspection and dark-web monitoring — safe and in scope.
Read it alongside `docs/LEGAL.md` (authorized use) and the AGENTS.md ground
rules.

## Authentication & authorization

- JWT access tokens (short-lived, held in memory client-side) + refresh tokens.
- RBAC with roles `admin`, `analyst`, `viewer`. Permissions are `resource:action`
  strings checked by the `requirePerms(...)` preHandler on every protected route.
- Every mutating action is written to the audit log (`aegis.audit_log`) via the
  shared `audit()` helper, including who did it and against which resource.

Relevant permissions for the newer features:

| Permission        | Grants                                         | Roles                    |
|-------------------|------------------------------------------------|--------------------------|
| `web:scan`        | Launch web (DAST) scans                         | admin, analyst           |
| `watchlist:write` | Create/update/delete dark-web watchlist entries | admin, analyst           |
| `darkweb:read`    | View dark-web sources and hits                  | admin, analyst, viewer   |

## Active web inspection (DAST)

Defense-in-depth, enforced across layers:

1. **Authorization gate (primary control).** Active probes run only against a
   registered asset with `assets.is_authorized = true`, checked in Rust in the
   scanner before the first probe. Ad-hoc targets and unauthorized assets get
   passive inspection only. The API additionally refuses an active web scan that
   has no `assetId`.
2. **Permission gate.** Launching a web scan requires `web:scan`.
3. **Benign payloads only.** Probes send non-destructive detection markers. There
   is no state mutation, no authentication bypass, no destructive HTTP method
   (only safe reads), and no time-based/resource-exhaustion behavior. Requests
   are rate-limited and carry an identifiable user-agent (`aegis-cti-scanner`).
4. **Findings, not exploits.** A finding records that a parameter *appears*
   injectable with supporting evidence; Aegis never escalates or weaponizes it.

If you remove or weaken the authorization gate, you are operating the tool
outside its intended, authorized-use design.

## Dark-web monitoring

1. **Fail-closed Tor routing.** All fetches go through the Tor SOCKS proxy
   (`TOR_SOCKS_PROXY`). If it is unset the collector logs and returns without
   making any request — there is **no clearnet fallback**, so the platform's real
   IP is never leaked to a hidden service.
2. **Read-only.** The collector issues GET requests to public pages only. It
   never authenticates, posts, purchases, registers, or interacts.
3. **Redaction on ingest.** Before a hit is persisted, the collector truncates
   context to a bounded snippet and masks emails and long digit runs
   (card/BIN/SSN-like). The database and UI store evidence of exposure, not a
   usable copy of leaked data.
4. **Curated, disabled-by-default sources.** Shipped sources are disabled with
   placeholder addresses and cover brand/victim/credential exposure on public
   leak/paste/forum pages. No illicit-market/transaction sources are seeded.
   Operators supply current addresses out-of-band and opt in per source.
5. **Polite polling.** Requests are jittered and rate-limited per source, and
   each source has a minimum poll interval, so monitoring is neither abusive nor
   easily fingerprintable.

## Alerting integration

Dark-web hits are raised through the same `aegis.raise_alert()` engine as every
other alert (dedupe-aware), so exposure surfaces on the dashboard live feed and
configured notification channels, and each hit links back to its alert via
`darkweb_hits.alert_id`.

## Operational notes

- Secrets (DB URL, JWT secret, channel webhooks, any API keys) come from the
  environment, never the repo. Rotate any key that is ever committed or exposed.
- The web console never receives `onion_url` values in source listings; operators
  manage those addresses out-of-band.
- Migrations are append-only. Never edit an applied migration; add a new one.
