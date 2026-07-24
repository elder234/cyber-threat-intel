# Database — Module 13 (PostgreSQL data layer)

The system of record for Aegis. PostgreSQL 15+ in a dedicated `aegis` schema.

## Applying migrations

```bash
export DATABASE_URL=postgres://aegis:pass@localhost:5432/aegis
./db/migrate.sh                                   # idempotent, tracks applied files
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f db/smoke_test.sql   # invariants
```

`migrate.sh` records each applied file in `aegis.schema_migrations`, so re-runs are
safe and only new migrations execute. The Node API also runs the same ordered files
on startup (`services/api/src/db/migrate.ts`) so containers self-migrate.

## Migration order

| File | Contents |
|------|----------|
| `0001_init_extensions.sql` | Extensions (pgcrypto, pg_trgm, citext, btree_gin), enums, `updated_at` trigger helper |
| `0002_identity_rbac.sql` | users, roles, permissions, role_permissions, user_roles, refresh_tokens, api_keys, audit_log |
| `0003_threat_intel_core.sql` | cves (CVSS/EPSS/KEV), mitre_tactics, mitre_techniques, threat_actors, malware_families |
| `0004_iocs_rules.sql` | iocs (+generated `value_norm`), ioc_sightings, ioc_relations, detection_rules (YARA/Sigma) |
| `0005_assets_scans.sql` | assets, scans, scan_ports, scan_tls, findings |
| `0006_feeds_alerts_jobs.sql` | feeds, feed_runs, alert_rules, alerts, notifications, scheduled_scans, jobs (durable queue) |
| `0007_procedures.sql` | Functions: dequeue/complete/fail/enqueue job, compute_ioc_score, upsert_ioc, write_audit, user_permissions, unified_search, dashboard_stats |
| `0008_views.sql` | Views: threat timeline, attack stats, top sources, recent KEV, cert expiry |
| `0009_seed.sql` | RBAC roles+permissions, 14 MITRE tactics, default feeds |

## Design notes

**Enums for ordered severity/confidence.** `severity` and `confidence` are enums whose
declaration order matters — `GREATEST(a, b)` picks the higher ordinal, which is how
`upsert_ioc` merges an indicator upward when a more severe sighting arrives.

**Durable job queue.** `aegis.jobs` + `dequeue_jobs()` use `FOR UPDATE SKIP LOCKED` so
many Rust workers can pull work concurrently without double-processing. Failures back
off exponentially (`10s * 2^attempts`) and land in `dead` after `max_attempts`.

**Deterministic risk scoring.** `compute_ioc_score(severity, confidence, last_seen)` is
`IMMUTABLE` and returns 0–100 from a severity weight × confidence multiplier × age decay
(floored at 0.4 so old-but-critical IOCs never fully decay).

**Search-ready.** Trigram GIN indexes on `iocs.value_norm`, `cves.description`,
`mitre_techniques.name`, and actor/malware names back `unified_search()` (Module 12's
DB half); OpenSearch handles large-scale full-text separately.

**Auditability.** `audit_log` is append-only and denormalizes `actor_email` so records
survive user deletion. `write_audit()` is the single insertion path.

## Verification status

⚠️ The migrations and `smoke_test.sql` were authored and manually reviewed but **not yet
executed against a live PostgreSQL in this session** (the sandbox DB was unavailable).
Run the two commands above to validate; `smoke_test.sql` asserts RBAC seeding, risk
scoring bounds, IOC upsert/merge, job enqueue/dequeue/complete, unified search, and
dashboard stats. Any failure raises and exits non-zero.

## ER overview

```
users ─┬─< user_roles >─ roles ─< role_permissions >─ permissions
       ├─< refresh_tokens
       ├─< api_keys
       └─< audit_log

iocs ─┬─< ioc_sightings
      ├─< ioc_relations >─ iocs
      ├──> threat_actors (actor_ids[])
      └──> malware_families (malware_ids[])

cves ──< findings >── scans ─┬─< scan_ports
                             ├─< scan_tls
                             └──> assets
scans ──> scheduled_scans
feeds ──< feed_runs
alert_rules ──< alerts ──< notifications
jobs   (standalone durable queue)
```
