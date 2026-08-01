# AGENTS.md

Aegis CTI — modular, containerized cyber-threat-intelligence platform.

## Repo map

- `services/api` — Node.js API. Fastify 4 + TypeScript (ESM), REST + GraphQL (mercurius) + WebSocket, JWT/RBAC, Postgres via `pg`, Redis via `ioredis`. Entry: `src/server.ts` (auto-runs migrations + admin seed on boot).
- `services/rust-core` — Cargo workspace (`crates/*`). Bins: `aegis-worker` (consumes `collectors`/`default` job queues), `aegis-scanner` (consumes `scanner` queue + ad-hoc CLI, lib+bin), `aegis-collectors`, `aegis-analyzer`. Libs: `aegis-common` (config/db/jobs), `aegis-ioc`, `aegis-osint`, `aegis-container`, `aegis-malware`.
- `web` — the frontend (React 18 + Vite + TS + Tailwind). Dev server on :5173 proxies `/api` and `/ws` to `localhost:8080`.
- `db/migrations/` — ordered SQL migrations (0001–0012), the single schema source of truth; also `db/migrate.sh`.
- `deploy/` — Helm chart + raw k8s manifests. `docs/DATABASE.md` documents the schema/queue design. (README links to `docs/ARCHITECTURE.md`, `SECURITY.md`, `LEGAL.md` — those files do not exist yet.)

## Commands

- API (`services/api`): `npm install && npm run dev` (tsx watch, port 8080). Verify with `npm run build` (tsc), `npm test` (vitest). Env comes from repo-root `.env` (copy `.env.example`).
- Rust (`services/rust-core`): `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`, `cargo fmt --check`. Build a single binary with `cargo build --release --bin aegis-worker` (same for `aegis-scanner`, `aegis-collectors`, `aegis-analyzer`).
- Web (`web`): `npm run typecheck`, `npm run lint`, `npm run build`.
- Full stack: `cp .env.example .env && docker compose up -d --build`. API at `:8080/api/health`, dashboard `:8080`, OpenSearch `:9200`. Rust services build ONE shared image (`ghcr.io/elder234/aegis-cti-rust`) that compiles all four binaries in a single cargo invocation (BuildKit cache mounts); compose selects the binary per service via `command: ["/usr/local/bin/aegis-<name>"]`. Never build the four as separate images — it recompiles the dep tree 4× in parallel and OOMs small VPSes.

## Gotchas

- **Node lockfiles are NOT committed** (no `package-lock.json`). Use `npm install`, never `npm ci`. `Cargo.lock` (services/rust-core) IS committed — generated with cargo 1.97; regenerate it whenever you change workspace deps (`cargo update`/`cargo generate-lockfile`).
- **API TS is ESM**: relative imports use explicit `.js` extension (`from './pool.js'`). Match this or tsx/node resolution breaks.
- **Rust builds set `SQLX_OFFLINE=true`** (Dockerfile, CI) since there is no DB at build time. Crates use runtime `sqlx::query()/query_as()` only — do NOT add compile-time `query!()`/`query_as!()` macros, which need `cargo sqlx prepare` against a live DB (see `services/rust-core/.sqlx/README.md`).
- **Adding a migration**: drop `NNNN_name.sql` into `db/migrations/`; both `db/migrate.sh` and the API's startup migration runner pick it up automatically (idempotent via `aegis.schema_migrations`). The API Dockerfile copies `db/` → `/db`.
- **All DB objects live in the `aegis` schema** (`search_path=aegis`). The `severity`/`confidence` enum declaration order is load-bearing — `upsert_ioc` merges upward via `GREATEST()` on enum ordinals.
- Auth: short-lived JWT + opaque refresh token (sha256, rotated with family-wide revocation). Access token is mirrored to `window.__aegisAccessToken` for the WS layer. Default admin seeded from `SEED_ADMIN_EMAIL`/`SEED_ADMIN_PASSWORD`.
- WebSocket endpoint: `GET /ws`; the client authenticates with a first message `{"type":"auth","token":"<jwt>"}` (never in the URL/handshake headers). Fan-out from Redis `events` channel, filtered per client by the caller's permissions.
- Job queue contract (API↔Rust): `feed.pull` → `collectors` queue (handled by `aegis-worker`); `scan.run` → `scanner` queue (handled by `aegis-scanner`). API enqueues via `aegis.*` stored procedures.

## Verification status

API (`npm run build`) and web (`typecheck`/`build`/`lint`) are verified green and API unit tests pass (43/43). Rust is still unverified — no toolchain available yet. First Rust compile may still hit dependency-version drift (e.g. rustls 0.23 / x509-parser API shapes). READMEs still carry "⚠️ RUNTIME VERIFICATION REQUIRED" markers; don't assume the full stack has run end-to-end.

## Tests

- API: unit tests are hermetic (`npm test` in `services/api`). `test/api.integration.test.ts` is skipped unless `RUN_INTEGRATION=1` with live `DATABASE_URL`/`REDIS_URL`.
- Rust: unit tests are pure logic (feed parsers, IOC normalization, port parsing, TLS/HTTP analysis): `cargo test --workspace`.
- CI (`.github/workflows/ci.yml`): api `build → test`; rust `check → test → clippy -D warnings`; web `typecheck → build → lint`; then `docker compose build`.

---

# Audit backlog (2026-07-31)

Findings from a full read-only review against a running stack. Every claim below was
verified by reading the cited file — no speculation. Line numbers are from the commit
at review time; re-grep if they have drifted.

Work these in the order given: P0 is remotely exploitable pre-auth, P1 boots insecure
by default, P2 makes the dashboard lie, P3 is a data-integrity bug.

## Resolution status

- **P0** — DONE. Datastore `ports:` removed from docker-compose.yml (`ac529bc`). Only
  `web` publishes `8080:8080`. OpenSearch security plugin is still disabled (dev mode);
  enable it before any non-dev deploy.
- **P1** — DONE. `config.ts` hard-fails on `/^change_me|^ChangeMe123!$/` when
  `NODE_ENV=production`; `SEED_ADMIN_PASSWORD` has no default. New migration
  `0013` adds `dashboard:read`.
- **P2** — DONE. Fixed in the SQL→frontend direction via `0013_align_dashboard_outputs.sql`
  (dashboard_stats now emits exactly the 10 `DashboardStats` keys incl. real
  `risk_score`/`by_severity`/`ingest_24h` aggregates; unified_search emits
  label/sub_label/rank/severity; v_attack_stats→tactic/count; v_top_sources→count/high_sev;
  v_recent_kev widened to the `Cve` shape). `SELECT *` replaced with explicit columns in
  alerts/search/dashboard/cves. `db/smoke_test.sql` asserts the full key set.
- **P3** — DONE. `malware.ts` uses `await data.toBuffer()` + a `truncated` check → 413;
  integration test posts >32 MiB and asserts no row stored.
- **P4** — DONE. `/api/health/ready` returns a bare status (detail logged server-side);
  dashboard routes + GraphQL `dashboardStats` now require `dashboard:read`; the WS hub
  authenticates via first message (no `?token=`), enforces a per-event permission filter,
  and times out unauth'd sockets.
- **P5** — DONE. `mem_limit` on every compose service; README quick-start no longer
  instructs `--build`; `SCANNER_MAX_CONCURRENCY` default lowered to 64.

## P0 — Datastores are published to 0.0.0.0

`docker-compose.yml` publishes five host ports; four should not be reachable from the
internet on a public VPS:

| Service | Line | Mapping |
|---|---|---|
| postgres | 32-33 | `5432:5432` |
| redis | 53-54 | `6379:6379` |
| opensearch | 77-78 | `9200:9200` |
| tor (SOCKS) | 204-205 | `9050:9050` |
| web | 171-174 | `8080:8080` — intended public entrypoint, keep |

Docker's short `"HOST:CONTAINER"` syntax with no IP prefix binds all interfaces. None of
these need a host port: `api` reaches all three datastores by service name over the
internal `aegis` bridge network (`api` itself is correctly `expose:`-only, line 102-103).

**Task:** delete the `ports:` entries for postgres/redis/opensearch/tor, or prefix each
with `127.0.0.1:` if host access is wanted for debugging.

**Do not rely on a host firewall here.** Docker inserts DNAT rules into the `DOCKER`
iptables chain, which bypasses a `ufw`/`nftables` INPUT policy. Closing the port in
compose is the actual fix.

Related: OpenSearch runs with the security plugin off — `plugins.security.disabled=true`
(`docker-compose.yml:71`, `deploy/k8s/opensearch.yaml:56-57`,
`deploy/helm/aegis/values.yaml:59`). With 9200 public that is unauthenticated
read/write/delete on the whole cluster. `OPENSEARCH_INITIAL_ADMIN_PASSWORD` (line 70) is
inert while the plugin is disabled. Enable security for any non-dev deploy, and treat it
as required even after the port is closed.

k8s/Helm are not affected by the port issue — no `NodePort`/`LoadBalancer` anywhere under
`deploy/`, all Services are ClusterIP.

## P1 — Placeholder secrets pass validation and boot silently

`services/api/src/config.ts` validates secret *shape* but never *value*:

- Line 25-26: `JWT_ACCESS_SECRET`/`JWT_REFRESH_SECRET` are `z.string().min(16)`.
  `change_me_access_secret` is 23 chars and `change_me_refresh_secret` is 24 — both pass
  and the app starts. A publicly-known signing key means forgeable admin tokens.
- Line 34: `SEED_ADMIN_PASSWORD: z.string().min(8).default('ChangeMe123!')` — a hardcoded
  default *inside application code*. Omit the env var entirely and the API seeds an admin
  at `admin@aegis.local` with a password published in this repo, with no warning.
- `docker-compose.yml:28,47,70` use `${VAR:-change_me_*}` shell defaults, so the
  datastores also start with placeholder passwords when `.env` is missing.
- Nothing checks `NODE_ENV === 'production'`; `NODE_ENV` itself defaults to `development`
  (`config.ts:12`).

Net effect: `git clone && docker compose up -d --build` with no `.env` edit yields public
datastores + known JWT signing key + known admin login. CI does `cp .env.example .env`, so
the placeholder set is a tested, working configuration.

**Task:** add a zod `.refine()` (or a boot-time assertion) that hard-fails when any secret
matches `/^change_me|^ChangeMe123!$/` while `NODE_ENV === 'production'`. Drop the
`.default('ChangeMe123!')` at line 34 outright — a seed admin password should have no
default. Consider raising the `min(16)` floor and rejecting low-entropy values.

Secrets *hygiene* is otherwise clean and should stay that way: no real credentials are
committed, `.gitignore:1-4` correctly excludes `.env` with a `!.env.example` negation, and
a full-history scan shows `.env` was never committed.

## P2 — Frontend types do not match what the DB returns (6 endpoints)

Root cause: types in `web/src/lib/types.ts` were transcribed from route handlers rather
than from live responses (the file header at lines 1-4 says so), and the drifted routes
are exactly the ones using `SELECT *` — nothing pins columns to types. TypeScript cannot
catch this; the mismatch is between SQL output and a hand-written interface.

**Decide the fix direction once and apply it consistently.** Renaming the SQL to match the
frontend is usually right (the UI names are better), but it means a new migration —
never edit an applied migration in place, add `0013_*.sql`. Renaming the frontend instead
is cheaper but propagates DB naming into the UI.

### P2.1 — `dashboard_stats()` — 6 of 10 fields missing (this is what the UI shows)

`aegis.dashboard_stats()` (`db/migrations/0007_procedures.sql:188-201`) returns 10 keys;
`DashboardStats` (`web/src/lib/types.ts:108-119`) declares 10; **only 4 overlap**
(`iocs_active`, `cves_kev`, `alerts_open`, `scans_running`).

Frontend expects but DB never returns: `iocs_total`, `feeds_healthy`, `feeds_total`,
`risk_score`, `by_severity`, `ingest_24h`.

DB returns but frontend ignores: `iocs_critical`, `cves_total`, `alerts_critical`,
`findings_open`, `feeds_enabled`, `jobs_pending`.

Visible symptoms: `Feeds healthy` renders `undefined/undefined` (`Dashboard.tsx:94`),
`Ingest 24h` blank (`:107`), risk gauge always `0/100` because `Dashboard.tsx:56` falls
back to `?? 0`, and the severity panel always shows the "No active indicators" empty state
(`:151`) even with 15k+ indicators loaded. **A SOC dashboard that always reports zero risk
is worse than one that errors** — it looks authoritative while conveying nothing.

Note `feeds_enabled` is the intended source for `feeds_healthy`/`feeds_total`, so part of
this is rename-drift rather than genuinely absent data. `risk_score`, `by_severity`, and
`ingest_24h` have no source at all and need real aggregate SQL written.

**Also fix the test that missed this:** `db/smoke_test.sql:57-59` asserts only that
`iocs_active` and `jobs_pending` exist — both in the matching set. Assert the full key set
the frontend consumes.

### P2.2 — `v_attack_stats` — 3 of 3 field names wrong

`AttackStat` (`types.ts:128-132`) declares `tactic`, `technique`, `count`. The view
(`db/migrations/0008_views.sql:22`) produces `tactic_id`, `tactic_name`, `ioc_count` —
zero overlap. `technique` has no source column anywhere; the view aggregates at tactic
level only, so decide whether to add it or drop it from the type.

Runtime effect, not just types: `Dashboard.tsx:216` sorts on `b.count - a.count` → `NaN`
for every row; `:226`/`:230` bind `dataKey="tactic"`/`dataKey="count"` → the ATT&CK chart
renders empty bars with blank axis labels.

### P2.3 — `unified_search` — 3 of 6 field names wrong

`SearchResult` (`types.ts:139-146`) vs `RETURNS TABLE` at
`db/migrations/0007_procedures.sql:159-161`: `label`→`title`, `sub_label`→`subtitle`,
`rank`→`score`. `severity` is declared but never produced. `entity_type`/`entity_id` match.

Effect: `Search.tsx:90` renders `{r.label}` → blank row text; `:91` guards `r.sub_label`
→ subtitles never render; `:89` guards `r.severity` → severity chips never render.

### P2.4 — `v_top_sources` — `count` vs `total`

`TopSource.count` (`types.ts:136`) vs view column `total` (`0008_views.sql:31`). View also
returns `high_sev` (`:32`), undeclared in the type.

### P2.5 — `v_recent_kev` — partial shape

`cves.recentKev()` (`web/src/lib/api.ts:189`) claims `Cve[]`, but the view
(`0008_views.sql:40-41`) returns only `cve_id`, `cvss_v31_score`, `epss_score`,
`kev_added_at`, `kev_ransomware`, `summary`. Missing vs `Cve` (`types.ts:57-67`):
`description` (view aliases it to `summary`), `cvss_v31_severity`, `epss_percentile`,
`kev`, `published_at`. Either widen the view or give the endpoint its own narrower type.

### P2.6 — `Alert.summary` has no matching column

`Alerts.tsx:78` renders `{alert.summary}`; `Alert.summary` (`types.ts:77`) has no column
in the alerts table — it is `body`. `alerts.ts:26` uses `SELECT *`, so the field is simply
absent at runtime.

**Guard against regression:** after fixing, replace `SELECT *` in `alerts.ts:26`,
`search.ts:30`, `dashboard.ts:26`, `dashboard.ts:33`, `cves.ts:62` with explicit column
lists. The routes that already do this (`iocs`, `rules`, `feeds`, `scans`, `channels`,
`alertRules`, `container`, `malware`, `auth.login`, `dashboard.timeline`) were all
verified clean — explicit columns are why.

## P3 — Malware upload silently truncates at 32 MiB and stores a wrong hash

`services/api/src/routes/malware.ts:66-68` consumes the multipart stream by hand:

```ts
for await (const chunk of data.file) { chunks.push(chunk); }
```

`@fastify/multipart` has `throwFileSizeLimit: true` by default, but on overflow its
`onError` only stashes the error — it does not throw and does not destroy the stream. The
error surfaces solely via `toBuffer()` or the next `parts` iteration, and this route uses
neither. Busboy truncates at the limit and ends the stream normally, so the loop completes
without error and `data.file.truncated` is never checked.

Result: a >32 MiB upload is silently truncated to exactly 32 MiB, then hashed and
persisted as if complete. The `sha256` written at `malware.ts:112` (unique-indexed at
`db/migrations/0012_malware_samples.sql:35`) is **the hash of a 32 MiB prefix, not of the
sample**. For a threat-intel tool this is an evidentiary-integrity failure: the registry
asserts a hash matching no real artifact, and reputation lookups keyed on it will miss.

**Task:** use `await data.toBuffer()` (which re-throws `RequestFileTooLargeError`), or
check `data.file.truncated` after the loop and return 413. Add a test that posts >32 MiB
and asserts a 413 rather than a stored row.

Both `malware.ts:16` and `aegis-analyzer/src/main.rs:14` carry
`⚠️ RUNTIME VERIFICATION REQUIRED` markers — this is exactly the class of bug they predict.

Not a vulnerability, but worth knowing: uploads are buffered fully in memory
(`malware.ts:64-69`, forwarded at `:78-82`, never written to disk — no `writeFile`/
`createWriteStream`/`saveRequestFiles` anywhere in the module, so the "never touches disk"
design claim holds and the filename is not a traversal sink). On a 4 GB box concurrent
32 MiB uploads are a memory-pressure vector; `RATE_LIMIT_MAX=300` is the only throttle.
There is also no MIME/extension validation — arguably correct for a malware endpoint, and
the route is gated by `requirePerms('malware:run')` (`malware.ts:58`).

## P4 — Hardening gaps in an otherwise solid auth layer

State this plainly so nobody "fixes" what isn't broken: **all 20 state-mutating routes
carry permission guards** (real RBAC via `requirePerms`, not bare authentication), JWT
signature and expiry are genuinely verified (`plugins/auth.ts:39` → `req.jwtVerify()`;
no `decode()`-instead-of-verify anywhere), claims are loaded server-side from
`aegis.user_permissions()` (`lib/auth.ts:40-62`) rather than trusted from the token,
passwords are Argon2id with lockout after 5 failures, refresh tokens are stored as SHA-256
hashes and rotated with family-wide revocation on reuse detection
(`routes/auth.ts:84-93`), and `config.ts:46-51` fails fast rather than falling back. Every
permission string used in a guard exists in the migrations — no typo'd guard silently
passing. Do not "simplify" any of this.

Remaining gaps:

- **`/api/health/ready` is public and leaks internals** (`routes/health.ts:15-32`). Returns
  `{ ok: false, error: err.message }` per dependency (`:27`); Postgres/Redis driver errors
  carry internal hostnames, ports, and DB names. Latency values (`:25`) are an
  unauthenticated health oracle. `/api/health` being public is fine; this is a different
  route. Return a bare status + HTTP code, log detail server-side.
- **Dashboard routes check authentication but no permission**
  (`routes/dashboard.ts:8,15,24,31`) — the only data reads using bare `app.authenticate`.
  Any authenticated user gets aggregate counts plus 200 rows of threat timeline including
  titles (`:18`). Same gap in GraphQL at `graphql/index.ts:116-117`, where `dashboardStats`
  checks only `ctx.user` while every sibling resolver calls `requirePerm`. Add a
  `dashboard:read` code.
- **WebSocket has no per-client filtering and takes the token in the query string**
  (`ws/hub.ts:25-48`). Signature/expiry are verified correctly at `:36`, but any valid
  token receives the full Redis `events` broadcast (`:19-23`) — a `viewer` sees what an
  admin sees. `?token=` (`:28`) risks the JWT landing in proxy/access logs; note
  `app.ts:41` redacts the `authorization` header but not query strings.

## P5 — Stack does not fit 4 GB as configured

- **No memory limits on any compose service.** A grep for `mem_limit|deploy:|resources`
  returns only Redis's internal `--maxmemory 512mb` (`docker-compose.yml:49-50`), which is
  an eviction policy, not a container limit. Any container can consume all host RAM and
  trigger the OOM killer against an arbitrary victim.
- **Helm requests total exactly 3.0 GiB**, limits 7.375 GiB (`values.yaml:22-158`,
  counting `replicas: 2` for api and web). On a 4 GB box that leaves ~1 GB for kernel,
  sshd, dockerd, and page cache.
- **OpenSearch heap is locked in RAM**: `-Xms512m -Xmx512m` (`docker-compose.yml:69`) with
  `bootstrap.memory_lock=true` (`:68`) and `memlock: -1` (`:73`). Real RSS runs well above
  heap once metaspace, thread stacks, and Lucene mmap are counted.
- **`codegen-units = 1`** (`services/rust-core/Cargo.toml:48-52`) maximizes peak linker
  memory across 9 workspace crates — the most memory-hungry release setting available.

Mitigation already in place: every service names a prebuilt `ghcr.io/elder234/aegis-cti-*`
image, so plain `docker compose up -d` **pulls instead of compiling**. But
`README.md:84` and the compose header both instruct `--build`, which is the worst case.

**Task:** add memory limits to every compose service; change the README quick-start to
omit `--build` for VPS deploys (build in CI, pull on the box). If building on-box is
unavoidable, add swap first and relax `codegen-units`. Also review the unconstrained
defaults `SCANNER_MAX_CONCURRENCY=512`, `SCANNER_RATE_PPS=2000`, `WORKER_CONCURRENCY=8`
(`.env.example:54-56`) for a shared 4 GB host.

## Ground rules for whoever picks this up

- **Verify before changing.** Line numbers drift; re-grep the symbol rather than trusting
  the number. If a finding no longer reproduces, say so instead of "fixing" it blind.
- **Never edit an applied migration.** Schema changes go in a new `NNNN_*.sql`.
- **Do not weaken the auth layer** while touching adjacent code — see P4 for what is
  already correct.
- **P2 needs one decision applied uniformly** (rename SQL vs rename frontend). Do not fix
  half the endpoints one way and half the other.
- Rust remains unverified end-to-end (see Verification status above); a first compile may
  surface dependency drift unrelated to anything here.
