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
- Full stack: `cp .env.example .env && docker compose up -d --build`. API at `:8080/api/health`, dashboard `:8080`, OpenSearch `:9200`. Rust services use one multi-binary Dockerfile: `docker build --build-arg BIN=aegis-<name> ...`.

## Gotchas

- **No lockfiles are committed** (no `package-lock.json`, no `Cargo.lock`). Use `npm install`, never `npm ci`.
- **API TS is ESM**: relative imports use explicit `.js` extension (`from './pool.js'`). Match this or tsx/node resolution breaks.
- **Rust builds set `SQLX_OFFLINE=true`** (Dockerfile, CI) since there is no DB at build time. Crates use runtime `sqlx::query()/query_as()` only — do NOT add compile-time `query!()`/`query_as!()` macros, which need `cargo sqlx prepare` against a live DB (see `services/rust-core/.sqlx/README.md`).
- **Adding a migration**: drop `NNNN_name.sql` into `db/migrations/`; both `db/migrate.sh` and the API's startup migration runner pick it up automatically (idempotent via `aegis.schema_migrations`). The API Dockerfile copies `db/` → `/db`.
- **All DB objects live in the `aegis` schema** (`search_path=aegis`). The `severity`/`confidence` enum declaration order is load-bearing — `upsert_ioc` merges upward via `GREATEST()` on enum ordinals.
- Auth: short-lived JWT + opaque refresh token (sha256, rotated with family-wide revocation). Access token is mirrored to `window.__aegisAccessToken` for the WS layer. Default admin seeded from `SEED_ADMIN_EMAIL`/`SEED_ADMIN_PASSWORD`.
- WebSocket endpoint: `GET /ws?token=<jwt>`, fan-out from Redis `events` channel.
- Job queue contract (API↔Rust): `feed.pull` → `collectors` queue (handled by `aegis-worker`); `scan.run` → `scanner` queue (handled by `aegis-scanner`). API enqueues via `aegis.*` stored procedures.

## Verification status

API (`npm run build`) and web (`typecheck`/`build`/`lint`) are verified green and API unit tests pass (43/43). Rust is still unverified — no toolchain available yet. First Rust compile may still hit dependency-version drift (e.g. rustls 0.23 / x509-parser API shapes). READMEs still carry "⚠️ RUNTIME VERIFICATION REQUIRED" markers; don't assume the full stack has run end-to-end.

## Tests

- API: unit tests are hermetic (`npm test` in `services/api`). `test/api.integration.test.ts` is skipped unless `RUN_INTEGRATION=1` with live `DATABASE_URL`/`REDIS_URL`.
- Rust: unit tests are pure logic (feed parsers, IOC normalization, port parsing, TLS/HTTP analysis): `cargo test --workspace`.
- CI (`.github/workflows/ci.yml`): api `build → test`; rust `check → test → clippy -D warnings`; web `typecheck → build → lint`; then `docker compose build`.
