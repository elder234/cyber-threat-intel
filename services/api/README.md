# Aegis API (Module 15)

Fastify (Node 20, ESM, TypeScript) API providing REST + GraphQL + WebSockets,
JWT auth with refresh-token rotation, RBAC, Redis-backed rate limiting & caching,
audit logging, and OpenAPI docs.

## Run

```bash
cd services/api
npm install
npm run migrate          # applies db/migrations + seeds admin
npm run dev              # http://localhost:8080  (docs at /api/docs)
```

Environment comes from the repo-root `.env` (see `.env.example`). In Docker the
API self-migrates on boot (`server.ts` → `runMigrations()` → `seedAdmin()`).

## Surface

| Area | Endpoints |
|------|-----------|
| Auth | `POST /api/auth/login`, `/refresh`, `/logout`, `GET /api/auth/me` |
| IOCs | `GET/POST /api/iocs`, `GET/DELETE /api/iocs/:id` |
| CVEs | `GET /api/cves`, `/api/cves/:id`, `/api/cves/kev/recent` |
| Search | `GET /api/search?q=` (unified) |
| Dashboard | `GET /api/dashboard/{stats,timeline,attack-matrix,top-sources}` |
| Alerts | `GET /api/alerts`, `POST /api/alerts/:id/{ack,resolve}` |
| Feeds | `GET /api/feeds`, `/:id/runs`, `POST /:id/sync` |
| Scans | `GET/POST /api/scans`, `GET /api/scans/:id` |
| System | `GET /api/health`, `/api/health/ready` |
| GraphQL | `POST /api/graphql` (GraphiQL in dev) |
| WebSocket | `GET /ws` — auth via first message `{"type":"auth","token":<jwt>}` |

## Security design

- **Passwords**: argon2id (`memoryCost 19456, timeCost 2`).
- **Access tokens**: short-lived JWT (15m default) with `roles` + flattened `perms`.
- **Refresh tokens**: opaque, stored as sha256, rotated on every use. Presenting a
  already-revoked token triggers **family-wide revocation** (reuse detection).
- **RBAC**: `requirePerms('ioc:write', …)` guards check the caller holds *all* listed
  permission codes; permissions are resolved from `aegis.user_permissions()`.
- **Lockout**: 5 failed logins → 15-minute account lock.
- **Rate limiting**: Redis sliding window, keyed by user id (falls back to IP).
- **Audit**: every state-changing action writes to `aegis.audit_log` via `write_audit()`.
- **Authorization gate**: scans against a registered asset require `is_authorized = true`.

## Tests

```bash
npm test                                  # unit tests (no DB)
RUN_INTEGRATION=1 DATABASE_URL=... REDIS_URL=... npm test   # + integration
```

- `test/auth.unit.test.ts` — pure crypto/token helpers, hermetic.
- `test/api.integration.test.ts` — full login→RBAC→IOC→search flow via
  `app.inject()`. **Skipped unless `RUN_INTEGRATION=1`** and a live Postgres+Redis
  are provided.

## ⚠️ Runtime verification status

This module was authored and self-reviewed but **not yet compiled or executed** in
this session — the sandbox VM was unavailable (no Node/Postgres/Redis). Before
production use, run the following once the environment is available and fix any
issues surfaced:

```bash
cd services/api
npm install
npx tsc --noEmit          # typecheck
npm test                  # unit
RUN_INTEGRATION=1 DATABASE_URL=postgres://... REDIS_URL=redis://... npm test
```

Known items to confirm at first run: `@fastify/*` peer-version alignment with
Fastify 4, Mercurius context typing, and the `ioredis` rate-limit store option
shape. These are standard integrations but unverified here.
