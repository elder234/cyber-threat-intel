# Aegis CTI — Security Assessment

**Date:** 2026-09-23
**Scope:** full read-only source review + dependency/advisory verification (read-only),
**Method:** code reading against `file:line`, OWASP Top 10:2025, STRIDE, red-team
narratives, and web-verified vendor advisories. Runtime-only behaviors are flagged
(per `AGENTS.md`, the stack has not run end-to-end — see Verification below).
_Treat the prior AGENTS.md audit backlog as untrusted history; it was independently re-verified._

## Executive summary

| ID | Severity | Finding | Status |
|---|---|---|---|
| H1 | High | Recognized placeholder secrets ship in every default deploy path; placeholder guard is disabled by the default `NODE_ENV=development` | **Recommended** — rotate secrets, set `NODE_ENV=production`, enforce Cloudflare Access |
| H2 | High | Pre-auth login rate-limit bypass via XFF spoofing + `@fastify/rate-limit` <11.2.0 (CVE-2026-15144); account-lockout DoS | **Fixed (edge)** — nginx now forwards only a trusted client IP; **Recommended** — fastify v5 upgrade path |
| H3 | Medium-High | SSRF across the internal `aegis` bridge from scanner/API (no private-IP filter, TLS verify-off) | **Fixed (fetch)** — SSRF blocklist in `web/fetch.rs`; **Recommended** — network isolation + deny metadata |
| M4 | Medium | Alert-rule regex ReDoS freezes the whole API event loop (analyst-triggerable) | **Recommended** — regex budget + engine out-of-process |
| M5 | Medium | Node 20 (`node:20-alpine`) EOL 2026-04-30; rustls 0.23.43 in vulnerable range (RUSTSEC-2026-0285) | **Fixed (images)** — `node:22-alpine`; **Recommended** — `cargo update -p rustls` |
| M6 | Medium | No CSP + tokens in `localStorage`/`window` (single XSS = session theft); Swagger UI public | **Fixed (CSP)** on SPA responses; **Recommended** — watchdog token model |
| L7 | Low | OpenSearch 2.13.0 CVE-2025-9624 (latent — API doesn't query it yet); nginx 1.27-alpine; nodemailer CVE-2025-14874; pcap 256 MiB vs analyzer 192 MiB mismatch; no security-event alerting | **Fixed (nginx tag)** ; **Recommended** — remainder |

## Findings

### H1 — Recognized placeholder secrets load in all default deploy paths
- `deploy/k8s/secrets.yaml:24-28` commits `JWT_ACCESS_SECRET=change_me_access_secret`,
  `JWT_REFRESH_SECRET=change_me_refresh_secret`, `SEED_ADMIN_PASSWORD=ChangeMe123!`.
- `services/api/src/config.ts:51` only hard-fails on placeholders when `NODE_ENV === 'production'`.
- `deploy/k8s/configmap.yaml:9` sets `NODE_ENV: "development"` → guard off **and**
  GraphiQL on (`services/api/src/graphql/index.ts:155` `graphiql: !config.isProd`).
  Swagger UI is registered unconditionally (`app.ts:84`).
- `docker-compose.yml` api uses `env_file: [.env]` (`:115`); `.env.example` ships the same
  placeholders and `NODE_ENV=development`.
- `SEED_ADMIN_PASSWORD` no longer has a default (`config.ts:37`, `.min(8)` only), but the
  seed credentials + signing keys remain public unless rotated.
- Boundary: Cloudflare Tunnel is the sole entry; Cloudflare Access is *recommended* only
  (`docker-compose.yml:211-213`) — not enforced.

**Fix in this review (config/deploy):** operator actions, see Remediation R1/R2.

### H2 — Pre-auth rate-limit bypass via X-Forwarded-For
- `app.ts:47` `trustProxy: true` → `req.ip` = leftmost XFF value.
- `web/nginx.conf` previously appended client-controlled XFF (`$proxy_add_x_forwarded_for`).
- `app.ts:61` `keyGenerator: (req) => req.user?.sub ?? req.ip` → anonymous requests keyed on the
  spoofable IP.
- `@fastify/rate-limit ^9.1.0` is below **CVE-2026-15144** (<11.2.0), which the advisory
  fixes by keying buckets on a normalized, trust-resolved client IP. Sources: GHSA,
  @fastify/rate-limit advisory.

**Fix applied:** `web/nginx.conf` now derives the trusted client IP once
(`$real_client_ip` = Cloudflare `cf-connecting-ip`, else `$remote_addr`) and forwards only
that as `X-Forwarded-For`/`X-Real-IP` to `/api` and `/ws`. The client-supplied header is
ignored. This neutralizes the pre-auth vector regardless of plugin version.

**Still recommended:** the durable fix is fastify v5 + `@fastify/rate-limit >= 11.2.0`
(note: do the upgrade in a branch — v11 is a fastify-v5-line release, and the project must
be tested before landing).

### H3 — SSRF across the internal bridge from scanner/API
- `scanner/src/web/fetch.rs` had no private-IP/169.254.169.254 filter, followed unrestricted
  redirects, `danger_accept_invalid_certs(true)`.
- All containers share the `aegis` bridge; postgres:5432, redis:6379, opensearch:9200,
  analyzer:7000, tor:9050, the DOCKER bridge gateway, and VPS cloud metadata are reachable
  from the scanner container. No egress/NSP exists.
- Targets are operator-supplied via `scan:run` + `assets.is_authorized` (`exposure.ts`,
  `scans.ts`) — any compromised `analyst` account becomes a full internal scanner.
- Notification webhooks (`lib/notify/dispatch.ts` → `postJson`) POST to operator-supplied URLs → SSRF from the API container.

**Fix applied:** `scanner/src/web/fetch.rs` — an SSRF blocklist (`is_blocked_ip`) always
refuses loopback, link-local (metadata), unspecified, broadcast, IPv4-mapped, and IPv6
unique-local targets; RFC1918 is refused unless `SCANNER_ALLOW_PRIVATE=1` (authorized
internal testing). Redirects are followed manually (bounded, ≤5 hops) with **each hop
re-validated**. `.env.example` documents the opt-in.

**Still recommended:** R3 (network isolation, resolve-then-connect, tighten
`danger_accept_invalid_certs`).

### M4 — Alert-rule regex ReDoS freezes the whole API
`alerts/match.ts:60` builds `new RegExp(c.value_regex, 'i')`; `alerts/engine.ts:87-92`
runs `matchRule()` synchronously inside the API process on every event. A catastrophic
rule (e.g. `^(a+)+$`) + a long event value blocks the event loop → **entire API down**,
alerts stop. Any `alert:manage` user (analyst-level) can trigger it, and can inflate
severities for alert fatigue.

Remediation: budget regex evaluation (size + time) or reject complex patterns; run the
engine as its own process (currently in-process via `server.ts`).

### M5 — EOL/affected runtime + TLS stacks
- `node:20-alpine` in `services/api/Dockerfile` + `web/Dockerfile` — Node 20 EOL
  **2026-04-30**, no further security patches. → **Fixed:** `node:22-alpine`.
- `services/rust-core/Cargo.lock:1942` — `rustls 0.23.43` inside affected range
  (≥0.23.13, <0.23.45) for **RUSTSEC-2026-0285** (TLS 1.3 handshake packets shipped
  before the encryption boundary). Fix: `cargo update -p rustls` (CI-verified).
- `sqlx 0.7.4` is at the patched version for RUSTSEC-2024-0363 — not affected.

### M6 — CSP absent; tokens survivable by one XSS
- `app.ts:54` `helmet, { contentSecurityPolicy: false }`; nginx shipped no CSP.
- Refresh bearer in `localStorage` (`web/src/lib/api.ts`), access token mirrored to
  `window.__aegisAccessToken` — one XSS or a poisoned dependency persists a session.
  No `dangerouslySetInnerHTML` exists today, but defense-in-depth is missing.

**Fix applied:** strict CSP on the SPA (`web/nginx.conf`, `location /`), scoped so the
Swagger UI and WS upgrade are unaffected. **Still recommended:** move refresh-token
handling to a same-origin HttpOnly cookie.

### L7 — Lower priority
- `opensearchproject/opensearch:2.13.0` — **CVE-2025-9624** (complex `query_string` DoS,
  <2.19.4). **Latent:** AGENTS F1 confirms no API component queries OpenSearch yet and it
  is profiled out of default compose; k8s runs it secured. Upgrade before wiring the API
  search to it.
- `web/Dockerfile` `nginx:1.27-alpine` below the rewrite-module fix (**CVE-2026-9256**,
  fixed in 1.28.3). **Fixed:** `nginx:1.28-alpine`.
- `nodemailer ^6.9.14` — **CVE-2025-14874** (addressparser infinite recursion DoS, fixed
  7.0.11). Only reachable if the SMTP channel is configured with attacker-influenced
  recipient headers (unlikely) — bump.
- `pcaps.ts` allows up to 256 MiB then base64 (+~33%) vs analyzer
  `ANALYZER_MAX_BYTES=201326592` (192 MiB) → mid-size uploads 500/502. Align the limits.
- No security-event alerting: failed logins, lockouts, permission denials, WS auth
  failures, scan target anomalies are logged/audited but not surfaced.

## Dependency / image advisory matrix (verified 2026-09-23)

| Component | Pin | Advisory | Verdict |
|---|---|---|---|
| fastify | `^4.28.1` | CVE-2025-32442 (content-type validation bypass <4.29.1) | In range; vulnerable pattern unused → Low |
| @fastify/rate-limit | `^9.1.0` | **CVE-2026-15144** (<11.2.0) | Affected (edge-fixed in nginx) |
| mercurius | `^14.1.0` | CVE-2025-64166 (CSRF, fixed 16.4.0) | Affected; mitigated by Bearer (non-cookie) auth |
| vite | `5.4.5` | CVE-2024-45811, CVE-2025-24010, CVE-2025-30208, CVE-2025-31486, CVE-2025-46565 | Dev-server only; binds 127.0.0.1 → Low |
| nodemailer | `^6.9.14` | **CVE-2025-14874** (fixed 7.0.11) | Affected (low-reach) |
| ioredis | `^5.4.1` | fixed 4.27.8 | Clean |
| argon2 npm | latest | none found | Clean |
| rustls | `0.23.43` | **RUSTSEC-2026-0285** | Affected → `cargo update -p rustls` |
| sqlx | `0.7.4` | RUSTSEC-2024-0363 (patched 0.7.4) | Clean |
| reqwest | `0.12.28` | none found | Clean |
| opensearch | `2.13.0` | **CVE-2025-9624** (<2.19.4) | Affected but latent (unconnected) |
| node | `20-alpine` | EOL line | **EOL 2026-04-30** — migrated to 22 |
| nginx | `1.27-alpine` | **CVE-2026-9256** (fixed 1.28.3) | migrated to 1.28-alpine |

## OWASP Top 10:2025 mapping

| 2025 | Assessment |
|---|---|
| A01 Broken Access Control | Strong: RBAC guards everywhere (incl. mutations), WS per-event filter, `is_authorized` gate for scans. Remaining: `/api/health/ready` probe names, public Swagger inventory. |
| A02 Security Misconfiguration | Worst cluster: `NODE_ENV=development` default (GraphiQL ON, placeholder guard OFF), CSP absent (now fixed), OpenSearch posture divergence, write-downed swagger. |
| A03 Software Supply Chain | No Node lockfile, `npm install` builds (non-reproducible), no `npm audit`/`cargo audit` in CI, EOL Node (fixed), affected rate-limit/mercurius/rustls, unpinned images. |
| A04 Cryptographic Failures | Argon2id good; OpenSearch TLS enabled on k8s/Helm (F1); plaintext internal bridge acceptable. Minor. |
| A05 Injection | No SQL/XSS found (all parameterized); **ReDoS via alert-rule regex = pattern-injection class** (M4). |
| A06 Insecure Design | Regex engine without budget; unbounded GraphQL queries (no depth/cost); pre-auth rate-limit keyed on spoofable value (edge-fixed); MFA omitted. |
| A07 Authentication Failures | Placeholder admin + signing keys (H1); MFA absent; token storage model (M6). |
| A08 Data Integrity Failures | Strong post-F3: explicit columns, upload hash integrity, dedupe. Supply-chain gaps above. |
| A09 Logging & Monitoring | Strong logging (pino redaction, `aegis.write_audit`); **no security-event alerting** (see L7). |
| A10 Exception Handling | Uniform error handler masks 5xx (good); `/health/ready` fixed to bare status (verified `health.ts:19-37`). |

## STRIDE (per data flow)

- **Internet → cloudflared → nginx**: Spoof (H2 — edge-fixed); Tampering (HSTS on); Repudiation (none).
- **nginx → Fastify API**: Spoof (resolved via `$real_client_ip`); Info discl. (Swagger pre-auth).
- **API → PG/Redis**: Tampering (none — parameterized); Elevation (schema objects are app-owned; row-level access rests on app-layer perms — acceptable, keep).
- **API → alert engine → webhook/email/telegram**: Spoof (SSRF via operator-supplied channel URLs); DoS (M4).
- **API → Redis queue → scanner → internet**: Spoof/Elevation — operator accounts drive internal scans (H3, fetch-side fixed; network isolation still recommended).
- **Collectors → feeds/darkweb**: Info discl./Repudiation — darkweb is Tor-only fail-closed with redaction.
- **Analyzer (HTTP-internal)**: DoS — uploads capped + 413; in-memory only.
- **WS hub → browser**: Spoof (first-message auth, verified); Info discl. (per-event perm filter present).
- **Config/startup**: Elevation — the entire H1 chain.

## Red-team narratives (in order of likelihood)

1. **The default deploy.** `git clone → cp .env.example .env → compose up` + a routed tunnel
   without Cloudflare Access → log in as `admin@aegis.local`/`ChangeMe123!`, or forge JWTs
   with `change_me_access_secret` → full platform takeover (read/destroy IOC evidence,
   disable alerts, launch internal scans, plant false intel).
2. **Lockout + stuffing.** Rotate `X-Forwarded-For` (pre-fix) → bypass the per-IP bucket,
   then lock out every account via the 5-fail/15-min lockout, or credential-stuff a target
   across lockout windows. No MFA makes low-entropy passwords crackable over time.
3. **Analyst-powered DoS.** `alert:manage` → catastrophic `value_regex` (`^(a+)+$`) → a single
   matching event freezes the API event loop (M4).
4. **Tunnel-ward SSRF.** Compromised/scoped operator is all it takes (pre-fix): point a
   `url`-kind authorized asset at `http://redis:6379`, the bridge gateway, or
   `169.254.169.254` — scanner reads internal services with cert validation off. Webhook
   channel URL → API-side SSRF (still open; gate by egress).
5. **XSS → token.** Any future rendering bug or poisoned dependency exfiltrates
   `aegis.refresh`/`window.__aegisAccessToken` (M6) — no CSP (now added) to blunt it.

## Verified-good controls (do not weaken)

- Argon2id (19,456/2) + account lockout (5 fails/15 min); refresh ≤48-byte random, SHA-256
  at rest, rotation + reuse detection (`routes/auth.ts:84-93`); server-side permissions via
  `aegis.user_permissions()` (claims never trusted from token).
- Every state-mutating route `requirePerms`-gated; permission strings all exist in migrations.
- WS authenticates via first message, filters per event (`EVENT_PERM`), times out unauth'd.
- SQL fully parameterized (REST + GraphQL); `func` objects `SELECT *` eliminated (F3).
- Uploads (malware/pcap/video) buffered in memory only, never persisted; 413 truncation
  check (P3); raw bytes never stored or forwarded.
- Darkweb collector: Tor-only, fail-closed, redacted snippets, dedupe.
- ffprobe/DAST invoked via `Command` arg-arrays (no shell).
- `web/nginx.conf` security headers; pino log redaction of `authorization`/`cookie`.
- Zero host ports in compose (`expose:`-only), egress-only VPS + tunnel design.

## Remediation plan

### Applied in this review (verify via CI before deploy)
- **R-A (H2)** `web/nginx.conf` — overwrite `X-Forwarded-For` with trusted `$real_client_ip`
  (cf-connecting-ip else remote_addr) on `/api` and `/ws`.
- **R-B (M6)** `web/nginx.conf` — strict CSP on SPA responses (`location /`), scoped away
  from `/api/docs` and `/ws`.
- **R-C (H3)** `services/rust-core/crates/aegis-scanner/src/web/fetch.rs` — SSRF blocklist
  + manual per-hop redirect validation; RFC1918 opt-in via `SCANNER_ALLOW_PRIVATE` (default 0).
- **R-D (M5/L7)** Dockerfiles → `node:22-alpine`; nginx `1.28-alpine`. `.env.example`
  documents `SCANNER_ALLOW_PRIVATE`.

### Required next actions (operator)
1. **R1 (H1)** Rotate all secrets in `.env`/k8s (`openssl rand -hex 48`); set
   `NODE_ENV=production` in `deploy/k8s/configmap.yaml` and `.env.example`; consider
   hard-failing placeholders regardless of `NODE_ENV`.
2. **R2 (H1)** Create/enforce the Cloudflare Access application (email/mTLS/SSO) in front
   of the tunnel (document in README + `config.yml.example`).
3. **R3 (H3)** Put the scanner/collector on a dedicated network with an NSP/firewall that
   only permits outbound internet (no access to `aegis` datastores or the host metadata);
   make `danger_accept_invalid_certs` a config flag.
4. **R4 (M4)** Budget/constrain `value_regex` (reject catastrophic patterns, cap input
   size); consider running the alert engine out-of-process.
5. **R5 (deps)** `cargo update -p rustls`; add `cargo audit` + `npm audit` (drop
   `--no-audit`) to CI; upgrade fastify→v5 + `@fastify/rate-limit ≥11.2.0` on a branch and
   test; bump `nodemailer`/`vite`; pin container image digests.
6. **R6 (web)** Migrate the refresh token to a same-origin HttpOnly cookie; keep the
   `window.__aegisAccessToken` mirror out of the hot path.
7. **R7 (ops)** Wire security-event alerting (failed logins, lockouts, 403s, scan anomalies);
   align pcap upload limit with `ANALYZER_MAX_BYTES`; upgrade OpenSearch ≥2.19.4 before any
   API integration.

## Open questions (answers change severity)

1. Live deploy: compose+cloudflared on one VPS, or k8s? Is the tunnel the only public entry
   and is Cloudflare Access actually enforced?
2. Are `JWT_*`/`SEED_ADMIN_PASSWORD` genuinely rotated in the running environment, and is
   `NODE_ENV=production` set at the deployed rings?
3. Are there real low-privilege `analyst`/`viewer` accounts, or is this single-operator?
   (H3/M4 assume non-admin roles exist.)
4. Is there any egress control on the `aegis` bridge / does host metadata exposure matter here?
5. Is OpenSearch going to be wired to the API (currently nothing queries it)?
6. Is MFA in scope for operators?

## Verification required

The patches in this review were written to the working tree and manually code-reviewed, but
no toolchain is available in the review environment. Before merge/deploy, run the project
gates: `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`,
`cargo fmt --check` (Rust fetch patch), `npm run build && npm test` (API),
`npm run typecheck && npm run lint && npm run build` (web); and smoke-test the SPA loads
under the new CSP (Swagger UI must keep working — it is deliberately excluded).