# Aegis Rust Core (`services/rust-core`)

High-performance Rust workspace for the Aegis CTI platform: threat-feed
collectors, IOC processing, background workers, and the vulnerability scanner.

> ⚠️ **Runtime verification status.** This workspace was authored while the build
> VM was unavailable, so it has **not** been compiled or executed. Pure logic
> (IOC normalization, feed parsers, port-spec parsing, service/banner
> identification, HTTP header analysis, TLS cert analysis) ships with unit tests
> intended to run under `cargo test`. Network/DB paths are structured for
> `cargo run` + integration testing once the VM is restored. See the verification
> checklist below.

## Crates

| Crate | Kind | Responsibility |
|-------|------|----------------|
| `aegis-common` | lib | Config, sqlx pool (search_path=aegis), telemetry, durable `JobQueue` wrapping the `aegis.*` stored procedures |
| `aegis-ioc` | lib | IOC type detection, defang/refang, normalization (pure, unit-tested) |
| `aegis-collectors` | lib | Public feed collectors: CISA KEV, EPSS, URLhaus, Feodo. Pure parsers + DB sink helpers |
| `aegis-worker` | bin | Job-loop consumer for `collectors`/`default` queues; dispatches `feed.pull`, `ioc.enrich` |
| `aegis-scanner` | lib+bin | Async TCP scanner, service ID, HTTP header audit, TLS cert inspection; worker for the `scanner` queue + ad-hoc CLI |

## Job / queue contract (shared with the Node API)

| Job kind | Queue | Enqueued by | Handled by |
|----------|-------|-------------|------------|
| `feed.pull` | `collectors` | API `POST /api/feeds/:id/sync` | `aegis-worker` |
| `scan.run` | `scanner` | API `POST /api/scans` | `aegis-scanner` |
| `ioc.enrich` | `default` | (future OSINT pipeline) | `aegis-worker` (stub) |

`feed.pull` payload: `{ "feed_id": "<uuid>", "provider": "cisa_kev" }` (also
accepts `slug`). `scan.run` payload: `{ "scan_id", "target", "asset_id"?,
"profile": { "ports": "top100" } }`.

## Security & legal constraints (enforced in code)

- **Scanner authorization gate.** `aegis-scanner` refuses to scan a registered
  asset unless `aegis.assets.is_authorized = true`. Ad-hoc CLI scans require the
  operator to assert authorization.
- **Feeds are public defensive sources** (CISA, FIRST.org EPSS, abuse.ch). No
  authentication is bypassed. A descriptive User-Agent is always sent.
- **Tor routing** is available via `TOR_SOCKS_PROXY` for public onion indexes
  only (Module 4), never to access restricted systems.

## Build

```bash
# All crates + tests
cargo test --workspace

# A specific binary
cargo build --release --bin aegis-worker
cargo build --release --bin aegis-scanner

# Container (multi-binary via build arg)
docker build -f services/rust-core/Dockerfile \
  --build-arg BIN=aegis-worker -t aegis-worker .
```

## Verification checklist (run once VM is restored)

1. `cargo fmt --check && cargo clippy --workspace -- -D warnings`
2. `cargo test --workspace` — expect all pure-logic unit tests green.
3. Bring up Postgres (migrations applied), export `DATABASE_URL`, run
   `aegis-worker`; enqueue a `feed.pull` for `cisa-kev` and confirm rows land in
   `aegis.cves` (kev=true) and `aegis.feed_runs`.
4. Run `aegis-scanner scanme.nmap.org top100` (an explicitly scan-authorized
   host) and confirm open-port output.
5. Confirm the `scanner` queue path: create an authorized asset + `POST /api/scans`
   and verify `scan_ports` / `scan_tls` / `findings` populate.

## Items to confirm at first compile

- `x509-parser` 0.16 API surface (`subject_alternative_name`, `GeneralName`).
- `rustls` 0.23 `builder_with_provider` + `dangerous()` verifier trait method
  signatures (pinned to the danger API used in `tls.rs`).
- `reqwest` built with `rustls-tls` + `socks` (no OpenSSL needed in the image).
