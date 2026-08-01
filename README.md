# Aegis CTI — Cyber Threat Intelligence Platform

Aegis is a modular, containerized Cyber Threat Intelligence (CTI) platform. It aggregates
threat feeds, synchronizes vulnerability databases (NVD/CVE, CISA KEV, EPSS), manages
IOCs and detection rules (YARA/Sigma), runs network/TLS/container scanners, integrates
OSINT sources, and surfaces everything through a real-time SOC dashboard.

> **Legal & ethical scope.** Aegis only queries publicly available data through official
> APIs and only scans assets you are authorized to test. Tor, OSINT, flight and maritime
> modules access **public** sources only and never bypass authentication or access
> controls. See [`docs/SECURITY.md`](docs/SECURITY.md) and [`docs/LEGAL.md`](docs/LEGAL.md).

## Architecture at a glance

```
                         ┌────────────────────────────────────────────┐
                         │                  Nginx                      │
                         │        (TLS termination, reverse proxy)      │
                         └───────────────┬───────────────┬─────────────┘
                                         │               │
                             /api, /ws   │               │  / (static)
                                         ▼               ▼
                        ┌────────────────────────┐   ┌───────────────────┐
                        │   Node.js API (Fastify) │   │  React + TS (SPA)  │
                        │  REST + GraphQL + WS     │   │  Tailwind SOC UI   │
                        │  JWT auth, RBAC, audit   │   └───────────────────┘
                        └───┬─────────┬─────────┬──┘
                            │         │         │
              ┌─────────────┘         │         └───────────────┐
              ▼                       ▼                         ▼
     ┌────────────────┐      ┌────────────────┐        ┌────────────────┐
     │  PostgreSQL 16 │      │    Redis 7     │        │ OpenSearch 2.x │
     │  (system of    │      │ cache / queues │        │  full-text /   │
     │   record)      │      │ / pub-sub      │        │  IOC search    │
     └────────▲───────┘      └───────▲────────┘        └───────▲────────┘
              │                      │                         │
              └──────────┬───────────┴────────────┬────────────┘
                         │                         │
              ┌──────────┴───────────┐  ┌──────────┴────────────┐
              │  Rust workers/scanner │  │  Rust collectors      │
              │  (scanner, ioc-proc,  │  │  (feeds, OSINT pull)   │
              │   background workers) │  │                        │
              └───────────────────────┘  └────────────────────────┘
```

Full diagrams: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Repository layout

```
aegis-cti/
├── docker-compose.yml          # Full local stack
├── .env.example                # All configuration knobs
├── db/                         # Module 13 — PostgreSQL data layer
│   ├── migrations/             # Ordered, idempotent SQL migrations
│   ├── procedures/             # Stored procedures / functions
│   └── seed/                   # Reference data (MITRE tactics, roles)
├── services/
│   ├── api/                    # Module 15 — Node.js API (Fastify, REST+GraphQL)
│   └── rust-core/              # Modules 5/6/9/14 — Rust workspace
│       └── crates/
│           ├── aegis-common/       # Shared types, DB, config, telemetry
│           ├── aegis-scanner/      # Network/port/TLS/HTTP scanner
│           ├── aegis-collectors/   # OSINT + threat-feed collectors
│           ├── aegis-ioc/          # IOC normalization & enrichment
│           ├── aegis-osint/        # OSINT provider integrations
│           ├── aegis-worker/       # Background job runner
│           ├── aegis-container/    # Container security analysis
│           ├── aegis-malware/      # Malware static analysis
│           └── aegis-analyzer/     # Malware analysis HTTP sidecar
├── web/                        # Modules 1/16 — React + TS + Tailwind SOC dashboard
├── deploy/
│   ├── k8s/                    # Kubernetes manifests
│   └── helm/                   # Helm chart
├── .github/workflows/          # CI/CD
└── docs/                       # Documentation
```

## Quick start (local)

```bash
git clone <repo> aegis-cti && cd aegis-cti
cp .env.example .env            # then edit secrets & API keys
# Cloudflare Tunnel — zero open ports: the VPS dials OUT, Cloudflare serves your
# domain on 443. One-time setup (same docker image the compose service uses):
docker run --rm -it -v "$PWD/deploy/cloudflared:/home/nonroot/.cloudflared" cloudflare/cloudflared tunnel login
docker run --rm -it -v "$PWD/deploy/cloudflared:/home/nonroot/.cloudflared" cloudflare/cloudflared tunnel create aegis
cp deploy/cloudflared/config.yml.example deploy/cloudflared/config.yml   # fill UUID + domain
docker compose up -d            # pulls prebuilt ghcr.io images (no build on the box)
#   Dashboard:  https://yourdomain.com    (put the hostname behind Cloudflare Access)
#   API health: curl https://yourdomain.com/api/health
```

Use `docker compose up -d --build` only when building from source (CI publishes the
images; a VPS deploy should pull, not compile).

Migrations run automatically on API startup (see `services/api/src/db/migrate.ts`).
A default admin is seeded from `SEED_ADMIN_EMAIL` / `SEED_ADMIN_PASSWORD`.

## Kubernetes

```bash
# Raw manifests
kubectl apply -f deploy/k8s/

# Or via Helm
helm install aegis deploy/helm/aegis/ --namespace aegis --create-namespace
```

## Build status by module

| # | Module | Status |
|---|--------|--------|
| 13 | PostgreSQL data layer (12 migrations) | ✅ implemented |
| 15 | Node.js API + auth/RBAC + GraphQL + WS | ✅ implemented |
| 14 | Rust workers/job queue | ✅ implemented |
| 5  | Vulnerability scanner (port/TLS/HTTP) | ✅ implemented |
| 2  | Threat intelligence (NVD/CVE/MITRE/EPSS) | ✅ implemented |
| 10 | Threat feed aggregation (7 collectors) | ✅ implemented |
| 3  | OSINT integrations (VT/AbuseIPDB/Shodan/GreyNoise/OTX) | ✅ implemented |
| 6  | Container security (Dockerfile/image/Trivy analysis) | ✅ implemented |
| 9  | Malware static analysis (sidecar) | ✅ implemented |
| 11 | Alert engine + notification channels | ✅ implemented |
| 12 | Unified search (OpenSearch) | ✅ implemented |
| 1/16 | SOC Dashboard + real-time WebSocket | ✅ implemented |
| 17 | Nginx reverse proxy | ✅ implemented |
| 18 | CI/CD + K8s + Helm | ✅ implemented |

## License

See [`LICENSE`](LICENSE). Use responsibly and only against systems you own or are
explicitly authorized to assess.
# cyber-threat-intel
# cyber-threat-intel
