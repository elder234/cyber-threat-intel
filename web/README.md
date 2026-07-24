# Aegis CTI — Web Console (Modules 1 & 16)

Professional SOC dashboard for the Aegis Cyber Threat Intelligence platform.
React 18 + TypeScript + Vite + TailwindCSS, with React Query for server state and
a resilient WebSocket layer for real-time updates.

> ⚠️ **Runtime verification pending.** This frontend was authored while the build
> VM was unavailable, so it has **not** yet been `npm install`-ed, type-checked,
> linted, or built. Components and API shapes marked
> `⚠️ RUNTIME VERIFICATION REQUIRED` were transcribed from the backend route
> handlers rather than observed from live responses. Run the verification steps
> below once the toolchain is available.

## Design language

A functional dark SOC console — deep desaturated slate (never pure black), a
single reserved **amber "signal"** accent used only for live/active threats, and
a strict, colorblind-tuned **severity scale** (critical→info) that is never
reused for decoration. Indicator/data values are always monospace (JetBrains
Mono); headings use Space Grotesk, body uses Inter.

The signature element is the **live threat-pulse rail** down the left edge of the
shell: incoming WebSocket events drop severity-colored ticks that fade over time,
giving an ambient read of tempo without stealing focus.

## Structure

```
src/
  main.tsx            React root + providers (Router, React Query, Auth)
  App.tsx             Routes + auth gate + Live provider
  index.css           Tailwind layers + console surface styles
  lib/
    types.ts          Domain types mirrored from the API
    api.ts            Typed fetch client (JWT, transparent refresh + retry)
    auth.tsx          Auth context (session resume via refresh token)
    live.tsx          WebSocket provider (reconnect w/ backoff, event bus)
    ui.ts             Severity color maps, risk banding, time/number fmt
  components/
    Shell.tsx         App frame: sidebar, header search, pulse rail
    primitives.tsx    Panel, chips, tiles, spinner, empty/error states
    DataTable.tsx     Dense sortable-friendly table
    WorldThreatMap.tsx  react-simple-maps world map w/ severity markers
  pages/
    Login, Dashboard, Iocs, Cves, Alerts, Feeds, Scans, Search
```

## Backend contract

The client talks to the Fastify API (see `services/api`) at a shared origin:

| Area       | Endpoints used |
|------------|----------------|
| auth       | `POST /api/auth/login`, `/refresh`, `/logout`, `GET /api/auth/me` |
| dashboard  | `GET /api/dashboard/{stats,timeline,attack-matrix,top-sources}` |
| iocs       | `GET/POST /api/iocs`, `GET/DELETE /api/iocs/:id` |
| cves       | `GET /api/cves`, `/api/cves/:id`, `/api/cves/kev/recent` |
| alerts     | `GET /api/alerts`, `POST /api/alerts/:id/{ack,resolve}` |
| feeds      | `GET /api/feeds`, `/api/feeds/:id/runs`, `POST /api/feeds/:id/sync` |
| scans      | `GET /api/scans`, `/api/scans/:id`, `POST /api/scans` |
| search     | `GET /api/search?q=` |
| realtime   | `GET /ws?token=` (JWT) — fans out the Redis `events` channel |

## Develop

```bash
npm install
npm run dev        # Vite dev server on :5173, proxies /api and /ws to :8080
```

## Verify (run once the toolchain is available)

```bash
npm install
npm run typecheck  # tsc --noEmit — strict mode
npm run lint       # eslint ts,tsx
npm run build      # tsc -b && vite build → dist/
```

## Build & run the container

```bash
docker build -t aegis-web .
docker run -p 8080:8080 aegis-web    # serves SPA, proxies /api + /ws to `api`
```

## Notes / follow-ups

- **World map data**: `WorldThreatMap` fetches `world-atlas` topojson from a CDN.
  For air-gapped deployments, vendor `countries-110m.json` into `public/` and
  point `GEO_URL` at it.
- **Threat geolocation**: the timeline API doesn't yet return coordinates, so map
  points are derived deterministically from event titles as a placeholder. Wire
  real geo once the API exposes source coordinates.
- **Access token**: held in memory and mirrored to `window.__aegisAccessToken`
  for the WS layer; only the refresh token is persisted (localStorage).
