# Legal & Authorized-Use Policy

Aegis CTI is a **defensive** cyber-threat-intelligence platform. It aggregates
publicly available threat intelligence and inspects assets **you own or are
explicitly authorized to test**. It is not an offensive or exploitation tool.
Using it against systems you do not control or lack written permission to assess
may be illegal in your jurisdiction. You are solely responsible for how you use
it.

## Core rules

1. **Only scan assets you are authorized to test.** Active inspection is gated in
   code: the scanner refuses to run active probes against a registered asset
   unless `assets.is_authorized = true`. Do not disable or work around this gate.
2. **Never bypass authentication or access controls.** Aegis discovers exposure;
   it does not defeat security controls, log in, or access protected data.
3. **Public data only.** Feed collectors pull from public threat-intelligence
   sources (CISA KEV, NVD, FIRST.org EPSS, abuse.ch, MITRE ATT&CK). No feed
   requires bypassing authentication.

## Web application inspection (DAST — Module / Feature F-DAST)

Passive fingerprinting (headers, technology/version detection, and correlation
of detected versions against known CVEs) runs against any target, because it
only reads what the server already returns.

**Active probing is different and is tightly constrained:**

- It runs **only** against a registered asset with `is_authorized = true`. Ad-hoc
  targets (a bare URL with no authorized asset behind it) are refused.
- Payloads are **benign detection markers only** — non-destructive strings used
  to observe reflection or error signatures. Aegis does **not** perform state
  mutation, authentication bypass, resource exhaustion / time-based flooding, or
  use destructive HTTP methods.
- The goal is **exposure discovery, not exploitation.** A finding tells you a
  parameter *appears* injectable; Aegis never attempts to weaponize it.

If you are a service provider, obtain written authorization (e.g. a signed rules
-of-engagement or scope document) from the asset owner before enabling active
probing, and keep it on file.

## Dark-web monitoring (Feature F-DARKWEB)

The dark-web monitor watches curated **public** leak/paste/forum pages for
mentions of watchlisted values you control (your domains, brands, employee email
domains, card BINs) and alerts you when your organization's data appears to be
exposed. Its purpose is **victim/breach notification for your own assets.**

- **Read-only and Tor-only.** The collector fetches and parses public pages
  through the Tor SOCKS proxy. It never authenticates, posts, purchases,
  registers, solicits, or otherwise interacts with any site or actor. It
  fails **closed**: if the Tor proxy is not configured it refuses to run and
  never falls back to a direct/clearnet connection.
- **No illicit-market participation.** Aegis does not transact, and no
  illicit-market/transaction sources are seeded — the shipped scope is
  brand/victim/credential *exposure* on public leak/paste/forum pages.
- **Redaction on ingest.** Matched snippets are truncated and credential/PII in
  them is masked **before** anything is written to the database or shown in the
  console. Aegis stores *evidence that exposure occurred*, not a usable copy of a
  leaked dump. Do not use Aegis to collect, store, or redistribute stolen data.
- **Operator responsibility.** You choose which sources to enable and supply
  their (frequently rotating) addresses out-of-band. Confirm that monitoring a
  given source is lawful where you operate before enabling it.

## Data handling

Aegis is designed for self-hosting so that you retain control of your data.
Collected intelligence, findings, and dark-web hits may include sensitive
information; store and share it in accordance with your own obligations
(contracts, regulation, and any applicable breach-notification duties).

*This document is operational guidance, not legal advice. Consult counsel for
your specific situation.*
