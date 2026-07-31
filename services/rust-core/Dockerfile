# syntax=docker/dockerfile:1
# ─────────────────────────────────────────────────────────────────────────────
# Aegis Rust services — single build stage producing all four binaries in ONE
# cargo invocation (the dep tree is compiled once, not once per binary), with
# BuildKit cache mounts so rebuilds reuse compiled crates.
#
# The runtime image contains all four binaries; docker-compose selects one per
# service via `command: ["/usr/local/bin/aegis-<name>"]`.
# ─────────────────────────────────────────────────────────────────────────────
FROM rust:1.97-slim-bookworm AS builder

# System deps: rustls needs no OpenSSL, but we keep ca-certificates + pkg-config.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the whole workspace (Cargo caching via layer ordering).
COPY Cargo.toml ./Cargo.toml
COPY Cargo.lock ./Cargo.lock
COPY crates ./crates

ENV SQLX_OFFLINE=true

# Compile the dependency graph once, link all four binaries.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --bin aegis-worker --bin aegis-collectors \
      --bin aegis-scanner --bin aegis-analyzer \
    && cp target/release/aegis-worker /usr/local/bin/ \
    && cp target/release/aegis-collectors /usr/local/bin/ \
    && cp target/release/aegis-scanner /usr/local/bin/ \
    && cp target/release/aegis-analyzer /usr/local/bin/

# ── Runtime image ────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home aegis

COPY --from=builder /usr/local/bin/aegis-* /usr/local/bin/

USER aegis
ENV RUST_LOG=info,aegis=debug
