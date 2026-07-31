# ─────────────────────────────────────────────────────────────────────────────
# Aegis Rust services — multi-stage, multi-binary build.
# Build a specific binary:  docker build --build-arg BIN=aegis-worker ...
# ⚠️ RUNTIME VERIFICATION REQUIRED: not built during authoring (VM unavailable).
# ─────────────────────────────────────────────────────────────────────────────
FROM rust:1.97-slim-bookworm AS builder

# System deps: rustls needs no OpenSSL, but we keep ca-certificates + pkg-config.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the whole workspace (Cargo caching via layer ordering).
COPY Cargo.toml ./Cargo.toml
COPY crates ./crates

ARG BIN=aegis-worker
ENV SQLX_OFFLINE=true
RUN cargo build --release --bin ${BIN} && \
    cp target/release/${BIN} /usr/local/bin/aegis-service

# ── Runtime image ────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home aegis

COPY --from=builder /usr/local/bin/aegis-service /usr/local/bin/aegis-service

USER aegis
ENV RUST_LOG=info,aegis=debug
ENTRYPOINT ["/usr/local/bin/aegis-service"]
