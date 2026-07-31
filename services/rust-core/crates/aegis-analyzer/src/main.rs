//! Aegis analyzer sidecar (Module 9 transport).
//!
//! A tiny, stateless HTTP service that wraps the offline `aegis-malware` static
//! analyzer. The API streams a sample's raw bytes to `POST /analyze` and gets a
//! JSON `StaticReport` back.
//!
//! # Why a sidecar
//! The analysis logic is Rust and unit-tested; the API is Node. Routing sample
//! bytes through the Postgres job queue would persist them, which the security
//! posture forbids. This service holds bytes in memory only for the duration of
//! one request, computes the report, and drops them — nothing is stored, logged,
//! or forwarded.
//!
//! ⚠️ RUNTIME VERIFICATION REQUIRED — HTTP wiring unverified (VM offline).

use axum::{
    body::Bytes,
    extract::DefaultBodyLimit,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use tower_http::limit::RequestBodyLimitLayer;

/// Default max sample size accepted (32 MiB). Override with ANALYZER_MAX_BYTES.
const DEFAULT_MAX_BYTES: usize = 32 * 1024 * 1024;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let max_bytes = std::env::var("ANALYZER_MAX_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_BYTES);

    let port: u16 = std::env::var("ANALYZER_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(7000);

    let app = Router::new()
        .route("/health", get(health))
        .route("/analyze", post(analyze))
        // Raise the body limit above the small axum default so large samples fit,
        // then cap it explicitly to `max_bytes`.
        .layer(RequestBodyLimitLayer::new(max_bytes))
        .layer(DefaultBodyLimit::disable());

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!(%addr, max_bytes, "aegis-analyzer listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "service": "aegis-analyzer" }))
}

/// Analyze raw bytes posted in the request body. Returns the `StaticReport`.
/// The bytes are never persisted, logged, or forwarded — only the derived
/// report leaves this function.
async fn analyze(body: Bytes) -> impl IntoResponse {
    if body.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "empty_body" })),
        )
            .into_response();
    }
    let report = aegis_malware::analyze(&body);
    // Bytes (`body`) drop at end of scope.
    (StatusCode::OK, Json(report)).into_response()
}
