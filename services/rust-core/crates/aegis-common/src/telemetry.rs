//! Structured logging/telemetry setup shared by all binaries.

use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Initialize tracing from `RUST_LOG` (defaults to info). Uses compact format in
/// dev; JSON when `LOG_FORMAT=json`.
pub fn init() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,aegis=debug"));

    let json = std::env::var("LOG_FORMAT").as_deref() == Ok("json");
    let registry = tracing_subscriber::registry().with(filter);
    if json {
        registry.with(fmt::layer().json()).init();
    } else {
        registry.with(fmt::layer().compact()).init();
    }
}
