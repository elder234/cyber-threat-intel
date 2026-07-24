//! Aegis collectors binary — scheduled feed synchronization service.
//!
//! Runs all configured threat-feed collectors on a configurable interval.
//! Each collector pulls data from a public feed (CISA KEV, NVD, EPSS, etc.)
//! and upserts records into PostgreSQL via the shared sink layer.
//!
//! This complements the worker's on-demand `feed.pull` jobs: the worker handles
//! user-triggered syncs while this service ensures feeds stay current even when
//! nobody clicks "Sync now" in the UI.

use aegis_common::{config::Config, connect, telemetry, JobQueue};
use std::time::Duration;

/// Feeds to pull, in priority order. Each slug maps to a collector in lib.rs.
const FEEDS: &[&str] = &[
    "cisa-kev",
    "epss",
    "nvd",
    "mitre",
    "urlhaus",
    "feodo",
    "malwarebazaar",
];

/// Default sync interval: 6 hours.
const DEFAULT_INTERVAL_SECS: u64 = 6 * 3600;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    telemetry::init();

    let cfg = Config::from_env()?;
    let pool = connect(&cfg.database_url, 4).await?;
    let jq = JobQueue::new(pool);

    let interval = Duration::from_secs(
        std::env::var("COLLECTOR_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_INTERVAL_SECS),
    );

    tracing::info!(
        worker_id = jq.worker_id(),
        interval_secs = interval.as_secs(),
        feeds = ?FEEDS,
        "aegis-collectors starting"
    );

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    // Run an initial sync immediately, then loop on the interval.
    let mut first_run = true;
    loop {
        if first_run {
            first_run = false;
        } else {
            tokio::select! {
                _ = &mut shutdown => {
                    tracing::info!("shutdown signal received");
                    break;
                }
                _ = tokio::time::sleep(interval) => {}
            }
        }

        tracing::info!("starting feed sync cycle");
        for slug in FEEDS {
            match aegis_collectors::run_collector(slug, &jq).await {
                Ok(stats) => {
                    tracing::info!(
                        feed = slug,
                        fetched = stats.fetched,
                        inserted = stats.inserted,
                        errors = stats.errors,
                        "feed sync completed"
                    );
                }
                Err(e) => {
                    tracing::error!(feed = slug, error = %format!("{e:#}"), "feed sync failed");
                }
            }
        }
        tracing::info!("feed sync cycle finished");
    }

    tracing::info!("aegis-collectors stopped");
    Ok(())
}
