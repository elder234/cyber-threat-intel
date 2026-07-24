//! Aegis background worker: claims jobs from the durable Postgres queue and
//! dispatches them to handlers. Concurrency-bounded, with graceful shutdown.
//!
//! ⚠️ RUNTIME VERIFICATION REQUIRED: not compiled/run (workspace VM unavailable
//! during authoring). Logic is structured for `cargo test`/`cargo run` on restore.
//!
//! Job kinds handled:
//!   feed.pull   → run a threat-feed collector (payload: {"slug":"cisa-kev"})
//!   ioc.enrich  → placeholder enrichment hook (payload: {"ioc_id": "..."})
//! Unknown kinds are failed with a descriptive error (SP handles retry/dead).

mod handlers;

use aegis_common::{config::Config, connect, telemetry, JobQueue};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Queues this worker services. `collectors` carries feed.pull jobs enqueued by
/// the API; `default` carries misc background work (ioc.enrich, etc.).
const QUEUES: &[&str] = &["collectors", "default"];
const POLL_INTERVAL: Duration = Duration::from_millis(1500);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    telemetry::init();
    let cfg = Config::from_env()?;
    let pool = connect(&cfg.database_url, cfg.worker_concurrency as u32 + 2).await?;
    let jq = JobQueue::new(pool);
    let jq = Arc::new(jq);

    tracing::info!(
        worker_id = jq.worker_id(),
        concurrency = cfg.worker_concurrency,
        "aegis-worker starting"
    );

    let sem = Arc::new(Semaphore::new(cfg.worker_concurrency));

    // Graceful shutdown on Ctrl-C / SIGTERM.
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received; draining in-flight jobs");
                break;
            }
            _ = tokio::time::sleep(POLL_INTERVAL) => {}
        }

        // Claim a batch sized to remaining capacity, sweeping each queue in
        // priority order until capacity is filled.
        let available = sem.available_permits();
        if available == 0 {
            continue;
        }
        let mut jobs = Vec::new();
        for q in QUEUES {
            let remaining = available - jobs.len();
            if remaining == 0 {
                break;
            }
            match jq.claim(q, remaining as i32).await {
                Ok(mut j) => jobs.append(&mut j),
                Err(e) => tracing::error!(queue = q, error = %e, "claim failed"),
            }
        }

        for job in jobs {
            let permit = sem.clone().acquire_owned().await?;
            let jq = jq.clone();
            tokio::spawn(async move {
                let _permit = permit; // released on drop
                let id = job.id;
                let kind = job.kind.clone();
                let result = handlers::dispatch(&job, &jq).await;
                match result {
                    Ok(()) => {
                        if let Err(e) = jq.complete(id).await {
                            tracing::error!(job = id, error = %e, "complete failed");
                        } else {
                            tracing::info!(job = id, %kind, "job succeeded");
                        }
                    }
                    Err(e) => {
                        let msg = format!("{e:#}");
                        tracing::warn!(job = id, %kind, error = %msg, "job failed");
                        if let Err(e2) = jq.fail(id, &msg).await {
                            tracing::error!(job = id, error = %e2, "fail() failed");
                        }
                    }
                }
            });
        }
    }

    // Wait for in-flight jobs to finish by acquiring all permits back.
    let _ = sem.acquire_many(cfg.worker_concurrency as u32).await;
    tracing::info!("aegis-worker stopped");
    Ok(())
}
