//! Job handlers. Each `kind` maps to a function; `dispatch` routes and records
//! side-effects (e.g. feed_runs) where relevant.

use aegis_common::{Job, JobQueue};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct FeedPullPayload {
    /// Collector selector. The API sends `provider` (e.g. "cisa_kev"); we also
    /// accept `slug` (e.g. "cisa-kev"). run_collector normalizes both forms.
    #[serde(default)]
    slug: Option<String>,
    #[serde(default)]
    provider: Option<String>,
    /// Optional feed row id to update run bookkeeping.
    #[serde(default)]
    feed_id: Option<String>,
}

impl FeedPullPayload {
    fn selector(&self) -> anyhow::Result<&str> {
        self.slug
            .as_deref()
            .or(self.provider.as_deref())
            .ok_or_else(|| anyhow::anyhow!("feed.pull payload missing 'slug'/'provider'"))
    }
}

/// Route a claimed job to its handler.
pub async fn dispatch(job: &Job, jq: &JobQueue) -> anyhow::Result<()> {
    match job.kind.as_str() {
        "feed.pull" => handle_feed_pull(job, jq).await,
        "ioc.enrich" => handle_ioc_enrich(job, jq).await,
        "container.audit" => handle_container_audit(job, jq).await,
        other => anyhow::bail!("no handler for job kind '{other}'"),
    }
}

async fn handle_feed_pull(job: &Job, jq: &JobQueue) -> anyhow::Result<()> {
    let p: FeedPullPayload = serde_json::from_value(job.payload.clone())
        .map_err(|e| anyhow::anyhow!("bad feed.pull payload: {e}"))?;

    let pool = jq.pool();
    // Open a feed_run row if we know the feed id.
    let run_id: Option<i64> = if let Some(fid) = &p.feed_id {
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO aegis.feed_runs(feed_id, status) VALUES ($1::uuid, 'running') RETURNING id",
        )
        .bind(fid)
        .fetch_one(pool)
        .await?;
        Some(row.0)
    } else {
        None
    };

    let result = aegis_collectors::run_collector(p.selector()?, jq).await;

    match &result {
        Ok(stats) => {
            if let Some(rid) = run_id {
                sqlx::query(
                    "UPDATE aegis.feed_runs
                        SET status='succeeded', items_new=$2, finished_at=now()
                      WHERE id=$1",
                )
                .bind(rid)
                .bind(stats.inserted as i32)
                .execute(pool)
                .await?;
            }
            if let Some(fid) = &p.feed_id {
                sqlx::query(
                    "UPDATE aegis.feeds
                        SET last_run_at=now(), last_status='succeeded',
                            last_error=NULL, last_item_count=$2
                      WHERE id=$1::uuid",
                )
                .bind(fid)
                .bind(stats.inserted as i32)
                .execute(pool)
                .await?;
            }
        }
        Err(e) => {
            let msg = format!("{e:#}");
            if let Some(rid) = run_id {
                sqlx::query(
                    "UPDATE aegis.feed_runs SET status='failed', error=$2, finished_at=now() WHERE id=$1",
                )
                .bind(rid)
                .bind(&msg)
                .execute(pool)
                .await?;
            }
            if let Some(fid) = &p.feed_id {
                sqlx::query(
                    "UPDATE aegis.feeds SET last_run_at=now(), last_status='failed', last_error=$2 WHERE id=$1::uuid",
                )
                .bind(fid)
                .bind(&msg)
                .execute(pool)
                .await?;
            }
        }
    }

    result.map(|_| ())
}

/// OSINT enrichment handler (Module 3). Loads the target IOC, fans out to every
/// configured provider, aggregates the verdicts, and persists the reputation
/// back onto the row. Providers without an API key are skipped; if none are
/// configured the job is a no-op success.
///
/// ⚠️ RUNTIME VERIFICATION REQUIRED — network + DB write paths unverified (VM offline).
async fn handle_ioc_enrich(job: &Job, jq: &JobQueue) -> anyhow::Result<()> {
    #[derive(Deserialize)]
    struct P {
        ioc_id: String,
    }
    let p: P = serde_json::from_value(job.payload.clone())
        .map_err(|e| anyhow::anyhow!("bad ioc.enrich payload: {e}"))?;

    let keys = osint_keys_from_env();
    if !keys.any() {
        tracing::info!(ioc_id = %p.ioc_id, "ioc.enrich skipped — no OSINT provider keys configured");
        return Ok(());
    }

    let pool = jq.pool();
    // Fetch the indicator's type + value.
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT type::text, value FROM aegis.iocs WHERE id = $1::uuid")
            .bind(&p.ioc_id)
            .fetch_optional(pool)
            .await?;

    let Some((ioc_type, value)) = row else {
        anyhow::bail!("ioc.enrich: no IOC with id {}", p.ioc_id);
    };

    // Skip indicator kinds no provider can enrich (e.g. mutex, email).
    if aegis_osint::TargetKind::from_ioc_type(&ioc_type).is_none() {
        tracing::info!(ioc_id = %p.ioc_id, ioc_type = %ioc_type, "ioc.enrich skipped — unsupported kind");
        return Ok(());
    }

    let client = aegis_collectors::http::default_client()?;
    let ioc_uuid = uuid::Uuid::parse_str(&p.ioc_id)
        .map_err(|e| anyhow::anyhow!("ioc.enrich: bad uuid {}: {e}", p.ioc_id))?;

    let rep =
        aegis_osint::enrich_and_persist(pool, &client, &keys, ioc_uuid, &ioc_type, &value).await?;
    tracing::info!(
        ioc_id = %p.ioc_id,
        score = rep.score,
        verdict = ?rep.verdict,
        sources = rep.sources,
        "ioc.enrich complete"
    );
    Ok(())
}

/// Container-security audit handler (Module 6). Loads the queued audit row,
/// runs the matching offline analyzer from `aegis-container` over the stored
/// input, persists the findings + risk summary, and marks the audit completed.
/// On any analysis error the audit is marked `failed` with the message.
///
/// All analysis is pure/offline — no Docker daemon or network is used here.
/// (Actually building/pulling images or invoking Trivy is out of scope and
/// would be a separate ⚠️ RUNTIME VERIFICATION REQUIRED path.)
///
/// ⚠️ RUNTIME VERIFICATION REQUIRED — DB read/write paths unverified (VM offline).
async fn handle_container_audit(job: &Job, jq: &JobQueue) -> anyhow::Result<()> {
    #[derive(Deserialize)]
    struct P {
        audit_id: String,
    }
    let p: P = serde_json::from_value(job.payload.clone())
        .map_err(|e| anyhow::anyhow!("bad container.audit payload: {e}"))?;

    let pool = jq.pool();

    // Load the audit and mark it running.
    let row: Option<(String, String)> = sqlx::query_as(
        "UPDATE aegis.container_audits
            SET status='running', updated_at=now()
          WHERE id = $1::uuid
        RETURNING kind::text, input",
    )
    .bind(&p.audit_id)
    .fetch_optional(pool)
    .await?;

    let Some((kind, input)) = row else {
        anyhow::bail!("container.audit: no audit with id {}", p.audit_id);
    };

    // Run the matching analyzer. Parsing errors (bad JSON) become a `failed`
    // audit rather than a worker error, so the UI can show the reason.
    let analyzed: Result<(Vec<aegis_container::Finding>, aegis_container::RiskSummary), String> =
        match kind.as_str() {
            "dockerfile" => Ok(aegis_container::audit_dockerfile(&input)),
            "image_config" => {
                aegis_container::audit_image_json(&input).map_err(|e| format!("{e:#}"))
            }
            "trivy" => aegis_container::audit_trivy(&input).map_err(|e| format!("{e:#}")),
            other => Err(format!("unknown container audit kind '{other}'")),
        };

    match analyzed {
        Ok((findings, summary)) => {
            let summary_json = serde_json::to_value(&summary)?;
            sqlx::query(
                "UPDATE aegis.container_audits
                    SET status='completed', score=$2, summary=$3,
                        error=NULL, finished_at=now(), updated_at=now()
                  WHERE id = $1::uuid",
            )
            .bind(&p.audit_id)
            .bind(summary.score as i32)
            .bind(&summary_json)
            .execute(pool)
            .await?;

            // Replace any prior findings (idempotent on re-run).
            sqlx::query("DELETE FROM aegis.container_findings WHERE audit_id = $1::uuid")
                .bind(&p.audit_id)
                .execute(pool)
                .await?;

            for f in &findings {
                sqlx::query(
                    "INSERT INTO aegis.container_findings
                        (audit_id, rule_id, category, severity, title, remediation, location)
                     VALUES ($1::uuid, $2, $3::aegis.container_finding_category,
                             $4::aegis.severity, $5, $6, $7)",
                )
                .bind(&p.audit_id)
                .bind(&f.id)
                .bind(f.category.as_str())
                .bind(f.severity.as_str())
                .bind(&f.title)
                .bind(&f.remediation)
                .bind(f.location.as_deref())
                .execute(pool)
                .await?;
            }

            tracing::info!(
                audit_id = %p.audit_id,
                kind = %kind,
                score = summary.score,
                total = summary.total,
                "container.audit complete"
            );
            Ok(())
        }
        Err(msg) => {
            sqlx::query(
                "UPDATE aegis.container_audits
                    SET status='failed', error=$2, finished_at=now(), updated_at=now()
                  WHERE id = $1::uuid",
            )
            .bind(&p.audit_id)
            .bind(&msg)
            .execute(pool)
            .await?;
            tracing::warn!(audit_id = %p.audit_id, error = %msg, "container.audit failed");
            Ok(())
        }
    }
}

/// Collect OSINT provider keys from the process environment.
fn osint_keys_from_env() -> aegis_osint::Keys {
    let e = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    aegis_osint::Keys {
        virustotal: e("VIRUSTOTAL_API_KEY"),
        abuseipdb: e("ABUSEIPDB_API_KEY"),
        shodan: e("SHODAN_API_KEY"),
        greynoise: e("GREYNOISE_API_KEY"),
        otx: e("OTX_API_KEY"),
    }
}
