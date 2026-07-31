//! Aegis scanner binary. Two modes:
//!   1. Worker mode (default): claims `scan.*` jobs from the queue and runs them,
//!      enforcing the asset authorization gate before touching the network.
//!   2. CLI mode: `aegis-scanner <target> <portspec>` for ad-hoc authorized scans
//!      (operator asserts authorization).
//!
//! ⚠️ RUNTIME VERIFICATION REQUIRED: not compiled/run (VM unavailable).

use aegis_common::{config::Config, connect, telemetry, JobQueue, Pool};
use aegis_scanner::ports::{scan_host, ScanConfig};
use aegis_scanner::{http_headers, parse_ports};
use serde::Deserialize;
use std::net::IpAddr;
use std::time::Duration;

const QUEUE: &str = "scanner";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    telemetry::init();
    let args: Vec<String> = std::env::args().collect();

    // CLI ad-hoc mode.
    if args.len() >= 3 {
        return cli_scan(&args[1], &args[2]).await;
    }

    // Worker mode.
    let cfg = Config::from_env()?;
    let pool = connect(&cfg.database_url, 6).await?;
    let jq = JobQueue::new(pool.clone());
    tracing::info!(worker_id = jq.worker_id(), "aegis-scanner worker starting");

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => { tracing::info!("shutdown"); break; }
            _ = tokio::time::sleep(Duration::from_millis(1500)) => {}
        }
        let jobs = match jq.claim(QUEUE, 2).await {
            Ok(j) => j,
            Err(e) => {
                tracing::error!(error=%e, "claim failed");
                continue;
            }
        };
        for job in jobs {
            let id = job.id;
            match run_scan_job(&pool, &cfg, &job.payload).await {
                Ok(()) => {
                    let _ = jq.complete(id).await;
                }
                Err(e) => {
                    tracing::warn!(job=id, error=%format!("{e:#}"), "scan job failed");
                    let _ = jq.fail(id, &format!("{e:#}")).await;
                }
            }
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct ScanPayload {
    scan_id: String,
    target: String,
    #[serde(default)]
    asset_id: Option<String>,
    #[serde(default)]
    profile: ScanProfile,
}

#[derive(Debug, Deserialize)]
struct ScanProfile {
    #[serde(default = "default_ports")]
    ports: String,
}
impl Default for ScanProfile {
    fn default() -> Self {
        Self {
            ports: default_ports(),
        }
    }
}
fn default_ports() -> String {
    "top100".to_string()
}

/// Execute a queued scan: enforce authorization, scan, persist, update status.
async fn run_scan_job(
    pool: &Pool,
    cfg: &Config,
    payload: &serde_json::Value,
) -> anyhow::Result<()> {
    let p: ScanPayload = serde_json::from_value(payload.clone())
        .map_err(|e| anyhow::anyhow!("bad scan payload: {e}"))?;

    // ── AUTHORIZATION GATE ──────────────────────────────────────────────────
    // A scan tied to a registered asset requires assets.is_authorized = true.
    if let Some(asset_id) = &p.asset_id {
        let authorized: Option<(bool,)> =
            sqlx::query_as("SELECT is_authorized FROM aegis.assets WHERE id = $1::uuid")
                .bind(asset_id)
                .fetch_optional(pool)
                .await?;
        match authorized {
            Some((true,)) => {}
            Some((false,)) => {
                mark_scan_failed(pool, &p.scan_id, "asset not authorized for scanning").await?;
                anyhow::bail!("refusing to scan unauthorized asset {asset_id}");
            }
            None => {
                mark_scan_failed(pool, &p.scan_id, "asset not found").await?;
                anyhow::bail!("asset {asset_id} not found");
            }
        }
    }

    sqlx::query(
        "UPDATE aegis.scans SET status='running', started_at=now(), progress=5 WHERE id=$1::uuid",
    )
    .bind(&p.scan_id)
    .execute(pool)
    .await?;

    let ip: IpAddr = resolve_target(&p.target)
        .await
        .ok_or_else(|| anyhow::anyhow!("could not resolve target '{}'", p.target))?;
    let ports = parse_ports(&p.profile.ports)?;

    let scfg = ScanConfig {
        max_concurrency: cfg.scanner_max_concurrency.min(1024),
        ..Default::default()
    };
    let open = scan_host(ip, &ports, &scfg).await;

    // Persist open ports.
    for op in &open {
        sqlx::query(
            "INSERT INTO aegis.scan_ports(scan_id, ip, port, protocol, state, service, product, version, banner)
             VALUES ($1::uuid, $2::inet, $3, 'tcp', 'open', $4, $5, $6, $7)",
        )
        .bind(&p.scan_id)
        .bind(op.ip.to_string())
        .bind(op.port as i32)
        .bind(&op.service.service)
        .bind(&op.service.product)
        .bind(&op.service.version)
        .bind(&op.banner)
        .execute(pool)
        .await?;
    }

    // For open HTTP(S) ports, run header analysis and record findings.
    for op in &open {
        if matches!(op.port, 80 | 443 | 8080 | 8443 | 8000 | 8888) {
            if let Some(findings) = analyze_http(&p.target, op.port).await {
                for f in findings {
                    sqlx::query(
                        "INSERT INTO aegis.findings(scan_id, category, title, severity, description, remediation, evidence)
                         VALUES ($1::uuid, 'http_header', $2, $3::aegis.severity, $4, $5, $6)",
                    )
                    .bind(&p.scan_id)
                    .bind(&f.title)
                    .bind(&f.severity)
                    .bind(format!("Header '{}' issue on port {}", f.header, op.port))
                    .bind(&f.remediation)
                    .bind(serde_json::json!({ "header": f.header, "port": op.port }))
                    .execute(pool)
                    .await?;
                }
            }
        }
    }

    // For open TLS ports, inspect the certificate and record scan_tls + findings.
    let tls_host = p
        .target
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .to_string();
    for op in &open {
        if matches!(op.port, 443 | 8443 | 993 | 995 | 465) {
            match aegis_scanner::tls::inspect(&tls_host, op.port).await {
                Ok(rep) => persist_tls(pool, &p.scan_id, &rep).await?,
                Err(e) => tracing::debug!(port = op.port, error = %e, "TLS inspect skipped"),
            }
        }
    }

    sqlx::query(
        "UPDATE aegis.scans SET status='completed', progress=100, finished_at=now() WHERE id=$1::uuid",
    )
    .bind(&p.scan_id)
    .execute(pool)
    .await?;

    tracing::info!(scan=%p.scan_id, open_ports=open.len(), "scan complete");
    Ok(())
}

async fn mark_scan_failed(pool: &Pool, scan_id: &str, err: &str) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE aegis.scans SET status='failed', error=$2, finished_at=now() WHERE id=$1::uuid",
    )
    .bind(scan_id)
    .bind(err)
    .execute(pool)
    .await?;
    Ok(())
}

/// Persist a TLS inspection report to scan_tls, and emit findings for weak items.
async fn persist_tls(
    pool: &Pool,
    scan_id: &str,
    rep: &aegis_scanner::tls::TlsReport,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO aegis.scan_tls
           (scan_id, host, port, cert_subject, cert_issuer, cert_serial, san,
            not_before, not_after, is_expired, is_self_signed, sha256_fp, weak_findings)
         VALUES ($1::uuid,$2,$3,$4,$5,$6,$7::text[],$8,$9,$10,$11,$12,$13::text[])",
    )
    .bind(scan_id)
    .bind(&rep.host)
    .bind(rep.port as i32)
    .bind(&rep.cert_subject)
    .bind(&rep.cert_issuer)
    .bind(&rep.cert_serial)
    .bind(&rep.san)
    .bind(rep.not_before)
    .bind(rep.not_after)
    .bind(rep.is_expired)
    .bind(rep.is_self_signed)
    .bind(&rep.sha256_fp)
    .bind(&rep.weak_findings)
    .execute(pool)
    .await?;

    for finding in &rep.weak_findings {
        let sev = if finding.contains("expired") {
            "high"
        } else {
            "medium"
        };
        sqlx::query(
            "INSERT INTO aegis.findings(scan_id, category, title, severity, description, evidence)
             VALUES ($1::uuid, 'tls', $2, $3::aegis.severity, $4, $5)",
        )
        .bind(scan_id)
        .bind(format!("TLS: {finding}"))
        .bind(sev)
        .bind(format!("{}:{} — {}", rep.host, rep.port, finding))
        .bind(
            serde_json::json!({ "host": rep.host, "port": rep.port, "fingerprint": rep.sha256_fp }),
        )
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// Resolve a target string (IP or hostname) to a single IP.
async fn resolve_target(target: &str) -> Option<IpAddr> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Some(ip);
    }
    // hostname:0 → resolve via tokio.
    let host = target.trim_end_matches('/');
    let host = host.strip_prefix("http://").unwrap_or(host);
    let host = host.strip_prefix("https://").unwrap_or(host);
    let lookup = format!("{host}:0");
    tokio::net::lookup_host(lookup)
        .await
        .ok()?
        .next()
        .map(|s| s.ip())
}

/// Fetch HTTP headers for the given host/port and analyze them.
async fn analyze_http(target: &str, port: u16) -> Option<Vec<http_headers::HeaderFinding>> {
    let scheme = if matches!(port, 443 | 8443) {
        "https"
    } else {
        "http"
    };
    let host = target
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');
    let url = format!("{scheme}://{host}:{port}/");
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .build()
        .ok()?;
    let resp = client.get(&url).send().await.ok()?;
    let pairs: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_ascii_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    Some(http_headers::analyze(&pairs))
}

/// Ad-hoc CLI scan (operator asserts they are authorized to scan `target`).
async fn cli_scan(target: &str, portspec: &str) -> anyhow::Result<()> {
    let ip = resolve_target(target)
        .await
        .ok_or_else(|| anyhow::anyhow!("cannot resolve {target}"))?;
    let ports = parse_ports(portspec)?;
    tracing::info!(%ip, count = ports.len(), "ad-hoc scan (authorization asserted by operator)");
    let open = scan_host(ip, &ports, &ScanConfig::default()).await;
    for op in &open {
        println!(
            "{}:{}\t{}\t{}",
            op.ip,
            op.port,
            op.service.service.as_deref().unwrap_or("?"),
            op.banner
                .as_deref()
                .unwrap_or("")
                .lines()
                .next()
                .unwrap_or("")
        );
    }
    println!("{} open port(s)", open.len());
    Ok(())
}
