//! EPSS (Exploit Prediction Scoring System) collector — FIRST.org.
//! Public daily CSV (gzip): https://epss.cyentia.com/epss_scores-current.csv.gz
//! Format: a `#model_version...` comment line, then header `cve,epss,percentile`,
//! then one row per CVE.

use crate::{http, sink, CollectStats};
use aegis_common::Pool;
use chrono::Utc;
use flate2::read::GzDecoder;
use std::io::Read;

const EPSS_URL: &str = "https://epss.cyentia.com/epss_scores-current.csv.gz";

/// Decompress a gzip byte stream to UTF-8 text.
pub fn gunzip(bytes: &[u8]) -> anyhow::Result<String> {
    let mut d = GzDecoder::new(bytes);
    let mut out = String::new();
    d.read_to_string(&mut out)?;
    Ok(out)
}

#[derive(Debug, Clone, PartialEq)]
pub struct EpssRow {
    pub cve: String,
    pub epss: f64,
    pub percentile: f64,
}

/// Parse EPSS CSV text (already decompressed). Skips comment lines starting with
/// '#' and the header row. Pure — unit-testable.
pub fn parse(text: &str) -> Vec<EpssRow> {
    let mut rows = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("cve,") {
            continue; // header
        }
        let mut it = line.split(',');
        let (Some(cve), Some(epss), Some(pct)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        let cve = cve.trim();
        if !cve.to_ascii_uppercase().starts_with("CVE-") {
            continue;
        }
        match (epss.trim().parse::<f64>(), pct.trim().parse::<f64>()) {
            (Ok(e), Ok(p)) => rows.push(EpssRow {
                cve: cve.to_ascii_uppercase(),
                epss: e,
                percentile: p,
            }),
            _ => continue,
        }
    }
    rows
}

pub async fn collect(pool: &Pool) -> anyhow::Result<CollectStats> {
    let mut stats = CollectStats::default();
    let client = http::default_client()?;
    // The endpoint serves a raw .gz file body (not Content-Encoding), so we
    // fetch bytes and gunzip explicitly.
    let bytes = client.get(EPSS_URL).send().await?.error_for_status()?.bytes().await?;
    let text = gunzip(&bytes)?;
    let rows = parse(&text);
    stats.fetched = rows.len();
    let now = Utc::now();

    for row in &rows {
        match sink::upsert_epss(pool, &row.cve, row.epss, row.percentile, now).await {
            Ok(_) => stats.inserted += 1,
            Err(e) => {
                stats.errors += 1;
                tracing::warn!(cve = %row.cve, error = %e, "EPSS upsert failed");
            }
        }
    }
    tracing::info!(?stats, "EPSS collection complete");
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "#model_version:v2023.03.01,score_date:2024-06-01T00:00:00+0000\n\
cve,epss,percentile\n\
CVE-2024-0001,0.97230,0.99900\n\
CVE-2024-0002,0.00042,0.10500\n\
garbage,line,here\n\
CVE-2024-0003,notanumber,0.5\n";

    #[test]
    fn parses_valid_rows_and_skips_junk() {
        let rows = parse(SAMPLE);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].cve, "CVE-2024-0001");
        assert!((rows[0].epss - 0.97230).abs() < 1e-9);
        assert!((rows[1].percentile - 0.10500).abs() < 1e-9);
    }

    #[test]
    fn uppercases_cve_ids() {
        let rows = parse("cve,epss,percentile\ncve-2024-9999,0.5,0.5\n");
        assert_eq!(rows[0].cve, "CVE-2024-9999");
    }

    #[test]
    fn empty_input_is_empty() {
        assert!(parse("").is_empty());
        assert!(parse("#only a comment\n").is_empty());
    }
}
