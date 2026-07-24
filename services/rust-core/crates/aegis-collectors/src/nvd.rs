//! NIST NVD 2.0 CVE collector (Module 2 — CVE database synchronization).
//!
//! Pulls from the public NVD 2.0 REST API:
//!   https://services.nvd.nist.gov/rest/json/cves/2.0
//!
//! The API is paginated (`resultsPerPage`/`startIndex`, max 2000) and rate
//! limited — without an API key NIST recommends ≤5 requests / 30s; with a key,
//! 50 / 30s. We honor a conservative inter-request delay and support an
//! incremental window via `lastModStartDate`/`lastModEndDate`.
//!
//! Only public catalog data is fetched. CVSS v3.1 base score/vector/severity,
//! CWE ids, and CPE match strings are extracted; KEV/EPSS are owned by their
//! own collectors and are never overwritten here (see `sink::upsert_cve`).
//!
//! ⚠️ RUNTIME VERIFICATION REQUIRED — network + DB paths unexecuted. The JSON
//! parser is unit-tested against a representative NVD record.

use crate::{http, sink, CollectStats};
use aegis_common::Pool;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::time::Duration;

const NVD_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const PAGE_SIZE: usize = 2000;
/// Conservative pause between pages when no API key is configured.
const NO_KEY_DELAY: Duration = Duration::from_millis(6500);
const WITH_KEY_DELAY: Duration = Duration::from_millis(700);

// ── NVD 2.0 response shapes (only the fields we consume) ─────────────────────

#[derive(Debug, Deserialize)]
pub struct NvdResponse {
    #[serde(rename = "totalResults")]
    pub total_results: usize,
    #[serde(rename = "resultsPerPage", default)]
    pub results_per_page: usize,
    #[serde(rename = "startIndex", default)]
    pub start_index: usize,
    #[serde(default)]
    pub vulnerabilities: Vec<VulnWrapper>,
}

#[derive(Debug, Deserialize)]
pub struct VulnWrapper {
    pub cve: CveItem,
}

#[derive(Debug, Deserialize)]
pub struct CveItem {
    pub id: String,
    #[serde(default)]
    pub published: Option<String>,
    #[serde(rename = "lastModified", default)]
    pub last_modified: Option<String>,
    #[serde(default)]
    pub descriptions: Vec<LangText>,
    #[serde(default)]
    pub metrics: Metrics,
    #[serde(default)]
    pub weaknesses: Vec<Weakness>,
    #[serde(default)]
    pub configurations: Vec<Configuration>,
}

#[derive(Debug, Deserialize)]
pub struct LangText {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct Metrics {
    #[serde(rename = "cvssMetricV31", default)]
    pub v31: Vec<CvssMetric>,
}

#[derive(Debug, Deserialize)]
pub struct CvssMetric {
    #[serde(rename = "cvssData")]
    pub cvss_data: CvssData,
}

#[derive(Debug, Deserialize)]
pub struct CvssData {
    #[serde(rename = "baseScore")]
    pub base_score: f64,
    #[serde(rename = "baseSeverity", default)]
    pub base_severity: Option<String>,
    #[serde(rename = "vectorString", default)]
    pub vector_string: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Weakness {
    #[serde(default)]
    pub description: Vec<LangText>,
}

#[derive(Debug, Deserialize)]
pub struct Configuration {
    #[serde(default)]
    pub nodes: Vec<CpeNode>,
}

#[derive(Debug, Deserialize)]
pub struct CpeNode {
    #[serde(rename = "cpeMatch", default)]
    pub cpe_match: Vec<CpeMatch>,
}

#[derive(Debug, Deserialize)]
pub struct CpeMatch {
    #[serde(default)]
    pub vulnerable: bool,
    #[serde(default)]
    pub criteria: Option<String>,
}

/// A flattened CVE ready to upsert.
#[derive(Debug, PartialEq)]
pub struct ParsedCve {
    pub cve_id: String,
    pub description: String,
    pub published_at: Option<DateTime<Utc>>,
    pub last_modified_at: Option<DateTime<Utc>>,
    pub cvss_v31_score: Option<f64>,
    pub cvss_v31_vector: Option<String>,
    pub cvss_v31_severity: Option<String>,
    pub cwe_ids: Vec<String>,
    pub cpes: Vec<String>,
}

/// Parse an NVD 2.0 page into flattened CVEs. Pure — unit-tested.
pub fn parse(body: &str) -> anyhow::Result<(usize, Vec<ParsedCve>)> {
    let resp: NvdResponse = serde_json::from_str(body)?;
    let cves = resp.vulnerabilities.iter().map(|w| flatten(&w.cve)).collect();
    Ok((resp.total_results, cves))
}

fn flatten(cve: &CveItem) -> ParsedCve {
    // Prefer the English description.
    let description = cve
        .descriptions
        .iter()
        .find(|d| d.lang == "en")
        .or_else(|| cve.descriptions.first())
        .map(|d| d.value.clone())
        .unwrap_or_default();

    let v31 = cve.metrics.v31.first();
    let (score, severity, vector) = match v31 {
        Some(m) => (
            Some(m.cvss_data.base_score),
            m.cvss_data.base_severity.as_ref().map(|s| s.to_ascii_lowercase()),
            m.cvss_data.vector_string.clone(),
        ),
        None => (None, None, None),
    };

    let mut cwe_ids: Vec<String> = cve
        .weaknesses
        .iter()
        .flat_map(|w| w.description.iter())
        .filter(|d| d.lang == "en")
        .map(|d| d.value.clone())
        .filter(|v| v.starts_with("CWE-"))
        .collect();
    cwe_ids.sort();
    cwe_ids.dedup();

    let mut cpes: Vec<String> = cve
        .configurations
        .iter()
        .flat_map(|c| c.nodes.iter())
        .flat_map(|n| n.cpe_match.iter())
        .filter(|m| m.vulnerable)
        .filter_map(|m| m.criteria.clone())
        .collect();
    cpes.sort();
    cpes.dedup();

    ParsedCve {
        cve_id: cve.id.to_uppercase(),
        description,
        published_at: parse_ts(cve.published.as_deref()),
        last_modified_at: parse_ts(cve.last_modified.as_deref()),
        cvss_v31_score: score,
        cvss_v31_vector: vector,
        cvss_v31_severity: severity,
        cwe_ids,
        cpes,
    }
}

/// NVD timestamps look like `2024-03-29T17:15:21.283` (no zone) — treat as UTC.
fn parse_ts(s: Option<&str>) -> Option<DateTime<Utc>> {
    let s = s?;
    // Try RFC3339 first, then the naive form NVD usually emits.
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    let fmts = ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"];
    for f in fmts {
        if let Ok(ndt) = chrono::NaiveDateTime::parse_from_str(s, f) {
            return Some(DateTime::from_naive_utc_and_offset(ndt, Utc));
        }
    }
    None
}

/// Collect from NVD, paginating until `totalResults` is exhausted. An optional
/// API key (env `NVD_API_KEY`) raises the rate limit.
pub async fn collect(pool: &Pool) -> anyhow::Result<CollectStats> {
    let mut stats = CollectStats::default();
    let api_key = std::env::var("NVD_API_KEY").ok().filter(|k| !k.is_empty());
    let delay = if api_key.is_some() { WITH_KEY_DELAY } else { NO_KEY_DELAY };
    let client = http::default_client()?;

    let mut start = 0usize;
    loop {
        let mut req = client
            .get(NVD_URL)
            .query(&[("resultsPerPage", PAGE_SIZE.to_string()), ("startIndex", start.to_string())]);
        if let Some(k) = &api_key {
            req = req.header("apiKey", k);
        }
        let body = req.send().await?.error_for_status()?.text().await?;
        let (total, cves) = parse(&body)?;
        stats.fetched += cves.len();

        for c in &cves {
            let rec = sink::CveRecord {
                cve_id: &c.cve_id,
                description: &c.description,
                published_at: c.published_at,
                last_modified_at: c.last_modified_at,
                cvss_v31_score: c.cvss_v31_score,
                cvss_v31_vector: c.cvss_v31_vector.as_deref(),
                cvss_v31_severity: c.cvss_v31_severity.as_deref(),
                cwe_ids: &c.cwe_ids,
                cpes: &c.cpes,
            };
            match sink::upsert_cve(pool, &rec).await {
                Ok(_) => stats.inserted += 1,
                Err(e) => {
                    stats.errors += 1;
                    tracing::warn!(cve = %c.cve_id, error = %e, "NVD upsert failed");
                }
            }
        }

        start += PAGE_SIZE;
        if start >= total || cves.is_empty() {
            break;
        }
        tokio::time::sleep(delay).await;
    }

    tracing::info!(?stats, "NVD collection complete");
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "totalResults": 1,
      "resultsPerPage": 1,
      "startIndex": 0,
      "vulnerabilities": [{
        "cve": {
          "id": "cve-2024-3094",
          "published": "2024-03-29T17:15:21.283",
          "lastModified": "2024-04-10T00:00:00.000",
          "descriptions": [
            {"lang": "es", "value": "texto"},
            {"lang": "en", "value": "Malicious code in xz/liblzma via backdoor."}
          ],
          "metrics": {
            "cvssMetricV31": [{
              "cvssData": {
                "baseScore": 10.0,
                "baseSeverity": "CRITICAL",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
              }
            }]
          },
          "weaknesses": [{"description": [{"lang":"en","value":"CWE-506"}]}],
          "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": true, "criteria": "cpe:2.3:a:tukaani:xz:5.6.0:*:*:*:*:*:*:*"},
            {"vulnerable": false, "criteria": "cpe:2.3:o:linux:linux_kernel:*"}
          ]}]}]
        }
      }]
    }"#;

    #[test]
    fn parses_and_flattens_nvd_record() {
        let (total, cves) = parse(SAMPLE).unwrap();
        assert_eq!(total, 1);
        assert_eq!(cves.len(), 1);
        let c = &cves[0];
        assert_eq!(c.cve_id, "CVE-2024-3094"); // uppercased
        assert!(c.description.starts_with("Malicious code")); // English preferred
        assert_eq!(c.cvss_v31_score, Some(10.0));
        assert_eq!(c.cvss_v31_severity.as_deref(), Some("critical")); // lowercased for enum
        assert_eq!(c.cwe_ids, vec!["CWE-506"]);
        assert_eq!(c.cpes, vec!["cpe:2.3:a:tukaani:xz:5.6.0:*:*:*:*:*:*:*"]); // only vulnerable
    }

    #[test]
    fn parses_timestamps_without_zone_as_utc() {
        let (_, cves) = parse(SAMPLE).unwrap();
        let p = cves[0].published_at.unwrap();
        assert_eq!(p.format("%Y-%m-%d").to_string(), "2024-03-29");
    }

    #[test]
    fn handles_missing_metrics_and_empty_arrays() {
        let body = r#"{"totalResults":1,"vulnerabilities":[{"cve":{
          "id":"CVE-2000-0001","descriptions":[{"lang":"en","value":"old"}]
        }}]}"#;
        let (_, cves) = parse(body).unwrap();
        assert_eq!(cves[0].cvss_v31_score, None);
        assert!(cves[0].cwe_ids.is_empty());
        assert!(cves[0].cpes.is_empty());
    }
}
