//! CISA Known Exploited Vulnerabilities (KEV) collector.
//! Public catalog: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

use crate::{http, sink, CollectStats};
use aegis_common::Pool;
use chrono::NaiveDate;
use serde::Deserialize;

const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

#[derive(Debug, Deserialize)]
pub struct KevCatalog {
    #[serde(default)]
    pub vulnerabilities: Vec<KevItem>,
}

#[derive(Debug, Deserialize)]
pub struct KevItem {
    #[serde(rename = "cveID")]
    pub cve_id: String,
    #[serde(rename = "vulnerabilityName", default)]
    pub name: String,
    #[serde(rename = "shortDescription", default)]
    pub short_description: String,
    #[serde(rename = "dateAdded", default)]
    pub date_added: String,
    #[serde(rename = "dueDate", default)]
    pub due_date: String,
    #[serde(rename = "knownRansomwareCampaignUse", default)]
    pub ransomware_use: String,
}

impl KevItem {
    pub fn is_ransomware(&self) -> bool {
        self.ransomware_use.eq_ignore_ascii_case("known")
    }
    pub fn added(&self) -> Option<NaiveDate> {
        NaiveDate::parse_from_str(&self.date_added, "%Y-%m-%d").ok()
    }
    pub fn due(&self) -> Option<NaiveDate> {
        NaiveDate::parse_from_str(&self.due_date, "%Y-%m-%d").ok()
    }
    /// Prefer the vulnerability name, fall back to the short description.
    pub fn description(&self) -> String {
        if !self.name.is_empty() {
            self.name.clone()
        } else {
            self.short_description.clone()
        }
    }
}

/// Parse the raw JSON body. Pure — unit-testable without network.
pub fn parse(body: &str) -> anyhow::Result<KevCatalog> {
    Ok(serde_json::from_str(body)?)
}

pub async fn collect(pool: &Pool) -> anyhow::Result<CollectStats> {
    let mut stats = CollectStats::default();
    let client = http::default_client()?;
    let body = client.get(KEV_URL).send().await?.error_for_status()?.text().await?;
    let catalog = parse(&body)?;
    stats.fetched = catalog.vulnerabilities.len();

    for item in &catalog.vulnerabilities {
        match sink::upsert_kev(
            pool,
            &item.cve_id,
            &item.description(),
            item.added(),
            item.due(),
            item.is_ransomware(),
        )
        .await
        {
            Ok(_) => stats.inserted += 1,
            Err(e) => {
                stats.errors += 1;
                tracing::warn!(cve = %item.cve_id, error = %e, "KEV upsert failed");
            }
        }
    }
    tracing::info!(?stats, "CISA KEV collection complete");
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "title": "CISA Catalog of Known Exploited Vulnerabilities",
      "vulnerabilities": [
        {
          "cveID": "CVE-2021-27104",
          "vulnerabilityName": "Accellion FTA OS Command Injection",
          "dateAdded": "2021-11-03",
          "shortDescription": "Accellion FTA contains an OS command injection vulnerability.",
          "dueDate": "2021-11-17",
          "knownRansomwareCampaignUse": "Known"
        },
        {
          "cveID": "CVE-2023-1234",
          "vulnerabilityName": "Example Unknown Ransomware",
          "dateAdded": "2023-05-01",
          "shortDescription": "desc",
          "dueDate": "2023-05-15",
          "knownRansomwareCampaignUse": "Unknown"
        }
      ]
    }"#;

    #[test]
    fn parses_catalog() {
        let c = parse(SAMPLE).unwrap();
        assert_eq!(c.vulnerabilities.len(), 2);
        let first = &c.vulnerabilities[0];
        assert_eq!(first.cve_id, "CVE-2021-27104");
        assert!(first.is_ransomware());
        assert_eq!(first.added(), NaiveDate::from_ymd_opt(2021, 11, 3));
        assert_eq!(first.due(), NaiveDate::from_ymd_opt(2021, 11, 17));
        assert_eq!(first.description(), "Accellion FTA OS Command Injection");
    }

    #[test]
    fn ransomware_flag_is_case_insensitive_and_defaults_false() {
        let c = parse(SAMPLE).unwrap();
        assert!(!c.vulnerabilities[1].is_ransomware());
    }

    #[test]
    fn empty_body_yields_empty_catalog() {
        let c = parse(r#"{"vulnerabilities":[]}"#).unwrap();
        assert_eq!(c.vulnerabilities.len(), 0);
    }
}
