//! Feodo Tracker (abuse.ch) collector — botnet C2 IP blocklist.
//! JSON: https://feodotracker.abuse.ch/downloads/ipblocklist.json

use crate::{http, sink, CollectStats};
use aegis_common::Pool;
use aegis_ioc::{IocType, NormalizedIoc};
use serde::Deserialize;

const FEODO_URL: &str = "https://feodotracker.abuse.ch/downloads/ipblocklist.json";

#[derive(Debug, Deserialize)]
pub struct FeodoEntry {
    pub ip_address: String,
    #[serde(default)]
    pub port: Option<u32>,
    #[serde(default)]
    pub malware: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
}

/// Parse the Feodo JSON array. Pure — unit-testable.
pub fn parse(body: &str) -> anyhow::Result<Vec<FeodoEntry>> {
    Ok(serde_json::from_str(body)?)
}

pub async fn collect(pool: &Pool) -> anyhow::Result<CollectStats> {
    let mut stats = CollectStats::default();
    let client = http::default_client()?;
    let body = client.get(FEODO_URL).send().await?.error_for_status()?.text().await?;
    let entries = parse(&body)?;
    stats.fetched = entries.len();

    for e in &entries {
        // Feodo lists C2 IPs — treat as high-severity, confirmed indicators.
        let ioc = NormalizedIoc {
            ioc_type: IocType::Ipv4,
            value: e.ip_address.to_lowercase(),
        };
        // Guard: only ingest if it really parses as an IP.
        if aegis_ioc::normalize(&e.ip_address).map(|n| n.ioc_type) != Some(IocType::Ipv4) {
            continue;
        }
        let mut tags = vec!["feodo".to_string(), "c2".to_string(), "botnet".to_string()];
        if let Some(m) = &e.malware {
            tags.push(m.to_lowercase());
        }
        match sink::upsert_ioc(pool, &ioc, "high", "confirmed", "feodo", &tags, "amber").await {
            Ok(_) => stats.inserted += 1,
            Err(err) => {
                stats.errors += 1;
                tracing::warn!(ip = %e.ip_address, error = %err, "Feodo upsert failed");
            }
        }
    }
    tracing::info!(?stats, "Feodo collection complete");
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"[
      {"ip_address":"203.0.113.10","port":443,"malware":"Emotet","status":"online"},
      {"ip_address":"198.51.100.55","port":8080,"malware":"Dridex","status":"online"}
    ]"#;

    #[test]
    fn parses_entries() {
        let v = parse(SAMPLE).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].ip_address, "203.0.113.10");
        assert_eq!(v[0].port, Some(443));
        assert_eq!(v[1].malware.as_deref(), Some("Dridex"));
    }

    #[test]
    fn handles_missing_optional_fields() {
        let v = parse(r#"[{"ip_address":"192.0.2.1"}]"#).unwrap();
        assert_eq!(v[0].ip_address, "192.0.2.1");
        assert!(v[0].malware.is_none());
    }
}
