//! AbuseIPDB reputation lookups (IP addresses only).
//!
//! Reads the `/api/v2/check` endpoint's `abuseConfidenceScore` (0..=100), which
//! maps almost directly onto our score. Requires `ABUSEIPDB_API_KEY`.

use crate::providers::{ProviderVerdict, TargetKind, Verdict};
use serde::Deserialize;

const NAME: &str = "abuseipdb";
const URL: &str = "https://api.abuseipdb.com/api/v2/check";

#[derive(Debug, Deserialize)]
struct Envelope {
    data: Data,
}
#[derive(Debug, Deserialize)]
struct Data {
    #[serde(rename = "abuseConfidenceScore", default)]
    abuse_confidence_score: u8,
    #[serde(rename = "totalReports", default)]
    total_reports: u32,
    #[serde(rename = "countryCode", default)]
    country_code: Option<String>,
    #[serde(rename = "isTor", default)]
    is_tor: bool,
    #[serde(rename = "usageType", default)]
    usage_type: Option<String>,
    #[serde(rename = "isp", default)]
    isp: Option<String>,
}

/// Pure parse of an AbuseIPDB `/check` body.
pub fn parse(body: &str) -> anyhow::Result<Option<ProviderVerdict>> {
    let env: Envelope = match serde_json::from_str(body) {
        Ok(e) => e,
        Err(_) => return Ok(None),
    };
    let d = env.data;
    let score = d.abuse_confidence_score.min(100);

    // Confidence grows with report volume; a 0-report/0-score answer is still a
    // (weak) clean signal.
    let confidence = match d.total_reports {
        0 => 0.3,
        1..=5 => 0.6,
        _ => 0.9,
    };

    let mut tags = Vec::new();
    if d.total_reports > 0 {
        tags.push(format!("abuseipdb:{}reports", d.total_reports));
    }
    if d.is_tor {
        tags.push("tor-exit".to_string());
    }
    if let Some(cc) = &d.country_code {
        tags.push(format!("cc:{cc}"));
    }
    if let Some(u) = &d.usage_type {
        tags.push(format!("usage:{}", u.to_lowercase().replace(' ', "-")));
    }

    Ok(Some(ProviderVerdict {
        provider: NAME.to_string(),
        score,
        confidence,
        verdict: Verdict::from_score(score),
        tags,
        raw: Some(serde_json::json!({
            "totalReports": d.total_reports,
            "isTor": d.is_tor,
            "isp": d.isp,
            "countryCode": d.country_code,
        })),
    }))
}

/// Network lookup — IP only. Ok(None) when key missing or kind unsupported.
pub async fn lookup(
    client: &reqwest::Client,
    api_key: Option<&str>,
    kind: TargetKind,
    value: &str,
) -> anyhow::Result<Option<ProviderVerdict>> {
    let Some(key) = api_key else { return Ok(None) };
    if kind != TargetKind::Ip {
        return Ok(None);
    }
    let resp = client
        .get(URL)
        .header("Key", key)
        .header("Accept", "application/json")
        .query(&[("ipAddress", value), ("maxAgeInDays", "90")])
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("abuseipdb HTTP {}", resp.status());
    }
    let body = resp.text().await?;
    parse(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_high_abuse_ip() {
        let body = r#"{"data":{"abuseConfidenceScore":100,"totalReports":523,
            "countryCode":"RU","isTor":true,"usageType":"Data Center/Web Hosting","isp":"Evil LLC"}}"#;
        let v = parse(body).unwrap().unwrap();
        assert_eq!(v.score, 100);
        assert_eq!(v.verdict, Verdict::Malicious);
        assert!(v.confidence >= 0.9);
        assert!(v.tags.iter().any(|t| t == "tor-exit"));
        assert!(v.tags.iter().any(|t| t == "cc:RU"));
    }

    #[test]
    fn clean_ip_low_confidence() {
        let body = r#"{"data":{"abuseConfidenceScore":0,"totalReports":0,"countryCode":"US","isTor":false}}"#;
        let v = parse(body).unwrap().unwrap();
        assert_eq!(v.score, 0);
        assert_eq!(v.verdict, Verdict::Clean);
        assert!(v.confidence < 0.5);
    }

    #[test]
    fn junk_body_yields_none() {
        assert!(parse("not json").unwrap().is_none());
    }
}
