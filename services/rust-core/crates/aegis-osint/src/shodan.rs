//! Shodan host lookups (IP addresses only).
//!
//! Uses `/shodan/host/{ip}` which returns open ports, detected services, tags
//! (e.g. "malware", "cnc", "self-signed"), and any matched CVEs. Shodan is not a
//! reputation service per se, so we translate exposure/known-bad tags into a
//! modest score and lean on its `tags`/`vulns` for context.
//!
//! Requires `SHODAN_API_KEY`.

use crate::providers::{ProviderVerdict, TargetKind, Verdict};
use serde::Deserialize;
use std::collections::BTreeSet;

const NAME: &str = "shodan";
const BASE: &str = "https://api.shodan.io/shodan/host";

#[derive(Debug, Deserialize)]
struct Host {
    #[serde(default)]
    ports: Vec<u32>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    vulns: Vec<String>,
    #[serde(default)]
    hostnames: Vec<String>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    os: Option<String>,
}

// Shodan tags that indicate outright malicious infrastructure.
const MALICIOUS_TAGS: &[&str] = &["malware", "cnc", "c2", "botnet", "compromised", "phishing"];

/// Pure parse of a Shodan host document.
pub fn parse(body: &str) -> anyhow::Result<Option<ProviderVerdict>> {
    let h: Host = match serde_json::from_str(body) {
        Ok(h) => h,
        Err(_) => return Ok(None),
    };

    let lower: Vec<String> = h.tags.iter().map(|t| t.to_lowercase()).collect();
    let has_bad = lower.iter().any(|t| MALICIOUS_TAGS.contains(&t.as_str()));

    // Score: known-bad tag dominates; otherwise scale gently with exposed vulns.
    let score: u8 = if has_bad {
        90
    } else {
        let v = h.vulns.len();
        match v {
            0 => 5,
            1..=2 => 25,
            3..=5 => 45,
            _ => 65,
        }
    };

    let mut tags: Vec<String> = BTreeSet::from_iter(lower.into_iter()).into_iter().collect();
    if !h.ports.is_empty() {
        tags.push(format!("ports:{}", h.ports.len()));
    }
    for cve in h.vulns.iter().take(10) {
        tags.push(cve.to_lowercase());
    }

    // Confidence is high when a malicious tag is present, otherwise low —
    // exposure alone is weak evidence of maliciousness.
    let confidence = if has_bad { 0.8 } else { 0.35 };

    Ok(Some(ProviderVerdict {
        provider: NAME.to_string(),
        score,
        confidence,
        verdict: Verdict::from_score(score),
        tags,
        raw: Some(serde_json::json!({
            "ports": h.ports,
            "vulns": h.vulns,
            "tags": h.tags,
            "hostnames": h.hostnames,
            "org": h.org,
            "os": h.os,
        })),
    }))
}

/// Network lookup — IP only.
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
        .get(format!("{BASE}/{value}"))
        .query(&[("key", key), ("minify", "false")])
        .send()
        .await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None); // Shodan has never seen this host
    }
    if !resp.status().is_success() {
        anyhow::bail!("shodan HTTP {}", resp.status());
    }
    let body = resp.text().await?;
    parse(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malicious_tag_dominates() {
        let body = r#"{"ports":[22,80],"tags":["malware","self-signed"],"vulns":["CVE-2021-1234"]}"#;
        let v = parse(body).unwrap().unwrap();
        assert_eq!(v.verdict, Verdict::Malicious);
        assert!(v.confidence >= 0.8);
        assert!(v.tags.iter().any(|t| t == "malware"));
        assert!(v.tags.iter().any(|t| t == "cve-2021-1234"));
    }

    #[test]
    fn exposure_scales_with_vulns() {
        let body = r#"{"ports":[80],"tags":[],"vulns":["CVE-1","CVE-2","CVE-3","CVE-4"]}"#;
        let v = parse(body).unwrap().unwrap();
        assert_eq!(v.verdict, Verdict::Suspicious);
        assert!(v.confidence < 0.5); // exposure alone is weak
    }

    #[test]
    fn clean_host_scores_low() {
        let body = r#"{"ports":[443],"tags":["cloud"],"vulns":[]}"#;
        let v = parse(body).unwrap().unwrap();
        assert_eq!(v.verdict, Verdict::Clean);
        assert!(v.tags.iter().any(|t| t == "ports:1"));
    }
}
