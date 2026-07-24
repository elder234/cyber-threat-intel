//! VirusTotal v3 reputation lookups (IP / domain / URL / file hash).
//!
//! Only the `last_analysis_stats` summary is consumed — we never upload files or
//! submit URLs for scanning, only read existing public reputation. Requires
//! `VIRUSTOTAL_API_KEY`; absent ⇒ the provider is skipped by the aggregator.

use crate::providers::{ProviderVerdict, TargetKind, Verdict};
use serde::Deserialize;

const NAME: &str = "virustotal";
const BASE: &str = "https://www.virustotal.com/api/v3";

#[derive(Debug, Deserialize)]
struct VtEnvelope {
    data: VtData,
}
#[derive(Debug, Deserialize)]
struct VtData {
    #[serde(default)]
    attributes: VtAttributes,
}
#[derive(Debug, Default, Deserialize)]
struct VtAttributes {
    #[serde(default)]
    last_analysis_stats: AnalysisStats,
    #[serde(default)]
    reputation: i64,
    #[serde(default)]
    tags: Vec<String>,
}
#[derive(Debug, Default, Deserialize)]
struct AnalysisStats {
    #[serde(default)]
    harmless: u32,
    #[serde(default)]
    malicious: u32,
    #[serde(default)]
    suspicious: u32,
    #[serde(default)]
    undetected: u32,
}

/// Pure parse of a VT v3 object body into a normalized verdict.
///
/// Score = (malicious + 0.5*suspicious) / total_engines * 100, so a handful of
/// detections among many engines yields a proportionate (not alarmist) score.
/// Confidence scales with how many engines weighed in.
pub fn parse(body: &str) -> anyhow::Result<Option<ProviderVerdict>> {
    let env: VtEnvelope = match serde_json::from_str(body) {
        Ok(e) => e,
        Err(_) => return Ok(None), // 404 / error object → no verdict
    };
    let a = env.data.attributes;
    let s = &a.last_analysis_stats;
    let total = s.harmless + s.malicious + s.suspicious + s.undetected;

    let score = if total == 0 {
        0.0
    } else {
        (s.malicious as f32 + 0.5 * s.suspicious as f32) / total as f32 * 100.0
    };
    let score = score.round().clamp(0.0, 100.0) as u8;

    // Confidence: more engines ⇒ more trustworthy, saturating around 70 engines.
    let confidence = (total as f32 / 70.0).clamp(0.15, 1.0);

    let mut tags = Vec::new();
    if s.malicious > 0 {
        tags.push(format!("vt:{}malicious", s.malicious));
    }
    for t in a.tags.iter().take(6) {
        tags.push(t.clone());
    }

    Ok(Some(ProviderVerdict {
        provider: NAME.to_string(),
        score,
        confidence,
        verdict: Verdict::from_score(score),
        tags,
        raw: Some(serde_json::json!({
            "malicious": s.malicious,
            "suspicious": s.suspicious,
            "harmless": s.harmless,
            "undetected": s.undetected,
            "reputation": a.reputation,
        })),
    }))
}

fn endpoint(kind: TargetKind, value: &str) -> Option<String> {
    let enc = urlencode(value);
    Some(match kind {
        TargetKind::Ip => format!("{BASE}/ip_addresses/{enc}"),
        TargetKind::Domain => format!("{BASE}/domains/{enc}"),
        TargetKind::FileHash => format!("{BASE}/files/{enc}"),
        // VT wants URL ids as unpadded base64url of the URL; done by caller side
        // rarely — we support hash/ip/domain here and skip URL to stay simple.
        TargetKind::Url => return None,
    })
}

/// Network lookup. Returns Ok(None) when the key is missing or VT has no record.
pub async fn lookup(
    client: &reqwest::Client,
    api_key: Option<&str>,
    kind: TargetKind,
    value: &str,
) -> anyhow::Result<Option<ProviderVerdict>> {
    let Some(key) = api_key else { return Ok(None) };
    let Some(url) = endpoint(kind, value) else { return Ok(None) };

    let resp = client.get(&url).header("x-apikey", key).send().await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        anyhow::bail!("virustotal HTTP {}", resp.status());
    }
    let body = resp.text().await?;
    parse(&body)
}

// Minimal percent-encoding for path segments (alnum + a few safe chars pass).
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_malicious_file() {
        let body = r#"{"data":{"attributes":{
            "last_analysis_stats":{"harmless":10,"malicious":40,"suspicious":0,"undetected":20},
            "reputation":-50,"tags":["peexe","trojan"]}}}"#;
        let v = parse(body).unwrap().unwrap();
        assert_eq!(v.provider, "virustotal");
        // 40 / 70 * 100 = ~57
        assert!(v.score >= 55 && v.score <= 60, "score {}", v.score);
        assert_eq!(v.verdict, Verdict::Suspicious);
        assert!(v.tags.iter().any(|t| t.contains("40malicious")));
        assert!(v.tags.iter().any(|t| t == "trojan"));
    }

    #[test]
    fn clean_when_no_detections() {
        let body = r#"{"data":{"attributes":{
            "last_analysis_stats":{"harmless":60,"malicious":0,"suspicious":0,"undetected":10}}}}"#;
        let v = parse(body).unwrap().unwrap();
        assert_eq!(v.score, 0);
        assert_eq!(v.verdict, Verdict::Clean);
    }

    #[test]
    fn error_body_yields_none() {
        let body = r#"{"error":{"code":"NotFoundError","message":"not found"}}"#;
        assert!(parse(body).unwrap().is_none());
    }

    #[test]
    fn zero_engines_is_low_confidence() {
        let body = r#"{"data":{"attributes":{"last_analysis_stats":{}}}}"#;
        let v = parse(body).unwrap().unwrap();
        assert_eq!(v.score, 0);
        assert!(v.confidence <= 0.2);
    }
}
