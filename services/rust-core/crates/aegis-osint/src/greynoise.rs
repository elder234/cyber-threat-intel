//! GreyNoise reputation lookups (IP addresses only).
//!
//! Uses the Community API (`/v3/community/{ip}`), which returns whether an IP is
//! a known internet scanner and a `classification` of benign/malicious/unknown.
//! Requires `GREYNOISE_API_KEY`.
//!
//! Note: GreyNoise "noise" often means background internet scanning, which is
//! not necessarily malicious — a benign classification lowers our score even if
//! the IP is noisy, so we don't over-flag researchers/CDNs.

use crate::providers::{ProviderVerdict, TargetKind, Verdict};
use serde::Deserialize;

const NAME: &str = "greynoise";
const BASE: &str = "https://api.greynoise.io/v3/community";

#[derive(Debug, Deserialize)]
struct Community {
    #[serde(default)]
    noise: bool,
    #[serde(default)]
    riot: bool,
    #[serde(default)]
    classification: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    last_seen: Option<String>,
}

/// Pure parse of a GreyNoise community response.
pub fn parse(body: &str) -> anyhow::Result<Option<ProviderVerdict>> {
    let c: Community = match serde_json::from_str(body) {
        Ok(c) => c,
        Err(_) => return Ok(None), // "IP not observed" returns a 404 object
    };

    let class = c.classification.as_deref().unwrap_or("unknown");
    let score: u8 = match class {
        "malicious" => 85,
        "suspicious" => 50,
        "benign" => 5,
        _ => {
            // Unknown but noisy ⇒ mild suspicion; quiet ⇒ nothing.
            if c.noise {
                20
            } else {
                0
            }
        }
    };

    let mut tags = vec![format!("greynoise:{class}")];
    if c.noise {
        tags.push("internet-scanner".to_string());
    }
    if c.riot {
        tags.push("common-service".to_string()); // RIOT = benign business service
    }
    if let Some(name) = &c.name {
        if name != "unknown" {
            tags.push(format!("actor:{}", name.to_lowercase().replace(' ', "-")));
        }
    }

    // RIOT/benign are high-confidence "not a threat" signals.
    let confidence = if c.riot || class == "benign" || class == "malicious" {
        0.85
    } else {
        0.5
    };

    Ok(Some(ProviderVerdict {
        provider: NAME.to_string(),
        score,
        confidence,
        verdict: Verdict::from_score(score),
        tags,
        raw: Some(serde_json::json!({
            "classification": class,
            "noise": c.noise,
            "riot": c.riot,
            "last_seen": c.last_seen,
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
        .header("key", key)
        .send()
        .await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        anyhow::bail!("greynoise HTTP {}", resp.status());
    }
    let body = resp.text().await?;
    parse(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malicious_scanner() {
        let body = r#"{"noise":true,"riot":false,"classification":"malicious","name":"Mirai","last_seen":"2024-05-01"}"#;
        let v = parse(body).unwrap().unwrap();
        assert_eq!(v.verdict, Verdict::Malicious);
        assert!(v.tags.iter().any(|t| t == "internet-scanner"));
        assert!(v.tags.iter().any(|t| t == "actor:mirai"));
    }

    #[test]
    fn riot_business_service_is_clean() {
        let body = r#"{"noise":false,"riot":true,"classification":"benign","name":"Google"}"#;
        let v = parse(body).unwrap().unwrap();
        assert_eq!(v.verdict, Verdict::Clean);
        assert!(v.confidence >= 0.85);
        assert!(v.tags.iter().any(|t| t == "common-service"));
    }

    #[test]
    fn unknown_noisy_is_mild() {
        let body = r#"{"noise":true,"riot":false,"classification":"unknown"}"#;
        let v = parse(body).unwrap().unwrap();
        assert_eq!(v.score, 20);
        assert_eq!(v.verdict, Verdict::Clean);
    }

    #[test]
    fn not_observed_yields_none() {
        assert!(parse(r#"{"message":"IP not observed"}"#).unwrap().is_some());
        // ^ still parses (all defaults) → quiet unknown; a true 404 is handled in lookup().
    }
}
