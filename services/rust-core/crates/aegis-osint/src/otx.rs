//! AlienVault OTX lookups (IP / domain / file hash).
//!
//! Uses the general indicator endpoint's `pulse_info` section. OTX has no single
//! reputation score, so we derive one from how many community "pulses" reference
//! the indicator (each pulse is a curated threat report) plus any bundled
//! validation/whitelist hints. Requires `OTX_API_KEY`.

use crate::providers::{ProviderVerdict, TargetKind, Verdict};
use serde::Deserialize;

const NAME: &str = "otx";
const BASE: &str = "https://otx.alienvault.com/api/v1/indicators";

#[derive(Debug, Deserialize)]
struct Indicator {
    #[serde(default)]
    pulse_info: PulseInfo,
    #[serde(default)]
    validation: Vec<Validation>,
}
#[derive(Debug, Default, Deserialize)]
struct PulseInfo {
    #[serde(default)]
    count: u32,
    #[serde(default)]
    pulses: Vec<Pulse>,
}
#[derive(Debug, Deserialize)]
struct Pulse {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    malware_families: Vec<serde_json::Value>,
}
#[derive(Debug, Deserialize)]
struct Validation {
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

/// Pure parse of an OTX indicator body.
///
/// Score scales with pulse count (community corroboration). A present
/// `validation` entry (e.g. an Alexa/whitelist source) is a strong "known good"
/// signal that caps the score down.
pub fn parse(body: &str) -> anyhow::Result<Option<ProviderVerdict>> {
    let ind: Indicator = match serde_json::from_str(body) {
        Ok(i) => i,
        Err(_) => return Ok(None),
    };

    let count = ind.pulse_info.count;
    let whitelisted = !ind.validation.is_empty();

    let mut score: u8 = match count {
        0 => 0,
        1 => 30,
        2..=4 => 55,
        5..=9 => 70,
        _ => 85,
    };
    if whitelisted {
        // Known-good listing overrides pulse-driven suspicion.
        score = score.min(15);
    }

    let mut tags = Vec::new();
    if count > 0 {
        tags.push(format!("otx:{count}pulses"));
    }
    if whitelisted {
        let src = ind
            .validation
            .iter()
            .filter_map(|v| v.source.as_deref().or(v.name.as_deref()))
            .next()
            .unwrap_or("whitelist");
        tags.push(format!("whitelisted:{}", src.to_lowercase()));
    }
    // Surface a few pulse names and any malware family tags for context.
    for p in ind.pulse_info.pulses.iter().take(3) {
        if let Some(n) = &p.name {
            tags.push(format!("pulse:{}", n.to_lowercase().replace(' ', "-")));
        }
        for t in p.tags.iter().take(2) {
            let t = t.to_lowercase();
            if !tags.contains(&t) {
                tags.push(t);
            }
        }
        if !p.malware_families.is_empty() {
            tags.push("malware-family".to_string());
        }
    }

    let confidence = if whitelisted {
        0.75
    } else {
        match count {
            0 => 0.3,
            1..=2 => 0.55,
            _ => 0.8,
        }
    };

    Ok(Some(ProviderVerdict {
        provider: NAME.to_string(),
        score,
        confidence,
        verdict: Verdict::from_score(score),
        tags,
        raw: Some(serde_json::json!({
            "pulse_count": count,
            "whitelisted": whitelisted,
        })),
    }))
}

/// OTX section path for each indicator kind.
fn section(kind: TargetKind, value: &str) -> Option<String> {
    Some(match kind {
        TargetKind::Ip => {
            // OTX splits IPv4/IPv6; a ':' in the value marks IPv6.
            if value.contains(':') {
                format!("{BASE}/IPv6/{value}/general")
            } else {
                format!("{BASE}/IPv4/{value}/general")
            }
        }
        TargetKind::Domain => format!("{BASE}/domain/{value}/general"),
        TargetKind::FileHash => format!("{BASE}/file/{value}/general"),
        TargetKind::Url => return None, // handled by url section rarely; skip
    })
}

/// Network lookup — IP / domain / file hash.
pub async fn lookup(
    client: &reqwest::Client,
    api_key: Option<&str>,
    kind: TargetKind,
    value: &str,
) -> anyhow::Result<Option<ProviderVerdict>> {
    let Some(key) = api_key else { return Ok(None) };
    let Some(url) = section(kind, value) else { return Ok(None) };
    let resp = client.get(&url).header("X-OTX-API-KEY", key).send().await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        anyhow::bail!("otx HTTP {}", resp.status());
    }
    let body = resp.text().await?;
    parse(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn many_pulses_is_malicious() {
        let body = r#"{"pulse_info":{"count":12,"pulses":[
            {"name":"Emotet C2","tags":["emotet"],"malware_families":[{"display_name":"Emotet"}]}]}}"#;
        let v = parse(body).unwrap().unwrap();
        assert_eq!(v.verdict, Verdict::Malicious);
        assert!(v.tags.iter().any(|t| t == "otx:12pulses"));
        assert!(v.tags.iter().any(|t| t.starts_with("pulse:emotet")));
        assert!(v.tags.iter().any(|t| t == "malware-family"));
    }

    #[test]
    fn whitelist_overrides_pulses() {
        let body = r#"{"pulse_info":{"count":6,"pulses":[]},
            "validation":[{"source":"whitelist","name":"Alexa"}]}"#;
        let v = parse(body).unwrap().unwrap();
        assert!(v.score <= 15);
        assert_eq!(v.verdict, Verdict::Clean);
        assert!(v.tags.iter().any(|t| t.starts_with("whitelisted:")));
    }

    #[test]
    fn no_pulses_is_clean_low_confidence() {
        let body = r#"{"pulse_info":{"count":0,"pulses":[]}}"#;
        let v = parse(body).unwrap().unwrap();
        assert_eq!(v.score, 0);
        assert_eq!(v.verdict, Verdict::Clean);
        assert!(v.confidence <= 0.3);
    }

    #[test]
    fn junk_yields_none() {
        assert!(parse("<html>").unwrap().is_none());
    }
}
