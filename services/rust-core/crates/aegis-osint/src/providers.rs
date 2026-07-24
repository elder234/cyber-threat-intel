//! Shared OSINT model + the aggregation brain.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// What kind of indicator we are enriching. Providers advertise which kinds
/// they support so the aggregator can skip irrelevant lookups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Ip,
    Domain,
    Url,
    FileHash,
}

impl TargetKind {
    /// Map an `aegis.ioc_type` string to an enrichment target kind.
    pub fn from_ioc_type(t: &str) -> Option<Self> {
        match t {
            "ipv4" | "ipv6" => Some(Self::Ip),
            "domain" => Some(Self::Domain),
            "url" => Some(Self::Url),
            "md5" | "sha1" | "sha256" | "sha512" => Some(Self::FileHash),
            _ => None,
        }
    }
}

/// A single provider's opinion on an indicator, normalized to 0..=100 where
/// higher means *more malicious*. `confidence` (0.0..=1.0) weights the vote in
/// aggregation — a provider with thin signal should not dominate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderVerdict {
    pub provider: String,
    pub score: u8,
    pub confidence: f32,
    pub verdict: Verdict,
    /// Compact, human-readable facts surfaced in the UI (e.g. "ASN: 13335").
    #[serde(default)]
    pub tags: Vec<String>,
    /// Full raw provider payload (already trimmed by the provider module).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
    Unknown,
}

impl Verdict {
    pub(crate) fn from_score(score: u8) -> Self {
        match score {
            0..=24 => Verdict::Clean,
            25..=64 => Verdict::Suspicious,
            _ => Verdict::Malicious,
        }
    }
}

/// The consolidated verdict written back to the indicator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reputation {
    /// 0..=100 weighted malicious score.
    pub score: u8,
    pub verdict: Verdict,
    /// Number of providers that actually returned a usable answer.
    pub sources: u32,
    /// De-duplicated union of provider tags (stable order).
    pub tags: Vec<String>,
    /// Per-provider breakdown, keyed by provider name (stable order).
    pub providers: BTreeMap<String, ProviderVerdict>,
}

/// Fold per-provider verdicts into one reputation.
///
/// The combined score is a confidence-weighted mean of provider scores. We then
/// apply a small "corroboration" bump: when two or more providers independently
/// call something malicious, the aggregate is nudged up (capped at 100) because
/// agreement is itself signal. Empty input ⇒ Unknown / score 0.
pub fn aggregate(verdicts: Vec<ProviderVerdict>) -> Reputation {
    if verdicts.is_empty() {
        return Reputation {
            score: 0,
            verdict: Verdict::Unknown,
            sources: 0,
            tags: Vec::new(),
            providers: BTreeMap::new(),
        };
    }

    let mut weighted_sum = 0.0_f32;
    let mut weight_total = 0.0_f32;
    let mut malicious_votes = 0_u32;
    let mut tags: Vec<String> = Vec::new();
    let mut providers = BTreeMap::new();

    for v in verdicts {
        let w = v.confidence.clamp(0.0, 1.0);
        weighted_sum += v.score as f32 * w;
        weight_total += w;
        if v.verdict == Verdict::Malicious {
            malicious_votes += 1;
        }
        for t in &v.tags {
            if !tags.contains(t) {
                tags.push(t.clone());
            }
        }
        providers.insert(v.provider.clone(), v);
    }

    let base = if weight_total > 0.0 {
        weighted_sum / weight_total
    } else {
        // All providers reported zero confidence: fall back to a plain mean.
        let n = providers.len() as f32;
        providers.values().map(|p| p.score as f32).sum::<f32>() / n
    };

    // Corroboration bump: +8 per extra malicious vote beyond the first.
    let bump = malicious_votes.saturating_sub(1) as f32 * 8.0;
    let score = (base + bump).round().clamp(0.0, 100.0) as u8;

    Reputation {
        score,
        verdict: Verdict::from_score(score),
        sources: providers.len() as u32,
        tags,
        providers,
    }
}

/// Convenience constructor used by provider modules.
pub fn verdict(provider: &str, score: u8, confidence: f32, tags: Vec<String>) -> ProviderVerdict {
    ProviderVerdict {
        provider: provider.to_string(),
        score,
        confidence,
        verdict: Verdict::from_score(score),
        tags,
        raw: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_unknown() {
        let r = aggregate(vec![]);
        assert_eq!(r.verdict, Verdict::Unknown);
        assert_eq!(r.score, 0);
        assert_eq!(r.sources, 0);
    }

    #[test]
    fn single_provider_passes_through() {
        let r = aggregate(vec![verdict("vt", 80, 1.0, vec!["malware".into()])]);
        assert_eq!(r.score, 80);
        assert_eq!(r.verdict, Verdict::Malicious);
        assert_eq!(r.sources, 1);
        assert_eq!(r.tags, vec!["malware".to_string()]);
    }

    #[test]
    fn confidence_weights_the_mean() {
        // High-confidence clean should outweigh a low-confidence malicious.
        let r = aggregate(vec![
            verdict("a", 0, 1.0, vec![]),
            verdict("b", 100, 0.2, vec![]),
        ]);
        // weighted = (0*1 + 100*0.2) / 1.2 = ~16.7 → Clean
        assert!(r.score < 25, "score was {}", r.score);
        assert_eq!(r.verdict, Verdict::Clean);
    }

    #[test]
    fn corroboration_bumps_agreeing_malicious() {
        let no_bump = aggregate(vec![verdict("a", 70, 1.0, vec![])]).score;
        let bumped = aggregate(vec![
            verdict("a", 70, 1.0, vec![]),
            verdict("b", 70, 1.0, vec![]),
        ])
        .score;
        assert!(bumped > no_bump, "{bumped} should exceed {no_bump}");
    }

    #[test]
    fn tags_are_deduped_in_order() {
        let r = aggregate(vec![
            verdict("a", 10, 1.0, vec!["tor".into(), "scanner".into()]),
            verdict("b", 10, 1.0, vec!["scanner".into(), "vpn".into()]),
        ]);
        assert_eq!(r.tags, vec!["tor", "scanner", "vpn"]);
    }

    #[test]
    fn score_is_capped_at_100() {
        let r = aggregate(vec![
            verdict("a", 100, 1.0, vec![]),
            verdict("b", 100, 1.0, vec![]),
            verdict("c", 100, 1.0, vec![]),
        ]);
        assert_eq!(r.score, 100);
    }

    #[test]
    fn target_kind_mapping() {
        assert_eq!(TargetKind::from_ioc_type("ipv4"), Some(TargetKind::Ip));
        assert_eq!(TargetKind::from_ioc_type("sha256"), Some(TargetKind::FileHash));
        assert_eq!(TargetKind::from_ioc_type("mutex"), None);
    }
}
