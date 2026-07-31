//! Shared finding model for container security analysis.
//!
//! Every analyzer (Dockerfile lint, image-config audit, external scanner report
//! normalization) emits `Finding`s so the API and UI see one uniform shape.

use serde::{Deserialize, Serialize};

/// Severity ranking aligned with the platform-wide `aegis.severity` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Lowercase label matching the DB enum.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Numeric weight used for risk scoring.
    pub fn weight(self) -> u32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 3,
            Severity::High => 8,
            Severity::Critical => 15,
        }
    }
}

/// Where a finding originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Dockerfile,
    ImageConfig,
    Vulnerability,
    Secret,
    Compose,
}

impl Category {
    /// snake_case label matching the `aegis.container_finding_category` DB enum.
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Dockerfile => "dockerfile",
            Category::ImageConfig => "image_config",
            Category::Vulnerability => "vulnerability",
            Category::Secret => "secret",
            Category::Compose => "compose",
        }
    }
}

/// A single container-security finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable rule id, e.g. "DKR-USER-ROOT" or a CVE id for vulnerabilities.
    pub id: String,
    pub category: Category,
    pub severity: Severity,
    pub title: String,
    /// Human-actionable remediation guidance.
    pub remediation: String,
    /// Optional source line / layer / package for context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

impl Finding {
    pub fn new(
        id: impl Into<String>,
        category: Category,
        severity: Severity,
        title: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Finding {
            id: id.into(),
            category,
            severity,
            title: title.into(),
            remediation: remediation.into(),
            location: None,
        }
    }

    pub fn at(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }
}

/// Aggregate a set of findings into a 0–100 risk score + severity counts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskSummary {
    pub score: u32,
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

/// Compute a bounded risk score. A single critical is already alarming, so the
/// curve saturates quickly: weighted sum scaled and capped at 100.
pub fn summarize(findings: &[Finding]) -> RiskSummary {
    let mut s = RiskSummary {
        score: 0,
        total: findings.len(),
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
    };
    let mut weight = 0u32;
    for f in findings {
        weight += f.severity.weight();
        match f.severity {
            Severity::Critical => s.critical += 1,
            Severity::High => s.high += 1,
            Severity::Medium => s.medium += 1,
            Severity::Low => s.low += 1,
            Severity::Info => s.info += 1,
        }
    }
    // Scale: 6 weight units ≈ 100 pts before capping, so one critical (15) maxes
    // out and a couple of mediums land mid-range.
    s.score = (weight * 100 / 20).min(100);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_and_labels() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::Info < Severity::Low);
        assert_eq!(Severity::High.as_str(), "high");
    }

    #[test]
    fn category_labels_match_db_enum() {
        assert_eq!(Category::Dockerfile.as_str(), "dockerfile");
        assert_eq!(Category::ImageConfig.as_str(), "image_config");
        assert_eq!(Category::Vulnerability.as_str(), "vulnerability");
        assert_eq!(Category::Secret.as_str(), "secret");
        assert_eq!(Category::Compose.as_str(), "compose");
    }

    #[test]
    fn empty_findings_score_zero() {
        let s = summarize(&[]);
        assert_eq!(s.score, 0);
        assert_eq!(s.total, 0);
    }

    #[test]
    fn one_critical_saturates_score() {
        let f = vec![Finding::new(
            "X",
            Category::Dockerfile,
            Severity::Critical,
            "t",
            "r",
        )];
        let s = summarize(&f);
        assert_eq!(s.score, 75); // 15*100/20 = 75
        assert_eq!(s.critical, 1);
    }

    #[test]
    fn score_caps_at_100() {
        let f: Vec<Finding> = (0..10)
            .map(|i| {
                Finding::new(
                    format!("X{i}"),
                    Category::Dockerfile,
                    Severity::Critical,
                    "t",
                    "r",
                )
            })
            .collect();
        let s = summarize(&f);
        assert_eq!(s.score, 100);
        assert_eq!(s.critical, 10);
    }

    #[test]
    fn counts_by_severity() {
        let f = vec![
            Finding::new("A", Category::Dockerfile, Severity::High, "t", "r"),
            Finding::new("B", Category::Dockerfile, Severity::Medium, "t", "r"),
            Finding::new("C", Category::Dockerfile, Severity::Medium, "t", "r"),
        ];
        let s = summarize(&f);
        assert_eq!(s.high, 1);
        assert_eq!(s.medium, 2);
        assert_eq!(s.total, 3);
    }
}
