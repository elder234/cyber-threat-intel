//! Version → CVE correlation.
//!
//! Given technologies detected by `super::fingerprint`, build the SQL predicate
//! that finds matching CVEs in `aegis.cves`, and turn matches into `findings`
//! rows (`category = 'version_cve'`). The DB query lives in the scanner binary
//! (runtime `sqlx::query`, per the SQLX_OFFLINE rule); this module holds the
//! pure matching/scoring logic so it can be unit tested without a database.

use serde::Serialize;

/// A CVE candidate row as read from `aegis.cves` (narrow projection).
#[derive(Debug, Clone, PartialEq)]
pub struct CveRow {
    pub cve_id: String,
    pub cvss_v31_score: Option<f64>,
    pub cvss_v31_severity: Option<String>,
    /// Free-text description used for the loose product-name match.
    pub description: String,
}

/// A correlated finding ready to insert into `aegis.findings`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct VersionCveFinding {
    pub cve_id: String,
    pub title: String,
    pub severity: String, // low|medium|high|critical
    pub product: String,
    pub version: Option<String>,
    pub cpe: Option<String>,
    pub confidence: f32,
}

/// Map a CVSS base score to the project severity enum. Mirrors the CVSS v3.1
/// qualitative bands; `None` score falls back to medium so a match is never
/// silently dropped.
pub fn severity_from_cvss(score: Option<f64>, declared: Option<&str>) -> String {
    if let Some(s) = score {
        return match s {
            s if s >= 9.0 => "critical",
            s if s >= 7.0 => "high",
            s if s >= 4.0 => "medium",
            s if s > 0.0 => "low",
            _ => "low",
        }
        .to_string();
    }
    // No numeric score — trust the declared band if it is one of ours.
    match declared.map(|d| d.to_ascii_lowercase()) {
        Some(d) if matches!(d.as_str(), "critical" | "high" | "medium" | "low") => d,
        _ => "medium".to_string(),
    }
}

/// Does a CVE row plausibly concern this product (and version, if known)?
///
/// This is intentionally conservative: the CVE description must mention the
/// product name, and — when we know the running version — that exact version
/// string must appear too. Version-less matches are reported at low confidence
/// and flagged so the UI can separate "confirmed vulnerable version" from
/// "product has known CVEs, version unknown".
pub fn matches(product: &str, version: Option<&str>, row: &CveRow) -> Option<f32> {
    let desc = row.description.to_ascii_lowercase();
    let prod = product.trim().to_ascii_lowercase();
    if prod.is_empty() || !desc.contains(&prod) {
        return None;
    }
    match version {
        Some(v) if !v.is_empty() => {
            if desc.contains(&v.to_ascii_lowercase()) {
                Some(0.7) // product + exact version string present in description
            } else {
                None // product matches but a different version — do not report
            }
        }
        // Product matches, version unknown: low-confidence "worth reviewing".
        _ => Some(0.3),
    }
}

/// Build `VersionCveFinding`s for one detected product across candidate CVEs.
pub fn correlate(
    product: &str,
    version: Option<&str>,
    cpe: Option<&str>,
    candidates: &[CveRow],
) -> Vec<VersionCveFinding> {
    candidates
        .iter()
        .filter_map(|row| {
            let confidence = matches(product, version, row)?;
            let severity = severity_from_cvss(row.cvss_v31_score, row.cvss_v31_severity.as_deref());
            let title = match version {
                Some(v) if confidence >= 0.7 => {
                    format!("{product} {v} is affected by {}", row.cve_id)
                }
                _ => format!("{product} has a known vulnerability ({})", row.cve_id),
            };
            Some(VersionCveFinding {
                cve_id: row.cve_id.clone(),
                title,
                severity,
                product: product.to_string(),
                version: version.map(|s| s.to_string()),
                cpe: cpe.map(|s| s.to_string()),
                confidence,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cve(id: &str, score: f64, desc: &str) -> CveRow {
        CveRow {
            cve_id: id.to_string(),
            cvss_v31_score: Some(score),
            cvss_v31_severity: None,
            description: desc.to_string(),
        }
    }

    #[test]
    fn severity_bands() {
        assert_eq!(severity_from_cvss(Some(9.8), None), "critical");
        assert_eq!(severity_from_cvss(Some(7.5), None), "high");
        assert_eq!(severity_from_cvss(Some(5.0), None), "medium");
        assert_eq!(severity_from_cvss(Some(2.1), None), "low");
    }

    #[test]
    fn severity_falls_back_to_declared_then_medium() {
        assert_eq!(severity_from_cvss(None, Some("High")), "high");
        assert_eq!(severity_from_cvss(None, None), "medium");
        assert_eq!(severity_from_cvss(None, Some("bogus")), "medium");
    }

    #[test]
    fn exact_version_match_is_high_confidence() {
        let row = cve("CVE-2021-1", 9.8, "Apache HTTP Server 2.4.52 allows RCE");
        let c = matches("Apache", Some("2.4.52"), &row);
        assert_eq!(c, Some(0.7));
    }

    #[test]
    fn different_version_does_not_match() {
        let row = cve("CVE-2021-1", 9.8, "Apache HTTP Server 2.4.52 allows RCE");
        // Running 2.4.99 — the vuln text names 2.4.52, so no false positive.
        assert_eq!(matches("Apache", Some("2.4.99"), &row), None);
    }

    #[test]
    fn versionless_match_is_low_confidence() {
        let row = cve("CVE-2021-1", 7.5, "WordPress core is affected by XSS");
        assert_eq!(matches("WordPress", None, &row), Some(0.3));
    }

    #[test]
    fn unrelated_product_does_not_match() {
        let row = cve("CVE-2021-1", 9.8, "Apache HTTP Server 2.4.52 allows RCE");
        assert_eq!(matches("nginx", Some("1.20"), &row), None);
    }

    #[test]
    fn correlate_titles_reflect_confidence() {
        let rows = vec![cve("CVE-2021-1", 9.8, "apache http server 2.4.52 rce")];
        let out = correlate(
            "apache",
            Some("2.4.52"),
            Some("a:apache:http_server"),
            &rows,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, "critical");
        assert!(out[0].title.contains("2.4.52 is affected"));
        assert_eq!(out[0].cpe.as_deref(), Some("a:apache:http_server"));
    }

    #[test]
    fn empty_product_never_matches() {
        let row = cve("CVE-2021-1", 9.8, "something");
        assert_eq!(matches("", None, &row), None);
    }
}
