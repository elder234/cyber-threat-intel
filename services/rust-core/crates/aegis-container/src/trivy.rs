//! Normalize a Trivy JSON report into Aegis findings.
//!
//! Trivy is the de-facto open-source image vulnerability scanner. Rather than
//! reimplement a vuln database, Aegis ingests Trivy's `--format json` output and
//! maps each vulnerability onto the shared `Finding` model. Pure + tested.

use crate::finding::{Category, Finding, Severity};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct TrivyReport {
    #[serde(rename = "Results", default)]
    results: Vec<TrivyResult>,
}

#[derive(Debug, Deserialize)]
struct TrivyResult {
    #[serde(rename = "Target", default)]
    target: String,
    #[serde(rename = "Vulnerabilities", default)]
    vulnerabilities: Vec<TrivyVuln>,
}

#[derive(Debug, Deserialize)]
struct TrivyVuln {
    #[serde(rename = "VulnerabilityID", default)]
    id: String,
    #[serde(rename = "PkgName", default)]
    pkg_name: String,
    #[serde(rename = "InstalledVersion", default)]
    installed_version: String,
    #[serde(rename = "FixedVersion", default)]
    fixed_version: String,
    #[serde(rename = "Severity", default)]
    severity: String,
    #[serde(rename = "Title", default)]
    title: String,
}

/// Map Trivy severity strings to our enum. Unknown → Low (conservative).
fn map_severity(s: &str) -> Severity {
    match s.to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        "UNKNOWN" | "NEGLIGIBLE" => Severity::Info,
        _ => Severity::Low,
    }
}

/// Parse a Trivy JSON report into findings.
pub fn parse(json: &str) -> anyhow::Result<Vec<Finding>> {
    let report: TrivyReport = serde_json::from_str(json)?;
    let mut findings = Vec::new();

    for result in &report.results {
        for v in &result.vulnerabilities {
            let title = if v.title.is_empty() {
                format!("{} in {} {}", v.id, v.pkg_name, v.installed_version)
            } else {
                format!("{}: {}", v.id, v.title)
            };
            let remediation = if v.fixed_version.is_empty() {
                "No fixed version published; assess exposure and consider mitigations".to_string()
            } else {
                format!("Upgrade {} to {} or later", v.pkg_name, v.fixed_version)
            };
            let location = if result.target.is_empty() {
                format!("{} {}", v.pkg_name, v.installed_version)
            } else {
                format!("{} · {} {}", result.target, v.pkg_name, v.installed_version)
            };
            findings.push(
                Finding::new(
                    if v.id.is_empty() {
                        "CVE-UNKNOWN".to_string()
                    } else {
                        v.id.clone()
                    },
                    Category::Vulnerability,
                    map_severity(&v.severity),
                    title,
                    remediation,
                )
                .at(location),
            );
        }
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "Results": [
        {
          "Target": "app:latest (alpine 3.19)",
          "Vulnerabilities": [
            {
              "VulnerabilityID": "CVE-2024-0001",
              "PkgName": "openssl",
              "InstalledVersion": "3.0.0",
              "FixedVersion": "3.0.13",
              "Severity": "CRITICAL",
              "Title": "buffer overflow in TLS"
            },
            {
              "VulnerabilityID": "CVE-2024-0002",
              "PkgName": "zlib",
              "InstalledVersion": "1.2.11",
              "FixedVersion": "",
              "Severity": "medium"
            }
          ]
        }
      ]
    }"#;

    #[test]
    fn parses_vulnerabilities() {
        let f = parse(SAMPLE).unwrap();
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].id, "CVE-2024-0001");
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(f[0].title.contains("buffer overflow"));
        assert!(f[0].remediation.contains("3.0.13"));
    }

    #[test]
    fn handles_missing_fix_and_title() {
        let f = parse(SAMPLE).unwrap();
        assert_eq!(f[1].severity, Severity::Medium);
        assert!(f[1].title.contains("zlib"));
        assert!(f[1].remediation.contains("No fixed version"));
    }

    #[test]
    fn empty_report_is_ok() {
        let f = parse(r#"{"Results":[]}"#).unwrap();
        assert!(f.is_empty());
    }

    #[test]
    fn missing_results_key_is_ok() {
        let f = parse(r#"{}"#).unwrap();
        assert!(f.is_empty());
    }

    #[test]
    fn severity_mapping() {
        assert_eq!(map_severity("HIGH"), Severity::High);
        assert_eq!(map_severity("unknown"), Severity::Info);
        assert_eq!(map_severity("weird"), Severity::Low);
    }
}
