//! Aegis container-security analysis library (Module 6).
//!
//! Pure, dependency-light analyzers for container hardening:
//!   - `dockerfile`  — Dockerfile security lint (CIS-aligned)
//!   - `image`       — OCI/`docker inspect` runtime-config audit
//!   - `trivy`       — normalize an external Trivy vuln report into findings
//!   - `finding`     — shared finding model + risk scoring
//!
//! All logic here is offline and unit-tested. Actually building/pulling images
//! or shelling out to Trivy happens in the worker (⚠️ RUNTIME VERIFICATION
//! REQUIRED) and feeds JSON into these parsers.

pub mod dockerfile;
pub mod finding;
pub mod image;
pub mod trivy;

pub use finding::{summarize, Category, Finding, RiskSummary, Severity};

/// Convenience: analyze a Dockerfile and return findings + risk summary.
pub fn audit_dockerfile(text: &str) -> (Vec<Finding>, RiskSummary) {
    let findings = dockerfile::analyze(text);
    let summary = summarize(&findings);
    (findings, summary)
}

/// Convenience: analyze an image config JSON and return findings + summary.
pub fn audit_image_json(json: &str) -> anyhow::Result<(Vec<Finding>, RiskSummary)> {
    let findings = image::analyze_json(json)?;
    let summary = summarize(&findings);
    Ok((findings, summary))
}

/// Convenience: normalize a Trivy report and return findings + summary.
pub fn audit_trivy(json: &str) -> anyhow::Result<(Vec<Finding>, RiskSummary)> {
    let findings = trivy::parse(json)?;
    let summary = summarize(&findings);
    Ok((findings, summary))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_dockerfile_produces_summary() {
        let (findings, summary) = audit_dockerfile("FROM ubuntu\nADD https://x/y /y\n");
        assert!(!findings.is_empty());
        assert_eq!(summary.total, findings.len());
        assert!(summary.score > 0);
    }

    #[test]
    fn audit_trivy_roundtrip() {
        let json = r#"{"Results":[{"Target":"t","Vulnerabilities":[
            {"VulnerabilityID":"CVE-1","PkgName":"p","InstalledVersion":"1","FixedVersion":"2","Severity":"HIGH"}]}]}"#;
        let (findings, summary) = audit_trivy(json).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(summary.high, 1);
    }
}
