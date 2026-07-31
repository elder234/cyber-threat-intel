//! HTTP security header analysis. Given a set of response headers, flag missing
//! or weak security controls and produce structured findings. Pure + tested.

use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HeaderFinding {
    pub header: String,
    pub severity: String, // low|medium|high
    pub title: String,
    pub remediation: String,
}

/// Security headers we expect on a hardened web endpoint, with the severity of
/// their absence.
const CHECKS: &[(&str, &str, &str)] = &[
    (
        "strict-transport-security",
        "medium",
        "Add HSTS: max-age=63072000; includeSubDomains; preload",
    ),
    (
        "content-security-policy",
        "medium",
        "Define a Content-Security-Policy restricting script/style/frame sources",
    ),
    (
        "x-content-type-options",
        "low",
        "Set X-Content-Type-Options: nosniff",
    ),
    (
        "x-frame-options",
        "low",
        "Set X-Frame-Options: DENY (or use CSP frame-ancestors)",
    ),
    (
        "referrer-policy",
        "low",
        "Set Referrer-Policy: no-referrer or strict-origin-when-cross-origin",
    ),
    (
        "permissions-policy",
        "low",
        "Set Permissions-Policy to restrict powerful browser features",
    ),
];

/// Normalize header names to lowercase keys for lookup.
pub fn normalize_headers<'a, I>(pairs: I) -> Vec<(String, String)>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    pairs
        .into_iter()
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect()
}

/// Analyze headers and return findings for missing/weak controls.
pub fn analyze(headers: &[(String, String)]) -> Vec<HeaderFinding> {
    let present = |name: &str| headers.iter().any(|(k, _)| k == name);
    let get = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };

    let mut findings = Vec::new();

    for (header, severity, remediation) in CHECKS {
        if !present(header) {
            findings.push(HeaderFinding {
                header: header.to_string(),
                severity: severity.to_string(),
                title: format!("Missing security header: {header}"),
                remediation: remediation.to_string(),
            });
        }
    }

    // Weak/leaky configurations even when present.
    if let Some(server) = get("server") {
        if server.contains('/') {
            findings.push(HeaderFinding {
                header: "server".into(),
                severity: "low".into(),
                title: "Server header discloses software version".into(),
                remediation: "Suppress version details in the Server header".into(),
            });
        }
    }
    if get("x-powered-by").is_some() {
        findings.push(HeaderFinding {
            header: "x-powered-by".into(),
            severity: "low".into(),
            title: "X-Powered-By header discloses technology stack".into(),
            remediation: "Remove the X-Powered-By header".into(),
        });
    }
    // HSTS present but too short.
    if let Some(hsts) = get("strict-transport-security") {
        if let Some(age) = parse_max_age(hsts) {
            if age < 15_552_000 {
                findings.push(HeaderFinding {
                    header: "strict-transport-security".into(),
                    severity: "low".into(),
                    title: "HSTS max-age is shorter than 180 days".into(),
                    remediation: "Increase HSTS max-age to at least 15552000 (180 days)".into(),
                });
            }
        }
    }

    findings
}

fn parse_max_age(hsts: &str) -> Option<u64> {
    for part in hsts.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("max-age=") {
            return v.trim().parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_all_missing_on_bare_response() {
        let h = normalize_headers(vec![("Content-Type", "text/html")]);
        let f = analyze(&h);
        // All six standard checks should fire.
        assert!(f.iter().any(|x| x.header == "content-security-policy"));
        assert!(f.iter().any(|x| x.header == "strict-transport-security"));
        assert!(f.len() >= 6);
    }

    #[test]
    fn no_missing_findings_when_all_present() {
        let h = normalize_headers(vec![
            (
                "Strict-Transport-Security",
                "max-age=63072000; includeSubDomains",
            ),
            ("Content-Security-Policy", "default-src 'self'"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "no-referrer"),
            ("Permissions-Policy", "geolocation=()"),
        ]);
        let f = analyze(&h);
        assert!(f.iter().all(|x| !x.title.starts_with("Missing")));
    }

    #[test]
    fn flags_version_disclosure() {
        let h = normalize_headers(vec![
            ("Server", "Apache/2.4.52"),
            ("X-Powered-By", "PHP/8.1"),
        ]);
        let f = analyze(&h);
        assert!(f.iter().any(|x| x.header == "server"));
        assert!(f.iter().any(|x| x.header == "x-powered-by"));
    }

    #[test]
    fn flags_short_hsts() {
        let h = normalize_headers(vec![("Strict-Transport-Security", "max-age=3600")]);
        let f = analyze(&h);
        assert!(f.iter().any(|x| x.title.contains("shorter than 180 days")));
    }

    #[test]
    fn parses_max_age() {
        assert_eq!(
            parse_max_age("max-age=63072000; includeSubDomains"),
            Some(63072000)
        );
        assert_eq!(parse_max_age("includeSubDomains"), None);
    }
}
