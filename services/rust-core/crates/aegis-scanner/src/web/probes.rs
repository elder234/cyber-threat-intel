//! Active DAST probes — benign, non-destructive markers only (feature F-DAST.3).
//!
//! # Safety model (read before touching this file)
//!
//! Every probe here is a *detection marker*, not an exploit:
//!   * reflected-XSS  → an inert unique token; we check whether it is reflected
//!     verbatim into the response. We never inject an executing `<script>` that
//!     changes server state.
//!   * error-based SQLi → a syntactically-breaking token; we look for database
//!     error signatures in the response. No stacked queries, no `OR 1=1` auth
//!     bypass, no time-based blind that hammers the target.
//!   * path traversal → a bounded `../` sequence toward a well-known read-only
//!     canary path; we match a signature. Never write, never escape to secrets.
//!   * open redirect → a marker host in a redirect parameter; we check whether
//!     the response 3xx-redirects to it.
//!
//! These are GET-only, idempotent, and capped per parameter. Destructive HTTP
//! methods and state-mutating form submissions are out of scope by construction.
//!
//! **This module never sends traffic on its own.** It builds probe requests and
//! classifies responses (pure logic, unit tested). The scanner binary is
//! responsible for enforcing `assets.is_authorized = true` and the scan's probe
//! policy BEFORE calling `dispatch`. If you cannot see that gate on the code
//! path that reaches here, the probe must not run.

use std::str::FromStr;

use serde::Serialize;

/// Probe classes, matching the `probe_classes` values seeded in
/// `db/migrations/0014_web_inspection.sql`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeClass {
    Xss,
    Sqli,
    PathTraversal,
    OpenRedirect,
}

impl ProbeClass {
    pub fn as_str(self) -> &'static str {
        match self {
            ProbeClass::Xss => "xss",
            ProbeClass::Sqli => "sqli",
            ProbeClass::PathTraversal => "path_traversal",
            ProbeClass::OpenRedirect => "open_redirect",
        }
    }
}

impl FromStr for ProbeClass {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "xss" => Ok(ProbeClass::Xss),
            "sqli" => Ok(ProbeClass::Sqli),
            "path_traversal" => Ok(ProbeClass::PathTraversal),
            "open_redirect" => Ok(ProbeClass::OpenRedirect),
            _ => Err(()),
        }
    }
}

/// A benign payload to place in a single parameter, plus how to recognise a hit.
#[derive(Debug, Clone, PartialEq)]
pub struct Payload {
    pub class: ProbeClass,
    /// The value to inject into the target parameter.
    pub value: String,
    /// A unique inert marker embedded in `value`, used to attribute reflections.
    pub marker: String,
}

/// A response as seen by the classifier. Header keys lowercased.
pub struct ProbeResponse<'a> {
    pub status: u16,
    pub headers: &'a [(String, String)],
    pub body: &'a str,
}

impl ProbeResponse<'_> {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A confirmed-or-suspected issue from one probe.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ProbeFinding {
    pub class: String,
    pub param: String,
    pub payload: String,
    pub marker: String,
    /// What in the response confirmed it (reflection / error signature / redirect).
    pub evidence: String,
    /// 0.0..1.0 — verbatim reflection is high, error-signature medium.
    pub confidence: f32,
    pub severity: String,
}

/// A short random-ish marker. Deterministic input keeps tests stable; callers
/// pass a per-scan nonce so markers are unique across scans.
pub fn marker(nonce: &str, class: ProbeClass) -> String {
    format!("aeg{}{}", class.as_str().chars().next().unwrap(), nonce)
}

/// Database error signatures for the SQLi classifier. Substring match, lowercased.
const SQL_ERROR_SIGNATURES: &[&str] = &[
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query()",
    "psql: error",
    "sqlite3::",
    "sqlstate[",
    "ora-01756",
    "odbc sql server driver",
    "syntax error at or near",
];

/// Path-traversal response signatures (contents of well-known readable files).
const TRAVERSAL_SIGNATURES: &[&str] = &["root:x:0:0:", "[extensions]", "; for 16-bit app support"];

/// Build the payloads for one parameter given the enabled classes and a per-scan
/// nonce. Capped by `max_per_param`.
pub fn payloads_for(classes: &[ProbeClass], nonce: &str, max_per_param: usize) -> Vec<Payload> {
    let mut out = Vec::new();
    for &class in classes {
        let m = marker(nonce, class);
        let value = match class {
            // Inert marker wrapped in a harmless tag-ish string; we only test for
            // verbatim reflection, not execution.
            ProbeClass::Xss => format!("\"'><{m}>"),
            // Breaks SQL string context to elicit a parser error — no logic bypass.
            ProbeClass::Sqli => format!("{m}'\""),
            // Bounded traversal toward a canonical read-only canary.
            ProbeClass::PathTraversal => "../../../../etc/passwd".to_string(),
            // Marker host in a redirect target.
            ProbeClass::OpenRedirect => format!("https://{m}.example.invalid/"),
        };
        out.push(Payload {
            class,
            value,
            marker: m,
        });
    }
    out.truncate(max_per_param);
    out
}

/// Classify a probe response. Returns a finding only when the marker/signature
/// actually appears — no speculative reporting.
pub fn classify(payload: &Payload, param: &str, resp: &ProbeResponse) -> Option<ProbeFinding> {
    match payload.class {
        ProbeClass::Xss => {
            // Verbatim reflection of the full injected value (incl. the angle
            // bracket) is the signal. Reflection of the bare marker alone is
            // weaker but still worth a low-confidence note.
            if resp.body.contains(&format!("<{}>", payload.marker)) {
                Some(finding(
                    payload,
                    param,
                    "payload reflected unencoded in body",
                    0.8,
                    "high",
                ))
            } else if resp.body.contains(&payload.marker) {
                Some(finding(
                    payload,
                    param,
                    "marker reflected (encoding unknown)",
                    0.4,
                    "medium",
                ))
            } else {
                None
            }
        }
        ProbeClass::Sqli => {
            let lower = resp.body.to_ascii_lowercase();
            let sig = SQL_ERROR_SIGNATURES.iter().find(|s| lower.contains(**s))?;
            Some(finding(
                payload,
                param,
                &format!("SQL error signature in response: {sig}"),
                0.6,
                "high",
            ))
        }
        ProbeClass::PathTraversal => {
            let sig = TRAVERSAL_SIGNATURES
                .iter()
                .find(|s| resp.body.contains(**s))?;
            Some(finding(
                payload,
                param,
                &format!("file-content signature in response: {sig}"),
                0.7,
                "high",
            ))
        }
        ProbeClass::OpenRedirect => {
            // A 3xx whose Location points at our marker host confirms it.
            if (300..400).contains(&resp.status) {
                if let Some(loc) = resp.header("location") {
                    if loc.contains(&payload.marker) {
                        return Some(finding(
                            payload,
                            param,
                            &format!("redirects to attacker-controlled host: {loc}"),
                            0.8,
                            "medium",
                        ));
                    }
                }
            }
            None
        }
    }
}

fn finding(
    payload: &Payload,
    param: &str,
    evidence: &str,
    confidence: f32,
    severity: &str,
) -> ProbeFinding {
    ProbeFinding {
        class: payload.class.as_str().to_string(),
        param: param.to_string(),
        payload: payload.value.clone(),
        marker: payload.marker.clone(),
        evidence: evidence.to_string(),
        confidence,
        severity: severity.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp<'a>(status: u16, headers: &'a [(String, String)], body: &'a str) -> ProbeResponse<'a> {
        ProbeResponse {
            status,
            headers,
            body,
        }
    }

    #[test]
    fn class_roundtrip() {
        for c in [
            ProbeClass::Xss,
            ProbeClass::Sqli,
            ProbeClass::PathTraversal,
            ProbeClass::OpenRedirect,
        ] {
            assert_eq!(c.as_str().parse(), Ok(c));
        }
        assert_eq!("nope".parse::<ProbeClass>(), Err(()));
    }

    #[test]
    fn payloads_are_capped() {
        let classes = [ProbeClass::Xss, ProbeClass::Sqli, ProbeClass::PathTraversal];
        let p = payloads_for(&classes, "abc", 2);
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn xss_verbatim_reflection_is_high_confidence() {
        let p = &payloads_for(&[ProbeClass::Xss], "n1", 4)[0];
        let body = format!("<html>hello <{}> world</html>", p.marker);
        let f = classify(p, "q", &resp(200, &[], &body)).unwrap();
        assert_eq!(f.severity, "high");
        assert!(f.confidence >= 0.8);
    }

    #[test]
    fn xss_no_reflection_no_finding() {
        let p = &payloads_for(&[ProbeClass::Xss], "n1", 4)[0];
        assert!(classify(p, "q", &resp(200, &[], "clean page")).is_none());
    }

    #[test]
    fn sqli_error_signature_detected() {
        let p = &payloads_for(&[ProbeClass::Sqli], "n1", 4)[0];
        let body = "Warning: mysql_fetch_array(): supplied argument...";
        let f = classify(p, "id", &resp(500, &[], body)).unwrap();
        assert_eq!(f.class, "sqli");
    }

    #[test]
    fn sqli_clean_response_no_finding() {
        let p = &payloads_for(&[ProbeClass::Sqli], "n1", 4)[0];
        assert!(classify(p, "id", &resp(200, &[], "normal results")).is_none());
    }

    #[test]
    fn traversal_passwd_signature_detected() {
        let p = &payloads_for(&[ProbeClass::PathTraversal], "n1", 4)[0];
        let f = classify(
            p,
            "file",
            &resp(200, &[], "root:x:0:0:root:/root:/bin/bash"),
        )
        .unwrap();
        assert_eq!(f.class, "path_traversal");
        assert!(f.confidence >= 0.7);
    }

    #[test]
    fn open_redirect_to_marker_host_detected() {
        let p = &payloads_for(&[ProbeClass::OpenRedirect], "n1", 4)[0];
        let headers = vec![(
            "location".to_string(),
            format!("https://{}.example.invalid/", p.marker),
        )];
        let f = classify(p, "next", &resp(302, &headers, "")).unwrap();
        assert_eq!(f.class, "open_redirect");
    }

    #[test]
    fn open_redirect_same_site_no_finding() {
        let p = &payloads_for(&[ProbeClass::OpenRedirect], "n1", 4)[0];
        let headers = vec![(
            "location".to_string(),
            "https://legit.example/home".to_string(),
        )];
        assert!(classify(p, "next", &resp(302, &headers, "")).is_none());
    }

    #[test]
    fn markers_differ_by_class() {
        assert_ne!(marker("x", ProbeClass::Xss), marker("x", ProbeClass::Sqli));
    }
}
