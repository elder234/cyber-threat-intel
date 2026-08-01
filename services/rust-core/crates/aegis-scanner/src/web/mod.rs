//! Web application inspection (feature F-DAST).
//!
//! Two stages:
//!   1. **Passive** (`fingerprint` + `correlate` + `fetch`): fetch the target,
//!      detect its tech stack, analyze headers/cookies, and correlate detected
//!      service versions against the CVE database. No attack traffic — safe
//!      against any reachable host.
//!   2. **Active** (`probes`): benign, non-destructive DAST markers, sent ONLY
//!      when the target asset is authorized (`assets.is_authorized = true`) and
//!      the scan's probe policy enables them. Enforced in the scanner binary
//!      before any probe is dispatched.
//!
//! The DB reads/writes live in the scanner binary (runtime `sqlx::query`, per
//! the `SQLX_OFFLINE=true` rule); this module holds network I/O and pure logic.

pub mod correlate;
pub mod fetch;
pub mod fingerprint;
pub mod probes;

pub use correlate::{CveRow, VersionCveFinding};
pub use fingerprint::{Fingerprint, Technology};

/// Result of the passive pass: what we detected and the raw snapshot, so the
/// caller can both persist fingerprints and drive the active stage from the same
/// fetch without hitting the network twice.
pub struct PassiveResult {
    pub fingerprint: Fingerprint,
    pub status: u16,
    pub final_url: String,
    /// Header findings from `http_headers::analyze`, reused verbatim.
    pub header_findings: Vec<crate::http_headers::HeaderFinding>,
}

/// Run the passive pass against a normalized `https?://host[:port]/` URL.
/// Returns `None` if the target could not be fetched.
pub async fn passive(url: &str) -> Option<PassiveResult> {
    let fetched = fetch::get(url).await?;
    let resp = fetched.as_response();
    let fingerprint = fingerprint::detect(&resp);
    let header_findings = crate::http_headers::analyze(&fetched.headers);
    Some(PassiveResult {
        fingerprint,
        status: fetched.status,
        final_url: fetched.final_url.clone(),
        header_findings,
    })
}

/// Normalize an operator-supplied target into a fetchable URL. Accepts bare
/// hosts (defaults to https), full URLs, and host:port.
pub fn normalize_url(target: &str) -> String {
    let t = target.trim();
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t.trim_end_matches('/'))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_defaults_to_https() {
        assert_eq!(normalize_url("example.com"), "https://example.com");
        assert_eq!(normalize_url("example.com/"), "https://example.com");
        assert_eq!(normalize_url("http://x.test"), "http://x.test");
        assert_eq!(normalize_url("https://x.test/a"), "https://x.test/a");
    }
}
