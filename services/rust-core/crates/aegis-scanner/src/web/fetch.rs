//! Web fetch + cookie/body extraction for the passive pass.
//!
//! This is the only part of the passive fingerprint pipeline that touches the
//! network. It performs a single benign GET (the same thing a browser does) and
//! returns a normalized snapshot the pure detectors consume. No probing here.

use std::time::Duration;

use super::fingerprint;

/// A fetched page, normalized for the pure detectors.
pub struct Fetched {
    pub status: u16,
    /// Lowercased header (name, value) pairs.
    pub headers: Vec<(String, String)>,
    /// Lowercased Set-Cookie cookie names.
    pub cookie_names: Vec<String>,
    /// Response body, truncated to `MAX_BODY`.
    pub body: String,
    /// Final URL after redirects.
    pub final_url: String,
}

impl Fetched {
    /// Borrow a `fingerprint::Response` view over this snapshot.
    pub fn as_response(&self) -> fingerprint::Response<'_> {
        fingerprint::Response {
            headers: &self.headers,
            cookie_names: &self.cookie_names,
            body: &self.body,
        }
    }
}

/// Cap the body we buffer — signatures only read a prefix, and this bounds
/// memory on a small host (see P5 in the audit backlog).
const MAX_BODY: usize = 512 * 1024;

const USER_AGENT: &str = "aegis-cti-scanner/1.0 (+https://github.com/elder234/cyber-threat-intel)";

/// Perform a single passive GET against `url`. Follows redirects (bounded),
/// accepts invalid certs (we inspect them separately), and never sends probe
/// payloads. Returns `None` on any transport error.
pub async fn get(url: &str) -> Option<Fetched> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent(USER_AGENT)
        .build()
        .ok()?;

    let resp = client.get(url).send().await.ok()?;
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();

    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_ascii_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();

    // Cookie names from all Set-Cookie headers.
    let cookie_names: Vec<String> = resp
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|c| c.split('=').next())
        .map(|name| name.trim().to_ascii_lowercase())
        .collect();

    // Bounded body read.
    let full = resp.bytes().await.ok()?;
    let slice = &full[..full.len().min(MAX_BODY)];
    let body = String::from_utf8_lossy(slice).to_string();

    Some(Fetched {
        status,
        headers,
        cookie_names,
        body,
        final_url,
    })
}
