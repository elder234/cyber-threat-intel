//! Web fetch + cookie/body extraction for the passive pass.
//!
//! This is the only part of the passive fingerprint pipeline that touches the
//! network. It performs a single benign GET (the same thing a browser does) and
//! returns a normalized snapshot the pure detectors consume. No probing here.
//!
//! Requests are SSRF-hardened: loopback, link-local (cloud metadata), and IPv6
//! unique-local targets are always refused, and RFC1918 private targets are
//! refused unless `SCANNER_ALLOW_PRIVATE=1` is set (authorized internal scans).
//! Redirects are followed manually (bounded) with every hop re-validated.

use std::net::{IpAddr, ToSocketAddrs};
use std::sync::LazyLock;
use std::time::Duration;

use reqwest::{redirect, header, Url};

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

/// Maximum total redirect hops (initial request + up to `MAX_REDIRECTS` hops),
/// matching the previous `Policy::limited(5)` behavior.
const MAX_REDIRECTS: u32 = 5;

const USER_AGENT: &str = "aegis-cti-scanner/1.0 (+https://github.com/elder234/cyber-threat-intel)";

/// Opt-in for scanning/probing RFC1918 assets (authorized internal testing).
/// Loopback + link-local + IPv6 unique-local are blocked regardless.
static ALLOW_PRIVATE: LazyLock<bool> =
    LazyLock::new(|| std::env::var("SCANNER_ALLOW_PRIVATE").as_deref() == Ok("1"));

/// SSRF blocklist. Never-valid targets are always refused; RFC1918 is refused
/// unless the operator opts in. IPv4-mapped IPv6 is unwrapped and re-checked.
fn is_blocked_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || (!*ALLOW_PRIVATE && v4.is_private())
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4() {
                return is_blocked_ip(&IpAddr::V4(v4));
            }
            let hi = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unicast_link_local()
                || (0xfc00..=0xfdff).contains(&hi)
        }
    }
}

/// Fail closed if `url` resolves to any blocked address (or cannot resolve at
/// all). `Url::host_str()` already strips IPv6 brackets.
fn blocked_for(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return true;
    };

    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_blocked_ip(&ip);
    }

    let Some(port) = url.port_or_known_default() else {
        return true;
    };
    let Ok(addrs) = (host, port).to_socket_addrs() else {
        return true;
    };
    let addrs: Vec<IpAddr> = addrs.map(|sa| sa.ip()).collect();
    if addrs.is_empty() {
        return true;
    }
    addrs.iter().any(is_blocked_ip)
}

/// Perform a single passive GET against `url`. Follows redirects (bounded),
/// re-validating every hop against the SSRF blocklist, accepts invalid certs
/// (we inspect them separately), and never sends probe payloads. Returns
/// `None` on any transport/policy error.
pub async fn get(url: &str) -> Option<Fetched> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return None;
    }
    let start = Url::parse(url).ok()?;
    if blocked_for(&start) {
        return None;
    }

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(15))
        .redirect(redirect::Policy::none())
        .user_agent(USER_AGENT)
        .build()
        .ok()?;

    let mut current = start;
    for _ in 0..=MAX_REDIRECTS {
        let resp = client.get(current.clone()).send().await.ok()?;

        // Manual redirect handling so each hop is re-validated against the blocklist.
        if let Some(location) = resp.headers().get(header::LOCATION) {
            let next = current.join(location.to_str().ok()?).ok()?;
            if blocked_for(&next) {
                return None; // fail closed on a blocked redirect target
            }
            current = next;
            continue;
        }

        let status = resp.status().as_u16();
        let final_url = current.to_string();

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
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .filter_map(|c| c.split('=').next())
            .map(|name| name.trim().to_ascii_lowercase())
            .collect();

        // Bounded body read.
        let full = resp.bytes().await.ok()?;
        let slice = &full[..full.len().min(MAX_BODY)];
        let body = String::from_utf8_lossy(slice).to_string();

        return Some(Fetched {
            status,
            headers,
            cookie_names,
            body,
            final_url,
        });
    }
    None // redirect limit exceeded
}
