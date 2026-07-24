//! Shared HTTP client for collectors: sane timeouts, gzip, a descriptive
//! User-Agent, and optional Tor SOCKS routing for onion/censored sources.

use std::time::Duration;

/// Build a reqwest client. If `tor_socks` is set (e.g. `socks5h://127.0.0.1:9050`),
/// all traffic is routed through the Tor SOCKS proxy — used only for public onion
/// indexes, never to bypass authentication.
pub fn client(tor_socks: Option<&str>) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .user_agent("AegisCTI/0.1 (+https://github.com/aegis-cti; defensive-threat-intel)")
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(120))
        .gzip(true);

    if let Some(proxy) = tor_socks {
        builder = builder.proxy(reqwest::Proxy::all(proxy)?);
    }
    Ok(builder.build()?)
}

/// Default (clearnet) client.
pub fn default_client() -> anyhow::Result<reqwest::Client> {
    client(None)
}
