//! Environment-driven configuration shared by all Rust services.

use anyhow::Context;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub redis_url: String,
    pub worker_concurrency: usize,
    pub scanner_max_concurrency: usize,
    pub scanner_rate_pps: u32,
    pub tor_socks_proxy: Option<String>,
    /// Optional OSINT / feed API keys (absent = provider skipped).
    pub nvd_api_key: Option<String>,
    pub otx_api_key: Option<String>,
    pub virustotal_api_key: Option<String>,
    pub abuseipdb_api_key: Option<String>,
    pub shodan_api_key: Option<String>,
    pub greynoise_api_key: Option<String>,
}

fn env_opt(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

impl Config {
    /// Load from process environment, failing fast on missing required values.
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            database_url: std::env::var("DATABASE_URL").context("DATABASE_URL is required")?,
            redis_url: std::env::var("REDIS_URL").unwrap_or_default(),
            worker_concurrency: env_opt("WORKER_CONCURRENCY")
                .and_then(|v| v.parse().ok())
                .unwrap_or(8),
            scanner_max_concurrency: env_opt("SCANNER_MAX_CONCURRENCY")
                .and_then(|v| v.parse().ok())
                .unwrap_or(512),
            scanner_rate_pps: env_opt("SCANNER_RATE_PPS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(2000),
            tor_socks_proxy: env_opt("TOR_SOCKS_PROXY"),
            nvd_api_key: env_opt("NVD_API_KEY"),
            otx_api_key: env_opt("OTX_API_KEY"),
            virustotal_api_key: env_opt("VIRUSTOTAL_API_KEY"),
            abuseipdb_api_key: env_opt("ABUSEIPDB_API_KEY"),
            shodan_api_key: env_opt("SHODAN_API_KEY"),
            greynoise_api_key: env_opt("GREYNOISE_API_KEY"),
        })
    }
}
