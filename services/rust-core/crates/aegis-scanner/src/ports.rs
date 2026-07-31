//! Async TCP connect scanner with bounded concurrency and a simple rate limiter.
//! Performs a connect() to each (ip, port); on success, attempts a short banner
//! read. Optionally issues a minimal HTTP HEAD for web ports.
//!
//! ⚠️ RUNTIME VERIFICATION REQUIRED: sockets not exercised (VM unavailable).

use crate::service::{self, ServiceInfo};
use futures::stream::{self, StreamExt};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout};

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub connect_timeout: Duration,
    pub banner_timeout: Duration,
    pub max_concurrency: usize,
    /// Minimum delay between connection starts (rate limit). Zero disables.
    pub per_conn_delay: Duration,
    /// Grab banners on open ports.
    pub grab_banner: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(2),
            banner_timeout: Duration::from_millis(1500),
            max_concurrency: 512,
            per_conn_delay: Duration::from_millis(0),
            grab_banner: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OpenPort {
    pub ip: IpAddr,
    pub port: u16,
    pub banner: Option<String>,
    pub service: ServiceInfo,
}

/// Scan a single host across many ports. Returns only open ports.
pub async fn scan_host(ip: IpAddr, ports: &[u16], cfg: &ScanConfig) -> Vec<OpenPort> {
    let sem = Arc::new(Semaphore::new(cfg.max_concurrency));
    let cfg = Arc::new(cfg.clone());

    let results = stream::iter(ports.iter().copied())
        .map(|port| {
            let sem = sem.clone();
            let cfg = cfg.clone();
            async move {
                let _permit = sem.acquire_owned().await.ok()?;
                if cfg.per_conn_delay > Duration::ZERO {
                    sleep(cfg.per_conn_delay).await;
                }
                probe(ip, port, &cfg).await
            }
        })
        .buffer_unordered(cfg.max_concurrency)
        .collect::<Vec<_>>()
        .await;

    results.into_iter().flatten().collect()
}

/// Probe one (ip, port). Returns Some(OpenPort) if the connect succeeds.
async fn probe(ip: IpAddr, port: u16, cfg: &ScanConfig) -> Option<OpenPort> {
    let addr = SocketAddr::new(ip, port);
    let conn = timeout(cfg.connect_timeout, TcpStream::connect(addr)).await;
    let mut stream = match conn {
        Ok(Ok(s)) => s,
        _ => return None, // closed / filtered / timeout
    };

    let mut banner = None;
    if cfg.grab_banner {
        banner = grab_banner(&mut stream, port, cfg.banner_timeout).await;
    }

    let service = match &banner {
        Some(b) => service::identify(port, b),
        None => ServiceInfo {
            service: service::service_for_port(port).map(String::from),
            ..Default::default()
        },
    };

    Some(OpenPort {
        ip,
        port,
        banner,
        service,
    })
}

/// Read a service banner. For HTTP-like ports, send a minimal request first to
/// elicit a response head; otherwise passively read whatever the server emits.
async fn grab_banner(stream: &mut TcpStream, port: u16, to: Duration) -> Option<String> {
    let is_http = matches!(port, 80 | 8080 | 8000 | 8008 | 8888);
    if is_http {
        let req = b"HEAD / HTTP/1.0\r\nHost: scan\r\nConnection: close\r\n\r\n";
        let _ = timeout(to, stream.write_all(req)).await;
    }

    let mut buf = vec![0u8; 2048];
    match timeout(to, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let text = String::from_utf8_lossy(&buf[..n]).trim().to_string();
            if text.is_empty() {
                None
            } else {
                Some(text)
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_reasonable() {
        let c = ScanConfig::default();
        assert!(c.max_concurrency >= 1);
        assert!(c.connect_timeout > Duration::ZERO);
    }

    // Network-dependent scan_host/probe are covered by integration tests once the
    // VM is available (RUN_INTEGRATION gated), since unit tests must stay hermetic.
    #[tokio::test]
    async fn scan_empty_ports_returns_empty() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let out = scan_host(ip, &[], &ScanConfig::default()).await;
        assert!(out.is_empty());
    }
}
