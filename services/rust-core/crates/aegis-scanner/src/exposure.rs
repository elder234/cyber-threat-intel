use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExposureResult {
    pub proxy_http: bool,
    pub proxy_socks: bool,
    pub smtp_open_relay: bool,
    pub dns_open_resolver: bool,
    pub score: i32,
    pub findings: Vec<String>,
}
pub fn score(r: &ExposureResult) -> i32 {
    (if r.proxy_http { 30 } else { 0 })
        + (if r.proxy_socks { 30 } else { 0 })
        + (if r.smtp_open_relay { 25 } else { 0 })
        + (if r.dns_open_resolver { 15 } else { 0 })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn score_is_bounded() {
        let r = ExposureResult {
            proxy_http: true,
            proxy_socks: true,
            smtp_open_relay: true,
            dns_open_resolver: true,
            ..Default::default()
        };
        assert_eq!(score(&r), 100);
    }
}
