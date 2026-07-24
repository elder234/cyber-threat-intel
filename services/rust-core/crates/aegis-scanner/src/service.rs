//! Lightweight service identification: map a port and/or a captured banner to a
//! best-guess service name and product. Pure heuristics — unit-tested. This is
//! deliberately conservative; deep fingerprinting is out of scope.

/// Well-known port → default service name.
pub fn service_for_port(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 | 587 => "smtp",
        53 => "dns",
        80 | 8080 | 8000 | 8008 => "http",
        110 => "pop3",
        143 => "imap",
        443 | 8443 => "https",
        445 => "smb",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        6379 => "redis",
        9200 => "elasticsearch",
        27017 => "mongodb",
        11211 => "memcached",
        _ => return None,
    })
}

/// Identified service details derived from a banner.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ServiceInfo {
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
}

/// Best-effort parse of a service banner. Recognizes common SSH/HTTP/FTP/SMTP
/// banners; falls back to leaving fields empty.
pub fn identify(port: u16, banner: &str) -> ServiceInfo {
    let b = banner.trim();
    let mut info = ServiceInfo {
        service: service_for_port(port).map(String::from),
        ..Default::default()
    };

    // SSH: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
    if let Some(rest) = b.strip_prefix("SSH-") {
        info.service = Some("ssh".into());
        if let Some(sw) = rest.split_whitespace().next() {
            // sw looks like "2.0-OpenSSH_8.9p1"
            if let Some((_, product)) = sw.split_once('-') {
                if let Some((name, ver)) = product.split_once('_') {
                    info.product = Some(name.to_string());
                    info.version = Some(ver.to_string());
                } else {
                    info.product = Some(product.to_string());
                }
            }
        }
        return info;
    }

    // HTTP Server header line: "Server: nginx/1.25.3"
    if let Some(server) = extract_header(b, "server") {
        info.service = Some(if port == 443 || port == 8443 { "https" } else { "http" }.into());
        if let Some((name, ver)) = server.split_once('/') {
            info.product = Some(name.trim().to_string());
            info.version = Some(ver.split_whitespace().next().unwrap_or("").to_string());
        } else {
            info.product = Some(server.trim().to_string());
        }
        return info;
    }

    // FTP: "220 (vsFTPd 3.0.5)"
    if b.starts_with("220") && b.to_lowercase().contains("ftp") {
        info.service = Some("ftp".into());
        if let Some(start) = b.find('(') {
            let inner = &b[start + 1..b.find(')').unwrap_or(b.len())];
            if let Some((name, ver)) = inner.split_once(' ') {
                info.product = Some(name.to_string());
                info.version = Some(ver.to_string());
            }
        }
        return info;
    }

    // SMTP: "220 mail.example.com ESMTP Postfix"
    if b.starts_with("220") && b.to_uppercase().contains("SMTP") {
        info.service = Some("smtp".into());
        if let Some(idx) = b.to_uppercase().find("ESMTP") {
            let tail = b[idx + 5..].trim();
            if !tail.is_empty() {
                info.product = Some(tail.split_whitespace().next().unwrap_or("").to_string());
            }
        }
        return info;
    }

    info
}

/// Extract a header value from a raw HTTP response head (case-insensitive key).
fn extract_header(raw: &str, key: &str) -> Option<String> {
    for line in raw.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(key) {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_common_ports() {
        assert_eq!(service_for_port(22), Some("ssh"));
        assert_eq!(service_for_port(443), Some("https"));
        assert_eq!(service_for_port(5432), Some("postgresql"));
        assert_eq!(service_for_port(9999), None);
    }

    #[test]
    fn parses_ssh_banner() {
        let i = identify(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1");
        assert_eq!(i.service.as_deref(), Some("ssh"));
        assert_eq!(i.product.as_deref(), Some("OpenSSH"));
        assert_eq!(i.version.as_deref(), Some("8.9p1"));
    }

    #[test]
    fn parses_http_server_header() {
        let raw = "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nContent-Type: text/html\r\n";
        let i = identify(80, raw);
        assert_eq!(i.service.as_deref(), Some("http"));
        assert_eq!(i.product.as_deref(), Some("nginx"));
        assert_eq!(i.version.as_deref(), Some("1.25.3"));
    }

    #[test]
    fn parses_ftp_banner() {
        let i = identify(21, "220 (vsFTPd 3.0.5)");
        assert_eq!(i.service.as_deref(), Some("ftp"));
        assert_eq!(i.product.as_deref(), Some("vsFTPd"));
        assert_eq!(i.version.as_deref(), Some("3.0.5"));
    }

    #[test]
    fn unknown_banner_keeps_port_default() {
        let i = identify(22, "garbage banner");
        assert_eq!(i.service.as_deref(), Some("ssh")); // from port
        assert!(i.product.is_none());
    }
}
