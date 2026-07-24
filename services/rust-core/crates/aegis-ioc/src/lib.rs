//! IOC normalization, defanging, and type detection. Pure functions with no I/O
//! so they are fully unit-testable without a database or network.

use serde::{Deserialize, Serialize};

/// Canonical IOC types — must match the `aegis.ioc_type` enum in the DB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocType {
    Ipv4,
    Ipv6,
    Domain,
    Url,
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Email,
    Cidr,
}

impl IocType {
    pub fn as_db(&self) -> &'static str {
        match self {
            IocType::Ipv4 => "ipv4",
            IocType::Ipv6 => "ipv6",
            IocType::Domain => "domain",
            IocType::Url => "url",
            IocType::Md5 => "md5",
            IocType::Sha1 => "sha1",
            IocType::Sha256 => "sha256",
            IocType::Sha512 => "sha512",
            IocType::Email => "email",
            IocType::Cidr => "cidr",
        }
    }
}

/// A normalized indicator ready for upsert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedIoc {
    pub ioc_type: IocType,
    pub value: String,
}

/// Refang a defanged indicator: `hxxp://1[.]2[.]3[.]4` → `http://1.2.3.4`, etc.
/// Threat feeds commonly defang to prevent accidental clicks; we store the real value.
pub fn refang(input: &str) -> String {
    input
        .trim()
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("{.}", ".")
        .replace("[.", ".")
        .replace(".]", ".")
        .replace("[:]", ":")
        .replace("hxxps", "https")
        .replace("hxxp", "http")
        .replace("[at]", "@")
        .replace("[@]", "@")
        .replace("fxp", "ftp")
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Best-effort type detection + normalization. Returns None if nothing matches.
pub fn normalize(raw: &str) -> Option<NormalizedIoc> {
    let v = refang(raw);
    let lower = v.to_lowercase();

    // Hashes (by length, hex only)
    if is_hex(&lower) {
        match lower.len() {
            32 => return mk(IocType::Md5, lower),
            40 => return mk(IocType::Sha1, lower),
            64 => return mk(IocType::Sha256, lower),
            128 => return mk(IocType::Sha512, lower),
            _ => {}
        }
    }

    // Email
    if lower.contains('@') && !lower.contains("://") {
        let parts: Vec<&str> = lower.split('@').collect();
        if parts.len() == 2 && !parts[0].is_empty() && parts[1].contains('.') {
            return mk(IocType::Email, lower);
        }
    }

    // URL
    if lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("ftp://") {
        return mk(IocType::Url, v); // keep original case for path
    }

    // CIDR
    if let Some((addr, mask)) = lower.split_once('/') {
        if mask.parse::<u8>().is_ok() && addr.parse::<std::net::IpAddr>().is_ok() {
            return mk(IocType::Cidr, lower);
        }
    }

    // IP literal
    if let Ok(ip) = lower.parse::<std::net::IpAddr>() {
        return mk(if ip.is_ipv4() { IocType::Ipv4 } else { IocType::Ipv6 }, lower);
    }

    // Domain: at least one dot, valid label characters, a non-numeric TLD
    if is_domain(&lower) {
        return mk(IocType::Domain, lower);
    }

    None
}

fn is_domain(s: &str) -> bool {
    if !s.contains('.') || s.contains(' ') || s.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let tld = labels.last().unwrap();
    if tld.len() < 2 || tld.bytes().any(|b| b.is_ascii_digit()) {
        return false;
    }
    labels.iter().all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    })
}

fn mk(t: IocType, v: String) -> Option<NormalizedIoc> {
    Some(NormalizedIoc { ioc_type: t, value: v })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refangs_common_patterns() {
        assert_eq!(refang("1[.]2[.]3[.]4"), "1.2.3.4");
        assert_eq!(refang("hxxps://evil[.]com/x"), "https://evil.com/x");
        assert_eq!(refang("bob[at]evil[.]com"), "bob@evil.com");
    }

    #[test]
    fn detects_hashes() {
        assert_eq!(normalize("d41d8cd98f00b204e9800998ecf8427e").unwrap().ioc_type, IocType::Md5);
        assert_eq!(normalize("da39a3ee5e6b4b0d3255bfef95601890afd80709").unwrap().ioc_type, IocType::Sha1);
        let s256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(normalize(s256).unwrap().ioc_type, IocType::Sha256);
    }

    #[test]
    fn detects_ip_and_cidr() {
        assert_eq!(normalize("8.8.8.8").unwrap().ioc_type, IocType::Ipv4);
        assert_eq!(normalize("2001:4860:4860::8888").unwrap().ioc_type, IocType::Ipv6);
        assert_eq!(normalize("10.0.0.0/8").unwrap().ioc_type, IocType::Cidr);
    }

    #[test]
    fn detects_domain_url_email() {
        assert_eq!(normalize("evil-domain.com").unwrap().ioc_type, IocType::Domain);
        assert_eq!(normalize("https://evil.com/payload").unwrap().ioc_type, IocType::Url);
        assert_eq!(normalize("attacker@evil.com").unwrap().ioc_type, IocType::Email);
    }

    #[test]
    fn refanged_domain_normalizes() {
        let n = normalize("evil[.]com").unwrap();
        assert_eq!(n.ioc_type, IocType::Domain);
        assert_eq!(n.value, "evil.com");
    }

    #[test]
    fn rejects_garbage() {
        assert!(normalize("not an ioc at all").is_none());
        assert!(normalize("12345").is_none()); // numeric, no dot, not a hash length
        assert!(normalize("").is_none());
    }
}
