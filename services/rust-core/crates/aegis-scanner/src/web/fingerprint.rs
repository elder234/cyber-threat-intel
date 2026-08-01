//! Passive web-application fingerprinting.
//!
//! Given an HTTP response (status, headers, cookies, body) this module detects
//! the server, framework, and CMS from a small static signature table — no
//! network wordlist busting, no attack traffic. Detection is pure and unit
//! tested; the network fetch lives in `super::fetch`.
//!
//! Detected `product` + `version` pairs feed version→CVE correlation
//! (`super::correlate`), which is the discovery input for the active probes in
//! `super::probes`.

use serde::Serialize;

/// A single detected technology.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Technology {
    pub name: String,
    /// Detected version, if the signature exposed one.
    pub version: Option<String>,
    /// CPE 2.3 vendor:product stub for CVE correlation, when known.
    pub cpe: Option<String>,
    /// header | cookie | meta | body | powered_by
    pub source: String,
    /// 0.0..1.0 — header/version matches are high, heuristic body matches low.
    pub confidence: f32,
}

/// Everything a passive pass extracts from one response.
#[derive(Debug, Clone, Serialize, Default, PartialEq)]
pub struct Fingerprint {
    pub technologies: Vec<Technology>,
}

/// Minimal view of a response the detector needs. Header keys are assumed
/// lowercased (use `http_headers::normalize_headers`).
pub struct Response<'a> {
    pub headers: &'a [(String, String)],
    /// Set-Cookie cookie names (lowercased), already split out.
    pub cookie_names: &'a [String],
    /// Response body (may be truncated by the caller; detection only reads a prefix).
    pub body: &'a str,
}

impl Response<'_> {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A version embedded in a header value like `Apache/2.4.52` or `PHP/8.1.2`.
/// Returns the substring after the first '/', trimmed at the first space.
fn version_after_slash(value: &str) -> Option<String> {
    let after = value.split('/').nth(1)?;
    let v = after.split_whitespace().next()?.trim();
    // Require it to look like a version (starts with a digit) to avoid noise.
    if v.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        Some(v.to_string())
    } else {
        None
    }
}

/// Product name embedded before the first '/', e.g. `Apache` from `Apache/2.4`.
fn product_before_slash(value: &str) -> &str {
    value.split('/').next().unwrap_or(value).trim()
}

/// Cookie-name → (technology, cpe stub) signatures. Session cookie names are a
/// reliable, low-noise framework tell.
const COOKIE_SIGNATURES: &[(&str, &str, &str)] = &[
    ("phpsessid", "PHP", "a:php:php"),
    ("jsessionid", "Java (Servlet)", ""),
    ("asp.net_sessionid", "ASP.NET", "a:microsoft:asp.net"),
    ("aspsessionid", "Classic ASP", ""),
    ("laravel_session", "Laravel", "a:laravel:laravel"),
    ("ci_session", "CodeIgniter", ""),
    ("wordpress_logged_in", "WordPress", "a:wordpress:wordpress"),
    ("wp-settings", "WordPress", "a:wordpress:wordpress"),
    ("_shopify_s", "Shopify", ""),
    ("django_session", "Django", "a:djangoproject:django"),
    ("connect.sid", "Express (Node.js)", "a:expressjs:express"),
];

/// Body substring → (technology, cpe stub). Heuristic, low confidence. Only a
/// bounded prefix of the body is searched by `detect`.
const BODY_SIGNATURES: &[(&str, &str, &str)] = &[
    ("/wp-content/", "WordPress", "a:wordpress:wordpress"),
    ("/wp-includes/", "WordPress", "a:wordpress:wordpress"),
    (
        "name=\"generator\" content=\"drupal",
        "Drupal",
        "a:drupal:drupal",
    ),
    (
        "name=\"generator\" content=\"joomla",
        "Joomla",
        "a:joomla:joomla",
    ),
    ("content=\"wordpress", "WordPress", "a:wordpress:wordpress"),
    ("__next", "Next.js", "a:vercel:next.js"),
    ("data-reactroot", "React", ""),
    ("ng-version", "Angular", "a:angular:angular"),
];

/// Search only the first this-many bytes of the body for signatures.
const BODY_SCAN_LIMIT: usize = 64 * 1024;

/// Byte length to truncate a `&str` to without splitting a UTF-8 char. Slicing
/// `&s[..n]` panics if `n` is not a char boundary; this walks back to the
/// nearest boundary at or below `limit`.
fn safe_prefix(s: &str, limit: usize) -> &str {
    if s.len() <= limit {
        return s;
    }
    let mut end = limit;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Detect technologies from a passive response. Pure — no I/O.
pub fn detect(resp: &Response) -> Fingerprint {
    let mut techs: Vec<Technology> = Vec::new();
    let mut push = |t: Technology| {
        // De-dupe by name, keeping the highest-confidence / version-bearing hit.
        if let Some(existing) = techs.iter_mut().find(|e| e.name == t.name) {
            if t.version.is_some() && existing.version.is_none() {
                existing.version = t.version.clone();
                existing.source = t.source.clone();
            }
            if t.confidence > existing.confidence {
                existing.confidence = t.confidence;
            }
            if existing.cpe.is_none() {
                existing.cpe = t.cpe.clone();
            }
        } else {
            techs.push(t);
        }
    };

    // Server header — product and often a version.
    if let Some(server) = resp.header("server") {
        let product = product_before_slash(server);
        if !product.is_empty() {
            push(Technology {
                name: product.to_string(),
                version: version_after_slash(server),
                cpe: None,
                source: "header".into(),
                confidence: 0.9,
            });
        }
    }

    // X-Powered-By — technology stack, often versioned (PHP/8.1, Express).
    if let Some(xpb) = resp.header("x-powered-by") {
        let product = product_before_slash(xpb);
        if !product.is_empty() {
            push(Technology {
                name: product.to_string(),
                version: version_after_slash(xpb),
                cpe: None,
                source: "powered_by".into(),
                confidence: 0.85,
            });
        }
    }

    // X-Generator / X-Drupal-Cache and friends.
    if let Some(gen) = resp.header("x-generator") {
        push(Technology {
            name: product_before_slash(gen).to_string(),
            version: version_after_slash(gen),
            cpe: None,
            source: "header".into(),
            confidence: 0.8,
        });
    }
    if resp.header("x-drupal-cache").is_some() || resp.header("x-drupal-dynamic-cache").is_some() {
        push(Technology {
            name: "Drupal".into(),
            version: None,
            cpe: Some("a:drupal:drupal".into()),
            source: "header".into(),
            confidence: 0.9,
        });
    }
    if let Some(aspnet) = resp.header("x-aspnet-version") {
        push(Technology {
            name: "ASP.NET".into(),
            version: Some(aspnet.to_string()),
            cpe: Some("a:microsoft:asp.net".into()),
            source: "header".into(),
            confidence: 0.9,
        });
    }

    // Cookie-name signatures.
    for (needle, name, cpe) in COOKIE_SIGNATURES {
        if resp.cookie_names.iter().any(|c| c == needle) {
            push(Technology {
                name: (*name).to_string(),
                version: None,
                cpe: (!cpe.is_empty()).then(|| (*cpe).to_string()),
                source: "cookie".into(),
                confidence: 0.75,
            });
        }
    }

    // Meta generator tag — often carries a precise version.
    if let Some(v) = meta_generator(resp.body) {
        let product = v.split_whitespace().next().unwrap_or(&v).to_string();
        let version = v.split_whitespace().nth(1).map(|s| s.to_string());
        push(Technology {
            name: product,
            version,
            cpe: None,
            source: "meta".into(),
            confidence: 0.8,
        });
    }

    // Body heuristics (bounded prefix only).
    let scan = safe_prefix(resp.body, BODY_SCAN_LIMIT);
    let lower = scan.to_ascii_lowercase();
    for (needle, name, cpe) in BODY_SIGNATURES {
        if lower.contains(needle) {
            push(Technology {
                name: (*name).to_string(),
                version: None,
                cpe: (!cpe.is_empty()).then(|| (*cpe).to_string()),
                source: "body".into(),
                confidence: 0.4,
            });
        }
    }

    Fingerprint {
        technologies: techs,
    }
}

/// Extract the content of `<meta name="generator" content="...">`, if present,
/// from a bounded prefix of the body. Case-insensitive on the tag.
fn meta_generator(body: &str) -> Option<String> {
    let hay = safe_prefix(body, BODY_SCAN_LIMIT);
    let lower = hay.to_ascii_lowercase();
    let mut from = 0usize;
    while let Some(rel) = lower[from..].find("name=\"generator\"") {
        let idx = from + rel;
        // Find content=" after the name attribute within the same tag.
        let end_win = safe_prefix(&lower[idx..], 300);
        let tail = end_win;
        if let Some(crel) = tail.find("content=\"") {
            let cstart = idx + crel + "content=\"".len();
            if let Some(end) = lower[cstart..].find('"') {
                let val = hay[cstart..cstart + end].trim().to_string();
                if !val.is_empty() {
                    return Some(val);
                }
            }
        }
        from = idx + 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp<'a>(
        headers: &'a [(String, String)],
        cookies: &'a [String],
        body: &'a str,
    ) -> Response<'a> {
        Response {
            headers,
            cookie_names: cookies,
            body,
        }
    }

    #[test]
    fn detects_server_and_version() {
        let h = vec![("server".to_string(), "Apache/2.4.52 (Debian)".to_string())];
        let fp = detect(&resp(&h, &[], ""));
        let apache = fp.technologies.iter().find(|t| t.name == "Apache").unwrap();
        assert_eq!(apache.version.as_deref(), Some("2.4.52"));
        assert!(apache.confidence >= 0.9);
    }

    #[test]
    fn detects_powered_by_php() {
        let h = vec![("x-powered-by".to_string(), "PHP/8.1.2".to_string())];
        let fp = detect(&resp(&h, &[], ""));
        let php = fp.technologies.iter().find(|t| t.name == "PHP").unwrap();
        assert_eq!(php.version.as_deref(), Some("8.1.2"));
    }

    #[test]
    fn detects_framework_from_cookie() {
        let cookies = vec!["laravel_session".to_string()];
        let fp = detect(&resp(&[], &cookies, ""));
        assert!(fp.technologies.iter().any(|t| t.name == "Laravel"));
    }

    #[test]
    fn detects_wordpress_from_body() {
        let body = r#"<link rel="stylesheet" href="/wp-content/themes/x/style.css">"#;
        let fp = detect(&resp(&[], &[], body));
        let wp = fp
            .technologies
            .iter()
            .find(|t| t.name == "WordPress")
            .unwrap();
        assert_eq!(wp.cpe.as_deref(), Some("a:wordpress:wordpress"));
        assert!(
            wp.confidence < 0.5,
            "body heuristic should be low confidence"
        );
    }

    #[test]
    fn parses_meta_generator_version() {
        let body = r#"<meta name="generator" content="WordPress 6.4.2" />"#;
        assert_eq!(meta_generator(body).as_deref(), Some("WordPress 6.4.2"));
        let fp = detect(&resp(&[], &[], body));
        let wp = fp
            .technologies
            .iter()
            .find(|t| t.name == "WordPress")
            .unwrap();
        assert_eq!(wp.version.as_deref(), Some("6.4.2"));
    }

    #[test]
    fn no_version_when_not_numeric() {
        // A Server header with no version must not invent one.
        let h = vec![("server".to_string(), "cloudflare".to_string())];
        let fp = detect(&resp(&h, &[], ""));
        let cf = fp
            .technologies
            .iter()
            .find(|t| t.name == "cloudflare")
            .unwrap();
        assert_eq!(cf.version, None);
    }

    #[test]
    fn dedupes_by_name_keeping_version() {
        // WordPress from both cookie (no version) and meta (version) → one entry, versioned.
        let cookies = vec!["wp-settings".to_string()];
        let body = r#"<meta name="generator" content="WordPress 6.4.2">"#;
        let fp = detect(&resp(&[], &cookies, body));
        let wps: Vec<_> = fp
            .technologies
            .iter()
            .filter(|t| t.name == "WordPress")
            .collect();
        assert_eq!(wps.len(), 1);
        assert_eq!(wps[0].version.as_deref(), Some("6.4.2"));
    }

    #[test]
    fn empty_response_detects_nothing() {
        let fp = detect(&resp(&[], &[], ""));
        assert!(fp.technologies.is_empty());
    }
}
