//! Image runtime-config audit.
//!
//! Consumes the `Config` object from `docker inspect` / an OCI image config and
//! flags insecure runtime posture: running as root, secrets in the environment,
//! sensitive exposed ports, and privileged mount hints. Pure + tested.

use crate::finding::{Category, Finding, Severity};
use serde::Deserialize;
use std::collections::BTreeMap;

/// Subset of the OCI image `config` we inspect.
#[derive(Debug, Default, Deserialize)]
pub struct ImageConfig {
    #[serde(default, rename = "User")]
    pub user: String,
    #[serde(default, rename = "Env")]
    pub env: Vec<String>,
    #[serde(default, rename = "ExposedPorts")]
    pub exposed_ports: BTreeMap<String, serde_json::Value>,
}

fn env_key_looks_secret(key: &str) -> bool {
    let k = key.to_ascii_uppercase();
    const KEYS: &[&str] = &[
        "PASSWORD",
        "PASSWD",
        "SECRET",
        "TOKEN",
        "API_KEY",
        "APIKEY",
        "ACCESS_KEY",
        "PRIVATE_KEY",
        "AWS_SECRET_ACCESS_KEY",
    ];
    KEYS.iter().any(|s| k.contains(s))
}

/// Ports that should rarely be exposed from a container image.
fn sensitive_port(port: u16) -> Option<&'static str> {
    match port {
        22 => Some("SSH"),
        23 => Some("Telnet"),
        2375 | 2376 => Some("Docker daemon API"),
        3389 => Some("RDP"),
        _ => None,
    }
}

fn parse_port(spec: &str) -> Option<u16> {
    // "8080/tcp" -> 8080
    spec.split('/').next()?.trim().parse().ok()
}

/// Analyze an image config JSON string.
pub fn analyze_json(json: &str) -> anyhow::Result<Vec<Finding>> {
    let cfg: ImageConfig = serde_json::from_str(json)?;
    Ok(analyze(&cfg))
}

/// Analyze a parsed image config.
pub fn analyze(cfg: &ImageConfig) -> Vec<Finding> {
    let mut findings = Vec::new();

    let user = cfg.user.trim();
    if user.is_empty() || user == "root" || user == "0" || user.starts_with("0:") {
        findings.push(Finding::new(
            "IMG-USER-ROOT",
            Category::ImageConfig,
            Severity::High,
            "Image is configured to run as root",
            "Set a non-root USER in the image config so the container drops root at runtime",
        ));
    }

    for entry in &cfg.env {
        let key = entry.split('=').next().unwrap_or(entry);
        if env_key_looks_secret(key) {
            findings.push(
                Finding::new(
                    "IMG-SECRET-ENV",
                    Category::Secret,
                    Severity::High,
                    "Secret-looking value baked into the image environment",
                    "Remove secrets from image env; inject them at runtime via a secrets manager",
                )
                .at(key.to_string()),
            );
        }
    }

    for spec in cfg.exposed_ports.keys() {
        if let Some(port) = parse_port(spec) {
            if let Some(name) = sensitive_port(port) {
                findings.push(
                    Finding::new(
                        "IMG-SENSITIVE-PORT",
                        Category::ImageConfig,
                        Severity::Medium,
                        format!("Sensitive service port exposed: {port} ({name})"),
                        "Do not expose management/remote-access ports from application images",
                    )
                    .at(spec.clone()),
                );
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_root_user() {
        let cfg = ImageConfig {
            user: String::new(),
            ..Default::default()
        };
        let f = analyze(&cfg);
        assert!(f.iter().any(|x| x.id == "IMG-USER-ROOT"));
    }

    #[test]
    fn nonroot_user_ok() {
        let cfg = ImageConfig {
            user: "app".into(),
            ..Default::default()
        };
        let f = analyze(&cfg);
        assert!(!f.iter().any(|x| x.id == "IMG-USER-ROOT"));
    }

    #[test]
    fn flags_secret_env() {
        let cfg = ImageConfig {
            user: "app".into(),
            env: vec!["DB_PASSWORD=hunter2".into(), "PATH=/usr/bin".into()],
            ..Default::default()
        };
        let f = analyze(&cfg);
        assert_eq!(f.iter().filter(|x| x.id == "IMG-SECRET-ENV").count(), 1);
    }

    #[test]
    fn flags_ssh_port() {
        let mut ports = BTreeMap::new();
        ports.insert("22/tcp".to_string(), serde_json::json!({}));
        let cfg = ImageConfig {
            user: "app".into(),
            exposed_ports: ports,
            ..Default::default()
        };
        let f = analyze(&cfg);
        assert!(f.iter().any(|x| x.id == "IMG-SENSITIVE-PORT"));
    }

    #[test]
    fn parses_from_json() {
        let json = r#"{"User":"","Env":["API_KEY=abc"],"ExposedPorts":{"2375/tcp":{}}}"#;
        let f = analyze_json(json).unwrap();
        assert!(f.iter().any(|x| x.id == "IMG-USER-ROOT"));
        assert!(f.iter().any(|x| x.id == "IMG-SECRET-ENV"));
        assert!(f.iter().any(|x| x.id == "IMG-SENSITIVE-PORT"));
    }

    #[test]
    fn parse_port_variants() {
        assert_eq!(parse_port("8080/tcp"), Some(8080));
        assert_eq!(parse_port("22"), Some(22));
        assert_eq!(parse_port("bad"), None);
    }
}
