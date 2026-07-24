//! TLS / certificate inspection. Connects to a host:port over TLS, captures the
//! peer certificate chain, and extracts subject/issuer/SAN/validity + weak-config
//! findings. Pure analysis (`analyze_cert`) is unit-testable; the connect path is
//! integration-tested once the VM is available.
//!
//! ⚠️ RUNTIME VERIFICATION REQUIRED: TLS handshake path not executed.

use chrono::{DateTime, TimeZone, Utc};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use x509_parser::prelude::*;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct TlsReport {
    pub host: String,
    pub port: u16,
    pub cert_subject: Option<String>,
    pub cert_issuer: Option<String>,
    pub cert_serial: Option<String>,
    pub san: Vec<String>,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub is_expired: Option<bool>,
    pub is_self_signed: Option<bool>,
    pub sha256_fp: Option<String>,
    pub weak_findings: Vec<String>,
}

/// Analyze a DER-encoded leaf certificate. `now` is injected for deterministic
/// tests. Pure — no I/O.
pub fn analyze_cert(host: &str, port: u16, der: &[u8], now: DateTime<Utc>) -> TlsReport {
    let mut r = TlsReport {
        host: host.to_string(),
        port,
        sha256_fp: Some(sha256_hex(der)),
        ..Default::default()
    };

    let Ok((_, cert)) = X509Certificate::from_der(der) else {
        r.weak_findings.push("certificate failed to parse".into());
        return r;
    };

    r.cert_subject = Some(cert.subject().to_string());
    r.cert_issuer = Some(cert.issuer().to_string());
    r.cert_serial = Some(cert.raw_serial_as_string());
    r.is_self_signed = Some(cert.subject() == cert.issuer());

    let nb = cert.validity().not_before.timestamp();
    let na = cert.validity().not_after.timestamp();
    r.not_before = Utc.timestamp_opt(nb, 0).single();
    r.not_after = Utc.timestamp_opt(na, 0).single();

    if let Some(na_dt) = r.not_after {
        r.is_expired = Some(na_dt < now);
        if na_dt < now {
            r.weak_findings.push("certificate expired".into());
        } else if na_dt < now + chrono::Duration::days(30) {
            r.weak_findings.push("certificate expires within 30 days".into());
        }
    }
    if r.is_self_signed == Some(true) {
        r.weak_findings.push("self-signed certificate".into());
    }

    // SAN extraction.
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                r.san.push(dns.to_string());
            }
        }
    }

    // Signature algorithm weakness (SHA-1 / MD5).
    let sig_oid = cert.signature_algorithm.algorithm.to_id_string();
    if sig_oid.contains("1.2.840.113549.1.1.5") || sig_oid.contains("1.2.840.113549.1.1.4") {
        r.weak_findings.push("weak certificate signature algorithm (SHA-1/MD5)".into());
    }

    r
}

/// Compute a lowercase hex SHA-256 of the DER bytes (certificate fingerprint).
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(bytes);
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Connect over TLS and inspect the peer's leaf certificate.
pub async fn inspect(host: &str, port: u16) -> anyhow::Result<TlsReport> {
    use rustls_pki_types::ServerName;
    use tokio_rustls::TlsConnector;

    // Accept any cert — we are inspecting, not validating trust. A custom verifier
    // that trusts everything lets us capture even self-signed/expired certs.
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(NoVerify))
    .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let tcp = timeout(
        Duration::from_secs(10),
        TcpStream::connect((host, port)),
    )
    .await??;

    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| anyhow::anyhow!("invalid server name: {host}"))?;
    let mut tls = timeout(Duration::from_secs(10), connector.connect(server_name, tcp)).await??;

    // Grab the leaf cert from the negotiated connection.
    let der = {
        let (_, conn) = tls.get_ref();
        conn.peer_certificates()
            .and_then(|c| c.first())
            .map(|c| c.as_ref().to_vec())
    };
    let _ = tls.shutdown().await;

    match der {
        Some(bytes) => Ok(analyze_cert(host, port, &bytes, Utc::now())),
        None => anyhow::bail!("peer presented no certificate"),
    }
}

/// A certificate verifier that accepts everything — used ONLY for inspection so
/// we can read expired/self-signed certs. Never used for trust decisions.
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512,
            ECDSA_NISTP256_SHA256, ECDSA_NISTP384_SHA384,
            RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512, ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_vector() {
        // SHA-256 of empty input.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn analyze_bad_der_reports_parse_failure() {
        let now = Utc::now();
        let r = analyze_cert("example.com", 443, b"not-a-cert", now);
        assert!(r.weak_findings.iter().any(|f| f.contains("failed to parse")));
        assert!(r.sha256_fp.is_some());
    }
}
