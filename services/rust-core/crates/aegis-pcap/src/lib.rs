use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PcapReport {
    pub sha256: String,
    pub size_bytes: usize,
    pub format: String,
    pub packet_count: u64,
    pub duration_ms: u64,
    pub interface_count: u32,
    pub top_talkers: serde_json::Value,
    pub protocol_mix: serde_json::Value,
    pub dns_queries: serde_json::Value,
    pub tls_snis: Vec<String>,
    pub http_hosts: Vec<String>,
    pub suspicious: serde_json::Value,
    pub ioc_matches: serde_json::Value,
    pub score: i32,
    pub summary: String,
    pub findings: Vec<PcapFinding>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapFinding {
    pub finding_id: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
}

pub fn analyze_capture(bytes: &[u8], iocs: &[String]) -> PcapReport {
    let mut h = Sha256::new();
    h.update(bytes);
    let format = if bytes.starts_with(b"\xd4\xc3\xb2\xa1") || bytes.starts_with(b"\xa1\xb2\xc3\xd4")
    {
        "pcap"
    } else if bytes.starts_with(b"\x0a\x0d\x0d\x0a") {
        "pcapng"
    } else {
        "unknown"
    };
    let packets = if format == "pcap" {
        pcap_packets(bytes)
    } else if format == "pcapng" {
        pcapng_packets(bytes)
    } else {
        Vec::new()
    };
    let packet_count = packets.len() as u64;
    let mut protocols: BTreeMap<String, u64> = BTreeMap::new();
    let mut talkers: BTreeMap<String, u64> = BTreeMap::new();
    let mut dns = BTreeSet::new();
    let mut hosts = BTreeSet::new();
    let mut snis = BTreeSet::new();
    for packet in &packets {
        inspect_packet(
            packet,
            &mut protocols,
            &mut talkers,
            &mut dns,
            &mut hosts,
            &mut snis,
        );
    }
    let mut matches = Vec::new();
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    for ioc in iocs {
        if text.contains(&ioc.to_ascii_lowercase()) {
            matches.push(ioc.clone());
        }
    }
    let mut findings = Vec::new();
    if !matches.is_empty() {
        findings.push(PcapFinding {
            finding_id: "PCAP-IOC".into(),
            severity: "high".into(),
            title: "Known IOC observed".into(),
            detail: format!("{} active IOC(s) matched", matches.len()),
        });
    }
    PcapReport {
        sha256: hex::encode(h.finalize()),
        size_bytes: bytes.len(),
        format: format.into(),
        packet_count,
        duration_ms: if format == "pcap" {
            pcap_duration_ms(bytes)
        } else {
            0
        },
        interface_count: if format == "pcapng" {
            pcapng_interfaces(bytes)
        } else if format == "pcap" {
            1
        } else {
            0
        },
        top_talkers: serde_json::json!(talkers
            .into_iter()
            .map(|(host, packets)| serde_json::json!({"host":host,"packets":packets}))
            .collect::<Vec<_>>()),
        protocol_mix: serde_json::json!(protocols),
        dns_queries: serde_json::json!(dns),
        tls_snis: snis.into_iter().collect(),
        http_hosts: hosts.into_iter().collect(),
        suspicious: serde_json::json!([]),
        ioc_matches: serde_json::json!(matches),
        score: if findings.is_empty() { 0 } else { 60 },
        summary: if findings.is_empty() {
            "No suspicious indicators detected".into()
        } else {
            "Known infrastructure matched in capture".into()
        },
        findings,
    }
}
fn pcap_packets(bytes: &[u8]) -> Vec<&[u8]> {
    let mut p = 24usize;
    let mut out = Vec::new();
    let little = bytes.starts_with(b"\xd4\xc3\xb2\xa1");
    while p + 16 <= bytes.len() {
        let raw: [u8; 4] = bytes[p + 8..p + 12].try_into().unwrap();
        let incl = if little {
            u32::from_le_bytes(raw)
        } else {
            u32::from_be_bytes(raw)
        } as usize;
        p += 16;
        if p + incl > bytes.len() {
            break;
        }
        out.push(&bytes[p..p + incl]);
        p += incl;
    }
    out
}
fn pcap_duration_ms(bytes: &[u8]) -> u64 {
    let little = bytes.starts_with(b"\xd4\xc3\xb2\xa1");
    let mut p = 24;
    let mut first = None;
    let mut last = 0;
    while p + 16 <= bytes.len() {
        let read = |s: &[u8]| {
            if little {
                u32::from_le_bytes(s.try_into().unwrap())
            } else {
                u32::from_be_bytes(s.try_into().unwrap())
            }
        };
        let t = read(&bytes[p..p + 4]) as u64 * 1000 + read(&bytes[p + 4..p + 8]) as u64 / 1000;
        first.get_or_insert(t);
        last = t;
        let n = read(&bytes[p + 8..p + 12]) as usize;
        p += 16 + n;
    }
    first.map(|x| last.saturating_sub(x)).unwrap_or(0)
}
fn pcapng_packets(bytes: &[u8]) -> Vec<&[u8]> {
    let mut p = 0;
    let mut out = Vec::new();
    while p + 12 <= bytes.len() {
        let kind = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[p + 4..p + 8].try_into().unwrap()) as usize;
        if len < 12 || p + len > bytes.len() {
            break;
        }
        if kind == 6 && len >= 32 {
            let cap = u32::from_le_bytes(bytes[p + 20..p + 24].try_into().unwrap()) as usize;
            if p + 28 + cap <= p + len {
                out.push(&bytes[p + 28..p + 28 + cap]);
            }
        }
        p += len;
    }
    out
}
fn pcapng_interfaces(bytes: &[u8]) -> u32 {
    let mut p = 0;
    let mut n = 0;
    while p + 12 <= bytes.len() {
        let kind = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[p + 4..p + 8].try_into().unwrap()) as usize;
        if len < 12 || p + len > bytes.len() {
            break;
        }
        if kind == 1 {
            n += 1
        }
        p += len;
    }
    n
}
fn inspect_packet(
    packet: &[u8],
    protocols: &mut BTreeMap<String, u64>,
    talkers: &mut BTreeMap<String, u64>,
    dns: &mut BTreeSet<String>,
    hosts: &mut BTreeSet<String>,
    snis: &mut BTreeSet<String>,
) {
    if packet.len() < 14 {
        return;
    }
    let et = u16::from_be_bytes([packet[12], packet[13]]);
    let (ip, proto, src, dst) = match et {
        0x0800 if packet.len() >= 34 => {
            let h = (packet[14] & 15) as usize * 4;
            if packet.len() < 14 + h {
                return;
            }
            (
                &packet[14 + h..],
                packet[23],
                format!(
                    "{}.{}.{}.{}",
                    packet[26], packet[27], packet[28], packet[29]
                ),
                format!(
                    "{}.{}.{}.{}",
                    packet[30], packet[31], packet[32], packet[33]
                ),
            )
        }
        _ => return,
    };
    *talkers.entry(src).or_default() += 1;
    *talkers.entry(dst).or_default() += 1;
    let (name, payload, sport, dport) = match proto {
        6 if ip.len() >= 20 => {
            let off = ((ip[12] >> 4) as usize) * 4;
            if ip.len() < off {
                return;
            }
            (
                "tcp",
                &ip[off..],
                u16::from_be_bytes([ip[0], ip[1]]),
                u16::from_be_bytes([ip[2], ip[3]]),
            )
        }
        17 if ip.len() >= 8 => (
            "udp",
            &ip[8..],
            u16::from_be_bytes([ip[0], ip[1]]),
            u16::from_be_bytes([ip[2], ip[3]]),
        ),
        1 => ("icmp", &ip[0..0], 0, 0),
        _ => ("other", &ip[0..0], 0, 0),
    };
    *protocols.entry(name.into()).or_default() += 1;
    if (sport == 53 || dport == 53) && payload.len() > 12 {
        if let Some(q) = dns_name(&payload[12..]) {
            dns.insert(q);
        }
    }
    if sport == 80 || dport == 80 || sport == 8080 || dport == 8080 {
        if let Ok(s) = std::str::from_utf8(payload) {
            for line in s.lines() {
                if let Some(v) = line
                    .strip_prefix("Host: ")
                    .or_else(|| line.strip_prefix("host: "))
                {
                    hosts.insert(v.trim().to_string());
                }
            }
        }
    }
    if sport == 443 || dport == 443 {
        for part in payload.split(|b| *b == 0) {
            if part.len() > 3
                && part.len() < 254
                && part.contains(&b'.')
                && part
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
            {
                if let Ok(s) = std::str::from_utf8(part) {
                    snis.insert(s.to_string());
                }
            }
        }
    }
}
fn dns_name(mut b: &[u8]) -> Option<String> {
    let mut labels = Vec::new();
    while !b.is_empty() {
        let n = b[0] as usize;
        if n == 0 {
            break;
        }
        if n > 63 || b.len() < n + 1 {
            return None;
        }
        labels.push(std::str::from_utf8(&b[1..=n]).ok()?);
        b = &b[n + 1..]
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_format_and_hash() {
        let r = analyze_capture(b"\xd4\xc3\xb2\xa1", &[]);
        assert_eq!(r.format, "pcap");
        assert!(!r.sha256.is_empty());
    }
    #[test]
    fn matches_ioc() {
        let r = analyze_capture(b"traffic 1.2.3.4", &["1.2.3.4".into()]);
        assert_eq!(r.ioc_matches.as_array().unwrap().len(), 1);
    }
}
