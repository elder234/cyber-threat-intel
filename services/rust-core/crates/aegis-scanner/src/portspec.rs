//! Port specification parsing: turn strings like "22,80,443,8000-8010" or
//! "top100" / "top1000" into a deduped, sorted list of ports. Pure + tested.

/// The 100 most common TCP ports (nmap-style top-100, abbreviated but representative).
pub const TOP_100: &[u16] = &[
    7, 20, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144,
    179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873,
    990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001,
    2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357,
    5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888,
    9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
];

/// A handful of extra common ports layered on top of TOP_100 for "top1000".
/// (Kept compact; a full 1000 list would bloat the binary — this is representative.)
pub const EXTRA_COMMON: &[u16] = &[
    1, 3, 4, 6, 9, 13, 17, 19, 24, 49, 70, 109, 125, 137, 138, 161, 162, 264, 465, 500, 512, 520,
    623, 636, 993, 1080, 1194, 1234, 1521, 1701, 2082, 2083, 2222, 2375, 2376, 3260, 3690, 4000,
    4433, 4444, 5044, 5222, 5601, 5672, 5984, 6379, 6667, 7001, 7777, 8000, 8086, 8088, 8161, 8500,
    8983, 9042, 9090, 9200, 9418, 9500, 11211, 15672, 27017, 27018, 50000, 61616,
];

/// Parse a port spec into a sorted, deduped list. Accepts:
///  - comma-separated ports:  "22,80,443"
///  - ranges:                 "8000-8010"
///  - keywords:               "top100", "top1000"
///
/// Returns Err on malformed input or out-of-range values.
pub fn parse_ports(spec: &str) -> anyhow::Result<Vec<u16>> {
    let spec = spec.trim();
    if spec.is_empty() {
        anyhow::bail!("empty port spec");
    }
    let mut set: Vec<u16> = Vec::new();

    for token in spec.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        match token.to_ascii_lowercase().as_str() {
            "top100" => set.extend_from_slice(TOP_100),
            "top1000" => {
                set.extend_from_slice(TOP_100);
                set.extend_from_slice(EXTRA_COMMON);
            }
            _ => {
                if let Some((a, b)) = token.split_once('-') {
                    let start: u32 = a.trim().parse().map_err(|_| bad(token))?;
                    let end: u32 = b.trim().parse().map_err(|_| bad(token))?;
                    if start == 0 || end == 0 || start > 65535 || end > 65535 {
                        anyhow::bail!("port out of range in '{token}'");
                    }
                    if start > end {
                        anyhow::bail!("inverted range '{token}'");
                    }
                    for p in start..=end {
                        set.push(p as u16);
                    }
                } else {
                    let p: u32 = token.parse().map_err(|_| bad(token))?;
                    if p == 0 || p > 65535 {
                        anyhow::bail!("port out of range: {p}");
                    }
                    set.push(p as u16);
                }
            }
        }
    }

    set.sort_unstable();
    set.dedup();
    if set.is_empty() {
        anyhow::bail!("no valid ports parsed from '{spec}'");
    }
    Ok(set)
}

fn bad(token: &str) -> anyhow::Error {
    anyhow::anyhow!("invalid port token: '{token}'")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_list_and_range() {
        let p = parse_ports("22,80,443,8000-8003").unwrap();
        assert_eq!(p, vec![22, 80, 443, 8000, 8001, 8002, 8003]);
    }

    #[test]
    fn dedupes_and_sorts() {
        let p = parse_ports("443,22,443,80,22").unwrap();
        assert_eq!(p, vec![22, 80, 443]);
    }

    #[test]
    fn top100_keyword() {
        let p = parse_ports("top100").unwrap();
        assert!(p.contains(&80) && p.contains(&443) && p.contains(&22));
        // sorted + deduped
        assert!(p.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn rejects_out_of_range_and_garbage() {
        assert!(parse_ports("70000").is_err());
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("abc").is_err());
        assert!(parse_ports("100-50").is_err());
        assert!(parse_ports("").is_err());
    }

    #[test]
    fn mixed_keyword_and_explicit() {
        let p = parse_ports("top100,12345").unwrap();
        assert!(p.contains(&12345));
    }
}
