//! URLhaus (abuse.ch) collector — public malicious-URL feed.
//! CSV: https://urlhaus.abuse.ch/downloads/csv_recent/
//! Columns: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter

use crate::{http, sink, CollectStats};
use aegis_common::Pool;

const URLHAUS_URL: &str = "https://urlhaus.abuse.ch/downloads/csv_recent/";

#[derive(Debug, Clone, PartialEq)]
pub struct UrlhausRow {
    pub url: String,
    pub status: String,
    pub threat: String,
    pub tags: Vec<String>,
}

/// Parse the URLhaus recent CSV. Comment lines begin with '#'. Fields are quoted.
/// Pure — unit-testable.
pub fn parse(text: &str) -> Vec<UrlhausRow> {
    let mut rows = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = split_csv(line);
        // id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
        if fields.len() < 7 {
            continue;
        }
        let url = fields[2].clone();
        if url.is_empty() || fields[0].eq_ignore_ascii_case("id") {
            continue; // skip header if present
        }
        let tags = fields[6]
            .split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();
        rows.push(UrlhausRow {
            url,
            status: fields[3].clone(),
            threat: fields[5].clone(),
            tags,
        });
    }
    rows
}

/// Minimal CSV splitter handling double-quoted fields (URLhaus quotes every field).
fn split_csv(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                if in_quotes && chars.peek() == Some(&'"') {
                    cur.push('"');
                    chars.next();
                } else {
                    in_quotes = !in_quotes;
                }
            }
            ',' if !in_quotes => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

pub async fn collect(pool: &Pool) -> anyhow::Result<CollectStats> {
    let mut stats = CollectStats::default();
    let client = http::default_client()?;
    let text = client
        .get(URLHAUS_URL)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    let rows = parse(&text);
    stats.fetched = rows.len();

    for row in &rows {
        // Only ingest online/active URLs as high-confidence malicious indicators.
        let confidence = if row.status.eq_ignore_ascii_case("online") {
            "high"
        } else {
            "medium"
        };
        let mut tags = vec!["urlhaus".to_string()];
        if !row.threat.is_empty() {
            tags.push(row.threat.clone());
        }
        tags.extend(row.tags.iter().cloned());

        match sink::upsert_raw_ioc(pool, &row.url, "high", confidence, "urlhaus", &tags).await {
            Ok(true) => stats.inserted += 1,
            Ok(false) => {}
            Err(e) => {
                stats.errors += 1;
                tracing::warn!(url = %row.url, error = %e, "URLhaus upsert failed");
            }
        }
    }
    tracing::info!(?stats, "URLhaus collection complete");
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "# URLhaus recent\n\
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n\
\"1001\",\"2024-06-01 10:00:00\",\"http://evil.example/malware.exe\",\"online\",\"2024-06-01\",\"malware_download\",\"exe,emotet\",\"https://urlhaus.abuse.ch/url/1001/\",\"anon\"\n\
\"1002\",\"2024-06-01 11:00:00\",\"http://bad.example/x\",\"offline\",\"\",\"malware_download\",\"\",\"https://urlhaus.abuse.ch/url/1002/\",\"anon\"\n";

    #[test]
    fn parses_quoted_rows() {
        let rows = parse(SAMPLE);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].url, "http://evil.example/malware.exe");
        assert_eq!(rows[0].status, "online");
        assert_eq!(rows[0].threat, "malware_download");
        assert_eq!(rows[0].tags, vec!["exe", "emotet"]);
        assert!(rows[1].tags.is_empty());
    }

    #[test]
    fn csv_splitter_handles_embedded_commas() {
        let f = split_csv("\"a,b\",\"c\",\"d,e,f\"");
        assert_eq!(f, vec!["a,b", "c", "d,e,f"]);
    }

    #[test]
    fn skips_comments_and_blanks() {
        assert!(parse("# just a comment\n\n").is_empty());
    }
}
