//! Dark-web monitor collector (Feature F-DARKWEB).
//!
//! Polls curated PUBLIC leak/paste/forum sources **exclusively through the Tor
//! SOCKS proxy**, matches fetched page text against the operator watchlist, and
//! upserts hits (which the API turns into alerts). Read-only: it fetches and
//! parses public pages and never authenticates, posts, purchases, or interacts.
//!
//! ## Safety invariants (see AGENTS.md Ground rules)
//! * **Fail closed on Tor.** If `TOR_SOCKS_PROXY` is unset the collector refuses
//!   to run — it never falls back to a clearnet request, which would leak the
//!   platform's real IP to a hidden service.
//! * **Redact on the way in.** [`redact`] masks emails/card-like numbers and
//!   [`snippet_around`] truncates context before anything is persisted. The
//!   platform stores evidence of exposure, not a usable copy of a dump.
//! * **Polite polling.** Requests are jittered and rate-limited; a monitor that
//!   hammers a hidden service is both rude and fingerprintable.
//!
//! ⚠️ RUNTIME VERIFICATION REQUIRED: the Tor fetch + DB upsert paths have not
//! been executed (no Tor/DB in CI). The pure matching/redaction logic is
//! unit-tested below.

use crate::http;
use aegis_common::Pool;
use std::time::Duration;

/// Max characters of surrounding context stored per hit.
const SNIPPET_RADIUS: usize = 80;
/// Cap on how much of a page body we scan (defensive against huge dumps).
const MAX_BODY_SCAN: usize = 512 * 1024;

/// One enabled watchlist entry, as read from `aegis.watchlist`.
#[derive(Debug, Clone, PartialEq)]
pub struct WatchEntry {
    pub id: String,
    pub kind: String, // domain|email|keyword|brand|bin
    pub value: String,
    pub severity: String,
}

/// A source to poll, as read from `aegis.darkweb_sources`.
#[derive(Debug, Clone, PartialEq)]
pub struct Source {
    pub id: String,
    pub name: String,
    pub onion_url: String,
    pub is_onion: bool,
}

/// A watchlist match found in a page, ready to upsert into `darkweb_hits`.
#[derive(Debug, Clone, PartialEq)]
pub struct Match {
    pub watchlist_id: String,
    pub matched_value: String,
    pub severity: String,
    pub snippet: String,
}

/// Mask likely secrets/PII so a stored snippet proves exposure without being a
/// usable copy. Emails → `u***@d***`, long digit runs (card/BIN/SSN-like) →
/// masked keeping only a short prefix. Applied before truncation.
pub fn redact(text: &str) -> String {
    // Mask runs of 7+ digits first (leave first 2 as a hint, e.g. BIN prefix),
    // working over chars so multibyte text is preserved intact.
    let mut out = String::with_capacity(text.len());
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_ascii_digit() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            let run = i - start;
            if run >= 7 {
                out.push(chars[start]);
                out.push(chars[start + 1]);
                for _ in 0..run - 2 {
                    out.push('*');
                }
                continue;
            }
            for &c in &chars[start..i] {
                out.push(c);
            }
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    // Mask emails: keep first char of local part and domain, star the rest.
    mask_emails(&out)
}

fn mask_emails(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    for token in split_keep(text) {
        if let Some(at) = token.find('@') {
            let (local, rest) = token.split_at(at);
            let domain = &rest[1..];
            if !local.is_empty() && domain.contains('.') {
                result.push(local.chars().next().unwrap());
                result.push_str("***@");
                result.push(domain.chars().next().unwrap_or('d'));
                result.push_str("***");
                continue;
            }
        }
        result.push_str(token);
    }
    result
}

/// Split into word / non-word tokens, preserving separators so we can rebuild.
fn split_keep(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut prev_word = false;
    for (i, c) in text.char_indices() {
        let is_word =
            c.is_alphanumeric() || c == '@' || c == '.' || c == '_' || c == '-' || c == '+';
        if i != 0 && is_word != prev_word {
            out.push(&text[start..i]);
            start = i;
        }
        prev_word = is_word;
    }
    if start < text.len() {
        out.push(&text[start..]);
    }
    out
}

/// Extract a redacted, truncated snippet of context around a match position.
pub fn snippet_around(haystack: &str, match_start: usize, match_len: usize) -> String {
    let lo = match_start.saturating_sub(SNIPPET_RADIUS);
    let hi = (match_start + match_len + SNIPPET_RADIUS).min(haystack.len());
    // Walk to char boundaries so slicing can't panic on multibyte text.
    let lo = floor_char_boundary(haystack, lo);
    let hi = floor_char_boundary(haystack, hi);
    let raw = haystack[lo..hi].replace(['\n', '\r', '\t'], " ");
    let collapsed = collapse_ws(&raw);
    redact(collapsed.trim())
}

fn floor_char_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn collapse_ws(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut ws = false;
    for c in s.chars() {
        if c == ' ' {
            if !ws {
                out.push(' ');
            }
            ws = true;
        } else {
            out.push(c);
            ws = false;
        }
    }
    out
}

/// Find all watchlist matches in a page body. Matching is case-insensitive.
/// `domain`/`email`/`bin` require the exact value to appear; `keyword`/`brand`
/// are substring (contains) matches. Deduped so one entry yields at most one hit
/// per page (first occurrence wins for the snippet).
pub fn match_watchlist(body: &str, watch: &[WatchEntry]) -> Vec<Match> {
    let scan = if body.len() > MAX_BODY_SCAN {
        &body[..floor_char_boundary(body, MAX_BODY_SCAN)]
    } else {
        body
    };
    let lower = scan.to_lowercase();

    let mut matches = Vec::new();
    for w in watch {
        let needle = w.value.trim().to_lowercase();
        if needle.is_empty() {
            continue;
        }
        if let Some(pos) = lower.find(&needle) {
            // For domain/email/bin, require a word-ish boundary to avoid
            // matching "example.com" inside "notexample.company".
            if matches!(w.kind.as_str(), "domain" | "email" | "bin")
                && !boundary_ok(&lower, pos, needle.len())
            {
                continue;
            }
            matches.push(Match {
                watchlist_id: w.id.clone(),
                matched_value: w.value.clone(),
                severity: w.severity.clone(),
                snippet: snippet_around(scan, pos, needle.len()),
            });
        }
    }
    matches
}

/// True if the match is bounded by non-identifier chars (or string edges).
fn boundary_ok(hay: &str, pos: usize, len: usize) -> bool {
    let before_ok = pos == 0
        || !hay[..pos]
            .chars()
            .next_back()
            .map(|c| c.is_alphanumeric() || c == '.' || c == '@')
            .unwrap_or(false);
    let end = pos + len;
    let after_ok = end >= hay.len()
        || !hay[end..]
            .chars()
            .next()
            .map(|c| c.is_alphanumeric() || c == '.' || c == '@')
            .unwrap_or(false);
    before_ok && after_ok
}

/// Poll every enabled source once. **Fails closed**: if the Tor proxy is not
/// configured, logs and returns without making any request.
pub async fn poll_all(pool: &Pool, tor_socks: Option<&str>) -> anyhow::Result<usize> {
    let Some(proxy) = tor_socks.filter(|p| !p.is_empty()) else {
        tracing::warn!(
            "dark-web monitor: TOR_SOCKS_PROXY is not set — refusing to poll (fail-closed). \
             No clearnet fallback is attempted."
        );
        return Ok(0);
    };

    let watch = load_watchlist(pool).await?;
    if watch.is_empty() {
        tracing::info!("dark-web monitor: watchlist empty, nothing to match");
        return Ok(0);
    }
    let sources = load_due_sources(pool).await?;
    if sources.is_empty() {
        tracing::info!("dark-web monitor: no enabled sources due for polling");
        return Ok(0);
    }

    // A dedicated Tor client. For onion sources we hard-require the proxy; the
    // `is_onion` flag is a belt-and-braces guard against a misconfigured row.
    let client = http::client(Some(proxy))?;
    let mut total_hits = 0usize;

    for src in &sources {
        if src.is_onion && (proxy.is_empty()) {
            // Unreachable given the guard above, but explicit for the invariant.
            tracing::error!(source = %src.name, "onion source without Tor proxy — skipped");
            continue;
        }
        match poll_source(pool, &client, src, &watch).await {
            Ok(n) => {
                total_hits += n;
                mark_source_health(pool, &src.id, "ok").await.ok();
            }
            Err(e) => {
                tracing::warn!(source = %src.name, error = %format!("{e:#}"), "dark-web poll failed");
                mark_source_health(pool, &src.id, "unreachable").await.ok();
            }
        }
        // Jittered delay between sources (polite + less fingerprintable).
        tokio::time::sleep(jitter(Duration::from_secs(5))).await;
    }
    Ok(total_hits)
}

/// Fetch one source over Tor and upsert any matches. Read-only GET.
async fn poll_source(
    pool: &Pool,
    client: &reqwest::Client,
    src: &Source,
    watch: &[WatchEntry],
) -> anyhow::Result<usize> {
    let body = client
        .get(&src.onion_url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    let hits = match_watchlist(&body, watch);
    let mut inserted = 0usize;
    for m in &hits {
        let affected = sqlx::query(
            "INSERT INTO aegis.darkweb_hits
               (source_id, watchlist_id, url, matched_value, snippet, severity)
             VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::aegis.severity)
             ON CONFLICT (source_id, url, matched_value) DO NOTHING",
        )
        .bind(&src.id)
        .bind(&m.watchlist_id)
        .bind(&src.onion_url)
        .bind(&m.matched_value)
        .bind(&m.snippet)
        .bind(&m.severity)
        .execute(pool)
        .await?
        .rows_affected();
        if affected > 0 {
            inserted += 1;
        }
    }

    sqlx::query("UPDATE aegis.darkweb_sources SET last_polled_at = now() WHERE id = $1::uuid")
        .bind(&src.id)
        .execute(pool)
        .await?;

    tracing::info!(source = %src.name, matched = hits.len(), new = inserted, "dark-web source polled");
    Ok(inserted)
}

async fn load_watchlist(pool: &Pool) -> anyhow::Result<Vec<WatchEntry>> {
    let rows = sqlx::query_as::<_, (String, String, String, String)>(
        "SELECT id::text, kind, value, severity::text
           FROM aegis.watchlist WHERE enabled = true",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, kind, value, severity)| WatchEntry {
            id,
            kind,
            value,
            severity,
        })
        .collect())
}

async fn load_due_sources(pool: &Pool) -> anyhow::Result<Vec<Source>> {
    let rows = sqlx::query_as::<_, (String, String, String, bool)>(
        "SELECT id::text, name, onion_url, is_onion
           FROM aegis.darkweb_sources
          WHERE enabled = true
            AND (last_polled_at IS NULL
                 OR last_polled_at < now() - make_interval(secs => poll_interval_secs))",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name, onion_url, is_onion)| Source {
            id,
            name,
            onion_url,
            is_onion,
        })
        .collect())
}

async fn mark_source_health(pool: &Pool, id: &str, health: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE aegis.darkweb_sources SET health = $2 WHERE id = $1::uuid")
        .bind(id)
        .bind(health)
        .execute(pool)
        .await?;
    Ok(())
}

/// Add up to +50% jitter to a base duration.
fn jitter(base: Duration) -> Duration {
    let extra = (base.as_millis() as u64) / 2;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    base + Duration::from_millis(extra.saturating_mul(nanos % 100) / 100)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(id: &str, kind: &str, value: &str) -> WatchEntry {
        WatchEntry {
            id: id.into(),
            kind: kind.into(),
            value: value.into(),
            severity: "high".into(),
        }
    }

    #[test]
    fn redacts_emails_and_long_digit_runs() {
        let out = redact("contact jdoe@acme.com card 4111111111111111 ok");
        assert!(!out.contains("jdoe@acme.com"), "email leaked: {out}");
        assert!(out.contains("j***@a***"), "email mask missing: {out}");
        assert!(!out.contains("4111111111111111"), "card leaked: {out}");
        assert!(out.contains("41**"), "card prefix hint missing: {out}");
    }

    #[test]
    fn short_numbers_are_not_masked() {
        // Ports, small ids etc. should survive.
        assert_eq!(redact("port 8080"), "port 8080");
    }

    #[test]
    fn keyword_match_is_substring() {
        let body = "leak dump for AcmeCorp employees";
        let hits = match_watchlist(body, &[w("1", "brand", "acmecorp")]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].matched_value, "acmecorp");
    }

    #[test]
    fn domain_requires_boundary() {
        // "example.com" must not match inside "notexample.company".
        let body = "see notexample.company here";
        let hits = match_watchlist(body, &[w("1", "domain", "example.com")]);
        assert!(hits.is_empty(), "boundary check failed: {hits:?}");
    }

    #[test]
    fn domain_matches_standalone() {
        let body = "dump from example.com database";
        let hits = match_watchlist(body, &[w("1", "domain", "example.com")]);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn snippet_is_redacted_and_bounded() {
        let body = format!(
            "{}victim jdoe@acme.com leaked{}",
            "x".repeat(200),
            "y".repeat(200)
        );
        let hits = match_watchlist(&body, &[w("1", "email", "jdoe@acme.com")]);
        assert_eq!(hits.len(), 1);
        let s = &hits[0].snippet;
        assert!(!s.contains("jdoe@acme.com"), "snippet leaked email: {s}");
        assert!(s.len() < 260, "snippet not bounded: {} chars", s.len());
    }

    #[test]
    fn empty_watch_value_ignored() {
        let hits = match_watchlist("anything", &[w("1", "keyword", "   ")]);
        assert!(hits.is_empty());
    }

    #[test]
    fn multibyte_body_does_not_panic() {
        let body = "café dump例 acme leaked 日本語";
        let hits = match_watchlist(body, &[w("1", "brand", "acme")]);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn case_insensitive_match() {
        let hits = match_watchlist("BREACH: AcMeCoRp", &[w("1", "brand", "acmecorp")]);
        assert_eq!(hits.len(), 1);
    }
}
