//! Threat-feed collectors. Each collector fetches a public feed, parses it into
//! typed records, and upserts into Postgres via the `aegis.*` stored procedures.
//!
//! ⚠️ RUNTIME VERIFICATION REQUIRED: network fetch + DB upsert paths have not been
//! executed (workspace VM unavailable during authoring). Pure parsers are unit-tested.
//!
//! Legal note: all feeds here are public threat-intelligence sources published for
//! defensive use (CISA, FIRST.org EPSS, abuse.ch). No authentication is bypassed.

pub mod cisa_kev;
pub mod epss;
pub mod feodo;
pub mod http;
pub mod malwarebazaar;
pub mod mitre;
pub mod nvd;
pub mod sink;
pub mod urlhaus;

use aegis_common::JobQueue;
use serde_json::Value;

/// Outcome of a single collector run, recorded to `feed_runs` by the worker.
#[derive(Debug, Default, Clone)]
pub struct CollectStats {
    pub fetched: usize,
    pub inserted: usize,
    pub errors: usize,
}

impl CollectStats {
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "fetched": self.fetched,
            "inserted": self.inserted,
            "errors": self.errors,
        })
    }
}

/// Dispatch a `feed.pull` job by feed slug/provider. Accepts both hyphen and
/// underscore forms (`cisa-kev` == `cisa_kev`). Returns run statistics.
pub async fn run_collector(slug: &str, jq: &JobQueue) -> anyhow::Result<CollectStats> {
    let pool = jq.pool().clone();
    let norm = slug.trim().to_ascii_lowercase().replace('_', "-");
    match norm.as_str() {
        "cisa-kev" => cisa_kev::collect(&pool).await,
        "epss" => epss::collect(&pool).await,
        "urlhaus" => urlhaus::collect(&pool).await,
        "feodo" => feodo::collect(&pool).await,
        "nvd" => nvd::collect(&pool).await,
        "mitre" | "mitre-attack" => mitre::collect(&pool).await,
        "malwarebazaar" => malwarebazaar::collect(&pool).await,
        other => anyhow::bail!("unknown feed slug: {other}"),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn stats_json_shape() {
        let s = super::CollectStats {
            fetched: 3,
            inserted: 2,
            errors: 1,
        };
        let v = s.to_json();
        assert_eq!(v["fetched"], 3);
        assert_eq!(v["inserted"], 2);
        assert_eq!(v["errors"], 1);
    }
}
