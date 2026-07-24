//! Aegis OSINT enrichment.
//!
//! This crate turns a single indicator (IP / domain / URL / file hash) into a
//! consolidated reputation verdict by querying multiple public OSINT providers
//! and folding their answers into one normalized score.
//!
//! Design:
//!  * Each provider lives in its own module and exposes a **pure** `parse()`
//!    over the raw JSON body plus a `lookup()` that performs the network call.
//!    The pure parsers are fully unit-tested with no network or DB.
//!  * [`aggregate`] combines per-provider [`ProviderVerdict`]s into a single
//!    [`Reputation`] — this is the scoring brain and is unit-tested.
//!  * [`sink`] persists the merged result onto `aegis.iocs.enrichment` and
//!    recomputes the stored risk score.
//!
//! Legal / safety posture: only public, authorized APIs are used, every
//! provider is gated on its API key being present (absent ⇒ silently skipped),
//! and we never submit indicator *content* anywhere — only look up reputation.

pub mod abuseipdb;
pub mod greynoise;
pub mod otx;
pub mod providers;
pub mod shodan;
pub mod sink;
pub mod virustotal;

pub use providers::{aggregate, ProviderVerdict, Reputation, TargetKind, Verdict};

use sqlx::PgPool;

/// OSINT provider API keys. Any field left `None` disables that provider.
#[derive(Debug, Clone, Default)]
pub struct Keys {
    pub virustotal: Option<String>,
    pub abuseipdb: Option<String>,
    pub shodan: Option<String>,
    pub greynoise: Option<String>,
    pub otx: Option<String>,
}

impl Keys {
    /// True when at least one provider is configured; nothing to do otherwise.
    pub fn any(&self) -> bool {
        self.virustotal.is_some()
            || self.abuseipdb.is_some()
            || self.shodan.is_some()
            || self.greynoise.is_some()
            || self.otx.is_some()
    }
}

/// Look up an indicator across every configured provider concurrently and fold
/// the results into a single [`Reputation`]. Providers that lack a key or do not
/// support the target kind are silently skipped. Per-provider network errors are
/// logged and dropped so one flaky API cannot fail the whole enrichment.
///
/// ⚠️ RUNTIME VERIFICATION REQUIRED — network paths are unverified (VM offline).
pub async fn enrich_indicator(
    client: &reqwest::Client,
    keys: &Keys,
    kind: TargetKind,
    value: &str,
) -> Reputation {
    use futures::future::join_all;

    // Each future yields Option<ProviderVerdict>; errors are logged then dropped.
    let vt = run("virustotal", virustotal::lookup(client, keys.virustotal.as_deref(), kind, value));
    let aip = run("abuseipdb", abuseipdb::lookup(client, keys.abuseipdb.as_deref(), kind, value));
    let shd = run("shodan", shodan::lookup(client, keys.shodan.as_deref(), kind, value));
    let grn = run("greynoise", greynoise::lookup(client, keys.greynoise.as_deref(), kind, value));
    let otx = run("otx", otx::lookup(client, keys.otx.as_deref(), kind, value));

    let results = join_all(vec![
        Box::pin(vt) as std::pin::Pin<Box<dyn std::future::Future<Output = Option<ProviderVerdict>> + Send>>,
        Box::pin(aip),
        Box::pin(shd),
        Box::pin(grn),
        Box::pin(otx),
    ])
    .await;

    aggregate(results.into_iter().flatten().collect())
}

/// Convenience: enrich then persist to `aegis.iocs`.
///
/// ⚠️ RUNTIME VERIFICATION REQUIRED — DB + network paths unverified.
pub async fn enrich_and_persist(
    pool: &PgPool,
    client: &reqwest::Client,
    keys: &Keys,
    ioc_id: uuid::Uuid,
    ioc_type: &str,
    value: &str,
) -> anyhow::Result<Reputation> {
    let Some(kind) = TargetKind::from_ioc_type(ioc_type) else {
        anyhow::bail!("unsupported ioc_type for enrichment: {ioc_type}");
    };
    let rep = enrich_indicator(client, keys, kind, value).await;
    sink::persist(pool, ioc_id, &rep).await?;
    Ok(rep)
}

/// Await a provider lookup, logging and swallowing errors into `None`.
async fn run(
    name: &str,
    fut: impl std::future::Future<Output = anyhow::Result<Option<ProviderVerdict>>>,
) -> Option<ProviderVerdict> {
    match fut.await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(provider = name, error = %e, "osint provider lookup failed");
            None
        }
    }
}
