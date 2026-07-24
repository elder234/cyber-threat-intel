//! Persist a merged [`Reputation`] back onto `aegis.iocs`.
//!
//! Writes the full reputation (per-provider breakdown + union tags) into the
//! `enrichment` jsonb column under a `reputation` key, recomputes the stored
//! integer `score`, merges provider tags into the IOC's `tags[]`, and bumps
//! `last_seen`. Idempotent: re-running overwrites the `reputation` block.

use crate::providers::Reputation;
use sqlx::PgPool;

/// Enrichment payload shape stored at `iocs.enrichment->'reputation'`.
fn reputation_json(rep: &Reputation) -> serde_json::Value {
    serde_json::json!({
        "score": rep.score,
        "verdict": rep.verdict,
        "sources": rep.sources,
        "tags": rep.tags,
        "providers": rep.providers,
        "enriched_at": chrono::Utc::now().to_rfc3339(),
    })
}

/// Persist the reputation for the IOC identified by `ioc_id`.
///
/// - `enrichment` is updated via `jsonb_set` so any sibling keys are preserved.
/// - `score` is overwritten with the aggregate reputation score.
/// - Provider tags are unioned into `tags[]` (Postgres array de-dup on read is
///   not automatic, so we merge in SQL with a subquery).
/// - `last_seen` and `updated_at` (trigger) advance.
pub async fn persist(pool: &PgPool, ioc_id: uuid::Uuid, rep: &Reputation) -> anyhow::Result<()> {
    let payload = reputation_json(rep);

    sqlx::query(
        r#"
        UPDATE aegis.iocs AS i
        SET enrichment = jsonb_set(
                COALESCE(i.enrichment, '{}'::jsonb),
                '{reputation}',
                $2::jsonb,
                true
            ),
            score = $3,
            tags = (
                SELECT ARRAY(
                    SELECT DISTINCT unnest(i.tags || $4::text[])
                )
            ),
            last_seen = now()
        WHERE i.id = $1
        "#,
    )
    .bind(ioc_id)
    .bind(&payload)
    .bind(rep.score as i32)
    .bind(&rep.tags)
    .execute(pool)
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{aggregate, verdict};

    #[test]
    fn reputation_json_shape() {
        let rep = aggregate(vec![verdict("vt", 80, 1.0, vec!["malware".into()])]);
        let j = reputation_json(&rep);
        assert_eq!(j["score"], 80);
        assert_eq!(j["sources"], 1);
        assert_eq!(j["tags"][0], "malware");
        assert!(j["providers"]["vt"].is_object());
        assert!(j["enriched_at"].is_string());
    }
}
