//! Database sink helpers: thin wrappers over the `aegis.*` procedures and CVE
//! upserts, so collectors never hand-write SQL.

use aegis_common::Pool;
use aegis_ioc::NormalizedIoc;
use chrono::{DateTime, NaiveDate, Utc};

/// Upsert an IOC via `aegis.upsert_ioc(...)`. `severity`/`confidence`/`tlp` are
/// passed as text and cast to the enums inside SQL.
pub async fn upsert_ioc(
    pool: &Pool,
    ioc: &NormalizedIoc,
    severity: &str,
    confidence: &str,
    source: &str,
    tags: &[String],
    tlp: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        "SELECT aegis.upsert_ioc($1::aegis.ioc_type, $2, $3::aegis.severity, \
         $4::aegis.confidence, $5, $6::text[], $7::aegis.tlp)",
    )
    .bind(ioc.ioc_type.as_db())
    .bind(&ioc.value)
    .bind(severity)
    .bind(confidence)
    .bind(source)
    .bind(tags)
    .bind(tlp)
    .execute(pool)
    .await?;
    Ok(())
}

/// Convenience: normalize a raw indicator and upsert if recognized. Returns
/// true if a row was written.
pub async fn upsert_raw_ioc(
    pool: &Pool,
    raw: &str,
    severity: &str,
    confidence: &str,
    source: &str,
    tags: &[String],
) -> anyhow::Result<bool> {
    match aegis_ioc::normalize(raw) {
        Some(ioc) => {
            upsert_ioc(pool, &ioc, severity, confidence, source, tags, "amber").await?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Mark a CVE as CISA KEV, creating a stub row if the CVE is not yet known.
/// `description` is only used when inserting a new stub.
pub async fn upsert_kev(
    pool: &Pool,
    cve_id: &str,
    description: &str,
    added: Option<NaiveDate>,
    due: Option<NaiveDate>,
    ransomware: bool,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO aegis.cves (cve_id, description, kev, kev_added_at, kev_due_date, kev_ransomware, source)
         VALUES ($1, $2, true, $3, $4, $5, 'cisa-kev')
         ON CONFLICT (cve_id) DO UPDATE
            SET kev = true,
                kev_added_at = COALESCE(EXCLUDED.kev_added_at, aegis.cves.kev_added_at),
                kev_due_date = COALESCE(EXCLUDED.kev_due_date, aegis.cves.kev_due_date),
                kev_ransomware = EXCLUDED.kev_ransomware,
                updated_at = now()",
    )
    .bind(cve_id)
    .bind(description)
    .bind(added)
    .bind(due)
    .bind(ransomware)
    .execute(pool)
    .await?;
    Ok(())
}

/// Update EPSS score/percentile for an existing CVE. Creates a stub row if the
/// CVE isn't present yet (EPSS covers CVEs we may not have synced from NVD).
pub async fn upsert_epss(
    pool: &Pool,
    cve_id: &str,
    score: f64,
    percentile: f64,
    when: DateTime<Utc>,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO aegis.cves (cve_id, epss_score, epss_percentile, epss_updated_at, source)
         VALUES ($1, $2, $3, $4, 'epss')
         ON CONFLICT (cve_id) DO UPDATE
            SET epss_score = EXCLUDED.epss_score,
                epss_percentile = EXCLUDED.epss_percentile,
                epss_updated_at = EXCLUDED.epss_updated_at,
                updated_at = now()",
    )
    .bind(cve_id)
    .bind(score)
    .bind(percentile)
    .bind(when)
    .execute(pool)
    .await?;
    Ok(())
}

/// Full CVE record from NVD. Preserves KEV/EPSS fields already set by other
/// collectors: NULL inputs COALESCE to the existing value, so ordering between
/// the NVD, KEV, and EPSS collectors does not matter.
#[allow(clippy::too_many_arguments)]
pub struct CveRecord<'a> {
    pub cve_id: &'a str,
    pub description: &'a str,
    pub published_at: Option<DateTime<Utc>>,
    pub last_modified_at: Option<DateTime<Utc>>,
    pub cvss_v31_score: Option<f64>,
    pub cvss_v31_vector: Option<&'a str>,
    pub cvss_v31_severity: Option<&'a str>, // 'low'|'medium'|'high'|'critical'
    pub cwe_ids: &'a [String],
    pub cpes: &'a [String],
}

/// Upsert a CVE from NVD. Never clears KEV/EPSS data an earlier collector wrote.
pub async fn upsert_cve(pool: &Pool, c: &CveRecord<'_>) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO aegis.cves
            (cve_id, description, published_at, last_modified_at,
             cvss_v31_score, cvss_v31_vector, cvss_v31_severity,
             cwe_ids, cpes, source)
         VALUES ($1,$2,$3,$4,$5,$6,$7::aegis.severity,$8::text[],$9::text[],'nvd')
         ON CONFLICT (cve_id) DO UPDATE SET
            description       = CASE WHEN EXCLUDED.description <> '' THEN EXCLUDED.description
                                     ELSE aegis.cves.description END,
            published_at      = COALESCE(EXCLUDED.published_at, aegis.cves.published_at),
            last_modified_at  = COALESCE(EXCLUDED.last_modified_at, aegis.cves.last_modified_at),
            cvss_v31_score    = COALESCE(EXCLUDED.cvss_v31_score, aegis.cves.cvss_v31_score),
            cvss_v31_vector   = COALESCE(EXCLUDED.cvss_v31_vector, aegis.cves.cvss_v31_vector),
            cvss_v31_severity = COALESCE(EXCLUDED.cvss_v31_severity, aegis.cves.cvss_v31_severity),
            cwe_ids           = CASE WHEN cardinality(EXCLUDED.cwe_ids) > 0 THEN EXCLUDED.cwe_ids
                                     ELSE aegis.cves.cwe_ids END,
            cpes              = CASE WHEN cardinality(EXCLUDED.cpes) > 0 THEN EXCLUDED.cpes
                                     ELSE aegis.cves.cpes END,
            updated_at        = now()",
    )
    .bind(c.cve_id)
    .bind(c.description)
    .bind(c.published_at)
    .bind(c.last_modified_at)
    .bind(c.cvss_v31_score)
    .bind(c.cvss_v31_vector)
    .bind(c.cvss_v31_severity)
    .bind(c.cwe_ids)
    .bind(c.cpes)
    .execute(pool)
    .await?;
    Ok(())
}

/// Upsert a MITRE ATT&CK tactic (idempotent).
pub async fn upsert_mitre_tactic(
    pool: &Pool,
    id: &str,
    name: &str,
    shortname: &str,
    description: &str,
    url: Option<&str>,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO aegis.mitre_tactics (id, name, shortname, description, url)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (id) DO UPDATE
            SET name = EXCLUDED.name, shortname = EXCLUDED.shortname,
                description = EXCLUDED.description, url = COALESCE(EXCLUDED.url, aegis.mitre_tactics.url)",
    )
    .bind(id)
    .bind(name)
    .bind(shortname)
    .bind(description)
    .bind(url)
    .execute(pool)
    .await?;
    Ok(())
}

/// A MITRE ATT&CK technique or sub-technique for upsert.
pub struct MitreTechnique<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub description: &'a str,
    pub is_subtechnique: bool,
    pub parent_id: Option<&'a str>,
    pub tactic_ids: &'a [String],
    pub platforms: &'a [String],
    pub url: Option<&'a str>,
    pub deprecated: bool,
}

/// Upsert a MITRE technique. Sub-techniques are inserted parent-first by the
/// collector so the self-referential FK is satisfied.
pub async fn upsert_mitre_technique(pool: &Pool, t: &MitreTechnique<'_>) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO aegis.mitre_techniques
            (id, name, description, is_subtechnique, parent_id, tactic_ids, platforms, url, deprecated)
         VALUES ($1,$2,$3,$4,$5,$6::text[],$7::text[],$8,$9)
         ON CONFLICT (id) DO UPDATE SET
            name = EXCLUDED.name, description = EXCLUDED.description,
            is_subtechnique = EXCLUDED.is_subtechnique, parent_id = EXCLUDED.parent_id,
            tactic_ids = EXCLUDED.tactic_ids, platforms = EXCLUDED.platforms,
            url = COALESCE(EXCLUDED.url, aegis.mitre_techniques.url),
            deprecated = EXCLUDED.deprecated, updated_at = now()",
    )
    .bind(t.id)
    .bind(t.name)
    .bind(t.description)
    .bind(t.is_subtechnique)
    .bind(t.parent_id)
    .bind(t.tactic_ids)
    .bind(t.platforms)
    .bind(t.url)
    .bind(t.deprecated)
    .execute(pool)
    .await?;
    Ok(())
}
