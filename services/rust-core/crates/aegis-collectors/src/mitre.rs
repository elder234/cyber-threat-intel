//! MITRE ATT&CK collector (Module 2 — MITRE ATT&CK integration).
//!
//! Parses the official ATT&CK STIX 2.1 bundle published by MITRE:
//!   https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
//!
//! STIX modeling notes:
//!   - Tactics  = `x-mitre-tactic` objects (external_id like `TA0001`).
//!   - Techniques = `attack-pattern` objects; the ATT&CK id (`T1566` /
//!     `T1566.001`) is in `external_references[].external_id` where
//!     `source_name == "mitre-attack"`.
//!   - A technique's tactics are the `phase_name`s of its `kill_chain_phases`
//!     (kill_chain_name == "mitre-attack"); those shortnames map back to tactic
//!     ids via the parsed tactics.
//!   - Sub-techniques set `x_mitre_is_subtechnique = true`; parent id is the
//!     portion before the dot (`T1566.001` → `T1566`).
//!
//! Only public, published ATT&CK content is fetched. ⚠️ RUNTIME VERIFICATION
//! REQUIRED — network + DB paths unexecuted; the STIX parser is unit-tested.

use crate::{http, sink, CollectStats};
use aegis_common::Pool;
use serde::Deserialize;
use std::collections::HashMap;

const ATTACK_URL: &str =
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json";

#[derive(Debug, Deserialize)]
pub struct StixBundle {
    #[serde(default)]
    pub objects: Vec<StixObject>,
}

#[derive(Debug, Deserialize)]
pub struct StixObject {
    #[serde(rename = "type")]
    pub otype: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "x_mitre_shortname", default)]
    pub shortname: Option<String>,
    #[serde(rename = "x_mitre_is_subtechnique", default)]
    pub is_subtechnique: bool,
    #[serde(rename = "x_mitre_platforms", default)]
    pub platforms: Vec<String>,
    #[serde(rename = "x_mitre_deprecated", default)]
    pub deprecated: bool,
    #[serde(default)]
    pub revoked: bool,
    #[serde(rename = "kill_chain_phases", default)]
    pub kill_chain_phases: Vec<KillChainPhase>,
    #[serde(rename = "external_references", default)]
    pub external_references: Vec<ExternalRef>,
}

#[derive(Debug, Deserialize)]
pub struct KillChainPhase {
    #[serde(rename = "kill_chain_name")]
    pub kill_chain_name: String,
    #[serde(rename = "phase_name")]
    pub phase_name: String,
}

#[derive(Debug, Deserialize)]
pub struct ExternalRef {
    #[serde(rename = "source_name")]
    pub source_name: String,
    #[serde(rename = "external_id", default)]
    pub external_id: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
}

impl StixObject {
    /// The ATT&CK id + url from the `mitre-attack` external reference.
    fn attack_ref(&self) -> Option<(&str, Option<&str>)> {
        self.external_references
            .iter()
            .find(|r| r.source_name == "mitre-attack")
            .and_then(|r| r.external_id.as_deref().map(|id| (id, r.url.as_deref())))
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct ParsedTactic {
    pub id: String,
    pub name: String,
    pub shortname: String,
    pub description: String,
    pub url: Option<String>,
}

#[derive(Debug, PartialEq)]
pub struct ParsedTechnique {
    pub id: String,
    pub name: String,
    pub description: String,
    pub is_subtechnique: bool,
    pub parent_id: Option<String>,
    pub tactic_ids: Vec<String>,
    pub platforms: Vec<String>,
    pub url: Option<String>,
    pub deprecated: bool,
}

/// Parsed ATT&CK content: tactics + techniques with tactic ids resolved.
#[derive(Debug, Default)]
pub struct Attack {
    pub tactics: Vec<ParsedTactic>,
    pub techniques: Vec<ParsedTechnique>,
}

/// Parse the STIX bundle into tactics + techniques. Pure — unit-tested.
pub fn parse(body: &str) -> anyhow::Result<Attack> {
    let bundle: StixBundle = serde_json::from_str(body)?;

    // First pass: tactics (so we can map technique kill-chain shortnames → TA ids).
    let mut tactics = Vec::new();
    let mut shortname_to_id: HashMap<String, String> = HashMap::new();
    for o in &bundle.objects {
        if o.otype != "x-mitre-tactic" || o.revoked {
            continue;
        }
        let Some((id, url)) = o.attack_ref() else {
            continue;
        };
        let shortname = o.shortname.clone().unwrap_or_default();
        if !shortname.is_empty() {
            shortname_to_id.insert(shortname.clone(), id.to_string());
        }
        tactics.push(ParsedTactic {
            id: id.to_string(),
            name: o.name.clone().unwrap_or_default(),
            shortname,
            description: o.description.clone().unwrap_or_default(),
            url: url.map(str::to_string),
        });
    }

    // Second pass: techniques.
    let mut techniques = Vec::new();
    for o in &bundle.objects {
        if o.otype != "attack-pattern" || o.revoked {
            continue;
        }
        let Some((id, url)) = o.attack_ref() else {
            continue;
        };

        let tactic_ids: Vec<String> = o
            .kill_chain_phases
            .iter()
            .filter(|p| p.kill_chain_name == "mitre-attack")
            .filter_map(|p| shortname_to_id.get(&p.phase_name).cloned())
            .collect();

        let parent_id = if o.is_subtechnique {
            id.split_once('.').map(|(p, _)| p.to_string())
        } else {
            None
        };

        techniques.push(ParsedTechnique {
            id: id.to_string(),
            name: o.name.clone().unwrap_or_default(),
            description: o.description.clone().unwrap_or_default(),
            is_subtechnique: o.is_subtechnique,
            parent_id,
            tactic_ids,
            platforms: o.platforms.clone(),
            url: url.map(str::to_string),
            deprecated: o.deprecated,
        });
    }

    Ok(Attack {
        tactics,
        techniques,
    })
}

pub async fn collect(pool: &Pool) -> anyhow::Result<CollectStats> {
    let mut stats = CollectStats::default();
    let client = http::default_client()?;
    let body = client
        .get(ATTACK_URL)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    let attack = parse(&body)?;
    stats.fetched = attack.tactics.len() + attack.techniques.len();

    for t in &attack.tactics {
        if let Err(e) = sink::upsert_mitre_tactic(
            pool,
            &t.id,
            &t.name,
            &t.shortname,
            &t.description,
            t.url.as_deref(),
        )
        .await
        {
            stats.errors += 1;
            tracing::warn!(tactic = %t.id, error = %e, "tactic upsert failed");
        } else {
            stats.inserted += 1;
        }
    }

    // Parents before sub-techniques to satisfy the self-referential FK.
    let (subs, parents): (Vec<_>, Vec<_>) =
        attack.techniques.iter().partition(|t| t.is_subtechnique);
    for t in parents.iter().chain(subs.iter()) {
        let rec = sink::MitreTechnique {
            id: &t.id,
            name: &t.name,
            description: &t.description,
            is_subtechnique: t.is_subtechnique,
            parent_id: t.parent_id.as_deref(),
            tactic_ids: &t.tactic_ids,
            platforms: &t.platforms,
            url: t.url.as_deref(),
            deprecated: t.deprecated,
        };
        if let Err(e) = sink::upsert_mitre_technique(pool, &rec).await {
            stats.errors += 1;
            tracing::warn!(technique = %t.id, error = %e, "technique upsert failed");
        } else {
            stats.inserted += 1;
        }
    }

    tracing::info!(
        ?stats,
        tactics = attack.tactics.len(),
        techniques = attack.techniques.len(),
        "MITRE ATT&CK collection complete"
    );
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "type": "bundle",
      "objects": [
        {
          "type": "x-mitre-tactic",
          "name": "Initial Access",
          "x_mitre_shortname": "initial-access",
          "description": "The adversary is trying to get into your network.",
          "external_references": [
            {"source_name": "mitre-attack", "external_id": "TA0001", "url": "https://attack.mitre.org/tactics/TA0001"}
          ]
        },
        {
          "type": "attack-pattern",
          "name": "Phishing",
          "description": "Adversaries may send phishing messages.",
          "x_mitre_platforms": ["Linux", "Windows"],
          "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
          "external_references": [
            {"source_name": "mitre-attack", "external_id": "T1566", "url": "https://attack.mitre.org/techniques/T1566"}
          ]
        },
        {
          "type": "attack-pattern",
          "name": "Spearphishing Attachment",
          "x_mitre_is_subtechnique": true,
          "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
          "external_references": [
            {"source_name": "mitre-attack", "external_id": "T1566.001"}
          ]
        },
        {
          "type": "attack-pattern",
          "name": "Revoked thing",
          "revoked": true,
          "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}]
        }
      ]
    }"#;

    #[test]
    fn parses_tactics_and_techniques() {
        let a = parse(SAMPLE).unwrap();
        assert_eq!(a.tactics.len(), 1);
        assert_eq!(a.tactics[0].id, "TA0001");
        // T1566, T1566.001 — the revoked T9999 is dropped.
        assert_eq!(a.techniques.len(), 2);
    }

    #[test]
    fn maps_kill_chain_phase_to_tactic_id() {
        let a = parse(SAMPLE).unwrap();
        let phishing = a.techniques.iter().find(|t| t.id == "T1566").unwrap();
        assert_eq!(phishing.tactic_ids, vec!["TA0001"]);
        assert_eq!(phishing.platforms, vec!["Linux", "Windows"]);
        assert!(!phishing.is_subtechnique);
    }

    #[test]
    fn derives_subtechnique_parent() {
        let a = parse(SAMPLE).unwrap();
        let sub = a.techniques.iter().find(|t| t.id == "T1566.001").unwrap();
        assert!(sub.is_subtechnique);
        assert_eq!(sub.parent_id.as_deref(), Some("T1566"));
    }
}
