//! Read-only Telegram video sighting collector. It downloads public bot updates
//! into memory, derives hashes, and drops bytes immediately after matching.
use aegis_common::Pool;
use serde_json::Value;

pub async fn poll(pool: &Pool) -> anyhow::Result<usize> {
    let Some(token) = std::env::var("TELEGRAM_BOT_TOKEN")
        .ok()
        .filter(|x| !x.is_empty())
    else {
        return Ok(0);
    };
    let sources=sqlx::query_as::<_,(String,Value)>("SELECT id::text,config FROM aegis.video_sources WHERE enabled=true AND kind='telegram' AND (last_polled_at IS NULL OR last_polled_at + make_interval(secs=>poll_interval_secs)<=now())").fetch_all(pool).await?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let mut inserted = 0;
    for (source_id, config) in sources {
        let offset = config["offset"].as_i64().unwrap_or(0);
        let updates: Value = client
            .get(format!("https://api.telegram.org/bot{token}/getUpdates"))
            .query(&[("offset", offset)])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let mut next = offset;
        for u in updates["result"].as_array().into_iter().flatten() {
            next = next.max(u["update_id"].as_i64().unwrap_or(0) + 1);
            let m = &u["message"];
            let media = if m["video"].is_object() {
                &m["video"]
            } else {
                &m["document"]
            };
            let Some(file_id) = media["file_id"].as_str() else {
                continue;
            };
            if media["file_size"].as_u64().unwrap_or(0) > 128 * 1024 * 1024 {
                continue;
            }
            let info: Value = client
                .get(format!("https://api.telegram.org/bot{token}/getFile"))
                .query(&[("file_id", file_id)])
                .send()
                .await?
                .json()
                .await?;
            let Some(path) = info["result"]["file_path"].as_str() else {
                continue;
            };
            let bytes = client
                .get(format!("https://api.telegram.org/file/bot{token}/{path}"))
                .send()
                .await?
                .error_for_status()?
                .bytes()
                .await?;
            let report = aegis_video::analyze_video_with_tools(&bytes);
            let candidates = sqlx::query_as::<_, (String, String, String, Vec<String>)>(
                "SELECT id::text,sha256,md5,perceptual_frame_hashes FROM aegis.video_fingerprints",
            )
            .fetch_all(pool)
            .await?;
            for (fingerprint_id, sha256, md5, stored) in candidates {
                let exact = sha256 == report.sha256 || md5 == report.md5;
                let confidence = if exact {
                    1.0
                } else {
                    frame_confidence(&report.perceptual_frame_hashes, &stored)
                };
                if confidence < 0.65 {
                    continue;
                }
                let chat = m["chat"]["username"].as_str().unwrap_or("unknown");
                let mid = m["message_id"].as_i64().unwrap_or(0);
                let url = format!("https://t.me/{chat}/{mid}");
                let author = m["from"]["username"].as_str();
                let snippet = redact(m["caption"].as_str().unwrap_or(""));
                inserted+=sqlx::query("INSERT INTO aegis.video_sightings(fingerprint_id,source_id,url,author,snippet,observed_at,matched_via,confidence) VALUES($1::uuid,$2::uuid,$3,$4,$5,to_timestamp($6),$7,$8) ON CONFLICT(source_id,url) DO NOTHING").bind(&fingerprint_id).bind(&source_id).bind(url).bind(author).bind(snippet).bind(m["date"].as_i64().unwrap_or(0) as f64).bind(if exact{"exact"}else{"perceptual"}).bind(confidence).execute(pool).await?.rows_affected() as usize;
            }
        }
        let mut new_config = config;
        new_config["offset"] = Value::from(next);
        sqlx::query("UPDATE aegis.video_sources SET config=$2,last_polled_at=now(),health='ok' WHERE id=$1::uuid").bind(&source_id).bind(new_config).execute(pool).await?;
    }
    Ok(inserted)
}
fn redact(s: &str) -> String {
    s.split_whitespace()
        .map(|w| {
            if w.contains('@') && w.contains('.') {
                "[redacted]"
            } else {
                w
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(240)
        .collect()
}
fn frame_confidence(a: &[String], b: &[String]) -> f64 {
    let a = a
        .iter()
        .filter_map(|x| u64::from_str_radix(x, 16).ok())
        .collect::<Vec<_>>();
    let b = b
        .iter()
        .filter_map(|x| u64::from_str_radix(x, 16).ok())
        .collect::<Vec<_>>();
    aegis_video::confidence(&a, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn redacts_email() {
        assert!(!redact("x a@b.com y").contains("a@b.com"));
    }
}
