use md5::Md5;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, process::Command};
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VideoReport {
    pub sha256: String,
    pub md5: String,
    pub size_bytes: usize,
    pub duration_ms: Option<i64>,
    pub width: Option<i32>,
    pub height: Option<i32>,
    pub fps: Option<f64>,
    pub codec: Option<String>,
    pub encoder: Option<String>,
    pub creation_time: Option<String>,
    pub gps: Option<String>,
    pub file_type: Option<String>,
    pub perceptual_frame_hashes: Vec<String>,
    pub summary: String,
}
pub fn dhash(gray: &[u8], width: usize) -> u64 {
    let mut out = 0;
    for y in 0..8 {
        for x in 0..8 {
            out <<= 1;
            if gray[y * width + x] > gray[y * width + x + 1] {
                out |= 1;
            }
        }
    }
    out
}
pub fn hamming(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}
pub fn confidence(a: &[u64], b: &[u64]) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let matched = a
        .iter()
        .filter(|x| b.iter().any(|y| hamming(**x, *y) <= 8))
        .count();
    matched as f64 / a.len().max(b.len()) as f64
}
pub fn analyze_video(bytes: &[u8]) -> VideoReport {
    let mut s = Sha256::new();
    s.update(bytes);
    let mut m = Md5::new();
    m.update(bytes);
    VideoReport {
        sha256: hex::encode(s.finalize()),
        md5: hex::encode(m.finalize()),
        size_bytes: bytes.len(),
        summary: "Video fingerprint registered; media bytes discarded".into(),
        ..Default::default()
    }
}

/// Analyze media using ffprobe/ffmpeg. The temporary file is deleted before
/// returning; callers persist only this derived report.
pub fn analyze_video_with_tools(bytes: &[u8]) -> VideoReport {
    let mut report = analyze_video(bytes);
    let path = std::env::temp_dir().join(format!(
        "aegis-video-{}-{}.bin",
        std::process::id(),
        &report.sha256[..12]
    ));
    if fs::write(&path, bytes).is_err() {
        return report;
    }
    if let Ok(out) = Command::new("ffprobe")
        .args([
            "-v",
            "error",
            "-print_format",
            "json",
            "-show_format",
            "-show_streams",
        ])
        .arg(&path)
        .output()
    {
        if out.status.success() {
            apply_ffprobe(&mut report, &out.stdout);
        }
    }
    if let Ok(out) = Command::new("ffmpeg")
        .args(["-v", "error", "-i"])
        .arg(&path)
        .args([
            "-vf",
            "fps=1/5,scale=9:8,format=gray",
            "-frames:v",
            "32",
            "-f",
            "rawvideo",
            "-",
        ])
        .output()
    {
        if out.status.success() {
            report.perceptual_frame_hashes = out
                .stdout
                .as_chunks::<72>()
                .0
                .iter()
                .map(|f| format!("{:016x}", dhash(f, 9)))
                .collect();
        }
    }
    let _ = fs::remove_file(&path);
    report
}

fn apply_ffprobe(report: &mut VideoReport, raw: &[u8]) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(raw) else {
        return;
    };
    let stream = v["streams"]
        .as_array()
        .and_then(|s| s.iter().find(|x| x["codec_type"] == "video"));
    if let Some(s) = stream {
        report.width = s["width"].as_i64().map(|x| x as i32);
        report.height = s["height"].as_i64().map(|x| x as i32);
        report.codec = s["codec_name"].as_str().map(str::to_owned);
        report.fps = s["avg_frame_rate"].as_str().and_then(parse_rate);
    }
    let f = &v["format"];
    report.file_type = f["format_name"].as_str().map(str::to_owned);
    report.duration_ms = f["duration"]
        .as_str()
        .and_then(|x| x.parse::<f64>().ok())
        .map(|x| (x * 1000.0) as i64);
    report.encoder = f["tags"]["encoder"].as_str().map(str::to_owned);
    report.creation_time = f["tags"]["creation_time"].as_str().map(str::to_owned);
    report.gps = f["tags"]["location"].as_str().map(str::to_owned);
}
fn parse_rate(s: &str) -> Option<f64> {
    let (n, d) = s.split_once('/')?;
    let d = d.parse::<f64>().ok()?;
    if d == 0.0 {
        return None;
    }
    Some(n.parse::<f64>().ok()? / d)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn distance() {
        assert_eq!(hamming(0, 3), 2)
    }
    #[test]
    fn hashes() {
        let r = analyze_video(b"video");
        assert_eq!(r.sha256.len(), 64);
        assert_eq!(r.md5.len(), 32)
    }
    #[test]
    fn parses_fractional_rate() {
        assert_eq!(parse_rate("30000/1001").unwrap().round(), 30.0);
    }
}
