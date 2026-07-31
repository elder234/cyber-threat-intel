//! Dockerfile security linter.
//!
//! Parses a Dockerfile into instructions and applies a set of hardening checks
//! (CIS Docker Benchmark + common supply-chain hygiene). Pure and unit-tested;
//! no Docker daemon or network required.

use crate::finding::{Category, Finding, Severity};

/// One parsed Dockerfile instruction (line continuations already joined).
#[derive(Debug, Clone, PartialEq)]
pub struct Instruction {
    pub line: usize,
    pub verb: String, // uppercased: FROM, RUN, USER, ...
    pub args: String,
}

/// Parse Dockerfile text into instructions, joining `\`-continued lines and
/// skipping comments/blank lines and parser directives.
pub fn parse(text: &str) -> Vec<Instruction> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut start_line = 0usize;
    let mut continuing = false;

    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = raw.trim_end();

        if !continuing {
            let lead = trimmed.trim_start();
            if lead.is_empty() || lead.starts_with('#') {
                continue; // comment / parser directive / blank
            }
            start_line = line_no;
        }

        let content = trimmed.trim_end_matches('\\');
        buf.push_str(content);

        if trimmed.ends_with('\\') {
            buf.push(' ');
            continuing = true;
            continue;
        }
        continuing = false;

        let joined = buf.trim().to_string();
        buf.clear();
        if joined.is_empty() {
            continue;
        }
        let mut parts = joined.splitn(2, char::is_whitespace);
        let verb = parts.next().unwrap_or("").to_ascii_uppercase();
        let args = parts.next().unwrap_or("").trim().to_string();
        out.push(Instruction {
            line: start_line,
            verb,
            args,
        });
    }
    out
}

/// True when a FROM image reference uses the mutable `:latest` tag or is
/// unpinned (no tag and no digest at all).
fn is_mutable_image(image: &str) -> bool {
    // Strip an "... AS stage" alias.
    let img = image.split_whitespace().next().unwrap_or(image);
    if img.contains('@') {
        return false; // digest-pinned
    }
    match img.rsplit_once(':') {
        Some((_, tag)) => tag.eq_ignore_ascii_case("latest"),
        None => true, // no tag == implicit latest
    }
}

/// Heuristic detection of a secret-looking value in ENV/ARG assignments.
fn looks_like_secret(args: &str) -> bool {
    let lower = args.to_ascii_lowercase();
    const KEYS: &[&str] = &[
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_key",
        "private_key",
        "aws_secret",
    ];
    KEYS.iter().any(|k| lower.contains(k))
}

/// Run all Dockerfile checks and return findings.
pub fn analyze(text: &str) -> Vec<Finding> {
    let instrs = parse(text);
    let mut findings = Vec::new();

    let mut has_user_nonroot = false;
    let mut has_healthcheck = false;
    let mut last_user_root = true; // default user is root until set otherwise

    for ins in &instrs {
        let loc = format!("L{}", ins.line);
        match ins.verb.as_str() {
            "FROM" => {
                if is_mutable_image(&ins.args) {
                    findings.push(
                        Finding::new(
                            "DKR-IMG-UNPINNED",
                            Category::Dockerfile,
                            Severity::Medium,
                            "Base image is not pinned to an immutable digest/tag",
                            "Pin the base image to a specific version and ideally a @sha256 digest",
                        )
                        .at(&loc),
                    );
                }
            }
            "USER" => {
                let u = ins.args.trim();
                if u.eq_ignore_ascii_case("root") || u == "0" {
                    last_user_root = true;
                } else if !u.is_empty() {
                    has_user_nonroot = true;
                    last_user_root = false;
                }
            }
            "HEALTHCHECK" => {
                if !ins.args.trim().eq_ignore_ascii_case("none") {
                    has_healthcheck = true;
                }
            }
            "ADD" => {
                // ADD with a URL or archive is riskier than COPY.
                let a = ins.args.to_ascii_lowercase();
                if a.contains("http://") || a.contains("https://") {
                    findings.push(
                        Finding::new(
                            "DKR-ADD-REMOTE", Category::Dockerfile, Severity::Medium,
                            "ADD fetches a remote URL (no integrity verification)",
                            "Use COPY for local files; for remote fetch use RUN curl with a checksum verification",
                        ).at(&loc),
                    );
                } else {
                    findings.push(
                        Finding::new(
                            "DKR-ADD-COPY", Category::Dockerfile, Severity::Low,
                            "ADD used where COPY is safer",
                            "Prefer COPY unless auto-extraction of a local tar is explicitly required",
                        ).at(&loc),
                    );
                }
            }
            "ENV" | "ARG" => {
                if looks_like_secret(&ins.args) {
                    findings.push(
                        Finding::new(
                            "DKR-SECRET-ENV", Category::Secret, Severity::High,
                            "Possible secret baked into image via ENV/ARG",
                            "Never bake secrets into layers; use build secrets (--mount=type=secret) or runtime injection",
                        ).at(&loc),
                    );
                }
            }
            "RUN" => {
                let a = ins.args.to_ascii_lowercase();
                // curl|bash style remote code execution.
                if (a.contains("curl") || a.contains("wget"))
                    && (a.contains("| sh")
                        || a.contains("|sh")
                        || a.contains("| bash")
                        || a.contains("|bash"))
                {
                    findings.push(
                        Finding::new(
                            "DKR-CURL-PIPE-SH",
                            Category::Dockerfile,
                            Severity::High,
                            "Piping a downloaded script directly into a shell",
                            "Download to a file, verify a checksum/signature, then execute",
                        )
                        .at(&loc),
                    );
                }
                // sudo inside a build is a smell.
                if a.split_whitespace().any(|w| w == "sudo") {
                    findings.push(
                        Finding::new(
                            "DKR-SUDO", Category::Dockerfile, Severity::Low,
                            "Use of sudo inside the image build",
                            "Builds run as root by default; drop sudo and set a non-root USER for runtime",
                        ).at(&loc),
                    );
                }
                // apt without cleanup bloats layers (hygiene, low).
                if a.contains("apt-get install") && !a.contains("--no-install-recommends") {
                    findings.push(
                        Finding::new(
                            "DKR-APT-RECOMMENDS", Category::Dockerfile, Severity::Info,
                            "apt-get install without --no-install-recommends",
                            "Add --no-install-recommends and clean /var/lib/apt/lists to shrink the image",
                        ).at(&loc),
                    );
                }
            }
            _ => {}
        }
    }

    if !has_user_nonroot || last_user_root {
        findings.push(Finding::new(
            "DKR-USER-ROOT",
            Category::Dockerfile,
            Severity::High,
            "Container runs as root (no non-root USER set)",
            "Add a dedicated non-root user and `USER <name>` before the entrypoint",
        ));
    }
    if !has_healthcheck {
        findings.push(Finding::new(
            "DKR-NO-HEALTHCHECK",
            Category::Dockerfile,
            Severity::Low,
            "No HEALTHCHECK instruction",
            "Add a HEALTHCHECK so orchestrators can detect an unhealthy container",
        ));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_continuation_lines() {
        let df = "RUN apt-get update && \\\n    apt-get install -y curl";
        let ins = parse(df);
        assert_eq!(ins.len(), 1);
        assert_eq!(ins[0].verb, "RUN");
        assert!(ins[0].args.contains("apt-get update"));
        assert!(ins[0].args.contains("install -y curl"));
    }

    #[test]
    fn skips_comments_and_blanks() {
        let df = "# comment\n\nFROM alpine:3.19\n";
        let ins = parse(df);
        assert_eq!(ins.len(), 1);
        assert_eq!(ins[0].verb, "FROM");
    }

    #[test]
    fn detects_mutable_images() {
        assert!(is_mutable_image("ubuntu"));
        assert!(is_mutable_image("ubuntu:latest"));
        assert!(is_mutable_image("nginx:LATEST"));
        assert!(!is_mutable_image("alpine:3.19"));
        assert!(!is_mutable_image("alpine@sha256:abc123"));
        assert!(!is_mutable_image("node:20 AS build"));
    }

    #[test]
    fn flags_root_and_missing_healthcheck_on_minimal_file() {
        let df = "FROM alpine:3.19\nCMD [\"/bin/sh\"]\n";
        let f = analyze(df);
        assert!(f.iter().any(|x| x.id == "DKR-USER-ROOT"));
        assert!(f.iter().any(|x| x.id == "DKR-NO-HEALTHCHECK"));
    }

    #[test]
    fn nonroot_user_clears_root_finding() {
        let df = "FROM alpine:3.19\nRUN adduser -D app\nUSER app\nHEALTHCHECK CMD true\n";
        let f = analyze(df);
        assert!(!f.iter().any(|x| x.id == "DKR-USER-ROOT"));
        assert!(!f.iter().any(|x| x.id == "DKR-NO-HEALTHCHECK"));
    }

    #[test]
    fn user_reverting_to_root_is_flagged() {
        let df = "FROM alpine:3.19\nUSER app\nUSER root\nHEALTHCHECK CMD true\n";
        let f = analyze(df);
        assert!(f.iter().any(|x| x.id == "DKR-USER-ROOT"));
    }

    #[test]
    fn flags_secret_env() {
        let df = "FROM alpine:3.19\nENV AWS_SECRET_ACCESS_KEY=abcd1234\nUSER app\n";
        let f = analyze(df);
        assert!(f
            .iter()
            .any(|x| x.id == "DKR-SECRET-ENV" && x.severity == Severity::High));
    }

    #[test]
    fn flags_curl_pipe_sh() {
        let df = "FROM alpine:3.19\nRUN curl -sSL https://get.example.com | sh\nUSER app\n";
        let f = analyze(df);
        assert!(f.iter().any(|x| x.id == "DKR-CURL-PIPE-SH"));
    }

    #[test]
    fn flags_add_remote_and_local() {
        let remote = analyze("FROM alpine:3.19\nADD https://x/y.tar /y\nUSER app\n");
        assert!(remote.iter().any(|x| x.id == "DKR-ADD-REMOTE"));
        let local = analyze("FROM alpine:3.19\nADD ./app /app\nUSER app\n");
        assert!(local.iter().any(|x| x.id == "DKR-ADD-COPY"));
    }
}
