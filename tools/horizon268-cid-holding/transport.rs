//! Fixed-key Foundation holding transport. curl supplies TLS and SigV4; credentials go only to stdin.
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

const BUCKET: &str = "solana-archive-with-accounts-data";
pub(super) const OWNER: &[u8] = br#"{"host":"horizon-vaultic","prefix":"foundation_node_01/","schema":"jetstreamer-horizon-holding-owner-v2"}"#;
const CURL: &str = "/usr/bin/curl";
pub(super) type R<T> = Result<T, String>;
pub(super) fn require(ok: bool, msg: &str) -> R<()> {
    if ok { Ok(()) } else { Err(msg.to_owned()) }
}
fn val(k: &str) -> R<String> {
    env::var(k).map_err(|_| format!("missing {k}"))
}
fn endpoint(s: &str) -> R<()> {
    let h = s
        .strip_prefix("https://")
        .and_then(|v| v.strip_suffix(&format!(".r2.cloudflarestorage.com/{BUCKET}")))
        .ok_or("foreign authenticated endpoint/bucket")?;
    require(
        h.len() == 32 && h.bytes().all(|c| c.is_ascii_hexdigit()),
        "foreign R2 account",
    )
}
pub(super) fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
pub(super) fn hash(p: &Path) -> R<String> {
    let output = Command::new("/usr/bin/sha256sum")
        .arg("--")
        .arg(p)
        .env_clear()
        .output()
        .map_err(|e| e.to_string())?;
    let digest = std::str::from_utf8(&output.stdout)
        .map_err(|_| "sha256 output")?
        .split_ascii_whitespace()
        .next()
        .ok_or("no sha256")?;
    require(output.status.success() && hex(digest, 64), "file hash")?;
    Ok(digest.into())
}
pub(super) fn hash_bytes(data: &[u8]) -> R<String> {
    let mut c = Command::new("/usr/bin/sha256sum")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    c.stdin
        .take()
        .ok_or("digest input")?
        .write_all(data)
        .map_err(|e| e.to_string())?;
    let o = c.wait_with_output().map_err(|e| e.to_string())?;
    let digest = std::str::from_utf8(&o.stdout)
        .map_err(|_| "digest output")?
        .split_ascii_whitespace()
        .next()
        .ok_or("empty digest")?;
    require(o.status.success() && hex(digest, 64), "digest failed")?;
    Ok(digest.into())
}
pub(super) struct Client {
    endpoint: String,
    credentials: String,
}
impl Client {
    pub(super) fn new() -> R<Self> {
        let e = val("HORIZON_S3_ENDPOINT")?;
        endpoint(&e)?;
        let id = val("HORIZON_ACCESS_KEY_ID")?;
        let secret = val("HORIZON_SECRET_ACCESS_KEY")?;
        require(
            [&id, &secret].iter().all(|v| {
                !v.is_empty()
                    && v.len() <= 128
                    && v.bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"/+=_-".contains(&c))
            }),
            "invalid credential shape",
        )?;
        require(
            hash(Path::new(CURL))?
                == "d90fe31761b6ac228a75507b62186b3ed00ccf1f0fc5c7ce704bbe3936e31343",
            "curl image drift",
        )?;
        Ok(Self {
            endpoint: e,
            credentials: format!("user = \"{id}:{secret}\"\n"),
        })
    }
    fn once(
        &self,
        key: &str,
        put: Option<&Path>,
        max: u64,
    ) -> R<(Option<i32>, Option<u16>, Vec<u8>)> {
        let mut c = Command::new(CURL);
        c.env_clear().args([
            "--disable",
            "--config",
            "-",
            "--silent",
            "--proto",
            "=https",
            "--max-redirs",
            "0",
            "--connect-timeout",
            "8",
            "--max-time",
            "180",
            "--retry",
            "0",
            "--aws-sigv4",
            "aws:amz:auto:s3",
            "--header",
            "Accept-Encoding: identity",
            "--max-filesize",
            &max.to_string(),
            "--output",
            "-",
            "--write-out",
            "%{stderr}%{http_code}",
        ]);
        if let Some(p) = put {
            c.args([
                "--request",
                "PUT",
                "--header",
                "If-None-Match: *",
                "--header",
                "Expect:",
                "--header",
                &format!("x-amz-content-sha256: {}", hash(p)?),
                "--upload-file",
            ])
            .arg(p);
        }
        c.arg(format!("{}/{key}", self.endpoint))
            .stdout(Stdio::piped())
            .stdin(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c.spawn().map_err(|e| e.to_string())?;
        child
            .stdin
            .take()
            .ok_or("curl stdin")?
            .write_all(self.credentials.as_bytes())
            .map_err(|e| e.to_string())?;
        let o = child.wait_with_output().map_err(|e| e.to_string())?;
        let code = std::str::from_utf8(&o.stderr)
            .ok()
            .and_then(|s| s.parse::<u16>().ok());
        require(o.stdout.len() as u64 <= max, "response exceeds bound")?;
        Ok((o.status.code(), code, o.stdout))
    }
    fn request(&self, key: &str, put: Option<&Path>, max: u64) -> R<(u16, Vec<u8>)> {
        // Every PUT uses If-None-Match. If a response was interrupted after
        // creation, a repeated 412 leads to the same authenticated readback.
        let mut retries = 0;
        loop {
            let (exit, status, body) = self.once(key, put, max)?;
            let transient = retryable(exit, status);
            if transient && retries < 4 {
                drop(body);
                std::thread::sleep(std::time::Duration::from_secs(1 << retries));
                retries += 1;
                continue;
            }
            if let (Some(0), Some(code)) = (exit, status) {
                if !transient {
                    return Ok((code, body));
                }
            }
            return Err(format!(
                "authenticated {} failed: curl {exit:?}, HTTP {status:?}",
                if put.is_some() {
                    "conditional PUT"
                } else {
                    "GET"
                }
            ));
        }
    }
}
fn retryable(exit: Option<i32>, status: Option<u16>) -> bool {
    match exit {
        Some(0) => matches!(status, Some(408 | 429 | 500 | 502 | 503 | 504)),
        Some(5 | 6 | 7 | 16 | 18 | 28 | 52 | 55 | 56 | 92) => true,
        _ => false,
    }
}
pub(super) trait Transport {
    fn request(&self, key: &str, put: Option<&Path>, max: u64) -> R<(u16, Vec<u8>)>;
    fn small(&self, key: &str, p: &Path, length: u64) -> R<()> {
        require((1..=1 << 20).contains(&length), "unbounded manifest")?;
        let mut bytes = Vec::new();
        fs::File::open(p)
            .and_then(|f| f.take(length + 1).read_to_end(&mut bytes))
            .map_err(|e| e.to_string())?;
        require(
            bytes.len() as u64 == length,
            "different local manifest length",
        )?;
        let response_limit = length.max(4096);
        let (code, old) = self.request(key, None, response_limit)?;
        if code == 200 {
            return require(
                old == bytes,
                "remote claim already consumed or conflicting manifest",
            );
        }
        require(code == 404, "unconfirmed absent marker")?;
        let (status, _) = self.request(key, Some(p), 4096)?;
        require(status == 200 || status == 412, "conditional marker failed")?;
        let (code, remote) = self.request(key, None, response_limit)?;
        require(code == 200 && remote == bytes, "manifest readback mismatch")
    }
}
impl Transport for Client {
    fn request(&self, key: &str, put: Option<&Path>, max: u64) -> R<(u16, Vec<u8>)> {
        Client::request(self, key, put, max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transport_retries_interruptions_and_preserves_conditional_results() {
        assert!(retryable(Some(18), Some(200)));
        assert!(retryable(Some(0), Some(503)));
        assert!(retryable(Some(0), Some(429)));
        for status in [200, 403, 404, 412] {
            assert!(!retryable(Some(0), Some(status)));
        }
        assert!(!retryable(Some(63), Some(200)));
    }
    #[test]
    fn endpoint_rejects_redirects_foreign_buckets_and_ambiguous_hosts() {
        let account = "0".repeat(32);
        let good = format!("https://{account}.r2.cloudflarestorage.com/{BUCKET}");
        assert!(endpoint(&good).is_ok());
        for other in [
            good.replace("https:", "http:"),
            good.replace(BUCKET, "other"),
            format!("{good}/../x"),
            good.replace(&account, "a.example"),
            format!("{good}?redirect="),
        ] {
            assert!(endpoint(&other).is_err());
        }
    }
}
