//! Fixed-key Foundation holding transport. curl supplies TLS and SigV4; credentials go only to stdin.
use std::env;
use std::fs;
use std::io::Write;
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
    fn request(&self, key: &str, put: Option<&Path>, max: u64) -> R<(u16, Vec<u8>)> {
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
        if !o.status.success() || code.is_none() {
            return Err("incomplete authenticated request".into());
        }
        require(o.stdout.len() as u64 <= max, "response exceeds bound")?;
        Ok((code.unwrap(), o.stdout))
    }
}
pub(super) trait Transport {
    fn request(&self, key: &str, put: Option<&Path>, max: u64) -> R<(u16, Vec<u8>)>;
    fn small(&self, key: &str, p: &Path) -> R<()> {
        let bytes = fs::read(p).map_err(|e| e.to_string())?;
        require(
            !bytes.is_empty() && bytes.len() < 65536,
            "unbounded manifest",
        )?;
        let (code, old) = self.request(key, None, 65536)?;
        if code == 200 {
            return require(
                old == bytes,
                "remote claim already consumed or conflicting manifest",
            );
        }
        require(code == 404, "unconfirmed absent marker")?;
        let (status, _) = self.request(key, Some(p), 65536)?;
        require(status == 200 || status == 412, "conditional marker failed")?;
        let (code, remote) = self.request(key, None, 65536)?;
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
