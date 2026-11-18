use crate::{Config, canonical_epoch, local::*};
use anyhow::{Context, Result, ensure};
use aws_credential_types::{Credentials, provider::SharedCredentialsProvider};
use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Region},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    io::Write,
    path::Path,
    time::{Duration, Instant},
};

pub struct Remote {
    pub client: Client,
    pub bucket: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Object {
    pub epoch: u64,
    pub key: String,
    pub etag: String,
    pub bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Inventory {
    pub schema: String,
    pub bucket: String,
    pub observed_at: u64,
    pub objects: Vec<Object>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Download {
    pub object: Object,
    pub version_id: Option<String>,
    pub sha256: String,
    pub bytes: u64,
    pub sidecar_sha256: Option<String>,
    pub sidecar_etag: Option<String>,
    pub metadata_sha256: Option<String>,
}
impl Remote {
    pub fn from_env() -> Result<Self> {
        let url = url::Url::parse(
            &env::var("HORIZON_S3_ENDPOINT").context("missing HORIZON_S3_ENDPOINT")?,
        )?;
        ensure!(
            url.scheme() == "https"
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.port().is_none(),
            "invalid R2 endpoint"
        );
        let host = url.host_str().context("missing R2 host")?;
        ensure!(
            host.ends_with(".r2.cloudflarestorage.com"),
            "unexpected R2 host"
        );
        let bucket = url.path().trim_matches('/').to_owned();
        ensure!(
            bucket == "solana-archive-with-accounts-data",
            "unexpected archive bucket"
        );
        let creds = Credentials::new(
            env::var("HORIZON_ACCESS_KEY_ID").context("missing R2 key")?,
            env::var("HORIZON_SECRET_ACCESS_KEY").context("missing R2 secret")?,
            None,
            None,
            "horizon-audit-read-only",
        );
        let conf = aws_sdk_s3::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("auto"))
            .credentials_provider(SharedCredentialsProvider::new(creds))
            .endpoint_url(format!("https://{host}"))
            .force_path_style(true)
            .timeout_config(
                aws_sdk_s3::config::timeout::TimeoutConfig::builder()
                    .connect_timeout(Duration::from_secs(30))
                    .operation_timeout(Duration::from_secs(120))
                    .build(),
            )
            .build();
        Ok(Self {
            client: Client::from_conf(conf),
            bucket,
        })
    }
    pub async fn inventory(&self) -> Result<Inventory> {
        let mut objects = BTreeMap::new();
        let mut token = None;
        loop {
            let page = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix("epoch-")
                .set_continuation_token(token.clone())
                .send()
                .await
                .context("list canonical R2 archives")?;
            for row in page.contents() {
                let Some(key) = row.key() else {
                    continue;
                };
                let Some(epoch) = canonical_epoch(key) else {
                    continue;
                };
                let obj = Object {
                    epoch,
                    key: key.into(),
                    etag: row.e_tag().context("archive lacks ETag")?.into(),
                    bytes: u64::try_from(row.size().context("archive lacks length")?)?,
                };
                ensure!(
                    obj.bytes > 0 && !obj.etag.is_empty(),
                    "invalid archive object metadata"
                );
                ensure!(
                    objects.insert(epoch, obj).is_none(),
                    "duplicate canonical epoch in inventory"
                );
            }
            if !page.is_truncated().unwrap_or(false) {
                break;
            }
            let next = page
                .next_continuation_token()
                .context("truncated inventory lacks next token")?
                .to_owned();
            ensure!(
                token.as_ref() != Some(&next),
                "inventory token did not advance"
            );
            token = Some(next);
        }
        Ok(Inventory {
            schema: "horizon-r2-chronological-audit-inventory-v1".into(),
            bucket: self.bucket.clone(),
            observed_at: now(),
            objects: objects.into_values().collect(),
        })
    }
    pub async fn check_identity(
        &self,
        object: &Object,
    ) -> Result<(Option<String>, Option<String>)> {
        let head = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(&object.key)
            .if_match(&object.etag)
            .send()
            .await
            .context("HEAD pinned archive")?;
        check_response(object, head.e_tag(), head.content_length())?;
        let metadata_hash = head.metadata().and_then(|m| m.get("sha256")).cloned();
        if let Some(ref value) = metadata_hash {
            ensure!(valid_digest(value), "invalid archive metadata digest");
        }
        Ok((head.version_id().map(str::to_owned), metadata_hash))
    }
    async fn sidecar(&self, object: &Object) -> Result<(Option<String>, Option<String>)> {
        let key = format!("{}.sha256", object.key);
        let head = match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
        {
            Ok(v) => v,
            Err(error) if error.as_service_error().is_some_and(|e| e.is_not_found()) => {
                return Ok((None, None));
            }
            Err(error) => return Err(error).context("HEAD checksum sidecar"),
        };
        let length = head.content_length().context("sidecar missing length")?;
        ensure!(
            (1..=1024).contains(&length),
            "invalid checksum sidecar length"
        );
        let etag = head.e_tag().context("sidecar missing ETag")?.to_owned();
        let response = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .if_match(&etag)
            .send()
            .await
            .context("read checksum sidecar")?;
        ensure!(
            response.e_tag() == Some(etag.as_str()) && response.content_length() == Some(length),
            "sidecar changed"
        );
        let data = response.body.collect().await?.into_bytes();
        ensure!(data.len() == usize::try_from(length)?, "short sidecar read");
        Ok((Some(parse_sidecar(object.epoch, &data)?), Some(etag)))
    }
    pub async fn download(
        &self,
        cfg: &Config,
        object: &Object,
        attempt: &Path,
    ) -> Result<Download> {
        let (version_id, metadata_sha256) = self.check_identity(object).await?;
        let (sidecar_sha256, sidecar_etag) = self.sidecar(object).await?;
        if let (Some(a), Some(b)) = (&metadata_sha256, &sidecar_sha256) {
            ensure!(a == b, "sidecar and metadata digests disagree");
        }
        let scratch = cfg.state_directory.join("scratch").join(&object.key);
        let mut output = create(&scratch)?;
        let owned = OwnedScratch {
            key: object.key.clone(),
            identity: Identity::from_file(&output)?,
            created_at: now(),
        };
        write_json(
            &cfg.state_directory.join("scratch-owner.json"),
            &owned,
            false,
        )?;
        let mut body = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&object.key)
            .if_match(&object.etag)
            .send()
            .await
            .context("GET pinned archive")?;
        check_response(object, body.e_tag(), body.content_length())?;
        ensure!(
            body.version_id().map(str::to_owned) == version_id,
            "archive version changed"
        );
        let mut count = 0_u64;
        let mut hash = Sha256::new();
        let mut last_progress = Instant::now();
        let began = Instant::now();
        while let Some(chunk) = tokio::time::timeout(
            Duration::from_secs(cfg.read_timeout_seconds),
            body.body.try_next(),
        )
        .await
        .context("archive stream stalled")??
        {
            count = count
                .checked_add(chunk.len() as u64)
                .context("download count overflow")?;
            ensure!(
                count <= object.bytes && count <= cfg.max_archive_bytes,
                "archive exceeds pinned length or budget"
            );
            ensure!(
                began.elapsed().as_secs() <= cfg.download_timeout_seconds,
                "archive download deadline exceeded"
            );
            require_space(&cfg.state_directory, cfg.reserve_bytes, chunk.len() as u64)?;
            output.write_all(&chunk)?;
            hash.update(&chunk);
            if last_progress.elapsed() >= Duration::from_secs(30) {
                crate::progress(
                    cfg,
                    "downloading",
                    Some(object.epoch),
                    count,
                    Some(object.bytes),
                    None,
                )?;
                last_progress = Instant::now();
            }
        }
        output.sync_all()?;
        let sha256 = hex(&hash.finalize());
        validate_download(
            count,
            object.bytes,
            &sha256,
            sidecar_sha256.as_deref(),
            metadata_sha256.as_deref(),
        )?;
        owned.identity.check(&scratch)?;
        set_readonly(&scratch)?;
        ensure!(
            hash_file(&scratch)? == sha256,
            "local readback differs from authenticated stream"
        );
        ensure!(
            self.check_identity(object).await? == (version_id.clone(), metadata_sha256.clone()),
            "archive changed after download"
        );
        let result = Download {
            object: object.clone(),
            version_id,
            sha256,
            bytes: count,
            sidecar_sha256,
            sidecar_etag,
            metadata_sha256,
        };
        write_json(&attempt.join("download.json"), &result, false)?;
        Ok(result)
    }
}
fn validate_download(
    actual: u64,
    expected: u64,
    digest: &str,
    sidecar: Option<&str>,
    metadata: Option<&str>,
) -> Result<()> {
    ensure!(
        actual == expected,
        "truncated archive: downloaded {actual}, expected {expected}"
    );
    ensure!(valid_digest(digest), "invalid stream digest");
    if let Some(value) = sidecar {
        ensure!(
            value == digest,
            "archive digest differs from canonical sidecar"
        );
    }
    if let Some(value) = metadata {
        ensure!(
            value == digest,
            "archive digest differs from remote metadata"
        );
    }
    Ok(())
}
pub fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn check_response(object: &Object, etag: Option<&str>, length: Option<i64>) -> Result<()> {
    ensure!(
        etag == Some(object.etag.as_str())
            && length.and_then(|v| u64::try_from(v).ok()) == Some(object.bytes),
        "remote object identity changed"
    );
    Ok(())
}
fn parse_sidecar(epoch: u64, bytes: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(bytes)?;
    let (digest, _) = text.split_once(' ').context("invalid checksum sidecar")?;
    ensure!(
        valid_digest(digest) && text == format!("{digest}  epoch-{epoch}.jet\n"),
        "noncanonical checksum sidecar"
    );
    Ok(digest.into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn download_rejects_truncation_and_corruption_but_includes_staged_archives() {
        let hash = "a".repeat(64);
        let wrong = "b".repeat(64);
        assert!(validate_download(50, 50, &hash, Some(&hash), Some(&hash)).is_ok());
        assert!(validate_download(50, 50, &hash, None, None).is_ok());
        assert!(validate_download(49, 50, &hash, None, None).is_err());
        assert!(validate_download(51, 50, &hash, None, None).is_err());
        assert!(validate_download(50, 50, &hash, Some(&wrong), None).is_err());
        assert!(validate_download(50, 50, &hash, None, Some(&wrong)).is_err());
    }
    #[test]
    fn response_requires_exact_length_and_etag() {
        let obj = Object {
            epoch: 0,
            key: "epoch-0.jet".into(),
            etag: "\"abc\"".into(),
            bytes: 50,
        };
        assert!(check_response(&obj, Some("\"abc\""), Some(50)).is_ok());
        assert!(check_response(&obj, Some("\"abc\""), Some(49)).is_err());
        assert!(check_response(&obj, Some("\"other\""), Some(50)).is_err());
        assert!(check_response(&obj, None, Some(50)).is_err());
    }
    #[test]
    fn sidecar_binds_exact_epoch() {
        let hash = "a".repeat(64);
        assert_eq!(
            parse_sidecar(3, format!("{hash}  epoch-3.jet\n").as_bytes()).unwrap(),
            hash
        );
        for bad in [
            format!("{hash}  epoch-4.jet\n"),
            format!("{hash}  ../epoch-3.jet\n"),
            format!("{hash}  epoch-3.jet\nextra"),
        ] {
            assert!(parse_sidecar(3, bad.as_bytes()).is_err());
        }
    }
}
