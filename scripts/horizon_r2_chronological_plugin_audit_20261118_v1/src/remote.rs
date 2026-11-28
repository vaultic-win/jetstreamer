use crate::{Config, canonical_epoch, local::*, range};
use anyhow::{Context, Result, ensure};
use aws_credential_types::{Credentials, provider::SharedCredentialsProvider};
use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Region},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    env, fmt,
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

impl Download {
    pub fn identity(&self, bucket: &str) -> TransferIdentity {
        TransferIdentity {
            bucket: bucket.into(),
            object: self.object.clone(),
            version_id: self.version_id.clone(),
            metadata_sha256: self.metadata_sha256.clone(),
            sidecar_sha256: self.sidecar_sha256.clone(),
            sidecar_etag: self.sidecar_etag.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransferIdentity {
    pub bucket: String,
    pub object: Object,
    pub version_id: Option<String>,
    pub metadata_sha256: Option<String>,
    pub sidecar_sha256: Option<String>,
    pub sidecar_etag: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransferInterruptionKind {
    BodyReadError,
    BodyReadTimeout,
}

/// Constructed only at the authenticated response-body transport boundary.
/// Digest, length, remote identity, disk, reader and plugin errors never acquire
/// this marker merely because their text mentions an I/O failure.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferInterruption {
    pub kind: TransferInterruptionKind,
    pub identity: TransferIdentity,
    pub downloaded_bytes: u64,
    pub detail: String,
}
impl fmt::Display for TransferInterruption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "archive body transport interrupted after {} bytes: {}",
            self.downloaded_bytes, self.detail
        )
    }
}
impl std::error::Error for TransferInterruption {}

#[cfg(test)]
fn body_read_result<T, E: fmt::Display>(
    result: std::result::Result<Option<T>, E>,
    identity: &TransferIdentity,
    downloaded_bytes: u64,
) -> Result<Option<T>> {
    result.map_err(|error| {
        TransferInterruption {
            kind: TransferInterruptionKind::BodyReadError,
            identity: identity.clone(),
            downloaded_bytes,
            detail: error.to_string(),
        }
        .into()
    })
}

fn require_same_transfer_identity(
    current: &TransferIdentity,
    prior: Option<&TransferIdentity>,
) -> Result<()> {
    ensure!(
        prior.is_none_or(|prior| prior == current),
        "remote archive or sidecar identity changed between transfer attempts"
    );
    Ok(())
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
    pub(super) async fn sidecar(
        &self,
        object: &Object,
    ) -> Result<(Option<String>, Option<String>)> {
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
    /// Reobserve the complete authenticated identity, including the canonical
    /// sidecar. Reused by copied-download recovery and the final playback check.
    pub async fn identity(&self, object: &Object) -> Result<TransferIdentity> {
        let (version_id, metadata_sha256) = self.check_identity(object).await?;
        let (sidecar_sha256, sidecar_etag) = self.sidecar(object).await?;
        if let (Some(a), Some(b)) = (&metadata_sha256, &sidecar_sha256) {
            ensure!(a == b, "sidecar and metadata digests disagree");
        }
        Ok(TransferIdentity {
            bucket: self.bucket.clone(),
            object: object.clone(),
            version_id,
            metadata_sha256,
            sidecar_sha256,
            sidecar_etag,
        })
    }
    pub async fn download(
        &self,
        cfg: &Config,
        object: &Object,
        attempt: &Path,
        prior_identity: Option<&TransferIdentity>,
    ) -> Result<Download> {
        let deadline = tokio::time::Instant::now()
            .checked_add(Duration::from_secs(cfg.download_timeout_seconds))
            .context("download deadline overflow")?;
        let identity = tokio::time::timeout_at(deadline, self.identity(object))
            .await
            .context("archive download deadline exceeded while pinning identity")??;
        let version_id = identity.version_id.clone();
        let metadata_sha256 = identity.metadata_sha256.clone();
        let sidecar_sha256 = identity.sidecar_sha256.clone();
        let sidecar_etag = identity.sidecar_etag.clone();
        require_same_transfer_identity(&identity, prior_identity)?;
        write_json(&attempt.join("download-identity.json"), &identity, false)?;
        write_json(
            &attempt.join("range-transfer-plan.json"),
            &range::plan(&identity)?,
            false,
        )?;
        cfg.require_download_capacity(object.bytes)?;
        let scratch = cfg.scratch_directory().join(&object.key);
        let mut output = create(&scratch)?;
        let owned = OwnedScratch {
            key: object.key.clone(),
            identity: Identity::from_file(&output)?,
            created_at: now(),
            external_scratch: cfg.external_scratch.clone(),
        };
        write_json(
            &cfg.state_directory.join("scratch-owner.json"),
            &owned,
            false,
        )?;
        let mut last_progress = Instant::now();
        let (count, sha256) = range::transfer(
            &self.client,
            &identity,
            deadline,
            Duration::from_secs(cfg.read_timeout_seconds),
            |start, bytes| {
                let count = start
                    .checked_add(u64::try_from(bytes.len())?)
                    .context("download count overflow")?;
                ensure!(
                    count <= object.bytes && count <= cfg.max_archive_bytes,
                    "archive exceeds pinned length or budget"
                );
                owned.identity.check(&scratch)?;
                cfg.require_download_write_capacity(u64::try_from(bytes.len())?)?;
                output.write_all(bytes)?;
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
                Ok(())
            },
        )
        .await?;
        output.sync_all()?;
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
            tokio::time::Instant::now() < deadline,
            "archive download deadline exceeded during local readback"
        );
        ensure!(
            tokio::time::timeout_at(deadline, self.identity(object))
                .await
                .context("archive download deadline exceeded during final identity check")??
                == identity,
            "archive or sidecar changed after download"
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
    fn identity() -> TransferIdentity {
        TransferIdentity {
            bucket: "solana-archive-with-accounts-data".into(),
            object: Object {
                epoch: 73,
                key: "epoch-73.jet".into(),
                etag: "pinned".into(),
                bytes: 100,
            },
            version_id: Some("version".into()),
            metadata_sha256: Some("a".repeat(64)),
            sidecar_sha256: Some("a".repeat(64)),
            sidecar_etag: Some("sidecar".into()),
        }
    }
    #[test]
    fn body_eof_error_is_typed_but_clean_short_read_and_digest_errors_are_not() {
        let error = body_read_result::<Vec<u8>, _>(
            Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection ended",
            )),
            &identity(),
            50,
        )
        .unwrap_err();
        let marker = error.downcast_ref::<TransferInterruption>().unwrap();
        assert_eq!(marker.downloaded_bytes, 50);
        assert_eq!(marker.identity, identity());
        assert_eq!(marker.kind, TransferInterruptionKind::BodyReadError);
        let clean = body_read_result::<Vec<u8>, std::io::Error>(Ok(None), &identity(), 50).unwrap();
        assert!(clean.is_none());
        for error in [
            validate_download(50, 100, &"a".repeat(64), None, None).unwrap_err(),
            validate_download(100, 100, &"a".repeat(64), Some(&"b".repeat(64)), None).unwrap_err(),
        ] {
            assert!(error.downcast_ref::<TransferInterruption>().is_none());
        }
    }
    #[test]
    fn retry_reobserves_every_pinned_remote_identity_field() {
        let original = identity();
        require_same_transfer_identity(&original, Some(&original)).unwrap();
        for field in 0..7 {
            let mut changed = original.clone();
            match field {
                0 => changed.object.etag.push('x'),
                1 => changed.object.bytes += 1,
                2 => changed.version_id = None,
                3 => changed.metadata_sha256 = None,
                4 => changed.sidecar_sha256 = None,
                5 => changed.sidecar_etag = None,
                _ => changed.bucket.push('x'),
            }
            let error = require_same_transfer_identity(&changed, Some(&original)).unwrap_err();
            assert!(error.downcast_ref::<TransferInterruption>().is_none());
        }
    }
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
