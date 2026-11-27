//! Retire explicitly selected obsolete local files after complete R2 delivery.
//! This is not a canonical-archive verifier: obsolete partial bodies need not
//! equal the complete archive. The operator must establish epoch association and
//! absence of staged dependencies before authorizing the exact immutable plan.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::fd::AsRawFd,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(feature = "anza-closed-144-lanek")]
mod anza_closed_144_lanek;
#[cfg(feature = "anza-closed-154")]
mod anza_closed_154;
#[cfg(feature = "anza-closed-canaries")]
mod anza_closed_canaries;
#[cfg(feature = "anza-closed-canaries")]
mod anza_closed_owned_indexes;
#[cfg(feature = "anza-closed-canaries")]
use anza_closed_canaries::closed_bootstrap_cohort;
#[cfg(feature = "anza-parked-183")]
mod anza_parked_183;

#[cfg(feature = "anza-closed-canaries")]
mod anza_167_index_copies;
#[cfg(feature = "anza-closed-canaries")]
mod anza_stopped_167;

const HOME_ROOT: &str = if cfg!(any(
    feature = "anza-closed-144-lanek",
    feature = "anza-parked-183",
    feature = "anza-closed-154",
    feature = "anza-closed-canaries"
)) {
    "/home/sol"
} else {
    "/home/ubuntu"
};
const LIMIT: u64 = 16 << 20;
const EPOCH246_BOOTSTRAP: &str = "/var/lib/jetstreamer/horizon246-bootstrap-copy1636-work-v2/projection/bootstrap/snapshot-106271618-6LSJUywaryX8vRn53cbWqLJiTwBCCb3wnNTPevWfqtQD.tar.zst";
const EPOCH246_BOOTSTRAP_SHA: &str =
    "c5abfce5d852b78860d22d71f1ce57f6752f45bb428257a73e037895ec6a03e7";
struct CloudBootstrap {
    review_schema: &'static str,
    path: &'static str,
    sha256: &'static str,
    bytes: u64,
    key: &'static str,
    generation: &'static str,
    md5: &'static str,
    crc32c: &'static str,
    inactive_units: &'static [&'static str],
}

const EPOCH207_BOOTSTRAP: CloudBootstrap = CloudBootstrap {
    review_schema: "horizon207-obsolete-bootstrap-main-review-v1",
    path: "/var/lib/jetstreamer/horizon-focused-207-complete-span-store8-ca2e38b-v2/snapshot-89423444-3NVZVHDVwXgMxuTP77gaZF4UBP1oNBQzGScBGyoLx2Px.tar.zst",
    sha256: "8af3cd20c8f9820dacd25932fc6b7938193e0d1a5dc83d8ddd59dfeea69b2ddc",
    bytes: 8_474_139_490,
    key: "89423444/snapshot-89423444-3NVZVHDVwXgMxuTP77gaZF4UBP1oNBQzGScBGyoLx2Px.tar.zst",
    generation: "1634790167725358",
    md5: "Dil5cEJL57SGxIfql2EAHQ==",
    crc32c: "Qynv0g==",
    inactive_units: &[
        "horizon-qualify-207-complete-span-ca2e38b-v2.service",
        "horizon-qualify-207-singleton-admitted-v1.service",
    ],
};

const EPOCH210_BOOTSTRAP: CloudBootstrap = CloudBootstrap {
    review_schema: "horizon210-obsolete-bootstrap-main-review-v1",
    path: "/var/lib/jetstreamer/horizon-focused-210-complete-span-store8-ca2e38b-v1/snapshot-90719638-3C18JGi6UtMvAi6M4AUPC96redPqo7h6QnAsrUi8d3SJ.tar.zst",
    sha256: "3f67f416d254d7fb795bc902d5c47a6ae374fa36c173c00411d4b541fc610ccd",
    bytes: 8_579_041_139,
    key: "90719638/snapshot-90719638-3C18JGi6UtMvAi6M4AUPC96redPqo7h6QnAsrUi8d3SJ.tar.zst",
    generation: "1628731675837475",
    md5: "pBPdxBtyTOt6A7LhXryC8Q==",
    crc32c: "rBQmbQ==",
    inactive_units: &[
        "horizon-qualify-210-complete-span-ca2e38b-v1.service",
        "horizon-singleton-210-capped-4aeca563-v1.service",
    ],
};

const EPOCH247_BOOTSTRAP: CloudBootstrap = CloudBootstrap {
    review_schema: "horizon247-obsolete-bootstrap-main-review-v1",
    path: "/var/lib/jetstreamer/horizon247-bootstrap-copy0347-work-v2/projection/bootstrap/snapshot-106703614-AtkJcCAEp3EfF4ymeeN9t3YvHuAq3aykuQ6vogtDYcf9.tar.zst",
    sha256: "060fa4a95bdbf8a41000ed043af667bcd9ae3b6a080c12415ce35f0b5d2bf5ba",
    bytes: 13_262_956_541,
    key: "106703614/snapshot-106703614-AtkJcCAEp3EfF4ymeeN9t3YvHuAq3aykuQ6vogtDYcf9.tar.zst",
    generation: "1637159461322785",
    md5: "Bl+pS/L8pYBfbwpO359gNg==",
    crc32c: "Z0Zcdw==",
    inactive_units: &[
        "horizon-qualify-247-bootstrap-copy0347-v2.service",
        "horizon-qualify-247-reboot-20261117-v2.service",
        "horizon-247-reboot-20261117-protective-v2.service",
        "horizon-247-reboot-20261117-protective-v2.timer",
    ],
};

const EPOCH248_BOOTSTRAP: CloudBootstrap = CloudBootstrap {
    review_schema: "horizon248-obsolete-bootstrap-main-review-v1",
    path: "/var/lib/jetstreamer/horizon248-bootstrap-copy2454-work-v1/projection/bootstrap/snapshot-107135393-BvNzVFUVa9kQwGJQxKFyDVPcBd8yVRbVDaN8YLr28i95.tar.zst",
    sha256: "7a9331400c84cba660aa208c08c18b40f4bc7376f998e25fd1d525143eb883bd",
    bytes: 13_405_638_044,
    key: "107135393/snapshot-107135393-BvNzVFUVa9kQwGJQxKFyDVPcBd8yVRbVDaN8YLr28i95.tar.zst",
    generation: "1637390510433248",
    md5: "ywjFbVgimmaMN0hriDVMJA==",
    crc32c: "Fnetbg==",
    inactive_units: &[
        "horizon-qualify-248-bootstrap-copy2454-v1.service",
        "horizon-qualify-248-reboot-20261117-v1.service",
        "horizon-248-reboot-20261117-protective-v1.service",
        "horizon-248-reboot-20261117-protective-v1.timer",
    ],
};

const EPOCH249_BOOTSTRAP: CloudBootstrap = CloudBootstrap {
    review_schema: "horizon249-obsolete-bootstrap-main-review-v1",
    path: "/var/lib/jetstreamer/horizon-contiguous-249-251-current-46b4b4a-v1/snapshot-107567592-DBPics19TxLy8wawfQYvS65d72vKvFGLCW9HZv5q6GeH.tar.zst",
    sha256: "f9e582d104477e52b6327e26fe011dcfdde437254b953f1a13b78ad43fdef64a",
    bytes: 13_571_383_805,
    key: "107567592/snapshot-107567592-DBPics19TxLy8wawfQYvS65d72vKvFGLCW9HZv5q6GeH.tar.zst",
    generation: "1637611511896161",
    md5: "5T7R2/oARnVkrPc85kobgA==",
    crc32c: "wUO8lg==",
    inactive_units: &[
        "horizon-249-cached-fingerprint-capability2418-v1.service",
        "horizon-qualify-249-reboot-20261117-v1.service",
    ],
};

const EPOCH251_BOOTSTRAP: CloudBootstrap = CloudBootstrap {
    review_schema: "horizon251-obsolete-bootstrap-main-review-v1",
    path: "/var/lib/jetstreamer/horizon251-native-input-20261118-v1/snapshot-108431365-C5eqGwzDFEDfeBovidro6WnY3Drw7caJ2p2mjnJbGJVE.tar.zst",
    sha256: "b7af2058dd498bdf8c0f7e2a717a0d7c8153c20027eca2c3c2de15351b87b311",
    bytes: 13_928_359_507,
    key: "108431365/snapshot-108431365-C5eqGwzDFEDfeBovidro6WnY3Drw7caJ2p2mjnJbGJVE.tar.zst",
    generation: "1638079985418599",
    md5: "uCcKc7cq/a7rkM5Xgz7dng==",
    crc32c: "ij8kmw==",
    inactive_units: &[
        "horizon-251-captured-node-fingerprint-20261118-v1.service",
        "horizon-251-captured-node-fingerprint-20261118-v2.service",
        "horizon-qualify-251-replacement-20261118-v1.service",
        "horizon211-drain-recheck-v191-a1-closed-251.service",
        "horizon211-drain-recheck-v191-a1-wrong-drain.service",
        "horizon251-native-input-small-20261118-v1.service",
        "horizon251-native-input-test-20261118-v1.service",
    ],
};

const EPOCH257_BOOTSTRAP: CloudBootstrap = CloudBootstrap {
    review_schema: "horizon257-obsolete-bootstrap-main-review-v1",
    path: "/var/lib/jetstreamer/horizon-contiguous-257-260-current-46b4b4a-v1/snapshot-111022755-8bRdfjkM7Lst2wWtAyv56VKTprAYt1DKPuVy2HzK1wX3.tar.zst",
    sha256: "3e2b236f2cba29fbfe40f39f133fe9c845df9280e3fc6dd1cb70e4e018a4744d",
    bytes: 15_020_667_485,
    key: "111022755/snapshot-111022755-8bRdfjkM7Lst2wWtAyv56VKTprAYt1DKPuVy2HzK1wX3.tar.zst",
    generation: "1639569360423179",
    md5: "EM4A1h/28JmELhRmnZtVrA==",
    crc32c: "sk+HmQ==",
    inactive_units: &[
        "horizon-qualify-257-singleton-v1.service",
        "horizon-257-singleton-protective-v1.service",
        "horizon-257-singleton-protective-v1.timer",
        "foundation-257-full-namespace-v230-a1.service",
        "foundation-257-full-namespace-v230-a2.service",
    ],
};

const EPOCH261_BOOTSTRAP: CloudBootstrap = CloudBootstrap {
    review_schema: "horizon261-obsolete-bootstrap-main-review-v1",
    path: "/var/lib/jetstreamer/horizon-contiguous-261-264-current-46b4b4a-v1/snapshot-112751208-Hgio4phsEt74AkKo6KdVmFzDoK35yS3fUkF6u3RkhSut.tar.zst",
    sha256: "5e84f74696d1f3100650e134fb91487d3e083c374a3262b05f67378b9b1c8256",
    bytes: 15_435_685_203,
    key: "112751208/snapshot-112751208-Hgio4phsEt74AkKo6KdVmFzDoK35yS3fUkF6u3RkhSut.tar.zst",
    generation: "1640541082024797",
    md5: "+rO5wMGyv//2LlZmM6sQog==",
    crc32c: "nMQ1xg==",
    inactive_units: &[
        "horizon-qualify-261-singleton-v1.service",
        "horizon-261-singleton-protective-v1.service",
        "horizon-261-singleton-protective-v1.timer",
        "foundation-261-full-input-namespace-v226-a1.service",
    ],
};

const EPOCH265_BOOTSTRAP: CloudBootstrap = CloudBootstrap {
    review_schema: "horizon265-obsolete-bootstrap-main-review-v1",
    path: "/var/lib/jetstreamer/horizon-contiguous-265-265-current-46b4b4a-v1/snapshot-114479281-Jo2p1i6wNNn71fwwkyoA6shEtYtovbqzVc6p2W16FzW.tar.zst",
    sha256: "04eb59e2dbbc2b0d4f1535741fa9d56794c32ad18e14c98df4fa76a5ae397641",
    bytes: 16_483_458_670,
    key: "114479281/snapshot-114479281-Jo2p1i6wNNn71fwwkyoA6shEtYtovbqzVc6p2W16FzW.tar.zst",
    generation: "1641500477962489",
    md5: "Q0FEYKFkXAJiwZNXZtq6rQ==",
    crc32c: "+0CPhA==",
    inactive_units: &[
        "horizon-focused-export-cli-directory-20261119-v1.service",
        "horizon-focused-export-cli-handoff-20261119-v1.service",
        "horizon-checkpoint-node-capability265-20261119-v1.service",
        "horizon-checkpoint-node-capability265-20261119-v2.service",
        "horizon-265-production-node-filename-20261119-v1.service",
        "horizon-qualify-265-replacement-20261119-v3.service",
    ],
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
struct Stamp {
    dev: u64,
    ino: u64,
    len: u64,
    blocks: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    epoch: u64,
    path: PathBuf,
    identity: Stamp,
    reason: String,
    #[serde(default)]
    external_bootstrap_review: Option<Bound>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapReview {
    schema: String,
    epoch: u64,
    path: PathBuf,
    identity: Stamp,
    snapshot_sha256: String,
    no_staged_consumers_confirmed: bool,
    original_copy_completion: Bound,
    #[serde(default)]
    original_generation: Option<Bound>,
    evidence: Vec<Bound>,
    inactive_units: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    epoch: u64,
    receipt: Bound,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    obsolete_local_files_authorized: bool,
    no_staged_consumers_confirmed: bool,
    remote_mutations: bool,
    inventory_binary: Bound,
    proofs: Vec<Proof>,
    targets: Vec<Target>,
    inactive_units: Vec<String>,
    audit: PathBuf,
    #[cfg(feature = "anza-parked-183")]
    #[serde(default)]
    holding_custody: Option<Bound>,
}
fn stamp(m: &fs::Metadata) -> Stamp {
    Stamp {
        dev: m.dev(),
        ino: m.ino(),
        len: m.len(),
        blocks: m.blocks(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
        nlink: m.nlink(),
        mtime: m.mtime(),
        mtime_ns: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
    }
}
fn exact(path: &Path) -> Result<fs::Metadata> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "aliased/relative path: {}",
        path.display()
    );
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file() && m.nlink() == 1,
        "not a singly linked regular file: {}",
        path.display()
    );
    Ok(m)
}
fn digest(path: &Path) -> Result<String> {
    // The kernel's own executable handle is deliberately a procfs magic link.
    // All ordinary evidence paths still refuse symlinks.
    let mut f = if path == Path::new("/proc/self/exe") {
        File::open(path)?
    } else {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?
    };
    let mut h = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}
fn bound(b: &Bound, limit: u64) -> Result<Vec<u8>> {
    let before = stamp(&exact(&b.path)?);
    ensure!(before.len <= limit, "oversized evidence");
    let bytes = fs::read(&b.path)?;
    ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == b.sha256 && stamp(&exact(&b.path)?) == before,
        "changed evidence: {}",
        b.path.display()
    );
    Ok(bytes)
}
fn ready(epoch: u64, receipt: &Value, inventory: &Value) -> Result<()> {
    let entries = inventory["entries"]
        .as_array()
        .context("missing inventory entries")?;
    let matching: Vec<_> = entries.iter().filter(|e| e["epoch"] == epoch).collect();
    ensure!(matching.len() == 1, "ambiguous/missing remote epoch");
    let e = matching[0];
    ensure!(
        inventory["schema"] == "jetstreamer-horizon-r2-inventory-v1" && e["state"] == "ready-pair",
        "remote pair not ready"
    );
    let sha = receipt["archive_sha256"]
        .as_str()
        .context("receipt SHA missing")?;
    ensure!(
        sha.len() == 64
            && sha
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "bad SHA"
    );
    ensure!(
        receipt["schema"] == "jetstreamer-horizon-r2-receipt-v1"
            && receipt["bucket"] == "solana-archive-with-accounts-data"
            && receipt["epoch"] == epoch
            && receipt["remote_sha256_readback"] == true
            && receipt["archive_key"] == format!("epoch-{epoch}.jet")
            && receipt["checksum_key"] == format!("epoch-{epoch}.jet.sha256"),
        "receipt lacks whole-object delivery proof"
    );
    ensure!(
        receipt["archive_length"].as_u64().is_some_and(|n| n > 0)
            && receipt["archive_etag"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
        "incomplete receipt"
    );
    ensure!(
        receipt["archive_length"] == e["archive_length"]
            && receipt["archive_etag"] == e["archive_etag"]
            && e["sidecar_sha256"] == sha
            && e["archive_metadata_sha256"] == sha,
        "remote pair differs from durable receipt"
    );
    Ok(())
}
fn check_target(t: &Target) -> Result<()> {
    let scope = match t.epoch {
        #[cfg(feature = "anza-closed-144-lanek")]
        144 => anza_closed_144_lanek::is_target(t),
        #[cfg(feature = "anza-closed-canaries")]
        119 | 121 | 129 | 130 | 133 | 134 | 149 | 191..=197 => anza_closed_canaries::is_target(t),
        #[cfg(feature = "anza-closed-canaries")]
        198 => closed_bootstrap_cohort::is_target(t),
        #[cfg(feature = "anza-closed-canaries")]
        160 | 174 | 183 | 184 if anza_closed_owned_indexes::is_target(t) => true,
        #[cfg(feature = "anza-closed-canaries")]
        154 if anza_closed_canaries::is_target(t) => true,
        #[cfg(feature = "anza-closed-154")]
        154 => anza_closed_154::is_target(t),
        #[cfg(feature = "anza-parked-183")]
        183 => anza_parked_183::is_target(t),
        _ => HOME_ROOT == "/home/ubuntu" && (201..=300).contains(&t.epoch),
    };
    ensure!(
        scope && !t.reason.trim().is_empty(),
        "invalid target authorization"
    );
    ensure!(
        ordinary_private_path(&t.path) || external_bootstrap_sha(t.epoch, &t.path).is_some(),
        "target outside private data"
    );
    ensure!(
        stamp(&exact(&t.path)?) == t.identity,
        "target changed: {}",
        t.path.display()
    );
    ensure!(t.identity.len > 1 << 20, "retain compact metadata");
    if external_bootstrap_sha(t.epoch, &t.path).is_some() {
        let binding = t
            .external_bootstrap_review
            .as_ref()
            .context("external bootstrap needs Main review")?;
        let metadata = exact(&binding.path)?;
        ensure!(
            metadata.uid() == 0 && metadata.mode() & 0o222 == 0,
            "external review must be sealed"
        );
        let review: BootstrapReview = serde_json::from_slice(&bound(binding, LIMIT)?)?;
        validate_bootstrap_review(t, &review)?;
        for evidence in &review.evidence {
            bound(evidence, LIMIT)?;
        }
        let completion: Value =
            serde_json::from_slice(&bound(&review.original_copy_completion, LIMIT)?)?;
        if let Some(profile) = cloud_bootstrap(t.epoch) {
            let generation = review
                .original_generation
                .as_ref()
                .context("external bootstrap needs an authenticated generation lookup")?;
            let metadata: Value = serde_json::from_slice(&bound(generation, LIMIT)?)?;
            validate_cloud_source(profile, &completion, &metadata)?;
        } else {
            ensure!(
                completion["schema"]
                    == "horizon246-guarded-exact-Rust-sealer-copy1024-completion-v1"
                    && completion["Main_accepted_copy_only"] == true
                    && completion["snapshot"]["path"] == EPOCH246_BOOTSTRAP
                    && completion["snapshot"]["sha256"] == EPOCH246_BOOTSTRAP_SHA
                    && completion["snapshot"]["bytes"] == t.identity.len,
                "external bootstrap differs from original copy evidence"
            );
        }
        inactive(&review.inactive_units)?;
    } else {
        ensure!(
            t.external_bootstrap_review.is_none(),
            "external review on ordinary private target"
        );
    }
    Ok(())
}

fn ordinary_private_path(path: &Path) -> bool {
    let private = Path::new(HOME_ROOT).join(".jetstreamer-private");
    path.starts_with(&private) && !path.starts_with(private.join("r2-receipts"))
}
fn cloud_bootstrap(epoch: u64) -> Option<&'static CloudBootstrap> {
    match epoch {
        207 => Some(&EPOCH207_BOOTSTRAP),
        210 => Some(&EPOCH210_BOOTSTRAP),
        247 => Some(&EPOCH247_BOOTSTRAP),
        248 => Some(&EPOCH248_BOOTSTRAP),
        249 => Some(&EPOCH249_BOOTSTRAP),
        251 => Some(&EPOCH251_BOOTSTRAP),
        257 => Some(&EPOCH257_BOOTSTRAP),
        261 => Some(&EPOCH261_BOOTSTRAP),
        265 => Some(&EPOCH265_BOOTSTRAP),
        _ => None,
    }
}

fn external_bootstrap_sha(epoch: u64, path: &Path) -> Option<&'static str> {
    if epoch == 246 && path == Path::new(EPOCH246_BOOTSTRAP) {
        return Some(EPOCH246_BOOTSTRAP_SHA);
    }
    let profile = cloud_bootstrap(epoch)?;
    (path == Path::new(profile.path)).then_some(profile.sha256)
}

fn validate_bootstrap_review(t: &Target, r: &BootstrapReview) -> Result<()> {
    let profile = cloud_bootstrap(t.epoch);
    let (schema, size, required_units): (&str, u64, &[&str]) = if let Some(profile) = profile {
        (profile.review_schema, profile.bytes, profile.inactive_units)
    } else {
        ensure!(t.epoch == 246, "unsupported external bootstrap review");
        (
            "horizon246-obsolete-bootstrap-main-review-v1",
            13_110_128_323,
            &[
                "horizon-qualify-246-general-shrink-debt-budget506-e3f15eb2-v1.service",
                "horizon-qualify-246-bootstrap-copy1636-v2.service",
                "horizon-monitor-246-bootstrap-copy1636-v2.service",
                "horizon-monitor-246-bootstrap-copy1636-v2.timer",
            ],
        )
    };
    let digest = external_bootstrap_sha(t.epoch, &t.path).context("unexpected bootstrap path")?;
    ensure!(
        r.schema == schema
            && r.epoch == t.epoch
            && r.path == t.path
            && r.identity == t.identity
            && r.snapshot_sha256 == digest
            && r.no_staged_consumers_confirmed
            && t.identity.uid == 0
            && t.identity.len == size
            && r.original_generation.is_some() == profile.is_some()
            && !r.evidence.is_empty(),
        "invalid external bootstrap review"
    );
    for required in required_units {
        ensure!(
            r.inactive_units.iter().any(|u| u == *required),
            "missing historical bootstrap consumer {required}"
        );
    }
    Ok(())
}
fn validate_cloud_source(profile: &CloudBootstrap, seal: &Value, metadata: &Value) -> Result<()> {
    let path = Path::new(profile.path);
    let members = seal["members"]
        .as_array()
        .context("missing sealed members")?;
    let mut matching = members
        .iter()
        .filter(|member| member["name"].as_str() == path.file_name().and_then(|n| n.to_str()));
    let member = matching.next().context("missing sealed bootstrap member")?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"].as_str() == path.parent().and_then(Path::to_str)
            && matching.next().is_none()
            && member["sha256"] == profile.sha256
            && member["bytes"] == profile.bytes,
        "bootstrap is outside the original sealed deployment"
    );
    ensure!(
        metadata["bucket"] == "mainnet-beta-ledger-us-ny5"
            && metadata["name"] == profile.key
            && metadata["generation"] == profile.generation
            && metadata["size"] == profile.bytes
            && metadata["md5_hash"] == profile.md5
            && metadata["crc32c_hash"] == profile.crc32c,
        "bootstrap generation differs from the catalog"
    );
    Ok(())
}

fn inactive(units: &[String]) -> Result<()> {
    for unit in units {
        ensure!(
            unit.ends_with(".service") || unit.ends_with(".timer"),
            "invalid unit"
        );
        ensure!(
            unit.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.@-".contains(&b)),
            "unsafe unit name"
        );
        let o = Command::new("/usr/bin/systemctl")
            .args([
                "show",
                unit,
                "-p",
                "ActiveState",
                "-p",
                "MainPID",
                "-p",
                "Job",
            ])
            .output()?;
        ensure!(o.status.success(), "cannot inspect unit {unit}");
        let s = String::from_utf8(o.stdout)?;
        ensure!(
            s.lines()
                .any(|s| s == "ActiveState=inactive" || s == "ActiveState=failed")
                && !s
                    .lines()
                    .any(|s| s.starts_with("MainPID=") && s != "MainPID=0")
                && s.lines().any(|s| s == "Job="),
            "unit is live: {unit}"
        );
    }
    Ok(())
}
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn has_mapping(maps: &[u8], t: &Target) -> bool {
    let dev = format!(
        "{:02x}:{:02x}",
        libc::major(t.identity.dev),
        libc::minor(t.identity.dev)
    );
    let ino = t.identity.ino.to_string();
    maps.split(|&b| b == b'\n').any(|line| {
        let mut fields = line
            .split(|b| b.is_ascii_whitespace())
            .filter(|part| !part.is_empty())
            .skip(3);
        fields.next() == Some(dev.as_bytes()) && fields.next() == Some(ino.as_bytes())
    })
}

fn scan_consumers(targets: &[Target]) -> Result<()> {
    let me = std::process::id().to_string();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let pid = entry.file_name();
        let pid = pid.to_string_lossy();
        if pid == me || !pid.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let root = entry.path();
        let check = || -> Result<()> {
            for name in ["cmdline", "maps"] {
                let data = fs::read(root.join(name))?;
                for t in targets {
                    #[cfg(feature = "anza-closed-canaries")]
                    ensure!(
                        !closed_bootstrap_cohort::alias_in_command(t, &data),
                        "PID {pid} references a reviewed bootstrap alias in {name}"
                    );
                    ensure!(
                        !contains(&data, t.path.as_os_str().as_bytes()),
                        "PID {pid} references {} in {name}",
                        t.path.display()
                    );
                    ensure!(
                        name != "maps" || !has_mapping(&data, t),
                        "PID {pid} maps the selected archive inode"
                    );
                }
            }
            for name in ["cwd", "root", "exe"] {
                match fs::read_link(root.join(name)) {
                    Ok(p) => {
                        for t in targets {
                            ensure!(p != t.path, "PID {pid} uses {}", t.path.display());
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
            for fd in fs::read_dir(root.join("fd"))? {
                let fd = fd?;
                match fs::metadata(fd.path()) {
                    Ok(m) => {
                        for t in targets {
                            ensure!(
                                (m.dev(), m.ino()) != (t.identity.dev, t.identity.ino),
                                "PID {pid} has {} open",
                                t.path.display()
                            );
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
            Ok(())
        };
        if let Err(e) = check()
            && root.exists()
        {
            return Err(e);
        }
    }
    Ok(())
}
fn event(log: &mut File, v: Value) -> Result<()> {
    serde_json::to_writer(&mut *log, &v)?;
    log.write_all(b"\n")?;
    log.sync_all()?;
    Ok(())
}
fn remove_exact(t: &Target) -> Result<()> {
    check_target(t)?;
    unlink_identity(&t.path, &t.identity)
}
fn unlink_identity(path: &Path, expected: &Stamp) -> Result<()> {
    let parent = path.parent().context("no parent")?;
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)?;
    let projected = PathBuf::from(format!(
        "/proc/self/fd/{}/{}",
        dir.as_raw_fd(),
        path.file_name().unwrap().to_string_lossy()
    ));
    ensure!(
        stamp(&fs::symlink_metadata(&projected)?) == *expected,
        "changed directory entry"
    );
    let name = std::ffi::CString::new(path.file_name().unwrap().as_bytes())?;
    ensure!(
        unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } == 0,
        "unlink failed: {}",
        std::io::Error::last_os_error()
    );
    dir.sync_all()?;
    Ok(())
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 4 || args.len() == 5,
        "usage: horizon-retire-completed PLAN PLAN_SHA256 SELF_SHA256 [--check-only]"
    );
    let check_only = args.len() == 5;
    ensure!(!check_only || args[4] == "--check-only", "unknown argument");
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "requires root for complete consumer inspection"
    );
    ensure!(
        digest(Path::new("/proc/self/exe"))? == args[3],
        "self digest mismatch"
    );
    let plan_path = PathBuf::from(&args[1]);
    let pm = exact(&plan_path)?;
    ensure!(
        pm.uid() == 0 && pm.mode() & 0o022 == 0,
        "plan not immutable root-owned evidence"
    );
    let bytes = bound(
        &Bound {
            path: plan_path.clone(),
            sha256: args[2].clone(),
        },
        LIMIT,
    )?;
    #[cfg(feature = "anza-closed-canaries")]
    if plan_path == Path::new(anza_stopped_167::REVIEW) {
        return anza_stopped_167::run(&bytes, &args[2], &args[3], check_only);
    }
    #[cfg(feature = "anza-closed-canaries")]
    if plan_path == Path::new(anza_167_index_copies::REVIEW) {
        return anza_167_index_copies::run(&bytes, &args[2], &args[3], check_only);
    }
    let p: Plan = serde_json::from_slice(&bytes)?;
    ensure!(
        p.schema == "horizon-retire-completed-v1"
            && p.obsolete_local_files_authorized
            && p.no_staged_consumers_confirmed
            && !p.remote_mutations,
        "unauthorized plan"
    );
    ensure!(
        !p.targets.is_empty() && !p.proofs.is_empty(),
        "empty selection"
    );
    let mut paths = BTreeSet::new();
    let mut epochs = BTreeSet::new();
    for t in &p.targets {
        ensure!(paths.insert(&t.path), "duplicate target");
        epochs.insert(t.epoch);
        check_target(t)?;
        if let Some(expected) = external_bootstrap_sha(t.epoch, &t.path) {
            ensure!(
                digest(&t.path)? == expected,
                "external bootstrap content changed"
            );
            check_target(t)?;
        }
    }
    let proof_epochs: BTreeSet<_> = p.proofs.iter().map(|x| x.epoch).collect();
    ensure!(
        proof_epochs == epochs && p.proofs.len() == epochs.len(),
        "proof/target epoch mismatch"
    );
    #[cfg(feature = "anza-closed-canaries")]
    let _first_sweep_lock = (epochs.contains(&119) || epochs.contains(&121))
        .then(anza_closed_canaries::lock_first_sweep_controller)
        .transpose()?;
    #[cfg(feature = "anza-closed-canaries")]
    let _index_locks = p
        .targets
        .iter()
        .any(anza_closed_canaries::is_index)
        .then(anza_closed_canaries::lock_index_controllers)
        .transpose()?;
    #[cfg(feature = "anza-closed-canaries")]
    let _singleton_locks = p
        .targets
        .iter()
        .any(anza_closed_canaries::is_singleton_index)
        .then(anza_closed_canaries::lock_singleton_controllers)
        .transpose()?;
    #[cfg(feature = "anza-closed-canaries")]
    let _early_singleton_locks = p
        .targets
        .iter()
        .any(anza_closed_canaries::is_early_singleton_index)
        .then(anza_closed_canaries::lock_early_singleton_controllers)
        .transpose()?;
    #[cfg(feature = "anza-closed-canaries")]
    let _epoch149_locks = epochs
        .contains(&149)
        .then(anza_closed_canaries::lock_epoch149_controllers)
        .transpose()?;
    #[cfg(feature = "anza-closed-canaries")]
    let _closed_bootstrap_locks = epochs
        .contains(&198)
        .then(closed_bootstrap_cohort::lock_controllers)
        .transpose()?;
    #[cfg(feature = "anza-closed-canaries")]
    let closed_owned_indexes = anza_closed_owned_indexes::profile(&epochs);
    #[cfg(feature = "anza-closed-canaries")]
    ensure!(
        !p.targets.iter().any(anza_closed_owned_indexes::is_target)
            || closed_owned_indexes.is_some(),
        "unexpected or mixed closed index scope"
    );
    #[cfg(feature = "anza-closed-canaries")]
    let _closed_index_locks = closed_owned_indexes
        .map(anza_closed_owned_indexes::lock_controllers)
        .transpose()?;
    #[cfg(feature = "anza-closed-144-lanek")]
    let _lane_k_lock = epochs
        .contains(&144)
        .then(anza_closed_144_lanek::lock_original_owner)
        .transpose()?;
    let receipts = Path::new(HOME_ROOT).join(".jetstreamer-private/r2-receipts");
    #[cfg(feature = "anza-parked-183")]
    let parked_183 = p.targets.iter().any(anza_parked_183::is_target);
    #[cfg(feature = "anza-parked-183")]
    let _holding_locks = parked_183
        .then(anza_parked_183::lock_original_owners)
        .transpose()?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(receipts.join("local-mutation.lock"))?;
    ensure!(
        lock.metadata()?.is_file() && lock.metadata()?.nlink() == 1,
        "unsafe lock"
    );
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "mutation lock busy"
    );
    #[cfg(feature = "anza-closed-144-lanek")]
    if epochs.contains(&144) {
        anza_closed_144_lanek::verify(&p, &lock)?;
    }
    #[cfg(feature = "anza-parked-183")]
    if parked_183 {
        anza_parked_183::verify(&p, &lock)?;
    } else {
        ensure!(p.holding_custody.is_none(), "unexpected holding custody");
    }
    #[cfg(feature = "anza-closed-154")]
    let closed_154 = p.targets.iter().any(anza_closed_154::is_target);
    #[cfg(feature = "anza-closed-154")]
    let _continuation_lock = p
        .targets
        .iter()
        .any(anza_closed_154::continuation::is_index)
        .then(anza_closed_154::continuation::lock)
        .transpose()?;
    #[cfg(feature = "anza-closed-154")]
    if closed_154 {
        anza_closed_154::verify_scope(&p, &lock)?;
    }
    #[cfg(feature = "anza-closed-canaries")]
    let canary_review = anza_closed_canaries::verify_scope(&p, &epochs, &lock)?;
    #[cfg(feature = "anza-closed-canaries")]
    let closed_index_review = closed_owned_indexes
        .map(|profile| {
            anza_closed_owned_indexes::verify(profile, &p).map(|review| (profile, review))
        })
        .transpose()?;
    #[cfg(feature = "anza-closed-canaries")]
    if epochs.contains(&198) {
        closed_bootstrap_cohort::verify_scope(&p, &lock)?;
    }
    let bm = exact(&p.inventory_binary.path)?;
    ensure!(
        bm.uid() == 0
            && bm.mode() & 0o022 == 0
            && digest(&p.inventory_binary.path)? == p.inventory_binary.sha256,
        "unqualified inventory binary"
    );
    inactive(&p.inactive_units)?;
    scan_consumers(&p.targets)?;
    let horizon = Path::new(HOME_ROOT).join("horizon");
    let range = (*epochs.first().unwrap(), *epochs.last().unwrap());
    #[cfg(feature = "anza-closed-154")]
    let range = if closed_154 {
        (range.0.min(153), range.1.max(155))
    } else {
        range
    };
    #[cfg(feature = "anza-closed-canaries")]
    let range = if let Some(review) = &canary_review {
        anza_closed_canaries::inventory_range(review, range)
    } else {
        range
    };
    #[cfg(feature = "anza-closed-canaries")]
    let range = if epochs.contains(&198) {
        (195, 198)
    } else {
        range
    };
    let output = Command::new(&p.inventory_binary.path)
        .env("TOKIO_WORKER_THREADS", "2")
        .arg("inventory")
        .arg(horizon)
        .arg("--epochs")
        .arg(format!("{}-{}", range.0, range.1))
        .arg("--receipt-directory")
        .arg(&receipts)
        .output()?;
    ensure!(
        output.status.success(),
        "authenticated inventory failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    ensure!(output.stdout.len() <= LIMIT as usize, "oversized inventory");
    let inventory: Value = serde_json::from_slice(&output.stdout)?;
    for proof in &p.proofs {
        let r: Value = serde_json::from_slice(&bound(&proof.receipt, LIMIT)?)?;
        ready(proof.epoch, &r, &inventory)?;
    }
    #[cfg(feature = "anza-closed-154")]
    if closed_154 {
        anza_closed_154::verify_delivery(&receipts, &inventory)?;
    }
    #[cfg(feature = "anza-closed-canaries")]
    if let Some(review) = &canary_review {
        anza_closed_canaries::verify_delivery(review, &epochs, &inventory)?;
    }
    #[cfg(feature = "anza-closed-canaries")]
    if epochs.contains(&198) {
        closed_bootstrap_cohort::verify_delivery(&receipts, &inventory)?;
        closed_bootstrap_cohort::check_owners()?;
    }
    inactive(&p.inactive_units)?;
    scan_consumers(&p.targets)?;
    for t in &p.targets {
        check_target(t)?;
    }
    #[cfg(feature = "anza-closed-canaries")]
    if let Some((profile, review)) = &closed_index_review {
        anza_closed_owned_indexes::check_owners(profile, review)?;
    }
    if check_only {
        println!(
            "checked {} exact files, {} verified R2 epochs; no deletion",
            p.targets.len(),
            epochs.len()
        );
        return Ok(());
    }
    ensure!(
        p.audit.is_absolute()
            && p.audit.parent().context("audit parent")?.canonicalize()?
                == p.audit.parent().unwrap(),
        "aliased audit path"
    );
    let mut log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p.audit)?;
    event(
        &mut log,
        json!({"event":"authorized","plan_sha256":args[2],"self_sha256":args[3],"unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"inventory":inventory}),
    )?;
    File::open(p.audit.parent().unwrap())?.sync_all()?;
    let mut bytes = 0;
    for t in &p.targets {
        #[cfg(feature = "anza-closed-144-lanek")]
        if t.epoch == 144 {
            anza_closed_144_lanek::check_owners()?;
        }
        #[cfg(feature = "anza-parked-183")]
        if anza_parked_183::is_target(t) {
            anza_parked_183::check_owners()?;
        }
        #[cfg(feature = "anza-closed-154")]
        if anza_closed_154::is_target(t) {
            anza_closed_154::check_owners(t)?;
        }
        #[cfg(feature = "anza-closed-canaries")]
        if let Some(review) = &canary_review {
            anza_closed_canaries::check_owners(review)?;
        }
        #[cfg(feature = "anza-closed-canaries")]
        if let Some((profile, review)) = &closed_index_review {
            anza_closed_owned_indexes::check_owners(profile, review)?;
        }
        inactive(&p.inactive_units)?;
        scan_consumers(std::slice::from_ref(t))?;
        event(
            &mut log,
            json!({"event":"intent","epoch":t.epoch,"path":t.path,"identity":t.identity,"reason":t.reason}),
        )?;
        #[cfg(feature = "anza-closed-canaries")]
        if closed_bootstrap_cohort::is_target(t) {
            closed_bootstrap_cohort::check_owners()?;
            closed_bootstrap_cohort::check_aliases(t, false)?;
            scan_consumers(std::slice::from_ref(t))?;
        }
        remove_exact(t)?;
        #[cfg(feature = "anza-closed-canaries")]
        if closed_bootstrap_cohort::is_target(t) {
            closed_bootstrap_cohort::check_aliases(t, true)?;
        }
        bytes += t.identity.blocks * 512;
        event(
            &mut log,
            json!({"event":"removed","epoch":t.epoch,"path":t.path,"allocated_bytes":t.identity.blocks*512}),
        )?;
    }
    event(
        &mut log,
        json!({"event":"complete","allocated_bytes_removed":bytes,"remote_mutations":false}),
    )?;
    println!(
        "removed {} files, {} allocated bytes; receipt {}",
        p.targets.len(),
        bytes,
        p.audit.display()
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e:#}");
        std::process::exit(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn external_routes_select_exact_epoch_files_and_never_metadata() {
        assert_eq!(
            external_bootstrap_sha(246, Path::new(EPOCH246_BOOTSTRAP)),
            Some(EPOCH246_BOOTSTRAP_SHA)
        );
        assert_eq!(
            external_bootstrap_sha(249, Path::new(EPOCH249_BOOTSTRAP.path)),
            Some(EPOCH249_BOOTSTRAP.sha256)
        );
        assert!(external_bootstrap_sha(246, Path::new(EPOCH249_BOOTSTRAP.path)).is_none());
        for path in [
            "/var/lib/jetstreamer/other/snapshot.tar.zst",
            "/var/lib/jetstreamer/horizon246-bootstrap-copy1636-work-v2/projection/bootstrap/deployment-seal-receipt.json",
            "/var/lib/jetstreamer/horizon246-bootstrap-copy1636-work-v2/projection/bootstrap",
        ] {
            assert!(external_bootstrap_sha(246, Path::new(path)).is_none());
        }
        assert!(external_bootstrap_sha(247, Path::new(EPOCH246_BOOTSTRAP)).is_none());
        let home = Path::new(HOME_ROOT);
        assert!(ordinary_private_path(
            &home.join(".jetstreamer-private/old/archive")
        ));
        assert!(!ordinary_private_path(
            &home.join(".jetstreamer-private/r2-receipts/epoch-246.r2.json")
        ));
    }

    #[test]
    fn external_review_requires_exact_identity_and_complete_inactive_consumer_set() {
        let mut r: BootstrapReview = serde_json::from_value(json!({
            "schema":"horizon246-obsolete-bootstrap-main-review-v1", "epoch":246,
            "path":EPOCH246_BOOTSTRAP,"snapshot_sha256":EPOCH246_BOOTSTRAP_SHA,
            "identity":{"dev":1,"ino":2,"len":13110128323u64,"blocks":25605744,
                "uid":0,"gid":0,"mode":33060,"nlink":1,"mtime":1,"mtime_ns":0,"ctime":1,"ctime_ns":0},
            "no_staged_consumers_confirmed":true,
            "original_copy_completion":{"path":"/completion","sha256":"a".repeat(64)},
            "evidence":[{"path":"/review","sha256":"b".repeat(64)}],
            "inactive_units":["horizon-qualify-246-general-shrink-debt-budget506-e3f15eb2-v1.service",
                "horizon-qualify-246-bootstrap-copy1636-v2.service","horizon-monitor-246-bootstrap-copy1636-v2.service",
                "horizon-monitor-246-bootstrap-copy1636-v2.timer"]
        })).unwrap();
        let t = Target {
            epoch: 246,
            path: EPOCH246_BOOTSTRAP.into(),
            identity: r.identity.clone(),
            reason: "obsolete".into(),
            external_bootstrap_review: None,
        };
        validate_bootstrap_review(&t, &r).unwrap();
        r.identity.ino += 1;
        assert!(validate_bootstrap_review(&t, &r).is_err());
        r.identity = t.identity.clone();
        r.no_staged_consumers_confirmed = false;
        assert!(validate_bootstrap_review(&t, &r).is_err());
        r.no_staged_consumers_confirmed = true;
        r.inactive_units.pop();
        assert!(validate_bootstrap_review(&t, &r).is_err());
    }
    #[test]
    fn cloud_bootstrap_requires_its_exact_epoch_file_and_generation() {
        for (epoch, profile) in [
            (207, &EPOCH207_BOOTSTRAP),
            (210, &EPOCH210_BOOTSTRAP),
            (247, &EPOCH247_BOOTSTRAP),
            (248, &EPOCH248_BOOTSTRAP),
            (249, &EPOCH249_BOOTSTRAP),
            (251, &EPOCH251_BOOTSTRAP),
            (257, &EPOCH257_BOOTSTRAP),
            (261, &EPOCH261_BOOTSTRAP),
            (265, &EPOCH265_BOOTSTRAP),
        ] {
            let path = Path::new(profile.path);
            assert_eq!(external_bootstrap_sha(epoch, path), Some(profile.sha256));
            assert!(external_bootstrap_sha(epoch + 1, path).is_none());
            let mut seal = json!({
                "schema": "jetstreamer-sealed-deployment-receipt-v1",
                "destination": path.parent().unwrap(),
                "members": [{
                    "name": path.file_name().unwrap().to_str().unwrap(),
                    "bytes": profile.bytes,
                    "sha256": profile.sha256,
                }],
            });
            let mut metadata = json!({
                "bucket": "mainnet-beta-ledger-us-ny5",
                "name": profile.key,
                "generation": profile.generation,
                "size": profile.bytes,
                "md5_hash": profile.md5,
                "crc32c_hash": profile.crc32c,
            });
            validate_cloud_source(profile, &seal, &metadata).unwrap();
            metadata["generation"] = json!("1234567890");
            assert!(validate_cloud_source(profile, &seal, &metadata).is_err());
            metadata["generation"] = json!(profile.generation);
            seal["members"][0]["bytes"] = json!(profile.bytes - 1);
            assert!(validate_cloud_source(profile, &seal, &metadata).is_err());
        }
    }

    #[test]
    fn running_executable_can_be_hashed() {
        assert_eq!(
            digest(Path::new("/proc/self/exe")).unwrap(),
            digest(&std::env::current_exe().unwrap()).unwrap()
        );
    }
    fn pair() -> (Value, Value) {
        let sha = "a".repeat(64);
        (
            json!({"schema":"jetstreamer-horizon-r2-receipt-v1","bucket":"solana-archive-with-accounts-data","epoch":202,"remote_sha256_readback":true,"archive_key":"epoch-202.jet","checksum_key":"epoch-202.jet.sha256","archive_length":100,"archive_etag":"etag","archive_sha256":sha}),
            json!({"schema":"jetstreamer-horizon-r2-inventory-v1","entries":[{"epoch":202,"state":"ready-pair","archive_length":100,"archive_etag":"etag","sidecar_sha256":sha,"archive_metadata_sha256":sha}]}),
        )
    }
    #[test]
    fn authentic_complete_pair() {
        let (r, i) = pair();
        ready(202, &r, &i).unwrap();
    }
    #[test]
    fn no_readback_rejected() {
        let (mut r, i) = pair();
        r["remote_sha256_readback"] = json!(false);
        assert!(ready(202, &r, &i).is_err());
    }
    #[test]
    fn remote_changes_rejected() {
        for field in [
            "archive_length",
            "archive_etag",
            "sidecar_sha256",
            "archive_metadata_sha256",
            "state",
        ] {
            let (r, mut i) = pair();
            i["entries"][0][field] = json!("changed");
            assert!(ready(202, &r, &i).is_err(), "{field}");
        }
    }
    #[test]
    fn wrong_epoch_and_duplicate_rejected() {
        let (r, mut i) = pair();
        assert!(ready(203, &r, &i).is_err());
        let e = i["entries"][0].clone();
        i["entries"].as_array_mut().unwrap().push(e);
        assert!(ready(202, &r, &i).is_err());
    }
    #[test]
    fn aliases_and_hardlinks_rejected() {
        let p = std::env::temp_dir().join(format!("retire-test-{}", std::process::id()));
        fs::create_dir(&p).unwrap();
        let f = p.join("data");
        fs::write(&f, b"test").unwrap();
        exact(&f).unwrap();
        let link = p.join("link");
        std::os::unix::fs::symlink(&f, &link).unwrap();
        assert!(exact(&link).is_err());
        fs::remove_file(&link).unwrap();
        fs::hard_link(&f, &link).unwrap();
        assert!(exact(&f).is_err());
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn deletion_rejects_changed_file_and_preserves_neighbor() {
        let p = std::env::temp_dir().join(format!("retire-unlink-test-{}", std::process::id()));
        fs::create_dir(&p).unwrap();
        let f = p.join("selected");
        let other = p.join("preserved");
        fs::write(&f, b"old").unwrap();
        fs::write(&other, b"evidence").unwrap();
        let before = stamp(&exact(&f).unwrap());
        fs::write(&f, b"changed content").unwrap();
        assert!(unlink_identity(&f, &before).is_err());
        assert_eq!(fs::read(&f).unwrap(), b"changed content");
        unlink_identity(&f, &stamp(&exact(&f).unwrap())).unwrap();
        assert!(!f.exists());
        assert_eq!(fs::read(&other).unwrap(), b"evidence");
        fs::remove_dir_all(p).unwrap();
    }
}
