//! Check the durable uploader and playback receipts for one completed publication.
//! This reads local evidence. The operator separately checks the original service
//! exit and the authenticated R2 archive/sidecar pair before retiring a status.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}

fn document(path: &Path) -> Result<(Bound, Value)> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical evidence path"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.uid() == 0
            && meta.nlink() == 1
            && meta.mode() & 0o022 == 0
            && meta.len() <= 1024 * 1024,
        "unsafe evidence file"
    );
    let mut bytes = Vec::new();
    file.by_ref()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    let identity = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.ctime(),
            m.ctime_nsec(),
            m.mode(),
        )
    };
    ensure!(
        bytes.len() as u64 == meta.len()
            && identity(&file.metadata()?) == identity(&meta)
            && identity(&fs::symlink_metadata(path)?) == identity(&meta),
        "evidence changed during read"
    );
    Ok((
        Bound {
            path: path.into(),
            sha256: format!("{:x}", Sha256::digest(&bytes)),
        },
        serde_json::from_slice(&bytes)?,
    ))
}

impl Bound {
    fn read(&self) -> Result<Value> {
        let (observed, value) = document(&self.path)?;
        ensure!(
            *self == observed,
            "evidence digest mismatch for {}",
            self.path.display()
        );
        Ok(value)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    epoch: u64,
    uploader_pid: u32,
    bucket: String,
    public_origin: String,
    archive_directory: PathBuf,
    receipt_directory: PathBuf,
    archive_sha256: String,
    archive_bytes: u64,
    reader_plan: Bound,
}

fn bound_child(parent: &Path, name: &str, binding: &Value) -> Result<Value> {
    let child: Bound = serde_json::from_value(binding.clone())?;
    ensure!(
        child.path == parent.join(name),
        "unexpected evidence path for {name}"
    );
    child.read()
}

fn verify(plan: &Plan) -> Result<Value> {
    let epoch = plan.epoch;
    let first = epoch.checked_mul(432000).context("epoch overflow")?;
    let last = first.checked_add(431999).context("slot overflow")?;
    let key = format!("epoch-{epoch}.jet");
    let reader = plan.reader_plan.read()?;
    let (archive_ref, archive) = document(
        &plan
            .receipt_directory
            .join(format!("epoch-{epoch}.r2.json")),
    )?;
    ensure!(
        archive["schema"] == "jetstreamer-horizon-r2-receipt-v1"
            && archive["bucket"] == plan.bucket
            && archive["epoch"] == epoch
            && archive["archive_key"] == key
            && archive["checksum_key"] == format!("{key}.sha256")
            && archive["archive_length"] == plan.archive_bytes
            && archive["archive_sha256"] == plan.archive_sha256
            && archive["remote_sha256_readback"] == true,
        "wrong archive or incomplete readback"
    );
    let tag = archive["archive_etag"]
        .as_str()
        .filter(|s| !s.is_empty())
        .context("missing archive ETag")?;
    let acceptance: Bound = serde_json::from_value(archive["current_reader_playback"].clone())?;
    let directory = acceptance
        .path
        .parent()
        .context("missing playback directory")?;
    let scratch = reader["scratch_directory"]
        .as_str()
        .context("missing scratch directory")?;
    let prefix = format!("epoch-{epoch}-{}-", plan.uploader_pid);
    ensure!(
        directory.parent() == Some(Path::new(scratch))
            && directory
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_prefix(&prefix))
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|s| s > 0),
        "playback belongs to another uploader run"
    );
    let playback = bound_child(
        directory,
        "remote-playback-acceptance.json",
        &archive["current_reader_playback"],
    )?;
    ensure!(
        playback["schema"] == "horizon-r2-current-reader-playback-acceptance-v1"
            && playback["epoch"] == epoch
            && playback["reader_plan"] == json!(plan.reader_plan)
            && playback["reader_commit"] == reader["reader_commit"]
            && playback["qualification"] == reader["qualification"],
        "unqualified playback"
    );
    let remote = &playback["remote_playback"];
    ensure!(
        remote["object"]
            == json!({"bucket":plan.bucket,"key":key,"length":plan.archive_bytes,"sha256":plan.archive_sha256,"etag":tag})
            && remote["public_origin"] == plan.public_origin,
        "different public object"
    );
    let inventory = bound_child(
        directory,
        "public-archive-inventory.json",
        &remote["archive_inventory"],
    )?;
    ensure!(
        inventory["schema"] == "horizon-r2-chronological-audit-inventory-v1"
            && inventory["bucket"] == plan.bucket
            && inventory["objects"]
                == json!([{"epoch":epoch,"key":key,"bytes":plan.archive_bytes,"etag":format!("\"{tag}\"")}]),
        "incorrect public inventory"
    );
    let threads = reader["threads"]
        .as_u64()
        .filter(|&v| v > 0)
        .context("invalid partition count")?;
    let local = &playback["local_playback"];
    let public = &remote["playback"];
    for (kind, entry, source) in [
        ("local", local, json!(plan.archive_directory)),
        ("remote", public, json!(plan.public_origin)),
    ] {
        let name = format!("{kind}-plugin.json");
        let report = bound_child(directory, &name, &entry["report_binding"])?;
        let mut args = vec![
            reader["pipeline"]["path"].clone(),
            json!(epoch.to_string()),
            source.clone(),
            json!("--verify-only"),
            json!("--threads"),
            json!(threads.to_string()),
            json!("--verification-report"),
            json!(directory.join(&name)),
        ];
        if kind == "remote" {
            args.extend([
                json!("--archive-inventory"),
                json!(directory.join("public-archive-inventory.json")),
            ]);
        }
        let counters = &report["report"];
        ensure!(
            counters["blocks"]
                .as_u64()
                .zip(counters["skipped"].as_u64())
                .and_then(|(a, b)| a.checked_add(b))
                == Some(432000),
            "plugin slot totals differ"
        );
        for key in [
            "entries",
            "transactions",
            "transaction_updates",
            "orphan_updates",
            "epoch_updates",
            "account_data_bytes",
        ] {
            ensure!(
                counters[key].as_u64().is_some(),
                "missing plugin counter {key}"
            );
        }
        ensure!(
            counters["stream_digest"].as_array().is_some_and(
                |a| a.len() == 32 && a.iter().all(|v| v.as_u64().is_some_and(|b| b <= 255))
            ),
            "missing plugin stream digest"
        );
        ensure!(
            entry["process_exit_code"].as_i64() == Some(0)
                && entry["pipeline"] == reader["pipeline"]
                && entry["invocation"] == json!(args)
                && report == entry["report"]
                && report["invocation"] == json!(args)
                && report["schema"] == "jetstreamer-horizon-plugin-playback-v1"
                && report["full_epoch_verified"] == true
                && report["expected_first_slot"] == first
                && report["expected_last_slot"] == last
                && report["source"] == source
                && counters["epoch"] == epoch
                && counters["first_slot"] == first
                && counters["last_slot"] == last
                && counters["slots"] == 432000
                && counters["worker_count"] == threads,
            "incomplete {kind} playback"
        );
    }
    ensure!(
        local["report"]["report"] == public["report"]["report"],
        "local and public plugin counts or digest differ"
    );
    Ok(
        json!({"epoch":epoch,"archive":archive_ref,"playback":acceptance,"archive_etag":tag,"fresh_remote_pair_check_required":true}),
    )
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [path, sha] = args.as_slice() else {
        anyhow::bail!("usage: publication_handoff PLAN.json SHA256");
    };
    let binding = Bound {
        path: path.into(),
        sha256: sha.to_str().context("invalid plan hash")?.into(),
    };
    let plan: Plan = serde_json::from_value(binding.read()?)?;
    println!("{}", verify(&plan)?);
    Ok(())
}
