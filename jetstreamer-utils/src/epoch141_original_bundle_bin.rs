//! Bounded complete-census original-entry input preparation; no runtime launch.
#[allow(dead_code)]
mod epoch141_acquired_input;
#[allow(dead_code)]
#[path = "epoch141_ledger_common.rs"]
mod evidence;

use anyhow::{Context, Result, ensure};
use epoch141_acquired_input::{Bound, decode};
use jetstreamer_utils::{
    horizon_legacy_bundle::{
        ACQUISITION_SHA256, GAP_CENSUS_SHA256, MAX_DATA_BYTES, OriginalBundleIndex,
        OriginalSlotIndex, POH_COMPLETION_SHA256,
    },
    horizon_legacy_entry::decode_v1_4_25_padded_entries,
    horizon_legacy_shred::{assemble_v1_4_25_padded_batches, decode_v1_4_25_complete_slot_meta},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    time::Instant,
};

const COMPLETE: &str =
    "/var/lib/jetstreamer/horizon-epoch141-census-poh-diagnostic-20261022-v2/completion.json";
const TARGET_ROOT: &str =
    "/var/lib/jetstreamer/horizon-epoch141-census-poh-diagnostic-20261022-v2/targets";
const RAW_ROOT: &str = "/home/sol/.jetstreamer-private/epoch141-native-acquisition-all-20261022-v2/results/target-acquisitions";
const MIN_FREE: u64 = 4_397_099_539_910;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    output_directory: PathBuf,
}

fn read(b: &Bound, limit: u64) -> Result<Value> {
    Ok(serde_json::from_slice(&evidence::bound_file(
        &b.path, &b.sha256, limit, false,
    )?)?)
}
fn prior(v: &Value) -> Result<Vec<Bound>> {
    ensure!(
        v["schema"] == "jetstreamer-epoch141-census-poh-diagnostic-v1"
            && v["epoch"] == 141
            && v["attempted_targets"] == 18283
            && v["passed_targets"] == 18283
            && v["failed_targets"] == 0
            && v["full_census_poh_chains_verified"] == true
            && v["verified_boundary_count"] == 84597
            && v["acquisition"]["sha256"] == ACQUISITION_SHA256,
        "prior full-census PoH proof differs"
    );
    for key in [
        "canonical_ancestry_proven",
        "source_completeness_proven",
        "live_state_proven",
        "runtime_boundary_input_authorized",
        "runtime_promotion_authorized",
        "replay_launch_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(v[key] == false, "prior proof gained authority:{key}");
    }
    let targets: Vec<Bound> = serde_json::from_value(v["target_receipts"].clone())?;
    ensure!(targets.len() == 18283, "incomplete target receipt census");
    Ok(targets)
}
fn guard(root: &Path, start: Instant) -> Result<()> {
    ensure!(
        start.elapsed().as_secs() < 7200,
        "original bundle build deadline exceeded"
    );
    let name = std::ffi::CString::new(root.as_os_str().as_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(name.as_ptr(), stat.as_mut_ptr()) } == 0,
        "bundle filesystem unreadable"
    );
    let stat = unsafe { stat.assume_init() };
    let free = (stat.f_bavail as u128) * (stat.f_frsize as u128);
    ensure!(
        free >= u128::from(MIN_FREE),
        "bundle protected free-space gate failed"
    );
    Ok(())
}
fn hash(v: &Value) -> Result<[u8; 32]> {
    bs58::decode(v.as_str().context("anchor absent")?)
        .into_vec()
        .map_err(|e| anyhow::anyhow!("invalid anchor:{e}"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("anchor length differs"))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 6 && args[2] == "--plan-sha256" && args[4] == "--self-sha256",
        "usage: original-bundle PLAN --plan-sha256 HEX --self-sha256 HEX"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "requires privileged immutable evidence reader"
    );
    let executable = std::env::current_exe()?.canonicalize()?;
    evidence::bound_file(&executable, &args[5], 128 << 20, true)?;
    let p: Plan = serde_json::from_slice(&evidence::bound_file(
        Path::new(&args[1]),
        &args[3],
        65536,
        true,
    )?)?;
    ensure!(
        p.schema == "jetstreamer-epoch141-original-bundle-build-plan-v1"
            && p.output_directory.parent() == Some(Path::new("/home/sol/.jetstreamer-private"))
            && p.output_directory
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("epoch141-original-bundle-")
                    && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
        "wrong private output scope"
    );
    let m = fs::symlink_metadata(&p.output_directory)?;
    ensure!(
        m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o077 == 0
            && p.output_directory.canonicalize()? == p.output_directory
            && fs::read_dir(&p.output_directory)?.next().is_none(),
        "output must be empty root-private directory"
    );
    let start = Instant::now();
    guard(&p.output_directory, start)?;
    let iid = std::env::var("INVOCATION_ID")?;
    ensure!(
        iid.len() == 32 && evidence::is_sha(&format!("{iid}{iid}")),
        "invalid persistent invocation"
    );
    let complete = Bound {
        path: COMPLETE.into(),
        sha256: POH_COMPLETION_SHA256.into(),
    };
    let targets = prior(&read(&complete, 8 << 20)?)?;
    let path = p.output_directory.join("original-entries.data");
    let mut data = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    evidence::write_receipt(
        &p.output_directory.join("intent.json"),
        &json!({"schema":"jetstreamer-epoch141-original-bundle-intent-v1","invocation_id":iid,"plan_sha256":args[3],"self_sha256":args[5],"maximum_data_bytes":MAX_DATA_BYTES,"minimum_free_bytes":MIN_FREE,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    )?;
    let mut index = OriginalBundleIndex {
        schema: "jetstreamer-epoch141-original-entry-bundle-v1".into(),
        acquisition_sha256: ACQUISITION_SHA256.into(),
        poh_completion_sha256: POH_COMPLETION_SHA256.into(),
        gap_census_sha256: GAP_CENSUS_SHA256.into(),
        scope_first_slot: 60911751,
        scope_last_slot: 61328765,
        ticks_per_slot: 64,
        hashes_per_tick: 12500,
        data_bytes: 0,
        data_sha256: String::new(),
        slots: Vec::with_capacity(targets.len()),
    };
    let mut hasher = Sha256::new();
    for (number, bound) in targets.iter().enumerate() {
        guard(&p.output_directory, start)?;
        let target = read(bound, 1 << 20)?;
        let slot = target["slot"].as_u64().context("target slot absent")?;
        let parent = target["parent_slot"]
            .as_u64()
            .context("target parent absent")?;
        ensure!(
            bound.path == Path::new(TARGET_ROOT).join(format!("slot-{slot}.json"))
                && target["diagnostic_passed"] == true
                && target["schema"] == "jetstreamer-epoch141-census-target-poh-diagnostic-v1"
                && target["finalized_metadata"]["slot"] == slot
                && target["finalized_metadata"]["parent_slot"] == parent,
            "target lineage differs"
        );
        let raw_bound: Bound = serde_json::from_value(target["raw_target"].clone())?;
        ensure!(
            raw_bound.path == Path::new(RAW_ROOT).join(format!("slot-{slot}.json")),
            "raw target path differs"
        );
        let raw = read(&raw_bound, 224 << 20)?;
        ensure!(
            raw["slot"] == slot
                && raw["parent_slot"] == parent
                && raw["outcome"]["status"] == "raw-acquired",
            "raw target scope differs"
        );
        let n = raw["outcome"]["summary"]["expected_data_shreds"]
            .as_u64()
            .context("missing shred count")?;
        ensure!((1..=65528).contains(&n), "shred count exceeds envelope");
        let first = decode(&raw["outcome"]["first_metadata"], 1)?;
        let records = decode(&raw["outcome"]["records"], n as usize + 8)?;
        let meta = decode_v1_4_25_complete_slot_meta(
            first[0].borrowed().value.context("metadata absent")?,
            slot,
            parent,
        )
        .map_err(anyhow::Error::msg)?;
        let shreds = records[8..]
            .iter()
            .map(|r| r.borrowed().value.context("shred absent"))
            .collect::<Result<Vec<_>>>()?;
        let batches = assemble_v1_4_25_padded_batches(slot, parent, meta.last_index, &shreds)
            .map_err(anyhow::Error::msg)?;
        ensure!(
            batches.iter().map(|b| b.last_index).collect::<Vec<_>>() == meta.completed_data_indexes,
            "batch endpoints differ"
        );
        let parent_hash = hash(&target["finalized_metadata"]["previous_poh_hash"])?;
        let final_hash = hash(&target["finalized_metadata"]["final_poh_hash"])?;
        let mut ticks = 0u64;
        let mut last = None;
        let mut record_hasher = Sha256::new();
        let batch_count = u32::try_from(batches.len())?;
        let count_bytes = batch_count.to_le_bytes();
        record_hasher.update(count_bytes);
        hasher.update(count_bytes);
        data.write_all(&count_bytes)?;
        let mut length = 4u64;
        for batch in &batches {
            let decoded =
                decode_v1_4_25_padded_entries(&batch.bytes).map_err(anyhow::Error::msg)?;
            ticks += decoded
                .entries
                .iter()
                .filter(|e| e.transaction_count == 0)
                .count() as u64;
            last = decoded.entries.last().map(|e| e.hash);
            let size = u32::try_from(batch.bytes.len())?;
            length = length
                .checked_add(u64::from(size) + 4)
                .context("slot length overflow")?;
            ensure!(
                length <= 64 << 20
                    && index
                        .data_bytes
                        .checked_add(length)
                        .is_some_and(|n| n <= MAX_DATA_BYTES),
                "bundle slot/data byte bound exceeded"
            );
            let size_bytes = size.to_le_bytes();
            record_hasher.update(size_bytes);
            hasher.update(size_bytes);
            data.write_all(&size_bytes)?;
            record_hasher.update(&batch.bytes);
            hasher.update(&batch.bytes);
            data.write_all(&batch.bytes)?;
        }
        let span = slot.checked_sub(parent).context("invalid parent")?;
        ensure!(
            ticks == span * 64
                && last == Some(final_hash)
                && target["diagnostic"]["executed_hashes"] == span * 64 * 12500
                && target["diagnostic"]["boundaries"]
                    .as_array()
                    .is_some_and(|v| v.len() as u64 == span),
            "original chain differs from prior bound proof"
        );
        index.slots.push(OriginalSlotIndex {
            slot,
            parent_slot: parent,
            parent_hash_hex: hex(&parent_hash),
            final_hash_hex: hex(&final_hash),
            offset: index.data_bytes,
            length,
            sha256: format!("{:x}", record_hasher.finalize()),
            batch_count,
        });
        index.data_bytes += length;
        if number == 0 || (number + 1).is_multiple_of(1000) {
            eprintln!(
                "original-bundle prepared={} total={} bytes={}",
                number + 1,
                targets.len(),
                index.data_bytes
            );
        }
    }
    data.sync_all()?;
    File::open(&p.output_directory)?.sync_all()?;
    index.data_sha256 = format!("{:x}", hasher.finalize());
    index.validate().map_err(anyhow::Error::msg)?;
    let mut input = File::open(&path)?;
    let mut hash = Sha256::new();
    let mut chunk = vec![0; 1 << 20];
    let mut read_bytes = 0u64;
    loop {
        guard(&p.output_directory, start)?;
        let n = input.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        read_bytes += n as u64;
        ensure!(read_bytes <= index.data_bytes, "data grew during reread");
        hash.update(&chunk[..n]);
    }
    ensure!(
        read_bytes == index.data_bytes && format!("{:x}", hash.finalize()) == index.data_sha256,
        "complete independent data reread differs"
    );
    prior(&read(&complete, 8 << 20)?)?;
    evidence::bound_file(&executable, &args[5], 128 << 20, true)?;
    let value = serde_json::to_value(&index)?;
    let serialized = serde_json::to_vec_pretty(&value)?;
    ensure!(
        serialized.len() < 16 << 20,
        "bundle index exceeds input bound"
    );
    evidence::write_receipt(&p.output_directory.join("index.json"), &value)?;
    evidence::write_receipt(
        &p.output_directory.join("completion.json"),
        &json!({"schema":"jetstreamer-epoch141-original-bundle-preparation-v1","invocation_id":iid,"self_sha256":args[5],"plan_sha256":args[3],"poh_completion_sha256":POH_COMPLETION_SHA256,"data_bytes":index.data_bytes,"data_sha256":index.data_sha256,"targets":index.slots.len(),"data_independently_reread":true,"elapsed_seconds":start.elapsed().as_secs(),"source_transaction_equivalence_proven":false,"source_completeness_proven":false,"runtime_promotion_authorized":false,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("original bundle preparation failed closed:{e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn incomplete_or_authorizing_prior_cannot_prepare_input() {
        assert!(prior(&json!({})).is_err());
        assert!(prior(&json!({"schema":"jetstreamer-epoch141-census-poh-diagnostic-v1","epoch":141,"attempted_targets":18283,"passed_targets":18283,"failed_targets":1,"full_census_poh_chains_verified":true,"verified_boundary_count":84597,"acquisition":{"sha256":ACQUISITION_SHA256}})).is_err());
        assert_eq!(hex(&[0xab; 32]), "ab".repeat(32));
    }
}
