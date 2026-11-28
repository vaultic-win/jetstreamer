//! Reconstruct the exact epoch 262 raw ranges from the sealed CAR windows.
use super::{hash, packet_bounded, read_checked, repair, transport};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs::File, path::Path};

const DIR: &str = "/var/lib/jetstreamer/horizon262-full-source-v1";
const SEAL: &str = "ae68252816bc3dc55e10fe7931cc0309934db6380f76f925efdcdab96d5ad096";
const SOURCE: &str = "epoch-262-slot-ranges.raw";
const CANDIDATE: &str = "epoch-262-slot-ranges.candidate.raw";
const RAW_SHA: &str = "e2e0b1f4c4fae981c815dd6e405753f1a20d2a28f0b8992b94f5b2b65d8aeb19";
const CAR_ROOT: &str = "bafyreih6fqjpt7o2tizpzgctxr6hmab4n7of2rjjdwrj2mfg4pg3nt4bma";
const SLOT_INDEX: &str = "epoch-262-bafyreih6fqjpt7o2tizpzgctxr6hmab4n7of2rjjdwrj2mfg4pg3nt4bma-mainnet-slot-to-cid.index";
const DOWNLOAD_SHA: &str = "ec437e8ba3e49409fb546ff664ed76797cba30987e535b1eb97c5cf66ab764d1";
const ROWS: u64 = 432_000;
const FIRST: u64 = 262 * ROWS;
const PRESENT: u64 = 414_396;
const PROFILE: repair::Source<'static> = repair::Source {
    epoch: 262,
    car_size: 467_291_726_435,
    window_bytes: 72_604_366,
    max_window: 5_708_335,
    plan_sha: "9bbe9d8eeeea50c285abb3ebfcebb87691d6dc6c9e6e4e19d01a30c9e9279833",
    prefix_sha: "3276204dcade02fc2c43e4ae4ca8cee5d6bbf18fd2fab841a17a476c4393377e",
};

pub(super) fn run(output: &Path) -> Result<()> {
    let dir = Path::new(DIR);
    let raw = read_checked(dir, SOURCE, ROWS * 12, RAW_SHA)?;
    let (present, gaps) = repair::scan_candidate(&PROFILE, &raw)?;
    ensure!(
        present == PRESENT && gaps == 18,
        "original 262 range census changed"
    );
    let mut edges = Vec::new();
    let mut previous = None;
    for slot in FIRST..FIRST + ROWS {
        let (offset, bytes) = repair::record(&raw, slot, FIRST);
        if bytes == 0 {
            continue;
        }
        if let Some((prior_slot, prior_end)) = previous {
            if prior_end != offset {
                edges.push((prior_slot, slot, prior_end, offset));
            }
        }
        previous = Some((slot, offset + u64::from(bytes)));
    }
    ensure!(edges.len() == 18, "original 262 interior gaps changed");
    let mut members: BTreeSet<String> = [
        SOURCE,
        SLOT_INDEX,
        "epoch-262.car.prefix",
        "car.headers",
        "ranges.headers",
        "slot-index.headers",
        "edge-windows.json",
        "fetch-windows.py",
        "download.json",
        "prefix-before.car",
        "prefix-after.car",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    members.extend(edges.iter().map(|(_, slot, _, _)| format!("{slot}.car")));
    let mut source = packet_bounded(DIR, SEAL, &members, |name| match name {
        SOURCE => ROWS * 12,
        SLOT_INDEX => 16_162_937,
        name if name.ends_with(".car") => PROFILE.max_window,
        _ => 16_384,
    })?;
    let mut candidate = source.remove(SOURCE).context("raw index missing")?;
    ensure!(candidate == raw, "raw index changed on reopen");
    let prefix = &source["epoch-262.car.prefix"];
    transport::car(prefix, CAR_ROOT)?;
    ensure!(
        hash(prefix) == PROFILE.prefix_sha,
        "CAR prefix digest changed"
    );
    let planned = repair::windows(&candidate, &source["edge-windows.json"], &edges, &PROFILE)?;
    let receipt = &source["download.json"];
    ensure!(hash(receipt) == DOWNLOAD_SHA, "download receipt changed");
    let receipt: Value = serde_json::from_slice(receipt)?;
    let reviews = repair::repair_windows(
        &PROFILE,
        &mut candidate,
        &planned,
        &receipt,
        |name, _, _| {
            source
                .remove(&format!("{name}.car"))
                .context("captured CAR body missing")
        },
    )?;
    let (present, gaps) = repair::scan_candidate(&PROFILE, &candidate)?;
    ensure!(
        gaps == 0 && present >= PRESENT,
        "candidate lost coverage or contains gaps"
    );
    let digest = hash(&candidate);
    let override_manifest = json!({"schema":"jetstreamer-local-slot-ranges-overrides-v1",
        "entries":[{"epoch":262,"path":output.join(CANDIDATE),"sha256":digest}]});
    let override_bytes = serde_json::to_vec_pretty(&override_manifest)?;
    let result = json!({"schema":"horizon262-direct-car-repair-candidate-v1","epoch":262,
        "source_sha256":RAW_SHA,"source_seal_sha256":SEAL,"car_root":CAR_ROOT,
        "download_plan_sha256":PROFILE.plan_sha,"download_sha256":DOWNLOAD_SHA,
        "original_present":PRESENT,"original_gaps":18,"rows_scanned":ROWS,
        "candidate_present":present,"candidate_gaps":gaps,"candidate_sha256":digest,
        "override_manifest_sha256":hash(&override_bytes),"edges":reviews,
        "all_windows_verified":true,"independent_native_comparison_pending":true,
        "replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false});
    repair::new_output(output)?;
    repair::write_new(output, CANDIDATE, &candidate)?;
    repair::write_new(output, "slot-ranges-override.json", &override_bytes)?;
    repair::write_new(
        output,
        "repair-candidate.json",
        &serde_json::to_vec_pretty(&result)?,
    )?;
    File::open(output)?.sync_all()?;
    File::open(output.parent().context("output parent missing")?)?.sync_all()?;
    Ok(())
}
