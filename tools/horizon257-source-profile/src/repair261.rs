//! Epoch 261 inputs are a complete raw index, two CAR prefixes, and sealed,
//! bracketed anomalous windows. No compact-index or full-CAR claim is made.
use super::{hash, manifest, packet, packet_bounded, repair, transport};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs::File, path::Path};

const SOURCE: &str = "/var/lib/jetstreamer/horizon261-car-prefix-and-slot-ranges-v136-v1";
const SOURCE_SEAL: &str = "ece1f5a503a1d63273f593db51526dfde8f6cbc82d9f6e1a1f0a758d48330499";
const PLAN_DIR: &str = "/var/lib/jetstreamer/horizon261-edge-source-v136-v1";
const PLAN_SEAL: &str = "66297f44f2d73c45afa14046febd9ed8dc0a8ab885912830a4c3fcbf5c2d0a45";
const WINDOWS: &str = "/var/lib/jetstreamer/horizon261-edge-source-readback-v136-v1";
const WINDOW_SEAL: &str = "081309fd9f0e4a4b03071c9215f3adeb7479a949caccaed8aaa075a59c85f795";
const DOWNLOAD_SHA: &str = "451f1a5e18b4b76fefee5b339eb28d9baac99e55383115b375af2b37d5b0eab9";
const MANIFEST: &str = "/var/lib/jetstreamer/horizon261-singleton-manifest-20261120-v1";
const MANIFEST_SEAL: &str = "8c9f2818a68a91d4338fcad356cefe25c72596054dc10052f623a0be6698f823";
const MANIFEST_SHA: &str = "54a868e938b03c7c7f1fffd24fdb0536ed35b6cc9413f5502f20ac3d039eed43";
const RAW: &str = "epoch-261-slot-ranges.raw";
const RAW_SHA: &str = "c232bfe6831cdad7cb10e526ee4b79fcc5f64c6c7364538ab5affddd0200dad8";
const PROFILE: repair::Source<'static> = repair::Source {
    epoch: 261,
    car_size: 468_345_828_349,
    window_bytes: 74_294_714,
    max_window: 6_101_028,
    plan_sha: "56d9c4275ca57e738e4f12c65e2070bbb111832a799769110ae80ca779af78aa",
    prefix_sha: "3cf280d4b03ab3a16eaacb2e18089276b23f26679e00b866e37d9e3825050414",
};
const ROWS: usize = 432_000;
const FIRST: u64 = 261 * ROWS as u64;
const CANDIDATE: &str = "epoch-261-slot-ranges.candidate.raw";

fn names(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}
fn edges(raw: &[u8], scan: &Value) -> Result<Vec<(u64, u64, u64, u64)>> {
    ensure!(raw.len() == 12 * ROWS, "incomplete original raw index");
    let mut prev = None;
    let mut out = Vec::new();
    let mut present = 0usize;
    for slot in FIRST..FIRST + ROWS as u64 {
        let (o, n) = repair::record(raw, slot, FIRST);
        if n == 0 {
            ensure!(o == 0, "partially absent raw row");
            continue;
        }
        let end = o.checked_add(u64::from(n)).context("raw range overflow")?;
        ensure!(o >= 59 && end <= PROFILE.car_size, "raw range outside CAR");
        if let Some((old, tail)) = prev {
            if o != tail {
                out.push((old, slot, tail, o));
            }
        } else {
            ensure!(o == 59, "first physical row lacks CAR header anchor");
        }
        prev = Some((slot, end));
        present += 1;
    }
    let evidence = scan["discontinuities"]
        .as_array()
        .context("sealed discontinuities")?;
    ensure!(
        present == 409850
            && out.len() == 16
            && evidence.len() == out.len()
            && out.iter().filter(|(_, _, end, off)| off < end).count() == 1,
        "original 261 row or edge coverage changed"
    );
    for (r, (left, right, end, off)) in evidence.iter().zip(&out) {
        ensure!(
            r["preceding_slot"] == *left
                && r["next_slot"] == *right
                && r["preceding_end"] == *end
                && r["next_offset"] == *off,
            "physical edge differs from sealed structural census"
        );
    }
    Ok(out)
}
pub(super) fn run(out: &Path) -> Result<()> {
    let source = packet_bounded(
        SOURCE,
        SOURCE_SEAL,
        &names(&[
            RAW,
            "epoch-261-slot-ranges.raw.headers",
            "epoch-260.car.prefix",
            "epoch-260.car.prefix.headers",
            "epoch-261.car.prefix",
            "epoch-261.car.prefix.headers",
            "result.json",
            "booking.json",
        ]),
        |n| if n == RAW { 5_184_000 } else { 16_384 },
    )?;
    let mut raw = source[RAW].clone();
    ensure!(hash(&raw) == RAW_SHA, "original raw index changed");
    let fetch: Value = serde_json::from_slice(&source["result.json"])?;
    for (e, size, cid) in [
        (
            260,
            443_668_996_773,
            "bafyreiabyb2rm444cdvvhwykyuwsaliebbnnz5o2rabpzir425gdy6cw6q",
        ),
        (
            261,
            PROFILE.car_size,
            "bafyreib6vznz6e6jrjjdh3clmdfpuxauj4okmjwgldevc2svggdksch4fq",
        ),
    ] {
        let name = format!("epoch-{e}.car.prefix");
        transport::car(&source[&name], cid)?;
        transport::headers(
            &source[&format!("{name}.headers")],
            size,
            false,
            "application/vnd.curl.car",
        )?;
        let r = &fetch["source"][&name];
        ensure!(
            r["url"] == format!("https://files.old-faithful.net/{e}/epoch-{e}.car")
                && r["object_length"] == size
                && r["body"]["sha256"] == hash(&source[&name]),
            "CAR prefix binding"
        );
    }
    transport::headers(
        &source["epoch-261-slot-ranges.raw.headers"],
        5_184_000,
        true,
        "binary/octet-stream",
    )?;
    ensure!(
        fetch["source"][RAW]["url"]
            == "https://files.old-faithful.net/261/epoch-261-slot-ranges.raw"
            && fetch["source"][RAW]["body"]["sha256"] == RAW_SHA
            && hash(&source["epoch-261.car.prefix"]) == PROFILE.prefix_sha,
        "source response binding"
    );
    let m = packet(
        MANIFEST,
        MANIFEST_SEAL,
        &names(&["preflight-261-singleton.json"]),
    )?;
    let mb = &m["preflight-261-singleton.json"];
    ensure!(hash(mb) == MANIFEST_SHA, "preflight manifest digest");
    let singleton = manifest::validate261(&serde_json::from_slice(mb)?)?;
    let plan = packet(
        PLAN_DIR,
        PLAN_SEAL,
        &names(&[
            "edge-windows.json",
            "structural-scan.json",
            "fetch-windows.py",
        ]),
    )?;
    let scan = serde_json::from_slice(&plan["structural-scan.json"])?;
    let original = edges(&raw, &scan)?;
    let planned = repair::windows(&raw, &plan["edge-windows.json"], &original, &PROFILE)?;
    let mut members = names(&[
        "booking.json",
        "download.json",
        "prefix-before.car",
        "prefix-after.car",
    ]);
    members.extend(original.iter().map(|(_, slot, _, _)| format!("{slot}.car")));
    let mut captured = packet_bounded(WINDOWS, WINDOW_SEAL, &members, |n| {
        if n.ends_with(".car") {
            PROFILE.max_window
        } else {
            16_384
        }
    })?;
    ensure!(
        hash(&captured["download.json"]) == DOWNLOAD_SHA,
        "download binding"
    );
    let download = serde_json::from_slice(&captured["download.json"])?;
    let reviews = repair::repair_windows(&PROFILE, &mut raw, &planned, &download, |n, _, _| {
        captured
            .remove(&format!("{n}.car"))
            .context("missing original captured body")
    })?;
    let (present, gaps) = repair::scan_candidate(&PROFILE, &raw)?;
    ensure!(
        gaps == 0 && present >= 409850,
        "candidate still has gaps or loses slot coverage"
    );
    repair::new_output(out)?;
    let digest = hash(&raw);
    let index_manifest = json!({"schema":"jetstreamer-local-slot-ranges-overrides-v1","entries":[{"epoch":261,"path":out.join(CANDIDATE),"sha256":digest}]});
    let manifest_bytes = serde_json::to_vec_pretty(&index_manifest)?;
    let report = json!({"schema":"horizon261-direct-car-repair-candidate-v1","epoch":261,"source_sha256":RAW_SHA,"source_seal_sha256":SOURCE_SEAL,"candidate_sha256":digest,"windows_seal_sha256":WINDOW_SEAL,"download_sha256":DOWNLOAD_SHA,"download_plan_sha256":PROFILE.plan_sha,"plan_seal_sha256":PLAN_SEAL,"singleton_manifest_sha256":MANIFEST_SHA,"singleton_manifest_seal_sha256":MANIFEST_SEAL,"singleton":singleton,"override_manifest_sha256":hash(&manifest_bytes),"rows_scanned":ROWS,"candidate_present":present,"candidate_gaps":gaps,"all_windows_verified":true,"edges":reviews,"replay_launch_authorized":false,"admission_authorized":false,"publication_authorized":false,"canonical_remote_objects_changed":false});
    repair::write_new(out, CANDIDATE, &raw)?;
    repair::write_new(out, "slot-ranges-override.json", &manifest_bytes)?;
    repair::write_new(
        out,
        "repair-candidate.json",
        &serde_json::to_vec_pretty(&report)?,
    )?;
    File::open(out)?.sync_all()?;
    File::open(out.parent().context("output parent")?)?.sync_all()?;
    Ok(())
}
