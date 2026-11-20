//! Independently rebuild the epoch 261 index from the authenticated original and
//! native Firehose block ancestry, then compare every emitted row and manifest.
mod native_window;
use native_window::{Block, Result};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

const DIR: &str = "/var/lib/jetstreamer/horizon261-edge-source-readback-v136-v1";
const SRC: &str = "/var/lib/jetstreamer/horizon261-car-prefix-and-slot-ranges-v136-v1";
const PLAN: &str = "/var/lib/jetstreamer/horizon261-edge-source-v136-v1/edge-windows.json";
const PREFLIGHT: &str =
    "/var/lib/jetstreamer/horizon261-singleton-manifest-20261120-v1/preflight-261-singleton.json";
const P_SHA: &str = "56d9c4275ca57e738e4f12c65e2070bbb111832a799769110ae80ca779af78aa";
const RAW_SHA: &str = "c232bfe6831cdad7cb10e526ee4b79fcc5f64c6c7364538ab5affddd0200dad8";
const DOWNLOAD: &str = "451f1a5e18b4b76fefee5b339eb28d9baac99e55383115b375af2b37d5b0eab9";
const PREFLIGHT_SHA: &str = "54a868e938b03c7c7f1fffd24fdb0536ed35b6cc9413f5502f20ac3d039eed43";
const SEAL: &str = "081309fd9f0e4a4b03071c9215f3adeb7479a949caccaed8aaa075a59c85f795";
const SOURCE_SEAL: &str = "ece1f5a503a1d63273f593db51526dfde8f6cbc82d9f6e1a1f0a758d48330499";
const PLAN_SEAL: &str = "66297f44f2d73c45afa14046febd9ed8dc0a8ab885912830a4c3fcbf5c2d0a45";
const MANIFEST_SEAL: &str = "8c9f2818a68a91d4338fcad356cefe25c72596054dc10052f623a0be6698f823";
const PREFIX: &str = "3cf280d4b03ab3a16eaacb2e18089276b23f26679e00b866e37d9e3825050414";
const ROWS: usize = 432000;
const FIRST: u64 = 112752000;
const CAR: u64 = 468345828349;
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn file(path: &Path, sha: &str, max: u64) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_file() || m.len() > max || path.canonicalize()? != path {
        return Err("source path/size differs".into());
    }
    let bytes = fs::read(path)?;
    if digest(&bytes) != sha {
        return Err(format!("source digest differs: {}", path.display()).into());
    }
    Ok(bytes)
}
fn num(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64().ok_or_else(|| format!("invalid {k}").into())
}
fn offset(slot: u64) -> Result<usize> {
    let index = usize::try_from(slot.checked_sub(FIRST).ok_or("slot before epoch")?)?;
    if index >= ROWS {
        return Err("slot after epoch".into());
    }
    Ok(index * 12)
}
fn row(raw: &[u8], slot: u64) -> Result<(u64, u32)> {
    let i = offset(slot)?;
    Ok((
        u64::from_le_bytes(raw[i..i + 8].try_into()?),
        u32::from_le_bytes(raw[i + 8..i + 12].try_into()?),
    ))
}
fn chain(blocks: &[Block], left: u64, right: u64, raw: &[u8]) -> Result<BTreeMap<u64, usize>> {
    let mut child = blocks.len().checked_sub(1).ok_or("empty native window")?;
    for (block, label) in [(&blocks[0], left), (&blocks[child], right)] {
        let (start, len) = row(raw, label)?;
        if block.slot != label
            || block.start != start
            || block.end != start.checked_add(len.into()).ok_or("anchor overflow")?
        {
            return Err("native physical anchor differs from original row".into());
        }
    }
    let mut chosen = BTreeMap::new();
    loop {
        let b = &blocks[child];
        if !(left..=right).contains(&b.slot)
            || b.parent >= b.slot
            || chosen.insert(b.slot, child).is_some()
        {
            return Err("noncanonical native ancestry".into());
        }
        if child == 0 {
            return Ok(chosen);
        }
        let mut parents = blocks[..child]
            .iter()
            .enumerate()
            .filter(|(_, p)| p.slot == b.parent);
        child = parents.next().ok_or("missing native parent")?.0;
        if parents.next().is_some() {
            return Err("ambiguous native parent".into());
        }
    }
}
fn run(report_path: &Path) -> Result<Value> {
    let report_path = report_path.canonicalize()?;
    let report = fs::read(&report_path)?;
    let r: Value = serde_json::from_slice(&report)?;
    if r["schema"] != "horizon261-direct-car-repair-candidate-v1"
        || r["epoch"] != 261
        || r["source_sha256"] != RAW_SHA
        || r["download_plan_sha256"] != P_SHA
        || r["download_sha256"] != DOWNLOAD
        || r["windows_seal_sha256"] != SEAL
        || r["singleton_manifest_sha256"] != PREFLIGHT_SHA
        || r["source_seal_sha256"] != SOURCE_SEAL
        || r["plan_seal_sha256"] != PLAN_SEAL
        || r["singleton_manifest_seal_sha256"] != MANIFEST_SEAL
        || r["all_windows_verified"] != true
        || [
            "replay_launch_authorized",
            "admission_authorized",
            "publication_authorized",
            "canonical_remote_objects_changed",
        ]
        .iter()
        .any(|&k| r[k] != false)
    {
        return Err("repair source identity".into());
    }
    for (member, sha) in [
        (Path::new(SRC), SOURCE_SEAL),
        (Path::new(PLAN).parent().unwrap(), PLAN_SEAL),
        (Path::new(PREFLIGHT).parent().unwrap(), MANIFEST_SEAL),
    ] {
        file(&member.join("deployment-seal-receipt.json"), sha, 16384)?;
    }
    let m: Value = serde_json::from_slice(&file(Path::new(PREFLIGHT), PREFLIGHT_SHA, 16_384)?)?;
    if r["singleton"]["manifest_fingerprint"] != m["manifest_fingerprint"]
        || r["singleton"]["runtime"] != m["manifest"]["epochs"][0]["runtime"]
        || r["singleton"]["snapshot_bodies_checked"] != false
        || r["singleton"]["bootstrap"] != m["manifest"]["epochs"][0]["bootstrap"]
        || r["singleton"]["final_checkpoint"]
            != m["manifest"]["verification_cohorts"][0]["root_checkpoints"][0]
    {
        return Err("singleton preflight report differs".into());
    }
    let ix = report_path.with_file_name("epoch-261-slot-ranges.candidate.raw");
    let index = file(
        &ix,
        r["candidate_sha256"].as_str().ok_or("candidate SHA")?,
        (ROWS * 12) as u64,
    )?;
    let mut expected = file(
        &Path::new(SRC).join("epoch-261-slot-ranges.raw"),
        RAW_SHA,
        (ROWS * 12) as u64,
    )?;
    if index.len() != ROWS * 12 || expected.len() != index.len() {
        return Err("incomplete index".into());
    }
    let om = file(
        &report_path.with_file_name("slot-ranges-override.json"),
        r["override_manifest_sha256"]
            .as_str()
            .ok_or("override digest")?,
        16_384,
    )?;
    let override_json: Value = serde_json::from_slice(&om)?;
    if override_json
        != json!({"schema":"jetstreamer-local-slot-ranges-overrides-v1","entries":[{"epoch":261,"path":ix,"sha256":digest(&index)}]})
    {
        return Err("override manifest differs from emitted candidate".into());
    }
    let plans: Vec<Value> = serde_json::from_slice(&file(Path::new(PLAN), P_SHA, 16_384)?)?;
    let dir = Path::new(DIR);
    file(&dir.join("deployment-seal-receipt.json"), SEAL, 16_384)?;
    let download: Value =
        serde_json::from_slice(&file(&dir.join("download.json"), DOWNLOAD, 16_384)?)?;
    let resources = download["resources"].as_array().ok_or("resource list")?;
    let edges = r["edges"].as_array().ok_or("edge list")?;
    if plans.len() != 16
        || edges.len() != 16
        || resources.len() != 18
        || download["plan_sha256"] != P_SHA
    {
        return Err("incomplete capture coverage".into());
    }
    let prefix = file(&Path::new(SRC).join("epoch-261.car.prefix"), PREFIX, 4096)?;
    for (n, resource) in [
        ("prefix-before", &resources[0]),
        ("prefix-after", &resources[17]),
    ] {
        if resource["name"] != n
            || resource["sha256"] != PREFIX
            || file(&dir.join(format!("{n}.car")), PREFIX, 4096)? != prefix
        {
            return Err("CAR prefix brackets disagree".into());
        }
    }
    let mut summary = Vec::new();
    let mut total_blocks = 0;
    let mut total_sections = 0;
    let mut previous_right = None;
    for ((p, e), w) in plans.iter().zip(edges).zip(&resources[1..17]) {
        let (edge, left, right, start, end) = (
            num(p, "edge")?,
            num(p, "left")?,
            num(p, "right")?,
            num(p, "start")?,
            num(p, "end")?,
        );
        if previous_right.is_some_and(|x| x >= left)
            || e["edge"] != edge
            || e["left_anchor"] != left
            || e["right_anchor"] != right
            || w["name"] != edge.to_string()
            || w["status"] != 206
            || w["url"] != "https://files.old-faithful.net/261/epoch-261.car"
            || w["content_range"] != format!("bytes {start}-{}/{CAR}", end - 1)
            || w["bytes"] != end - start
            || w["sha256"] != e["capture_sha256"]
        {
            return Err("window capture or scope mismatch".into());
        }
        previous_right = Some(right);
        let body = file(
            &dir.join(format!("{edge}.car")),
            w["sha256"].as_str().ok_or("window digest")?,
            end - start,
        )?;
        if body.len() as u64 != end - start {
            return Err("incomplete sealed window".into());
        }
        let (blocks, sections) = native_window::decode(&prefix, &body, start)?;
        let chosen = chain(&blocks, left, right, &expected)?;
        let declared = e["blocks"].as_array().ok_or("block list")?;
        if blocks.len() != declared.len() {
            return Err("unexpected number of native blocks".into());
        }
        for (i, (b, d)) in blocks.iter().zip(declared).enumerate() {
            if d != &json!({"slot":b.slot,"parent":b.parent,"start":b.start,"end":b.end,"block_cid_hex":b.cid,"on_anchor_chain":chosen.get(&b.slot)==Some(&i)})
            {
                return Err("native terminal CID, parent, range or ancestry differs".into());
            }
        }
        let mut changes = Vec::new();
        for slot in left..=right {
            let before = row(&expected, slot)?;
            let after = if let Some(i) = chosen.get(&slot) {
                let b = &blocks[*i];
                (b.start, u32::try_from(b.end - b.start)?)
            } else {
                (0, 0)
            };
            if before != after {
                let i = offset(slot)?;
                expected[i..i + 8].copy_from_slice(&after.0.to_le_bytes());
                expected[i + 8..i + 12].copy_from_slice(&after.1.to_le_bytes());
                changes.push(json!({"slot":slot,"before":before,"after":after}));
            }
        }
        if e["changed_rows"] != json!(changes) {
            return Err("native changed rows disagree".into());
        }
        total_blocks += blocks.len();
        total_sections += sections;
        summary.push(json!({"edge":edge,"blocks":blocks.len(),"sections":sections,"left_anchor":left,"right_anchor":right,"capture_sha256":w["sha256"]}));
    }
    let mut physical = 59;
    let mut present = 0;
    for slot in FIRST..FIRST + ROWS as u64 {
        let (o, n) = row(&index, slot)?;
        if (o, n) != row(&expected, slot)? {
            return Err(format!("candidate differs from native reconstruction at {slot}").into());
        }
        if (o, n) == (0, 0) {
            continue;
        }
        if n == 0 || o != physical {
            return Err("noncontiguous native candidate".into());
        }
        physical = o.checked_add(n.into()).ok_or("candidate offset overflow")?;
        if physical > CAR {
            return Err("candidate exceeds CAR".into());
        }
        present += 1;
    }
    if r["rows_scanned"] != ROWS || r["candidate_present"] != present || r["candidate_gaps"] != 0 {
        return Err("full index summary mismatch".into());
    }
    Ok(
        json!({"schema":"horizon261-native-window-comparison-v1","candidate_sha256":digest(&index),"repair_report_sha256":digest(&report),"source_sha256":RAW_SHA,"singleton_manifest_sha256":PREFLIGHT_SHA,"override_manifest_sha256":digest(&om),"rows_scanned":ROWS,"present":present,"windows":summary,"total_sections":total_sections,"total_blocks":total_blocks,"all_cids_checked":true,"all_terminal_blocks_offsets_parents_cids_match":true,"all_candidate_rows_match":true,"replay_authorized":false,"publication_authorized":false}),
    )
}
fn main() -> Result<()> {
    let args: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    let [report] = args.as_slice() else {
        return Err("usage: epoch261-native-window-audit REPAIR_CANDIDATE_JSON".into());
    };
    println!("{}", serde_json::to_string_pretty(&run(report)?)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(slot: u64, parent: u64, start: u64) -> Block {
        Block {
            slot,
            parent,
            start,
            end: start + 10,
            cid: String::new(),
        }
    }

    #[test]
    fn anchors_and_unique_native_ancestry_bind_the_selected_rows() -> Result<()> {
        let mut raw = vec![0; 48];
        let mut b = [
            block(FIRST, FIRST - 1, 59),
            block(FIRST + 1, FIRST, 69),
            block(FIRST + 2, FIRST, 79),
            block(FIRST + 3, FIRST + 2, 89),
        ];
        for i in [0, 3] {
            raw[i * 12..i * 12 + 8].copy_from_slice(&b[i].start.to_le_bytes());
            raw[i * 12 + 8..i * 12 + 12].copy_from_slice(&10u32.to_le_bytes());
        }
        let run = |b: &[Block]| chain(b, FIRST, FIRST + 3, &raw);
        assert_eq!(
            run(&b)?,
            BTreeMap::from([(FIRST, 0), (FIRST + 2, 2), (FIRST + 3, 3)])
        );
        b[1].slot = FIRST + 2;
        assert!(run(&b).is_err());
        b[1].slot = FIRST + 1;
        b[3].parent = FIRST - 1;
        assert!(run(&b).is_err());
        b[3].parent = FIRST + 2;
        b[0].start += 1;
        assert!(run(&b).is_err());
        b[0].start -= 1;
        b[3].end -= 1;
        assert!(run(&b).is_err());
        assert!(offset(FIRST - 1).is_err());
        assert!(offset(FIRST + ROWS as u64).is_err());
        Ok(())
    }
}
