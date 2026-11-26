//! Cross-check the repaired epoch 262 ranges with the production Firehose decoder.
#[path = "../../jetstreamer-firehose/src/bin/native_window/mod.rs"]
mod native_window;

use native_window::Result;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};

const SOURCE: &str = "/var/lib/jetstreamer/horizon262-full-source-v1";
const FIRST: u64 = 113_184_000;
const ROWS: u64 = 432_000;
const RAW_SHA: &str = "e2e0b1f4c4fae981c815dd6e405753f1a20d2a28f0b8992b94f5b2b65d8aeb19";
const PREFIX_SHA: &str = "3276204dcade02fc2c43e4ae4ca8cee5d6bbf18fd2fab841a17a476c4393377e";
const PLAN_SHA: &str = "9bbe9d8eeeea50c285abb3ebfcebb87691d6dc6c9e6e4e19d01a30c9e9279833";
const DOWNLOAD_SHA: &str = "ec437e8ba3e49409fb546ff664ed76797cba30987e535b1eb97c5cf66ab764d1";

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn fetch(path: &Path, max: u64, sha: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > max || path.canonicalize()? != path {
        return Err(format!("invalid local source {}", path.display()).into());
    }
    let data = fs::read(path)?;
    if data.len() as u64 != metadata.len() || digest(&data) != sha {
        return Err(format!("SHA-256 mismatch at {}", path.display()).into());
    }
    Ok(data)
}

fn num(value: &Value, key: &str) -> Result<u64> {
    value[key]
        .as_u64()
        .ok_or_else(|| format!("missing {key}").into())
}

fn start(slot: u64) -> Result<usize> {
    if !(FIRST..FIRST + ROWS).contains(&slot) {
        return Err("slot outside epoch 262".into());
    }
    Ok((slot - FIRST) as usize * 12)
}

fn row(raw: &[u8], slot: u64) -> Result<(u64, u32)> {
    let i = start(slot)?;
    Ok((
        u64::from_le_bytes(raw[i..i + 8].try_into()?),
        u32::from_le_bytes(raw[i + 8..i + 12].try_into()?),
    ))
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 1 {
        return Err("usage: epoch262-native-audit CANDIDATE_DIRECTORY".into());
    }
    let candidate_dir = Path::new(&args[0]).canonicalize()?;
    let dir = Path::new(SOURCE);
    let report: Value =
        serde_json::from_slice(&fs::read(candidate_dir.join("repair-candidate.json"))?)?;
    if report["schema"] != "horizon262-direct-car-repair-candidate-v1"
        || report["source_sha256"] != RAW_SHA
        || report["download_sha256"] != DOWNLOAD_SHA
        || report["download_plan_sha256"] != PLAN_SHA
        || report["rows_scanned"] != ROWS
        || report["candidate_gaps"] != 0
    {
        return Err("candidate source and shape differ".into());
    }
    let expected_sha = report["candidate_sha256"]
        .as_str()
        .ok_or("candidate digest")?;
    let index = fetch(
        &candidate_dir.join("epoch-262-slot-ranges.candidate.raw"),
        ROWS * 12,
        expected_sha,
    )?;
    let mut expected = fetch(&dir.join("epoch-262-slot-ranges.raw"), ROWS * 12, RAW_SHA)?;
    if expected.len() as u64 != ROWS * 12 || expected.len() != index.len() {
        return Err("short slot range table".into());
    }
    let prefix = fetch(&dir.join("epoch-262.car.prefix"), 4096, PREFIX_SHA)?;
    let plan: Vec<Value> =
        serde_json::from_slice(&fetch(&dir.join("edge-windows.json"), 16384, PLAN_SHA)?)?;
    let download: Value =
        serde_json::from_slice(&fetch(&dir.join("download.json"), 16384, DOWNLOAD_SHA)?)?;
    let responses = download["resources"].as_array().ok_or("response records")?;
    let reports = report["edges"].as_array().ok_or("edge reports")?;
    if plan.len() != 18 || reports.len() != 18 || responses.len() != 20 {
        return Err("incomplete window roster".into());
    }
    let mut total_sections = 0;
    let mut total_blocks = 0;
    let mut total_patches = 0;
    for ((window, capture), reported) in plan.iter().zip(&responses[1..19]).zip(reports) {
        let edge = num(window, "edge")?;
        let left = num(window, "left")?;
        let right = num(window, "right")?;
        let offset = num(window, "start")?;
        let end = num(window, "end")?;
        let bytes = end.checked_sub(offset).ok_or("window endpoints")?;
        let sha = capture["sha256"].as_str().ok_or("capture digest")?;
        if capture["name"] != edge.to_string()
            || reported["capture_sha256"] != sha
            || bytes > 5_708_335
        {
            return Err("window capture binding differs".into());
        }
        let body = fetch(&dir.join(format!("{edge}.car")), bytes, sha)?;
        if body.len() as u64 != bytes {
            return Err("short CAR body".into());
        }
        let (blocks, sections) = native_window::decode(&prefix, &body, offset)?;
        let left_block = blocks.first().ok_or("missing left CAR anchor")?;
        let right_block = blocks.last().ok_or("missing right CAR anchor")?;
        for (block, anchor) in [(left_block, left), (right_block, right)] {
            let (start, len) = row(&expected, anchor)?;
            if block.slot != anchor || block.start != start || block.end != start + u64::from(len) {
                return Err("native anchor differs from upstream offset".into());
            }
        }
        let mut chain = BTreeMap::new();
        let mut child = blocks.len() - 1;
        loop {
            let b = &blocks[child];
            if !(left..=right).contains(&b.slot)
                || b.parent >= b.slot
                || chain.insert(b.slot, child).is_some()
            {
                return Err("invalid native block ancestry".into());
            }
            if child == 0 {
                break;
            }
            let mut parents = blocks[..child]
                .iter()
                .enumerate()
                .filter(|(_, p)| p.slot == b.parent);
            child = parents.next().ok_or("native parent missing")?.0;
            if parents.next().is_some() {
                return Err("native parent ambiguous".into());
            }
        }
        let physical: Vec<_> = blocks.iter().enumerate().map(|(i, b)| json!({
            "slot":b.slot,"parent":b.parent,"start":b.start,"end":b.end,"block_cid_hex":b.cid,
            "on_anchor_chain":chain.get(&b.slot)==Some(&i),
        })).collect();
        let mut patches = Vec::new();
        for slot in left..=right {
            let before = row(&expected, slot)?;
            let after = if let Some(i) = chain.get(&slot) {
                let b = &blocks[*i];
                (b.start, u32::try_from(b.end - b.start)?)
            } else {
                (0, 0)
            };
            if before != after {
                let at = start(slot)?;
                expected[at..at + 8].copy_from_slice(&after.0.to_le_bytes());
                expected[at + 8..at + 12].copy_from_slice(&after.1.to_le_bytes());
                patches.push(json!({"slot":slot,"before":before,"after":after}));
            }
        }
        if reported["edge"] != edge
            || reported["left_anchor"] != left
            || reported["right_anchor"] != right
            || reported["blocks"] != json!(physical)
            || reported["changed_rows"] != json!(patches)
        {
            return Err(format!("native comparison differs at edge {edge}").into());
        }
        total_patches += patches.len();
        total_blocks += blocks.len();
        total_sections += sections;
    }
    if expected != index {
        return Err("native reconstruction differs from candidate bytes".into());
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema":"horizon262-independent-native-range-comparison-v1","epoch":262,
            "candidate_sha256":expected_sha,"source_sha256":RAW_SHA,"rows_compared":ROWS,
            "native_windows":plan.len(),"native_blocks":total_blocks,"native_sections":total_sections,
            "changed_rows":total_patches,"candidate_matches_native_reconstruction":true,
            "replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,
        }))?
    );
    Ok(())
}
