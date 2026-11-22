//! Recover affected index rows from CID-verified Old Faithful CAR windows.
#[path = "../../jetstreamer-firehose/src/bin/native_window/mod.rs"]
mod native_window;

use jetstreamer_firehose::node::{Node, NodeReader};
use native_window::{Block, Result};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    env, fs,
    io::{Cursor, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
};

const SLOTS: u64 = 432_000;
const HEADER: u64 = 59;
const PROFILE: &str = include_str!("plan.json");

fn sha(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

fn number(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .ok_or_else(|| format!("missing unsigned {key}").into())
}

fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| format!("missing text {key}").into())
}

fn read(path: &Path, size: u64) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.len() != size {
        return Err(format!("size/type mismatch for {}", path.display()).into());
    }
    let b = fs::read(path)?;
    if b.len() as u64 != size {
        return Err("input changed during read".into());
    }
    Ok(b)
}

fn save(p: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(p)?;
    file.write_all(bytes)?;
    file.set_permissions(fs::Permissions::from_mode(0o400))?;
    file.sync_all()?;
    fs::File::open(p.parent().ok_or("output parent")?)?.sync_all()?;
    Ok(())
}

struct Captures<'a> {
    root: &'a Path,
    entries: BTreeMap<String, &'a Value>,
}

impl Captures<'_> {
    fn read(&self, e: u64, kind: &str, lo: u64, hi: u64) -> Result<Vec<u8>> {
        let name = format!("{e}-{kind}-{lo}-{hi}.car");
        let proof = self
            .entries
            .get(&name)
            .ok_or("missing range from transfer manifest")?;
        if number(proof, "lo")? != lo
            || number(proof, "hi")? != hi
            || number(proof, "epoch")? != e
            || text(proof, "kind")? != kind
        {
            return Err("capture identity mismatch".into());
        }
        let body = read(
            &self.root.join(name),
            hi.checked_sub(lo).ok_or("negative range")?,
        )?;
        if sha(&body) != text(proof, "sha256")? {
            return Err("capture hash mismatch".into());
        }
        Ok(body)
    }
}

fn known_root(e: u64) -> Result<&'static str> {
    match e {
        199 => Ok("bafyreid5x4ci3xei4wy5rijuqfjh4y6svca3a7tkhhsirxuhu3bj7p5z7y"),
        200 => Ok("bafyreibhxmsejxsshqpplpyhrpvf3tbl2cgl7qj33snet5b3q2txorimfu"),
        267 => Ok("bafyreifn4ykgns5ih2lzfzrvky2u5vfh4jvqcqy7tdylujrbvl6pqavi4m"),
        _ => Err("unexpected epoch".into()),
    }
}

fn row(raw: &[u8], e: u64, slot: u64) -> Result<(u64, u32)> {
    let i = slot
        .checked_sub(e * SLOTS)
        .filter(|i| *i < SLOTS)
        .ok_or("slot outside epoch")? as usize;
    let b = &raw[i * 12..(i + 1) * 12];
    Ok((
        u64::from_le_bytes(b[..8].try_into()?),
        u32::from_le_bytes(b[8..].try_into()?),
    ))
}

fn check_window(
    header: &[u8],
    body: &[u8],
    raw: &[u8],
    e: u64,
    w: &Value,
) -> Result<(Vec<Block>, u64)> {
    let lo = number(w, "lo_slot")?;
    let hi = number(w, "hi_slot")?;
    if lo >= hi || hi - lo > 64 {
        return Err("invalid flanking slot span".into());
    }
    let a = number(w, "start")?;
    let b = number(w, "end")?;
    let (ao, al) = row(raw, e, lo)?;
    let (bo, bl) = row(raw, e, hi)?;
    if ao != a || bo + u64::from(bl) != b || a < HEADER || body.len() as u64 != b - a {
        return Err("proposed window changed".into());
    }
    let (nodes, sections) = native_window::decode(header, body, a)?;
    let first = nodes.first().ok_or("empty window")?;
    let last = nodes.last().ok_or("empty window")?;
    if (first.slot, first.start, first.end - first.start) != (lo, ao, u64::from(al))
        || (last.slot, last.start, last.end) != (hi, bo, b)
        || first.parent >= first.slot
        || nodes
            .windows(2)
            .any(|p| p[0].slot >= p[1].slot || p[0].slot != p[1].parent || p[0].end != p[1].start)
    {
        return Err("native flanking block or physical parent chain mismatch".into());
    }
    Ok((nodes, sections))
}

type Witness = (u64, u32, u64, String);

fn membership(
    e: u64,
    header: &[u8],
    footer: Vec<u8>,
    witness: &BTreeMap<u64, Option<Witness>>,
) -> Result<(usize, usize)> {
    let mut targets = BTreeMap::new();
    for (slot, w) in witness {
        if let Some((_, _, _, hex)) = w {
            if hex.len() % 2 != 0 {
                return Err("invalid CID bytes".into());
            }
            let bytes = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
                .collect::<std::result::Result<Vec<u8>, _>>()?;
            if targets.insert(bytes, (*slot, 0_u32)).is_some() {
                return Err("duplicate physical CID".into());
            }
        }
    }
    let mut bytes = header.to_vec();
    bytes.extend_from_slice(&footer);
    let len = bytes.len() as u64;
    let mut reader = NodeReader::new(Cursor::new(bytes))?;
    reader.read_raw_header()?;
    let mut subsets = Vec::new();
    let mut all = HashSet::new();
    let mut prior_last = None;
    loop {
        let n = reader.next()?;
        n.verify_sha256_cid()?;
        match n.parse()? {
            Node::Subset(s) => {
                if s.first > s.last
                    || s.first < e * SLOTS
                    || s.last >= (e + 1) * SLOTS
                    || prior_last.is_some_and(|p| s.first <= p)
                {
                    return Err("subset slot limits overlap or leave epoch".into());
                }
                prior_last = Some(s.last);
                subsets.push(*n.get_cid());
                for cid in s.blocks {
                    if !all.insert(cid) {
                        return Err("duplicate CID in canonical subsets".into());
                    }
                    if let Some((slot, count)) = targets.get_mut(&cid.to_bytes()) {
                        if !(s.first..=s.last).contains(slot) {
                            return Err("canonical subset disagrees with block slot".into());
                        }
                        *count += 1;
                    }
                }
            }
            Node::Epoch(root)
                if root.epoch == e
                    && n.get_cid().to_string() == known_root(e)?
                    && root.subsets == subsets
                    && !subsets.is_empty() =>
            {
                break;
            }
            _ => return Err("unexpected footer node or epoch membership".into()),
        }
    }
    if reader.into_inner().position() != len || targets.values().any(|(_, n)| *n != 1) {
        return Err("incomplete footer or missing rooted physical block".into());
    }
    Ok((all.len(), targets.len()))
}

fn run_epoch(plan: &Value, source: &Path, cap: &Captures<'_>, out: &Path) -> Result<Value> {
    let e = number(plan, "epoch")?;
    known_root(e)?;
    let raw = read(
        &source.join(format!("epoch-{e}-slot-ranges.raw")),
        SLOTS * 12,
    )?;
    if sha(&raw) != text(plan, "raw_sha256")? {
        return Err("original raw index mismatch".into());
    }
    let head = cap.read(e, "header", 0, HEADER)?;
    if sha(&head) != text(plan, "header_sha256")? {
        return Err("unexpected canonical CAR header".into());
    }
    let tail = number(plan, "footer_at")?;
    let footer = cap.read(e, "footer", tail, number(plan, "car_bytes")?)?;
    let mut witness: BTreeMap<u64, Option<Witness>> = BTreeMap::new();
    let mut sections = 0;
    let mut failures = Vec::new();
    let mut passed = 0;
    for w in plan["individual_windows"]
        .as_array()
        .ok_or("absent windows")?
    {
        let a = number(w, "start")?;
        let b = number(w, "end")?;
        let lo = number(w, "lo_slot")?;
        let hi = number(w, "hi_slot")?;
        let body = cap.read(e, "window", a, b)?;
        let (blocks, n) = match check_window(&head, &body, &raw, e, w) {
            Ok(row) => row,
            Err(error) => {
                failures.push(
                    json!({"lo_slot":lo,"hi_slot":hi,"start":a,"end":b,"error":error.to_string()}),
                );
                continue;
            }
        };
        let mut rows = BTreeMap::new();
        for node in blocks {
            rows.insert(
                node.slot,
                (
                    node.start,
                    u32::try_from(node.end - node.start)?,
                    node.parent,
                    node.cid,
                ),
            );
        }
        for slot in lo..=hi {
            let value = rows.remove(&slot);
            if let Some(prior) = witness.insert(slot, value.clone())
                && prior != value
            {
                return Err("incompatible overlapping native slot witnesses".into());
            }
        }
        if !rows.is_empty() {
            return Err("physical block outside accepted anchors".into());
        }
        passed += 1;
        sections += n;
    }
    let (canonical_count, rooted_witnesses) = membership(e, &head, footer, &witness)?;
    let partial = json!({"epoch":e,"root":known_root(e)?,"canonical_block_cids":canonical_count,"verified_windows":passed,
                      "verified_sections":sections,"rooted_observed_blocks":rooted_witnesses,"failures":failures});
    save(
        &out.join(format!("epoch-{e}-windows.json")),
        serde_json::to_string_pretty(&partial)?.as_bytes(),
    )?;
    if !failures.is_empty() {
        return Err(format!("{} windows failed for epoch {e}", failures.len()).into());
    }
    let mut corrected = raw.clone();
    let mut changes = Vec::new();
    for (slot, value) in witness {
        let was = row(&raw, e, slot)?;
        let now = value.as_ref().map(|v| (v.0, v.1)).unwrap_or_default();
        if was != now {
            let i = ((slot - e * SLOTS) * 12) as usize;
            corrected[i..i + 8].copy_from_slice(&now.0.to_le_bytes());
            corrected[i + 8..i + 12].copy_from_slice(&now.1.to_le_bytes());
            changes.push(json!({"slot":slot,"was":was,"now":now,"rooted_witness":value}));
        }
    }
    let mut pos = HEADER;
    let mut present = 0;
    for slot in e * SLOTS..(e + 1) * SLOTS {
        let (offset, len) = row(&corrected, e, slot)?;
        if len == 0 {
            if offset != 0 {
                return Err("nonzero skipped row".into());
            }
            continue;
        }
        if offset != pos {
            return Err(format!("still discontinuous at slot {slot}: {offset} vs {pos}").into());
        }
        pos = pos.checked_add(u64::from(len)).ok_or("CAR overflow")?;
        present += 1;
    }
    if pos != tail || present != canonical_count {
        return Err(format!(
            "whole-epoch coverage differs: end {pos} vs {tail} count {present} vs {canonical_count}"
        )
        .into());
    }
    let result = json!({"epoch":e,"root":known_root(e)?,"windows":partial,"changes":changes,"present":present,"skips":SLOTS-present as u64,
        "physical_end":pos,"original_sha256":sha(&raw),"corrected_sha256":sha(&corrected)});
    save(&out.join(format!("epoch-{e}-slot-ranges.raw")), &corrected)?;
    save(
        &out.join(format!("epoch-{e}-repair.json")),
        serde_json::to_string_pretty(&result)?.as_bytes(),
    )?;
    Ok(
        json!({"epoch":e,"changes":changes.len(),"present":present,"rooted_blocks":rooted_witnesses,"windows":passed,"sections":sections,"corrected_sha256":sha(&corrected)}),
    )
}

fn main() -> Result<()> {
    let mut command = env::args_os().skip(1).peekable();
    let (profile, body_bytes, range_count) = if command.next_if(|s| s == "--epoch267").is_some() {
        (
            include_str!("../horizon267-slot-input/repair-windows.json"),
            99_707_283,
            32,
        )
    } else {
        (PROFILE, 205_729_899, 139)
    };
    let args: Vec<_> = command.collect();
    if args.len() != 4 {
        return Err(
            "usage: repair [--epoch267] PINNED_INDEX_DIR CAPTURE_DIR CAPTURE_MANIFEST_SHA256 EMPTY_OUTPUT_DIR"
                .into(),
        );
    }
    let source = Path::new(&args[0]);
    let captured = Path::new(&args[1]);
    let out = Path::new(&args[3]);
    let expected = args[2].to_str().ok_or("invalid SHA")?;
    if out.read_dir()?.next().is_some() {
        return Err("output directory must be empty".into());
    }
    let plan: Value = serde_json::from_str(profile)?;
    let manifest_path = captured.join("RESULT.json");
    let size = fs::symlink_metadata(&manifest_path)?.len();
    if size > 256_000 {
        return Err("oversized transfer manifest".into());
    }
    let m = read(&manifest_path, size)?;
    if sha(&m) != expected {
        return Err("capture manifest differs".into());
    }
    let manifest: Value = serde_json::from_slice(&m)?;
    if text(&manifest, "plan_sha256")? != text(&plan, "capture_plan_sha256")?
        || number(&manifest, "body_bytes")? != body_bytes
    {
        return Err("incomplete capture".into());
    }
    let mut entries = BTreeMap::new();
    for v in manifest["source_ranges"]
        .as_array()
        .ok_or("source ranges")?
    {
        if entries.insert(text(v, "name")?.to_owned(), v).is_some() {
            return Err("duplicate capture".into());
        }
    }
    if entries.len() != range_count {
        return Err(format!("expected {range_count} distinct captured ranges").into());
    }
    let cap = Captures {
        root: captured,
        entries,
    };
    let mut bad = false;
    for e in plan["epochs"].as_array().ok_or("epochs")? {
        match run_epoch(e, source, &cap, out) {
            Ok(report) => println!("{report}"),
            Err(err) => {
                eprintln!("epoch {}: {err}", e["epoch"]);
                bad = true;
            }
        }
    }
    if bad {
        return Err("incomplete qualification".into());
    }
    Ok(())
}
