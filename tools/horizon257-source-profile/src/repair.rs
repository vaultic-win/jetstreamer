//! Reconstruct candidate rows from authenticated physical CAR sections and the slot ancestry
//! between two endpoints outside each anomalous edge. Never infer a correction from offsets.
use super::{PACKET, RAW, RAW_SHA, SEAL, hash, inputs, inspect, packet, read_checked};
use crate::{
    edges::EDGES,
    ranges::{CAR_SIZE, SLOTS, START},
};
use anyhow::{Context, Result, ensure};
use serde_cbor::Value as Cbor;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

const PLAN: &[u8] = include_bytes!("../edge-windows.json");
const PLAN_SHA: &str = "b8459e69dbecdffc9086c7954f1ae2bdd8a841ac70f85e034d38cfb8ec708f3b";
const SOURCE_URL: &str = "https://files.old-faithful.net/257/epoch-257.car";
const PREFIX_SHA: &str = "b05ac5e7b6c0d9b595c98bec38ba37b00d9183154eb5a922d6f69a05724affea";

#[derive(Clone, Debug)]
struct Window {
    edge: u64,
    left: u64,
    right: u64,
    start: u64,
    end: u64,
}
#[derive(Clone, Debug, PartialEq)]
struct Block {
    slot: u64,
    parent: u64,
    start: u64,
    end: u64,
    cid: String,
}

fn record(raw: &[u8], slot: u64) -> (u64, u32) {
    let i = (slot - START) as usize * 12;
    (
        u64::from_le_bytes(raw[i..i + 8].try_into().unwrap()),
        u32::from_le_bytes(raw[i + 8..i + 12].try_into().unwrap()),
    )
}
fn windows(raw: &[u8]) -> Result<Vec<Window>> {
    ensure!(hash(PLAN) == PLAN_SHA, "window plan changed");
    let rows: Vec<Value> = serde_json::from_slice(PLAN)?;
    ensure!(rows.len() == EDGES.len(), "edge coverage");
    let mut windows = Vec::new();
    let mut bytes = 0;
    let mut previous = 0;
    for (row, &(left_edge, edge, _, _)) in rows.iter().zip(EDGES) {
        let get = |k: &str| row[k].as_u64().context("invalid plan integer");
        let w = Window {
            edge: get("edge")?,
            left: get("left")?,
            right: get("right")?,
            start: get("start")?,
            end: get("end")?,
        };
        ensure!(
            w.edge == edge
                && (START..left_edge).contains(&w.left)
                && w.right > edge
                && w.right < START + SLOTS as u64
                && w.start >= previous
                && w.end > w.start
                && w.end - w.start <= 6971573,
            "window scope"
        );
        let (lo, ln) = record(raw, w.left);
        let (ro, rn) = record(raw, w.right);
        ensure!(
            lo == w.start && ln > 0 && rn > 0 && ro + u64::from(rn) == w.end,
            "window endpoints differ from original"
        );
        ensure!(
            (w.left + 1..left_edge).all(|s| record(raw, s) == (0, 0))
                && (edge + 1..w.right).all(|s| record(raw, s) == (0, 0)),
            "window anchors are not the nearest unaffected records"
        );
        bytes += w.end - w.start;
        previous = w.end;
        windows.push(w);
    }
    ensure!(bytes == 118427890, "download budget");
    Ok(windows)
}

fn quantity(v: Option<&Cbor>) -> Result<u64> {
    match v {
        Some(Cbor::Integer(n)) => Ok(u64::try_from(*n)?),
        _ => anyhow::bail!("expected unsigned CBOR integer"),
    }
}
fn array(v: Option<&Cbor>) -> Result<&[Cbor]> {
    match v {
        Some(Cbor::Array(a)) => Ok(a),
        _ => anyhow::bail!("expected CBOR array"),
    }
}
fn section<'a>(body: &'a [u8], at: &mut usize) -> Result<(&'a [u8], &'a [u8])> {
    let mut n = 0usize;
    for i in 0..4 {
        let b = *body.get(*at).context("truncated section length")?;
        *at += 1;
        n |= usize::from(b & 127) << (7 * i);
        if b & 128 == 0 {
            ensure!((i == 0 || b != 0) && n > 36, "invalid CAR section length");
            let s = body.get(*at..*at + n).context("truncated CAR section")?;
            *at += n;
            ensure!(
                s[..4] == [1, 0x71, 0x12, 0x20] && Sha256::digest(&s[36..])[..] == s[4..36],
                "section CID mismatch"
            );
            return Ok((&s[..36], &s[36..]));
        }
    }
    anyhow::bail!("section exceeds closed window bound")
}

fn decode(w: &Window, bytes: &[u8]) -> Result<Vec<Block>> {
    ensure!(
        bytes.len() as u64 == w.end - w.start,
        "window length mismatch"
    );
    let mut at = 0;
    let mut start = w.start;
    let mut blocks = Vec::new();
    let mut data_slot = None;
    while at < bytes.len() {
        let (cid, payload) = section(bytes, &mut at)?;
        let parsed: Cbor = serde_cbor::from_slice(payload)?;
        let fields = array(Some(&parsed))?;
        match quantity(fields.first())? {
            0 | 5 => {
                let i = if fields.first() == Some(&Cbor::Integer(0)) {
                    3
                } else {
                    1
                };
                let slot = quantity(fields.get(i))?;
                ensure!(data_slot.is_none_or(|s| s == slot), "mixed slot payloads");
                data_slot = Some(slot);
            }
            1 | 6 => {}
            2 => {
                let slot = quantity(fields.get(1))?;
                let parent = quantity(array(fields.get(4))?.first())?;
                ensure!(
                    parent < slot && data_slot.is_none_or(|s| s == slot),
                    "terminal block/slot payload disagree"
                );
                let end = w.start + at as u64;
                blocks.push(Block {
                    slot,
                    parent,
                    start,
                    end,
                    cid: cid.iter().map(|b| format!("{b:02x}")).collect(),
                });
                start = end;
                data_slot = None;
            }
            _ => anyhow::bail!("unexpected non-slot section in boundary window"),
        }
    }
    ensure!(
        start == w.end && !blocks.is_empty(),
        "window ends inside a slot"
    );
    Ok(blocks)
}

fn ancestry<'a>(w: &Window, blocks: &'a [Block], raw: &[u8]) -> Result<BTreeMap<u64, &'a Block>> {
    let first = blocks.first().context("empty window")?;
    let last = blocks.last().unwrap();
    for (anchor, expect) in [(first, w.left), (last, w.right)] {
        let (o, n) = record(raw, expect);
        ensure!(
            anchor.slot == expect && (anchor.start, anchor.end) == (o, o + u64::from(n)),
            "physical exterior anchor disagrees"
        );
    }
    let mut chain = BTreeMap::new();
    let mut idx = blocks.len() - 1;
    loop {
        let current = &blocks[idx];
        ensure!(
            chain.insert(current.slot, current).is_none(),
            "duplicate canonical block"
        );
        if idx == 0 {
            break;
        }
        ensure!(current.parent >= w.left, "parent outside immutable bracket");
        let mut parents = blocks[..idx]
            .iter()
            .enumerate()
            .filter(|(_, b)| b.slot == current.parent);
        let (parent_idx, _) = parents.next().context("missing parent inside bracket")?;
        ensure!(
            parents.next().is_none(),
            "ambiguous same-slot parent in bracket"
        );
        idx = parent_idx;
    }
    Ok(chain)
}

fn apply_window(raw: &mut [u8], w: &Window, blocks: &[Block]) -> Result<Value> {
    let chain = ancestry(w, blocks, raw)?;
    let mut patches = Vec::new();
    for slot in w.left..=w.right {
        let row = chain.get(&slot);
        let after = if let Some(block) = row {
            (block.start, u32::try_from(block.end - block.start)?)
        } else {
            (0, 0)
        };
        let before = record(raw, slot);
        if before != after {
            let pos = ((slot - START) * 12) as usize;
            raw[pos..pos + 8].copy_from_slice(&after.0.to_le_bytes());
            raw[pos + 8..pos + 12].copy_from_slice(&after.1.to_le_bytes());
            patches.push(json!({"slot":slot,"before":before,"after":after}));
        }
    }
    let physical:Vec<_>=blocks.iter().map(|b|json!({"slot":b.slot,"parent":b.parent,"start":b.start,"end":b.end,"block_cid_hex":b.cid,"on_anchor_chain":chain.get(&b.slot).is_some_and(|v|*v==b)})).collect();
    Ok(
        json!({"edge":w.edge,"left_anchor":w.left,"right_anchor":w.right,"blocks":physical,"changed_rows":patches}),
    )
}

fn write_new(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(dir.join(name))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
pub fn run(out: &Path) -> Result<()> {
    inspect()?;
    let dir = Path::new("/run/horizon257-edge-source-20261120-v1/result/windows");
    ensure!(
        dir.canonicalize()? == dir
            && dir.metadata()?.uid() == 0
            && dir.metadata()?.mode() & 0o222 == 0,
        "source window directory custody"
    );
    const DOWNLOAD_SHA: &str = "91b0303d552386fcbaec36178259f2af33b09e2b06f2e2cdf92ad6778a223521";
    let seal_hash = "257f04ac37448632fc78dd8a3be39e1364eaea65e911157bed2ed364450a2c4b";
    let witness = packet(
        "/var/lib/jetstreamer/horizon257-edge-source-readback-20261120-v1",
        seal_hash,
        &BTreeSet::from(["booking.json".into(), "download.json".into()]),
    )?;
    let b = read_checked(dir, "download.json", 65536, DOWNLOAD_SHA)?;
    ensure!(
        witness["download.json"] == b,
        "runtime and durable capture manifests differ"
    );
    let download: Value = serde_json::from_slice(&b)?;
    let source = packet(PACKET, SEAL, &inputs())?;
    let mut raw = source[RAW].clone();
    let planned = windows(&raw)?;
    ensure!(
        download["schema"] == "horizon257-window-download-v1"
            && download["plan_sha256"] == PLAN_SHA
            && download["total_bytes"] == 118436082,
        "wrong download manifest"
    );
    let resources = download["resources"]
        .as_array()
        .context("download records")?;
    ensure!(resources.len() == planned.len() + 2, "coverage");
    let mut reviews = Vec::new();
    for (i, r) in resources.iter().enumerate() {
        let (name, start, end) = if i == 0 {
            ("prefix-before".to_owned(), 0, 4096)
        } else if i == resources.len() - 1 {
            ("prefix-after".to_owned(), 0, 4096)
        } else {
            let w = &planned[i - 1];
            (w.edge.to_string(), w.start, w.end)
        };
        ensure!(
            r["name"] == name
                && r["status"] == 206
                && r["url"] == SOURCE_URL
                && r["bytes"] == end - start
                && r["request_range"] == format!("bytes={start}-{}", end - 1)
                && r["content_range"] == format!("bytes {start}-{}/{CAR_SIZE}", end - 1),
            "bounded HTTP source differs"
        );
        let bytes = read_checked(
            dir,
            &format!("{name}.car"),
            end - start,
            r["sha256"].as_str().context("body digest")?,
        )?;
        ensure!(
            bytes.len() as u64 == end - start && r["sha256"] == hash(&bytes),
            "capture digest"
        );
        if name.starts_with("prefix-") {
            ensure!(r["sha256"] == PREFIX_SHA, "CAR source anchor");
        } else {
            let w = &planned[i - 1];
            let blocks = decode(w, &bytes).with_context(|| format!("decode edge {}", w.edge))?;
            let mut report = apply_window(&mut raw, w, &blocks)
                .with_context(|| format!("derive edge {}", w.edge))?;
            report["capture_sha256"] = r["sha256"].clone();
            reviews.push(report);
        }
    }
    let mut previous_end = 59;
    let mut present = 0;
    let mut gaps = 0;
    for slot in START..START + SLOTS as u64 {
        let (o, n) = record(&raw, slot);
        if n == 0 {
            ensure!(o == 0, "partial absent record");
            continue;
        }
        let end = o.checked_add(u64::from(n)).context("overflow")?;
        ensure!(
            o >= previous_end && end <= CAR_SIZE,
            "candidate still overlaps or exceeds CAR at {slot}"
        );
        gaps += u64::from(o > previous_end);
        present += 1;
        previous_end = end;
    }
    ensure!(
        present == 385300
            && gaps == 0
            && hash(&raw) == "5810e796b7565404320544ebb5cd98055eb5cfaf60af64884c96481e5f75d126",
        "exact measured candidate changed"
    );
    let report = json!({"schema":"horizon257-direct-car-repair-candidate-v1","source_sha256":RAW_SHA,"candidate_sha256":hash(&raw),"windows_seal_sha256":seal_hash,"download_plan_sha256":PLAN_SHA,"candidate_present":present,"candidate_gaps":gaps,"all_windows_verified":true,"edges":reviews,"replay_launch_authorized":false,"admission_authorized":false,"publication_authorized":false,"canonical_remote_objects_changed":false});
    ensure!(
        out.is_absolute()
            && out.parent().context("output parent")?.canonicalize()? == out.parent().unwrap(),
        "use fresh canonical output"
    );
    std::os::unix::fs::DirBuilderExt::mode(&mut fs::DirBuilder::new(), 0o700).create(out)?;
    write_new(out, "epoch-257-slot-ranges.candidate.raw", &raw)?;
    write_new(
        out,
        "repair-candidate.json",
        &serde_json::to_vec_pretty(&report)?,
    )?;
    File::open(out)?.sync_all()?;
    File::open(out.parent().unwrap())?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn frame(v: Cbor) -> Vec<u8> {
        let p = serde_cbor::to_vec(&v).unwrap();
        let mut n = 36 + p.len();
        let mut out = Vec::new();
        while n >= 128 {
            out.push((n as u8 & 127) | 128);
            n >>= 7;
        }
        out.push(n as u8);
        out.extend([1, 0x71, 0x12, 0x20]);
        out.extend(Sha256::digest(&p));
        out.extend(p);
        out
    }
    fn block(slot: u64, parent: u64) -> Vec<u8> {
        frame(Cbor::Array(vec![
            Cbor::Integer(2),
            Cbor::Integer(slot.into()),
            Cbor::Array(vec![]),
            Cbor::Array(vec![]),
            Cbor::Array(vec![Cbor::Integer(parent.into())]),
        ]))
    }
    #[test]
    fn verified_parent_chain_preserves_physical_orphan_and_corrects_mislabeled_slot() -> Result<()>
    {
        let l = START;
        let rows = [
            block(l, l - 1),
            block(l + 1, l),
            block(l + 2, l),
            block(l + 4, l + 2),
        ];
        let mut raw = vec![0; 5 * 12];
        let mut o = 59u64;
        for (i, b) in rows.iter().enumerate() {
            if i == 0 || i == 3 {
                let ix = if i == 0 { 0 } else { 4 } * 12;
                raw[ix..ix + 8].copy_from_slice(&o.to_le_bytes());
                raw[ix + 8..ix + 12].copy_from_slice(&(b.len() as u32).to_le_bytes());
            }
            o += b.len() as u64;
        }
        let w = Window {
            edge: l + 4,
            left: l,
            right: l + 4,
            start: 59,
            end: o,
        };
        let mut bytes = rows.concat();
        let decoded = decode(&w, &bytes)?;
        let r = apply_window(&mut raw, &w, &decoded)?;
        assert_eq!(r["blocks"][1]["on_anchor_chain"], false);
        assert_eq!(record(&raw, l + 1), (0, 0));
        assert_eq!(
            record(&raw, l + 2),
            (
                59 + (rows[0].len() + rows[1].len()) as u64,
                rows[2].len() as u32
            )
        );
        let n = bytes.len();
        bytes[n - 1] ^= 1;
        assert!(decode(&w, &bytes).is_err());
        assert!(decode(&w, &bytes[..n - 1]).is_err());
        let mut broken = decoded.clone();
        broken[3].parent = l + 3;
        assert!(ancestry(&w, &broken, &raw).is_err());
        broken = decoded;
        broken[1].slot = l + 2;
        assert!(ancestry(&w, &broken, &raw).is_err());
        Ok(())
    }
    #[test]
    fn partial_varints_and_unknown_section_types_fail_closed() {
        for bad in [vec![128], vec![128, 0], vec![0xff; 6]] {
            assert!(section(&bad, &mut 0).is_err());
        }
        let body = frame(Cbor::Array(vec![Cbor::Integer(4)]));
        let w = Window {
            edge: START,
            left: START,
            right: START + 1,
            start: 59,
            end: 59 + body.len() as u64,
        };
        assert!(decode(&w, &body).is_err());
    }
}
