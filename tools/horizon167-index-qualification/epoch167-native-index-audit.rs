//! Read-only, root-bound comparison of a captured epoch 167 CAR window and its original index.
#[path = "../../jetstreamer-firehose/src/bin/native_window/mod.rs"]
mod native_window;
use jetstreamer_firehose::node::{Node, NodeReader};
use native_window::{Block, Result};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, env, fs, io::Cursor, path::Path};

const FIRST: u64 = 167 * 432_000;
const ROOT: &str = "bafyreienhstqouv46ysqm2r5dqeixnhmil3qem77x76q5hicq4egi3uzhi";
const RAW: &str = "cf6e016275088a0849d6706b892f2d65dbe7a0641d904105b6878ff9ba3524b7";
const HEADER: &str = "9b443650ac7774a4c56c8823dd9bfd4c192f0ba50c7be29b7d996ac74eb598a1";
const FOOTER: &str = "3320deb44596928e5b122a524a881b6585af1be815561d5132c61edf3d2524b1";
const FOOTER_START: u64 = 141_829_223_419;

fn read(path: &Path, bytes: usize) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_file() || m.len() != u64::try_from(bytes)? {
        return Err("capture type or length changed".into());
    }
    let data = fs::read(path)?;
    if data.len() != bytes {
        return Err("short capture".into());
    }
    Ok(data)
}

fn pinned(path: &Path, bytes: usize, expected: &str) -> Result<Vec<u8>> {
    let data = read(path, bytes)?;
    if format!("{:x}", Sha256::digest(&data)) != expected {
        return Err("capture digest changed".into());
    }
    Ok(data)
}

fn row(raw: &[u8], slot: u64) -> Result<(u64, u64)> {
    let i = usize::try_from(slot.checked_sub(FIRST).ok_or("slot before epoch")?)?;
    if i >= 432_000 {
        return Err("slot after epoch".into());
    }
    let r = &raw[i * 12..(i + 1) * 12];
    Ok((
        u64::from_le_bytes(r[..8].try_into()?),
        u64::from(u32::from_le_bytes(r[8..].try_into()?)),
    ))
}

fn check_membership(prefix: &[u8], footer: &[u8], blocks: &[Block]) -> Result<()> {
    let mut targets: BTreeMap<_, _> = blocks
        .iter()
        .map(|b| (b.cid.as_str(), (b.slot, 0u8)))
        .collect();
    if targets.len() != blocks.len() {
        return Err("duplicate physical block CID".into());
    }
    let mut data = prefix[..59].to_vec();
    data.extend_from_slice(footer);
    let mut cursor = Cursor::new(data);
    let len = cursor.get_ref().len() as u64;
    let mut reader = NodeReader::new(&mut cursor)?;
    reader.read_raw_header()?;
    let mut subsets = Vec::new();
    loop {
        let raw = reader.next()?;
        raw.verify_sha256_cid()?;
        match raw.parse()? {
            Node::Subset(subset) if subsets.len() < 16 => {
                subsets.push(*raw.get_cid());
                if blocks
                    .iter()
                    .any(|b| (subset.first..=subset.last).contains(&b.slot))
                {
                    for cid in subset.blocks {
                        let key = cid
                            .to_bytes()
                            .iter()
                            .map(|x| format!("{x:02x}"))
                            .collect::<String>();
                        if let Some((slot, count)) = targets.get_mut(key.as_str()) {
                            if !(subset.first..=subset.last).contains(slot) {
                                return Err("subset bounds disagree with block slot".into());
                            }
                            *count = count.checked_add(1).ok_or("duplicate CID count overflow")?;
                        }
                    }
                }
            }
            Node::Epoch(epoch)
                if raw.get_cid().to_string() == ROOT
                    && epoch.epoch == 167
                    && epoch.subsets == subsets
                    && subsets.len() == 16 =>
            {
                break;
            }
            _ => return Err("unrecognized node or broken epoch-to-subset links in footer".into()),
        }
    }
    if reader.into_inner().position() != len || targets.values().any(|(_, count)| *count != 1) {
        return Err("footer coverage or subset-to-block membership differs".into());
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.len() != 6 {
        return Err(
            "usage: epoch167-native-index-audit RAW PREFIX FOOTER WINDOW LEFT_SLOT RIGHT_SLOT"
                .into(),
        );
    }
    let raw = pinned(Path::new(&args[0]), 5_184_000, RAW)?;
    let prefix = pinned(Path::new(&args[1]), 4096, HEADER)?;
    let footer = pinned(Path::new(&args[2]), 15_535_807, FOOTER)?;
    let (left, right) = (args[4].parse()?, args[5].parse()?);
    let (start, left_len) = row(&raw, left)?;
    let (last, right_len) = row(&raw, right)?;
    let end = last.checked_add(right_len).ok_or("anchor overflow")?;
    if left >= right
        || right - left > 64
        || left_len == 0
        || right_len == 0
        || start < 59
        || end > FOOTER_START
        || !(1..=8_388_608).contains(&end.checked_sub(start).ok_or("inverted window")?)
    {
        return Err("invalid window or anchors".into());
    }
    let body = read(Path::new(&args[3]), usize::try_from(end - start)?)?;
    let (blocks, sections) = native_window::decode(&prefix, &body, start)?;
    let first = blocks.first().ok_or("empty window")?;
    let final_block = blocks.last().ok_or("empty window")?;
    if (first.slot, first.start, first.end - first.start) != (left, start, left_len)
        || (final_block.slot, final_block.start, final_block.end) != (right, last, end)
        || first.parent >= first.slot
        || blocks
            .windows(2)
            .any(|pair| pair[0].slot >= pair[1].slot || pair[1].parent != pair[0].slot)
    {
        return Err("window boundaries or block ancestry differ".into());
    }
    check_membership(&prefix, &footer, &blocks)?;
    let rows: BTreeMap<_, _> = blocks.iter().map(|b| (b.slot, b)).collect();
    println!(
        "root={ROOT} start={start} end={end} sections={sections} blocks={} sha256={:x}",
        blocks.len(),
        Sha256::digest(&body)
    );
    for slot in left..=right {
        let (old_start, old_len) = row(&raw, slot)?;
        if let Some(b) = rows.get(&slot) {
            println!(
                "{slot}\t{old_start}\t{old_len}\t{}\t{}\t{}\t{}",
                b.start,
                b.end - b.start,
                b.parent,
                b.cid
            );
        } else if (old_start, old_len) != (0, 0) {
            println!("{slot}\t{old_start}\t{old_len}\t0\t0\t-\t-");
        }
    }
    Ok(())
}
