//! Qualify the descriptor ranges without traversing the compact-index payloads.
use super::{PACKET, SEAL, hash, inputs, packet, read_checked, transport};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::path::Path;
const CAPTURE: &str = "/var/lib/jetstreamer/horizon257-compact-tables-20261120-v1";
const FETCH: &str = "4272987ce13a4b8791d8291d318a8666219a395784360fd06ae09922245bc79e";

fn coverage(data: &[u8], header: usize, buckets: u32, width: u64, total: u64) -> Result<u64> {
    let table_end = header + usize::try_from(buckets)? * 16;
    let mut extents = Vec::new();
    let mut entries = 0u64;
    for row in data
        .get(header..table_end)
        .context("incomplete descriptor table")?
        .as_chunks::<16>()
        .0
    {
        let count = u64::from(u32::from_le_bytes(row[4..8].try_into()?));
        ensure!(
            count > 0 && row[8] == 3 && row[9] == 0,
            "unexpected zero bucket, hash width or reserved bits"
        );
        let mut offset = [0; 8];
        offset[..6].copy_from_slice(&row[10..]);
        let offset = u64::from_le_bytes(offset);
        extents.push((offset, offset + count * (width + 3)));
        entries += count;
    }
    extents.sort_unstable();
    ensure!(
        extents.first().map(|e| e.0) == Some(table_end as u64)
            && extents.last().map(|e| e.1) == Some(total)
            && extents.windows(2).all(|e| e[0].1 == e[1].0),
        "bucket entries do not tile entity"
    );
    Ok(entries)
}

pub fn run() -> Result<Value> {
    let capture = Path::new(CAPTURE);
    read_checked(
        capture,
        "deployment-seal-receipt.json",
        8192,
        "07d0746970802110ec78db82e8c7985d372bafc29c69bab92142792fea10465e",
    )?;
    let fetch: Value = serde_json::from_slice(&read_checked(
        capture,
        "compact-table-fetch.json",
        8192,
        FETCH,
    )?)?;
    let rows = fetch["rows"].as_array().context("fetch rows")?;
    ensure!(
        fetch["schema"] == "horizon257-compact-table-fetch-v1" && rows.len() == 2,
        "transport schema"
    );
    let source = packet(PACKET, SEAL, &inputs())?;
    let mut checked = Vec::new();
    for e in &transport::EPOCHS {
        let (table_sha, slot_entries, offset_entries) = match e.number {
            256 => (
                "467606595fee0990eaabbe068440abc5e2162ae77d82fbe64e0d2022d3853f2d",
                396619,
                859310064,
            ),
            257 => (
                "4ab6923d0a27da276e6f0a1df53c3e55abdbbf33ec5cf11095d181b7bba1427e",
                385300,
                785204663,
            ),
            _ => anyhow::bail!("foreign source"),
        };
        let kind = "cid-to-offset-and-size";
        let full = 130 + 16 * u64::from(e.offset_buckets);
        let table = read_checked(capture, &format!("{}.table", e.number), full, table_sha)?;
        let original = &source[&format!("{}.{kind}.prefix", e.number)];
        ensure!(
            table.len() as u64 == full && table.starts_with(original),
            "range prefix identity mismatch"
        );
        let r = rows
            .iter()
            .find(|r| r["epoch"] == e.number)
            .context("missing epoch acquisition")?;
        let url = format!(
            "https://files.old-faithful.net/{0}/epoch-{0}-{1}-mainnet-{kind}.index",
            e.number, e.cid
        );
        ensure!(
            r["url"] == url
                && r["http_status"] == 206
                && r["content_range"] == format!("bytes 4064-{}/{}", full - 1, e.offset_bytes)
                && r["response_bytes"] == full - 4064
                && r["overlap_bytes"] == 32
                && r["table_bytes"] == full
                && r["entity_bytes"] == e.offset_bytes
                && r["table_sha256"] == table_sha
                && r["response_sha256"] == hash(&table[4064..]),
            "range provenance"
        );
        let offset = transport::compact(&table, e, kind)?;
        let slot = &source[&format!("{}.slot-to-cid.prefix", e.number)];
        let slots = transport::compact(slot, e, "slot-to-cid")?;
        ensure!(
            coverage(slot, 119, e.slot_buckets, 36, e.slot_bytes)? == slot_entries
                && coverage(&table, 130, e.offset_buckets, 9, e.offset_bytes)? == offset_entries,
            "closed record census differs"
        );
        checked.push(json!({"epoch":e.number,"offset_table_sha256":table_sha,"slot_metadata":slots,"offset_metadata":offset,"slot_entry_count":slot_entries,"offset_entry_count":offset_entries}));
    }
    Ok(
        json!({"schema":"horizon257-full-compact-table-qualification-v1","source_seal_sha256":SEAL,"fetch_sha256":FETCH,"metadata":checked,"full_descriptor_coverage":true,"payloads_hashed":false,"ordinary_cache_materialized":false,"native_bootstrap_authorized":false,"replay_launch_authorized":false,"remote_mutations":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn catches_holes_overlaps_and_missing_descriptors() {
        let mut b = vec![0u8; 32];
        for (i, offset) in [(0, 32u64), (1, 44)] {
            let p = 16 * i;
            b[p + 4] = 1;
            b[p + 8] = 3;
            b[p + 10..p + 16].copy_from_slice(&offset.to_le_bytes()[..6]);
        }
        assert_eq!(coverage(&b, 0, 2, 9, 56).unwrap(), 2);
        for z in [43, 45] {
            let mut bad = b.clone();
            bad[26] = z;
            assert!(coverage(&bad, 0, 2, 9, 56).is_err());
        }
        assert!(coverage(&b[..20], 0, 2, 9, 56).is_err());
    }
}
