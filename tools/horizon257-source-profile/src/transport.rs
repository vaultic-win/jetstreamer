use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub struct Epoch {
    pub number: u64,
    pub cid: &'static str,
    pub car: u64,
    pub slot_bytes: u64,
    pub slot_buckets: u32,
    pub offset_bytes: u64,
    pub offset_buckets: u32,
}

pub const EPOCHS: [Epoch; 2] = [
    Epoch {
        number: 256,
        cid: "bafyreief4qucc6dk7mq62wl4jbglnii745jd6aipu52cjwbo4u6wgkwrye",
        car: 420045146364,
        slot_bytes: 15468900,
        slot_buckets: 40,
        offset_bytes: 10313095810,
        offset_buckets: 85932,
    },
    Epoch {
        number: 257,
        cid: "bafyreienrbuyzpqtxdf2sywy67idahbpakcahmqeonwz276n62pupetgbu",
        car: 392183478837,
        slot_bytes: 15027443,
        slot_buckets: 39,
        offset_bytes: 9423712422,
        offset_buckets: 78521,
    },
];

// Read the same canonical CIDv1 dag-cbor SHA256 form as the sealed 265 compact indexes.
fn cid_bytes(cid: &str) -> Result<Vec<u8>> {
    ensure!(cid.len() == 59 && cid.starts_with('b'), "CID encoding");
    let mut out = Vec::with_capacity(36);
    let (mut bits, mut n) = (0u16, 0);
    for c in cid.bytes().skip(1) {
        let v = match c {
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            _ => anyhow::bail!("noncanonical CID"),
        };
        bits = bits << 5 | u16::from(v);
        n += 5;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
            bits &= (1 << n) - 1;
        }
    }
    ensure!(
        n == 2 && bits == 0 && out.len() == 36 && out[..4] == [1, 0x71, 0x12, 0x20],
        "CID type/padding"
    );
    Ok(out)
}

pub fn car(prefix: &[u8], cid: &str) -> Result<()> {
    ensure!(prefix.len() == 4096, "CAR prefix size");
    let mut header = b"\x3a\xa2eroots\x81\xd8\x2a\x58\x25\0".to_vec();
    header.extend(cid_bytes(cid)?);
    header.extend(b"gversion\x01");
    ensure!(
        prefix.starts_with(&header),
        "CARv1 canonical root header differs"
    );
    Ok(())
}

pub fn headers(raw: &[u8], total: u64, full: bool, mime: &str) -> Result<()> {
    let text = std::str::from_utf8(raw)?
        .strip_suffix("\r\n\r\n")
        .context("incomplete HTTP response")?;
    let mut lines = text.split("\r\n");
    ensure!(
        lines.next() == Some(if full { "HTTP/2 200 " } else { "HTTP/2 206 " }),
        "HTTP response status"
    );
    let mut map = BTreeMap::new();
    for line in lines {
        let (name, val) = line.split_once(':').context("malformed HTTP field")?;
        ensure!(
            !name.is_empty() && map.insert(name.to_ascii_lowercase(), val.trim()).is_none(),
            "duplicate HTTP field"
        );
    }
    let size = if full { total } else { 4096 };
    ensure!(
        map.get("content-length") == Some(&size.to_string().as_str())
            && map.get("content-type") == Some(&mime),
        "HTTP entity size/type"
    );
    ensure!(map.get("accept-ranges") == Some(&"bytes"), "range support");
    if full {
        ensure!(
            !map.contains_key("content-range"),
            "partial body advertised as full"
        );
    } else {
        ensure!(
            map.get("content-range") == Some(&format!("bytes 0-4095/{total}").as_str()),
            "unexpected range or source size"
        );
    }
    Ok(())
}

fn field<'a>(data: &mut &'a [u8]) -> Result<&'a [u8]> {
    let (&length, rest) = data.split_first().context("missing field length")?;
    let (value, tail) = rest
        .split_at_checked(usize::from(length))
        .context("short metadata field")?;
    *data = tail;
    Ok(value)
}

pub fn compact(prefix: &[u8], epoch: &Epoch, kind: &str) -> Result<Value> {
    ensure!(
        prefix.len() == 4096
            || (kind == "cid-to-offset-and-size"
                && prefix.len() == 130 + 16 * epoch.offset_buckets as usize),
        "compact index prefix/table length"
    );
    let (width, buckets, limit, header_bytes) = match kind {
        "slot-to-cid" => (36, epoch.slot_buckets, epoch.slot_bytes, 119),
        "cid-to-offset-and-size" => (9, epoch.offset_buckets, epoch.offset_bytes, 130),
        _ => anyhow::bail!("unsupported index kind"),
    };
    ensure!(
        &prefix[..8] == b"compiszd" && prefix[24] == 1,
        "compact magic/version"
    );
    let end = 12 + u32::from_le_bytes(prefix[8..12].try_into()?) as usize;
    ensure!(
        end == header_bytes
            && u64::from_le_bytes(prefix[12..20].try_into()?) == width
            && u32::from_le_bytes(prefix[20..24].try_into()?) == buckets,
        "compact dimensions"
    );
    let mut meta = &prefix[26..end];
    let mut fields = BTreeMap::new();
    for _ in 0..prefix[25] {
        ensure!(
            fields
                .insert(field(&mut meta)?, field(&mut meta)?)
                .is_none(),
            "duplicate compact metadata key"
        );
    }
    let cid = cid_bytes(epoch.cid)?;
    ensure!(
        meta.is_empty()
            && fields.len() == 4
            && fields.get(b"epoch".as_slice()).copied()
                == Some(epoch.number.to_le_bytes().as_slice())
            && fields.get(b"kind".as_slice()).copied() == Some(kind.as_bytes())
            && fields.get(b"network".as_slice()).copied() == Some(b"mainnet".as_slice())
            && fields.get(b"rootCid".as_slice()).copied() == Some(cid.as_slice()),
        "wrong compact epoch/network/root/kind metadata"
    );
    let table_end = end as u64 + u64::from(buckets) * 16;
    ensure!(table_end < limit, "table out of bounds");
    let count = ((prefix.len() - end) / 16).min(buckets as usize);
    let mut intervals = Vec::new();
    for h in prefix[end..end + count * 16].as_chunks::<16>().0 {
        let entries = u64::from(u32::from_le_bytes(h[4..8].try_into()?));
        if entries == 0 {
            continue;
        }
        let hash_width = u64::from(h[8]);
        ensure!((1..=8).contains(&hash_width), "bucket hash width");
        let mut start = [0; 8];
        start[..6].copy_from_slice(&h[10..16]);
        let start = u64::from_le_bytes(start);
        let stop = start + entries * (hash_width + width);
        ensure!(
            start >= table_end && stop <= limit,
            "visible bucket outside object"
        );
        intervals.push((start, stop));
    }
    intervals.sort_unstable();
    ensure!(
        !intervals.is_empty() && intervals.windows(2).all(|a| a[0].1 <= a[1].0),
        "visible bucket overlap"
    );
    Ok(
        json!({"epoch":epoch.number,"kind":kind,"root_cid":epoch.cid,"entity_bytes":limit,"header_bytes":end,"buckets":buckets,"bucket_descriptors_checked":count,"complete_bucket_table_checked":count==buckets as usize,"full_index_body_checked":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn header_rejects_wrong_status_duplicates_and_false_full_read() {
        let good=b"HTTP/2 206 \r\ncontent-length: 4096\r\ncontent-range: bytes 0-4095/9000\r\ncontent-type: application/octet-stream\r\naccept-ranges: bytes\r\n\r\n";
        assert!(headers(good, 9000, false, "application/octet-stream").is_ok());
        assert!(headers(good, 9001, false, "application/octet-stream").is_err());
        assert!(headers(good, 9000, true, "application/octet-stream").is_err());
        let dup = String::from_utf8_lossy(good)
            .replace("accept-ranges:", "CONTENT-LENGTH: 4096\r\naccept-ranges:");
        assert!(headers(dup.as_bytes(), 9000, false, "application/octet-stream").is_err());
    }
}
