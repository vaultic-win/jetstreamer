//! Structural checks adapted from the qualified 250/251 cache checker.
use super::*;
use std::collections::BTreeMap;

// Both selected CIDs are canonical lowercase base32 multibase CIDv1 dag-cbor SHA256.
fn cid_bytes(cid: &str) -> Result<Vec<u8>> {
    ensure!(cid.len() == 59 && cid.starts_with('b'), "noncanonical CID");
    let mut out = Vec::new();
    let mut bits = 0u32;
    let mut count = 0;
    for c in cid.bytes().skip(1) {
        let value = match c {
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            _ => anyhow::bail!("invalid CID character"),
        };
        bits = (bits << 5) | u32::from(value);
        count += 5;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    ensure!(
        count == 2 && bits == 0 && out.len() == 36 && out[..4] == [1, 0x71, 0x12, 0x20],
        "CID type or padding differs"
    );
    Ok(out)
}
fn metadata(data: &[u8]) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    let count = usize::from(*data.first().context("empty metadata")?);
    let mut at = 1;
    let mut map = BTreeMap::new();
    for _ in 0..count {
        let n = usize::from(*data.get(at).context("key length")?);
        at += 1;
        let key = data.get(at..at + n).context("key")?.to_vec();
        at += n;
        let n = usize::from(*data.get(at).context("value length")?);
        at += 1;
        let value = data.get(at..at + n).context("value")?.to_vec();
        at += n;
        ensure!(map.insert(key, value).is_none(), "duplicate index metadata");
    }
    ensure!(at == data.len(), "trailing metadata");
    Ok(map)
}
fn inspect_file(file: &mut File, size: u64, epoch: u64, kind: &str, cid: &str) -> Result<Value> {
    let mut prefix = [0u8; 25];
    file.read_exact(&mut prefix)?;
    ensure!(
        &prefix[..8] == b"compiszd" && prefix[24] == 1,
        "index magic/version"
    );
    let header_len = u32::from_le_bytes(prefix[8..12].try_into()?) as usize;
    ensure!((13..=4096).contains(&header_len), "index header length");
    let header_end = 12 + header_len;
    let value_size = u64::from_le_bytes(prefix[12..20].try_into()?);
    let buckets = u32::from_le_bytes(prefix[20..24].try_into()?);
    ensure!(
        (1..=1_000_000).contains(&buckets) && (1..=64).contains(&value_size),
        "index dimensions"
    );
    let mut rest = vec![0u8; header_end - 25];
    file.read_exact(&mut rest)?;
    let m = metadata(&rest)?;
    ensure!(
        m.get(b"kind".as_slice()).map(Vec::as_slice) == Some(kind.as_bytes()),
        "index kind differs"
    );
    ensure!(
        m.get(b"epoch".as_slice()).map(Vec::as_slice) == Some(epoch.to_le_bytes().as_slice()),
        "index epoch differs"
    );
    ensure!(
        m.get(b"rootCid".as_slice()) == Some(&cid_bytes(cid)?),
        "index root CID differs"
    );
    let table_end = header_end as u64 + u64::from(buckets) * 16;
    ensure!(table_end < size, "index table outside file");
    let mut table = vec![0u8; buckets as usize * 16];
    file.read_exact(&mut table)?;
    let mut entries = 0u64;
    let mut intervals = Vec::new();
    for h in table.as_chunks::<16>().0 {
        let count = u64::from(u32::from_le_bytes(h[4..8].try_into()?));
        if count == 0 {
            continue;
        }
        let hash_len = u64::from(h[8]);
        ensure!((1..=8).contains(&hash_len), "index hash width");
        let mut off = [0u8; 8];
        off[..6].copy_from_slice(&h[10..16]);
        let start = u64::from_le_bytes(off);
        let span = count
            .checked_mul(hash_len + value_size)
            .context("span overflow")?;
        let end = start.checked_add(span).context("offset overflow")?;
        ensure!(
            start >= table_end && end <= size,
            "index bucket outside file"
        );
        intervals.push((start, end));
        entries = entries.checked_add(count).context("entry overflow")?;
    }
    ensure!(entries > 0, "empty index");
    intervals.sort_unstable();
    ensure!(
        intervals.windows(2).all(|w| w[0].1 <= w[1].0),
        "overlapping buckets"
    );
    file.seek(SeekFrom::Start(size - 1))?;
    file.read_exact(&mut [0u8; 1])?;
    Ok(
        json!({"epoch":epoch,"kind":kind,"root_cid":cid,"header_bytes":header_end,"value_size":value_size,"buckets":buckets,"entries":entries,"nonoverlapping_in_bounds_buckets":true}),
    )
}
pub(super) fn inspect(path: &Path, size: u64, epoch: u64, kind: &str, cid: &str) -> Result<Value> {
    let (mut file, id) = open_sealed(path)?;
    ensure!(id["bytes"] == size, "index size differs");
    let result = inspect_file(&mut file, size, epoch, kind, cid)?;
    stable(path, &file, &id)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cid_decoder_binds_both_epochs_and_rejects_noncanonical_encoding() {
        let a = cid_bytes(CID264).unwrap();
        let b = cid_bytes(CID265).unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 36);
        assert!(cid_bytes(&CID265.to_uppercase()).is_err());
        let mut bad = CID265.to_string();
        bad.pop();
        bad.push('v');
        assert!(cid_bytes(&bad).is_err());
    }
    #[test]
    fn metadata_refuses_duplicates_truncation_and_trailing_data() {
        let one = [1, 1, b'k', 1, b'v'];
        assert_eq!(metadata(&one).unwrap().get(b"k".as_slice()).unwrap(), b"v");
        for bad in [
            &[][..],
            &[1, 1, b'k'][..],
            &[0, 0][..],
            &[2, 1, b'k', 1, b'v', 1, b'k', 1, b'v'][..],
        ] {
            assert!(metadata(bad).is_err());
        }
    }
    #[test]
    fn structure_rejects_wrong_epoch_kind_cid_and_bucket_extent() {
        let mut metadata = vec![3];
        for (key, value) in [
            (b"epoch".as_slice(), 265u64.to_le_bytes().to_vec()),
            (b"kind".as_slice(), b"slot-to-cid".to_vec()),
            (b"rootCid".as_slice(), cid_bytes(CID265).unwrap()),
        ] {
            metadata.push(key.len() as u8);
            metadata.extend(key);
            metadata.push(value.len() as u8);
            metadata.extend(value);
        }
        let header_end = 25 + metadata.len();
        let table_end = header_end + 16;
        let mut bytes = b"compiszd".to_vec();
        bytes.extend(((header_end - 12) as u32).to_le_bytes());
        bytes.extend(8u64.to_le_bytes());
        bytes.extend(1u32.to_le_bytes());
        bytes.push(1);
        bytes.extend(metadata);
        bytes.resize(table_end + 16, 0);
        bytes[header_end + 4..header_end + 8].copy_from_slice(&1u32.to_le_bytes());
        bytes[header_end + 8] = 8;
        bytes[header_end + 10..header_end + 16]
            .copy_from_slice(&(table_end as u64).to_le_bytes()[..6]);
        let p = std::env::temp_dir().join(format!(
            "horizon265-index-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&p)
            .unwrap();
        fs::remove_file(&p).unwrap();
        f.write_all(&bytes).unwrap();
        for (epoch, kind, cid, valid) in [
            (265, "slot-to-cid", CID265, true),
            (264, "slot-to-cid", CID265, false),
            (265, "cid-to-offset-and-size", CID265, false),
            (265, "slot-to-cid", CID264, false),
        ] {
            f.rewind().unwrap();
            assert_eq!(
                inspect_file(&mut f, bytes.len() as u64, epoch, kind, cid).is_ok(),
                valid
            );
        }
        f.seek(SeekFrom::Start((header_end + 10) as u64)).unwrap();
        f.write_all(&((table_end + 1) as u64).to_le_bytes()[..6])
            .unwrap();
        f.rewind().unwrap();
        assert!(inspect_file(&mut f, bytes.len() as u64, 265, "slot-to-cid", CID265).is_err());
    }
}
