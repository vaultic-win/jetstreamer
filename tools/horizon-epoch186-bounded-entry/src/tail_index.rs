//! Repair the two native-proven missing block ranges in the epoch 186 verification tail.
use super::*;
use std::io::Write;

const START: u64 = 80_784_000;
const LAST: u64 = 80_791_699;
const RECORD: usize = 12;
const INDEX_BYTES: usize = 432_000 * RECORD;
const CAR_BYTES: u64 = 158_378_913_826;
const SOURCE_SHA: &str = "5ad5e024f95743986bb2721b143e11786e5d16caf02b11e9e0ad151c5ee7468e";
const NATIVE_SHA: &str = "f5e5eafcf2cd6a27ae4dedd3e459d52fb08abd157a7189962d17badd40ed9a75";
const REPAIRS: [(u64, u64, u32); 2] = [
    (80_786_964, 1_024_855_050, 497_090),
    (80_788_728, 1_650_011_082, 844_278),
];

fn read_bound(path: &Path, maximum: u64, digest: &str) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "indirect tail index input"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file() && before.len() <= maximum,
        "invalid tail index input size"
    );
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file).take(maximum + 1).read_to_end(&mut bytes)?;
    stable(path, &file, &before)?;
    ensure!(
        bytes.len() as u64 == before.len() && format!("{:x}", Sha256::digest(&bytes)) == digest,
        "tail index input digest changed"
    );
    Ok(bytes)
}

fn repair_rows(bytes: &mut [u8]) -> Result<()> {
    ensure!(bytes.len() == INDEX_BYTES, "wrong epoch 187 index length");
    for (slot, _, _) in REPAIRS {
        let at = (slot - START) as usize * RECORD;
        ensure!(
            bytes[at..at + RECORD] == [0; RECORD],
            "repair would overwrite a populated row at slot {slot}"
        );
    }
    for (slot, offset, length) in REPAIRS {
        let at = (slot - START) as usize * RECORD;
        bytes[at..at + 8].copy_from_slice(&offset.to_le_bytes());
        bytes[at + 8..at + RECORD].copy_from_slice(&length.to_le_bytes());
    }
    Ok(())
}

fn verify_tail(bytes: &[u8]) -> Result<()> {
    let mut previous_end = 59;
    let mut present = 0;
    for (index, row) in bytes
        .as_chunks::<RECORD>()
        .0
        .iter()
        .take((LAST - START + 1) as usize)
        .enumerate()
    {
        let offset = u64::from_le_bytes(row[..8].try_into()?);
        let length = u64::from(u32::from_le_bytes(row[8..].try_into()?));
        if offset == 0 && length == 0 {
            continue;
        }
        let end = offset.checked_add(length).context("CAR range overflow")?;
        ensure!(
            length != 0 && offset == previous_end && end <= CAR_BYTES,
            "discontinuous indexed CAR range at slot {}",
            START + index as u64
        );
        previous_end = end;
        present += 1;
    }
    ensure!(
        present == 5_640 && previous_end == 2_702_540_516,
        "changed verification tail coverage"
    );
    Ok(())
}

pub fn repair(index: &Path, native_report: &Path, output: &Path) -> Result<Value> {
    let mut bytes = read_bound(index, INDEX_BYTES as u64, SOURCE_SHA)?;
    read_bound(native_report, 1 << 20, NATIVE_SHA)?;
    repair_rows(&mut bytes)?;
    verify_tail(&bytes)?;
    let parent = output
        .parent()
        .context("missing private index staging directory")?;
    let meta = fs::symlink_metadata(parent)?;
    ensure!(
        parent.starts_with("/home/sol/.jetstreamer-private")
            && parent.canonicalize()? == parent
            && meta.is_dir()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o077 == 0,
        "unsafe tail index staging directory"
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(output)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(json!({
        "schema": "horizon-epoch186-verification-tail-index-repair-v1",
        "source_index": binding(index, SOURCE_SHA),
        "native_car_window_report": binding(native_report, NATIVE_SHA),
        "repaired_index": binding(output, &format!("{:x}", Sha256::digest(&bytes))),
        "validated_inclusive_range": [START, LAST],
        "repaired_slots": REPAIRS.map(|(slot, _, _)| slot),
        "replay_launch_authorized": false,
        "publication_authorized": false
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repair_touches_only_the_two_missing_rows_and_rejects_populated_rows() {
        let mut index = vec![0; INDEX_BYTES];
        repair_rows(&mut index).unwrap();
        for (slot, offset, length) in REPAIRS {
            let at = (slot - START) as usize * RECORD;
            assert_eq!(&index[at..at + 8], &offset.to_le_bytes());
            assert_eq!(&index[at + 8..at + RECORD], &length.to_le_bytes());
        }
        assert_eq!(
            index
                .as_chunks::<RECORD>()
                .0
                .iter()
                .filter(|row| **row != [0; RECORD])
                .count(),
            REPAIRS.len()
        );
        assert!(repair_rows(&mut index).is_err());
    }
}
