//! Apply the root-verified physical row corrections and test the normal Firehose local-index path.
use jetstreamer_firehose::index::{SlotOffsetIndex, SlotOffsetIndexError, get_index_base_url};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    error::Error,
    fs,
    io::{self, Write},
    path::Path,
};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
const FIRST: u64 = 167 * 432_000;
const ORIGINAL: &str = "cf6e016275088a0849d6706b892f2d65dbe7a0641d904105b6878ff9ba3524b7";
const PROOFS: &str = "8301da313f63e66a23f76ab94f6a22bec0f1e58f4cf4515a92dbe360c3dd3a38";
const CANDIDATE: &str = "379692ca3092bcbdd29c968606dc72cf6703a7e41a8c4a774ee4540ba51d9cf7";
const FOOTER: u64 = 141_829_223_419;
type Row = (u64, u32);
fn digest(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}
fn prepared(original: &Path, proofs: &Path) -> Result<(Vec<u8>, BTreeMap<u64, Row>)> {
    let mut output = fs::read(original)?;
    let proof = fs::read(proofs)?;
    if output.len() != 432_000 * 12 || digest(&output) != ORIGINAL || digest(&proof) != PROOFS {
        return Err("original or native evidence changed".into());
    }
    let mut checked = BTreeMap::new();
    for line in std::str::from_utf8(&proof)?
        .lines()
        .filter(|s| !s.starts_with("root="))
    {
        let cells: [&str; 7] = line
            .split('\t')
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| "expected seven native fields")?;
        let [slot, old_start, old_len, start, len, _, _] = cells;
        let slot: u64 = slot.parse()?;
        let idx = usize::try_from(slot.checked_sub(FIRST).ok_or("slot before epoch")?)?;
        let position = idx.checked_mul(12).ok_or("row overflow")?;
        let row = output
            .get_mut(position..position + 12)
            .ok_or("slot after epoch")?;
        if u64::from_le_bytes(row[..8].try_into()?) != old_start.parse::<u64>()?
            || u32::from_le_bytes(row[8..].try_into()?) != old_len.parse::<u32>()?
        {
            return Err("source row differs from native proof".into());
        }
        let corrected: Row = (start.parse()?, len.parse()?);
        if checked.insert(slot, corrected).is_some() {
            return Err("duplicate proof slot".into());
        }
        row[..8].copy_from_slice(&corrected.0.to_le_bytes());
        row[8..].copy_from_slice(&corrected.1.to_le_bytes());
    }
    let mut next = 59_u64;
    for row in output.chunks_exact(12) {
        let offset = u64::from_le_bytes(row[..8].try_into()?);
        let length = u32::from_le_bytes(row[8..].try_into()?);
        if length == 0 && offset == 0 {
            continue;
        }
        if length == 0 || offset != next {
            return Err("candidate has noncanonical empty row or discontinuity".into());
        }
        next = next
            .checked_add(u64::from(length))
            .ok_or("candidate extent overflow")?;
    }
    if next != FOOTER || digest(&output) != CANDIDATE {
        return Err("candidate footer boundary or digest differs".into());
    }
    Ok((output, checked))
}
async fn lookup(output: &[u8], proof_rows: usize) -> Result<()> {
    if env::var_os("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST").is_none()
        || env::var_os("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256").is_none()
        || env::var_os("JETSTREAMER_FORCE_LEGACY_INDEX").is_some()
    {
        return Err("expected pinned local manifest and normal slot ranges lookup".into());
    }
    let base = get_index_base_url()?;
    if base.as_str() != "https://files.old-faithful.net/" {
        return Err("unexpected index origin".into());
    }
    let index = SlotOffsetIndex::new(base)?;
    for _ in 0..2 {
        index.invalidate_epoch(167);
        for (idx, row) in output.chunks_exact(12).enumerate() {
            let slot = FIRST + u64::try_from(idx)?;
            let start = u64::from_le_bytes(row[..8].try_into()?);
            let len = u32::from_le_bytes(row[8..].try_into()?);
            match index.get_range(slot).await {
                Ok(got) if len != 0 && got == (start, u64::from(len)) => {}
                Err(SlotOffsetIndexError::SlotNotFound(missing, url))
                    if len == 0 && missing == slot && url.scheme() == "file" => {}
                res => return Err(format!("slot {slot} lookup mismatch: {res:?}").into()),
            }
        }
    }
    println!(
        "epoch=167 digest={CANDIDATE} proof_rows={proof_rows} epoch_rows={} reloads=2",
        output.len() / 12
    );
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.len() != 3 {
        return Err("usage: epoch167-index-reuse emit|lookup ORIGINAL NATIVE_PROOFS".into());
    }
    let (output, checked) = prepared(Path::new(&args[1]), Path::new(&args[2]))?;
    if args[0] == "emit" {
        io::stdout().lock().write_all(&output)?;
    } else if args[0] == "lookup" {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(lookup(&output, checked.len()))?;
    } else {
        return Err("expected emit or lookup".into());
    }
    Ok(())
}
