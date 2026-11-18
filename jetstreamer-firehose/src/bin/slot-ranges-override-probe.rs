//! Read-only qualification of digest-pinned local slot-ranges indexes.
use jetstreamer_firehose::index::{SlotOffsetIndex, get_index_base_url};
use std::{env, error::Error};

fn main() -> Result<(), Box<dyn Error>> {
    if env::var_os("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST").is_none()
        || env::var_os("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256").is_none()
    {
        return Err("a digest-pinned local override manifest is required".into());
    }
    if env::var_os("JETSTREAMER_FORCE_LEGACY_INDEX").is_some() {
        return Err("forced legacy indexes are incompatible with this probe".into());
    }
    let base = get_index_base_url()?;
    if base.as_str() != "https://files.old-faithful.net/" {
        return Err("expected exact Old Faithful source URL".into());
    }
    let slots: Vec<u64> = env::args()
        .skip(1)
        .map(|arg| arg.parse::<u64>())
        .collect::<Result<_, _>>()?;
    if slots.is_empty()
        || slots.len() > 32
        || slots
            .iter()
            .any(|slot| !(109_296_000..=110_591_999).contains(slot))
    {
        return Err("expected 1 to 32 slots from epochs 253 through 255".into());
    }
    let index = SlotOffsetIndex::new(base)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        for slot in slots {
            let (offset, length) = index.get_range(slot).await?;
            println!("{slot}\t{offset}\t{length}");
        }
        Ok::<_, Box<dyn Error>>(())
    })?;
    Ok(())
}
