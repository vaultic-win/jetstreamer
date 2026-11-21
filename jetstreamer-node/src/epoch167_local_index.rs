//! Optional startup binding for the repaired epoch 167 Firehose source index.
use jetstreamer_firehose::index::{
    SlotOffsetIndex, SlotOffsetIndexError, get_index_base_url, slot_to_range,
};
use std::env;

const MANIFEST: &str = "8d0bb4e330a3d6d9c3c014e63df99069856af6298de43a319ef710021b88a7b2";
const INDEX: &str = "379692ca3092bcbdd29c968606dc72cf6703a7e41a8c4a774ee4540ba51d9cf7";

pub(super) async fn verify() -> Result<(), String> {
    if env::var_os("JETSTREAMER_FORCE_LEGACY_INDEX").is_some() {
        return Err("forced legacy indexing is incompatible with the pinned 167 source".into());
    }
    if env::var("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256").as_deref() != Ok(MANIFEST) {
        return Err("expected the qualified epoch 167 manifest digest".into());
    }
    // Construct through the native manifest parser first so bad configuration
    // produces an error before the replay singleton's lazy initialization.
    let validated = SlotOffsetIndex::new(get_index_base_url().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    validated.invalidate_epoch(167);
    match validated.get_range(72_195_172).await {
        Err(SlotOffsetIndexError::SlotNotFound(72_195_172, url)) if url.scheme() == "file" => {}
        other => return Err(format!("local missing-slot proof differs: {other:?}")),
    }
    // The replay reader seeks via this same global lookup. Force a second load
    // so a populated result cache cannot satisfy the startup binding.
    validated.invalidate_epoch(167);
    for (slot, expected) in [
        (72_195_176, (17_577_007_956, 363_395)),
        (72_257_922, (35_176_867_917, 445_507)),
        (72_257_923, (35_177_313_424, 539_295)),
    ] {
        let got = slot_to_range(slot).await.map_err(|e| e.to_string())?;
        if got != expected {
            return Err(format!(
                "slot {slot} range is {got:?}, expected {expected:?}"
            ));
        }
    }
    log::info!(
        "verified epoch 167 local slot ranges via replay lookup: index_sha256={INDEX} manifest_sha256={MANIFEST}"
    );
    Ok(())
}
