//! Fixed private suffix plus descendant-checkpoint qualification on the normal v1.4.25 worker.
use crate::{BankHashExpectation, Hash, QualificationPlan, SlotExecutionBuffer};
use jetstreamer_firehose::{
    archive,
    index::{SlotOffsetIndex, SlotOffsetIndexError, get_index_base_url, slot_to_range},
};
use std::{collections::BTreeMap, env, path::Path, sync::OnceLock};

const BOOT: u64 = 61_328_765;
const END: u64 = 61_343_999;
const ROOT: u64 = 61_414_189;
const MANIFEST: &str = "843e0a479dcd3f7634f026ab8f0f4857fb52778e1769059397c972e605d6078c";
const SNAPSHOT: &str = "snapshot-61328765-8LfMXtdKmPEvMcBzEz2XZ56HZ8pUPGSaWGA6mYG4dAFY.tar.zst";
const REQUIRED_ROOTS: [(u64, &str); 2] = [
    (BOOT, "8LfMXtdKmPEvMcBzEz2XZ56HZ8pUPGSaWGA6mYG4dAFY"),
    (ROOT, "3Nqh4AvG4B3K51pDWbzfFA7CHKbztYuuMZDZDzqpY5Mh"),
];
static PRESENT: OnceLock<Vec<bool>> = OnceLock::new();

pub(super) fn active() -> bool {
    PRESENT.get().is_some()
}
fn validate_roots(expected: &BTreeMap<u64, BankHashExpectation>) -> Result<(), String> {
    for (slot, hash) in REQUIRED_ROOTS {
        if !matches!(expected.get(&slot),Some(BankHashExpectation::LegacyAccountsHash(actual)) if actual.to_string() == hash)
        {
            return Err(format!(
                "epoch 141 suffix requires its independently trusted accounts hash at {slot}"
            ));
        }
    }
    Ok(())
}
pub(super) fn recheck_roots(expected: &BTreeMap<u64, BankHashExpectation>) -> Result<(), String> {
    if active() {
        validate_roots(expected)
    } else {
        Ok(())
    }
}
pub(super) async fn configure(
    plan: Option<QualificationPlan>,
    forbidden: bool,
    snapshot: Option<&Path>,
    hashes: Option<&Path>,
    dest: &Path,
    output: Option<&Path>,
    scratch: Option<&Path>,
) -> Result<(), String> {
    let required = QualificationPlan {
        epoch: 141,
        bootstrap_slot: BOOT,
        replay_start: BOOT + 1,
        output_slot_start: BOOT + 1,
        end_inclusive: ROOT,
    };
    if forbidden
        || plan != Some(required)
        || snapshot.and_then(Path::file_name) != Some(SNAPSHOT.as_ref())
    {
        return Err("epoch 141 strict suffix requires the trusted 61328765 snapshot and qualification through 61414189".into());
    }
    let output = output.ok_or("missing private suffix output")?;
    let scratch = scratch.ok_or("missing private suffix scratch")?;
    let private = Path::new("/home/sol/.jetstreamer-private");
    for path in [
        dest,
        scratch,
        output.parent().ok_or("suffix output has no parent")?,
    ] {
        let canonical = path
            .canonicalize()
            .map_err(|e| format!("suffix private directory {}: {e}", path.display()))?;
        if !canonical.is_dir()
            || canonical != path
            || !canonical.starts_with(private)
            || canonical == private
        {
            return Err(format!(
                "suffix paths must be real private directories: {}",
                path.display()
            ));
        }
    }
    if output.file_name() != Some("epoch141-suffix-through-checkpoint-61414189.jet".as_ref())
        || output.try_exists().map_err(|e| e.to_string())?
        || output.is_symlink()
    {
        return Err("epoch 141 suffix needs a fresh private epoch141-suffix-through-checkpoint-61414189.jet".into());
    }
    validate_roots(&crate::read_epoch_hashes_file(
        hashes.ok_or("missing canonical roots")?,
        crate::compatibility::SOLANA_V1_4_25_RUNTIME.bootstrap,
    )?)?;
    let worker = crate::configured_historical_worker_executable(
        &crate::compatibility::SOLANA_V1_4_25_RUNTIME,
    )?;
    let sealed = Path::new(
        "/usr/local/lib/jetstreamer/horizon-v1425-corrected-default-candidate-20261023-v1/jetstreamer-historical-worker-v1-4-25",
    );
    if worker != sealed
        || crate::hash_bound_recovery_file(&worker)?
            != crate::parse_lower_sha256(
                "c536dcf360b7866b3aa99e0ff6d7d927dcf5db27bfbbb8f73887eb4bb7d87344",
                "strict worker digest",
            )?
    {
        return Err("expected the sealed strict v1.4.25 worker".into());
    }
    if env::var_os("JETSTREAMER_FORCE_LEGACY_INDEX").is_some()
        || env::var("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256").as_deref() != Ok(MANIFEST)
    {
        return Err(
            "required epoch 141 corrected manifest binding absent or forced legacy set".into(),
        );
    }
    if [archive::car_location(), archive::index_location()]
        .into_iter()
        .any(|location| {
            !location.is_http() || location.url().as_str() != "https://files.old-faithful.net/"
        })
    {
        return Err("epoch 141 requires the qualified Old Faithful CAR and index origin".into());
    }
    let index = SlotOffsetIndex::new(get_index_base_url().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    index.invalidate_epoch(141);
    let mut present = Vec::with_capacity((END - BOOT + 1) as usize);
    for slot in BOOT..=END {
        match slot_to_range(slot).await {
            Ok(_) => present.push(true),
            Err(SlotOffsetIndexError::SlotNotFound(missing, url))
                if missing == slot && url.scheme() == "file" =>
            {
                present.push(false)
            }
            result => return Err(format!("epoch 141 source at {slot}: {result:?}")),
        }
    }
    if !present[0]
        || !present.last().copied().unwrap_or(false)
        || present[1..].iter().filter(|v| **v).count() != 13_183
    {
        return Err("corrected epoch 141 source census differs".into());
    }
    log::info!(
        "verified private epoch 141 suffix source, 13183 blocks through 61343999, strict v1.4.25 replay requires trusted 61414189"
    );
    let path = snapshot.ok_or("missing epoch 141 bootstrap")?;
    let file = jetstreamer_node::archive_checksum::open_regular_nofollow(path)
        .map_err(|e| format!("epoch 141 bootstrap archive {}: {e}", path.display()))?;
    if file.metadata().map_err(|e| e.to_string())?.len() != 4_297_291_805 {
        return Err(
            "epoch 141 bootstrap archive size differs from generation 1634786682225857".into(),
        );
    }
    PRESENT
        .set(present)
        .map_err(|_| "suffix source was already installed")?;
    Ok(())
}

/// The recorder and worker verify parent hashes from the restored Bank forward.
/// Additionally require the corrected source's exact epoch positions at each edge.
pub(super) fn edge(parent: u64, slot: u64) -> Result<(), String> {
    let Some(present) = PRESENT.get() else {
        return Ok(());
    };
    if parent < BOOT || slot <= parent {
        return Err(format!("invalid epoch 141 suffix parent {parent}->{slot}"));
    }
    let marks = |s: u64| present[(s - BOOT) as usize];
    if (parent <= END && !marks(parent))
        || (slot <= END && !marks(slot))
        || (parent + 1..slot.min(END + 1)).any(marks)
    {
        return Err(format!(
            "decoded parent edge {parent}->{slot} differs from corrected epoch 141 source"
        ));
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Anchor {
    pub parent: u64,
    pub last: Hash,
}
impl Anchor {
    pub(super) fn from_source(
        parent: u64,
        slot: u64,
        previous: &str,
        last: &str,
    ) -> Result<Self, String> {
        let last: Hash = last
            .parse()
            .map_err(|e| format!("invalid suffix blockhash: {e}"))?;
        // Both anchors are independent Compact V2 registry values, cross-checked with the CAR.
        if slot == END
            && (parent != END - 1
                || last.to_bytes()
                    != crate::parse_lower_sha256(
                        "4fea1501dea2fcd60eca13fa44f7751c62ead42b70734cd3f93e40d88fc1048b",
                        "terminal blockhash",
                    )?
                || previous
                    .parse::<Hash>()
                    .map_err(|e| e.to_string())?
                    .to_bytes()
                    != crate::parse_lower_sha256(
                        "bdac9d4c59f7ddc3d4550e48fe19a873b2ddc669f20a78b99dbce7d8b671efe6",
                        "terminal parent blockhash",
                    )?)
        {
            return Err("epoch 141 terminal source chain differs from canonical anchors".into());
        }
        Ok(Self { parent, last })
    }
}
pub(super) fn complete(slot: u64, buffer: &SlotExecutionBuffer) -> Result<bool, String> {
    let Some(anchor) = buffer.suffix_anchor else {
        return Ok(false);
    };
    if !buffer.complete_ordered_source(true)? {
        return Ok(false);
    }
    let expected_ticks = slot
        .checked_sub(anchor.parent)
        .and_then(|n| n.checked_mul(64))
        .ok_or("suffix tick height overflow")?;
    let mut ticks = 0u64;
    let mut work = 0u64;
    for entry in &buffer.pending_entries {
        if entry.num_hashes == 0 {
            return Err(format!("zero-work original entry at slot {slot}"));
        }
        work = work
            .checked_add(entry.num_hashes)
            .ok_or("suffix hash work overflow")?;
        if entry.tx_count == 0 {
            if work != 12_500 {
                return Err(format!("original tick work mismatch at slot {slot}"));
            }
            work = 0;
            ticks += 1;
        } else if work >= 12_500 {
            return Err(format!("missing original tick at slot {slot}"));
        }
    }
    if work != 0
        || ticks != expected_ticks
        || buffer
            .pending_entries
            .back()
            .is_none_or(|entry| entry.hash != anchor.last || entry.tx_count != 0)
    {
        return Err(format!(
            "incomplete original ticks or final entry hash at slot {slot}"
        ));
    }
    for (index, source) in buffer.txs.iter().enumerate() {
        let transaction = &source.as_ref().ok_or("incomplete suffix transaction")?.tx;
        transaction
            .sanitize()
            .map_err(|e| format!("invalid original transaction at {slot}/{index}: {e}"))?;
        transaction.verify_and_hash_message().map_err(|e| {
            format!("invalid original transaction signature at {slot}/{index}: {e}")
        })?;
    }
    Ok(true)
}
