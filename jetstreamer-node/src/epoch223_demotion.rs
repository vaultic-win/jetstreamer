//! Exact private diagnostic. No ordinary registry entry or publication gate.
use crate::{
    BankHashExpectation, QualificationPlan, ReadyEntry, compatibility as c, historical as h,
};
use solana_hash::Hash;
use std::{
    collections::BTreeMap,
    ops::Range,
    path::Path,
    sync::{Mutex, OnceLock},
};
pub(crate) const BOOTSTRAP: u64 = 96_335_538;
const FIRST: u64 = 96_336_000;
pub(crate) const END: u64 = 96_544_588;
pub(crate) const BACKEND: &str = "solana-v1.6.20-epoch223-called-program-demotion-candidate";
// Independently captured production build from frozen source 551728fd.
const WORKER_SHA: &str = "0f8cc22ad76365f4feb1ef328ce77babbb5242a9b5edb38e9bd076528bc530c0";
const SNAPSHOT_SHA: &str = "301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665";
const SNAPSHOT_SIZE: u64 = 9_815_262_303;
const BOOT_ACCOUNTS: &str = "Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE";
const BOOT_BANK: &str = "8LxWwzEvnAvZC6FwgcqFMxeswZD5skZ7zacYhf1eYW1F";
const BANK586: &str = "3PMZX37CYLF9Ay87r1aKREnf1cZoWDLRKXRAMx5TZYso";
const BANK587: &str = "5UsE976GhKUXyUyKG1tUDiN7cT2BPYvKJN7Wx1ptJHm7";
#[cfg(any(
    feature = "epoch223-v1-6-20-prefix-qualification",
    feature = "epoch223-v1-6-25-qualification",
    feature = "epoch224-v1-6-25-qualification",
    feature = "epoch225-v1-6-25-qualification"
))]
compile_error!("private 223 demotion bracket requires an exclusive parent build");
pub(crate) fn planning_report(
    plan: QualificationPlan,
    selection: &c::RuntimeSelection,
) -> serde_json::Value {
    serde_json::json!({"schema":"jetstreamer-private-epoch223-demotion-bracket-preflight-v1",
        "epoch":223,"bootstrap_slot":plan.bootstrap_slot,"terminal_slot":plan.end_inclusive,
        "output_slot_start":plan.output_slot_start,"output_slot_count":END-FIRST+1,
        "runtime_profile":selection.descriptor.identity.name,"worker_sha256":WORKER_SHA,
        "canonical_bootstrap_bound":true,"real_bank_slots_required":[96544586,96544587],
        "original_parent432_and_vote_required":true,"worker_spawned":false,"archive_created":false,
        "native_input_qualified":false,"fresh_resource_admission_passed":false,
        "publication_authorized":false,"runtime_promotion_authorized":false,"r2_mutations":false})
}
#[derive(Default)]
struct Progress {
    initialized: bool,
    bank586: bool,
    bank587: bool,
    parent432: bool,
    vote: bool,
}
static PROGRESS: Mutex<Progress> = Mutex::new(Progress {
    initialized: false,
    bank586: false,
    bank587: false,
    parent432: false,
    vote: false,
});
pub(crate) fn digest(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || s.bytes().all(|b| b == b'0')
    {
        return Err("private 223 requires exact nonzero lowercase SHA256".into());
    }
    let mut out = [0; 32];
    for (i, pair) in s.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).map_err(|e| e.to_string())?, 16)
            .map_err(|e| e.to_string())?;
    }
    Ok(out)
}
pub(crate) fn validate_worker_digest(actual: [u8; 32]) -> Result<(), String> {
    if actual != digest(WORKER_SHA)? {
        return Err("private demotion worker digest differs before executable spawn".into());
    }
    Ok(())
}
pub(crate) fn selected(range: &Range<u64>) -> bool {
    range.end == END + 1 && [BOOTSTRAP + 1, FIRST].contains(&range.start)
}
pub(crate) fn is_candidate(client: &h::HistoricalRuntimeClient) -> bool {
    digest(WORKER_SHA).is_ok_and(|sha| sha == client.executable_sha256())
}
pub(crate) fn active() -> bool {
    // Poisoning remains fail-closed at each operation; this discriminator
    // merely leaves unrelated source-unit test sessions on their old path.
    PROGRESS.lock().map_or(true, |p| p.initialized)
}
pub(crate) fn exact(plan: QualificationPlan) -> bool {
    (
        plan.epoch,
        plan.bootstrap_slot,
        plan.replay_start,
        plan.output_slot_start,
        plan.end_inclusive,
    ) == (223, BOOTSTRAP, BOOTSTRAP + 1, FIRST, END)
}
pub(crate) fn entrypoint(args: &[String]) -> Result<(), String> {
    let comparison = args.iter().any(|a| a == "--epoch223-tail-comparison");
    if !matches!(args.first().map(String::as_str), Some("223" | "223-223"))
        || !comparison
        || args.iter().any(|a| a == "--epoch223-prefix-preflight")
    {
        return Err("private demotion parent requires explicit 223 diagnostic comparison; no ordinary entrypoints".into());
    }
    digest(WORKER_SHA)?;
    Ok(())
}
pub(crate) fn select(
    range: Range<u64>,
    focused: bool,
    allow: bool,
) -> Result<c::RuntimeSelection, String> {
    if !focused || !allow || range.end != END + 1 || ![BOOTSTRAP + 1, FIRST].contains(&range.start)
    {
        return Err("private demotion route accepts only exact cold-to-failed-Vote bracket".into());
    }
    static DESCRIPTOR: OnceLock<c::RuntimeDescriptor> = OnceLock::new();
    let descriptor=DESCRIPTOR.get_or_init(|| {
        let mut d=c::SOLANA_V1_6_20_RUNTIME;
        d.identity.name=BACKEND;
        d.worker=Some(c::WorkerExecutable {
            identity:"jetstreamer-historical-worker-v1-6-20",
            environment_override:"JETSTREAMER_HISTORICAL_WORKER_EPOCH223_DEMOTION",
            // Never fall back to an ordinary target or worker generation.
            default_manifest_relative_path:"/nonexistent/private-epoch223-demotion-worker-requires-explicit-binding",
        });
        d
    });
    Ok(c::RuntimeSelection {
        backend: c::RuntimeBackend::SolanaV1_6_20,
        descriptor,
        admission: c::AdmissionLevel::Candidate,
    })
}
pub(crate) fn worker_profile(d: &c::RuntimeDescriptor) -> Result<h::WorkerProfile, String> {
    if d.identity.name != BACKEND
        || d.identity.revision != c::SOLANA_V1_6_20_REVISION
        || d.worker.is_none_or(|w| {
            w.environment_override != "JETSTREAMER_HISTORICAL_WORKER_EPOCH223_DEMOTION"
        })
    {
        return Err("private 223 descriptor differs from exact semantic candidate".into());
    }
    Ok(h::WorkerProfile {
        backend_id: BACKEND,
        ..h::SOLANA_V1_6_20_CANDIDATE
    })
}
pub(crate) fn launch(
    first: u64,
    last: u64,
    focused: Option<(u64, u64)>,
    cohort: bool,
    recovery: bool,
    paths: Option<(&Path, &Path, &Path)>,
) -> Result<(), String> {
    if first != 223 || last != 223 || focused != Some((BOOTSTRAP, END)) || cohort || recovery {
        return Err(
            "private demotion bracket rejects cohorts, recovery, other spans and inherited work"
                .into(),
        );
    }
    let (ledger, output, scratch) = paths.ok_or("explicit private bracket paths required")?;
    let root = ledger.parent().ok_or("missing bracket root")?;
    let valid_name = root
        .file_name()
        .and_then(|s| s.to_str())
        .and_then(|s| s.strip_prefix("qualification-223-demotion-bracket-"))
        .is_some_and(|s| {
            !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if !valid_name
        || root.parent() != Some(Path::new("/home/ubuntu/.jetstreamer-private"))
        || ledger != root.join("ledger")
        || output != root.join("output/epoch-223.jet")
        || scratch != root.join("scratch")
    {
        return Err("private demotion bracket requires its own exact namespace".into());
    }
    Ok(())
}
pub(crate) fn tail_mode(
    enabled: bool,
    _preflight: bool,
    focused: Option<(u64, u64)>,
    ledger: &Path,
) -> Result<(), String> {
    if !enabled || focused != Some((BOOTSTRAP, END)) {
        return Err("private demotion requires explicit exact bracket comparison".into());
    }
    let root = ledger.parent().ok_or("missing root")?;
    launch(
        223,
        223,
        focused,
        false,
        false,
        Some((
            ledger,
            &root.join("output/epoch-223.jet"),
            &root.join("scratch"),
        )),
    )
}
pub(crate) fn expectations(
    mut expected: BTreeMap<u64, BankHashExpectation>,
    plan: QualificationPlan,
    snapshot: &Path,
    bootstrap: c::BootstrapState,
) -> Result<BTreeMap<u64, BankHashExpectation>, String> {
    if !exact(plan) {
        return Err("private bracket expectation span differs".into());
    }
    let (slot, value) = crate::snapshot_path_expectation(snapshot, bootstrap)?;
    let known =
        BankHashExpectation::LegacyAccountsHash(BOOT_ACCOUNTS.parse().map_err(|e| format!("{e}"))?);
    if slot != BOOTSTRAP
        || value != known
        || expected.get(&slot) != Some(&known)
        || expected.range(BOOTSTRAP + 1..=END).next().is_some()
    {
        return Err("bracket retains exact bootstrap; do not invent intermediate or terminal accounts hashes".into());
    }
    expected.retain(|slot, _| *slot == BOOTSTRAP);
    Ok(expected)
}
pub(crate) fn bind_initialization(
    mut init: h::HistoricalInitialization,
) -> Result<h::HistoricalInitialization, String> {
    match &mut init {
        h::HistoricalInitialization::SnapshotArchive(s)
            if s.expected_slot == BOOTSTRAP
                && Hash::new_from_array(s.expected_accounts_hash).to_string() == BOOT_ACCOUNTS =>
        {
            s.expected_archive_sha256 = Some(digest(SNAPSHOT_SHA)?);
            s.expected_archive_size = Some(SNAPSHOT_SIZE);
        }
        _ => return Err("private bracket requires exact digest-bound canonical cold input".into()),
    }
    Ok(init)
}
pub(crate) fn initialize(client: &mut h::HistoricalRuntimeClient) -> Result<(), String> {
    if client.executable_sha256() != digest(WORKER_SHA)? || client.initialized().slot != BOOTSTRAP {
        return Err("private bracket live bound worker/input mismatch".into());
    }
    let cp = client
        .freeze_checkpoint(BOOTSTRAP)
        .map_err(|e| e.to_string())?;
    if !cp.slot_complete
        || !cp.writes.is_empty()
        || Hash::new_from_array(cp.bank_hash).to_string() != BOOT_BANK
        || Hash::new_from_array(cp.accounts_hash).to_string() != BOOT_ACCOUNTS
        || Hash::new_from_array(cp.last_blockhash).to_string()
            != "9cdE7Epzr7jcLCz8Ke2Lndf8DBqb3DJmxedKaKuCJHaa"
        || cp.capitalization != 503_889_539_326_183_230
        || cp.transaction_count != 27_822_879_094
        || cp.tick_height != 6_165_474_496
        || cp.next_write_version != 105_933_183_112
    {
        return Err(
            "private bracket cold native consensus tuple differs before first entry".into(),
        );
    }
    let mut p = PROGRESS.lock().map_err(|_| "bracket progress poisoned")?;
    if p.initialized {
        return Err("private bracket cannot reuse initialized session".into());
    }
    p.initialized = true;
    log::info!(
        "epoch223 demotion cold input verified worker_sha256={WORKER_SHA} slot={BOOTSTRAP} replay_entries=0 bootstrap_writes=0"
    );
    Ok(())
}
pub(crate) fn checkpoint(cp: &h::HistoricalCheckpoint) -> Result<(), String> {
    let mut p = PROGRESS.lock().map_err(|_| "bracket progress poisoned")?;
    if !p.initialized {
        return Err("bracket checkpoint lacks genuine initialized worker".into());
    }
    match cp.slot {
        96_544_586 | 96_544_587 => {
            let expected = if cp.slot == 96_544_586 {
                BANK586
            } else {
                BANK587
            };
            if !cp.slot_complete
                || Hash::new_from_array(cp.bank_hash).to_string() != expected
                || (cp.slot == 96_544_587 && !p.bank586)
            {
                return Err("private bracket actual canonical Bank comparison failed".into());
            }
            if cp.slot == 96_544_586 {
                p.bank586 = true;
            } else {
                p.bank587 = true;
            }
            log::info!(
                "epoch223 demotion real Bank verified slot={} bank_hash={expected}",
                cp.slot
            );
        }
        END => {
            if !cp.slot_complete || !(p.bank586 && p.bank587 && p.parent432 && p.vote) {
                return Err(
                    "private bracket terminal lacks both real Banks and exact successful wires"
                        .into(),
                );
            }
            log::info!(
                "epoch223 demotion bracket verified terminal={END} complete=true publication_authorized=false"
            );
        }
        _ => {}
    }
    Ok(())
}
pub(crate) fn outcomes(
    entry: &ReadyEntry,
    results: &[h::HistoricalTransactionOutcome],
) -> Result<(), String> {
    if ![96_544_587, END].contains(&entry.slot) {
        return Ok(());
    }
    let mut p = PROGRESS.lock().map_err(|_| "bracket progress poisoned")?;
    for (offset, (tx, result)) in entry.txs.iter().zip(results).enumerate() {
        let index = entry.start_index + offset;
        let expected: &[u8] = match (entry.slot, index) {
            (96_544_587, 432) => include_bytes!(
                "../../historical-runtime/fixtures/epoch223-parent96544587-tx432.bin"
            ),
            (END, 0) => include_bytes!(
                "../../historical-runtime/fixtures/epoch223-failing96544588-vote.bin"
            ),
            _ => continue,
        };
        if !p.initialized
            || tx.expected_status.as_ref() != Some(&Ok(()))
            || result.error.is_some()
            || bincode::serialize(&tx.tx).map_err(|e| e.to_string())? != expected
        {
            return Err("private bracket exact wire must have canonical observed success and native success".into());
        }
        if entry.slot == END {
            if entry.entry_index != 4 || !p.bank586 || !p.bank587 || !p.parent432 {
                return Err(
                    "private bracket Vote arrived without canonical predecessor evidence".into(),
                );
            }
            p.vote = true;
        } else {
            p.parent432 = true;
        }
        log::info!(
            "epoch223 demotion exact native wire success slot={} transaction_index={index}",
            entry.slot
        );
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_wires_roundtrip_through_current_parent_types() {
        for wire in [
            &include_bytes!("../../historical-runtime/fixtures/epoch223-parent96544587-tx432.bin")
                [..],
            &include_bytes!("../../historical-runtime/fixtures/epoch223-failing96544588-vote.bin")
                [..],
        ] {
            let tx: solana_transaction::versioned::VersionedTransaction =
                bincode::deserialize(wire).unwrap();
            assert_eq!(bincode::serialize(&tx).unwrap().as_slice(), wire);
        }
    }
    #[test]
    fn digest_binding_rejects_placeholders_and_uppercase() {
        assert!(digest(&"0".repeat(64)).is_err());
        assert!(digest(&"A".repeat(64)).is_err());
        assert_eq!(digest(&"ab".repeat(32)).unwrap(), [0xab; 32]);
    }
    #[test]
    fn route_is_exact_and_requires_focused_candidate() {
        for (r, f, a, ok) in [
            (BOOTSTRAP + 1..END + 1, true, true, true),
            (FIRST..END + 1, true, true, true),
            (FIRST..END + 2, true, true, false),
            (FIRST..END + 1, false, true, false),
            (FIRST..END + 1, true, false, false),
        ] {
            assert_eq!(select(r, f, a).is_ok(), ok);
        }
        assert_ne!(c::SOLANA_V1_6_20_RUNTIME.identity.name, BACKEND);
        assert!(worker_profile(&c::SOLANA_V1_6_20_RUNTIME).is_err());
    }
    #[test]
    fn bracket_cannot_reuse_prefix_namespace_or_expand_to_root() {
        let root = Path::new(
            "/home/ubuntu/.jetstreamer-private/qualification-223-demotion-bracket-source-test",
        );
        let ledger = root.join("ledger");
        let output = root.join("output/epoch-223.jet");
        let scratch = root.join("scratch");
        assert!(
            launch(
                223,
                223,
                Some((BOOTSTRAP, END)),
                false,
                false,
                Some((&ledger, &output, &scratch))
            )
            .is_ok()
        );
        assert!(
            launch(
                223,
                223,
                Some((BOOTSTRAP, 96_767_522)),
                false,
                false,
                Some((&ledger, &output, &scratch))
            )
            .is_err()
        );
        assert!(
            launch(
                223,
                223,
                Some((BOOTSTRAP, END)),
                true,
                false,
                Some((&ledger, &output, &scratch))
            )
            .is_err()
        );
        assert!(
            launch(
                223,
                223,
                Some((BOOTSTRAP, END)),
                false,
                true,
                Some((&ledger, &output, &scratch))
            )
            .is_err()
        );
    }
    #[test]
    fn comparison_never_invents_terminal_accounts_hash() {
        let p = QualificationPlan {
            epoch: 223,
            bootstrap_slot: BOOTSTRAP,
            replay_start: BOOTSTRAP + 1,
            output_slot_start: FIRST,
            end_inclusive: END,
        };
        let snapshot = Path::new(
            "/var/lib/jetstreamer/horizon-223-known-root-prefix-b1670f57-v1/snapshot-96335538-Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE.tar.zst",
        );
        let known = BankHashExpectation::LegacyAccountsHash(BOOT_ACCOUNTS.parse().unwrap());
        let good = BTreeMap::from([(BOOTSTRAP, known)]);
        let bootstrap = c::SOLANA_V1_6_20_RUNTIME.bootstrap;
        assert!(expectations(good.clone(), p, snapshot, bootstrap).is_ok());
        let mut invented = good;
        invented.insert(END, known);
        assert!(expectations(invented, p, snapshot, bootstrap).is_err());
    }
}
