//! Exact typed/native clock bindings for a private first-target diagnostic.
use super::{
    epoch141_acquired_input::{Bound, read},
    evidence,
};
use anyhow::{Result, ensure};
use serde::Serialize;
use serde_json::Value;
pub(super) const CLOCK_PATH: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch140-serialized-clock-complete-20261020-v1/clock.json";
pub(super) const CLOCK_SHA: &str =
    "f74aacd82655179686a43c6bb137e0c0e7c7bd2955809008a745ef80f16f8be2";
pub(super) const NATIVE_PATH: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch140-native-restore-complete-20261020-v1/native.json";
pub(super) const NATIVE_SHA: &str =
    "53f1aa88f8f5f24aed1e291ff02318c102fac3bfb8ececf5c215c9fb70c11b20";
const SNAPSHOT: &str = "47d5911465901975e397c570e06ccf72296db7ecd3b3b1beda710cacd3e683a1";
const BANK: &[u8] =
    include_bytes!("../../historical-runtime/v1_4_25/vendor/solana-runtime-1.4.25/src/bank.rs");
// Preserve the exact source reviewed with the original typed/native proof.
// Subsequent trace/capped-storage candidates are a separate provenance pin.
const REVIEWED_WORKER: &[u8] =
    include_bytes!("../tests/fixtures/epoch141-clock-reviewed-worker-a6e0d6ab.rs.txt");
// The current source pin includes the prose spacing cleanup. Historical proof
// remains bound to the unchanged reviewed-worker fixture above.
const CURRENT_WORKER: &[u8] =
    include_bytes!("../../historical-runtime/v1_4_25/worker/src/runtime.rs");
#[derive(Debug, Serialize)]
pub(super) struct ClockBindings {
    pub(super) snapshot_slot: u64,
    pub(super) ticks_per_slot: u64,
    pub(super) hashes_per_tick: u64,
    pub(super) bank_source_sha256: String,
    pub(super) worker_runtime_source_sha256: String,
    pub(super) current_worker_runtime_source_sha256: String,
    pub(super) diagnostic_only: bool,
}
fn validate(c: &Value, n: &Value) -> Result<ClockBindings> {
    ensure!(
        c["schema"] == "jetstreamer-epoch140-serialized-snapshot-clock-v1"
            && c["self_sha256"]
                == "9c04f3381e008705be100aa4d2bf4d55d55aadac45d9636ed177019289fb70dd"
            && c["layout_source_sha256"]
                == "4baee9ce91616985b8872b6f77fc3358cce5ca44ef95a7d337d235598d7148db"
            && c["input_sha256"] == SNAPSHOT
            && c["pinned_typed_serialized_clock_only"] == true
            && c["census"]["clock"]["slot"] == 60911751
            && c["census"]["clock"]["complete"] == true
            && c["census"]["clock"]["ticks_per_slot"] == 64
            && c["census"]["clock"]["hashes_per_tick"] == 12500,
        "not exact typed snapshot clock"
    );
    ensure!(
        n["schema"] == "jetstreamer-private-epoch140-native-restore-probe-v1"
            && n["passed"] == true
            && n["native_result"]["comparison_passed"] == true
            && n["native_result"]["shutdown_passed"] == true
            && n["serialized_clock_sha256"] == CLOCK_SHA
            && n["snapshot_sha256"] == SNAPSHOT
            && n["worker_sha256"]
                == "abe395d482174e490833928c7343a33d135d8572096faf873ce3103c35fe520d"
            && n["self_sha256"]
                == "c8ccd1086dca6a288284fb7bc11387400d3f34cac643baa579b1b0db42f3dcf5"
            && n["replay_entries_sent"] == 0
            && n["native_result"]["replay_entries_sent"] == 0
            && n["native_consensus_comparison_only"] == true
            && n["executing_suffix_must_repeat_native_tuple_check"] == true,
        "not exact native clock comparison"
    );
    let k = &n["native_result"]["native_checkpoint"];
    let clock = &c["census"]["clock"];
    for (left, right) in [
        ("slot", "slot"),
        ("bank_hash", "bank_hash"),
        ("last_blockhash", "last_blockhash"),
        ("capitalization", "capitalization"),
        ("transaction_count", "transaction_count"),
        ("tick_height", "tick_height"),
        ("initialized_ticks_per_slot", "ticks_per_slot"),
        ("slot_complete", "complete"),
    ] {
        ensure!(
            !k[left].is_null() && k[left] == clock[right],
            "native/typed clock differs:{left}"
        );
    }
    for key in [
        "accounts_restored",
        "archive_modified",
        "native_bank_restored",
        "native_checkpoint_match_proven",
        "poh_recovery_authorized",
        "publication_authorized",
        "r2_mutations",
        "remote_mutations",
        "replay_launch_authorized",
        "snapshot_extracted",
    ] {
        ensure!(c[key] == false, "clock acquired authority:{key}");
    }
    for key in [
        "archive_prefix_verified",
        "assembly_authorized",
        "local_retirement_authorized",
        "prefix_manifest_created",
        "publication_authorized",
        "r2_mutations",
        "remote_mutations",
        "replay_launch_authorized",
        "suffix_generated",
    ] {
        ensure!(n[key] == false, "native probe acquired authority:{key}");
    }
    let bank = evidence::sha(BANK);
    let worker = evidence::sha(REVIEWED_WORKER);
    let current_worker = evidence::sha(CURRENT_WORKER);
    ensure!(
        bank == "f136ec6b4d40bced37936df1800cc7f2d64484a0640d76edb2839dd04599d4ac"
            && worker == "ae01b0813fa1564511e450acc693941268076659e4d741aae085fb288d0fd2ac"
            && current_worker == "1b4dc1c973d67707596b2971ddd9c2027038ce8845d4e75db09b7f045a21c5f5",
        "reviewed clock inheritance source changed"
    );
    let bank_text = std::str::from_utf8(BANK)?;
    let worker_text = std::str::from_utf8(REVIEWED_WORKER)?;
    let current_worker_text = std::str::from_utf8(CURRENT_WORKER)?;
    ensure!(
        bank_text.contains("hashes_per_tick: parent.hashes_per_tick,")
            && bank_text.contains("ticks_per_slot: parent.ticks_per_slot,")
            && !worker_text.contains(".set_hashes_per_tick(")
            && !current_worker_text.contains(".set_hashes_per_tick("),
        "clock inheritance differs"
    );
    Ok(ClockBindings {
        snapshot_slot: 60911751,
        ticks_per_slot: 64,
        hashes_per_tick: 12500,
        bank_source_sha256: bank,
        worker_runtime_source_sha256: worker,
        current_worker_runtime_source_sha256: current_worker,
        diagnostic_only: true,
    })
}
pub(super) fn load(clock: &Bound, native: &Bound) -> Result<ClockBindings> {
    ensure!(
        clock.path == std::path::Path::new(CLOCK_PATH)
            && clock.sha256 == CLOCK_SHA
            && native.path == std::path::Path::new(NATIVE_PATH)
            && native.sha256 == NATIVE_SHA,
        "foreign clock proof binding"
    );
    validate(&read(clock, true)?, &read(native, true)?)
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture() -> (Value, Value) {
        let c = json!({"schema":"jetstreamer-epoch140-serialized-snapshot-clock-v1","self_sha256":"9c04f3381e008705be100aa4d2bf4d55d55aadac45d9636ed177019289fb70dd","layout_source_sha256":"4baee9ce91616985b8872b6f77fc3358cce5ca44ef95a7d337d235598d7148db","input_sha256":SNAPSHOT,"pinned_typed_serialized_clock_only":true,"census":{"clock":{"slot":60911751,"complete":true,"ticks_per_slot":64,"hashes_per_tick":12500,"bank_hash":"bank","last_blockhash":"last","capitalization":1,"transaction_count":2,"tick_height":3}},"accounts_restored":false,"archive_modified":false,"native_bank_restored":false,"native_checkpoint_match_proven":false,"poh_recovery_authorized":false,"publication_authorized":false,"r2_mutations":false,"remote_mutations":false,"replay_launch_authorized":false,"snapshot_extracted":false});
        let n = json!({"schema":"jetstreamer-private-epoch140-native-restore-probe-v1","passed":true,"serialized_clock_sha256":CLOCK_SHA,"snapshot_sha256":SNAPSHOT,"worker_sha256":"abe395d482174e490833928c7343a33d135d8572096faf873ce3103c35fe520d","self_sha256":"c8ccd1086dca6a288284fb7bc11387400d3f34cac643baa579b1b0db42f3dcf5","replay_entries_sent":0,"native_consensus_comparison_only":true,"executing_suffix_must_repeat_native_tuple_check":true,"native_result":{"comparison_passed":true,"shutdown_passed":true,"replay_entries_sent":0,"native_checkpoint":{"slot":60911751,"slot_complete":true,"initialized_ticks_per_slot":64,"bank_hash":"bank","last_blockhash":"last","capitalization":1,"transaction_count":2,"tick_height":3}},"archive_prefix_verified":false,"assembly_authorized":false,"local_retirement_authorized":false,"prefix_manifest_created":false,"publication_authorized":false,"r2_mutations":false,"remote_mutations":false,"replay_launch_authorized":false,"suffix_generated":false});
        (c, n)
    }
    #[test]
    fn clock_is_independent_not_fitted_to_observed_hash_work() {
        let (c, n) = fixture();
        let bindings = validate(&c, &n).unwrap();
        assert_eq!(
            bindings.worker_runtime_source_sha256,
            "ae01b0813fa1564511e450acc693941268076659e4d741aae085fb288d0fd2ac"
        );
        assert_eq!(
            bindings.current_worker_runtime_source_sha256,
            "1b4dc1c973d67707596b2971ddd9c2027038ce8845d4e75db09b7f045a21c5f5"
        );
        for (pointer, value) in [
            ("/census/clock/hashes_per_tick", json!(1)),
            ("/census/clock/ticks_per_slot", json!(32)),
            ("/census/clock/complete", json!(false)),
            ("/census/clock/bank_hash", json!("other")),
            ("/input_sha256", json!(CLOCK_SHA)),
            ("/poh_recovery_authorized", json!(true)),
        ] {
            let mut changed = c.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(validate(&changed, &n).is_err(), "{pointer}");
        }
        for (pointer, value) in [
            ("/passed", json!(false)),
            ("/worker_sha256", json!(CLOCK_SHA)),
            ("/native_result/shutdown_passed", json!(false)),
            ("/native_result/native_checkpoint/tick_height", json!(4)),
            ("/publication_authorized", json!(true)),
        ] {
            let mut changed = n.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(validate(&c, &changed).is_err(), "{pointer}");
        }
    }
}
