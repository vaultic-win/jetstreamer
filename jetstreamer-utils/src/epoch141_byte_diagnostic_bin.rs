//! Exact first-target byte interpretation, never connected recovery or PoH proof.
mod epoch141_acquired_input;
#[allow(dead_code)]
#[path = "epoch141_ledger_common.rs"]
mod evidence;
use anyhow::{Context, Result, ensure};
use epoch141_acquired_input::{
    Bound, Owned, RAW, RAW_SHA, TARGET, TARGET_SHA, decode, read, terminal, validate_acquisition,
};
use jetstreamer_utils::{
    horizon_legacy_byte_diagnostic::diagnose_v1_4_25_acquired_bytes,
    horizon_legacy_recovery::LegacySlotScope,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    acquisition: Bound,
    finalized_target: Bound,
    output: PathBuf,
}
struct Prepared {
    target: Value,
    first: Vec<Owned>,
    records: Vec<Owned>,
    final_hash: [u8; 32],
}
fn validate_plan(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-epoch141-first-target-byte-diagnostic-plan-v1"
            && p.acquisition
                == Bound {
                    path: RAW.into(),
                    sha256: RAW_SHA.into()
                }
            && p.finalized_target
                == Bound {
                    path: TARGET.into(),
                    sha256: TARGET_SHA.into()
                },
        "foreign diagnostic plan"
    );
    ensure!(
        p.output.file_name().is_some_and(|s| s == "diagnostic.json")
            && p.output.parent().is_some_and(|d| d.parent()
                == Some(Path::new("/var/lib/jetstreamer"))
                && d.file_name().is_some_and(|n| n
                    .to_string_lossy()
                    .starts_with("horizon-epoch141-first-target-byte-diagnostic-"))),
        "foreign output namespace"
    );
    Ok(())
}
fn prepare(p: &Plan) -> Result<Prepared> {
    validate_plan(p)?;
    let raw = read(&p.acquisition, true)?;
    validate_acquisition(&raw)?;
    let target = read(&p.finalized_target, false)?;
    ensure!(
        target["schema"] == "jetstreamer-epoch140-finalized-gap-target-v1"
            && target["metadata"]["slot"] == 60911776
            && target["metadata"]["parent_slot"] == 60911771
            && target["hidden_poh_hashes_recovered"] == false
            && target["replay_launch_authorized"] == false
            && target["publication_authorized"] == false
            && target["r2_mutations"] == false,
        "wrong independent finalized target"
    );
    for key in ["request", "response"] {
        let b: Bound = serde_json::from_value(target[key].clone())?;
        read(&b, false)?;
    }
    let hash = bs58::decode(
        target["metadata"]["final_poh_hash"]
            .as_str()
            .context("final hash")?,
    )
    .into_vec()
    .map_err(|e| anyhow::anyhow!("invalid finalized base58 hash:{e}"))?;
    let hash: [u8; 32] = hash
        .try_into()
        .map_err(|_| anyhow::anyhow!("wrong final hash length"))?;
    let first = decode(&raw["first_metadata"], 1)?;
    let records = decode(&raw["records"], 786)?;
    let parent = p.output.parent().unwrap();
    ensure!(
        parent.canonicalize()? == parent,
        "noncanonical output parent"
    );
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(parent)?;
    let m = dir.metadata()?;
    ensure!(
        m.uid() == 0 && m.mode() & 0o777 == 0o700,
        "output parent not root-private"
    );
    Ok(Prepared {
        target,
        first,
        records,
        final_hash: hash,
    })
}
fn run() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    let check = a.len() == 7 && a[6] == "--check-only";
    ensure!(
        (a.len() == 6 || check)
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: byte-diagnostic PLAN --plan-sha256 SHA --self-sha256 SHA [--check-only]"
    );
    evidence::bound_file(&fs::read_link("/proc/self/exe")?, &a[5], 128 << 20, true)?;
    let p: Plan = serde_json::from_slice(&evidence::bound_file(
        Path::new(&a[1]),
        &a[3],
        1 << 20,
        true,
    )?)?;
    let Prepared {
        target,
        first,
        records,
        final_hash: hash,
    } = prepare(&p)?;
    let owner = terminal()?;
    if check {
        println!(
            "first-target byte diagnostic inputs validated; no decode, PoH, writes or recovery"
        );
        return Ok(());
    }
    evidence::write_receipt(
        &p.output.parent().unwrap().join("intent.json"),
        &json!({"schema":"jetstreamer-epoch141-first-target-byte-diagnostic-intent-v1","plan":{"path":a[1],"sha256":a[3]},"tool_sha256":a[5],"acquisition":p.acquisition,"finalized_target":p.finalized_target,"native_terminal":owner,"recorded_is_connected":false,"poh_chain_verified":false,"publication_authorized":false,"r2_mutations":false}),
    )?;
    let first: Vec<_> = first.iter().map(Owned::borrowed).collect();
    let records: Vec<_> = records.iter().map(Owned::borrowed).collect();
    let result = diagnose_v1_4_25_acquired_bytes(
        &first,
        LegacySlotScope {
            slot: 60911776,
            parent_slot: 60911771,
        },
        &records,
        hash,
    );
    ensure!(
        terminal()? == owner,
        "native terminal changed during diagnostic"
    );
    read(&p.acquisition, true)?;
    read(&p.finalized_target, false)?;
    let passed = result
        .as_ref()
        .is_ok_and(|r| r.final_entry_matches_finalized_hash);
    let (diagnostic, error) = match result {
        Ok(r) => (serde_json::to_value(r)?, Value::Null),
        Err(e) => (Value::Null, json!(e)),
    };
    evidence::write_receipt(
        &p.output,
        &json!({"schema":"jetstreamer-epoch141-first-target-byte-diagnostic-v1","epoch":141,"slot":60911776,"parent_slot":60911771,"plan":{"path":a[1],"sha256":a[3]},"tool_sha256":a[5],"acquisition":p.acquisition,"finalized_target":p.finalized_target,"native_terminal":owner,"diagnostic_passed":passed,"diagnostic":diagnostic,"decode_error":error,"expected_final_poh_hash":target["metadata"]["final_poh_hash"],"connected_recovery_route_changed":false,"recovered_target_count":0,"canonical_ancestry_proven":false,"source_completeness_proven":false,"runtime_clock_authenticated":false,"poh_chain_verified":false,"hidden_poh_hashes_recovered":false,"replay_launch_authorized":false,"runtime_promotion_authorized":false,"publication_authorized":false,"retirement_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    File::open(p.output.parent().unwrap())?.sync_all()?;
    ensure!(
        passed,
        "byte diagnostic failed; preserved explicit result:{}",
        p.output.display()
    );
    println!("{}", p.output.display());
    Ok(())
}
fn main() -> Result<()> {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plan_cannot_read_other_raw_targets_or_write_public_outputs() {
        let p=Plan{schema:"jetstreamer-epoch141-first-target-byte-diagnostic-plan-v1".into(),acquisition:Bound{path:RAW.into(),sha256:RAW_SHA.into()},finalized_target:Bound{path:TARGET.into(),sha256:TARGET_SHA.into()},output:"/var/lib/jetstreamer/horizon-epoch141-first-target-byte-diagnostic-test/diagnostic.json".into()};
        validate_plan(&p).unwrap();
        let mut p = p;
        p.output = "/home/sol/horizon/epoch-141.jet".into();
        assert!(validate_plan(&p).is_err());
        p.output="/var/lib/jetstreamer/horizon-epoch141-first-target-byte-diagnostic-test/diagnostic.json".into();
        p.acquisition.sha256 = TARGET_SHA.into();
        assert!(validate_plan(&p).is_err());
    }
    #[test]
    #[ignore = "explicit root read-only exact retained acquisition decode, no writes or native rerun"]
    fn retained_actual_first_target_byte_decode() {
        let raw = read(
            &Bound {
                path: RAW.into(),
                sha256: RAW_SHA.into(),
            },
            true,
        )
        .unwrap();
        validate_acquisition(&raw).unwrap();
        let target = read(
            &Bound {
                path: TARGET.into(),
                sha256: TARGET_SHA.into(),
            },
            false,
        )
        .unwrap();
        let hash: [u8; 32] = bs58::decode(target["metadata"]["final_poh_hash"].as_str().unwrap())
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();
        let first = decode(&raw["first_metadata"], 1).unwrap();
        let records = decode(&raw["records"], 786).unwrap();
        let first: Vec<_> = first.iter().map(Owned::borrowed).collect();
        let records: Vec<_> = records.iter().map(Owned::borrowed).collect();
        let r = diagnose_v1_4_25_acquired_bytes(
            &first,
            LegacySlotScope {
                slot: 60911776,
                parent_slot: 60911771,
            },
            &records,
            hash,
        )
        .unwrap();
        println!("{}", serde_json::to_string(&r).unwrap());
        assert!(r.final_entry_matches_finalized_hash);
        assert!(!r.recorded_is_connected && !r.poh_chain_verified);
    }
    #[test]
    #[ignore = "explicit root read-only PoH diagnostic from exact retained typed/native clock; no receipt, runtime route or publication"]
    fn retained_actual_first_target_poh_diagnostic() {
        use jetstreamer_utils::{
            horizon_legacy_entry::decode_v1_4_25_padded_entries,
            horizon_legacy_poh::{PohExpectation, verify_v1_4_25_poh_chain},
            horizon_legacy_shred::{
                assemble_v1_4_25_padded_batches, assemble_v1_4_25_slot_from_meta,
                decode_v1_4_25_complete_slot_meta,
            },
        };
        let clock_sha = "f74aacd82655179686a43c6bb137e0c0e7c7bd2955809008a745ef80f16f8be2";
        let clock=read(&Bound{path:"/usr/local/lib/jetstreamer/horizon-epoch140-serialized-clock-complete-20261020-v1/clock.json".into(),sha256:clock_sha.into()},true).unwrap();
        let native=read(&Bound{path:"/usr/local/lib/jetstreamer/horizon-epoch140-native-restore-complete-20261020-v1/native.json".into(),sha256:"53f1aa88f8f5f24aed1e291ff02318c102fac3bfb8ececf5c215c9fb70c11b20".into()},true).unwrap();
        assert_eq!(
            clock["schema"],
            "jetstreamer-epoch140-serialized-snapshot-clock-v1"
        );
        assert_eq!(clock["pinned_typed_serialized_clock_only"], true);
        assert_eq!(
            clock["input_sha256"],
            "47d5911465901975e397c570e06ccf72296db7ecd3b3b1beda710cacd3e683a1"
        );
        assert_eq!(clock["census"]["clock"]["slot"], 60911751);
        assert_eq!(clock["census"]["clock"]["complete"], true);
        assert_eq!(
            native["schema"],
            "jetstreamer-private-epoch140-native-restore-probe-v1"
        );
        assert_eq!(native["passed"], true);
        assert_eq!(native["native_result"]["comparison_passed"], true);
        assert_eq!(native["serialized_clock_sha256"], clock_sha);
        assert_eq!(native["snapshot_sha256"], clock["input_sha256"]);
        assert_eq!(
            native["native_result"]["native_checkpoint"]["bank_hash"],
            clock["census"]["clock"]["bank_hash"]
        );
        assert_eq!(
            native["native_result"]["native_checkpoint"]["initialized_ticks_per_slot"],
            clock["census"]["clock"]["ticks_per_slot"]
        );
        let bank = include_bytes!(
            "../../historical-runtime/v1_4_25/vendor/solana-runtime-1.4.25/src/bank.rs"
        );
        assert_eq!(
            evidence::sha(bank),
            "f136ec6b4d40bced37936df1800cc7f2d64484a0640d76edb2839dd04599d4ac"
        );
        let bank = std::str::from_utf8(bank).unwrap();
        assert!(
            bank.contains("hashes_per_tick: parent.hashes_per_tick,")
                && bank.contains("ticks_per_slot: parent.ticks_per_slot,")
        );
        let worker = include_str!("../../historical-runtime/v1_4_25/worker/src/runtime.rs");
        assert!(!worker.contains(".set_hashes_per_tick("));
        let raw = read(
            &Bound {
                path: RAW.into(),
                sha256: RAW_SHA.into(),
            },
            true,
        )
        .unwrap();
        validate_acquisition(&raw).unwrap();
        let target = read(
            &Bound {
                path: TARGET.into(),
                sha256: TARGET_SHA.into(),
            },
            false,
        )
        .unwrap();
        let hash = |field: &str| -> [u8; 32] {
            bs58::decode(target["metadata"][field].as_str().unwrap())
                .into_vec()
                .unwrap()
                .try_into()
                .unwrap()
        };
        let expected = PohExpectation {
            parent_slot: 60911771,
            slot: 60911776,
            parent_hash: hash("previous_poh_hash"),
            final_hash: hash("final_poh_hash"),
            ticks_per_slot: clock["census"]["clock"]["ticks_per_slot"].as_u64().unwrap(),
            hashes_per_tick: clock["census"]["clock"]["hashes_per_tick"]
                .as_u64()
                .unwrap(),
        };
        assert_eq!(
            (expected.ticks_per_slot, expected.hashes_per_tick),
            (64, 12500)
        );
        let first = decode(&raw["first_metadata"], 1).unwrap();
        let records = decode(&raw["records"], 786).unwrap();
        let first: Vec<_> = first.iter().map(Owned::borrowed).collect();
        let records: Vec<_> = records.iter().map(Owned::borrowed).collect();
        let byte = diagnose_v1_4_25_acquired_bytes(
            &first,
            LegacySlotScope {
                slot: expected.slot,
                parent_slot: expected.parent_slot,
            },
            &records,
            expected.final_hash,
        )
        .unwrap();
        assert!(!byte.recorded_is_connected && byte.final_entry_matches_finalized_hash);
        let meta = decode_v1_4_25_complete_slot_meta(
            first[0].value.unwrap(),
            expected.slot,
            expected.parent_slot,
        )
        .unwrap();
        let shreds: Vec<_> = records[8..].iter().map(|r| r.value.unwrap()).collect();
        assert!(assemble_v1_4_25_slot_from_meta(&meta, &shreds).is_err());
        let assembled = assemble_v1_4_25_padded_batches(
            expected.slot,
            expected.parent_slot,
            meta.last_index,
            &shreds,
        )
        .unwrap();
        assert_eq!(
            assembled.iter().map(|b| b.last_index).collect::<Vec<_>>(),
            meta.completed_data_indexes
        );
        let entries: Vec<_> = assembled
            .iter()
            .map(|b| decode_v1_4_25_padded_entries(&b.bytes).unwrap())
            .collect();
        let result = verify_v1_4_25_poh_chain(&entries, &expected, 4_000_000, || Ok(())).unwrap();
        assert_eq!(result.boundaries.len(), 5);
        assert!(!result.source_completeness_proven && !result.publication_authorized);
        assert!(!meta.is_connected && assemble_v1_4_25_slot_from_meta(&meta, &shreds).is_err());
        let boundaries:Vec<_>=result.boundaries.iter().map(|b|json!({"slot":b.slot,"tick_ordinal":b.tick_ordinal,"hash":bs58::encode(b.hash).into_string()})).collect();
        println!(
            "{}",
            json!({"diagnostic_only":true,"clock_sha256":clock_sha,"executed_hashes":result.executed_hashes,"boundaries":boundaries,"canonical_ancestry_proven":false,"source_completeness_proven":false,"runtime_route_changed":false,"publication_authorized":false})
        );
    }
}
