//! Durable private PoH diagnostic for one exact acquired target. No recovery
//! planner, runtime boundary input, native DB open, archive, or remote mutation.
mod epoch141_acquired_input;
mod epoch141_poh_clock;
#[allow(dead_code)]
#[path = "epoch141_ledger_common.rs"]
mod evidence;
use anyhow::{Context, Result, ensure};
use epoch141_acquired_input::{
    Bound, Owned, RAW, RAW_SHA, TARGET, TARGET_SHA, decode, read, terminal, validate_acquisition,
};
use epoch141_poh_clock::{CLOCK_PATH, CLOCK_SHA, ClockBindings, NATIVE_PATH, NATIVE_SHA};
use jetstreamer_utils::{
    horizon_legacy_byte_diagnostic::diagnose_v1_4_25_acquired_bytes,
    horizon_legacy_entry::decode_v1_4_25_padded_entries,
    horizon_legacy_poh::{PohExpectation, verify_v1_4_25_poh_chain},
    horizon_legacy_recovery::LegacySlotScope,
    horizon_legacy_shred::{
        assemble_v1_4_25_padded_batches, assemble_v1_4_25_slot_from_meta,
        decode_v1_4_25_complete_slot_meta,
    },
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Instant,
};
const BYTE_PATH: &str = "/var/lib/jetstreamer/horizon-epoch141-first-target-byte-diagnostic-20261022-v1/diagnostic.json";
const BYTE_SHA: &str = "9a822fd962fc58995950e3b2a622746a1c19c058d94d893b35edffc2191a8b8a";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    acquisition: Bound,
    finalized_target: Bound,
    byte_diagnostic: Bound,
    clock: Bound,
    native_clock: Bound,
    output: PathBuf,
}
struct Inputs {
    first: Vec<Owned>,
    records: Vec<Owned>,
    clock: ClockBindings,
    expected: PohExpectation,
}
fn validate_plan(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-epoch141-first-target-poh-diagnostic-plan-v1"
            && p.acquisition
                == Bound {
                    path: RAW.into(),
                    sha256: RAW_SHA.into()
                }
            && p.finalized_target
                == Bound {
                    path: TARGET.into(),
                    sha256: TARGET_SHA.into()
                }
            && p.byte_diagnostic
                == Bound {
                    path: BYTE_PATH.into(),
                    sha256: BYTE_SHA.into()
                }
            && p.clock
                == Bound {
                    path: CLOCK_PATH.into(),
                    sha256: CLOCK_SHA.into()
                }
            && p.native_clock
                == Bound {
                    path: NATIVE_PATH.into(),
                    sha256: NATIVE_SHA.into()
                },
        "foreign first-target PoH plan"
    );
    ensure!(
        p.output.file_name().is_some_and(|n| n == "poh.json")
            && p.output.parent().is_some_and(|d| d.parent()
                == Some(Path::new("/var/lib/jetstreamer"))
                && d.file_name().is_some_and(|n| n
                    .to_string_lossy()
                    .starts_with("horizon-epoch141-first-target-poh-diagnostic-"))),
        "foreign PoH output namespace"
    );
    Ok(())
}
fn hash(v: &Value, field: &str) -> Result<[u8; 32]> {
    bs58::decode(v[field].as_str().context("missing finalized hash")?)
        .into_vec()
        .map_err(|e| anyhow::anyhow!("invalid finalized base58:{e}"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("wrong finalized hash length"))
}
fn inputs(p: &Plan) -> Result<Inputs> {
    validate_plan(p)?;
    let raw = read(&p.acquisition, true)?;
    validate_acquisition(&raw)?;
    let byte = read(&p.byte_diagnostic, false)?;
    ensure!(
        byte["schema"] == "jetstreamer-epoch141-first-target-byte-diagnostic-v1"
            && byte["epoch"] == 141
            && byte["slot"] == 60911776
            && byte["parent_slot"] == 60911771
            && byte["tool_sha256"]
                == "055e1a8e1b64b62158b22e8d6ad87e759c59959fc0d2c7aec11bc5db586e88d8"
            && byte["diagnostic_passed"] == true
            && byte["diagnostic"]["recorded_is_connected"] == false
            && byte["diagnostic"]["final_entry_matches_finalized_hash"] == true
            && byte["poh_chain_verified"] == false
            && byte["runtime_clock_authenticated"] == false
            && byte["connected_recovery_route_changed"] == false
            && byte["publication_authorized"] == false
            && byte["r2_mutations"] == false,
        "not exact original byte-only result"
    );
    let target = read(&p.finalized_target, false)?;
    ensure!(
        target["schema"] == "jetstreamer-epoch140-finalized-gap-target-v1"
            && target["metadata"]["slot"] == 60911776
            && target["metadata"]["parent_slot"] == 60911771
            && target["hidden_poh_hashes_recovered"] == false
            && target["publication_authorized"] == false
            && target["replay_launch_authorized"] == false
            && target["r2_mutations"] == false,
        "wrong finalized target"
    );
    for field in ["request", "response"] {
        let b: Bound = serde_json::from_value(target[field].clone())?;
        read(&b, false)?;
    }
    let clock = epoch141_poh_clock::load(&p.clock, &p.native_clock)?;
    let expected = PohExpectation {
        slot: 60911776,
        parent_slot: 60911771,
        parent_hash: hash(&target["metadata"], "previous_poh_hash")?,
        final_hash: hash(&target["metadata"], "final_poh_hash")?,
        ticks_per_slot: clock.ticks_per_slot,
        hashes_per_tick: clock.hashes_per_tick,
    };
    ensure!(
        clock.snapshot_slot < expected.parent_slot,
        "clock is not prior to target"
    );
    Ok(Inputs {
        first: decode(&raw["first_metadata"], 1)?,
        records: decode(&raw["records"], 786)?,
        clock,
        expected,
    })
}
fn compute(i: &Inputs) -> Result<Value> {
    let start = Instant::now();
    let first: Vec<_> = i.first.iter().map(Owned::borrowed).collect();
    let records: Vec<_> = i.records.iter().map(Owned::borrowed).collect();
    let byte = diagnose_v1_4_25_acquired_bytes(
        &first,
        LegacySlotScope {
            slot: i.expected.slot,
            parent_slot: i.expected.parent_slot,
        },
        &records,
        i.expected.final_hash,
    )
    .map_err(anyhow::Error::msg)?;
    ensure!(
        !byte.recorded_is_connected && byte.final_entry_matches_finalized_hash,
        "raw interpretation differs"
    );
    let meta = decode_v1_4_25_complete_slot_meta(
        first[0].value.context("missing metadata")?,
        i.expected.slot,
        i.expected.parent_slot,
    )
    .map_err(anyhow::Error::msg)?;
    let shreds: Vec<_> = records[8..].iter().map(|r| r.value.unwrap()).collect();
    ensure!(
        !meta.is_connected && assemble_v1_4_25_slot_from_meta(&meta, &shreds).is_err(),
        "connected recovery must remain rejected"
    );
    let batches = assemble_v1_4_25_padded_batches(
        i.expected.slot,
        i.expected.parent_slot,
        meta.last_index,
        &shreds,
    )
    .map_err(anyhow::Error::msg)?;
    ensure!(
        batches.iter().map(|b| b.last_index).collect::<Vec<_>>() == meta.completed_data_indexes,
        "unchanged endpoints differ"
    );
    let decoded: Vec<_> = batches
        .iter()
        .map(|b| decode_v1_4_25_padded_entries(&b.bytes).map_err(anyhow::Error::msg))
        .collect::<Result<_>>()?;
    let result = verify_v1_4_25_poh_chain(&decoded, &i.expected, 4_000_000, || {
        if start.elapsed().as_secs() > 90 {
            Err("private diagnostic hash deadline exceeded".into())
        } else {
            Ok(())
        }
    })
    .map_err(anyhow::Error::msg)?;
    ensure!(
        result.boundaries.len() == 5
            && result.executed_hashes == 4_000_000
            && !result.source_completeness_proven
            && !result.publication_authorized,
        "unexpected diagnostic chain shape/authority"
    );
    ensure!(
        !meta.is_connected && assemble_v1_4_25_slot_from_meta(&meta, &shreds).is_err(),
        "diagnostic changed connectivity"
    );
    let boundaries:Vec<_>=result.boundaries.iter().map(|b|json!({"slot":b.slot,"tick_ordinal":b.tick_ordinal,"hash":bs58::encode(b.hash).into_string()})).collect();
    Ok(
        json!({"executed_hashes":result.executed_hashes,"verified_boundary_count":5,"verified_hidden_boundary_count":4,"boundaries":boundaries,"byte_observations":byte,"clock_bindings":i.clock,"elapsed_millis":u64::try_from(start.elapsed().as_millis())?,"diagnostic_only":true}),
    )
}
fn absent(p: &Path) -> Result<()> {
    ensure!(
        matches!(fs::symlink_metadata(p),Err(e)if e.kind()==std::io::ErrorKind::NotFound),
        "PoH namespace already exists"
    );
    Ok(())
}
fn run() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    let check = a.len() == 7 && a[6] == "--check-only";
    ensure!(
        (a.len() == 6 || check)
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: poh-diagnostic PLAN --plan-sha256 SHA --self-sha256 SHA [--check-only]"
    );
    evidence::bound_file(&fs::read_link("/proc/self/exe")?, &a[5], 128 << 20, true)?;
    let p: Plan = serde_json::from_slice(&evidence::bound_file(
        Path::new(&a[1]),
        &a[3],
        1 << 20,
        true,
    )?)?;
    let i = inputs(&p)?;
    let owner = terminal()?;
    let parent = p.output.parent().unwrap();
    ensure!(
        parent.canonicalize()? == parent,
        "noncanonical PoH output parent"
    );
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(parent)?;
    let m = dir.metadata()?;
    ensure!(
        m.uid() == 0 && m.mode() & 0o777 == 0o700,
        "PoH output parent not root-private"
    );
    let intent = parent.join("intent.json");
    absent(&intent)?;
    absent(&p.output)?;
    if check {
        println!(
            "exact first-target PoH inputs validated; no entry decoding, hashing, writes or recovery"
        );
        return Ok(());
    }
    let context = json!({"plan":{"path":a[1],"sha256":a[3]},"tool_sha256":a[5],"acquisition":p.acquisition,"finalized_target":p.finalized_target,"byte_diagnostic":p.byte_diagnostic,"clock":p.clock,"native_clock":p.native_clock,"native_terminal":owner,"scope_target_count":1,"slot":60911776,"parent_slot":60911771,"source_completeness_proven":false,"canonical_ancestry_proven":false,"publication_authorized":false,"runtime_promotion_authorized":false,"r2_mutations":false});
    evidence::write_receipt(
        &intent,
        &json!({"schema":"jetstreamer-epoch141-first-target-poh-diagnostic-intent-v1","context":context}),
    )?;
    let result = compute(&i);
    ensure!(terminal()? == owner, "native terminal changed during PoH");
    for (b, immutable) in [
        (&p.acquisition, true),
        (&p.finalized_target, false),
        (&p.byte_diagnostic, false),
        (&p.clock, true),
        (&p.native_clock, true),
    ] {
        read(b, immutable)?;
    }
    let passed = result.is_ok();
    let (diagnostic, error) = match result {
        Ok(v) => (v, Value::Null),
        Err(e) => (Value::Null, json!(format!("{e:#}"))),
    };
    let output = json!({"schema":"jetstreamer-epoch141-first-target-poh-diagnostic-v1","epoch":141,"context":context,"diagnostic_passed":passed,"poh_chain_verified":passed,"clock_bindings_validated":true,"diagnostic":diagnostic,"error":error,"recorded_is_connected":false,"connected_recovery_route_changed":false,"recovered_target_count":0,"full_target_census_complete":false,"full_epoch_hidden_poh_recovery_complete":false,"canonical_ancestry_proven":false,"live_state_proven":false,"source_completeness_proven":false,"runtime_boundary_input_authorized":false,"replay_launch_authorized":false,"runtime_promotion_authorized":false,"publication_authorized":false,"retirement_authorized":false,"remote_mutations":false,"r2_mutations":false});
    ensure!(
        serde_json::to_vec(&output)?.len() <= 1 << 20,
        "PoH diagnostic output exceeded cap"
    );
    evidence::write_receipt(&p.output, &output)?;
    ensure!(passed, "PoH failed; durable explicit diagnostic retained");
    println!("{}", p.output.display());
    Ok(())
}
fn main() -> Result<()> {
    run()
}
#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> Plan {
        Plan {
            schema: "jetstreamer-epoch141-first-target-poh-diagnostic-plan-v1".into(),
            acquisition: Bound {
                path: RAW.into(),
                sha256: RAW_SHA.into(),
            },
            finalized_target: Bound {
                path: TARGET.into(),
                sha256: TARGET_SHA.into(),
            },
            byte_diagnostic: Bound {
                path: BYTE_PATH.into(),
                sha256: BYTE_SHA.into(),
            },
            clock: Bound {
                path: CLOCK_PATH.into(),
                sha256: CLOCK_SHA.into(),
            },
            native_clock: Bound {
                path: NATIVE_PATH.into(),
                sha256: NATIVE_SHA.into(),
            },
            output:
                "/var/lib/jetstreamer/horizon-epoch141-first-target-poh-diagnostic-test/poh.json"
                    .into(),
        }
    }
    #[test]
    fn only_exact_private_diagnostic_plan_is_allowed() {
        validate_plan(&plan()).unwrap();
        let mut p = plan();
        p.output = "/home/sol/horizon/epoch-141.jet".into();
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.byte_diagnostic.sha256 = CLOCK_SHA.into();
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.clock.path = RAW.into();
        assert!(validate_plan(&p).is_err());
    }
    #[test]
    #[ignore = "explicit root read-only exact retained PoH computation, no receipt/route/native DB"]
    fn actual_retained_poh_inputs_and_complete_chain() {
        let i = inputs(&plan()).unwrap();
        let r = compute(&i).unwrap();
        println!("{r}");
        assert_eq!(r["verified_boundary_count"], 5);
        assert_eq!(r["verified_hidden_boundary_count"], 4);
    }
}
