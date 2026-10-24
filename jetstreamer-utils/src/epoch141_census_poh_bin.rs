//! Complete private diagnostic of acquired 141shreds, never a recovery route.
#[allow(dead_code)]
mod epoch141_acquired_input;
mod epoch141_poh_clock;
#[allow(dead_code)]
#[path = "epoch141_ledger_common.rs"]
mod evidence;
#[allow(dead_code)]
#[path = "epoch140_gap_metadata_fetch_bin.rs"]
mod finalized;

use anyhow::{Context, Result, ensure};
use epoch141_acquired_input::{Bound, Owned, decode};
use jetstreamer_utils::{
    horizon_legacy_byte_diagnostic::diagnose_v1_4_25_acquired_bytes,
    horizon_legacy_entry::decode_v1_4_25_padded_entries,
    horizon_legacy_poh::{PohExpectation, verify_v1_4_25_poh_chain},
    horizon_legacy_recovery::LegacySlotScope,
    horizon_legacy_shred::{assemble_v1_4_25_padded_batches, decode_v1_4_25_complete_slot_meta},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

const UNIT: &str = "horizon-epoch141-native-full-census-acquisition-all-20261022-v2.service";
const IID: &str = "4721c4110425431cbddedac185e7d6e9";
const ROOT: &str =
    "/home/sol/.jetstreamer-private/epoch141-native-acquisition-all-20261022-v2/results";
const NATIVE_SHA: &str = "153a0d1302369f7ff1272d8b62ca9e777d4d1e3bd5a172e5edec5fe3ad28c295";
const PLAN_SHA: &str = "5419f63050d9f89da87cfab8a2ab94e5ce24ae560fe4b9efb4918695fbb057cc";
const ADMISSION_SHA: &str = "2f17e7eb127ccad5f602954aeaad17f9dccdae0a1a32ca70a356419950042e4f";
const FINAL_PLAN: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch140-gap-metadata-fetch-20261021-v1/plan.json";
const FINAL_PLAN_SHA: &str = "fc320b12c2a53c95f6781ed9130a57e179078ce09b654f96b79c675a96fdf5cc";
const FINAL_RECEIPT: &str = "/var/lib/jetstreamer-epoch140-gap-metadata-20261021-v1/complete.json";
const FINAL_SHA: &str = "21427d5debbc22ab44c337fb32679620ec663f44c52c5ceeb7100fcb450f8fe4";
const TARGETS: usize = 18_283;
const BOUNDARIES: u64 = 84_597;
const MAX_OUTPUT: u64 = 256 << 20;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    acquisition: Bound,
    output_directory: PathBuf,
}
const OWN_UNIT: &str = "horizon-epoch141-census-poh-diagnostic-20261022-v1.service";
fn own_identity() -> Result<Value> {
    let iid = std::env::var("INVOCATION_ID")?;
    let o=Command::new("/usr/bin/systemctl").args(["show",OWN_UNIT,"--property=Id,InvocationID,MainPID,NRestarts,Restart,Type,ActiveState,SubState,ExecStart"]).output()?;
    ensure!(
        o.status.success() && o.stdout.len() <= 32768,
        "diagnostic owner unreadable"
    );
    let text = std::str::from_utf8(&o.stdout)?;
    let fields: std::collections::BTreeMap<_, _> = text
        .lines()
        .map(|s| s.split_once('=').context("diagnostic property malformed"))
        .collect::<Result<_>>()?;
    let v = json!(fields);
    validate_own(&v, &iid, std::process::id())?;
    Ok(v)
}
fn validate_own(v: &Value, iid: &str, pid: u32) -> Result<()> {
    ensure!(
        iid.len() == 32 && evidence::is_sha(&format!("{iid}{iid}")),
        "invalid diagnostic invocation"
    );
    ensure!(
        v["Id"] == OWN_UNIT
            && v["InvocationID"] == iid
            && v["MainPID"].as_str().and_then(|s| s.parse::<u32>().ok()) == Some(pid)
            && v["NRestarts"] == "0"
            && v["Restart"] == "no"
            && v["Type"] == "exec"
            && v["ActiveState"] == "active"
            && v["SubState"] == "running",
        "diagnostic requires exact live nonrestarting owner"
    );
    Ok(())
}
fn memory_admission() -> Result<Value> {
    let text = fs::read_to_string("/proc/meminfo")?;
    let available = text
        .lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))
        .context("MemAvailable absent")?
        .split_whitespace()
        .next()
        .context("MemAvailable malformed")?
        .parse::<u64>()?
        .checked_mul(1024)
        .context("memory overflow")?;
    let minimum = 130u64 << 30; // existing 128 GiB host reserve plus hard 2 GiB diagnostic envelope
    ensure!(
        available >= minimum,
        "private PoH memory admission unavailable"
    );
    Ok(
        json!({"available_bytes":available,"protected_memory_bytes":128u64<<30,"diagnostic_memory_max_bytes":2u64<<30,"minimum_available_bytes":minimum,"admitted":true}),
    )
}
fn read(b: &Bound, maximum: u64, immutable: bool) -> Result<Value> {
    Ok(serde_json::from_slice(&evidence::bound_file(
        &b.path, &b.sha256, maximum, immutable,
    )?)?)
}
fn terminal() -> Result<Value> {
    let o = Command::new("/usr/bin/systemctl").args(["show", UNIT,
        "--property=InvocationID,MainPID,NRestarts,Restart,Result,ExecMainStatus,ActiveState,SubState,Type"]).output()?;
    ensure!(
        o.status.success() && o.stdout.len() <= 32768,
        "native terminal query failed"
    );
    let text = std::str::from_utf8(&o.stdout)?;
    let fields: std::collections::BTreeMap<_, _> = text
        .lines()
        .map(|s| s.split_once('=').context("native property malformed"))
        .collect::<Result<_>>()?;
    let v = json!(fields);
    terminal_value(&v)?;
    Ok(v)
}
fn terminal_value(v: &Value) -> Result<()> {
    for (key, expected) in [
        ("InvocationID", IID),
        ("MainPID", "0"),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
        ("ActiveState", "active"),
        ("SubState", "exited"),
        ("Type", "exec"),
    ] {
        ensure!(
            v[key] == expected,
            "native source not exact clean terminal:{key}"
        );
    }
    Ok(())
}
fn no_authority(v: &Value) -> Result<()> {
    for flag in [
        "source_completeness_proven",
        "live_state_proven",
        "canonical_ancestry_proven",
        "runtime_clock_authenticated",
        "hidden_poh_hashes_recovered",
        "runtime_promotion_authorized",
        "replay_launch_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(v[flag] == false, "raw acquisition authority changed:{flag}");
    }
    Ok(())
}
fn manifest(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-epoch141-native-all-target-acquisition-v2"
            && v["epoch"] == 141
            && v["invocation_id"] == IID
            && v["self_sha256"] == NATIVE_SHA
            && v["plan_sha256"] == PLAN_SHA
            && v["admission_sha256"] == ADMISSION_SHA
            && v["source_verification_sha256"]
                == "93228cf8caaae18d07c501c9a0430773239af05da0047f1129c670bbe4fe0e2a"
            && v["collection_sha256"]
                == "569df15e8ce87beca8df0a800c85e616aaf252baeb365a7c92f35b8b39b4e937"
            && v["complete_census_sha256"]
                == "7dba362278d8cdd7689f053a6a5ef4d79623d9029b12320bed5bdfbc5b79668e"
            && v["finalized_collection_plan_sha256"] == FINAL_PLAN_SHA
            && v["finalized_collection_receipt_sha256"] == FINAL_SHA
            && v["gap_census_sha256"]
                == "11a6049bc9378b4e3e063e765ce2b908b621f5d7845a49d372aca509d6d37a9f"
            && v["complete_finalized_target_census_count"] == TARGETS
            && v["attempted_target_count"] == TARGETS
            && v["raw_acquired_target_count"] == TARGETS
            && v["metadata_rejected_target_count"] == 0
            && v["missing_data_shred_count"] == 0
            && v["unexpected_shred_length_count"] == 0
            && v["recovered_target_count"] == 0
            && v["full_target_attempt_census_complete"] == true
            && v["full_target_raw_acquisition_complete"] == true
            && v["native_session_complete"] == true
            && v["complete_retained_census_revalidated_after_close"] == true
            && v["native_session"]["batches"] == 36_566
            && v["native_session"]["complete_census_revalidated"] == true
            && v["native_session"]["source_completeness_proven"] == false
            && v["native_session"]["live_state_proven"] == false
            && v["native_session"]["publication_authorized"] == false
            && v["output_reservation_bytes"] == 34_359_738_368u64
            && v["minimum_free_bytes"] == 4_740_696_923_590u64
            && v["acquisition_only"] == true,
        "not exact full post-close acquisition"
    );
    no_authority(v)?;
    ensure!(
        v["target_receipts"]
            .as_array()
            .is_some_and(|a| a.len() == TARGETS),
        "incomplete acquired target census"
    );
    Ok(())
}
fn plan_shape(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-epoch141-census-poh-diagnostic-plan-v1"
            && p.acquisition.path == Path::new(ROOT).join("all-target-acquisition.json")
            && evidence::is_sha(&p.acquisition.sha256)
            && p.output_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && p.output_directory.file_name().is_some_and(|n| n
                .to_string_lossy()
                .starts_with("horizon-epoch141-census-poh-diagnostic-")),
        "foreign census PoH plan"
    );
    Ok(())
}
fn guard(root: &Path, start: Instant) -> Result<()> {
    ensure!(
        start.elapsed().as_secs() < 21_600,
        "complete diagnostic deadline exceeded"
    );
    let path = std::ffi::CString::new(root.as_os_str().as_encoded_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } == 0,
        "diagnostic filesystem unreadable"
    );
    let stat = unsafe { stat.assume_init() };
    let available = (stat.f_bavail as u128) * (stat.f_frsize as u128);
    ensure!(
        available >= (100u128 << 30) + MAX_OUTPUT as u128,
        "OS filesystem protected reserve unavailable"
    );
    Ok(())
}
fn target_binding(v: &Value, expected_slot: u64) -> Result<Bound> {
    let b = Bound {
        path: v["path"].as_str().context("target path")?.into(),
        sha256: v["sha256"].as_str().context("target digest")?.into(),
    };
    ensure!(
        v["slot"] == expected_slot
            && b.path
                == Path::new(ROOT)
                    .join("target-acquisitions")
                    .join(format!("slot-{expected_slot}.json"))
            && evidence::is_sha(&b.sha256),
        "changed, reordered, duplicate or foreign acquired target"
    );
    Ok(b)
}
fn target(v: &Value, m: &finalized::Metadata) -> Result<(Vec<Owned>, Vec<Owned>)> {
    ensure!(
        v["schema"] == "jetstreamer-epoch141-native-provisional-acquisition-target-v2"
            && v["invocation_id"] == IID
            && v["plan_sha256"] == PLAN_SHA
            && v["census_sha256"]
                == "11a6049bc9378b4e3e063e765ce2b908b621f5d7845a49d372aca509d6d37a9f"
            && v["slot"] == m.slot
            && v["parent_slot"] == m.parent_slot
            && v["native_session_complete"] == false
            && v["outcome"]["status"] == "raw-acquired",
        "acquired target lineage differs"
    );
    no_authority(v)?;
    let n = v["outcome"]["summary"]["expected_data_shreds"]
        .as_u64()
        .context("missing shred count")?;
    ensure!(
        (1..=65_528).contains(&n),
        "shred count exceeds query envelope"
    );
    Ok((
        decode(&v["outcome"]["first_metadata"], 1)?,
        decode(&v["outcome"]["records"], usize::try_from(n)? + 8)?,
    ))
}
fn hash(s: &str) -> Result<[u8; 32]> {
    bs58::decode(s)
        .into_vec()
        .map_err(|e| anyhow::anyhow!("invalid finalized base58: {e}"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid finalized hash length"))
}
fn compute(
    first: &[Owned],
    records: &[Owned],
    m: &finalized::Metadata,
    clock: &epoch141_poh_clock::ClockBindings,
    mut safety: impl FnMut() -> Result<(), String>,
) -> Result<Value> {
    let start = Instant::now();
    let first: Vec<_> = first.iter().map(Owned::borrowed).collect();
    let records: Vec<_> = records.iter().map(Owned::borrowed).collect();
    let scope = LegacySlotScope {
        slot: m.slot,
        parent_slot: m.parent_slot,
    };
    let byte = diagnose_v1_4_25_acquired_bytes(&first, scope, &records, hash(&m.final_poh_hash)?)
        .map_err(anyhow::Error::msg)?;
    ensure!(
        byte.final_entry_matches_finalized_hash,
        "final entry disagrees with finalized anchor"
    );
    let meta = decode_v1_4_25_complete_slot_meta(
        first[0].value.context("missing target metadata")?,
        m.slot,
        m.parent_slot,
    )
    .map_err(anyhow::Error::msg)?;
    let shreds: Vec<_> = records[8..]
        .iter()
        .map(|r| r.value.context("missing acquired shred"))
        .collect::<Result<_>>()?;
    let batches = assemble_v1_4_25_padded_batches(m.slot, m.parent_slot, meta.last_index, &shreds)
        .map_err(anyhow::Error::msg)?;
    ensure!(
        batches.iter().map(|b| b.last_index).collect::<Vec<_>>() == meta.completed_data_indexes,
        "unchanged batch endpoints differ"
    );
    let decoded = batches
        .iter()
        .map(|b| decode_v1_4_25_padded_entries(&b.bytes).map_err(anyhow::Error::msg))
        .collect::<Result<Vec<_>>>()?;
    let expected = PohExpectation {
        slot: m.slot,
        parent_slot: m.parent_slot,
        parent_hash: hash(&m.previous_poh_hash)?,
        final_hash: hash(&m.final_poh_hash)?,
        ticks_per_slot: clock.ticks_per_slot,
        hashes_per_tick: clock.hashes_per_tick,
    };
    let result = verify_v1_4_25_poh_chain(&decoded, &expected, 51_200_000, || {
        if start.elapsed().as_secs() >= 90 {
            return Err("per-target PoH deadline exceeded".into());
        }
        safety()
    })
    .map_err(anyhow::Error::msg)?;
    ensure!(
        result.boundaries.len() as u64 == m.slot - m.parent_slot
            && !result.source_completeness_proven
            && !result.publication_authorized,
        "diagnostic chain shape/authority differs"
    );
    let boundaries:Vec<_> = result.boundaries.iter().map(|b|json!({"slot":b.slot,"tick_ordinal":b.tick_ordinal,"hash":bs58::encode(b.hash).into_string()})).collect();
    Ok(
        json!({"executed_hashes":result.executed_hashes,"boundaries":boundaries,"byte_observations":byte,"elapsed_millis":start.elapsed().as_millis(),"diagnostic_only":true}),
    )
}
fn write(root: &Path, name: &str, v: &Value, accounted: &mut u64) -> Result<Bound> {
    let bytes = serde_json::to_vec_pretty(v)?.len() as u64 + 1;
    *accounted = accounted
        .checked_add(bytes)
        .context("diagnostic output overflow")?;
    ensure!(
        *accounted <= MAX_OUTPUT,
        "diagnostic output budget exhausted"
    );
    let path = root.join(name);
    evidence::write_receipt(&path, v)?;
    Ok(Bound {
        sha256: evidence::sha(&fs::read(&path)?),
        path,
    })
}
fn run() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    ensure!(
        a.len() == 7
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256"
            && matches!(a[6].as_str(), "--check-only" | "--run")
            && unsafe { libc::geteuid() } == 0,
        "usage: census-poh PLAN --plan-sha256 SHA --self-sha256 SHA --check-only|--run"
    );
    evidence::bound_file(&fs::read_link("/proc/self/exe")?, &a[5], 128 << 20, true)?;
    let pb = Bound {
        path: a[1].clone().into(),
        sha256: a[3].clone(),
    };
    let p: Plan = serde_json::from_value(read(&pb, 1 << 20, true)?)?;
    plan_shape(&p)?;
    let start = Instant::now();
    let dir = fs::symlink_metadata(&p.output_directory)?;
    ensure!(
        p.output_directory.canonicalize()? == p.output_directory
            && dir.is_dir()
            && dir.uid() == 0
            && dir.mode() & 0o777 == 0o700
            && dir.dev() == fs::metadata("/var/lib/jetstreamer")?.dev()
            && dir.dev() != fs::metadata("/home/sol")?.dev()
            && fs::read_dir(&p.output_directory)?.next().is_none(),
        "diagnostic root not empty/root-private"
    );
    guard(&p.output_directory, start)?;
    let owner = terminal()?;
    let raw = read(&p.acquisition, 8 << 20, false)?;
    manifest(&raw)?;
    let clock = epoch141_poh_clock::load(
        &Bound {
            path: epoch141_poh_clock::CLOCK_PATH.into(),
            sha256: epoch141_poh_clock::CLOCK_SHA.into(),
        },
        &Bound {
            path: epoch141_poh_clock::NATIVE_PATH.into(),
            sha256: epoch141_poh_clock::NATIVE_SHA.into(),
        },
    )?;
    let metadata = finalized::validate_complete_collection(
        Path::new(FINAL_PLAN),
        FINAL_PLAN_SHA,
        Path::new(FINAL_RECEIPT),
        FINAL_SHA,
    )?;
    ensure!(
        metadata.len() == TARGETS
            && metadata
                .first()
                .is_some_and(|m| m.slot == 60911776 && m.parent_slot == 60911771)
            && metadata.last().is_some_and(|m| m.slot == 61328744)
            && metadata.windows(2).all(|w| w[0].slot < w[1].slot),
        "finalized scope changed"
    );
    ensure!(
        metadata.iter().try_fold(0u64, |sum, m| sum
            .checked_add(m.slot.checked_sub(m.parent_slot)?))
            == Some(BOUNDARIES),
        "full boundary census changed"
    );
    let targets = raw["target_receipts"].as_array().unwrap();
    for (v, m) in targets.iter().zip(&metadata) {
        target_binding(v, m.slot)?;
    }
    terminal()?;
    guard(&p.output_directory, start)?;
    if a[6] == "--check-only" {
        println!(
            "full18283 closed acquisition/clock/finalized census bound; no raw target decode,PoH,output or recovery"
        );
        return Ok(());
    }
    let own = own_identity()?;
    let memory = memory_admission()?;
    let mut accounted = 8 << 20; // final manifest/context reservation
    write(
        &p.output_directory,
        "intent.json",
        &json!({"schema":"jetstreamer-epoch141-census-poh-intent-v2","plan":pb,"tool_sha256":a[5],"acquisition":p.acquisition,"native_terminal":owner,"owner":own,"memory_admission":memory,"clock":clock,"target_count":TARGETS,"expected_boundaries":BOUNDARIES,"publication_authorized":false,"runtime_boundary_input_authorized":false,"replay_launch_authorized":false,"runtime_promotion_authorized":false,"remote_mutations":false,"r2_mutations":false}),
        &mut accounted,
    )?;
    let outputs = p.output_directory.join("targets");
    fs::DirBuilder::new().mode(0o700).create(&outputs)?;
    File::open(&p.output_directory)?.sync_all()?;
    let mut receipts = Vec::with_capacity(TARGETS);
    let mut passed = 0usize;
    let mut boundaries = 0u64;
    let mut last_guard = Instant::now();
    for (index, (v, m)) in targets.iter().zip(&metadata).enumerate() {
        guard(&p.output_directory, start)?;
        let b = target_binding(v, m.slot)?;
        let value = read(&b, 224 << 20, false)?;
        let (first, records) = target(&value, m)?;
        let mut safety_failed = false;
        let result = compute(&first, &records, m, &clock, || {
            if last_guard.elapsed().as_secs() >= 1 {
                if let Err(e) = guard(&p.output_directory, start) {
                    safety_failed = true;
                    return Err(e.to_string());
                }
                last_guard = Instant::now();
            }
            Ok(())
        });
        ensure!(
            !safety_failed,
            "resource guard failed during PoH; no diagnostic normalization permitted"
        );
        // A failed chain is retained as a diagnostic result, never dropped or
        // normalized into success. Input/native/guard errors remain fatal.
        guard(&p.output_directory, start)?;
        let (diagnostic, error) = match result {
            Ok(v) => {
                passed += 1;
                boundaries += m.slot - m.parent_slot;
                (v, Value::Null)
            }
            Err(e) => (Value::Null, json!(format!("{e:#}"))),
        };
        let receipt = write(
            &outputs,
            &format!("slot-{}.json", m.slot),
            &json!({"schema":"jetstreamer-epoch141-census-target-poh-diagnostic-v1","epoch":141,"slot":m.slot,"parent_slot":m.parent_slot,"raw_target":b,"finalized_metadata":m,"diagnostic_passed":error.is_null(),"diagnostic":diagnostic,"error":error,"canonical_ancestry_proven":false,"source_completeness_proven":false,"live_state_proven":false,"runtime_boundary_input_authorized":false,"replay_launch_authorized":false,"runtime_promotion_authorized":false,"publication_authorized":false,"r2_mutations":false}),
            &mut accounted,
        )?;
        receipts.push(receipt);
        if index == 0 || (index + 1).is_multiple_of(100) {
            eprintln!(
                "census-poh attempted={} total={TARGETS} passed={passed}",
                index + 1
            );
        }
    }
    // Independently rehash every input and output before final accounting.
    for (v, m) in targets.iter().zip(&metadata) {
        guard(&p.output_directory, start)?;
        read(&target_binding(v, m.slot)?, 224 << 20, false)?;
    }
    for b in &receipts {
        read(b, 1 << 20, false)?;
    }
    finalized::validate_complete_collection(
        Path::new(FINAL_PLAN),
        FINAL_PLAN_SHA,
        Path::new(FINAL_RECEIPT),
        FINAL_SHA,
    )?;
    read(&p.acquisition, 8 << 20, false)?;
    read(&pb, 1 << 20, true)?;
    terminal()?;
    guard(&p.output_directory, start)?;
    ensure!(
        receipts.len() == TARGETS && (passed != TARGETS || boundaries == BOUNDARIES),
        "incomplete diagnostic accounting"
    );
    write(
        &p.output_directory,
        "completion.json",
        &json!({"schema":"jetstreamer-epoch141-census-poh-diagnostic-v1","epoch":141,"plan":pb,"tool_sha256":a[5],"acquisition":p.acquisition,"attempted_targets":TARGETS,"passed_targets":passed,"failed_targets":TARGETS-passed,"verified_boundary_count":boundaries,"full_census_poh_chains_verified":passed==TARGETS && boundaries==BOUNDARIES,"target_receipts":receipts,"elapsed_seconds":start.elapsed().as_secs(),"diagnostic_only":true,"recovered_target_count":0,"canonical_ancestry_proven":false,"source_completeness_proven":false,"live_state_proven":false,"runtime_boundary_input_authorized":false,"replay_launch_authorized":false,"runtime_promotion_authorized":false,"publication_authorized":false,"retirement_authorized":false,"remote_mutations":false,"r2_mutations":false}),
        &mut accounted,
    )?;
    println!(
        "complete private PoH diagnostic attempted={TARGETS} passed={passed}; no recovery/runtime/publication authority"
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("census PoH diagnostic failed closed:{e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn own_execution_cannot_borrow_a_foreign_pid_restart_or_unit() {
        let iid = "a".repeat(32);
        let v = json!({"Id":OWN_UNIT,"InvocationID":iid,"MainPID":"123","NRestarts":"0","Restart":"no","Type":"exec","ActiveState":"active","SubState":"running"});
        validate_own(&v, &iid, 123).unwrap();
        assert!(validate_own(&v, &iid, 124).is_err());
        for (key, value) in [
            ("Id", "foreign.service"),
            ("InvocationID", "foreign"),
            ("MainPID", "0"),
            ("NRestarts", "1"),
            ("Restart", "on-failure"),
            ("Type", "oneshot"),
            ("SubState", "exited"),
        ] {
            let mut bad = v.clone();
            bad[key] = json!(value);
            assert!(validate_own(&bad, &iid, 123).is_err());
        }
    }
    #[test]
    #[ignore = "root read-only retained first-target/clock proof; no outputs or full-census claim"]
    fn actual_first_target_matches_previously_verified_chain_without_connectivity_promotion() {
        let raw = read(
            &Bound {
                path: epoch141_acquired_input::RAW.into(),
                sha256: epoch141_acquired_input::RAW_SHA.into(),
            },
            4 << 20,
            true,
        )
        .unwrap();
        epoch141_acquired_input::validate_acquisition(&raw).unwrap();
        epoch141_acquired_input::terminal().unwrap();
        let target = read(
            &Bound {
                path: epoch141_acquired_input::TARGET.into(),
                sha256: epoch141_acquired_input::TARGET_SHA.into(),
            },
            4 << 20,
            false,
        )
        .unwrap();
        let m: finalized::Metadata = serde_json::from_value(target["metadata"].clone()).unwrap();
        let clock = epoch141_poh_clock::load(
            &Bound {
                path: epoch141_poh_clock::CLOCK_PATH.into(),
                sha256: epoch141_poh_clock::CLOCK_SHA.into(),
            },
            &Bound {
                path: epoch141_poh_clock::NATIVE_PATH.into(),
                sha256: epoch141_poh_clock::NATIVE_SHA.into(),
            },
        )
        .unwrap();
        let first = decode(&raw["first_metadata"], 1).unwrap();
        let records = decode(&raw["records"], 786).unwrap();
        let result = compute(&first, &records, &m, &clock, || Ok(())).unwrap();
        assert_eq!(result["executed_hashes"], 4_000_000);
        assert_eq!(result["boundaries"].as_array().unwrap().len(), 5);
        assert_eq!(result["byte_observations"]["recorded_is_connected"], false);
        assert_eq!(result["boundaries"][4]["hash"], m.final_poh_hash);
        assert!(compute(&first, &records, &m, &clock, || Err("guard fixture".into())).is_err());
        let mut bad = m;
        bad.previous_poh_hash = bs58::encode([0u8; 32]).into_string();
        assert!(compute(&first, &records, &bad, &clock, || Ok(())).is_err());
    }
    #[test]
    fn raw_paths_and_plan_cannot_expand_or_cross_attempts() {
        let p = Plan {
            schema: "jetstreamer-epoch141-census-poh-diagnostic-plan-v1".into(),
            acquisition: Bound {
                path: Path::new(ROOT).join("all-target-acquisition.json"),
                sha256: "a".repeat(64),
            },
            output_directory: "/var/lib/jetstreamer/horizon-epoch141-census-poh-diagnostic-test"
                .into(),
        };
        plan_shape(&p).unwrap();
        let v = json!({"slot":60911776,"path":format!("{ROOT}/target-acquisitions/slot-60911776.json"),"sha256":"b".repeat(64)});
        target_binding(&v, 60911776).unwrap();
        assert!(target_binding(&v, 60911777).is_err());
        let mut wrong = v;
        wrong["path"] = json!("/other/slot-60911776.json");
        assert!(target_binding(&wrong, 60911776).is_err());
        let mut p = p;
        p.acquisition.path = Path::new(ROOT).join("target-acquisitions/slot-60911776.json");
        assert!(plan_shape(&p).is_err());
    }
    #[test]
    fn provisional_or_changed_native_owner_never_supplies_closed_session_proof() {
        let v = json!({"InvocationID":IID,"MainPID":"0","NRestarts":"0","Restart":"no","Result":"success","ExecMainStatus":"0","ActiveState":"active","SubState":"exited","Type":"exec"});
        terminal_value(&v).unwrap();
        for (key, value) in [
            ("InvocationID", "foreign"),
            ("MainPID", "123"),
            ("NRestarts", "1"),
            ("SubState", "running"),
            ("Result", "exit-code"),
        ] {
            let mut wrong = v.clone();
            wrong[key] = json!(value);
            assert!(terminal_value(&wrong).is_err());
        }
        assert!(manifest(&json!({"schema":"jetstreamer-epoch141-native-all-target-acquisition-v2","native_session_complete":false})).is_err());
    }
}
