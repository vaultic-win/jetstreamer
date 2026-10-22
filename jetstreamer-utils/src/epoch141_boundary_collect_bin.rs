//! Independent complete-census boundary collection; no runtime promotion.
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
use epoch141_acquired_input::Bound;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};
const ROOT: &str = "/var/lib/jetstreamer/horizon-epoch141-census-poh-diagnostic-20261022-v2";
const UNIT: &str = "horizon-epoch141-census-poh-diagnostic-20261022-v1.service";
const IID: &str = "a3aa22142895434ebeaae311a89ed7df";
const DIAGNOSTIC_SHA: &str = "02c267ef5ac68d24cc75d22988254bb426f7c2d2805074d7a8838e6ab27e9234";
const DIAGNOSTIC_PLAN_SHA: &str =
    "64334d5250d51021b8460947536a896d2bc9e7500c86aa54c1e617975aa11e98";
const INTENT_SHA: &str = "8d5974b74d2aa29d88d035d136b50a74439f101b0a5559dbcd837145dce7adf4";
const RAW_ROOT: &str =
    "/home/sol/.jetstreamer-private/epoch141-native-acquisition-all-20261022-v2/results";
const RAW_SHA: &str = "0335b1131663c0f8df77b3cddb5f79e49af2956067ebc46af74b9a08adafb949";
const FINAL_PLAN: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch140-gap-metadata-fetch-20261021-v1/plan.json";
const FINAL_PLAN_SHA: &str = "fc320b12c2a53c95f6781ed9130a57e179078ce09b654f96b79c675a96fdf5cc";
const FINAL_RECEIPT: &str = "/var/lib/jetstreamer-epoch140-gap-metadata-20261021-v1/complete.json";
const FINAL_SHA: &str = "21427d5debbc22ab44c337fb32679620ec663f44c52c5ceeb7100fcb450f8fe4";
const TARGETS: usize = 18283;
const BOUNDARIES: usize = 84597;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    diagnostic: Bound,
    output_directory: PathBuf,
}
fn read(b: &Bound, max: u64, immutable: bool) -> Result<Value> {
    Ok(serde_json::from_slice(&evidence::bound_file(
        &b.path, &b.sha256, max, immutable,
    )?)?)
}
fn hash(s: &str) -> Result<[u8; 32]> {
    let h: [u8; 32] = bs58::decode(s)
        .into_vec()
        .map_err(|e| anyhow::anyhow!("invalid boundary base58:{e}"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("wrong boundary length"))?;
    ensure!(
        bs58::encode(h).into_string() == s,
        "noncanonical boundary hash"
    );
    Ok(h)
}
fn deny(v: &Value) -> Result<()> {
    for flag in [
        "canonical_ancestry_proven",
        "source_completeness_proven",
        "live_state_proven",
        "runtime_boundary_input_authorized",
        "replay_launch_authorized",
        "runtime_promotion_authorized",
        "publication_authorized",
        "r2_mutations",
    ] {
        ensure!(v[flag] == false, "diagnostic acquired authority:{flag}");
    }
    Ok(())
}
fn terminal_value(v: &Value) -> Result<()> {
    for (k, x) in [
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
        ensure!(v[k] == x, "PoH diagnostic not exact clean terminal:{k}");
    }
    Ok(())
}
fn terminal() -> Result<Value> {
    let o=Command::new("/usr/bin/systemctl").args(["show",UNIT,"--property=InvocationID,MainPID,NRestarts,Restart,Result,ExecMainStatus,ActiveState,SubState,Type"]).output()?;
    ensure!(
        o.status.success() && o.stdout.len() <= 32768,
        "PoH terminal query failed"
    );
    let text = std::str::from_utf8(&o.stdout)?;
    let fields: std::collections::BTreeMap<_, _> = text
        .lines()
        .map(|s| s.split_once('=').context("PoH property malformed"))
        .collect::<Result<_>>()?;
    let v = json!(fields);
    terminal_value(&v)?;
    Ok(v)
}
fn manifest(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-epoch141-census-poh-diagnostic-v1"
            && v["epoch"] == 141
            && v["tool_sha256"] == DIAGNOSTIC_SHA
            && v["plan"]["sha256"] == DIAGNOSTIC_PLAN_SHA
            && v["plan"]["path"]
                == "/usr/local/lib/jetstreamer/horizon-census141-poh-candidate-20261022-v2/plan.json"
            && v["attempted_targets"] == TARGETS
            && v["passed_targets"] == TARGETS
            && v["failed_targets"] == 0
            && v["verified_boundary_count"] == BOUNDARIES
            && v["full_census_poh_chains_verified"] == true
            && v["diagnostic_only"] == true
            && v["recovered_target_count"] == 0
            && v["target_receipts"]
                .as_array()
                .is_some_and(|a| a.len() == TARGETS)
            && v["acquisition"]["path"] == format!("{RAW_ROOT}/all-target-acquisition.json")
            && v["acquisition"]["sha256"] == RAW_SHA,
        "not the complete exact141PoH diagnostic"
    );
    deny(v)?;
    ensure!(
        v["retirement_authorized"] == false && v["remote_mutations"] == false,
        "PoH completion acquired authority"
    );
    Ok(())
}
fn boundary_slots(
    m: &finalized::Metadata,
    d: &Value,
    seen: &mut BTreeSet<[u8; 32]>,
) -> Result<Value> {
    let span = m
        .slot
        .checked_sub(m.parent_slot)
        .filter(|n| (2..=64).contains(n))
        .context("invalid gap span")?;
    ensure!(
        d["diagnostic_only"] == true && d["executed_hashes"].as_u64() == span.checked_mul(800_000),
        "PoH work differs from bound64tick/12500hash clock"
    );
    let rows = d["boundaries"].as_array().context("missing boundaries")?;
    ensure!(rows.len() as u64 == span, "incomplete boundary group");
    let final_hash = hash(&m.final_poh_hash)?;
    let mut local = BTreeSet::new();
    let mut out = Vec::with_capacity(rows.len());
    for (index, b) in rows.iter().enumerate() {
        let step = index as u64 + 1;
        ensure!(
            b["slot"].as_u64() == m.parent_slot.checked_add(step) && b["tick_ordinal"] == step * 64,
            "boundary order/slot/tick ordinal differs"
        );
        let text = b["hash"].as_str().context("boundary hash missing")?;
        let h = hash(text)?;
        ensure!(
            !seen.contains(&h) && local.insert(h),
            "repeated hidden/final boundary hash"
        );
        if step == span {
            ensure!(
                h == final_hash,
                "final boundary disagrees with finalized blockhash"
            );
        }
        out.push(json!({"tick_ordinal":step*64,"hash":text}));
    }
    // Failed groups must not contaminate successful prior coverage.
    seen.extend(local);
    Ok(json!({"slot":m.slot,"parent_slot":m.parent_slot,"boundaries":out}))
}
fn target(
    m: &finalized::Metadata,
    v: &Value,
    raw: &Bound,
    seen: &mut BTreeSet<[u8; 32]>,
) -> Result<Value> {
    ensure!(
        v["schema"] == "jetstreamer-epoch141-census-target-poh-diagnostic-v1"
            && v["epoch"] == 141
            && v["slot"] == m.slot
            && v["parent_slot"] == m.parent_slot
            && v["diagnostic_passed"] == true
            && v["error"].is_null()
            && v["raw_target"] == serde_json::to_value(raw)?
            && v["finalized_metadata"] == serde_json::to_value(m)?,
        "target/source/finalized lineage changed"
    );
    deny(v)?;
    let byte = &v["diagnostic"]["byte_observations"];
    ensure!(
        byte["final_entry_matches_finalized_hash"] == true
            && byte["zero_work_entries"] == 0
            && byte["last_entry_hash"] == json!(hash(&m.final_poh_hash)?)
            && byte["publication_authorized"] == false
            && byte["canonical_ancestry_proven"] == false
            && byte["poh_chain_verified"] == false
            && byte["runtime_clock_authenticated"] == false,
        "byte-only observations changed"
    );
    boundary_slots(m, &v["diagnostic"], seen)
}
fn guard(root: &Path, start: Instant) -> Result<()> {
    ensure!(
        start.elapsed().as_secs() < 600,
        "boundary collection deadline exceeded"
    );
    let path = std::ffi::CString::new(root.as_os_str().as_encoded_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } == 0,
        "collection filesystem unreadable"
    );
    let stat = unsafe { stat.assume_init() };
    ensure!(
        (stat.f_bavail as u128) * (stat.f_frsize as u128) >= (100u128 << 30) + (64u128 << 20),
        "OS protected reserve unavailable"
    );
    Ok(())
}
fn run() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    ensure!(
        a.len() == 7
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256"
            && matches!(a[6].as_str(), "--check-only" | "--run")
            && unsafe { libc::geteuid() } == 0,
        "usage: boundary-collect PLAN --plan-sha256 SHA --self-sha256 SHA --check-only|--run"
    );
    evidence::bound_file(&fs::read_link("/proc/self/exe")?, &a[5], 128 << 20, true)?;
    let pb = Bound {
        path: a[1].clone().into(),
        sha256: a[3].clone(),
    };
    let p: Plan = serde_json::from_value(read(&pb, 1 << 20, true)?)?;
    ensure!(
        p.schema == "jetstreamer-epoch141-census-boundary-collection-plan-v1"
            && p.diagnostic.path == Path::new(ROOT).join("completion.json")
            && evidence::is_sha(&p.diagnostic.sha256)
            && p.output_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && p.output_directory.file_name().is_some_and(|n| n
                .to_string_lossy()
                .starts_with("horizon-epoch141-boundary-collection-")),
        "foreign boundary collection plan"
    );
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
        "output not empty/root-private OS directory"
    );
    guard(&p.output_directory, start)?;
    let owner = terminal()?;
    let completed = read(&p.diagnostic, 8 << 20, false)?;
    manifest(&completed)?;
    let intent = Bound {
        path: Path::new(ROOT).join("intent.json"),
        sha256: INTENT_SHA.into(),
    };
    let iv = read(&intent, 1 << 20, false)?;
    ensure!(
        iv["schema"] == "jetstreamer-epoch141-census-poh-intent-v2"
            && iv["owner"]["Id"] == UNIT
            && iv["owner"]["InvocationID"] == IID
            && iv["tool_sha256"] == DIAGNOSTIC_SHA
            && iv["plan"] == completed["plan"]
            && iv["acquisition"] == completed["acquisition"],
        "closed diagnostic launch changed"
    );
    let raw: Bound = serde_json::from_value(completed["acquisition"].clone())?;
    let rv = read(&raw, 8 << 20, false)?;
    ensure!(
        rv["schema"] == "jetstreamer-epoch141-native-all-target-acquisition-v2"
            && rv["native_session_complete"] == true
            && rv["complete_retained_census_revalidated_after_close"] == true
            && rv["full_target_raw_acquisition_complete"] == true
            && rv["raw_acquired_target_count"] == TARGETS
            && rv["recovered_target_count"] == 0
            && rv["publication_authorized"] == false,
        "native input not complete"
    );
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
    ensure!(
        clock.ticks_per_slot == 64 && clock.hashes_per_tick == 12500,
        "clock changed"
    );
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
            && metadata
                .windows(2)
                .all(|w| w[0].slot <= w[1].parent_slot && w[0].slot < w[1].slot)
            && metadata.iter().try_fold(0u64, |s, m| s
                .checked_add(m.slot.checked_sub(m.parent_slot)?))
                == Some(BOUNDARIES as u64),
        "fixed boundary/gap census differs"
    );
    let raw_targets = rv["target_receipts"]
        .as_array()
        .context("raw target bindings missing")?;
    ensure!(
        raw_targets.len() == TARGETS,
        "raw target binding census changed"
    );
    let diagnostics: Vec<Bound> = serde_json::from_value(completed["target_receipts"].clone())?;
    for (b, m) in diagnostics.iter().zip(&metadata) {
        ensure!(
            b.path
                == Path::new(ROOT)
                    .join("targets")
                    .join(format!("slot-{}.json", m.slot)),
            "missing,reordered,duplicate or foreign PoH target"
        );
    }
    terminal()?;
    guard(&p.output_directory, start)?;
    if a[6] == "--check-only" {
        println!(
            "complete closed PoH/source/clock/finalized scope bound; no boundary target reads,output or runtime authority"
        );
        return Ok(());
    }
    evidence::write_receipt(
        &p.output_directory.join("intent.json"),
        &json!({"schema":"jetstreamer-epoch141-boundary-collection-intent-v1","plan":pb,"tool_sha256":a[5],"diagnostic":p.diagnostic,"diagnostic_intent":intent,"diagnostic_terminal":owner,"acquisition":raw,"clock":clock,"runtime_boundary_input_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    let mut seen = BTreeSet::new();
    let mut slots = Vec::with_capacity(TARGETS);
    for (index, ((b, m), r)) in diagnostics
        .iter()
        .zip(&metadata)
        .zip(raw_targets)
        .enumerate()
    {
        if index.is_multiple_of(100) {
            guard(&p.output_directory, start)?;
        }
        ensure!(r["slot"] == m.slot, "raw target order changed");
        let raw_target = Bound {
            path: r["path"].as_str().context("raw target path")?.into(),
            sha256: r["sha256"].as_str().context("raw target digest")?.into(),
        };
        ensure!(
            raw_target.path
                == Path::new(RAW_ROOT)
                    .join("target-acquisitions")
                    .join(format!("slot-{}.json", m.slot))
                && evidence::is_sha(&raw_target.sha256),
            "raw target namespace changed"
        );
        slots.push(target(
            m,
            &read(b, 1 << 20, false)?,
            &raw_target,
            &mut seen,
        )?);
    }
    ensure!(
        slots.len() == TARGETS && seen.len() == BOUNDARIES,
        "incomplete/duplicate boundary census"
    );
    // Rehash every diagnostic target after collection; a matching top-level
    // manifest alone cannot prove its mutable child files stayed unchanged.
    for (index, b) in diagnostics.iter().enumerate() {
        if index.is_multiple_of(100) {
            guard(&p.output_directory, start)?;
        }
        read(b, 1 << 20, false)?;
    }
    read(&p.diagnostic, 8 << 20, false)?;
    read(&intent, 1 << 20, false)?;
    read(&raw, 8 << 20, false)?;
    read(&pb, 1 << 20, true)?;
    finalized::validate_complete_collection(
        Path::new(FINAL_PLAN),
        FINAL_PLAN_SHA,
        Path::new(FINAL_RECEIPT),
        FINAL_SHA,
    )?;
    terminal()?;
    guard(&p.output_directory, start)?;
    let value = json!({"schema":"jetstreamer-epoch141-decoded-gap-boundaries-v1","slots":slots});
    ensure!(
        serde_json::to_vec_pretty(&value)?.len() < 32 << 20,
        "boundary output exceeds cap"
    );
    let output = p.output_directory.join("boundaries.json");
    evidence::write_receipt(&output, &value)?;
    let binding = Bound {
        sha256: evidence::sha(&fs::read(&output)?),
        path: output,
    };
    read(&binding, 32 << 20, false)?;
    let result = json!({"schema":"jetstreamer-epoch141-collected-gap-boundaries-v1","epoch":141,"plan":pb,"tool_sha256":a[5],"diagnostic":p.diagnostic,"diagnostic_intent":intent,"diagnostic_terminal":owner,"acquisition":raw,"finalized_collection":{"path":FINAL_RECEIPT,"sha256":FINAL_SHA},"clock":clock,"output":binding,"target_count":TARGETS,"total_boundaries":BOUNDARIES,"hidden_boundaries":BOUNDARIES-TARGETS,"all_boundary_hashes_distinct":true,"finalized_parent_and_final_hash_matches":true,"complete_diagnostic_lineage_validated":true,"elapsed_seconds":start.elapsed().as_secs(),"canonical_ancestry_proven":false,"source_completeness_proven":false,"live_state_proven":false,"runtime_boundary_input_authorized":false,"replay_launch_authorized":false,"runtime_promotion_authorized":false,"publication_authorized":false,"retirement_authorized":false,"remote_mutations":false,"r2_mutations":false});
    ensure!(
        serde_json::to_vec_pretty(&result)?.len() < 16 << 20,
        "collection receipt exceeds cap"
    );
    evidence::write_receipt(&p.output_directory.join("collection.json"), &result)?;
    File::open(&p.output_directory)?.sync_all()?;
    println!(
        "all18283target84597boundaries collected privately; no runtime/replay/publication authority"
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("boundary collection failed closed:{e:#}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "root retained first-target boundary fixture only; no full-census claim,output or live-owner access"]
    fn actual_retained_five_boundaries_match_finalized_metadata() {
        let p=read(&Bound {path:"/var/lib/jetstreamer/horizon-epoch141-first-target-poh-diagnostic-20261022-v1/poh.json".into(),sha256:"8594d2f391fa88f4a2b8f2936028e02dcad45769f614ff9de51c0c5db836ba1f".into()},1<<20,false).unwrap();
        assert_eq!(
            p["schema"],
            "jetstreamer-epoch141-first-target-poh-diagnostic-v1"
        );
        assert_eq!(p["diagnostic_passed"], true);
        assert_eq!(p["poh_chain_verified"], true);
        let t = read(
            &Bound {
                path: epoch141_acquired_input::TARGET.into(),
                sha256: epoch141_acquired_input::TARGET_SHA.into(),
            },
            1 << 20,
            false,
        )
        .unwrap();
        let m: finalized::Metadata = serde_json::from_value(t["metadata"].clone()).unwrap();
        let mut seen = BTreeSet::new();
        let value = boundary_slots(&m, &p["diagnostic"], &mut seen).unwrap();
        assert_eq!(seen.len(), 5);
        assert_eq!(value["slot"], 60911776);
        assert_eq!(
            value["boundaries"][0]["hash"],
            "4D13FksJYTUtKqkpuEmza1r5ouUeKqmLxnfbcNSu5pVx"
        );
        assert_eq!(value["boundaries"][4]["hash"], m.final_poh_hash);
    }
    fn fixture() -> (finalized::Metadata, Value) {
        let m = finalized::Metadata {
            slot: 100,
            parent_slot: 97,
            final_poh_hash: bs58::encode([3u8; 32]).into_string(),
            previous_poh_hash: bs58::encode([0u8; 32]).into_string(),
        };
        let rows:Vec<_>=(1..=3u8).map(|n|json!({"slot":97+n as u64,"tick_ordinal":64*n as u64,"hash":bs58::encode([n;32]).into_string()})).collect();
        (
            m,
            json!({"diagnostic_only":true,"executed_hashes":2400000,"boundaries":rows}),
        )
    }
    #[test]
    fn exact_ordered_boundaries_are_complete_distinct_and_final_anchor_bound() {
        let (m, d) = fixture();
        let mut seen = BTreeSet::new();
        let result = boundary_slots(&m, &d, &mut seen).unwrap();
        assert_eq!(seen.len(), 3);
        assert_eq!(result["boundaries"][2]["hash"], m.final_poh_hash);
        assert!(boundary_slots(&m, &d, &mut seen).is_err());
    }
    #[test]
    fn missing_reordered_repeated_wrong_tick_and_wrong_final_never_collect() {
        let (m, d) = fixture();
        for which in 0..7 {
            let mut bad = d.clone();
            match which {
                0 => {
                    bad["boundaries"].as_array_mut().unwrap().pop();
                }
                1 => {
                    bad["boundaries"][1]["slot"] = json!(98);
                }
                2 => {
                    bad["boundaries"][1]["tick_ordinal"] = json!(64);
                }
                3 => {
                    bad["boundaries"][1]["hash"] = bad["boundaries"][0]["hash"].clone();
                }
                4 => {
                    bad["boundaries"][2]["hash"] = json!(bs58::encode([4u8; 32]).into_string());
                }
                5 => {
                    bad["executed_hashes"] = json!(2399999);
                }
                _ => {
                    bad["boundaries"][0]["hash"] = json!("invalid");
                }
            }
            let mut seen = BTreeSet::new();
            assert!(boundary_slots(&m, &bad, &mut seen).is_err(), "{which}");
            assert!(seen.is_empty());
        }
    }
    #[test]
    fn partial_completion_and_live_owner_are_not_collection_authority() {
        assert!(manifest(&json!({"schema":"jetstreamer-epoch141-census-poh-diagnostic-v1","passed_targets":700})).is_err());
        let v = json!({"InvocationID":IID,"MainPID":"0","NRestarts":"0","Restart":"no","Result":"success","ExecMainStatus":"0","ActiveState":"active","SubState":"exited","Type":"exec"});
        terminal_value(&v).unwrap();
        for (k, x) in [
            ("InvocationID", "foreign"),
            ("MainPID", "694"),
            ("NRestarts", "1"),
            ("SubState", "running"),
            ("Result", "exit-code"),
        ] {
            let mut bad = v.clone();
            bad[k] = json!(x);
            assert!(terminal_value(&bad).is_err());
        }
    }
    #[test]
    fn complete_header_cannot_drop_targets_change_tool_or_grant_authority() {
        let mut v = json!({"schema":"jetstreamer-epoch141-census-poh-diagnostic-v1","epoch":141,"tool_sha256":DIAGNOSTIC_SHA,"plan":{"path":"/usr/local/lib/jetstreamer/horizon-census141-poh-candidate-20261022-v2/plan.json","sha256":DIAGNOSTIC_PLAN_SHA},"attempted_targets":TARGETS,"passed_targets":TARGETS,"failed_targets":0,"verified_boundary_count":BOUNDARIES,"full_census_poh_chains_verified":true,"diagnostic_only":true,"recovered_target_count":0,"target_receipts":vec![Value::Null;TARGETS],"acquisition":{"path":format!("{RAW_ROOT}/all-target-acquisition.json"),"sha256":RAW_SHA},"canonical_ancestry_proven":false,"source_completeness_proven":false,"live_state_proven":false,"runtime_boundary_input_authorized":false,"replay_launch_authorized":false,"runtime_promotion_authorized":false,"publication_authorized":false,"r2_mutations":false,"retirement_authorized":false,"remote_mutations":false});
        manifest(&v).unwrap();
        for key in v.as_object().unwrap().keys() {
            let mut bad = v.clone();
            bad[key] = Value::Null;
            assert!(manifest(&bad).is_err(), "{key}");
        }
        v["runtime_boundary_input_authorized"] = json!(true);
        assert!(manifest(&v).is_err());
    }
    #[test]
    fn target_binds_raw_digest_metadata_success_and_non_authorizing_byte_observations() {
        let (m, mut d) = fixture();
        d["byte_observations"] = json!({"final_entry_matches_finalized_hash":true,"zero_work_entries":0,"last_entry_hash":vec![3u8;32],"publication_authorized":false,"canonical_ancestry_proven":false,"poh_chain_verified":false,"runtime_clock_authenticated":false});
        let raw = Bound {
            path: "/raw".into(),
            sha256: "a".repeat(64),
        };
        let v = json!({"schema":"jetstreamer-epoch141-census-target-poh-diagnostic-v1","epoch":141,"slot":m.slot,"parent_slot":m.parent_slot,"diagnostic_passed":true,"error":null,"raw_target":raw,"finalized_metadata":m,"diagnostic":d,"canonical_ancestry_proven":false,"source_completeness_proven":false,"live_state_proven":false,"runtime_boundary_input_authorized":false,"replay_launch_authorized":false,"runtime_promotion_authorized":false,"publication_authorized":false,"r2_mutations":false});
        target(&m, &v, &raw, &mut BTreeSet::new()).unwrap();
        for key in [
            "schema",
            "epoch",
            "slot",
            "parent_slot",
            "diagnostic_passed",
            "raw_target",
            "finalized_metadata",
            "diagnostic",
            "runtime_boundary_input_authorized",
        ] {
            let mut bad = v.clone();
            bad[key] = Value::Null;
            assert!(
                target(&m, &bad, &raw, &mut BTreeSet::new()).is_err(),
                "{key}"
            );
        }
        let mut bad = v;
        bad["diagnostic"]["byte_observations"]["poh_chain_verified"] = json!(true);
        assert!(target(&m, &bad, &raw, &mut BTreeSet::new()).is_err());
    }
}
