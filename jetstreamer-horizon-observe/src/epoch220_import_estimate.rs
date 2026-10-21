//! Incident-scoped historical-duration prior for the live 220-222 importer.
#[allow(dead_code)]
#[path = "status_estimate.rs"]
mod clock_binding;
#[allow(dead_code)]
#[path = "../../jetstreamer-utils/src/epoch141_ledger_common.rs"]
mod evidence;
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    env, fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
const UNIT: &str = "horizon-publish-220-222-failed-prefix-1880b7b-v1.service";
const IID: &str = "c51f76a285804a8399a81aedc32bfa41";
const MODEL_SHA: &str = "4856245e3842d784e090b2a17a80057a885806f14c7cddeb697f5e6963440cae";
const READ_SHAS: [&str; 3] = [
    "c20a4f1d69025ed89e01a60be5cade6226e66d67bdb310bbfe10587407d74fa3",
    "77eec7e2df95921eedcf6b0a92e50101aadc03f11e044837cdc8e1175334d73e",
    "4f6de3d6df60b2d277ac607c5e2b077c2d2209a3e833758a23723bf383274b7b",
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    observer: Bound,
    fleet: Bound,
    prior_model: Bound,
    private_full_receipts: Vec<Bound>,
    output: PathBuf,
}
fn read(b: &Bound, immutable: bool) -> Result<Value> {
    Ok(serde_json::from_slice(&evidence::bound_file(
        &b.path,
        &b.sha256,
        16 * 1024 * 1024,
        immutable,
    )?)?)
}
fn prior_budget(maximum_full_millis: u64) -> Result<u64> {
    // Explicit scheduling assumption: 25% overhead for normal semantic/context
    // collection, trusted219 anchoring and hashing beyond the measured reader.
    ensure!(maximum_full_millis > 0, "empty duration prior");
    maximum_full_millis
        .checked_mul(5)
        .and_then(|n| n.checked_add(3))
        .map(|n| n / 4)
        .context("duration overflow")
}
fn remaining(budget: u64, elapsed: u64, downstream: u64) -> Result<u64> {
    ensure!(
        elapsed < budget,
        "import duration prior expired: diagnose and revise; do not clamp or invent progress"
    );
    budget
        .checked_sub(elapsed)
        .and_then(|n| downstream.checked_mul(1000).and_then(|d| n.checked_add(d)))
        .context("ETA overflow")
}
fn live_unit(fleet: &Value) -> Result<Value> {
    let active = fleet["active"]
        .as_array()
        .context("fleet active census missing")?;
    let mut unit: Option<Value> = None;
    for epoch in 220..=222 {
        let rows: Vec<_> = active.iter().filter(|a| a["epoch"] == epoch).collect();
        ensure!(
            rows.len() == 1 && rows[0]["phase"] == "local-publication",
            "epoch is not exclusively in importer phase"
        );
        let current = &rows[0]["unit"];
        ensure!(
            current["Id"] == UNIT
                && current["InvocationID"] == IID
                && current["NRestarts"] == "0"
                && current["ActiveState"] == "active"
                && current["SubState"] == "running",
            "wrong or non-running importer"
        );
        if let Some(prior) = &unit {
            ensure!(prior == current, "inconsistent importer census");
        } else {
            unit = Some(current.clone());
        }
    }
    unit.context("importer missing")
}
fn run() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let args: Vec<_> = env::args().skip(1).collect();
    ensure!(args.len() == 3, "usage: PLAN PLAN_SHA256 SELF_SHA256");
    evidence::bound_file(
        &fs::read_link("/proc/self/exe")?,
        &args[2],
        64 * 1024 * 1024,
        true,
    )?;
    let p: Plan = serde_json::from_slice(&evidence::bound_file(
        Path::new(&args[0]),
        &args[1],
        65536,
        true,
    )?)?;
    ensure!(
        p.schema == "horizon-epoch220-import-estimate-plan-v1"
            && p.prior_model.sha256 == MODEL_SHA
            && p.private_full_receipts.len() == 3,
        "wrong estimate scope/prior"
    );
    let observer = read(&p.observer, false)?;
    let fleet = read(&p.fleet, false)?;
    let model = read(&p.prior_model, true)?;
    ensure!(
        observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && fleet["first_epoch"] == 201
            && fleet["last_epoch"] == 300
            && fleet["sampled_at_utc"] == observer["recorded_at_utc"]
            && fleet["observer_sha256"] == p.observer.sha256,
        "observer/fleet binding differs"
    );
    let u = live_unit(&fleet)?;
    let clock: clock_binding::Unit = serde_json::from_value(
        json!({"unit":UNIT,"invocation_id":IID,"restarts":0,"active_state":"active","sub_state":"running"}),
    )?;
    let start = serde_json::to_value(clock_binding::producer_start_proof(
        "220-222",
        &clock,
        observer["recorded_at_utc"]
            .as_str()
            .context("sample timestamp missing")?,
    )?)?;
    let sampled = start["sampled_at_unix_micros"]
        .as_u64()
        .context("clock missing")?
        / 1000000;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        sampled <= now && now - sampled <= 1800,
        "stale or future sample"
    );
    let elapsed = start["elapsed_execution_millis"]
        .as_u64()
        .context("elapsed missing")?;
    let mut durations = Vec::new();
    for (i, b) in p.private_full_receipts.iter().enumerate() {
        ensure!(b.sha256 == READ_SHAS[i], "wrong private reader evidence");
        let r = read(b, true)?;
        ensure!(
            r["schema"] == "horizon-private-full-verification-v1"
                && r["status"] == "passed"
                && r["epoch"] == 220 + i as u64
                && r["command"]["threads"] == 8
                && r["command"]["full"] == true
                && r["command"]["internal_full"] == true,
            "wrong reader/duration basis"
        );
        let a = r["unit"]["journal_first_realtime_timestamp_us"]
            .as_u64()
            .context("reader start missing")?;
        let z = r["unit"]["journal_last_realtime_timestamp_us"]
            .as_u64()
            .context("reader end missing")?;
        ensure!(z > a, "invalid prior duration");
        durations.push((z - a).div_ceil(1000));
    }
    let budget = prior_budget(*durations.iter().max().context("duration missing")?)?;
    let allowances = [8779, 11221, 13663];
    let mut estimates = Vec::new();
    for (i, downstream) in allowances.into_iter().enumerate() {
        let epoch = 220 + i as u64;
        ensure!(
            model["ranges"][0]["epoch_downstream_allowance_seconds"][epoch.to_string()]
                == downstream,
            "downstream prior differs"
        );
        estimates.push(json!({"epoch":epoch,"estimated_remaining_millis":remaining(budget,elapsed,downstream)?,"downstream_allowance_seconds":downstream}));
    }
    evidence::write_receipt(
        &p.output,
        &json!({"schema":"horizon-epoch220-import-estimates-v1","sampled_at_utc":observer["recorded_at_utc"],"phase":"publication","unit":u,"phase_elapsed_millis":elapsed,"phase_start_proof":start,"private_full_duration_millis":durations,"projected_import_duration_millis":budget,"estimate_basis":"Historical maximum8-thread private full reread duration plus explicit25% normal semantic/context/hash/anchor overhead prior; remaining importer time plus retained per-epoch full/plugin/upload/readback/sidecar allowance. No measured current progress is claimed. Prior expires rather than clamping an overdue live job.","estimates":estimates,"observer_sha256":p.observer.sha256,"fleet_sha256":p.fleet.sha256,"prior_model_sha256":MODEL_SHA,"private_reader_receipt_shas":READ_SHAS,"plan_sha256":args[1],"self_sha256":args[2],"archive_mutations":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    println!("{}", p.output.display());
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_duration_prior_and_inclusive_downstream() {
        assert_eq!(prior_budget(4000000).unwrap(), 5000000);
        assert_eq!(remaining(5000000, 1000000, 8779).unwrap(), 12779000);
        assert!(remaining(5, 5, 1).is_err());
        assert!(prior_budget(0).is_err());
        assert!(prior_budget(u64::MAX).is_err());
        assert!(remaining(5, 1, u64::MAX).is_err());
    }
    #[test]
    fn must_bind_all_three_epochs_to_one_live_importer() {
        let unit = json!({"Id":UNIT,"InvocationID":IID,"NRestarts":"0","ActiveState":"active","SubState":"running"});
        let good = json!({"active":(220..=222).map(|epoch|json!({"epoch":epoch,"phase":"local-publication","unit":unit})).collect::<Vec<_>>()});
        live_unit(&good).unwrap();
        for (key, value) in [
            ("InvocationID", json!("other")),
            ("NRestarts", json!("1")),
            ("SubState", json!("dead")),
        ] {
            let mut bad = good.clone();
            bad["active"][1]["unit"][key] = value;
            assert!(live_unit(&bad).is_err());
        }
        let mut bad = good;
        bad["active"].as_array_mut().unwrap().pop();
        assert!(live_unit(&bad).is_err());
    }
}
