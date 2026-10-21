//! Bounded identical-worker historical-rate prior while exact223 has no markers.
//! Does not relax the normal estimator's requirement for measured current rates.
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

const UNIT: &str = "horizon-qualify-223-singleton-postcount-ad1d65a-v1.service";
const IID: &str = "04ef9d97a36446d49b452d982cb0be46";
const OLD_IID: &str = "c2adebaad0cb42b385156631156813fe";
const OLD_CID: &str = "0b69b5009dc74bbda94b94d059a3daa7";
const OLD_OBSERVER_SHA: &str = "e445a035f6cff2f9886ac5825498dcf37f24de1c7a7ff78f169b17aea8033215";
const OLD_MODEL_SHA: &str = "4856245e3842d784e090b2a17a80057a885806f14c7cddeb697f5e6963440cae";
const LAUNCH_SHA: &str = "03230e9c0aabe01b3e3da54fc5bbaf33f38bf9bcfece0b0d6647c95846bed511";
const DOWNSTREAM: u64 = 8779;
const STARTUP_MILLIS: u64 = 3600000;
const FIRST_REPLAY_SLOT: u64 = 96335539;
const LAST_SLOT: u64 = 96767999;
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
    historical_observer: Bound,
    prior_model: Bound,
    launch: Bound,
    output: PathBuf,
}
fn read(b: &Bound, immutable: bool) -> Result<Value> {
    Ok(serde_json::from_slice(&evidence::bound_file(
        &b.path,
        &b.sha256,
        8 * 1024 * 1024,
        immutable,
    )?)?)
}
fn row<'a>(observer: &'a Value, range: &str) -> Result<&'a Value> {
    ensure!(
        observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2",
        "wrong observer schema"
    );
    let rows: Vec<_> = observer["replays"]
        .as_array()
        .context("missing replay census")?
        .iter()
        .filter(|r| r["range"] == range)
        .collect();
    ensure!(rows.len() == 1, "missing or duplicate replay range");
    Ok(rows[0])
}
fn live(r: &Value, cid: &str, pid: &str) -> Result<()> {
    ensure!(
        r["invocation_binding_stable"] == true,
        "unstable observer identity"
    );
    for (key, id) in [("controller_after", cid), ("producer_after", pid)] {
        ensure!(
            r[key]["invocation_id"] == id
                && r[key]["restarts"] == 0
                && r[key]["active_state"] == "active"
                && r[key]["sub_state"] == "running",
            "wrong or non-running owner"
        );
    }
    Ok(())
}
fn startup(r: &Value) -> Result<()> {
    live(r, IID, IID)?;
    ensure!(
        r["controller_after"]["unit"] == UNIT && r["producer_after"]["unit"] == UNIT,
        "wrong standalone owner"
    );
    ensure!(
        r["useful_work"]["matching_markers"] == 0
            && r["useful_work"]["sufficient_for_rates"] == false
            && r["useful_work"]["last"].is_null()
            && r["useful_work"]["first"].is_null()
            && r["useful_work"]["slots_per_second"].is_null(),
        "use current progress/rate estimator once markers exist"
    );
    ensure!(
        r["worker_after"]["matching_workers"] == 1
            && r["worker_before"]["pid"] == r["worker_after"]["pid"]
            && r["worker_after"]["executable_beneath_bound_scratch"] == true,
        "startup lacks one stable bound worker"
    );
    Ok(())
}
fn historical_rate(r: &Value) -> Result<f64> {
    live(r, OLD_CID, OLD_IID)?;
    let p = &r["useful_work"];
    ensure!(
        p["sufficient_for_rates"] == true
            && p["counter_resets"] == 0
            && p["last"]["terminal_slot"] == LAST_SLOT
            && p["last"]["slot"]
                .as_u64()
                .is_some_and(|s| (96336000..=LAST_SLOT).contains(&s)),
        "historical rate is not from epoch223"
    );
    let rate = p["slots_per_second"]
        .as_f64()
        .context("historical rate missing")?;
    ensure!(rate.is_finite() && rate > 0.0, "invalid historical rate");
    Ok(rate)
}
fn remaining(rate: f64, elapsed: u64) -> Result<u64> {
    ensure!(
        rate.is_finite() && rate > 0.0 && elapsed < STARTUP_MILLIS,
        "invalid rate or expired startup prior"
    );
    let seconds = ((LAST_SLOT - FIRST_REPLAY_SLOT + 1) as f64 / rate
        + (STARTUP_MILLIS - elapsed) as f64 / 1000.0
        + DOWNSTREAM as f64)
        .round();
    ensure!(
        seconds.is_finite() && seconds > 0.0 && seconds < (u64::MAX / 1000) as f64,
        "ETA overflow"
    );
    Ok((seconds as u64) * 1000)
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
    let plan: Plan = serde_json::from_slice(&evidence::bound_file(
        Path::new(&args[0]),
        &args[1],
        65536,
        true,
    )?)?;
    ensure!(
        plan.schema == "horizon-epoch223-bootstrap-eta-plan-v1"
            && plan.historical_observer.sha256 == OLD_OBSERVER_SHA
            && plan.prior_model.sha256 == OLD_MODEL_SHA
            && plan.launch.sha256 == LAUNCH_SHA,
        "wrong bootstrap prior or launch authority"
    );
    let current = read(&plan.observer, false)?;
    let historical = read(&plan.historical_observer, false)?;
    let model = read(&plan.prior_model, true)?;
    let launch = read(&plan.launch, true)?;
    ensure!(
        launch["epoch"] == 223
            && launch["invocation_id"] == IID
            && launch["worker_sha256"]
                == "f39140b9a9659e7c6e8207076a2d0c560a6b69df42cc92e19a421cf46c2b761c"
            && launch["bootstrap_slot"] == FIRST_REPLAY_SLOT - 1
            && launch["archive_terminal_slot"] == LAST_SLOT
            && model["ranges"][0]["epoch_downstream_allowance_seconds"]["220"] == DOWNSTREAM,
        "wrong worker, singleton bounds or retained first-epoch delivery allowance"
    );
    ensure!(
        current["replays"].as_array().is_some_and(|r| r.len() == 1),
        "unexpected ordinary replay census"
    );
    let r = row(&current, "223-223")?;
    startup(r)?;
    let rate = historical_rate(row(&historical, "220-223")?)?;
    let unit: clock_binding::Unit = serde_json::from_value(r["producer_after"].clone())?;
    let start = serde_json::to_value(clock_binding::producer_start_proof(
        "223-223",
        &unit,
        current["recorded_at_utc"]
            .as_str()
            .context("sample time missing")?,
    )?)?;
    let sampled = start["sampled_at_unix_micros"]
        .as_u64()
        .context("sample time proof missing")?
        / 1000000;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        sampled <= now && now - sampled <= 1800,
        "stale or future observer"
    );
    let elapsed = start["elapsed_execution_millis"]
        .as_u64()
        .context("elapsed proof missing")?;
    let millis = remaining(rate, elapsed)?;
    evidence::write_receipt(
        &plan.output,
        &json!({"schema":"horizon-epoch223-bootstrap-eta-v1","epoch":223,"phase":"replay","sampled_at_utc":current["recorded_at_utc"],"expected_controller_invocation_id":IID,"expected_producer_invocation_id":IID,"elapsed_execution_millis":elapsed,"estimated_remaining_millis":millis,"basis":"Bounded historical-rate prior for same historical worker while current invocation has no markers; not a measured current rate. Reuse first-in-queue downstream allowance, not old223's last-in-cohort penalty. Includes remaining startup, complete warmup/replay, close/import, independent full/plugin, upload/readback and sidecar commit.","historical_slots_per_second":rate,"replay_slots":LAST_SLOT-FIRST_REPLAY_SLOT+1,"remaining_startup_allowance_millis":STARTUP_MILLIS-elapsed,"downstream_allowance_seconds":DOWNSTREAM,"producer_start_proof":start,"observer":{"path":plan.observer.path,"sha256":plan.observer.sha256},"historical_observer_sha256":OLD_OBSERVER_SHA,"prior_model_sha256":OLD_MODEL_SHA,"launch_sha256":LAUNCH_SHA,"self_sha256":args[2],"plan_sha256":args[1],"replay_launch_authorized":false,"archive_publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    println!("{}", plan.output.display());
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
    fn current() -> Value {
        json!({"invocation_binding_stable":true,"controller_after":{"unit":UNIT,"invocation_id":IID,"restarts":0,"active_state":"active","sub_state":"running"},"producer_after":{"unit":UNIT,"invocation_id":IID,"restarts":0,"active_state":"active","sub_state":"running"},"useful_work":{"matching_markers":0,"sufficient_for_rates":false,"last":null,"first":null,"slots_per_second":null},"worker_before":{"pid":123},"worker_after":{"pid":123,"matching_workers":1,"executable_beneath_bound_scratch":true}})
    }
    #[test]
    fn startup_prior_rejects_current_progress_restarts_wrong_owners_and_workers() {
        let good = current();
        startup(&good).unwrap();
        for (pointer, value) in [
            ("/useful_work/matching_markers", json!(1)),
            ("/useful_work/last", json!({"slot":1})),
            ("/producer_after/invocation_id", json!(OLD_IID)),
            ("/producer_after/restarts", json!(1)),
            ("/worker_after/matching_workers", json!(2)),
            ("/worker_after/pid", json!(124)),
            ("/producer_after/active_state", json!("failed")),
        ] {
            let mut wrong = good.clone();
            *wrong.pointer_mut(pointer).unwrap() = value;
            assert!(startup(&wrong).is_err(), "{pointer}");
        }
    }
    #[test]
    fn definite_estimate_includes_bootstrap_warmup_and_delivery_without_old_cohort_queue() {
        assert_eq!(remaining(1.0, 0).unwrap(), (432461 + 3600 + 8779) * 1000);
        assert_eq!(
            remaining(1.0, 60000).unwrap(),
            (432461 + 3540 + 8779) * 1000
        );
        for rate in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert!(remaining(rate, 0).is_err());
        }
        assert!(remaining(1.0, STARTUP_MILLIS).is_err());
    }
    #[test]
    fn historical_rate_must_be_positive_bound_same_epoch_and_stable() {
        let mut r = current();
        r["controller_after"]["invocation_id"] = json!(OLD_CID);
        r["producer_after"]["invocation_id"] = json!(OLD_IID);
        r["useful_work"] = json!({"sufficient_for_rates":true,"counter_resets":0,"last":{"slot":96540000,"terminal_slot":LAST_SLOT},"slots_per_second":2.0});
        assert_eq!(historical_rate(&r).unwrap(), 2.0);
        r["useful_work"]["last"]["slot"] = json!(95900000);
        assert!(historical_rate(&r).is_err());
    }
}
