//! Prepare a same-clock pending-observer handoff; never stop/start a unit or seal a deployment.
#[allow(dead_code)]
#[path = "../../../horizon_retry6_170_guarded_launch_20261119_v1/src/audit_budget.rs"]
mod audit_budget;
#[allow(dead_code)]
#[path = "../observer170_join.rs"]
mod observer170_join;
use anyhow::{Context, Result, ensure};
use observer170_join::{
    HOME_RUNTIME, bound, home, joined, merge_config, native, read, run, sha, string,
};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
const OBSERVER: &str = "/usr/local/lib/jetstreamer/horizon-observer-exit-census-20261107-v1/jetstreamer-horizon-observe";
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn unix(stamp: &str) -> Result<u64> {
    run(Command::new("/usr/bin/date").args(["-u", "--date", stamp, "+%s"]))?
        .trim()
        .parse()
        .context("scheduled timestamp")
}
fn save(root: &Path, name: &str, value: &Value) -> Result<Value> {
    ensure!(
        !name.contains('/') && name != "." && name != "..",
        "leaf required"
    );
    let path = root.join(name);
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(root)?.sync_all()?;
    Ok(json!({"path":path,"sha256":sha(&bytes)}))
}
fn pending(
    timer: &Value,
    service: &Value,
    timer_name: &str,
    config_path: &str,
    due: u64,
) -> Result<()> {
    let service_name = timer_name
        .strip_suffix(".timer")
        .context("pending timer suffix")?
        .to_owned()
        + ".service";
    ensure!(
        timer["Id"] == timer_name
            && timer["ActiveState"] == "active"
            && timer["SubState"] == "waiting"
            && timer["Job"] == ""
            && timer["Triggers"] == service_name
            && string(timer, "InvocationID")?.len() == 32
            && service["Id"] == service_name
            && service["ActiveState"] == "inactive"
            && service["MainPID"] == "0"
            && service["ControlPID"] == "0"
            && service["Job"] == ""
            && string(service, "ExecStart")?.contains(OBSERVER)
            && string(service, "ExecStart")?.contains(config_path)
            && unix(string(timer, "NextElapseUSecRealtime")?)? == due
            && now()?.checked_add(60).context("clock overflow")? < due,
        "pending observer changed, started or is too near its actual deadline"
    );
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        unsafe { libc::geteuid() } == 0 && args.len() == 4 && args[2] == "--plan-sha256",
        "Root required: prepare_observe170_homeaudit_join PLAN --plan-sha256 SHA"
    );
    let (plan, pb) = read(&args[1])?;
    ensure!(pb["sha256"] == args[3], "input plan digest differs");
    ensure!(
        plan["schema"] == "horizon170-pending-observer-join-plan-v1" && plan["owner"] == "/root",
        "foreign join plan"
    );
    let original = bound(&plan["pending_config"])?;
    let fleet = bound(&plan["previous_fleet"])?;
    audit_budget::validate_fleet_obligation(&fleet["continuing_audit_obligation"])?;
    ensure!(
        fleet["owner"] == "/root"
            && fleet["sole_next_observer"] == plan["pending_config"]
            && original["minimum_interval_seconds"] == 1800
            && original["previous_sample"] == fleet["observer"]["path"]
            && (original["observation_reason"].is_null()
                || original["observation_reason"] == "routine"),
        "accepted pending config/fleet differs"
    );
    bound(&fleet["observer"])?;
    let clock = string(&original, "not_before_utc")?;
    let due = unix(clock)?;
    let old_timer = string(&plan, "pending_timer")?;
    let old_service = old_timer
        .strip_suffix(".timer")
        .context("pending timer")?
        .to_owned()
        + ".service";
    let timer = native(old_timer)?;
    let service = native(&old_service)?;
    pending(
        &timer,
        &service,
        old_timer,
        string(&plan["pending_config"], "path")?,
        due,
    )?;
    let existing = original["replays"].as_array().context("pending peers")?;
    ensure!(
        existing.len() == 2 && existing[0]["range"] == "166" && existing[1]["range"] == "167",
        "exact two-peer predecessor required"
    );
    let mut peers = Vec::new();
    for (row, iid) in existing.iter().zip([
        "4f09db5f45074244a45b06aeef932d1d",
        "a680103e76f546faaf469aa80c35fa3b",
    ]) {
        let unit = string(row, "producer_unit")?;
        let observed = native(unit)?;
        ensure!(
            row["expected_producer_invocation_id"] == iid
                && row["expected_controller_invocation_id"] == iid
                && observed["InvocationID"] == iid
                && observed["ActiveState"] == "active"
                && observed["SubState"] == "running"
                && observed["NRestarts"] == "0"
                && observed["ControlPID"] == "0"
                && observed["Job"] == "",
            "existing peer changed"
        );
        peers.push(observed);
    }
    let (owner, observer) = joined()?;
    let mut config = original.clone();
    let retired = merge_config(&mut config, &observer)?;
    let root = Path::new(string(&plan, "output_directory")?);
    let destination = Path::new(string(&plan, "sealed_config_directory")?);
    let sample = Path::new(string(&plan, "successor_sample_path")?);
    for path in [root, destination, sample] {
        ensure!(
            path.starts_with(HOME_RUNTIME)
                && path.components().all(|p| matches!(
                    p,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                ))
                && !path.try_exists()?,
            "new HOME output required"
        );
        home(path.parent().context("output parent")?)?;
    }
    let new_unit = string(&plan, "successor_unit")?;
    ensure!(
        new_unit.starts_with("horizon-observer-")
            && new_unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            && format!("{new_unit}.timer") != old_timer
            && native(&format!("{new_unit}.timer"))?["LoadState"] == "not-found"
            && native(&format!("{new_unit}.service"))?["LoadState"] == "not-found",
        "successor unit must be fresh"
    );
    config["output"] = json!(sample);
    ensure!(
        config["not_before_utc"] == original["not_before_utc"]
            && config["previous_sample"] == original["previous_sample"],
        "join moved the pending cadence"
    );
    let timer_after = native(old_timer)?;
    let service_after = native(&old_service)?;
    pending(
        &timer_after,
        &service_after,
        old_timer,
        string(&plan["pending_config"], "path")?,
        due,
    )?;
    ensure!(
        timer_after == timer
            && service_after == service
            && bound(&plan["pending_config"])? == original
            && bound(&plan["previous_fleet"])? == fleet,
        "predecessor changed during join preparation"
    );
    for peer in &peers {
        ensure!(
            native(string(peer, "Id")?)? == *peer,
            "original peer changed during join preparation"
        );
    }
    fs::DirBuilder::new().mode(0o700).create(root)?;
    home(root)?;
    let cb = save(root, "next-observer.json", &config)?;
    let seal = save(
        root,
        "seal-plan.json",
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":destination,
        "members":[{"source":cb["path"],"name":"next-observer.json","sha256":cb["sha256"],"mode":292}]}),
    )?;
    let owner_binding = save(root, "ACTUAL170_JOIN_IDENTITY.json", &owner)?;
    let retained = save(root, "UNCHANGED_PREDECESSOR_FLEET.json", &fleet)?;
    observer170_join::preserve_fleet_obligations(&fleet, &bound(&retained)?)?;
    let handoff = save(
        root,
        "PENDING_JOIN_HANDOFF.json",
        &json!({"schema":"horizon170-pending-observer-join-preparation-v1","owner":"/root",
        "input_plan":pb,"previous_fleet":plan["previous_fleet"],"retained_fleet":retained,
        "old_config":plan["pending_config"],"old_timer_native":timer,"old_service_native":service,"unchanged_peers":peers,
        "new_config_source":cb,"new_config_destination":destination.join("next-observer.json"),"seal_plan":seal,
        "successor_unit":new_unit,"successor_sample_path":sample,"actual170_join_identity":owner_binding,
        "historical_terminal170_diagnostics":retired,"same_scheduled_unix_seconds":due,"same_not_before_utc":clock,"cadence_seconds":1800,
        "status_bindings_preserved":true,"resource_promises_unchanged":true,"new_capacity_credit_bytes":0,
        "timer_replaced":false,"sample_created":false,"deployment_sealed":false,"replay_launch_authorized":false,
        "remote_mutations":false,"observer_handoff_execution_authorized":false,"recorded_unix_seconds":now()?,
        "required_activation":"Normally seal the proposed config. Revalidate this exact pending timer, idle service, owner and deadline immediately before a separate guarded same-clock handoff. Stop and drain the old timer before arming the new one; verify exactly one waiting timer and bind its actual invocation. If the original clock is due or has fired, discard this preparation and use the next accepted cycle. Do not move the clock or manufacture a new sample."}),
    )?;
    println!("{handoff}");
    Ok(())
}
