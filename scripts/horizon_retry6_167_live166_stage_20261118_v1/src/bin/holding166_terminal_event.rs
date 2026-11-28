//! Record completed holding custody and cache retirement without granting admission.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    process::Command,
};

const UNIT: &str = "horizon-closed166-retry6-park-20261119-v1.service";
const IID: &str = "afc04ba6096f4826836919c2020dcdc6";
const START: &str = "/var/lib/jetstreamer/root0832-holding166-event-20261119-v1/EVENT.json";
const CUSTODY: &str = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/receipts/custody-1b3cfb30c50e1072e002c10bb8a2f036b808c76a0458db6a316f575aae671369.json";
const DEPS: &str = "/var/lib/jetstreamer/holding141-deps-retire-20261119-v1/completion.json";
const BUILD: &str = "/var/lib/jetstreamer/holding141-build-retire-20261119-v1/completion.json";
const ROOT: &str = "/var/lib/jetstreamer/root0958-holding166-terminal-cleanup-event-20261119-v1";
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn bound(path: &str) -> Result<Value> {
    Ok(json!({"path":path,"sha256":sha(&fs::read(path)?)}))
}
fn exact(path: &str, digest: &str) -> Result<Value> {
    let bytes = fs::read(path)?;
    ensure!(sha(&bytes) == digest, "evidence changed: {path}");
    Ok(serde_json::from_slice(&bytes)?)
}
fn save(name: &str, value: &Value) -> Result<Value> {
    let path = format!("{ROOT}/{name}");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.sync_all()?;
    File::open(ROOT)?.sync_all()?;
    bound(&path)
}
fn terminal(row: &Value) -> Result<()> {
    for (key, expected) in [
        ("Id", UNIT),
        ("InvocationID", IID),
        ("ActiveState", "active"),
        ("SubState", "exited"),
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("Job", ""),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
        ("Restart", "no"),
        ("TriggeredBy", ""),
    ] {
        ensure!(row[key] == expected, "holding terminal mismatch: {key}");
    }
    Ok(())
}
fn native() -> Result<Value> {
    let out = Command::new("/usr/bin/systemctl").args(["show", UNIT,
        "-pId,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,Job,Result,ExecMainStatus,Restart,TriggeredBy,ExecStart,FragmentPath,DropInPaths"]).output()?;
    ensure!(
        out.status.success() && out.stderr.is_empty(),
        "native capture failed"
    );
    let mut fields = serde_json::Map::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (key, value) = line.split_once('=').context("native property")?;
        ensure!(
            fields.insert(key.into(), json!(value)).is_none(),
            "duplicate native property"
        );
    }
    let value = Value::Object(fields);
    terminal(&value)?;
    Ok(value)
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        unsafe { libc::geteuid() } == 0 && args.len() == 3,
        "root; PREVIOUS_FLEET SHA256"
    );
    let mut fleet = exact(&args[1], &args[2])?;
    ensure!(
        fleet["owner"] == "/root"
            && fleet["sampled_at_utc"] == "2026-11-19T09:58:09Z"
            && fleet["live_replay_count"] == 2,
        "expected accepted cycle required"
    );
    let start = exact(
        START,
        "d5beb401ed0e015f371a7123fa34c6772f2d7f88b854d4cb1a01c4c8b2f0a0bb",
    )?;
    ensure!(
        fleet["current_nonreplay_transition"] == bound(START)?
            && fleet["continuing_holding166retry6_obligation"] == start,
        "original holding history changed"
    );
    let custody = exact(
        CUSTODY,
        "a61bad61fba797de68da201fb7ededbf5de7ed3a05c2b9eee9368b414a85ef81",
    )?;
    ensure!(
        custody["remote_sha256_readback"] == true
            && custody["local_source_revalidated"] == true
            && custody["local_retirement_authorized"] == false
            && custody["length"] == 56173984550u64
            && custody["sha256"]
                == "c6edc4b47bb905fe8825f09155edcbc217d9ea44246a3a3b4d8deb4387384e85",
        "complete exact custody required"
    );
    for (path, digest, selected) in [
        (
            DEPS,
            "8b7620234444f82ee9071981915b286196a8c85413930566a326101fe56f1dfd",
            3301343232u64,
        ),
        (
            BUILD,
            "a3e6137f753e23d6837d264264e7013fa18257b535bb5dda11786043ed0c38a6",
            224313344u64,
        ),
    ] {
        let value = exact(path, digest)?;
        let bytes: u64 = value["before"]
            .as_array()
            .context("cleanup selection")?
            .iter()
            .map(|row| {
                row["selected_allocated_bytes"]
                    .as_u64()
                    .context("selected bytes")
            })
            .collect::<Result<Vec<_>>>()?
            .iter()
            .sum();
        ensure!(
            value["selected_paths_absent"] == true
                && value["all_locks_preserved"] == true
                && value["r2_mutations"] == false
                && bytes == selected,
            "qualified cleanup completion required"
        );
    }
    let before = native()?;
    let command = before["ExecStart"].as_str().context("park command")?;
    ensure!(
        command.contains("holding-park")
            && command.contains(start["image"]["path"].as_str().context("helper")?)
            && command.contains(start["plan"]["path"].as_str().context("plan")?),
        "park command changed"
    );
    for name in ["image", "plan"] {
        ensure!(
            bound(start[name]["path"].as_str().context("start binding")?)? == start[name],
            "park binding changed"
        );
    }
    ensure!(
        native()? == before,
        "holding identity changed during capture"
    );
    fs::DirBuilder::new().mode(0o700).create(ROOT)?;
    let proof = json!({"schema":"horizon-closed166-retry6-park-terminal-v1","unit":UNIT,"invocation_id":IID,
        "park_plan":start["plan"],"helper":start["image"],"native":before});
    let proof_binding = save("park-terminal.json", &proof)?;
    fleet["previous_Root_completion_event_fleet"] = bound(&args[1])?;
    fleet["completed_holding166retry6_custody"] = bound(CUSTODY)?;
    fleet["holding166retry6_terminal"] = proof_binding;
    fleet["actual_active_holding_transfers"] = json!([]);
    fleet["completed_holding141_dependency_cleanup"] = bound(DEPS)?;
    fleet["completed_holding141_build_cleanup"] = bound(BUILD)?;
    fleet["holding166_admission_requirement"] = json!(
        "Holding transfer completed with full readback. Local partial remains until fresh complete consumer closure and separate retirement; no DATA credit or promise release. Historical transfer budget retained conservatively until new admission."
    );
    fleet["next_lane_recovery"]["last_result"] = json!(
        "56.17GB closed partial has full holding custody; local retirement still requires fresh consumer closure. ROOT compiler cleanup completed for audit capacity."
    );
    fleet["next_lane_recovery"]["next_action"] = json!(
        "Complete consumer review and optimize the 17-minute census without weakening freshness gates; qualify successor, retire exact held partial, then remeasure full epoch170 fit and launch through qualified successors."
    );
    fleet["audit_root_capacity_recovery"] = json!({"completed_dependency_cleanup":bound(DEPS)?,"completed_build_cleanup":bound(BUILD)?,
        "observed_root_free_after_build_cleanup_bytes":55033221120u64,"epoch75_required_root_bytes":54850871789u64,
        "measurement_before":bound("/var/lib/jetstreamer/holding141-build-retire-20261119-v1/root-free-before.txt")?,
        "measurement_after":bound("/var/lib/jetstreamer/holding141-build-retire-20261119-v1/root-free-after.txt")?,
        "next_scheduled_capacity_retry_utc":"2026-11-19T10:26:36Z","audit_advance_claimed":false});
    fleet["fresh_campaign_unit_census_claimed"] = json!(false);
    fleet["nonreplay_event_supplements_previous_complete_census"] = json!(true);
    fleet["resource_credit_bytes"] = json!(0);
    println!("{}", save("ROOT_COMPLETE_OPERATIONAL_FLEET.json", &fleet)?);
    Ok(())
}
