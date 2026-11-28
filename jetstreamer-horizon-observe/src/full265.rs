//! Exact ordinary-node265 lifecycle. Observations retain reservations and never admit work.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::Command,
};
pub const UNIT: &str = "horizon-qualify-265-replacement-20261119-v3.service";
pub const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/qualification-265-replacement-20261119-v3";
pub const OUTPUT: &str =
    "/home/ubuntu/.jetstreamer-private/qualification-265-replacement-20261119-v3/output";
pub const NODE: &str = "/var/lib/jetstreamer/horizon253255-node-index-20261118-v2/jetstreamer-node";
pub const NODE_SHA: &str = "2789f8211dafc4230a084910867db99699e6470b4a08a6fd8cc6dc00bf080f32";
pub const MANIFEST: &str =
    "/var/lib/jetstreamer/horizon265-singleton-manifest-20261119-v1/preflight-265-singleton.json";
pub const MANIFEST_SHA: &str = "a269b418dc5bcd508850d0293cf05e64875d7610c402b696cf8d15f9775c5fcf";
pub const FINGERPRINT: &str =
    "sha256:a126bce31196effaf656230c7185e92f73db9574e13a45e3976aae1859461e28";
pub const SNAPSHOT: &str = "/var/lib/jetstreamer/horizon-contiguous-265-265-current-46b4b4a-v1/snapshot-114479281-Jo2p1i6wNNn71fwwkyoA6shEtYtovbqzVc6p2W16FzW.tar.zst";
pub const HANDOFF: &str = "/var/lib/jetstreamer/horizon265-replacement-20261119-state-v3/launch-v1/guarded-startup-handoff.json";
const LAUNCHER: &str =
    "/var/lib/jetstreamer/horizon-full265-attempt3-controller-20261120-v1/horizon265-launch";
const LAUNCHER_SHA: &str = "199b6077d9233f59e21c0aebf47679cf92fbd5ad3bab120b8339a794407b48cc";
const GUARD_SHA: &str = "938889f9dcca0b4bf271cf8c2cbad985edc3d841f944d132f1e96c8fad81386d";
const GUARD_UNIT: &str = "horizon-265-replacement-20261119-protective-v3.service";
const NATIVE: &str =
    "/var/lib/jetstreamer/horizon-native265-terminal-proof-2048-20261119-v1/proof.json";
const NATIVE_SHA: &str = "62d7d71ee1a9c7215c4fffa7d5fec49ef449bb6be24de3e450432217a3efa519";
const EOF: &str = "jetstreamer::firehose] 🚒 firehose finished successfully.";
pub const LAST_SLOT: u64 = 114_911_999;
const PROPS: &str = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ExecMainPID,ControlPID,NRestarts,Result,ExecMainCode,ExecMainStatus,Job,Restart,KillMode,Delegate,ControlGroup,ExecStart";
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("265 missing {k}"))
}
fn num(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64().with_context(|| format!("265 missing {k}"))
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn command() -> String {
    format!(
        "{NODE} 265 {OUTPUT} --verify --root-checkpoint-cohort --cohort-manifest={MANIFEST} --cohort-manifest-fingerprint={FINGERPRINT} --snapshot-archive={SNAPSHOT}"
    )
}
pub fn prefix() -> String {
    format!("{{ path={NODE} ; argv[]={}", command())
}
fn identity(m: &fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn read(path: &Path, sha: Option<&str>, limit: u64) -> Result<Vec<u8>> {
    ensure!(
        path.starts_with("/var/lib/jetstreamer") && path.canonicalize()? == path,
        "265 evidence namespace"
    );
    for parent in path.ancestors().skip(1) {
        let m = fs::symlink_metadata(parent)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "265 mutable evidence ancestor"
        );
    }
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o222 == 0
            && before.len() <= limit,
        "265 evidence custody"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(
        identity(&before) == identity(&f.metadata()?),
        "265 open race"
    );
    let mut b = Vec::new();
    (&mut f).take(limit + 1).read_to_end(&mut b)?;
    ensure!(
        b.len() as u64 <= limit
            && identity(&before) == identity(&f.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(path)?),
        "265 evidence changed"
    );
    if let Some(sha) = sha {
        ensure!(
            hex(sha, 64) && format!("{:x}", Sha256::digest(&b)) == sha,
            "265 evidence digest"
        );
    }
    Ok(b)
}
fn bound(v: &Value) -> Result<Value> {
    Ok(serde_json::from_slice(&read(
        Path::new(text(v, "path")?),
        Some(text(v, "sha256")?),
        16 << 20,
    )?)?)
}
#[derive(Clone, Debug)]
pub struct Owner {
    pub iid: String,
    pub boot: String,
    pub handoff_sha: String,
}
/// Historical clocks are compared to one another; the original lease is never renewed.
fn startup(h: &Value, a: &Value, t: &Value) -> Result<()> {
    let u = &h["producer"];
    let iid = text(u, "InvocationID")?;
    ensure!(
        h["schema"] == "horizon265-reboot-guarded-startup-v2"
            && u["Id"] == UNIT
            && hex(iid, 32)
            && u["LoadState"] == "loaded"
            && u["ActiveState"] == "activating"
            && u["SubState"] == "start-pre"
            && u["MainPID"] == "0"
            && u["NRestarts"] == "0"
            && u["Restart"] == "no"
            && u["KillMode"] == "control-group"
            && u["Delegate"] == "no"
            && h["transaction_replay_observed"] == false
            && h["remote_mutations"] == false,
        "265 startup is not original held direct node"
    );
    ensure!(
        a["schema"] == "horizon265-current-fleet-launch-admission-v1"
            && a["candidate_epoch"] == 265
            && a["admitted"] == true
            && a["launch_plan"] == h["plan"]
            && a["launcher_sha256"] == LAUNCHER_SHA
            && a["candidate_memory_max_bytes"] == 128_000_000_000u64
            && a["candidate_root_cap_bytes"] == 506_191_984_640u64
            && a["remote_mutations"] == false
            && a["publication_authorized"] == false
            && num(a, "issued_unix_seconds")? <= num(h, "recorded_unix_seconds")?
            && num(h, "recorded_unix_seconds")? < num(a, "expires_unix_seconds")?
            && num(a, "expires_unix_seconds")? > num(a, "issued_unix_seconds")?
            && num(a, "expires_unix_seconds")? - num(a, "issued_unix_seconds")? <= 60,
        "265 original admission differs"
    );
    ensure!(
        h["first_fire_token"]["path"]
            == format!(
                "/var/lib/jetstreamer/horizon265-replacement-20261119-tokens-v3/{iid}/guard-admission.json"
            )
            && h["guard_plan"]["path"]
                == "/var/lib/jetstreamer/horizon265-replacement-20261119-guard-v3/guard-plan.json"
            && t["schema"] == "horizon265-reboot-real-first-timer-guard-admission-v1"
            && t["actual_invocation_id"] == iid
            && t["admission"] == h["admission"]
            && t["guard_plan_sha256"] == h["guard_plan"]["sha256"]
            && t["guard_sha256"] == GUARD_SHA
            && t["first_guard_invocation_id"] == h["guard_invocation_id"]
            && t["producer_before_and_after_first_guard_zero_restart_start_pre"] == true,
        "265 first token substituted"
    );
    let s = &t["guard_sample"];
    ensure!(
        s["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && s["producer_invocation_id"] == iid
            && s["guard_invocation_id"] == h["guard_invocation_id"]
            && s["guard_sha256"] == GUARD_SHA
            && s["plan_sha256"] == h["guard_plan"]["sha256"]
            && s["plan"] == h["guard_plan"]["path"]
            && s["producer"]["pid"] == 0
            && s["producer"]["active"] == "activating"
            && s["producer"]["sub"] == "start-pre"
            && s["producer_stop_enabled"] == true
            && s["workers"] == json!([])
            && s["maximum_root_physical_bytes"] == 506_191_984_640u64
            && s["maximum_worker_vmas"] == 3_500_000
            && s["minimum_free_bytes"] == a["guard_minimum_free_bytes"]
            && num(s, "available_bytes")? >= num(a, "required_initial_free_bytes")?
            && s["root_physical_observation"].is_null()
            && num(s, "recorded_unix_seconds")? >= num(a, "issued_unix_seconds")?
            && num(s, "recorded_unix_seconds")? <= num(h, "recorded_unix_seconds")?,
        "265 first guard sample differs"
    );
    for k in [
        "trip_reason",
        "worker_observation_error",
        "root_physical_observation_error",
        "target_handoff_error",
        "canary_target_error",
    ] {
        ensure!(
            s.get(k).is_some_and(Value::is_null),
            "265 first guard failure"
        );
    }
    for k in [
        "publication_authorized",
        "archive_mutations",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(t[k] == false, "265 first token authority");
    }
    let events = t["native_guard_events"]
        .as_array()
        .context("265 PID1 first guard")?;
    ensure!(
        !events.is_empty()
            && events.len() < 16
            && events.iter().all(|r| r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["UNIT"] == GUARD_UNIT
                && r["INVOCATION_ID"] == h["guard_invocation_id"]),
        "265 foreign first guard PID1 record"
    );
    ensure!(
        events.iter().any(|r| r["JOB_TYPE"] == "start"
            && r["MESSAGE"]
                .as_str()
                .is_some_and(|m| m.starts_with("Starting ")))
            && events.iter().any(|r| r["JOB_RESULT"] == "done"),
        "265 incomplete first guard PID1 lifecycle"
    );
    ensure!(
        events.iter().any(|r| r["_PID"] == "1"
            && r["_UID"] == "0"
            && r["UNIT"] == GUARD_UNIT
            && r["INVOCATION_ID"] == h["guard_invocation_id"]
            && r["MESSAGE"] == format!("{GUARD_UNIT}: Deactivated successfully.")),
        "265 first guard PID1 absent"
    );
    Ok(())
}
pub fn load() -> Result<Owner> {
    let bytes = read(Path::new(HANDOFF), None, 16 << 20)?;
    let h: Value = serde_json::from_slice(&bytes)?;
    let a = bound(&h["admission"])?;
    let t = bound(&h["first_fire_token"])?;
    startup(&h, &a, &t)?;
    let argument = &h["guard_argument_binding"];
    let env_path = "/var/lib/jetstreamer/horizon265-replacement-20261119-guard-v3/guard.env";
    ensure!(
        argument["schema"] == "horizon265-preloaded-guard-argument-binding-v1"
            && argument["unit"] == GUARD_UNIT
            && argument["timer"] == "horizon-265-replacement-20261119-protective-v3.timer"
            && argument["guard_plan"] == h["guard_plan"]
            && argument["environment"]["path"] == env_path
            && argument["unit_files_preloaded_before_fresh_admission"] == true
            && argument["daemon_reload_after_fresh_admission"] == false
            && argument["first_guard_evidence_still_required"] == true,
        "265 preloaded guard argument declaration differs"
    );
    let environment = read(
        Path::new(env_path),
        Some(text(&argument["environment"], "sha256")?),
        256,
    )?;
    ensure!(
        environment
            == format!(
                "HORIZON265_GUARD_PLAN_SHA256={}\n",
                text(&h["guard_plan"], "sha256")?
            )
            .as_bytes(),
        "265 immutable guard argument differs from token/plan"
    );
    ensure!(
        argument["deployment_seal"]["path"]
            == "/var/lib/jetstreamer/horizon265-replacement-20261119-guard-v3/deployment-seal-receipt.json",
        "265 guard argument seal path differs"
    );
    let argument_seal = bound(&argument["deployment_seal"])?;
    ensure!(
        argument_seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && argument_seal["destination"]
                == "/var/lib/jetstreamer/horizon265-replacement-20261119-guard-v3"
            && argument_seal["members"]
                .as_array()
                .is_some_and(|members| members.len() == 2
                    && members.iter().any(|m| m["name"] == "guard.env"
                        && m["sha256"] == argument["environment"]["sha256"]
                        && m["mode"] == "0444")
                    && members.iter().any(|m| m["name"] == "guard-plan.json"
                        && m["sha256"] == h["guard_plan"]["sha256"]
                        && m["mode"] == "0444")),
        "265 guard argument seal differs"
    );
    let plan = bound(&h["plan"])?;
    ensure!(
        plan["schema"] == "horizon265-current-fleet-launch-plan-v1" && plan["worker_root"] == ROOT,
        "265 plan route differs"
    );
    let review = bound(&a["review"])?;
    ensure!(
        review["launch_plan"] == h["plan"] && a["native_admission"]["review"] == a["review"],
        "265 review extraction"
    );
    let source = bound(&review["source_publication"])?;
    ensure!(
        source["schema"] == "horizon265-source-publication-v1"
            && source["remote_ref"] == "refs/heads/account-updates"
            && source["all_required_dependencies_in_remote"] == true
            && source["exact_deployed_source_provenance_reviewed"] == true
            && source["artifacts"]
                .as_array()
                .is_some_and(|rows| rows.iter().any(|r| r["role"] == "launcher"
                    && r["artifact"] == json!({"path":LAUNCHER,"sha256":LAUNCHER_SHA}))),
        "265 source publication differs"
    );
    let native: Value =
        serde_json::from_slice(&read(Path::new(NATIVE), Some(NATIVE_SHA), 16 << 20)?)?;
    ensure!(
        native["native_input_qualified"] == true && native["epoch"] == 265,
        "265 native input not qualified"
    );
    let gp = bound(&h["guard_plan"])?;
    ensure!(
        gp["unit"] == UNIT
            && gp["invocation_id"] == h["producer"]["InvocationID"]
            && gp["worker_root"] == ROOT
            && gp["maximum_root_physical_bytes"] == 506_191_984_640u64
            && gp["minimum_free_bytes"] == a["guard_minimum_free_bytes"],
        "265 guard plan differs"
    );
    let lifecycle = bound(&review["prestart_qualification"])?;
    ensure!(
        lifecycle["schema"] == "horizon265-prestart-qualification-v1"
            && lifecycle["launcher_artifact_sha256"] == LAUNCHER_SHA
            && lifecycle["source_publication"] == review["source_publication"]
            && lifecycle["node"] == json!({"path":NODE,"sha256":NODE_SHA}),
        "265 prestart provenance"
    );
    for key in [
        "observer_complete_tuple_accepted",
        "fleet_running_and_terminal_accepted",
        "inactive_status_exact_owner_accepted",
        "terminal_retention_accepted",
        "singleton265_terminal_delivery_route_accepted",
        "prestart_gate_tests_accepted",
        "actual_first_guard_required_before_useful_work",
    ] {
        ensure!(
            lifecycle[key] == true,
            "265 consumer gate not accepted {key}"
        );
    }
    bound(&lifecycle["qualification_evidence"])?;
    let boot = text(&a["native_admission"], "boot_id")?.to_owned();
    Ok(Owner {
        iid: text(&h["producer"], "InvocationID")?.into(),
        boot,
        handoff_sha: format!("{:x}", Sha256::digest(bytes)),
    })
}
pub fn manager() -> Result<Value> {
    let out = Command::new("/usr/bin/systemctl")
        .args(["show", UNIT, "--property", PROPS])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 65536,
        "265 PID1 read failed"
    );
    let mut v = serde_json::Map::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, x) = line.split_once('=').context("265 PID1 framing")?;
        ensure!(
            v.insert(k.into(), json!(x)).is_none(),
            "duplicate PID1 field"
        );
    }
    Ok(Value::Object(v))
}
pub fn owner(o: &Owner, u: &Value) -> Result<bool> {
    ensure!(
        u["Id"] == UNIT
            && u["LoadState"] == "loaded"
            && u["InvocationID"] == o.iid
            && u["NRestarts"] == "0"
            && u["ControlPID"] == "0"
            && u["Job"] == ""
            && u["Restart"] == "no"
            && u["KillMode"] == "control-group"
            && u["Delegate"] == "no"
            && text(u, "ExecStart")?
                .starts_with(&format!("{} ; ignore_errors=no ; start_time=", prefix()))
            && text(u, "ExecStart")?.matches("{ path=").count() == 1,
        "265 owner/command changed"
    );
    if u["ActiveState"] == "active" && u["SubState"] == "running" {
        ensure!(
            text(u, "MainPID")?.parse::<u64>()? > 1
                && u["Result"] == "success"
                && u["ControlGroup"] == format!("/system.slice/{UNIT}"),
            "265 live owner differs"
        );
        return Ok(true);
    }
    ensure!(
        u["MainPID"] == "0"
            && matches!(u["ActiveState"].as_str(), Some("inactive" | "failed"))
            && matches!(u["SubState"].as_str(), Some("dead" | "failed")),
        "265 ambiguous terminal owner"
    );
    Ok(false)
}
pub fn same_snapshot(a: &Value, b: &Value) -> Result<()> {
    for k in [
        "Id",
        "LoadState",
        "ActiveState",
        "SubState",
        "InvocationID",
        "MainPID",
        "NRestarts",
        "Result",
        "ControlGroup",
    ] {
        ensure!(!a[k].is_null() && a[k] == b[k], "265 census changed {k}");
    }
    ensure!(
        text(a, "ExecStart")?.split(" ; start_time=").next()
            == text(b, "ExecStart")?.split(" ; start_time=").next(),
        "265 census command changed"
    );
    Ok(())
}
pub fn check_manager(current: &Value) -> Result<Owner> {
    let o = load()?;
    ensure!(
        o.boot == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        "265 boot changed"
    );
    let actual = manager()?;
    same_snapshot(current, &actual)?;
    if owner(&o, &actual)? {
        mapped(text(&actual, "MainPID")?.parse()?)?;
    }
    Ok(o)
}
fn mapped(pid: u64) -> Result<()> {
    read(Path::new(NODE), Some(NODE_SHA), 128 << 20)?;
    read(Path::new(MANIFEST), Some(MANIFEST_SHA), 1 << 20)?;
    let path = format!("/proc/{pid}/exe");
    let m = fs::metadata(&path)?;
    let d = fs::symlink_metadata(NODE)?;
    ensure!(
        fs::read_link(path)? == Path::new(NODE) && m.dev() == d.dev() && m.ino() == d.ino(),
        "265 mapped node changed"
    );
    Ok(())
}
pub fn events(o: &Owner, pid: u64, rows: &[Value], sample: u64) -> Result<Option<Value>> {
    let cutoff = sample
        .checked_mul(1_000_000)
        .context("265 cutoff overflow")?;
    let last = format!("jetstreamer::firehose] processed slot {LAST_SLOT}");
    let mut chosen = Vec::new();
    for marker in [last.as_str(), EOF] {
        let matches = rows
            .iter()
            .filter(|r| r["MESSAGE"].as_str().is_some_and(|m| m.ends_with(marker)))
            .collect::<Vec<_>>();
        ensure!(matches.len() <= 1, "265 duplicate finalization marker");
        let Some(r) = matches.first() else { continue };
        ensure!(
            r["_SYSTEMD_UNIT"] == UNIT
                && r["_SYSTEMD_INVOCATION_ID"] == o.iid
                && r["_PID"].as_str() == Some(pid.to_string().as_str())
                && r["_UID"] == "1000"
                && r["_EXE"] == NODE
                && r["_CMDLINE"] == command()
                && r["_BOOT_ID"] == o.boot.replace('-', ""),
            "265 foreign phase event"
        );
        let time = text(r, "__REALTIME_TIMESTAMP")?.parse::<u64>()?;
        ensure!(time > 0, "265 zero timestamp");
        if time <= cutoff {
            chosen.push((marker, time, (*r).clone()));
        }
    }
    if !chosen.iter().any(|(m, _, _)| *m == EOF) {
        return Ok(None);
    }
    ensure!(
        chosen.len() == 2 && chosen[0].1 < chosen[1].1,
        "265 EOF lacks ordered terminal slot"
    );
    Ok(Some(
        json!({"schema":"horizon-full265-finalization-events-v1","epoch":265,"unit":UNIT,"invocation_id":o.iid,"main_pid":pid,
        "startup_handoff":{"path":HANDOFF,"sha256":o.handoff_sha},"boot_id":o.boot,"node_sha256":NODE_SHA,"manifest_sha256":MANIFEST_SHA,
        "terminal_slot":LAST_SLOT,"sampled_unix_seconds":sample,"events":chosen.iter().map(|(_,_,r)|r).collect::<Vec<_>>(),
        "replay_terminal_observed":true,"producer_terminal_proven":false,"resource_release_authorized":false,
        "independent_full_verification_passed":false,"publication_authorized":false,"replay_launch_authorized":false,"r2_mutations":false}),
    ))
}
pub fn capture_phase(current: &Value, sample: u64) -> Result<Option<Value>> {
    let o = check_manager(current)?;
    let actual = manager()?;
    same_snapshot(current, &actual)?;
    ensure!(owner(&o, &actual)?, "265 phase requires live producer");
    let pid = text(current, "MainPID")?.parse()?;
    mapped(pid)?;
    let out = Command::new("/usr/bin/journalctl")
        .args([
            "--all",
            "--no-pager",
            "-o",
            "json",
            "--boot=0",
            "-n",
            "16",
            &format!("_SYSTEMD_UNIT={UNIT}"),
            &format!("_SYSTEMD_INVOCATION_ID={}", o.iid),
            "-g",
            &format!("processed slot {LAST_SLOT}|firehose finished successfully"),
        ])
        .output()?;
    ensure!(
        (out.status.success()
            || (out.status.code() == Some(1) && out.stdout.is_empty() && out.stderr.is_empty()))
            && out.stdout.len() <= 1 << 20,
        "265 phase journal unavailable"
    );
    let rows = serde_json::Deserializer::from_slice(&out.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    events(&o, pid, &rows, sample)
}
pub fn validate_delivery(
    epoch: u64,
    unit: &str,
    iid: &str,
    exec: &str,
    output: &Path,
    manifest: &Value,
    startup: &Value,
) -> Result<()> {
    let o = load()?;
    ensure!(
        epoch == 265
            && unit == UNIT
            && iid == o.iid
            && exec == prefix()
            && output == Path::new(OUTPUT)
            && manifest == &json!({"path":MANIFEST,"sha256":MANIFEST_SHA})
            && startup == &json!({"path":HANDOFF,"sha256":o.handoff_sha}),
        "265 delivery changes exact ordinary singleton"
    );
    Ok(())
}
pub fn matches_primary(entry: &Value, replay: &Value) -> bool {
    entry["epoch"] == 265
        && entry["phase"] == "producer-finalization"
        && entry["live"] == true
        && entry["unit"]["Id"] == UNIT
        && entry["finalization_evidence"]["schema"] == "horizon-full265-finalization-events-v1"
        && entry["finalization_evidence"]["replay_terminal_observed"] == true
        && replay["range"] == "265-265"
        && replay["invocation_binding_stable"] == true
        && [
            "controller_before",
            "controller_after",
            "producer_before",
            "producer_after",
        ]
        .iter()
        .all(|k| {
            replay[*k]["unit"] == UNIT
                && replay[*k]["invocation_id"] == entry["unit"]["InvocationID"]
                && replay[*k]["restarts"] == 0
                && replay[*k]["active_state"] == "active"
                && replay[*k]["sub_state"] == "running"
        })
}

pub fn telemetry_tuple(
    range: &str,
    producer: &str,
    controller: &str,
    producer_iid: &str,
    controller_iid: &str,
    root: &Path,
) -> Result<()> {
    ensure!(
        range == "265-265"
            && producer == UNIT
            && controller == UNIT
            && hex(producer_iid, 32)
            && producer_iid == controller_iid
            && root == Path::new(ROOT),
        "265 observer tuple differs"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn owner_fixture() -> Owner {
        Owner {
            iid: "a".repeat(32),
            boot: "12345678-1234-1234-1234-123456789abc".into(),
            handoff_sha: "b".repeat(64),
        }
    }
    fn unit() -> Value {
        let o = owner_fixture();
        json!({"Id":UNIT,"LoadState":"loaded","InvocationID":o.iid,"MainPID":"42","ExecMainPID":"42","NRestarts":"0","ControlPID":"0","Job":"","Restart":"no","KillMode":"control-group","Delegate":"no","ActiveState":"active","SubState":"running","Result":"success","ControlGroup":format!("/system.slice/{UNIT}"),"ExecStart":format!("{} ; ignore_errors=no ; start_time=[x] ; stop_time=[n/a] ; pid=42 ; code=(null) ; status=0/0 }}",prefix())})
    }
    fn chain() -> (Value, Value, Value) {
        let iid = "a".repeat(32);
        let gid = "c".repeat(32);
        let gp = json!({"path":"/var/lib/jetstreamer/horizon265-replacement-20261119-guard-v3/guard-plan.json","sha256":"d".repeat(64)});
        let admission =
            json!({"path":"/var/lib/jetstreamer/admission/admission.json","sha256":"e".repeat(64)});
        let plan = json!({"path":"/var/lib/jetstreamer/plan/plan.json","sha256":"f".repeat(64)});
        let h = json!({"schema":"horizon265-reboot-guarded-startup-v2","producer":{"Id":UNIT,"LoadState":"loaded","InvocationID":iid,"ActiveState":"activating","SubState":"start-pre","MainPID":"0","NRestarts":"0","Restart":"no","KillMode":"control-group","Delegate":"no"},"transaction_replay_observed":false,"remote_mutations":false,"recorded_unix_seconds":120,"plan":plan,"admission":admission,"guard_plan":gp,"guard_invocation_id":gid,"first_fire_token":{"path":format!("/var/lib/jetstreamer/horizon265-replacement-20261119-tokens-v3/{iid}/guard-admission.json"),"sha256":"0".repeat(64)}});
        let a = json!({"schema":"horizon265-current-fleet-launch-admission-v1","candidate_epoch":265,"admitted":true,"launch_plan":plan,"launcher_sha256":LAUNCHER_SHA,"candidate_memory_max_bytes":128_000_000_000u64,"candidate_root_cap_bytes":506_191_984_640u64,"remote_mutations":false,"publication_authorized":false,"issued_unix_seconds":100,"expires_unix_seconds":160,"guard_minimum_free_bytes":1000,"required_initial_free_bytes":1500});
        let t = json!({"schema":"horizon265-reboot-real-first-timer-guard-admission-v1","actual_invocation_id":iid,"admission":admission,"guard_plan_sha256":gp["sha256"],"guard_sha256":GUARD_SHA,"first_guard_invocation_id":gid,"producer_before_and_after_first_guard_zero_restart_start_pre":true,
            "guard_sample":{"schema":"jetstreamer-horizon-standalone-guard-sample-v1","producer_invocation_id":iid,"guard_invocation_id":gid,"guard_sha256":GUARD_SHA,"plan_sha256":gp["sha256"],"plan":gp["path"],"producer":{"pid":0,"active":"activating","sub":"start-pre"},"producer_stop_enabled":true,"workers":[],"maximum_root_physical_bytes":506_191_984_640u64,"maximum_worker_vmas":3500000,"minimum_free_bytes":1000,"available_bytes":2000,"recorded_unix_seconds":110,"root_physical_observation":null,"trip_reason":null,"worker_observation_error":null,"root_physical_observation_error":null,"target_handoff_error":null,"canary_target_error":null},
            "publication_authorized":false,"archive_mutations":false,"remote_mutations":false,"r2_mutations":false,"native_guard_events":[{"_PID":"1","_UID":"0","UNIT":GUARD_UNIT,"INVOCATION_ID":gid,"JOB_TYPE":"start","MESSAGE":"Starting guard"},{"_PID":"1","_UID":"0","UNIT":GUARD_UNIT,"INVOCATION_ID":gid,"MESSAGE":format!("{GUARD_UNIT}: Deactivated successfully."),"JOB_RESULT":"done"}]});
        (h, a, t)
    }
    #[test]
    fn original_start_pre_handoff_does_not_need_fabricated_main_pid() {
        let (h, a, t) = chain();
        startup(&h, &a, &t).unwrap();
        let mut bad = h;
        bad["producer"]["MainPID"] = json!(42);
        assert!(startup(&bad, &a, &t).is_err());
    }
    #[test]
    fn startup_rejects_rebound_owner_clock_image_and_guard() {
        let (h, a, t) = chain();
        for (pointer, value) in [
            ("/producer/InvocationID", json!("b".repeat(32))),
            ("/recorded_unix_seconds", json!(160)),
            ("/producer/SubState", json!("running")),
            ("/remote_mutations", json!(true)),
        ] {
            let mut b = h.clone();
            *b.pointer_mut(pointer).unwrap() = value;
            assert!(startup(&b, &a, &t).is_err(), "{pointer}");
        }
        let mut b = a.clone();
        b["launcher_sha256"] = json!("0".repeat(64));
        assert!(startup(&h, &b, &t).is_err());
        for (pointer, value) in [
            ("/guard_sample/trip_reason", json!("floor")),
            ("/guard_sample/available_bytes", json!(999)),
            ("/guard_sample/workers", json!([[42, 10]])),
            ("/guard_sample/plan_sha256", json!("0".repeat(64))),
            ("/native_guard_events", json!([])),
        ] {
            let mut b = t.clone();
            *b.pointer_mut(pointer).unwrap() = value;
            assert!(startup(&h, &a, &b).is_err(), "{pointer}");
        }
    }
    #[test]
    fn exact_live_then_terminal_identity_never_authorizes_release() {
        let o = owner_fixture();
        let u = unit();
        assert!(owner(&o, &u).unwrap());
        let mut dead = u.clone();
        dead["MainPID"] = json!("0");
        dead["ActiveState"] = json!("inactive");
        dead["SubState"] = json!("dead");
        assert!(!owner(&o, &dead).unwrap());
        for (key, value) in [
            ("InvocationID", "replacement"),
            ("NRestarts", "1"),
            ("ControlPID", "42"),
            ("ExecStart", "different"),
            ("Job", "queued"),
        ] {
            let mut bad = dead.clone();
            bad[key] = json!(value);
            assert!(owner(&o, &bad).is_err(), "{key}");
        }
    }
    #[test]
    fn eof_needs_exact_boot_pid_command_and_cutoff() {
        let o = owner_fixture();
        let rows=[format!("jetstreamer::firehose] processed slot {LAST_SLOT}"),EOF.into()].iter().enumerate().map(|(i,m)|json!({"MESSAGE":m,"_SYSTEMD_UNIT":UNIT,"_SYSTEMD_INVOCATION_ID":o.iid,"_PID":"42","_UID":"1000","_EXE":NODE,"_CMDLINE":command(),"_BOOT_ID":o.boot.replace('-',""),"__REALTIME_TIMESTAMP":((10+i as u64)*1_000_000).to_string()})).collect::<Vec<_>>();
        assert!(events(&o, 42, &rows, 10).unwrap().is_none());
        let proof = events(&o, 42, &rows, 11).unwrap().unwrap();
        assert_eq!(proof["producer_terminal_proven"], false);
        assert_eq!(proof["resource_release_authorized"], false);
        assert!(events(&o, 42, &rows[1..], 11).is_err());
        assert!(events(&o, 43, &rows, 11).is_err());
        for key in [
            "_SYSTEMD_UNIT",
            "_SYSTEMD_INVOCATION_ID",
            "_PID",
            "_EXE",
            "_CMDLINE",
            "_BOOT_ID",
        ] {
            let mut bad = rows.clone();
            bad[1][key] = json!("different");
            assert!(events(&o, 42, &bad, 11).is_err(), "{key}");
        }
        let mut repeated = rows.clone();
        repeated.push(rows[1].clone());
        assert!(events(&o, 42, &repeated, 11).is_err());
    }
    #[test]
    fn ordinary_tuple_rejects_native_and_cross_epoch_aliases() {
        let iid = "a".repeat(32);
        telemetry_tuple("265-265", UNIT, UNIT, &iid, &iid, Path::new(ROOT)).unwrap();
        assert!(telemetry_tuple("265-266", UNIT, UNIT, &iid, &iid, Path::new(ROOT)).is_err());
        assert!(
            telemetry_tuple(
                "265-265",
                "horizon-265-native-input-20261119-v1.service",
                UNIT,
                &iid,
                &iid,
                Path::new(ROOT)
            )
            .is_err()
        );
        assert!(
            telemetry_tuple(
                "265-265",
                UNIT,
                UNIT,
                &iid,
                &"b".repeat(32),
                Path::new(ROOT)
            )
            .is_err()
        );
    }
}
