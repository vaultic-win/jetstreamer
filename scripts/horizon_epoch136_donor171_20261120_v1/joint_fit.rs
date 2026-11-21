//! Writer-side binding to 145's authoritative, read-only concurrent fit.
//! Resource estimates are produced once by the normally sealed 145 calculator.
use super::{
    BASE, CANDIDATE_DISK, CANDIDATE_MEMORY, UNIT, binding, closed, fence, fit, json_pin, n, now,
    root_file, show,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-publication-20261121-v1/joint-tools-v2/export145";
const EXPORTER: &str = "horizon-holding-export145-20261121-v1.service";
const SEALER: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .with_context(|| format!("joint fit missing {k}"))
}
fn observe_145() -> Result<Value> {
    let unit = show(EXPORTER)?;
    if closed(&unit) {
        super::cgroup_empty(EXPORTER)?;
        return Ok(json!({"unit":EXPORTER,"state":"absent","iid":unit["InvocationID"]}));
    }
    ensure!(
        unit["ActiveState"] == "active"
            && unit["SubState"] == "running"
            && unit["Job"] == ""
            && unit["NRestarts"] == "0",
        "145 phase is changing"
    );
    let pid = text(&unit, "MainPID")?.parse::<u32>()?;
    let proc = Path::new("/proc").join(pid.to_string());
    let ticks = super::ticks(u64::from(pid))?;
    let image = fs::metadata(proc.join("exe"))?;
    let cmd = fs::read(proc.join("cmdline"))?;
    ensure!(
        pid > 1
            && fs::read_to_string(proc.join("cgroup"))?.trim()
                == format!("0::/system.slice/{EXPORTER}"),
        "unexpected native 145 owner"
    );
    let mode = cmd.split(|b| *b == 0).nth(1).context("145 actor mode")?;
    Ok(
        json!({"unit":EXPORTER,"state":"running","iid":unit["InvocationID"],"pid":pid,"start_ticks":ticks,
        "image":fs::read_link(proc.join("exe"))?,"device":image.dev(),"inode":image.ino(),"mode":std::str::from_utf8(mode)?}),
    )
}
fn image(provider: &Value) -> Result<PathBuf> {
    let file = &provider["image"];
    let path = PathBuf::from(text(file, "path")?);
    let parent = path.parent().context("provider directory")?;
    ensure!(
        path == Path::new(IMAGE),
        "joint 145 provider deployment namespace"
    );
    let sealref = &provider["seal"];
    ensure!(
        Path::new(text(sealref, "path")?) == parent.join("deployment-seal-receipt.json"),
        "145 provider seal path"
    );
    let seal = json_pin(Path::new(text(sealref, "path")?), text(sealref, "sha256")?)?;
    let bytes = root_file(&path, 64 << 20)?;
    let hash = format!("{:x}", Sha256::digest(&bytes));
    let meta = fs::symlink_metadata(&path)?;
    ensure!(
        meta.mode() & 0o777 == 0o555
            && seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["sealer_sha256"] == SEALER
            && seal["destination"].as_str() == parent.to_str()
            && hash == text(file, "sha256")?
            && seal["members"].as_array().is_some_and(|rows| rows
                .iter()
                .filter(|v| v["name"] == "export145"
                    && v["mode"] == "0555"
                    && v["bytes"] == bytes.len()
                    && v["sha256"] == hash)
                .count()
                == 1),
        "actual provider image/sealer/member differs"
    );
    Ok(path)
}
fn candidate(waiting: Option<&str>) -> Result<Value> {
    super::candidate_state(waiting)?;
    let u = show(UNIT)?;
    let path = Path::new(BASE).join("reproduction");
    let Some(iid) = waiting else {
        ensure!(closed(&u), "136 candidate unexpectedly occupied");
        super::cgroup_empty(UNIT)?;
        ensure!(
            fs::symlink_metadata(&path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "unused candidate root required for initial admission"
        );
        return Ok(Value::Null);
    };
    ensure!(
        iid.len() == 32
            && iid.bytes().all(|b| b.is_ascii_hexdigit())
            && u["InvocationID"] == iid
            && u["ActiveState"] == "active"
            && u["SubState"] == "running"
            && u["NRestarts"] == "0"
            && u["Job"] == "",
        "waiting candidate changed native identity"
    );
    let admission = Path::new(BASE).join("admission.json");
    let bytes = root_file(&admission, 2 << 20)?;
    let bound = binding(&admission, &format!("{:x}", Sha256::digest(&bytes)));
    let r: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        r["schema"] == "horizon-epoch136-actual-admission-v1"
            && r["data_reservation_bytes"] == CANDIDATE_DISK
            && r["memory_max_bytes"] == CANDIDATE_MEMORY
            && r["cpu_quota_micros"] == 3_000_000
            && r["publication_authorized"] == false,
        "unfunded 136 admission"
    );
    let pid = text(&u, "MainPID")?.parse::<u64>()?;
    let ticks = super::ticks(pid)?;
    let receipts = path.join("receipts");
    let ready: Value = serde_json::from_slice(&root_file(&receipts.join("ready.json"), 2 << 20)?)?;
    ensure!(
        ready["launch"]["path"] == receipts.join("launch.json").to_str().unwrap(),
        "wrong launch path"
    );
    let launch = json_pin(
        &receipts.join("launch.json"),
        text(&ready["launch"], "sha256")?,
    )?;
    ensure!(
        ready["unit"] == UNIT
            && ready["node_spawned"] == false
            && ready["worker_spawned"] == false
            && ready["invocation_id"] == iid
            && ready["schema"] == "horizon-epoch136-actual-ready-v1"
            && launch["admission"] == bound
            && launch["pid"] == pid
            && launch["start_ticks"] == ticks
            && launch["invocation_id"] == iid
            && launch["unit"] == UNIT
            && ready["pid"] == pid
            && ready["start_ticks"] == ticks,
        "candidate is not the admitted pre-initialize waiter"
    );
    Ok(
        json!({"admission":bound,"writer_invocation_id":r["writer_invocation_id"],"unit":UNIT,"iid":iid,"producer_pid":pid,"start_ticks":ticks,"root":path,"guard_plan":binding(&receipts.join("guard-plan.json"),text(&ready,"guard_plan_sha256")?)}),
    )
}
fn bind_incumbents(fleet: &Value, proof: &Value, own: &Value) -> Result<()> {
    let rows = proof
        .as_object()
        .context("six live peer/guard identities")?;
    let mut seen = std::collections::BTreeSet::new();
    for key in [
        "actual_executing_replays",
        "actual_active_bootstraps",
        "actual_active_private_diagnostics",
    ] {
        for row in fleet[key].as_array().context("complete fleet peer class")? {
            let epoch = n(row, "epoch")?;
            if epoch == 136 {
                ensure!(
                    !own.is_null()
                        && row["unit"]["Id"] == UNIT
                        && row["unit"]["InvocationID"] == own["iid"]
                        && seen.insert(epoch),
                    "foreign registered candidate"
                );
                continue;
            }
            ensure!(
                [166, 167, 168, 169, 170, 172].contains(&epoch) && seen.insert(epoch),
                "unexpected or duplicate fleet peer"
            );
            let peer = rows
                .get(&epoch.to_string())
                .context("missing peer identity")?;
            ensure!(
                peer["unit"] == row["unit"]["Id"]
                    && peer["invocation_id"] == row["unit"]["InvocationID"],
                "live peer differs from accepted fleet {epoch}"
            );
            let timer = if let Some(iid) = row["guard_timer"]["InvocationID"].as_str() {
                iid.to_owned()
            } else {
                let b = &row["guard_protection"];
                let protection = json_pin(Path::new(text(b, "path")?), text(b, "sha256")?)?;
                ensure!(
                    protection["producer_unit"] == peer["unit"]
                        && protection["producer_invocation_id"] == peer["invocation_id"],
                    "crossed incumbent guard {epoch}"
                );
                text(&protection, "timer_invocation_id")?.to_owned()
            };
            ensure!(
                timer.len() == 32
                    && timer.bytes().all(|c| c.is_ascii_hexdigit())
                    && peer["guard_timer_invocation_id"] == timer,
                "wrong native guard timer {epoch}"
            );
        }
    }
    ensure!(
        [166, 167, 168, 169, 170, 172]
            .iter()
            .all(|e| seen.contains(e))
            && rows.len() == 6,
        "exact six incumbents required"
    );
    Ok(())
}
fn evaluate(wire: &Value, own: &Value, active: &Value, need_start: bool) -> Result<()> {
    let r = &wire["resources"];
    let c = &wire["candidate"];
    let phase = &wire["phase145"];
    ensure!(
        n(r, "complete_memory_plus_reserve_bytes")? == 810658050048
            && n(r, "existing_cpu_quota_micros")? == 64_000_000
            && n(r, "unfenced_with_candidate_cpu_micros")? == 68_250_000
            && n(r, "available_memory_bytes")? >= n(r, "required_available_memory_bytes")?,
        "joint complete memory/CPU budget differs"
    );
    let realized = n(c, "realized_bytes")?;
    let remaining = n(c, "remaining_bytes")?;
    let required = n(c, "required_total_bytes")?;
    let free = n(r, "free_HOME_bytes")?;
    ensure!(
        n(c, "limit_bytes")? == CANDIDATE_DISK
            && realized <= 64u64 << 30
            && realized.checked_add(remaining) == Some(CANDIDATE_DISK)
            && n(r, "protected_existing_only_bytes")?.checked_add(remaining) == Some(required)
            && wire["disk_fits"] == json!(free >= required),
        "candidate growth charged more or less than once"
    );
    if own.is_null() {
        ensure!(
            c["identity"].is_null() && realized == 0,
            "idle candidate credited an existing allocation"
        );
    } else {
        let id = &c["identity"];
        ensure!(
            id["unit"] == UNIT
                && id["invocation_id"] == own["iid"]
                && id["admission"] == own["admission"]
                && id["writer_invocation_id"] == own["writer_invocation_id"]
                && id["guard_plan"] == own["guard_plan"]
                && id["pid"] == own["producer_pid"]
                && id["start_ticks"] == own["start_ticks"]
                && id["node_pid"] == Value::Null
                && id["worker_pid"] == Value::Null
                && id["guard_sample"].is_object(),
            "wrong waiting candidate or unprotected prefire"
        );
    }
    ensure!(
        phase["output_device"] == 64512 && phase["output_inode"] == 103237059,
        "changed funded epoch 145 output"
    );
    let supports = phase["activation_compatible"]
        .as_bool()
        .context("missing 145 capability")?;
    ensure!(
        phase["seven_capable"].is_boolean(),
        "missing current actor topology capability"
    );
    if active["state"] == "running" {
        ensure!(
            phase["unit"] == EXPORTER
                && phase["invocation_id"] == active["iid"]
                && phase["pid"] == active["pid"]
                && phase["start_ticks"] == active["start_ticks"],
            "replaced live 145 capacity actor"
        );
        ensure!(
            phase["phase"] == active["mode"]
                && phase["image"]["path"] == active["image"]
                && phase["image"]["sha256"]
                    .as_str()
                    .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())),
            "reported actor phase or image differs from /proc"
        );
    } else {
        ensure!(
            active["state"] == "absent"
                && phase["phase"] == "gap"
                && phase["unit"] == EXPORTER
                && phase["invocation_id"].is_null()
                && phase["image"].is_null()
                && phase["seven_capable"] == false,
            "foreign gap witness"
        );
    }
    if supports {
        ensure!(
            active["state"] == "running"
                && (active["mode"] == "post-full" || active["mode"] == "publish")
                && phase["seven_capable"] == true
                && phase["image"] == wire["provider"],
            "six-only exporter or empty handoff claimed support for a seventh worker"
        );
    }
    if need_start {
        ensure!(
            supports && wire["disk_fits"] == true,
            "current 145 topology or physical free space bars 136 admission"
        );
    }
    Ok(())
}
pub(super) fn inspect(
    plan: &Value,
    fleet_path: &Path,
    fleet_sha: &str,
    waiting_iid: Option<&str>,
    require_activation_compatible: bool,
) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0 && (waiting_iid.is_none() || require_activation_compatible),
        "joint writer host/phase mismatch"
    );
    let fleet = json_pin(fleet_path, fleet_sha)?;
    ensure!(
        fleet["owner"] == "/root"
            && fleet["all_reservation_ending_bytes"] == 0
            && fleet["complete_DATA_bytes"] == 6_794_761_027_378u64
            && fleet["complete_projected_memory_bytes"] == 761_131_708_416u64,
        "complete preexisting reservations changed"
    );
    let ancestry = fence::ancestry()?;
    let audit = fit::observe_audit(&fleet["continuing_audit_obligation"])?;
    let p = &plan["joint_fit_145"];
    let executable = image(p)?;
    let provider = &p["image"];
    let mut cmd = Command::new(&executable);
    cmd.arg("joint-fit")
        .arg(fleet_path)
        .arg(fleet_sha)
        .arg(text(provider, "sha256")?)
        .stdin(Stdio::null());
    for k in [
        "SYSTEMD_HOST",
        "SYSTEMD_BUS_ADDRESS",
        "DBUS_SYSTEM_BUS_ADDRESS",
        "DBUS_SESSION_BUS_ADDRESS",
    ] {
        cmd.env_remove(k);
    }
    let own = candidate(waiting_iid)?;
    let active = observe_145()?;
    if let Some(iid) = waiting_iid {
        cmd.arg(iid)
            .arg(text(&own["admission"], "path")?)
            .arg(text(&own["admission"], "sha256")?);
    }
    let start = now()?;
    let o = cmd.output().context("run sealed 145 joint fit")?;
    ensure!(
        o.status.success() && o.stdout.len() <= 4 << 20,
        "145 joint fit failed: {}",
        String::from_utf8_lossy(&o.stderr[..o.stderr.len().min(4096)])
    );
    let wire: Value = serde_json::from_slice(&o.stdout)?;
    let stamp = n(&wire, "recorded_unix_seconds")?;
    ensure!(
        wire["schema"] == "horizon-145-136-joint-fit-v1"
            && wire["fleet"] == binding(fleet_path, fleet_sha)
            && wire["provider"] == *provider
            && wire["actual_native_fit"]["joint136_enabled"] == true
            && wire["actual_native_fit"]["fleet"] == wire["fleet"]
            && wire["actual_native_fit"]["existing_total_memory"]
                == wire["resources"]["complete_memory_plus_reserve_bytes"]
            && wire["actual_native_fit"]["charged_cpu_micros"]
                == wire["resources"]["existing_cpu_quota_micros"]
            && wire["replay_launch_authorized"] == false
            && wire["r2_mutations"] == false
            && (start..=now()?).contains(&stamp),
        "stale or foreign 145 response"
    );
    bind_incumbents(&fleet, &wire["incumbents"], &own)?;
    evaluate(&wire, &own, &active, require_activation_compatible)?;
    if !own.is_null() {
        let id = &wire["candidate"]["identity"];
        let sample_ref = &id["guard_sample"];
        let sample_path = Path::new(text(sample_ref, "path")?);
        let guard_dir = Path::new(BASE).join("reproduction/receipts/guard");
        ensure!(
            sample_path.parent() == Some(&guard_dir),
            "foreign 136 guard sample"
        );
        let sample = json_pin(sample_path, text(sample_ref, "sha256")?)?;
        let guard_iid = text(&sample, "guard_invocation_id")?;
        ensure!(
            guard168::iid(guard_iid)
                && sample_path == guard_dir.join(format!("sample-{guard_iid}.json"))
                && sample["producer_invocation_id"] == own["iid"]
                && sample["plan_sha256"] == own["guard_plan"]["sha256"]
                && sample["producer"]["pid"] == own["producer_pid"],
            "wrong protected candidate"
        );
    }
    if wire["phase145"]["activation_compatible"] == true {
        let sealed = fs::symlink_metadata(&executable)?;
        ensure!(
            active["device"] == sealed.dev() && active["inode"] == sealed.ino(),
            "live phase must run the sealed seven-capable 145 image"
        );
    }
    ensure!(
        candidate(waiting_iid)? == own
            && observe_145()? == active
            && fit::observe_audit(&fleet["continuing_audit_obligation"])? == audit,
        "136 or 145 generation changed during fit"
    );
    let (total_memory, available_memory) = fit::memory()?;
    ensure!(
        total_memory >= n(&wire["resources"], "complete_memory_plus_reserve_bytes")?
            && available_memory >= n(&wire["resources"], "required_available_memory_bytes")?,
        "changed available physical RAM"
    );
    Ok(
        json!({"schema":"horizon-136-writer-joint-fit-v1","total_memory_bytes":total_memory,"fleet":wire["fleet"],"provider_seal":p["seal"],"authoritative_joint_fit":wire,"audit":audit,"donor171_ancestry":ancestry,"waiting_candidate":own,"native_145":active,"activation_compatible":wire["phase145"]["activation_compatible"],"disk_fits":wire["disk_fits"],"complete_memory_plus_reserve_bytes":wire["resources"]["complete_memory_plus_reserve_bytes"],"available_HOME_bytes":wire["resources"]["free_HOME_bytes"],"protected_raw_floor_bytes":wire["resources"]["protected_existing_only_bytes"],"candidate_remaining_growth_bytes":wire["candidate"]["remaining_bytes"],"complete_required_HOME_bytes":wire["candidate"]["required_total_bytes"],"unfenced_with_candidate_cpu_micros":wire["resources"]["unfenced_with_candidate_cpu_micros"],"new_resource_credit_bytes":0}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(mode: &str, compatible: bool) -> (Value, Value) {
        let provider = json!({"path": IMAGE, "sha256": "a".repeat(64)});
        let image = if mode == "run" {
            json!({"path": "/old/export145","sha256":"b".repeat(64)})
        } else {
            provider.clone()
        };
        let active = json!({"state":"running","mode": mode,"image":image["path"],"pid":42,"iid":"1".repeat(32),"start_ticks":20});
        let phase = json!({"unit":EXPORTER,"phase":mode,"image":image,"pid":42,"invocation_id":active["iid"],"start_ticks":20,
            "seven_capable":compatible,"activation_compatible":compatible,"output_device":64512,"output_inode":103237059});
        let wire = json!({"resources":{"complete_memory_plus_reserve_bytes":810658050048u64,
            "existing_cpu_quota_micros":64_000_000,"unfenced_with_candidate_cpu_micros":68_250_000,
            "available_memory_bytes":60,"required_available_memory_bytes":50,
            "free_HOME_bytes":100+CANDIDATE_DISK,"protected_existing_only_bytes":100},
            "candidate":{"limit_bytes":CANDIDATE_DISK,"realized_bytes":0,"remaining_bytes":CANDIDATE_DISK,
            "required_total_bytes":100+CANDIDATE_DISK,"identity":null},"phase145":phase,"provider":provider,"disk_fits":true});
        (wire, active)
    }

    #[test]
    fn idle_feasibility_cannot_authorize_a_seventh_worker_during_the_original_export_or_gap() {
        let (mut wire, active) = sample("run", false);
        assert!(evaluate(&wire, &Value::Null, &active, false).is_ok());
        assert!(evaluate(&wire, &Value::Null, &active, true).is_err());
        wire["phase145"]["seven_capable"] = true.into();
        wire["phase145"]["activation_compatible"] = true.into();
        assert!(evaluate(&wire, &Value::Null, &active, true).is_err());
        let absent = json!({"state":"absent"});
        wire["phase145"] = json!({"phase":"gap","unit":EXPORTER,"invocation_id":null,"image":null,
            "output_device":64512,"output_inode":103237059,"seven_capable":false,"activation_compatible":false});
        assert!(evaluate(&wire, &Value::Null, &absent, false).is_ok());
        assert!(evaluate(&wire, &Value::Null, &absent, true).is_err());
    }

    #[test]
    fn admission_needs_the_live_compatible_image_and_the_entire_resulting_floor() {
        let (mut wire, active) = sample("post-full", true);
        assert!(evaluate(&wire, &Value::Null, &active, true).is_ok());
        wire["resources"]["free_HOME_bytes"] = (99 + CANDIDATE_DISK).into();
        wire["disk_fits"] = false.into();
        assert!(evaluate(&wire, &Value::Null, &active, false).is_ok());
        assert!(evaluate(&wire, &Value::Null, &active, true).is_err());
        wire["resources"]["free_HOME_bytes"] = (100 + CANDIDATE_DISK).into();
        wire["disk_fits"] = true.into();
        wire["phase145"]["image"]["sha256"] = "c".repeat(64).into();
        assert!(evaluate(&wire, &Value::Null, &active, true).is_err());
    }

    #[test]
    fn only_the_identified_waiting_root_can_reduce_its_own_remaining_growth_once() {
        let (mut w, active) = sample("publish", true);
        let own = json!({"iid":"2".repeat(32),"writer_invocation_id":"3".repeat(32),
            "admission":{"path":"admission.json","sha256":"a".repeat(64)},
            "producer_pid":123,"start_ticks":10,"guard_plan":{"path":"guard-plan.json","sha256":"b".repeat(64)}});
        w["candidate"]["identity"] = json!({"unit":UNIT,"invocation_id":own["iid"],"writer_invocation_id":own["writer_invocation_id"],
            "admission":own["admission"],"pid":123,"start_ticks":10,"node_pid":null,"worker_pid":null,
            "guard_plan":own["guard_plan"],"guard_sample":{"path":"sample.json","sha256":"c".repeat(64)}});
        w["candidate"]["realized_bytes"] = 10.into();
        w["candidate"]["remaining_bytes"] = (CANDIDATE_DISK - 10).into();
        w["candidate"]["required_total_bytes"] = (CANDIDATE_DISK + 90).into();
        assert!(evaluate(&w, &own, &active, true).is_ok());
        assert!(evaluate(&w, &Value::Null, &active, false).is_err());
        w["candidate"]["required_total_bytes"] = (CANDIDATE_DISK + 80).into();
        assert!(evaluate(&w, &own, &active, true).is_err());
        w["candidate"]["required_total_bytes"] = (CANDIDATE_DISK + 90).into();
        w["candidate"]["identity"]["guard_plan"]["sha256"] = "d".repeat(64).into();
        assert!(evaluate(&w, &own, &active, true).is_err());
    }
}
