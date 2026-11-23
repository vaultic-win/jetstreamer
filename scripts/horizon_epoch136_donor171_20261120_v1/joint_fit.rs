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
const LEGACY_IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-publication-20261121-v1/joint-tools-v2/export145";
const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-publication-20261121-v1/joint-tools-v3/export145";
const TERMINAL: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch168-terminal-trace-20261121-v1/TERMINAL.json";
const TERMINAL_SHA: &str = "29672efbaff97d23a9a9d45a824840cb2d4cf43c6f5e8427ed3b532b41a38de2";
const ORIGINAL: &[u64] = &[166, 167, 168, 169, 170, 172];
const SURVIVORS: &[u64] = &[166, 167, 169, 170, 172];
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
fn check_generation(fleet: &Value, path: &Path) -> Result<()> {
    let terminal = &fleet["terminal168_trace_mismatch"];
    if terminal.is_null() && path == Path::new(LEGACY_IMAGE) {
        return Ok(());
    }
    ensure!(
        *terminal == binding(Path::new(TERMINAL), TERMINAL_SHA) && path == Path::new(IMAGE),
        "145 provider and fleet trace generation differ"
    );
    Ok(())
}

fn terminal_evidence(fleet: &Value) -> Result<Value> {
    if fleet["terminal168_trace_mismatch"].is_null() {
        return Ok(Value::Null);
    }
    let t = json_pin(Path::new(TERMINAL), TERMINAL_SHA)?;
    let unit = text(&t, "unit")?;
    let state = show(unit)?;
    let guard = show(text(&t["guard_state"], "Id")?)?;
    ensure!(
        t["schema"] == "horizon-epoch168-target-trace-terminal-v1"
            && t["epoch"] == 168
            && t["resource_credit_bytes"] == 0
            && t["archive_verified"] == false
            && t["archive_publication_authorized"] == false
            && t["r2_mutations"] == false
            && t["boot"]
                == fs::read_to_string("/proc/sys/kernel/random/boot_id")?
                    .trim()
                    .replace('-', "")
            && closed(&state)
            && state["InvocationID"] == t["invocation"]
            && [
                "ActiveState",
                "SubState",
                "ExecMainStatus",
                "Result",
                "NRestarts",
                "ControlGroup"
            ]
            .iter()
            .all(|k| state[*k] == t["state"][*k])
            && closed(&guard)
            && guard["ActiveState"] == "inactive",
        "168 original producer or guard is no longer closed"
    );
    super::cgroup_empty(unit)?;
    Ok(t)
}

fn bind_terminal(native: &Value, terminal: &Value) -> Result<()> {
    if terminal.is_null() {
        ensure!(
            native.is_null(),
            "unexpected 168 terminal for original fleet"
        );
    } else {
        ensure!(
            native["terminal"] == *terminal
                && native["partial145"]["terminal168"]
                    == binding(Path::new(TERMINAL), TERMINAL_SHA)
                && native["resource_credit_bytes"] == 0,
            "145 fit does not retain the same closed trace and commitments"
        );
    }
    Ok(())
}

fn image(provider: &Value, fleet: &Value) -> Result<PathBuf> {
    let file = &provider["image"];
    let path = PathBuf::from(text(file, "path")?);
    let parent = path.parent().context("provider directory")?;
    check_generation(fleet, &path)?;
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
fn bind_incumbents(fleet: &Value, proof: &Value, own: &Value, terminal: &Value) -> Result<()> {
    let expected = if terminal.is_null() {
        ORIGINAL
    } else {
        SURVIVORS
    };
    let rows = proof.as_object().context("live peer/guard identities")?;
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
                expected.contains(&epoch) && seen.insert(epoch),
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
            if !terminal.is_null() {
                let original = &terminal["live_original_owners"][epoch.to_string()];
                ensure!(
                    original["Id"] == peer["unit"]
                        && original["InvocationID"] == peer["invocation_id"]
                        && (key == "actual_active_private_diagnostics") == (epoch == 169),
                    "different original peer or role after trace closure {epoch}"
                );
            }
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
        expected.iter().all(|e| seen.contains(e)) && rows.len() == expected.len(),
        "incomplete or substituted incumbent roster"
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
    if phase["seven_capable"] == true {
        ensure!(
            active["state"] == "running"
                && (active["mode"] == "post-full" || active["mode"] == "publish")
                && phase["image"] == wire["provider"],
            "incompatible 145 actor claimed support for another worker"
        );
    }
    ensure!(
        !supports || phase["seven_capable"] == true,
        "145 admission requires an eligible live actor"
    );
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
    if fleet.get("active_ready_range_audit_obligation").is_some() {
        let own = candidate(waiting_iid)?;
        let active = observe_145()?;
        let fence = if require_activation_compatible
            && Path::new("/run/horizon-epoch171-exclusive-to136-g1/standard169-cpu.json")
                .try_exists()?
        {
            fence::check(true)?
        } else {
            Value::Null
        };
        let mut cmd = Command::new("/usr/bin/python3");
        let result = cmd
            .args(["-I", "-B", "-c", include_str!("incident_prestart.py")])
            .arg(fleet_path)
            .arg(fleet_sha)
            .arg(serde_json::to_string(&own)?)
            .arg(if require_activation_compatible {
                "session"
            } else {
                "preflight"
            })
            .arg(serde_json::to_string(&plan["joint_fit_145"])?)
            .arg(serde_json::to_string(&fence)?)
            .args(
                cfg!(feature = "fixture-semantic").then_some(if cfg!(feature = "v5n-semantic") {
                    "v5n-semantic"
                } else if cfg!(feature = "retry-semantic") {
                    "retry-semantic"
                } else {
                    "fixture-semantic"
                }),
            )
            .stdin(Stdio::null())
            .output()
            .context("capture epoch 136 incident prestart")?;
        ensure!(
            result.status.success() && result.stdout.len() <= 4 << 20,
            "136 incident price: {}",
            String::from_utf8_lossy(&result.stderr[..result.stderr.len().min(4096)])
        );
        let mut confirmed: Value = serde_json::from_slice(&result.stdout)?;
        ensure!(
            confirmed["fleet"] == binding(fleet_path, fleet_sha)
                && (!require_activation_compatible || confirmed["activation_compatible"] == true)
                && candidate(waiting_iid)? == own
                && observe_145()? == active,
            "changed candidate, holding owner or incident price"
        );
        confirmed["donor171_ancestry"] = ancestry;
        confirmed["native_145"] = active;
        return Ok(confirmed);
    }
    let audit = fit::observe_audit(&fleet["continuing_audit_obligation"])?;
    let p = &plan["joint_fit_145"];
    let executable = image(p, &fleet)?;
    let terminal = terminal_evidence(&fleet)?;
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
    bind_terminal(&wire["actual_native_fit"]["terminal168"], &terminal)?;
    bind_incumbents(&fleet, &wire["incumbents"], &own, &terminal)?;
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
            && terminal_evidence(&fleet)? == terminal
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
    fn provider_generation_and_native_terminal_are_bound_to_the_same_receipt() {
        let old = json!({});
        let receipt = binding(Path::new(TERMINAL), TERMINAL_SHA);
        let mut fleet = json!({"terminal168_trace_mismatch":receipt});
        for (f, path, accepted) in [
            (&old, LEGACY_IMAGE, true),
            (&old, IMAGE, false),
            (&fleet, LEGACY_IMAGE, false),
            (&fleet, IMAGE, true),
        ] {
            assert_eq!(check_generation(f, Path::new(path)).is_ok(), accepted);
        }
        fleet["terminal168_trace_mismatch"]["sha256"] = "0".repeat(64).into();
        assert!(check_generation(&fleet, Path::new(IMAGE)).is_err());

        let terminal = json!({"resource_credit_bytes":0,"archive_verified":false});
        let mut native = json!({"terminal":terminal,"resource_credit_bytes":0,"partial145":{"terminal168":receipt}});
        assert!(bind_terminal(&native, &terminal).is_ok());
        assert!(bind_terminal(&native, &Value::Null).is_err());
        assert!(bind_terminal(&Value::Null, &terminal).is_err());
        native["resource_credit_bytes"] = 1.into();
        assert!(bind_terminal(&native, &terminal).is_err());
        native["resource_credit_bytes"] = 0.into();
        native["terminal"]["archive_verified"] = true.into();
        assert!(bind_terminal(&native, &terminal).is_err());
        native["terminal"] = terminal.clone();
        native["partial145"]["terminal168"]["path"] = "/foreign".into();
        assert!(bind_terminal(&native, &terminal).is_err());
    }

    #[test]
    fn surviving_peers_keep_the_original_invocations_and_roles() {
        let mut fleet = json!({"actual_executing_replays":[], "actual_active_bootstraps":[], "actual_active_private_diagnostics":[]});
        let mut proof = json!({});
        let mut t = json!({"live_original_owners":{}});
        for e in SURVIVORS {
            let unit = json!({"Id":format!("worker-{e}"), "InvocationID":format!("{e:032x}")});
            let guard = format!("{:032x}", e + 10);
            let key = if *e == 169 {
                "actual_active_private_diagnostics"
            } else {
                "actual_executing_replays"
            };
            fleet[key]
                .as_array_mut()
                .unwrap()
                .push(json!({"epoch":e,"unit":unit,"guard_timer":{"InvocationID":guard}}));
            proof[e.to_string()] = json!({"unit":unit["Id"],"invocation_id":unit["InvocationID"],"guard_timer_invocation_id":guard});
            t["live_original_owners"][e.to_string()] = unit;
        }
        assert!(bind_incumbents(&fleet, &proof, &Value::Null, &t).is_ok());
        assert!(bind_incumbents(&fleet, &proof, &Value::Null, &Value::Null).is_err());
        let mut crossed = fleet.clone();
        crossed["actual_executing_replays"][0]["epoch"] = 168.into();
        assert!(bind_incumbents(&crossed, &proof, &Value::Null, &t).is_err());
        let mut impersonated = proof.clone();
        impersonated["166"]["invocation_id"] = "c".repeat(32).into();
        crossed = fleet.clone();
        crossed["actual_executing_replays"][0]["unit"]["InvocationID"] =
            impersonated["166"]["invocation_id"].clone();
        assert!(bind_incumbents(&crossed, &impersonated, &Value::Null, &t).is_err());
        crossed = fleet.clone();
        let private = crossed["actual_active_private_diagnostics"]
            .as_array_mut()
            .unwrap()
            .pop()
            .unwrap();
        crossed["actual_executing_replays"]
            .as_array_mut()
            .unwrap()
            .push(private);
        assert!(bind_incumbents(&crossed, &proof, &Value::Null, &t).is_err());
        let mut missing = proof;
        missing.as_object_mut().unwrap().remove("167");
        assert!(bind_incumbents(&fleet, &missing, &Value::Null, &t).is_err());
    }

    #[test]
    #[ignore = "reads the native original 168 close and the private 145 recovery receipt on the campaign host"]
    fn original_recovery_receipt_binds_the_closed_diagnostic_and_live_survivors() {
        let path = Path::new(
            "/var/lib/jetstreamer/horizon_runtime_data/root081959-live166167170-20261121-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json",
        );
        let fleet = json_pin(
            path,
            "dca8533d21f7e17ea46b957d5a8693a8ae04615b08905e224463624bf6f67bfb",
        )
        .unwrap();
        check_generation(&fleet, Path::new(IMAGE)).unwrap();
        let t = terminal_evidence(&fleet).unwrap();
        let recovery = json_pin(Path::new("/var/lib/jetstreamer/horizon_runtime_data/epoch145-guarded-export-20261121-v1/state/5dfb817906f74b73a27f61a386751d75/recovery-started.json"), "abfd9eca8c8249e4f1f6b69aaa7ba05c6b970a3d0a932d0087b8cea51e0ff0c2").unwrap();
        bind_terminal(&recovery["fresh_fit"]["terminal168"], &t).unwrap();
        assert_eq!(recovery["fresh_fit"]["joint136_enabled"], false);
        let mut proof = json!({});
        for name in [
            "actual_executing_replays",
            "actual_active_private_diagnostics",
        ] {
            for row in fleet[name].as_array().unwrap() {
                let epoch = row["epoch"].as_u64().unwrap();
                let owner = show(row["unit"]["Id"].as_str().unwrap()).unwrap();
                assert_eq!(owner["ActiveState"], "active");
                let guard = if let Some(unit) = row["guard_timer"]["Id"].as_str() {
                    unit.to_string()
                } else {
                    let b = &row["guard_protection"];
                    let p = json_pin(
                        Path::new(text(b, "path").unwrap()),
                        text(b, "sha256").unwrap(),
                    )
                    .unwrap();
                    text(&p, "timer_unit").unwrap().to_string()
                };
                let timer = show(&guard).unwrap();
                assert_eq!(timer["ActiveState"], "active");
                proof[epoch.to_string()] = json!({"unit":owner["Id"], "invocation_id":owner["InvocationID"], "guard_timer_invocation_id":timer["InvocationID"]});
            }
        }
        bind_incumbents(&fleet, &proof, &Value::Null, &t).unwrap();
        assert!(bind_incumbents(&fleet, &proof, &Value::Null, &Value::Null).is_err());
    }

    #[test]
    fn recovery_never_admits_even_when_space_fits() {
        let (mut wire, active) = sample("recover-full-output", false);
        assert!(evaluate(&wire, &Value::Null, &active, false).is_ok());
        assert!(evaluate(&wire, &Value::Null, &active, true).is_err());
        wire["phase145"]["activation_compatible"] = true.into();
        assert!(evaluate(&wire, &Value::Null, &active, false).is_err());
        wire["phase145"]["seven_capable"] = true.into();
        assert!(evaluate(&wire, &Value::Null, &active, false).is_err());
        let (mut wire, active) = sample("publish", true);
        wire["resources"]["available_memory_bytes"] = 49.into();
        assert!(evaluate(&wire, &Value::Null, &active, true).is_err());
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
