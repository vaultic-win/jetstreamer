mod fence;
mod identity;
mod platform;
mod publisher;

use anyhow::{Context, Result, ensure};
use fence::*;
use identity::*;
use platform::*;
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

const NEW_COMMIT: &str = "2db5b99d5d213e921ebcbb08d5b25e00b754a0d4";
fn dropin() -> PathBuf {
    Path::new("/etc/systemd/system").join(format!("{UNIT}.d/99-z-public-v14.conf"))
}
fn drop_bytes() -> String {
    let p = package(true);
    format!(
        "[Unit]\nRequiresMountsFor={}\n[Service]\nExecStartPre=\nExecStart=\nExecStart={}/audit run-public {}/config.json\n",
        p.display(),
        p.display(),
        p.display()
    )
}
fn meta(p: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&read(p)?)?)
}
fn smoke(require_idle: bool) -> Result<Value> {
    let old = old_live()?;
    let (r, f, cfg) = latest_fleet(require_idle)?;
    let old_proof = pinned(&old_owner(), OLD_OWNER)?;
    ensure!(old_proof["native"] == old, "native v13 launch mismatch");
    let inventory = bound(&public().join("inventory.json"))?;
    ensure!(inventory["sha256"] == INV_SHA, "frozen inventory differs");
    verify_seal(&observer(), OBS_SEAL)?;
    verify_seal(&package(false), OLD_SEAL)?;
    verify_seal(&package(true), NEW_SEAL)?;
    let qa = pinned(&base(E2E), E2E_SHA)?;
    ensure!(
        qa["current_build"].is_string()
            && qa["same_epoch_counters_and_digest"] == true
            && qa["old_and_new_links_verified"] == true,
        "v14 genuine recovery QA missing"
    );
    let prev = meta(&public().join("results/epoch-72.json"))?;
    let proof = pinned(&attempt().join("reports/epoch-72.json"), R72_SHA)?;
    ensure!(
        prev["native_report_sha256"] == R72_SHA
            && prev["invocation"] == proof["invocation"]
            && prev["reader_commit"] == "5bb2637754782ad3f03f5b780a5024fa89602adc",
        "epoch 72 lineage differs"
    );
    let old_manifest = manifest()?;
    Ok(
        json!({"at":now(),"previous_owner":bound(&old_owner())?,"inventory":inventory,"prior_fleet":r,
        "prior_audit_observation":f["continuing_audit_obligation"]["current_observation"],"peers":owners(&f)?,
        "accepted_result_sha256":old_manifest,"next_timer":cfg["timer"],"old_row":old,"v14_e2e":bound(&base(E2E))?}),
    )
}
fn stopped() -> Result<Value> {
    let row = show(UNIT, FIELDS)?;
    ensure!(
        row["Id"] == UNIT
            && row["ActiveState"] == "inactive"
            && row["MainPID"] == "0"
            && row["Job"] == ""
            && (row["InvocationID"] == "" || row["InvocationID"] == OLD_IID)
            && ticks(OLD_PID).ok() != Some(OLD_TICKS)
            && group_members(CG)?.is_empty(),
        "old owner still present"
    );
    Ok(row)
}
fn watch_units() -> Result<Value> {
    let mut peers = Vec::new();
    for u in [
        "horizon-public-epochs0-100-256-global-slots-compact-20261120-v3.service",
        "horizon-public-epochs0-100-rseek-updates-pair-20261121-v3.service",
    ] {
        let r = show(
            u,
            "Id,MainPID,InvocationID,ActiveState,SubState,NRestarts,Job,ControlGroup",
        )?;
        ensure!(
            r["NRestarts"] == "0" && r["Job"] == "",
            "trial or comparison changing ownership"
        );
        peers.push(r);
    }
    Ok(json!(peers))
}
fn owner_for(is_new: bool, stop: &Value) -> Result<Value> {
    let pkg = package(is_new);
    let row = show(UNIT, FIELDS)?;
    let pid = identity(&row, &pkg)?;
    ensure!(
        row["InvocationID"] != OLD_IID && ticks(pid)? > OLD_TICKS,
        "new owner reused old identity"
    );
    let old = pinned(&old_owner(), OLD_OWNER)?;
    let mut receipt = json!({"at":now(),"InvocationID":row["InvocationID"],"pid":pid,"start_ticks":ticks(pid)?,"native":row,
        "previous_owner":bound(&old_owner())?,"previous_stopped":stop,"stopped":old["stopped"],
        "source_commit":if is_new{json!(NEW_COMMIT)}else{old["source_commit"].clone()},
        "seal":bound(&pkg.join("deployment-seal-receipt.json"))?});
    if !is_new {
        receipt["rollback"] = bound(&work().join("ROLLBACK.json"))?
    }
    Ok(receipt)
}
fn finish_start(stop: Value) -> Result<()> {
    let rollback = work().join("ROLLBACK.json");
    let new = !rollback.try_exists()?;
    let r = show(UNIT, FIELDS)?;
    if r["MainPID"] == "0" {
        ensure!(
            group_members(CG)?.is_empty(),
            "unexpected process before start"
        );
        if let Err(e) = ctl(&["start", UNIT]) {
            let failed = show(UNIT, FIELDS)?;
            if failed["MainPID"] != "0" || !group_members(CG)?.is_empty() || !new {
                return Err(e.context("start or ownership uncertain"));
            }
            let boundary = from_ref(&from_ref(&stop)?["boundary"])?;
            ensure!(
                manifest()? == boundary["accepted_result_sha256"],
                "accepted set changed before rollback"
            );
            save(
                &rollback,
                &json!({"at":now(),"attempted_seal":bound(&package(true).join("deployment-seal-receipt.json"))?,
                "stopped":stop,"v14_cgroup_empty":true,"accepted_results_unchanged":true,"failed":failed,"error":e.to_string()}),
            )?;
            effective_drop()?;
            return finish_start(stop);
        }
    }
    let owner = owner_for(new, &stop)?;
    save(&work().join("PUBLIC_OWNER.json"), &owner)?;
    confirm_preserved(&from_ref(&from_ref(&stop)?["boundary"])?["accepted_result_sha256"])?;
    Ok(())
}
fn effective_drop() -> Result<()> {
    let path = dropin();
    let bytes = drop_bytes();
    if work().join("ROLLBACK.json").try_exists()? {
        if path.try_exists()? {
            ensure!(
                read(&path)? == bytes.as_bytes(),
                "foreign drop-in during rollback"
            );
            fs::remove_file(&path)?;
            fs::File::open(path.parent().context("drop-in parent")?)?.sync_all()?;
        }
    } else if path.try_exists()? {
        ensure!(read(&path)? == bytes.as_bytes(), "foreign v14 drop-in");
    } else {
        create(&path, bytes.as_bytes(), 0o644)?;
    }
    ctl(&["daemon-reload"])?;
    Ok(())
}
fn closed_start() -> Result<()> {
    let path = work().join("STOPPED.json");
    if !path.try_exists()? {
        let b = work().join("BOUNDARY.json");
        let v = meta(&b)?;
        ensure!(
            v["previous_child_drained"] == true
                && v["new_playback_started"] == false
                && v["previous_owner"]["sha256"] == OLD_OWNER,
            "incorrect closure boundary"
        );
        let r = stopped()?;
        save(
            &path,
            &json!({"at":now(),"native":r,"previous_owner":bound(&old_owner())?,
            "old_cgroup_empty":true,"old_pid_absent_or_reused":true,"boundary":bound(&b)?}),
        )?;
    }
    let current = show(UNIT, FIELDS)?;
    if current["MainPID"] != "0" {
        let _ = owner_for(!work().join("ROLLBACK.json").try_exists()?, &bound(&path)?)?;
    }
    effective_drop()?;
    finish_start(bound(&path)?)
}
fn cut() -> Result<()> {
    ensure!(
        !work().join("BOUNDARY.json").try_exists()? && !dropin().try_exists()?,
        "boundary already processed or drop-in installed"
    );
    let event = bound(&attempt().join("branch-change.json"))?;
    let marker = from_ref(&event)?;
    let native = bound(&attempt().join("reports/epoch-73.json"))?;
    let ref72 = pinned(&attempt().join("reports/epoch-72.json"), R72_SHA)?;
    validate_report(&from_ref(&native)?, &ref72, &marker)?;
    ensure!(
        marker["at"]
            .as_u64()
            .is_some_and(|stamp| (stamp..=stamp.saturating_add(90)).contains(&now())),
        "stale marker"
    );
    let observer = publisher::check()?;
    let guard = ParentFence::acquire()?;
    let mut boundary = smoke(true)?;
    let trials = watch_units()?;
    boundary["qualifying_branch"] = branch_equivalent()?;
    boundary["at"] = json!(now());
    for (k, v) in [
        ("event", event),
        ("epoch", json!(73)),
        ("native_report", native),
        ("accepted_epochs", json!((0..73).collect::<Vec<_>>())),
        ("previous_child_pid", json!(OLD_CHILD)),
        ("previous_child_drained", json!(true)),
        ("new_playback_started", json!(false)),
        ("cadence_owner", observer),
        ("independent_trials", trials.clone()),
    ] {
        boundary[k] = v;
    }
    ensure!(
        group_members(CG)? == [OLD_PID] && watch_units()? == trials,
        "owners changed during fence"
    );
    no_new_playback()?;
    save(&work().join("BOUNDARY.json"), &boundary)?;
    // systemd sends SIGCONT with SIGTERM. No native reader exists in this unit.
    ctl(&["stop", UNIT])?;
    drop(guard);
    closed_start()
}
fn recover() -> Result<()> {
    // ExecStopPost also runs after a normal exit. Never stop a different live invocation.
    if work().join("PUBLIC_OWNER.json").try_exists()? {
        return Ok(());
    }
    let r = show(UNIT, FIELDS)?;
    if r["InvocationID"] == OLD_IID && text(&r["MainPID"])?.parse::<i32>()? == OLD_PID {
        if !work().join("FENCE_INTENT.json").try_exists()? {
            return Ok(());
        }
        let intent = meta(&work().join("FENCE_INTENT.json"))?;
        ensure!(
            intent["owner"] == bound(&old_owner())?
                && intent["pid"] == OLD_PID
                && intent["ticks"] == OLD_TICKS
                && intent["event"] == bound(&attempt().join("branch-change.json"))?,
            "invalid fence recovery intent"
        );
        old_live()?;
        let stat = fs::read_to_string(proc_path(OLD_PID, "status"))?;
        if stat.lines().any(|s| s.starts_with("State:\tT")) {
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, OLD_PID, 0) } as i32;
            ensure!(
                fd >= 0 && ticks(OLD_PID)? == OLD_TICKS,
                "wrong recovery PID"
            );
            let rc = unsafe { libc::syscall(libc::SYS_pidfd_send_signal, fd, libc::SIGCONT, 0, 0) };
            unsafe {
                libc::close(fd);
            }
            ensure!(rc == 0, "failed to resume original process");
        }
        return Ok(());
    }
    if work().join("BOUNDARY.json").try_exists()? {
        closed_start()?;
    }
    Ok(())
}
fn main() -> Result<()> {
    let mode = std::env::args()
        .nth(1)
        .context("expected qualify, publisher, cut, or recover")?;
    ensure!(
        std::env::args().count() == 2 && unsafe { libc::geteuid() } == 0,
        "root, single command required"
    );
    match mode.as_str() {
        "qualify" => {
            let mut q = smoke(false)?;
            q["source_comparison"] = compare_branch("/home/sol/workspace/jetstreamer")?;
            q["idle_publisher"] = publisher::cadence_owner(false)?;
            q["native_independent_trials"] = watch_units()?;
            println!("{}", q);
        }
        "recovery-facts" => {
            old_live()?;
            verify_seal(&package(false), OLD_SEAL)?;
            verify_seal(&package(true), NEW_SEAL)?;
            let qa = pinned(&base(E2E), E2E_SHA)?;
            ensure!(
                qa["same_epoch_counters_and_digest"] == true
                    && qa["old_and_new_links_verified"] == true,
                "invalid recovery QA"
            );
            println!(
                "{}",
                json!({"old_row":old_live()?,"source_comparison":branch_equivalent()?,
                "v14_e2e":bound(&base(E2E))?,"native_independent_trials":watch_units()?})
            );
        }
        "finish-boundary" => closed_start()?,
        "publisher" => publisher::switch()?,
        "cut" => cut()?,
        "recover" => recover()?,
        "active" => println!("{}", review_live()?),
        _ => anyhow::bail!("unknown mode: {mode}"),
    }
    Ok(())
}
fn owner_static(saved: &Value, stopped: &Value) -> Result<Value> {
    let mut live = owner_for(saved.get("rollback").is_none(), stopped)?;
    live["at"] = saved["at"].clone();
    Ok(live)
}

fn review_live() -> Result<Value> {
    let stop = bound(&work().join("STOPPED.json"))?;
    let owner = meta(&work().join("PUBLIC_OWNER.json"))?;
    ensure!(owner == owner_static(&owner, &stop)?, "live owner differs");
    let closed = from_ref(&stop)?;
    let boundary = from_ref(&closed["boundary"])?;
    confirm_preserved(&boundary["accepted_result_sha256"])?;
    let latest = meta(&public().join("progress.json"))?;
    ensure!(
        latest["pid"] == owner["pid"]
            && latest["archive_scratch_bytes"] == 0
            && latest["remote_mutations"] == false,
        "public owner has not yet issued its progress"
    );
    let path = public().join("results/epoch-73.json");
    let mut report = json!({"at":now(),"owner":owner,"progress":latest,"prior_results_unchanged":73,"epoch_73_accepted":false});
    if path.try_exists()? {
        let receipt = bound(&path)?;
        let result = from_ref(&receipt)?;
        let inventory = from_ref(&boundary["inventory"])?;
        let obj = inventory["objects"]
            .as_array()
            .context("inventory")?
            .iter()
            .find(|x| x["epoch"] == 73)
            .context("missing 73")?;
        ensure!(
            result["epoch"] == 73
                && result["object"] == *obj
                && result["epoch_plugin_completed"] == true
                && result["remote_mutations"] == false
                && result["inventory_sha256"] == INV_SHA
                && result["status"] == "passed",
            "invalid accepted epoch 73"
        );
        let state = Path::new(
            "/var/lib/jetstreamer/r2-chronological-plugin-audit-20261118-v1/public-stream-v1",
        );
        let data_path = |field: &str| -> Result<PathBuf> {
            Ok(public().join(Path::new(text(&result[field])?).strip_prefix(state)?))
        };
        let native = pinned(
            &data_path("native_report")?,
            text(&result["native_report_sha256"])?,
        )?;
        ensure!(
            native["invocation"] == result["invocation"]
                && native["report"] == result["report"]
                && native["report"]["slots"] == 432000
                && native["report"]["epoch"] == 73,
            "native accepted report changed"
        );
        let same = bound(&data_path("native_report")?)? == boundary["native_report"];
        let proof = pinned(
            &data_path("reader_proof")?,
            text(&result["reader_proof_sha256"])?,
        )?;
        if same {
            for key in ["playback_source_proof", "matching_current_build"] {
                let r = &proof[key];
                let p = public().join(Path::new(text(&r["path"])?).strip_prefix(state)?);
                let linked = pinned(&p, text(&r["sha256"])?)?;
                ensure!(
                    linked["artifact_sha256"] == result["reader_sha256"],
                    "mismatched current or original build"
                );
            }
        }
        report["epoch_73_accepted"] = json!(true);
        report["original_native_report_recovered"] = json!(same);
        report["result"] = receipt;
        report["transactions"] = result["report"]["transactions"].clone();
        report["authenticated_readiness"] = result["authenticated_readiness"].clone();
    }
    Ok(report)
}
