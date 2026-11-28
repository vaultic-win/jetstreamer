use super::identity::*;
use super::platform::*;
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const PREV_IID: &str = "b9aa118912884bce9876f0e8c2b4cb99";
const PREV_PID: i32 = 3485442;
fn dropin() -> PathBuf {
    Path::new("/run/systemd/system").join(format!("{PUB_UNIT}.d/85-public-audit73-natural.conf"))
}
pub fn cadence_owner(next: bool) -> Result<Value> {
    let unit = show(
        PUB_UNIT,
        "MainPID,InvocationID,ActiveState,SubState,ControlGroup,Job,NRestarts",
    )?;
    ensure!(
        unit["ActiveState"] == "active"
            && unit["SubState"] == "running"
            && unit["NRestarts"] == "0"
            && unit["Job"] == "",
        "publisher not steady"
    );
    let pid: i32 = text(&unit["MainPID"])?.parse()?;
    let pkg = if next {
        observer()
    } else {
        base("full172-guard-refresh-20261121-v1/observer-package")
    };
    let exe = pkg.join("consume");
    ensure!(
        fs::read_link(proc_path(pid, "fd/255"))? == exe
            && fs::read_link(proc_path(pid, "fd/9"))?
                == base("stable-cadence-controller-20261120-v1/consumer.lock"),
        "unexpected publisher or lock"
    );
    ensure!(
        fs::read_to_string(proc_path(pid, "fdinfo/9"))?
            .lines()
            .any(|s| s.starts_with("lock:") && s.contains("FLOCK") && s.contains("WRITE")),
        "publisher lock is not held"
    );
    if next {
        ensure!(
            unit["InvocationID"] != PREV_IID,
            "publisher was not replaced"
        );
    } else {
        ensure!(
            unit["InvocationID"] == PREV_IID && pid == PREV_PID && ticks(pid)? == 357470692,
            "prior publisher changed"
        );
    }
    let members = group_members(text(&unit["ControlGroup"])?)?;
    ensure!(
        members.len() == 2
            && members.contains(&pid)
            && members
                .into_iter()
                .filter(|p| *p != pid)
                .all(|p| proc_exe(p).is_ok_and(|exe| exe == Path::new("/usr/bin/sleep"))),
        "publisher not between scheduled cycles"
    );
    Ok(unit)
}
pub fn switch() -> Result<()> {
    ensure!(
        !work().join("OBSERVER_SWITCH.json").try_exists()? && !dropin().try_exists()?,
        "publisher already managed"
    );
    verify_seal(&observer(), OBS_SEAL)?;
    let (r, f, cfg) = latest_fleet(true)?;
    let peers = owners(&f)?;
    old_live()?;
    let before = cadence_owner(false)?;
    let bytes = format!(
        "[Service]\nExecStartPre=\nExecStart=\nExecStart={} {} {}\n",
        observer().join("consume").display(),
        text(&r["path"])?,
        text(&r["sha256"])?
    );
    let intent = json!({"at":now(),"before":before,"fleet":r,"peers":peers,"timer":cfg["timer"],"dropin_sha256":sha(bytes.as_bytes()),"seal":bound(&observer().join("deployment-seal-receipt.json"))?});
    save(&work().join("OBSERVER_INTENT.json"), &intent)?;
    create(&dropin(), bytes.as_bytes(), 0o644)?;
    let result = (|| -> Result<_> {
        ctl(&["daemon-reload"])?;
        ensure!(
            cadence_owner(false)? == before && owners(&f)? == peers,
            "owners changed before publisher transition"
        );
        ctl(&["restart", PUB_UNIT])?;
        let until = Instant::now() + Duration::from_secs(12);
        let after = loop {
            if let Ok(v) = cadence_owner(true) {
                break v;
            }
            ensure!(
                Instant::now() < until,
                "new publisher did not take its existing lock"
            );
            std::thread::sleep(Duration::from_millis(100));
        };
        ensure!(
            owners(&f)? == peers
                && show(text(&cfg["timer"])?, "ActiveState")?["ActiveState"] == "active",
            "protected owner or timer changed"
        );
        save(
            &work().join("OBSERVER_SWITCH.json"),
            &json!({"at":now(),"before":before,"after":after,"anchor":r,"timer":cfg["timer"],"package":bound(&observer().join("deployment-seal-receipt.json"))?,"shared_lock_held":true,"old_epoch_workers_preserved":true}),
        )
    })();
    if let Err(e) = result {
        // If the right successor already started, leave the native owner intact.
        let current = show(PUB_UNIT, "MainPID,ActiveState,InvocationID")?;
        if current["MainPID"] != "0" && current["InvocationID"] != PREV_IID {
            return Err(e.context(
                "new publisher owns the unit; inspect its receipt without restarting it",
            ));
        }
        ensure!(
            sha(&read(&dropin())?) == sha(bytes.as_bytes()),
            "publisher drop-in changed before restore"
        );
        fs::remove_file(dropin())?;
        ctl(&["daemon-reload"])?;
        if current["MainPID"] == "0" {
            ctl(&["start", PUB_UNIT])?;
        }
        return Err(e);
    }
    Ok(())
}
pub fn check() -> Result<Value> {
    let r = bound(&work().join("OBSERVER_SWITCH.json"))?;
    let v = from_ref(&r)?;
    let current = cadence_owner(true)?;
    ensure!(
        v["after"] == current && v["package"]["sha256"] == OBS_SEAL,
        "current cadence owner differs from switch"
    );
    Ok(r)
}
