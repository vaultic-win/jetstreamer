//! A periodic oneshot may be firing while its last successful proof remains fresh.
use super::native211::{self as c, num, text};
use super::*;
const TIMER: &str = "horizon-native211-protective-v1.timer";
const FIELDS: &str = "LoadState,ActiveState,SubState,InvocationID,Result,ExecMainStatus,ExecStart,DropInPaths,Restart,MemoryMax,MemorySwapMax,StartLimitIntervalUSec,Type,RemainAfterExit,TimeoutStartUSec,ExecMainStartTimestampMonotonic";
fn manager_values(m: &Value, gb: &BoundFile, now: u64) -> Result<bool> {
    let command = format!(
        "{{ path={} ; argv[]={0} {} --plan-sha256 {} --self-sha256 {}",
        c::GUARD,
        gb.path.display(),
        gb.sha256,
        c::GUARD_SHA
    );
    for (k, v) in [
        ("LoadState", "loaded"),
        ("Type", "oneshot"),
        ("RemainAfterExit", "no"),
        ("TimeoutStartUSec", "15s"),
        ("Restart", "no"),
        ("MemoryMax", "268435456"),
        ("MemorySwapMax", "0"),
        ("StartLimitIntervalUSec", "0"),
        ("DropInPaths", ""),
        ("Result", "success"),
    ] {
        ensure!(m[k] == v, "211 protective manager differs: {k}");
    }
    ensure!(
        text(m, "ExecStart")?.split(" ; ignore_errors=").next() == Some(command.as_str())
            && c::hex(text(m, "InvocationID")?, 32),
        "211 guard command/invocation differs"
    );
    let firing = m["ActiveState"] == "activating" && m["SubState"] == "start";
    if firing {
        let start = text(m, "ExecMainStartTimestampMonotonic")?.parse::<u64>()?;
        ensure!(
            start > 0 && start <= now && now - start <= 15_000_000,
            "211 guard firing exceeded its bound"
        );
    } else {
        ensure!(
            m["ActiveState"] == "inactive" && m["SubState"] == "dead" && m["ExecMainStatus"] == "0",
            "211 guard is not successful or bounded in progress"
        );
    }
    Ok(firing)
}
// Select from actual PID1 events, never from receipt filenames or a synthetic clock.
fn completed(
    rows: &[Value],
    m: &Value,
    boot: &str,
    firing: bool,
    now: u64,
    wall: u64,
) -> Result<String> {
    ensure!(
        !rows.is_empty() && rows.len() <= 64,
        "211 periodic PID1 bounds"
    );
    let mut starts = BTreeMap::new();
    let mut last = None;
    let mut prior = 0;
    for r in rows {
        ensure!(
            r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["UNIT"] == c::GUARD_UNIT
                && r["_BOOT_ID"] == boot.replace('-', ""),
            "211 periodic PID1 identity"
        );
        let iid = text(r, "INVOCATION_ID")?;
        let mono = text(r, "__MONOTONIC_TIMESTAMP")?.parse::<u64>()?;
        ensure!(
            c::hex(iid, 32) && mono >= prior && mono <= now,
            "211 periodic PID1 clock/owner"
        );
        prior = mono;
        let message = text(r, "MESSAGE")?;
        ensure!(
            !message.contains("Failed")
                && !message.contains("Main process exited")
                && !message.contains("timed out"),
            "211 recent guard failure"
        );
        if message.starts_with(&format!("Starting {} -", c::GUARD_UNIT)) {
            ensure!(
                starts.insert(iid.to_owned(), mono).is_none(),
                "211 duplicate guard start"
            );
        }
        if message == format!("{}: Deactivated successfully.", c::GUARD_UNIT) {
            let realtime = text(r, "__REALTIME_TIMESTAMP")?.parse::<u64>()? / 1_000_000;
            last = Some((iid.to_owned(), mono, realtime));
        }
    }
    let (iid, finished, realtime) = last.context("211 no completed protective firing")?;
    let start = *starts
        .get(&iid)
        .context("211 latest guard completion lacks start")?;
    ensure!(
        finished > start
            && finished - start <= 15_000_000
            && realtime <= wall
            && wall - realtime <= 120,
        "211 completed guard stale or over bound"
    );
    if firing {
        let current = text(m, "InvocationID")?;
        ensure!(
            iid != current && starts.get(current).is_some_and(|start| *start > finished),
            "211 firing must follow completed proof"
        );
    } else {
        ensure!(
            m["InvocationID"] == iid,
            "211 latest completed guard differs from manager"
        );
    }
    Ok(iid)
}
fn timer_values(t: &Value, firing: bool) -> Result<()> {
    ensure!(
        t["LoadState"] == "loaded"
            && t["ActiveState"] == "active"
            && t["Unit"] == c::GUARD_UNIT
            && t["DropInPaths"] == ""
            && t["Job"] == "",
        "211 timer scope differs"
    );
    ensure!(
        (t["SubState"] == "waiting"
            && !text(t, "NextElapseUSecMonotonic")?.is_empty()
            && t["NextElapseUSecMonotonic"] != "0"
            && t["NextElapseUSecMonotonic"] != "infinity")
            || (firing && t["SubState"] == "running"),
        "211 guard timer is not armed"
    );
    Ok(())
}
fn sample(directory: &Path, iid: &str) -> Result<Value> {
    ensure!(c::hex(iid, 32), "211 sample invocation");
    let path = directory.join(format!("sample-{iid}.json"));
    let m = fs::symlink_metadata(&path)?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0,
        "211 periodic sample custody"
    );
    for parent in path.ancestors().skip(1) {
        let m = fs::symlink_metadata(parent)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "211 periodic sample ancestor"
        );
    }
    bound_json(&c::binding(&private157::file_binding(&path)?)?)
}
pub(super) fn check(h: &Value) -> Result<()> {
    let gb = c::binding(&h["guard_plan"])?;
    let gp = c::sealed(&gb)?;
    let manager = json!(singleton227_capture::properties(c::GUARD_UNIT, FIELDS)?);
    let mut ts = std::mem::MaybeUninit::<libc::timespec>::uninit();
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, ts.as_mut_ptr()) } == 0,
        "211 monotonic clock"
    );
    let ts = unsafe { ts.assume_init() };
    let mono = u64::try_from(ts.tv_sec)?
        .checked_mul(1_000_000)
        .and_then(|n| n.checked_add(u64::try_from(ts.tv_nsec).ok()? / 1000))
        .context("211 monotonic overflow")?;
    let firing = manager_values(&manager, &gb, mono)?;
    let wall = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let out = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            "--all",
            "--no-pager",
            "--output=json",
            "--boot=0",
            "--lines=64",
            &format!("--since=@{}", wall.saturating_sub(120)),
            "_PID=1",
            &format!("UNIT={}", c::GUARD_UNIT),
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 1 << 20,
        "211 periodic PID1 journal unavailable"
    );
    let rows = serde_json::Deserializer::from_slice(&out.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let gid = completed(&rows, &manager, boot.trim(), firing, mono, wall)?;
    let directory = Path::new(text(&gp, "receipt_directory")?);
    ensure!(
        directory.starts_with("/var/lib/jetstreamer") && directory.canonicalize()? == directory,
        "211 periodic receipt namespace"
    );
    let validate = |g: &Value| {
        super::native211_guard::sample_valid(
            &gp,
            g,
            &h["guard_plan"],
            text(h, "invocation_id")?,
            num(h, "main_pid")?.try_into()?,
            wall,
            120,
        )
    };
    let last = sample(directory, &gid)?;
    ensure!(
        last["guard_invocation_id"] == gid,
        "211 completed sample owner differs"
    );
    validate(&last)?;
    if firing {
        let current = text(&manager, "InvocationID")?;
        let path = directory.join(format!("sample-{current}.json"));
        match fs::symlink_metadata(path) {
            Ok(_) => {
                let g = sample(directory, current)?;
                ensure!(
                    g["guard_invocation_id"] == current,
                    "211 firing sample owner differs"
                );
                validate(&g)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    for name in ["stop-intent.json", "stop-completion.json"] {
        match fs::symlink_metadata(directory.join(name)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            _ => bail!("211 protective stop receipt exists or is inaccessible"),
        }
    }
    let timer = json!(singleton227_capture::properties(
        TIMER,
        "LoadState,ActiveState,SubState,Unit,DropInPaths,Job,NextElapseUSecMonotonic"
    )?);
    timer_values(&timer, firing)?;
    ensure!(
        json!(singleton227_capture::properties(c::GUARD_UNIT, FIELDS)?) == manager,
        "211 guard transitioned during capture"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn periodic_firing_uses_latest_completed_proof_and_rejects_failure_or_staleness() {
        let gb = BoundFile {
            path: "/var/lib/jetstreamer/guard/plan.json".into(),
            sha256: "a".repeat(64),
        };
        let gid = "b".repeat(32);
        let next = "c".repeat(32);
        let mut manager = json!({"LoadState":"loaded","Type":"oneshot","RemainAfterExit":"no","TimeoutStartUSec":"15s","Restart":"no","MemoryMax":"268435456","MemorySwapMax":"0","StartLimitIntervalUSec":"0","DropInPaths":"","Result":"success","ExecStart":format!("{{ path={} ; argv[]={0} {} --plan-sha256 {} --self-sha256 {} ; ignore_errors=no }}",c::GUARD,gb.path.display(),gb.sha256,c::GUARD_SHA),"ActiveState":"inactive","SubState":"dead","ExecMainStatus":"0","InvocationID":gid,"ExecMainStartTimestampMonotonic":"100"});
        let row = |iid: &str, message: String, mono: u64| json!({"_PID":"1","_UID":"0","_BOOT_ID":"boot","UNIT":c::GUARD_UNIT,"INVOCATION_ID":iid,"MESSAGE":message,"__MONOTONIC_TIMESTAMP":mono.to_string(),"__REALTIME_TIMESTAMP":"100000000"});
        let mut rows = vec![
            row(&gid, format!("Starting {} - guard", c::GUARD_UNIT), 100),
            row(
                &gid,
                format!("{}: Deactivated successfully.", c::GUARD_UNIT),
                200,
            ),
        ];
        // The bounded journal may cut off an older invocation's start. Only
        // the selected most recent completed firing must have its full pair.
        rows.insert(
            0,
            row(
                &"d".repeat(32),
                format!("{}: Deactivated successfully.", c::GUARD_UNIT),
                50,
            ),
        );
        assert!(!manager_values(&manager, &gb, 1000).unwrap());
        assert_eq!(
            completed(&rows, &manager, "boot", false, 1000, 101).unwrap(),
            gid
        );
        manager["ActiveState"] = json!("activating");
        manager["SubState"] = json!("start");
        manager["InvocationID"] = json!(next);
        manager["ExecMainStartTimestampMonotonic"] = json!("900");
        rows.push(row(
            &next,
            format!("Starting {} - guard", c::GUARD_UNIT),
            900,
        ));
        assert!(manager_values(&manager, &gb, 1000).unwrap());
        assert_eq!(
            completed(&rows, &manager, "boot", true, 1000, 101).unwrap(),
            gid
        );
        assert!(completed(&rows, &manager, "old-boot", true, 1000, 101).is_err());
        assert!(completed(&rows, &manager, "boot", true, 1000, 221).is_err());
        assert!(manager_values(&manager, &gb, 15_001_000).is_err());
        rows[2]["MESSAGE"] = json!("Failed guard");
        assert!(completed(&rows, &manager, "boot", true, 1000, 101).is_err());
        let timer = json!({"LoadState":"loaded","ActiveState":"active","SubState":"running","Unit":c::GUARD_UNIT,"DropInPaths":"","Job":"","NextElapseUSecMonotonic":"infinity"});
        timer_values(&timer, true).unwrap();
        assert!(timer_values(&timer, false).is_err());
    }
}
