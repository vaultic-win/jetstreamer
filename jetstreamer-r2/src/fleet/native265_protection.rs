//! A periodic oneshot may be firing while its last successful proof remains fresh.
use super::native265::{self as c, num, text};
use super::*;
pub(super) const MAX_FIRING_MICROS: u64 = 60_000_000;
const TIMER: &str = "horizon-native265-protective-v1.timer";
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
        ("TimeoutStartUSec", "1min"),
        ("Restart", "no"),
        ("MemoryMax", "268435456"),
        ("MemorySwapMax", "0"),
        ("StartLimitIntervalUSec", "0"),
        ("DropInPaths", ""),
        ("Result", "success"),
    ] {
        ensure!(m[k] == v, "265 protective manager differs: {k}");
    }
    ensure!(
        text(m, "ExecStart")?.split(" ; ignore_errors=").next() == Some(command.as_str())
            && c::hex(text(m, "InvocationID")?, 32),
        "265 guard command/invocation differs"
    );
    let firing = m["ActiveState"] == "activating" && m["SubState"] == "start";
    if firing {
        let start = text(m, "ExecMainStartTimestampMonotonic")?.parse::<u64>()?;
        ensure!(
            start > 0 && start <= now && now - start <= MAX_FIRING_MICROS,
            "265 guard firing exceeded its bound"
        );
    } else {
        ensure!(
            m["ActiveState"] == "inactive" && m["SubState"] == "dead" && m["ExecMainStatus"] == "0",
            "265 guard is not successful or bounded in progress"
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
    completed_for(rows, m, boot, firing, now, wall, c::GUARD_UNIT)
}
pub(super) fn completed_for(
    rows: &[Value],
    m: &Value,
    boot: &str,
    firing: bool,
    now: u64,
    wall: u64,
    unit: &str,
) -> Result<String> {
    ensure!(
        !rows.is_empty() && rows.len() <= 64,
        "265 periodic PID1 bounds"
    );
    let mut starts = BTreeMap::new();
    let mut last = None;
    let mut prior = 0;
    for r in rows {
        ensure!(
            r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["UNIT"] == unit
                && r["_BOOT_ID"] == boot.replace('-', ""),
            "265 periodic PID1 identity"
        );
        let iid = text(r, "INVOCATION_ID")?;
        let mono = text(r, "__MONOTONIC_TIMESTAMP")?.parse::<u64>()?;
        ensure!(
            c::hex(iid, 32) && mono >= prior && mono <= now,
            "265 periodic PID1 clock/owner"
        );
        prior = mono;
        let message = text(r, "MESSAGE")?;
        ensure!(
            !message.contains("Failed")
                && !message.contains("Main process exited")
                && !message.contains("timed out"),
            "265 recent guard failure"
        );
        if message.starts_with(&format!("Starting {} -", unit)) {
            ensure!(
                starts.insert(iid.to_owned(), mono).is_none(),
                "265 duplicate guard start"
            );
        }
        if message == format!("{}: Deactivated successfully.", unit) {
            let realtime = text(r, "__REALTIME_TIMESTAMP")?.parse::<u64>()? / 1_000_000;
            last = Some((iid.to_owned(), mono, realtime));
        }
    }
    let (iid, finished, realtime) = last.context("265 no completed protective firing")?;
    let start = *starts
        .get(&iid)
        .context("265 latest guard completion lacks start")?;
    ensure!(
        finished > start
            && finished - start <= MAX_FIRING_MICROS
            && realtime <= wall
            && wall - realtime <= 120,
        "265 completed guard stale or over bound"
    );
    if firing {
        let current = text(m, "InvocationID")?;
        ensure!(
            iid != current && starts.get(current).is_some_and(|start| *start > finished),
            "265 firing must follow completed proof"
        );
    } else {
        ensure!(
            m["InvocationID"] == iid,
            "265 latest completed guard differs from manager"
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
        "265 timer scope differs"
    );
    ensure!(
        (t["SubState"] == "waiting"
            && !text(t, "NextElapseUSecMonotonic")?.is_empty()
            && t["NextElapseUSecMonotonic"] != "0"
            && t["NextElapseUSecMonotonic"] != "infinity")
            || (firing && t["SubState"] == "running"),
        "265 guard timer is not armed"
    );
    Ok(())
}
fn sample(directory: &Path, iid: &str) -> Result<Value> {
    ensure!(c::hex(iid, 32), "265 sample invocation");
    let path = directory.join(format!("sample-{iid}.json"));
    let m = fs::symlink_metadata(&path)?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0,
        "265 periodic sample custody"
    );
    for parent in path.ancestors().skip(1) {
        let m = fs::symlink_metadata(parent)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "265 periodic sample ancestor"
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
        "265 monotonic clock"
    );
    let ts = unsafe { ts.assume_init() };
    let mono = u64::try_from(ts.tv_sec)?
        .checked_mul(1_000_000)
        .and_then(|n| n.checked_add(u64::try_from(ts.tv_nsec).ok()? / 1000))
        .context("265 monotonic overflow")?;
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
        "265 periodic PID1 journal unavailable"
    );
    let rows = serde_json::Deserializer::from_slice(&out.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let gid = completed(&rows, &manager, boot.trim(), firing, mono, wall)?;
    let directory = Path::new(text(&gp, "receipt_directory")?);
    ensure!(
        directory.starts_with("/var/lib/jetstreamer") && directory.canonicalize()? == directory,
        "265 periodic receipt namespace"
    );
    let validate = |g: &Value| {
        super::native265_guard::sample_valid(
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
        "265 completed sample owner differs"
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
                    "265 firing sample owner differs"
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
            _ => bail!("265 protective stop receipt exists or is inaccessible"),
        }
    }
    let timer = json!(singleton227_capture::properties(
        TIMER,
        "LoadState,ActiveState,SubState,Unit,DropInPaths,Job,NextElapseUSecMonotonic"
    )?);
    timer_values(&timer, firing)?;
    ensure!(
        json!(singleton227_capture::properties(c::GUARD_UNIT, FIELDS)?) == manager,
        "265 guard transitioned during capture"
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
        let mut manager = json!({"LoadState":"loaded","Type":"oneshot","RemainAfterExit":"no","TimeoutStartUSec":"1min","Restart":"no","MemoryMax":"268435456","MemorySwapMax":"0","StartLimitIntervalUSec":"0","DropInPaths":"","Result":"success","ExecStart":format!("{{ path={} ; argv[]={0} {} --plan-sha256 {} --self-sha256 {} ; ignore_errors=no }}",c::GUARD,gb.path.display(),gb.sha256,c::GUARD_SHA),"ActiveState":"inactive","SubState":"dead","ExecMainStatus":"0","InvocationID":gid,"ExecMainStartTimestampMonotonic":"100"});
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
        assert!(manager_values(&manager, &gb, 60_001_000).is_err());
        rows[2]["MESSAGE"] = json!("Failed guard");
        assert!(completed(&rows, &manager, "boot", true, 1000, 101).is_err());
        let timer = json!({"LoadState":"loaded","ActiveState":"active","SubState":"running","Unit":c::GUARD_UNIT,"DropInPaths":"","Job":"","NextElapseUSecMonotonic":"infinity"});
        timer_values(&timer, true).unwrap();
        assert!(timer_values(&timer, false).is_err());
    }
    fn retained_manager() -> (BoundFile, Value) {
        let gb=BoundFile { path:"/var/lib/jetstreamer/horizon-native265-guard-binding-native-20261119-v1/guard-plan.json".into(), sha256:"d6aa8d26f07c17ce85705f4cb4cd554b4a64d56fcb3fd02726a87fe7b04983ea".into() };
        // Derived manager fixture, NOT a captured PID1 manager snapshot. The
        // retained service declares TimeoutStartSec=60; PID1 renders it as 1min.
        let m = json!({"LoadState":"loaded","Type":"oneshot","RemainAfterExit":"no","TimeoutStartUSec":"1min","Restart":"no","MemoryMax":"268435456","MemorySwapMax":"0","StartLimitIntervalUSec":"0","DropInPaths":"","Result":"success","ExecStart":format!("{{ path={} ; argv[]={0} {} --plan-sha256 {} --self-sha256 {} ; ignore_errors=no }}",c::GUARD,gb.path.display(),gb.sha256,c::GUARD_SHA),"ActiveState":"inactive","SubState":"dead","ExecMainStatus":"0","InvocationID":"50fa014e70b54592a43a35606621b1eb","ExecMainStartTimestampMonotonic":"263167558159"});
        (gb, m)
    }
    #[test]
    fn retained_first_fire_accepts_actual_sixty_second_contract() {
        let rows: Vec<Value> =
            serde_json::from_str(include_str!("fixtures/native265-first-fire-20261119.json"))
                .unwrap();
        let (gb, m) = retained_manager();
        assert!(!manager_values(&m, &gb, 263168374797).unwrap());
        assert_eq!(
            completed(
                &rows,
                &m,
                "3b17d005-5c3a-4a0e-8841-da097e0957b5",
                false,
                263168374797,
                1795118095
            )
            .unwrap(),
            "50fa014e70b54592a43a35606621b1eb"
        );
        for timeout in ["15s", "infinity", "0", "2min"] {
            let mut bad = m.clone();
            bad["TimeoutStartUSec"] = json!(timeout);
            assert!(
                manager_values(&bad, &gb, 263168374797).is_err(),
                "{timeout}"
            );
        }
    }
    #[test]
    fn actual_sixty_second_boundary_applies_to_firing_and_completed_proof() {
        let (gb, mut m) = retained_manager();
        m["ActiveState"] = json!("activating");
        m["SubState"] = json!("start");
        let start = 263167558159;
        assert!(manager_values(&m, &gb, start + MAX_FIRING_MICROS).unwrap());
        assert!(manager_values(&m, &gb, start + MAX_FIRING_MICROS + 1).is_err());
        m["ActiveState"] = json!("inactive");
        m["SubState"] = json!("dead");
        let mut rows: Vec<Value> =
            serde_json::from_str(include_str!("fixtures/native265-first-fire-20261119.json"))
                .unwrap();
        rows.truncate(2);
        rows[1]["__MONOTONIC_TIMESTAMP"] = json!((start + MAX_FIRING_MICROS).to_string());
        rows[1]["__REALTIME_TIMESTAMP"] = json!("1795118154435640");
        assert!(
            completed(
                &rows,
                &m,
                "3b17d005-5c3a-4a0e-8841-da097e0957b5",
                false,
                start + MAX_FIRING_MICROS + 1,
                1795118155
            )
            .is_ok()
        );
        rows[1]["__MONOTONIC_TIMESTAMP"] = json!((start + MAX_FIRING_MICROS + 1).to_string());
        assert!(
            completed(
                &rows,
                &m,
                "3b17d005-5c3a-4a0e-8841-da097e0957b5",
                false,
                start + MAX_FIRING_MICROS + 1,
                1795118155
            )
            .is_err()
        );
    }
}
