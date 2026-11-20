//! Closed harness plus at most one exact direct worker; no name-based admission.
use super::native265 as c;
use super::*;
pub(super) fn stat(pid: u64) -> Result<(u64, u64)> {
    let s = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let (head, tail) = s.rsplit_once(')').context("265 stat framing")?;
    ensure!(
        head.split_whitespace().next() == Some(pid.to_string().as_str()),
        "265 stat PID"
    );
    let fields: Vec<_> = tail.split_whitespace().collect();
    ensure!(fields.len() >= 20, "265 short stat");
    Ok((fields[1].parse()?, fields[19].parse()?))
}
#[cfg(test)]
pub(super) fn sample(v: &Value, gp: &Value, main: u64) -> Result<()> {
    sample_for(v, gp, main, c::TEST, c::TEST_SHA, &c::WORKER_PROFILE)
}
pub(super) fn sample_for(
    v: &Value,
    gp: &Value,
    main: u64,
    harness: &str,
    harness_sha: &str,
    worker: &c::WorkerProfile,
) -> Result<()> {
    ensure!(
        v["stable_census"] == true && v["boot_id"] == gp["boot_id"],
        "265 unstable process sample"
    );
    let pins = v["processes"].as_array().context("265 pins")?;
    ensure!(
        (1..=2).contains(&pins.len()) && (pins.len() == 1 || v["token_present"] == true),
        "265 child before token/count"
    );
    let mut ids = BTreeSet::new();
    for p in pins {
        let pid = c::num(p, "pid")?;
        let is_main = pid == main;
        ensure!(
            pid > 1
                && ids.insert(pid)
                && p["boot_id"] == gp["boot_id"]
                && p["executable"] == if is_main { harness } else { worker.path }
                && p["sha256"] == if is_main { harness_sha } else { worker.sha256 }
                && p["parent_pid"] == if is_main { 1 } else { main }
                && c::num(p, "start_ticks")? >= c::num(gp, "main_start_ticks")?
                && (!is_main || p["start_ticks"] == gp["main_start_ticks"])
                && p["uid"] == 0
                && p["nlink"] == 1
                && c::num(p, "mode")? & 0o222 == 0,
            "265 process pin differs"
        );
    }
    ensure!(ids.contains(&main), "265 missing main pin");
    let workers = v["workers"].as_array().context("265 worker VMAs")?;
    let mut measured = BTreeSet::new();
    for w in workers {
        let pid = w[0].as_u64().context("265 worker PID")?;
        ensure!(
            measured.insert(pid) && w[1].as_u64().is_some_and(|n| n > 0 && n < 3_500_000),
            "265 worker VMA census"
        );
    }
    ensure!(measured == ids, "265 pin/VMA membership differs");
    Ok(())
}
pub(super) fn live(members: &[String], main: u64, guard: &Value) -> Result<()> {
    live_for(
        members,
        main,
        guard,
        c::UNIT,
        c::TEST,
        c::TEST_SHA,
        &c::WORKER_PROFILE,
    )
}
pub(super) fn live_for(
    members: &[String],
    main: u64,
    guard: &Value,
    unit: &str,
    harness: &str,
    harness_sha: &str,
    worker: &c::WorkerProfile,
) -> Result<()> {
    let gb = c::binding(guard)?;
    let gp = c::sealed(&gb)?;
    let initial = stat(main)?;
    ensure!(
        initial == (1, c::num(&gp, "main_start_ticks")?),
        "265 main parent/start changed"
    );
    let mut seen = BTreeSet::new();
    for id in members {
        let pid = id.parse::<u64>()?;
        ensure!(pid > 1 && seen.insert(pid), "265 duplicate PID");
        let before = stat(pid)?;
        let exe = if pid == main { harness } else { worker.path };
        let sha = if pid == main {
            harness_sha
        } else {
            worker.sha256
        };
        ensure!(
            before.0 == if pid == main { 1 } else { main } && before.1 >= initial.1,
            "265 foreign process parent/start"
        );
        let path = PathBuf::from(format!("/proc/{pid}/exe"));
        let disk = fs::symlink_metadata(exe)?;
        let mapped = fs::metadata(&path)?;
        ensure!(
            Path::new(exe).canonicalize()? == Path::new(exe)
                && disk.is_file()
                && disk.uid() == 0
                && disk.nlink() == 1
                && disk.mode() & 0o222 == 0
                && disk.len() <= 64 << 20
                && fs::read_link(&path)? == Path::new(exe)
                && disk.dev() == mapped.dev()
                && disk.ino() == mapped.ino()
                && hex_lower(&Sha256::digest(fs::read(&path)?)) == sha
                && fs::read_to_string(format!("/proc/{pid}/cgroup"))?.trim()
                    == format!("0::/system.slice/{unit}")
                && stat(pid)? == before,
            "265 mapped process differs"
        );
    }
    let after = fs::read_to_string(format!("/sys/fs/cgroup/system.slice/{unit}/cgroup.procs"))?
        .split_whitespace()
        .map(str::parse)
        .collect::<std::result::Result<BTreeSet<u64>, _>>()?;
    ensure!(
        after == seen && seen.contains(&main) && (1..=2).contains(&seen.len()),
        "265 process census raced"
    );
    Ok(())
}
pub(super) fn drained(main: u64, worker: u64) -> Result<()> {
    drained_for(c::UNIT, &[main, worker])
}
pub(super) fn drained_for(unit: &str, pids: &[u64]) -> Result<()> {
    for &pid in pids {
        ensure!(pid > 1, "265 terminal PID");
        match fs::symlink_metadata(format!("/proc/{pid}")) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
            Ok(_) => bail!("265 original process still present or PID reused"),
        }
    }
    let group = PathBuf::from(format!("/sys/fs/cgroup/system.slice/{unit}"));
    match fs::symlink_metadata(&group) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(m) => {
            ensure!(
                m.is_dir() && group.canonicalize()? == group,
                "265 terminal cgroup path"
            );
            for entry in fs::read_dir(&group)? {
                ensure!(!entry?.file_type()?.is_dir(), "265 nested terminal cgroup");
            }
            for leaf in ["cgroup.procs", "cgroup.threads"] {
                ensure!(
                    fs::read_to_string(group.join(leaf))?.trim().is_empty(),
                    "265 terminal group populated"
                );
            }
            ensure!(
                fs::read_to_string(group.join("cgroup.events"))?
                    .lines()
                    .any(|l| l == "populated 0"),
                "265 descendants populated"
            );
            Ok(())
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sample_binds_child_to_exact_image_parent_start_and_token() {
        let gp = json!({"boot_id":"boot","main_start_ticks":5});
        let pin = |pid, parent, exe, sha| json!({"pid":pid,"parent_pid":parent,"start_ticks":5,"boot_id":"boot","executable":exe,"sha256":sha,"uid":0,"nlink":1,"mode":0o100555});
        let mut v = json!({"stable_census":true,"boot_id":"boot","token_present":true,"processes":[pin(42,1,c::TEST,c::TEST_SHA),pin(43,42,c::WORKER,c::WORKER_SHA)],"workers":[[42,10],[43,20]]});
        sample(&v, &gp, 42).unwrap();
        for (pointer, bad) in [
            ("/token_present", json!(false)),
            ("/processes/1/parent_pid", json!(1)),
            ("/processes/1/sha256", json!(c::TEST_SHA)),
            ("/processes/1/start_ticks", json!(4)),
            ("/processes/1/pid", json!(42)),
            ("/workers/1/0", json!(44)),
        ] {
            let mut changed = v.clone();
            *changed.pointer_mut(pointer).unwrap() = bad;
            assert!(sample(&changed, &gp, 42).is_err(), "{pointer}");
        }
        v["processes"].as_array_mut().unwrap().pop();
        v["workers"].as_array_mut().unwrap().pop();
        v["token_present"] = json!(false);
        sample(&v, &gp, 42).unwrap();
    }
}
