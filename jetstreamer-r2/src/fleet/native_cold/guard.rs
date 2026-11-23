// Validate the epoch-specific guard argument, kernel samples, and PID1 clock.
use super::current as c;
use super::*;
use crate::fleet::native265::{EvidenceReader, FsEvidence, binding, hex, num, sealed, text};
pub(in crate::fleet) fn directory(h: &Value, gp: &Value) -> Result<PathBuf> {
    let iid = text(h, "invocation_id")?;
    ensure!(hex(iid, 32), "native bootstrap invocation");
    let dir = PathBuf::from(format!(
        "/var/lib/jetstreamer/horizon-native{EPOCH}-guard-receipts-{iid}"
    ));
    let alias = Path::new(text(h, "receipt_mount")?);
    let m = fs::symlink_metadata(&dir)?;
    ensure!(
        Path::new(text(gp, "receipt_directory")?) == dir
            && dir.canonicalize()? == dir
            && m.is_dir()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o7777 == 0o700
            && fs::symlink_metadata(alias)?.uid() == 0
            && fs::read_link(alias)? == dir,
        "native bootstrap changed receipt directory"
    );
    Ok(dir)
}
pub(in crate::fleet) fn record(path: &Path) -> Result<Value> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o077 == 0,
        "native bootstrap guard record custody"
    );
    Ok(serde_json::from_slice(&read_stable_bounded(
        path,
        2 << 20,
        "native bootstrap guard record",
    )?)?)
}
pub(super) fn identity(handoff: &Value) -> Result<(&'static str, &'static str)> {
    if EPOCH == 257 {
        horizon_singleton211_launch::native257::saved_guard(handoff)
    } else {
        Ok((c::GUARD, c::GUARD_SHA))
    }
}
pub(in crate::fleet) fn sample(
    h: &Value,
    gp: &Value,
    g: &Value,
    wall: u64,
    age: u64,
) -> Result<()> {
    native265_guard::sample_for(
        gp,
        g,
        &h["guard_plan"],
        text(h, "invocation_id")?,
        num(h, "main_pid")?.try_into()?,
        wall,
        age,
        &native265_guard::SampleProfile {
            guard_sha: identity(h)?.1,
            ..c::PROFILE
        },
    )?;
    let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?;
    ensure!(page.is_power_of_two(), "native bootstrap kernel page size");
    let m = &g["memory_observation"];
    ensure!(
        m["maximum_bytes"] == c::PROFILE.memory / page * page
            && m["high_bytes"] == 100_000_000_000u64 / page * page
            && num(m, "tasks")? > 0
            && g["scratch_deleted"] == false,
        "native bootstrap kernel sample limits"
    );
    Ok(())
}
pub(in crate::fleet) fn journal(args: &[String]) -> Result<Vec<Value>> {
    let output = ProcessCommand::new("/usr/bin/journalctl")
        .args(["--all", "--no-pager", "--output=json", "--boot=0"])
        .args(args)
        .output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 16 << 20,
        "native bootstrap journal inaccessible or oversized"
    );
    Ok(serde_json::Deserializer::from_slice(&output.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?)
}
pub(in crate::fleet) fn live(h: &Value) -> Result<()> {
    let gb = binding(&h["guard_plan"])?;
    let gp = sealed(&gb)?;
    let dir = directory(h, &gp)?;
    let fields = "Id,LoadState,ActiveState,SubState,InvocationID,Result,ExecMainStatus,ExecStart,DropInPaths,Restart,MemoryMax,MemorySwapMax,StartLimitIntervalUSec,Type,RemainAfterExit,TimeoutStartUSec,ExecMainStartTimestampMonotonic,EnvironmentFiles,PassEnvironment,UnsetEnvironment,ReadWritePaths,Environment,User,TasksMax";
    let manager = c::props(c::GUARD_UNIT, fields)?;
    for (k, v) in [
        ("Id", c::GUARD_UNIT),
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
        ("PassEnvironment", ""),
        ("UnsetEnvironment", ""),
        ("Environment", ""),
        ("User", "root"),
        ("TasksMax", "64"),
    ] {
        ensure!(manager[k] == v, "native bootstrap guard manager {k}");
    }
    let env = gb.path.with_file_name("guard.env");
    let bytes = format!("HORIZON{EPOCH}_GUARD_PLAN_SHA256={}\n", gb.sha256);
    FsEvidence.bytes(
        &BoundFile {
            path: env.clone(),
            sha256: hex_lower(&Sha256::digest(bytes.as_bytes())),
        },
        256,
    )?;
    let (guard_path, guard_sha) = identity(h)?;
    let command = format!(
        "{{ path={} ; argv[]={0} {} --plan-sha256 ${{HORIZON{EPOCH}_GUARD_PLAN_SHA256}} --self-sha256 {}",
        guard_path,
        gb.path.display(),
        guard_sha
    );
    ensure!(
        text(&manager, "ExecStart")?
            .split(" ; ignore_errors=")
            .next()
            == Some(command.as_str())
            && manager["EnvironmentFiles"] == format!("{} (ignore_errors=no)", env.display())
            && manager["ReadWritePaths"] == h["receipt_mount"],
        "native bootstrap guard arguments changed"
    );
    let firing = manager["ActiveState"] == "activating" && manager["SubState"] == "start";
    let mut ts = std::mem::MaybeUninit::<libc::timespec>::uninit();
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, ts.as_mut_ptr()) } == 0,
        "monotonic clock"
    );
    let ts = unsafe { ts.assume_init() };
    let mono = u64::try_from(ts.tv_sec)? * 1_000_000 + u64::try_from(ts.tv_nsec)? / 1000;
    if firing {
        let start = text(&manager, "ExecMainStartTimestampMonotonic")?.parse::<u64>()?;
        ensure!(
            start > 0 && start <= mono && mono - start <= native265_protection::MAX_FIRING_MICROS,
            "native bootstrap guard firing overdue"
        );
    } else {
        ensure!(
            manager["ActiveState"] == "inactive"
                && manager["SubState"] == "dead"
                && manager["ExecMainStatus"] == "0",
            "native bootstrap guard failed"
        );
    }
    let wall = c::now()?;
    let rows = journal(&[
        "--lines=64".into(),
        format!("--since=@{}", wall.saturating_sub(120)),
        "_PID=1".into(),
        format!("UNIT={}", c::GUARD_UNIT),
    ])?;
    let last = native265_protection::completed_for(
        &rows,
        &manager,
        text(&gp, "boot_id")?,
        firing,
        mono,
        wall,
        c::GUARD_UNIT,
    )?;
    let first = sealed(&binding(&h["first_guard_sample"])?)?;
    let check = |id: &str| -> Result<()> {
        ensure!(hex(id, 32), "native bootstrap guard iid");
        let value = record(&dir.join(format!("sample-{id}.json")))?;
        ensure!(
            value["guard_invocation_id"] == id,
            "native bootstrap guard substitution"
        );
        c::sample_mount(&first, &value)?;
        sample(h, &gp, &value, wall, 120)
    };
    check(&last)?;
    if firing {
        let id = text(&manager, "InvocationID")?;
        if dir.join(format!("sample-{id}.json")).try_exists()? {
            check(id)?;
        }
    }
    for entry in fs::read_dir(&dir)? {
        let name = entry?.file_name();
        let name = name.to_str().context("native bootstrap guard filename")?;
        ensure!(
            !name.starts_with("stop-")
                && !name.starts_with("transition-")
                && !name.starts_with("terminal-"),
            "native bootstrap guard reports terminal/trip"
        );
    }
    let t = c::props(
        c::TIMER,
        "Id,LoadState,ActiveState,SubState,Unit,DropInPaths,Job,NextElapseUSecMonotonic",
    )?;
    ensure!(
        t["Id"] == c::TIMER
            && t["ActiveState"] == "active"
            && t["LoadState"] == "loaded"
            && t["Unit"] == c::GUARD_UNIT
            && t["DropInPaths"] == ""
            && t["Job"] == ""
            && ((t["SubState"] == "waiting"
                && !matches!(text(&t, "NextElapseUSecMonotonic")?, "" | "0" | "infinity"))
                || (firing && t["SubState"] == "running"))
            && c::props(c::GUARD_UNIT, fields)? == manager,
        "native bootstrap protective timer/owner changed"
    );
    Ok(())
}
