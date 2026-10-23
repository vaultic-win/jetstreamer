//! Persistent191–194 owner. Admissions are supplied after actual resource
//! observations; a queued slot never contains an invented child or future hash.
use super::*;
use crate::cohort191_delivery::{self as custody, Bound};
use serde_json::json;
use std::{
    collections::BTreeSet,
    os::fd::AsRawFd,
    process::{Command as Process, Stdio},
    time::Instant,
};
const UNIT: &str = "horizon-cohort191-delivery-queue-20261023-v1.service";
const ROOT: &str = "/var/lib/jetstreamer/horizon-cohort191-delivery-queue-20261023-v1";
const PROGRAM: &str =
    "/usr/local/lib/jetstreamer/horizon-cohort191-delivery-tools-20261023-v1/jetstreamer-r2";
const RECEIPTS: &str = "/home/sol/.jetstreamer-private/r2-receipts";
// Confirmed fixed deployment contract; never accept an admission-supplied envfile.
const ENVFILE: &str = "/etc/jetstreamer/horizon-r2.env";
const DISPATCH_ROOT: &str =
    "/var/lib/jetstreamer/horizon-cohort191-verification-dispatch-20261023-v1";
fn now_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .with_context(|| format!("191 queue missing {key}"))
}
fn number(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .with_context(|| format!("191 queue missing {key}"))
}
fn binding(v: &Value) -> Result<Bound> {
    Ok(serde_json::from_value(v.clone())?)
}
fn root_dir(p: &Path) -> Result<()> {
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.canonicalize()? == p && m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "191 queue directory is not canonical root-private storage"
    );
    Ok(())
}
fn bound_path(p: &Path, maximum: u64, uid: u32) -> Result<Bound> {
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.canonicalize()? == p
            && m.is_file()
            && m.uid() == uid
            && m.nlink() == 1
            && m.mode() & 0o022 == 0,
        "unsafe191 queue receipt/admission"
    );
    let bytes = read_stable_bounded(p, maximum, "191 queue bound")?;
    Ok(Bound {
        path: p.into(),
        sha256: hex_lower(&Sha256::digest(bytes)),
    })
}
fn admission_file(path: &Path) -> Result<Bound> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.uid() == 0 && m.mode() & 0o077 == 0,
        "191 task admission is not root-only"
    );
    bound_path(path, 1 << 20, 0)
}
fn executable(b: &Bound) -> Result<()> {
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        b.path.canonicalize()? == b.path
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && m.mode() & 0o111 != 0,
        "unsealed191 queue executable"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&b.path)?;
    ensure!(m.len() <= 512 << 20, "191 executable exceeds bound");
    let before = identity(&f.metadata()?);
    let mut hash = Sha256::new();
    std::io::copy(&mut f, &mut hash)?;
    ensure!(
        hex_lower(&hash.finalize()) == b.sha256
            && before == identity(&f.metadata()?)
            && regular_identity(&b.path)? == before,
        "191 executable changed"
    );
    Ok(())
}
fn ticks(pid: u64) -> Result<u64> {
    let s = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    Ok(s.rsplit_once(") ")
        .context("191 stat framing")?
        .1
        .split_whitespace()
        .nth(19)
        .context("191 stat start")?
        .parse()?)
}
fn process(owner: &Value) -> Result<()> {
    let pid = number(owner, "pid")?;
    let start = number(owner, "start_ticks")?;
    let b = binding(&owner["program"])?;
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.mode() & 0o222 == 0,
        "191 task executable lost immutable custody"
    );
    let actual = fs::metadata(format!("/proc/{pid}/exe"))?;
    ensure!(
        actual.ino() == m.ino() && actual.dev() == m.dev(),
        "191 process executable inode differs"
    );
    ensure!(
        pid > 0
            && ticks(pid)? == start
            && fs::symlink_metadata(format!("/proc/{pid}"))?.uid() == 0
            && fs::read_link(format!("/proc/{pid}/exe"))? == b.path,
        "191 task identity changed"
    );
    ensure!(
        fs::read_to_string(format!("/proc/{pid}/cgroup"))?
            .lines()
            .any(|s| s == format!("0::/system.slice/{}", text(owner, "unit").unwrap_or(""))),
        "191 task cgroup differs"
    );
    Ok(())
}
// All clients are short and bounded. A timeout kills this client only; its
// durable launch intent forbids automatic redispatch/retry of the native task.
fn command(program: &str, args: &[String], seconds: u64) -> Result<Vec<u8>> {
    use std::io::{Seek, SeekFrom};
    let mut out = tempfile::tempfile()?;
    let mut err = tempfile::tempfile()?;
    let mut child = Process::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(out.try_clone()?)
        .stderr(err.try_clone()?)
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let status = loop {
        if out.metadata()?.len() > 1 << 20 || err.metadata()?.len() > 1 << 20 {
            let _ = child.kill();
            let _ = child.wait();
            bail!("191 client output limit; reconcile durable intent, no retry");
        }
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("191 client timeout; preserve intent and child, no retry");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    ensure!(
        status.success(),
        "191 short client failed; preserve task and intent"
    );
    ensure!(
        out.metadata()?.len() <= 1 << 20 && err.metadata()?.len() <= 1 << 20,
        "191 client output limit"
    );
    out.seek(SeekFrom::Start(0))?;
    err.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    out.read_to_end(&mut bytes)?;
    Ok(bytes)
}
fn manager(unit: &str) -> Result<Value> {
    ensure!(
        unit.ends_with(".service")
            && unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "191 unsafe unit"
    );
    let bytes=command("/usr/bin/systemctl",&["show".into(),unit.into(),"--property=Id,LoadState,ActiveState,SubState,Type,InvocationID,MainPID,NRestarts,Job,ExecStart,ControlGroup,Result,ExecMainStatus,PrivateNetwork,EnvironmentFiles,Restart".into()],10)?;
    let mut map = serde_json::Map::new();
    for s in std::str::from_utf8(&bytes)?.lines() {
        let (k, v) = s.split_once('=').context("191 manager property")?;
        ensure!(
            map.insert(k.into(), json!(v)).is_none(),
            "191 duplicate manager property"
        );
    }
    Ok(Value::Object(map))
}
fn nil_job(v: &Value) -> bool {
    matches!(v["Job"].as_str(), Some("" | "0" | "0 /"))
}
fn owner_matches(owner: &Value, u: &Value) -> Result<()> {
    ensure!(
        u["Id"] == owner["unit"]
            && u["InvocationID"] == owner["invocation_id"]
            && u["LoadState"] == "loaded"
            && u["NRestarts"] == "0"
            && u["Restart"] == "no"
            && nil_job(u)
            && pipeline_status::same_exec_start(
                text(owner, "expected_exec_start")?,
                text(u, "ExecStart")?
            ),
        "191 native owner changed/restarted"
    );
    Ok(())
}
fn terminal(owner: &Value, u: &Value) -> Result<bool> {
    owner_matches(owner, u)?;
    if u["MainPID"] != "0" {
        ensure!(
            u["ActiveState"] == "active"
                && u["SubState"] == "running"
                && text(u, "MainPID")?.parse::<u64>()? == number(owner, "pid")?,
            "191 child neither exact live nor terminal"
        );
        process(owner)?;
        return Ok(false);
    }
    ensure!(
        u["ControlGroup"] == ""
            && u["Result"] == "success"
            && u["ExecMainStatus"] == "0"
            && matches!(u["ActiveState"].as_str(), Some("active" | "inactive"))
            && matches!(u["SubState"].as_str(), Some("exited" | "dead")),
        "191 task failed or has unknown terminal users"
    );
    Ok(true)
}
fn admission_path(epoch: u64, stage: &str) -> PathBuf {
    Path::new(ROOT).join(format!("admissions/epoch-{epoch}-{stage}.json"))
}
fn pending_stage(row: &Value) -> Option<&'static str> {
    match row["stage"].as_str() {
        Some("queued-full") => Some("full"),
        Some("queued-plugin") => Some("plugin"),
        Some("queued-upload") => Some("sync"),
        _ => None,
    }
}
// Ascending verifier order, but a separately admitted upload can overlap the
// next epoch's verifier. Admissions are read only for the stage eligible now.
fn eligible(state: &Value) -> Vec<(usize, &'static str)> {
    let rows = state["epochs"]
        .as_array()
        .expect("internally constructed epochs");
    let verifier = rows.iter().any(|r| {
        matches!(
            r["stage"].as_str(),
            Some("full-verification" | "plugin-verification")
        )
    });
    let sync = rows.iter().any(|r| {
        matches!(
            r["stage"].as_str(),
            Some("upload" | "readback" | "source-revalidation")
        )
    });
    let mut out = Vec::new();
    if !sync {
        if let Some((i, _)) = rows
            .iter()
            .enumerate()
            .find(|(_, r)| pending_stage(r) == Some("sync"))
        {
            out.push((i, "sync"));
        }
    }
    if !verifier {
        if let Some((i, r)) = rows
            .iter()
            .enumerate()
            .find(|(_, r)| matches!(pending_stage(r), Some("full" | "plugin")))
        {
            out.push((i, pending_stage(r).unwrap()));
        }
    }
    out
}
fn persist(state: &mut Value) -> Result<()> {
    state["revision"] = json!(
        number(state, "revision")?
            .checked_add(1)
            .context("191 revision overflow")?
    );
    state["updated_unix_millis"] = json!(now_ms()?);
    let root = Path::new(ROOT);
    root_dir(root)?;
    root_dir(&root.join("history"))?;
    let history = root
        .join("history")
        .join(format!("state-{:06}.json", number(state, "revision")?));
    // Seal the new inode before its no-clobber publication; no published
    // history revision is subsequently modified or chmodded.
    let mut revision = tempfile::NamedTempFile::new_in(root.join("history"))?;
    serde_json::to_writer_pretty(revision.as_file_mut(), state)?;
    revision.as_file_mut().write_all(b"\n")?;
    use std::os::unix::fs::PermissionsExt;
    revision
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o444))?;
    revision.as_file().sync_all()?;
    revision
        .persist_noclobber(&history)
        .map_err(|e| anyhow!("191 immutable revision publication: {e}"))?;
    File::open(root.join("history"))?.sync_all()?;
    // History is durable before replacing current. A crash can leave an orphan
    // history row; next startup refuses existing state/history, never replays.
    let mut tmp = tempfile::NamedTempFile::new_in(root)?;
    serde_json::to_writer_pretty(tmp.as_file_mut(), state)?;
    tmp.as_file_mut().write_all(b"\n")?;
    tmp.as_file().sync_all()?;
    tmp.persist(root.join("state.json"))
        .map_err(|e| anyhow!("191 atomic state replacement: {e}"))?;
    File::open(root)?.sync_all()?;
    Ok(())
}
fn launched_owner(
    launch: &Value,
    admission: &Bound,
    launch_bound: &Bound,
    program: &Bound,
) -> Result<Value> {
    let u = &launch["native_owner"];
    let p = &launch["process_identity"];
    let owner = json!({"unit":u["Id"],"invocation_id":u["InvocationID"],"pid":p["pid"],"start_ticks":p["start_ticks"],"program":program,"expected_exec_start":u["ExecStart"],"admission":admission,"launch_receipt":launch_bound});
    ensure!(
        is_lower_hex(text(&owner, "invocation_id")?, 32),
        "191 child IID missing"
    );
    let current = manager(text(&owner, "unit")?)?;
    owner_matches(&owner, &current)?;
    ensure!(
        !terminal(&owner, &current)?,
        "191 child was not observed running; reconcile without retry"
    );
    Ok(owner)
}
fn dispatch(
    epoch: u64,
    stage: &str,
    a: &Value,
    ab: &Bound,
    self_sha: &str,
    queue_plan: &Bound,
    row: &Value,
) -> Result<Value> {
    let db = binding(&a["dispatch_plan"])?;
    let d = custody::bound(&db, true)?;
    let qp = custody::bound(queue_plan, true)?;
    let spec = custody::bound(&binding(&d["verifier_plan"])?, true)?;
    ensure!(
        d["source_batch"] == qp["source_batch"]
            && d["public_batch"] == qp["public_batch"]
            && spec["expected_archive_sha256"] == row["archive_sha256"],
        "191 dispatch does not bind this queue's actual imports/archive"
    );
    let out = Path::new(DISPATCH_ROOT).join(format!("epoch-{epoch}-{stage}"));
    ensure!(
        d["output_directory"] == json!(out) && d["epoch"] == epoch && d["stage"] == stage,
        "191 dispatch scope changed"
    );
    command(
        PROGRAM,
        &[
            "dispatch-verification-191".into(),
            db.path.display().to_string(),
            "--plan-sha256".into(),
            db.sha256,
            "--self-sha256".into(),
            self_sha.into(),
        ],
        120,
    )?;
    let lb = bound_path(&out.join("launch.json"), 1 << 20, 0)?;
    let l = custody::bound(&lb, false)?;
    ensure!(
        l["schema"] == "jetstreamer-cohort191-verification-dispatch-launch-v1"
            && l["epoch"] == epoch
            && l["stage"] == stage
            && l["program"] == d["program"]
            && l["verifier_plan"] == d["verifier_plan"],
        "191 dispatcher launch evidence differs"
    );
    launched_owner(&l, ab, &lb, &binding(&d["program"])?)
}
fn sync_unit(epoch: u64) -> String {
    format!("horizon-r2-sync-{epoch}-native191-20261023-v1.service")
}
fn sync_dir(epoch: u64) -> PathBuf {
    Path::new(ROOT).join(format!("sync/epoch-{epoch}"))
}
fn normal_sync_argv(epoch: u64) -> Vec<String> {
    vec![
        PROGRAM.into(),
        "sync".into(),
        "/home/sol/horizon".into(),
        "--epochs".into(),
        format!("{epoch}-{epoch}"),
        "--receipt-directory".into(),
        RECEIPTS.into(),
        "--part-size-mib".into(),
        "64".into(),
        "--concurrency".into(),
        "2".into(),
    ]
}
fn sync_args(epoch: u64, plan: &Bound, self_sha: &str) -> Vec<String> {
    vec![
        format!("--unit={}", sync_unit(epoch)),
        "--no-block".into(),
        "--property=Type=exec".into(),
        "--property=Restart=no".into(),
        "--property=RemainAfterExit=yes".into(),
        "--property=RuntimeMaxSec=172800".into(),
        "--property=UMask=0077".into(),
        "--property=KillMode=control-group".into(),
        "--property=LimitCORE=0".into(),
        "--property=LimitFSIZE=16M".into(),
        "--property=CPUQuota=200%".into(),
        "--property=MemoryHigh=1G".into(),
        "--property=MemoryMax=2G".into(),
        "--property=MemorySwapMax=0".into(),
        "--property=TasksMax=512".into(),
        "--property=ProtectSystem=strict".into(),
        "--property=ProtectHome=read-only".into(),
        "--property=PrivateTmp=yes".into(),
        "--property=NoNewPrivileges=yes".into(),
        "--property=CapabilityBoundingSet=CAP_DAC_OVERRIDE".into(),
        "--property=AmbientCapabilities=CAP_DAC_OVERRIDE".into(),
        format!("--property=EnvironmentFile={ENVFILE}"),
        "--property=Environment=TOKIO_WORKER_THREADS=2".into(),
        format!(
            "--property=ReadWritePaths={RECEIPTS} {}",
            sync_dir(epoch).display()
        ),
        PROGRAM.into(),
        "sync-verified191".into(),
        plan.path.display().to_string(),
        "--plan-sha256".into(),
        plan.sha256.clone(),
        "--self-sha256".into(),
        self_sha.into(),
    ]
}
fn resource_fields(s: &Value) -> Result<(Bound, Bound, u64)> {
    let observer = binding(&s["observer"])?;
    let completion = binding(&s["routine_completion"])?;
    ensure!(
        is_lower_hex(&observer.sha256, 64) && is_lower_hex(&completion.sha256, 64),
        "191 sync resource receipt digest malformed"
    );
    Ok((
        observer,
        completion,
        number(s, "other_pending_os_growth_bytes")?,
    ))
}
fn resource_admission(s: &Value, a: &Value) -> Result<Value> {
    for key in [
        "observer",
        "routine_completion",
        "other_pending_os_growth_bytes",
    ] {
        ensure!(
            a[key] == s[key],
            "191 sync intake/resource plan binding differs:{key}"
        );
    }
    let (observer, completion, other) = resource_fields(s)?;
    crate::cohort191_dispatch::check_resources(&observer, &completion, other)
}
fn validate_sync(s: &Value, plan: &Bound, iid: &str, row: &Value) -> Result<()> {
    resource_fields(s)?;
    let e = number(row, "epoch")?;
    ensure!(
        s["schema"] == "jetstreamer-cohort191-sync-plan-v2"
            && s["queue_plan"] == serde_json::to_value(plan)?
            && s["queue_invocation_id"] == iid
            && s["epoch"] == e
            && s["program"]["path"] == PROGRAM
            && s["archive_sha256"] == row["archive_sha256"]
            && s["archive_length"] == row["archive_length"]
            && s["full_receipt"] == row["full_receipt"]
            && s["plugin_receipt"] == row["plugin_receipt"]
            && s["output_directory"] == json!(sync_dir(e)),
        "191 sync plan lacks exact queue/import/gate bindings"
    );
    Ok(())
}
fn launch_sync(
    epoch: u64,
    a: &Value,
    ab: &Bound,
    plan: &Bound,
    iid: &str,
    row: &Value,
) -> Result<Value> {
    use std::os::unix::fs::DirBuilderExt;
    let sb = binding(&a["sync_plan"])?;
    let s = custody::bound(&sb, true)?;
    validate_sync(&s, plan, iid, row)?;
    sync_inputs(&s, plan, iid, row)?;
    let program = binding(&s["program"])?;
    executable(&program)?;
    let env = fs::symlink_metadata(ENVFILE)?;
    ensure!(
        Path::new(ENVFILE).canonicalize()? == Path::new(ENVFILE)
            && env.is_file()
            && env.uid() == 0
            && env.nlink() == 1
            && env.mode() & 0o077 == 0,
        "191 fixed R2 envfile not root private"
    );
    // Every managed sync namespace is observed, so no second uploader is
    // launched merely because the queue lacks its owner in memory.
    for e in 191..=194 {
        let u = manager(&sync_unit(e))?;
        ensure!(
            u["MainPID"] == "0" && nil_job(&u) && u["ControlGroup"] == "",
            "191 sync namespace occupied"
        );
        if e == epoch {
            ensure!(
                u["LoadState"] == "not-found",
                "191 sync unit already used; no replay"
            );
        }
    }
    let out = sync_dir(epoch);
    root_dir(out.parent().context("191 sync parent")?)?;
    fs::DirBuilder::new().mode(0o700).create(&out)?;
    File::open(out.parent().unwrap())?.sync_all()?;
    fleet::persist(
        &out.join("intent.json"),
        &json!({"schema":"jetstreamer-cohort191-sync-intent-v2","admission":ab,"sync_plan":sb,"argv":sync_args(epoch,&sb,&program.sha256),"r2_mutation_authorized_by_admission":true,"delete_local":false,"overwrite_existing":false}),
    )?;
    let resources = resource_admission(&s, a)?;
    fleet::persist(
        &out.join("prelaunch-resources.json"),
        &json!({"schema":"jetstreamer-cohort191-sync-prelaunch-resources-v1","sync_plan":sb,"admission":ab,"observer":s["observer"],"routine_completion":s["routine_completion"],"other_pending_os_growth_bytes":s["other_pending_os_growth_bytes"],"resource_admission":resources,"recorded_unix_millis":now_ms()?}),
    )?;
    command(
        "/usr/bin/systemd-run",
        &sync_args(epoch, &sb, &program.sha256),
        10,
    )?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let u = loop {
        let u = manager(&sync_unit(epoch))?;
        if u["ActiveState"] == "active" && u["SubState"] == "running" {
            break u;
        }
        ensure!(
            Instant::now() < deadline
                && matches!(u["ActiveState"].as_str(), Some("activating" | "active")),
            "191 sync not observed running; no retry"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    let lb = out.join("launch.json");
    // The native gate wrapper writes launch before its same-PID Unix exec.
    // Never reconstruct that receipt from service exit or queue assumptions.
    let receipt_deadline = Instant::now() + Duration::from_secs(10);
    while !lb.try_exists()? {
        ensure!(
            Instant::now() < receipt_deadline,
            "191 sync native launch receipt missing; no retry"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let lb = bound_path(&lb, 1 << 20, 0)?;
    let l = custody::bound(&lb, false)?;
    ensure!(
        l["schema"] == "jetstreamer-cohort191-sync-launch-v2"
            && l["epoch"] == epoch
            && l["sync_plan"] == serde_json::to_value(&sb)?
            && l["exec_argv"] == json!(normal_sync_argv(epoch))
            && l["native_owner"]["InvocationID"] == u["InvocationID"],
        "191 sync wrapper launch differs"
    );
    let owner = launched_owner(&l, ab, &lb, &program)?;
    // The wrapper can still be between fsync and exec; wait boundedly for the
    // approved same-PID argv without treating it as a second process.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if proc_argv(number(&owner, "pid")?)? == normal_sync_argv(epoch) {
            break;
        }
        ensure!(
            Instant::now() < deadline,
            "191 sync exec not observed; no retry"
        );
        process(&owner)?;
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(owner)
}
fn proc_argv(pid: u64) -> Result<Vec<String>> {
    let bytes = fs::read(format!("/proc/{pid}/cmdline"))?;
    ensure!(bytes.len() <= 65536, "191 command line bound");
    Ok(bytes
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8(s.to_vec()))
        .collect::<std::result::Result<_, _>>()?)
}
fn sync_inputs(s: &Value, plan: &Bound, iid: &str, row: &Value) -> Result<()> {
    validate_sync(s, plan, iid, row)?;
    let qp = custody::bound(plan, true)?;
    for key in ["source_batch", "public_batch", "source_revalidation_policy"] {
        ensure!(
            s[key] == qp[key],
            "191 sync changed queue import/policy binding"
        );
    }
    let epoch = number(row, "epoch")?;
    let import = custody::dispatch_import_check(
        &binding(&s["source_batch"])?,
        &binding(&s["public_batch"])?,
        &BTreeSet::from([epoch]),
    )?;
    let member = import["public_members"]
        .as_array()
        .context("191 sync native imports")?
        .iter()
        .find(|m| m["epoch"] == epoch)
        .context("191 sync native member")?;
    ensure!(
        member["archive_sha256"] == row["archive_sha256"]
            && member["committed_archive"]["length"] == row["archive_length"],
        "191 sync imported archive changed"
    );
    for stage in ["full", "plugin"] {
        custody::queue_gate(
            &binding(&s[format!("{stage}_receipt")])?,
            epoch,
            stage,
            &binding(&s["gate_tools"][stage]["wrapper"])?,
            &binding(&s["gate_tools"][stage]["verifier"])?,
            text(row, "archive_sha256")?,
        )?;
    }
    custody::bound(&binding(&s["source_revalidation_policy"])?, true)?;
    Ok(())
}
/// This root service alone receives the fixed R2 credentials/network. It
/// authenticates native import and both independently qualified receipts before
/// replacing itself with normal sync: PID/start/IID/executable remain identical.
pub(super) fn sync_verified() -> Result<()> {
    use std::os::unix::process::CommandExt;
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "191 sync gate requires root"
    );
    let a: Vec<_> = env::args().collect();
    ensure!(
        a.len() == 7
            && a[1] == "sync-verified191"
            && a[3] == "--plan-sha256"
            && a[5] == "--self-sha256"
            && is_lower_hex(&a[4], 64)
            && is_lower_hex(&a[6], 64),
        "191 sync gate usage"
    );
    let sb = Bound {
        path: a[2].clone().into(),
        sha256: a[4].clone(),
    };
    let s = custody::bound(&sb, true)?;
    let program = binding(&s["program"])?;
    executable(&program)?;
    ensure!(
        program.path == Path::new(PROGRAM)
            && program.sha256 == a[6]
            && fs::read_link("/proc/self/exe")? == program.path,
        "191 sync self differs"
    );
    let qp = binding(&s["queue_plan"])?;
    let iid = text(&s, "queue_invocation_id")?;
    let epoch = number(&s, "epoch")?;
    ensure!((191..=194).contains(&epoch), "191 sync epoch out of range");
    let state = custody::bound(
        &bound_path(&Path::new(ROOT).join("state.json"), 1 << 20, 0)?,
        false,
    )?;
    ensure!(
        state["plan"] == serde_json::to_value(&qp)?
            && state["invocation_id"] == iid
            && state["status"] == "managing",
        "191 sync parent queue changed"
    );
    let row = state["epochs"]
        .as_array()
        .context("191 sync queue epochs")?
        .iter()
        .find(|r| r["epoch"] == epoch)
        .context("191 sync queued epoch")?;
    ensure!(
        row["stage"] == "queued-upload" && row["task_owner"].is_null(),
        "191 sync not independently queued after actual gates"
    );
    let admission = admission_file(&admission_path(epoch, "sync"))?;
    let admitted = custody::queue_admission_check(&admission, &qp, iid, epoch, "sync")?;
    ensure!(
        admitted["sync_plan"] == serde_json::to_value(&sb)?,
        "191 sync plan is not this queue's fresh admission"
    );
    sync_inputs(&s, &qp, iid, row)?;
    custody::bound(&sb, true)?;
    executable(&program)?;
    // The shared checker revalidates existing actors and84GiB combined spare
    // envelope against these actual same-cutoff receipts. It samples no replay.
    let resources = resource_admission(&s, &admitted)?;
    let u = manager(&sync_unit(epoch))?;
    let pid = u64::from(std::process::id());
    let start = ticks(pid)?;
    let expected = format!(
        "{{ path={PROGRAM} ; argv[]={PROGRAM} sync-verified191 {} --plan-sha256 {} --self-sha256 {} ; ignore_errors=no ;",
        sb.path.display(),
        sb.sha256,
        a[6]
    );
    ensure!(
        u["Id"] == sync_unit(epoch)
            && u["InvocationID"] == env::var("INVOCATION_ID")?
            && is_lower_hex(text(&u, "InvocationID")?, 32)
            && u["MainPID"] == pid.to_string()
            && u["ActiveState"] == "active"
            && u["SubState"] == "running"
            && u["NRestarts"] == "0"
            && u["Restart"] == "no"
            && text(&u, "ExecStart")?.starts_with(&expected)
            && text(&u, "EnvironmentFiles")? == format!("{ENVFILE} (ignore_errors=no)")
            && env::var("TOKIO_WORKER_THREADS").as_deref() == Ok("2"),
        "191 sync is not its exact admitted isolated service"
    );
    let owner = json!({"pid":pid,"start_ticks":start,"unit":sync_unit(epoch),"program":program});
    process(&owner)?;
    let exec = normal_sync_argv(epoch);
    fleet::persist(
        &sync_dir(epoch).join("launch.json"),
        &json!({"schema":"jetstreamer-cohort191-sync-launch-v2","epoch":epoch,"queue_plan":qp,"queue_invocation_id":iid,"sync_plan":sb,"admission":admission,"native_owner":u,"process_identity":{"pid":pid,"start_ticks":start},"program":program,"exec_argv":exec,"source_batch":s["source_batch"],"public_batch":s["public_batch"],"source_revalidation_policy":s["source_revalidation_policy"],"full_receipt":s["full_receipt"],"plugin_receipt":s["plugin_receipt"],"observer":s["observer"],"routine_completion":s["routine_completion"],"other_pending_os_growth_bytes":s["other_pending_os_growth_bytes"],"resource_admission":resources,"prelaunch_resources":bound_path(&sync_dir(epoch).join("prelaunch-resources.json"),1<<20,0)?,"recorded_unix_millis":now_ms()?}),
    )?;
    // All native gates and fresh resource identities were rechecked above;
    // only the fsynced authenticated launch publication separates them from exec.
    Err(Process::new(PROGRAM).args(&exec[1..]).exec().into())
}

fn finish_verifier(row: &mut Value, stage: &str) -> Result<()> {
    let e = number(row, "epoch")?;
    let owner = &row["task_owner"];
    let ab = binding(&owner["admission"])?;
    let a = custody::bound(&ab, false)?;
    let d = custody::bound(&binding(&a["dispatch_plan"])?, true)?;
    let spec = custody::bound(&binding(&d["verifier_plan"])?, true)?;
    let state = Path::new(text(&spec, "state_directory")?);
    let launch = custody::bound(&bound_path(&state.join("launch.json"), 1 << 20, 0)?, false)?;
    ensure!(
        launch["schema"] == "horizon-cohort191-native-verification-launch-v1"
            && launch["claim"]["unit"] == owner["unit"]
            && launch["claim"]["invocation_id"] == owner["invocation_id"]
            && launch["plan"] == d["verifier_plan"],
        "191 verifier native launch missing/foreign"
    );
    let directory = if stage == "full" {
        "/home/sol/.jetstreamer-private/final-audits/epochs-101-200-parallel-v1/receipts"
    } else {
        "/home/sol/.jetstreamer-private/horizon-plugin-current-101-200-v2/receipts"
    };
    let gate_path = Path::new(directory).join(format!("epoch-{e}.{stage}.ok"));
    let uid = fs::symlink_metadata(&gate_path)?.uid();
    ensure!(matches!(uid, 0 | 1001), "191 gate writer differs");
    let gate = bound_path(&gate_path, 512, uid)?;
    custody::queue_gate(
        &gate,
        e,
        stage,
        &binding(&d["program"])?,
        &binding(&spec["verifier"])?,
        text(row, "archive_sha256")?,
    )?;
    let local = bound_path(
        &state.join(format!("receipts/epoch-{e}.{stage}.ok")),
        512,
        0,
    )?;
    ensure!(
        local.sha256 == gate.sha256,
        "191 canonical gate lacks this launched task's durable native receipt"
    );
    row[format!("{stage}_receipt")] = serde_json::to_value(gate)?;
    row["task_owner"] = Value::Null;
    row["stage"] = json!(if stage == "full" {
        "queued-plugin"
    } else {
        "queued-upload"
    });
    Ok(())
}
fn finish_sync(row: &mut Value) -> Result<()> {
    let e = number(row, "epoch")?;
    let ready_path = receipt_path(Path::new(RECEIPTS), e);
    let ready_uid = fs::symlink_metadata(&ready_path)?.uid();
    ensure!(matches!(ready_uid, 0 | 1001), "191 ready receipt writer differs");
    let b = bound_path(&ready_path, 16 << 10, ready_uid)?;
    let r = custody::queue_ready(&b, e, now_ms()? / 1000)?;
    ensure!(
        r.remote_sha256_readback
            && r.archive_sha256 == text(row, "archive_sha256")?
            && r.archive_length == number(row, "archive_length")?
            && r.verified_unix_seconds >= number(row, "started_unix_seconds")?
            && r.verified_unix_seconds <= now_ms()? / 1000,
        "191 sync lacks its own whole-object readback/source-revalidated ready receipt"
    );
    row["ready_receipt"] = serde_json::to_value(b)?;
    row["stage"] = json!("ready");
    row["task_owner"] = Value::Null;
    Ok(())
}
fn phase_from_journal(row: &Value, lines: &[u8]) -> Result<&'static str> {
    let owner = &row["task_owner"];
    let epoch = number(row, "epoch")?;
    let mut phase = match row["stage"].as_str() {
        Some("source-revalidation") => "source-revalidation",
        Some("readback") => "readback",
        _ => "upload",
    };
    for bytes in lines.split(|b| *b == b'\n').filter(|b| !b.is_empty()) {
        let j: Value = serde_json::from_slice(bytes)?;
        let Some(message) = j["MESSAGE"].as_str() else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(message) else {
            continue;
        };
        if !matches!(
            v["event"].as_str(),
            Some("r2-readback-start" | "r2-readback-progress" | "r2-readback-verified")
        ) {
            continue;
        }
        // Ignore other actual journal writers; never attribute their progress to
        // the admitted main process merely because they share a service name.
        if j["_SYSTEMD_UNIT"] != owner["unit"]
            || j["_SYSTEMD_INVOCATION_ID"] != owner["invocation_id"]
            || j["_PID"] != number(owner, "pid")?.to_string()
            || j["_UID"] != "0"
        {
            continue;
        }
        ensure!(
            v["key"] == format!("epoch-{epoch}.jet") && v["total_bytes"] == row["archive_length"],
            "191 own readback event object changed"
        );
        if v["event"] == "r2-readback-verified" {
            ensure!(
                v["whole_file_sha256_verified"] == true
                    && v["hashed_bytes"] == row["archive_length"],
                "191 own readback verified marker incomplete"
            );
            phase = "source-revalidation";
        } else if phase != "source-revalidation" {
            ensure!(
                v["whole_file_sha256_verified"] == false,
                "191 in-progress readback claims integrity"
            );
            phase = "readback";
        }
    }
    Ok(phase)
}
fn observe_sync_phase(row: &Value) -> Result<&'static str> {
    let o = &row["task_owner"];
    ensure!(
        proc_argv(number(o, "pid")?)? == normal_sync_argv(number(row, "epoch")?),
        "191 sync same-PID approved exec changed"
    );
    let bytes = command(
        "/usr/bin/journalctl",
        &[
            "--no-pager".into(),
            "--output=json".into(),
            "--lines=1024".into(),
            "-u".into(),
            text(o, "unit")?.into(),
            format!("_SYSTEMD_INVOCATION_ID={}", text(o, "invocation_id")?),
        ],
        10,
    )?;
    phase_from_journal(row, &bytes)
}
fn execute(state: &mut Value, plan: &Bound, self_sha: &str) -> Result<()> {
    loop {
        let mut changed = false;
        for row in state["epochs"].as_array_mut().context("191 queue rows")? {
            if row["task_owner"].is_object() {
                let u = manager(text(&row["task_owner"], "unit")?)?;
                if terminal(&row["task_owner"], &u)? {
                    match row["stage"].as_str() {
                        Some("full-verification") => finish_verifier(row, "full")?,
                        Some("plugin-verification") => finish_verifier(row, "plugin")?,
                        Some("upload" | "readback" | "source-revalidation") => finish_sync(row)?,
                        _ => bail!("191 unknown active stage"),
                    };
                    changed = true;
                } else if matches!(
                    row["stage"].as_str(),
                    Some("upload" | "readback" | "source-revalidation")
                ) {
                    let phase = observe_sync_phase(row)?;
                    if row["stage"] != phase {
                        row["stage"] = json!(phase);
                        changed = true;
                    }
                }
            }
        }
        if changed {
            persist(state)?;
        }
        if state["epochs"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["stage"] == "ready")
        {
            state["status"] = json!("complete");
            persist(state)?;
            return Ok(());
        }
        for (index, stage) in eligible(state) {
            let epoch = number(&state["epochs"][index], "epoch")?;
            let path = admission_path(epoch, stage);
            // Permission/metadata errors are never interpreted as no admission.
            match fs::symlink_metadata(&path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
                Ok(_) => {}
            }
            let ab = admission_file(&path)?;
            let iid = text(state, "invocation_id")?.to_owned();
            let a = custody::queue_admission_check(&ab, plan, &iid, epoch, stage)?;
            let intent = Path::new(ROOT)
                .join("intents")
                .join(format!("epoch-{epoch}-{stage}.json"));
            fleet::persist(
                &intent,
                &json!({"schema":"jetstreamer-cohort191-queue-task-intent-v2","queue_plan":plan,"queue_invocation_id":iid,"epoch":epoch,"stage":stage,"admission":ab,"recorded_unix_millis":now_ms()?}),
            )?;
            let started = now_ms()? / 1000;
            let owner = if stage == "sync" {
                launch_sync(epoch, &a, &ab, plan, &iid, &state["epochs"][index])?
            } else {
                dispatch(
                    epoch,
                    stage,
                    &a,
                    &ab,
                    self_sha,
                    plan,
                    &state["epochs"][index],
                )?
            };
            let row = &mut state["epochs"][index];
            row["task_owner"] = owner;
            // Sync duration binding lives outside task_owner, whose exact shape
            // is consumed by the read-only metadata observer.
            row["started_unix_seconds"] = json!(started);
            row["stage"] = json!(match stage {
                "full" => "full-verification",
                "plugin" => "plugin-verification",
                _ => "upload",
            });
            persist(state)?;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}
pub(super) fn run() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "191 queue requires root");
    let a: Vec<_> = env::args().collect();
    ensure!(
        a.len() == 7
            && a[1] == "delivery-queue-191"
            && a[3] == "--plan-sha256"
            && a[5] == "--self-sha256"
            && is_lower_hex(&a[4], 64)
            && is_lower_hex(&a[6], 64),
        "usage: delivery-queue-191 PLAN --plan-sha256 SHA --self-sha256 SHA"
    );
    let plan = Bound {
        path: a[2].clone().into(),
        sha256: a[4].clone(),
    };
    let p = custody::queue_plan_check(&plan, &BTreeSet::from([191, 192, 193, 194]))?;
    let program = binding(&p["program"])?;
    ensure!(
        program.path == Path::new(PROGRAM)
            && program.sha256 == a[6]
            && fs::read_link("/proc/self/exe")? == program.path,
        "191 queue self binding"
    );
    executable(&program)?;
    for path in [
        ROOT,
        &format!("{ROOT}/history"),
        &format!("{ROOT}/admissions"),
        &format!("{ROOT}/intents"),
        &format!("{ROOT}/sync"),
    ] {
        root_dir(Path::new(path))?;
    }
    let lock_path = Path::new(ROOT).join("queue.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&lock_path)?;
    let m = lock.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o077 == 0
            && fs::symlink_metadata(&lock_path)?.ino() == m.ino()
            && unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "191 queue lease unsafe/busy"
    );
    ensure!(
        !Path::new(ROOT).join("state.json").try_exists()?
            && fs::read_dir(Path::new(ROOT).join("history"))?
                .next()
                .is_none()
            && fs::read_dir(Path::new(ROOT).join("intents"))?
                .next()
                .is_none(),
        "191 queue already has custody/history; manual reconciliation required, never retry"
    );
    let iid = env::var("INVOCATION_ID")?;
    let u = manager(UNIT)?;
    let expected = format!(
        "{{ path={PROGRAM} ; argv[]={PROGRAM} delivery-queue-191 {} --plan-sha256 {} --self-sha256 {} ; ignore_errors=no ;",
        plan.path.display(),
        plan.sha256,
        a[6]
    );
    ensure!(
        is_lower_hex(&iid, 32)
            && u["Id"] == UNIT
            && u["InvocationID"] == iid
            && u["MainPID"] == std::process::id().to_string()
            && u["ActiveState"] == "active"
            && u["SubState"] == "running"
            && u["NRestarts"] == "0"
            && u["Restart"] == "no"
            && u["PrivateNetwork"] == "yes"
            && matches!(u["EnvironmentFiles"].as_str(), None | Some(""))
            && text(&u, "ExecStart")?.starts_with(&expected),
        "191 queue must be exact isolated non-restarting credential-free manager"
    );
    for key in [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "R2_ACCESS_KEY_ID",
        "R2_SECRET_ACCESS_KEY",
    ] {
        ensure!(
            env::var_os(key).is_none(),
            "191 queue must not hold R2 credentials"
        );
    }
    let pid = u64::from(std::process::id());
    let start = ticks(pid)?;
    let mut state = json!({"schema":"jetstreamer-cohort191-delivery-queue-state-v2","revision":0,"plan":plan,"unit":UNIT,"invocation_id":iid,"manager_pid":pid,"manager_start_ticks":start,"updated_unix_millis":0,"status":"managing","epochs":p["imported_members"].as_array().context("191 imported rows")?.iter().map(|r|json!({"epoch":r["epoch"],"archive_sha256":r["archive_sha256"],"archive_length":r["archive_length"],"stage":"queued-full","task_owner":null})).collect::<Vec<_>>()});
    process(&json!({"pid":pid,"start_ticks":start,"unit":UNIT,"program":program}))?;
    persist(&mut state)?;
    if let Err(e) = execute(&mut state, &plan, &a[6]) {
        state["status"] = json!("failed");
        state["failure"] = json!(format!("{e:#}"));
        persist(&mut state)
            .context("191 failed state persistence; preserve history and intents")?;
        return Err(e);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn state(stages: &[&str]) -> Value {
        json!({"epochs":stages.iter().enumerate().map(|(i,s)|json!({"epoch":191+i,"stage":s,"task_owner":null})).collect::<Vec<_>>()})
    }
    #[test]
    fn scheduling_serializes_verifiers_and_overlaps_one_upload() {
        assert_eq!(
            eligible(&state(&[
                "queued-full",
                "queued-full",
                "queued-full",
                "queued-full"
            ])),
            vec![(0, "full")]
        );
        assert_eq!(
            eligible(&state(&[
                "queued-upload",
                "queued-full",
                "queued-full",
                "queued-full"
            ])),
            vec![(0, "sync"), (1, "full")]
        );
        assert_eq!(
            eligible(&state(&[
                "upload",
                "full-verification",
                "queued-full",
                "queued-full"
            ])),
            Vec::<(usize, &str)>::new()
        );
        assert_eq!(
            eligible(&state(&[
                "upload",
                "queued-upload",
                "queued-plugin",
                "queued-full"
            ])),
            vec![(2, "plugin")]
        );
    }
    #[test]
    fn queued_plan_never_is_an_active_owner() {
        assert_eq!(
            pending_stage(&json!({"stage":"queued-full","dispatch_plan":{"sha256":"future"}})),
            Some("full")
        );
        assert_eq!(pending_stage(&json!({"stage":"full-verification"})), None);
    }
    #[test]
    fn sync_argv_cannot_weaken_normal_gates_or_share_manager_network() {
        let a = sync_args(
            191,
            &Bound {
                path: "/sealed/sync-plan.json".into(),
                sha256: "a".repeat(64),
            },
            &"b".repeat(64),
        );
        for bad in [
            "--overwrite-existing",
            "--delete-local",
            "--legacy-etag-only",
            "--repair-orphaned-archive",
        ] {
            assert!(!a.iter().any(|s| s == bad));
        }
        assert!(
            a.iter()
                .any(|s| s == &format!("--property=EnvironmentFile={ENVFILE}"))
        );
        assert!(a.iter().any(|s| s == "--property=MemoryMax=2G"));
        assert!(a.iter().any(|s| s == "--property=Restart=no"));
        assert!(!a.iter().any(|s| s == "--wait"));
    }
    #[test]
    fn exit_success_does_not_replace_identity_or_gate_evidence() {
        let owner = json!({"unit":"test.service","invocation_id":"a".repeat(32),"expected_exec_start":"{ path=/tool ; argv[]=/tool ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"});
        let u = json!({"Id":"test.service","InvocationID":"b".repeat(32),"LoadState":"loaded","NRestarts":"0","Restart":"no","Job":"","ExecStart":owner["expected_exec_start"],"MainPID":"0","ControlGroup":"","Result":"success","ExecMainStatus":"0","ActiveState":"active","SubState":"exited"});
        assert!(terminal(&owner, &u).is_err());
    }
    #[test]
    fn sync_plan_cannot_borrow_another_queue_invocation_or_gate() {
        let plan = Bound {
            path: "/sealed/queue.json".into(),
            sha256: "a".repeat(64),
        };
        let row = json!({"epoch":191,"archive_sha256":"b".repeat(64),"archive_length":100,"full_receipt":{"path":"/full","sha256":"c".repeat(64)},"plugin_receipt":{"path":"/plugin","sha256":"d".repeat(64)}});
        let spec = json!({"schema":"jetstreamer-cohort191-sync-plan-v2","queue_plan":plan,"queue_invocation_id":"e".repeat(32),"epoch":191,"program":{"path":PROGRAM,"sha256":"f".repeat(64)},"archive_sha256":row["archive_sha256"],"archive_length":100,"full_receipt":row["full_receipt"],"plugin_receipt":row["plugin_receipt"],"output_directory":sync_dir(191),"observer":{"path":"/observer","sha256":"1".repeat(64)},"routine_completion":{"path":"/completion","sha256":"2".repeat(64)},"other_pending_os_growth_bytes":0});
        validate_sync(&spec, &plan, &"e".repeat(32), &row).unwrap();
        for (key, value) in [
            ("queue_invocation_id", json!("f".repeat(32))),
            ("epoch", json!(192)),
            ("archive_length", json!(101)),
            ("full_receipt", Value::Null),
            ("plugin_receipt", row["full_receipt"].clone()),
            (
                "queue_plan",
                json!({"path":"/sealed/old.json","sha256":"a".repeat(64)}),
            ),
        ] {
            let mut bad = spec.clone();
            bad[key] = value;
            assert!(
                validate_sync(&bad, &plan, &"e".repeat(32), &row).is_err(),
                "{key}"
            );
        }
    }
    #[test]
    fn readback_phase_requires_own_native_pid_iid_object_and_verified_marker() {
        let mut row = json!({"epoch":191,"stage":"upload","archive_length":100,"task_owner":{"unit":sync_unit(191),"invocation_id":"a".repeat(32),"pid":123}});
        let event = json!({"event":"r2-readback-verified","key":"epoch-191.jet","total_bytes":100,"hashed_bytes":100,"whole_file_sha256_verified":true});
        let line = json!({"_SYSTEMD_UNIT":sync_unit(191),"_SYSTEMD_INVOCATION_ID":"a".repeat(32),"_PID":"123","_UID":"0","MESSAGE":event.to_string()});
        assert_eq!(
            phase_from_journal(&row, &serde_json::to_vec(&line).unwrap()).unwrap(),
            "source-revalidation"
        );
        for (key, value) in [
            ("_PID", "124"),
            ("_SYSTEMD_INVOCATION_ID", "b"),
            ("_UID", "1001"),
            ("_SYSTEMD_UNIT", "other.service"),
        ] {
            let mut foreign = line.clone();
            foreign[key] = json!(value);
            assert_eq!(
                phase_from_journal(&row, &serde_json::to_vec(&foreign).unwrap()).unwrap(),
                "upload"
            );
        }
        let mut incomplete = event.clone();
        incomplete["hashed_bytes"] = json!(99);
        let mut bad = line.clone();
        bad["MESSAGE"] = json!(incomplete.to_string());
        assert!(phase_from_journal(&row, &serde_json::to_vec(&bad).unwrap()).is_err());
        row["stage"] = json!("source-revalidation");
        assert_eq!(
            phase_from_journal(&row, b"").unwrap(),
            "source-revalidation"
        );
    }
    #[test]
    fn no_two_syncs_can_become_eligible_while_readback_or_tail_is_active() {
        for stage in ["upload", "readback", "source-revalidation"] {
            assert_eq!(
                eligible(&state(&[stage, "queued-upload", "queued-upload", "ready"])),
                Vec::<(usize, &str)>::new()
            );
        }
    }
    #[test]
    fn sync_resource_fields_are_required_and_intake_cannot_substitute_them() {
        let s = json!({"observer":{"path":"/observer","sha256":"a".repeat(64)},"routine_completion":{"path":"/completion","sha256":"b".repeat(64)},"other_pending_os_growth_bytes":123});
        assert_eq!(resource_fields(&s).unwrap().2, 123);
        for key in [
            "observer",
            "routine_completion",
            "other_pending_os_growth_bytes",
        ] {
            let mut missing = s.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(resource_fields(&missing).is_err());
            let mut mismatch = s.clone();
            mismatch[key] = Value::Null;
            // Mismatch returns before the shared checker can read any files.
            assert!(resource_admission(&s, &mismatch).is_err());
        }
    }
}
