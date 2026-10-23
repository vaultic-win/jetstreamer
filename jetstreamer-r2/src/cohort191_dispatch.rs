//! One exact native191 verifier admission/launch. Never replays or mutates R2.
use super::*;
use crate::cohort191_delivery::{self as custody, Bound};
use std::{
    collections::BTreeSet,
    os::fd::AsRawFd,
    process::{Command, Stdio},
    time::Instant,
};

const ROOT: &str = "/var/lib/jetstreamer/horizon-cohort191-verification-dispatch-20261023-v1";
const STATE: &str = "/var/lib/jetstreamer/horizon-cohort191-canonical-verification-20261023-v1";
const PROGRAM: &str = "/usr/local/lib/jetstreamer/horizon-cohort191-delivery-tools-20261023-v1/jetstreamer-horizon-verify-pair";
const PLANS: &str = "/usr/local/lib/jetstreamer/horizon-cohort191-verification-plans-20261023-v1";
const OLD_OS_PROTECTED: u64 = 228_833_779_142;
const OS_BUDGET: (&str, &str) = (
    "/usr/local/lib/jetstreamer/horizon-v1425-portability-os-budget-20261023-v2/budget.json",
    "2e95927a3c49972630c9de458e32359a859b90de7b0fa9b195d6dbb1083ed620",
);
// Eight fixed tasks, each with at most two16MiB logs, plus bounded custody files.
// Reserve64MiB per task and8MiB for dispatcher evidence; retain completed files.
const OS_ALLOWANCE: u64 = 520 << 20;
const GIB: u64 = 1 << 30;
const FULL_DIR: &str =
    "/home/sol/.jetstreamer-private/final-audits/epochs-101-200-parallel-v1/receipts";
const PLUGIN_DIR: &str =
    "/home/sol/.jetstreamer-private/horizon-plugin-current-101-200-v2/receipts";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Stage {
    Full,
    Plugin,
}
impl Stage {
    fn name(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Plugin => "plugin",
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    epoch: u64,
    stage: Stage,
    source_batch: Bound,
    public_batch: Bound,
    program: Bound,
    verifier_plan: Bound,
    observer: Bound,
    routine_completion: Bound,
    // Explicit coordinator accounting for other newly admitted OS allocations.
    // This is not permission to reassign any old compiler/fixture reservation.
    other_pending_os_growth_bytes: u64,
    output_directory: PathBuf,
}
fn unit(epoch: u64, stage: Stage) -> String {
    format!(
        "horizon-{}-verify-{epoch}-native191-20261023-v1.service",
        stage.name()
    )
}
fn state(p: &Plan) -> PathBuf {
    Path::new(STATE)
        .join(format!("epoch-{}", p.epoch))
        .join(p.stage.name())
}
fn validate(p: &Plan, spec: &Value) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-cohort191-verification-dispatch-plan-v1"
            && (191..=194).contains(&p.epoch)
            && p.program.path == Path::new(PROGRAM)
            && is_lower_hex(&p.program.sha256, 64)
            && p.verifier_plan.path
                == Path::new(PLANS).join(format!("epoch-{}-{}.json", p.epoch, p.stage.name()))
            && p.output_directory
                == Path::new(ROOT).join(format!("epoch-{}-{}", p.epoch, p.stage.name())),
        "foreign191 verifier dispatch"
    );
    ensure!(
        spec["schema"] == "horizon-verify-canonical-pair-dev-samjohnson191-v1"
            && spec["epoch"] == p.epoch
            && spec["stage"] == p.stage.name()
            && spec["archive_directory"] == "/home/sol/horizon"
            && spec["state_directory"] == state(p).to_str().unwrap()
            && spec["admission_observer"] == serde_json::to_value(&p.observer)?
            && spec["threads_per_command"]
                .as_u64()
                .is_some_and(|n| (1..=16).contains(&n)),
        "191 verifier spec differs"
    );
    // The native verify-pair independently pins its compatible full/plugin
    // executable and authenticates its exact systemd invocation before hashing.
    ensure!(
        is_lower_hex(spec["expected_archive_sha256"].as_str().unwrap_or(""), 64),
        "191 missing archive digest"
    );
    let (name, hash) = match p.stage {
        Stage::Full => (
            "verify_archive",
            "5fc5640254f6a065e96bf73ad951c9dacd57aa963b87a4379e1f27c6ebeb3574",
        ),
        Stage::Plugin => (
            "horizon_pipeline",
            "e20892a111f8e26c8e25561a939eaf171771789753059100510c936d92092137",
        ),
    };
    ensure!(
        spec["verifier"]["path"]
            == Path::new(
                "/usr/local/lib/jetstreamer/horizon-epoch198-compatible-verifiers-20261021-v1"
            )
            .join(name)
            .to_str()
            .unwrap()
            && spec["verifier"]["sha256"] == hash,
        "191 spec uses an unqualified reader"
    );
    Ok(())
}
fn private_directory(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path && m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "191 dispatch directory is not canonical root-private storage"
    );
    Ok(())
}
fn make_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)?;
    private_directory(path)?;
    File::open(path.parent().context("191 directory parent")?)?.sync_all()?;
    Ok(())
}
fn clock() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn utc(s: &str) -> Result<u64> {
    let input = std::ffi::CString::new(s)?;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let end = unsafe { libc::strptime(input.as_ptr(), c"%Y-%m-%dT%H:%M:%SZ".as_ptr(), &mut tm) };
    ensure!(
        !end.is_null() && unsafe { *end } == 0,
        "191 bad resource clock"
    );
    let t = unsafe { libc::timegm(&mut tm) };
    let canonical = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    );
    ensure!(t >= 0 && canonical == s, "191 noncanonical resource clock");
    Ok(t as u64)
}
fn resources(p: &Plan, o: &Value, c: &Value, now: u64) -> Result<()> {
    let sample = o["recorded_at_utc"]
        .as_str()
        .context("191 observer clock")?;
    let time = utc(sample)?;
    ensure!(
        time <= now
            && now - time <= 900
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && o["cadence"]["routine_minimum_interval_enforced"] == true
            && c["schema"] == "jetstreamer-horizon-routine-cycle-completion-v1"
            && c["sampled_at_utc"] == sample
            && c["observer"] == serde_json::to_value(&p.observer)?
            && c["capacity_decision"]["sampled_at_utc"] == sample,
        "191 mismatched/stale coordinated resources"
    );
    let m = &c["capacity_decision"]["memory_concurrency_target"];
    let resident = m["host_resident_planning_bytes"]
        .as_u64()
        .context("191 resident envelope")?;
    let reserve = m["reservation_ceiling_bytes"]
        .as_u64()
        .context("191 protected memory growth")?;
    let total = m["host_total_bytes"].as_u64().context("191 total memory")?;
    let need = resident
        .checked_add(reserve)
        .and_then(|n| n.checked_add(81 * GIB))
        .context("191 memory overflow")?;
    ensure!(
        m["valid"] == true && need <= total,
        "191 lacks protected growth +64GiB verifier +16GiB compiler +1GiB dispatcher envelope"
    );
    ensure!(
        o["host_memory"]["conservative_available_kib"]
            .as_u64()
            .is_some_and(|n| n >= 128 * 1024 * 1024),
        "191 available memory too low"
    );
    Ok(())
}
fn os_capacity(p: &Plan) -> Result<u64> {
    let root = Path::new(ROOT);
    private_directory(root)?;
    ensure!(
        fs::symlink_metadata(root)?.dev() == 2304,
        "191 OS output device changed"
    );
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    let name = std::ffi::CString::new(ROOT)?;
    ensure!(
        unsafe { libc::statvfs(name.as_ptr(), &mut s) } == 0,
        "191 statvfs failed"
    );
    let available = s
        .f_bavail
        .checked_mul(s.f_frsize)
        .context("191 free-space overflow")?;
    let required = OLD_OS_PROTECTED
        .checked_add(p.other_pending_os_growth_bytes)
        .and_then(|n| n.checked_add(OS_ALLOWANCE))
        .context("191 OS budget overflow")?;
    ensure!(
        available >= required,
        "191 OS floor/other claims/log reserve do not fit"
    );
    Ok(available)
}
fn bounded_command(program: &str, args: &[String], maximum: usize) -> Result<Vec<u8>> {
    // Regular private output gives a hard bounded read and a service timeout;
    // never pipe a potentially full stderr stream while waiting for its child.
    let mut out = tempfile::tempfile_in(ROOT)?;
    let mut err = tempfile::tempfile_in(ROOT)?;
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(out.try_clone()?)
        .stderr(err.try_clone()?)
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if Instant::now() >= deadline {
            // This kills only the short client, never PID1's verifier service.
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!(
                "191 manager client timed out; preserve intent and reconcile its exact unit, never restart from this timeout"
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    use std::io::{Seek, SeekFrom};
    ensure!(
        out.metadata()?.len() <= maximum as u64 && err.metadata()?.len() <= maximum as u64,
        "191 manager output exceeded bound"
    );
    out.seek(SeekFrom::Start(0))?;
    err.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    out.read_to_end(&mut bytes)?;
    let mut errors = Vec::new();
    err.read_to_end(&mut errors)?;
    ensure!(
        status.success(),
        "191 manager client failed: {}",
        String::from_utf8_lossy(&errors)
    );
    Ok(bytes)
}
fn manager(name: &str) -> Result<Value> {
    let bytes=bounded_command("/usr/bin/systemctl",&["show".into(),name.into(),"--property=Id,LoadState,ActiveState,SubState,InvocationID,MainPID,NRestarts,Job,Type,ExecStart,ControlGroup,Result".into()],1<<20)?;
    let mut map = serde_json::Map::new();
    for line in std::str::from_utf8(&bytes)?.lines() {
        let (k, v) = line.split_once('=').context("191 manager row")?;
        ensure!(
            map.insert(k.into(), json!(v)).is_none(),
            "191 duplicate manager field"
        );
    }
    Ok(Value::Object(map))
}
fn idle(v: &Value, expected: &str, selected: bool) -> Result<()> {
    ensure!(
        v["Id"] == expected
            && v["Job"] == ""
            && v["MainPID"] == "0"
            && v["ControlGroup"] == ""
            && matches!(
                v["ActiveState"].as_str(),
                Some("inactive" | "failed" | "active")
            ),
        "191 verifier namespace is live/queued/unknown"
    );
    if selected {
        ensure!(
            v["LoadState"] == "not-found" && v["ActiveState"] == "inactive",
            "191 selected unit already exists; preserve/reconcile, do not replay dispatch"
        );
    } else if v["LoadState"] == "loaded" {
        ensure!(
            matches!(v["SubState"].as_str(), Some("dead" | "exited" | "failed")),
            "191 competing verifier is not terminal"
        );
    } else {
        ensure!(v["LoadState"] == "not-found", "191 unknown competing unit");
    }
    Ok(())
}
fn census(p: &Plan) -> Result<Value> {
    let mut values = Vec::new();
    for epoch in 191..=194 {
        for stage in [Stage::Full, Stage::Plugin] {
            let name = unit(epoch, stage);
            let v = manager(&name)?;
            idle(&v, &name, epoch == p.epoch && stage == p.stage)?;
            values.push(v);
        }
    }
    Ok(json!(values))
}
fn argv(p: &Plan) -> Vec<String> {
    let target = unit(p.epoch, p.stage);
    let mirror = match p.stage {
        Stage::Full => FULL_DIR,
        Stage::Plugin => PLUGIN_DIR,
    };
    vec![
        format!("--unit={target}"),
        "--no-block".into(),
        "--property=Type=exec".into(),
        "--property=Restart=no".into(),
        "--property=RemainAfterExit=yes".into(),
        "--property=RuntimeMaxSec=43200".into(),
        "--property=UMask=0077".into(),
        "--property=KillMode=control-group".into(),
        "--property=LimitCORE=0".into(),
        "--property=LimitFSIZE=16M".into(),
        "--property=CPUQuota=400%".into(),
        "--property=MemoryHigh=48G".into(),
        "--property=MemoryMax=64G".into(),
        "--property=MemorySwapMax=0".into(),
        "--property=TasksMax=512".into(),
        "--property=PrivateNetwork=yes".into(),
        "--property=ProtectSystem=strict".into(),
        "--property=ProtectHome=read-only".into(),
        "--property=PrivateTmp=yes".into(),
        "--property=NoNewPrivileges=yes".into(),
        "--property=CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE".into(),
        "--property=AmbientCapabilities=CAP_DAC_OVERRIDE CAP_SYS_PTRACE".into(),
        format!("--property=ReadWritePaths={} {mirror}", state(p).display()),
        PROGRAM.into(),
        p.verifier_plan.path.to_string_lossy().into_owned(),
        p.verifier_plan.sha256.clone(),
        p.program.sha256.clone(),
    ]
}
fn selected_live(p: &Plan, v: &Value) -> Result<Value> {
    let name = unit(p.epoch, p.stage);
    let prefix = format!(
        "{{ path={PROGRAM} ; argv[]={PROGRAM} {} {} {} ; ignore_errors=no ;",
        p.verifier_plan.path.display(),
        p.verifier_plan.sha256,
        p.program.sha256
    );
    ensure!(
        v["Id"] == name
            && v["LoadState"] == "loaded"
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["Type"] == "exec"
            && v["NRestarts"] == "0"
            && v["ControlGroup"] == format!("/system.slice/{name}")
            && is_lower_hex(v["InvocationID"].as_str().unwrap_or(""), 32)
            && v["ExecStart"]
                .as_str()
                .is_some_and(|s| s.starts_with(&prefix)),
        "191 service not its exact live verifier"
    );
    let pid = v["MainPID"]
        .as_str()
        .context("191 launched PID")?
        .parse::<u32>()?;
    ensure!(
        pid > 0 && fs::read_link(format!("/proc/{pid}/exe"))? == Path::new(PROGRAM),
        "191 verifier PID/executable differs"
    );
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let tail = stat
        .rsplit_once(") ")
        .context("191 process stat framing")?
        .1;
    let ticks = tail
        .split_whitespace()
        .nth(19)
        .context("191 process start ticks")?
        .parse::<u64>()?;
    let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    ensure!(
        cgroup
            .lines()
            .any(|line| line == format!("0::/system.slice/{name}")),
        "191 process escaped verifier cgroup"
    );
    ensure!(
        manager(&name)? == *v
            && fs::read_to_string(format!("/proc/{pid}/stat"))?
                .rsplit_once(") ")
                .and_then(|(_, s)| s.split_whitespace().nth(19))
                .and_then(|s| s.parse::<u64>().ok())
                == Some(ticks),
        "191 process identity changed during capture"
    );
    Ok(json!({"pid":pid,"start_ticks":ticks,"cgroup":cgroup,"executable":PROGRAM}))
}
pub(super) fn run() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "191 dispatcher requires root"
    );
    let a: Vec<_> = env::args().collect();
    ensure!(
        (a.len() == 7 || (a.len() == 8 && a[7] == "--check-only"))
            && a[1] == "dispatch-verification-191"
            && a[3] == "--plan-sha256"
            && a[5] == "--self-sha256",
        "191 dispatcher usage: dispatch-verification-191 PLAN --plan-sha256 SHA --self-sha256 SHA [--check-only]"
    );
    ensure!(
        is_lower_hex(&a[4], 64) && is_lower_hex(&a[6], 64),
        "191 dispatcher digest"
    );
    let own = fs::read("/proc/self/exe")?;
    ensure!(
        hex_lower(&Sha256::digest(own)) == a[6],
        "191 dispatcher self hash"
    );
    let plan_bound = Bound {
        path: PathBuf::from(&a[2]),
        sha256: a[4].clone(),
    };
    let p: Plan = serde_json::from_value(custody::bound(&plan_bound, true)?)?;
    let spec = custody::bound(&p.verifier_plan, true)?;
    validate(&p, &spec)?;
    private_directory(Path::new(ROOT))?;
    let budget = custody::bound(
        &Bound {
            path: OS_BUDGET.0.into(),
            sha256: OS_BUDGET.1.into(),
        },
        true,
    )?;
    ensure!(
        budget["required_initial_free_bytes"] == OLD_OS_PROTECTED
            && budget["minimum_retained_free_bytes"] == 205_211_459_014u64
            && budget["reservations"]["modern_builder_remaining_bytes"] == 4 * GIB
            && budget["reservations"]["legacy_build_and_artifact_staging_increment_bytes"]
                == 8 * GIB
            && budget["reservations"]["fixture_maximum_physical_bytes"] == 10 * GIB,
        "191 retained OS budget changed"
    );
    // One fixed native191 dispatcher at a time, including fsynced intent and
    // actual manager capture. This lock does not purport to mediate other work.
    let lock_path = Path::new(ROOT).join("dispatch.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&lock_path)?;
    let lm = lock.metadata()?;
    ensure!(
        lm.is_file()
            && lm.uid() == 0
            && lm.nlink() == 1
            && lm.mode() & 0o077 == 0
            && fs::symlink_metadata(&lock_path)?.ino() == lm.ino()
            && unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "191 dispatcher lease unavailable/unsafe"
    );
    let materialized = BTreeSet::from([p.epoch]);
    let import = custody::dispatch_import_check(&p.source_batch, &p.public_batch, &materialized)?;
    ensure!(
        serde_json::to_vec(&import)?.len() <= 1 << 20,
        "191 import evidence exceeds dispatch bound"
    );
    // Native receipts may be UID1001-owned: the custody helper validates that
    // exact policy, unlike the root-only operational-plan reader.
    let members = import["public_members"]
        .as_array()
        .context("191 committed members")?;
    let member = members
        .iter()
        .find(|m| m["epoch"] == p.epoch)
        .context("191 selected native member")?;
    ensure!(
        member["archive_sha256"] == spec["expected_archive_sha256"],
        "191 spec/native digest mismatch"
    );
    let o = custody::bound(&p.observer, false)?;
    let c = custody::bound(&p.routine_completion, false)?;
    resources(&p, &o, &c, clock()?)?;
    let available = os_capacity(&p)?;
    let before = census(&p)?;
    // Immutable executables are streamed, not passed through the JSON reader.
    let im = fs::symlink_metadata(&p.program.path)?;
    ensure!(
        p.program.path.canonicalize()? == p.program.path
            && im.is_file()
            && im.uid() == 0
            && im.nlink() == 1
            && im.mode() & 0o222 == 0
            && im.mode() & 0o111 != 0
            && im.len() <= 512 << 20,
        "191 unsealed verifier wrapper"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p.program.path)?;
    let mut hash = Sha256::new();
    std::io::copy(&mut file, &mut hash)?;
    ensure!(
        hex_lower(&hash.finalize()) == p.program.sha256
            && identity(&file.metadata()?) == identity(&im)
            && regular_identity(&p.program.path)? == identity(&im),
        "191 wrapper bytes/identity changed"
    );
    ensure!(
        !p.output_directory.try_exists()? && !state(&p).try_exists()?,
        "191 dispatch or verifier state already exists; preserve evidence"
    );
    if a.len() == 8 {
        println!("191 dispatch check passed; no launch or sampling");
        return Ok(());
    }
    make_directory(&p.output_directory)?;
    private_directory(Path::new(STATE))?;
    let epoch_parent = Path::new(STATE).join(format!("epoch-{}", p.epoch));
    if !epoch_parent.try_exists()? {
        make_directory(&epoch_parent)?;
    } else {
        private_directory(&epoch_parent)?;
    }
    make_directory(&state(&p))?;
    let intent = json!({"schema":"jetstreamer-cohort191-verification-dispatch-intent-v1","plan":plan_bound,"self_sha256":a[6],"epoch":p.epoch,"stage":p.stage,"unit":unit(p.epoch,p.stage),"source_batch":p.source_batch,"public_batch":p.public_batch,"native_import":import,"program":p.program,"verifier_plan":p.verifier_plan,"observer":p.observer,"routine_completion":p.routine_completion,"before":before,"os_available_bytes":available,"old_os_claims_protected_bytes":OLD_OS_PROTECTED,"other_pending_os_growth_bytes":p.other_pending_os_growth_bytes,"new_os_allowance_bytes":OS_ALLOWANCE,"argv":argv(&p),"verification_complete":false,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false});
    fleet::persist(&p.output_directory.join("intent.json"), &intent)?;
    ensure!(
        census(&p)? == before,
        "191 competing verifier changed before launch"
    );
    let again = custody::dispatch_import_check(&p.source_batch, &p.public_batch, &materialized)?;
    ensure!(again == import, "191 native import changed before launch");
    resources(
        &p,
        &custody::bound(&p.observer, false)?,
        &custody::bound(&p.routine_completion, false)?,
        clock()?,
    )?;
    os_capacity(&p)?;
    bounded_command("/usr/bin/systemd-run", &argv(&p), 1 << 20)?;
    let name = unit(p.epoch, p.stage);
    let deadline = Instant::now() + Duration::from_secs(15);
    let (live, process) = loop {
        let v = manager(&name)?;
        if v["ActiveState"] == "active" && v["SubState"] == "running" {
            let process = selected_live(&p, &v)?;
            break (v, process);
        }
        ensure!(
            matches!(v["ActiveState"].as_str(), Some("activating" | "active"))
                && Instant::now() < deadline,
            "191 launch not observed live; preserve intent and reconcile exact unit, never restart automatically"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    fleet::persist(
        &p.output_directory.join("launch.json"),
        &json!({"schema":"jetstreamer-cohort191-verification-dispatch-launch-v1","intent":p.output_directory.join("intent.json"),"epoch":p.epoch,"stage":p.stage,"native_owner":live,"process_identity":process,"source_batch":p.source_batch,"public_batch":p.public_batch,"program":p.program,"verifier_plan":p.verifier_plan,"recorded_unix_seconds":clock()?,"verification_complete":false,"publication_authorized":false,"replay_launch_authorized":false,"r2_mutations":false}),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bound(path: &str) -> Bound {
        Bound {
            path: path.into(),
            sha256: "a".repeat(64),
        }
    }
    fn fixture() -> (Plan, Value) {
        let observer = bound(
            "/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261023T225600Z.json",
        );
        let p = Plan {
            schema: "jetstreamer-cohort191-verification-dispatch-plan-v1".into(),
            epoch: 191,
            stage: Stage::Full,
            source_batch: bound("/native/source"),
            public_batch: bound("/native/public"),
            program: bound(PROGRAM),
            verifier_plan: bound(&format!("{PLANS}/epoch-191-full.json")),
            observer,
            routine_completion: bound("/native/cycle"),
            other_pending_os_growth_bytes: 0,
            output_directory: format!("{ROOT}/epoch-191-full").into(),
        };
        let spec = json!({"schema":"horizon-verify-canonical-pair-dev-samjohnson191-v1","epoch":191,"stage":"full","archive_directory":"/home/sol/horizon","state_directory":state(&p),"admission_observer":p.observer,"threads_per_command":4,"expected_archive_sha256":"b".repeat(64),"verifier":{"path":"/usr/local/lib/jetstreamer/horizon-epoch198-compatible-verifiers-20261021-v1/verify_archive","sha256":"5fc5640254f6a065e96bf73ad951c9dacd57aa963b87a4379e1f27c6ebeb3574"}});
        (p, spec)
    }
    #[test]
    fn dispatcher_scope_never_inherits_another_epoch_program_or_spec() {
        let (mut p, s) = fixture();
        validate(&p, &s).unwrap();
        p.epoch = 199;
        assert!(validate(&p, &s).is_err());
        p.epoch = 191;
        p.program.path = "/usr/bin/true".into();
        assert!(validate(&p, &s).is_err());
        p.program.path = PROGRAM.into();
        p.verifier_plan.path = "/other/plan.json".into();
        assert!(validate(&p, &s).is_err());
        let (p, mut s) = fixture();
        s["epoch"] = json!(192);
        assert!(validate(&p, &s).is_err());
    }
    #[test]
    fn serial_census_rejects_queued_active_or_reused_units() {
        let name = unit(191, Stage::Full);
        let v = json!({"Id":name,"Job":"","MainPID":"0","ControlGroup":"","LoadState":"not-found","ActiveState":"inactive","SubState":"dead"});
        idle(&v, &name, true).unwrap();
        for (key, value) in [
            ("Job", "41 start"),
            ("MainPID", "123"),
            ("ControlGroup", "/system.slice/other"),
            ("LoadState", "loaded"),
        ] {
            let mut bad = v.clone();
            bad[key] = json!(value);
            assert!(idle(&bad, &name, true).is_err());
        }
        let mut terminal = v;
        terminal["LoadState"] = json!("loaded");
        terminal["ActiveState"] = json!("active");
        terminal["SubState"] = json!("exited");
        idle(&terminal, &name, false).unwrap();
    }
    #[test]
    fn resource_envelope_keeps_growth_and_compiler_reserves() {
        let (p, _) = fixture();
        let sample = "2026-10-23T22:56:00Z";
        let now = utc(sample).unwrap();
        let o = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":sample,"cadence":{"routine_minimum_interval_enforced":true},"host_memory":{"conservative_available_kib":192u64*1024*1024}});
        let mut c = json!({"schema":"jetstreamer-horizon-routine-cycle-completion-v1","sampled_at_utc":sample,"observer":p.observer,"capacity_decision":{"sampled_at_utc":sample,"memory_concurrency_target":{"valid":true,"host_resident_planning_bytes":500*GIB,"reservation_ceiling_bytes":180*GIB,"host_total_bytes":761*GIB}}});
        resources(&p, &o, &c, now).unwrap();
        c["capacity_decision"]["memory_concurrency_target"]["host_total_bytes"] = json!(760 * GIB);
        assert!(resources(&p, &o, &c, now).is_err());
        c["capacity_decision"]["memory_concurrency_target"]["host_total_bytes"] = json!(761 * GIB);
        assert!(resources(&p, &o, &c, now + 901).is_err());
        c["observer"]["sha256"] = json!("b".repeat(64));
        assert!(resources(&p, &o, &c, now).is_err());
    }
    #[test]
    fn launcher_is_network_isolated_nonrestarting_and_exact() {
        let (p, _) = fixture();
        let a = argv(&p);
        for required in [
            "--property=Restart=no",
            "--property=PrivateNetwork=yes",
            "--property=MemorySwapMax=0",
            "--property=LimitFSIZE=16M",
        ] {
            assert!(a.iter().any(|s| s == required));
        }
        assert_eq!(a[a.len() - 4], PROGRAM);
        assert_eq!(a[a.len() - 2], p.verifier_plan.sha256);
        assert!(
            !a.iter()
                .any(|s| s.contains("EnvironmentFile") || s == "--wait")
        );
    }
    #[test]
    fn utc_rejects_normalized_or_noncanonical_dates() {
        assert!(utc("2026-02-30T00:00:00Z").is_err());
        assert!(utc("2026-10-23T22:56:00Zjunk").is_err());
    }
}
