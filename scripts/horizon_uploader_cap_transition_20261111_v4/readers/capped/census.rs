//! Read-only identity-bound delivery census. It never freezes, signals or grants credit.
use crate::evidence;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    env, fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(not(horizon_uploader_freeze_fixture))]
pub(super) const UNIT: &str = "horizon-r2-progressive-epochs101-200-v21-rust-authenticated.service";

#[cfg(not(horizon_uploader_freeze_fixture))]
pub(super) const CGROUP: &str =
    "/system.slice/horizon-r2-progressive-epochs101-200-v21-rust-authenticated.service";

#[cfg(not(horizon_uploader_freeze_fixture))]
pub(super) const ORIGINAL: &str =
    "/etc/systemd/system/horizon-r2-progressive-epochs101-200-v21-rust-authenticated.service";

#[cfg(not(horizon_uploader_freeze_fixture))]
pub(super) const PRESERVED: &str =
    "/etc/systemd/system/.horizon-uploader-v21-original-preserved-freeze-fence-20261103-v1";

#[cfg(not(horizon_uploader_freeze_fixture))]
pub(super) const OUTPUT: &str = "/var/lib/jetstreamer/horizon-uploader-freeze-fence-20261103-v1";

#[cfg(horizon_uploader_freeze_fixture)]
#[path = "fixture_profile.rs"]
mod fixture_profile;
#[cfg(horizon_uploader_freeze_fixture)]
pub(super) use fixture_profile::{CGROUP, ORIGINAL, OUTPUT, UNIT};
#[cfg(horizon_uploader_freeze_fixture)]
pub(super) const PRESERVED: &str = fixture_profile::PRESERVED;
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Bound {
    pub(super) path: PathBuf,
    pub(super) sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SleepChild {
    pub(super) pid: u32,
    pub(super) start_ticks: u64,
    pub(super) program: Bound,
    pub(super) seconds: u32,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Plan {
    pub(super) schema: String,
    pub(super) unit: String,
    pub(super) invocation_id: String,
    pub(super) main_pid: u32,
    pub(super) start_ticks: u64,
    pub(super) kind: String,
    pub(super) program: Bound,
    pub(super) wrapper: Bound,
    pub(super) command_line: Vec<String>,
    pub(super) expected_exec_start: String,
    pub(super) expected_control_group: String,
    pub(super) memory_max: String,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) sleep_child: Option<SleepChild>,
    pub(super) frozen: bool,
    pub(super) pre_freeze_receipt: Option<Bound>,
    pub(super) output: PathBuf,
    pub(super) source_files: Vec<Bound>,
}
fn bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let mut f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open bounded census {}", path.display()))?;
    let mut raw = Vec::new();
    Read::by_ref(&mut f)
        .take(maximum as u64 + 1)
        .read_to_end(&mut raw)?;
    ensure!(raw.len() <= maximum, "census input exceeds bound");
    Ok(raw)
}
fn text(path: &Path) -> Result<String> {
    String::from_utf8(bounded(path, 65536)?).context("census UTF-8")
}
pub(super) fn image(b: &Bound) -> Result<()> {
    let system = matches!(b.path.to_str(), Some("/usr/bin/bash" | "/usr/bin/sleep"));
    evidence::bound_file(&b.path, &b.sha256, 64 << 20, !system)?;
    Ok(())
}
fn integers(raw: &str, maximum: usize) -> Result<Vec<u32>> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for word in raw.split_whitespace() {
        let pid = word.parse::<u32>()?;
        ensure!(
            pid > 1 && seen.insert(pid),
            "zero, reserved or duplicate PID"
        );
        out.push(pid);
        ensure!(out.len() <= maximum, "PID census exceeds bound");
    }
    out.sort_unstable();
    Ok(out)
}
fn stat_identity(raw: &str) -> Result<(u32, u64)> {
    let (_, tail) = raw
        .rsplit_once(')')
        .context("process stat command delimiter")?;
    let fields = tail.split_whitespace().collect::<Vec<_>>();
    ensure!(fields.len() >= 20, "short process stat");
    Ok((fields[1].parse()?, fields[19].parse()?))
}
fn field<'a>(raw: &'a str, name: &str) -> Result<&'a str> {
    let values = raw
        .lines()
        .filter_map(|s| s.strip_prefix(name))
        .collect::<Vec<_>>();
    ensure!(
        values.len() == 1,
        "missing or duplicate process status field"
    );
    Ok(values[0].trim())
}
pub(super) fn shape(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "horizon-uploader-freeze-census-plan-v1"
            && p.unit == UNIT
            && p.kind == "coordinator"
            && p.sleep_child.is_none()
            && p.uid == 1001
            && p.gid == 1003,
        "wrong sole uploader profile"
    );
    #[cfg(not(horizon_uploader_freeze_fixture))]
    ensure!(
        p.invocation_id == "7ac4617f73ab4f979a8527cce461c6a4"
            && p.main_pid == 3204661
            && p.program.path
                == Path::new(
                    "/usr/local/lib/jetstreamer/horizon-r2-rust-20261017-v3-auth-only/jetstreamer-r2-progressive"
                )
            && p.program.sha256
                == "1eede7d15cec7e5b1907ee44328caf2b20457ca8513472ca17e83fe3e08f9087"
            && p.wrapper.path
                == Path::new(
                    "/usr/local/lib/jetstreamer/horizon-cohort183-uploader-transition-20261029-v2/upload-progressive.zsh"
                )
            && p.wrapper.sha256
                == "d9b3bc9c64664b17f9da7275834abb01f7e00fec4d2257c8aa92156d185e07f3",
        "production uploader generation differs"
    );
    #[cfg(horizon_uploader_freeze_fixture)]
    ensure!(
        p.program.path
            == Path::new(
                "/usr/local/lib/jetstreamer/horizon-uploader-freeze-fixture-tools-20261103-v1/waiter"
            )
            && p.wrapper.path == p.program.path,
        "foreign fixture image"
    );
    ensure!(
        p.invocation_id.len() == 32
            && p.invocation_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && p.main_pid > 1
            && p.start_ticks > 0,
        "invalid native owner identity"
    );
    ensure!(
        p.expected_control_group == CGROUP
            && !p.expected_exec_start.is_empty()
            && p.expected_exec_start.len() <= 32768,
        "foreign native scope"
    );
    ensure!(
        p.memory_max == "infinity",
        "legacy uploader infinite cap must remain an honest fact"
    );
    ensure!(
        p.output.parent() == Some(Path::new(OUTPUT)),
        "foreign uploader receipt root"
    );
    validate_sources(p)?;
    ensure!(
        !p.command_line.is_empty()
            && p.command_line.len() <= 64
            && p.command_line
                .iter()
                .all(|s| !s.contains('\0') && s.len() <= 8192),
        "unbounded command identity"
    );
    ensure!(
        matches!(p.kind.as_str(), "coordinator" | "shell"),
        "unknown idle role"
    );
    if let Some(s) = &p.sleep_child {
        ensure!(
            p.kind == "shell"
                && s.pid > 1
                && s.pid != p.main_pid
                && s.start_ticks > 0
                && (1..=600).contains(&s.seconds)
                && s.program.path == Path::new("/usr/bin/sleep"),
            "foreign sleep child"
        );
    }
    if p.kind == "shell" {
        ensure!(
            p.sleep_child.is_some() && p.program.path == Path::new("/usr/bin/bash"),
            "shell census needs exact Bash and idle sleep child"
        );
    }
    ensure!(
        p.frozen == p.pre_freeze_receipt.is_some(),
        "freeze phase/predecessor mismatch"
    );
    Ok(())
}

fn validate_sources(p: &Plan) -> Result<()> {
    #[cfg(not(horizon_uploader_freeze_fixture))]
    let expected = vec![
        (
            ORIGINAL,
            "84f38e11624b2e6f1a5a39a6118f806990d0b88b3d2c372b30e3dcdba605fa62",
        ),
        (
            "/etc/systemd/system/horizon-r2-progressive-epochs101-200-v21-rust-authenticated.service.d/50-native198-receipts.conf",
            "d30674cd19a0a702f201eb0f0100d31594ff180d7613fdc6eadbfeac60600640",
        ),
        (
            "/etc/systemd/system/horizon-r2-progressive-epochs101-200-v21-rust-authenticated.service.d/60-native183-receipts.conf",
            "d2a82a817becf0cf30be4cb3cff98bdffbe62b1ea7513b1f7de0978046aad5fe",
        ),
    ];
    #[cfg(horizon_uploader_freeze_fixture)]
    let expected = vec![(
        ORIGINAL,
        p.source_files
            .first()
            .context("fixture source")?
            .sha256
            .as_str(),
    )];
    ensure!(
        p.source_files.len() == expected.len(),
        "source cover set differs"
    );
    for (bound, (path, sha)) in p.source_files.iter().zip(expected) {
        ensure!(
            bound.path == Path::new(path) && bound.sha256 == sha,
            "unit source binding differs"
        );
        evidence::bound_file(&bound.path, &bound.sha256, 65536, false)?;
    }
    Ok(())
}

pub(super) fn scope_hash(p: &Plan) -> Result<String> {
    let mut v = serde_json::to_value(p)?;
    let map = v.as_object_mut().context("plan object")?;
    for k in ["frozen", "pre_freeze_receipt", "output"] {
        map.remove(k);
    }
    Ok(evidence::sha(&serde_json::to_vec(&v)?))
}
pub(super) fn unit(name: &str) -> Result<Value> {
    let keys = "Id,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,NRestarts,ExecStart,ControlGroup,Restart,Triggers,TriggeredBy,Job,Delegate,MemoryMax,StandardInput,StandardOutput,StandardError,FreezerState,KillMode,KillSignal,FinalKillSignal,SendSIGKILL,RestartUSec,FragmentPath,DropInPaths";
    let out = Command::new("/usr/bin/systemctl")
        .args(["show", name, "--no-pager", &format!("--property={keys}")])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 65536,
        "native census query failed or oversized"
    );
    let mut map = serde_json::Map::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("native property delimiter")?;
        ensure!(
            map.insert(k.into(), v.into()).is_none(),
            "duplicate native property"
        );
    }
    Ok(map.into())
}
pub(super) fn validate_unit(v: &Value, p: &Plan) -> Result<()> {
    let expected_dropins = p
        .source_files
        .iter()
        .skip(1)
        .map(|b| b.path.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    ensure!(
        v["DropInPaths"] == expected_dropins,
        "effective source drop-in census differs"
    );
    for (k, want) in [
        ("Id", p.unit.clone()),
        ("LoadState", "loaded".into()),
        ("ActiveState", "active".into()),
        ("SubState", "running".into()),
        ("MainPID", p.main_pid.to_string()),
        ("ControlPID", "0".into()),
        ("InvocationID", p.invocation_id.clone()),
        ("NRestarts", "0".into()),
        ("ExecStart", p.expected_exec_start.clone()),
        ("ControlGroup", p.expected_control_group.clone()),
        ("Restart", "on-failure".into()),
        (
            "FreezerState",
            if p.frozen {
                "frozen".into()
            } else {
                "running".into()
            },
        ),
        ("Triggers", "".into()),
        ("TriggeredBy", "".into()),
        ("Job", "".into()),
        ("Delegate", "no".into()),
        ("MemoryMax", p.memory_max.clone()),
        ("KillMode", "control-group".into()),
        ("KillSignal", "15".into()),
        ("FinalKillSignal", "9".into()),
        ("SendSIGKILL", "yes".into()),
        ("RestartUSec", "30s".into()),
        ("FragmentPath", ORIGINAL.into()),
        ("StandardInput", "null".into()),
        ("StandardOutput", "journal".into()),
        ("StandardError", "inherit".into()),
    ] {
        ensure!(
            v[k] == want,
            "idle native owner or launch custody differs: {k}"
        );
    }
    Ok(())
}
fn fd_allowed(fd: u32, target: &str, flags: u64, kind: &str, p: &Plan) -> bool {
    match fd {
        0 => target == "/dev/null" && kind == "character" && (flags & 3) == 0,
        1 | 2 => {
            (target == "/dev/null" && kind == "character")
                || ((target.starts_with("socket:[") || target.starts_with("pipe:["))
                    && target.ends_with(']')
                    && matches!(kind, "socket" | "fifo"))
        }
        255 => {
            p.kind == "shell"
                && target == p.wrapper.path.to_str().unwrap_or("")
                && kind == "regular"
                && (flags & 3) == 0
        }
        _ => {
            p.kind == "coordinator"
                && matches!(target, "anon_inode:[eventpoll]" | "anon_inode:[eventfd]")
        }
    }
}
fn fd_census(root: &Path, p: &Plan) -> Result<Value> {
    let mut rows = Vec::new();
    let mut entries = fs::read_dir(root.join("fd"))?.collect::<std::io::Result<Vec<_>>>()?;
    ensure!(entries.len() <= 256, "too many descriptors");
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let fd = e.file_name().to_str().context("FD name")?.parse::<u32>()?;
        let target = fs::read_link(e.path())?;
        let target = target.to_str().context("FD target UTF-8")?;
        let m = fs::metadata(e.path())?;
        let mode = m.mode() & libc::S_IFMT;
        let kind = match mode {
            libc::S_IFREG => "regular",
            libc::S_IFCHR => "character",
            libc::S_IFSOCK => "socket",
            libc::S_IFIFO => "fifo",
            _ => "other",
        };
        let info = text(&root.join(format!("fdinfo/{fd}")))?;
        let flags = u64::from_str_radix(field(&info, "flags:")?, 8)?;
        ensure!(
            fd_allowed(fd, target, flags, kind, p),
            "work or unknown descriptor retained: {fd}"
        );
        rows.push(json!({"fd":fd,"target":target,"flags":flags,"device":m.dev(),"inode":m.ino(),"kind":kind}));
    }
    ensure!(
        rows.iter().any(|v| v["fd"] == 0)
            && rows.iter().any(|v| v["fd"] == 1)
            && rows.iter().any(|v| v["fd"] == 2),
        "missing standard descriptor custody"
    );
    Ok(json!(rows))
}
fn map_allowed(path: &str, executable: bool, p: &Plan) -> bool {
    if path.is_empty() {
        return !executable;
    }
    if path.starts_with('[') {
        return !executable || matches!(path, "[vdso]" | "[vsyscall]");
    }
    if path.ends_with(" (deleted)") {
        return false;
    }
    let path = Path::new(path);
    path == p.program.path
        || p.sleep_child
            .as_ref()
            .is_some_and(|s| path == s.program.path)
        || ["/usr/bin", "/usr/lib", "/usr/lib64", "/lib", "/lib64"]
            .iter()
            .any(|root| path.starts_with(root))
}
fn maps_census(root: &Path, p: &Plan) -> Result<Value> {
    let raw = String::from_utf8(bounded(&root.join("maps"), 1 << 20)?)?;
    let mut n = 0usize;
    for line in raw.lines() {
        let mut rest = line;
        let mut fields = Vec::new();
        for _ in 0..5 {
            rest = rest.trim_start();
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            fields.push(&rest[..end]);
            rest = &rest[end..];
        }
        ensure!(
            fields.len() == 5 && fields[1].len() == 4,
            "malformed maps row"
        );
        let path = rest.trim_start();
        ensure!(
            map_allowed(path, fields[1].as_bytes()[2] == b'x', p),
            "work or unknown mapping retained"
        );
        n += 1;
        ensure!(n <= 8192, "too many process mappings");
    }
    Ok(json!({"rows":n,"raw_sha256":evidence::sha(raw.as_bytes()),"raw":raw}))
}
fn default_term(status: &str) -> Result<()> {
    let term = 1u64 << (libc::SIGTERM - 1);
    ensure!(
        u64::from_str_radix(field(status, "SigIgn:")?, 16)? & term == 0
            && u64::from_str_radix(field(status, "SigCgt:")?, 16)? & term == 0
            && u64::from_str_radix(field(status, "SigBlk:")?, 16)? & term == 0,
        "uploader does not retain default SIGTERM handling"
    );
    Ok(())
}
fn process(
    pid: u32,
    start: u64,
    program: &Bound,
    cmd: &[String],
    parent: Option<u32>,
    p: &Plan,
) -> Result<Value> {
    let root = PathBuf::from(format!("/proc/{pid}"));
    let stat = text(&root.join("stat"))?;
    let (ppid, ticks) = stat_identity(&stat)?;
    ensure!(
        ticks == start && parent.is_none_or(|v| v == ppid),
        "reused or reparented process"
    );
    let actual = fs::read_link(root.join("exe"))?;
    let disk = fs::metadata(&program.path)?;
    let mapped = fs::metadata(root.join("exe"))?;
    ensure!(
        actual == program.path && disk.dev() == mapped.dev() && disk.ino() == mapped.ino(),
        "process executable identity differs"
    );
    let raw = bounded(&root.join("cmdline"), 65536)?;
    ensure!(raw.last() == Some(&0), "unterminated process command");
    let actual_cmd = raw[..raw.len() - 1]
        .split(|b| *b == 0)
        .map(|b| std::str::from_utf8(b).map(str::to_owned))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(actual_cmd == cmd, "process command differs");
    let status = text(&root.join("status"))?;
    default_term(&status)?;
    let uids = integers_allow_zero(field(&status, "Uid:")?)?;
    let gids = integers_allow_zero(field(&status, "Gid:")?)?;
    ensure!(
        uids == vec![p.uid; 4] && gids == vec![p.gid; 4],
        "process credentials differ"
    );
    let mut tasks = fs::read_dir(root.join("task"))?.collect::<std::io::Result<Vec<_>>>()?;
    ensure!(
        tasks.len() == 1 && tasks[0].file_name().to_str() == Some(pid.to_string().as_str()),
        "extra or foreign process thread"
    );
    let child_text = text(&tasks.pop().context("process task")?.path().join("children"))?;
    let children = integers(&child_text, 2)?;
    let environment = bounded(&root.join("environ"), 1 << 20)?;
    ensure!(
        !environment
            .split(|b| *b == 0)
            .any(|s| s.starts_with(b"LD_") || s.starts_with(b"GLIBC_TUNABLES=")),
        "dynamic loader override on idle process"
    );
    let wchan = text(&root.join("wchan"))?.trim().to_owned();
    if !p.frozen {
        ensure!(
            wchan
                == if p.kind == "shell" && pid == p.main_pid {
                    "do_wait"
                } else {
                    "hrtimer_nanosleep"
                },
            "process is not in its exact idle wait"
        );
    }
    let files = fd_census(&root, p)?;
    let maps = maps_census(&root, p)?;
    let end = text(&root.join("stat"))?;
    ensure!(
        stat_identity(&end)? == (ppid, ticks),
        "process changed during census"
    );
    Ok(
        json!({"pid":pid,"parent":ppid,"start_ticks":ticks,"program":actual,"device":mapped.dev(),"inode":mapped.ino(),"command_line":actual_cmd,"children":children,"thread_count":1,"sig_ignored":field(&status,"SigIgn:")?,"sig_caught":field(&status,"SigCgt:")?,"sig_blocked":field(&status,"SigBlk:")?,"wchan":wchan,"descriptors":files,"maps":maps}),
    )
}
fn integers_allow_zero(raw: &str) -> Result<Vec<u32>> {
    let out = raw
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(out.len() == 4, "credential field width differs");
    Ok(out)
}
pub(super) fn snapshot(p: &Plan) -> Result<Value> {
    snapshot_at_memory_limit(p, "max")
}

pub(super) fn snapshot_at_memory_limit(p: &Plan, expected_memory_max: &str) -> Result<Value> {
    let cg = PathBuf::from("/sys/fs/cgroup").join(p.expected_control_group.trim_start_matches('/'));
    ensure!(
        cg.canonicalize()? == cg && fs::symlink_metadata(&cg)?.is_dir(),
        "foreign cgroup directory"
    );
    for e in fs::read_dir(&cg)? {
        ensure!(
            !e?.file_type()?.is_dir(),
            "nested delivery cgroup is not classified"
        );
    }
    let memory_max = text(&cg.join("memory.max"))?.trim().to_owned();
    let memory_swap_max = text(&cg.join("memory.swap.max"))?.trim().to_owned();
    ensure!(
        memory_max == expected_memory_max,
        "actual cgroup memory cap differs from the declared phase"
    );
    let members = integers(&text(&cg.join("cgroup.procs"))?, 2)?;
    let frozen = text(&cg.join("cgroup.events"))?
        .lines()
        .any(|s| s == "frozen 1");
    ensure!(frozen == p.frozen, "actual cgroup freeze state differs");
    let main = process(
        p.main_pid,
        p.start_ticks,
        &p.program,
        &p.command_line,
        None,
        p,
    )?;
    let mut expected = vec![p.main_pid];
    let child = if let Some(c) = &p.sleep_child {
        expected.push(c.pid);
        let v = process(
            c.pid,
            c.start_ticks,
            &c.program,
            &[c.program.path.display().to_string(), c.seconds.to_string()],
            Some(p.main_pid),
            p,
        )?;
        ensure!(v["children"] == json!([]), "sleep child has descendants");
        ensure!(
            main["children"] == json!([c.pid]),
            "shell child census differs"
        );
        Some(v)
    } else {
        ensure!(main["children"] == json!([]), "coordinator has a child");
        None
    };
    expected.sort_unstable();
    ensure!(members == expected, "unclassified cgroup process");
    ensure!(
        integers(&text(&cg.join("cgroup.procs"))?, 2)? == members
            && text(&cg.join("cgroup.events"))?
                .lines()
                .any(|line| line == "frozen 1")
                == frozen,
        "cgroup changed across process census"
    );
    Ok(
        json!({"main":main,"idle_sleep_child":child,"cgroup_processes":members,"cgroup_frozen":frozen,"no_work_descriptors_or_mappings":true,"actual_memory_max":memory_max,"actual_memory_swap_max":memory_swap_max}),
    )
}
pub(super) fn capture(p: &Plan, plan: &Bound, self_sha: &str) -> Result<Value> {
    shape(p)?;
    image(&p.program)?;
    image(&p.wrapper)?;
    if let Some(s) = &p.sleep_child {
        image(&s.program)?;
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let scope = scope_hash(p)?;
    if let Some(b) = &p.pre_freeze_receipt {
        let previous: Value =
            serde_json::from_slice(&evidence::bound_file(&b.path, &b.sha256, 1 << 20, false)?)?;
        let time = previous["recorded_unix_seconds"]
            .as_u64()
            .context("pre-freeze clock")?;
        ensure!(
            previous["schema"] == "horizon-uploader-freeze-census-proof-v1"
                && previous["scope_sha256"] == scope
                && previous["frozen"] == false
                && previous["idle_census_proven"] == true
                && time <= now
                && now - time <= 60,
            "stale or foreign pre-freeze proof"
        );
    }
    let before = unit(&p.unit)?;
    validate_unit(&before, p)?;
    let first = snapshot(p)?;
    let after = unit(&p.unit)?;
    validate_unit(&after, p)?;
    let second = snapshot(p)?;
    ensure!(
        before == after && first == second,
        "owner or process census changed"
    );
    let final_unit = unit(&p.unit)?;
    validate_unit(&final_unit, p)?;
    ensure!(
        after == final_unit,
        "native owner changed after final census"
    );
    image(&p.program)?;
    image(&p.wrapper)?;
    if let Some(child) = &p.sleep_child {
        image(&child.program)?;
    }
    let parent = p.output.parent().context("output parent")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        parent.is_absolute()
            && parent.canonicalize()? == parent
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o077 == 0,
        "unsafe private receipt directory"
    );
    let proof = json!({"schema":"horizon-uploader-freeze-census-proof-v1","recorded_unix_seconds":now,"scope_sha256":scope,"plan":plan,"self_sha256":self_sha,"unit":after,"snapshot":second,"idle_census_proven":true,"frozen":p.frozen,"pre_freeze_receipt":p.pre_freeze_receipt,"signal_sent":false,"service_state_changed":false,"archive_mutations":false,"R2_mutations":false,"memory_credit_bytes":0,"stop_or_migration_authorized":false});
    Ok(proof)
}
pub(super) fn run_cli() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let a = env::args().skip(1).collect::<Vec<_>>();
    ensure!(a.len() == 3, "usage PLAN PLAN_SHA SELF_SHA");
    let exe = fs::read_link("/proc/self/exe")?;
    evidence::bound_file(&exe, &a[2], 64 << 20, true)?;
    let plan = Bound {
        path: a[0].clone().into(),
        sha256: a[1].clone(),
    };
    let p: Plan = serde_json::from_slice(&evidence::bound_file(
        &plan.path,
        &plan.sha256,
        65536,
        true,
    )?)?;
    let proof = capture(&p, &plan, &a[2])?;
    evidence::write_receipt(&p.output, &proof)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn p() -> Plan {
        serde_json::from_str(include_str!("test-plan.json")).unwrap()
    }
    #[test]
    fn sigterm_ignored_or_caught_rejects() {
        default_term(
            "SigIgn:\t0000000000000000\nSigCgt:\t0000000000000000\nSigBlk:\t0000000000000000\n",
        )
        .unwrap();
        let term = 1u64 << (libc::SIGTERM - 1);
        assert!(
            default_term(&format!(
                "SigIgn:\t0000000000000000\nSigCgt:\t0000000000000000\nSigBlk:\t{term:016x}\n"
            ))
            .is_err()
        );
        for key in ["SigIgn", "SigCgt"] {
            let status = if key == "SigIgn" {
                format!(
                    "SigIgn:\t{term:016x}\nSigCgt:\t0000000000000000\nSigBlk:\t0000000000000000\n"
                )
            } else {
                format!(
                    "SigIgn:\t0000000000000000\nSigCgt:\t{term:016x}\nSigBlk:\t0000000000000000\n"
                )
            };
            assert!(default_term(&status).is_err());
        }
    }
    #[test]
    fn unknown_or_archive_descriptor_is_work() {
        let p = p();
        assert!(fd_allowed(0, "/dev/null", 0, "character", &p));
        assert!(!fd_allowed(5, "/tmp/archive.jet", 0, "regular", &p));
        assert!(!fd_allowed(5, "socket:[37]", 2, "socket", &p));
        assert!(!fd_allowed(5, "/dev/null", 0, "character", &p));
        assert!(!fd_allowed(255, "/tmp/wrapper", 0, "regular", &p));
    }
    #[test]
    fn working_mapping_and_deleted_image_reject() {
        let p = p();
        assert!(!map_allowed("/tmp/archive.jet", false, &p));
        assert!(!map_allowed("/usr/lib/libc.so (deleted)", true, &p));
        assert!(!map_allowed("", true, &p));
    }
    #[test]
    fn freeze_scope_cannot_borrow_another_owner() {
        let p = p();
        let h = scope_hash(&p).unwrap();
        let mut frozen = p.clone();
        frozen.frozen = true;
        frozen.output = "/private/frozen.json".into();
        frozen.pre_freeze_receipt = Some(Bound {
            path: "/private/pre.json".into(),
            sha256: "a".repeat(64),
        });
        assert_eq!(h, scope_hash(&frozen).unwrap());
        frozen.start_ticks += 1;
        assert_ne!(h, scope_hash(&frozen).unwrap());
    }
}
