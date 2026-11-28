//! Authenticate the ACTUAL held native process, never caller-provided PID totals.
use super::*;
const FIELDS: &str = "--property=Id,LoadState,InvocationID,MainPID,ControlPID,NRestarts,Restart,Type,User,MemoryAccounting,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,NoNewPrivileges,PrivateNetwork,EnvironmentFiles,ActiveState,SubState,Result,ExecMainStatus,RemainAfterExit,ControlGroup,Job,ExecStart,ExecMainStartTimestampMonotonic";
pub(super) fn allowed_unit(unit: &str) -> bool {
    [ACTOR, ISSUER, super::provenance::CURRENT_DOWNLOAD_UNIT].contains(&unit)
        || (unit.starts_with("horizon-epoch163-snapshot-download-")
            && unit.ends_with(".service")
            && unit.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c)))
}
pub(super) fn native(unit: &str) -> Result<Value> {
    ensure!(allowed_unit(unit), "native metadata unit scope");
    let out = ProcessCommand::new("/usr/bin/systemctl")
        .args(["show", unit, "--no-pager", FIELDS])
        .env("LC_ALL", "C")
        .env_remove("SYSTEMD_HOST")
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 65536,
        "native metadata query"
    );
    let mut obj = serde_json::Map::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("native property framing")?;
        ensure!(
            obj.insert(k.into(), json!(v)).is_none(),
            "duplicate native property"
        );
    }
    Ok(Value::Object(obj))
}
pub(super) fn command(n: &Value, image: &Path, args: &[String]) -> Result<()> {
    let raw = n["ExecStart"].as_str().context("native exact ExecStart")?;
    let (head, tail) = raw
        .split_once(" ; ignore_errors=")
        .context("native ExecStart framing")?;
    ensure!(
        head == format!("{{ path={} ; argv[]={}", image.display(), args.join(" "))
            && tail.starts_with("no ; "),
        "native image/argv/ignore-errors changed"
    );
    Ok(())
}
fn bounded(path: &Path, cap: u64) -> Result<Vec<u8>> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let mut out = Vec::new();
    Read::by_ref(&mut f).take(cap + 1).read_to_end(&mut out)?;
    ensure!(out.len() as u64 <= cap, "native proc bound");
    Ok(out)
}
fn ticks(pid: u32) -> Result<u64> {
    let bytes = bounded(&PathBuf::from(format!("/proc/{pid}/stat")), 65536)?;
    let text = std::str::from_utf8(&bytes)?;
    let rest = text.rsplit_once(") ").context("native proc stat")?.1;
    ensure!(
        !rest.starts_with('Z') && !rest.starts_with('X'),
        "native actor dead/zombie"
    );
    Ok(rest
        .split_whitespace()
        .nth(19)
        .context("native start ticks")?
        .parse()?)
}
pub(super) fn mapped(pid: u32, image: &Bound, args: &[String]) -> Result<()> {
    storage::bytes(image, 256 << 20, true)?;
    let proc = PathBuf::from(format!("/proc/{pid}/exe"));
    ensure!(
        fs::read_link(&proc)? == image.path,
        "native mapped source path changed"
    );
    let mut file = File::open(&proc)?;
    let m = file.metadata()?;
    let named = fs::metadata(&image.path)?;
    ensure!(
        (m.dev(), m.ino(), m.len()) == (named.dev(), named.ino(), named.len()),
        "native mapped image inode changed"
    );
    let mut hash = Sha256::new();
    let mut buf = [0u8; 65536];
    let mut size = 0u64;
    loop {
        let got = file.read(&mut buf)?;
        if got == 0 {
            break;
        }
        size = size
            .checked_add(got as u64)
            .context("native image overflow")?;
        ensure!(size <= m.len(), "native image grew");
        hash.update(&buf[..got]);
    }
    ensure!(
        size == m.len() && hex_lower(&hash.finalize()) == image.sha256,
        "native actual mapped image digest"
    );
    let raw = bounded(&PathBuf::from(format!("/proc/{pid}/cmdline")), 1 << 20)?;
    ensure!(raw.last() == Some(&0), "native argv framing");
    let actual = raw[..raw.len() - 1]
        .split(|b| *b == 0)
        .map(|b| Ok(std::str::from_utf8(b)?.to_owned()))
        .collect::<Result<Vec<_>>>()?;
    ensure!(actual == args, "native actual proc argv differs");
    Ok(())
}
fn identity(m: &fs::Metadata) -> Value {
    json!({"device":m.dev(),"inode":m.ino(),"length":m.len(),"uid":m.uid(),"gid":m.gid(),"mode":m.mode(),"links":m.nlink(),"mtime":m.mtime(),"mtime_nsec":m.mtime_nsec(),"ctime":m.ctime(),"ctime_nsec":m.ctime_nsec()})
}
fn ready(p: &NativePlan, pb: &Bound, pid: u32, iid: &str) -> Result<Value> {
    let path = p.state.join("ready.json");
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o777 == 0o600
            && before.len() <= 65536,
        "native original writer-ready custody"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(65537)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.len()
            && identity(&before) == identity(&file.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(path)?),
        "native ready changed"
    );
    let v: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        v == json!({"schema":"epoch163-native-input-held-v1","plan":pb,"iid":iid,"pid":pid,"snapshot_body_opened":false}),
        "native exact held ready writer/process binding"
    );
    let t = now()?;
    let modified = u64::try_from(before.mtime()).context("native ready time")?;
    ensure!(
        modified <= t && t - modified < 110,
        "native original ready window expired"
    );
    Ok(json!({"original_bytes_sha256":storage::sha(&bytes),"identity":identity(&before),"value":v}))
}
fn caps(status: &str) -> Result<Value> {
    let mut out = json!({});
    for key in ["CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd"] {
        let prefix = format!("{key}:");
        let value = status
            .lines()
            .find_map(|s| s.strip_prefix(&prefix))
            .context("native capability field missing")?
            .trim();
        let bits = u64::from_str_radix(value, 16)?;
        ensure!(bits & (1 << 21) == 0, "held native retains SYS_ADMIN");
        out[key] = json!(value);
    }
    for (key, expected) in [("NoNewPrivs", "1"), ("Uid", "0\t0\t0\t0")] {
        let prefix = format!("{key}:");
        let actual = status
            .lines()
            .find_map(|s| s.strip_prefix(&prefix))
            .context("native status identity")?
            .trim();
        ensure!(actual == expected, "native held status {key}");
        out[key] = json!(actual);
    }
    Ok(out)
}
fn statvfs(path: &Path) -> Result<libc::statvfs> {
    let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let mut out = std::mem::MaybeUninit::uninit();
    ensure!(
        unsafe { libc::statvfs(name.as_ptr(), out.as_mut_ptr()) } == 0,
        "held namespace statvfs"
    );
    Ok(unsafe { out.assume_init() })
}
fn rooted(pid: u32, path: &Path) -> Result<PathBuf> {
    ensure!(path.is_absolute(), "native absolute namespace path");
    Ok(PathBuf::from(format!("/proc/{pid}/root")).join(path.strip_prefix("/")?))
}
fn namespaces(pid: u32, p: &NativePlan) -> Result<Value> {
    let ns = fs::read_link(format!("/proc/{pid}/ns/mnt"))?;
    ensure!(
        ns != fs::read_link("/proc/self/ns/mnt")?,
        "held native requires distinct mount namespace"
    );
    let info = bounded(&PathBuf::from(format!("/proc/{pid}/mountinfo")), 4 << 20)?;
    ensure!(!info.is_empty(), "native mountinfo absent");
    let mut sources = Vec::new();
    for path in [&p.snapshot, &p.ledger] {
        let target = rooted(pid, path)?;
        let original = fs::symlink_metadata(path)?;
        let actual = fs::metadata(&target)?;
        ensure!(
            (actual.dev(), actual.ino()) == (original.dev(), original.ino())
                && statvfs(&target)?.f_flag & libc::ST_RDONLY != 0,
            "held actor source identity/read-only namespace"
        );
        sources.push(json!({"path":path,"identity":identity(&actual),"read_only":true}));
    }
    let scratch = rooted(pid, &p.scratch)?;
    let sv = statvfs(&scratch)?;
    let name = std::ffi::CString::new(scratch.as_os_str().as_encoded_bytes())?;
    let mut sf = std::mem::MaybeUninit::<libc::statfs>::uninit();
    ensure!(
        unsafe { libc::statfs(name.as_ptr(), sf.as_mut_ptr()) } == 0,
        "native scratch statfs"
    );
    let sf = unsafe { sf.assume_init() };
    let bytes = sv
        .f_blocks
        .checked_mul(sv.f_frsize)
        .context("native scratch overflow")?;
    ensure!(
        sf.f_type == libc::TMPFS_MAGIC
            && bytes > 0
            && bytes <= SCRATCH
            && sv.f_files > 0
            && sv.f_files <= INODES
            && sv.f_flag & (libc::ST_NOSUID | libc::ST_NODEV) == libc::ST_NOSUID | libc::ST_NODEV
            && sv.f_flag & (libc::ST_NOEXEC | libc::ST_RDONLY) == 0
            && fs::read_dir(&scratch)?.next().is_none(),
        "held native fresh executable bounded nosuid/nodev tmpfs"
    );
    ensure!(
        fs::metadata(&scratch)?.dev() != fs::metadata(rooted(pid, &p.protected_filesystem)?)?.dev()
            && fs::metadata(rooted(pid, &p.ledger)?)?.dev()
                == fs::metadata(rooted(pid, &p.protected_filesystem)?)?.dev(),
        "held DATA/ledger/scratch device isolation"
    );
    let environment = bounded(&PathBuf::from(format!("/proc/{pid}/environ")), 1 << 20)?;
    for k in ["TMPDIR", "TMP", "TEMP"] {
        let prefix = format!("{k}=");
        let entries = environment
            .split(|c| *c == 0)
            .filter(|v| v.starts_with(prefix.as_bytes()))
            .collect::<Vec<_>>();
        let expected = format!("{k}={}", p.scratch.display());
        ensure!(
            entries.len() == 1 && entries[0] == expected.as_bytes(),
            "native scratch environment binding"
        );
    }
    ensure!(
        !environment
            .split(|c| *c == 0)
            .any(|v| v.starts_with(b"LD_") || v.starts_with(b"GLIBC_TUNABLES=")),
        "held actor loader override"
    );
    let mut invocation = b"INVOCATION_ID=".to_vec();
    invocation.extend_from_slice(
        native(ACTOR)?["InvocationID"]
            .as_str()
            .context("held IID")?
            .as_bytes(),
    );
    ensure!(
        environment
            .split(|c| *c == 0)
            .filter(|v| v.starts_with(b"INVOCATION_ID="))
            .collect::<Vec<_>>()
            == vec![invocation.as_slice()],
        "held original environment IID"
    );
    let snap = fs::metadata(&p.snapshot)?;
    for fd in fs::read_dir(format!("/proc/{pid}/fd"))? {
        let fd = fd?.path();
        let m = fs::metadata(&fd)?;
        ensure!(
            (m.dev(), m.ino()) != (snap.dev(), snap.ino()),
            "held actor already opened snapshot body"
        );
    }
    let maps = bounded(&PathBuf::from(format!("/proc/{pid}/maps")), 64 << 20)?;
    let count = maps
        .split(|c| *c == b'\n')
        .filter(|v| !v.is_empty())
        .count() as u64;
    ensure!(
        count < VMA
            && fs::read_to_string("/proc/sys/vm/max_map_count")?
                .trim()
                .parse::<u64>()?
                > VMA,
        "held actor VMA limit"
    );
    ensure!(
        !std::str::from_utf8(&maps)?.contains(p.snapshot.to_str().context("snapshot UTF8")?),
        "held actor mapped snapshot before admission"
    );
    Ok(
        json!({"mount_namespace":ns,"mountinfo_sha256":storage::sha(&info),"sources":sources,"scratch_identity":identity(&fs::metadata(&scratch)?),"scratch_bytes":bytes,"scratch_inodes":sv.f_files,"source_readonly":true,"scratch_executable":true,"held_vmas":count}),
    )
}
pub(super) fn capture(p: &NativePlan, pb: &Bound) -> Result<Value> {
    let n = native(ACTOR)?;
    let iid = n["InvocationID"].as_str().context("held native IID")?;
    let pid = n["MainPID"]
        .as_str()
        .context("held native PID")?
        .parse::<u32>()?;
    ensure!(
        storage::hex(iid, 32)
            && pid > 1
            && n["Id"] == ACTOR
            && n["LoadState"] == "loaded"
            && n["ControlPID"] == "0"
            && n["NRestarts"] == "0"
            && n["Restart"] == "no"
            && n["Type"] == "exec"
            && n["User"] == "root"
            && n["MemoryAccounting"] == "yes"
            && n["MemoryMax"].as_str() == Some(MEMORY.to_string().as_str())
            && n["MemorySwapMax"] == "0"
            && n["CPUQuotaPerSecUSec"] == "8s"
            && n["TasksMax"] == "512"
            && n["NoNewPrivileges"] == "yes"
            && n["PrivateNetwork"] == "yes"
            && n["ActiveState"] == "active"
            && n["SubState"] == "running"
            && n["Result"] == "success"
            && n["Job"] == ""
            && n["ControlGroup"] == format!("/system.slice/{ACTOR}"),
        "actual held native fixed service profile"
    );
    let args = vec![
        p.program.path.to_string_lossy().into_owned(),
        pb.path.to_string_lossy().into_owned(),
        "--plan-sha256".into(),
        pb.sha256.clone(),
        "--self-sha256".into(),
        p.program.sha256.clone(),
    ];
    command(&n, &p.program.path, &args)?;
    let start = ticks(pid)?;
    let clock = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    ensure!(clock > 0, "native tick rate");
    let mut boot = std::mem::MaybeUninit::<libc::timespec>::uninit();
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, boot.as_mut_ptr()) } == 0,
        "native monotonic clock"
    );
    let boot = unsafe { boot.assume_init() };
    let elapsed = u64::try_from(boot.tv_sec)?
        .checked_sub(start / u64::try_from(clock)?)
        .context("native start in future")?;
    // Conservative: age from true process creation, never from a supplied/replaced ready timestamp.
    ensure!(
        elapsed < 105,
        "native original120s held deadline has insufficient margin"
    );
    let cg = PathBuf::from(format!("/sys/fs/cgroup/system.slice/{ACTOR}"));
    ensure!(
        fs::read_to_string(format!("/proc/{pid}/cgroup"))?.trim()
            == format!("0::/system.slice/{ACTOR}")
            && fs::read_to_string(cg.join("cgroup.procs"))?
                .split_whitespace()
                .collect::<Vec<_>>()
                == vec![pid.to_string().as_str()]
            && fs::read_to_string(cg.join("memory.max"))?.trim() == MEMORY.to_string()
            && fs::read_to_string(cg.join("memory.swap.max"))?.trim() == "0",
        "held actor cgroup exact sole process/native memory controls"
    );
    mapped(pid, &p.program, &args)?;
    let proof = ready(p, pb, pid, iid)?;
    let status = String::from_utf8(bounded(
        &PathBuf::from(format!("/proc/{pid}/status")),
        65536,
    )?)?;
    let capabilities = caps(&status)?;
    let mounts = namespaces(pid, p)?;
    ensure!(
        ticks(pid)? == start
            && native(ACTOR)? == n
            && !p.admission.try_exists()?
            && !p.state.join("initial-guard.json").try_exists()?
            && fs::read_dir(rooted(pid, &p.scratch)?)?.next().is_none(),
        "native actor advanced/replaced during held validation"
    );
    Ok(
        json!({"iid":iid,"pid":pid,"start_ticks":start,"native":n,"ready":proof,"capabilities":capabilities,"namespace":mounts,"snapshot_body_opened":false}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_download_unit_is_additive_and_no_generic_bootstrap_scope_is_accepted() {
        assert!(allowed_unit(super::super::provenance::CURRENT_DOWNLOAD_UNIT));
        assert!(allowed_unit("horizon-epoch163-snapshot-download-20261106-v1.service"));
        for name in ["horizon-visible-bootstrap163-download-20261107-v2.service",
            "horizon-visible-bootstrap164-download-20261107-v1.service", "other.service",
            "horizon-epoch163-snapshot-download-evil/name.service"] {
            assert!(!allowed_unit(name), "{name}");
        }
    }
    #[test]
    fn capability_absence_must_cover_bounding_and_permitted_too() {
        let good = "CapEff:\t00000000\nCapPrm:\t00000000\nCapInh:\t00000000\nCapAmb:\t00000000\nCapBnd:\t00000000\nNoNewPrivs:\t1\nUid:\t0\t0\t0\t0\n";
        caps(good).unwrap();
        for k in ["CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd"] {
            assert!(
                caps(&good.replace(&format!("{k}:\t00000000"), &format!("{k}:\t00200000")))
                    .is_err()
            );
        }
        assert!(caps(&good.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0")).is_err());
    }
    #[test]
    fn command_rejects_argv_and_ignore_errors_changes() {
        let image = Path::new("/sealed/native");
        let args = vec!["/sealed/native".into(), "/sealed/plan".into()];
        let good = json!({"ExecStart":"{ path=/sealed/native ; argv[]=/sealed/native /sealed/plan ; ignore_errors=no ; start_time=[x] ; stop_time=[n/a] ; pid=42 ; code=(null) ; status=0/0 }"});
        command(&good, image, &args).unwrap();
        let mut bad = good.clone();
        bad["ExecStart"] = json!(
            good["ExecStart"]
                .as_str()
                .unwrap()
                .replace("ignore_errors=no", "ignore_errors=yes")
        );
        assert!(command(&bad, image, &args).is_err());
        assert!(
            command(
                &good,
                image,
                &["/sealed/native".into(), "/other/plan".into()]
            )
            .is_err()
        );
    }
}
