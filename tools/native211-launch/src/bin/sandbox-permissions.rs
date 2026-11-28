//! Disjoint native permissions fixture. Never invokes an epoch harness or touches its units.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
const SEALER: &str =
    "/var/lib/jetstreamer/horizon251-published-sealer-20261118-v1/horizon251-sealer";
const SEALER_SHA: &str = "faf7aa8270b3472969bf394d4486cdf94445e30e4f15bc6acd38bed56880877a";
const LAUNCHER: &str =
    "/var/lib/jetstreamer/horizon-native211-launch-248c9b49-20261119-v1/horizon-native211-launch";
const LAUNCHER_SHA: &str = "de4d986c624bc462f687923efd99d8d5846b6ab1c2f969fd46993ebaadb00821";
const PROPS: &str = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,ExecMainStatus,Result,NRestarts,Restart,KillMode,Delegate,ControlGroup,MemoryMax,MemorySwapMax,TasksMax,User,ProtectHome,ProtectSystem,PrivateNetwork,PrivateTmp,NoNewPrivileges,CapabilityBoundingSet,ReadWritePaths,Job,Unit,DropInPaths,FragmentPath,Wants,Requires,BindsTo,Upholds,After,DefaultDependencies,IgnoreOnIsolate";
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    attempt: String,
    fixture: Binding,
    launcher: Binding,
    read_evidence: Vec<Binding>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    path: PathBuf,
    sha256: String,
}
fn hash(p: &Path) -> Result<String> {
    let mut f = File::open(p)?;
    let mut h = Sha256::new();
    let mut b = [0; 131072];
    loop {
        let n = f.read(&mut b)?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}
fn hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn immutable(b: &Binding) -> Result<()> {
    ensure!(
        hex(&b.sha256) && b.path.is_absolute() && b.path.canonicalize()? == b.path,
        "binding path/hash"
    );
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o222 == 0,
        "unsealed binding"
    );
    ensure!(hash(&b.path)? == b.sha256, "binding digest");
    Ok(())
}
fn write_new(p: &Path, b: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(p)?;
    f.write_all(b)?;
    f.sync_all()?;
    File::open(p.parent().context("parent")?)?.sync_all()?;
    Ok(())
}
fn absent(p: &Path) -> Result<()> {
    match fs::symlink_metadata(p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => bail!("fixture path already exists: {}", p.display()),
    }
}
fn safe_attempt(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
struct Fixture {
    root: PathBuf,
    seq: u32,
    deadline: Instant,
}
impl Fixture {
    fn command(&mut self, exe: &str, args: &[&str], success: bool) -> Result<Vec<u8>> {
        ensure!(Instant::now() < self.deadline, "fixture deadline");
        self.seq += 1;
        let out = self.root.join(format!("command-{:03}.stdout", self.seq));
        let err = self.root.join(format!("command-{:03}.stderr", self.seq));
        let output = |p: &Path| {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(p)
        };
        let mut child = Command::new(exe)
            .args(args)
            .stdin(Stdio::null())
            .stdout(output(&out)?)
            .stderr(output(&err)?)
            .spawn()?;
        let limit = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(s) = child.try_wait()? {
                break s;
            }
            if Instant::now() > limit || Instant::now() > self.deadline {
                let _ = child.kill();
                let _ = child.wait();
                bail!("fixture command deadline")
            };
            std::thread::sleep(Duration::from_millis(20));
        };
        ensure!(
            status.success() == success,
            "unexpected command result: {exe} {:?}; {}",
            args,
            err.display()
        );
        ensure!(
            fs::metadata(&out)?.len() <= 4 << 20,
            "oversized fixture output"
        );
        Ok(fs::read(out)?)
    }
    fn show(&mut self, u: &str) -> Result<Value> {
        let out = self.command(
            "/usr/bin/systemctl",
            &["show", u, "--no-pager", "--property", PROPS],
            true,
        )?;
        let mut v = serde_json::Map::new();
        for l in std::str::from_utf8(&out)?.lines() {
            let (k, x) = l.split_once('=').context("manager field")?;
            ensure!(
                v.insert(k.into(), json!(x)).is_none(),
                "duplicate manager field"
            );
        }
        Ok(Value::Object(v))
    }
    fn seal(
        &mut self,
        destination: &Path,
        members: &[(&str, PathBuf)],
        repeat: bool,
    ) -> Result<()> {
        let members: Vec<_> = members
            .iter()
            .map(|(n, p)| Ok(json!({"source":p,"name":n,"sha256":hash(p)?,"mode":292})))
            .collect::<Result<_>>()?;
        let p = self.root.join(format!("seal-{}.json", self.seq));
        write_new(
            &p,
            &serde_json::to_vec_pretty(
                &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":destination,"members":members}),
            )?,
        )?;
        let digest = hash(&p)?;
        let args = [
            p.to_str().context("plan path")?,
            "--plan-sha256",
            &digest,
            "--self-sha256",
            SEALER_SHA,
        ];
        let mask = unsafe { libc::umask(0o022) };
        let result = self.command(SEALER, &args, true);
        unsafe { libc::umask(mask) };
        result?;
        if repeat {
            let before = hash(&destination.join("deployment-seal-receipt.json"))?;
            self.command(SEALER, &args, false)?;
            ensure!(
                hash(&destination.join("deployment-seal-receipt.json"))? == before,
                "duplicate publication changed destination"
            );
        }
        Ok(())
    }
}
fn pid(v: &Value) -> Result<u64> {
    Ok(v["MainPID"].as_str().context("main PID")?.parse()?)
}
fn drain(unit: &str) -> Result<()> {
    let root = Path::new("/sys/fs/cgroup/system.slice").join(unit);
    if root.exists() {
        ensure!(
            fs::read_to_string(root.join("cgroup.procs"))?
                .trim()
                .is_empty()
                && fs::read_to_string(root.join("cgroup.threads"))?
                    .trim()
                    .is_empty()
                && fs::read_to_string(root.join("cgroup.events"))?
                    .lines()
                    .any(|l| l == "populated 0"),
            "fixture not drained"
        );
    }
    for e in fs::read_dir("/proc")? {
        let e = e?;
        if e.file_name().to_string_lossy().parse::<u64>().is_err() {
            continue;
        }
        match fs::read_to_string(e.path().join("cgroup")) {
            Ok(s) => ensure!(
                !s.lines().any(|l| l == format!("0::/system.slice/{unit}")
                    || l.starts_with(&format!("0::/system.slice/{unit}/"))),
                "fixture process remains"
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn mount_readonly(path: &Path) -> Result<bool> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::statvfs(c.as_ptr(), &mut stat) } == 0,
        "mount access probe"
    );
    Ok(stat.f_flag & libc::ST_RDONLY != 0)
}
fn monotonic_us() -> Result<u64> {
    let mut t: libc::timespec = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) } == 0,
        "monotonic clock"
    );
    Ok((t.tv_sec as u64) * 1_000_000 + (t.tv_nsec as u64) / 1000)
}
fn child(attempt: &str) -> Result<()> {
    ensure!(
        safe_attempt(attempt) && unsafe { libc::geteuid() } == 1000,
        "disjoint reader identity"
    );
    let base = format!("horizon-native211-permission-{attempt}");
    let iid = std::env::var("INVOCATION_ID")?;
    ensure!(
        iid.len() == 32 && iid.bytes().all(|b| b.is_ascii_hexdigit()),
        "reader invocation environment"
    );
    let token = PathBuf::from(format!(
        "/var/lib/jetstreamer/{base}-tokens/{iid}/guard-admission.json"
    ));
    let scratch = PathBuf::from(format!(
        "/home/ubuntu/.jetstreamer-private/native211-permission-{attempt}"
    ));
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        match fs::read(&token) {
            Ok(bytes) => {
                ensure!(
                    bytes == b"{\"permission_fixture_only\":true}\n",
                    "fixture token"
                );
                let sidecar = fs::read_to_string(token.with_file_name("guard-admission.sha256"))?;
                ensure!(
                    sidecar == format!("{}\n", hash(&token)?),
                    "fixture token sidecar"
                );
                write_new(&scratch.join("read-token.json"), &bytes)?;
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        };
        ensure!(Instant::now() < deadline, "fixture token timeout");
        std::thread::sleep(Duration::from_millis(50));
    }
}
fn run(plan: &Path, sha: &str) -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root fixture required");
    immutable(&Binding {
        path: plan.into(),
        sha256: sha.into(),
    })?;
    let p: Plan = serde_json::from_slice(&fs::read(plan)?)?;
    ensure!(
        p.schema == "horizon-native211-permission-fixture-plan-v1" && safe_attempt(&p.attempt),
        "fixture scope"
    );
    ensure!(
        p.launcher.path == Path::new(LAUNCHER) && p.launcher.sha256 == LAUNCHER_SHA,
        "exact intended launcher"
    );
    immutable(&p.launcher)?;
    immutable(&p.fixture)?;
    ensure!(
        fs::read_link("/proc/self/exe")? == p.fixture.path
            && hash(Path::new("/proc/self/exe"))? == p.fixture.sha256,
        "fixture running image"
    );
    immutable(&Binding {
        path: SEALER.into(),
        sha256: SEALER_SHA.into(),
    })?;
    ensure!(
        !p.read_evidence.is_empty() && p.read_evidence.len() <= 32,
        "fixture evidence count"
    );
    for r in &p.read_evidence {
        ensure!(
            fs::metadata(&r.path)?.len() <= 16 << 20,
            "permission evidence bound"
        );
        immutable(r)?;
    }
    let base = format!("horizon-native211-permission-{}", p.attempt);
    let unit = format!("{base}-reader.service");
    let guard = format!("{base}-guard.service");
    let timer = format!("{base}-guard.timer");
    let target = format!("{base}-retain.target");
    let supervisor = format!("{base}.service");
    let root = PathBuf::from(format!("/var/lib/jetstreamer/{base}-execution"));
    let package = PathBuf::from(format!("/var/lib/jetstreamer/{base}-units"));
    let token_root = PathBuf::from(format!("/var/lib/jetstreamer/{base}-tokens"));
    let scratch = PathBuf::from(format!(
        "/home/ubuntu/.jetstreamer-private/native211-permission-{}",
        p.attempt
    ));
    for d in [&root, &package, &token_root] {
        absent(d)?;
    }
    let sm = fs::symlink_metadata(&scratch)?;
    ensure!(
        scratch.canonicalize()? == scratch
            && sm.is_dir()
            && sm.uid() == 1000
            && sm.gid() == 1000
            && sm.mode() & 0o777 == 0o700
            && fs::read_dir(&scratch)?.next().is_none(),
        "Main-prepared disjoint scratch"
    );
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    File::open(root.parent().unwrap())?.sync_all()?;
    let mut f = Fixture {
        root: root.clone(),
        seq: 0,
        deadline: Instant::now() + Duration::from_secs(110),
    };
    let mut installed = Vec::new();
    let mut child_iid: Option<String> = None;
    let result = (|| -> Result<()> {
        let self_unit = f.show(&supervisor)?;
        let expected = BTreeMap::from([
            ("User", "root"),
            ("MemoryMax", "268435456"),
            ("MemorySwapMax", "0"),
            ("TasksMax", "64"),
            ("Restart", "no"),
            ("KillMode", "control-group"),
            ("Delegate", "no"),
            ("ProtectHome", "read-only"),
            ("ProtectSystem", "strict"),
            ("PrivateNetwork", "yes"),
            ("PrivateTmp", "yes"),
            ("NoNewPrivileges", "yes"),
            ("ReadWritePaths", "/var/lib/jetstreamer /etc/systemd/system"),
        ]);
        for (k, want) in expected {
            ensure!(self_unit[k] == want, "supervisor sandbox mismatch {k}");
        }
        ensure!(
            pid(&self_unit)? == u64::from(std::process::id()),
            "fixture unit identity"
        );
        let caps = self_unit["CapabilityBoundingSet"]
            .as_str()
            .context("capabilities")?;
        let got: std::collections::BTreeSet<_> = caps.split_whitespace().collect();
        ensure!(
            got == std::collections::BTreeSet::from(["cap_dac_read_search", "cap_sys_ptrace"]),
            "fixture capabilities differ"
        );
        ensure!(
            self_unit["DropInPaths"] == ""
                && self_unit["ControlGroup"] == format!("/system.slice/{supervisor}"),
            "supervisor overrides/cgroup"
        );
        let cg = Path::new("/sys/fs/cgroup/system.slice").join(&supervisor);
        for (leaf, want) in [
            ("memory.max", "268435456"),
            ("memory.swap.max", "0"),
            ("pids.max", "64"),
        ] {
            ensure!(
                fs::read_to_string(cg.join(leaf))?.trim() == want,
                "supervisor kernel limit"
            );
        }
        write_new(
            &root.join("supervisor.json"),
            &serde_json::to_vec_pretty(&self_unit)?,
        )?;
        write_new(
            &root.join("mountinfo.txt"),
            &fs::read("/proc/self/mountinfo")?,
        )?;
        for path in ["/usr", "/home/ubuntu/.jetstreamer-private"] {
            ensure!(
                mount_readonly(Path::new(path))?,
                "expected read-only mount {path}"
            );
        }
        for path in ["/var/lib/jetstreamer", "/etc/systemd/system"] {
            ensure!(
                !mount_readonly(Path::new(path))?,
                "expected writable mount {path}"
            );
        }
        f.command(
            "/usr/bin/git",
            &[
                "-c",
                "safe.directory=/home/ubuntu/workspace/jetstreamer",
                "-C",
                "/home/ubuntu/workspace/jetstreamer",
                "show",
                "248c9b49:tools/native211-launch/src/main.rs",
            ],
            true,
        )?;
        f.command(
            "/usr/bin/busctl",
            &[
                "get-property",
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                "Version",
            ],
            true,
        )?;
        for u in [&unit, &guard, &timer, &target] {
            ensure!(
                f.show(u)?["LoadState"] == "not-found",
                "fixture unit already loaded"
            );
            for d in ["/etc/systemd/system", "/run/systemd/system"] {
                absent(&Path::new(d).join(u))?;
                absent(&Path::new(d).join(format!("{u}.d")))?;
            }
        }
        let reader = format!(
            "[Unit]\nDescription=Disjoint native211 permission reader\n[Service]\nType=exec\nUser=ubuntu\nGroup=ubuntu\nRestart=no\nKillMode=control-group\nDelegate=no\nMemoryMax=16777216\nMemorySwapMax=0\nTasksMax=8\nCPUQuota=100%\nRuntimeMaxSec=60\nProtectHome=read-only\nProtectSystem=strict\nPrivateNetwork=yes\nPrivateTmp=yes\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nReadWritePaths={}\nUMask=0077\nExecStart={} reader {}\n",
            scratch.display(),
            p.fixture.path.display(),
            p.attempt
        );
        let g="[Unit]\nDescription=Disjoint native211 permission timer firing\nStartLimitIntervalSec=0\n[Service]\nType=oneshot\nUser=root\nRestart=no\nKillMode=control-group\nMemoryMax=16777216\nMemorySwapMax=0\nTasksMax=8\nCPUQuota=100%\nTimeoutStartSec=10\nProtectHome=read-only\nProtectSystem=strict\nPrivateNetwork=yes\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nExecStart=/usr/bin/true\n".to_string();
        let t = format!(
            "[Unit]\nDescription=Disjoint native211 permission timer\n[Timer]\nOnActiveSec=1s\nOnUnitActiveSec=30s\nAccuracySec=1s\nRandomizedDelaySec=0\nUnit={guard}\n"
        );
        let retain = format!(
            "[Unit]\nDescription=Disjoint native211 permission retention\nDefaultDependencies=no\nAfter={unit}\nIgnoreOnIsolate=yes\n"
        );
        let mut members = Vec::new();
        for (name, bytes) in [(&unit, reader), (&guard, g), (&timer, t), (&target, retain)] {
            let path = root.join(name);
            write_new(&path, bytes.as_bytes())?;
            members.push((name.as_str(), path));
        }
        f.seal(&package, &members, true)?;
        for u in [&unit, &guard, &timer, &target] {
            let dst = Path::new("/etc/systemd/system").join(u);
            symlink(package.join(u), &dst)?;
            installed.push(u.clone());
            ensure!(
                symlink(package.join(u), &dst).is_err(),
                "unit link clobber allowed"
            );
        }
        File::open("/etc/systemd/system")?.sync_all()?;
        f.command("/usr/bin/systemctl", &["daemon-reload"], true)?;
        f.command("/usr/bin/systemctl", &["start", &target], true)?;
        let before = f.show(&unit)?;
        ensure!(
            before["ActiveState"] == "inactive"
                && before["MainPID"] == "0"
                && before["InvocationID"] == "",
            "retention activated reader"
        );
        let retain = f.show(&target)?;
        ensure!(
            retain["ActiveState"] == "active"
                && retain["After"] == unit
                && retain["DefaultDependencies"] == "no"
                && retain["IgnoreOnIsolate"] == "yes",
            "retention contract"
        );
        for k in ["Wants", "Requires", "BindsTo", "Upholds"] {
            ensure!(retain[k] == "", "retention activates another unit");
        }
        f.command("/usr/bin/systemctl", &["start", &unit], true)?;
        let live = f.show(&unit)?;
        let child_pid = pid(&live)?;
        ensure!(
            live["ActiveState"] == "active" && live["SubState"] == "running" && child_pid > 1,
            "reader not running"
        );
        let iid = live["InvocationID"]
            .as_str()
            .context("reader IID")?
            .to_owned();
        child_iid = Some(iid.clone());
        let proc = PathBuf::from(format!("/proc/{child_pid}"));
        ensure!(
            fs::read_link(proc.join("exe"))? == p.fixture.path,
            "other-user mapped image"
        );
        ensure!(
            fs::metadata(proc.join("exe"))?.ino() == fs::metadata(&p.fixture.path)?.ino(),
            "mapped inode"
        );
        for leaf in ["maps", "cgroup", "status"] {
            write_new(
                &root.join(format!("reader-{leaf}.txt")),
                &fs::read(proc.join(leaf))?,
            )?;
        }
        ensure!(
            fs::read_to_string(proc.join("cgroup"))?.trim() == format!("0::/system.slice/{unit}"),
            "reader cgroup"
        );
        let reader_cg = Path::new("/sys/fs/cgroup/system.slice").join(&unit);
        for (leaf, want) in [
            ("memory.max", "16777216"),
            ("memory.swap.max", "0"),
            ("pids.max", "8"),
        ] {
            ensure!(
                fs::read_to_string(reader_cg.join(leaf))?.trim() == want,
                "reader kernel limit"
            );
        }
        f.command("/usr/bin/systemctl", &["start", &timer], true)?;
        let until = Instant::now() + Duration::from_secs(10);
        let fired = loop {
            let v = f.show(&guard)?;
            if v["ActiveState"] == "inactive"
                && v["Result"] == "success"
                && v["ExecMainStatus"] == "0"
                && v["InvocationID"].as_str().is_some_and(|s| s.len() == 32)
            {
                break v;
            }
            ensure!(Instant::now() < until, "fixture timer never fired");
            std::thread::sleep(Duration::from_millis(100));
        };
        let gid = fired["InvocationID"].as_str().context("guard IID")?;
        let journal = f.command(
            "/usr/bin/journalctl",
            &[
                "--all",
                "--no-pager",
                "--output=json",
                "--boot=0",
                "_PID=1",
                &format!("UNIT={guard}"),
                &format!("INVOCATION_ID={gid}"),
            ],
            true,
        )?;
        let rows: Vec<Value> = serde_json::Deserializer::from_slice(&journal)
            .into_iter::<Value>()
            .collect::<std::result::Result<_, _>>()?;
        ensure!(
            rows.iter().any(|r| r["_PID"] == "1"
                && r["INVOCATION_ID"] == gid
                && r["MESSAGE"]
                    .as_str()
                    .is_some_and(|s| s.starts_with(&format!("Starting {guard} -"))))
                && rows.iter().any(|r| r["_PID"] == "1"
                    && r["INVOCATION_ID"] == gid
                    && r["MESSAGE"] == format!("{guard}: Deactivated successfully.")),
            "actual PID1 timer journal missing"
        );
        let object = format!(
            "/org/freedesktop/systemd1/unit/{}",
            timer
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() {
                    c.to_string()
                } else {
                    format!("_{:02x}", c as u32)
                })
                .collect::<String>()
        );
        let raw = f.command(
            "/usr/bin/busctl",
            &[
                "get-property",
                "org.freedesktop.systemd1",
                &object,
                "org.freedesktop.systemd1.Timer",
                "NextElapseUSecMonotonic",
            ],
            true,
        )?;
        let fields: Vec<_> = std::str::from_utf8(&raw)?.split_whitespace().collect();
        ensure!(fields.len() == 2 && fields[0] == "t", "typed timer framing");
        let next = fields[1].parse::<u64>()?;
        let clock = monotonic_us()?;
        ensure!(
            next > clock && next - clock <= 35_000_000,
            "typed timer deadline"
        );
        let armed = f.show(&timer)?;
        ensure!(
            armed["LoadState"] == "loaded"
                && armed["ActiveState"] == "active"
                && armed["SubState"] == "waiting"
                && armed["Unit"] == guard,
            "fixture timer not armed"
        );
        fs::create_dir(&token_root)?;
        fs::set_permissions(&token_root, fs::Permissions::from_mode(0o755))?;
        File::open(token_root.parent().unwrap())?.sync_all()?;
        let token = token_root.join(&iid);
        let payload = root.join("token.json");
        write_new(&payload, b"{\"permission_fixture_only\":true}\n")?;
        let sidecar = root.join("token.sha256");
        write_new(&sidecar, format!("{}\n", hash(&payload)?).as_bytes())?;
        f.seal(
            &token,
            &[
                ("guard-admission.json", payload),
                ("guard-admission.sha256", sidecar),
            ],
            true,
        )?;
        let until = Instant::now() + Duration::from_secs(10);
        let terminal = loop {
            let v = f.show(&unit)?;
            if v["ActiveState"] == "inactive" && v["SubState"] == "dead" {
                break v;
            }
            ensure!(Instant::now() < until, "reader did not exit");
            std::thread::sleep(Duration::from_millis(100));
        };
        ensure!(
            terminal["InvocationID"] == iid
                && terminal["Result"] == "success"
                && terminal["ExecMainStatus"] == "0"
                && terminal["NRestarts"] == "0",
            "reader terminal failed"
        );
        ensure!(
            fs::read(scratch.join("read-token.json"))? == b"{\"permission_fixture_only\":true}\n",
            "unprivileged token read/scratch write failed"
        );
        drain(&unit)?;
        f.command("/usr/bin/systemctl", &["restart", &target], true)?;
        let after = f.show(&unit)?;
        ensure!(
            after["InvocationID"] == iid
                && after["MainPID"] == "0"
                && after["ActiveState"] == "inactive",
            "target restarted reader"
        );
        write_new(
            &root.join("qualification.json"),
            &serde_json::to_vec_pretty(
                &json!({"schema":"horizon-native211-permission-fixture-qualification-v1","plan":{"path":plan,"sha256":sha},"launcher":p.launcher,"fixture":p.fixture,"supervisor":self_unit,"retention":retain,"reader_live":live,"reader_terminal":terminal,"guard":fired,"pid1_journal":rows,"permission_operations_passed":true,"production_first_guard_qualified":false,"actual_native_startup_qualified":false,"native_input_qualified":false,"entry_replay":false,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
            )?,
        )?;
        Ok(())
    })();
    // Every stop/removal is confined to links created in this invocation and
    // still bound to this immutable package. A changed unit fails cleanup closed.
    let cleanup = (|| -> Result<()> {
        f.deadline = Instant::now() + Duration::from_secs(30);
        for u in [&timer, &guard, &unit, &target]
            .into_iter()
            .filter(|u| installed.contains(u))
        {
            let path = Path::new("/etc/systemd/system").join(u);
            ensure!(
                fs::read_link(&path)? == package.join(u),
                "fixture cleanup link changed"
            );
            let v = f.show(u)?;
            if v["LoadState"] != "not-found" {
                ensure!(
                    v["Id"] == *u && v["DropInPaths"] == "",
                    "fixture cleanup unit override"
                );
                ensure!(
                    Path::new(v["FragmentPath"].as_str().context("fixture fragment")?)
                        .canonicalize()?
                        == package.join(u),
                    "fixture loaded fragment replaced"
                );
                if u == &unit
                    && let Some(iid) = &child_iid
                {
                    ensure!(
                        v["InvocationID"] == *iid,
                        "fixture reader invocation replaced"
                    );
                }
                f.command("/usr/bin/systemctl", &["stop", u], true)?;
            }
        }
        for u in &installed {
            let path = Path::new("/etc/systemd/system").join(u);
            ensure!(
                fs::read_link(&path)? == package.join(u),
                "fixture unlink changed"
            );
            fs::remove_file(path)?;
        }
        File::open("/etc/systemd/system")?.sync_all()?;
        if !installed.is_empty() {
            f.command("/usr/bin/systemctl", &["daemon-reload"], true)?;
        }
        drain(&unit)?;
        drain(&guard)?;
        write_new(
            &root.join("cleanup.json"),
            b"{\"fixture_links_removed\":true,\"fixture_processes_drained\":true}\n",
        )?;
        Ok(())
    })();
    if let Err(ref e) = cleanup {
        let _ = write_new(
            &root.join("cleanup-failure.json"),
            format!("{e:#}\n").as_bytes(),
        );
    }
    if let Err(ref e) = result {
        let _ = write_new(
            &root.join("failure.json"),
            &serde_json::to_vec(&json!({"error":format!("{e:#}"),"automatic_retry":false}))?,
        );
    }
    result?;
    cleanup
}
fn main() {
    let a: Vec<_> = std::env::args().collect();
    let result = match a.get(1).map(String::as_str) {
        Some("reader") if a.len() == 3 => child(&a[2]),
        Some("qualify") if a.len() == 4 => run(Path::new(&a[2]), &a[3]),
        _ => Err(anyhow::anyhow!(
            "usage: sandbox-permissions qualify SEALED_PLAN SHA256 | reader ATTEMPT"
        )),
    };
    if let Err(e) = result {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixture_names_cannot_escape_disjoint_namespace() {
        assert!(safe_attempt("20261119-v1"));
        for bad in [
            "",
            "../actual",
            "x/y",
            "x.service",
            "x y",
            "-../../",
            "UPPER",
        ] {
            assert!(!safe_attempt(bad));
        }
        assert!(!safe_attempt(&"x".repeat(33)));
    }
    #[test]
    fn plan_rejects_extra_authority_or_execution_fields() {
        let mut v = json!({"schema":"horizon-native211-permission-fixture-plan-v1","attempt":"20261119-v1","fixture":{"path":"/var/lib/jetstreamer/fixture","sha256":"a".repeat(64)},"launcher":{"path":LAUNCHER,"sha256":LAUNCHER_SHA},"read_evidence":[]});
        serde_json::from_value::<Plan>(v.clone()).unwrap();
        v["exec"] = json!("/usr/bin/something");
        assert!(serde_json::from_value::<Plan>(v).is_err());
    }
}
