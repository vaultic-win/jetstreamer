use anyhow::{ensure, Context, Result};
use horizon_old220_peers1012::{
    capture_condition_blocked, read_directory_names, read_file, Backend, Pin, ReadFile, Reply,
    Request, ReviewBinding,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const SCHEMA: &str = "horizon-old220-peers1061-native-capture-admission-v1";
const CAPS: u64 = (1 << 1) | (1 << 19); // DAC_OVERRIDE and SYS_PTRACE only.
const OWN_PROPERTIES: &str = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,ControlGroup,NRestarts,Type,User,Group,Restart,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,RuntimeMaxUSec,NoNewPrivileges,ProtectSystem,ProtectHome,PrivateNetwork,KillMode,ExecStart,ReadWritePaths,CapabilityBoundingSet,AmbientCapabilities,PrivateDevices,PrivateTmp,PrivateMounts,ProtectKernelTunables,ProtectKernelModules,ProtectControlGroups,RootDirectory,RootImage,MountImages,ExtensionImages,ExtensionDirectories,BindPaths,BindReadOnlyPaths,TemporaryFileSystem,RuntimeDirectory,StateDirectory,CacheDirectory,LogsDirectory,ConfigurationDirectory,ReadOnlyPaths,InaccessiblePaths";
const STREAM_LIMIT: u64 = 2 << 20;
const TOTAL_STREAM_LIMIT: usize = 32 << 20;
const RESULT_LIMIT: usize = 48 << 20;
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Lineage {
    schema: String,
    binary: Bound,
    source_manifest: Bound,
    normal_build: Bound,
    cargo_features: Vec<String>,
    normal_binary_test: bool,
    normal_library_test: bool,
    test_fixtures_enabled: bool,
    source_hashes: BTreeMap<String, String>,
}
/// Separately sealed qualification attestations, emitted only after Main has
/// checked the original complete frozen manifest and actual normal build proof.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceAcceptance {
    schema: String,
    original_frozen_manifest: Bound,
    compiled_source_hashes: BTreeMap<String, String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LibraryArtifact {
    file: Bound,
    cargo_features: Vec<String>,
    test: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildAcceptance {
    schema: String,
    original_normal_build: Bound,
    source_acceptance: Bound,
    binary: Bound,
    cargo_features: Vec<String>,
    binary_test: bool,
    peer_library: LibraryArtifact,
    actual_extern_crate: String,
    actual_extern_file: Bound,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Admission {
    schema: String,
    issued_unix_seconds: u64,
    expires_unix_seconds: u64,
    self_binary: Bound,
    lineage: Bound,
    review: ReviewBinding,
    unit: String,
    invocation_id: String,
    main_pid: u32,
    start_ticks: u64,
    expected_properties: BTreeMap<String, String>,
    output: PathBuf,
}
fn digest(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn stamp(m: &fs::Metadata) -> (u64, u64, u64, u64, u32, u32, u32, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.nlink(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn immutable_bytes(bound: &Bound, limit: u64) -> Result<Vec<u8>> {
    ensure!(
        hex(&bound.sha256, 64)
            && bound.path.is_absolute()
            && bound.path.canonicalize()? == bound.path,
        "invalid evidence binding"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&bound.path)?;
    let before = f.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.gid() == 0
            && before.nlink() == 1
            && before.mode() & 0o222 == 0
            && before.len() <= limit,
        "evidence custody or size differs"
    );
    let mut bytes = Vec::new();
    (&mut f).take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.len()
            && digest(&bytes) == bound.sha256
            && stamp(&before) == stamp(&f.metadata()?)
            && stamp(&before) == stamp(&fs::symlink_metadata(&bound.path)?),
        "evidence changed"
    );
    Ok(bytes)
}
fn decode<T: serde::de::DeserializeOwned>(b: &Bound) -> Result<T> {
    Ok(serde_json::from_slice(&immutable_bytes(b, 1 << 20)?)?)
}
fn ticks(text: &str) -> Result<u64> {
    let end = text.rfind(')').context("missing proc comm delimiter")?;
    text.get(end + 2..)
        .context("truncated proc stat")?
        .split_whitespace()
        .nth(19)
        .context("missing start ticks")?
        .parse()
        .context("invalid start ticks")
}
fn properties(text: &str) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for line in text.lines() {
        let (k, v) = line.split_once('=').context("malformed native property")?;
        ensure!(
            !k.is_empty() && result.insert(k.into(), v.into()).is_none(),
            "duplicate native property"
        );
    }
    Ok(result)
}
fn valid_unit(s: &str) -> bool {
    s.starts_with("horizon-old220-peers")
        && s.ends_with(".service")
        && s.len() <= 180
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
fn validate_window(a: &Admission, clock: u64) -> Result<()> {
    ensure!(
        a.schema == SCHEMA
            && valid_unit(&a.unit)
            && hex(&a.invocation_id, 32)
            && a.invocation_id != "0".repeat(32)
            && a.issued_unix_seconds <= clock
            && clock <= a.expires_unix_seconds
            && a.expires_unix_seconds > a.issued_unix_seconds
            && a.expires_unix_seconds - a.issued_unix_seconds <= 180
            && a.main_pid > 1
            && a.start_ticks > 0,
        "wrong or stale native capture admission"
    );
    Ok(())
}
fn validate_output(p: &Path) -> Result<()> {
    let parent = p.parent().context("missing output parent")?;
    ensure!(
        p.file_name().is_some_and(|s| s == "result.json")
            && parent.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && parent
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-old220-peers")
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)))
            && parent.canonicalize()? == parent,
        "unsafe output path"
    );
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "output parent is not Root0700"
    );
    for ancestor in parent.ancestors().skip(1) {
        let m = fs::symlink_metadata(ancestor)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "unsafe output ancestor"
        );
    }
    ensure!(
        matches!(fs::symlink_metadata(p),Err(e)if e.kind()==std::io::ErrorKind::NotFound),
        "output already exists or cannot be inspected"
    );
    Ok(())
}
fn embedded_sources() -> BTreeMap<String, String> {
    [
        ("lib.rs", include_bytes!("lib.rs").as_slice()),
        (
            "condition_blocked.rs",
            include_bytes!("condition_blocked.rs").as_slice(),
        ),
        (
            "predecessor_summary.rs",
            include_bytes!("predecessor_summary.rs").as_slice(),
        ),
        (
            "native_capture.rs",
            include_bytes!("native_capture.rs").as_slice(),
        ),
        (
            "capture_main.rs",
            include_bytes!("capture_main.rs").as_slice(),
        ),
        ("specs.json", include_bytes!("../specs.json").as_slice()),
        ("Cargo.toml", include_bytes!("../Cargo.toml").as_slice()),
        ("Cargo.lock", include_bytes!("../Cargo.lock").as_slice()),
    ]
    .into_iter()
    .map(|(n, b)| (n.into(), digest(b)))
    .collect()
}
fn validate_lineage_links(
    a: &Admission,
    l: &Lineage,
    source: &SourceAcceptance,
    build: &BuildAcceptance,
) -> Result<()> {
    ensure!(
        source.schema == "horizon-old220-peers1061-source-acceptance-v1"
            && source.compiled_source_hashes == embedded_sources()
            && source.compiled_source_hashes == l.source_hashes
            && build.schema == "horizon-old220-peers1061-build-acceptance-v1"
            && build.source_acceptance == l.source_manifest
            && build.binary == a.self_binary
            && build.cargo_features.is_empty()
            && !build.binary_test
            && build.peer_library.cargo_features.is_empty()
            && !build.peer_library.test
            && build.actual_extern_crate == "horizon_old220_peers1012"
            && build.actual_extern_file.sha256 == build.peer_library.file.sha256
            && build.actual_extern_file.path.is_absolute()
            && build.actual_extern_file.path.components().all(|c| matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            ))
            && build.actual_extern_file.path.file_name()
                == build.peer_library.file.path.file_name()
            && build.peer_library.file.path.parent() == a.self_binary.path.parent()
            && build
                .peer_library
                .file
                .path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(
                    |n| n.starts_with("libhorizon_old220_peers1012") && n.ends_with(".rlib")
                ),
        "normal qualification source/artifact/feature/extern links differ"
    );
    Ok(())
}
#[derive(Debug, PartialEq, Eq)]
struct MountView {
    raw: String,
    writable: Vec<(String, String)>,
}
fn mount_path(s: &str) -> Result<String> {
    let mut bytes = Vec::new();
    let mut input = s.as_bytes();
    while !input.is_empty() {
        if input[0] == b'\\' {
            ensure!(input.len() >= 4, "truncated mount escape");
            bytes.push(match &input[..4] {
                b"\\040" => b' ',
                b"\\011" => b'\t',
                b"\\012" => b'\n',
                b"\\134" => b'\\',
                _ => anyhow::bail!("unrecognized mount escape"),
            });
            input = &input[4..];
        } else {
            bytes.push(input[0]);
            input = &input[1..];
        }
    }
    let path = String::from_utf8(bytes)?;
    ensure!(
        Path::new(&path).is_absolute() && !path.contains('\0'),
        "invalid mount path"
    );
    Ok(path)
}
fn mount_view(raw: String, output: &Path) -> Result<MountView> {
    ensure!(
        raw.len() <= 4 << 20 && raw.ends_with('\n'),
        "mount view exceeds bound or is truncated"
    );
    let mut ids = std::collections::BTreeSet::new();
    let mut writable = Vec::new();
    let mut output_count = 0;
    let mut root_read_only = false;
    for line in raw.lines() {
        ensure!(ids.len() < 16384, "mount count bound");
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let split = fields
            .iter()
            .position(|s| *s == "-")
            .context("missing mount separator")?;
        ensure!(
            split >= 6 && fields.len() == split + 4,
            "malformed mount record"
        );
        ensure!(ids.insert(fields[0].parse::<u64>()?), "duplicate mount ID");
        let root = mount_path(fields[3])?;
        let point = mount_path(fields[4])?;
        let mount_options = fields[5].split(',').collect::<Vec<_>>();
        let super_options = fields[split + 3].split(',').collect::<Vec<_>>();
        ensure!(
            mount_options.contains(&"rw") ^ mount_options.contains(&"ro"),
            "ambiguous mount access"
        );
        ensure!(
            super_options.contains(&"rw") ^ super_options.contains(&"ro"),
            "ambiguous superblock access"
        );
        let rw = mount_options.contains(&"rw") && super_options.contains(&"rw");
        if point == "/" {
            root_read_only = !rw;
        }
        if Path::new(&point) == output {
            output_count += 1;
            ensure!(
                rw && Path::new(&root) == output,
                "result mount is not the exact writable host directory"
            );
        } else if rw {
            // Fixed private API filesystems are the only intentional writable
            // surfaces besides the result leaf. Never admit ordinary data paths.
            ensure!(
                root == "/"
                    && matches!(
                        (point.as_str(), fields[split + 1]),
                        ("/proc", "proc")
                            | ("/dev", "tmpfs")
                            | ("/dev/pts", "devpts")
                            | ("/dev/shm", "tmpfs")
                            | ("/dev/mqueue", "mqueue")
                    ),
                "unexpected writable mount: {point}"
            );
        }
        if rw {
            writable.push((point, fields[split + 1].into()));
        }
    }
    ensure!(
        root_read_only && output_count == 1,
        "missing read-only root or unique writable result mount"
    );
    Ok(MountView { raw, writable })
}
fn actual_mount_view(a: &Admission) -> Result<MountView> {
    let mut bytes = Vec::new();
    File::open("/proc/self/mountinfo")?
        .take((4 << 20) + 1)
        .read_to_end(&mut bytes)?;
    mount_view(
        String::from_utf8(bytes)?,
        a.output.parent().context("result parent")?,
    )
}
fn validate_write_properties(p: &BTreeMap<String, String>, output: &Path) -> Result<()> {
    for (key, expected) in [
        ("PrivateDevices", "yes"),
        ("PrivateTmp", "no"),
        ("PrivateMounts", "yes"),
        ("ProtectKernelTunables", "yes"),
        ("ProtectKernelModules", "yes"),
        ("ProtectControlGroups", "yes"),
    ] {
        ensure!(
            p.get(key).map(String::as_str) == Some(expected),
            "unexpected sandbox field {key}"
        );
    }
    for key in [
        "RootDirectory",
        "RootImage",
        "MountImages",
        "ExtensionImages",
        "ExtensionDirectories",
        "BindPaths",
        "BindReadOnlyPaths",
        "TemporaryFileSystem",
        "RuntimeDirectory",
        "StateDirectory",
        "CacheDirectory",
        "LogsDirectory",
        "ConfigurationDirectory",
        "ReadOnlyPaths",
        "InaccessiblePaths",
    ] {
        ensure!(
            p.get(key).map(String::as_str) == Some(""),
            "unexpected sandbox projection {key}"
        );
    }
    ensure!(
        p.get("ReadWritePaths").map(String::as_str) == output.to_str(),
        "wrong writable result grant"
    );
    Ok(())
}
struct Native {
    start: Instant,
    queries: Vec<Value>,
    stream_bytes: usize,
}
impl Native {
    fn remaining(&self) -> Result<Duration> {
        Duration::from_secs(150)
            .checked_sub(self.start.elapsed())
            .filter(|d| !d.is_zero())
            .context("native capture deadline exhausted")
    }
    fn invoke(&mut self, program: &str, argv: &[String]) -> Result<Reply> {
        let timeout = self.remaining()?.min(Duration::from_secs(5));
        ensure!(
            self.queries.len() < 256 && matches!(program, "/usr/bin/systemctl" | "/usr/bin/busctl"),
            "unregistered native request"
        );
        ensure!(
            if program == "/usr/bin/systemctl" {
                argv.first()
                    .is_some_and(|a| matches!(a.as_str(), "show" | "list-jobs"))
            } else {
                argv.len() == 8
                    && argv[3] == "get-property"
                    && argv[4] == "org.freedesktop.systemd1"
            },
            "native request is not read-only"
        );
        fn memfd() -> Result<File> {
            let name = CString::new("old220-peer-native")?;
            let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
            ensure!(fd >= 0, "native capture memfd failed");
            Ok(unsafe { File::from_raw_fd(fd) })
        }
        let out = memfd()?;
        let err = memfd()?;
        let mut cmd = Command::new("/usr/bin/timeout");
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .args([
                "--signal=TERM",
                "--kill-after=1s",
                &format!("{}s", timeout.as_secs_f64()),
                program,
            ])
            .args(argv)
            .stdin(Stdio::null())
            .stdout(Stdio::from(out.try_clone()?))
            .stderr(Stdio::from(err.try_clone()?));
        unsafe {
            cmd.pre_exec(|| {
                let limit = libc::rlimit {
                    rlim_cur: STREAM_LIMIT + 1,
                    rlim_max: STREAM_LIMIT + 1,
                };
                if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let status = cmd.status()?;
        let read = |mut f: File| -> Result<String> {
            ensure!(
                f.metadata()?.len() <= STREAM_LIMIT,
                "native stream exceeds bound"
            );
            f.seek(SeekFrom::Start(0))?;
            let mut b = Vec::new();
            f.take(STREAM_LIMIT + 1).read_to_end(&mut b)?;
            ensure!(b.len() as u64 <= STREAM_LIMIT, "native stream grew");
            Ok(String::from_utf8(b)?)
        };
        let reply = Reply {
            code: status.code().unwrap_or(-1),
            stdout: read(out)?,
            stderr: read(err)?,
        };
        self.stream_bytes = self
            .stream_bytes
            .checked_add(reply.stdout.len() + reply.stderr.len())
            .context("native aggregate overflow")?;
        ensure!(
            self.stream_bytes <= TOTAL_STREAM_LIMIT,
            "native aggregate stream bound"
        );
        self.queries.push(json!({"program":program,"argv":argv,"exit_code":reply.code,"stdout":reply.stdout,"stderr":reply.stderr}));
        self.remaining()?;
        Ok(reply)
    }
    fn own(&mut self, a: &Admission) -> Result<BTreeMap<String, String>> {
        let reply = self.invoke(
            "/usr/bin/systemctl",
            &[
                "show".into(),
                "--no-pager".into(),
                format!("--property={OWN_PROPERTIES}"),
                "--".into(),
                a.unit.clone(),
            ],
        )?;
        ensure!(
            reply.code == 0 && reply.stderr.is_empty(),
            "own native query failed"
        );
        let p = properties(&reply.stdout)?;
        ensure!(p == a.expected_properties, "own native envelope changed");
        for (key, value) in [
            ("Id", a.unit.as_str()),
            ("LoadState", "loaded"),
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("InvocationID", a.invocation_id.as_str()),
            ("ControlPID", "0"),
            ("NRestarts", "0"),
            ("Type", "exec"),
            ("User", "root"),
            ("Group", "root"),
            ("Restart", "no"),
            ("MemoryMax", "536870912"),
            ("MemorySwapMax", "0"),
            ("CPUQuotaPerSecUSec", "2s"),
            ("TasksMax", "128"),
            ("RuntimeMaxUSec", "3min"),
            ("NoNewPrivileges", "yes"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "read-only"),
            ("PrivateNetwork", "yes"),
            ("KillMode", "control-group"),
        ] {
            ensure!(
                p.get(key).map(String::as_str) == Some(value),
                "unexpected own native field {key}"
            );
        }
        validate_write_properties(&p, a.output.parent().context("output parent")?)?;
        ensure!(
            p.get("MainPID") == Some(&a.main_pid.to_string())
                && p.get("ControlGroup") == Some(&format!("/system.slice/{}", a.unit))
                && p.get("ReadWritePaths")
                    == Some(&a.output.parent().unwrap().display().to_string())
                && p.get("ExecStart").is_some_and(|v| !v.is_empty()),
            "own native owner/write scope differs"
        );
        kernel(a)?;
        Ok(p)
    }
    fn jobs(&mut self) -> Result<String> {
        let r = self.invoke(
            "/usr/bin/systemctl",
            &[
                "list-jobs".into(),
                "--no-pager".into(),
                "--no-legend".into(),
            ],
        )?;
        ensure!(r.code == 0 && r.stderr.is_empty(), "jobs query failed");
        Ok(r.stdout)
    }
}
impl Backend for Native {
    fn read(&mut self, p: &Pin) -> Result<ReadFile> {
        self.remaining()?;
        let r = read_file(p)?;
        self.remaining()?;
        Ok(r)
    }
    fn query(&mut self, r: &Request) -> Result<Reply> {
        self.invoke(r.program, &r.argv)
    }
    fn directory_names(&mut self, p: &str) -> Result<Option<Vec<String>>> {
        self.remaining()?;
        let r = read_directory_names(p)?;
        self.remaining()?;
        Ok(r)
    }
}
fn kernel(a: &Admission) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0
            && unsafe { libc::getegid() } == 0
            && std::process::id() == a.main_pid
            && ticks(&fs::read_to_string("/proc/self/stat")?)? == a.start_ticks
            && std::env::var("INVOCATION_ID")? == a.invocation_id,
        "actual capture owner differs"
    );
    let status = fs::read_to_string("/proc/self/status")?;
    let fields = status
        .lines()
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k, v.trim()))
        .collect::<BTreeMap<_, _>>();
    for key in ["CapEff", "CapPrm", "CapBnd", "CapAmb"] {
        ensure!(
            u64::from_str_radix(fields.get(key).context("missing capability field")?, 16)? == CAPS,
            "unexpected actual capability set"
        );
    }
    ensure!(
        fields.get("NoNewPrivs") == Some(&"1"),
        "actual NoNewPrivs absent"
    );
    for key in ["Uid", "Gid"] {
        ensure!(
            fields
                .get(key)
                .context("missing identity field")?
                .split_whitespace()
                .collect::<Vec<_>>()
                == ["0", "0", "0", "0"],
            "actual Root identity differs"
        );
    }
    let cg = format!("0::/system.slice/{}\n", a.unit);
    ensure!(
        fs::read_to_string("/proc/self/cgroup")? == cg,
        "unexpected actual cgroup"
    );
    let root = Path::new("/sys/fs/cgroup/system.slice").join(&a.unit);
    for (name, value) in [
        ("memory.max", "536870912"),
        ("memory.swap.max", "0"),
        ("pids.max", "128"),
    ] {
        ensure!(
            fs::read_to_string(root.join(name))?.trim() == value,
            "kernel cgroup limit differs"
        );
    }
    let cpu = fs::read_to_string(root.join("cpu.max"))?;
    let parts = cpu.split_whitespace().collect::<Vec<_>>();
    ensure!(
        parts.len() == 2
            && parts[0].parse::<u64>()?
                == parts[1]
                    .parse::<u64>()?
                    .checked_mul(2)
                    .context("cpu period overflow")?,
        "kernel CPU quota differs"
    );
    Ok(())
}
fn publish(output: &Path, value: &Value) -> Result<()> {
    validate_output(output)?;
    let bytes = serde_json::to_vec_pretty(value)?;
    ensure!(bytes.len() <= RESULT_LIMIT, "result exceeds bound");
    publish_bytes(output.parent().context("publication parent")?, &bytes)
}
fn publish_bytes(parent: &Path, bytes: &[u8]) -> Result<()> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(parent)?;
    let identity = directory.metadata()?;
    let name = CString::new(format!(".result-{}.tmp", std::process::id()))?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o400,
        )
    };
    ensure!(fd >= 0, "cannot create private publication temporary");
    let mut f = unsafe { File::from_raw_fd(fd) };
    let result = (|| -> Result<()> {
        f.write_all(&bytes)?;
        f.write_all(b"\n")?;
        f.sync_all()?;
        let named_parent = fs::symlink_metadata(parent)?;
        ensure!(
            identity.dev() == named_parent.dev()
                && identity.ino() == named_parent.ino()
                && named_parent.uid() == identity.uid()
                && named_parent.gid() == identity.gid()
                && named_parent.mode() == identity.mode(),
            "publication directory changed"
        );
        let target = CString::new("result.json")?;
        ensure!(
            unsafe {
                libc::renameat2(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    directory.as_raw_fd(),
                    target.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } == 0,
            "no-clobber result publication failed"
        );
        directory.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        // After a successful rename this name is absent. Never remove the final
        // record or an existing result, including when directory fsync fails.
        unsafe {
            libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0);
        }
    }
    result
}
pub fn run() -> Result<()> {
    ensure!(
        !cfg!(test) && !cfg!(feature = "test-fixtures"),
        "test image cannot run native capture"
    );
    let args = std::env::args().collect::<Vec<_>>();
    ensure!(
        args.len() == 4,
        "usage: jetstreamer-old220-peer-capture ADMISSION ADMISSION_SHA256 SELF_SHA256"
    );
    let bound = Bound {
        path: args[1].clone().into(),
        sha256: args[2].clone(),
    };
    let a: Admission = decode(&bound)?;
    validate_window(&a, now()?)?;
    validate_output(&a.output)?;
    ensure!(
        hex(&args[3], 64)
            && a.self_binary.sha256 == args[3]
            && fs::canonicalize("/proc/self/exe")? == a.self_binary.path,
        "wrong native binary binding"
    );
    immutable_bytes(&a.self_binary, 32 << 20)?;
    let lineage: Lineage = decode(&a.lineage)?;
    ensure!(
        lineage.schema == "horizon-old220-peers1061-normal-lineage-v1"
            && lineage.binary == a.self_binary
            && lineage.cargo_features.is_empty()
            && !lineage.normal_binary_test
            && !lineage.normal_library_test
            && !lineage.test_fixtures_enabled
            && lineage.source_hashes == embedded_sources(),
        "wrong normal source/feature lineage"
    );
    let source: SourceAcceptance = decode(&lineage.source_manifest)?;
    let build: BuildAcceptance = decode(&lineage.normal_build)?;
    validate_lineage_links(&a, &lineage, &source, &build)?;
    immutable_bytes(&source.original_frozen_manifest, 16 << 20)?;
    immutable_bytes(&build.original_normal_build, 4 << 20)?;
    immutable_bytes(&build.peer_library.file, 128 << 20)?;
    let mut native = Native {
        start: Instant::now(),
        queries: Vec::new(),
        stream_bytes: 0,
    };
    let attempt = (|| -> Result<(Value, MountView)> {
        let before = native.own(&a)?;
        let mounts = actual_mount_view(&a)?;
        let jobs = native.jobs()?;
        let proof = capture_condition_blocked(&mut native, &a.review, &jobs)?;
        ensure!(
            native.jobs()? == jobs && native.own(&a)? == before,
            "jobs or native owner changed"
        );
        validate_window(&a, now()?)?;
        ensure!(
            decode::<Admission>(&bound)?.self_binary == a.self_binary,
            "admission changed"
        );
        immutable_bytes(&a.lineage, 1 << 20)?;
        immutable_bytes(&lineage.source_manifest, 1 << 20)?;
        immutable_bytes(&lineage.normal_build, 1 << 20)?;
        ensure!(
            actual_mount_view(&a)? == mounts,
            "native mount layout changed during capture"
        );
        native.remaining()?;
        validate_window(&a, now()?)?;
        Ok((proof.summary(), mounts))
    })();
    match attempt {
        Ok((summary, mounts)) => publish(
            &a.output,
            &json!({"schema":"horizon-old220-peers1061-native-capture-result-v1","admission":bound,"normal_lineage":a.lineage,"actual_unit":a.unit,"actual_IID":a.invocation_id,"actual_main_pid":a.main_pid,"summary":summary,"sandbox_mountinfo_sha256":digest(mounts.raw.as_bytes()),"sandbox_mounts":mounts.raw,"writable_mounts":mounts.writable,"writable_api_filesystems_are_explicit_exceptions":true,"native_queries":native.queries,"elapsed_millis":native.start.elapsed().as_millis(),"historical_loader_execution_qualified":false,"global_alias_closure_qualified":false,"data_retirement_authorized":false,"capacity_credit_bytes":0}),
        ),
        Err(error) => {
            publish(
                &a.output,
                &json!({"schema":"horizon-old220-peers1061-native-capture-failure-v1","admission":bound,"actual_unit":a.unit,"actual_IID":a.invocation_id,"failure":format!("{error:#}"),"native_queries":native.queries,"data_retirement_authorized":false,"capacity_credit_bytes":0}),
            )?;
            Err(error)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn provenance_case() -> (Admission, Lineage, SourceAcceptance, BuildAcceptance) {
        let binary = json!({"path":"/var/lib/jetstreamer/package/capture","sha256":"a".repeat(64)});
        let source_ref =
            json!({"path":"/var/lib/jetstreamer/package/source.json","sha256":"b".repeat(64)});
        let original = json!({"path":"/var/lib/jetstreamer/original.json","sha256":"c".repeat(64)});
        let library = json!({"path":"/var/lib/jetstreamer/package/libhorizon_old220_peers1012-abc.rlib","sha256":"d".repeat(64)});
        let a = serde_json::from_value(json!({"schema":SCHEMA,"issued_unix_seconds":100,"expires_unix_seconds":280,"self_binary":binary,"lineage":original,"review":{"sha256":"e".repeat(64),"bytes":100},"unit":"horizon-old220-peers-test.service","invocation_id":"f".repeat(32),"main_pid":42,"start_ticks":123,"expected_properties":{},"output":"/var/lib/jetstreamer/horizon-old220-peers-test/result.json"})).unwrap();
        let l = serde_json::from_value(json!({"schema":"horizon-old220-peers1061-normal-lineage-v1","binary":binary,"source_manifest":source_ref,"normal_build":original,"cargo_features":[],"normal_binary_test":false,"normal_library_test":false,"test_fixtures_enabled":false,"source_hashes":embedded_sources()})).unwrap();
        let source = serde_json::from_value(json!({"schema":"horizon-old220-peers1061-source-acceptance-v1","original_frozen_manifest":original,"compiled_source_hashes":embedded_sources()})).unwrap();
        let build = serde_json::from_value(json!({"schema":"horizon-old220-peers1061-build-acceptance-v1","original_normal_build":original,"source_acceptance":source_ref,"binary":binary,"cargo_features":[],"binary_test":false,"peer_library":{"file":library,"cargo_features":[],"test":false},"actual_extern_crate":"horizon_old220_peers1012","actual_extern_file":{"path":"/frozen/target/release/deps/libhorizon_old220_peers1012-abc.rlib","sha256":"d".repeat(64)}})).unwrap();
        (a, l, source, build)
    }
    #[test]
    fn qualification_requires_source_artifact_feature_and_real_extern_links() {
        let (a, l, source, build) = provenance_case();
        validate_lineage_links(&a, &l, &source, &build).unwrap();
        let (_, _, mut bad, _) = provenance_case();
        bad.compiled_source_hashes
            .insert("lib.rs".into(), "0".repeat(64));
        assert!(validate_lineage_links(&a, &l, &bad, &build).is_err());
        for choice in 0..8 {
            let (_, _, _, mut bad) = provenance_case();
            match choice {
                0 => bad.source_acceptance.sha256 = "0".repeat(64),
                1 => bad.binary.sha256 = "0".repeat(64),
                2 => bad.cargo_features.push("test-fixtures".into()),
                3 => bad.binary_test = true,
                4 => bad.peer_library.test = true,
                5 => bad.peer_library.cargo_features.push("test-fixtures".into()),
                6 => bad.actual_extern_crate = "unrelated".into(),
                _ => bad.actual_extern_file.sha256 = "0".repeat(64),
            }
            assert!(
                validate_lineage_links(&a, &l, &source, &bad).is_err(),
                "case {choice}"
            );
        }
    }
    fn mount_fixture() -> (String, PathBuf) {
        let output = PathBuf::from("/var/lib/jetstreamer/horizon-old220-peers-test");
        let text = format!("1 0 8:1 / / ro - ext4 /dev/root rw\n2 1 0:1 / /proc rw - proc proc rw\n3 1 0:2 / /dev rw - tmpfs tmpfs rw\n4 1 0:3 / /sys ro - sysfs sysfs rw\n5 1 8:1 {} {} rw - ext4 /dev/root rw\n", output.display(), output.display());
        (text, output)
    }
    #[test]
    fn actual_mount_policy_rejects_unregistered_write_surfaces_and_redirects() {
        let (good, output) = mount_fixture();
        let valid = mount_view(good.clone(), &output).unwrap();
        assert_eq!(valid.writable.len(), 3);
        for bad in [
            format!("{good}6 1 8:1 /var/lib/extra /var/lib/extra rw - ext4 /dev/root rw\n"),
            good.replace("/ / ro -", "/ / rw -"),
            good.replace(
                &format!("{} {} rw", output.display(), output.display()),
                &format!("/foreign {} rw", output.display()),
            ),
            good.lines().take(4).map(|l| format!("{l}\n")).collect(),
            format!(
                "{good}6 1 8:1 {} {} rw - ext4 /dev/root rw\n",
                output.display(),
                output.display()
            ),
        ] {
            assert!(mount_view(bad, &output).is_err());
        }
        assert!(mount_path("/bad\\777escape").is_err());
        assert_eq!(mount_path("/a\\040b").unwrap(), "/a b");
    }
    #[test]
    fn sandbox_projection_properties_cannot_hide_extra_writable_directories() {
        let (_, output) = mount_fixture();
        let mut p = BTreeMap::new();
        for name in OWN_PROPERTIES.split(',') {
            p.insert(name.into(), String::new());
        }
        for key in [
            "PrivateDevices",
            "PrivateMounts",
            "ProtectKernelTunables",
            "ProtectKernelModules",
            "ProtectControlGroups",
        ] {
            p.insert(key.into(), "yes".into());
        }
        p.insert("PrivateTmp".into(), "no".into());
        p.insert("ReadWritePaths".into(), output.display().to_string());
        validate_write_properties(&p, &output).unwrap();
        for key in [
            "StateDirectory",
            "BindPaths",
            "TemporaryFileSystem",
            "RuntimeDirectory",
        ] {
            let mut bad = p.clone();
            bad.insert(key.into(), "extra".into());
            assert!(validate_write_properties(&bad, &output).is_err());
        }
    }
    #[test]
    fn atomic_result_publication_never_overwrites_an_existing_result() {
        let root = std::env::temp_dir().join(format!(
            "old220-atomic-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        publish_bytes(&root, b"{\"first\":true}").unwrap();
        assert_eq!(
            fs::read(root.join("result.json")).unwrap(),
            b"{\"first\":true}\n"
        );
        assert!(publish_bytes(&root, b"{\"second\":true}").is_err());
        assert_eq!(
            fs::read(root.join("result.json")).unwrap(),
            b"{\"first\":true}\n"
        );
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_file(root.join("result.json")).unwrap();
        fs::remove_dir(root).unwrap();
    }
    #[test]
    fn proc_comm_with_parentheses_preserves_start_identity() {
        let tail = std::iter::once("S")
            .chain(std::iter::repeat("0").take(18))
            .chain(std::iter::once("9876"))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            ticks(&format!("123 (a (strange) name) {tail}\n")).unwrap(),
            9876
        );
        assert!(ticks("123 (incomplete)").is_err());
    }
    #[test]
    fn native_properties_cannot_silently_replace_duplicates() {
        assert!(properties("MainPID=1\nMainPID=2\n").is_err());
        assert!(properties("not-a-property\n").is_err());
        assert_eq!(properties("Job=\n").unwrap()["Job"], "");
    }
    #[test]
    fn admission_rejects_expired_future_foreign_and_reused_owners() {
        let make = || Admission {
            schema: SCHEMA.into(),
            issued_unix_seconds: 100,
            expires_unix_seconds: 280,
            self_binary: Bound {
                path: "/var/lib/jetstreamer/package/capture".into(),
                sha256: "a".repeat(64),
            },
            lineage: Bound {
                path: "/var/lib/jetstreamer/package/lineage.json".into(),
                sha256: "b".repeat(64),
            },
            review: ReviewBinding {
                sha256: "c".repeat(64),
                bytes: 100,
            },
            unit: "horizon-old220-peers1061-native-v1.service".into(),
            invocation_id: "d".repeat(32),
            main_pid: 42,
            start_ticks: 123,
            expected_properties: BTreeMap::new(),
            output: "/var/lib/jetstreamer/horizon-old220-peers-result/result.json".into(),
        };
        validate_window(&make(), 101).unwrap();
        assert!(validate_window(&make(), 99).is_err());
        assert!(validate_window(&make(), 281).is_err());
        let mut a = make();
        a.expires_unix_seconds = 281;
        assert!(validate_window(&a, 101).is_err());
        let mut a = make();
        a.unit = "unrelated.service".into();
        assert!(validate_window(&a, 101).is_err());
        let mut a = make();
        a.invocation_id = "0".repeat(32);
        assert!(validate_window(&a, 101).is_err());
        let mut a = make();
        a.main_pid = 0;
        assert!(validate_window(&a, 101).is_err());
        let mut a = make();
        a.start_ticks = 0;
        assert!(validate_window(&a, 101).is_err());
    }
    #[test]
    fn output_must_be_exact_private_result_leaf() {
        for p in [
            "/tmp/result.json",
            "/var/lib/jetstreamer/foreign/result.json",
            "/var/lib/jetstreamer/horizon-old220-peers-x/other.json",
            "/var/lib/jetstreamer/horizon-old220-peers-x/../result.json",
        ] {
            assert!(validate_output(Path::new(p)).is_err());
        }
    }
}
