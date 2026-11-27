//! Launch an admitted private Foundation interval behind its first native guard.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const BASE: &str = "/var/lib/jetstreamer";
const LOCK: &str = "/var/lib/jetstreamer/horizon-seven-publication-controller-v222/cycle.lock";
const THIRD_SCOPE: &str = "d0007aef065d1bc9af56f14fc22c63edf1f87cdf9b35f3f9b702b44f969acbfa";
const FOURTH_SCOPE: &str = "e418efbb8329dd5e05c08aa9d829d50c719fd4412981a019416301985bbdf3a6";
const RAM: u64 = 74 << 30;
const GUARD_RAM: u64 = 1 << 30;
const TMPFS: u64 = 44 << 30;
const HOME: u64 = (4 << 30) + (320 << 20);

fn str_at<'a>(row: &'a Value, key: &str) -> Result<&'a str> {
    row[key].as_str().with_context(|| format!("missing {key}"))
}

fn number(row: &Value, key: &str) -> Result<u64> {
    row[key].as_u64().with_context(|| format!("missing {key}"))
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn stamp(m: &Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

fn sealed(path: &Path) -> Result<(File, Metadata)> {
    let m = path.symlink_metadata()?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && m.uid() == 0
            && m.mode() & 0o222 == 0
            && m.nlink() == 1,
        "unsealed artifact {}",
        path.display()
    );
    let file = File::open(path)?;
    ensure!(
        stamp(&file.metadata()?) == stamp(&m),
        "opened artifact changed"
    );
    Ok((file, m))
}

fn reference(path: &Path) -> Result<Value> {
    let (mut file, m) = sealed(path)?;
    let mut hash = Sha256::new();
    io::copy(&mut file, &mut hash)?;
    ensure!(
        stamp(&file.metadata()?) == stamp(&m) && stamp(&path.symlink_metadata()?) == stamp(&m),
        "artifact changed during SHA-256"
    );
    Ok(json!({"path":path,"sha256":format!("{:x}",hash.finalize())}))
}

fn load(path: &Path, expected: &str) -> Result<Value> {
    let actual = reference(path)?;
    ensure!(
        actual["sha256"] == expected && path.metadata()?.len() <= 8 << 20,
        "invalid sealed JSON {}",
        path.display()
    );
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn resolve(row: &Value) -> Result<Value> {
    load(Path::new(str_at(row, "path")?), str_at(row, "sha256")?)
}

fn write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    use std::ffi::CString;
    let parent = path.parent().context("receipt parent")?;
    let pending = parent.join(format!(
        ".{}.{}-pending",
        path.file_name().context("receipt name")?.to_string_lossy(),
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&pending)?;
    file.write_all(bytes)?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.sync_all()?;
    let from = CString::new(pending.as_os_str().as_bytes())?;
    let to = CString::new(path.as_os_str().as_bytes())?;
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(io::Error::last_os_error()).context("publish new interval evidence");
    }
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn record(path: &Path, value: &Value) -> Result<Value> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write(path, &bytes, 0o400)?;
    reference(path)
}

fn run(command: &mut Command) -> Result<String> {
    let output = command.output()?;
    ensure!(
        output.status.success(),
        "{}: {}",
        command.get_program().to_string_lossy(),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

fn properties(unit: &str, fields: &str) -> Result<BTreeMap<String, String>> {
    run(Command::new("/usr/bin/systemctl").args(["show", unit, "-p", fields]))?
        .lines()
        .map(|line| {
            line.split_once('=')
                .context("bad manager property")
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
        })
        .collect()
}

fn has(unit: &str, state: &str) -> Result<bool> {
    Ok(properties(unit, "ActiveState")?
        .get("ActiveState")
        .is_some_and(|value| value == state))
}

fn property_args(command: &mut Command, properties: &BTreeMap<String, String>) {
    for (key, value) in properties {
        command.arg(format!("--property={key}={value}"));
    }
}

fn dir(path: &Path, uid: &str, mode: &str) -> Result<()> {
    ensure!(
        path.symlink_metadata()
            .is_err_and(|error| error.kind() == io::ErrorKind::NotFound),
        "runtime path already exists {}",
        path.display()
    );
    run(Command::new("/usr/bin/install")
        .args(["-d", "-m", mode, "-o", uid, "-g", uid])
        .arg(path))?;
    Ok(())
}

fn available(path: &Path) -> Result<u64> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let path = CString::new(path.as_os_str().as_bytes())?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    stat.f_bavail
        .checked_mul(stat.f_frsize)
        .context("free-byte overflow")
}

fn peer_check(roster: &Value, home: &Path) -> Result<()> {
    let cap = &roster["capacity"];
    ensure!(
        roster["admission_issued"] == false
            && cap["fits"] == true
            && now()?
                .checked_sub(number(roster, "recorded_unix_seconds")?)
                .is_some_and(|age| age <= 120)
            && home.metadata()?.dev() == number(roster, "filesystem_device")?
            && cap["candidate_disk_bytes"] == HOME
            && available(home)? >= number(cap, "required_disk_bytes")?,
        "stale or unfunded interval roster"
    );
    let meminfo = fs::read_to_string("/proc/meminfo")?;
    let available = meminfo
        .lines()
        .find_map(|line| {
            line.strip_prefix("MemAvailable:")?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()
        })
        .context("missing available RAM")?
        .checked_mul(1024)
        .context("available RAM overflow")?;
    ensure!(
        available >= number(cap, "required_remaining_memory_bytes")?
            && number(cap, "host_total_memory_bytes")?
                >= number(cap, "required_hard_memory_bytes")?,
        "RAM changed since the admission quote"
    );
    let mut expected_running = std::collections::BTreeSet::new();
    for (unit, proof) in roster["owners"]
        .as_object()
        .context("missing complete owner census")?
    {
        let keys =
            "ActiveState,AllowedCPUs,ControlGroup,InvocationID,Job,MainPID,MemoryMax,MemorySwapMax";
        let actual = properties(unit, keys)?;
        for key in keys.split(',') {
            ensure!(
                actual.get(key).map(String::as_str) == proof["systemd"][key].as_str(),
                "fleet owner {unit} changed {key}"
            );
        }
        expected_running.insert(unit.as_str());
    }
    let live = run(Command::new("/usr/bin/systemctl").args([
        "list-units",
        "--type=service",
        "--state=running,activating",
        "--plain",
        "--no-legend",
        "--no-pager",
    ]))?;
    for unit in live
        .lines()
        .filter_map(|line| line.split_whitespace().next())
    {
        let campaign = ["horizon-", "foundation-", "archive-", "jetstreamer-"]
            .iter()
            .any(|p| unit.starts_with(p));
        let existing_guard = roster["periodic_guards"]
            .as_object()
            .context("missing guard census")?
            .values()
            .any(|guard| guard["unit"] == unit)
            || ([
                "horizon-141-foundation-interval2-guard-v1.service",
                "horizon-141-foundation-interval3-guard-v1.service",
                "horizon-141-foundation-interval4-guard-v1.service",
            ]
            .contains(&unit)
                && expected_running.contains(
                    unit.replace("horizon-141-foundation", "horizon-qualify-141-foundation")
                        .replace("-guard-v1.service", "-v1.service")
                        .as_str(),
                ));
        ensure!(
            !campaign || expected_running.contains(unit) || existing_guard,
            "unbooked live owner {unit}"
        );
    }
    Ok(())
}

fn guarded_sample(
    directory: &Path,
    unit: &str,
    invocation: &str,
    pid: u64,
    plan: &Value,
) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(58);
    while Instant::now() < deadline {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if !path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("sample-") && n.ends_with(".json"))
            {
                continue;
            }
            let m = path.symlink_metadata()?;
            ensure!(
                m.is_file()
                    && m.uid() == 0
                    && m.gid() == 0
                    && m.nlink() == 1
                    && m.mode() & 0o7777 == 0o600
                    && m.len() <= 1 << 20,
                "unexpected native guard sample"
            );
            let mut bytes = Vec::new();
            let mut f = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)?;
            ensure!(
                stamp(&f.metadata()?) == stamp(&m),
                "native guard sample replaced"
            );
            Read::by_ref(&mut f)
                .take((1 << 20) + 1)
                .read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() as u64 == m.len()
                    && stamp(&f.metadata()?) == stamp(&m)
                    && stamp(&path.symlink_metadata()?) == stamp(&m),
                "native guard sample changed"
            );
            let binding = json!({"path":path,"sha256":format!("{:x}",Sha256::digest(&bytes))});
            let sample: Value = serde_json::from_slice(&bytes)?;
            if sample["producer_invocation_id"] != invocation {
                continue;
            }
            ensure!(
                sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
                    && sample["producer"]["pid"] == pid
                    && sample["producer"]["active"] == "active"
                    && sample["producer"]["cgroup"] == format!("/system.slice/{unit}")
                    && sample["plan_sha256"] == plan["sha256"]
                    && sample["trip_reason"].is_null()
                    && sample["worker_observation_error"].is_null()
                    && sample["root_physical_observation_error"].is_null(),
                "first guard sample does not cover the held owner"
            );
            return Ok(binding);
        }
        ensure!(
            has(unit, "active")?,
            "held producer left before first guard"
        );
        thread::sleep(Duration::from_millis(400));
    }
    anyhow::bail!("first protective sample did not arrive")
}

fn scoped(ordinal: u8) -> Result<(PathBuf, PathBuf, Value)> {
    let scope_sha = match ordinal {
        3 => THIRD_SCOPE,
        4 => FOURTH_SCOPE,
        _ => anyhow::bail!("unknown private interval"),
    };
    let state = Path::new(BASE).join(format!(
        "horizon141-foundation-interval{ordinal}-runtime-v1"
    ));
    let scope_path = state.join("runtime-scope.json");
    let scope = load(&scope_path, scope_sha)?;
    ensure!(
        scope["ordinal"] == ordinal
            && scope["runtime_launch_authorized"] == false
            && scope["canonical_publication_authorized"] == false
            && scope["producer_memory_bytes"] == RAM
            && scope["guard_memory_bytes"] == GUARD_RAM
            && scope["private_tmpfs_bytes"] == TMPFS,
        "changed runtime scope"
    );
    Ok((state, scope_path, scope))
}

fn record_exit(ordinal: u8) -> Result<()> {
    let (state, scope_path, scope) = scoped(ordinal)?;
    let unit = str_at(&scope, "unit")?;
    let iid = env::var("INVOCATION_ID")?;
    let expected = format!("0::/system.slice/{unit}");
    ensure!(
        fs::read_to_string("/proc/self/cgroup")?
            .lines()
            .any(|line| line == expected),
        "terminal capture is outside its native producer cgroup"
    );
    let observed = properties(
        unit,
        "Id,InvocationID,ActiveState,MainPID,ControlPID,ExecMainPID,ExecMainCode,ExecMainStatus,ExecMainExitTimestampMonotonic,Result",
    )?;
    ensure!(
        iid.len() == 32
            && observed["InvocationID"] == iid
            && observed["Id"] == unit
            && observed["MainPID"] == "0"
            && observed["ControlPID"] == std::process::id().to_string()
            && observed["ExecMainPID"].parse::<u64>()? > 0
            && observed["ExecMainExitTimestampMonotonic"].parse::<u64>()? > 0,
        "terminal capture differs from the native invocation"
    );
    let launch = state.join("replay-launch.json");
    let launch = if launch.try_exists()? {
        let binding = reference(&launch)?;
        ensure!(
            resolve(&binding)?["invocation_id"] == iid,
            "terminal launch differs"
        );
        Some(binding)
    } else {
        None
    };
    let proof = record(
        &state.join("terminal-evidence/native-exit.json"),
        &json!({
            "schema":format!("foundation-epoch141-interval{ordinal}-native-exit-v1"),
            "unit":unit,"invocation_id":iid,"observed_unix_seconds":now()?,
            "scope":reference(&scope_path)?,"launch":launch,"native_properties":observed,
            "service_result":env::var("SERVICE_RESULT")?,
            "exit_code":env::var("EXIT_CODE")?,"exit_status":env::var("EXIT_STATUS")?
        }),
    )?;
    println!("{}", serde_json::to_string(&proof)?);
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "Foundation launch requires root"
    );
    if args.len() == 3 && args[1] == "--record-exit" {
        return record_exit(args[2].parse()?);
    }
    ensure!(
        args.len() == 4,
        "usage: horizon-native141-foundation-launch INTERVAL ROSTER ROSTER_SHA256"
    );
    let ordinal = args[1].parse::<u8>()?;
    let (state, scope_path, scope) = scoped(ordinal)?;
    let lock = OpenOptions::new().read(true).open(LOCK)?;
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "fleet cadence lock busy"
    );
    let roster_file = Path::new(&args[2]);
    let roster = load(roster_file, &args[3])?;
    ensure!(
        roster["schema"] == format!("foundation-epoch141-interval{ordinal}-roster-binding-v1"),
        "foreign interval roster"
    );
    let inputs = &roster["private_interval_141_candidate"];
    let input_doc = resolve(&inputs["static_inputs"])?;
    ensure!(
        inputs["static_inputs"]["path"] == json!(state.join("static-inputs.json"))
            && input_doc["interval"] == scope["interval"],
        "static inputs do not match the scoped interval"
    );
    let boot = resolve(&input_doc["bootstrap_intake"])?;
    let payload = Path::new(str_at(&boot, "installed_path")?);
    let payload_meta = payload.symlink_metadata()?;
    ensure!(
        payload.parent() == Some(state.join("payloads").as_path())
            && payload_meta.is_file()
            && payload_meta.uid() == 0
            && payload_meta.mode() & 0o222 == 0
            && payload_meta.nlink() == 1
            && payload_meta.ino() == number(&boot, "inode")?
            && payload_meta.dev() == number(&boot, "device")?
            && payload_meta.len() == number(&boot, "bytes")?
            && boot["gcs_generation_checksums_match"] == true,
        "boot payload changed after verified intake"
    );
    for key in [
        "node",
        "worker",
        "genesis",
        "guard",
        "gate",
        "checkpoint_names",
    ] {
        ensure!(
            reference(Path::new(str_at(&scope[key], "path")?))? == scope[key],
            "{key} changed"
        );
    }
    let unit = str_at(&scope, "unit")?;
    let guard_unit = str_at(&scope, "guard_unit")?;
    let guard_timer = str_at(&scope, "guard_timer")?;
    for actor in [unit, guard_unit, guard_timer] {
        ensure!(
            properties(actor, "LoadState")?["LoadState"] == "not-found",
            "existing actor {actor}"
        );
    }
    let alias = Path::new(str_at(&scope, "alias")?);
    let tmpfs = Path::new(str_at(&scope, "tmpfs")?);
    let release = state.join("release");
    let guard_reports = state.join("guard-samples");
    let terminal = state.join("terminal-evidence");
    for mount in [tmpfs, alias, &release, &guard_reports, &terminal] {
        ensure!(
            !mount.try_exists()?,
            "reserved runtime path exists {}",
            mount.display()
        );
    }
    let handoff_path = state.join(if ordinal == 3 {
        "inputs/epoch141-third-foundation-handoff.json"
    } else {
        "inputs/foundation-assignment.json"
    });
    let handoff = reference(&handoff_path)?;
    if ordinal == 4 {
        ensure!(handoff == inputs["handoff"], "fourth assignment changed");
    }
    peer_check(&roster, &state)?;
    let mut admission = json!({
        "schema":format!("foundation-epoch141-interval{ordinal}-replay-admission-v1"),
        "issued_unix_seconds":now()?,"handoff":handoff,"runtime_scope":reference(&scope_path)?,
        "roster":reference(roster_file)?,"static_inputs":inputs["static_inputs"],
        "producer_cpus":scope["producer_cpus"],"guard_cpu":scope["guard_cpu"],
        "producer_memory_bytes":RAM,"guard_memory_bytes":GUARD_RAM,"future_home_bytes":HOME,
        "canonical_publication_authorized":false
    });
    if ordinal == 3 {
        admission["predecessor_terminal"] = inputs["predecessor_terminal"].clone();
        admission["predecessor_drain"] = inputs["predecessor_drain"].clone();
    }
    let admission = record(&state.join("replay-admission.json"), &admission)?;
    dir(tmpfs, "root", "0700")?;
    dir(alias, "root", "0700")?;
    dir(&release, "root", "0755")?;
    dir(&guard_reports, "root", "0700")?;
    dir(&terminal, "root", "0700")?;
    let options = format!("rw,noswap,nosuid,nodev,exec,size={TMPFS},uid=1000,gid=1000,mode=0700");
    run(Command::new("/usr/bin/mount")
        .args(["-t", "tmpfs", "-o", &options, "tmpfs"])
        .arg(tmpfs))?;
    run(Command::new("/usr/bin/mount")
        .arg("--bind")
        .arg(tmpfs)
        .arg(alias))?;
    ensure!(
        stamp(&tmpfs.metadata()?) == stamp(&alias.metadata()?),
        "host alias differs from private tmpfs"
    );
    for child in ["ledger", "scratch", "private"] {
        dir(&tmpfs.join(child), "ubuntu", "0700")?;
    }
    let genesis = fs::read(str_at(&scope["genesis"], "path")?)?;
    write(&tmpfs.join("ledger/genesis.tar.bz2"), &genesis, 0o444)?;
    let affinity = if ordinal == 3 { "24-25" } else { "27-28" };
    let binding = scope["read_only_bindings"]
        .as_object()
        .context("missing read-only projections")?
        .iter()
        .map(|(source, target)| {
            Ok(format!(
                "{source}:{}",
                target.as_str().context("projection alias")?
            ))
        })
        .collect::<Result<Vec<_>>>()?
        .join(" ");
    let sandbox = BTreeMap::from([
        ("Type".into(),"exec".into()), ("User".into(),"ubuntu".into()), ("Group".into(),"ubuntu".into()),
        ("UMask".into(),"0077".into()),("NoNewPrivileges".into(),"yes".into()),
        ("ProtectSystem".into(),"strict".into()),("ProtectHome".into(),"read-only".into()),
        ("PrivateTmp".into(),"yes".into()),("TemporaryFileSystem".into(),"/home:rw,nosuid,nodev,size=1M,mode=0755".into()),
        ("BindPaths".into(),format!("{}:{}",tmpfs.display(),alias.display())),
        ("ReadWritePaths".into(),format!("{} {}",alias.display(),terminal.display())),("BindReadOnlyPaths".into(),binding),
        ("UnsetEnvironment".into(),"HORIZON_S3_ENDPOINT HORIZON_ACCESS_KEY_ID HORIZON_SECRET_ACCESS_KEY HORIZON_TOKEN AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN".into()),
        ("AllowedCPUs".into(),affinity.into()),("CPUAffinity".into(),affinity.into()),("CPUQuota".into(),"200%".into()),
        ("MemoryMax".into(),RAM.to_string()),("MemorySwapMax".into(),"0".into()),("TasksMax".into(),"128".into()),
        ("KillMode".into(),"control-group".into()),("Restart".into(),"no".into()),
        ("RuntimeMaxSec".into(),format!("{}s",number(&scope,"runtime_seconds")?)),("TimeoutStopSec".into(),"15s".into()),
        ("ExecStopPost".into(),format!("+{} --record-exit {ordinal}",env::current_exe()?.display())),
    ]);
    peer_check(&roster, &state)?;
    let mut producer = Command::new("/usr/bin/systemd-run");
    producer.args(["--quiet", &format!("--unit={unit}")]);
    property_args(&mut producer, &sandbox);
    for (key, value) in scope["env"].as_object().context("runtime environment")? {
        producer.arg(format!(
            "--setenv={key}={}",
            value.as_str().context("environment value")?
        ));
    }
    for arg in scope["argv"].as_array().context("runtime argv")? {
        producer.arg(arg.as_str().context("runtime argument")?);
    }
    run(&mut producer)?;
    let keys = "Id,ActiveState,InvocationID,MainPID,AllowedCPUs,MemoryMax,MemorySwapMax,ControlGroup,NRestarts";
    let owner = properties(unit, keys)?;
    let iid = &owner["InvocationID"];
    let pid = owner["MainPID"].parse::<u64>()?;
    ensure!(
        iid.len() == 32
            && iid.bytes().all(|b| b.is_ascii_hexdigit())
            && pid > 0
            && owner["ActiveState"] == "active"
            && owner["AllowedCPUs"] == affinity
            && owner["MemoryMax"] == RAM.to_string()
            && owner["MemorySwapMax"] == "0"
            && owner["NRestarts"] == "0",
        "guarded producer has a foreign process envelope"
    );
    let root = PathBuf::from(format!("/proc/{pid}/root"));
    let projected = root.join(alias.strip_prefix("/")?);
    ensure!(
        stamp(&projected.metadata()?) == stamp(&alias.metadata()?)
            && stamp(&fs::metadata(format!("/proc/{pid}/exe"))?)
                == stamp(&fs::metadata(str_at(&scope["gate"], "path")?)?),
        "held namespace or gate changed"
    );
    let namespace = fs::read_to_string(format!("/proc/{pid}/mountinfo"))?;
    for (source, target) in scope["read_only_bindings"]
        .as_object()
        .context("projections")?
    {
        let target = target.as_str().context("projection alias")?;
        ensure!(
            stamp(&fs::metadata(source)?)
                == stamp(&root.join(target.trim_start_matches('/')).metadata()?)
                && namespace.lines().any(|line| {
                    let c: Vec<_> = line.split_ascii_whitespace().collect();
                    c.get(4) == Some(&target)
                        && c.get(5)
                            .is_some_and(|flags| flags.split(',').any(|v| v == "ro"))
                }),
            "held read-only projection is foreign: {target}"
        );
    }
    let held = record(
        &state.join("held-namespace.json"),
        &json!({"schema":format!("foundation-epoch141-interval{ordinal}-held-namespace-v1"),
        "unit":unit,"producer":owner,"alias":alias,"tmpfs":tmpfs,"runtime_scope":reference(&scope_path)?,
        "read_only_projection_count":scope["read_only_bindings"].as_object().unwrap().len()}),
    )?;
    let plan = record(
        &state.join("guard-plan.json"),
        &json!({
            "schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":unit,"invocation_id":iid,
            "filesystem":tmpfs.join("ledger"),"worker_root":alias,"minimum_free_bytes":scope["minimum_tmpfs_free_bytes"],
            "maximum_root_physical_bytes":TMPFS,"maximum_worker_vmas":scope["maximum_worker_vmas"],
            "receipt_directory":guard_reports
        }),
    )?;
    let guard_stem = guard_unit
        .strip_suffix(".service")
        .context("unexpected guard unit name")?;
    let guard_cpu = number(&scope, "guard_cpu")?.to_string();
    run(Command::new("/usr/bin/systemd-run").args([
        "--quiet",
        &format!("--unit={guard_stem}"),
        "--on-active=1s",
        "--on-unit-active=30s",
        "--timer-property=AccuracySec=1s",
        &format!("--property=AllowedCPUs={guard_cpu}"),
        &format!("--property=CPUAffinity={guard_cpu}"),
        "--property=CPUQuota=100%",
        &format!("--property=MemoryMax={GUARD_RAM}"),
        "--property=MemorySwapMax=0",
        "--property=RuntimeMaxSec=25s",
        "--property=Type=exec",
        str_at(&scope["guard"], "path")?,
        str_at(&plan, "path")?,
        "--plan-sha256",
        str_at(&plan, "sha256")?,
        "--self-sha256",
        str_at(&scope["guard"], "sha256")?,
    ]))?;
    let first = guarded_sample(&guard_reports, unit, iid, pid, &plan)?;
    let timer = properties(guard_timer, "ActiveState,InvocationID,Unit")?;
    ensure!(
        timer["ActiveState"] == "active"
            && timer["Unit"] == guard_unit
            && timer["InvocationID"].len() == 32,
        "lost private interval guard timer"
    );
    ensure!(
        properties(unit, keys)? == owner,
        "guarded owner changed before invocation release"
    );
    let receipt = record(
        &state.join("replay-launch.json"),
        &json!({
            "schema":format!("foundation-epoch141-interval{ordinal}-replay-launch-v1"),
            "unit":unit,"invocation_id":iid,"recorded_unix_seconds":now()?,"admission":admission,
            "held_namespace":held,"guard_plan":plan,"guard_timer_invocation_id":timer["InvocationID"],
            "first_guard":first,"canonical_publication_authorized":false
        }),
    )?;
    let token = format!("{iid}\n{}\n", str_at(&first, "sha256")?);
    write(
        &release.join(format!("{iid}.release")),
        token.as_bytes(),
        0o444,
    )?;
    println!("{}", serde_json::to_string(&receipt)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_token_is_published_with_its_final_identity_and_never_replaced() {
        let folder = tempfile::tempdir().unwrap();
        let token = folder.path().join("guard.release");
        let body = format!("{}\n{}\n", "a".repeat(32), "b".repeat(64));
        write(&token, body.as_bytes(), 0o444).unwrap();
        assert_eq!(fs::read(&token).unwrap(), body.as_bytes());
        let metadata = fs::symlink_metadata(&token).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o444);
        assert_eq!(metadata.nlink(), 1);
        assert!(write(&token, b"foreign", 0o444).is_err());
        assert_eq!(fs::read(&token).unwrap(), body.as_bytes());
    }
}
