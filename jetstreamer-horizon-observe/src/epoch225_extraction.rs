//! Metadata contract for one admitted epoch 225 extraction task.
//! This module grants no admission, archive, runtime promotion or R2 authority.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
pub const PLAN: &str = "jetstreamer-epoch225-prefix-extraction-plan-v1";
pub const ADMISSION: &str = "jetstreamer-epoch225-prefix-extraction-admission-v1";
pub const RELEASE: &str = "jetstreamer-epoch225-prefix-extraction-release-v1";
pub const LAUNCH: &str = "jetstreamer-epoch225-prefix-extraction-launch-v1";
pub const MEMORY: u64 = 96 << 30;
pub const OUTPUT: u64 = 320 << 30;
pub const METADATA: u64 = 256 << 20;
pub const OLD_UNIT: &str =
    "horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service";
pub const OLD_IID: &str = "4cd76ae1353a4411885b997f04306402";
pub const ORIGINAL: &str = "/home/ubuntu/.jetstreamer-private/qualification-225-v1625-natural-root-shrink-budget-2f856bd-v1/output/epoch-225.jet";
pub const MANIFEST_SHA: &str = "53a69d801e70866b0bc048e1b3a75d9c16c1fb93995503157fc206742f3cdcf6";
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Bound {
    pub path: PathBuf,
    pub sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema: String,
    pub attempt: String,
    pub unit: String,
    pub guard_unit: String,
    pub root: PathBuf,
    pub executable: Bound,
    pub admitter: Bound,
    pub deployment_seal: Bound,
    pub qualification: Bound,
    pub unit_file: PathBuf,
    pub terminal_handoff: Bound,
    pub source_manifest: Bound,
    pub guard_executable: Bound,
    pub guard_qualification: Bound,
    pub admission: PathBuf,
    pub release: PathBuf,
}
pub fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
pub fn denied() -> Value {
    json!({"replay_launch_authorized":false,"runtime_promotion_authorized":false,
    "publication_authorized":false,"canonical_sidecar_authorized":false,"retirement_authorized":false,"r2_mutations":false})
}
pub fn identity(m: &fs::Metadata) -> Value {
    json!({"device":m.dev(),"inode":m.ino(),"bytes":m.len(),
    "mtime":m.mtime(),"mtime_ns":m.mtime_nsec(),"ctime":m.ctime(),"ctime_ns":m.ctime_nsec(),"uid":m.uid(),"mode":m.mode(),"links":m.nlink()})
}
pub fn bytes(b: &Bound, maximum: u64, frozen: bool) -> Result<Vec<u8>> {
    ensure!(
        hex(&b.sha256, 64) && b.path.is_absolute() && b.path.canonicalize()? == b.path,
        "epoch 225 evidence path or hash differs"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&b.path)?;
    let before = f.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.len() <= maximum
            && before.mode() & if frozen { 0o222 } else { 0o022 } == 0,
        "epoch 225 evidence custody differs"
    );
    let mut raw = Vec::new();
    (&mut f).take(maximum + 1).read_to_end(&mut raw)?;
    ensure!(
        raw.len() as u64 <= maximum
            && identity(&before) == identity(&f.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(&b.path)?)
            && format!("{:x}", Sha256::digest(&raw)) == b.sha256,
        "epoch 225 evidence changed"
    );
    Ok(raw)
}
pub fn read(b: &Bound) -> Result<Value> {
    Ok(serde_json::from_slice(&bytes(b, 16 << 20, true)?)?)
}
pub fn binding(path: &Path) -> Result<Bound> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.len() <= 16 << 20
            && m.mode() & 0o222 == 0,
        "epoch 225 receipt is not frozen"
    );
    let raw = fs::read(path)?;
    let b = Bound {
        path: path.into(),
        sha256: format!("{:x}", Sha256::digest(&raw)),
    };
    read(&b)?;
    Ok(b)
}
pub fn persist(path: &Path, v: &Value) -> Result<()> {
    let parent = path.parent().context("epoch 225 receipt parent missing")?;
    private(parent)?;
    ensure!(!path.try_exists()?, "epoch 225 receipt already exists");
    let mut f = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(f.as_file_mut(), v)?;
    f.write_all(b"\n")?;
    f.as_file()
        .set_permissions(fs::Permissions::from_mode(0o444))?;
    f.as_file().sync_all()?;
    f.persist_noclobber(path)
        .map_err(|e| anyhow::anyhow!("epoch 225 receipt conflict: {e}"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
pub fn private(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o7777 == 0o700,
        "epoch 225 directory must be canonical root-private"
    );
    Ok(())
}
pub fn shape(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == PLAN
            && !p.attempt.is_empty()
            && p.attempt.len() <= 64
            && !p.attempt.ends_with("-guard")
            && p.attempt
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && p.unit == format!("horizon-qualify-225-prefix-extract-{}.service", p.attempt)
            && p.guard_unit
                == format!(
                    "horizon-qualify-225-prefix-extract-{}-guard.service",
                    p.attempt
                )
            && p.root
                == Path::new("/home/ubuntu/.jetstreamer-private")
                    .join(format!("epoch225-prefix-extract-{}", p.attempt))
            && p.release == p.root.join("release.json")
            && p.unit_file == Path::new("/etc/systemd/system").join(&p.unit)
            && p.admission
                == Path::new("/var/lib/jetstreamer").join(format!(
                    "horizon-epoch225-extract-admission-{}/admission.json",
                    p.attempt
                ))
            && p.executable
                .path
                .file_name()
                .is_some_and(|n| n == "jetstreamer-epoch225-prefix-extract")
            && p.source_manifest.path == Path::new(&format!("{ORIGINAL}.segment.json"))
            && p.source_manifest.sha256 == MANIFEST_SHA,
        "epoch 225 plan scope differs"
    );
    Ok(())
}
pub fn argv(p: &Plan, b: &Bound) -> Vec<String> {
    vec![
        p.executable.path.display().to_string(),
        b.path.display().to_string(),
        "--plan-sha256".into(),
        b.sha256.clone(),
        "--self-sha256".into(),
        p.executable.sha256.clone(),
    ]
}
fn unit_controls(p: &Plan, b: &Bound) -> BTreeMap<&'static str, String> {
    let mut expected=BTreeMap::from([
        ("Type","exec"),("User","root"),("Group","root"),("UMask","0077"),("MemoryHigh","72G"),("MemoryMax","96G"),("MemorySwapMax","0"),
        ("CPUQuota","800%"),("CPUQuotaPeriodSec","100ms"),("TasksMax","512"),("RuntimeMaxSec","86400"),("Restart","no"),
        ("KillMode","control-group"),("Delegate","no"),("PrivateNetwork","yes"),("ProtectSystem","strict"),("ProtectHome","read-only"),
        ("NoNewPrivileges","yes"),("CapabilityBoundingSet","CAP_DAC_READ_SEARCH"),("AmbientCapabilities","CAP_DAC_READ_SEARCH"),
        ("StandardOutput","journal"),("StandardError","journal"),("Environment","RUST_LOG=info"),("WorkingDirectory","/var/lib/jetstreamer"),
        ("UnsetEnvironment","LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT BASH_ENV ENV PYTHONPATH PYTHONHOME RUBYOPT PERL5OPT GCONV_PATH"),
    ].map(|(k,v)|(k,v.to_string())));
    expected.insert("ExecStart", argv(p, b).join(" "));
    expected.insert("ReadWritePaths", p.root.display().to_string());
    expected
}
fn unit_shape(p: &Plan, b: &Bound, raw: &str) -> Result<()> {
    let mut section = "";
    let mut controls = BTreeMap::new();
    for line in raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with(';'))
    {
        if line.starts_with('[') {
            ensure!(
                matches!(line, "[Unit]" | "[Service]" | "[Install]"),
                "epoch 225 unknown unit section"
            );
            section = line;
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .context("epoch 225 unit declaration malformed")?;
        match section {
            "[Service]" => {
                ensure!(
                    controls.insert(k, v.to_string()).is_none(),
                    "epoch 225 duplicate unit control"
                );
            }
            "[Unit]" => ensure!(
                k == "Description" && !v.is_empty(),
                "epoch 225 unit trigger/dependency is not admitted"
            ),
            "[Install]" => ensure!(
                k == "WantedBy" && v == "multi-user.target",
                "epoch 225 install target differs"
            ),
            _ => anyhow::bail!("epoch 225 unit control has no section"),
        }
    }
    ensure!(
        controls == unit_controls(p, b),
        "epoch 225 native unit source contains missing, changed or additional controls"
    );
    Ok(())
}
pub fn unit_binding(p: &Plan, b: &Bound) -> Result<Bound> {
    let before = fs::symlink_metadata(&p.unit_file)?;
    ensure!(
        p.unit_file.canonicalize()? == p.unit_file
            && before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o222 == 0
            && before.len() <= 64 << 10,
        "epoch 225 installed unit is not frozen root-owned source"
    );
    let mut raw = Vec::new();
    File::open(&p.unit_file)?
        .take((64 << 10) + 1)
        .read_to_end(&mut raw)?;
    ensure!(
        raw.len() <= 64 << 10
            && identity(&before) == identity(&fs::symlink_metadata(&p.unit_file)?),
        "epoch 225 unit source changed"
    );
    unit_shape(p, b, std::str::from_utf8(&raw)?)?;
    Ok(Bound {
        path: p.unit_file.clone(),
        sha256: format!("{:x}", Sha256::digest(&raw)),
    })
}
pub fn load(b: &Bound) -> Result<Plan> {
    let p: Plan = serde_json::from_value(read(b)?)?;
    shape(&p)?;
    Ok(p)
}
pub fn qualified(p: &Plan) -> Result<()> {
    bytes(&p.executable, 256 << 20, true)?;
    bytes(&p.admitter, 256 << 20, true)?;

    bytes(&p.guard_executable, 256 << 20, true)?;
    let g = read(&p.guard_qualification)?;
    ensure!(
        g["schema"] == "jetstreamer-epoch225-extraction-guard-qualification-v1"
            && g["executable"] == json!(p.guard_executable)
            && g["standalone_guard_qa_passed"] == true
            && g["empty_worker_set_supported"] == true
            && g["producer_stop_supported"] == true
            && g["source_qa_passed"] == true
            && g["publication_authorized"] == false,
        "epoch 225 protective guard lacks exact role qualification"
    );
    let seal = read(&p.deployment_seal)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"]
                == serde_json::to_value(
                    p.executable
                        .path
                        .parent()
                        .context("epoch 225 executable parent missing")?
                )?
            && seal["replay_launch_authorized"] == false
            && seal["publication_authorized"] == false
            && seal["r2_mutations"] == false
            && seal["members"].as_array().is_some_and(|a| a
                .iter()
                .any(|v| v["name"] == "jetstreamer-epoch225-prefix-extract"
                    && v["sha256"] == p.executable.sha256)),
        "epoch 225 executable is not a sealed member"
    );
    ensure!(
        p.executable.path.parent() == p.deployment_seal.path.parent(),
        "epoch 225 executable escaped its seal"
    );
    let q = read(&p.qualification)?;
    ensure!(
        q["schema"] == "jetstreamer-epoch225-extraction-role-qualification-v1"
            && q["role"] == "prefix-extraction"
            && q["executable"] == json!(p.executable)
            && q["source_qa_passed"] == true
            && q["cli_qa_passed"] == true
            && q["resource_admission_claimed"] == false
            && q["runtime_promotion_authorized"] == false
            && q["publication_authorized"] == false
            && q["source_commit"].as_str().is_some_and(|s| hex(s, 40))
            && q["source_tree"].as_str().is_some_and(|s| hex(s, 40))
            && q["qa_evidence"].as_array().is_some_and(|a| !a.is_empty()),
        "epoch 225 role lacks exact source and CLI qualification"
    );
    for b in q["qa_evidence"].as_array().unwrap() {
        read(&serde_json::from_value(b.clone())?)?;
    }
    Ok(())
}
pub fn manager(unit: &str) -> Result<Value> {
    let o=Command::new("/usr/bin/systemctl").args(["show",unit,"--no-pager",
        "--property=Id,LoadState,InvocationID,MainPID,NRestarts,ActiveState,SubState,Result,ExecMainStatus,ExecStart,ControlGroup,Type,User,Group,Restart,KillMode,Delegate,MemoryMax,MemoryHigh,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec,RuntimeMaxUSec,PrivateNetwork,ProtectHome,ProtectSystem,ReadWritePaths,NoNewPrivileges,FragmentPath,DropInPaths,NeedDaemonReload,CapabilityBoundingSet,AmbientCapabilities"]).output()?;
    ensure!(
        o.status.success() && o.stdout.len() <= 65536,
        "epoch 225 manager metadata failed"
    );
    let mut v = serde_json::Map::new();
    for l in std::str::from_utf8(&o.stdout)?.lines() {
        let (k, n) = l.split_once('=').context("epoch 225 manager shape")?;
        ensure!(
            v.insert(k.into(), json!(n)).is_none(),
            "epoch 225 duplicate manager field"
        );
    }
    Ok(Value::Object(v))
}
pub fn ticks(pid: u32) -> Result<u64> {
    fs::read_to_string(format!("/proc/{pid}/stat"))?
        .rsplit_once(')')
        .context("epoch 225 stat shape")?
        .1
        .split_whitespace()
        .nth(19)
        .context("epoch 225 process clock missing")?
        .parse()
        .map_err(Into::into)
}
pub fn live_shape(p: &Plan, m: &Value, iid: &str, pid: u32) -> Result<()> {
    ensure!(
        hex(iid, 32)
            && iid.bytes().any(|b| b != b'0')
            && pid > 1
            && m["Id"] == p.unit
            && m["InvocationID"] == iid
            && m["MainPID"].as_str().and_then(|s| s.parse::<u32>().ok()) == Some(pid)
            && m["ControlGroup"] == format!("/system.slice/{}", p.unit),
        "epoch 225 actual task owner differs"
    );
    for (k, v) in [
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("NRestarts", "0"),
        ("Type", "exec"),
        ("User", "root"),
        ("Group", "root"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("MemoryMax", "103079215104"),
        ("MemoryHigh", "77309411328"),
        ("MemorySwapMax", "0"),
        ("TasksMax", "512"),
        ("CPUQuotaPerSecUSec", "8s"),
        ("RuntimeMaxUSec", "1d"),
        ("PrivateNetwork", "yes"),
        ("ProtectHome", "read-only"),
        ("ProtectSystem", "strict"),
        ("NoNewPrivileges", "yes"),
        ("DropInPaths", ""),
        ("NeedDaemonReload", "no"),
    ] {
        ensure!(m[k] == v, "epoch 225 effective task control differs: {k}");
    }
    ensure!(
        m["ReadWritePaths"].as_str() == p.root.to_str() && m["FragmentPath"] == json!(p.unit_file),
        "epoch 225 task writable scope or fragment changed"
    );
    for key in ["CapabilityBoundingSet", "AmbientCapabilities"] {
        ensure!(
            m[key] == "cap_dac_read_search",
            "epoch 225 task must retain read-only source capability: {key}"
        );
    }
    Ok(())
}
fn command_shape(p: &Plan, b: &Bound, m: &Value) -> Result<()> {
    let prefix = format!(
        "{{ path={} ; argv[]={}",
        p.executable.path.display(),
        argv(p, b).join(" ")
    );
    ensure!(
        m["ExecStart"]
            .as_str()
            .and_then(|s| s.split_once(" ; ignore_errors=no"))
            .is_some_and(|(s, _)| s == prefix),
        "epoch 225 effective native command differs"
    );
    Ok(())
}
pub fn actor(p: &Plan, b: &Bound, iid: &str, pid: u32) -> Result<Value> {
    let unit_file = unit_binding(p, b)?;
    let m = manager(&p.unit)?;
    live_shape(p, &m, iid, pid)?;
    let expected = argv(p, b);
    command_shape(p, b, &m)?;
    let raw = fs::read(format!("/proc/{pid}/cmdline"))?;
    let actual = raw
        .split(|b| *b == 0)
        .filter(|b| !b.is_empty())
        .map(std::str::from_utf8)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        actual == expected && fs::read_link(format!("/proc/{pid}/exe"))? == p.executable.path,
        "epoch 225 native executable or argv changed"
    );
    let start = ticks(pid)?;
    let exe = fs::metadata(format!("/proc/{pid}/exe"))?;
    let pinned = fs::symlink_metadata(&p.executable.path)?;
    ensure!(
        exe.dev() == pinned.dev()
            && exe.ino() == pinned.ino()
            && fs::read_to_string(format!("/proc/{pid}/cgroup"))?.trim()
                == format!("0::/system.slice/{}", p.unit),
        "epoch 225 mapped executable or cgroup changed"
    );
    let cg = Path::new("/sys/fs/cgroup/system.slice").join(&p.unit);
    for (k, v) in [
        ("memory.max", MEMORY.to_string()),
        ("memory.high", (72u64 << 30).to_string()),
        ("memory.swap.max", "0".into()),
        ("pids.max", "512".into()),
        ("cpu.max", "800000 100000".into()),
    ] {
        ensure!(
            fs::read_to_string(cg.join(k))?.trim() == v,
            "epoch 225 native cap differs: {k}"
        );
    }
    ensure!(
        ticks(pid)? == start && manager(&p.unit)? == m,
        "epoch 225 task changed during capture"
    );
    Ok(
        json!({"manager":m,"pid":pid,"start_ticks":start,"boot_id":fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),"executable":p.executable,"unit_file":unit_file,"argv":expected}),
    )
}
pub fn admission(p: &Plan, plan: &Bound, v: &Value, at: u64) -> Result<u64> {
    let t = v["recorded_unix_seconds"]
        .as_u64()
        .context("epoch 225 admission time missing")?;
    let floor = v["capacity"]["minimum_free_bytes"]
        .as_u64()
        .filter(|n| *n > 0)
        .context("epoch 225 protected floor missing")?;
    ensure!(
        v["schema"] == ADMISSION
            && v["unit_file"]["path"] == json!(p.unit_file)
            && v["unit_file"]["sha256"]
                .as_str()
                .is_some_and(|s| hex(s, 64))
            && v["admitted"] == true
            && v["plan"] == json!(plan)
            && v["executable"] == json!(p.executable)
            && v["terminal_handoff"] == json!(p.terminal_handoff)
            && t <= at
            && at - t <= 900
            && v["capacity"]["additional_bytes"] == OUTPUT + METADATA
            && v["capacity"]["memory_before"]["candidate_memory_max_bytes"]
                == MEMORY + (2u64 << 30)
            && v["capacity"]["memory_after"]["candidate_memory_max_bytes"] == MEMORY + (2u64 << 30)
            && v["maximum_output_bytes"] == OUTPUT
            && v["memory_max_bytes"] == MEMORY
            && v["authority"] == denied(),
        "epoch 225 admission is stale or foreign"
    );
    Ok(floor)
}
pub fn guard_shape(
    p: &Plan,
    plan: &Value,
    sample: &Value,
    iid: &str,
    floor: u64,
    at: u64,
) -> Result<()> {
    let t = sample["recorded_unix_seconds"]
        .as_u64()
        .context("epoch 225 guard time missing")?;
    ensure!(
        plan["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && plan["bounded_measurement"].is_null()
            && plan["bounded_canary"].is_null()
            && plan["native_main"].is_null()
            && plan["receipt_directory"]
                == json!(
                    Path::new("/var/lib/jetstreamer")
                        .join(format!("horizon-epoch225-extract-guard-{}", p.attempt))
                )
            && plan["unit"] == p.unit
            && plan["invocation_id"] == iid
            && plan["worker_root"] == json!(p.root)
            && plan["minimum_free_bytes"] == floor
            && plan["maximum_root_physical_bytes"] == OUTPUT + METADATA
            && plan["maximum_worker_vmas"] == 3500000
            && sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && sample["producer_invocation_id"] == iid
            && sample["producer"]["invocation_id"] == iid
            && sample["producer"]["active"] == "active"
            && sample["guard_sha256"] == p.guard_executable.sha256
            && sample["producer"]["sub"] == "running"
            && sample["producer"]["restarts"] == 0
            && sample["producer_stop_enabled"] == true
            && sample["minimum_free_bytes"] == floor
            && sample["available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= floor)
            && t <= at
            && at - t <= 120
            && sample["trip_reason"].is_null()
            && sample["worker_observation_error"].is_null()
            && sample["root_physical_observation_error"].is_null()
            && sample["bounded_measurement"] == false
            && sample["bounded_canary"].is_null()
            && sample["native_main"].is_null()
            && sample["workers"]
                .as_array()
                .is_some_and(|workers| workers.is_empty())
            && sample["maximum_root_physical_bytes"] == OUTPUT + METADATA
            && sample["root_physical_observation"]["maximum_physical_bytes"] == OUTPUT + METADATA
            && sample["root_physical_observation"]["conservative_physical_bytes"]
                .as_u64()
                .is_some_and(|n| n <= OUTPUT + METADATA)
            && sample["root_physical_observation"]["exceeds_budget"] == false
            && sample["r2_mutations"] == false,
        "epoch 225 guard is stale, tripped or bound to another task/floor"
    );
    Ok(())
}
pub fn latest_guard(p: &Plan, guard_bound: &Bound, iid: &str, floor: u64) -> Result<Value> {
    let plan = read(guard_bound)?;
    let directory = Path::new(
        plan["receipt_directory"]
            .as_str()
            .context("epoch 225 guard directory missing")?,
    );
    private(directory)?;
    let mut samples = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().context("epoch 225 guard name")?;
        if !(name.starts_with("sample-") && name.ends_with(".json")) {
            continue;
        }
        ensure!(
            samples.len() < 3072,
            "epoch 225 guard history bound exceeded"
        );
        let meta = fs::symlink_metadata(entry.path())?;
        ensure!(
            meta.is_file()
                && meta.uid() == 0
                && meta.nlink() == 1
                && meta.mode() & 0o022 == 0
                && meta.len() <= 64 << 10,
            "epoch 225 guard custody differs"
        );
        let raw = fs::read(entry.path())?;
        let b = Bound {
            path: entry.path(),
            sha256: format!("{:x}", Sha256::digest(&raw)),
        };
        let s: Value = serde_json::from_slice(&bytes(&b, 4 << 20, false)?)?;
        if s["producer_invocation_id"] == iid {
            samples.push((
                s["recorded_unix_seconds"]
                    .as_u64()
                    .context("epoch 225 guard timestamp missing")?,
                b,
                s,
            ));
        }
    }
    samples.sort_by_key(|v| v.0);
    let (_, bound, sample) = samples
        .pop()
        .context("epoch 225 has no protective sample")?;
    ensure!(
        sample["plan"] == json!(guard_bound.path) && sample["plan_sha256"] == guard_bound.sha256,
        "epoch 225 guard plan binding differs"
    );
    guard_shape(p, &plan, &sample, iid, floor, now()?)?;
    let timer = manager(&p.guard_unit.replace(".service", ".timer"))?;
    let guard = manager(&p.guard_unit)?;
    let owner = manager(&p.unit)?;
    ensure!(
        timer["ActiveState"] == "active"
            && timer["Id"] == p.guard_unit.replace(".service", ".timer")
            && sample["producer"]["pid"].as_u64()
                == owner["MainPID"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
            && owner["InvocationID"] == iid
            && guard["NRestarts"] == "0"
            && guard["Result"] == "success"
            && guard["ExecMainStatus"] == "0",
        "epoch 225 protective timer or completed manager failed"
    );
    Ok(json!({"binding":bound,"sample":sample,"plan":guard_bound,"timer":timer,"manager":guard}))
}
pub fn free(path: &Path) -> Result<u64> {
    let s = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let mut v = unsafe { std::mem::zeroed::<libc::statvfs>() };
    ensure!(
        unsafe { libc::statvfs(s.as_ptr(), &mut v) } == 0,
        "epoch 225 free-space check failed"
    );
    v.f_bavail
        .checked_mul(v.f_frsize)
        .context("epoch 225 free-space overflow")
}
pub fn stage_policy(v: &Value) -> Result<BTreeMap<u64, u64>> {
    ensure!(
        v["schema"] == "jetstreamer-epoch225-extraction-sidecar-policy-v1"
            && v["source_validation_complete"].as_bool().is_some()
            && v["sidecar_inclusive"] == true
            && v["current_best_guesses"] == true
            && v["estimate_basis"]
                .as_str()
                .is_some_and(|s| !s.trim().is_empty())
            && v["missing226_suffix_slots"] == 535,
        "epoch 225/226 planning policy differs"
    );
    let mut result = BTreeMap::new();
    for e in [225, 226] {
        let m = v["remaining_stage_millis"][e.to_string()]
            .as_object()
            .context("epoch 225/226 stage model missing")?;
        let keys = [
            "source_validation",
            "extraction_and_assembly",
            "runtime_qualification",
            "suffix_restore_and_replay",
            "full_verification",
            "current_plugin_verification",
            "boundary_checks",
            "upload",
            "readback",
            "source_revalidation_and_sidecar",
            "recovery",
        ];
        let keys = keys
            .into_iter()
            .filter(|k| e == 226 || *k != "suffix_restore_and_replay")
            .collect::<Vec<_>>();
        ensure!(
            m.len() == keys.len() && keys.iter().all(|k| m.contains_key(*k)),
            "epoch 225/226 stage model incomplete"
        );
        let complete = v["source_validation_complete"] == true;
        ensure!(
            m["source_validation"]
                .as_u64()
                .is_some_and(|n| if complete { n == 0 } else { n > 0 }),
            "epoch 225 source allowance does not match its proved phase"
        );
        let sum = m.iter().try_fold(0u64, |sum, (key, n)| {
            let n = n
                .as_u64()
                .context("epochs 225 and 226 allowances must be integers")?;
            ensure!(
                n > 0 || (key == "source_validation" && complete),
                "epochs 225 and 226 allowance is zero without completed phase evidence"
            );
            sum.checked_add(n)
                .context("epochs 225 and 226 ETA overflow")
        })?;
        result.insert(e, sum);
    }
    ensure!(
        v["remaining_stage_millis"]
            .as_object()
            .is_some_and(|m| m.len() == 2),
        "foreign status epoch"
    );
    Ok(result)
}

pub fn write_floor(floor: u64, written: u64, delta: u64) -> Result<u64> {
    ensure!(
        written.checked_add(delta).is_some_and(|n| n <= OUTPUT),
        "epoch 225 output cap crossed"
    );
    floor
        .checked_add(METADATA)
        .and_then(|n| n.checked_add(delta))
        .context("epoch 225 write floor overflow")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bound(name: &str) -> Bound {
        Bound {
            path: format!("/sealed/{name}").into(),
            sha256: "a".repeat(64),
        }
    }
    fn plan() -> Plan {
        Plan {
            schema: PLAN.into(),
            attempt: "test-v1".into(),
            unit: "horizon-qualify-225-prefix-extract-test-v1.service".into(),
            guard_unit: "horizon-qualify-225-prefix-extract-test-v1-guard.service".into(),
            root: "/home/ubuntu/.jetstreamer-private/epoch225-prefix-extract-test-v1".into(),
            executable: bound("jetstreamer-epoch225-prefix-extract"),
            admitter: bound("jetstreamer-r2"),
            deployment_seal: bound("seal.json"),
            qualification: bound("qualification.json"),
            unit_file: "/etc/systemd/system/horizon-qualify-225-prefix-extract-test-v1.service"
                .into(),
            terminal_handoff: bound("terminal.json"),
            source_manifest: Bound {
                path: format!("{ORIGINAL}.segment.json").into(),
                sha256: MANIFEST_SHA.into(),
            },
            guard_executable: bound("guard"),
            guard_qualification: bound("guard-qualification.json"),
            admission:
                "/var/lib/jetstreamer/horizon-epoch225-extract-admission-test-v1/admission.json"
                    .into(),
            release:
                "/home/ubuntu/.jetstreamer-private/epoch225-prefix-extract-test-v1/release.json"
                    .into(),
        }
    }
    #[test]
    fn e225_control_unit_definition_has_no_plan_hash_cycle_or_extra_commands() {
        let p = plan();
        let raw = serde_json::to_vec(&p).unwrap();
        let b = Bound {
            path: "/sealed/plan.json".into(),
            sha256: format!("{:x}", Sha256::digest(&raw)),
        };
        assert!(json!(p)["unit_file"].is_string());
        let service = format!(
            "[Unit]\nDescription=Private epoch 225 extraction\n[Service]\n{}\n[Install]\nWantedBy=multi-user.target\n",
            unit_controls(&p, &b)
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
        unit_shape(&p, &b, &service).unwrap();
        let bad = service.replace("[Service]", "[Service]\nExecStartPre=/bin/true");
        assert!(unit_shape(&p, &b, &bad).is_err());
        let bad = service.replace("MemoryMax=96G", "MemoryMax=infinity");
        assert!(unit_shape(&p, &b, &bad).is_err());
        let bad = service.replace("PrivateNetwork=yes", "PrivateNetwork=no");
        assert!(unit_shape(&p, &b, &bad).is_err());
        let bad = service.replace(&b.sha256, &"b".repeat(64));
        assert!(unit_shape(&p, &b, &bad).is_err());
    }
    #[test]
    fn e225_control_plan_rejects_foreign_namespace_manifest_and_skip_flags() {
        let p = plan();
        shape(&p).unwrap();
        let original = json!(p);
        for (key, value) in [
            ("unit", json!(OLD_UNIT)),
            ("root", json!("/home/ubuntu/horizon")),
            ("release", json!("/foreign/release.json")),
        ] {
            let mut bad = original.clone();
            bad[key] = value;
            assert!(shape(&serde_json::from_value(bad).unwrap()).is_err());
        }
        let mut bad = original.clone();
        bad["source_manifest"]["sha256"] = json!("b".repeat(64));
        assert!(shape(&serde_json::from_value(bad).unwrap()).is_err());
        for key in ["skip_guard", "ignore_admission", "publish_sidecar"] {
            let mut bad = original.clone();
            bad[key] = json!(true);
            assert!(serde_json::from_value::<Plan>(bad).is_err());
        }
    }
    #[test]
    fn e225_control_admission_binds_full_caps_and_uses_protected_floor() {
        let p = plan();
        let b = bound("plan.json");
        let good = json!({"schema":ADMISSION,"admitted":true,"plan":b,"executable":p.executable,
            "terminal_handoff":p.terminal_handoff,"recorded_unix_seconds":100,"maximum_output_bytes":OUTPUT,"memory_max_bytes":MEMORY,"authority":denied(),
            "unit_file":{"path":p.unit_file,"sha256":"a".repeat(64)},"capacity":{"minimum_free_bytes":1000,"required_initial_free_bytes":1000+OUTPUT+METADATA,"additional_bytes":OUTPUT+METADATA,
                "memory_before":{"candidate_memory_max_bytes":MEMORY+(2u64<<30)},"memory_after":{"candidate_memory_max_bytes":MEMORY+(2u64<<30)}}});
        assert_eq!(admission(&p, &b, &good, 101).unwrap(), 1000);
        assert!(admission(&p, &b, &good, 99).is_err());
        assert!(admission(&p, &b, &good, 1001).is_err());
        for (pointer, value) in [
            ("/capacity/minimum_free_bytes", json!(0)),
            (
                "/capacity/memory_after/candidate_memory_max_bytes",
                json!(MEMORY),
            ),
            ("/plan/sha256", json!("b".repeat(64))),
            ("/authority/publication_authorized", json!(true)),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(admission(&p, &b, &bad, 101).is_err(), "{pointer}");
        }
    }
    #[test]
    fn e225_control_native_owner_and_command_reject_restarts_replacements_and_write_caps() {
        let p = plan();
        let b = bound("plan.json");
        let iid = "b".repeat(32);
        let mut m = json!({"Id":p.unit,"InvocationID":iid,"MainPID":"42","ControlGroup":format!("/system.slice/{}",p.unit),"ReadWritePaths":p.root,"FragmentPath":p.unit_file});
        for (k, v) in [
            ("LoadState", "loaded"),
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("NRestarts", "0"),
            ("Type", "exec"),
            ("User", "root"),
            ("Group", "root"),
            ("Restart", "no"),
            ("KillMode", "control-group"),
            ("Delegate", "no"),
            ("MemoryMax", "103079215104"),
            ("MemoryHigh", "77309411328"),
            ("MemorySwapMax", "0"),
            ("TasksMax", "512"),
            ("CPUQuotaPerSecUSec", "8s"),
            ("RuntimeMaxUSec", "1d"),
            ("PrivateNetwork", "yes"),
            ("ProtectHome", "read-only"),
            ("ProtectSystem", "strict"),
            ("NoNewPrivileges", "yes"),
            ("DropInPaths", ""),
            ("NeedDaemonReload", "no"),
            ("CapabilityBoundingSet", "cap_dac_read_search"),
            ("AmbientCapabilities", "cap_dac_read_search"),
        ] {
            m[k] = json!(v);
        }
        m["ExecStart"] = json!(format!(
            "{{ path={} ; argv[]={} ; ignore_errors=no ; start_time=[n/a] }}",
            p.executable.path.display(),
            argv(&p, &b).join(" ")
        ));
        live_shape(&p, &m, &iid, 42).unwrap();
        command_shape(&p, &b, &m).unwrap();
        for (k, v) in [
            ("MainPID", "43"),
            ("InvocationID", "foreign"),
            ("NRestarts", "1"),
            ("MemoryMax", "max"),
            ("CapabilityBoundingSet", "cap_dac_override"),
            ("ReadWritePaths", ORIGINAL),
        ] {
            let mut bad = m.clone();
            bad[k] = json!(v);
            assert!(live_shape(&p, &bad, &iid, 42).is_err(), "{k}");
        }
        m["ExecStart"] = json!("/bin/sleep infinity");
        assert!(command_shape(&p, &b, &m).is_err());
    }
    #[test]
    fn e225_control_guard_rejects_stale_foreign_floor_and_budget_exemptions() {
        let p = plan();
        let iid = "b".repeat(32);
        let plan = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":p.unit,"invocation_id":iid,"worker_root":p.root,
            "receipt_directory":format!("/var/lib/jetstreamer/horizon-epoch225-extract-guard-{}",p.attempt),"minimum_free_bytes":1000,"maximum_root_physical_bytes":OUTPUT+METADATA,"maximum_worker_vmas":3500000});
        let good = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","recorded_unix_seconds":100,"producer_invocation_id":iid,
            "producer":{"invocation_id":iid,"active":"active","sub":"running","restarts":0},"guard_sha256":p.guard_executable.sha256,
            "workers":[],"producer_stop_enabled":true,"minimum_free_bytes":1000,"available_bytes":2000,"trip_reason":null,"worker_observation_error":null,
            "root_physical_observation_error":null,"bounded_measurement":false,"maximum_root_physical_bytes":OUTPUT+METADATA,"r2_mutations":false,
            "root_physical_observation":{"maximum_physical_bytes":OUTPUT+METADATA,"conservative_physical_bytes":4096,"exceeds_budget":false}});
        guard_shape(&p, &plan, &good, &iid, 1000, 101).unwrap();
        assert!(guard_shape(&p, &plan, &good, &iid, 1000, 221).is_err());
        for (pointer, value) in [
            ("/minimum_free_bytes", json!(1001)),
            ("/producer/invocation_id", json!("foreign")),
            ("/bounded_measurement", json!(true)),
            ("/guard_sha256", json!("c".repeat(64))),
            ("/root_physical_observation/exceeds_budget", json!(true)),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                guard_shape(&p, &plan, &bad, &iid, 1000, 101).is_err(),
                "{pointer}"
            );
        }
    }
    #[test]
    fn e225_control_sidecar_policy_keeps_226_debt_and_rejects_zero_missing_overflow() {
        let keys = [
            "source_validation",
            "extraction_and_assembly",
            "runtime_qualification",
            "full_verification",
            "current_plugin_verification",
            "boundary_checks",
            "upload",
            "readback",
            "source_revalidation_and_sidecar",
            "recovery",
        ];
        let stages = keys
            .into_iter()
            .map(|k| (k.to_string(), json!(1000)))
            .collect::<serde_json::Map<_, _>>();
        let mut good = json!({"schema":"jetstreamer-epoch225-extraction-sidecar-policy-v1","sidecar_inclusive":true,"current_best_guesses":true,
            "estimate_basis":"current evidence-backed guesses through sidecar, including the mandatory full source decode","source_validation_complete":false,"missing226_suffix_slots":535,"remaining_stage_millis":{"225":stages,"226":stages}});
        good["remaining_stage_millis"]["226"]["suffix_restore_and_replay"] = json!(1000);
        assert_eq!(
            stage_policy(&good).unwrap(),
            BTreeMap::from([(225, 10000), (226, 11000)])
        );
        for (pointer, value) in [
            ("/missing226_suffix_slots", json!(0)),
            (
                "/remaining_stage_millis/226/suffix_restore_and_replay",
                json!(0),
            ),
            ("/remaining_stage_millis/225/upload", json!(u64::MAX)),
            ("/sidecar_inclusive", json!(false)),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(stage_policy(&bad).is_err(), "{pointer}");
        }
        let mut completed = good.clone();
        completed["source_validation_complete"] = json!(true);
        for epoch in ["225", "226"] {
            completed["remaining_stage_millis"][epoch]["source_validation"] = json!(0);
        }
        assert_eq!(
            stage_policy(&completed).unwrap(),
            BTreeMap::from([(225, 9000), (226, 10000)])
        );
        completed["source_validation_complete"] = json!(false);
        assert!(stage_policy(&completed).is_err());
        good["remaining_stage_millis"]
            .as_object_mut()
            .unwrap()
            .remove("226");
        assert!(stage_policy(&good).is_err());
    }
    #[test]
    fn e225_control_write_floor_protects_next_write_and_checks_overflow() {
        assert_eq!(write_floor(1000, 10, 30).unwrap(), 1000 + METADATA + 30);
        assert!(write_floor(1000, OUTPUT, 1).is_err());
        assert!(write_floor(1000, 0, OUTPUT + 1).is_err());
        assert!(write_floor(u64::MAX, 0, 1).is_err());
    }
}
