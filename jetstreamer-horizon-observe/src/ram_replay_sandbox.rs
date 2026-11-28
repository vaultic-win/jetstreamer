//! Persistent mount and actual sandbox authentication shared with a future
//! supervisor. This module deliberately has no launch, signal, mount or unlink.
//! Its only write is the exact private storage-capability metadata receipt.
use {
    anyhow::{Context, Result, ensure},
    serde::Deserialize,
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    std::{
        collections::BTreeMap,
        env,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
        process::Command,
    },
};

const GIB: u64 = 1 << 30;
const MAX_MEMORY: u64 = 320 * GIB;
const HIGH_MEMORY: u64 = 304 * GIB;
const TMPFS_SIZE: u64 = 768 * GIB;
const FLOOR: u64 = 231_874_716_783;
const ROOT_PARENT: &str = "/home/ubuntu/.jetstreamer-private";
const SERVICE_PREFIX: &str = "horizon-203-ram-storage-probe-";
const ROOT_PREFIX: &str = "ram-resource-203-";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    unit: String,
    run_root: PathBuf,
    mount_unit: String,
    mount_invocation_id: String,
    host_mount_id: u64,
    mount_device: [u64; 2],
    host_peer_group: u64,
}

fn canonical_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn unit_name(s: &str, suffix: &str) -> bool {
    s.len() <= 255
        && s.ends_with(suffix)
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.\\".contains(&b))
}

fn validate_plan(p: &Plan) -> Result<()> {
    validate_plan_scope(p, SERVICE_PREFIX)
}

fn validate_plan_scope(p: &Plan, prefix: &str) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-private-epoch203-ram-storage-probe-plan-v2",
        "wrong plan schema"
    );
    ensure!(
        p.unit.starts_with(prefix) && unit_name(&p.unit, ".service"),
        "wrong probe unit"
    );
    ensure!(
        unit_name(&p.mount_unit, ".mount")
            && canonical_hex(&p.mount_invocation_id, 32)
            && p.host_mount_id != 0
            && p.mount_device[0] == 0
            && p.mount_device[1] != 0
            && p.host_peer_group != 0,
        "unbound persistent mount"
    );
    ensure!(
        p.run_root.parent() == Some(Path::new(ROOT_PARENT))
            && p.run_root
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with(ROOT_PREFIX)
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))),
        "wrong RAM root"
    );
    Ok(())
}

fn bound_input(path: &Path, sha: &str) -> Result<Vec<u8>> {
    ensure!(
        canonical_hex(sha, 64) && path.is_absolute() && path.canonicalize()? == path,
        "invalid evidence path or digest"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let before = f.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o222 == 0
            && before.len() <= 65536,
        "unsafe sealed plan"
    );
    let mut bytes = Vec::new();
    (&mut f).take(65537).read_to_end(&mut bytes)?;
    let id = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mode(),
            m.uid(),
            m.gid(),
            m.nlink(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    ensure!(
        id(&before) == id(&f.metadata()?)
            && id(&before) == id(&fs::symlink_metadata(path)?)
            && before.len() == bytes.len() as u64
            && format!("{:x}", Sha256::digest(&bytes)) == sha,
        "sealed evidence changed"
    );
    Ok(bytes)
}

fn properties(text: &str) -> Result<BTreeMap<&str, &str>> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line.split_once('=').context("malformed unit property")?;
        ensure!(
            !key.is_empty() && map.insert(key, value).is_none(),
            "duplicate unit property"
        );
    }
    Ok(map)
}

fn expect(map: &BTreeMap<&str, &str>, key: &str, value: &str) -> Result<()> {
    ensure!(map.get(key).copied() == Some(value), "wrong property {key}");
    Ok(())
}

fn validate_service(text: &str, p: &Plan, inv: &str, pid: u32) -> Result<()> {
    let m = properties(text)?;
    for (key, value) in [
        ("Id", p.unit.as_str()),
        ("InvocationID", inv),
        // A fixed setpriv exec wrapper clears NSS supplementary groups and
        // the bounding set before this process starts. systemd User=1000
        // alone would retain ubuntu's sudo/lxd groups. This process itself
        // must independently prove UID/GID1000 and all five capability sets 0.
        ("User", "root"),
        ("Group", "root"),
        ("SupplementaryGroups", ""),
        ("Type", "oneshot"),
        ("Restart", "no"),
        ("NRestarts", "0"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("NoNewPrivileges", "yes"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("ProtectControlGroups", "yes"),
        ("PrivateNetwork", "no"),
        ("TemporaryFileSystem", ""),
        ("CapabilityBoundingSet", "cap_setgid cap_setuid cap_setpcap"),
        // The fixed wrapper needs these effective at the UID/GID drop point.
        // It must then clear both inherited and ambient sets before exec.
        ("AmbientCapabilities", "cap_setgid cap_setuid cap_setpcap"),
        ("OOMPolicy", "kill"),
        ("OOMScoreAdjust", "1000"),
        ("PrivateDevices", "yes"),
        ("RestrictSUIDSGID", "yes"),
        ("UMask", "0077"),
    ] {
        expect(&m, key, value)?;
    }
    expect(&m, "MainPID", &pid.to_string())?;
    expect(
        &m,
        "ReadWritePaths",
        p.run_root.to_str().context("RAM root is not UTF8")?,
    )?;
    ensure!(
        matches!(m.get("ActiveState").copied(), Some("activating" | "active")),
        "inactive probe"
    );
    ensure!(
        matches!(m.get("SubState").copied(), Some("start" | "running")),
        "wrong probe phase"
    );
    Ok(())
}

fn validate_mount(text: &str, p: &Plan) -> Result<()> {
    let m = properties(text)?;
    for (key, value) in [
        ("Id", p.mount_unit.as_str()),
        ("InvocationID", p.mount_invocation_id.as_str()),
        ("ActiveState", "active"),
        ("SubState", "mounted"),
        ("What", "tmpfs"),
        ("Type", "tmpfs"),
        ("StopWhenUnneeded", "no"),
        ("BindsTo", ""),
        ("PartOf", ""),
    ] {
        expect(&m, key, value)?;
    }
    expect(
        &m,
        "Where",
        p.run_root.to_str().context("RAM root is not UTF8")?,
    )?;
    // This cannot guarantee future administrative action; it rejects the
    // automatic producer-lifetime teardown that loses diagnostic artifacts.
    Ok(())
}

fn option_set(text: &str) -> Result<std::collections::BTreeSet<&str>> {
    let mut set = std::collections::BTreeSet::new();
    for option in text.split(',') {
        ensure!(
            !option.is_empty() && set.insert(option),
            "duplicate/empty mount option"
        );
    }
    Ok(set)
}

fn mountinfo(
    text: &str,
    root: &Path,
    device: [u64; 2],
    host_peer_group: u64,
) -> Result<(u64, u64)> {
    let root = root.to_str().context("RAM path is not UTF8")?;
    let mut found = None;
    for line in text.lines() {
        let (left, right) = line
            .split_once(" - ")
            .context("malformed mountinfo separator")?;
        let a: Vec<_> = left.split_whitespace().collect();
        let b: Vec<_> = right.split_whitespace().collect();
        ensure!(a.len() >= 6 && b.len() == 3, "malformed mountinfo fields");
        if a[4] != root {
            continue;
        }
        ensure!(
            found.is_none() && a[3] == "/" && b[0] == "tmpfs" && b[1] == "tmpfs",
            "foreign or multiply mounted RAM root"
        );
        let options = option_set(a[5])?;
        ensure!(
            ["rw", "nosuid", "nodev"]
                .iter()
                .all(|s| options.contains(s))
                && !options.contains("noexec"),
            "unsafe/unusable RAM mount flags"
        );
        let super_options = option_set(b[2])?;
        ensure!(
            ["rw", "mode=700", "uid=1000", "gid=1000"]
                .iter()
                .all(|s| super_options.contains(s)),
            "RAM mount ownership/mode differs"
        );
        let (major, minor) = a[2].split_once(':').context("malformed mount device")?;
        ensure!(
            [major.parse::<u64>()?, minor.parse::<u64>()?] == device,
            "sandbox mount is not the bound host RAM device"
        );
        // ProtectHome/ReadWritePaths assign namespace-local mount IDs. Bind
        // the inherited host source by device and propagation master, then
        // pin the actual local ID/peer for the before/after race check.
        let master: Vec<_> = a[6..]
            .iter()
            .filter_map(|s| s.strip_prefix("master:"))
            .collect();
        let shared: Vec<_> = a[6..]
            .iter()
            .filter_map(|s| s.strip_prefix("shared:"))
            .collect();
        ensure!(
            master.len() == 1 && master[0].parse::<u64>()? == host_peer_group && shared.len() == 1,
            "RAM source propagation binding differs"
        );
        let local_id = a[0].parse::<u64>()?;
        let local_peer = shared[0].parse::<u64>()?;
        ensure!(
            local_id > 0 && local_peer > 0,
            "invalid namespace mount identity"
        );
        found = Some((local_id, local_peer));
    }
    found.context("persistent RAM root not mounted in this namespace")
}

fn validate_cgroup(read: impl Fn(&str) -> Result<String>) -> Result<Value> {
    let mut output = serde_json::Map::new();
    for (key, expected) in [
        ("memory.high", HIGH_MEMORY),
        ("memory.max", MAX_MEMORY),
        ("memory.swap.max", 0),
        ("memory.oom.group", 1),
        ("pids.max", 512),
    ] {
        let raw = read(key)?;
        ensure!(
            raw.trim().parse::<u64>()? == expected,
            "wrong actual cgroup {key}"
        );
        output.insert(key.into(), json!(raw));
    }
    let cpu = read("cpu.max")?;
    let fields: Vec<_> = cpu.split_whitespace().collect();
    ensure!(fields.len() == 2, "bad CPU quota");
    let period = fields[1].parse::<u64>()?;
    ensure!(
        period != 0
            && fields[0].parse::<u64>()? == period.checked_mul(16).context("CPU quota overflow")?,
        "wrong RAM diagnostic CPU quota"
    );
    output.insert("cpu.max".into(), json!(cpu));
    Ok(Value::Object(output))
}

fn show(unit: &str, props: &str) -> Result<String> {
    let result = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            unit,
            "--no-pager",
            "--no-ask-password",
            &format!("--property={props}"),
        ])
        .output()?;
    ensure!(
        result.status.success() && result.stdout.len() <= 65536 && result.stderr.len() <= 65536,
        "cannot authenticate systemd unit"
    );
    Ok(String::from_utf8(result.stdout)?)
}

fn bounded_text(path: &Path, limit: u64) -> Result<String> {
    Ok(String::from_utf8(bounded_text_bytes(path, limit)?)?)
}

fn bounded_text_bytes(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "oversized kernel evidence");
    Ok(bytes)
}

fn same_metadata(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mode() == b.mode()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
        && a.nlink() == b.nlink()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}

fn directory(root: &Path) -> Result<u64> {
    let m = fs::symlink_metadata(root)?;
    ensure!(
        root.is_absolute()
            && root.canonicalize()? == root
            && m.is_dir()
            && m.uid() == 1000
            && m.gid() == 1000
            && m.mode() & 0o7777 == 0o700,
        "unsafe private RAM directory"
    );
    Ok(m.dev())
}

pub(crate) fn validate_process_status(status: &str) -> Result<()> {
    for key in ["Uid:", "Gid:"] {
        let entries: Vec<_> = status.lines().filter_map(|l| l.strip_prefix(key)).collect();
        ensure!(
            entries.len() == 1 && entries[0].split_whitespace().collect::<Vec<_>>() == ["1000"; 4],
            "real/effective/saved/filesystem identity was not dropped"
        );
    }
    for key in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        let entries: Vec<_> = status.lines().filter_map(|l| l.strip_prefix(key)).collect();
        ensure!(
            entries.len() == 1 && u64::from_str_radix(entries[0].trim(), 16)? == 0,
            "probe retains capabilities"
        );
    }
    let groups = status
        .lines()
        .find_map(|s| s.strip_prefix("Groups:"))
        .context("missing groups")?;
    ensure!(
        groups.split_whitespace().all(|s| s == "1000"),
        "foreign supplementary group"
    );
    let nnp: Vec<_> = status
        .lines()
        .filter_map(|s| s.strip_prefix("NoNewPrivs:"))
        .collect();
    ensure!(
        nnp.len() == 1 && nnp[0].trim() == "1",
        "no-new-privileges is not effective"
    );
    Ok(())
}

/// Explicit compile-selected phases, never selected by a JSON plan field.
#[derive(Clone, Copy)]
pub enum ReplayPhase {
    BeforePreparation,
    BeforeSpawn,
}

/// Authenticate a future replay supervisor's actual persistent sandbox. This
/// grants no CPU/fleet/resource admission and launches no child. The caller
/// must have verified the hash-bound outer plan before passing these bytes.
pub fn authenticate_replay(
    bytes: &[u8],
    unit: &str,
    root: &Path,
    phase: ReplayPhase,
) -> Result<Value> {
    ensure!(bytes.len() <= 65536, "oversized sandbox input");
    let p: Plan = serde_json::from_slice(bytes)?;
    validate_plan_scope(&p, "horizon-203-ram-resource-")?;
    ensure!(
        p.unit == unit && p.run_root == root,
        "sandbox differs from bounded runner"
    );
    authenticate(&p, Some(phase))
}

fn authenticate(p: &Plan, phase: Option<ReplayPhase>) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 1000 && unsafe { libc::getegid() } == 1000,
        "probe must run as the unprivileged replay identity"
    );
    validate_process_status(&bounded_text(Path::new("/proc/self/status"), 65536)?)?;
    let inv = env::var("INVOCATION_ID")?;
    ensure!(canonical_hex(&inv, 32), "invalid probe invocation");
    let cg = format!("0::/system.slice/{}", p.unit);
    ensure!(
        bounded_text(Path::new("/proc/self/cgroup"), 65536)?.trim() == cg,
        "wrong probe cgroup"
    );
    let service_props = "Id,InvocationID,User,Group,SupplementaryGroups,Type,Restart,NRestarts,KillMode,Delegate,NoNewPrivileges,ProtectSystem,ProtectHome,ProtectControlGroups,PrivateNetwork,TemporaryFileSystem,CapabilityBoundingSet,AmbientCapabilities,OOMPolicy,OOMScoreAdjust,PrivateDevices,RestrictSUIDSGID,UMask,MainPID,ReadWritePaths,ActiveState,SubState";
    validate_service(&show(&p.unit, service_props)?, p, &inv, std::process::id())?;
    let mount_props =
        "Id,InvocationID,ActiveState,SubState,What,Where,Type,StopWhenUnneeded,BindsTo,PartOf";
    validate_mount(&show(&p.mount_unit, mount_props)?, p)?;
    let mount_before = bounded_text(Path::new("/proc/self/mountinfo"), 4 << 20)?;
    let namespace_mount = mountinfo(
        &mount_before,
        &p.run_root,
        p.mount_device,
        p.host_peer_group,
    )?;
    let [major, minor] = p.mount_device;
    let dev = directory(&p.run_root)?;
    let root_inode = fs::symlink_metadata(&p.run_root)?.ino();
    ensure!(
        u64::from(libc::major(dev)) == major && u64::from(libc::minor(dev)) == minor,
        "RAM directory device does not match mount"
    );
    let croot = Path::new("/sys/fs/cgroup/system.slice").join(&p.unit);
    let limits = validate_cgroup(|name| bounded_text(&croot.join(name), 65536))?;
    let tmp = p.run_root.join("tmp");
    ensure!(
        env::var_os("TMPDIR").as_deref() == Some(tmp.as_os_str()),
        "TMPDIR escapes persistent RAM root"
    );
    for name in ["scratch", "output", "ledger", "tmp", "receipts"] {
        let path = p.run_root.join(name);
        ensure!(
            directory(&path)? == dev,
            "RAM child directory is on another filesystem"
        );
        if name == "ledger" && matches!(phase, Some(ReplayPhase::BeforeSpawn)) {
            let names: Vec<_> = fs::read_dir(&path)?
                .map(|e| e.map(|e| e.file_name()))
                .collect::<std::io::Result<_>>()?;
            ensure!(
                names == [std::ffi::OsString::from("genesis.tar.bz2")],
                "prepared ledger differs"
            );
            let genesis = path.join("genesis.tar.bz2");
            let m = fs::symlink_metadata(&genesis)?;
            ensure!(
                m.is_file()
                    && m.uid() == 1000
                    && m.nlink() == 1
                    && m.dev() == dev
                    && m.mode() & 0o777 == 0o400
                    && m.len() <= 10 << 20,
                "unsafe copied genesis"
            );
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&genesis)?;
            ensure!(
                same_metadata(&m, &file.metadata()?),
                "copied genesis changed at open"
            );
            let mut bytes = Vec::new();
            (&mut file).take((10 << 20) + 1).read_to_end(&mut bytes)?;
            ensure!(
                format!("{:x}", Sha256::digest(bytes))
                    == "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
                "copied genesis differs"
            );
            let after = fs::symlink_metadata(&genesis)?;
            ensure!(
                same_metadata(&m, &after) && same_metadata(&m, &file.metadata()?),
                "copied genesis changed"
            );
        } else {
            ensure!(
                fs::read_dir(path)?.next().is_none(),
                "RAM child directory is nonempty"
            );
        }
    }
    let raw = std::ffi::CString::new(p.run_root.as_os_str().as_encoded_bytes())?;
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    let mut v: libc::statvfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::statfs(raw.as_ptr(), &mut s) } == 0 && s.f_type == 0x01021994,
        "persistent root is not tmpfs"
    );
    ensure!(
        unsafe { libc::statvfs(raw.as_ptr(), &mut v) } == 0,
        "RAM statvfs failed"
    );
    ensure!(
        v.f_blocks.checked_mul(v.f_frsize) == Some(TMPFS_SIZE),
        "wrong tmpfs capacity"
    );
    let available = v
        .f_bavail
        .checked_mul(v.f_frsize)
        .context("RAM available overflow")?;
    ensure!(
        available
            .checked_sub(MAX_MEMORY)
            .is_some_and(|n| n >= FLOOR),
        "RAM free space cannot preserve century floor"
    );
    // Recheck exact service and mount identities after all filesystem reads.
    validate_service(&show(&p.unit, service_props)?, p, &inv, std::process::id())?;
    validate_mount(&show(&p.mount_unit, mount_props)?, p)?;
    let mount_after = bounded_text(Path::new("/proc/self/mountinfo"), 4 << 20)?;
    ensure!(
        mountinfo(&mount_after, &p.run_root, p.mount_device, p.host_peer_group)? == namespace_mount
            && directory(&p.run_root)? == dev
            && fs::symlink_metadata(&p.run_root)?.ino() == root_inode,
        "persistent mount changed during probe"
    );
    Ok(
        json!({"invocation_id":inv,"unit":p.unit,"run_root":p.run_root,
        "mount_unit":p.mount_unit,"mount_invocation_id":p.mount_invocation_id,
        "host_mount_id_from_plan":p.host_mount_id,"host_peer_group":p.host_peer_group,
        "namespace_mount_id":namespace_mount.0,"namespace_peer_group":namespace_mount.1,
        "mount_device":[major,minor],"tmpfs_capacity_bytes":TMPFS_SIZE,
        "tmpfs_available_bytes":available,"cgroup_limits":limits,
        "unprivileged_identity_verified":true,"producer_lifetime_teardown_disabled":true}),
    )
}

fn write_capability(root: &Path, report: &Value) -> Result<String> {
    let parent = root.join("receipts");
    ensure!(
        directory(root)? == directory(&parent)?,
        "receipt escaped RAM filesystem"
    );
    let mut bytes = serde_json::to_vec_pretty(report)?;
    bytes.push(b'\n');
    ensure!(bytes.len() <= 65536, "oversized capability receipt");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(parent.join("storage-capability.json"))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub fn run_probe() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    ensure!(
        args.len() == 5 && args[1] == "--plan-sha256" && args[3] == "--self-sha256",
        "usage: storage-probe PLAN --plan-sha256 HEX --self-sha256 HEX"
    );
    // The executable may be larger than a plan; hash it separately without
    // buffering it, with the same no-follow/identity requirements.
    let exe = fs::read_link("/proc/self/exe")?;
    ensure!(
        canonical_hex(&args[4], 64) && exe.is_absolute() && exe.canonicalize()? == exe,
        "invalid supervisor hash/path"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&exe)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o222 == 0
            && before.len() <= 256 << 20,
        "unsafe probe executable"
    );
    let mut hash = Sha256::new();
    let mut buf = [0u8; 131072];
    let mut count = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        count = count.checked_add(n as u64).context("executable grew")?;
        ensure!(count <= 256 << 20, "oversized executable");
        hash.update(&buf[..n]);
    }
    let id = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mode(),
            m.uid(),
            m.gid(),
            m.nlink(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    ensure!(
        format!("{:x}", hash.finalize()) == args[4]
            && count == before.len()
            && id(&before) == id(&file.metadata()?)
            && id(&before) == id(&fs::symlink_metadata(exe)?),
        "probe executable identity/hash changed"
    );
    let plan: Plan = serde_json::from_slice(&bound_input(Path::new(&args[0]), &args[2])?)?;
    validate_plan(&plan)?;
    let report = authenticate(&plan, None)?;
    let output = json!({
            "schema":"jetstreamer-private-epoch203-ram-storage-capability-v1",
            "plan_path":args[0],"plan_sha256":args[2],"self_sha256":args[4],"sandbox":report,
            "live_resource_sample_taken":false,"host_memory_sample_taken":false,
            "fixture_inputs_verified":false,"cpu_release_verified":false,"fresh_admission_passed":false,
            "authority":{"replay_launch_authorized":false,"publication_authorized":false,
                "runtime_promotion_authorized":false,"local_retirement_authorized":false,
                "mount_or_unmount_authorized":false,"remote_mutations":false,"r2_mutations":false}
    });
    let sha = write_capability(&plan.run_root, &output)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "receipt_path":plan.run_root.join("receipts/storage-capability.json"),
            "receipt_sha256":sha,"durable_disk_copy_still_required":true,
            "replay_launch_authorized":false
        }))?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> Plan {
        Plan {
            schema: "jetstreamer-private-epoch203-ram-storage-probe-plan-v2".into(),
            unit: format!("{SERVICE_PREFIX}test.service"),
            run_root: Path::new(ROOT_PARENT).join("ram-resource-203-test"),
            mount_unit: "home-ubuntu-ram.mount".into(),
            mount_invocation_id: "a".repeat(32),
            host_mount_id: 123,
            mount_device: [0, 71],
            host_peer_group: 357,
        }
    }
    fn service(p: &Plan) -> String {
        format!(
            "Id={}\nInvocationID={}\nUser=root\nGroup=root\nSupplementaryGroups=\nType=oneshot\nRestart=no\nNRestarts=0\nKillMode=control-group\nDelegate=no\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=read-only\nProtectControlGroups=yes\nPrivateNetwork=no\nTemporaryFileSystem=\nCapabilityBoundingSet=cap_setgid cap_setuid cap_setpcap\nAmbientCapabilities=cap_setgid cap_setuid cap_setpcap\nOOMPolicy=kill\nOOMScoreAdjust=1000\nPrivateDevices=yes\nRestrictSUIDSGID=yes\nUMask=0077\nMainPID=456\nReadWritePaths={}\nActiveState=activating\nSubState=start\n",
            p.unit,
            "b".repeat(32),
            p.run_root.display()
        )
    }
    fn mount(p: &Plan) -> String {
        format!(
            "Id={}\nInvocationID={}\nActiveState=active\nSubState=mounted\nWhat=tmpfs\nWhere={}\nType=tmpfs\nStopWhenUnneeded=no\nBindsTo=\nPartOf=\n",
            p.mount_unit,
            p.mount_invocation_id,
            p.run_root.display()
        )
    }
    fn info(p: &Plan) -> String {
        format!(
            "471 1 0:71 / {} rw,nosuid,nodev,relatime shared:392 master:357 - tmpfs tmpfs rw,size=805306368k,mode=700,uid=1000,gid=1000\n",
            p.run_root.display()
        )
    }
    #[test]
    fn exact_persistent_mount_and_unprivileged_sandbox_are_required() {
        let p = plan();
        validate_plan(&p).unwrap();
        validate_service(&service(&p), &p, &"b".repeat(32), 456).unwrap();
        validate_mount(&mount(&p), &p).unwrap();
        assert_eq!(
            mountinfo(&info(&p), &p.run_root, [0, 71], 357).unwrap(),
            (471, 392)
        );
    }
    #[test]
    fn ephemeral_mount_and_identity_substitution_fail() {
        let p = plan();
        for (a, b) in [
            (
                "TemporaryFileSystem=\n",
                "TemporaryFileSystem=/tmp:rw,size=768G\n",
            ),
            ("User=root", "User=1000"),
            ("MainPID=456", "MainPID=457"),
            ("Restart=no", "Restart=on-failure"),
            ("NRestarts=0", "NRestarts=1"),
            (
                "CapabilityBoundingSet=cap_setgid cap_setuid cap_setpcap\n",
                "CapabilityBoundingSet=cap_sys_admin\n",
            ),
            ("ReadWritePaths=", "ReadWritePaths=/tmp "),
            ("SupplementaryGroups=\n", "SupplementaryGroups=27\n"),
            (
                "AmbientCapabilities=cap_setgid cap_setuid cap_setpcap\n",
                "AmbientCapabilities=\n",
            ),
        ] {
            assert!(
                validate_service(&service(&p).replace(a, b), &p, &"b".repeat(32), 456).is_err(),
                "accepted {a}"
            );
        }
        assert!(validate_service(&service(&p), &p, &"c".repeat(32), 456).is_err());
        assert!(properties("Id=x\nId=x\n").is_err());
    }
    #[test]
    fn producer_tied_or_wrong_mount_is_not_retention() {
        let p = plan();
        for (a, b) in [
            ("StopWhenUnneeded=no", "StopWhenUnneeded=yes"),
            ("PartOf=\n", "PartOf=replay.service\n"),
            ("BindsTo=\n", "BindsTo=replay.service\n"),
            ("Type=tmpfs", "Type=ext4"),
            ("SubState=mounted", "SubState=mounting"),
            ("Where=", "Where=/other/"),
        ] {
            assert!(
                validate_mount(&mount(&p).replace(a, b), &p).is_err(),
                "accepted {a}"
            );
        }
        assert!(mountinfo(&info(&p), &p.run_root, [0, 72], 357).is_err());
        assert!(mountinfo(&info(&p), &p.run_root, [0, 71], 358).is_err());
        for (a, b) in [
            (" - tmpfs ", " - ext4 "),
            ("mode=700", "mode=777"),
            ("uid=1000", "uid=0"),
            ("rw,nosuid,nodev,relatime", "rw,nosuid,nodev,noexec"),
            (" / ", " /subtree "),
            ("rw,nosuid,nodev,relatime", "rw,relatime"),
        ] {
            assert!(
                mountinfo(&info(&p).replace(a, b), &p.run_root, [0, 71], 357).is_err(),
                "accepted {a}"
            );
        }
        assert!(
            mountinfo(
                &format!("{}{}", info(&p), info(&p)),
                &p.run_root,
                [0, 71],
                357
            )
            .is_err()
        );
    }
    fn counters(key: &str) -> Result<String> {
        Ok(match key {
            "memory.high" => HIGH_MEMORY.to_string(),
            "memory.max" => MAX_MEMORY.to_string(),
            "memory.swap.max" => "0".into(),
            "memory.oom.group" => "1".into(),
            "pids.max" => "512".into(),
            "cpu.max" => "1600000 100000".into(),
            _ => anyhow::bail!("unexpected counter"),
        })
    }
    #[test]
    fn real_cgroup_caps_not_scheduling_estimates() {
        validate_cgroup(counters).unwrap();
        for key in [
            "memory.high",
            "memory.max",
            "memory.swap.max",
            "memory.oom.group",
            "pids.max",
            "cpu.max",
        ] {
            assert!(
                validate_cgroup(|k| if k == key {
                    Ok("max".into())
                } else {
                    counters(k)
                })
                .is_err()
            );
        }
        for bad in [
            "0 0",
            "1600000 0",
            "max 100000",
            "800000 100000",
            "1600000 100000 extra",
        ] {
            assert!(
                validate_cgroup(|k| if k == "cpu.max" {
                    Ok(bad.into())
                } else {
                    counters(k)
                })
                .is_err()
            );
        }
    }
    #[test]
    fn scope_cannot_be_extended_to_another_epoch_or_root() {
        let mut p = plan();
        p.unit = "unrelated.service".into();
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.run_root = "/tmp/ram-resource-203-test".into();
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.run_root = Path::new(ROOT_PARENT).join("ram-resource-203-test/child");
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.mount_invocation_id = "A".repeat(32);
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.host_mount_id = 0;
        assert!(validate_plan(&p).is_err());
    }
    #[test]
    fn replay_api_scope_is_separate_from_the_probe_and_matches_the_runner() {
        let mut p = plan();
        p.unit = "horizon-203-ram-resource-baseline-test.service".into();
        validate_plan_scope(&p, "horizon-203-ram-resource-").unwrap();
        assert!(validate_plan(&p).is_err());
        let bytes=serde_json::to_vec(&json!({"schema":p.schema,"unit":p.unit,"run_root":p.run_root,
            "mount_unit":p.mount_unit,"mount_invocation_id":p.mount_invocation_id,"host_mount_id":p.host_mount_id,
            "mount_device":p.mount_device,"host_peer_group":p.host_peer_group})).unwrap();
        assert!(
            authenticate_replay(
                &bytes,
                "wrong.service",
                &p.run_root,
                ReplayPhase::BeforePreparation
            )
            .is_err()
        );
        assert!(
            authenticate_replay(
                &bytes,
                &p.unit,
                Path::new("/unrelated"),
                ReplayPhase::BeforeSpawn
            )
            .is_err()
        );
        assert!(
            authenticate_replay(
                &vec![b'x'; 65537],
                &p.unit,
                &p.run_root,
                ReplayPhase::BeforePreparation
            )
            .is_err()
        );
        let mut bad: Value = serde_json::from_slice(&bytes).unwrap();
        bad["phase"] = json!("weaken");
        assert!(
            authenticate_replay(
                &serde_json::to_vec(&bad).unwrap(),
                &p.unit,
                &p.run_root,
                ReplayPhase::BeforeSpawn
            )
            .is_err()
        );
    }
    #[test]
    fn kernel_input_reader_is_bounded_and_does_not_follow_links() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("counter");
        fs::write(&p, b"123\n").unwrap();
        assert_eq!(bounded_text(&p, 4).unwrap(), "123\n");
        assert!(bounded_text(&p, 3).is_err());
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(bounded_text(&link, 4).is_err());
    }
    #[test]
    fn actual_drop_includes_saved_ids_groups_bounding_set_and_nnp() {
        let good = "Uid:\t1000 1000 1000 1000\nGid:\t1000 1000 1000 1000\nGroups:\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n";
        validate_process_status(good).unwrap();
        for (a, b) in [
            ("Uid:\t1000 1000 1000 1000", "Uid:\t1000 1000 0 1000"),
            ("Gid:\t1000 1000 1000 1000", "Gid:\t0 1000 1000 1000"),
            ("Groups:\n", "Groups:\t1000 27 102\n"),
            ("CapBnd:\t0000000000000000", "CapBnd:\t00000000000000c0"),
            ("CapEff:\t0000000000000000", "CapEff:\t0000000000000001"),
            ("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
        ] {
            assert!(
                validate_process_status(&good.replace(a, b)).is_err(),
                "accepted {a}"
            );
        }
    }
    #[test]
    fn capability_metadata_is_private_and_never_overwrites_an_existing_receipt() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let receipts = t.path().join("receipts");
        fs::create_dir(&receipts).unwrap();
        fs::set_permissions(&receipts, fs::Permissions::from_mode(0o700)).unwrap();
        let value = json!({"replay_launch_authorized":false});
        if unsafe { libc::geteuid() } != 1000 || unsafe { libc::getegid() } != 1000 {
            assert!(write_capability(t.path(), &value).is_err());
            return;
        }
        let sha = write_capability(t.path(), &value).unwrap();
        let path = receipts.join("storage-capability.json");
        let bytes = fs::read(&path).unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&bytes)), sha);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o400);
        assert!(write_capability(t.path(), &json!({"replay_launch_authorized":true})).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
}
