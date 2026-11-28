use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
type R<T> = Result<T, Box<dyn std::error::Error>>;
const ROOT: &str = "/home/sol/.jetstreamer-private";
const RECEIPTS: &str =
    "/home/sol/.jetstreamer-private/completed-cache-cleanup-20261109-v1/receipts-optimized-v2";
const R2_RECEIPTS: &str = "/home/sol/.jetstreamer-private/r2-receipts";
const FULL: &str =
    "/home/sol/.jetstreamer-private/final-audits/epochs-101-200-parallel-v1/receipts";
const PLUGIN: &str = "/home/sol/.jetstreamer-private/horizon-plugin-current-101-200-v2/receipts";
const BOUNDARY: &str = "/home/sol/.jetstreamer-private/horizon-boundary-audit-101-200-v1/receipts";
const ALLOW: &str = include_str!("allowlist.json");
const POLICY: &str = include_str!("verifier-policy.json");
const NOFOLLOW: i32 = 0x20000;
const CLOEXEC: i32 = 0x80000;
unsafe extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
    fn statvfs(path: *const std::ffi::c_char, output: *mut Statvfs) -> i32;
}
#[repr(C)]
#[allow(dead_code)] // All ABI fields are required even when only bavail/frsize are read.
struct Statvfs {
    bsize: u64,
    frsize: u64,
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    favail: u64,
    fsid: u64,
    flag: u64,
    namemax: u64,
    spare: [i32; 6],
}

// This successor retains the predecessor's exact-tree, no-follow, two-pass
// retirement. Its only payload class is reproducible compact-index files.
// Archives, snapshots, logs and credentials cannot be selected.
fn mutation_lock() -> R<File> {
    let p = Path::new(R2_RECEIPTS).join("local-mutation.lock");
    exact(&p)?;
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(NOFOLLOW | CLOEXEC)
        .open(&p)?;
    let m = f.metadata()?;
    require(
        m.is_file() && m.nlink() == 1 && [0, 1001].contains(&m.uid()) && m.mode() & 0o777 == 0o600,
        "unsafe shared mutation lock",
    )?;
    require(
        unsafe { flock(f.as_raw_fd(), 2 | 4) } == 0,
        "shared local mutation lock occupied",
    )?;
    Ok(f)
}
fn free_bytes() -> R<u64> {
    require(
        cfg!(all(target_os = "linux", target_arch = "x86_64")),
        "statvfs ABI requires Linux x86_64",
    )?;
    let p = std::ffi::CString::new(ROOT)?;
    let mut v = std::mem::MaybeUninit::<Statvfs>::uninit();
    require(
        unsafe { statvfs(p.as_ptr(), v.as_mut_ptr()) } == 0,
        "statvfs failed",
    )?;
    let v = unsafe { v.assume_init() };
    v.bavail
        .checked_mul(v.frsize)
        .ok_or_else(|| "free-space overflow".into())
}

fn require(ok: bool, reason: &str) -> R<()> {
    if ok { Ok(()) } else { Err(reason.into()) }
}
fn digest(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn read_small(p: &Path, cap: u64) -> R<Vec<u8>> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(NOFOLLOW)
        .open(p)?;
    let before = f.metadata()?;
    require(
        before.is_file() && before.len() <= cap,
        "unsafe or oversized metadata",
    )?;
    let mut b = Vec::new();
    f.read_to_end(&mut b)?;
    require(
        identity(&before) == identity(&f.metadata()?) && b.len() as u64 == before.len(),
        "metadata changed while reading",
    )?;
    Ok(b)
}
fn json_bound(p: &Path, hash: &str) -> R<Value> {
    let b = read_small(p, 64 * 1024 * 1024)?;
    require(digest(&b) == hash, "evidence hash mismatch")?;
    Ok(serde_json::from_slice(&b)?)
}
fn durable(p: &Path, value: &Value) -> R<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(NOFOLLOW)
        .open(p)?;
    f.write_all(&serde_json::to_vec(value)?)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(p.parent().ok_or("missing parent")?)?.sync_all()?;
    Ok(())
}
fn identity(m: &fs::Metadata) -> Value {
    json!([
        m.dev(),
        m.ino(),
        m.mode(),
        m.uid(),
        m.gid(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
        m.blocks()
    ])
}
fn exact(p: &Path) -> R<()> {
    require(
        p.is_absolute() && fs::canonicalize(p)? == p,
        "noncanonical or symbolic path",
    )
}
fn census_at(p: &Path, base: &Path, dev: u64, out: &mut BTreeMap<String, Value>) -> R<()> {
    let m = fs::symlink_metadata(p)?;
    require(
        m.dev() == dev && !m.file_type().is_symlink() && (m.is_file() || m.is_dir()),
        "symlink, mount crossing or special file",
    )?;
    require(
        m.uid() == 1001 && (!m.is_file() || m.nlink() == 1),
        "foreign owner or hard-linked cache member",
    )?;
    require(out.len() < 100, "cache exceeds entry allowance")?;
    out.insert(
        p.strip_prefix(base)?
            .to_str()
            .ok_or("non UTF-8 path")?
            .to_string(),
        identity(&m),
    );
    if m.is_dir() {
        let mut children = fs::read_dir(p)?
            .map(|x| x.map(|e| e.path()))
            .collect::<Result<Vec<_>, _>>()?;
        children.sort();
        for child in children {
            census_at(&child, base, dev, out)?;
        }
    }
    Ok(())
}
fn census(p: &Path) -> R<BTreeMap<String, Value>> {
    exact(p)?;
    let m = fs::symlink_metadata(p)?;
    require(m.is_dir(), "target not directory")?;
    let mut out = BTreeMap::new();
    census_at(p, p, m.dev(), &mut out)?;
    Ok(out)
}
fn path_ref(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).enumerate().any(|(i, s)| {
        s == needle
            && (i + needle.len() == bytes.len()
                || b"/\0\n\r\t '\";|&()<>[]{}:=,".contains(&bytes[i + needle.len()]))
    })
}
fn check_blob(bytes: &[u8], targets: &[PathBuf], label: &str) -> R<()> {
    for p in targets {
        require(
            !path_ref(bytes, p.as_os_str().as_encoded_bytes()),
            &format!("consumer reference: {label}"),
        )?;
    }
    Ok(())
}
fn transient(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::NotFound || e.raw_os_error() == Some(3)
}
fn proc_scan(targets: &[PathBuf]) -> R<Value> {
    let me = std::process::id().to_string();
    let mut count = 0;
    for entry in fs::read_dir("/proc")? {
        let p = entry?.path();
        let name = p.file_name().ok_or("pid name")?.to_string_lossy();
        if name == me || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let before = match fs::read(p.join("stat")) {
            Ok(x) => x,
            Err(e) if transient(&e) => continue,
            Err(e) => return Err(e.into()),
        };
        for n in ["cmdline", "maps", "environ"] {
            match fs::read(p.join(n)) {
                Ok(b) => check_blob(&b, targets, &format!("{name}/{n}"))?,
                Err(e) if transient(&e) => {}
                Err(e) => return Err(e.into()),
            }
        }
        for n in ["cwd", "root", "exe"] {
            match fs::read_link(p.join(n)) {
                Ok(q) => check_blob(
                    q.as_os_str().as_encoded_bytes(),
                    targets,
                    &format!("{name}/{n}"),
                )?,
                Err(e) if transient(&e) => {}
                Err(e) => return Err(e.into()),
            }
        }
        match fs::read_dir(p.join("fd")) {
            Ok(fds) => {
                for fd in fds {
                    let fd = fd?;
                    match fs::read_link(fd.path()) {
                        Ok(q) => check_blob(
                            q.as_os_str().as_encoded_bytes(),
                            targets,
                            &format!("{name}/fd"),
                        )?,
                        Err(e) if transient(&e) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
            }
            Err(e) if transient(&e) => {}
            Err(e) => return Err(e.into()),
        }
        if let Ok(after) = fs::read(p.join("stat")) {
            require(
                start_ticks(&before)? == start_ticks(&after)?,
                "PID reused during census",
            )?;
        }
        count += 1;
    }
    Ok(json!({"processes":count,"permission_errors":0}))
}
fn start_ticks(b: &[u8]) -> R<&str> {
    let s = std::str::from_utf8(b)?;
    s.rsplit_once(')')
        .ok_or("bad proc stat")?
        .1
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| "missing proc start ticks".into())
}
fn unit_walk(p: &Path, targets: &[PathBuf], count: &mut usize) -> R<()> {
    let md = match fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(e) if transient(&e) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if md.is_dir() {
        for e in fs::read_dir(p)? {
            unit_walk(&e?.path(), targets, count)?;
        }
    } else {
        // Definitions can legitimately be links to /dev/null or another unit.
        match fs::metadata(p) {
            Ok(m) if m.is_file() => {
                require(m.len() <= 16 * 1024 * 1024, "oversized staged definition")?;
                check_blob(&fs::read(p)?, targets, &p.display().to_string())?;
                *count += 1;
            }
            Ok(_) => {}
            Err(e) if transient(&e) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn staged_scan(targets: &[PathBuf]) -> R<Value> {
    let mut count = 0;
    for root in [
        "/etc/systemd/system",
        "/run/systemd/system",
        "/run/systemd/transient",
        "/run/systemd/generator",
        "/run/systemd/generator.early",
        "/run/systemd/generator.late",
        "/home/sol/.config/systemd/user",
        "/etc/cron.d",
    ] {
        unit_walk(Path::new(root), targets, &mut count)?;
    }
    Ok(json!({"definitions":count,"errors":0}))
}
fn mounts(targets: &[PathBuf]) -> R<()> {
    for line in fs::read_to_string("/proc/self/mountinfo")?.lines() {
        let s = line.split_whitespace().nth(4).ok_or("bad mountinfo")?;
        let decoded = s
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\");
        let m = Path::new(&decoded);
        for t in targets {
            require(!m.starts_with(t), "mountpoint inside target")?;
        }
    }
    Ok(())
}
fn index_name(name: &str, epoch: u64) -> bool {
    let Some(rest) = name.strip_prefix(&format!("epoch-{epoch}-")) else {
        return false;
    };
    [
        "-mainnet-slot-to-cid.index",
        "-mainnet-cid-to-offset-and-size.index",
    ]
    .iter()
    .any(|suffix| {
        rest.strip_suffix(suffix).is_some_and(|cid| {
            cid.len() >= 20
                && cid
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
    })
}
fn proofs(inventory: &Value, receipt_dir: &Path) -> R<BTreeMap<u64, Value>> {
    require(
        inventory["schema"] == "jetstreamer-horizon-r2-inventory-v1",
        "wrong inventory schema",
    )?;
    let mut out = BTreeMap::new();
    for x in inventory["entries"].as_array().ok_or("inventory entries")? {
        if x["state"] != "ready-pair" {
            continue;
        }
        let e = x["epoch"].as_u64().ok_or("epoch missing")?;
        if !(150..=156).contains(&e) {
            continue;
        }
        let receipt: Value = serde_json::from_slice(&read_small(
            &receipt_dir.join(format!("epoch-{e}.r2.json")),
            1024 * 1024,
        )?)?;
        receipt_matches(&receipt, x)?;
        require(
            out.insert(e, x.clone()).is_none(),
            "duplicate inventory epoch",
        )?;
    }
    Ok(out)
}
fn receipt_matches(receipt: &Value, x: &Value) -> R<()> {
    let epoch = x["epoch"].as_u64().ok_or("inventory epoch")?;
    require(
        (150..=156).contains(&epoch)
            && x["archive_length"].as_u64().is_some_and(|n| n > 0)
            && x["archive_etag"].as_str().is_some_and(|s| !s.is_empty())
            && x["sidecar_sha256"].as_str().is_some_and(valid_sha),
        "malformed neighboring inventory identity",
    )?;
    require(
        receipt["schema"] == "jetstreamer-horizon-r2-receipt-v1"
            && receipt["bucket"] == "solana-archive-with-accounts-data"
            && receipt["epoch"] == x["epoch"]
            && receipt["archive_key"] == format!("epoch-{epoch}.jet")
            && receipt["checksum_key"] == format!("epoch-{epoch}.jet.sha256")
            && receipt["archive_length"] == x["archive_length"]
            && receipt["archive_etag"] == x["archive_etag"]
            && receipt["archive_sha256"] == x["sidecar_sha256"]
            && receipt["remote_sha256_readback"] == true,
        "whole-object R2 receipt differs from inventory",
    )
}
fn now() -> R<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}
fn fresh(at: u64, clock: u64) -> R<()> {
    require(
        at <= clock && clock - at <= 900,
        "evidence review is future-dated or older than 900 seconds",
    )
}
fn valid_sha(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn approved(policy: &Value, key: &str, hash: &str) -> R<()> {
    require(valid_sha(hash), "noncanonical verifier hash")?;
    require(
        policy[key]
            .as_array()
            .ok_or("missing verifier allowlist")?
            .iter()
            .any(|v| v == hash),
        "unapproved verifier or script",
    )
}
fn check_gate_text(
    text: &str,
    expected: &[&str],
    binary_key: &str,
    script_key: &str,
    policy: &Value,
) -> R<()> {
    let fields: Vec<_> = text.split_whitespace().collect();
    require(
        fields.len() == expected.len() + 2 && fields[..expected.len()] == *expected,
        "receipt digest or field count differs",
    )?;
    approved(policy, binary_key, fields[expected.len()])?;
    approved(policy, script_key, fields[expected.len() + 1])
}
fn gate_file(
    p: &Path,
    expected: &[&str],
    binary_key: &str,
    script_key: &str,
    policy: &Value,
    out: &mut BTreeMap<String, String>,
) -> R<()> {
    let b = read_small(p, 4096)?;
    check_gate_text(
        std::str::from_utf8(&b)?,
        expected,
        binary_key,
        script_key,
        policy,
    )?;
    out.insert(p.display().to_string(), digest(&b));
    Ok(())
}
fn gates(ready: &BTreeMap<u64, Value>) -> R<Value> {
    let policy: Value = serde_json::from_str(POLICY)?;
    let mut out = BTreeMap::new();
    let sha = |epoch: u64| -> R<&str> {
        ready
            .get(&epoch)
            .and_then(|r| r["sidecar_sha256"].as_str())
            .ok_or_else(|| "selected epoch or adjacent neighbor is not ready".into())
    };
    for epoch in 150..=156 {
        let p = Path::new(R2_RECEIPTS).join(format!("epoch-{epoch}.r2.json"));
        let b = read_small(&p, 1024 * 1024)?;
        // proofs() validates the exact immutable object identity; pin these small
        // readback receipts as well so check and execution cannot change evidence.
        require(sha(epoch)?.len() == 64, "invalid inventory digest")?;
        receipt_matches(
            &serde_json::from_slice(&b)?,
            ready.get(&epoch).ok_or("missing neighboring R2 identity")?,
        )?;
        out.insert(p.display().to_string(), digest(&b));
    }
    for epoch in 151..=155 {
        gate_file(
            &Path::new(FULL).join(format!("epoch-{epoch}.full.ok")),
            &[sha(epoch)?],
            "full_binary",
            "full_script",
            &policy,
            &mut out,
        )?;
        gate_file(
            &Path::new(PLUGIN).join(format!("epoch-{epoch}.plugin.ok")),
            &[sha(epoch)?],
            "plugin_binary",
            "plugin_script",
            &policy,
            &mut out,
        )?;
    }
    for left in 150..=155 {
        gate_file(
            &Path::new(BOUNDARY).join(format!("boundary-{left}-{}.ok", left + 1)),
            &[sha(left)?, sha(left + 1)?],
            "boundary_binary",
            "boundary_script",
            &policy,
            &mut out,
        )?;
    }
    Ok(serde_json::to_value(out)?)
}
fn owner_outputs(targets: &[PathBuf]) -> R<Vec<PathBuf>> {
    let mut out = BTreeSet::new();
    for p in targets {
        out.insert(
            p.parent()
                .and_then(Path::parent)
                .ok_or("missing owning output")?
                .to_path_buf(),
        );
    }
    Ok(out.into_iter().collect())
}
fn dependency_review(plan: &Value) -> R<()> {
    let p = Path::new(
        plan["dependency_review"]["path"]
            .as_str()
            .ok_or("dependency review path")?,
    );
    let v = json_bound(
        p,
        plan["dependency_review"]["sha256"]
            .as_str()
            .ok_or("dependency review digest")?,
    )?;
    let m = fs::symlink_metadata(p)?;
    require(
        m.uid() == 0 && m.mode() & 0o022 == 0,
        "dependency review must be Root-owned and non-writable",
    )?;
    require(
        v["schema"] == "horizon-nine-completed-cache-dependency-review-v1"
            && v["allowlist_sha256"] == digest(ALLOW.as_bytes())
            && v["targets"] == plan["targets"]
            && v["inventory"] == plan["inventory"]
            && v["no_live_or_staged_or_indirect_index_consumers"] == true
            && v["indexes_reproducible_from_retained_public_sources"] == true
            && v["original199_old185_and_current_dependency_closure_preserved"] == true,
        "dependency review does not authorize these exact caches",
    )?;
    fresh(
        v["recorded_unix_seconds"]
            .as_u64()
            .ok_or("dependency review clock")?,
        now()?,
    )
}
fn inspect_tree(target: &Path, tree: &BTreeMap<String, Value>, epoch: u64) -> R<Value> {
    let mut bytes = 0u64;
    let mut physical = 0u64;
    let mut files = 0u64;
    for (relative, id) in tree {
        let p = target.join(relative);
        let mode = id[2].as_u64().ok_or("mode")?;
        if mode & 0o170000 != 0o100000 {
            require(relative.is_empty(), "nested cache directories rejected")?;
            continue;
        }
        let len = id[6].as_u64().ok_or("length")?;
        bytes = bytes.checked_add(len).ok_or("byte overflow")?;
        require(
            !relative.contains('/') && index_name(relative, epoch),
            "non-index or wrong-epoch payload rejected",
        )?;
        let m = fs::symlink_metadata(&p)?;
        require(identity(&m) == *id, "cache identity changed")?;
        physical = physical
            .checked_add(m.blocks().checked_mul(512).ok_or("block overflow")?)
            .ok_or("physical byte overflow")?;
        files += 1;
    }
    require(
        files > 0 && files <= 2,
        "empty or unexpected cache file count",
    )?;
    Ok(
        json!({"epoch":epoch,"logical_bytes":bytes,"physical_bytes":physical,"files":files,"payload_body_reads":0}),
    )
}
fn root_private(p: &Path) -> R<()> {
    exact(p)?;
    let m = fs::symlink_metadata(p)?;
    require(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "receipt directory must be Root-private",
    )
}
fn allow_selection(plan: &Value, allow: &Value) -> R<Vec<PathBuf>> {
    let map: BTreeMap<&str, &Value> = allow
        .as_array()
        .ok_or("allowlist array")?
        .iter()
        .map(|v| Ok((v["path"].as_str().ok_or("allowlist path")?, v)))
        .collect::<R<_>>()?;
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for v in plan["targets"].as_array().ok_or("targets missing")? {
        let p = v.as_str().ok_or("target string")?;
        require(
            map.contains_key(p) && seen.insert(p),
            "target absent from exact compiled allowlist or duplicated",
        )?;
        require(
            Path::new(p).starts_with(ROOT) && p != ROOT,
            "invalid target root",
        )?;
        out.push(PathBuf::from(p));
    }
    require(
        out.len() == map.len() && out.len() == 9,
        "all nine exact cache targets required",
    )?;
    for a in &out {
        for b in &out {
            require(a == b || !a.starts_with(b), "overlapping targets")?;
        }
    }
    Ok(out)
}
fn remove_exact(p: &Path, expected: &BTreeMap<String, Value>) -> R<()> {
    require(census(p)? == *expected, "tree drift before deletion")?;
    fs::remove_dir_all(p)?;
    require(!p.try_exists()?, "target remains after removal")?;
    File::open(p.parent().ok_or("target parent")?)?.sync_all()?;
    Ok(())
}
fn run() -> R<()> {
    let args: Vec<String> = std::env::args().collect();
    require(
        args.len() == 7
            && args[2] == "--plan-sha256"
            && args[4] == "--self-sha256"
            && ["check", "execute"].contains(&args[6].as_str()),
        "usage: TOOL PLAN --plan-sha256 HASH --self-sha256 HASH check|execute",
    )?;
    require(
        digest(&fs::read("/proc/self/exe")?) == args[5],
        "self hash mismatch",
    )?;
    require(
        fs::metadata("/proc/self")?.uid() == 0,
        "Root execution required",
    )?;
    let _shared_lock = mutation_lock()?;
    let plan = json_bound(Path::new(&args[1]), &args[3])?;
    let plan_meta = fs::symlink_metadata(&args[1])?;
    require(
        plan_meta.uid() == 0 && plan_meta.mode() & 0o022 == 0,
        "plan must be Root-owned and non-writable",
    )?;
    require(
        plan["schema"] == "horizon-nine-completed-cache-cleanup-plan-v1"
            && plan["allowlist_sha256"] == digest(ALLOW.as_bytes())
            && plan["verifier_policy_sha256"] == digest(POLICY.as_bytes()),
        "plan schema, exact allowlist or verifier policy mismatch",
    )?;
    require(
        plan["authority"]["local_index_retirement_authorized"] == true
            && plan["authority"]["archive_deletion_authorized"] == false
            && plan["authority"]["snapshot_deletion_authorized"] == false
            && plan["authority"]["remote_mutations"] == false
            && plan["authority"]["replay_launch_authorized"] == false,
        "foreign cleanup authority",
    )?;
    fresh(
        plan["evidence_observed_unix_seconds"]
            .as_u64()
            .ok_or("inventory observation clock")?,
        now()?,
    )?;
    dependency_review(&plan)?;
    let allow: Value = serde_json::from_str(ALLOW)?;
    let targets = allow_selection(&plan, &allow)?;
    let out = Path::new(RECEIPTS);
    root_private(out)?;
    require(
        !out.join("intent.json").exists() && !out.join("completion.json").exists(),
        "existing intent/completion: review instead of retry",
    )?;
    let inv = json_bound(
        Path::new(plan["inventory"]["path"].as_str().ok_or("inventory path")?),
        plan["inventory"]["sha256"]
            .as_str()
            .ok_or("inventory sha")?,
    )?;
    let ready = proofs(&inv, Path::new(R2_RECEIPTS))?;
    let gate_proof = gates(&ready)?;
    for target in &targets {
        let a = allow
            .as_array()
            .ok_or("allowlist")?
            .iter()
            .find(|x| x["path"] == target.to_str().unwrap_or(""))
            .ok_or("target binding")?;
        for epoch in a["epochs"].as_array().ok_or("allowlist epochs")? {
            require(
                ready.contains_key(&epoch.as_u64().ok_or("epoch")?),
                "target includes non-ready epoch",
            )?;
        }
    }
    let mut consumers = targets.clone();
    consumers.extend(owner_outputs(&targets)?);
    mounts(&targets)?;
    let before_process = proc_scan(&consumers)?;
    let before_staged = staged_scan(&consumers)?;
    let mut trees = Vec::new();
    let mut records = Vec::new();
    for p in &targets {
        let epoch = p
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("cache epoch name")?
            .parse()?;
        let t = census(p)?;
        let record = inspect_tree(p, &t, epoch)?;
        records.push(json!({"path":p,"tree":t,"evidence":record}));
        trees.push(t);
    }
    let available_before = free_bytes()?;
    let before = json!({"schema":"horizon-nine-completed-cache-cleanup-check-v1","plan_sha256":args[3],"self_sha256":args[5],"archive_body_reads":0,"index_body_reads":0,"remote_mutations":0,"processes":before_process,"staged":before_staged,"gate_proof":gate_proof,"targets":records,"filesystem_available_bytes_before":available_before});
    let checking = args[6] == "check";
    durable(
        &out.join(if checking {
            "check.json"
        } else {
            "execute-check.json"
        }),
        &before,
    )?;
    if checking {
        println!(
            "checked {} exact obsolete targets; no deletion, archive body reads or remote mutations",
            targets.len()
        );
        return Ok(());
    }
    let prior = json_bound(
        &out.join("check.json"),
        plan["prior_check_sha256"]
            .as_str()
            .ok_or("execute plan needs bound prior_check_sha256")?,
    )?;
    // Metadata and tree evidence must reproduce the earlier, separately reviewed check.
    require(
        prior["schema"] == before["schema"]
            && prior["targets"] == before["targets"]
            && prior["gate_proof"] == before["gate_proof"]
            && prior["self_sha256"] == before["self_sha256"],
        "prior check does not match exact current trees and proof",
    )?;
    mounts(&targets)?;
    proc_scan(&consumers)?;
    staged_scan(&consumers)?;
    for (p, t) in targets.iter().zip(&trees) {
        require(census(p)? == *t, "tree changed after inspection")?;
    }
    require(
        gates(&proofs(&inv, Path::new(R2_RECEIPTS))?)? == gate_proof,
        "retirement gate evidence drift",
    )?;
    dependency_review(&plan)?;
    durable(
        &out.join("intent.json"),
        &json!({"schema":"horizon-nine-completed-cache-cleanup-intent-v1","plan_sha256":args[3],"check_sha256":digest(&read_small(&out.join("execute-check.json"),64*1024*1024)?),"targets":targets,"archive_body_reads":0,"index_body_reads":0,"remote_mutations":0,"filesystem_available_bytes_before":available_before}),
    )?;
    let mut removed = Vec::new();
    let mut journal = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(NOFOLLOW)
        .open(out.join("removed.jsonl"))?;
    journal.sync_all()?;
    File::open(out)?.sync_all()?;
    for (p, t) in targets.iter().zip(&trees) {
        mounts(std::slice::from_ref(p))?;
        proc_scan(&consumers)?;
        staged_scan(&consumers)?;
        fresh(
            plan["evidence_observed_unix_seconds"]
                .as_u64()
                .ok_or("inventory observation clock")?,
            now()?,
        )?;
        dependency_review(&plan)?;
        require(
            gates(&proofs(&inv, Path::new(R2_RECEIPTS))?)? == gate_proof,
            "retirement gate evidence drift",
        )?;
        remove_exact(p, t)?;
        removed.push(p);
        journal.write_all(&serde_json::to_vec(&json!({"path":p,"absent":true}))?)?;
        journal.write_all(b"\n")?;
        journal.sync_all()?;
    }
    let physical_bytes = records.iter().try_fold(0u64, |sum, r| {
        sum.checked_add(
            r["evidence"]["physical_bytes"]
                .as_u64()
                .ok_or("physical byte evidence")?,
        )
        .ok_or("physical byte sum overflow")
    })?;
    durable(
        &out.join("completion.json"),
        &json!({"schema":"horizon-nine-completed-cache-cleanup-completion-v1","plan_sha256":args[3],"removed":removed,"retired_physical_file_bytes":physical_bytes,"archive_body_reads":0,"index_body_reads":0,"remote_mutations":0,"filesystem_available_bytes_before":available_before,"filesystem_available_bytes_after":free_bytes()?,"raw_claim_release_authorized":false,"new_lane_admission_authorized":false}),
    )?;
    println!("removed {} exact obsolete targets", targets.len());
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("cleanup refused: {e}");
        std::process::exit(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn temp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("horizon-cleanup-{}-{name}", std::process::id()));
        fs::create_dir(&p).unwrap();
        p
    }
    #[test]
    fn path_boundaries() {
        assert!(path_ref(b"x /private/tree/file", b"/private/tree"));
        assert!(!path_ref(b"/private/tree-sibling", b"/private/tree"));
        assert!(path_ref(b"/private/tree\0", b"/private/tree"));
    }
    #[test]
    fn symlink_rejected() {
        let p = temp("symlink");
        std::os::unix::fs::symlink("/etc/passwd", p.join("link")).unwrap();
        assert!(census(&p).is_err());
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn tree_drift_rejected() {
        let p = temp("drift");
        fs::write(p.join("a"), b"old").unwrap();
        let c = census(&p).unwrap();
        fs::write(p.join("a"), b"changed").unwrap();
        assert!(remove_exact(&p, &c).is_err());
        assert!(p.join("a").exists());
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn only_selected_epoch_index_names() {
        let n = "epoch-152-bafyreid7rvvr5sf7clk6i3cubdke2t74-mainnet-slot-to-cid.index";
        assert!(index_name(n, 152));
        assert!(!index_name(n, 153));
        for n in [
            "epoch-152.jet",
            "snapshot.tar.zst",
            "credentials.db",
            "epoch-152-x-mainnet-slot-to-cid.index",
        ] {
            assert!(!index_name(n, 152));
        }
    }
    #[test]
    fn exact_allowlist_rejects_sibling() {
        let allow = json!([{"path":"/home/sol/.jetstreamer-private/old"}]);
        assert!(
            allow_selection(
                &json!({"targets":["/home/sol/.jetstreamer-private/old-neighbor"]}),
                &allow
            )
            .is_err()
        );
    }
    #[test]
    fn nofollow_read_rejected() {
        let p = temp("read-link");
        std::os::unix::fs::symlink("/etc/passwd", p.join("link")).unwrap();
        assert!(read_small(&p.join("link"), 10000).is_err());
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn synthetic_removal_only_exact_tree() {
        let p = temp("remove");
        let q = temp("neighbor");
        fs::write(p.join("a"), b"scratch").unwrap();
        fs::write(q.join("b"), b"retain").unwrap();
        let c = census(&p).unwrap();
        remove_exact(&p, &c).unwrap();
        assert!(!p.exists());
        assert!(q.join("b").exists());
        fs::remove_dir_all(q).unwrap();
    }
    #[test]
    fn receipt_gates_fail_closed() {
        let p: Value = serde_json::from_str(POLICY).unwrap();
        let good = format!(
            "digest {} {}\n",
            p["full_binary"][0].as_str().unwrap(),
            p["full_script"][0].as_str().unwrap()
        );
        assert!(check_gate_text(&good, &["digest"], "full_binary", "full_script", &p).is_ok());
        assert!(check_gate_text(&good, &["changed"], "full_binary", "full_script", &p).is_err());
        assert!(
            check_gate_text(
                &(good.clone() + "extra"),
                &["digest"],
                "full_binary",
                "full_script",
                &p
            )
            .is_err()
        );
        assert!(approved(&p, "full_binary", &"0".repeat(64)).is_err());
    }
    #[test]
    fn replacement_symlink_never_deletes_neighbor() {
        let p = temp("replace-link");
        let q = temp("retain-link");
        fs::write(q.join("keep"), b"keep").unwrap();
        let c = census(&p).unwrap();
        fs::remove_dir(&p).unwrap();
        std::os::unix::fs::symlink(&q, &p).unwrap();
        assert!(remove_exact(&p, &c).is_err());
        assert!(q.join("keep").exists());
        fs::remove_file(p).unwrap();
        fs::remove_dir_all(q).unwrap();
    }
    #[test]
    fn hard_links_rejected() {
        let p = temp("hardlink");
        fs::write(p.join("a"), b"keep").unwrap();
        fs::hard_link(p.join("a"), p.join("b")).unwrap();
        assert!(census(&p).is_err());
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn non_index_tree_rejected_without_reading_payload() {
        let p = temp("payload");
        fs::write(p.join("epoch-152.jet"), b"archive").unwrap();
        let c = census(&p).unwrap();
        assert!(inspect_tree(&p, &c, 152).is_err());
        assert!(p.join("epoch-152.jet").exists());
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn complete_selection_required() {
        let a: Value = serde_json::from_str(ALLOW).unwrap();
        let targets: Vec<_> = a
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["path"].clone())
            .collect();
        assert!(allow_selection(&json!({"targets":targets}), &a).is_ok());
        let mut less = targets;
        less.pop();
        assert!(allow_selection(&json!({"targets":less}), &a).is_err());
    }
    #[test]
    fn freshness_rejects_future_and_expiry() {
        assert!(fresh(1000, 1000).is_ok());
        assert!(fresh(1000, 1900).is_ok());
        assert!(fresh(1001, 1000).is_err());
        assert!(fresh(1000, 1901).is_err());
    }
    #[test]
    fn owning_output_paths_are_scanned() {
        let a: Value = serde_json::from_str(ALLOW).unwrap();
        let targets: Vec<_> = a
            .as_array()
            .unwrap()
            .iter()
            .map(|r| PathBuf::from(r["path"].as_str().unwrap()))
            .collect();
        let outputs = owner_outputs(&targets).unwrap();
        assert_eq!(outputs.len(), 4);
        assert!(outputs.iter().all(|p| p.file_name().unwrap() == "output"));
    }
    #[test]
    fn r2_evidence_requires_readback_and_exact_identity() {
        let sha = "a".repeat(64);
        let x =
            json!({"epoch":152,"archive_length":100,"archive_etag":"etag","sidecar_sha256":sha});
        let mut r = json!({"schema":"jetstreamer-horizon-r2-receipt-v1","bucket":"solana-archive-with-accounts-data","epoch":152,"archive_key":"epoch-152.jet","checksum_key":"epoch-152.jet.sha256","archive_length":100,"archive_etag":"etag","archive_sha256":sha,"remote_sha256_readback":true});
        assert!(receipt_matches(&r, &x).is_ok());
        r["remote_sha256_readback"] = json!(false);
        assert!(receipt_matches(&r, &x).is_err());
        r["remote_sha256_readback"] = json!(true);
        r["archive_length"] = json!(101);
        assert!(receipt_matches(&r, &x).is_err());
        assert!(receipt_matches(&json!({}), &json!({})).is_err());
    }
}
