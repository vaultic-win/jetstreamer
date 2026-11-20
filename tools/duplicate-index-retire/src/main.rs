//! Exact local retirement of two independently sealed duplicate CID indexes.
//! Closed profile registry; no recursive removal, service mutation or R2 routes.
mod process_references;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
const DEV: u64 = 66305;
const LIMIT: u64 = 8 << 20;
const FLOOR: u64 = 3_908_104_436_088;
const IMAGE: &str =
    "/var/lib/jetstreamer/horizon-duplicate-index-retirer-20261120-v4/duplicate-index-retire";
const LOCK: &str = "/home/ubuntu/.jetstreamer-private/r2-receipts/local-mutation.lock";
const PROTECTED: &str = "horizon-qualify-250-reboot-20261117-v1.service";
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
    len: u64,
    blocks: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
fn stamp(m: &fs::Metadata) -> Stamp {
    Stamp {
        dev: m.dev(),
        ino: m.ino(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
        nlink: m.nlink(),
        len: m.len(),
        blocks: m.blocks(),
        mtime: m.mtime(),
        mtime_ns: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
    }
}
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn absent(p: &Path) -> Result<()> {
    match fs::symlink_metadata(p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => bail!("expected absent exact path: {}", p.display()),
    }
}
fn file_bytes(
    p: &Path,
    expected: &str,
    uid: u32,
    ino: Option<u64>,
    immutable: bool,
) -> Result<Vec<u8>> {
    ensure!(digest(expected), "digest syntax");
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.canonicalize()? == p
            && m.is_file()
            && m.uid() == uid
            && m.gid() == uid
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && (!immutable || m.mode() & 0o222 == 0)
            && m.len() <= LIMIT
            && ino.is_none_or(|i| i == m.ino())
            && (uid != 1000 || (m.dev() == DEV && m.mode() & 0o7777 == 0o600)),
        "file custody: {}",
        p.display()
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?;
    ensure!(stamp(&f.metadata()?) == stamp(&m), "file open race");
    let mut raw = Vec::new();
    Read::by_ref(&mut f).take(LIMIT + 1).read_to_end(&mut raw)?;
    ensure!(
        raw.len() as u64 <= LIMIT
            && sha(&raw) == expected
            && stamp(&f.metadata()?) == stamp(&m)
            && stamp(&fs::symlink_metadata(p)?) == stamp(&m),
        "file changed/hash mismatch"
    );
    Ok(raw)
}
fn bound(b: &Bound) -> Result<Value> {
    ensure!(
        b.path.starts_with("/var/lib/jetstreamer"),
        "immutable evidence namespace"
    );
    for p in b.path.ancestors().skip(1) {
        let m = fs::symlink_metadata(p)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "evidence ancestor custody"
        );
    }
    Ok(serde_json::from_slice(&file_bytes(
        &b.path, &b.sha256, 0, None, true,
    )?)?)
}
fn write_new(p: &Path, v: &Value) -> Result<Bound> {
    let raw = serde_json::to_vec_pretty(v)?;
    ensure!(raw.len() as u64 <= LIMIT, "receipt limit");
    let parent = p.parent().context("receipt parent")?;
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .mode(0o444)
        .custom_flags(libc::O_TMPFILE | libc::O_CLOEXEC)
        .open(parent)?;
    f.write_all(&raw)?;
    f.sync_all()?;
    let parent_fd = File::open(parent)?;
    let source = std::ffi::CString::new(format!("/proc/self/fd/{}", f.as_raw_fd()))?;
    let name = std::ffi::CString::new(p.file_name().context("receipt name")?.as_encoded_bytes())?;
    // Publish the fully synced anonymous inode. An interrupted write leaves no
    // named partial receipt, and linkat cannot replace an existing name.
    if unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            source.as_ptr(),
            parent_fd.as_raw_fd(),
            name.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    parent_fd.sync_all()?;
    Ok(Bound {
        path: p.into(),
        sha256: sha(&raw),
    })
}
fn lock() -> Result<File> {
    let p = Path::new(LOCK);
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.canonicalize()? == p
            && m.is_file()
            && m.nlink() == 1
            && [0, 1000].contains(&m.uid())
            && m.mode() & 0o077 == 0,
        "shared mutation lock custody"
    );
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?;
    ensure!(
        stamp(&f.metadata()?) == stamp(&m)
            && unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "mutation lock race/busy"
    );
    Ok(f)
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Profile {
    epoch: u64,
    target: PathBuf,
    preserved: PathBuf,
    sha256: String,
    header_hex: String,
    target_identity: Stamp,
    preserved_identity: Stamp,
    target_parent_inode: u64,
    package_inode: u64,
    sums_sha256: String,
    seal_sha256: String,
    seal: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    epoch: u64,
    target: PathBuf,
    preserved: PathBuf,
    main_review: Bound,
    exclusive_campaign_mutation_owner: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Review {
    schema: String,
    epoch: u64,
    target: PathBuf,
    preserved: PathBuf,
    main_accepted: bool,
    source_acquisition_and_seal_actors_closed: bool,
    transitive_scripts_plans_and_user_units_reviewed: bool,
    staged_original_cache_consumers_absent: bool,
    evidence: Vec<Bound>,
    protected250: BTreeMap<String, String>,
    closed_units: Vec<ClosedUnit>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClosedUnit {
    unit: String,
    properties: BTreeMap<String, String>,
}
fn profile(epoch: u64) -> Result<Profile> {
    let all: Vec<Profile> = serde_json::from_str(include_str!("profiles.json"))?;
    all.into_iter()
        .find(|p| p.epoch == epoch)
        .context("unregistered epoch")
}
fn validate_plan(p: &Plan, r: &Review, q: &Profile) -> Result<()> {
    ensure!(
        p.schema == "horizon-duplicate-index-retirement-plan-v1"
            && p.epoch == q.epoch
            && p.target == q.target
            && p.preserved == q.preserved
            && p.exclusive_campaign_mutation_owner,
        "plan scope"
    );
    ensure!(
        r.schema == "horizon-duplicate-index-retirement-review-v1"
            && r.epoch == q.epoch
            && r.target == q.target
            && r.preserved == q.preserved
            && r.main_accepted
            && r.source_acquisition_and_seal_actors_closed
            && r.transitive_scripts_plans_and_user_units_reviewed
            && r.staged_original_cache_consumers_absent
            && !r.evidence.is_empty()
            && !r.closed_units.is_empty(),
        "missing complete Main closure review"
    );
    ensure!(
        q.target_identity.nlink == 1
            && q.preserved_identity.nlink == 1
            && (q.target_identity.dev, q.target_identity.ino)
                != (q.preserved_identity.dev, q.preserved_identity.ino),
        "copies are not independent"
    );
    ensure!(
        r.protected250.get("Id").map(String::as_str) == Some(PROTECTED)
            && r.protected250.get("ActiveState").map(String::as_str) == Some("active")
            && r.protected250.get("SubState").map(String::as_str) == Some("running"),
        "protected250 must be the running invocation"
    );
    ensure!(
        r.protected250
            .get("MainPID")
            .context("protected PID")?
            .parse::<u32>()?
            > 0
            && r.protected250
                .get("InvocationID")
                .is_some_and(|s| s.len() == 32),
        "protected250 identity"
    );
    for key in [
        "ControlGroup",
        "ExecStart",
        "FragmentPath",
        "DropInPaths",
        "NRestarts",
        "LoadState",
    ] {
        ensure!(
            r.protected250.contains_key(key),
            "protected property missing {key}"
        );
    }
    let mut units = BTreeSet::new();
    for u in &r.closed_units {
        ensure!(
            u.unit.ends_with(".service")
                && !u.unit.contains('/')
                && units.insert(&u.unit)
                && u.unit != PROTECTED,
            "closed unit selection"
        );
        for (key, want) in [
            ("Id", u.unit.as_str()),
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
            ("MainPID", "0"),
            ("ControlPID", "0"),
            ("Job", ""),
        ] {
            ensure!(
                u.properties.get(key).map(String::as_str) == Some(want),
                "closed unit is not drained: {key}"
            );
        }
        for key in [
            "InvocationID",
            "ExecStart",
            "FragmentPath",
            "DropInPaths",
            "LoadState",
            "TriggeredBy",
        ] {
            ensure!(
                u.properties.contains_key(key),
                "closed unit property missing {key}"
            );
        }
        ensure!(
            u.properties["TriggeredBy"].is_empty(),
            "closed unit retains triggers"
        );
    }
    Ok(())
}
fn ancestors(p: &Path) -> Result<()> {
    ensure!(
        p.is_absolute() && p.canonicalize()? == p,
        "noncanonical path"
    );
    for a in p.ancestors().skip(1) {
        let m = fs::symlink_metadata(a)?;
        ensure!(
            m.is_dir() && [0, 1000].contains(&m.uid()) && m.mode() & 0o022 == 0,
            "unsafe path ancestor {}",
            a.display()
        );
    }
    Ok(())
}
fn exact(p: &Path, want: &Stamp) -> Result<()> {
    ancestors(p)?;
    let m = fs::symlink_metadata(p)?;
    ensure!(
        m.is_file() && m.nlink() == 1 && stamp(&m) == *want,
        "exact file identity changed {}",
        p.display()
    );
    Ok(())
}
fn parent_fd(q: &Profile) -> Result<File> {
    let p = q.target.parent().context("target parent")?;
    ancestors(p)?;
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        m.dev() == q.target_identity.dev
            && m.ino() == q.target_parent_inode
            && m.uid() == 1000
            && m.gid() == 1000
            && m.mode() & 0o7777 == 0o700,
        "original cache parent changed"
    );
    Ok(f)
}
fn decode_hex(s: &str) -> Result<Vec<u8>> {
    ensure!(
        s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit()),
        "hex syntax"
    );
    (0..s.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&s[i..i + 2], 16)?))
        .collect()
}
fn hash_file(
    p: &Path,
    want: &Stamp,
    digest: &str,
    header: &[u8],
    tick: impl Fn() -> Result<()>,
) -> Result<()> {
    exact(p, want)?;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?;
    ensure!(stamp(&f.metadata()?) == *want, "hash open race");
    hash_reader(&mut f, want.len, digest, header, &tick)?;
    ensure!(
        stamp(&f.metadata()?) == *want,
        "file identity changed during hash"
    );
    exact(p, want)?;
    tick()
}
fn hash_reader(
    mut f: impl Read,
    expected_len: u64,
    digest: &str,
    header: &[u8],
    tick: impl Fn() -> Result<()>,
) -> Result<()> {
    ensure!(
        digest.len() == 64 && header.len() as u64 <= expected_len,
        "invalid hash parameters"
    );
    let mut prefix = vec![0; header.len()];
    f.read_exact(&mut prefix)?;
    ensure!(prefix == header, "compactindex header/CID/epoch changed");
    let mut h = Sha256::new();
    h.update(&prefix);
    let mut n = prefix.len() as u64;
    let mut buf = vec![0; 1 << 20];
    let mut ticks = 0u64;
    loop {
        let got = f.read(&mut buf)?;
        if got == 0 {
            break;
        }
        h.update(&buf[..got]);
        n = n.checked_add(got as u64).context("hash size overflow")?;
        ensure!(n <= expected_len, "file grew during hash");
        ticks += 1;
        if ticks.is_multiple_of(256) {
            tick()?;
        }
    }
    ensure!(
        n == expected_len && format!("{:x}", h.finalize()) == digest,
        "full file hash/length/identity mismatch"
    );
    Ok(())
}
fn validate_sums(raw: &[u8], q: &Profile) -> Result<()> {
    let mut expected = BTreeMap::from([(
        "deployment-seal-receipt.json".to_string(),
        q.seal_sha256.clone(),
    )]);
    for member in q.seal["members"].as_array().context("seal members")? {
        let name = member["name"].as_str().context("member name")?;
        ensure!(
            expected
                .insert(
                    name.into(),
                    member["sha256"].as_str().context("member hash")?.into()
                )
                .is_none(),
            "duplicate sealed member"
        );
    }
    let mut actual = BTreeMap::new();
    for line in std::str::from_utf8(raw)?.lines() {
        let (sum, name) = line.split_once("  ").context("SHA256SUMS framing")?;
        ensure!(
            digest(sum)
                && !name.is_empty()
                && !name.contains('/')
                && actual.insert(name.into(), sum.into()).is_none(),
            "invalid/duplicate checksum entry"
        );
    }
    ensure!(actual == expected, "exact sealed sums set differs");
    Ok(())
}
fn package(q: &Profile, tick: impl Fn() -> Result<()>) -> Result<Value> {
    let root = q.preserved.parent().context("package parent")?;
    ancestors(root)?;
    let m = fs::symlink_metadata(root)?;
    ensure!(
        m.is_dir()
            && m.dev() == q.preserved_identity.dev
            && m.ino() == q.package_inode
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o7777 == 0o555,
        "immutable package changed"
    );
    let seal = file_bytes(
        &root.join("deployment-seal-receipt.json"),
        &q.seal_sha256,
        0,
        None,
        true,
    )?;
    ensure!(
        serde_json::from_slice::<Value>(&seal)? == q.seal,
        "genuine seal mismatch"
    );
    let sums = file_bytes(&root.join("SHA256SUMS"), &q.sums_sha256, 0, None, true)?;
    let members = q.seal["members"].as_array().context("seal members")?;
    validate_sums(&sums, q)?;
    let mut expected: BTreeSet<String> =
        ["SHA256SUMS".into(), "deployment-seal-receipt.json".into()]
            .into_iter()
            .collect();
    let mut associated = false;
    for member in members {
        let name = member["name"].as_str().context("member name")?;
        ensure!(
            !name.contains('/') && expected.insert(name.into()),
            "duplicate/unsafe member"
        );
        let path = root.join(name);
        let meta = fs::symlink_metadata(&path)?;
        ensure!(
            meta.is_file()
                && meta.uid() == 0
                && meta.gid() == 0
                && meta.mode() & 0o7777 == 0o444
                && meta.nlink() == 1
                && Some(meta.len()) == member["bytes"].as_u64(),
            "member custody changed"
        );
        let sum = member["sha256"].as_str().context("member digest")?;
        let lines = std::str::from_utf8(&sums)?;
        ensure!(
            lines
                .lines()
                .filter(|line| *line == format!("{sum}  {name}"))
                .count()
                == 1,
            "member omitted from sealed sums"
        );
        if path == q.preserved {
            ensure!(
                member["source"] == q.target.to_string_lossy().as_ref()
                    && sum == q.sha256
                    && meta.len() == q.target_identity.len,
                "original-to-sealed association changed"
            );
            associated = true;
            hash_file(
                &path,
                &q.preserved_identity,
                sum,
                &decode_hex(&q.header_hex)?,
                &tick,
            )?;
        } else {
            hash_file(&path, &stamp(&meta), sum, &[], &tick)?;
        }
    }
    ensure!(associated, "seal association or sums set");
    let actual: BTreeSet<_> = fs::read_dir(root)?
        .map(|e| {
            e?.file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("nonUTF8 package child"))
        })
        .collect::<Result<_>>()?;
    ensure!(actual == expected, "package member set changed");
    Ok(
        json!({"seal_sha256":q.seal_sha256,"sums_sha256":q.sums_sha256,"preserved":q.preserved_identity,"all_members_rehashed":true}),
    )
}
fn wall() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}
fn booking_valid(b: &Value, plan: &Bound, epoch: u64, now: u64) -> Result<()> {
    let issued = b["recorded_unix_seconds"].as_u64().context("issued")?;
    let expires = b["expires_unix_seconds"].as_u64().context("expires")?;
    ensure!(
        issued <= now
            && now < expires
            && expires <= issued.checked_add(1800).context("clock overflow")?,
        "booking stale/future/oversized"
    );
    ensure!(
        b["schema"] == "horizon-duplicate-index-retirement-booking-v1"
            && b["Main_accepted"] == true
            && b["complete_fleet_funding_accepted"] == true
            && b["epoch"] == epoch
            && b["plan"] == json!(plan)
            && b["maximum_memory_bytes"] == 536870912u64
            && b["maximum_metadata_bytes"] == 16777216u64
            && b["maximum_wall_seconds"] == 1800
            && b["future_growth_credit_taken_bytes"] == 0
            && b["physical_credit_taken_bytes"] == 0,
        "booking capacity/authority mismatch"
    );
    ensure!(
        b["minimum_free_bytes"].as_u64().context("minimum free")? >= FLOOR,
        "live265 floor cannot be lowered"
    );
    ensure!(
        digest(
            b["fleet_evidence_sha256"]
                .as_str()
                .context("fleet digest")?
        ),
        "fleet digest"
    );
    Ok(())
}
fn capacity(b: &Value, plan: &Bound, epoch: u64) -> Result<()> {
    booking_valid(b, plan, epoch, wall()?)?;
    ensure!(
        fs::metadata("/")?.dev() == DEV,
        "floor and candidates are not on the same backing filesystem"
    );
    let mut s = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(c"/".as_ptr(), s.as_mut_ptr()) } == 0,
        "statvfs failed"
    );
    let s = unsafe { s.assume_init() };
    let free = (s.f_bavail as u128) * (s.f_frsize as u128);
    ensure!(
        free >= b["minimum_free_bytes"].as_u64().unwrap() as u128,
        "free-space floor failed"
    );
    Ok(())
}
// Bound output while the child runs; timeout bounds unresponsive PID1 queries.
fn show(unit: &str) -> Result<BTreeMap<String, String>> {
    ensure!(
        unit.ends_with(".service")
            && unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b)),
        "unit name syntax"
    );
    let properties = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,ExecStart,ControlGroup,FragmentPath,DropInPaths,Job,TriggeredBy,NRestarts,MemoryMax,MemorySwapMax,RuntimeMaxUSec,TasksMax,Type,User";
    let mut child = Command::new("/usr/bin/timeout")
        .args([
            "--signal=KILL",
            "15s",
            "/usr/bin/systemctl",
            "show",
            "--all",
            unit,
            "--property",
            properties,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut raw = Vec::new();
    let got = child
        .stdout
        .take()
        .context("manager stdout")?
        .take((1 << 20) + 1)
        .read_to_end(&mut raw);
    if got.is_err() || raw.len() > 1 << 20 {
        let _ = child.kill();
        let _ = child.wait();
        bail!("manager output unreadable/oversized");
    }
    got?;
    ensure!(child.wait()?.success(), "PID1 query failed/timed out");
    let mut out = BTreeMap::new();
    for line in std::str::from_utf8(&raw)?.lines() {
        let (k, v) = line.split_once('=').context("manager framing")?;
        ensure!(
            out.insert(k.into(), v.into()).is_none(),
            "duplicate manager property"
        );
    }
    if out.get("LoadState").is_some_and(|state| state == "masked") && !out.contains_key("ExecStart")
    {
        verify_empty_commands(unit, &["ExecStart"])?;
        out.insert("ExecStart".into(), String::new());
    }
    Ok(out)
}
// systemctl omits empty command arrays even with --all. Ask PID1 for their typed values.
fn verify_empty_commands(unit: &str, properties: &[&str]) -> Result<()> {
    let mut object = String::from("/org/freedesktop/systemd1/unit/");
    for byte in unit.bytes() {
        if byte.is_ascii_alphanumeric() {
            object.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(object, "_{byte:02x}")?;
        }
    }
    let commands = Command::new("/usr/bin/busctl")
        .args([
            "--timeout=15s",
            "get-property",
            "org.freedesktop.systemd1",
            &object,
            "org.freedesktop.systemd1.Service",
        ])
        .args(properties)
        .output()?;
    ensure!(
        commands.status.success()
            && commands.stdout == b"a(sasbttttuii) 0\n".repeat(properties.len()),
        "expected empty native command arrays for {unit}: {properties:?}"
    );
    Ok(())
}
fn compare(actual: &BTreeMap<String, String>, expected: &BTreeMap<String, String>) -> Result<()> {
    for (key, val) in expected {
        ensure!(actual.get(key) == Some(val), "PID1 property changed {key}");
    }
    Ok(())
}
fn manager_closure(r: &Review) -> Result<Value> {
    let live = show(PROTECTED)?;
    compare(&live, &r.protected250)?;
    let mut closed = BTreeMap::new();
    for unit in &r.closed_units {
        let m = show(&unit.unit)?;
        compare(&m, &unit.properties)?;
        closed.insert(unit.unit.clone(), m);
    }
    Ok(json!({"protected250":live,"closed":closed}))
}
fn controller(mode: &str, q: &Profile, b: &Value, args: &[String]) -> Result<(String, PathBuf)> {
    let unit = format!(
        "horizon-duplicate-index{}-retirement-{mode}-20261120-v1.service",
        q.epoch
    );
    ensure!(
        fs::read_to_string("/proc/self/cgroup")?.trim() == format!("0::/system.slice/{unit}"),
        "not exact helper controller"
    );
    let m = show(&unit)?;
    ensure!(
        m.get("MainPID").context("helper PID")?.parse::<u32>()? == std::process::id()
            && m.get("Id") == Some(&unit)
            && m.get("ActiveState").map(String::as_str) == Some("active")
            && m.get("Type").map(String::as_str) == Some("exec")
            && m.get("User").is_some_and(|v| v == "root" || v.is_empty()),
        "helper native identity"
    );
    ensure!(
        m.get("MemoryMax").map(String::as_str) == Some("536870912")
            && m.get("MemorySwapMax").map(String::as_str) == Some("0")
            && m.get("RuntimeMaxUSec").map(String::as_str) == Some("30min"),
        "helper native resource bounds"
    );
    ensure!(
        m.get("DropInPaths").is_some_and(String::is_empty),
        "helper drop-ins not qualified"
    );
    let mut actual = Vec::new();
    for arg in args {
        actual.extend_from_slice(arg.as_bytes());
        actual.push(0);
    }
    ensure!(
        fs::read("/proc/self/cmdline")? == actual,
        "actual argv differs"
    );
    let native = m.get("ExecStart").context("helper ExecStart")?;
    let prefix = native
        .split_once(" ; start_time=")
        .context("helper ExecStart framing")?
        .0;
    let expected = format!(
        "{{ path={IMAGE} ; argv[]={}; ignore_errors=no",
        args.join(" ") + " "
    );
    ensure!(prefix == expected, "helper native argv differs");
    let fragment = PathBuf::from(m.get("FragmentPath").context("helper fragment")?);
    ensure!(
        fragment == Path::new(&format!("/run/systemd/transient/{unit}")),
        "helper fragment namespace"
    );
    verify_empty_commands(
        &unit,
        &["ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost"],
    )?;
    ensure!(b["controller_unit"] == unit, "booking controller differs");
    let raw = read_bounded(&fragment, 1 << 20)?;
    file_bytes(&fragment, &sha(&raw), 0, None, false)?;
    Ok((unit, fragment))
}
fn read_bounded(p: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    File::open(p)?.take(limit + 1).read_to_end(&mut b)?;
    ensure!(
        b.len() as u64 <= limit,
        "bounded read exceeded {}",
        p.display()
    );
    Ok(b)
}
fn unescape(s: &str) -> Result<String> {
    let b = s.as_bytes();
    let (mut out, mut i) = (Vec::new(), 0);
    while i < b.len() {
        if b[i] == b'\\' {
            ensure!(i + 3 < b.len(), "mount escape");
            let v = &b[i + 1..i + 4];
            ensure!(v.iter().all(|v| (b'0'..=b'7').contains(v)), "mount octal");
            let n = (v[0] - b'0') as u16 * 64 + (v[1] - b'0') as u16 * 8 + (v[2] - b'0') as u16;
            ensure!(n <= 255, "mount escape overflow");
            out.push(n as u8);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Ok(String::from_utf8(out)?)
}
fn mount_check(raw: &str, target: &Path, dev: u64) -> Result<()> {
    for line in raw.lines() {
        let w: Vec<_> = line.split_whitespace().collect();
        ensure!(w.len() >= 10 && w.contains(&"-"), "mountinfo framing");
        let root = PathBuf::from(unescape(w[3])?);
        let point = PathBuf::from(unescape(w[4])?);
        ensure!(
            !(point == target || point.starts_with(target)),
            "target mountpoint"
        );
        if w[2] == format!("{}:{}", libc::major(dev), libc::minor(dev)) {
            ensure!(
                !(root == target || root.starts_with(target)),
                "target mount alias"
            );
            if let Ok(suffix) = target.strip_prefix(&root) {
                ensure!(point.join(suffix) == target, "ancestor mount alias");
            }
        }
    }
    Ok(())
}
fn inode_match(m: &fs::Metadata, q: &Profile) -> bool {
    m.dev() == q.target_identity.dev
        && [q.target_identity.ino, q.target_parent_inode].contains(&m.ino())
}
fn start(p: &Path) -> Result<String> {
    let bytes = read_bounded(&p.join("stat"), 65536)?;
    let s = std::str::from_utf8(&bytes)?;
    Ok(s.rsplit_once(')')
        .context("proc stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("proc start")?
        .into())
}
fn maps_inodes(p: &Path, q: &Profile) -> Result<()> {
    let f = File::open(p)?;
    let mut reader = BufReader::with_capacity(65536, f);
    let mut total = 0u64;
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = reader.by_ref().take(1 << 20).read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        ensure!(n < 1 << 20, "oversized map line");
        total += n as u64;
        ensure!(total <= 1 << 30, "maps bound");
        let text = std::str::from_utf8(&line)?;
        let w: Vec<_> = text.split_whitespace().take(5).collect();
        ensure!(w.len() == 5, "maps framing");
        let (major, minor) = w[3].split_once(':').context("map device")?;
        let dev = libc::makedev(
            u32::from_str_radix(major, 16)?,
            u32::from_str_radix(minor, 16)?,
        );
        let ino = w[4].parse::<u64>()?;
        ensure!(
            dev != q.target_identity.dev
                || ![q.target_identity.ino, q.target_parent_inode].contains(&ino),
            "mapped target inode alias"
        );
    }
    Ok(())
}
fn process_closure(q: &Profile) -> Result<Value> {
    let target_parent = q.target.parent().context("cache parent")?;
    let scan = process_references::scan(Path::new("/proc"), target_parent)?;
    ensure!(
        scan.references.is_empty(),
        "original cache has live references: {:?}",
        scan.references
    );
    let mut count = 0;
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let n = entry.file_name();
        let name = n.to_string_lossy();
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_digit())
            || name == std::process::id().to_string()
        {
            continue;
        }
        let p = entry.path();
        let check = || -> Result<()> {
            let before = start(&p)?;
            maps_inodes(&p.join("maps"), q)?;
            let mounts = read_bounded(&p.join("mountinfo"), 16 << 20)?;
            mount_check(
                std::str::from_utf8(&mounts)?,
                &q.target,
                q.target_identity.dev,
            )?;
            for link in ["cwd", "root", "exe"] {
                match fs::metadata(p.join(link)) {
                    Ok(m) => ensure!(!inode_match(&m, q), "process inode alias"),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                    Err(e) => return Err(e.into()),
                }
            }
            for fd in fs::read_dir(p.join("fd"))? {
                match fs::metadata(fd?.path()) {
                    Ok(m) => ensure!(!inode_match(&m, q), "open inode alias"),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                    Err(e) => return Err(e.into()),
                }
            }
            ensure!(before == start(&p)?, "PID reused during alias scan");
            Ok(())
        };
        if let Err(e) = check()
            && p.try_exists()?
        {
            return Err(e);
        }
        count += 1;
    }
    mount_check(
        std::str::from_utf8(&read_bounded(Path::new("/proc/self/mountinfo"), 16 << 20)?)?,
        &q.target,
        q.target_identity.dev,
    )?;
    Ok(json!({"path_scan":scan,"inode_mount_scan_processes":count}))
}
fn scan_staged(
    root: &Path,
    needle: &[u8],
    own: &Path,
    visited: &mut BTreeSet<PathBuf>,
    budget: &mut u64,
) -> Result<()> {
    let meta = match fs::symlink_metadata(root) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if root == own {
        return Ok(());
    }
    if meta.file_type().is_symlink() {
        let link = fs::read_link(root)?;
        ensure!(
            !process_references::encoded_reference(link.as_os_str().as_bytes(), needle, true),
            "staged symlink references cache {}",
            root.display()
        );
    }
    // A masked systemd unit is an intentional /dev/null link, never open devices.
    let canonical = match root.canonicalize() {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if canonical == Path::new("/dev/null") {
        return Ok(());
    }
    ensure!(canonical != own, "foreign staged alias of helper fragment");
    if !visited.insert(canonical.clone()) {
        return Ok(());
    }
    ensure!(visited.len() < 100_000, "staged entry budget");
    let resolved = fs::metadata(root)?;
    if resolved.is_dir() {
        for e in fs::read_dir(root)? {
            scan_staged(&e?.path(), needle, own, visited, budget)?;
        }
    } else {
        ensure!(resolved.is_file(), "unqualified staged special file");
        let raw = read_bounded(root, 8 << 20)?;
        *budget = budget
            .checked_add(raw.len() as u64)
            .context("staged byte overflow")?;
        ensure!(*budget <= 128 << 20, "staged scan budget");
        ensure!(
            stamp(&fs::metadata(root)?) == stamp(&resolved),
            "staged recipe changed"
        );
        ensure!(
            !process_references::encoded_reference(&raw, needle, true),
            "staged recipe references original cache {}",
            root.display()
        );
    }
    Ok(())
}
fn staged_closure(q: &Profile, own: &Path) -> Result<Value> {
    let mut roots: Vec<PathBuf> = [
        "/etc/systemd/system",
        "/run/systemd/system",
        "/run/systemd/transient",
        "/run/systemd/generator",
        "/run/systemd/generator.early",
        "/run/systemd/generator.late",
        "/usr/lib/systemd/system",
        "/usr/local/lib/systemd/system",
        "/etc/systemd/user",
        "/usr/lib/systemd/user",
        "/root/.config/systemd",
        "/root/.local/share/systemd",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect();
    for home in fs::read_dir("/home")? {
        let home = home?;
        if home.file_type()?.is_dir() {
            roots.push(home.path().join(".config/systemd"));
            roots.push(home.path().join(".local/share/systemd"));
        }
    }
    match fs::read_dir("/run/user") {
        Ok(users) => {
            for user in users {
                let base = user?.path().join("systemd");
                for suffix in [
                    "user",
                    "transient",
                    "generator",
                    "generator.early",
                    "generator.late",
                ] {
                    roots.push(base.join(suffix));
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    let (mut visited, mut bytes) = (BTreeSet::new(), 0);
    let needle = q
        .target
        .parent()
        .context("cache parent")?
        .as_os_str()
        .as_bytes();
    for root in &roots {
        scan_staged(root, needle, own, &mut visited, &mut bytes)?;
    }
    Ok(
        json!({"roots":roots,"inspected_entries":visited.len(),"inspected_bytes":bytes,"only_exempt_fragment":own}),
    )
}
fn siblings(q: &Profile) -> Result<BTreeMap<String, Stamp>> {
    let _parent = parent_fd(q)?;
    let mut out = BTreeMap::new();
    for e in fs::read_dir(q.target.parent().unwrap())? {
        let e = e?;
        if e.path() == q.target {
            continue;
        }
        let m = fs::symlink_metadata(e.path())?;
        let name = e
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("nonUTF8 sibling"))?;
        ensure!(out.len() < 10000, "sibling bound");
        out.insert(name, stamp(&m));
    }
    Ok(out)
}
fn remove_exact(q: &Profile, parent: &File) -> Result<()> {
    let fresh = parent_fd(q)?;
    ensure!(
        fresh.metadata()?.ino() == parent.metadata()?.ino(),
        "parent replaced"
    );
    unlink_entry(&q.target, &q.target_identity, parent)
}
fn unlink_entry(target: &Path, expected: &Stamp, parent: &File) -> Result<()> {
    let name = target.file_name().context("target name")?;
    let projected = PathBuf::from(format!(
        "/proc/self/fd/{}/{}",
        parent.as_raw_fd(),
        name.to_string_lossy()
    ));
    ensure!(
        stamp(&fs::symlink_metadata(projected)?) == *expected,
        "directory entry changed before unlink"
    );
    let c = std::ffi::CString::new(name.as_bytes())?;
    ensure!(
        unsafe { libc::unlinkat(parent.as_raw_fd(), c.as_ptr(), 0) } == 0,
        "unlink failed: {}",
        std::io::Error::last_os_error()
    );
    parent.sync_all()?;
    Ok(())
}
fn saved(state: &Path, name: &str, digest: &str) -> Result<Value> {
    bound(&Bound {
        path: state.join(name),
        sha256: digest.into(),
    })
}
fn state_dir(p: &Path) -> Result<()> {
    ancestors(p)?;
    let m = fs::symlink_metadata(p)?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "state custody"
    );
    Ok(())
}
fn receipt_scope(v: &Value, schema: &str, plan: &Bound, image: &str, q: &Profile) -> Result<()> {
    ensure!(
        v["schema"] == schema
            && v["plan"] == json!(plan)
            && v["helper_sha256"] == image
            && v["profile"] == json!(q),
        "receipt scope mismatch"
    );
    Ok(())
}
fn intent_scope(
    intent: &Value,
    plan: &Bound,
    image: &str,
    q: &Profile,
    state: &Path,
    check_sha: &str,
) -> Result<()> {
    receipt_scope(
        intent,
        "horizon-duplicate-index-retirement-intent-v1",
        plan,
        image,
        q,
    )?;
    ensure!(
        intent["check"]
            == json!(Bound {
                path: state.join("check.json"),
                sha256: check_sha.into()
            })
            && intent["physical_credit_bytes"] == 0,
        "intent binding"
    );
    Ok(())
}
fn target_present(q: &Profile) -> Result<bool> {
    match fs::symlink_metadata(&q.target) {
        Ok(_) => {
            exact(&q.target, &q.target_identity)?;
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
fn run() -> Result<()> {
    let a: Vec<String> = env::args().collect();
    ensure!(
        a.len() >= 7,
        "usage: duplicate-index-retire check|retire|resume|attest PLAN PLAN_SHA SELF_SHA BOOKING BOOKING_SHA [CHECK_OR_COMPLETION_SHA [INTENT_SHA]]"
    );
    let mode = &a[1];
    ensure!(
        matches!(mode.as_str(), "check" | "retire" | "resume" | "attest")
            && a.len()
                == match mode.as_str() {
                    "check" => 7,
                    "resume" => 9,
                    _ => 8,
                },
        "mode/argument count"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0 && env::current_exe()? == Path::new(IMAGE) && digest(&a[4]),
        "helper identity"
    );
    ancestors(Path::new(IMAGE))?;
    let em = fs::symlink_metadata(IMAGE)?;
    ensure!(
        em.is_file()
            && em.uid() == 0
            && em.gid() == 0
            && em.nlink() == 1
            && em.mode() & 0o222 == 0
            && em.len() < 64 << 20,
        "helper custody"
    );
    ensure!(
        sha(&read_bounded(Path::new("/proc/self/exe"), 64 << 20)?) == a[4]
            && stamp(&fs::metadata("/proc/self/exe")?) == stamp(&em),
        "running helper image mismatch"
    );
    let plan_ref = Bound {
        path: a[2].clone().into(),
        sha256: a[3].clone(),
    };
    let p: Plan = serde_json::from_value(bound(&plan_ref)?)?;
    let q = profile(p.epoch)?;
    let review: Review = serde_json::from_value(bound(&p.main_review)?)?;
    validate_plan(&p, &review, &q)?;
    for evidence in &review.evidence {
        bound(evidence)?;
    }
    let booking_ref = Bound {
        path: a[5].clone().into(),
        sha256: a[6].clone(),
    };
    let booking = bound(&booking_ref)?;
    capacity(&booking, &plan_ref, q.epoch)?;
    let (_, own) = controller(mode, &q, &booking, &a)?;
    let own_raw = read_bounded(&own, 1 << 20)?;
    let _lock = lock()?;
    let state = PathBuf::from(format!(
        "/var/lib/jetstreamer/horizon-duplicate-index{}-retirement-20261120-v1",
        q.epoch
    ));
    state_dir(&state)?;
    if mode == "check" {
        ensure!(
            fs::read_dir(&state)?.next().is_none(),
            "check state is not unused"
        );
    }
    if mode == "retire" || mode == "resume" {
        absent(&state.join("completion.json"))?;
    }
    let present = target_present(&q)?;
    ensure!(
        !matches!(mode.as_str(), "check" | "retire") || present,
        "fresh check/retire requires original target"
    );
    let mut original_check = Value::Null;
    let mut intent_ref = None;
    if mode == "retire" || mode == "resume" {
        original_check = saved(&state, "check.json", &a[7])?;
        receipt_scope(
            &original_check,
            "horizon-duplicate-index-retirement-check-v1",
            &plan_ref,
            &a[4],
            &q,
        )?;
        ensure!(
            original_check["retirement_performed"] == false
                && original_check["physical_credit_bytes"] == 0,
            "invalid check evidence"
        );
        if mode == "resume" {
            let intent = saved(&state, "intent.json", &a[8])?;
            intent_scope(&intent, &plan_ref, &a[4], &q, &state, &a[7])?;
            intent_ref = Some(Bound {
                path: state.join("intent.json"),
                sha256: a[8].clone(),
            });
        } else {
            absent(&state.join("intent.json"))?;
        }
    }
    if mode == "attest" {
        ensure!(!present, "target reappeared");
        let c = saved(&state, "completion.json", &a[7])?;
        receipt_scope(
            &c,
            "horizon-duplicate-index-retirement-completion-v1",
            &plan_ref,
            &a[4],
            &q,
        )?;
        ensure!(c["target_absent"] == true, "invalid completion");
    }
    let before = manager_closure(&review)?;
    let keep = siblings(&q)?;
    if !original_check.is_null() {
        ensure!(
            original_check["siblings"] == json!(keep),
            "siblings changed since qualification"
        );
    }
    let tick = || capacity(&booking, &plan_ref, q.epoch);
    let preserved = package(&q, tick)?;
    if present {
        hash_file(
            &q.target,
            &q.target_identity,
            &q.sha256,
            &decode_hex(&q.header_hex)?,
            tick,
        )?;
    }
    let processes = process_closure(&q)?;
    let staged = staged_closure(&q, &own)?;
    ensure!(
        manager_closure(&review)? == before
            && siblings(&q)? == keep
            && read_bounded(&own, 1 << 20)? == own_raw,
        "scope changed during qualification"
    );
    controller(mode, &q, &booking, &a)?;
    tick()?;
    let base = json!({"recorded_unix_seconds":wall()?,"plan":plan_ref,"helper_sha256":a[4],"profile":q,"booking":booking_ref,"manager":before,"siblings":keep,"package":preserved,"process_closure":processes,"staged_closure":staged,"own_fragment_sha256":sha(&own_raw),"physical_credit_bytes":0,"remote_mutations":false,"r2_mutations":false,"replay_launch_authorized":false});
    if mode == "check" {
        let mut v = base;
        v["schema"] = json!("horizon-duplicate-index-retirement-check-v1");
        v["retirement_performed"] = json!(false);
        println!(
            "{}",
            serde_json::to_string(&write_new(&state.join("check.json"), &v)?)?
        );
        return Ok(());
    }
    if mode == "attest" {
        let mut v = base;
        v["schema"] = json!("horizon-duplicate-index-retirement-attestation-v1");
        v["completion"] = json!(Bound {
            path: state.join("completion.json"),
            sha256: a[7].clone()
        });
        v["target_absent"] = json!(true);
        v["new_physical_credit_bytes"] = json!(0);
        println!("{}", serde_json::to_string(&v)?);
        return Ok(());
    }
    if intent_ref.is_none() {
        let mut v = base.clone();
        v["schema"] = json!("horizon-duplicate-index-retirement-intent-v1");
        v["check"] = json!(Bound {
            path: state.join("check.json"),
            sha256: a[7].clone()
        });
        intent_ref = Some(write_new(&state.join("intent.json"), &v)?);
    }
    // Rescan after the durable intent and immediately before the one unlink.
    process_closure(&q)?;
    staged_closure(&q, &own)?;
    ensure!(
        manager_closure(&review)? == before && siblings(&q)? == keep,
        "scope changed before unlink"
    );
    tick()?;
    if present {
        exact(&q.preserved, &q.preserved_identity)?;
        remove_exact(&q, &parent_fd(&q)?)?;
    }
    absent(&q.target)?;
    exact(&q.preserved, &q.preserved_identity)?;
    ensure!(
        siblings(&q)? == keep && manager_closure(&review)? == before,
        "scope changed after unlink"
    );
    tick()?;
    let mut v = base;
    v["schema"] = json!("horizon-duplicate-index-retirement-completion-v1");
    v["intent"] = json!(intent_ref.unwrap());
    v["target_absent"] = json!(true);
    v["unlinked_in_this_invocation"] = json!(present);
    v["retired_original_allocated_bytes"] = json!(
        q.target_identity
            .blocks
            .checked_mul(512)
            .context("allocation overflow")?
    );
    v["physical_credit_bytes"] = v["retired_original_allocated_bytes"].clone();
    v["credit_claim_id"] = json!(format!(
        "duplicate-index-{}-{}-{}",
        q.epoch, q.target_identity.dev, q.target_identity.ino
    ));
    v["credit_requires_main_reconciliation"] = json!(true);
    println!(
        "{}",
        serde_json::to_string(&write_new(&state.join("completion.json"), &v)?)?
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("duplicate-index-retire: {error:#}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    fn fixture() -> (tempfile::TempDir, Profile) {
        let t = tempfile::tempdir().unwrap();
        let parent = t.path().join("original");
        let keep = t.path().join("sealed");
        fs::create_dir(&parent).unwrap();
        fs::create_dir(&keep).unwrap();
        let target = parent.join("cid249.partial");
        let preserved = keep.join("cid.index");
        fs::write(&target, b"compiszd independent content").unwrap();
        fs::write(&preserved, b"compiszd independent content").unwrap();
        let mut q = profile(249).unwrap();
        q.target = target;
        q.preserved = preserved;
        q.target_identity = stamp(&fs::metadata(&q.target).unwrap());
        q.preserved_identity = stamp(&fs::metadata(&q.preserved).unwrap());
        q.sha256 = sha(b"compiszd independent content");
        q.header_hex = "636f6d7069737a64".into();
        q.target_parent_inode = fs::metadata(parent).unwrap().ino();
        (t, q)
    }
    fn booking() -> (Value, Bound) {
        let p = Bound {
            path: "/var/lib/jetstreamer/plan.json".into(),
            sha256: "a".repeat(64),
        };
        let b = json!({"schema":"horizon-duplicate-index-retirement-booking-v1","Main_accepted":true,"complete_fleet_funding_accepted":true,"epoch":249,"plan":p,"recorded_unix_seconds":100,"expires_unix_seconds":1900,"maximum_memory_bytes":536870912u64,"maximum_metadata_bytes":16777216u64,"maximum_wall_seconds":1800,"future_growth_credit_taken_bytes":0,"physical_credit_taken_bytes":0,"minimum_free_bytes":FLOOR,"fleet_evidence_sha256":"b".repeat(64)});
        (b, p)
    }
    #[test]
    fn closed_registry_rejects_unselected_epochs() {
        for e in [0, 205, 223, 247, 248, 251, 265, u64::MAX] {
            assert!(profile(e).is_err());
        }
        for e in [249, 250] {
            let p = profile(e).unwrap();
            assert_eq!(p.epoch, e);
            assert_ne!(p.target_identity.ino, p.preserved_identity.ino);
            assert_eq!(p.target_identity.len, p.preserved_identity.len);
            assert_eq!(decode_hex(&p.header_hex).unwrap()[..8], *b"compiszd");
        }
    }
    #[test]
    fn booking_rejects_time_floor_credit_and_memory_changes() {
        let (b, p) = booking();
        booking_valid(&b, &p, 249, 101).unwrap();
        for now in [0, 99, 1900, u64::MAX] {
            assert!(booking_valid(&b, &p, 249, now).is_err());
        }
        for (key, val) in [
            ("minimum_free_bytes", json!(FLOOR - 1)),
            ("physical_credit_taken_bytes", json!(1)),
            ("future_growth_credit_taken_bytes", json!(1)),
            ("maximum_memory_bytes", json!(536870913u64)),
            ("maximum_metadata_bytes", json!(16777217u64)),
            ("maximum_wall_seconds", json!(1801)),
            ("expires_unix_seconds", json!(1901)),
            ("complete_fleet_funding_accepted", json!(false)),
        ] {
            let mut altered = b.clone();
            altered[key] = val;
            assert!(booking_valid(&altered, &p, 249, 101).is_err(), "{key}");
        }
        assert!(booking_valid(&b, &p, 250, 101).is_err());
    }
    #[test]
    fn changed_receipt_plan_image_profile_cannot_authorize() {
        let (_, p) = booking();
        let q = profile(249).unwrap();
        let good = json!({"schema":"check","plan":p,"helper_sha256":"c".repeat(64),"profile":q});
        receipt_scope(&good, "check", &p, &"c".repeat(64), &q).unwrap();
        for key in ["schema", "plan", "helper_sha256", "profile"] {
            let mut altered = good.clone();
            altered[key] = Value::Null;
            assert!(receipt_scope(&altered, "check", &p, &"c".repeat(64), &q).is_err());
        }
    }
    #[test]
    fn inode_alias_matches_even_when_path_differs() {
        let (_t, q) = fixture();
        let alias = q.target.with_file_name("hardlink");
        fs::hard_link(&q.target, &alias).unwrap();
        assert!(inode_match(&fs::metadata(&alias).unwrap(), &q));
        assert_ne!(alias, q.target);
        assert_ne!(stamp(&fs::metadata(&q.target).unwrap()), q.target_identity);
        assert!(!inode_match(&fs::metadata(&q.preserved).unwrap(), &q));
    }
    #[test]
    fn symlink_is_not_regular_stamp() {
        let (_t, q) = fixture();
        let alias = q.target.with_file_name("symlink");
        symlink(&q.target, &alias).unwrap();
        assert!(!fs::symlink_metadata(alias).unwrap().is_file());
    }
    #[test]
    fn mount_aliases_and_direct_mounts_fail() {
        let q = profile(249).unwrap();
        let dev = format!(
            "{}:{}",
            libc::major(q.target_identity.dev),
            libc::minor(q.target_identity.dev)
        );
        let direct = format!("1 0 {dev} / {} rw - ext4 /dev/x rw\n", q.target.display());
        assert!(mount_check(&direct, &q.target, q.target_identity.dev).is_err());
        let alias = format!(
            "1 0 {dev} {} /hidden rw - ext4 /dev/x rw\n",
            q.target.parent().unwrap().display()
        );
        assert!(mount_check(&alias, &q.target, q.target_identity.dev).is_err());
        let ordinary = format!("1 0 {dev} / / rw - ext4 /dev/x rw\n");
        mount_check(&ordinary, &q.target, q.target_identity.dev).unwrap();
        assert!(mount_check("bad", &q.target, q.target_identity.dev).is_err());
        assert!(unescape("/bad\\777").is_err());
    }
    #[test]
    fn staged_parent_reference_and_foreign_own_alias_fail() {
        let t = tempfile::tempdir().unwrap();
        let own = t.path().join("own.service");
        let foreign = t.path().join("foreign.service");
        fs::write(&own, "ReadWritePaths=/private/cache\n").unwrap();
        fs::write(
            &foreign,
            "ExecStart=/runner --index=/private/cache/cid249.partial\n",
        )
        .unwrap();
        assert!(
            scan_staged(
                t.path(),
                b"/private/cache",
                &own,
                &mut BTreeSet::new(),
                &mut 0
            )
            .is_err()
        );
        fs::remove_file(&foreign).unwrap();
        scan_staged(
            t.path(),
            b"/private/cache",
            &own,
            &mut BTreeSet::new(),
            &mut 0,
        )
        .unwrap();
        symlink(&own, &foreign).unwrap();
        assert!(
            scan_staged(
                t.path(),
                b"/private/cache",
                &own,
                &mut BTreeSet::new(),
                &mut 0
            )
            .is_err()
        );
    }
    #[test]
    fn protected_native_replacement_is_rejected() {
        let old: BTreeMap<String, String> = [
            ("InvocationID".into(), "original".into()),
            ("MainPID".into(), "123".into()),
            ("ExecStart".into(), "sealed-image exact-plan".into()),
        ]
        .into();
        compare(&old, &old).unwrap();
        for key in ["InvocationID", "MainPID", "ExecStart"] {
            let mut new = old.clone();
            new.insert(key.into(), "replacement".into());
            assert!(compare(&new, &old).is_err());
        }
    }
    #[test]
    fn inode_maps_detect_hidden_alias() {
        let (t, q) = fixture();
        let maps = t.path().join("maps");
        let dev = format!(
            "{:x}:{:x}",
            libc::major(q.target_identity.dev),
            libc::minor(q.target_identity.dev)
        );
        fs::write(
            &maps,
            format!(
                "1000-2000 r--p 00000000 {dev} {} /unrelated-alias\n",
                q.target_identity.ino
            ),
        )
        .unwrap();
        assert!(maps_inodes(&maps, &q).is_err());
        fs::write(
            &maps,
            format!(
                "1000-2000 r--p 00000000 {dev} {} /preserved\n",
                q.preserved_identity.ino
            ),
        )
        .unwrap();
        maps_inodes(&maps, &q).unwrap();
    }
    #[test]
    fn relative_unlink_preserves_siblings_and_rejects_replaced_entry() {
        let (_t, q) = fixture();
        let sibling = q.target.with_file_name("hash.result.jsonl");
        fs::write(&sibling, b"custody").unwrap();
        let dir = File::open(q.target.parent().unwrap()).unwrap();
        let mut changed = q.target_identity.clone();
        changed.ino += 1;
        assert!(unlink_entry(&q.target, &changed, &dir).is_err());
        assert!(q.target.exists());
        unlink_entry(&q.target, &q.target_identity, &dir).unwrap();
        assert!(!q.target.exists());
        assert_eq!(fs::read(&sibling).unwrap(), b"custody");
        assert_eq!(
            stamp(&fs::metadata(&q.preserved).unwrap()),
            q.preserved_identity
        );
        assert!(unlink_entry(&q.target, &q.target_identity, &dir).is_err());
    }
    #[test]
    fn metadata_changes_invalidate_exact_stamp() {
        let (_t, q) = fixture();
        fs::set_permissions(&q.target, fs::Permissions::from_mode(0o400)).unwrap();
        assert_ne!(stamp(&fs::metadata(&q.target).unwrap()), q.target_identity);
        fs::remove_file(&q.target).unwrap();
        fs::write(&q.target, b"compiszd independent content").unwrap();
        assert_ne!(stamp(&fs::metadata(&q.target).unwrap()), q.target_identity);
    }
    #[test]
    fn full_hash_rejects_wrong_digest_header_length_and_guard_failure() {
        let data = b"compiszd independent content";
        hash_reader(
            &data[..],
            data.len() as u64,
            &sha(data),
            b"compiszd",
            || Ok(()),
        )
        .unwrap();
        assert!(
            hash_reader(
                &data[..],
                data.len() as u64,
                &"0".repeat(64),
                b"compiszd",
                || Ok(())
            )
            .is_err()
        );
        assert!(
            hash_reader(
                &data[..],
                data.len() as u64,
                &sha(data),
                b"compisze",
                || Ok(())
            )
            .is_err()
        );
        for len in [data.len() as u64 - 1, data.len() as u64 + 1] {
            assert!(hash_reader(&data[..], len, &sha(data), b"compiszd", || Ok(())).is_err());
        }
        struct Forever;
        impl Read for Forever {
            fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                b.fill(0);
                Ok(b.len())
            }
        }
        assert!(
            hash_reader(Forever, 1 << 30, &"0".repeat(64), b"", || bail!(
                "expired booking"
            ))
            .is_err()
        );
    }
    #[test]
    fn interrupted_unlink_recovery_requires_exact_intent_and_no_clobber_completion() {
        let (t, q) = fixture();
        let (_, plan) = booking();
        let state = t.path().join("state");
        fs::create_dir(&state).unwrap();
        let check = write_new(&state.join("check.json"), &json!({"qualification":true})).unwrap();
        let image = "c".repeat(64);
        assert!(intent_scope(&Value::Null, &plan, &image, &q, &state, &check.sha256).is_err());
        let value = json!({"schema":"horizon-duplicate-index-retirement-intent-v1","plan":plan,"helper_sha256":image,"profile":q,"check":check,"physical_credit_bytes":0});
        write_new(&state.join("intent.json"), &value).unwrap();
        intent_scope(&value, &plan, &image, &q, &state, &check.sha256).unwrap();
        let dir = File::open(q.target.parent().unwrap()).unwrap();
        // Durable intent exists while the original remains; interrupted-before-unlink retry.
        assert!(q.target.exists());
        unlink_entry(&q.target, &q.target_identity, &dir).unwrap();
        // Interrupted-after-unlink recovery reuses that same intent; wrong check fails.
        intent_scope(&value, &plan, &image, &q, &state, &check.sha256).unwrap();
        assert!(intent_scope(&value, &plan, &image, &q, &state, &"d".repeat(64)).is_err());
        let complete = json!({"intent_sha256":sha(&serde_json::to_vec_pretty(&value).unwrap()),"target_absent":true});
        write_new(&state.join("completion.json"), &complete).unwrap();
        assert!(write_new(&state.join("completion.json"), &complete).is_err());
        assert!(write_new(&state.join("intent.json"), &value).is_err());
        assert_eq!(
            fs::read(&q.preserved).unwrap(),
            b"compiszd independent content"
        );
    }
    #[test]
    fn plan_rejects_substitution_and_same_inode() {
        let q = profile(249).unwrap();
        let review:Review=serde_json::from_value(json!({
            "schema":"horizon-duplicate-index-retirement-review-v1","epoch":249,"target":q.target,"preserved":q.preserved,
            "main_accepted":true,"source_acquisition_and_seal_actors_closed":true,"transitive_scripts_plans_and_user_units_reviewed":true,"staged_original_cache_consumers_absent":true,
            "evidence":[{"path":"/var/lib/jetstreamer/closure.json","sha256":"a".repeat(64)}],
            "protected250":{"Id":PROTECTED,"ActiveState":"active","SubState":"running","MainPID":"123","InvocationID":"f".repeat(32),"ControlGroup":"/system.slice/protected","ExecStart":"pinned","FragmentPath":"pinned","DropInPaths":"","NRestarts":"0","LoadState":"loaded"},
            "closed_units":[{"unit":"closed.service","properties":{"Id":"closed.service","ActiveState":"inactive","SubState":"dead","MainPID":"0","ControlPID":"0","Job":"","InvocationID":"old","ExecStart":"old","FragmentPath":"old","DropInPaths":"","LoadState":"loaded","TriggeredBy":""}}]
        })).unwrap();
        let mut plan = Plan {
            schema: "horizon-duplicate-index-retirement-plan-v1".into(),
            epoch: 249,
            target: q.target.clone(),
            preserved: q.preserved.clone(),
            main_review: Bound {
                path: "/var/lib/jetstreamer/review.json".into(),
                sha256: "e".repeat(64),
            },
            exclusive_campaign_mutation_owner: true,
        };
        validate_plan(&plan, &review, &q).unwrap();
        plan.target = q.preserved.clone();
        assert!(validate_plan(&plan, &review, &q).is_err());
        plan.target = q.target.clone();
        plan.preserved = q.target.clone();
        assert!(validate_plan(&plan, &review, &q).is_err());
        plan.preserved = q.preserved.clone();
        let mut changed = q.clone();
        changed.preserved_identity.ino = q.target_identity.ino;
        assert!(validate_plan(&plan, &review, &changed).is_err());
        changed = q.clone();
        changed.target_identity.nlink = 2;
        assert!(validate_plan(&plan, &review, &changed).is_err());
    }
    #[test]
    fn genuine_seal_checksum_lists_include_exact_receipt_entry() {
        for (epoch, raw) in [
            (
                249,
                include_bytes!("fixtures/actual-249-SHA256SUMS").as_slice(),
            ),
            (
                250,
                include_bytes!("fixtures/actual-250-SHA256SUMS").as_slice(),
            ),
        ] {
            let q = profile(epoch).unwrap();
            assert_eq!(sha(raw), q.sums_sha256);
            validate_sums(raw, &q).unwrap();
            let text = std::str::from_utf8(raw).unwrap();
            let absent = text.lines().skip(1).collect::<Vec<_>>().join("\n");
            assert!(validate_sums(absent.as_bytes(), &q).is_err());
            let duplicate = format!("{}{}\n", text, text.lines().next().unwrap());
            assert!(validate_sums(duplicate.as_bytes(), &q).is_err());
            let mut changed = q.clone();
            changed.seal_sha256 = "0".repeat(64);
            assert!(validate_sums(raw, &changed).is_err());
            let extra = format!("{}{sha}  foreign.index\n", text, sha = "e".repeat(64));
            assert!(validate_sums(extra.as_bytes(), &q).is_err());
        }
    }
}
