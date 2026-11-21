//! Exact retirement of closed epoch223 duplicate CID indexes.
//! Retains a full independently verified copy and every partial archive.
//! Closed profile registry; no recursive removal, service mutation or R2 routes.
mod closed_owners;
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
const IMAGE: &str = "/var/lib/jetstreamer/horizon223-duplicate-index-retirer-20261121-v5/epoch223-duplicate-index-retire";
const LOCK: &str = "/home/ubuntu/.jetstreamer-private/r2-receipts/local-mutation.lock";
const SURVEY_SEAL_SHA: &str = "5bf563acabd1702013328ded7d219f90f34a7a20bbe6a076b8edab47c73c589d";
const SURVEY_SUMS_SHA: &str = "9367b3f35f60cf92b60b0ec92bd892eb7f3407ea3fc5ce22b18c6d407634046a";
const PROTECTED: [(&str, &str); 4] = [
    (
        "horizon-singleton-211-capped-4aeca563-v1.service",
        "49ea83a3a5e94e99af51153d2fd79e92",
    ),
    (
        "horizon-qualify-251-replacement-20261118-v1.service",
        "cd2477bfec7f4e498545762c633e7bb0",
    ),
    (
        "horizon-qualify-265-replacement-20261119-v3.service",
        "182de64d33674f95b7758d410eb1812b",
    ),
    (
        "horizon-upload-247-staged-680e1173-v1.service",
        "3e08307874db424886cd8c46b3ecfba6",
    ),
];
const CLOSED: [&str; 12] = [
    "archive-223-tail-reread-1743245a-v3.service",
    "horizon-qualify-223-v1625-tail-1743245a-v3.service",
    "horizon-qualify-223-singleton-postcount-ad1d65a-v1.service",
    "horizon-qualify-223-v1620-warmup-resource-d15ee08b-v1.service",
    "horizon-import-233-committed-v2.service",
    "horizon-import-233-common-mount-probe-v2.service",
    "horizon-import-239-current-20261117-v2.service",
    "horizon-import-239-current-20261117-v3.service",
    "horizon-import-239-namespace-probe-20261117-v2.service",
    "horizon-import-239-namespace-probe-20261117-v3.service",
    "horizon-import-244-current-20261117-v1.service",
    "horizon-import-244-namespace-probe-20261117-v1.service",
];
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
    selection: String,
    epoch: u64,
    target: PathBuf,
    preserved: PathBuf,
    attempt_root: PathBuf,
    preserved_root: PathBuf,
    target_parent_inode: u64,
    target_parent_mode: u32,
    target_identity: Stamp,
    preserved_identity: Stamp,
    sha256: String,
    header_hex: String,
    owner_receipt: OriginalEvidence,
    owner_unit: String,
    owner_invocation: String,
    owner_success: bool,
    owner_child_return_code: i64,
    owner_plan: Bound,
    preserved_owner_receipt: OriginalEvidence,
    preserved_owner_unit: String,
    preserved_owner_invocation: String,
    preserved_owner_plan: Bound,
    protected_archives: Vec<ProtectedFile>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ProtectedFile {
    path: PathBuf,
    identity: Stamp,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OriginalEvidence {
    path: PathBuf,
    sha256: String,
    identity: Stamp,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    selection: String,
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
    selection: String,
    epoch: u64,
    target: PathBuf,
    preserved: PathBuf,
    main_accepted: bool,
    source_acquisition_and_seal_actors_closed: bool,
    transitive_scripts_plans_and_user_units_reviewed: bool,
    staged_original_cache_consumers_absent: bool,
    evidence: Vec<Bound>,
    protected_owners: BTreeMap<String, BTreeMap<String, String>>,
    closed_units: Vec<ClosedUnit>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClosedUnit {
    unit: String,
    properties: BTreeMap<String, String>,
}
fn profile(selection: &str) -> Result<Profile> {
    let all: Vec<Profile> = serde_json::from_str(include_str!("profiles.json"))?;
    let extra: Vec<Profile> = serde_json::from_str(include_str!("new-profiles.json"))?;
    all.into_iter()
        .chain(extra)
        .find(|p| p.selection == selection)
        .context("unregistered epoch")
}
fn validate_plan(p: &Plan, r: &Review, q: &Profile) -> Result<()> {
    ensure!(
        p.schema == "horizon223-duplicate-index-retirement-plan-v1"
            && p.epoch == 223
            && p.epoch == q.epoch
            && p.selection == q.selection
            && p.target == q.target
            && p.preserved == q.preserved
            && p.exclusive_campaign_mutation_owner,
        "plan scope"
    );
    ensure!(
        r.schema == "horizon223-duplicate-index-retirement-review-v1"
            && r.epoch == q.epoch
            && r.selection == q.selection
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
        r.protected_owners.len() == PROTECTED.len(),
        "incomplete accepted live roster"
    );
    for (name, iid) in PROTECTED {
        let row = r
            .protected_owners
            .get(name)
            .context("missing protected owner")?;
        ensure!(
            row.get("Id").map(String::as_str) == Some(name)
                && row.get("InvocationID").map(String::as_str) == Some(iid)
                && row.get("ActiveState").map(String::as_str) == Some("active")
                && row.get("SubState").map(String::as_str) == Some("running")
                && row.get("NRestarts").map(String::as_str) == Some("0")
                && row.get("MainPID").context("PID")?.parse::<u32>()? > 0
                && [
                    "ExecStart",
                    "MemoryMax",
                    "ControlGroup",
                    "DropInPaths",
                    "FragmentPath"
                ]
                .iter()
                .all(|k| row.contains_key(*k)),
            "protected owner identity"
        );
    }
    let mut units = BTreeSet::new();
    for u in &r.closed_units {
        ensure!(
            u.unit.ends_with(".service")
                && !u.unit.contains('/')
                && units.insert(&u.unit)
                && !PROTECTED.iter().any(|(n, _)| *n == u.unit),
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
    for name in CLOSED {
        let row = r
            .closed_units
            .iter()
            .find(|u| u.unit == name)
            .context("missing original/import reader")?;
        ensure!(
            row.properties.get("LoadState").map(String::as_str) == Some("masked")
                && row
                    .properties
                    .get("ExecStart")
                    .is_some_and(String::is_empty),
            "reader still launchable"
        );
    }
    for required in [&q.owner_unit, &q.preserved_owner_unit] {
        ensure!(
            r.closed_units.iter().any(|u| &u.unit == required),
            "missing exact original owner closure {required}"
        );
    }
    ensure!(
        !q.protected_archives.is_empty()
            && q.protected_archives
                .iter()
                .all(|a| a.path != q.target && a.path != q.preserved),
        "protected archive scope"
    );
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
            && m.mode() == q.target_parent_mode,
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
fn original(e: &OriginalEvidence) -> Result<Value> {
    exact(&e.path, &e.identity)?;
    let raw = read_bounded(&e.path, LIMIT)?;
    ensure!(sha(&raw) == e.sha256, "original receipt hash changed");
    exact(&e.path, &e.identity)?;
    Ok(serde_json::from_slice(&raw)?)
}
fn original_owner(q: &Profile, retained: bool) -> Result<Value> {
    if !retained
        && matches!(
            q.selection.as_str(),
            "tail-1743245a-v3" | "singleton-223-postcount"
        )
    {
        return closed_owners::owner(q);
    }
    let (e, unit, iid, plan) = if retained {
        (
            &q.preserved_owner_receipt,
            &q.preserved_owner_unit,
            &q.preserved_owner_invocation,
            &q.preserved_owner_plan,
        )
    } else {
        (
            &q.owner_receipt,
            &q.owner_unit,
            &q.owner_invocation,
            &q.owner_plan,
        )
    };
    let v = original(e)?;
    ensure!(
        v["epoch"] == 223
            && v["unit"] == *unit
            && v["invocation_id"] == *iid
            && v["plan"] == json!(plan)
            && v["external_signal"] == 0,
        "original owner association"
    );
    ensure!(
        v["success"]
            == if retained {
                json!(false)
            } else {
                json!(q.owner_success)
            }
            && v["child_return_code"]
                == if retained {
                    json!(130)
                } else {
                    json!(q.owner_child_return_code)
                },
        "original outcome cannot be promoted"
    );
    for field in [
        "publication_authorized",
        "ordinary_replay_authorized",
        "r2_mutations",
        "remote_mutations",
    ] {
        ensure!(
            v["authority"][field] == false,
            "unexpected original authority"
        );
    }
    let p = bound(plan)?;
    ensure!(
        p["run_root"]
            == if retained {
                json!(q.preserved_root)
            } else {
                json!(q.attempt_root)
            }
            && p["unit"] == *unit,
        "original plan root/unit binding"
    );
    Ok(
        json!({"receipt":e,"original_success":v["success"],"original_child_return_code":v["child_return_code"],"unit":unit,"invocation_id":iid,"plan":plan}),
    )
}
fn archive_protection(q: &Profile) -> Result<Value> {
    closed_owners::archive_custody()?;
    for item in &q.protected_archives {
        exact(&item.path, &item.identity)?;
    }
    Ok(json!(q.protected_archives))
}
fn survey(q: &Profile) -> Result<Value> {
    let root = Path::new("/var/lib/jetstreamer/horizon223-index-duplicate-survey-20261120-v1");
    let seal = bound(&Bound {
        path: root.join("deployment-seal-receipt.json"),
        sha256: SURVEY_SEAL_SHA.into(),
    })?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == root.to_string_lossy().as_ref(),
        "survey genuine seal"
    );
    let mut expected = BTreeMap::from([(
        "deployment-seal-receipt.json".to_string(),
        SURVEY_SEAL_SHA.to_string(),
    )]);
    for member in seal["members"].as_array().context("survey members")? {
        let name = member["name"].as_str().context("survey member name")?;
        ensure!(
            !name.contains('/')
                && expected
                    .insert(
                        name.into(),
                        member["sha256"]
                            .as_str()
                            .context("survey member SHA")?
                            .into()
                    )
                    .is_none(),
            "survey member scope"
        );
        file_bytes(
            &root.join(name),
            member["sha256"].as_str().unwrap(),
            0,
            None,
            true,
        )?;
    }
    let sums = file_bytes(&root.join("SHA256SUMS"), SURVEY_SUMS_SHA, 0, None, true)?;
    let mut actual = BTreeMap::new();
    for line in std::str::from_utf8(&sums)?.lines() {
        let (sum, name) = line.split_once("  ").context("survey sums")?;
        ensure!(
            actual.insert(name.to_string(), sum.to_string()).is_none(),
            "duplicate survey sum"
        );
    }
    ensure!(actual == expected, "survey sums set");
    let summary: Value = serde_json::from_slice(&file_bytes(
        &root.join("summary.json"),
        "432adb16dd495bbae625935955c1fb15d308ebde4e151307730178044e824f7f",
        0,
        None,
        true,
    )?)?;
    ensure!(
        summary["epoch"] == 223
            && summary["body_sha256"] == q.sha256
            && summary["bytes_per_body"] == q.target_identity.len
            && summary["distinct_inodes"] == 8
            && summary["reclamation_credit"] == 0,
        "survey scope"
    );
    let ids: Value = serde_json::from_slice(&file_bytes(
        &root.join("file-identities-before.json"),
        "fb9ca5ad789d8a493baa1527af5cb76cd239958aa781e6e2f96e14bb7317367a",
        0,
        None,
        true,
    )?)?;
    for (path, identity) in [
        (&q.target, &q.target_identity),
        (&q.preserved, &q.preserved_identity),
    ] {
        let rows: Vec<_> = ids
            .as_array()
            .context("survey identity list")?
            .iter()
            .filter(|v| v["path"] == path.to_string_lossy().as_ref())
            .collect();
        ensure!(rows.len() == 1, "survey selection missing/duplicate");
        let row = rows[0];
        ensure!(
            row["device"] == identity.dev
                && row["inode"] == identity.ino
                && row["bytes"] == identity.len
                && row["uid"] == identity.uid
                && row["gid"] == identity.gid
                && row["mode"] == identity.mode
                && row["nlink"] == 1
                && row["allocation"] == identity.blocks * 512
                && row["mtime_ns"].as_i64()
                    == Some(identity.mtime * 1_000_000_000 + identity.mtime_ns)
                && row["ctime_ns"].as_i64()
                    == Some(identity.ctime * 1_000_000_000 + identity.ctime_ns),
            "survey immutable identity differs"
        );
    }
    Ok(json!({"seal_sha256":SURVEY_SEAL_SHA,"summary":summary}))
}
fn package(q: &Profile, tick: impl Fn() -> Result<()>) -> Result<Value> {
    let original = original_owner(q, false)?;
    let retained = original_owner(q, true)?;
    let historical = survey(q)?;
    hash_file(
        &q.preserved,
        &q.preserved_identity,
        &q.sha256,
        &decode_hex(&q.header_hex)?,
        &tick,
    )?;
    Ok(
        json!({"original_owner":original,"retained_owner":retained,"survey":historical,"retained_whole_body_rehashed":true,"protected_archives":archive_protection(q)?}),
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
        b["schema"] == "horizon223-duplicate-index-retirement-booking-v1"
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
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for line in std::str::from_utf8(&raw)?.lines() {
        let (k, v) = line.split_once('=').context("manager framing")?;
        ensure!(
            out.insert(k.into(), v.into()).is_none(),
            "duplicate manager property"
        );
    }
    if out
        .get("LoadState")
        .is_some_and(|state| matches!(state.as_str(), "masked" | "not-found"))
        && !out.contains_key("ExecStart")
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
    let mut live = BTreeMap::new();
    for (name, _) in PROTECTED {
        let actual = show(name)?;
        compare(&actual, &r.protected_owners[name])?;
        live.insert(name, actual);
    }
    let mut closed = BTreeMap::new();
    for unit in &r.closed_units {
        let m = show(&unit.unit)?;
        compare(&m, &unit.properties)?;
        ensure!(
            !Path::new("/sys/fs/cgroup/system.slice")
                .join(&unit.unit)
                .exists(),
            "closed reader cgroup"
        );
        if CLOSED.contains(&unit.unit.as_str()) {
            verify_empty_commands(
                &unit.unit,
                &[
                    "ExecStart",
                    "ExecStartPre",
                    "ExecStartPost",
                    "ExecStop",
                    "ExecStopPost",
                ],
            )?;
        }
        closed.insert(unit.unit.clone(), m);
    }
    Ok(json!({"protected_owners":live,"closed":closed}))
}
fn controller(mode: &str, q: &Profile, b: &Value, args: &[String]) -> Result<(String, PathBuf)> {
    let unit = format!(
        "horizon223-duplicate-index-{}-retirement-{mode}-20261120-v1.service",
        q.selection
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
    let target_parent = &q.attempt_root;
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
        "/home/ubuntu/.jetstreamer-private/systemd-staging",
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
    let needle = q.attempt_root.as_os_str().as_bytes();
    for root in &roots {
        scan_staged(root, needle, own, &mut visited, &mut bytes)?;
    }
    Ok(
        json!({"roots":roots,"inspected_entries":visited.len(),"inspected_bytes":bytes,"only_exempt_fragment":own}),
    )
}
fn retained_scope(q: &Profile) -> Result<Profile> {
    let mut p = q.clone();
    p.target = q.preserved.clone();
    p.target_identity = q.preserved_identity.clone();
    p.target_parent_inode = fs::metadata(q.preserved.parent().context("retained parent")?)?.ino();
    p.attempt_root = q.preserved_root.clone();
    Ok(p)
}
fn all_process_closure(q: &Profile) -> Result<Value> {
    Ok(json!({"original":process_closure(q)?,"retained":process_closure(&retained_scope(q)?)?}))
}
fn all_staged_closure(q: &Profile, own: &Path) -> Result<Value> {
    let reader = Path::new(IMAGE).with_file_name("readers.py");
    file_bytes(&reader, &sha(include_bytes!("readers.py")), 0, None, true)?;
    let output = Command::new("/usr/bin/timeout")
        .args(["45", "/usr/bin/python3", "-I", "-B"])
        .arg(reader)
        .arg("--verify-closed")
        .arg(own)
        .output()?;
    ensure!(
        output.status.success() && output.stdout.len() < 65536,
        "current staged/indirect reader closure failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let indirect: Value = serde_json::from_slice(&output.stdout)?;
    ensure!(
        indirect["all_readers_closed"] == true,
        "reader closure missing"
    );
    Ok(
        json!({"original":staged_closure(q,own)?,"retained":staged_closure(&retained_scope(q)?,own)?,"indirect":indirect}),
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
        "horizon223-duplicate-index-retirement-intent-v1",
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
    ensure!(
        matches!(
            p.selection.as_str(),
            "tail-1743245a-v3" | "singleton-223-postcount"
        ),
        "only the two newly closed original profiles are supported in v4"
    );
    let q = profile(&p.selection)?;
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
        "/var/lib/jetstreamer/horizon223-duplicate-index-{}-retirement-20261120-v1",
        q.selection
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
            "horizon223-duplicate-index-retirement-check-v1",
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
            "horizon223-duplicate-index-retirement-completion-v1",
            &plan_ref,
            &a[4],
            &q,
        )?;
        ensure!(c["target_absent"] == true, "invalid completion");
    }
    let before = manager_closure(&review)?;
    let keep = siblings(&q)?;
    let archive_baseline = archive_protection(&q)?;
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
    let processes = all_process_closure(&q)?;
    let staged = all_staged_closure(&q, &own)?;
    ensure!(
        manager_closure(&review)? == before
            && siblings(&q)? == keep
            && read_bounded(&own, 1 << 20)? == own_raw
            && archive_protection(&q)? == archive_baseline,
        "scope changed during qualification"
    );
    controller(mode, &q, &booking, &a)?;
    tick()?;
    let base = json!({"recorded_unix_seconds":wall()?,"plan":plan_ref,"helper_sha256":a[4],"profile":q,"booking":booking_ref,"manager":before,"siblings":keep,"package":preserved,"all_partial_archives_preserved":archive_baseline,"process_closure":processes,"staged_closure":staged,"own_fragment_sha256":sha(&own_raw),"physical_credit_bytes":0,"remote_mutations":false,"r2_mutations":false,"replay_launch_authorized":false});
    if mode == "check" {
        let mut v = base;
        v["schema"] = json!("horizon223-duplicate-index-retirement-check-v1");
        v["retirement_performed"] = json!(false);
        println!(
            "{}",
            serde_json::to_string(&write_new(&state.join("check.json"), &v)?)?
        );
        return Ok(());
    }
    if mode == "attest" {
        let mut v = base;
        v["schema"] = json!("horizon223-duplicate-index-retirement-attestation-v1");
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
        v["schema"] = json!("horizon223-duplicate-index-retirement-intent-v1");
        v["check"] = json!(Bound {
            path: state.join("check.json"),
            sha256: a[7].clone()
        });
        intent_ref = Some(write_new(&state.join("intent.json"), &v)?);
    }
    // Rescan after the durable intent and immediately before the one unlink.
    all_process_closure(&q)?;
    all_staged_closure(&q, &own)?;
    ensure!(
        manager_closure(&review)? == before
            && siblings(&q)? == keep
            && archive_protection(&q)? == archive_baseline,
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
        siblings(&q)? == keep
            && manager_closure(&review)? == before
            && archive_protection(&q)? == archive_baseline,
        "scope changed after unlink"
    );
    tick()?;
    let mut v = base;
    v["schema"] = json!("horizon223-duplicate-index-retirement-completion-v1");
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
    use std::os::unix::fs::symlink;
    fn q() -> Profile {
        profile("8457f800-v2").unwrap()
    }
    fn bound_plan() -> Bound {
        Bound {
            path: "/var/lib/jetstreamer/p.json".into(),
            sha256: "a".repeat(64),
        }
    }
    fn fixture() -> (tempfile::TempDir, Profile) {
        let t = tempfile::tempdir().unwrap();
        let mut p = q();
        p.target = t.path().join("original.index");
        p.preserved = t.path().join("retained.index");
        fs::write(&p.target, b"compiszd preserved bytes").unwrap();
        fs::write(&p.preserved, b"compiszd preserved bytes").unwrap();
        p.target_identity = stamp(&fs::metadata(&p.target).unwrap());
        p.preserved_identity = stamp(&fs::metadata(&p.preserved).unwrap());
        p.sha256 = sha(b"compiszd preserved bytes");
        (t, p)
    }
    #[test]
    fn exact_profile_registry_and_archive_protection() {
        let mut inodes = BTreeSet::new();
        let mut sum = 0;
        for key in ["8457f800-v2", "0f7f1b6e-v1", "5072b7ba-v4", "full-root-v1"] {
            let p = profile(key).unwrap();
            assert_eq!(p.epoch, 223);
            assert!(inodes.insert(p.target_identity.ino));
            assert_ne!(p.target_identity.ino, p.preserved_identity.ino);
            assert_eq!(p.protected_archives.len(), 8);
            assert!(
                p.protected_archives
                    .iter()
                    .all(|a| a.path != p.target && a.path != p.preserved)
            );
            assert_eq!(p.target_identity.len, 9_709_637_370);
            sum += p.target_identity.blocks * 512;
        }
        assert_eq!(sum, 38_838_599_680);
        let full_root = profile("full-root-v1").unwrap();
        assert!(!full_root.owner_success);
        assert_eq!(full_root.owner_child_return_code, 1);
        assert_eq!(
            full_root.owner_invocation,
            "e70aaf097e7c4583b216aba454145910"
        );
        for bad in [
            "223",
            "249",
            "d15ee08b-v1",
            "8457f800-v1",
            "../../archive",
            "all",
        ] {
            assert!(profile(bad).is_err());
        }
    }
    #[test]
    fn historical_failure_is_not_success() {
        let a = profile("0f7f1b6e-v1").unwrap();
        let b = profile("5072b7ba-v4").unwrap();
        assert!(!a.owner_success);
        assert!(!b.owner_success);
        assert_eq!(a.owner_child_return_code, 1);
        assert_eq!(b.owner_child_return_code, 1);
        let c = q();
        assert!(c.owner_success);
        assert_eq!(c.owner_child_return_code, 1);
        assert_eq!(c.owner_invocation, "58ab3d9221a6452685b8eab3ceabdb49");
    }
    #[test]
    fn full_body_hash_header_length_and_io_failure() {
        let data = b"compiszd preserved bytes";
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
                b"wronghdr",
                || Ok(())
            )
            .is_err()
        );
        assert!(
            hash_reader(
                &data[..],
                data.len() as u64 + 1,
                &sha(data),
                b"compiszd",
                || Ok(())
            )
            .is_err()
        );
        struct Denied;
        impl Read for Denied {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::PermissionDenied.into())
            }
        }
        assert!(hash_reader(Denied, 100, &"0".repeat(64), b"", || Ok(())).is_err());
    }
    #[test]
    fn relative_unlink_rejects_replacement_and_preserves_every_other_file() {
        let (t, p) = fixture();
        let partial = t.path().join("epoch-223.jet");
        let slot = t.path().join("slot.index");
        fs::write(&partial, b"partial archive must survive").unwrap();
        fs::write(&slot, b"sibling").unwrap();
        let before = stamp(&fs::metadata(&partial).unwrap());
        let dir = File::open(t.path()).unwrap();
        let mut changed = p.target_identity.clone();
        changed.ino += 1;
        assert!(unlink_entry(&p.target, &changed, &dir).is_err());
        assert!(p.target.exists());
        unlink_entry(&p.target, &p.target_identity, &dir).unwrap();
        assert!(!p.target.exists());
        assert_eq!(stamp(&fs::metadata(&partial).unwrap()), before);
        assert_eq!(fs::read(&slot).unwrap(), b"sibling");
        assert_eq!(
            stamp(&fs::metadata(&p.preserved).unwrap()),
            p.preserved_identity
        );
        assert!(unlink_entry(&p.target, &p.target_identity, &dir).is_err());
    }
    #[test]
    fn hardlink_symlink_and_maps_alias_are_rejected() {
        let (t, p) = fixture();
        let alias = t.path().join("alias");
        fs::hard_link(&p.target, &alias).unwrap();
        assert!(inode_match(&fs::metadata(&alias).unwrap(), &p));
        assert_ne!(stamp(&fs::metadata(&p.target).unwrap()), p.target_identity);
        let link = t.path().join("symlink");
        symlink(&p.target, &link).unwrap();
        assert!(!fs::symlink_metadata(link).unwrap().is_file());
        let maps = t.path().join("maps");
        fs::write(
            &maps,
            format!(
                "1000-2000 r--p 0000 {:x}:{:x} {} /hidden\n",
                libc::major(p.target_identity.dev),
                libc::minor(p.target_identity.dev),
                p.target_identity.ino
            ),
        )
        .unwrap();
        assert!(maps_inodes(&maps, &p).is_err());
    }
    #[test]
    fn staged_readonly_parent_is_not_silently_exempt() {
        let t = tempfile::tempdir().unwrap();
        let own = t.path().join("own.service");
        fs::write(&own, "ReadWritePaths=/selected\n").unwrap();
        let other = t.path().join("other.service");
        fs::write(&other, "ReadOnlyPaths=/selected\nExecStart=/importer 239\n").unwrap();
        assert!(scan_staged(t.path(), b"/selected", &own, &mut BTreeSet::new(), &mut 0).is_err());
        fs::remove_file(&other).unwrap();
        scan_staged(t.path(), b"/selected", &own, &mut BTreeSet::new(), &mut 0).unwrap();
        symlink(&own, &other).unwrap();
        assert!(scan_staged(t.path(), b"/selected", &own, &mut BTreeSet::new(), &mut 0).is_err());
    }
    #[test]
    fn mount_alias_fails() {
        let p = q();
        let dev = format!(
            "{}:{}",
            libc::major(p.target_identity.dev),
            libc::minor(p.target_identity.dev)
        );
        let alias = format!(
            "1 0 {dev} {} /alias rw - ext4 /dev/x rw\n",
            p.attempt_root.display()
        );
        assert!(mount_check(&alias, &p.target, p.target_identity.dev).is_err());
        mount_check(
            &format!("1 0 {dev} / / rw - ext4 /dev/x rw\n"),
            &p.target,
            p.target_identity.dev,
        )
        .unwrap();
    }
    #[test]
    fn booking_keeps_live265_floor_and_zero_prospective_credit() {
        let p = bound_plan();
        let b = json!({"schema":"horizon223-duplicate-index-retirement-booking-v1","Main_accepted":true,"complete_fleet_funding_accepted":true,"epoch":223,"plan":p,"recorded_unix_seconds":100,"expires_unix_seconds":1900,"maximum_memory_bytes":536870912u64,"maximum_metadata_bytes":16777216u64,"maximum_wall_seconds":1800,"future_growth_credit_taken_bytes":0,"physical_credit_taken_bytes":0,"minimum_free_bytes":FLOOR,"fleet_evidence_sha256":"b".repeat(64)});
        booking_valid(&b, &p, 223, 101).unwrap();
        for (k, v) in [
            ("minimum_free_bytes", json!(FLOOR - 1)),
            ("physical_credit_taken_bytes", json!(1)),
            ("maximum_memory_bytes", json!(536870913u64)),
            ("expires_unix_seconds", json!(1901)),
        ] {
            let mut changed = b.clone();
            changed[k] = v;
            assert!(booking_valid(&changed, &p, 223, 101).is_err());
        }
        for now in [99, 1900] {
            assert!(booking_valid(&b, &p, 223, now).is_err());
        }
    }
    #[test]
    fn interrupted_unlink_requires_bound_intent_and_completion_is_once() {
        let (t, q) = fixture();
        let plan = bound_plan();
        let state = t.path().join("state");
        fs::create_dir(&state).unwrap();
        let check = write_new(&state.join("check.json"), &json!({"qualified":true})).unwrap();
        let image = "c".repeat(64);
        assert!(intent_scope(&Value::Null, &plan, &image, &q, &state, &check.sha256).is_err());
        let intent = json!({"schema":"horizon223-duplicate-index-retirement-intent-v1","plan":plan,"helper_sha256":image,"profile":q,"check":check,"physical_credit_bytes":0});
        write_new(&state.join("intent.json"), &intent).unwrap();
        intent_scope(&intent, &plan, &image, &q, &state, &check.sha256).unwrap();
        assert!(q.target.exists());
        unlink_entry(
            &q.target,
            &q.target_identity,
            &File::open(t.path()).unwrap(),
        )
        .unwrap();
        intent_scope(&intent, &plan, &image, &q, &state, &check.sha256).unwrap();
        assert!(intent_scope(&intent, &plan, &image, &q, &state, &"d".repeat(64)).is_err());
        let done = json!({"target_absent":true});
        write_new(&state.join("completion.json"), &done).unwrap();
        assert!(write_new(&state.join("completion.json"), &done).is_err());
        assert_eq!(
            stamp(&fs::metadata(&q.preserved).unwrap()),
            q.preserved_identity
        );
    }
    #[test]
    fn real_survey_pins_and_original_plan_bindings_are_not_synthetic() {
        let survey: Value =
            serde_json::from_str(include_str!("fixtures/survey-summary.json")).unwrap();
        let ids: Value =
            serde_json::from_str(include_str!("fixtures/survey-file-identities-before.json"))
                .unwrap();
        for key in ["8457f800-v2", "0f7f1b6e-v1", "5072b7ba-v4", "full-root-v1"] {
            let q = profile(key).unwrap();
            assert_eq!(survey["body_sha256"], q.sha256);
            assert_eq!(survey["bytes_per_body"], q.target_identity.len);
            let row = ids
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["path"] == q.target.to_string_lossy().as_ref())
                .unwrap();
            assert_eq!(row["inode"], q.target_identity.ino);
            assert_eq!(row["allocation"], q.target_identity.blocks * 512);
            assert_eq!(q.owner_plan.sha256.len(), 64);
        }
    }
}
