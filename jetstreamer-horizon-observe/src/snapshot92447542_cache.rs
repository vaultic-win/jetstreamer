//! Finite lifecycle for the generation-pinned slot 92447542 compressed cache.
//!
//! This tool cannot select another artifact, start replay, or mutate cloud data.
//! Check/evict require an independent, root-sealed consumer/readset disposition
//! and restore qualification. Restore requires a separate fresh capacity booking.
//! New receipt schemas below are requirements for future qualification, not
//! assertions that a deployed helper, source review or native probe has passed.
use {
    crate::{
        bootstrap227_cache_retire::{absent, lock, persist, private_dir},
        dev_cache_check, process_references,
        ram_artifact_retention::{self as evidence, Bound},
    },
    anyhow::{Context, Result, bail, ensure},
    base64::{Engine, engine::general_purpose::STANDARD},
    md5::Md5,
    serde::{Deserialize, Serialize},
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    std::{
        collections::{BTreeMap, BTreeSet},
        env,
        ffi::CString,
        fs::{self, File, OpenOptions},
        io::{BufRead, BufReader, Read},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{
                ffi::OsStrExt,
                fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
                process::CommandExt,
            },
        },
        path::{Path, PathBuf},
        process::{Child, Command, ExitStatus, Stdio},
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    },
};

const SLOT: u64 = 92_447_542;
const NAME: &str = "snapshot-92447542-4gX8J8Y3c36L6W4D38ax2RYShfKmYxHWuDHAkQKeNzqd.tar.zst";
const CACHE_ROOT: &str = "/home/ubuntu/.jetstreamer-private/qualification-later-snapshots";
const STATE: &str = "/home/ubuntu/.jetstreamer-private/cache-retirements";
const HISTORICAL: &str = "bootstrap-92447542-restore-receipt.json";
const HISTORICAL_SHA: &str = "6eea2e296dd26800e6deda86e1f0c93273638dc42f07a4c1f14a8b725f67dc16";
const ACQUISITION_UNIT: &str = "horizon-restore-later-bootstrap-92447542.service";
const ACQUISITION_FRAGMENT_SHA: &str =
    "48d7e6246b954a59be4418d1dec7d40e4432f3ef05f56da1a3b190c2ce4b3c0a";
const BUCKET: &str = "mainnet-beta-ledger-us-ny5";
const OBJECT: &str =
    "92447542/snapshot-92447542-4gX8J8Y3c36L6W4D38ax2RYShfKmYxHWuDHAkQKeNzqd.tar.zst";
const GENERATION: &str = "1629744948337785";
const URI: &str = "gs://mainnet-beta-ledger-us-ny5/92447542/snapshot-92447542-4gX8J8Y3c36L6W4D38ax2RYShfKmYxHWuDHAkQKeNzqd.tar.zst#1629744948337785";
const SIZE: u64 = 8_894_131_881;
const CRC: &str = "2aRcEQ==";
const MD5: &str = "cjxmnTAGSMNCZcYD91XjbQ==";
const SLACK: u64 = 64 << 20;
const MEMORY: u64 = 512 << 20;
const CENTURY_MINIMUM: u64 = 205_211_459_014;
const PREFIX: &str = "slot92447542";
const IMPORTER_SHA: &str = "362e928c778c171dff190c2efcf631a7fc9675b96be4f1b699e433993ac365a1";
const IMPORTER_MAIN_SHA: &str = "e477ab534d0a0681348e272cd16879c37b4b287585c3c7df0db0ba8de628a107";
const UNIT_PROPERTIES: &str = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,ControlGroup,NRestarts,Job,Triggers,TriggeredBy,FragmentPath,DropInPaths,ExecStart,ExecStartPre,ExecStartPost,ExecCondition,ExecStop,ExecStopPost,ExecReload,Conditions,Result,ExecMainStatus";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    device: u64,
    inode: u64,
    length: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    mtime_seconds: i64,
    mtime_nanoseconds: i64,
    ctime_seconds: i64,
    ctime_nanoseconds: i64,
}
impl Identity {
    fn of(m: &fs::Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            length: m.len(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            links: m.nlink(),
            mtime_seconds: m.mtime(),
            mtime_nanoseconds: m.mtime_nsec(),
            ctime_seconds: m.ctime(),
            ctime_nanoseconds: m.ctime_nsec(),
        }
    }
    // rename changes ctime. Everything else, including ownership and mtime,
    // must survive the one descriptor-relative transition unchanged.
    fn renamed_from(&self, old: &Self) -> bool {
        let mut copy = self.clone();
        copy.ctime_seconds = old.ctime_seconds;
        copy.ctime_nanoseconds = old.ctime_nanoseconds;
        copy == *old
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}
impl DirectoryIdentity {
    fn of(m: &fs::Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
        }
    }
}
struct Directory {
    path: PathBuf,
    file: File,
    identity: DirectoryIdentity,
}
impl Directory {
    fn open(path: &Path, expected: &DirectoryIdentity) -> Result<Self> {
        ensure!(
            path.is_absolute() && path.canonicalize()? == path,
            "noncanonical directory"
        );
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let m = file.metadata()?;
        ensure!(
            m.is_dir() && DirectoryIdentity::of(&m) == *expected,
            "directory identity changed"
        );
        let result = Self {
            path: path.into(),
            file,
            identity: expected.clone(),
        };
        result.validate()?;
        Ok(result)
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            self.path.canonicalize()? == self.path
                && DirectoryIdentity::of(&fs::symlink_metadata(&self.path)?) == self.identity
                && DirectoryIdentity::of(&self.file.metadata()?) == self.identity,
            "named/open directory changed"
        );
        Ok(())
    }
    fn open_file(&self, name: &str) -> Result<File> {
        self.validate()?;
        let name = component(name)?;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        ensure!(
            fd >= 0,
            "nofollow open failed: {}",
            std::io::Error::last_os_error()
        );
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn absent(&self, name: &str) -> Result<bool> {
        self.validate()?;
        absent(&self.path.join(name))
    }
    fn sync(&self) -> Result<()> {
        self.file.sync_all()?;
        self.validate()
    }
}
fn component(s: &str) -> Result<CString> {
    ensure!(
        !s.is_empty() && !matches!(s, "." | "..") && !s.contains('/'),
        "unsafe component"
    );
    Ok(CString::new(s)?)
}
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn is_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn state_name(suffix: &str) -> String {
    format!("{PREFIX}-{suffix}.json")
}
fn reference(p: &Path) -> Result<Value> {
    let (h, _) = evidence::hash_file(p, 1 << 20)?;
    Ok(json!({"path":p,"sha256":h}))
}
fn load(p: &Path) -> Result<Value> {
    let b = reference(p)?;
    evidence::bound_json(&Bound {
        path: p.into(),
        sha256: b["sha256"].as_str().context("hash")?.into(),
    })
}
fn persist_same(p: &Path, v: &Value) -> Result<()> {
    if absent(p)? {
        persist(p, v)
    } else {
        ensure!(
            load(p)? == *v,
            "conflicting lifecycle journal {}",
            p.display()
        );
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    deployment_seal: Bound,
    qualification: Bound,
    historical_acceptance: Bound,
    source_identity: Identity,
    cache_directory: DirectoryIdentity,
    receipt_directory: DirectoryIdentity,
    consumer_review: Bound,
    gcloud: Bound,
    #[serde(default)]
    restore: Option<Restore>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Restore {
    admission: Bound,
    attempt: String,
    maximum_runtime_seconds: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumerReview {
    schema: String,
    cache_path: PathBuf,
    // The independently reviewed finite expansion set includes command argv,
    // launcher/environment/template expansion and each referenced sealed plan.
    // These are source artifacts, not an invented RocksDB complete-scan receipt.
    reviewed_sources: Vec<Bound>,
    consumers: Vec<Consumer>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Consumer {
    kind: String,
    unit: String,
    fragment: Bound,
    expected_properties: BTreeMap<String, String>,
    readset: Bound,
    guard: Bound,
    guard_marker: Bound,
    dropins: Vec<Bound>,
    #[serde(default)]
    importer: Option<Bound>,
    program: Bound,
    #[serde(default)]
    interpreter: Option<Bound>,
    #[serde(default)]
    installed_fragment: Option<consumer_contract::InstalledFragment>,
    native_commands: Bound,
    declared_environment: Bound,
}
fn root_bound_file(b: &Bound, max: u64, immutable: bool) -> Result<Vec<u8>> {
    ensure!(
        is_sha(&b.sha256) && b.path.is_absolute() && b.path.canonicalize()? == b.path,
        "invalid input binding"
    );
    let (h, m) = evidence::hash_file(&b.path, max)?;
    ensure!(
        h == b.sha256 && m.uid() == 0 && m.mode() & if immutable { 0o222 } else { 0o022 } == 0,
        "unsafe root-bound file"
    );
    let bytes = fs::read(&b.path)?;
    ensure!(
        bytes.len() as u64 <= max
            && sha(&bytes) == b.sha256
            && Identity::of(&m) == Identity::of(&fs::symlink_metadata(&b.path)?),
        "bound file changed at decode"
    );
    Ok(bytes)
}
fn validate_original(i: &Identity) -> Result<()> {
    ensure!(
        i.device == 66305
            && i.inode == 2508808
            && i.length == SIZE
            && i.uid == 1000
            && i.gid == 1000
            && i.mode & 0o177777 == 0o100600
            && i.links == 1
            && i.mtime_seconds == 1791429738
            && i.mtime_nanoseconds == 862379752,
        "unsupported original cache provenance"
    );
    Ok(())
}
fn validate_plan(p: &Plan, self_path: &Path, self_sha: &str) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-snapshot92447542-cache-plan-v1",
        "wrong fixed cache plan"
    );
    validate_original(&p.source_identity)?;
    ensure!(
        p.cache_directory.device == 66305
            && p.cache_directory.uid == 1000
            && p.cache_directory.gid == 1000
            && p.cache_directory.mode & 0o7777 == 0o700
            && p.receipt_directory.device == 66305
            && p.receipt_directory.uid == 0
            && p.receipt_directory.mode & 0o7777 == 0o700,
        "wrong host directory custody"
    );
    let seal = evidence::bound_json(&p.deployment_seal)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"].as_str() == self_path.parent().and_then(Path::to_str),
        "wrong deployment seal"
    );
    let members = seal["members"].as_array().context("seal members")?;
    ensure!(
        members
            .iter()
            .filter(
                |x| x["name"].as_str() == self_path.file_name().and_then(|x| x.to_str())
                    && x["sha256"] == self_sha
            )
            .count()
            == 1,
        "self image not in sealed deployment"
    );
    let q = evidence::bound_json(&p.qualification)?;
    ensure!(
        q["schema"] == "jetstreamer-snapshot92447542-lifecycle-qualification-v1"
            && q["helper_sha256"] == self_sha
            && q["uri"] == URI
            && q["gcloud"] == json!({"path":p.gcloud.path,"sha256":p.gcloud.sha256})
            && q["cloudsdk_config"] == "/home/ubuntu/.config/gcloud"
            && q["sdk_uid"] == 1000
            && q["sdk_gid"] == 1000
            && q["supplementary_groups_cleared"] == true
            && q["account"] == "sam.johnson@anza.xyz"
            && q["billing_project"] == "principal-lane-200702"
            && q["restore_roundtrip_passed"] == true
            && q["quarantine_same_mount_rename_passed"] == true
            && q["recovery_frontiers_passed"] == true
            && q["actual_uid1000_sdk_profile_passed"] == true,
        "exact lifecycle qualification missing"
    );
    let tests: Bound = serde_json::from_value(q["test_evidence"].clone())?;
    evidence::bound_json(&tests)?;
    let native: Bound = serde_json::from_value(q["native_profile_evidence"].clone())?;
    evidence::bound_json(&native)?;
    let sources: Vec<Bound> = serde_json::from_value(q["source_evidence"].clone())?;
    ensure!(!sources.is_empty(), "qualification source evidence missing");
    for b in sources {
        root_bound_file(&b, 16 << 20, true)?;
    }
    let a = evidence::bound_json(&p.historical_acceptance)?;
    ensure!(
        a["schema"] == "jetstreamer-snapshot92447542-historical-custody-acceptance-v1"
            && a["historical_path"].as_str() == Path::new(CACHE_ROOT).join(HISTORICAL).to_str()
            && a["historical_sha256"] == HISTORICAL_SHA
            && a["original_identity"] == serde_json::to_value(&p.source_identity)?,
        "historical root custody acceptance differs"
    );
    if let Some(r) = &p.restore {
        ensure!(
            r.attempt.starts_with("slot92447542-restore-")
                && r.attempt.len() <= 100
                && r.attempt
                    .bytes()
                    .all(|x| x.is_ascii_alphanumeric() || x == b'-')
                && (60..=7200).contains(&r.maximum_runtime_seconds),
            "unsafe restore attempt/runtime"
        );
    }
    Ok(())
}

// Scoped adaptation of epoch141_ledger_common::validate_object_metadata. No
// numeric coercion: accept only exact u64 or canonical decimal strings. Missing
// bucket is safe only when the canonical versioned URL supplies that binding.
fn exact_number(v: &Value, n: u64) -> bool {
    v.as_u64() == Some(n) || v.as_str() == Some(n.to_string().as_str())
}
fn validate_metadata(v: &Value) -> Result<()> {
    ensure!(
        v.is_object()
            && v["name"] == OBJECT
            && exact_number(&v["generation"], GENERATION.parse()?)
            && exact_number(&v["size"], SIZE),
        "wrong exact generation/location/size"
    );
    if let Some(b) = v.get("bucket") {
        ensure!(b == BUCKET, "conflicting bucket");
    } else {
        ensure!(
            v["storage_url"] == URI,
            "bucket requires canonical versioned URL"
        );
    }
    for (raw, normalized, want) in [("crc32c", "crc32c_hash", CRC), ("md5Hash", "md5_hash", MD5)] {
        let aliases: Vec<_> = [raw, normalized]
            .into_iter()
            .filter_map(|k| v.get(k))
            .collect();
        ensure!(
            !aliases.is_empty() && aliases.iter().all(|x| x.as_str() == Some(want)),
            "missing/conflicting {normalized}"
        );
    }
    ensure!(
        v.get("id").is_some() || v.get("storage_url").is_some(),
        "missing generation identity"
    );
    if let Some(id) = v.get("id") {
        ensure!(
            id.as_str() == Some(format!("{BUCKET}/{OBJECT}/{GENERATION}").as_str()),
            "conflicting raw identity"
        );
    }
    if let Some(uri) = v.get("storage_url") {
        ensure!(uri.as_str() == Some(URI), "conflicting versioned URL");
    }
    Ok(())
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Digests {
    bytes: u64,
    crc32c: String,
    md5: String,
    sha256: String,
}
// Adapted from the reviewed exact-generation download digest_reader. The guard
// runs during hashing as well as transport, including every final EOF attempt.
fn digest_reader(
    mut input: impl Read,
    limit: u64,
    mut guard: impl FnMut() -> Result<()>,
) -> Result<Digests> {
    let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI);
    let mut c = crc.digest();
    let mut m = Md5::new();
    let mut s = Sha256::new();
    let mut bytes = 0u64;
    let mut buf = vec![0; 4 << 20];
    let mut heartbeat = Instant::now();
    loop {
        guard()?;
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        bytes = bytes.checked_add(n as u64).context("hash overflow")?;
        ensure!(bytes <= limit, "oversized compressed object");
        c.update(&buf[..n]);
        m.update(&buf[..n]);
        s.update(&buf[..n]);
        if heartbeat.elapsed() >= Duration::from_secs(60) {
            println!("slot92447542 hash progress bytes={bytes}");
            heartbeat = Instant::now();
        }
    }
    Ok(Digests {
        bytes,
        crc32c: STANDARD.encode(c.finalize().to_be_bytes()),
        md5: STANDARD.encode(m.finalize()),
        sha256: format!("{:x}", s.finalize()),
    })
}
fn validate_digests(d: &Digests, expected_sha: Option<&str>) -> Result<()> {
    ensure!(
        d.bytes == SIZE
            && d.crc32c == CRC
            && d.md5 == MD5
            && is_sha(&d.sha256)
            && expected_sha.is_none_or(|h| h == d.sha256),
        "compressed generation digest mismatch"
    );
    Ok(())
}
fn digest_at(
    dir: &Directory,
    name: &str,
    expected: Option<&Identity>,
    expected_bytes: u64,
    verify: impl FnOnce(&Digests) -> Result<()>,
    mut guard: impl FnMut() -> Result<()>,
) -> Result<(Identity, Digests, u64)> {
    let mut f = dir.open_file(name)?;
    let m = f.metadata()?;
    let before = Identity::of(&m);
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.len() == expected_bytes
            && expected.is_none_or(|x| x == &before),
        "unexpected source identity"
    );
    let d = digest_reader(&mut f, expected_bytes, || {
        dir.validate()?;
        guard()
    })?;
    ensure!(d.bytes == expected_bytes, "truncated compressed input");
    verify(&d)?;
    ensure!(
        before == Identity::of(&f.metadata()?)
            && before == Identity::of(&fs::symlink_metadata(dir.path.join(name))?),
        "same-name replacement/content change during hashing"
    );
    dir.validate()?;
    Ok((
        before,
        d,
        m.blocks().checked_mul(512).context("blocks overflow")?,
    ))
}
fn hash_at(
    dir: &Directory,
    name: &str,
    expected: Option<&Identity>,
    expected_sha: Option<&str>,
    guard: impl FnMut() -> Result<()>,
) -> Result<(Identity, Digests, u64)> {
    digest_at(
        dir,
        name,
        expected,
        SIZE,
        |d| validate_digests(d, expected_sha),
        guard,
    )
}
fn historical(dir: &Directory) -> Result<Value> {
    let f = dir.open_file(HISTORICAL)?;
    let before = f.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 1000
            && before.gid() == 1000
            && before.nlink() == 1
            && before.mode() & 0o7777 == 0o600
            && before.len() <= 1 << 20,
        "historical receipt custody changed"
    );
    let mut b = Vec::new();
    f.take((1 << 20) + 1).read_to_end(&mut b)?;
    ensure!(
        sha(&b) == HISTORICAL_SHA
            && Identity::of(&before)
                == Identity::of(&fs::symlink_metadata(dir.path.join(HISTORICAL))?),
        "historical receipt changed"
    );
    Ok(json!({"sha256":HISTORICAL_SHA,"identity":Identity::of(&before)}))
}

fn safe_unit(s: &str) -> bool {
    s.ends_with(".service")
        && !s.starts_with('-')
        && s.len() <= 255
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.@".contains(&c))
}
fn terminal_values(unit: &str, v: &BTreeMap<String, String>) -> Result<()> {
    for (key, want) in [
        ("Id", unit),
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("ControlGroup", ""),
        ("NRestarts", "0"),
        ("Job", ""),
        ("Triggers", ""),
        ("TriggeredBy", ""),
    ] {
        ensure!(
            v.get(key).map(String::as_str) == Some(want),
            "consumer is live/restarted/triggered: {key}"
        );
    }
    ensure!(
        matches!(
            v.get("ActiveState").map(String::as_str),
            Some("inactive" | "failed")
        ) && matches!(
            v.get("SubState").map(String::as_str),
            Some("dead" | "failed")
        ),
        "consumer is not terminal"
    );
    Ok(())
}
fn acquisition_terminal_values(unit: &str, v: &BTreeMap<String, String>) -> Result<()> {
    terminal_values(unit, v)?;
    ensure!(
        v.get("Result").map(String::as_str) == Some("success")
            && v.get("ExecMainStatus").map(String::as_str) == Some("0"),
        "original acquisition did not finish cleanly"
    );
    Ok(())
}
// The path scanner remains authoritative for commands/cwd/root/exe. Also
// compare inode numbers in maps and open FDs so file-bind aliases do not escape
// the finite file-target census. Permission failures are never absence.
pub(crate) fn inode_references(proc_root: &Path, device: u64, inode: u64) -> Result<Vec<String>> {
    let mut refs = Vec::new();
    for e in fs::read_dir(proc_root)? {
        let e = e?;
        let name = e.file_name();
        let Some(pid) = name
            .to_str()
            .filter(|s| !s.is_empty() && s.bytes().all(|x| x.is_ascii_digit()))
        else {
            continue;
        };
        if pid.parse::<u32>().ok() == Some(std::process::id()) {
            continue;
        }
        let root = e.path();
        match File::open(root.join("maps")) {
            Ok(f) => {
                let mut total = 0usize;
                for line in BufReader::new(f).lines() {
                    let line = line?;
                    total = total
                        .checked_add(line.len() + 1)
                        .context("maps byte overflow")?;
                    ensure!(
                        total <= 1 << 30 && line.len() <= 65536,
                        "maps census bound exceeded"
                    );
                    let fields: Vec<_> = line.split_whitespace().take(5).collect();
                    ensure!(fields.len() == 5, "malformed maps row");
                    let (major, minor) =
                        fields[3].split_once(':').context("maps device missing")?;
                    let dev = libc::makedev(
                        u32::from_str_radix(major, 16)?,
                        u32::from_str_radix(minor, 16)?,
                    );
                    if dev == device && fields[4].parse::<u64>()? == inode {
                        refs.push(format!("pid {pid} inode-map"));
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e).context("incomplete inode-map census"),
        }
        match fs::read_dir(root.join("fd")) {
            Ok(fds) => {
                for fd in fds {
                    let fd = fd?;
                    match fs::metadata(fd.path()) {
                        Ok(m) if m.dev() == device && m.ino() == inode => refs.push(format!(
                            "pid {pid} inode-fd {}",
                            fd.file_name().to_string_lossy()
                        )),
                        Ok(_) => (),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                        Err(e) => return Err(e).context("incomplete inode-FD census"),
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e).context("incomplete inode-FD directory"),
        }
    }
    refs.sort();
    refs.dedup();
    Ok(refs)
}
fn condition_resets(bytes: &[u8]) -> Result<()> {
    for line in std::str::from_utf8(bytes)?.lines() {
        let line = line.trim();
        ensure!(!line.starts_with(".include"), "unexpanded unit include");
        if let Some((key, value)) = line.split_once('=') {
            ensure!(
                key.trim() != "ConditionPathExists" || !value.trim().is_empty(),
                "condition reset can make consumer launchable"
            );
        }
    }
    Ok(())
}
#[path = "snapshot92447542_consumer_contract.rs"]
mod consumer_contract;
fn consumer_proof(p: &Plan) -> Result<Value> {
    consumer_proof_core(&p.consumer_review, &p.source_identity)
}
fn consumer_proof_core(review_binding: &Bound, source_identity: &Identity) -> Result<Value> {
    let raw = evidence::bound_json(review_binding)?;
    let review: ConsumerReview = serde_json::from_value(raw)?;
    ensure!(
        review.schema == "jetstreamer-snapshot92447542-finite-consumer-readset-review-v2"
            && review.cache_path == Path::new(CACHE_ROOT).join(NAME)
            && !review.reviewed_sources.is_empty(),
        "missing exact finite source/readset review"
    );
    let mut sources = Vec::new();
    for b in &review.reviewed_sources {
        root_bound_file(b, 16 << 20, true)?;
        sources.push(json!({"path":b.path,"sha256":b.sha256}));
    }
    let mut excluded = BTreeSet::new();
    let mut owners = Vec::new();
    let mut names = BTreeSet::new();
    let mut acquisition = false;
    for c in &review.consumers {
        ensure!(
            safe_unit(&c.unit) && names.insert(c.unit.clone()),
            "unsafe/duplicate consumer"
        );
        let bytes = root_bound_file(&c.fragment, 1 << 20, false)?;
        condition_resets(&bytes)?;
        let v = evidence::properties(&c.unit, UNIT_PROPERTIES)?;
        terminal_values(&c.unit, &v)?;
        ensure!(
            v == c.expected_properties,
            "consumer native envelope changed"
        );
        let installed = consumer_contract::installed(c, &v)?;
        let (native, argv) = consumer_contract::native(c)?;
        let rs = evidence::bound_json(&c.readset)?;
        consumer_contract::readset(c, &rs, &sources, &argv)?;
        consumer_contract::program(c, &argv, &sources)?;
        if c.kind == "acquisition" {
            acquisition_terminal_values(&c.unit, &v)?;
            ensure!(
                !acquisition
                    && c.unit == ACQUISITION_UNIT
                    && c.fragment.sha256 == ACQUISITION_FRAGMENT_SHA
                    && c.importer.is_none(),
                "unknown acquisition envelope"
            );
            acquisition = true;
            ensure!(
                std::str::from_utf8(&bytes)?
                    .lines()
                    .any(|x| x == format!("ConditionPathExists=!{CACHE_ROOT}/{HISTORICAL}")),
                "original acquisition condition changed"
            );
        }
        // No fragment is ignored merely because its old process ended. Require
        // an independently sealed nonlaunchable disposition at the exact unit.
        let guard = root_bound_file(&c.guard, 1 << 20, true)?;
        evidence::bound_json(&c.guard_marker)?;
        let required = format!(
            "[Unit]\nConditionPathExists=!{}\n",
            c.guard_marker.path.display()
        );
        ensure!(
            guard == required.as_bytes(),
            "guard must contain only the required negative condition"
        );
        let actual_dropins: BTreeSet<_> = v
            .get("DropInPaths")
            .context("dropin census missing")?
            .split_whitespace()
            .map(PathBuf::from)
            .collect();
        let mut expected_dropins = BTreeSet::new();
        for dropin in &c.dropins {
            ensure!(
                expected_dropins.insert(dropin.path.clone()),
                "duplicate dropin binding"
            );
            let bytes = root_bound_file(dropin, 1 << 20, false)?;
            condition_resets(&bytes)?;
        }
        ensure!(
            actual_dropins == expected_dropins && expected_dropins.contains(&c.guard.path),
            "unbound effective dropin or missing guard"
        );
        ensure!(
            excluded.insert(c.fragment.path.clone()),
            "duplicate excluded fragment"
        );
        excluded.extend(expected_dropins);
        owners.push(json!({"unit":c.unit,"native":v,"installed_fragment":installed,"typed_native_envelope":native,"fragment_sha256":c.fragment.sha256,"readset_sha256":c.readset.sha256,"guard_sha256":c.guard.sha256,"marker_sha256":c.guard_marker.sha256}));
    }
    ensure!(acquisition, "original acquisition disposition missing");
    ensure!(
        names == consumer_contract::registered_units()?,
        "finite consumer set missing/unknown units"
    );
    let roots: Vec<_> = crate::snapshot92447542_census::ROOTS
        .iter()
        .map(Path::new)
        .collect();
    let load_paths = crate::snapshot92447542_census::load_paths()?;
    let mut missing = Vec::new();
    // Parent masks are relevant too. Every resulting fragment needs the finite
    // authenticated readset/guard disposition above; unknown fragments reject.
    let staged = dev_cache_check::staged_references_exact(
        &roots,
        Path::new(CACHE_ROOT),
        &mut missing,
        &excluded,
    )?;
    ensure!(
        staged.is_empty(),
        "unknown staged parent/cache reference: {staged:?}"
    );
    let inode_refs = inode_references(
        Path::new("/proc"),
        source_identity.device,
        source_identity.inode,
    )?;
    ensure!(inode_refs.is_empty(), "live inode aliases: {inode_refs:?}");
    let scan = process_references::scan(Path::new("/proc"), &Path::new(CACHE_ROOT).join(NAME))?;
    ensure!(
        scan.references.is_empty(),
        "live cache references: {:?}",
        scan.references
    );
    let quarantine = Path::new(STATE).join(format!("{PREFIX}-quarantine"));
    let qs = process_references::scan(Path::new("/proc"), &quarantine)?;
    ensure!(qs.references.is_empty(), "live quarantine references");
    for c in &review.consumers {
        ensure!(
            evidence::properties(&c.unit, UNIT_PROPERTIES)? == c.expected_properties,
            "consumer changed during census"
        );
        let installed_after = consumer_contract::installed(c, &c.expected_properties)?;
        ensure!(
            owners
                .iter()
                .find(|v| v["unit"] == c.unit)
                .context("consumer before image missing")?["installed_fragment"]
                == installed_after,
            "installed fragment parent/link changed during census"
        );
        let (_, argv) = consumer_contract::native(c)?;
        consumer_contract::program(c, &argv, &sources)?;
        root_bound_file(&c.fragment, 1 << 20, false)?;
        root_bound_file(&c.guard, 1 << 20, true)?;
        evidence::bound_json(&c.guard_marker)?;
        for dropin in &c.dropins {
            root_bound_file(dropin, 1 << 20, false)?;
        }
    }
    ensure!(
        crate::snapshot92447542_census::load_paths()? == load_paths,
        "consumer unit load paths changed"
    );
    Ok(
        json!({"source_evidence":sources,"consumers":owners,"exact_live_path_scan":scan,"exact_inode_alias_references":inode_refs,"quarantine_live_path_scan":qs,"staged_references":staged,"missing_inactive_aliases":missing,"excluded_only_authenticated_nonlaunchable_fragments":excluded}),
    )
}

fn rename_noreplace(from: &Directory, old: &str, to: &Directory, new: &str) -> Result<()> {
    from.validate()?;
    to.validate()?;
    let a = component(old)?;
    let b = component(new)?;
    let result = unsafe {
        libc::renameat2(
            from.file.as_raw_fd(),
            a.as_ptr(),
            to.file.as_raw_fd(),
            b.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .context("no-clobber rename failed (same writable mount required)");
    }
    from.sync()?;
    to.sync()?;
    Ok(())
}
fn unlink_at(dir: &Directory, name: &str, expected: &Identity) -> Result<()> {
    dir.validate()?;
    ensure!(
        Identity::of(&fs::symlink_metadata(dir.path.join(name))?) == *expected,
        "quarantine inode changed before unlink"
    );
    let n = component(name)?;
    ensure!(
        unsafe { libc::unlinkat(dir.file.as_raw_fd(), n.as_ptr(), 0) } == 0,
        "exact unlink failed: {}",
        std::io::Error::last_os_error()
    );
    dir.sync()?;
    ensure!(dir.absent(name)?, "quarantine remains");
    Ok(())
}
#[path = "snapshot92447542_lifecycle_engine.rs"]
mod lifecycle_engine;
#[path = "snapshot92447542_mount_probe.rs"]
mod mount_probe;

struct ProductionLifecycle<'a> {
    plan: &'a Plan,
    cache: &'a Directory,
    state: &'a Directory,
    bindings: lifecycle_engine::Bindings,
    object: lifecycle_engine::ObjectSpec,
    check_sha: &'a str,
    recovery: Option<Bound>,
}
impl<'a> ProductionLifecycle<'a> {
    fn new(
        plan: &'a Plan,
        plan_sha: &str,
        self_sha: &str,
        check_sha: &'a str,
        cache: &'a Directory,
        state: &'a Directory,
        recovery: Option<Bound>,
    ) -> Self {
        Self {
            plan,
            cache,
            state,
            bindings: lifecycle_engine::Bindings::production(plan, plan_sha, self_sha),
            object: lifecycle_engine::ObjectSpec::fixed_generation(),
            check_sha,
            recovery,
        }
    }
}
impl lifecycle_engine::Environment for ProductionLifecycle<'_> {
    fn cache(&self) -> &Directory {
        self.cache
    }
    fn state(&self) -> &Directory {
        self.state
    }
    fn source_identity(&self) -> &Identity {
        &self.plan.source_identity
    }
    fn bindings(&self) -> &lifecycle_engine::Bindings {
        &self.bindings
    }
    fn object(&self) -> &lifecycle_engine::ObjectSpec {
        &self.object
    }
    fn history(&self) -> Result<Value> {
        historical(self.cache)
    }
    fn consumers(&self) -> Result<Value> {
        consumer_proof(self.plan)
    }
    fn metadata(&self) -> Result<Vec<u8>> {
        metadata(self.plan)
    }
    fn restore_request(&self) -> Option<lifecycle_engine::RestoreRequest> {
        self.plan
            .restore
            .as_ref()
            .map(|r| lifecycle_engine::RestoreRequest {
                attempt: r.attempt.clone(),
                maximum_runtime_seconds: r.maximum_runtime_seconds,
                admission_sha256: r.admission.sha256.clone(),
            })
    }
    fn restore_admission(&self, verified: &str) -> Result<lifecycle_engine::Booking> {
        let r = self
            .plan
            .restore
            .as_ref()
            .context("restore admission required")?;
        let a = admission(self.plan, r, &self.bindings.self_sha256, verified)?;
        Ok(lifecycle_engine::Booking {
            protected_floor_bytes: a.protected_floor_bytes,
            owner: Owner {
                unit: a.owner_unit,
                invocation_id: a.owner_invocation_id,
                exec_start: a.owner_exec_start,
            },
            protected_owners: a.protected_owners,
        })
    }
    fn guard_owners(&self, a: &lifecycle_engine::Booking) -> Result<()> {
        owner(&a.owner.unit, &a.owner.invocation_id, &a.owner.exec_start)?;
        for x in &a.protected_owners {
            owner(&x.unit, &x.invocation_id, &x.exec_start)?;
        }
        Ok(())
    }
    fn spawn_download(&self, destination: &Path) -> Result<OwnedSdk> {
        let mut command = sdk_command(&self.plan.gcloud)?;
        command
            .args([
                "storage",
                "cp",
                "--no-clobber",
                "--quiet",
                "--account=sam.johnson@anza.xyz",
                "--billing-project=principal-lane-200702",
                URI,
            ])
            .arg(destination);
        Ok(OwnedSdk(Some(command.spawn()?)))
    }
    fn authorize_recovery(
        &self,
        prior: &Value,
        stage: Option<&DirectoryIdentity>,
    ) -> Result<Value> {
        let bound = self
            .recovery
            .as_ref()
            .context("fresh independent restore-recovery capability required")?;
        let bytes = root_bound_file(bound, 1 << 20, true)?;
        let a: RestoreRecoveryAdmission = serde_json::from_slice(&bytes)?;
        let r = self
            .plan
            .restore
            .as_ref()
            .context("restore plan required for recovery")?;
        let intent = self.state.path.join(format!("{}-intent.json", r.attempt));
        ensure!(
            a.schema == "jetstreamer-snapshot92447542-restore-attempt-recovery-admission-v1"
                && a.route == "reconcile-owned-attempt-only"
                && a.issued_unix_seconds <= now()?
                && now()? <= a.expires_unix_seconds
                && a.expires_unix_seconds > a.issued_unix_seconds
                && a.expires_unix_seconds - a.issued_unix_seconds <= 180
                && a.helper_sha256 == self.bindings.self_sha256
                && a.original_plan_sha256 == self.bindings.operation_sha256
                && a.check_sha256 == self.check_sha
                && a.generation == GENERATION
                && a.attempt == r.attempt
                && a.attempt_identity.as_ref() == stage
                && a.original_attempt_intent.path == intent
                && reference(&intent)?
                    == json!({"path":a.original_attempt_intent.path,"sha256":a.original_attempt_intent.sha256}),
            "wrong/stale/broadened restore recovery authority"
        );
        ensure!(
            evidence::bound_json(&a.original_attempt_intent)? == *prior,
            "recovery intent differs"
        );
        let original: Owner = serde_json::from_value(prior["original_owner"].clone())?;
        ensure!(
            original != a.current_owner,
            "recovery cannot impersonate the prior invocation"
        );
        let disposition: RestoreOwnerDisposition = serde_json::from_slice(&root_bound_file(
            &a.original_owner_disposition,
            1 << 20,
            true,
        )?)?;
        ensure!(
            disposition.schema
                == "jetstreamer-snapshot92447542-original-restore-owner-disposition-v1"
                && disposition.original_owner == original
                && disposition.attempt_intent.path == intent
                && disposition.attempt_intent.sha256 == a.original_attempt_intent.sha256
                && disposition.attempt_identity.as_ref() == stage,
            "prior attempt ownership disposition differs"
        );
        let old_properties = || -> Result<BTreeMap<String, String>> {
            let actual = evidence::properties(
                &original.unit,
                &disposition
                    .current_properties
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(","),
            )?;
            ensure!(
                actual == disposition.current_properties,
                "prior invocation current envelope changed"
            );
            terminal_values(&original.unit, &actual)?;
            ensure!(
                actual.get("Restart").map(String::as_str) == Some("no"),
                "prior owner may automatically relaunch"
            );
            Ok(actual)
        };
        ensure!(
            safe_unit(&original.unit)
                && original.invocation_id.len() == 32
                && original
                    .invocation_id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && !original.exec_start.is_empty(),
            "invalid prior owner binding"
        );
        let before = old_properties()?;
        let events = root_bound_file(&disposition.terminal_pid1_events, 4 << 20, true)?;
        let events: Vec<Value> = std::str::from_utf8(&events)?
            .lines()
            .map(serde_json::from_str)
            .collect::<std::result::Result<_, _>>()?;
        ensure!(
            !events.is_empty()
                && events.iter().all(|v| v["_PID"] == "1"
                    && v["UNIT"] == original.unit
                    && v["INVOCATION_ID"] == original.invocation_id)
                && events.iter().any(|v| matches!(
                    v["CODE_FUNC"].as_str(),
                    Some("unit_log_success" | "unit_log_failure")
                )),
            "original PID1 terminal events do not prove this invocation ended"
        );
        let current = owner(
            &a.current_owner.unit,
            &a.current_owner.invocation_id,
            &a.current_owner.exec_start,
        )?;
        ensure!(
            current["MainPID"].as_str() == Some(std::process::id().to_string().as_str())
                && env::var("INVOCATION_ID")? == a.current_owner.invocation_id,
            "recovery authority is not this actual MainPID/IID"
        );
        let current_pid = std::process::id().to_string();
        for (key, want) in [
            ("Id", a.current_owner.unit.as_str()),
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("InvocationID", a.current_owner.invocation_id.as_str()),
            ("MainPID", current_pid.as_str()),
            ("NRestarts", "0"),
            ("Type", "exec"),
            ("MemoryMax", "536870912"),
            ("MemorySwapMax", "0"),
            ("CPUQuotaPerSecUSec", "2s"),
            ("NoNewPrivileges", "yes"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "read-only"),
            ("KillMode", "control-group"),
        ] {
            ensure!(
                a.current_properties.get(key).map(String::as_str) == Some(want),
                "recovery required property differs: {key}"
            );
        }
        ensure!(
            matches!(
                a.current_properties.get("User").map(String::as_str),
                Some("" | "root")
            ) && matches!(
                a.current_properties.get("Group").map(String::as_str),
                Some("" | "root")
            ) && matches!(
                a.current_properties.get("TasksMax").map(String::as_str),
                Some("128" | "512")
            ) && matches!(
                a.current_properties
                    .get("RuntimeMaxUSec")
                    .map(String::as_str),
                Some("3min" | "180s")
            ),
            "recovery identity/resource profile differs"
        );
        let actual_current = evidence::properties(
            &a.current_owner.unit,
            &a.current_properties
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(","),
        )?;
        ensure!(
            actual_current == a.current_properties
                && old_properties()? == before
                && now()? <= a.expires_unix_seconds,
            "recovery owner raced or expired"
        );
        Ok(
            json!({"admission":{"path":bound.path,"sha256":bound.sha256},"original_owner_disposition":{"path":a.original_owner_disposition.path,"sha256":a.original_owner_disposition.sha256},"original_owner":original,"original_terminal_properties":before,"current_owner":actual_current,"attempt_identity":stage,"scope":"owned prior stage reconciliation only; no source mutation, fresh download or replay authority"}),
        )
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreRecoveryAdmission {
    schema: String,
    route: String,
    issued_unix_seconds: u64,
    expires_unix_seconds: u64,
    helper_sha256: String,
    original_plan_sha256: String,
    check_sha256: String,
    generation: String,
    attempt: String,
    attempt_identity: Option<DirectoryIdentity>,
    original_attempt_intent: Bound,
    original_owner_disposition: Bound,
    current_owner: Owner,
    current_properties: BTreeMap<String, String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreOwnerDisposition {
    schema: String,
    original_owner: Owner,
    attempt_intent: Bound,
    attempt_identity: Option<DirectoryIdentity>,
    current_properties: BTreeMap<String, String>,
    terminal_pid1_events: Bound,
}
fn check(
    p: &Plan,
    plan_sha: &str,
    self_sha: &str,
    cache: &Directory,
    state: &Directory,
) -> Result<()> {
    lifecycle_engine::run_check(&ProductionLifecycle::new(
        p, plan_sha, self_sha, "", cache, state, None,
    ))
}
fn evict(
    p: &Plan,
    plan_sha: &str,
    self_sha: &str,
    check_sha: &str,
    cache: &Directory,
    state: &Directory,
) -> Result<()> {
    lifecycle_engine::run_evict(
        &ProductionLifecycle::new(p, plan_sha, self_sha, check_sha, cache, state, None),
        check_sha,
    )
}
fn restore(
    p: &Plan,
    plan_sha: &str,
    self_sha: &str,
    check_sha: &str,
    cache: &Directory,
    state: &Directory,
) -> Result<()> {
    lifecycle_engine::run_restore(
        &ProductionLifecycle::new(p, plan_sha, self_sha, check_sha, cache, state, None),
        check_sha,
    )
}
fn restore_recover(
    p: &Plan,
    plan_sha: &str,
    self_sha: &str,
    check_sha: &str,
    cache: &Directory,
    state: &Directory,
    recovery: Bound,
) -> Result<()> {
    lifecycle_engine::run_recover_restore(
        &ProductionLifecycle::new(
            p,
            plan_sha,
            self_sha,
            check_sha,
            cache,
            state,
            Some(recovery),
        ),
        check_sha,
    )
}

fn recovery_frontier(source: bool, quarantine: bool, moved: bool, unlink: bool) -> Result<()> {
    ensure!(
        !(source && quarantine),
        "source reappeared/conflicting quarantine"
    );
    ensure!(!unlink || moved, "unlink intent without moved proof");
    ensure!(
        source || quarantine || unlink,
        "unknown absence before unlink intent"
    );
    ensure!(
        !(source && (moved || unlink)),
        "source reappeared after move"
    );
    Ok(())
}
fn free_bytes(path: &Path) -> Result<u64> {
    let p = CString::new(path.as_os_str().as_bytes())?;
    let mut s = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(p.as_ptr(), s.as_mut_ptr()) } == 0,
        "free-space read failed"
    );
    let s = unsafe { s.assume_init() };
    s.f_bavail
        .checked_mul(s.f_frsize)
        .context("free-byte overflow")
}
// Adapted from generation_download::OwnedDownload: keep leader unreaped with
// WNOWAIT until killing only its owned PGID, preventing PID/PGID reuse races.
struct OwnedSdk(Option<Child>);
impl OwnedSdk {
    fn exited(&self) -> Result<bool> {
        let c = self.0.as_ref().context("SDK already reaped")?;
        let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        ensure!(
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    c.id(),
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            } == 0,
            "SDK waitid failed"
        );
        Ok(unsafe { info.si_pid() } != 0)
    }
    fn finish(&mut self) -> Result<ExitStatus> {
        let c = self.0.as_mut().context("SDK already reaped")?;
        let rc = unsafe { libc::kill(-(c.id() as i32), libc::SIGKILL) };
        ensure!(
            rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH),
            "cannot kill owned SDK group"
        );
        let status = c.wait()?;
        self.0 = None;
        Ok(status)
    }
}
impl Drop for OwnedSdk {
    fn drop(&mut self) {
        if let Some(c) = &mut self.0 {
            let rc = unsafe { libc::kill(-(c.id() as i32), libc::SIGKILL) };
            if rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                let _ = c.wait();
            }
        }
    }
}
fn stop_owned_sdk(owned: &mut Option<OwnedSdk>) -> Result<()> {
    if let Some(sdk) = owned.as_mut() {
        if sdk.0.is_some() {
            sdk.finish()?;
        }
        ensure!(sdk.0.is_none(), "SDK leader was not reaped");
    }
    Ok(())
}
fn sdk_command(gcloud: &Bound) -> Result<Command> {
    ensure!(
        gcloud.path.is_absolute()
            && gcloud.path.starts_with("/home/linuxbrew/.linuxbrew")
            && gcloud.path.file_name().is_some_and(|x| x == "gcloud")
            && gcloud.path.canonicalize()? == gcloud.path,
        "SDK must be the exact canonical Homebrew gcloud"
    );
    let (h, m) = evidence::hash_file(&gcloud.path, 16 << 20)?;
    ensure!(
        h == gcloud.sha256
            && matches!(m.uid(), 0 | 1000)
            && m.mode() & 0o022 == 0
            && m.mode() & 0o111 != 0,
        "installed SDK digest/custody changed"
    );
    let mut c = Command::new(&gcloud.path);
    c.env_clear()
        .env("PATH", "/home/linuxbrew/.linuxbrew/bin:/usr/bin:/bin")
        .env("HOME", "/home/ubuntu")
        .env("LANG", "C.UTF-8")
        .env("CLOUDSDK_CONFIG", "/home/ubuntu/.config/gcloud")
        .env("CLOUDSDK_CORE_DISABLE_PROMPTS", "1")
        .env("CLOUDSDK_CORE_DISABLE_FILE_LOGGING", "1")
        .env("CLOUDSDK_STORAGE_PROCESS_COUNT", "1")
        .env("CLOUDSDK_STORAGE_THREAD_COUNT", "1")
        .env("CLOUDSDK_STORAGE_SLICED_OBJECT_DOWNLOAD_THRESHOLD", "0")
        .env(
            "CLOUDSDK_STORAGE_SLICED_OBJECT_DOWNLOAD_MAX_COMPONENTS",
            "1",
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        c.pre_exec(|| {
            if libc::setpgid(0, 0) != 0
                || libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(1000) != 0
                || libc::setuid(1000) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(c)
}
fn metadata(p: &Plan) -> Result<Vec<u8>> {
    metadata_core(&p.gcloud, |_, _| Ok(()))
}
// Native qualification observes the actual SDK child at spawn and immediately
// before owned-group shutdown. Production uses this identical metadata engine
// with a no-op witness; no qualification Plan or snapshot body is fabricated.
#[derive(Clone, Copy)]
enum SdkWitnessPoint {
    Spawned,
    BeforeReap,
}
fn metadata_core(
    gcloud: &Bound,
    mut witness: impl FnMut(u32, SdkWitnessPoint) -> Result<()>,
) -> Result<Vec<u8>> {
    let mut c = sdk_command(gcloud)?;
    c.args([
        "storage",
        "objects",
        "describe",
        URI,
        "--account=sam.johnson@anza.xyz",
        "--billing-project=principal-lane-200702",
        "--format=json",
        "--quiet",
    ])
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let mut child = OwnedSdk(Some(c.spawn()?));
    let pid = child.0.as_ref().context("SDK child missing")?.id();
    if let Err(error) = witness(pid, SdkWitnessPoint::Spawned) {
        // Cleanup precedes propagation, including a failed native /proc witness.
        child
            .finish()
            .context("SDK witness failure cleanup failed")?;
        return Err(error);
    }
    let process = child.0.as_mut().context("SDK child missing")?;
    let out = process.stdout.take().context("SDK stdout missing")?;
    let err = process.stderr.take().context("SDK stderr missing")?;
    fn capture(mut p: impl Read) -> std::io::Result<Vec<u8>> {
        let mut b = Vec::new();
        (&mut p).take((16 << 10) + 1).read_to_end(&mut b)?;
        Ok(b)
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let tx_out = tx.clone();
    let stdout = thread::spawn(move || {
        let _ = tx_out.send((true, capture(out)));
    });
    let stderr = thread::spawn(move || {
        let _ = tx.send((false, capture(err)));
    });
    let start = Instant::now();
    while !child.exited()? {
        ensure!(
            start.elapsed() < Duration::from_secs(60),
            "SDK metadata timeout"
        );
        thread::sleep(Duration::from_millis(25));
    }
    if let Err(error) = witness(pid, SdkWitnessPoint::BeforeReap) {
        child
            .finish()
            .context("SDK final witness failure cleanup failed")?;
        return Err(error);
    }
    let status = child.finish()?;
    // Do not join a pipe reader indefinitely if an SDK descendant escaped its
    // process group while inheriting a pipe. The service's qualified
    // KillMode=control-group remains the final containment boundary.
    let mut bytes = None;
    let mut errors = None;
    for _ in 0..2 {
        let (is_stdout, result) = rx
            .recv_timeout(Duration::from_secs(5))
            .context("SDK pipes remained open after group shutdown")?;
        if is_stdout {
            bytes = Some(result?);
        } else {
            errors = Some(result?);
        }
    }
    stdout
        .join()
        .map_err(|_| anyhow::anyhow!("metadata stdout reader panicked"))?;
    stderr
        .join()
        .map_err(|_| anyhow::anyhow!("metadata stderr reader panicked"))?;
    let bytes = bytes.context("metadata stdout result missing")?;
    let errors = errors.context("metadata stderr result missing")?;
    ensure!(
        status.success() && bytes.len() <= 16 << 10 && errors.len() <= 16 << 10,
        "SDK metadata failed (private stderr withheld)"
    );
    validate_metadata(&serde_json::from_slice::<Value>(&bytes)?)?;
    sdk_command(gcloud)?;
    Ok(bytes)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Admission {
    schema: String,
    main_accepted: bool,
    helper_sha256: String,
    qualification_sha256: String,
    generation: String,
    verified_sha256: String,
    attempt: String,
    recorded_unix_seconds: u64,
    expires_unix_seconds: u64,
    protected_floor_bytes: u64,
    candidate_incremental_peak_bytes: u64,
    memory_max_bytes: u64,
    restore_only: bool,
    replay_launch_authorized: bool,
    publication_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
    fleet: Bound,
    floor_evidence: Bound,
    owner_unit: String,
    owner_invocation_id: String,
    owner_exec_start: String,
    protected_owners: Vec<Owner>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Owner {
    unit: String,
    invocation_id: String,
    exec_start: String,
}
fn owner(unit: &str, iid: &str, exec: &str) -> Result<Value> {
    ensure!(
        safe_unit(unit)
            && iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && !exec.is_empty(),
        "invalid admitted owner"
    );
    let p = evidence::properties(
        unit,
        "Id,ActiveState,SubState,InvocationID,NRestarts,MainPID,ExecStart",
    )?;
    ensure!(
        p.get("Id").map(String::as_str) == Some(unit)
            && p.get("ActiveState").map(String::as_str) == Some("active")
            && p.get("SubState").map(String::as_str) == Some("running")
            && p.get("InvocationID").map(String::as_str) == Some(iid)
            && p.get("NRestarts").map(String::as_str) == Some("0")
            && p.get("ExecStart").map(String::as_str) == Some(exec)
            && p.get("MainPID")
                .is_some_and(|x| x.parse::<u32>().is_ok_and(|n| n > 0)),
        "admitted owner changed"
    );
    Ok(serde_json::to_value(p)?)
}
fn validate_admission_fields(
    a: &Admission,
    qualification_sha: &str,
    attempt: &str,
    self_sha: &str,
    verified: &str,
    n: u64,
) -> Result<()> {
    ensure!(
        a.schema == "jetstreamer-snapshot92447542-restore-only-admission-v1"
            && a.main_accepted
            && a.helper_sha256 == self_sha
            && a.qualification_sha256 == qualification_sha
            && a.generation == GENERATION
            && a.verified_sha256 == verified
            && a.attempt == attempt
            && a.recorded_unix_seconds <= n
            && n <= a.expires_unix_seconds
            && a.expires_unix_seconds - a.recorded_unix_seconds <= 300
            && a.protected_floor_bytes >= CENTURY_MINIMUM
            && a.candidate_incremental_peak_bytes == SIZE + SLACK
            && a.memory_max_bytes == MEMORY
            && a.restore_only
            && !a.replay_launch_authorized
            && !a.publication_authorized
            && !a.remote_mutations
            && !a.r2_mutations,
        "wrong/stale/broadened restore-only admission"
    );
    Ok(())
}
fn admission(p: &Plan, r: &Restore, self_sha: &str, verified: &str) -> Result<Admission> {
    let a: Admission = serde_json::from_value(evidence::bound_json(&r.admission)?)?;
    validate_admission_fields(
        &a,
        &p.qualification.sha256,
        &r.attempt,
        self_sha,
        verified,
        now()?,
    )?;
    evidence::bound_json(&a.fleet)?;
    let floor = evidence::bound_json(&a.floor_evidence)?;
    ensure!(
        floor["protected_floor_bytes"] == a.protected_floor_bytes
            && floor["all_current_growth_claims_included"] == true
            && floor["century_floor_bytes"]
                .as_u64()
                .is_some_and(|n| n >= CENTURY_MINIMUM),
        "protected-growth/century-floor evidence differs"
    );
    let o = owner(&a.owner_unit, &a.owner_invocation_id, &a.owner_exec_start)?;
    ensure!(
        o["MainPID"].as_str() == Some(std::process::id().to_string().as_str())
            && env::var("INVOCATION_ID").ok().as_deref() == Some(a.owner_invocation_id.as_str()),
        "restore booking is not this actual service invocation"
    );
    let mut names = BTreeSet::new();
    for x in &a.protected_owners {
        ensure!(names.insert(&x.unit), "duplicate protected owner");
        owner(&x.unit, &x.invocation_id, &x.exec_start)?;
    }
    Ok(a)
}
fn staged_bytes(d: &Directory) -> Result<u64> {
    d.validate()?;
    let mut bytes = 0u64;
    let mut n = 0;
    for e in fs::read_dir(&d.path)? {
        let m = fs::symlink_metadata(e?.path())?;
        n += 1;
        ensure!(
            n <= 4
                && m.is_file()
                && m.nlink() == 1
                && m.dev() == d.identity.device
                && matches!(m.uid(), 0 | 1000),
            "unsafe SDK staging member"
        );
        bytes = bytes.checked_add(m.len()).context("staging overflow")?;
    }
    Ok(bytes)
}
fn chown(file: &File, uid: u32, gid: u32) -> Result<()> {
    ensure!(
        unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } == 0,
        "custody change failed"
    );
    Ok(())
}
fn freeze_stage(dir: &mut Directory) -> Result<()> {
    dir.validate()?;
    chown(&dir.file, 0, 0)?;
    dir.file
        .set_permissions(fs::Permissions::from_mode(0o700))?;
    dir.identity = DirectoryIdentity::of(&dir.file.metadata()?);
    dir.sync()
}
fn cleanup_attempt(dir: &mut Directory) -> Result<()> {
    let refs = process_references::scan(Path::new("/proc"), &dir.path)?;
    ensure!(
        refs.references.is_empty(),
        "temporary still referenced; preserve it for inspection"
    );
    ensure!(
        inode_references(Path::new("/proc"), dir.identity.device, dir.identity.inode)?.is_empty(),
        "temporary directory inode still referenced"
    );
    // Complete and validate the owned enrollment before unlinking any member.
    // Per-file inode scans also find retained FD/map aliases whose visible
    // names no longer point below the staging path.
    staged_bytes(dir)?;
    freeze_stage(dir)?;
    let mut members = Vec::new();
    for entry in fs::read_dir(&dir.path)? {
        let entry = entry?;
        let m = fs::symlink_metadata(entry.path())?;
        ensure!(
            m.is_file()
                && m.nlink() == 1
                && m.dev() == dir.identity.device
                && matches!(m.uid(), 0 | 1000),
            "foreign temporary retained"
        );
        let name = entry
            .file_name()
            .to_str()
            .context("temporary filename")?
            .to_owned();
        component(&name)?;
        let identity = Identity::of(&m);
        ensure!(
            inode_references(Path::new("/proc"), identity.device, identity.inode)?.is_empty(),
            "temporary payload inode alias still referenced"
        );
        members.push((name, identity));
    }
    members.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, identity) in members {
        unlink_at(dir, &name, &identity)?;
    }
    dir.validate()?;
    fs::remove_dir(&dir.path)?;
    File::open(dir.path.parent().context("attempt parent")?)?.sync_all()?;
    Ok(())
}

pub fn run() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let args: Vec<_> = env::args().skip(1).collect();
    if args.first().is_some_and(|x| x == "probe-mounts") {
        ensure!(
            args.len() == 4,
            "usage: BIN probe-mounts ADMISSION ADMISSION_SHA SELF_SHA"
        );
        return mount_probe::run(&args[1], &args[2], &args[3]);
    }
    if args.first().is_some_and(|x| x == "review-consumers") {
        ensure!(
            args.len() == 4,
            "usage: BIN review-consumers ADMISSION ADMISSION_SHA SELF_SHA"
        );
        return consumer_contract::run_review(&args[1], &args[2], &args[3]);
    }
    ensure!(
        matches!(args.len(), 6 | 7 | 9) && args[1] == "--plan-sha256" && args[3] == "--self-sha256",
        "usage: BIN PLAN --plan-sha256 HASH --self-sha256 HASH check | evict CHECK_SHA | restore CHECK_SHA | restore-recover CHECK_SHA RECOVERY_ADMISSION RECOVERY_SHA"
    );
    let self_path = fs::read_link("/proc/self/exe")?;
    let (self_sha, m) = evidence::hash_file(&self_path, 256 << 20)?;
    ensure!(
        self_sha == args[4]
            && is_sha(&self_sha)
            && m.uid() == 0
            && m.mode() & 0o222 == 0
            && Identity::of(&m) == Identity::of(&fs::metadata("/proc/self/exe")?),
        "unsealed/wrong self image"
    );
    let p: Plan = serde_json::from_value(evidence::bound_json(&Bound {
        path: args[0].clone().into(),
        sha256: args[2].clone(),
    })?)?;
    validate_plan(&p, &self_path, &self_sha)?;
    private_dir(Path::new(STATE))?;
    let state = Directory::open(Path::new(STATE), &p.receipt_directory)?;
    let cache = Directory::open(Path::new(CACHE_ROOT), &p.cache_directory)?;
    match args[5].as_str() {
        "check" => {
            ensure!(args.len() == 6, "check takes no extra operand");
            check(&p, &args[2], &self_sha, &cache, &state)
        }
        "evict" | "restore" | "restore-recover" => {
            ensure!(
                args.len() >= 7 && is_sha(&args[6]),
                "exact check digest required"
            );
            if args[5] == "restore-recover" {
                ensure!(
                    args.len() == 9 && is_sha(&args[8]),
                    "fresh independent recovery admission and digest required"
                );
                restore_recover(
                    &p,
                    &args[2],
                    &self_sha,
                    &args[6],
                    &cache,
                    &state,
                    Bound {
                        path: args[7].clone().into(),
                        sha256: args[8].clone(),
                    },
                )
            } else {
                ensure!(args.len() == 7, "exact check digest required");
                if args[5] == "evict" {
                    evict(&p, &args[2], &self_sha, &args[6], &cache, &state)
                } else {
                    restore(&p, &args[2], &self_sha, &args[6], &cache, &state)
                }
            }
        }
        _ => bail!("unsupported fixed lifecycle mode"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn dir(path: &Path) -> Directory {
        Directory::open(path, &DirectoryIdentity::of(&fs::metadata(path).unwrap())).unwrap()
    }
    fn raw_metadata() -> Value {
        json!({"bucket":BUCKET,"name":OBJECT,"generation":GENERATION,"size":SIZE.to_string(),"crc32c":CRC,"md5Hash":MD5,"id":format!("{BUCKET}/{OBJECT}/{GENERATION}")})
    }
    #[test]
    fn raw_and_normalized_metadata_require_unambiguous_generation_identity() {
        let raw = raw_metadata();
        validate_metadata(&raw).unwrap();
        let mut normalized = raw.clone();
        normalized.as_object_mut().unwrap().remove("bucket");
        normalized["storage_url"] = json!(URI);
        validate_metadata(&normalized).unwrap();
        normalized.as_object_mut().unwrap().remove("storage_url");
        assert!(validate_metadata(&normalized).is_err());
        for (key, value) in [
            ("bucket", json!("another-bucket")),
            ("name", json!("92447542/wrong.tar.zst")),
            ("generation", json!("01629744948337785")),
            ("generation", json!(1629744948337785.0)),
            ("size", json!(SIZE - 1)),
            ("size", json!(8894131881.0)),
            ("crc32c_hash", json!("wrong")),
            ("md5_hash", Value::Null),
            ("id", json!("wrong")),
            ("storage_url", json!(URI.replace('#', "/"))),
        ] {
            let mut bad = raw.clone();
            bad[key] = value;
            assert!(validate_metadata(&bad).is_err(), "{key}");
        }
        for key in ["md5Hash", "crc32c", "id"] {
            let mut bad = raw.clone();
            bad.as_object_mut().unwrap().remove(key);
            assert!(validate_metadata(&bad).is_err(), "{key}");
        }
    }
    #[test]
    fn streaming_digests_reject_bound_failure_and_preserve_raw_bytes() {
        let bytes = b"123456789";
        let d = digest_reader(bytes.as_slice(), bytes.len() as u64, || Ok(())).unwrap();
        assert_eq!(d.bytes, 9);
        assert_eq!(d.crc32c, "4waSgw=="); // Castagnoli e3069283, network byte order.
        assert_eq!(d.md5, "JfnnlDI7RTiF9RgfG2JNCw==");
        assert_eq!(
            d.sha256,
            "15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225"
        );
        assert!(digest_reader(bytes.as_slice(), 8, || Ok(())).is_err());
        assert!(digest_reader(bytes.as_slice(), 9, || bail!("floor crossed")).is_err());
        let short = digest_reader(&bytes[..8], 9, || Ok(())).unwrap();
        assert_ne!(short, d);
        assert!(validate_digests(&d, None).is_err()); // Small fixture never becomes fixed-generation proof.
    }
    #[test]
    fn nofollow_hash_rejects_symlinks_hardlinks_wrong_identity_and_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let d = dir(temp.path());
        fs::write(temp.path().join("body"), b"bytes").unwrap();
        let expected = Identity::of(&fs::metadata(temp.path().join("body")).unwrap());
        let verify = |d: &Digests| {
            ensure!(d.sha256 == sha(b"bytes"), "content");
            Ok(())
        };
        digest_at(&d, "body", Some(&expected), 5, verify, || Ok(())).unwrap();
        symlink("body", temp.path().join("link")).unwrap();
        assert!(digest_at(&d, "link", None, 5, verify, || Ok(())).is_err());
        fs::hard_link(temp.path().join("body"), temp.path().join("hard")).unwrap();
        assert!(digest_at(&d, "body", None, 5, verify, || Ok(())).is_err());
        fs::remove_file(temp.path().join("hard")).unwrap();
        let before = Identity::of(&fs::metadata(temp.path().join("body")).unwrap());
        let mut changed = false;
        assert!(
            digest_at(&d, "body", Some(&before), 5, verify, || {
                if !changed {
                    fs::rename(temp.path().join("body"), temp.path().join("preserved"))?;
                    fs::write(temp.path().join("body"), b"bytes")?;
                    changed = true;
                }
                Ok(())
            })
            .is_err()
        );
        assert_eq!(fs::read(temp.path().join("preserved")).unwrap(), b"bytes");
        assert!(digest_at(&d, "body", Some(&before), 5, verify, || Ok(())).is_err());
        fs::write(temp.path().join("body"), b"wrong").unwrap();
        assert!(digest_at(&d, "body", None, 5, verify, || Ok(())).is_err());
    }
    #[test]
    fn directory_substitution_rejects_descriptor_and_path_disagreement() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("source");
        fs::create_dir(&path).unwrap();
        let d = dir(&path);
        fs::rename(&path, temp.path().join("old")).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(d.validate().is_err());
        assert!(d.absent("body").is_err());
        assert!(d.open_file("body").is_err());
    }
    #[test]
    fn quarantine_no_clobber_and_identity_check_preserve_collisions() {
        let temp = tempfile::tempdir().unwrap();
        let src = temp.path().join("source");
        let dst = temp.path().join("private");
        fs::create_dir(&src).unwrap();
        fs::create_dir(&dst).unwrap();
        let source = dir(&src);
        let private = dir(&dst);
        fs::write(src.join("cache"), b"original").unwrap();
        fs::write(dst.join("quarantine"), b"foreign").unwrap();
        let original = Identity::of(&fs::metadata(src.join("cache")).unwrap());
        let collision = rename_noreplace(&source, "cache", &private, "quarantine").unwrap_err();
        assert_eq!(
            collision
                .downcast_ref::<std::io::Error>()
                .and_then(std::io::Error::raw_os_error),
            Some(libc::EEXIST)
        );
        assert_eq!(fs::read(dst.join("quarantine")).unwrap(), b"foreign");
        fs::remove_file(dst.join("quarantine")).unwrap();
        rename_noreplace(&source, "cache", &private, "quarantine").unwrap();
        let moved = Identity::of(&fs::metadata(dst.join("quarantine")).unwrap());
        assert!(moved.renamed_from(&original));
        fs::rename(dst.join("quarantine"), dst.join("preserved")).unwrap();
        fs::write(dst.join("quarantine"), b"injected").unwrap();
        assert!(unlink_at(&private, "quarantine", &moved).is_err());
        assert_eq!(fs::read(dst.join("preserved")).unwrap(), b"original");
        assert_eq!(fs::read(dst.join("quarantine")).unwrap(), b"injected");
    }
    #[test]
    fn crash_frontiers_only_accept_identical_owned_transitions() {
        // Before/after intent, after move before its receipt, after moved proof,
        // before unlink, and after unlink before completion.
        for state in [
            (true, false, false, false),
            (false, true, false, false),
            (false, true, true, false),
            (false, true, true, true),
            (false, false, true, true),
        ] {
            recovery_frontier(state.0, state.1, state.2, state.3).unwrap();
        }
        for state in [
            (false, false, false, false),
            (false, false, true, false),
            (false, false, false, true),
            (true, true, false, false),
            (true, false, true, false),
            (true, false, true, true),
        ] {
            assert!(
                recovery_frontier(state.0, state.1, state.2, state.3).is_err(),
                "{state:?}"
            );
        }
    }
    #[test]
    fn inode_aliases_and_malformed_proc_reads_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let body = temp.path().join("body");
        fs::write(&body, b"input").unwrap();
        let m = fs::metadata(&body).unwrap();
        let proc = temp.path().join("proc");
        fs::create_dir(&proc).unwrap();
        let pid = proc.join("4294967294");
        fs::create_dir(&pid).unwrap();
        fs::create_dir(pid.join("fd")).unwrap();
        let row = format!(
            "0000-1000 r--p 00000000 {:x}:{:x} {} /different-bind-name\n",
            libc::major(m.dev()),
            libc::minor(m.dev()),
            m.ino()
        );
        fs::write(pid.join("maps"), row).unwrap();
        symlink(&body, pid.join("fd/8")).unwrap();
        assert_eq!(inode_references(&proc, m.dev(), m.ino()).unwrap().len(), 2);
        fs::remove_file(pid.join("maps")).unwrap();
        fs::create_dir(pid.join("maps")).unwrap();
        assert!(inode_references(&proc, m.dev(), m.ino()).is_err());
    }
    #[test]
    fn terminal_consumers_must_be_unqueued_unrestarted_and_process_free() {
        let unit = ACQUISITION_UNIT;
        let v = BTreeMap::from(
            [
                ("Id", unit),
                ("MainPID", "0"),
                ("ControlPID", "0"),
                ("ControlGroup", ""),
                ("NRestarts", "0"),
                ("Job", ""),
                ("Triggers", ""),
                ("TriggeredBy", ""),
                ("ActiveState", "inactive"),
                ("SubState", "dead"),
                ("Result", "success"),
                ("ExecMainStatus", "0"),
            ]
            .map(|(k, v)| (k.into(), v.into())),
        );
        terminal_values(unit, &v).unwrap();
        acquisition_terminal_values(unit, &v).unwrap();
        for (key, value) in [("Result", "exit-code"), ("ExecMainStatus", "1")] {
            let mut bad = v.clone();
            bad.insert(key.into(), value.into());
            assert!(acquisition_terminal_values(unit, &bad).is_err(), "{key}");
        }
        let mut missing = v.clone();
        missing.remove("Result");
        assert!(acquisition_terminal_values(unit, &missing).is_err());
        for (key, value) in [
            ("MainPID", "42"),
            ("ControlPID", "43"),
            ("ControlGroup", "/still-live"),
            ("NRestarts", "1"),
            ("Job", "44"),
            ("Triggers", "other.service"),
            ("TriggeredBy", "a.timer"),
            ("ActiveState", "active"),
            ("Id", "other.service"),
        ] {
            let mut bad = v.clone();
            bad.insert(key.into(), value.into());
            assert!(terminal_values(unit, &bad).is_err(), "{key}");
        }
        assert!(condition_resets(b"[Unit]\nConditionPathExists=\n").is_err());
        assert!(condition_resets(b"[Unit]\n ConditionPathExists = \n").is_err());
        assert!(condition_resets(b".include /unbound/other.conf\n").is_err());
        condition_resets(b"[Unit]\nConditionPathExists=!/root/marker\n").unwrap();
    }
    fn admission_fixture() -> Value {
        json!({"schema":"jetstreamer-snapshot92447542-restore-only-admission-v1","main_accepted":true,"helper_sha256":"a".repeat(64),"qualification_sha256":"b".repeat(64),"generation":GENERATION,"verified_sha256":"c".repeat(64),"attempt":"slot92447542-restore-test","recorded_unix_seconds":1000,"expires_unix_seconds":1300,"protected_floor_bytes":CENTURY_MINIMUM,"candidate_incremental_peak_bytes":SIZE+SLACK,"memory_max_bytes":MEMORY,"restore_only":true,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false,"fleet":{"path":"/root/fleet.json","sha256":"d".repeat(64)},"floor_evidence":{"path":"/root/floor.json","sha256":"e".repeat(64)},"owner_unit":"restore.service","owner_invocation_id":"f".repeat(32),"owner_exec_start":"exact","protected_owners":[]})
    }
    #[test]
    fn restore_capacity_authority_is_fresh_exact_and_not_replay_authority() {
        let fixture = admission_fixture();
        let a: Admission = serde_json::from_value(fixture.clone()).unwrap();
        let validate = |a: &Admission, n| {
            validate_admission_fields(
                a,
                &"b".repeat(64),
                "slot92447542-restore-test",
                &"a".repeat(64),
                &"c".repeat(64),
                n,
            )
        };
        validate(&a, 1100).unwrap();
        assert!(validate(&a, 999).is_err());
        assert!(validate(&a, 1301).is_err());
        for (key, value) in [
            ("helper_sha256", json!("wrong")),
            ("generation", json!("1629744948337786")),
            ("protected_floor_bytes", json!(CENTURY_MINIMUM - 1)),
            ("candidate_incremental_peak_bytes", json!(SIZE)),
            ("memory_max_bytes", json!(MEMORY + 1)),
            ("expires_unix_seconds", json!(1400)),
            ("restore_only", json!(false)),
            ("replay_launch_authorized", json!(true)),
            ("publication_authorized", json!(true)),
            ("remote_mutations", json!(true)),
            ("r2_mutations", json!(true)),
        ] {
            let mut bad = fixture.clone();
            bad[key] = value;
            let bad: Admission = serde_json::from_value(bad).unwrap();
            assert!(validate(&bad, 1100).is_err(), "{key}");
        }
        let mut bad = fixture;
        bad["unknown_floor_waiver"] = json!(true);
        assert!(serde_json::from_value::<Admission>(bad).is_err());
    }
    #[test]
    fn fixed_original_provenance_does_not_accept_a_rehydrated_or_other_inode() {
        let i = Identity {
            device: 66305,
            inode: 2508808,
            length: SIZE,
            uid: 1000,
            gid: 1000,
            mode: 0o100600,
            links: 1,
            mtime_seconds: 1791429738,
            mtime_nanoseconds: 862379752,
            ctime_seconds: 1,
            ctime_nanoseconds: 2,
        };
        validate_original(&i).unwrap();
        let mut replacement = i.clone();
        replacement.inode += 1;
        assert!(validate_original(&replacement).is_err());
        replacement = i.clone();
        replacement.links = 2;
        assert!(validate_original(&replacement).is_err());
        replacement = i;
        replacement.mode = 0o100444;
        assert!(validate_original(&replacement).is_err());
    }
}

#[cfg(test)]
mod retained_metadata_fixture {
    use super::*;
    // Byte-for-byte retained 1019 fixture (796 bytes, e984727c...). It DOES
    // contain bucket. The separate no-bucket derivative exercises the scoped
    // canonical storage_url alternative without rewriting historical evidence.
    const FROZEN: &str = r#"{
  "bucket": "mainnet-beta-ledger-us-ny5",
  "content_language": "en",
  "content_type": "application/octet-stream",
  "crc32c_hash": "2aRcEQ==",
  "creation_time": "2021-08-23T18:55:48+0000",
  "custom_fields": {
    "goog-reserved-file-mtime": "1629419261"
  },
  "etag": "CPm44YXpx/ICEAE=",
  "generation": "1629744948337785",
  "md5_hash": "cjxmnTAGSMNCZcYD91XjbQ==",
  "metageneration": 1,
  "name": "92447542/snapshot-92447542-4gX8J8Y3c36L6W4D38ax2RYShfKmYxHWuDHAkQKeNzqd.tar.zst",
  "size": 8894131881,
  "storage_class": "STANDARD",
  "storage_class_update_time": "2021-08-23T18:55:48+0000",
  "storage_url": "gs://mainnet-beta-ledger-us-ny5/92447542/snapshot-92447542-4gX8J8Y3c36L6W4D38ax2RYShfKmYxHWuDHAkQKeNzqd.tar.zst#1629744948337785",
  "update_time": "2021-08-23T18:55:48+0000"
}
"#;
    #[test]
    fn exact_retained_metadata_and_missing_bucket_derivative() {
        assert_eq!(FROZEN.len(), 796);
        assert_eq!(
            sha(FROZEN.as_bytes()),
            "e984727c358aff2b76c0a354334cca8281b9673a6cedefb40f3455e188663596"
        );
        let mut v: Value = serde_json::from_str(FROZEN).unwrap();
        validate_metadata(&v).unwrap();
        v.as_object_mut().unwrap().remove("bucket");
        validate_metadata(&v).unwrap();
        v["bucket"] = json!("conflict");
        assert!(validate_metadata(&v).is_err());
    }
    #[test]
    fn owned_sdk_group_reaps_leader_and_closes_descendant_pipes() {
        use std::sync::mpsc;
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "sleep 60 & printf 'ready\\n'; wait"])
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .stdin(Stdio::null());
        let mut child = OwnedSdk(Some(command.spawn().unwrap()));
        let pipe = child.0.as_mut().unwrap().stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut pipe = BufReader::new(pipe);
            let mut line = String::new();
            let read = pipe.read_line(&mut line);
            tx.send((read.is_ok(), line)).unwrap();
            let mut rest = Vec::new();
            let result = pipe.read_to_end(&mut rest);
            tx.send((result.is_ok(), String::new())).unwrap();
        });
        let (ok, line) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(ok);
        assert_eq!(line, "ready\n");
        let mut owned = Some(child);
        stop_owned_sdk(&mut owned).unwrap();
        assert!(owned.as_ref().unwrap().0.is_none());
        // A second shutdown is safe and must not signal a reused process group.
        stop_owned_sdk(&mut owned).unwrap();
        assert!(rx.recv_timeout(Duration::from_secs(5)).unwrap().0);
        reader.join().unwrap();
    }
}

// A native SDK control must be explicitly selected. The ordinary module test
// inventory remains unchanged and cannot make an authenticated cloud call.
#[cfg(all(test, feature = "snapshot92447542-native-sdk-tests"))]
#[path = "snapshot92447542_native_sdk.rs"]
mod native_sdk;

#[cfg(all(test, feature = "snapshot92447542-native-lifecycle-tests"))]
#[path = "snapshot92447542_native_engine.rs"]
mod native_engine;
