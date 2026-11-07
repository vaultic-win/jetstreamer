//! Terminal, non-authoritative Old Faithful compact-index cache retirement.
//! Reads only existing small evidence and the real compiszd header. No archive
//! body read/hash, remote client, tree deletion, producer stop or build exists.
use {
    anyhow::{Context, Result, ensure},
    serde::{Deserialize, Serialize},
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    std::{
        collections::{BTreeMap, BTreeSet},
        ffi::CString,
        fs::{self, File, Metadata, OpenOptions},
        io::{Read, Write},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{
                ffi::OsStrExt,
                fs::{MetadataExt, OpenOptionsExt},
            },
        },
        path::{Path, PathBuf},
        process::{Command, Stdio},
        time::{SystemTime, UNIX_EPOCH},
    },
};
const LIMIT: u64 = 4 << 20;
const HEADER_LIMIT: usize = 65536;
const PRIVATE: &str = "/home/ubuntu/.jetstreamer-private";
const UNIT_ROOTS: &[&str] = &[
    "/run/systemd/system",
    "/etc/systemd/system",
    "/run/systemd/transient",
    "/run/systemd/generator",
    "/run/systemd/generator.early",
    "/run/systemd/generator.late",
];
const READY: &[u64] = &[
    202, 203, 206, 207, 209, 213, 216, 217, 218, 219, 220, 221, 222, 225,
];
const ROOTS: &[&str] = &[
    "qualification-202",
    "qualification-203",
    "qualification-213",
    "qualification-225-v1625-natural-root-shrink-budget-2f856bd-v1",
    "qualification-206",
    "qualification-207-singleton-admitted-v1",
    "qualification-209-singleton-capped-v1",
    "shrink-root-prefix-resource-203-f9fc5a0-v1",
    "checkpoint-continuation-203-ed66145-v1",
    "checkpoint-continuation-213-ae43646-v1",
    "qualification-216-219-contiguous-v2",
    "adaptive-220-232-v1",
    "adaptive-220-223-current-9d8e964-v1",
];
mod legacy202 {
    include!("terminal_compact_index/legacy202_check.rs");
}
mod reviewed {
    include!("terminal_compact_index/reviewed_closure.rs");
}
mod typed {
    include!("terminal_compact_index/typed_closure.rs");
}
mod imported {
    include!("terminal_compact_index/imported_canonical.rs");
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    device: u64,
    inode: u64,
    size: u64,
    blocks: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
    mtime: i64,
    mtime_nsec: i64,
}
fn identity(m: &Metadata) -> Identity {
    Identity {
        device: m.dev(),
        inode: m.ino(),
        size: m.len(),
        blocks: m.blocks(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
        nlink: m.nlink(),
        mtime: m.mtime(),
        mtime_nsec: m.mtime_nsec(),
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    path: PathBuf,
    sha256: String,
    uid: u32,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Preserved {
    path: PathBuf,
    identity: Identity,
    ctime: i64,
    ctime_nsec: i64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Actor {
    unit: String,
    invocation_id: String,
    historical_provenance: Option<ActorProvenance>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ActorProvenance {
    evidence: Evidence,
    unit_json_pointer: String,
    invocation_id_json_pointer: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InertRecipe {
    path: PathBuf,
    sha256: String,
    unit: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    root: PathBuf,
    actors: Vec<Actor>,
    preserved: Vec<Preserved>,
    #[serde(default)]
    imported_canonical: Option<imported::ImportedCanonical>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Index {
    path: PathBuf,
    identity: Identity,
    original_ctime: i64,
    original_ctime_nsec: i64,
    owner: usize,
    epoch: u64,
    header_hex: String,
    reproduction_url: String,
    canonical_r2_receipt: Evidence,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    state: PathBuf,
    owners: Vec<Owner>,
    indexes: Vec<Index>,
    source_review: Evidence,
    inert_recipes: Vec<InertRecipe>,
    #[serde(default)]
    typed_recipes: Vec<typed::Recipe>,
    #[serde(default)]
    current_operation: Option<typed::Operation>,
    #[serde(default)]
    legacy202_check: Option<legacy202::Profile>,
    #[serde(default)]
    completed_check: Option<typed::CompletedCurrentCheck>,
    local_index_retirement_authorized: bool,
    archive_deletion_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}
fn valid_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn now() -> Result<u128> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
}
fn open_read(p: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?)
}
fn absent(p: &Path) -> Result<bool> {
    match fs::symlink_metadata(p) {
        Ok(_) => Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e.into()),
    }
}
fn small(p: &Path, uid: u32) -> Result<Vec<u8>> {
    ensure!(
        p.is_absolute() && p.canonicalize()? == p,
        "aliased evidence"
    );
    let mut f = open_read(p)?;
    let a = f.metadata()?;
    ensure!(
        a.is_file()
            && a.uid() == uid
            && a.nlink() == 1
            && a.mode() & 0o022 == 0
            && a.len() <= LIMIT,
        "unsafe evidence"
    );
    let mut b = Vec::new();
    (&mut f).take(LIMIT + 1).read_to_end(&mut b)?;
    let z = f.metadata()?;
    ensure!(
        b.len() as u64 == a.len()
            && identity(&a) == identity(&z)
            && a.ctime() == z.ctime()
            && a.ctime_nsec() == z.ctime_nsec(),
        "evidence changed"
    );
    Ok(b)
}
fn evidence(e: &Evidence) -> Result<Vec<u8>> {
    ensure!(
        !matches!(
            e.path.extension().and_then(|s| s.to_str()),
            Some("jet" | "index" | "car" | "sst")
        ),
        "payload cannot be small evidence"
    );
    ensure!(valid_sha(&e.sha256), "invalid evidence digest");
    let b = small(&e.path, e.uid)?;
    ensure!(hash(&b) == e.sha256, "evidence digest changed");
    Ok(b)
}
fn unhex(s: &str) -> Result<Vec<u8>> {
    ensure!(
        s.len() % 2 == 0 && s.len() <= HEADER_LIMIT * 2,
        "header hex bound"
    );
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| {
            let t = std::str::from_utf8(p)?;
            Ok(u8::from_str_radix(t, 16)?)
        })
        .collect()
}
fn base32(s: &str) -> Result<Vec<u8>> {
    ensure!(s.starts_with('b'), "CID is not base32lower");
    let mut out = Vec::new();
    let (mut bits, mut value) = (0u32, 0u32);
    for c in s[1..].bytes() {
        let n = match c {
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            _ => anyhow::bail!("invalid CID"),
        };
        value = (value << 5) | u32::from(n);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((value >> bits) as u8);
            value &= (1 << bits) - 1;
        }
    }
    ensure!(bits < 5 && value == 0, "noncanonical CID padding");
    Ok(out)
}
fn name_parts(index: &Index) -> Result<(String, String)> {
    let name = index
        .path
        .file_name()
        .and_then(|p| p.to_str())
        .context("index filename")?;
    let start = format!("epoch-{}-", index.epoch);
    let rest = name.strip_prefix(&start).context("index epoch filename")?;
    let (cid, kind) = rest
        .split_once("-mainnet-")
        .context("index network filename")?;
    let kind = kind.strip_suffix(".index").context("index extension")?;
    ensure!(
        ["slot-to-cid", "cid-to-offset-and-size"].contains(&kind),
        "unqualified index kind"
    );
    ensure!(
        base32(cid)?.len() == 36,
        "unexpected canonical CAR root CID"
    );
    Ok((cid.into(), kind.into()))
}
// Actual compiszd v1 format, mirroring index.rs. No cache-validation schema is
// manufactured: retain the complete bounded original header/metadata verbatim.
fn header(bytes: &[u8], epoch: u64, cid: &str, kind: &str) -> Result<()> {
    ensure!(
        bytes.len() >= 26 && bytes.len() <= HEADER_LIMIT && &bytes[..8] == b"compiszd",
        "compactindex magic/bound"
    );
    let n = u32::from_le_bytes(bytes[8..12].try_into()?) as usize;
    ensure!(
        n >= 14 && n + 12 == bytes.len() && bytes[24] == 1,
        "compactindex version/header length"
    );
    let width = u64::from_le_bytes(bytes[12..20].try_into()?);
    ensure!(
        width == if kind == "slot-to-cid" { 36 } else { 9 },
        "index value width"
    );
    let (mut offset, mut metadata) = (26usize, BTreeMap::new());
    for _ in 0..bytes[25] {
        let k = *bytes.get(offset).context("metadata key length")? as usize;
        offset += 1;
        let key = bytes
            .get(offset..offset + k)
            .context("metadata key")?
            .to_vec();
        offset += k;
        let v = *bytes.get(offset).context("metadata value length")? as usize;
        offset += 1;
        let value = bytes
            .get(offset..offset + v)
            .context("metadata value")?
            .to_vec();
        offset += v;
        ensure!(
            metadata.insert(key, value).is_none(),
            "duplicate metadata key"
        );
    }
    ensure!(offset == bytes.len(), "unparsed header metadata");
    ensure!(
        metadata.get(b"epoch".as_slice()) == Some(&epoch.to_le_bytes().to_vec())
            && metadata.get(b"rootCid".as_slice()) == Some(&base32(cid)?)
            && metadata.get(b"network".as_slice()) == Some(&b"mainnet".to_vec())
            && metadata.get(b"kind".as_slice()) == Some(&kind.as_bytes().to_vec()),
        "real compactindex metadata differs from filename"
    );
    Ok(())
}
fn validate_plan(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-terminal-compact-index-retirement-plan-v1"
            && p.local_index_retirement_authorized
            && !p.archive_deletion_authorized
            && !p.remote_mutations
            && !p.r2_mutations,
        "invalid local-only retirement authority"
    );
    ensure!(
        !p.owners.is_empty() && !p.indexes.is_empty() && p.indexes.len() <= 128,
        "empty/oversized exact selection"
    );
    ensure!(
        p.state.starts_with("/var/lib/jetstreamer")
            && !p.owners.iter().any(|o| p.state.starts_with(&o.root)),
        "unsafe state path"
    );
    ensure!(
        p.source_review.uid == 0 && valid_sha(&p.source_review.sha256),
        "source review must be Root-bound"
    );
    let (mut roots, mut names, mut ids) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for owner in &p.owners {
        let name = owner
            .root
            .file_name()
            .and_then(|p| p.to_str())
            .context("owner root name")?;
        ensure!(
            owner.root.parent() == Some(Path::new(PRIVATE))
                && (ROOTS.contains(&name) || owner.imported_canonical.is_some())
                && roots.insert(owner.root.clone()),
            "unqualified/duplicate owner root"
        );
        ensure!(
            !owner.actors.is_empty()
                && !owner.preserved.is_empty()
                && (owner.imported_canonical.is_some()
                    || owner
                        .preserved
                        .iter()
                        .any(|f| f.path.extension().is_some_and(|e| e == "jet"))),
            "exact terminal actors/source archives missing"
        );
        if let Some(imported) = &owner.imported_canonical {
            imported::validate_owner(owner, imported)?;
        }
        for actor in &owner.actors {
            ensure!(
                actor.unit.ends_with(".service")
                    && actor
                        .unit
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))
                    && actor.invocation_id.len() == 32
                    && actor.invocation_id.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid terminal actor binding"
            );
            if let Some(h) = &actor.historical_provenance {
                ensure!(
                    h.evidence.uid == 0
                        && valid_sha(&h.evidence.sha256)
                        && [&h.unit_json_pointer, &h.invocation_id_json_pointer]
                            .iter()
                            .all(|s| s.starts_with('/') && s.len() <= 512)
                        && h.unit_json_pointer != h.invocation_id_json_pointer,
                    "historical actor provenance must pin original Root-bound JSON fields"
                );
            }
        }
        for f in &owner.preserved {
            ensure!(
                f.path.starts_with(&owner.root)
                    && !f
                        .path
                        .components()
                        .any(|c| c.as_os_str() == "compact-indexes"),
                "preserved evidence overlaps cache"
            );
        }
    }
    for index in &p.indexes {
        let owner = p.owners.get(index.owner).context("index owner ordinal")?;
        ensure!(
            index.canonical_r2_receipt.uid == 0 && valid_sha(&index.canonical_r2_receipt.sha256),
            "canonical receipt must be Root-bound"
        );
        ensure!(
            (READY.contains(&index.epoch) || owner.imported_canonical.is_some())
                && index.path.starts_with(&owner.root)
                && index.identity.uid == 1000
                && index.identity.nlink == 1
                && index.identity.mode & libc::S_IFMT == libc::S_IFREG
                && index.identity.mode & 0o022 == 0
                && names.insert(index.path.clone())
                && ids.insert((index.identity.device, index.identity.inode)),
            "unqualified/overlapping cache file"
        );
        if let Some(imported) = &owner.imported_canonical {
            imported::validate_index(owner, imported, index)?;
        }
        let parent = index.path.parent().context("index parent")?;
        ensure!(
            parent.file_name().and_then(|p| p.to_str()) == Some(index.epoch.to_string().as_str())
                && parent.parent().and_then(Path::file_name)
                    == Some(std::ffi::OsStr::new("compact-indexes")),
            "not an exact compact-index cache member"
        );
        let (cid, kind) = name_parts(index)?;
        let bytes = unhex(&index.header_hex)?;
        header(&bytes, index.epoch, &cid, &kind)?;
        ensure!(
            index.identity.size >= bytes.len() as u64
                && index.reproduction_url
                    == format!(
                        "https://files.old-faithful.net/{}/{}",
                        index.epoch,
                        index.path.file_name().unwrap().to_str().unwrap()
                    ),
            "unbound deterministic source URL"
        );
    }
    let actors: BTreeSet<_> = p
        .owners
        .iter()
        .flat_map(|o| o.actors.iter().map(|a| a.unit.as_str()))
        .collect();
    for r in &p.inert_recipes {
        ensure!(
            valid_sha(&r.sha256)
                && actors.contains(r.unit.as_str())
                && UNIT_ROOTS.contains(
                    &r.path
                        .parent()
                        .context("recipe parent")?
                        .to_str()
                        .context("recipe parent UTF8")?
                )
                && r.path.file_name().and_then(|s| s.to_str()) == Some(r.unit.as_str()),
            "inert recipe is not exact bound terminal actor"
        );
    }
    typed::validate(p)?;
    Ok(())
}
fn read_header(index: &Index, path: &Path, original: bool) -> Result<()> {
    ensure!(path.canonicalize()? == path, "aliased cache target");
    let mut f = open_read(path)?;
    let a = f.metadata()?;
    ensure!(
        identity(&a) == index.identity
            && (!original
                || (a.ctime() == index.original_ctime
                    && a.ctime_nsec() == index.original_ctime_nsec)),
        "cache identity changed"
    );
    let expected = unhex(&index.header_hex)?;
    let mut bytes = vec![0; expected.len()];
    f.read_exact(&mut bytes)?;
    let z = f.metadata()?;
    ensure!(
        bytes == expected
            && identity(&z) == index.identity
            && a.ctime() == z.ctime()
            && a.ctime_nsec() == z.ctime_nsec(),
        "bounded header or inode changed"
    );
    named_matches(path, &z)?;
    Ok(())
}
fn named_matches(path: &Path, opened: &Metadata) -> Result<()> {
    let named = fs::symlink_metadata(path)?;
    ensure!(
        identity(&named) == identity(opened)
            && named.ctime() == opened.ctime()
            && named.ctime_nsec() == opened.ctime_nsec(),
        "cache named path replaced after header open"
    );
    Ok(())
}
fn preserved(p: &Plan) -> Result<()> {
    evidence(&p.source_review)?;
    for owner in &p.owners {
        ensure!(owner.root.canonicalize()? == owner.root, "owner root alias");
        if let Some(imported) = &owner.imported_canonical {
            imported::preserved(owner, imported, p)?;
        }
        for f in &owner.preserved {
            ensure!(
                f.path.canonicalize()? == f.path
                    && identity(&fs::symlink_metadata(&f.path)?) == f.identity
                    && fs::symlink_metadata(&f.path)?.ctime() == f.ctime
                    && fs::symlink_metadata(&f.path)?.ctime_nsec() == f.ctime_nsec,
                "retained source/archive metadata changed"
            );
        }
    }
    for index in &p.indexes {
        let r: Value = serde_json::from_slice(&evidence(&index.canonical_r2_receipt)?)?;
        canonical_receipt(&r, index.epoch)?;
    }
    Ok(())
}
fn canonical_receipt(r: &Value, epoch: u64) -> Result<()> {
    ensure!(
        r["schema"] == "jetstreamer-horizon-r2-receipt-v1"
            && r["epoch"] == epoch
            && r["bucket"] == "solana-archive-with-accounts-data"
            && r["remote_sha256_readback"] == true
            && r["archive_key"] == format!("epoch-{epoch}.jet")
            && r["checksum_key"] == format!("epoch-{epoch}.jet.sha256")
            && r["archive_length"].as_u64().is_some_and(|n| n > 0)
            && r["archive_sha256"].as_str().is_some_and(valid_sha),
        "not a genuine canonical readback receipt"
    );
    Ok(())
}
// Same bounded native transport for every manager query: anonymous captured
// streams, finite process-group timeout and kernel output-size ceiling. No disk
// scratch or unbounded Command::output allocation is used.
fn native_output(program: &str, args: &[&str]) -> Result<std::process::Output> {
    use std::os::unix::process::CommandExt;
    fn capture() -> Result<File> {
        let name = CString::new("horizon-index-manager")?;
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        ensure!(fd >= 0, "manager memfd failed");
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    let out = capture()?;
    let err = capture()?;
    let mut command = Command::new("/usr/bin/timeout");
    command
        .args(["--signal=TERM", "--kill-after=1s", "5s", program])
        .args(args)
        .stdout(Stdio::from(out.try_clone()?))
        .stderr(Stdio::from(err.try_clone()?));
    unsafe {
        command.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: LIMIT + 1,
                rlim_max: LIMIT + 1,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let status = command.status()?;
    let read = |mut f: File| -> Result<Vec<u8>> {
        use std::io::{Seek, SeekFrom};
        ensure!(f.metadata()?.len() <= LIMIT, "native output exceeds bound");
        f.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        f.take(LIMIT + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() as u64 <= LIMIT, "native output grew");
        Ok(bytes)
    };
    Ok(std::process::Output {
        status,
        stdout: read(out)?,
        stderr: read(err)?,
    })
}
fn systemctl(args: &[&str]) -> Result<String> {
    let o = native_output("/usr/bin/systemctl", args)?;
    ensure!(o.status.success(), "manager query failed or timed out");
    Ok(String::from_utf8(o.stdout)?)
}
fn actor_state(
    a: &Actor,
    text: &str,
    code: Option<i32>,
    historical: Option<&Value>,
) -> Result<Value> {
    let mut s = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line.split_once('=').context("malformed manager row")?;
        ensure!(s.insert(key, value).is_none(), "duplicate manager property");
    }
    let load = s.get("LoadState").copied().context("missing LoadState")?;
    let active = s
        .get("ActiveState")
        .copied()
        .context("missing ActiveState")?;
    let sub = s.get("SubState").copied().context("missing SubState")?;
    let iid = s
        .get("InvocationID")
        .copied()
        .context("missing InvocationID")?;
    ensure!(
        ["MainPID", "ControlPID", "NRestarts"]
            .iter()
            .all(|k| s.get(k) == Some(&"0"))
            && s.get("Job").is_some_and(|v| v.is_empty() || *v == "0")
            && ((active == "inactive" && sub == "dead") || (active == "failed" && sub == "failed")),
        "actor remains active/restarting/queued or lacks explicit closure properties"
    );
    ensure!(
        iid.is_empty() || iid == a.invocation_id,
        "replacement nonempty actor invocation"
    );
    let collected = iid.is_empty();
    if load == "not-found" {
        ensure!(
            matches!(code, Some(0 | 1 | 4))
                && active == "inactive"
                && sub == "dead"
                && collected
                && s.get("Restart").is_some_and(|v| v.is_empty() || *v == "no"),
            "not a positively identified collected not-found actor"
        );
    } else {
        ensure!(
            load == "loaded" && code == Some(0) && s.get("Restart") == Some(&"no"),
            "manager query failed or actor is not loaded and non-restartable"
        );
        if collected {
            ensure!(
                active == "inactive" && sub == "dead",
                "cleared invocation is not collected inactive/dead"
            );
        }
    }
    if collected {
        let h = a
            .historical_provenance
            .as_ref()
            .context("collected actor lacks pinned historical provenance")?;
        let original =
            historical.context("collected actor historical evidence was not inspected")?;
        ensure!(
            original
                .pointer(&h.unit_json_pointer)
                .and_then(Value::as_str)
                == Some(a.unit.as_str())
                && original
                    .pointer(&h.invocation_id_json_pointer)
                    .and_then(Value::as_str)
                    == Some(a.invocation_id.as_str()),
            "historical provenance does not identify this original actor"
        );
    }
    Ok(
        json!({"unit":a.unit,"original_invocation_id":a.invocation_id,"actual_manager":s,
        "show_exit_code":code,"collected_current_invocation":collected,
        "historical_provenance":a.historical_provenance}),
    )
}
fn terminal(p: &Plan) -> Result<Value> {
    let mut states = Vec::new();
    let jobs = systemctl(&["list-jobs", "--no-legend", "--plain"])?;
    for a in p.owners.iter().flat_map(|o| &o.actors) {
        let out = native_output(
            "/usr/bin/systemctl",
            &[
                "show",
                &a.unit,
                "--all",
                "--property=LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,NRestarts,Restart,Job",
            ],
        )?;
        ensure!(
            out.stdout.len() as u64 <= LIMIT && out.stderr.len() as u64 <= LIMIT,
            "manager show output oversized"
        );
        let historical: Option<Value> = a
            .historical_provenance
            .as_ref()
            .map(|h| -> Result<Value> { Ok(serde_json::from_slice(&evidence(&h.evidence)?)?) })
            .transpose()?;
        let state = actor_state(
            a,
            std::str::from_utf8(&out.stdout)?,
            out.status.code(),
            historical.as_ref(),
        )?;
        ensure!(
            !jobs.split_whitespace().any(|v| v == a.unit),
            "queued terminal actor relaunch"
        );
        states.push(json!({"state":state,"show_stderr":std::str::from_utf8(&out.stderr)?}));
    }
    let typed_states = typed::historical(p, &jobs)?;
    let completed_check = typed::completed_current_check(p, &jobs)?;
    for root in UNIT_ROOTS {
        if !absent(Path::new(root))? {
            scan_staged(Path::new(root), p, &jobs)?;
        }
    }
    Ok(
        json!({"actual_terminal_actors":states,"queued_jobs":jobs,"staged_recipe_roots":UNIT_ROOTS,"typed_recipe_states":typed_states,"completed_current_check":completed_check}),
    )
}
fn path_reference(bytes: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && bytes.windows(needle.len()).enumerate().any(|(i, w)| {
            w == needle
                && (i + needle.len() == bytes.len()
                    || b"/\0\n\r\t '\";|&()<>[]{}".contains(&bytes[i + needle.len()]))
        })
}
fn recipe_reference(bytes: &[u8], p: &Plan) -> bool {
    typed::recipe_mentions(bytes, p)
        || legacy202::metadata_reference(bytes, p)
        || p.owners.iter().any(|o| {
            path_reference(bytes, o.root.as_os_str().as_bytes())
                || o.actors
                    .iter()
                    .any(|a| bytes.windows(a.unit.len()).any(|w| w == a.unit.as_bytes()))
        })
}
fn scan_staged(root: &Path, p: &Plan, jobs: &str) -> Result<()> {
    for e in fs::read_dir(root)? {
        let path = e?.path();
        let m = fs::symlink_metadata(&path)?;
        if m.is_dir() {
            scan_staged(&path, p, jobs)?;
            continue;
        }
        let bytes = reviewed::staged_body(&path)?;
        if typed::staged(p, &path, &bytes, jobs)? {
            continue;
        }
        if !recipe_reference(&bytes, p) {
            continue;
        }
        let allow = p
            .inert_recipes
            .iter()
            .find(|r| r.path == path)
            .context("foreign staged recipe references terminal cache owner")?;
        ensure!(
            hash(&bytes) == allow.sha256
                && !jobs.split_whitespace().any(|w| w == allow.unit)
                && typed::direct_installed_path(&path, &allow.unit),
            "changed or queued inert recipe"
        );
    }
    Ok(())
}
fn selected_parent_directories(p: &Plan) -> Result<BTreeSet<PathBuf>> {
    let mut paths = BTreeSet::new();
    for index in &p.indexes {
        let root = &p.owners.get(index.owner).context("directory owner")?.root;
        let parent = index.path.parent().context("index parent directory")?;
        ensure!(parent.starts_with(root), "index parent outside owner");
        for ancestor in parent.ancestors() {
            ensure!(ancestor.starts_with(root), "directory chain escaped owner");
            paths.insert(ancestor.to_path_buf());
            if ancestor == root {
                break;
            }
        }
    }
    Ok(paths)
}
fn references(p: &Plan) -> Result<Value> {
    let own = typed::authenticate_current(p)?;
    let mut inspected = 0u64;
    let indirect_ids = typed::indirect_inodes(p)?;
    let directory_ids: BTreeSet<_> = selected_parent_directories(p)?
        .iter()
        .map(|path| -> Result<(u64, u64)> {
            let m = fs::metadata(path)?;
            ensure!(m.is_dir(), "selected parent is not a directory");
            Ok((m.dev(), m.ino()))
        })
        .collect::<Result<_>>()?;
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        else {
            continue;
        };
        if pid.parse::<u32>()? == std::process::id() {
            ensure!(
                own["pid"] == std::process::id(),
                "own process was not authenticated"
            );
            continue;
        }
        inspected += 1;
        let proc = entry.path();
        let original_ticks = match fs::read_to_string(proc.join("stat")) {
            Ok(s) => typed::process_ticks(&s)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).context("incomplete process identity scan"),
        };
        for leaf in ["cmdline", "maps"] {
            match fs::read(proc.join(leaf)) {
                Ok(b) => {
                    ensure!(
                        !p.owners
                            .iter()
                            .any(|o| path_reference(&b, o.root.as_os_str().as_bytes())),
                        "live process references cache owner"
                    );
                    if leaf == "cmdline" {
                        for token in b.split(|c| *c == 0) {
                            let target =
                                token.split(|c| *c == b'=').next_back().unwrap_or_default();
                            if target.starts_with(b"/") {
                                let path = Path::new(std::ffi::OsStr::from_bytes(target));
                                match fs::metadata(path) {
                                    Ok(m) => ensure!(
                                        !indirect_ids.contains(&(m.dev(), m.ino())),
                                        "indirect metadata/script command inode alias"
                                    ),
                                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                                    Err(e) => {
                                        return Err(e)
                                            .context("incomplete indirect command alias scan");
                                    }
                                };
                            }
                        }
                        ensure!(
                            !typed::indirect_reference(&b, p),
                            "live process references an indirect staged readset"
                        );
                    }
                    if leaf == "maps" {
                        for i in &p.indexes {
                            ensure!(
                                !reviewed::maps_reference(&b, i.identity.device, i.identity.inode)?,
                                "mapped cache inode, including alias with closed fd"
                            );
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).context("incomplete process scan"),
            }
        }
        let mut links = vec![proc.join("cwd"), proc.join("root"), proc.join("exe")];
        match fs::read_dir(proc.join("fd")) {
            Ok(fds) => {
                for f in fds {
                    links.push(f?.path());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).context("incomplete descriptor scan"),
        }
        for path in links {
            match fs::read_link(&path) {
                Ok(link) => {
                    let text = link.to_string_lossy();
                    let actual = Path::new(text.strip_suffix(" (deleted)").unwrap_or(&text));
                    ensure!(
                        !p.owners.iter().any(|o| actual.starts_with(&o.root)),
                        "live process link references cache owner"
                    );
                    match fs::metadata(&path) {
                        Ok(m) => ensure!(
                            !p.indexes.iter().any(
                                |i| m.dev() == i.identity.device && m.ino() == i.identity.inode
                            ) && !indirect_ids.contains(&(m.dev(), m.ino()))
                                && !(m.is_dir() && directory_ids.contains(&(m.dev(), m.ino()))),
                            "live descriptor/index or reopenable-directory inode alias"
                        ),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e).context("incomplete link inode scan"),
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).context("incomplete process link scan"),
            }
        }
        match fs::read_to_string(proc.join("stat")) {
            Ok(current) => ensure!(
                typed::process_ticks(&current)? == original_ticks,
                "PID reused during reference scan"
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).context("incomplete final process identity scan"),
        };
    }
    Ok(
        json!({"processes_inspected":inspected,"target_inode_count":p.indexes.len(),"references":[],"checked":["commands","device-inode-maps","cwd","root","exe","file-descriptors","descriptor-inodes"],"permission_errors_ignored":false,"authenticated_current_operation":own}),
    )
}
fn child(name: &str) -> Result<CString> {
    ensure!(
        Path::new(name).components().count() == 1
            && matches!(
                Path::new(name).components().next(),
                Some(std::path::Component::Normal(_))
            ),
        "unsafe mutation child"
    );
    Ok(CString::new(name)?)
}
fn rename_child(a: &File, old: &str, b: &File, new: &str) -> Result<()> {
    ensure!(
        unsafe {
            libc::renameat2(
                a.as_raw_fd(),
                child(old)?.as_ptr(),
                b.as_raw_fd(),
                child(new)?.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
        "exact no-clobber rename failed: {}",
        std::io::Error::last_os_error()
    );
    a.sync_all()?;
    b.sync_all()?;
    Ok(())
}
fn write_once(dir: &File, name: &str, value: &Value) -> Result<()> {
    let temp = format!(".{name}.{}-{}.tmp", std::process::id(), now()?);
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            child(&temp)?.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o400,
        )
    };
    ensure!(fd >= 0, "receipt create failed");
    let mut f = unsafe { File::from_raw_fd(fd) };
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    f.write_all(&bytes)?;
    f.sync_all()?;
    rename_child(dir, &temp, dir, name)
}
fn record(state: &Path, name: &str, op: &str) -> Result<Value> {
    let v: Value = serde_json::from_slice(&small(&state.join(name), 0)?)?;
    ensure!(
        v["operation"] == op,
        "interrupted operation/plan identity changed"
    );
    Ok(v)
}
fn file_record(state: &Path, name: &str, op: &str, index: &Index) -> Result<Value> {
    let v = record(state, name, op)?;
    bind_file_record(&v, op, index)?;
    Ok(v)
}
fn bind_file_record(v: &Value, op: &str, index: &Index) -> Result<()> {
    ensure!(
        v["operation"] == op && v["index"] == serde_json::to_value(index)?,
        "interrupted file receipt binds another index"
    );
    Ok(())
}
fn lifecycle(
    source: bool,
    quarantine: bool,
    intent: bool,
    closure: bool,
    done: bool,
) -> Result<()> {
    ensure!(
        !(source && quarantine) && (!closure || intent),
        "invalid custody lifecycle"
    );
    if done {
        ensure!(
            !source && !quarantine && intent && closure,
            "completed namespace reappeared or lacks unlink chain"
        );
    } else if !intent {
        ensure!(
            source && !quarantine && !closure,
            "fresh cache source missing/foreign quarantine"
        );
    } else if source {
        ensure!(
            !quarantine && !closure,
            "original namespace reappeared after closure"
        );
    } else if !quarantine {
        ensure!(closure, "missing cache lacks durable unlink closure");
    }
    Ok(())
}
fn free(path: &Path) -> Result<u64> {
    let p = CString::new(path.as_os_str().as_bytes())?;
    let mut s = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(p.as_ptr(), s.as_mut_ptr()) } == 0,
        "statvfs"
    );
    let s = unsafe { s.assume_init() };
    s.f_bavail
        .checked_mul(s.f_frsize)
        .context("free bytes overflow")
}
// Imported235/237 profiles retain quarantine on each exact original parent.
// This avoids EXDEV across separate systemd ReadWritePaths binds. Legacy profile
// custody paths stay unchanged; old Root state/receipts are never moved/deleted.
fn quarantine_path(p: &Plan, index: &Index, ordinal: usize, op: &str) -> Result<PathBuf> {
    let owner = p.owners.get(index.owner).context("quarantine owner")?;
    quarantine_destination(
        index.path.parent().context("quarantine parent")?,
        &p.state,
        ordinal,
        op,
        (owner.imported_canonical.is_some() && p.current_operation.is_some())
            || legacy202::same_parent(p, index),
    )
}
fn quarantine_destination(
    parent: &Path,
    state: &Path,
    ordinal: usize,
    op: &str,
    same_parent: bool,
) -> Result<PathBuf> {
    if same_parent {
        ensure!(valid_sha(op), "invalid operation quarantine digest");
        Ok(parent.join(format!(".jetstreamer-index-{op}-{ordinal}.quarantine")))
    } else {
        Ok(state.join(format!("index-{ordinal}.quarantine")))
    }
}
fn directory_at(dir: &File, path: &Path) -> Result<()> {
    ensure!(path.canonicalize()? == path, "directory path alias");
    let actual = fs::symlink_metadata(path)?;
    let opened = dir.metadata()?;
    ensure!(
        actual.is_dir() && actual.dev() == opened.dev() && actual.ino() == opened.ino(),
        "parent directory path replaced"
    );
    Ok(())
}
fn anchor_matches(dir: &File, name: &str, index: &Index) -> Result<()> {
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            child(name)?.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    ensure!(fd >= 0, "anchored index disappeared");
    let file = unsafe { File::from_raw_fd(fd) };
    ensure!(
        identity(&file.metadata()?) == index.identity,
        "anchored index name replaced"
    );
    Ok(())
}
fn run(p: &Plan, op: &str, self_sha: &str, check: bool) -> Result<Value> {
    validate_plan(p)?;
    legacy202::action_allowed(p, check)?;
    legacy202::authenticate_original(p)?;
    typed::authenticate_current(p)?;
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&p.state)?;
    let m = dir.metadata()?;
    ensure!(
        p.state.canonicalize()? == p.state
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o7777 == 0o700,
        "state must be exact Root0700 directory"
    );
    ensure!(
        unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "retirement already owned"
    );
    preserved(p)?;
    let actors = terminal(p)?;
    let initial_references = references(p)?;
    let intent = p.state.join("intent.json");
    let completion = p.state.join("completion.json");
    if !absent(&intent)? {
        let first = record(&p.state, "intent.json", op)?;
        ensure!(
            first["tool_sha256"] == self_sha
                && first["indexes_and_original_headers"] == serde_json::to_value(&p.indexes)?
                && first["preserved_source_archives"] == serde_json::to_value(&p.owners)?,
            "different retirement tool or original selection on resume"
        );
    }
    if !absent(&completion)? {
        let first = record(&p.state, "intent.json", op)?;
        ensure!(
            first["tool_sha256"] == self_sha,
            "different retirement tool on resume"
        );
        let done = record(&p.state, "completion.json", op)?;
        ensure!(done["status"] == "complete", "invalid completion status");
        for (n, i) in p.indexes.iter().enumerate() {
            ensure!(
                absent(&i.path)? && absent(&quarantine_path(p, i, n, op)?)?,
                "completed target reappeared"
            );
            file_record(&p.state, &format!("file-{n}.intent.json"), op, i)?;
            file_record(&p.state, &format!("file-{n}.closure.json"), op, i)?;
        }
        return Ok(done);
    }
    for (n, i) in p.indexes.iter().enumerate() {
        let q = quarantine_path(p, i, n, op)?;
        let a = !absent(&i.path)?;
        let b = !absent(&q)?;
        let c = !absent(&p.state.join(format!("file-{n}.intent.json")))?;
        let d = !absent(&p.state.join(format!("file-{n}.closure.json")))?;
        ensure!(
            !absent(&intent)? || (!b && !c && !d),
            "per-file custody lacks global intent"
        );
        lifecycle(a, b, c, d, false)?;
        if c {
            file_record(&p.state, &format!("file-{n}.intent.json"), op, i)?;
        }
        if d {
            file_record(&p.state, &format!("file-{n}.closure.json"), op, i)?;
        }
        ensure!(
            i.identity.device == m.dev(),
            "quarantine filesystem differs"
        );
        if a {
            read_header(i, &i.path, true)?;
        } else if b {
            read_header(i, &q, false)?;
        } else {
            file_record(&p.state, &format!("file-{n}.closure.json"), op, i)?;
        }
    }
    if check {
        return Ok(
            json!({"status":"check-passed","operation":op,"indexes":p.indexes,"preserved_source_archives":p.owners,"source_review":p.source_review,"terminal_closure":actors,"reference_closure":initial_references,"payload_read":false,"capacity_credit_bytes":0}),
        );
    }
    if absent(&intent)? {
        write_once(
            &dir,
            "intent.json",
            &json!({"operation":op,"tool_sha256":self_sha,"at":now()?,"available_bytes_before":free(&p.state)?,"indexes_and_original_headers":p.indexes,"preserved_source_archives":p.owners,"terminal_closure":actors,"reference_closure":initial_references}),
        )?;
    } else {
        ensure!(
            record(&p.state, "intent.json", op)?["tool_sha256"] == self_sha,
            "different retirement tool on resume"
        );
    }
    for (n, i) in p.indexes.iter().enumerate() {
        let q = quarantine_path(p, i, n, op)?;
        let qname = q
            .file_name()
            .and_then(|s| s.to_str())
            .context("quarantine basename")?
            .to_owned();
        let qparent = q.parent().context("quarantine parent")?;
        ensure!(
            qparent.canonicalize()? == qparent,
            "quarantine parent alias"
        );
        let qdir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(qparent)?;
        let finame = format!("file-{n}.intent.json");
        let clname = format!("file-{n}.closure.json");
        preserved(p)?;
        terminal(p)?;
        references(p)?;
        if !absent(&i.path)? {
            read_header(i, &i.path, true)?;
            if absent(&p.state.join(&finame))? {
                write_once(
                    &dir,
                    &finame,
                    &json!({"operation":op,"index":i,"at":now()?}),
                )?;
            } else {
                file_record(&p.state, &finame, op, i)?;
            }
            let parent = i.path.parent().context("source parent")?;
            ensure!(parent.canonicalize()? == parent, "source parent alias");
            let same_parent =
                p.owners[i.owner].imported_canonical.is_some() && p.current_operation.is_some();
            let a = if same_parent {
                ensure!(
                    parent == qparent,
                    "imported quarantine moved from exact source parent"
                );
                qdir.try_clone()?
            } else {
                OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                    .open(parent)?
            };
            directory_at(&a, parent)?;
            directory_at(&qdir, qparent)?;
            anchor_matches(
                &a,
                i.path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .context("source name")?,
                i,
            )?;
            rename_child(
                &a,
                i.path
                    .file_name()
                    .unwrap()
                    .to_str()
                    .context("cache filename")?,
                &qdir,
                &qname,
            )?;
        }
        if !absent(&q)? {
            read_header(i, &q, false)?;
            ensure!(absent(&i.path)?, "cache source reappeared");
            preserved(p)?;
            let terminal_closure = terminal(p)?;
            let reference_closure = references(p)?;
            if absent(&p.state.join(&clname))? {
                write_once(
                    &dir,
                    &clname,
                    &json!({"operation":op,"index":i,"original_header_preserved":true,"terminal_closure":terminal_closure,"reference_closure":reference_closure,"at":now()?}),
                )?;
            } else {
                file_record(&p.state, &clname, op, i)?;
            }
            read_header(i, &q, false)?;
            directory_at(&qdir, qparent)?;
            anchor_matches(&qdir, &qname, i)?;
            ensure!(
                unsafe { libc::unlinkat(qdir.as_raw_fd(), child(&qname)?.as_ptr(), 0) } == 0,
                "exact quarantine unlink failed"
            );
            qdir.sync_all()?;
        } else {
            file_record(&p.state, &finame, op, i)?;
            file_record(&p.state, &clname, op, i)?;
        }
        ensure!(absent(&i.path)? && absent(&q)?, "cache remains/reappeared");
        preserved(p)?;
    }
    let initial = record(&p.state, "intent.json", op)?;
    let done = json!({"operation":op,"status":"complete","at":now()?,"available_bytes_before":initial["available_bytes_before"],"available_bytes_after":free(&p.state)?,"all_other_files_and_directories_preserved":true,"archive_body_read_or_hashed":false,"remote_mutations":false,"r2_mutations":false,"capacity_credit_requires_fresh_independent_observation":true});
    write_once(&dir, "completion.json", &done)?;
    Ok(done)
}
fn main() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "must run as root");
    let a: Vec<String> = std::env::args().skip(1).collect();
    ensure!(
        (a.len() == 6 || a.len() == 7)
            && a[0] == "--plan"
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256"
            && (a.len() == 6
                || ["--check-only", "--retirement-preflight"].contains(&a[6].as_str())),
        "usage: --plan PATH --plan-sha256 HEX --self-sha256 HEX [--check-only|--retirement-preflight]"
    );
    ensure!(
        (valid_sha(&a[3]) || a[3] == "env") && valid_sha(&a[5]),
        "invalid independent digest"
    );
    let mut f = File::open("/proc/self/exe")?;
    let mut h = Sha256::new();
    let mut b = [0; 65536];
    loop {
        let n = f.read(&mut b)?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    ensure!(format!("{:x}", h.finalize()) == a[5], "self digest differs");
    let plan_sha = if a[3] == "env" {
        std::env::var("HORIZON_INDEX_PLAN_SHA256")
            .context("missing independent plan digest transport")?
    } else {
        a[3].clone()
    };
    ensure!(valid_sha(&plan_sha), "invalid plan digest transport");
    let bytes = small(Path::new(&a[1]), 0)?;
    ensure!(hash(&bytes) == plan_sha, "plan digest differs");
    let p: Plan = serde_json::from_slice(&bytes)?;
    println!("{}", run(&p, &plan_sha, &a[5], a.len() == 7)?);
    Ok(())
}
#[cfg(test)]
mod tests {
    include!("terminal_compact_index/tests.rs");
}
