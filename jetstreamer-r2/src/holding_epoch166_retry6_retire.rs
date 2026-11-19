//! Exact old166 retry6 partial-only retirement after complete holding custody.
//! A distinct route: old166/169 profiles, scratch and canonical archives are unchanged.
use super::*;
use std::{
    collections::BTreeMap,
    ffi::CString,
    os::fd::{AsRawFd, FromRawFd},
};
#[path = "holding_epoch166_retry6_consumers.rs"]
mod consumers;

const SOURCE: &str = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry6-20261110-v1/private/destination-d53ec84bc26887772d067cda9258daa995dc2541cb1e81e71b72376b619ffe51/work/root-cohort-166-166/run-689067-1794918104133897328/archives/epoch-166.jet";
const RUN: &str = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry6-20261110-v1/private/destination-d53ec84bc26887772d067cda9258daa995dc2541cb1e81e71b72376b619ffe51/work/root-cohort-166-166/run-689067-1794918104133897328";
const DESTINATION: &str = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry6-20261110-v1/private/destination-d53ec84bc26887772d067cda9258daa995dc2541cb1e81e71b72376b619ffe51";
const SHA: &str = "c6edc4b47bb905fe8825f09155edcbc217d9ea44246a3a3b4d8deb4387384e85";
const LENGTH: u64 = 56_173_984_550;
const ALLOCATED: u64 = 56_174_063_616;
const INODE: u64 = 103678035;
const ELIGIBILITY: &str =
    "/usr/local/lib/jetstreamer/horizon-closed166-retry6-holding-plan-20261119-v1/eligibility.json";
const ELIGIBILITY_SHA: &str = "6d7243eb5912b92d96367f57c94633be768937158d16a07923669ea972e79a97";
const INSPECTION: &str =
    "/var/lib/jetstreamer/epoch166-retry6-holding-review-20261119-v1/INSPECTION.json";
const INSPECTION_SHA: &str = "c2eb4c497d23b0be00468eedc6eb8445659beb188c5bbe58bb8ec1845b6b7c7f";
const PARK_PLAN: &str =
    "/usr/local/lib/jetstreamer/horizon-closed166-retry6-holding-plan-20261119-v1/plan.json";
const PARK_PLAN_SHA: &str = "a835a7adf66726ffbdc07eb13def1b917a9de799ff3dc9062ad7441cd182c640";
const MAPPING: &str = "/usr/local/lib/jetstreamer/horizon-node02-holding-20261023-v1/mapping.json";
const MAPPING_SHA: &str = "61f7601f78a7aa1f71394a020cbbb28aa9dbd85de858f139def1c989f2b2a89e";
const PARK: &str = "horizon-closed166-retry6-park-20261119-v1.service";
const PARK_IID: &str = "afc04ba6096f4826836919c2020dcdc6";
const PARK_START: &str = "/var/lib/jetstreamer/root0832-holding166-event-20261119-v1/EVENT.json";
const PARK_START_SHA: &str = "d5beb401ed0e015f371a7123fa34c6772f2d7f88b854d4cb1a01c4c8b2f0a0bb";
const PRODUCER: &str = "horizon-qualify-166-replacement-local3retry6-20261110-v1.service";
const GUARD: &str = "horizon-guard-replacement-166-local3retry6-20261110-v1";
const MUTATION_LOCK: &str = "/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock";
const EPOCH_LOCK: &str = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry6-20261110-v1/private/destination-d53ec84bc26887772d067cda9258daa995dc2541cb1e81e71b72376b619ffe51/locks/epoch-166.lock";
const QUARANTINE: &str = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/retirements/epoch166-retry6-c6edc4b47bb905fe8825f09155edcbc217d9ea44246a3a3b4d8deb4387384e85.jet";
const STATE_SHA: &str = "ef63e2a2e443375f84b1c851c8d0ffc51454d3ef0f5bea03124f8ce3cd73e47a";
const LIFECYCLE: &str =
    "/usr/local/lib/jetstreamer/horizon-holding166-retry6-retirement-20261119-v2";
// Runtime sealing precedes census/review, and check receipts precede execution
// plans. Keep their immutable versioned bundles separate from the runtime.
const EVIDENCE_ROOT: &str = "/var/lib/jetstreamer/holding166-retry6-retirement-evidence";
pub(super) fn inspect_consumers(spec: &Bound) -> Result<()> {
    consumers::inspect(spec)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Retire {
    schema: String,
    mapping: Bound,
    eligibility: Bound,
    inspection: Bound,
    custody: Bound,
    park_terminal: Bound,
    consumer_closure: Bound,
    prior_check: Option<Bound>,
}
fn binding(path: &str, sha: &str) -> Bound {
    Bound {
        path: path.into(),
        sha256: sha.into(),
    }
}
fn same_bound(a: &Bound, b: &Bound) -> bool {
    a.path == b.path && a.sha256 == b.sha256
}
fn clock() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
fn directory(path: &Path) -> Result<File> {
    use std::os::unix::ffi::OsStrExt;
    ensure!(path.is_absolute(), "166retry6 directory must be absolute");
    let mut dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    for part in path.components() {
        match part {
            std::path::Component::RootDir => (),
            std::path::Component::Normal(name) => {
                let name = CString::new(name.as_bytes())?;
                let fd = unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                ensure!(
                    fd >= 0,
                    "166retry6 no-follow parent open failed: {}",
                    std::io::Error::last_os_error()
                );
                dir = unsafe { File::from_raw_fd(fd) };
            }
            _ => bail!("166retry6 noncanonical parent component"),
        }
    }
    Ok(dir)
}
fn stable_directory(m: &fs::Metadata) -> Value {
    json!([m.dev(), m.ino(), m.uid(), m.gid(), m.mode()])
}
fn preserved_entry(path: &Path) -> Result<Value> {
    let md = fs::symlink_metadata(path)?;
    ensure!(
        md.dev() == 64512
            && md.uid() == 1001
            && md.gid() == 1003
            && md.mode() & 0o022 == 0
            && (md.is_dir() || md.is_file())
            && (md.is_dir() || md.nlink() == 1),
        "166retry6 retained artifact changed"
    );
    Ok(json!([
        md.dev(),
        md.ino(),
        md.uid(),
        md.gid(),
        md.mode(),
        md.nlink(),
        md.len(),
        md.blocks(),
        md.mtime(),
        md.mtime_nsec(),
        md.ctime(),
        md.ctime_nsec()
    ]))
}
fn walk_inputs(path: &Path, out: &mut BTreeMap<String, Value>, depth: usize) -> Result<()> {
    ensure!(
        depth <= 32 && out.len() < 4096,
        "166retry6 retained input census exceeded bound"
    );
    out.insert(path.to_string_lossy().into_owned(), preserved_entry(path)?);
    if fs::symlink_metadata(path)?.is_dir() {
        let _ = directory(path)?;
        for entry in fs::read_dir(path)? {
            walk_inputs(&entry?.path(), out, depth + 1)?;
        }
    }
    Ok(())
}
fn preserved() -> Result<Value> {
    let run = Path::new(RUN);
    let md = directory(run)?.metadata()?;
    ensure!(
        md.dev() == 64512 && md.ino() == 103678018 && md.uid() == 1001 && md.gid() == 1003,
        "166retry6 run replaced"
    );
    let scratch = run.join("scratch");
    let sm = directory(&scratch)?.metadata()?;
    ensure!(
        sm.dev() == 64512 && sm.ino() == 103678021 && sm.uid() == 1001 && sm.gid() == 1003,
        "166retry6 retained scratch root replaced"
    );
    let state = run.join("cohort-state.json");
    let st = fs::symlink_metadata(&state)?;
    ensure!(
        st.ino() == 103678019 && st.len() == 222,
        "166retry6 state changed"
    );
    let state_id = preserved_entry(&state)?;
    let bytes = read_stable_bounded(&state, 222, "166retry6 retained state")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == STATE_SHA,
        "166retry6 cohort state digest changed"
    );
    let mut inputs = BTreeMap::new();
    walk_inputs(&run.join("inputs"), &mut inputs, 0)?;
    let ancestors: BTreeMap<_, _> = run
        .ancestors()
        .map(|path| {
            Ok((
                path.to_string_lossy().into_owned(),
                stable_directory(&directory(path)?.metadata()?),
            ))
        })
        .collect::<Result<_>>()?;
    Ok(
        json!({"run":preserved_entry(run)?,"scratch":preserved_entry(&scratch)?,"state":state_id,
        "state_sha256":STATE_SHA,"inputs":inputs,"ancestors":ancestors,
        "archives_directory":stable_directory(&directory(&run.join("archives"))?.metadata()?)}),
    )
}
fn locks() -> Result<Vec<(PathBuf, File, Value)>> {
    [(MUTATION_LOCK, 101135013), (EPOCH_LOCK, 103678014)]
        .into_iter()
        .map(|(path, inode)| {
            let path = PathBuf::from(path);
            let _parent = directory(path.parent().context("lock parent")?)?;
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)?;
            let md = file.metadata()?;
            ensure!(
                md.dev() == 64512
                    && md.ino() == inode
                    && md.uid() == 1001
                    && md.gid() == 1003
                    && md.is_file()
                    && md.nlink() == 1
                    && md.mode() & 0o7777 == 0o600,
                "166retry6 exact existing lock changed"
            );
            let before = preserved_entry(&path)?;
            ensure!(
                unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
                "166retry6 shared/epoch lock occupied"
            );
            Ok((path, file, before))
        })
        .collect()
}
fn check_locks(held: &[(PathBuf, File, Value)]) -> Result<()> {
    for (path, file, before) in held {
        ensure!(
            preserved_entry(path)? == *before
                && identity(&file.metadata()?) == regular_identity(path)?,
            "166retry6 lock changed while held"
        );
    }
    Ok(())
}
fn source_identity(path: &Path) -> Result<FileIdentity> {
    let id = regular_identity(path)?;
    let md = fs::symlink_metadata(path)?;
    ensure!(
        id.device == 64512
            && id.inode == INODE
            && id.length == LENGTH
            && id.modified_seconds == 1795004048
            && id.modified_nanoseconds == 625036367
            && md.uid() == 1001
            && md.gid() == 1003
            && md.mode() & 0o7777 == 0o600
            && md.nlink() == 1
            && md.blocks().checked_mul(512) == Some(ALLOCATED),
        "166retry6 exact partial identity changed"
    );
    Ok(id)
}
fn native(unit: &str) -> Result<Value> {
    let out = std::process::Command::new("/usr/bin/systemctl").args(["show",unit,
        "-pId,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,Job,Result,ExecMainStatus,Restart,TriggeredBy,ExecStart,FragmentPath,DropInPaths"]).output()?;
    ensure!(
        out.status.success() && out.stderr.is_empty() && out.stdout.len() <= 256 << 10,
        "166retry6 native owner query failed"
    );
    let mut map = serde_json::Map::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (key, value) = line.split_once('=').context("166retry6 native field")?;
        ensure!(
            map.insert(key.into(), json!(value)).is_none(),
            "duplicate native field"
        );
    }
    Ok(Value::Object(map))
}
fn closed(row: &Value, unit: &str) -> Result<()> {
    ensure!(
        row["Id"] == unit
            && row["ActiveState"] == "inactive"
            && row["SubState"] == "dead"
            && row["Job"] == ""
            && (row["MainPID"].is_null() || row["MainPID"] == "0")
            && (row["ControlPID"].is_null() || row["ControlPID"] == "0"),
        "166retry6 owner active or queued: {unit}"
    );
    Ok(())
}
fn park_shape(row: &Value, iid: &str) -> Result<()> {
    ensure!(
        iid == PARK_IID,
        "park invocation differs from genuine original start event"
    );
    ensure!(
        row["Id"] == PARK
            && row["InvocationID"] == iid
            && ((row["ActiveState"] == "inactive" && row["SubState"] == "dead")
                || (row["ActiveState"] == "active" && row["SubState"] == "exited"))
            && row["Result"] == "success"
            && row["ExecMainStatus"] == "0"
            && row["MainPID"] == "0"
            && row["ControlPID"] == "0"
            && row["Job"] == ""
            && row["Restart"] == "no"
            && row["TriggeredBy"] == "",
        "166retry6 park is not the exact successful terminal invocation"
    );
    Ok(())
}
fn park(p: &Retire) -> Result<Value> {
    let start = bound(&binding(PARK_START, PARK_START_SHA))?;
    let proof = bound(&p.park_terminal)?;
    let iid = proof["invocation_id"]
        .as_str()
        .context("recorded park invocation")?;
    ensure!(
        proof["schema"] == "horizon-closed166-retry6-park-terminal-v1"
            && proof["unit"] == PARK
            && proof["park_plan"] == serde_json::to_value(binding(PARK_PLAN, PARK_PLAN_SHA))?
            && start["schema"] == "horizon-exact-holding166-start-event-v1"
            && start["native"]["Id"] == PARK
            && start["native"]["InvocationID"] == PARK_IID
            && start["plan"] == proof["park_plan"]
            && start["image"] == proof["helper"],
        "foreign park terminal evidence"
    );
    park_shape(&proof["native"], iid)?;
    let helper: Bound = serde_json::from_value(proof["helper"].clone())?;
    let md = fs::symlink_metadata(&helper.path)?;
    ensure!(
        md.is_file()
            && md.uid() == 0
            && md.mode() & 0o222 == 0
            && digest(&helper.sha256)
            && hex_lower(&Sha256::digest(read_stable_bounded(
                &helper.path,
                128 << 20,
                "park helper"
            )?)) == helper.sha256,
        "recorded park helper changed"
    );
    let argv = format!(
        "{} holding-park {PARK_PLAN} --spec-sha256 {PARK_PLAN_SHA} --self-sha256 {}",
        helper.path.display(),
        helper.sha256
    );
    let exec = proof["native"]["ExecStart"]
        .as_str()
        .context("park native command")?;
    ensure!(
        exec.contains(&format!("argv[]={argv} ;")) && exec.matches("argv[]=").count() == 1,
        "park command does not bind exact held source plan"
    );
    let row = native(PARK)?;
    park_shape(&row, iid)?;
    ensure!(
        row["ExecStart"] == proof["native"]["ExecStart"],
        "park native command changed"
    );
    Ok(row)
}
fn scope(p: &Retire) -> Result<Value> {
    ensure!(
        p.schema == "jetstreamer-horizon-holding-retire166-retry6-plan-v1"
            && same_bound(&p.mapping, &binding(MAPPING, MAPPING_SHA))
            && same_bound(&p.eligibility, &binding(ELIGIBILITY, ELIGIBILITY_SHA))
            && p.inspection.sha256 == INSPECTION_SHA,
        "foreign retry6 partial retirement scope"
    );
    let plan = bound(&binding(PARK_PLAN, PARK_PLAN_SHA))?;
    let e = bound(&p.eligibility)?;
    let park_plan: Park = serde_json::from_value(plan)?;
    source_scope(&park_plan, &e)?;
    ensure!(
        park_plan.source == Path::new(SOURCE)
            && park_plan.sha256 == SHA
            && park_plan.length == LENGTH
            && same_bound(&park_plan.mapping, &p.mapping)
            && same_bound(&park_plan.eligibility, &p.eligibility)
            && e["inspection"] == serde_json::to_value(binding(INSPECTION, INSPECTION_SHA))?,
        "166retry6 park/eligibility binding differs"
    );
    let inspected = bound(&p.inspection)?;
    ensure!(
        inspected["schema"] == "horizon-epoch166-retry6-closed-prefix-inspection-v1"
            && inspected["source"] == SOURCE
            && inspected["sha256"] == SHA
            && inspected["length"] == LENGTH
            && inspected["source_stable"] == true
            && inspected["native_consumers_clear"] == true
            && inspected["source_identity"]
                == json!([
                    64512,
                    INODE,
                    LENGTH,
                    109714968u64,
                    1001,
                    1003,
                    33152,
                    1,
                    1795004048u64,
                    625036367,
                    1795004048u64,
                    625036367
                ])
            && inspected["complete_transitive_consumer_graph_qualified"] == false,
        "exact historical inspection differs"
    );
    // That historical false is preserved. The distinct fresh consumer graph below
    // must supply the missing authority; it is never inferred from this inspection.
    Ok(inspected)
}
fn exact_custody(c: &Value, p: &Retire) -> Result<()> {
    ensure!(
        c["source"] == SOURCE
            && c["sha256"] == SHA
            && c["length"] == LENGTH
            && c["eligibility"] == serde_json::to_value(&p.eligibility)?
            && c["mapping"] == serde_json::to_value(&p.mapping)?
            && c["manifest"]["uid"] == 1001
            && c["manifest"]["gid"] == 1003
            && c["manifest"]["mode"] == 0o600,
        "166retry6 custody does not bind exact inspected partial"
    );
    Ok(())
}
async fn remote(client: &Client, m: &Mapping, c: &Value, p: &Retire) -> Result<RemoteArchive> {
    let (key, etag, sha, length) = custody(c, m)?;
    exact_custody(c, p)?;
    let owner = owner_bytes(m)?;
    ensure!(
        get_mutable_object(client, BUCKET, &format!("{}owner.json", m.prefix))
            .await?
            .is_some_and(|o| o.bytes == owner),
        "166retry6 holding owner differs"
    );
    let manifest = get_mutable_object(
        client,
        BUCKET,
        c["manifest_key"].as_str().context("manifest key")?,
    )
    .await?
    .context("held manifest absent")?;
    ensure!(
        hex_lower(&Sha256::digest(&manifest.bytes)) == c["manifest_sha256"]
            && serde_json::from_slice::<Value>(&manifest.bytes)? == c["manifest"],
        "166retry6 held manifest changed"
    );
    let blob = head_archive(client, BUCKET, &key)
        .await?
        .context("166retry6 held object absent")?;
    remote_matches(&blob, &key, length, &sha, Some(&etag))?;
    Ok(blob)
}
fn closure(p: &Retire, current: Option<&Path>) -> Result<Value> {
    let units = [
        PRODUCER.to_owned(),
        format!("{GUARD}.service"),
        format!("{GUARD}.timer"),
    ];
    let mut owners = BTreeMap::new();
    for unit in units {
        let row = native(&unit)?;
        closed(&row, &unit)?;
        owners.insert(unit, row);
    }
    let park = park(p)?;
    let process = no_references(Path::new(RUN))?;
    let current_process = current.map(no_references).transpose()?;
    let graph = consumers::verify(p)?;
    for (unit, before) in &owners {
        ensure!(
            native(unit)? == *before,
            "166retry6 owner changed across consumer closure"
        );
    }
    ensure!(
        self::park(p)? == park,
        "166retry6 park changed across closure"
    );
    Ok(
        json!({"owners":owners,"park":park,"process":process,"transition_process":current_process,
        "consumer_closure":p.consumer_closure,"transitive_graph":graph}),
    )
}
fn record(path: &Path) -> Result<Option<Value>> {
    if !exists(path)? {
        return Ok(None);
    }
    let md = fs::symlink_metadata(path)?;
    ensure!(
        md.is_file()
            && md.uid() == 0
            && md.nlink() == 1
            && md.mode() & 0o222 == 0
            && md.len() <= 1 << 20,
        "unsafe retry6 transition record"
    );
    let bytes = read_stable_bounded(path, 1 << 20, "retry6 transition")?;
    Ok(Some(serde_json::from_slice(&bytes)?))
}
fn transition_shape(
    intent: bool,
    moved: bool,
    unlink: bool,
    complete: bool,
    source: bool,
    quarantine: bool,
) -> Result<()> {
    ensure!(!moved || intent, "retry6 moved without intent");
    ensure!(!unlink || moved, "retry6 unlink without moved proof");
    ensure!(!complete || unlink, "retry6 complete without unlink intent");
    ensure!(!(source && quarantine), "retry6 duplicate local source");
    ensure!(!quarantine || intent, "retry6 quarantine without intent");
    ensure!(
        !moved || !source,
        "retry6 moved proof conflicts with source"
    );
    ensure!(
        source || quarantine || unlink,
        "retry6 local absence without durable unlink intent"
    );
    ensure!(
        !complete || (!source && !quarantine),
        "retry6 source reappeared after completion"
    );
    Ok(())
}
fn parallel_hash(path: &Path, expected: FileIdentity, part_size: u64) -> Result<LocalProof> {
    ensure!(
        part_size > 0 && part_size <= DEFAULT_PART_SIZE,
        "invalid bounded hash part size"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(
        identity(&file.metadata()?) == expected,
        "archive changed before hashing"
    );
    let mut whole = Sha256::new();
    let mut combined_md5 = Md5::new();
    let mut combined_sha256 = Sha256::new();
    let mut remaining = expected.length;
    let mut parts = 0u64;
    let mut buffer = vec![0u8; usize::try_from(part_size.min(remaining))?];
    while remaining > 0 {
        let count = usize::try_from(remaining.min(part_size))?;
        file.read_exact(&mut buffer[..count])?;
        let bytes = &buffer[..count];
        let (md5, sha256) = std::thread::scope(|scope| -> Result<_> {
            let whole_worker = scope.spawn(|| whole.update(bytes));
            let md5_worker = scope.spawn(|| Md5::digest(bytes));
            let part_sha256 = Sha256::digest(bytes);
            whole_worker
                .join()
                .map_err(|_| anyhow::anyhow!("whole-file hasher panicked"))?;
            let part_md5 = md5_worker
                .join()
                .map_err(|_| anyhow::anyhow!("part MD5 hasher panicked"))?;
            Ok((part_md5, part_sha256))
        })?;
        combined_md5.update(md5);
        combined_sha256.update(sha256);
        parts += 1;
        remaining -= count as u64;
    }
    ensure!(
        identity(&file.metadata()?) == expected,
        "archive changed while hashing"
    );
    ensure!(
        regular_identity(path)? == expected,
        "archive namespace changed while hashing"
    );
    Ok(LocalProof {
        sha256_hex: format!("{:x}", whole.finalize()),
        multipart_etag: format!("{:x}-{parts}", combined_md5.finalize()),
        composite_sha256: BASE64_STANDARD.encode(combined_sha256.finalize()),
    })
}

fn move_exact(source: &Path, quarantine: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let from = directory(source.parent().context("source parent")?)?;
    let to = directory(quarantine.parent().context("quarantine parent")?)?;
    let a = CString::new(source.file_name().context("source name")?.as_bytes())?;
    let b = CString::new(
        quarantine
            .file_name()
            .context("quarantine name")?
            .as_bytes(),
    )?;
    source_identity(source)?;
    ensure!(
        unsafe {
            libc::renameat2(
                from.as_raw_fd(),
                a.as_ptr(),
                to.as_raw_fd(),
                b.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
        "retry6 no-clobber quarantine move failed: {}",
        std::io::Error::last_os_error()
    );
    from.sync_all()?;
    to.sync_all()?;
    source_identity(quarantine)?;
    Ok(())
}
fn unlink_exact(path: &Path, expected: FileIdentity) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    ensure!(
        path == Path::new(QUARANTINE) && source_identity(path)? == expected,
        "foreign retry6 unlink target"
    );
    let parent = directory(path.parent().context("quarantine parent")?)?;
    let name = CString::new(path.file_name().context("quarantine name")?.as_bytes())?;
    ensure!(
        unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } == 0,
        "retry6 unlink failed: {}",
        std::io::Error::last_os_error()
    );
    parent.sync_all()?;
    Ok(())
}

pub(super) async fn run(
    client: &Client,
    m: &Mapping,
    p: &Retire,
    spec: &Bound,
    check: bool,
) -> Result<()> {
    ensure!(
        fs::read_link("/proc/self/exe")?.parent() == Some(Path::new(LIFECYCLE))
            && evidence_bundle_path(&p.consumer_closure.path)
            && evidence_bundle_path(&spec.path),
        "retry6 requires its sealed runtime and separate versioned evidence bundles"
    );
    scope(p)?;
    let held = locks()?;
    let supplied: Mapping = serde_json::from_value(bound(&p.mapping)?)?;
    mapping(&supplied)?;
    ensure!(
        supplied.host == m.host && supplied.prefix == m.prefix,
        "retry6 holding mapping changed"
    );
    let c = bound(&p.custody)?;
    remote(client, m, &c, p).await?;
    let root = Path::new(STATE).join("retirements");
    private(&root)?;
    let source = Path::new(SOURCE);
    let quarantine = Path::new(QUARANTINE);
    let intent_path = root.join("epoch166-retry6-intent.json");
    let moved_path = root.join("epoch166-retry6-moved.json");
    let unlink_path = root.join("epoch166-retry6-unlink-intent.json");
    let completion_path = root.join("epoch166-retry6-completion.json");
    let retained = preserved()?;
    // A fresh consumer closure may change after interruption, but the exact
    // original held bytes, park invocation, custody and preserved run may not.
    let descriptor = json!({"schema":"jetstreamer-holding-retire166-retry6-intent-v1",
        "source":SOURCE,"quarantine":QUARANTINE,"sha256":SHA,"length":LENGTH,"inode":INODE,
        "eligibility":p.eligibility,"inspection":p.inspection,"custody":p.custody,"mapping":p.mapping,
        "park_terminal":p.park_terminal,"preserved":retained,
        "canonical_archive":false,"scratch_retirement_authorized":false,"resource_credit_bytes":0,
        "resource_promise_ending_authorized":false,"replay_launch_authorized":false,
        "remote_mutations":false,"r2_mutations":false});
    let expected_moved = json!({"schema":"jetstreamer-holding-retire166-retry6-moved-v1","intent":descriptor,
        "local_sha256":SHA,"local_multipart_etag":c["object_etag"]});
    let expected_unlink = json!({"schema":"jetstreamer-holding-retire166-retry6-unlink-intent-v1",
        "moved":expected_moved,"authenticated_custody_revalidated":true});
    let expected_completion = json!({"schema":"jetstreamer-holding-retire166-retry6-completion-v1",
        "intent":descriptor,"source_absent":true,"quarantine_absent":true,"preserved":retained,
        "retired_censused_physical_bytes":ALLOCATED,"actual_free_delta_claimed":false,
        "authenticated_custody_revalidated":true,"scratch_retirement_authorized":false,
        "resource_credit_bytes":0,"resource_promise_ending_authorized":false,"replay_launch_authorized":false,
        "remote_mutations":false,"r2_mutations":false});
    let old_intent = record(&intent_path)?;
    let old_moved = record(&moved_path)?;
    let old_unlink = record(&unlink_path)?;
    let old_completion = record(&completion_path)?;
    for (old, want) in [
        (&old_intent, &descriptor),
        (&old_moved, &expected_moved),
        (&old_unlink, &expected_unlink),
        (&old_completion, &expected_completion),
    ] {
        ensure!(
            old.as_ref().is_none_or(|v| v == want),
            "retry6 immutable transition proof differs"
        );
    }
    let has_source = exists(source)?;
    let has_quarantine = exists(quarantine)?;
    transition_shape(
        old_intent.is_some(),
        old_moved.is_some(),
        old_unlink.is_some(),
        old_completion.is_some(),
        has_source,
        has_quarantine,
    )?;
    let current = if has_source {
        Some(source)
    } else if has_quarantine {
        Some(quarantine)
    } else {
        None
    };
    if old_completion.is_some() {
        closure(p, None)?;
        check_locks(&held)?;
        println!("{}", completion_path.display());
        return Ok(());
    }
    let local_proof = if let Some(path) = current {
        let id = source_identity(path)?;
        let proof = parallel_hash(path, id, DEFAULT_PART_SIZE)?;
        ensure!(
            proof.sha256_hex == SHA && proof.multipart_etag == c["object_etag"],
            "retry6 source differs from authenticated holding custody"
        );
        Some(json!({"identity":id,"sha256":proof.sha256_hex,"multipart_etag":proof.multipart_etag}))
    } else {
        None
    };
    let gate = closure(p, current)?;
    remote(client, m, &c, p).await?;
    ensure!(
        preserved()? == retained,
        "retry6 preserved artifacts changed during hash/closure"
    );
    check_locks(&held)?;
    let attempt = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let check_path = Path::new(STATE).join("receipts").join(format!(
        "retire166-retry6-check-{}-{attempt}.json",
        spec.sha256
    ));
    if check {
        ensure!(
            p.prior_check.is_none(),
            "retry6 check cannot borrow another check"
        );
        persist(
            &check_path,
            &json!({"schema":"jetstreamer-holding-retire166-retry6-check-v1",
            "descriptor":descriptor,"checked":true,"data_removed":false,"local_proof":local_proof,
            "recovering_after_durable_unlink":current.is_none()&&old_unlink.is_some(),
            "consumer_closure":p.consumer_closure,"gates":gate,"recorded_unix_seconds":clock()?}),
        )?;
        println!("{}", check_path.display());
        return Ok(());
    }
    let prior_binding = p
        .prior_check
        .as_ref()
        .context("retry6 execution requires sealed successful check")?;
    let prior = bound(prior_binding)?;
    let at = clock()?;
    ensure!(
        prior["schema"] == "jetstreamer-holding-retire166-retry6-check-v1"
            && prior["descriptor"] == descriptor
            && prior["checked"] == true
            && prior["data_removed"] == false
            && prior["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t <= at && at - t <= 900),
        "retry6 check stale or foreign"
    );
    // Refresh before each mutation and retain a hash-bound record of the actual
    // graph/closure used, independently of the stable interruption descriptor.
    let qualification_path = root.join(format!(
        "epoch166-retry6-qualified-{}-{attempt}.json",
        spec.sha256
    ));
    persist(
        &qualification_path,
        &json!({"schema":"jetstreamer-holding-retire166-retry6-qualified-v1",
        "spec":spec,"check":prior_binding,"descriptor":descriptor,"consumer_closure":p.consumer_closure,"gates":gate}),
    )?;
    if old_intent.is_none() {
        persist(&intent_path, &descriptor)?;
    }
    if current == Some(source) {
        closure(p, Some(source))?;
        remote(client, m, &c, p).await?;
        check_locks(&held)?;
        ensure!(
            preserved()? == retained,
            "retry6 retained data changed before move"
        );
        move_exact(source, quarantine)?;
        ensure!(
            preserved()? == retained,
            "retry6 retained data changed after move"
        );
    }
    if exists(quarantine)? {
        let id = source_identity(quarantine)?;
        let proof = parallel_hash(quarantine, id, DEFAULT_PART_SIZE)?;
        ensure!(
            proof.sha256_hex == SHA && proof.multipart_etag == c["object_etag"],
            "retry6 quarantined bytes differ"
        );
        if old_moved.is_none() {
            persist(&moved_path, &expected_moved)?;
        }
        closure(p, Some(quarantine))?;
        remote(client, m, &c, p).await?;
        check_locks(&held)?;
        if old_unlink.is_none() {
            persist(&unlink_path, &expected_unlink)?;
        }
        ensure!(
            !exists(source)? && source_identity(quarantine)? == id,
            "retry6 source reappeared or quarantine replaced"
        );
        ensure!(
            preserved()? == retained,
            "retry6 retained data changed before unlink"
        );
        unlink_exact(quarantine, id)?;
    }
    ensure!(
        !exists(source)? && !exists(quarantine)?,
        "retry6 partial remains"
    );
    ensure!(
        preserved()? == retained,
        "retry6 retained run changed after unlink"
    );
    closure(p, None)?;
    remote(client, m, &c, p).await?;
    check_locks(&held)?;
    persist(&completion_path, &expected_completion)?;
    println!("{}", completion_path.display());
    Ok(())
}

fn evidence_bundle_path(path: &Path) -> bool {
    path.parent().is_some_and(|bundle| {
        bundle.parent() == Some(Path::new(EVIDENCE_ROOT))
            && bundle
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|name| {
                    !name.is_empty()
                        && name.len() <= 128
                        && name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
                })
    }) && path.extension().is_some_and(|s| s == "json")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn evidence_versions_are_separate_from_the_already_sealed_runtime() {
        for version in ["check-v1", "execute-v1", "renewed-closure-v2"] {
            assert!(evidence_bundle_path(
                &Path::new(EVIDENCE_ROOT).join(version).join("plan.json")
            ));
        }
        for path in [
            Path::new(LIFECYCLE).join("plan.json"),
            Path::new(EVIDENCE_ROOT).join("plan.json"),
            Path::new(EVIDENCE_ROOT).join("version/nested/plan.json"),
            Path::new(EVIDENCE_ROOT).join("../plan.json"),
            Path::new(EVIDENCE_ROOT).join("version/tool.sh"),
        ] {
            assert!(!evidence_bundle_path(&path));
        }
    }
    #[test]
    fn transitions_recover_only_durable_move_and_unlink_windows() {
        for row in [
            (false, false, false, false, true, false),
            (true, false, false, false, true, false),
            (true, false, false, false, false, true),
            (true, true, false, false, false, true),
            (true, true, true, false, false, true),
            (true, true, true, false, false, false),
            (true, true, true, true, false, false),
        ] {
            transition_shape(row.0, row.1, row.2, row.3, row.4, row.5).unwrap();
        }
        for row in [
            (false, false, false, false, false, true),
            (false, true, false, false, false, true),
            (true, false, true, false, false, false),
            (true, true, false, false, false, false),
            (true, true, true, true, true, false),
            (true, true, false, false, true, true),
        ] {
            assert!(transition_shape(row.0, row.1, row.2, row.3, row.4, row.5).is_err());
        }
    }
    #[test]
    fn park_gate_rejects_running_restarted_failed_and_foreign_invocations() {
        let iid = PARK_IID;
        let good = json!({"Id":PARK,"InvocationID":iid,"ActiveState":"active","SubState":"exited",
            "Result":"success","ExecMainStatus":"0","MainPID":"0","ControlPID":"0","Job":"","Restart":"no","TriggeredBy":""});
        park_shape(&good, iid).unwrap();
        for (key, value) in [
            ("InvocationID", json!("b".repeat(32))),
            ("SubState", json!("running")),
            ("MainPID", json!("1")),
            ("Job", json!("1/start")),
            ("Result", json!("exit-code")),
            ("Restart", json!("always")),
        ] {
            let mut changed = good.clone();
            changed[key] = value;
            assert!(park_shape(&changed, iid).is_err());
        }
        assert!(park_shape(&good, &"a".repeat(32)).is_err());
    }
    #[test]
    fn inherited_parallel_proof_matches_serial_and_rejects_replaced_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input");
        for length in [1, 63, 64, 65, 65537] {
            fs::write(
                &path,
                (0..length).map(|i| (i % 251) as u8).collect::<Vec<_>>(),
            )
            .unwrap();
            let id = regular_identity(&path).unwrap();
            for size in [63, 64, 65536, DEFAULT_PART_SIZE] {
                let a = hash_and_etag(&path, id, size).unwrap();
                let b = parallel_hash(&path, id, size).unwrap();
                assert_eq!(a.sha256_hex, b.sha256_hex);
                assert_eq!(a.multipart_etag, b.multipart_etag);
                assert_eq!(a.composite_sha256, b.composite_sha256);
            }
        }
        let id = regular_identity(&path).unwrap();
        fs::write(&path, b"changed").unwrap();
        assert!(parallel_hash(&path, id, 64).is_err());
    }
    #[test]
    fn custody_cannot_borrow_another_retry_or_use_unqualified_remote_bytes() {
        let p = Retire {
            schema: "jetstreamer-horizon-holding-retire166-retry6-plan-v1".into(),
            mapping: binding(MAPPING, MAPPING_SHA),
            eligibility: binding(ELIGIBILITY, ELIGIBILITY_SHA),
            inspection: binding("/sealed/inspection.json", INSPECTION_SHA),
            custody: binding("/sealed/custody.json", &"a".repeat(64)),
            park_terminal: binding("/sealed/terminal.json", &"b".repeat(64)),
            consumer_closure: binding("/sealed/closure.json", &"c".repeat(64)),
            prior_check: None,
        };
        let c = json!({"source":SOURCE,"sha256":SHA,"length":LENGTH,"eligibility":p.eligibility,"mapping":p.mapping,
            "manifest":{"uid":1001,"gid":1003,"mode":0o600}});
        exact_custody(&c, &p).unwrap();
        for (key, value) in [
            ("source", json!(SOURCE.replace("retry6", "retry4"))),
            ("sha256", json!("d".repeat(64))),
            ("length", json!(LENGTH + 1)),
            ("manifest", json!({"uid":1001,"gid":1003,"mode":0o100600})),
        ] {
            let mut changed = c.clone();
            changed[key] = value;
            assert!(exact_custody(&changed, &p).is_err());
        }
        let m = Mapping {
            schema: "jetstreamer-horizon-host-holding-prefix-v2".into(),
            host: HOST.into(),
            prefix: "node_02/".into(),
            user_provided_prefix: true,
            authorization_reference: "test fixture".into(),
        };
        assert!(custody(&c, &m).is_err()); // Exact local fields never substitute for full readback custody.
    }
}
