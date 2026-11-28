//! Exact old lane-d157 partial retirement after genuine node_02 custody.
//! Independent profile; every existing route, snapshot and metadata remains unchanged.
use super::*;
use std::{
    collections::BTreeMap,
    ffi::CString,
    os::fd::{AsRawFd, FromRawFd},
};
#[path = "holding_epoch157_laned_consumers.rs"]
mod consumers;
#[path = "holding_epoch157_laned_creator_fence.rs"]
mod creator_fence;

const SOURCE: &str = "/home/sol/.jetstreamer-private/epochs150-173-20260923-v2/lane-d/private/destination-0b7ad71c41faf6eb847f0327cab4c67067e2b6ff55be1f2ab499ca6787159dcc/work/root-cohort-157-157/run-642701-1790799438469365438/archives/epoch-157.jet";
const RUN: &str = "/home/sol/.jetstreamer-private/epochs150-173-20260923-v2/lane-d/private/destination-0b7ad71c41faf6eb847f0327cab4c67067e2b6ff55be1f2ab499ca6787159dcc/work/root-cohort-157-157/run-642701-1790799438469365438";
const DESTINATION: &str = "/home/sol/.jetstreamer-private/epochs150-173-20260923-v2/lane-d/private/destination-0b7ad71c41faf6eb847f0327cab4c67067e2b6ff55be1f2ab499ca6787159dcc";
const SNAPSHOT: &str = "/home/sol/.jetstreamer-private/epochs150-173-20260923-v2/lane-d/private/destination-0b7ad71c41faf6eb847f0327cab4c67067e2b6ff55be1f2ab499ca6787159dcc/work/root-cohort-157-157/run-642701-1790799438469365438/inputs/snapshot-67823809-2mfgWDcrXmDMRrPtUJtJgE1oJ9jKgRZ9ETru9XjsdmuF.tar.zst";
const LENGTH: u64 = 122_379_391_003;
const ALLOCATED: u64 = 122_379_591_680;
const INODE: u64 = 99418151;
const ELIGIBILITY: &str =
    "/usr/local/lib/jetstreamer/horizon-closed157-laned-holding-plan-20261119-v1/eligibility.json";
const INSPECTION: &str =
    "/var/lib/jetstreamer/epoch157-laned-holding-review-20261119-v1/INSPECTION.json";
const PARK_PLAN: &str =
    "/usr/local/lib/jetstreamer/horizon-closed157-laned-holding-plan-20261119-v1/plan.json";
const MAPPING: &str = "/usr/local/lib/jetstreamer/horizon-node02-holding-20261023-v1/mapping.json";
const MAPPING_SHA: &str = "61f7601f78a7aa1f71394a020cbbb28aa9dbd85de858f139def1c989f2b2a89e";
const PARK: &str = "horizon-closed157-laned-park-20261119-v1.service";
const INSPECTOR: &str = "horizon-157-laned-inspection-20261119-v2.service";
const INSPECTOR_IID: &str = "b64669184d8c4214a5f0c3eb6a056d88";
const INSPECTOR_IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-closed157-laned-inspector-20261119-v1/inspector";
const INSPECTOR_SHA: &str = "7f5d6751f04fc1517508c007d9a7afa93e03af39d4645d048abc57ef99113a43";
const INSPECTOR_PROOF: &str =
    "/usr/local/lib/jetstreamer/horizon-closed157-laned-inspector-20261119-v1/build-proof.json";
const INSPECTOR_PROOF_SHA: &str =
    "075a7ac35c7baf6603c78d743cd4f7ad1f8d2f921006a8bdceb2f18fbcc265da";
const PRODUCER: &str = "jetstreamer-root-sweep-historical-151-173-v91-e157-157-lane-d-63.service";
const MUTATION_LOCK: &str = "/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock";
const EPOCH_LOCK: &str = "/home/sol/.jetstreamer-private/epochs150-173-20260923-v2/lane-d/private/destination-0b7ad71c41faf6eb847f0327cab4c67067e2b6ff55be1f2ab499ca6787159dcc/locks/epoch-157.lock";
const QUARANTINE: &str = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/retirements/epoch157-laned-original.jet";
const STATE_SHA: &str = "adf94e5dfdc9eeac826334a65f2e6026a140b04bc5fc34c8123f97513d2ada3d";
const LIFECYCLE: &str =
    "/usr/local/lib/jetstreamer/horizon-holding157-laned-retirement-20261119-v2";
// Runtime sealing precedes census/review, and check receipts precede execution
// plans. Keep their immutable versioned bundles separate from the runtime.
const EVIDENCE_ROOT: &str = "/var/lib/jetstreamer/holding157-laned-retirement-evidence";
pub(super) fn inspect_consumers(spec: &Bound) -> Result<()> {
    consumers::inspect(spec)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Retire {
    schema: String,
    archive_sha256: String,
    mapping: Bound,
    eligibility: Bound,
    inspection: Bound,
    custody: Bound,
    park_plan: Bound,
    park_start: Bound,
    park_terminal: Bound,
    inspector_image: Bound,
    inspector_provenance: Bound,
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
    ensure!(path.is_absolute(), "157laned directory must be absolute");
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
                    "157laned no-follow parent open failed: {}",
                    std::io::Error::last_os_error()
                );
                dir = unsafe { File::from_raw_fd(fd) };
            }
            _ => bail!("157laned noncanonical parent component"),
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
        "157laned retained artifact changed"
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
        "157laned retained input census exceeded bound"
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
        md.dev() == 64512
            && md.ino() == 99419227
            && md.uid() == 1001
            && md.gid() == 1003
            && md.mode() & 0o7777 == 0o700,
        "157laned run replaced"
    );
    let scratch = run.join("scratch");
    let sm = directory(&scratch)?.metadata()?;
    ensure!(
        sm.dev() == 64512
            && sm.ino() == 99419241
            && sm.uid() == 1001
            && sm.gid() == 1003
            && sm.mode() & 0o7777 == 0o700,
        "157laned retained scratch root replaced"
    );
    let archives = directory(&run.join("archives"))?.metadata()?;
    let destination = directory(Path::new(DESTINATION))?.metadata()?;
    for (metadata, inode) in [(&archives, 99419240), (&destination, 94109733)] {
        ensure!(
            metadata.dev() == 64512
                && metadata.ino() == inode
                && metadata.uid() == 1001
                && metadata.gid() == 1003
                && metadata.mode() & 0o7777 == 0o700,
            "157laned preserved directory replaced"
        );
    }
    let state = run.join("cohort-state.json");
    let st = fs::symlink_metadata(&state)?;
    ensure!(
        st.ino() == 99419235 && st.len() == 222,
        "157laned state changed"
    );
    let state_id = preserved_entry(&state)?;
    let bytes = read_stable_bounded(&state, 222, "157laned retained state")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == STATE_SHA,
        "157laned cohort state digest changed"
    );
    let mut inputs = BTreeMap::new();
    walk_inputs(&run.join("inputs"), &mut inputs, 0)?;
    ensure!(
        preserved_entry(Path::new(SNAPSHOT))?
            == json!([
                64512, 99418792, 1001, 1003, 33152, 1, 1663314014, 3248672, 1790799461, 181574643,
                1790799462, 272581851
            ]),
        "157laned exact preserved sibling snapshot changed"
    );
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
        "archives_directory":stable_directory(&archives)}),
    )
}
fn locks() -> Result<Vec<(PathBuf, File, Value)>> {
    [(MUTATION_LOCK, 101135013), (EPOCH_LOCK, 94109798)]
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
                    && md.len() == 0
                    && md.nlink() == 1
                    && md.mode() & 0o7777 == 0o600,
                "157laned exact existing lock changed"
            );
            let before = preserved_entry(&path)?;
            ensure!(
                unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
                "157laned shared/epoch lock occupied"
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
            "157laned lock changed while held"
        );
    }
    Ok(())
}
fn source_identity(path: &Path) -> Result<FileIdentity> {
    ensure!(
        (path == Path::new(SOURCE) || path == Path::new(QUARANTINE))
            && path.canonicalize()? == path,
        "foreign or aliased157 source"
    );
    let id = regular_identity(path)?;
    let md = fs::symlink_metadata(path)?;
    ensure!(
        id.device == 64512
            && id.inode == INODE
            && id.length == LENGTH
            && id.modified_seconds == 1791080938
            && id.modified_nanoseconds == 139629319
            && md.uid() == 1001
            && md.gid() == 1003
            && md.mode() & 0o7777 == 0o600
            && md.nlink() == 1
            && md.blocks().checked_mul(512) == Some(ALLOCATED),
        "157laned exact partial identity changed"
    );
    if path == Path::new(SOURCE) {
        ensure!(
            md.ctime() == 1791080938 && md.ctime_nsec() == 139629319,
            "157laned original source metadata changed"
        );
    }
    Ok(id)
}
fn native(unit: &str) -> Result<Value> {
    let out = std::process::Command::new("/usr/bin/systemctl").args(["show",unit,
        "-pId,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,ControlGroup,Job,Result,ExecMainStatus,Restart,NRestarts,TriggeredBy,Triggers,ExecCondition,ExecStartPre,ExecStart,ExecStartPost,ExecStop,ExecStopPost,FragmentPath,DropInPaths"]).output()?;
    ensure!(
        out.status.success() && out.stderr.is_empty() && out.stdout.len() <= 256 << 10,
        "157laned native owner query failed"
    );
    let mut map = serde_json::Map::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (key, value) = line.split_once('=').context("157laned native field")?;
        ensure!(
            map.insert(key.into(), json!(value)).is_none(),
            "duplicate native field"
        );
    }
    // systemctl omits empty Exec arrays even with --all. Only a positively
    // typed empty D-Bus reply can fill an omitted property.
    for property in [
        "ExecCondition",
        "ExecStartPre",
        "ExecStart",
        "ExecStartPost",
        "ExecStop",
        "ExecStopPost",
    ] {
        if !map.contains_key(property) {
            let reply = std::process::Command::new("/usr/bin/busctl")
                .args([
                    "--system",
                    "--json=short",
                    "get-property",
                    "org.freedesktop.systemd1",
                    &unit_object_path(unit),
                    "org.freedesktop.systemd1.Service",
                    property,
                ])
                .output()?;
            ensure!(
                reply.status.success() && reply.stderr.is_empty() && reply.stdout.len() <= 4096,
                "157laned typed native property unavailable: {property}"
            );
            typed_empty_exec(&reply.stdout)?;
            map.insert(property.into(), json!(""));
        }
    }
    Ok(Value::Object(map))
}
fn unit_object_path(unit: &str) -> String {
    let encoded: String = unit
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() {
                char::from(b).to_string()
            } else {
                format!("_{b:02x}")
            }
        })
        .collect();
    format!("/org/freedesktop/systemd1/unit/{encoded}")
}
fn typed_empty_exec(bytes: &[u8]) -> Result<()> {
    let value: Value = serde_json::from_slice(bytes)?;
    ensure!(
        value == json!({"type":"a(sasbttttuii)","data":[]}),
        "157laned command array is not positively typed empty"
    );
    Ok(())
}
fn exact_retained_terminal(row: &Value, unit: &str) -> Result<bool> {
    // Preserve the original successful/failed bookkeeping evidence. These
    // exact completed invocations have no executing process or activation;
    // semantic closure independently reviews their actual archive scope.
    let retained: Vec<Value> =
        serde_json::from_str(include_str!("testdata/holding157-terminal-consumers.json"))?;
    let Some(expected) = retained.iter().find(|entry| entry["Id"] == unit) else {
        return Ok(false);
    };
    for (key, value) in expected.as_object().context("terminal fixture")? {
        ensure!(
            row[key] == *value,
            "157laned retained terminal changed: {unit}/{key}"
        );
    }
    for key in [
        "ControlGroup",
        "Job",
        "TriggeredBy",
        "Triggers",
        "DropInPaths",
        "ExecCondition",
        "ExecStartPre",
        "ExecStartPost",
        "ExecStop",
        "ExecStopPost",
    ] {
        ensure!(
            row[key] == "",
            "157laned retained terminal has dispatch: {unit}/{key}"
        );
    }
    for (key, value) in [
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("Restart", "no"),
        ("NRestarts", "0"),
    ] {
        ensure!(
            row[key] == value,
            "157laned retained terminal not drained: {unit}/{key}"
        );
    }
    Ok(true)
}
fn closed(row: &Value, unit: &str) -> Result<()> {
    if exact_retained_terminal(row, unit)? {
        return Ok(());
    }
    ensure!(
        row["Id"] == unit
            && row["ActiveState"] == "inactive"
            && row["SubState"] == "dead"
            && row["Job"] == ""
            && (row["MainPID"].is_null() || row["MainPID"] == "0")
            && (row["ControlPID"].is_null() || row["ControlPID"] == "0"),
        "157laned owner active or queued: {unit}"
    );
    if unit == PRODUCER {
        ensure!(
            row["LoadState"] == "not-found"
                && row["MainPID"] == "0"
                && row["ControlPID"] == "0"
                && [
                    "InvocationID",
                    "ControlGroup",
                    "FragmentPath",
                    "DropInPaths",
                    "TriggeredBy",
                    "Triggers",
                    "ExecCondition",
                    "ExecStartPre",
                    "ExecStart",
                    "ExecStartPost",
                    "ExecStop",
                    "ExecStopPost"
                ]
                .iter()
                .all(|key| row[*key] == ""),
            "original157 owner has current dispatch or activation state"
        );
    }
    Ok(())
}
fn park_shape(row: &Value, iid: &str) -> Result<()> {
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "actual park invocation required"
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
            && row["NRestarts"] == "0"
            && row["TriggeredBy"] == "",
        "157laned park is not the exact successful terminal invocation"
    );
    Ok(())
}
fn park_evidence(p: &Retire, start: &Value, proof: &Value) -> Result<()> {
    let iid = proof["invocation_id"]
        .as_str()
        .context("recorded park invocation")?;
    ensure!(
        proof["schema"] == "horizon-closed157-laned-park-terminal-v1"
            && proof["unit"] == PARK
            && proof["park_plan"] == serde_json::to_value(&p.park_plan)?
            && start["schema"] == "horizon-exact-holding157-start-event-v1"
            && start["native"]["Id"] == PARK
            && start["native"]["InvocationID"] == iid
            && start["native"]["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|pid| pid > 0)
            && start["native"]["ActiveState"] == "active"
            && start["native"]["SubState"] == "running"
            && start["native"]["NRestarts"] == "0"
            && start["admission"]["schema"] == "horizon-closed157-laned-holding-admission-v1"
            && start["admission"]["plan"] == PARK_PLAN
            && start["admission"]["source_sha256"] == p.archive_sha256
            && start["admission"]["source_length"] == LENGTH
            && start["admission"]["inspection"]["path"] == INSPECTION
            && start["admission"]["inspection"]["sha256"] == p.inspection.sha256
            && start["admission"]["inspection"]["unit"] == INSPECTOR
            && start["admission"]["inspection"]["invocation_id"] == INSPECTOR_IID
            && start["admission"]["inspection"]["exit_code"] == 0,
        "foreign or invented park terminal evidence"
    );
    park_shape(&proof["native"], iid)?;
    Ok(())
}
fn park(p: &Retire) -> Result<Value> {
    let start = bound(&p.park_start)?;
    let proof = bound(&p.park_terminal)?;
    park_evidence(p, &start, &proof)?;
    let iid = proof["invocation_id"]
        .as_str()
        .context("recorded park invocation")?;
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
        "{} holding-park {PARK_PLAN} --spec-sha256 {} --self-sha256 {}",
        helper.path.display(),
        p.park_plan.sha256,
        helper.sha256
    );
    let exec = proof["native"]["ExecStart"]
        .as_str()
        .context("park native command")?;
    ensure!(
        exec.contains(&format!("argv[]={argv} ;")) && exec.matches("argv[]=").count() == 1,
        "park command does not bind exact157 plan"
    );
    let row = native(PARK)?;
    park_shape(&row, iid)?;
    ensure!(
        row["ExecStart"] == proof["native"]["ExecStart"],
        "park native command changed"
    );
    Ok(row)
}
fn inspector_provenance(p: &Retire) -> Result<()> {
    ensure!(
        same_bound(&p.inspector_image, &binding(INSPECTOR_IMAGE, INSPECTOR_SHA))
            && same_bound(
                &p.inspector_provenance,
                &binding(INSPECTOR_PROOF, INSPECTOR_PROOF_SHA)
            ),
        "exact successful157 inspector provenance required"
    );
    consumers::read_artifact(&p.inspector_image, 128 << 20, true)?;
    let v = bound(&p.inspector_provenance)?;
    ensure!(
        v["schema"] == "horizon-epoch157-inspector-build-proof-v1"
            && v["commit"] == "804b31ca14878c5fb63740a27c97a5c2eb68cf40"
            && v["inspector_sha256"] == INSPECTOR_SHA
            && v["remote_containment_verified"] == true
            && v["tests_passed"] == 10
            && v["tests_failed"] == 0
            && v["clippy_exit"] == 0
            && v["build_exit"] == 0
            && v["local_retirement_authorized"] == false,
        "successful157 inspector build provenance differs"
    );
    inspector_shape(&native(INSPECTOR)?)
}
fn inspector_shape(row: &Value) -> Result<()> {
    // Bind the actual successful inspector, not the unknown original producer.
    // Original owner absence and all seven creator leases remain independent gates.
    let argv = format!("{INSPECTOR_IMAGE} --self-sha256 {INSPECTOR_SHA}");
    let exec = row["ExecStart"]
        .as_str()
        .context("inspector native command")?;
    ensure!(
        row["Id"] == INSPECTOR
            && row["LoadState"] == "loaded"
            && row["InvocationID"] == INSPECTOR_IID
            && row["ActiveState"] == "active"
            && row["SubState"] == "exited"
            && row["Result"] == "success"
            && row["ExecMainStatus"] == "0"
            && row["MainPID"] == "0"
            && row["ControlPID"] == "0"
            && row["Job"] == ""
            && row["ControlGroup"] == ""
            && row["Restart"] == "no"
            && row["NRestarts"] == "0"
            && row["TriggeredBy"] == ""
            && row["Triggers"] == ""
            && row["DropInPaths"] == ""
            && row["FragmentPath"] == format!("/run/systemd/transient/{INSPECTOR}")
            && [
                "ExecCondition",
                "ExecStartPre",
                "ExecStartPost",
                "ExecStop",
                "ExecStopPost"
            ]
            .iter()
            .all(|key| row[*key].is_null() || row[*key] == "")
            && exec.contains(&format!("argv[]={argv} ;"))
            && exec.matches("argv[]=").count() == 1,
        "157 inspector is not its exact successful terminal invocation"
    );
    Ok(())
}
fn scope(p: &Retire) -> Result<Value> {
    ensure!(
        p.schema == "jetstreamer-horizon-holding-retire157-laned-plan-v1"
            && digest(&p.archive_sha256)
            && same_bound(&p.mapping, &binding(MAPPING, MAPPING_SHA))
            && p.eligibility.path == Path::new(ELIGIBILITY)
            && digest(&p.eligibility.sha256)
            && p.park_plan.path == Path::new(PARK_PLAN)
            && digest(&p.park_plan.sha256)
            && digest(&p.inspection.sha256)
            && p.inspection.path == Path::new(INSPECTION)
            && digest(&p.inspector_image.sha256)
            && p.inspector_image
                .path
                .starts_with("/usr/local/lib/jetstreamer"),
        "foreign157 partial retirement scope"
    );
    let plan: Park = serde_json::from_value(bound(&p.park_plan)?)?;
    let e = bound(&p.eligibility)?;
    source_scope(&plan, &e)?;
    ensure!(
        plan.source == Path::new(SOURCE)
            && plan.sha256 == p.archive_sha256
            && plan.length == LENGTH
            && same_bound(&plan.mapping, &p.mapping)
            && same_bound(&plan.eligibility, &p.eligibility)
            && e["inspection"] == serde_json::to_value(binding(INSPECTION, &p.inspection.sha256))?,
        "157 park/eligibility bindings differ"
    );
    let inspected = bound(&p.inspection)?;
    ensure!(
        inspected["schema"] == "horizon-epoch157-laned-closed-partial-inspection-v1"
            && inspected["source"] == SOURCE
            && inspected["sha256"] == p.archive_sha256
            && inspected["length"] == LENGTH
            && inspected["source_stable"] == true
            && inspected["native_consumers_clear"] == true
            && inspected["creator_fence_held_across_hash"] == true
            && inspected["controller_count"] == 7
            && inspected["original_producer"] == PRODUCER
            && inspected["original_pid"] == 642701
            && inspected["original_start_ticks"] == 353584446
            && inspected["historical_stop_proven"] == false
            && inspected["original_invocation_id"].is_null()
            && inspected["source_identity"]
                == json!([
                    64512, INODE, LENGTH, 239022640, 1001, 1003, 33152, 1, 1791080938, 139629319,
                    1791080938, 139629319
                ])
            && inspected["snapshot_identity"]
                == json!([
                    64512, 99418792, 1663314014, 3248672, 1001, 1003, 33152, 1, 1790799461,
                    181574643, 1790799462, 272581851
                ])
            && inspected["complete_transitive_consumer_graph_qualified"] == false,
        "exact historical fenced157 inspection differs"
    );
    inspector_provenance(p)?;
    Ok(inspected)
}
fn exact_custody(c: &Value, p: &Retire) -> Result<()> {
    ensure!(
        c["source"] == SOURCE
            && c["sha256"] == p.archive_sha256
            && c["length"] == LENGTH
            && c["eligibility"] == serde_json::to_value(&p.eligibility)?
            && c["mapping"] == serde_json::to_value(&p.mapping)?
            && c["manifest"]["uid"] == 1001
            && c["manifest"]["gid"] == 1003
            && c["manifest"]["mode"] == 0o600,
        "157laned custody does not bind exact inspected partial"
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
        "157laned holding owner differs"
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
        "157laned held manifest changed"
    );
    let blob = head_archive(client, BUCKET, &key)
        .await?
        .context("157laned held object absent")?;
    remote_matches(&blob, &key, length, &sha, Some(&etag))?;
    Ok(blob)
}
fn closure(p: &Retire, current: Option<&Path>) -> Result<Value> {
    ensure!(
        !exists(Path::new(&format!("{SOURCE}.sha256")))?,
        "157laned partial acquired a canonical readiness sidecar"
    );
    let units = [PRODUCER.to_owned()];
    creator_fence::original_absent()?;
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
            "157laned owner changed across consumer closure"
        );
    }
    ensure!(
        self::park(p)? == park,
        "157laned park changed across closure"
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
        "unsafe laned transition record"
    );
    let bytes = read_stable_bounded(path, 1 << 20, "laned transition")?;
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
    ensure!(!moved || intent, "laned moved without intent");
    ensure!(!unlink || moved, "laned unlink without moved proof");
    ensure!(!complete || unlink, "laned complete without unlink intent");
    ensure!(!(source && quarantine), "laned duplicate local source");
    ensure!(!quarantine || intent, "laned quarantine without intent");
    ensure!(!moved || !source, "laned moved proof conflicts with source");
    ensure!(
        source || quarantine || unlink,
        "laned local absence without durable unlink intent"
    );
    ensure!(
        !complete || (!source && !quarantine),
        "laned source reappeared after completion"
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
    let started = std::time::Instant::now();
    let mut last_report = started;
    eprintln!(
        "{}",
        json!({"at":clock()?,"epoch":157,"phase":"retirement-hash-start",
        "path":path,"archive_length":expected.length,"archive_bytes_read":0})
    );
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
        if last_report.elapsed() >= std::time::Duration::from_secs(60) {
            let at = clock()?;
            eprintln!(
                "{}",
                json!({"at":at,"epoch":157,"phase":"retirement-hash-progress",
                "path":path,"archive_length":expected.length,"archive_bytes_read":expected.length-remaining,
                "elapsed_seconds":started.elapsed().as_secs(),"last_substantive_progress_unix":at,
                "verification_complete":false})
            );
            last_report = std::time::Instant::now();
        }
    }
    ensure!(
        identity(&file.metadata()?) == expected,
        "archive changed while hashing"
    );
    ensure!(
        regular_identity(path)? == expected,
        "archive namespace changed while hashing"
    );
    eprintln!(
        "{}",
        json!({"at":clock()?,"epoch":157,"phase":"retirement-hash-complete-revalidating-closure",
        "path":path,"archive_bytes_read":expected.length,"elapsed_seconds":started.elapsed().as_secs(),
        "verification_complete":false})
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
        "laned no-clobber quarantine move failed: {}",
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
        "foreign laned unlink target"
    );
    let parent = directory(path.parent().context("quarantine parent")?)?;
    let name = CString::new(path.file_name().context("quarantine name")?.as_bytes())?;
    ensure!(
        unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } == 0,
        "laned unlink failed: {}",
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
        "laned requires its sealed runtime and separate versioned evidence bundles"
    );
    scope(p)?;
    consumers::preflight(p)?;
    // Fail cheaply on stale supplied evidence; retain descriptor and freshness
    // validation after the full hash/closure below.
    if !check {
        let prior = bound(
            p.prior_check
                .as_ref()
                .context("laned execution requires sealed successful check")?,
        )?;
        prior_check_freshness(&prior, clock()?)?;
    }
    let creator_leases = creator_fence::acquire()?;
    let held = locks()?;
    let supplied: Mapping = serde_json::from_value(bound(&p.mapping)?)?;
    mapping(&supplied)?;
    ensure!(
        supplied.host == m.host && supplied.prefix == m.prefix,
        "laned holding mapping changed"
    );
    let c = bound(&p.custody)?;
    remote(client, m, &c, p).await?;
    let root = Path::new(STATE).join("retirements");
    private(&root)?;
    let source = Path::new(SOURCE);
    let quarantine = Path::new(QUARANTINE);
    let intent_path = root.join("epoch157-laned-intent.json");
    let moved_path = root.join("epoch157-laned-moved.json");
    let unlink_path = root.join("epoch157-laned-unlink-intent.json");
    let completion_path = root.join("epoch157-laned-completion.json");
    let retained = preserved()?;
    // A fresh consumer closure may change after interruption, but the exact
    // original held bytes, park invocation, custody and preserved run may not.
    let descriptor = json!({"schema":"jetstreamer-holding-retire157-laned-intent-v1",
        "source":SOURCE,"quarantine":QUARANTINE,"sha256":p.archive_sha256,"length":LENGTH,"inode":INODE,
        "eligibility":p.eligibility,"inspection":p.inspection,"custody":p.custody,"mapping":p.mapping,
        "park_plan":p.park_plan,"park_start":p.park_start,"park_terminal":p.park_terminal,
        "inspector_image":p.inspector_image,"inspector_provenance":p.inspector_provenance,"preserved":retained,
        "canonical_archive":false,"scratch_retirement_authorized":false,"resource_credit_bytes":0,
        "resource_promise_ending_authorized":false,"replay_launch_authorized":false,
        "remote_mutations":false,"r2_mutations":false});
    let expected_moved = json!({"schema":"jetstreamer-holding-retire157-laned-moved-v1","intent":descriptor,
        "local_sha256":p.archive_sha256,"local_multipart_etag":c["object_etag"]});
    let expected_unlink = json!({"schema":"jetstreamer-holding-retire157-laned-unlink-intent-v1",
        "moved":expected_moved,"authenticated_custody_revalidated":true});
    let expected_completion = json!({"schema":"jetstreamer-holding-retire157-laned-completion-v1",
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
            "laned immutable transition proof differs"
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
        creator_fence::check(&creator_leases)?;
        println!("{}", completion_path.display());
        return Ok(());
    }
    let local_proof = if let Some(path) = current {
        let id = source_identity(path)?;
        let proof = parallel_hash(path, id, DEFAULT_PART_SIZE)?;
        ensure!(
            proof.sha256_hex == p.archive_sha256 && proof.multipart_etag == c["object_etag"],
            "laned source differs from authenticated holding custody"
        );
        Some(json!({"identity":id,"sha256":proof.sha256_hex,"multipart_etag":proof.multipart_etag}))
    } else {
        None
    };
    let gate = closure(p, current)?;
    remote(client, m, &c, p).await?;
    ensure!(
        preserved()? == retained,
        "laned preserved artifacts changed during hash/closure"
    );
    check_locks(&held)?;
    creator_fence::check(&creator_leases)?;
    let attempt = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let check_path = Path::new(STATE).join("receipts").join(format!(
        "retire157-laned-check-{}-{attempt}.json",
        spec.sha256
    ));
    if check {
        ensure!(
            p.prior_check.is_none(),
            "laned check cannot borrow another check"
        );
        persist(
            &check_path,
            &json!({"schema":"jetstreamer-holding-retire157-laned-check-v1",
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
        .context("laned execution requires sealed successful check")?;
    let prior = bound(prior_binding)?;
    let at = clock()?;
    ensure!(
        prior["schema"] == "jetstreamer-holding-retire157-laned-check-v1"
            && prior["descriptor"] == descriptor
            && prior["checked"] == true
            && prior["data_removed"] == false
            && prior_check_freshness(&prior, at).is_ok(),
        "laned check stale or foreign"
    );
    // Refresh before each mutation and retain a hash-bound record of the actual
    // graph/closure used, independently of the stable interruption descriptor.
    let qualification_path = root.join(format!(
        "epoch157-laned-qualified-{}-{attempt}.json",
        spec.sha256
    ));
    persist(
        &qualification_path,
        &json!({"schema":"jetstreamer-holding-retire157-laned-qualified-v1",
        "spec":spec,"check":prior_binding,"descriptor":descriptor,"consumer_closure":p.consumer_closure,"gates":gate}),
    )?;
    if old_intent.is_none() {
        persist(&intent_path, &descriptor)?;
    }
    if current == Some(source) {
        closure(p, Some(source))?;
        remote(client, m, &c, p).await?;
        check_locks(&held)?;
        creator_fence::check(&creator_leases)?;
        ensure!(
            preserved()? == retained,
            "laned retained data changed before move"
        );
        move_exact(source, quarantine)?;
        ensure!(
            preserved()? == retained,
            "laned retained data changed after move"
        );
    }
    if exists(quarantine)? {
        let id = source_identity(quarantine)?;
        let proof = parallel_hash(quarantine, id, DEFAULT_PART_SIZE)?;
        ensure!(
            proof.sha256_hex == p.archive_sha256 && proof.multipart_etag == c["object_etag"],
            "laned quarantined bytes differ"
        );
        if old_moved.is_none() {
            persist(&moved_path, &expected_moved)?;
        }
        closure(p, Some(quarantine))?;
        remote(client, m, &c, p).await?;
        check_locks(&held)?;
        creator_fence::check(&creator_leases)?;
        if old_unlink.is_none() {
            persist(&unlink_path, &expected_unlink)?;
        }
        ensure!(
            !exists(source)? && source_identity(quarantine)? == id,
            "laned source reappeared or quarantine replaced"
        );
        ensure!(
            preserved()? == retained,
            "laned retained data changed before unlink"
        );
        unlink_exact(quarantine, id)?;
    }
    ensure!(
        !exists(source)? && !exists(quarantine)?,
        "laned partial remains"
    );
    ensure!(
        preserved()? == retained,
        "laned retained run changed after unlink"
    );
    closure(p, None)?;
    remote(client, m, &c, p).await?;
    check_locks(&held)?;
    creator_fence::check(&creator_leases)?;
    persist(&completion_path, &expected_completion)?;
    println!("{}", completion_path.display());
    Ok(())
}

fn prior_check_freshness(prior: &Value, now: u64) -> Result<()> {
    ensure!(
        prior["schema"] == "jetstreamer-holding-retire157-laned-check-v1"
            && prior["checked"] == true
            && prior["data_removed"] == false
            && prior["recorded_unix_seconds"]
                .as_u64()
                .and_then(|at| now.checked_sub(at))
                .is_some_and(|age| age <= 900),
        "laned check stale or malformed"
    );
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
    pub(super) fn fixture_plan() -> Retire {
        Retire {
            schema: "jetstreamer-horizon-holding-retire157-laned-plan-v1".into(),
            archive_sha256: "1".repeat(64),
            mapping: binding(MAPPING, MAPPING_SHA),
            eligibility: binding(ELIGIBILITY, &"2".repeat(64)),
            inspection: binding("/sealed/inspection.json", &"3".repeat(64)),
            custody: binding("/sealed/custody.json", &"a".repeat(64)),
            park_plan: binding(PARK_PLAN, &"4".repeat(64)),
            park_start: binding("/sealed/start.json", &"5".repeat(64)),
            park_terminal: binding("/sealed/terminal.json", &"b".repeat(64)),
            inspector_image: binding("/sealed/node", &"6".repeat(64)),
            inspector_provenance: binding("/sealed/provenance.json", &"7".repeat(64)),
            consumer_closure: binding("/sealed/closure.json", &"c".repeat(64)),
            prior_check: None,
        }
    }
    #[test]
    fn original_owner_must_have_no_current_activation_or_dispatch_state() {
        let mut good = json!({"Id":PRODUCER,"LoadState":"not-found","ActiveState":"inactive",
            "SubState":"dead","MainPID":"0","ControlPID":"0","Job":""});
        for key in [
            "InvocationID",
            "ControlGroup",
            "FragmentPath",
            "DropInPaths",
            "TriggeredBy",
            "Triggers",
            "ExecCondition",
            "ExecStartPre",
            "ExecStart",
            "ExecStartPost",
            "ExecStop",
            "ExecStopPost",
        ] {
            good[key] = json!("");
        }
        closed(&good, PRODUCER).unwrap();
        for (key, value) in [
            ("LoadState", "loaded"),
            ("Job", "1/start"),
            ("MainPID", "7"),
            ("ControlGroup", "/system.slice/original"),
            ("InvocationID", "a"),
            ("TriggeredBy", "resume.timer"),
            ("ExecStart", "reader original"),
            ("ExecStartPre", "reader original"),
            ("ExecStopPost", "reader original"),
        ] {
            let mut changed = good.clone();
            changed[key] = json!(value);
            assert!(closed(&changed, PRODUCER).is_err(), "{key}");
        }
        // Default Result=success on an unloaded unit is deliberately neither
        // checked nor exported as historical stop evidence.
        good["Result"] = json!("unobserved");
        closed(&good, PRODUCER).unwrap();
    }
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
        let iid = "0123456789abcdef0123456789abcdef";
        let good = json!({"Id":PARK,"InvocationID":iid,"ActiveState":"active","SubState":"exited",
            "Result":"success","ExecMainStatus":"0","MainPID":"0","ControlPID":"0","Job":"","Restart":"no","NRestarts":"0","TriggeredBy":""});
        park_shape(&good, iid).unwrap();
        for (key, value) in [
            ("InvocationID", json!("b".repeat(32))),
            ("SubState", json!("running")),
            ("MainPID", json!("1")),
            ("Job", json!("1/start")),
            ("Result", json!("exit-code")),
            ("Restart", json!("always")),
            ("NRestarts", json!("1")),
        ] {
            let mut changed = good.clone();
            changed[key] = value;
            assert!(park_shape(&changed, iid).is_err());
        }
        assert!(park_shape(&good, &"a".repeat(32)).is_err());
    }
    #[test]
    fn omitted_native_commands_require_actual_typed_empty_reply() {
        typed_empty_exec(br#"{"type":"a(sasbttttuii)","data":[]}"#).unwrap();
        for bad in [
            br#"{}"#.as_slice(),
            br#"{"type":"as","data":[]}"#,
            br#"{"type":"a(sasbttttuii)","data":[[]]}"#,
            br#"{"type":"a(sasbttttuii)"}"#,
            b"",
            b"null",
        ] {
            assert!(typed_empty_exec(bad).is_err());
        }
        assert_eq!(
            unit_object_path("one-two_3.service"),
            "/org/freedesktop/systemd1/unit/one_2dtwo_5f3_2eservice"
        );
    }
    #[test]
    fn historical_terminal_consumers_require_exact_identity_and_no_dispatch() {
        let retained: Vec<Value> =
            serde_json::from_str(include_str!("testdata/holding157-terminal-consumers.json"))
                .unwrap();
        assert_eq!(retained.len(), 4);
        for mut row in retained {
            for property in [
                "ExecCondition",
                "ExecStartPre",
                "ExecStartPost",
                "ExecStop",
                "ExecStopPost",
            ] {
                assert!(row[property].is_null());
                row[property] = json!(""); // fixture models the separately tested typed reply
            }
            let unit = row["Id"].as_str().unwrap().to_owned();
            closed(&row, &unit).unwrap();
            for (key, value) in [
                ("InvocationID", "changed"),
                ("MainPID", "1"),
                ("ControlGroup", "/x"),
                ("Job", "1/start"),
                ("TriggeredBy", "x.timer"),
                ("ExecStopPost", "/bin/true"),
                ("NRestarts", "1"),
                ("ExecStart", "changed"),
                ("Result", "changed"),
                ("FragmentPath", "/changed"),
            ] {
                let mut changed = row.clone();
                changed[key] = json!(value);
                assert!(closed(&changed, &unit).is_err(), "{unit}/{key}");
            }
            let mut foreign = row.clone();
            foreign["Id"] = json!("foreign.service");
            assert!(closed(&foreign, "foreign.service").is_err());
            let mut original = row.clone();
            original["Id"] = json!(PRODUCER);
            assert!(closed(&original, PRODUCER).is_err());
        }
    }
    #[test]
    fn prior_check_uses_unchanged_nine_hundred_second_window() {
        let good = json!({"schema":"jetstreamer-holding-retire157-laned-check-v1","checked":true,"data_removed":false,"recorded_unix_seconds":1000});
        prior_check_freshness(&good, 1000).unwrap();
        prior_check_freshness(&good, 1900).unwrap();
        assert!(prior_check_freshness(&good, 1901).is_err());
        assert!(prior_check_freshness(&good, 999).is_err());
        let mut bad = good;
        bad["data_removed"] = json!(true);
        assert!(prior_check_freshness(&bad, 1000).is_err());
    }
    #[test]
    fn genuine157_start_and_terminal_receipts_bind_the_same_transfer() {
        let start: Value =
            serde_json::from_str(include_str!("testdata/holding157-park-start.json")).unwrap();
        let terminal: Value =
            serde_json::from_str(include_str!("testdata/holding157-park-terminal.json")).unwrap();
        let mut plan = fixture_plan();
        plan.archive_sha256 = start["admission"]["source_sha256"].as_str().unwrap().into();
        plan.inspection = binding(
            INSPECTION,
            start["admission"]["inspection"]["sha256"].as_str().unwrap(),
        );
        plan.park_plan = serde_json::from_value(terminal["park_plan"].clone()).unwrap();
        park_evidence(&plan, &start, &terminal).unwrap();
        for (path, value) in [
            (
                "/schema",
                json!("horizon-exact-holding157-laned-start-event-v1"),
            ),
            ("/native/InvocationID", json!("f".repeat(32))),
            ("/native/MainPID", json!("0")),
            ("/native/NRestarts", json!("1")),
            ("/admission/plan", json!("/another-plan")),
            ("/admission/source_sha256", json!("0".repeat(64))),
            ("/admission/source_length", json!(LENGTH - 1)),
            ("/admission/inspection/invocation_id", json!("f".repeat(32))),
            ("/admission/inspection/sha256", json!("0".repeat(64))),
            ("/admission/inspection/exit_code", json!(1)),
        ] {
            let mut changed = start.clone();
            *changed.pointer_mut(path).unwrap() = value;
            assert!(park_evidence(&plan, &changed, &terminal).is_err(), "{path}");
        }
        for (path, value) in [
            ("/park_plan/sha256", json!("0".repeat(64))),
            ("/native/NRestarts", json!("1")),
            ("/native/ExecMainStatus", json!("1")),
            ("/native/InvocationID", json!("f".repeat(32))),
        ] {
            let mut changed = terminal.clone();
            *changed.pointer_mut(path).unwrap() = value;
            assert!(park_evidence(&plan, &start, &changed).is_err(), "{path}");
        }
    }
    #[test]
    fn successful_inspector_is_distinct_from_unknown_historical_producer() {
        let good = json!({"Id":INSPECTOR,"InvocationID":INSPECTOR_IID,"LoadState":"loaded",
            "ActiveState":"active","SubState":"exited","Result":"success","ExecMainStatus":"0",
            "MainPID":"0","ControlPID":"0","Job":"","ControlGroup":"","Restart":"no","NRestarts":"0",
            "TriggeredBy":"","Triggers":"","DropInPaths":"",
            "FragmentPath":format!("/run/systemd/transient/{INSPECTOR}"),
            "ExecStart":format!("{{ path={INSPECTOR_IMAGE} ; argv[]={INSPECTOR_IMAGE} --self-sha256 {INSPECTOR_SHA} ; }}")});
        inspector_shape(&good).unwrap();
        assert!(closed(&good, INSPECTOR).is_err());
        for (key, value) in [
            ("Id", PRODUCER),
            ("InvocationID", "unknown"),
            ("SubState", "running"),
            ("MainPID", "1"),
            ("NRestarts", "1"),
            ("ExecMainStatus", "1"),
            ("Job", "1/start"),
            ("TriggeredBy", "retry.timer"),
            ("Restart", "always"),
            ("ExecStartPre", "unexpected"),
            ("ExecStopPost", "unexpected"),
            ("ExecStart", "different command"),
            ("DropInPaths", "/different/override.conf"),
        ] {
            let mut changed = good.clone();
            changed[key] = json!(value);
            assert!(inspector_shape(&changed).is_err(), "{key}");
        }
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
    fn custody_cannot_borrow_another_lane_or_use_unqualified_remote_bytes() {
        let p = fixture_plan();
        let c = json!({"source":SOURCE,"sha256":p.archive_sha256,"length":LENGTH,"eligibility":p.eligibility,"mapping":p.mapping,
            "manifest":{"uid":1001,"gid":1003,"mode":0o600}});
        exact_custody(&c, &p).unwrap();
        for (key, value) in [
            ("source", json!(SOURCE.replace("lane-d", "lane-e"))),
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
