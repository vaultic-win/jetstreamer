//! Exclusive first-slot resource diagnostic. No canonical terminal checkpoint,
//! qualified segment manifest, checksum, publication or ordinary replay route.
use crate::{QualificationPlan, ReplayRunResult};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
pub const BOOTSTRAP: u64 = 70_415_741;
pub const TARGET: u64 = 70_416_000;
pub const FINAL_ROOT: u64 = 70_847_738;
pub const MEMORY: u64 = 128 << 30;
pub const EXPORT_FLOOR: u64 = 642_177_138_688;
pub const ROOT: &str = "/home/sol/.jetstreamer-private/epoch163-first-output128-20261106-v1/work";
pub const INPUTS: &str =
    "/home/sol/.jetstreamer-private/epoch163-first-output128-20261106-v1/inputs";
pub const UNIT: &str = "horizon-epoch163-first-output128-20261106-v1.service";
pub const SNAPSHOT: &str = "snapshot-70415741-2aSbRXHXZJgT4bdrY34gWizngFB527wavw6Ar9KadzUY.tar.zst";
const TAIL: &str = "snapshot-70847738-H5pk5Ew133pHrsEXH6VATUzeyAwbmHWBmANLvVdiYRnS.tar.zst";
const WORKER_SHA: &str = "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819";
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    node: Bound,
    guard: Bound,
    admission_program: Bound,
    input_policy: Bound,
    admission: Bound,
    admission_capsule: Bound,
    input_acceptance: Bound,
    first_slot_source: Bound,
    memory: Bound,
    memory_completion: Bound,
    data: Bound,
    data_completion: Bound,
    maximum_runtime_seconds: u64,
    maximum_replayed_slots: u64,
    maximum_output_bytes: u64,
    exporter_floor_bytes: u64,
}
pub fn enabled() -> bool {
    cfg!(feature = "epoch163-first-output128-diagnostic")
}
pub fn selected(p: QualificationPlan) -> bool {
    enabled()
        && p.epoch == 163
        && p.bootstrap_slot == BOOTSTRAP
        && p.replay_start == BOOTSTRAP + 1
        && p.output_slot_start == TARGET
        && p.end_inclusive == TARGET
}
fn hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn error(s: impl ToString) -> String {
    s.to_string()
}
fn identity(m: &fs::Metadata) -> (u64, u64, u64, u32, u32, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.uid(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn read(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    if !path.is_absolute() || path.canonicalize().map_err(error)? != path {
        return Err("first163 noncanonical source".into());
    }
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(error)?;
    let m = f.metadata().map_err(error)?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o222 != 0 || m.nlink() != 1 || m.len() > max {
        return Err("first163 root immutable regular source custody".into());
    }
    let mut raw = vec![];
    Read::by_ref(&mut f)
        .take(max + 1)
        .read_to_end(&mut raw)
        .map_err(error)?;
    if raw.len() as u64 != m.len()
        || identity(&m) != identity(&f.metadata().map_err(error)?)
        || identity(&m) != identity(&fs::symlink_metadata(path).map_err(error)?)
    {
        return Err("first163 source changed".into());
    }
    Ok(raw)
}
fn bound(b: &Bound) -> Result<Value, String> {
    let raw = read(&b.path, 32 << 20)?;
    if !hex(&b.sha256) || format!("{:x}", Sha256::digest(&raw)) != b.sha256 {
        return Err("first163 source SHA".into());
    }
    serde_json::from_slice(&raw).map_err(error)
}
fn normal_member(b: &Bound, mode: &str) -> Result<(), String> {
    let parent = b.path.parent().ok_or("first163 seal parent")?;
    if parent.parent() != Some(Path::new("/usr/local/lib/jetstreamer")) {
        return Err("first163 normal package namespace".into());
    }
    let seal: Value = serde_json::from_slice(&read(
        &parent.join("deployment-seal-receipt.json"),
        8 << 20,
    )?)
    .map_err(error)?;
    let name = b
        .path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("first163 seal member name")?;
    if seal["schema"] != "jetstreamer-sealed-deployment-receipt-v1"
        || seal["destination"] != parent.to_string_lossy().as_ref()
        || seal["replay_launch_authorized"] != false
        || seal["publication_authorized"] != false
        || seal["r2_mutations"] != false
        || !seal["members"].as_array().is_some_and(|v| {
            v.iter()
                .filter(|m| m["name"] == name && m["sha256"] == b.sha256 && m["mode"] == mode)
                .count()
                == 1
        })
    {
        return Err("first163 exact normal seal member".into());
    }
    Ok(())
}
pub fn expected_args() -> Vec<String> {
    vec![
        "163".into(),
        format!("{ROOT}/ledger"),
        "--verify".into(),
        format!("--qualification-end-slot={TARGET}"),
        format!("--snapshot-archive={INPUTS}/{SNAPSHOT}"),
        format!("--epoch-hashes={INPUTS}/checkpoint-names.txt"),
        format!("--horizon-output={ROOT}/output/first-output.jet"),
        format!("--replay-scratch={ROOT}/scratch"),
    ]
}
pub fn entrypoint(args: &[String]) -> Result<(), String> {
    if args != expected_args() && args != [format!("--probe-successor-boundary={TARGET}")] {
        Err("first163128 build accepts only exact private first-slot arguments or its exact metadata-only target probe; recovery/cohort/publication/other probes unavailable".into())
    } else {
        Ok(())
    }
}
fn native(p: &Plan, iid: &str) -> Result<(), String> {
    let o=std::process::Command::new("/usr/bin/timeout").args(["--signal=TERM","--kill-after=2s","8s","/usr/bin/systemctl","--system","show",UNIT,"--no-pager","--property=Id,InvocationID,MainPID,ControlPID,NRestarts,Restart,ActiveState,SubState,MemoryMax,MemorySwapMax,Job,RuntimeMaxUSec,ControlGroup"])
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS").env_remove("DBUS_SESSION_BUS_ADDRESS").env_remove("SYSTEMD_BUS_ADDRESS").env_remove("SYSTEMD_HOST").output().map_err(error)?;
    if !o.status.success() || !o.stderr.is_empty() || o.stdout.len() > 65536 {
        return Err("first163 bounded native query".into());
    }
    let mut n = BTreeMap::new();
    for line in std::str::from_utf8(&o.stdout).map_err(error)?.lines() {
        let (k, v) = line.split_once('=').ok_or("native framing")?;
        if n.insert(k.to_owned(), v.to_owned()).is_some() {
            return Err("duplicate native".into());
        }
    }
    for (k, v) in [
        ("Id", UNIT.into()),
        ("InvocationID", iid.into()),
        ("MainPID", std::process::id().to_string()),
        ("ControlPID", "0".into()),
        ("NRestarts", "0".into()),
        ("Restart", "no".into()),
        ("ActiveState", "active".into()),
        ("SubState", "running".into()),
        ("MemoryMax", MEMORY.to_string()),
        ("MemorySwapMax", "0".into()),
        ("Job", "".into()),
        ("RuntimeMaxUSec", "1h".into()),
        ("ControlGroup", format!("/system.slice/{UNIT}")),
    ] {
        if n.get(k) != Some(&v) {
            return Err(format!("first163 exact native mismatch {k}"));
        }
    }
    let raw = read(&p.node.path, 128 << 20)?;
    let mapped = fs::read("/proc/self/exe").map_err(error)?;
    let a = fs::metadata("/proc/self/exe").map_err(error)?;
    let b = fs::metadata(&p.node.path).map_err(error)?;
    if (a.dev(), a.ino()) != (b.dev(), b.ino())
        || mapped != raw
        || format!("{:x}", Sha256::digest(&raw)) != p.node.sha256
    {
        return Err("first163 exact node self image".into());
    }
    Ok(())
}
fn completed(receipt: &Value, done: &Value, b: &Bound, schema: &str) -> Result<(), String> {
    if done["schema"] != schema
        || done["receipt"] != json!(b)
        || done["invocation_id"] != receipt["invocation_id"]
        || done["result"] != "success"
        || done["exec_main_status"] != 0
        || done["original_outer_reaped"] != true
        || done["original_cgroup_empty"] != true
        || done["original_descriptors_drained"] != true
    {
        return Err("first163 original completion/reap/cgroup/descriptor proof".into());
    }
    Ok(())
}
fn request_projection(p: &Plan) -> Result<Value, String> {
    let mut v = serde_json::to_value(p).map_err(error)?;
    let o = v.as_object_mut().ok_or("first163 request object")?;
    o.remove("admission");
    o.remove("admission_capsule");
    o.remove("input_policy");
    o.insert(
        "schema".into(),
        json!("epoch163-first-output128-input-policy-v1"),
    );
    Ok(v)
}
fn envelope(now: u64) -> Result<(), String> {
    let available = fs::read_to_string("/proc/meminfo").map_err(error)?;
    let available = available
        .lines()
        .find_map(|s| s.strip_prefix("MemAvailable:"))
        .ok_or("first163 MemAvailable")?
        .split_whitespace()
        .next()
        .ok_or("first163 memory scalar")?
        .parse::<u64>()
        .map_err(error)?
        .checked_mul(1024)
        .ok_or("memory overflow")?;
    let need = EXPORT_FLOOR
        .checked_add(MEMORY)
        .and_then(|v| v.checked_add(2u64 << 30))
        .and_then(|v| v.checked_add(512u64 << 20))
        .and_then(|v| v.checked_add(8u64 << 30))
        .ok_or("first163 envelope overflow")?;
    if available < need {
        return Err(
            "first163128 full hard growth plus8GiB margin would cross exporter floor".into(),
        );
    }
    if now == 0 {
        return Err("first163 invalid clock".into());
    }
    Ok(())
}
fn timer_armed(enrollment: &Value) -> Result<(), String> {
    let b: Bound = serde_json::from_value(enrollment["timer_source"].clone()).map_err(error)?;
    normal_member(&b, "0444")?;
    let raw = read(&b.path, 1 << 20)?;
    if format!("{:x}", Sha256::digest(&raw)) != b.sha256 {
        return Err("first163 timer source SHA".into());
    }
    let name = "horizon-guard-epoch163-first-output128-20261106-v1.timer";
    let o = std::process::Command::new("/usr/bin/timeout")
        .args([
            "--signal=TERM",
            "--kill-after=2s",
            "8s",
            "/usr/bin/systemctl",
            "--system",
            "show",
            name,
            "--no-pager",
            "--property=Id,LoadState,ActiveState,SubState,Job,Unit,FragmentPath,DropInPaths",
        ])
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env_remove("SYSTEMD_BUS_ADDRESS")
        .env_remove("SYSTEMD_HOST")
        .output()
        .map_err(error)?;
    if !o.status.success() || !o.stderr.is_empty() || o.stdout.len() > 65536 {
        return Err("first163 timer native read".into());
    }
    let mut n = BTreeMap::new();
    for l in std::str::from_utf8(&o.stdout).map_err(error)?.lines() {
        let (k, v) = l.split_once('=').ok_or("timer framing")?;
        if n.insert(k, v).is_some() {
            return Err("duplicate timer property".into());
        }
    }
    for (k, v) in [
        ("Id", name),
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "waiting"),
        ("Job", ""),
        (
            "Unit",
            "horizon-guard-epoch163-first-output128-20261106-v1.service",
        ),
        ("DropInPaths", ""),
    ] {
        if n.get(k) != Some(&v) {
            return Err(format!("first163 timer not armed: {k}"));
        }
    }
    if fs::read(n.get("FragmentPath").ok_or("timer fragment")?).map_err(error)? != raw {
        return Err("first163 loaded timer source differs".into());
    }
    Ok(())
}
fn authority(p: &Plan, now: u64) -> Result<(), String> {
    if p.schema != "epoch163-first-output128-private-plan-v1"
        || p.maximum_runtime_seconds != 3600
        || p.maximum_replayed_slots != TARGET - BOOTSTRAP
        || p.maximum_output_bytes != 1 << 30
        || p.exporter_floor_bytes != EXPORT_FLOOR
    {
        return Err("first163 exact bounded profile".into());
    }
    if p.node.path
        != Path::new(
            "/usr/local/lib/jetstreamer/horizon-first-lane-witness-first163128-node-tools-20261107-v2/jetstreamer-node",
        )
        || p.guard.path
            != Path::new(
                "/usr/local/lib/jetstreamer/horizon-first-lane-witness-first163128-guard-tools-20261107-v2/first163128-guard",
            )
    {
        return Err("first163 exact node/guard package names".into());
    }
    normal_member(&p.node, "0555")?;
    normal_member(&p.guard, "0555")?;
    normal_member(&p.admission_program,"0555")?;
    normal_member(&p.input_policy, "0444")?;
    if bound(&p.input_policy)? != request_projection(p)? {
        return Err("first163 immutable pre-admission request crossed".into());
    }
    if p.admission_capsule.path!=Path::new(ROOT).join("admission-capsule.json"){return Err("first163 private admission capsule namespace".into());}
    // Original evidence stays root-only. The qualified privileged Rust actor
    // revalidates both opaque views and emits this compact, hash-bound statement
    // into the owner's0700 work directory; no private receipt is copied/exposed.
    let a=bound(&p.admission_capsule)?;
    let m=&a["memory_summary"];
    let d=&a["DATA_summary"];
    completed(
        m,
        &a["memory_completion_summary"],
        &p.memory,
        "epoch163-parent-memory-selector-original-completion-v1",
    )?;
    completed(
        d,
        &a["DATA_completion_summary"],
        &p.data,
        "epoch163-ended183-DATA-selector-original-completion-v1",
    )?;
    if m["capability_only"] != false
        || m["selection"]["original199_parent_retirement_bytes"] != 192u64 << 30
        || m["selection"]["completed_cached145_parent_retirement_bytes"] != 192u64 << 30
        || d["memory_selection"] != json!(p.memory)
        || d["program"]
            != json!({"path":"/usr/local/lib/jetstreamer/horizon-first-lane-witness-ended183-DATA-selector-tools-20261107-v4/ended183-data","sha256":"85f374198bd5418bfa269faf01c9751b50f30a94a0cb0c0cc9a9b8b18133d243"})
    {
        return Err("first163 exact current opaque memory/DATA lineage".into());
    }
    if a["schema"] != "epoch163-first-output128-admission-capsule-v1"
        ||a["issuer"]!=json!(p.admission_program)||a["original_admission"]!=json!(p.admission)
        || a["input_policy"] != json!(p.input_policy)
        || a["admitted"] != true
        || a["parent_unit"] != UNIT
        || a["parent_program"] != json!(p.node)
        || a["parent_hard_bytes"] != MEMORY
        || a["guard_bytes"] != 2u64 << 30
        || a["fallback_bytes"] != 512u64 << 20
        || a["exporter_floor_bytes"] != EXPORT_FLOOR
        || a["complete_current_owner_accounting"] != true
        || a["input_capability"] != json!(p.input_acceptance)
        || a["memory_receipt"] != json!(p.memory)
        || a["data_receipt"] != json!(p.data)
        || a["original_inputs_and_resource_actors_drained"] != true
        || a["recorded_unix_seconds"]
            .as_u64()
            .is_none_or(|t| t == 0 || now.checked_sub(t).is_none_or(|age| age > 180))
        || a["publication_authorized"] != false
        || a["r2_mutations"] != false
    {
        return Err("first163 original180s full source/native/resource admission missing".into());
    }
    let inputs=&a["input_capability_summary"];
    let first=&a["first_slot_source_summary"];
    if inputs["schema"] != "epoch163-first-output128-input-capability-v1"
        || inputs["bootstrap_generation"] != 1634787272998262u64
        || inputs["bootstrap_slot"] != BOOTSTRAP
        || inputs["snapshot_integrity_verified"] != true
        || inputs["mapped_worker_sha256"] != WORKER_SHA
        || inputs["original_capability_actor_drained"] != true
        || first["schema"] != "jetstreamer-successor-boundary-source-probe-v1"
        || first["epoch"] != 163
        || first["requested_slot"] != TARGET
        || first["first_block_slot"] != TARGET
        || first["parent_slot"]
            .as_u64()
            .is_none_or(|p| !(BOOTSTRAP..TARGET).contains(&p))
        || first["production_boundary_reader"] != true
        || first["publication_authorized"] != false
        || first["replay_launch_authorized"] != false
    {
        return Err("first163 actual input/first-present-slot capability missing; source probe alone never proves hidden PoH or replay success".into());
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub fn admit_launch(
    first: u64,
    last: u64,
    plan: Option<QualificationPlan>,
    cohort: bool,
    recovery: bool,
    ledger: &Path,
    output: Option<&Path>,
    scratch: Option<&Path>,
    snapshot: Option<&Path>,
    hashes: Option<&Path>,
) -> Result<(), String> {
    let q = plan.ok_or("first163 focused plan required")?;
    if first != 163
        || last != 163
        || !selected(q)
        || cohort
        || recovery
        || ledger != Path::new(ROOT).join("ledger")
        || output != Some(Path::new(ROOT).join("output/first-output.jet").as_path())
        || scratch != Some(Path::new(ROOT).join("scratch").as_path())
        || snapshot != Some(Path::new(INPUTS).join(SNAPSHOT).as_path())
        || hashes != Some(Path::new(INPUTS).join("checkpoint-names.txt").as_path())
    {
        return Err("first163 private exact path/slot scope".into());
    }
    let names = read(hashes.unwrap(), 4096)?;
    if names != format!("{SNAPSHOT}\n{TAIL}\n").as_bytes() {
        return Err("first163 trusted original bootstrap/final-root names differ".into());
    }
    if fs::symlink_metadata(output.unwrap()).is_ok()
        || fs::symlink_metadata(output.unwrap().with_extension("jet.sha256")).is_ok()
    {
        return Err("first163 refuses occupied output/sidecar".into());
    }
    let pb = Bound {
        path: std::env::var("JETSTREAMER_FIRST163128_PLAN")
            .map_err(error)?
            .into(),
        sha256: std::env::var("JETSTREAMER_FIRST163128_PLAN_SHA256").map_err(error)?,
    };
    let p: Plan = serde_json::from_value(bound(&pb)?).map_err(error)?;
    normal_member(&pb, "0444")?;
    let iid = std::env::var("INVOCATION_ID").map_err(error)?;
    native(&p, &iid)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(error)?
        .as_secs();
    authority(&p, now)?;
    let began = Instant::now();
    let mut last_heartbeat = Instant::now();
    eprintln!(
        "epoch163-first-output128 phase=held waiting=original-first-guard-and-fleet-release deadline_seconds=150 archive_opened=false"
    );
    let release_path = Path::new(ROOT).join(format!("release-{iid}.json"));
    loop {
        if release_path.try_exists().map_err(error)? {
            let raw = read(&release_path, 1 << 20)?;
            let v: Value = serde_json::from_slice(&raw).map_err(error)?;
            if v["schema"] != "epoch163-first-output128-release-v1"
                || v["parent_invocation_id"] != iid
                || v["parent_pid"] != std::process::id()
                || v["plan"] != json!(pb)
                || v["admission"] != json!(p.admission)
            {
                return Err("first163 exact original release differs".into());
            }
            let guard: Bound = serde_json::from_value(v["first_guard"].clone()).map_err(error)?;
            let g = bound(&guard)?;
            if g["schema"] != "epoch163-first-output128-original-first-guard-v1"
                || g["parent_invocation_id"] != iid
                || g["program"] != json!(p.guard)
                || g["original_PID1_success"] != true
                || g["original_outer_reaped"] != true
                || g["original_cgroup_empty"] != true
                || g["original_descriptors_drained"] != true
            {
                return Err("first163 genuine original first guard incomplete".into());
            }
            let enrolled: Bound = serde_json::from_value(v["enrollment"].clone()).map_err(error)?;
            let enrolled = bound(&enrolled)?;
            if enrolled["schema"] != "epoch163-first-output128-fleet-enrollment-v1"
                || enrolled["parent_unit"] != UNIT
                || enrolled["parent_invocation_id"] != iid
                || enrolled["admission"] != json!(p.admission)
                || enrolled["input_policy"] != json!(p.input_policy)
                || enrolled["first_guard"] != json!(guard)
                || enrolled["complete_current_claim_census"] != true
                || enrolled["common_observer_and_fleet_handoff_qualified"] != true
                || enrolled["publication_authorized"] != false
            {
                return Err("first163 actual source-qualified fleet enrollment missing".into());
            }
            timer_armed(&enrolled)?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(error)?
                .as_secs();
            authority(&p, now)?;
            native(&p, &iid)?;
            envelope(now)?;
            return Ok(());
        }
        if began.elapsed() > Duration::from_secs(150) {
            return Err(
                "first163 held startup expired without original first guard/release".into(),
            );
        }
        if last_heartbeat.elapsed() >= Duration::from_secs(60) {
            eprintln!(
                "epoch163-first-output128 phase=held heartbeat=true substantive_progress=false remaining_seconds={}",
                150u64.saturating_sub(began.elapsed().as_secs())
            );
            last_heartbeat = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
pub fn checkpoint_scope<T>(
    expected: &BTreeMap<u64, T>,
    p: QualificationPlan,
) -> Result<(), String> {
    if !selected(p)
        || expected.len() != 2
        || !expected.contains_key(&BOOTSTRAP)
        || !expected.contains_key(&FINAL_ROOT)
    {
        Err("first163 exact two original checkpoints required; no invented first-slot canonical hash".into())
    } else {
        Ok(())
    }
}
pub fn write_private_outcome(
    plan: QualificationPlan,
    path: &Path,
    result: &ReplayRunResult,
) -> Result<(), String> {
    if !selected(plan) || path != Path::new(ROOT).join("output/first-output.jet") {
        return Err("first163 outcome scope".into());
    }
    let e = result
        .historical_evidence
        .as_ref()
        .ok_or("first163 missing worker evidence")?;
    if e.bootstrap.slot != BOOTSTRAP || e.terminal.slot != TARGET || !e.terminal.slot_complete {
        return Err("first163 actual completed first target missing".into());
    }
    let worker = result
        .historical_worker_executable_sha256
        .ok_or("first163 no mapped worker digest")?;
    let actual_worker = worker
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if actual_worker != WORKER_SHA {
        return Err("first163 worker profile drift".into());
    }
    let f = jetstreamer_node::archive_checksum::open_regular_nofollow(path).map_err(error)?;
    let before = identity(&f.metadata().map_err(error)?);
    if before.2 > 1 << 30 {
        return Err("first163 output work bound".into());
    }
    let mut r = jetstreamer_horizon::archive::ArchiveReader::open(std::io::BufReader::new(f))
        .map_err(error)?;
    if r.header().slot_start != TARGET || r.header().slot_count != 1 {
        return Err("first163 archive is not exactly one output slot".into());
    }
    r.verify_chain = true;
    let mut v = crate::ArchiveVerificationVisitor::new();
    let mut slots = 0;
    for i in 0..r.bucket_count() {
        slots += r
            .read_bucket_with_header(i, &mut v, |h, v| v.on_bucket_header(h))
            .map_err(error)?;
    }
    if slots != 1
        || v.chain.first_block.is_none_or(|b| b.slot != TARGET)
        || v.chain.terminal_block.is_none_or(|b| b.slot != TARGET)
        || identity(&fs::symlink_metadata(path).map_err(error)?) != before
    {
        return Err("first163 skipped/empty/replaced output is not first-block success".into());
    }
    let value = json!({"schema":"epoch163-first-output128-private-outcome-v1","epoch":163,"bootstrap":crate::segment_checkpoint_summary(&e.bootstrap),"terminal":crate::segment_checkpoint_summary(&e.terminal),"worker_sha256":WORKER_SHA,"output_slot_start":TARGET,"output_slot_count":1,"present_output_block":true,"canonical_terminal_checkpoint_verified":false,"canonical_segment_manifest_authorized":false,"publication_authorized":false,"r2_mutations":false,"independent_verification_and_original_owner_completion_pending":true});
    let output = path.with_extension("private-outcome.json");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&output)
        .map_err(error)?;
    file.write_all(&serde_json::to_vec_pretty(&value).map_err(error)?)
        .map_err(error)?;
    file.sync_all().map_err(error)?;
    File::open(output.parent().unwrap())
        .and_then(|f| f.sync_all())
        .map_err(error)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn plan_fixture() -> Plan {
        let b = || Bound {
            path: "/test/root-metadata".into(),
            sha256: "a".repeat(64),
        };
        Plan {
            schema: "epoch163-first-output128-private-plan-v1".into(),
            node: b(),
            guard: b(),
            admission_program: b(),
            admission_capsule: b(),
            input_policy: b(),
            admission: b(),
            input_acceptance: b(),
            first_slot_source: b(),
            memory: b(),
            memory_completion: b(),
            data: b(),
            data_completion: b(),
            maximum_runtime_seconds: 3600,
            maximum_replayed_slots: 259,
            maximum_output_bytes: 1 << 30,
            exporter_floor_bytes: EXPORT_FLOOR,
        }
    }
    fn q() -> QualificationPlan {
        QualificationPlan {
            epoch: 163,
            bootstrap_slot: BOOTSTRAP,
            replay_start: BOOTSTRAP + 1,
            output_slot_start: TARGET,
            end_inclusive: TARGET,
        }
    }
    #[test]
    fn only_exact_first_output_cli_is_available() {
        entrypoint(&expected_args()).unwrap();
        entrypoint(&[format!("--probe-successor-boundary={TARGET}")]).unwrap();
        assert!(entrypoint(&["--probe-successor-boundary=70848000".into()]).is_err());
        for i in 0..expected_args().len() {
            let mut a = expected_args();
            a[i] = "other".into();
            assert!(entrypoint(&a).is_err());
        }
        let mut a = expected_args();
        a.push("--root-checkpoint-cohort".into());
        assert!(entrypoint(&a).is_err());
    }
    #[test]
    fn source_clock_never_claims_first_slot_is_a_canonical_checkpoint() {
        let mut e = BTreeMap::from([(BOOTSTRAP, 1), (FINAL_ROOT, 2)]);
        if enabled() {
            checkpoint_scope(&e, q()).unwrap();
        } else {
            assert!(checkpoint_scope(&e, q()).is_err());
        }
        e.insert(TARGET, 3);
        assert!(checkpoint_scope(&e, q()).is_err());
    }
    #[test]
    fn original_completion_requires_actual_same_invocation_and_all_drains() {
        let b = Bound {
            path: "/receipt".into(),
            sha256: "a".repeat(64),
        };
        let r = json!({"invocation_id":"a".repeat(32)});
        let d = json!({"schema":"test","receipt":b,"invocation_id":"a".repeat(32),"result":"success","exec_main_status":0,"original_outer_reaped":true,"original_cgroup_empty":true,"original_descriptors_drained":true});
        completed(&r, &d, &b, "test").unwrap();
        for key in [
            "original_outer_reaped",
            "original_cgroup_empty",
            "original_descriptors_drained",
        ] {
            let mut bad = d.clone();
            bad[key] = json!(false);
            assert!(completed(&r, &bad, &b, "test").is_err());
        }
    }
    #[test]
    fn pre_admission_request_has_no_runtime_plan_or_admission_digest_cycle() {
        let mut p = plan_fixture();
        let request = request_projection(&p).unwrap();
        assert!(request.get("admission").is_none());
        assert!(request.get("admission_capsule").is_none());
        assert!(request.get("input_policy").is_none());
        p.admission.sha256 = "b".repeat(64);
        p.admission_capsule.sha256 = "d".repeat(64);
        p.input_policy.sha256 = "c".repeat(64);
        assert_eq!(request_projection(&p).unwrap(), request);
        assert_eq!(
            request["schema"],
            "epoch163-first-output128-input-policy-v1"
        );
    }
    #[test]
    fn program_resource_and_original_selection_changes_require_new_input_policy() {
        let mut p = plan_fixture();
        let request = request_projection(&p).unwrap();
        p.memory.sha256 = "b".repeat(64);
        assert_ne!(request_projection(&p).unwrap(), request);
        let mut p = plan_fixture();
        p.node.sha256 = "c".repeat(64);
        assert_ne!(request_projection(&p).unwrap(), request);
        let mut p = plan_fixture();
        p.maximum_runtime_seconds = 3601;
        assert_ne!(request_projection(&p).unwrap(), request);
    }
}
