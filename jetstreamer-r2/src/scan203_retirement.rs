//! Fixed203 replica retirement. No remote mutation, canonical-pair deletion,
//! directory removal, recipe removal, or scan204 body access is implemented.
use super::*;
use std::{
    ffi::CString,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
};

#[cfg(test)]
#[path = "scan203_retirement_tests.rs"]
mod tests;

const RETIRE_UNIT: &str = "horizon-scan203-retirement-v1.service";
const GUARD_UNIT: &str = "horizon-guard-scan203-retirement-v1.service";
const GUARD_TIMER: &str = "horizon-guard-scan203-retirement-v1.timer";
const STATE: &str = "/var/lib/jetstreamer/horizon-scan203-retirement-v1";
const GUARD_STATE: &str = "/var/lib/jetstreamer/horizon-scan203-retirement-guard-v1";
const LOCK: &str = "/home/ubuntu/.jetstreamer-private/r2-receipts/local-mutation.lock";
const SOURCE_NAME: &str = "epoch-203.jet";
const QUARANTINE_NAME: &str = ".epoch-203-retirement-7efb3b28b2761cd646d20fa282d87c508249488fd0fb27ce8e033a1aed7d39ad.quarantine";
const MEMORY: u64 = 4 << 30;
const METADATA_CAP: u64 = 64 << 20;
const ETAG203: &str = "6f543a2b1f7c1d60647a9f5f8b541150-1547";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RetirePlan {
    schema: String,
    inspection_plan: Bound,
    inspection: Bound,
    closure_plan: Bound,
    state_identity: Parent,
    guard_directory_identity: Parent,
    lock_identity: Stamp,
    guard_binary: Bound,
    guard_recipe: Bound,
    guard_timer_recipe: Bound,
    minimum_free_bytes: u64,
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn qpath() -> PathBuf {
    Path::new(ROOT).join(QUARANTINE_NAME)
}
fn present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
fn same_body(a: &Stamp, b: &Stamp) -> bool {
    let mut a = a.clone();
    let mut b = b.clone();
    a.ctime_ns = 0;
    b.ctime_ns = 0;
    a == b
}
fn directory(path: &Path, expected: &Parent) -> Result<File> {
    ensure!(path.canonicalize()? == path, "retirement directory alias");
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    directory_binding(path, &f, expected)?;
    Ok(f)
}
fn directory_binding(path: &Path, f: &File, expected: &Parent) -> Result<()> {
    let m = f.metadata()?;
    let named = fs::symlink_metadata(path)?;
    let actual = Parent {
        device: m.dev(),
        inode: m.ino(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode() & 0o7777,
    };
    ensure!(
        m.is_dir()
            && named.is_dir()
            && named.dev() == m.dev()
            && named.ino() == m.ino()
            && actual == *expected
            && actual.uid == 0
            && actual.mode & 0o022 == 0,
        "retirement directory custody/identity changed"
    );
    Ok(())
}
fn child_path(dir: &File, name: &str) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}/{}", dir.as_raw_fd(), name))
}
fn child(name: &str) -> Result<CString> {
    ensure!(
        name == SOURCE_NAME || name == QUARANTINE_NAME,
        "foreign retirement child"
    );
    Ok(CString::new(name)?)
}
fn move_child(dir: &File) -> Result<()> {
    let from = child(SOURCE_NAME)?;
    let to = child(QUARANTINE_NAME)?;
    ensure!(
        unsafe {
            libc::renameat2(
                dir.as_raw_fd(),
                from.as_ptr(),
                dir.as_raw_fd(),
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
        "fixed203 quarantine rename failed: {}",
        std::io::Error::last_os_error()
    );
    dir.sync_all()?;
    Ok(())
}
fn unlink_child(dir: &File) -> Result<()> {
    let q = child(QUARANTINE_NAME)?;
    ensure!(
        unsafe { libc::unlinkat(dir.as_raw_fd(), q.as_ptr(), 0) } == 0,
        "fixed203 quarantine unlink failed: {}",
        std::io::Error::last_os_error()
    );
    dir.sync_all()?;
    Ok(())
}

fn bindings_superset(old: &[Bound], new: &[Bound]) -> bool {
    let old = old
        .iter()
        .map(|b| (&b.path, &b.sha256))
        .collect::<BTreeMap<_, _>>();
    let next = new
        .iter()
        .map(|b| (&b.path, &b.sha256))
        .collect::<BTreeMap<_, _>>();
    next.len() == new.len() && old.iter().all(|(path, sha)| next.get(path) == Some(sha))
}
fn continuation(old: &Plan, new: &Plan, inspection: &Bound, v: &Value) -> Result<()> {
    let core = |p: &Plan| -> Result<Value> {
        let mut v = serde_json::to_value(p)?;
        for k in [
            "executor_recipe",
            "actors",
            "historical_recipes",
            "dependency_metadata",
        ] {
            v.as_object_mut().unwrap().remove(k);
        }
        Ok(v)
    };
    ensure!(
        core(old)? == core(new)?
            && bindings_superset(&old.historical_recipes, &new.historical_recipes)
            && bindings_superset(&old.dependency_metadata, &new.dependency_metadata)
            && old.actors.iter().all(|(n, a)| new
                .actors
                .get(n)
                .is_some_and(|b| a.invocation_id == b.invocation_id
                    && a.original_terminal.path == b.original_terminal.path
                    && a.original_terminal.sha256 == b.original_terminal.sha256)),
        "retirement dropped/changed original evidence, recipes, identities or consumers"
    );
    let actor = new
        .actors
        .get(UNIT)
        .context("original inspector missing from historical consumers")?;
    ensure!(
        v["schema"] == "jetstreamer-scan203-retention-inspection-v1"
            && v["retirement_authorized"] == false
            && v["archive_body_opened"] == false
            && v["source_identity"] == serde_json::to_value(&old.source_identity)?
            && v["retained204_identity"] == serde_json::to_value(&old.retained204_identity)?
            && v["executor"]["unit"] == UNIT
            && v["executor"]["invocation_id"] == actor.invocation_id
            && actor.original_terminal.path == inspection.path
            && actor.original_terminal.sha256 == inspection.sha256
            && new
                .historical_recipes
                .iter()
                .any(|b| b.path == old.executor_recipe.path
                    && b.sha256 == old.executor_recipe.sha256),
        "retirement lost the genuine prior inspector identity/recipe"
    );
    Ok(())
}
fn fresh_inspection(v: &Value, time: u64) -> Result<()> {
    let t = v["recorded_unix_seconds"]
        .as_u64()
        .context("inspection clock missing")?;
    ensure!(
        t <= time && time - t <= 900,
        "initial retirement inspection is stale/future"
    );
    Ok(())
}
fn plan_scope(p: &RetirePlan, c: &Plan) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-scan203-retirement-plan-v1"
            && p.minimum_free_bytes > 0
            && p.state_identity.device == c.source_identity.device
            && p.guard_directory_identity.device == c.source_identity.device
            && p.state_identity.inode != p.guard_directory_identity.inode
            && p.state_identity.mode == 0o700
            && p.guard_directory_identity.mode == 0o700
            && p.lock_identity.uid <= 1000
            && matches!(p.lock_identity.uid, 0 | 1000)
            && p.lock_identity.links == 1
            && p.lock_identity.mode & 0o077 == 0
            && is_lower_hex(&p.guard_binary.sha256, 64)
            && p.guard_binary.sha256.bytes().any(|b| b != b'0'),
        "foreign retirement scope, lock, guard or state"
    );
    for (b, name) in [
        (&p.guard_recipe, GUARD_UNIT),
        (&p.guard_timer_recipe, GUARD_TIMER),
    ] {
        ensure!(
            b.path == Path::new("/etc/systemd/system").join(name),
            "foreign protective recipe"
        );
    }
    scope_for(c, RETIRE_UNIT)?;
    Ok(())
}

fn executor_properties(
    m: &BTreeMap<String, String>,
    args: &[String],
    iid: &str,
    pid: u32,
    check: bool,
) -> Result<()> {
    ensure!(is_lower_hex(iid, 32), "retirement IID missing/invalid");
    let get = |k| m.get(k).map(String::as_str);
    ensure!(
        get("Id") == Some(RETIRE_UNIT)
            && get("ActiveState") == Some("active")
            && get("SubState") == Some("running")
            && get("InvocationID") == Some(iid)
            && get("MainPID") == Some(pid.to_string().as_str())
            && get("ControlPID") == Some("0")
            && get("NRestarts") == Some("0")
            && get("Restart") == Some("no")
            && get("ProtectSystem") == Some("strict")
            && get("ProtectHome") == Some("read-only")
            && get("PrivateNetwork") == Some(if check { "yes" } else { "no" })
            && get("NoNewPrivileges") == Some("yes")
            && [
                "Job",
                "Triggers",
                "TriggeredBy",
                "ExecCondition",
                "ExecStartPre",
                "ExecStartPost",
                "ExecStop",
                "ExecStopPost",
                "ExecReload",
                "OnSuccess",
                "OnFailure"
            ]
            .iter()
            .all(|k| get(k) == Some("")),
        "foreign current retirement executor"
    );
    let actual = get("ReadWritePaths")
        .context("missing current writable paths")?
        .split_whitespace()
        .collect::<BTreeSet<_>>();
    let expected = if check {
        BTreeSet::new()
    } else {
        [ROOT, STATE, LOCK].into_iter().collect()
    };
    ensure!(actual == expected, "retirement writable scope differs");
    if !check {
        ensure!(
            get("MemoryMax") == Some("4294967296")
                && get("MemorySwapMax") == Some("0")
                && get("TasksMax") == Some("512")
                && get("CPUQuotaPerSecUSec") == Some("2s")
                && get("RuntimeMaxUSec") == Some("2h"),
            "current retirement resource envelope differs"
        );
    }
    ensure!(
        get("ExecStart").is_some_and(|s| s.matches("argv[]=").count() == 1
            && (s.contains(&format!("argv[]={};", args.join(" ")))
                || s.contains(&format!("argv[]={} ;", args.join(" "))))),
        "retirement actual command differs"
    );
    Ok(())
}
fn owner(c: &Plan, args: &[String], iid: &str, check: bool) -> Result<Value> {
    let m = manager(RETIRE_UNIT)?;
    executor_properties(&m, args, iid, std::process::id(), check)?;
    metadata_bytes(&c.executor_recipe)?;
    Ok(
        json!({"unit":RETIRE_UNIT,"invocation_id":iid,"pid":std::process::id(),"recipe":c.executor_recipe,"properties":m}),
    )
}

fn guard_sample(v: &Value, p: &RetirePlan, iid: &str, pid: u32, time: u64) -> Result<()> {
    let t = v["recorded_unix_millis"]
        .as_u64()
        .context("guard clock missing")?;
    ensure!(
        v["schema"] == "jetstreamer-horizon-build-guard-sample-v1"
            && v["unit"] == RETIRE_UNIT
            && v["actor_invocation_id"] == iid
            && v["self_sha256"] == p.guard_binary.sha256
            && v["native_MainPID"] == pid
            && v["native_ControlPID"] == 0
            && v["native_NRestarts"] == 0
            && v["native_Type"] == "exec"
            && v["native_ActiveState"] == "active"
            && v["native_SubState"] == "running"
            && v["guard_invocation_id"]
                .as_str()
                .is_some_and(|id| is_lower_hex(id, 32))
            && v["native_owner_stable"] == true
            && v["trip"] == false
            && v["root"] == STATE
            && v["root_uid"] == 0
            && v["root_device"] == p.state_identity.device
            && v["root_inode"] == p.state_identity.inode
            && v["minimum_free_bytes"] == p.minimum_free_bytes
            && v["maximum_root_bytes"] == METADATA_CAP
            && v["memory_max_bytes"] == MEMORY
            && v["memory_swap_max_bytes"] == 0
            && v["tasks_max"] == 512
            && v["cpu_quota_usec"] == 2_000_000
            && v["maximum_run_usec"] == 7_200_000_000u64
            && v["available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= p.minimum_free_bytes)
            && v["conservative_physical_bytes"]
                .as_u64()
                .is_some_and(|n| n <= METADATA_CAP)
            && t / 1000 <= time
            && time - t / 1000 <= 180,
        "stale/foreign/tripped or mismatched actual guard sample"
    );
    Ok(())
}
fn guard_command(p: &RetirePlan, iid: &str) -> String {
    format!(
        "{} --unit {RETIRE_UNIT} --expected-invocation-id {iid} --self-sha256 {} --root {STATE} --root-uid 0 --root-device {} --root-inode {} --receipt-directory {GUARD_STATE} --minimum-free-bytes {} --maximum-root-bytes {METADATA_CAP} --expected-memory-max-bytes {MEMORY} --expected-memory-swap-max-bytes 0 --expected-tasks-max 512 --expected-cpu-quota-usec 2000000 --expected-max-run-usec 7200000000",
        p.guard_binary.path.display(),
        p.guard_binary.sha256,
        p.state_identity.device,
        p.state_identity.inode,
        p.minimum_free_bytes
    )
}
fn current_guard(p: &RetirePlan, iid: &str) -> Result<Bound> {
    let dir = directory(Path::new(GUARD_STATE), &p.guard_directory_identity)?;
    ensure!(
        !present(&Path::new(GUARD_STATE).join("stop-intent.json"))?
            && !present(&Path::new(GUARD_STATE).join("stop-completion.json"))?,
        "protective guard has stop evidence"
    );
    metadata_bytes(&p.guard_binary)?;
    let service = manager(GUARD_UNIT)?;
    let get = |k| service.get(k).map(String::as_str);
    ensure!(
        get("Id") == Some(GUARD_UNIT)
            && get("NRestarts") == Some("0")
            && get("Restart") == Some("no")
            && matches!(
                get("ActiveState"),
                Some("inactive" | "active" | "activating")
            )
            && get("Result") == Some("success")
            && get("MemoryMax") == Some("1073741824")
            && get("MemorySwapMax") == Some("0")
            && get("TasksMax") == Some("256")
            && get("CPUQuotaPerSecUSec") == Some("1s")
            && get("ExecStart").is_some_and(|s| s.matches("argv[]=").count() == 1
                && [
                    guard_command(p, iid),
                    guard_command(p, "${HORIZON_SCAN203_ACTOR_IID}")
                ]
                .iter()
                .any(|cmd| s.contains(&format!("argv[]={cmd} ;")))),
        "current protective guard command/resource envelope changed"
    );
    let timer = manager(GUARD_TIMER)?;
    ensure!(
        timer.get("Id").map(String::as_str) == Some(GUARD_TIMER)
            && timer.get("ActiveState").map(String::as_str) == Some("active")
            && matches!(
                timer.get("SubState").map(String::as_str),
                Some("waiting" | "running")
            )
            && timer.get("Triggers").map(String::as_str) == Some(GUARD_UNIT),
        "retirement guard timer is not armed"
    );
    let mut candidates = Vec::new();
    let mut count = 0;
    for entry in fs::read_dir(GUARD_STATE)? {
        let entry = entry?;
        count += 1;
        ensure!(count <= 16384, "guard receipt count bound");
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name
            .strip_prefix("sample-")
            .and_then(|s| s.strip_suffix(".json"))
            .is_some_and(|s| is_lower_hex(s, 32))
        {
            continue;
        }
        let path = entry.path();
        let raw = read_stable_bounded(&path, 16384, "current guard sample")?;
        let binding = Bound {
            path,
            sha256: hex_lower(&Sha256::digest(&raw)),
        };
        let v = saved(&binding)?;
        ensure!(
            v["guard_invocation_id"]
                .as_str()
                .is_some_and(|id| name == format!("sample-{id}.json")),
            "guard sample filename/IID differs"
        );
        if v["actor_invocation_id"] == iid {
            candidates.push((
                v["recorded_unix_millis"].as_u64().context("guard clock")?,
                binding,
                v,
            ));
        }
    }
    candidates.sort_by_key(|v| v.0);
    let (_, binding, v) = candidates
        .pop()
        .context("no genuine current guard sample")?;
    guard_sample(&v, p, iid, std::process::id(), now()?)?;
    directory_binding(Path::new(GUARD_STATE), &dir, &p.guard_directory_identity)?;
    Ok(binding)
}
async fn startup(p: &RetirePlan, binding: &Bound, self_sha: &str, iid: &str) -> Result<Bound> {
    let path = Path::new(STATE).join(format!("startup-{iid}.json"));
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut heartbeat = Instant::now();
    eprintln!(
        "scan203 phase=await-startup unit={RETIRE_UNIT} invocation_id={iid} deadline_seconds=120 unix_seconds={}",
        now()?
    );
    loop {
        if present(&path)? {
            let raw = read_stable_bounded(&path, 65536, "retirement startup release")?;
            let b = Bound {
                path,
                sha256: hex_lower(&Sha256::digest(&raw)),
            };
            let v = saved(&b)?;
            let t = v["recorded_unix_seconds"]
                .as_u64()
                .context("startup clock")?;
            let time = now()?;
            ensure!(
                v["schema"] == "jetstreamer-scan203-retirement-startup-v1"
                    && v["plan"] == serde_json::to_value(binding)?
                    && v["unit"] == RETIRE_UNIT
                    && v["invocation_id"] == iid
                    && v["pid"] == std::process::id()
                    && v["self_sha256"] == self_sha
                    && t <= time
                    && time - t <= 120,
                "foreign/stale actual startup release"
            );
            let first: Bound = serde_json::from_value(v["first_guard_sample"].clone())?;
            ensure!(
                first.path.parent() == Some(Path::new(GUARD_STATE)),
                "foreign first guard receipt directory"
            );
            guard_sample(&saved(&first)?, p, iid, std::process::id(), time)?;
            current_guard(p, iid)?;
            return Ok(b);
        }
        ensure!(
            Instant::now() < deadline,
            "actual guard startup release deadline elapsed"
        );
        if heartbeat.elapsed() >= Duration::from_secs(60) {
            eprintln!(
                "scan203 phase=await-startup-heartbeat invocation_id={iid} remaining_seconds={} next_on_expiry=fail-closed unix_seconds={}",
                deadline.saturating_duration_since(Instant::now()).as_secs(),
                now()?
            );
            heartbeat = Instant::now();
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn closure(
    p: &RetirePlan,
    c: &Plan,
    binding: &Bound,
    args: &[String],
    iid: &str,
    check: bool,
) -> Result<Value> {
    parent(&c.parent_identity)?;
    replica(Path::new(RETAINED), &c.retained204_identity)?;
    gates(c)?;
    let who = owner(c, args, iid, check)?;
    let before = actor_census(c)?;
    let recipes = staged_for(
        c,
        &[
            (RETIRE_UNIT, &c.executor_recipe),
            (GUARD_UNIT, &p.guard_recipe),
            (GUARD_TIMER, &p.guard_timer_recipe),
        ],
        &[
            binding.path.as_path(),
            p.closure_plan.path.as_path(),
            p.inspection_plan.path.as_path(),
        ],
    )?;
    process_references(
        Path::new("/proc"),
        Path::new(SOURCE),
        &c.source_identity,
        std::process::id(),
        &c.dependency_metadata,
    )?;
    process_references(
        Path::new("/proc"),
        &qpath(),
        &c.source_identity,
        std::process::id(),
        &c.dependency_metadata,
    )?;
    ensure!(
        before == actor_census(c)?
            && recipes
                == staged_for(
                    c,
                    &[
                        (RETIRE_UNIT, &c.executor_recipe),
                        (GUARD_UNIT, &p.guard_recipe),
                        (GUARD_TIMER, &p.guard_timer_recipe)
                    ],
                    &[
                        binding.path.as_path(),
                        p.closure_plan.path.as_path(),
                        p.inspection_plan.path.as_path()
                    ]
                )?
            && who == owner(c, args, iid, check)?,
        "retirement closure changed"
    );
    Ok(
        json!({"owner":who,"actors":before,"recipes":recipes,"dependency_metadata":c.dependency_metadata}),
    )
}

fn body_at(
    dir: &File,
    name: &str,
    expected: &Stamp,
    original: bool,
    receipt: &Receipt,
) -> Result<(Stamp, LocalProof)> {
    child(name)?;
    let path = child_path(dir, name);
    let m = fs::symlink_metadata(&path)?;
    let stamp = Stamp::of(&m);
    ensure!(
        m.is_file()
            && if original {
                stamp == *expected
            } else {
                same_body(&stamp, expected)
            },
        "retirement body generation differs"
    );
    let started = Instant::now();
    let mut last_report = started;
    eprintln!(
        "scan203 phase=hash-start child={name} expected_bytes={} unix_seconds={}",
        expected.length,
        now()?
    );
    let proof = hash_and_etag_observed(
        &path,
        regular_identity(&path)?,
        receipt.multipart_part_size,
        |bytes| {
            if last_report.elapsed() >= Duration::from_secs(60) {
                eprintln!(
                    "scan203 phase=hash-progress child={name} read_bytes={bytes} expected_bytes={} elapsed_seconds={} unix_seconds={}",
                    expected.length,
                    started.elapsed().as_secs(),
                    now().unwrap_or(0)
                );
                last_report = Instant::now();
            }
        },
    )?;
    eprintln!(
        "scan203 phase=hash-complete child={name} read_bytes={} elapsed_seconds={} unix_seconds={}",
        expected.length,
        started.elapsed().as_secs(),
        now()?
    );
    validate_retirement_body_proof(
        203,
        expected.length,
        &receipt.archive_sha256,
        &proof,
        receipt,
    )?;
    ensure!(
        Stamp::of(&fs::symlink_metadata(path)?) == stamp,
        "retirement body changed during shared integrity proof"
    );
    Ok((stamp, proof))
}
async fn remote(client: &Client, r2: &R2Config, receipt: &Receipt) -> Result<()> {
    let before = head_archive(client, &r2.bucket, &receipt.archive_key)
        .await?
        .context("remote203 archive missing")?;
    validate_remote_against_receipt(&before, receipt)?;
    ensure!(
        remote_sidecar(client, &r2.bucket, &receipt.checksum_key)
            .await?
            .as_deref()
            == Some(canonical_sidecar(receipt).as_slice()),
        "remote203 canonical sidecar differs"
    );
    let after = head_archive(client, &r2.bucket, &receipt.archive_key)
        .await?
        .context("remote203 archive disappeared")?;
    validate_remote_against_receipt(&after, receipt)?;
    Ok(())
}

fn operation(binding: &Bound, c: &Plan, p: &RetirePlan) -> Value {
    json!({"profile":"fixed203-replica-retirement-v1","retire_plan":binding,"inspection":p.inspection,
        "inspection_plan":p.inspection_plan,"closure_plan":p.closure_plan,
        "source":SOURCE,"quarantine":qpath(),"source_identity":c.source_identity,
        "retained204":RETAINED,"retained204_identity":c.retained204_identity,"parent_identity":c.parent_identity})
}
fn record_path(phase: &str) -> Result<PathBuf> {
    ensure!(
        ["intent", "moved", "verified", "unlink-intent", "completion"].contains(&phase),
        "foreign lifecycle phase"
    );
    Ok(Path::new(STATE).join(format!("{phase}.json")))
}
fn record(phase: &str, op: &Value) -> Result<Option<(Bound, Value)>> {
    let path = record_path(phase)?;
    if !present(&path)? {
        return Ok(None);
    }
    let raw = read_stable_bounded(&path, MAX_METADATA, "fixed203 lifecycle record")?;
    let b = Bound {
        path,
        sha256: hex_lower(&Sha256::digest(&raw)),
    };
    let v = saved(&b)?;
    ensure!(
        v["schema"] == "jetstreamer-scan203-retirement-record-v1"
            && v["phase"] == phase
            && v["operation"] == *op,
        "foreign fixed203 lifecycle record"
    );
    Ok(Some((b, v)))
}
fn publish(phase: &str, op: &Value, data: Value, state: &File) -> Result<(Bound, Value)> {
    let path = record_path(phase)?;
    let v = json!({"schema":"jetstreamer-scan203-retirement-record-v1","phase":phase,
        "operation":op,"recorded_unix_seconds":now()?,"data":data});
    let b = publish_at(&path, &v, state)?;
    Ok((b, v))
}
fn publish_at(path: &Path, v: &Value, state: &File) -> Result<Bound> {
    let parent = path.parent().context("record parent")?;
    let opened = state.metadata()?;
    let named = fs::symlink_metadata(parent)?;
    ensure!(
        opened.is_dir()
            && named.is_dir()
            && opened.dev() == named.dev()
            && opened.ino() == named.ino()
            && opened.uid() == 0
            && opened.mode() & 0o077 == 0,
        "record parent changed before publication"
    );
    let bytes = serde_json::to_vec(v)?;
    ensure!(
        bytes.len() as u64 <= MAX_METADATA,
        "retirement record bound"
    );
    let mut tmp = tempfile::NamedTempFile::new_in(path.parent().context("record parent")?)?;
    tmp.write_all(&bytes)?;
    // Reuse the canonical writer's no-clobber publication, then fsync the final
    // metadata (including its0440 mode) and only this private directory.
    persist_noclobber(tmp, path)?;
    File::open(path)?.sync_all()?;
    state.sync_all()?;
    let after = fs::symlink_metadata(parent)?;
    ensure!(
        after.is_dir() && after.dev() == opened.dev() && after.ino() == opened.ino(),
        "record parent replaced during publication"
    );
    let binding = Bound {
        path: path.to_path_buf(),
        sha256: hex_lower(&Sha256::digest(&bytes)),
    };
    metadata_bytes(&binding)?;
    Ok(binding)
}
fn predecessor(v: &Value, key: &str, b: &Bound) -> Result<()> {
    ensure!(
        v["data"][key] == serde_json::to_value(b)?,
        "retirement lifecycle predecessor changed"
    );
    Ok(())
}
fn recorded_body(v: &Value, expected: &Stamp) -> Result<()> {
    let stamp: Stamp = serde_json::from_value(v["data"]["quarantine_identity"].clone())?;
    ensure!(
        same_body(&stamp, expected)
            && v["data"]["body_sha256"] == SHA203
            && v["data"]["multipart_etag"] == ETAG203,
        "recorded quarantine does not prove original203 bytes"
    );
    Ok(())
}
#[derive(Debug, PartialEq, Eq)]
enum Phase {
    Initial,
    Intent,
    Moved,
    Verified,
    UnlinkPending,
    Unlinked,
    Complete,
}
fn lifecycle(
    source: bool,
    q: bool,
    intent: bool,
    moved: bool,
    verified: bool,
    unlink: bool,
    complete: bool,
) -> Result<Phase> {
    ensure!(
        !(source && q)
            && (!moved || intent)
            && (!verified || moved)
            && (!unlink || verified)
            && (!complete || unlink),
        "invalid fixed203 lifecycle chain"
    );
    Ok(if complete {
        ensure!(!source && !q, "completed source/quarantine reappeared");
        Phase::Complete
    } else if unlink {
        ensure!(!source, "unlink lifecycle source reappeared");
        if q {
            Phase::UnlinkPending
        } else {
            Phase::Unlinked
        }
    } else if verified {
        ensure!(!source && q, "verified quarantine missing/replaced");
        Phase::Verified
    } else if moved {
        ensure!(!source && q, "moved quarantine missing");
        Phase::Moved
    } else if intent {
        ensure!(source || q, "intent alone cannot prove disappearance");
        if q { Phase::Moved } else { Phase::Intent }
    } else {
        ensure!(source && !q, "initial source missing or foreign quarantine");
        Phase::Initial
    })
}
fn free_bytes(dir: &File) -> Result<u64> {
    let mut s = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::fstatvfs(dir.as_raw_fd(), s.as_mut_ptr()) } == 0,
        "retirement free witness failed"
    );
    let s = unsafe { s.assume_init() };
    s.f_bavail
        .checked_mul(s.f_frsize)
        .context("free witness overflow")
}

pub(crate) async fn run() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    let check = args.last().is_some_and(|s| s == "--check-only");
    ensure!(
        args.len() == if check { 6 } else { 5 }
            && args[1] == "retire-scan203"
            && args[3] == "--self-sha256",
        "usage: retire-scan203 PLAN --self-sha256 SHA [--check-only]; Root EnvironmentFile supplies HORIZON_SCAN203_PLAN_SHA256"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "fixed203 retirement requires Root"
    );
    ensure!(
        is_lower_hex(&args[4], 64)
            && hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == args[4],
        "actual retirement executable changed"
    );
    let binding = Bound {
        path: args[2].clone().into(),
        sha256: env::var("HORIZON_SCAN203_PLAN_SHA256")
            .context("Root plan digest transport missing")?,
    };
    let p: RetirePlan = serde_json::from_value(saved(&binding)?)?;
    let old: Plan = serde_json::from_value(saved(&p.inspection_plan)?)?;
    scope(&old)?;
    let c: Plan = serde_json::from_value(saved(&p.closure_plan)?)?;
    plan_scope(&p, &c)?;
    let prior = saved(&p.inspection)?;
    ensure!(
        prior["plan"] == serde_json::to_value(&p.inspection_plan)?,
        "prior inspection names another plan"
    );
    continuation(&old, &c, &p.inspection, &prior)?;
    let state = directory(Path::new(STATE), &p.state_identity)?;
    let scan = directory(Path::new(ROOT), &c.parent_identity)?;
    let iid = env::var("INVOCATION_ID").context("actual retirement invocation absent")?;
    owner(&c, &args, &iid, check)?;
    let op = operation(&binding, &c, &p);
    let records = |op: &Value| -> Result<_> {
        Ok((
            record("intent", op)?,
            record("moved", op)?,
            record("verified", op)?,
            record("unlink-intent", op)?,
            record("completion", op)?,
        ))
    };
    let (mut intent, mut moved, mut verified, mut unlink, complete) = records(&op)?;
    let initial = lifecycle(
        present(Path::new(SOURCE))?,
        present(&qpath())?,
        intent.is_some(),
        moved.is_some(),
        verified.is_some(),
        unlink.is_some(),
        complete.is_some(),
    )?;
    if let (Some((i, _)), Some((_, m))) = (&intent, &moved) {
        predecessor(m, "intent", i)?;
    }
    if let (Some((m, _)), Some((_, v))) = (&moved, &verified) {
        predecessor(v, "moved", m)?;
    }
    if let (Some((v, _)), Some((_, u))) = (&verified, &unlink) {
        predecessor(u, "verified", v)?;
    }
    if let (Some((u, _)), Some((_, done))) = (&unlink, &complete) {
        predecessor(done, "unlink_intent", u)?;
    }
    if let Some((_, i)) = &intent {
        ensure!(
            i["data"]["body_sha256"] == SHA203 && i["data"]["multipart_etag"] == ETAG203,
            "intent did not prove exact original203 bytes"
        );
    }
    if let Some((_, v)) = &verified {
        recorded_body(v, &c.source_identity)?;
        ensure!(
            moved.as_ref().unwrap().1["data"]["quarantine_identity"]
                == v["data"]["quarantine_identity"],
            "moved/verified quarantine generation differs"
        );
    }
    if let Some((_, u)) = &unlink {
        ensure!(
            u["data"]["quarantine_identity"]
                == verified.as_ref().unwrap().1["data"]["quarantine_identity"],
            "unlink intent changed verified generation"
        );
    }
    let chain = [&intent, &moved, &verified, &unlink, &complete];
    let mut prior_time = 0;
    for entry in chain.into_iter().flatten() {
        let t = entry.1["recorded_unix_seconds"]
            .as_u64()
            .context("lifecycle clock omitted")?;
        ensure!(
            t >= prior_time && t <= now()?,
            "lifecycle clock order/future"
        );
        prior_time = t;
    }
    replica(Path::new(RETAINED), &c.retained204_identity)?;
    if initial == Phase::Complete {
        println!("{}", serde_json::to_string(&complete.unwrap().1)?);
        return Ok(());
    }
    let close = closure(&p, &c, &binding, &args, &iid, check)?;
    if check {
        directory(Path::new(GUARD_STATE), &p.guard_directory_identity)?;
        metadata_bytes(&p.guard_binary)?;
        ensure!(
            Stamp::of(&fs::symlink_metadata(LOCK)?) == p.lock_identity,
            "shared lock metadata differs before action"
        );
        if intent.is_none() {
            fresh_inspection(&prior, now()?)?;
        }
        if present(Path::new(SOURCE))? {
            replica(Path::new(SOURCE), &c.source_identity)?;
        }
        if present(&qpath())? {
            ensure!(
                same_body(
                    &Stamp::of(&fs::symlink_metadata(qpath())?),
                    &c.source_identity
                ),
                "foreign quarantine"
            );
        }
        println!(
            "{}",
            json!({"schema":"jetstreamer-scan203-retirement-check-v1","plan":binding,"phase":format!("{initial:?}"),
            "closure":close,"retirement_authorized":false,"archive_body_opened":false,"remote_requests":0,"locks_acquired":0,"space_credit_bytes":0})
        );
        return Ok(());
    }
    let release = startup(&p, &binding, &args[4], &iid).await?;
    let lease = fleet::scan203_mutation_lock()?;
    ensure!(
        Stamp::of(&lease.metadata()?) == p.lock_identity
            && Stamp::of(&fs::symlink_metadata(LOCK)?) == p.lock_identity,
        "shared mutation lock identity/owner changed"
    );
    // Another admitted actor may have completed while startup waited. Refuse an
    // unexpected lifecycle change; never act on the pre-lock view.
    let locked = records(&op)?;
    ensure!(
        serde_json::to_value(&locked)?
            == serde_json::to_value(&(
                intent.clone(),
                moved.clone(),
                verified.clone(),
                unlink.clone(),
                None::<(Bound, Value)>
            ))?,
        "lifecycle changed before shared lock"
    );
    let r2 = r2_config_from_env()?;
    metadata_bytes(&c.remote_receipt203)?;
    let receipt = read_restore_receipt(
        Path::new("/home/ubuntu/.jetstreamer-private/r2-receipts"),
        &r2.bucket,
        203,
    )?;
    ensure!(
        receipt.archive_sha256 == SHA203
            && receipt.archive_length == LENGTH203
            && receipt.multipart_part_size == DEFAULT_PART_SIZE
            && receipt.remote_sha256_readback,
        "original203 durable remote proof differs"
    );
    ensure!(
        receipt.archive_etag == ETAG203,
        "original203 multipart identity changed"
    );
    let client = s3_client(&r2);
    remote(&client, &r2, &receipt).await?;
    current_guard(&p, &iid)?;
    if intent.is_none() {
        fresh_inspection(&prior, now()?)?;
        directory_binding(Path::new(ROOT), &scan, &c.parent_identity)?;
        let (_, proof) = body_at(&scan, SOURCE_NAME, &c.source_identity, true, &receipt)?;
        let close = closure(&p, &c, &binding, &args, &iid, false)?;
        current_guard(&p, &iid)?;
        remote(&client, &r2, &receipt).await?;
        fresh_inspection(&prior, now()?)?;
        replica(Path::new(SOURCE), &c.source_identity)?;
        let allocated = fs::symlink_metadata(SOURCE)?
            .blocks()
            .checked_mul(512)
            .context("allocation overflow")?;
        intent = Some(publish(
            "intent",
            &op,
            json!({"original_invocation_id":iid,"startup_release":release,
            "prior_inspection_recorded_unix_seconds":prior["recorded_unix_seconds"],"body_sha256":proof.sha256_hex,"multipart_etag":proof.multipart_etag,
            "closure":close,"allocated_upper_bytes":allocated,"available_before_bytes":free_bytes(&scan)?,"remote_receipt":c.remote_receipt203}),
            &state,
        )?);
    }
    if present(Path::new(SOURCE))? {
        ensure!(
            moved.is_none() && verified.is_none() && unlink.is_none() && !present(&qpath())?,
            "replacement source/lifecycle"
        );
        replica(Path::new(SOURCE), &c.source_identity)?;
        current_guard(&p, &iid)?;
        closure(&p, &c, &binding, &args, &iid, false)?;
        directory_binding(Path::new(ROOT), &scan, &c.parent_identity)?;
        let anchored = fs::symlink_metadata(child_path(&scan, SOURCE_NAME))?;
        ensure!(
            anchored.is_file() && Stamp::of(&anchored) == c.source_identity,
            "anchored source changed before rename"
        );
        move_child(&scan)?;
    }
    let mut unlinked_this_invocation = false;
    if present(&qpath())? {
        let stamp = Stamp::of(&fs::symlink_metadata(qpath())?);
        ensure!(
            same_body(&stamp, &c.source_identity),
            "quarantine is not the original203 inode"
        );
        if let Some((_, m)) = &moved {
            ensure!(
                m["data"]["quarantine_identity"] == serde_json::to_value(&stamp)?,
                "moved quarantine metadata changed"
            );
        } else {
            moved = Some(publish(
                "moved",
                &op,
                json!({"intent":intent.as_ref().unwrap().0,"quarantine_identity":stamp}),
                &state,
            )?);
        }
        let (stamp, proof) = body_at(&scan, QUARANTINE_NAME, &c.source_identity, false, &receipt)?;
        if let Some((_, v)) = &verified {
            ensure!(
                v["data"]["quarantine_identity"] == serde_json::to_value(&stamp)?
                    && v["data"]["body_sha256"] == proof.sha256_hex
                    && v["data"]["multipart_etag"] == proof.multipart_etag,
                "verified quarantine proof changed"
            );
        } else {
            verified = Some(publish(
                "verified",
                &op,
                json!({"moved":moved.as_ref().unwrap().0,"quarantine_identity":stamp,
            "body_sha256":proof.sha256_hex,"multipart_etag":proof.multipart_etag}),
                &state,
            )?);
        }
        remote(&client, &r2, &receipt).await?;
        current_guard(&p, &iid)?;
        let close = closure(&p, &c, &binding, &args, &iid, false)?;
        if unlink.is_none() {
            unlink = Some(publish(
                "unlink-intent",
                &op,
                json!({"verified":verified.as_ref().unwrap().0,
            "quarantine_identity":stamp,"closure":close,"current_invocation_id":iid,"startup_release":release}),
                &state,
            )?);
        }
        directory_binding(Path::new(ROOT), &scan, &c.parent_identity)?;
        ensure!(
            !present(Path::new(SOURCE))?
                && Stamp::of(&fs::symlink_metadata(child_path(&scan, QUARANTINE_NAME))?) == stamp,
            "source reappeared/quarantine replaced immediately before unlink"
        );
        replica(Path::new(RETAINED), &c.retained204_identity)?;
        unlink_child(&scan)?;
        unlinked_this_invocation = true;
    }
    ensure!(
        unlink.is_some() && !present(Path::new(SOURCE))? && !present(&qpath())?,
        "unproved203 disappearance"
    );
    let close = closure(&p, &c, &binding, &args, &iid, false)?;
    replica(Path::new(RETAINED), &c.retained204_identity)?;
    directory_binding(Path::new(STATE), &state, &p.state_identity)?;
    directory_binding(Path::new(ROOT), &scan, &c.parent_identity)?;
    let available = free_bytes(&scan)?;
    let done = publish(
        "completion",
        &op,
        json!({"unlink_intent":unlink.as_ref().unwrap().0,"intent":intent.as_ref().unwrap().0,
        "source_absent":true,"quarantine_absent":true,"retained204_identity":c.retained204_identity,"closure":close,
        "original_invocation_id":intent.as_ref().unwrap().1["data"]["original_invocation_id"],"completion_invocation_id":iid,
        "reconciled_after_prior_unlink_intent":!unlinked_this_invocation,"unlink_performed_this_invocation":unlinked_this_invocation,"available_after_bytes":available,
        "available_before_bytes":intent.as_ref().unwrap().1["data"]["available_before_bytes"],
        "historical_allocated_upper_bytes":intent.as_ref().unwrap().1["data"]["allocated_upper_bytes"],
        "retired_source_logical_bytes":LENGTH203,"removed_logical_bytes_this_invocation":if unlinked_this_invocation{LENGTH203}else{0},"net_free_delta_is_not_exact_reclaimed_bytes":true,
        "space_credit_bytes":0,"remote_mutations":false,"canonical_or_retained204_mutations":false,
        "restore_required_before_historical_body_consumer_reuse":true,"all_lineage_and_original_metadata_preserved":true}),
        &state,
    )?;
    println!("{}", serde_json::to_string(&done.1)?);
    Ok(())
}
