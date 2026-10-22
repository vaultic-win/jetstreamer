//! One event-driven private reader handoff; no replay, retirement or R2 authority.
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const ROOT: &str = "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-203-f9fc5a0-v1";
const PRODUCER: &str = "horizon-qualify-203-shrink-root-prefix-resource-f9fc5a0-v1.service";
const PRODUCER_IID: &str = "748ffa40e0a2408da0a10fc9e160cf0a";
const OTHER: &str = "horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service";
const OTHER_IID: &str = "4cd76ae1353a4411885b997f04306402";
const DISPATCH: &str = "horizon-prefix203-completion-dispatch-v1.service";
const WATCH: &str = "horizon-prefix203-completion-v1.path";
const READER: &str = "horizon-independent-prefix203-completion-reader-v1.service";
const READER_BINARY: &str = "/var/lib/jetstreamer/horizon-native203-restore-prepared-76e5194-v1/jetstreamer-qualification-verify";
const READER_SHA: &str = "660199772c8a3f8752a84fb3bbb1f3aa80adf67cfc3b8b113f2b004852ad879b";
const WORKER: &str = "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc";
const STATE: &str = "/var/lib/jetstreamer/horizon-prefix203-completion-v1";
const BINARY: &str = "/var/lib/jetstreamer/horizon-prefix203-completion-dispatch-v1/jetstreamer-prefix203-completion-dispatch";
const FLOOR: u64 = 248_289_182_611;
const GIB: u64 = 1 << 30;
const REQUIRED_MEMORY: u64 = (448 + 128 + 8 + 4) * GIB;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    observer: Bound,
    fleet: Bound,
    reader_unit_file: Bound,
    path_unit_file: Bound,
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|n| format!("{n:02x}")).collect()
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identity(m: &fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn read(path: &Path, uid: u32, immutable: bool, max: u64) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical input"
    );
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file()
            && m.uid() == uid
            && m.nlink() == 1
            && m.mode() & 0o6022 == 0
            && (!immutable || m.mode() & 0o222 == 0)
            && m.len() <= max,
        "unsafe input:{}",
        path.display()
    );
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    ensure!(
        identity(&m) == identity(&f.metadata()?),
        "input replaced at open"
    );
    let mut bytes = Vec::new();
    (&f).take(max + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == m.len()
            && identity(&m) == identity(&f.metadata()?)
            && identity(&m) == identity(&fs::symlink_metadata(path)?),
        "input changed during read"
    );
    Ok(bytes)
}
fn bound(b: &Bound, max: u64) -> Result<Vec<u8>> {
    ensure!(digest(&b.sha256), "invalid digest");
    let bytes = read(&b.path, 0, true, max)?;
    ensure!(
        hex(&Sha256::digest(&bytes)) == b.sha256,
        "digest mismatch:{}",
        b.path.display()
    );
    Ok(bytes)
}
fn show(unit: &str) -> Result<BTreeMap<String, String>> {
    let o=Command::new("systemctl").args(["show",unit,"--property=Id,InvocationID,LoadState,ActiveState,SubState,MainPID,NRestarts,Result,ExecMainStatus,ExecStart,FragmentPath,Type,OnSuccess,User,ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges,ReadWritePaths"]).output()?;
    ensure!(
        o.status.success() && o.stdout.len() < 32768,
        "unit unreadable:{unit}"
    );
    Ok(std::str::from_utf8(&o.stdout)?
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.into(), v.into()))
        .collect())
}
fn field<'a>(s: &'a BTreeMap<String, String>, k: &str) -> Result<&'a str> {
    Ok(s.get(k)
        .with_context(|| format!("unit field missing:{k}"))?)
}
fn terminal(s: &BTreeMap<String, String>) -> Result<()> {
    ensure!(
        field(s, "Id")? == PRODUCER
            && field(s, "ActiveState")? == "inactive"
            && field(s, "SubState")? == "dead"
            && field(s, "MainPID")? == "0"
            && field(s, "NRestarts")? == "0"
            && field(s, "Result")? == "success"
            && field(s, "ExecMainStatus")? == "0"
            && matches!(field(s, "InvocationID")?, "" | PRODUCER_IID),
        "producer is not the clean terminal owner"
    );
    Ok(())
}
fn manager_success() -> Result<()> {
    let o = Command::new("journalctl")
        .args([
            &format!("INVOCATION_ID={PRODUCER_IID}"),
            "--no-pager",
            "-o",
            "json",
        ])
        .output()?;
    ensure!(
        o.status.success() && o.stdout.len() < 4 << 20,
        "manager journal unreadable"
    );
    let expected = format!("{PRODUCER}: Deactivated successfully.");
    let mut found = false;
    for line in o.stdout.split(|b| *b == b'\n').filter(|b| !b.is_empty()) {
        let v: Value = serde_json::from_slice(line)?;
        found |= v["UNIT"] == PRODUCER
            && v["INVOCATION_ID"] == PRODUCER_IID
            && v["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
            && v["MESSAGE"] == expected;
    }
    ensure!(
        found,
        "exact producer invocation lacks manager success evidence"
    );
    Ok(())
}
fn producer_result(v: &Value, m: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-private-epoch203-shrink-root-prefix-resource-v1"
            && v["epoch"] == 203
            && v["unit"] == PRODUCER
            && v["invocation_id"] == PRODUCER_IID
            && v["success"] == true
            && v["error"].is_null()
            && v["natural_parent_completion_required"] == true
            && v["child_return_code"] == 0
            && v["external_signal"] == 0
            && v["producer_canonical_root_prefix_present"] == true
            && v["terminal_root_slot"] == 88127580u64
            && v["target_slot"] == 88127580u64
            && v["worker_sha256"] == WORKER
            && v["runner_sha256"]
                == "7b6406fd2d0c36a1469cc3fef98cd647f54ae35764f3e82f9e2a395da8f42464"
            && v["node_sha256"]
                == "025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d"
            && v["snapshot_sha256"]
                == "e45584858d0c825f095a43ff5e5909e62a68d197d39c042a76727454525228c4"
            && v["producer_segment_manifest"] == *m,
        "wrong producer terminal result"
    );
    for key in [
        "canonical_prefix_independently_qualified",
        "full_cold_epoch_peak_qualified",
        "ordinary_replay_authorized",
        "runtime_promotion_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            v["authority"][key] == false,
            "producer result grants foreign authority:{key}"
        );
    }
    ensure!(
        m["epoch"] == 203
            && m["output_slot_start"] == 87696000u64
            && m["output_slot_count"] == 431581
            && m["bootstrap"]["slot"] == 87695515u64
            && m["bootstrap"]["slot_complete"] == true
            && m["terminal"]["slot"] == 88127580u64
            && m["terminal"]["slot_complete"] == true
            && m["terminal"]["accounts_hash"] == "4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf"
            && m["worker_executable_sha256"] == WORKER
            && m["runtime"]["runtime_profile"] == "solana-v1.6.16"
            && m["archive_sha256"].as_str().is_some_and(digest),
        "wrong private prefix manifest"
    );
    Ok(())
}
fn utc(s: &str) -> Result<u64> {
    ensure!(s.len() == 20 && s.is_ascii(), "invalid sample time");
    let c = std::ffi::CString::new(s)?;
    let mut t: libc::tm = unsafe { std::mem::zeroed() };
    let end = unsafe { libc::strptime(c.as_ptr(), c"%Y-%m-%dT%H:%M:%SZ".as_ptr(), &mut t) };
    ensure!(
        !end.is_null() && unsafe { *end } == 0,
        "invalid sample time"
    );
    let n = unsafe { libc::timegm(&mut t) };
    ensure!(n >= 0, "negative time");
    let mut out = [0i8; 32];
    unsafe {
        libc::strftime(
            out.as_mut_ptr(),
            out.len(),
            c"%Y-%m-%dT%H:%M:%SZ".as_ptr(),
            &t,
        )
    };
    ensure!(
        unsafe { std::ffi::CStr::from_ptr(out.as_ptr()) }.to_str()? == s,
        "noncanonical sample time"
    );
    Ok(n as u64)
}
fn evidence(o: &Value, f: &Value, hash: &str, now: u64) -> Result<()> {
    let sample = o["recorded_at_utc"]
        .as_str()
        .context("sample time missing")?;
    let at = utc(sample)?;
    ensure!(
        at <= now
            && now - at <= 1800
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && o["cadence"]["routine_minimum_interval_enforced"] == true
            && o["cadence"]["minimum_interval_seconds"] == 1800
            && o["cadence"]["observation_reason"] == "routine"
            && o["host_memory"]["conservative_available_kib"]
                .as_u64()
                .and_then(|n| n.checked_mul(1024))
                .is_some_and(|n| n >= REQUIRED_MEMORY),
        "stale or inadmissible resource evidence"
    );
    for key in [
        "producer_or_controller_signals_sent",
        "service_state_changed",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(o["mutation"][key] == false, "mutating resource observation");
    }
    let diagnostics = o["diagnostic_replays"]
        .as_array()
        .context("diagnostic census absent")?;
    ensure!(
        diagnostics.len() == 2 && o["replays"].as_array().is_some_and(Vec::is_empty),
        "resource census changed"
    );
    for (range, unit, id) in [
        ("203-203", PRODUCER, PRODUCER_IID),
        ("225-226", OTHER, OTHER_IID),
    ] {
        let matching: Vec<_> = diagnostics.iter().filter(|d| d["range"] == range).collect();
        ensure!(matching.len() == 1, "missing/duplicate baseline diagnostic");
        let d = matching[0];
        ensure!(
            d["status"] == "observed"
                && d["producer_unit"] == unit
                && d["expected_producer_invocation_id"] == id
                && d["observation"]["invocation_binding_stable"] == true,
            "unbound baseline diagnostic"
        );
        for state in [
            "controller_before",
            "controller_after",
            "producer_before",
            "producer_after",
        ] {
            ensure!(
                d["observation"][state]["invocation_id"] == id
                    && d["observation"][state]["restarts"] == 0
                    && d["observation"][state]["active_state"] == "active",
                "unstable baseline diagnostic"
            );
        }
    }
    ensure!(
        f["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && f["observer_sha256"] == hash
            && f["sampled_at_utc"] == sample
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["producer_mutations"] == false
            && f["remote_mutations"] == false,
        "unbound complete fleet"
    );
    let entries = f["inventory"]["entries"]
        .as_array()
        .context("inventory missing")?;
    ensure!(entries.len() == 100, "incomplete inventory");
    let mut sum = 0u64;
    let mut count = 0u64;
    for (i, e) in entries.iter().enumerate() {
        ensure!(e["epoch"] == 201 + i as u64, "inventory census changed");
        if e["state"] == "ready-pair" {
            sum = sum
                .checked_add(
                    e["archive_length"]
                        .as_u64()
                        .context("ready length missing")?,
                )
                .context("length overflow")?;
            count += 1;
        }
    }
    ensure!(
        count == 13
            && sum
                .checked_mul(2)
                .context("floor overflow")?
                .div_ceil(count)
                == FLOOR,
        "century samples changed"
    );
    let a = f["active"].as_array().context("active census missing")?;
    let mut seen = std::collections::BTreeSet::new();
    for e in a {
        let epoch = e["epoch"].as_u64().context("active epoch missing")?;
        ensure!(seen.insert(epoch), "duplicate active epoch");
        if epoch == 203 || epoch == 225 {
            let (unit, id) = if epoch == 203 {
                (PRODUCER, PRODUCER_IID)
            } else {
                (OTHER, OTHER_IID)
            };
            ensure!(
                e["phase"] == "diagnostic-qualification"
                    && e["producer"]["Id"] == unit
                    && e["producer"]["InvocationID"] == id
                    && e["producer"]["NRestarts"] == "0",
                "foreign baseline replay"
            );
        } else {
            ensure!(
                epoch == 223
                    && e["phase"] == "private-cold-snapshot-verification"
                    && e["expected_invocation_id"] == "8530e388da6640a68e6ca0f85b8828b1"
                    && e["unit"]["Id"] == "archive-223-cold-snapshot-test-actual-v1.service",
                "foreign auxiliary work"
            );
        }
    }
    ensure!(
        seen.contains(&203) && seen.contains(&225),
        "baseline producer missing"
    );
    Ok(())
}
fn current_other(f: &Value) -> Result<()> {
    let s = show(OTHER)?;
    ensure!(
        field(&s, "InvocationID")? == OTHER_IID
            && field(&s, "NRestarts")? == "0"
            && field(&s, "ActiveState")? == "active"
            && field(&s, "SubState")? == "running",
        "older225owner changed"
    );
    let old = f["active"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["epoch"] == 225)
        .unwrap();
    let expected = old["producer"]["ExecStart"]
        .as_str()
        .context("baseline225command absent")?;
    ensure!(
        expected.split_once(" ; ignore_errors=").map(|x| x.0)
            == field(&s, "ExecStart")?
                .split_once(" ; ignore_errors=")
                .map(|x| x.0),
        "older225command changed"
    );
    Ok(())
}
fn available_memory() -> Result<u64> {
    let text = fs::read_to_string("/proc/meminfo")?;
    let n = text
        .lines()
        .find_map(|l| {
            l.strip_prefix("MemAvailable:")
                .and_then(|s| s.split_whitespace().next())
        })
        .context("memory unavailable")?
        .parse::<u64>()?;
    n.checked_mul(1024).context("memory overflow")
}
fn free_bytes() -> Result<u64> {
    let path = std::ffi::CString::new("/")?;
    let mut v: libc::statvfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), &mut v) } == 0,
        "filesystem unreadable"
    );
    v.f_bavail.checked_mul(v.f_frsize).context("free overflow")
}
fn absent(path: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "path occupied:{}",
        path.display()
    );
    Ok(())
}
fn reader_command() -> String {
    format!(
        "{{ path={READER_BINARY} ; argv[]={READER_BINARY} {ROOT}/output/epoch-203-prefix.jet --private-root={ROOT} --expected-epoch=203 --expected-output-start-slot=87696000 --expected-bootstrap-slot=87695515 --expected-terminal-slot=88127580 --expected-runtime-profile=solana-v1.6.16 --expected-worker-sha256={WORKER} --receipt={ROOT}/independent-native-reader-v1/epoch-203-prefix.validation.json"
    )
}
fn persist(v: &Value) -> Result<()> {
    let dir = Path::new(STATE);
    let m = fs::symlink_metadata(dir)?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o6077 == 0 && dir.canonicalize()? == dir,
        "unsafe handoff receipt directory"
    );
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir.join("ready.json"))?;
    serde_json::to_writer_pretty(&mut f, v)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(dir)?.sync_all()?;
    Ok(())
}
fn dispatch_unit_text(plan_path: &Path, plan_hash: &str, self_hash: &str) -> String {
    format!(
        "[Unit]\nDescription=One-shot closed private epoch203 prefix reader handoff\nOnSuccess={READER}\nOnSuccessJobMode=fail\n\n[Service]\nType=oneshot\nUser=root\nGroup=root\nRestart=no\nKillMode=control-group\nTimeoutStartSec=2min\nUMask=0077\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=read-only\nPrivateNetwork=yes\nPrivateTmp=yes\nCapabilityBoundingSet=CAP_DAC_OVERRIDE\nAmbientCapabilities=CAP_DAC_OVERRIDE\nReadWritePaths={STATE}\nCPUQuota=100%\nMemoryHigh=2G\nMemoryMax=4G\nMemorySwapMax=0\nTasksMax=256\nExecStart={BINARY} {} --plan-sha256 {plan_hash} --self-sha256 {self_hash}\n",
        plan_path.display()
    )
}
fn execute(plan: &Plan, plan_path: &Path, plan_hash: &str, self_hash: &str) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0
            && plan.schema == "jetstreamer-private-epoch203-prefix-reader-dispatch-plan-v1",
        "wrong dispatcher profile"
    );
    for (b, name) in [
        (&plan.reader_unit_file, READER),
        (&plan.path_unit_file, WATCH),
    ] {
        ensure!(
            b.path == Path::new("/etc/systemd/system").join(name),
            "foreign unit file"
        );
        bound(b, 65536)?;
    }
    let dispatch_path = Path::new("/etc/systemd/system").join(DISPATCH);
    ensure!(
        read(&dispatch_path, 0, true, 65536)?
            == dispatch_unit_text(plan_path, plan_hash, self_hash).as_bytes(),
        "dispatcher unit differs from closed compiled template"
    );
    let own = show(DISPATCH)?;
    let inv = env::var("INVOCATION_ID")?;
    ensure!(
        field(&own, "MainPID")? == std::process::id().to_string()
            && field(&own, "InvocationID")? == inv
            && field(&own, "NRestarts")? == "0"
            && field(&own, "Type")? == "oneshot"
            && field(&own, "OnSuccess")? == READER
            && field(&own, "User")? == "root"
            && field(&own, "ProtectSystem")? == "strict"
            && field(&own, "ProtectHome")? == "read-only"
            && field(&own, "PrivateNetwork")? == "yes"
            && field(&own, "NoNewPrivileges")? == "yes"
            && field(&own, "ReadWritePaths")? == STATE,
        "unbound dispatcher sandbox"
    );
    let watch = show(WATCH)?;
    ensure!(
        field(&watch, "FragmentPath")? == plan.path_unit_file.path.to_str().unwrap()
            && field(&watch, "ActiveState")? == "active"
            && matches!(field(&watch, "SubState")?, "waiting" | "running"),
        "unbound completion watcher"
    );
    // Stop this exact one-shot event source even if a later admission gate fails.
    ensure!(
        Command::new("systemctl")
            .args(["stop", WATCH])
            .status()?
            .success(),
        "cannot stop completion watcher"
    );
    absent(&Path::new(STATE).join("ready.json"))?;
    if fs::symlink_metadata(Path::new(ROOT).join("receipts/root-prefix.json"))
        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    {
        terminal(&show(PRODUCER)?)?;
        anyhow::bail!("clean terminal producer lacks its durable result");
    }
    for attempt in 0..60 {
        if terminal(&show(PRODUCER)?).is_ok() {
            break;
        }
        ensure!(attempt < 59, "producer did not reach clean terminal state");
        thread::sleep(Duration::from_millis(250));
    }
    terminal(&show(PRODUCER)?)?;
    for attempt in 0..60 {
        if manager_success().is_ok() {
            break;
        }
        ensure!(
            attempt < 59,
            "clean terminal manager event did not become durable"
        );
        thread::sleep(Duration::from_millis(250));
    }
    manager_success()?;
    let reader = show(READER)?;
    ensure!(
        field(&reader, "ActiveState")? == "inactive"
            && field(&reader, "MainPID")? == "0"
            && field(&reader, "NRestarts")? == "0"
            && field(&reader, "InvocationID")?.is_empty()
            && field(&reader, "ExecStart")?
                .split_once(" ; ignore_errors=")
                .map(|x| x.0)
                == Some(reader_command().as_str()),
        "reader is occupied or command differs"
    );
    let rb = Bound {
        path: READER_BINARY.into(),
        sha256: READER_SHA.into(),
    };
    bound(&rb, 64 << 20)?;
    let result_path = Path::new(ROOT).join("receipts/root-prefix.json");
    let manifest_path = Path::new(ROOT).join("output/epoch-203-prefix.jet.segment.json");
    let archive = Path::new(ROOT).join("output/epoch-203-prefix.jet");
    let result_bytes = read(&result_path, 1000, false, 4 << 20)?;
    let result: Value = serde_json::from_slice(&result_bytes)?;
    let manifest_bytes = read(&manifest_path, 1000, false, 1 << 20)?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)?;
    producer_result(&result, &manifest)?;
    let manifest_hash = hex(&Sha256::digest(&manifest_bytes));
    ensure!(
        result["producer_segment_manifest_sha256"] == manifest_hash,
        "manifest raw digest differs"
    );
    let a = fs::symlink_metadata(&archive)?;
    ensure!(
        a.is_file()
            && a.nlink() == 1
            && a.uid() == 1000
            && a.mode() & 0o6077 == 0
            && a.len() > 0
            && result["archive_length"] == a.len(),
        "archive identity differs"
    );
    absent(&archive.with_file_name("epoch-203-prefix.jet.sha256"))?;
    absent(&Path::new(ROOT).join("independent-native-reader-v1/epoch-203-prefix.validation.json"))?;
    let receipt_parent = Path::new(ROOT).join("independent-native-reader-v1");
    let parent = fs::symlink_metadata(&receipt_parent)?;
    ensure!(
        parent.is_dir()
            && parent.uid() == 0
            && parent.mode() & 0o6077 == 0
            && receipt_parent.canonicalize()? == receipt_parent,
        "unsafe independent reader receipt parent"
    );
    let o: Value = serde_json::from_slice(&bound(&plan.observer, 16 << 20)?)?;
    let f: Value = serde_json::from_slice(&bound(&plan.fleet, 16 << 20)?)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    evidence(&o, &f, &plan.observer.sha256, now)?;
    current_other(&f)?;
    let memory = available_memory()?;
    let free = free_bytes()?;
    ensure!(
        memory >= REQUIRED_MEMORY && free >= FLOOR + 640 * GIB + (1 << 20),
        "fresh reader resource admission failed"
    );
    terminal(&show(PRODUCER)?)?;
    current_other(&f)?;
    ensure!(
        identity(&a) == identity(&fs::symlink_metadata(&archive)?)
            && read(&result_path, 1000, false, 4 << 20)? == result_bytes
            && read(&manifest_path, 1000, false, 1 << 20)? == manifest_bytes,
        "terminal artifact changed before handoff"
    );
    absent(&archive.with_file_name("epoch-203-prefix.jet.sha256"))?;
    persist(
        &json!({"schema":"jetstreamer-private-epoch203-prefix-reader-handoff-v1","epoch":203,"dispatcher_invocation_id":inv,"producer_unit":PRODUCER,"producer_invocation_id":PRODUCER_IID,"producer_manager_success_proven":true,"producer_result_sha256":hex(&Sha256::digest(&result_bytes)),"segment_manifest_sha256":manifest_hash,"archive_bytes":a.len(),"reader":READER,"reader_sha256":READER_SHA,"plan_sha256":plan_hash,"self_sha256":self_hash,"observer_sha256":plan.observer.sha256,"fleet_sha256":plan.fleet.sha256,"available_memory_bytes":memory,"available_filesystem_bytes":free,"reader_handoff_authorized":true,"independent_prefix_validation_passed":false,"replay_launch_authorized":false,"native_restart_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )
}
fn main() {
    let r = (|| -> Result<()> {
        let a: Vec<_> = env::args().skip(1).collect();
        ensure!(
            a.len() == 5 && a[1] == "--plan-sha256" && a[3] == "--self-sha256",
            "usage: prefix203-completion-dispatch PLAN --plan-sha256 HEX --self-sha256 HEX"
        );
        ensure!(
            fs::read_link("/proc/self/exe")? == Path::new(BINARY),
            "foreign dispatcher executable path"
        );
        bound(
            &Bound {
                path: fs::read_link("/proc/self/exe")?,
                sha256: a[4].clone(),
            },
            64 << 20,
        )?;
        let p: Plan = serde_json::from_slice(&bound(
            &Bound {
                path: a[0].clone().into(),
                sha256: a[2].clone(),
            },
            1 << 20,
        )?)?;
        execute(&p, Path::new(&a[0]), &a[2], &a[4])
    })();
    if let Err(e) = r {
        eprintln!("prefix203 completion dispatch failed closed: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn manifest() -> Value {
        json!({"epoch":203,"output_slot_start":87696000,"output_slot_count":431581,"bootstrap":{"slot":87695515,"slot_complete":true},"terminal":{"slot":88127580,"slot_complete":true,"accounts_hash":"4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf"},"worker_executable_sha256":WORKER,"runtime":{"runtime_profile":"solana-v1.6.16"},"archive_sha256":"a".repeat(64)})
    }
    fn result() -> Value {
        json!({"schema":"jetstreamer-private-epoch203-shrink-root-prefix-resource-v1","epoch":203,"unit":PRODUCER,"invocation_id":PRODUCER_IID,"success":true,"error":null,"natural_parent_completion_required":true,"child_return_code":0,"external_signal":0,"producer_canonical_root_prefix_present":true,"terminal_root_slot":88127580,"target_slot":88127580,"worker_sha256":WORKER,"runner_sha256":"7b6406fd2d0c36a1469cc3fef98cd647f54ae35764f3e82f9e2a395da8f42464","node_sha256":"025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d","snapshot_sha256":"e45584858d0c825f095a43ff5e5909e62a68d197d39c042a76727454525228c4","producer_segment_manifest":manifest(),"authority":{"canonical_prefix_independently_qualified":false,"full_cold_epoch_peak_qualified":false,"ordinary_replay_authorized":false,"runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}})
    }
    #[test]
    fn exact_parent_result_and_all_authority_denials_are_required() {
        let r = result();
        producer_result(&r, &manifest()).unwrap();
        for key in r.as_object().unwrap().keys() {
            if key == "error" {
                continue;
            }
            let mut bad = r.clone();
            bad[key] = Value::Null;
            assert!(producer_result(&bad, &manifest()).is_err(), "{key}");
        }
        for key in r["authority"].as_object().unwrap().keys() {
            let mut bad = r.clone();
            bad["authority"][key] = json!(true);
            assert!(producer_result(&bad, &manifest()).is_err(), "{key}");
        }
    }
    #[test]
    fn altered_span_or_canonical_root_cannot_start_reader() {
        let r = result();
        for key in [
            "epoch",
            "output_slot_start",
            "output_slot_count",
            "bootstrap",
            "terminal",
            "worker_executable_sha256",
            "runtime",
            "archive_sha256",
        ] {
            let mut m = manifest();
            m[key] = Value::Null;
            let mut bad = r.clone();
            bad["producer_segment_manifest"] = m.clone();
            assert!(producer_result(&bad, &m).is_err(), "{key}");
        }
    }
    #[test]
    fn live_restarted_or_replaced_producer_is_never_terminal() {
        let s = BTreeMap::from([
            ("Id".into(), PRODUCER.into()),
            ("InvocationID".into(), PRODUCER_IID.into()),
            ("ActiveState".into(), "inactive".into()),
            ("SubState".into(), "dead".into()),
            ("MainPID".into(), "0".into()),
            ("NRestarts".into(), "0".into()),
            ("Result".into(), "success".into()),
            ("ExecMainStatus".into(), "0".into()),
        ]);
        terminal(&s).unwrap();
        for (k, v) in [
            ("ActiveState", "active"),
            ("NRestarts", "1"),
            ("InvocationID", "foreign"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "1"),
            ("MainPID", "42"),
        ] {
            let mut bad = s.clone();
            bad.insert(k.into(), v.into());
            assert!(terminal(&bad).is_err(), "{k}");
        }
        let mut collected = s;
        collected.insert("InvocationID".into(), "".into());
        terminal(&collected).unwrap();
    }
    #[test]
    fn timestamp_roundtrip_rejects_normalization() {
        assert!(utc("2026-10-22T23:57:52Z").is_ok());
        assert!(utc("2026-02-30T00:00:00Z").is_err());
        assert!(utc("2026-10-22T23:57:52+00:00").is_err());
        assert_eq!(REQUIRED_MEMORY, 588 * GIB);
    }
    fn baseline() -> (Value, Value) {
        let mut diagnostics = Vec::new();
        let mut active = Vec::new();
        for (epoch, range, unit, id) in [
            (203, "203-203", PRODUCER, PRODUCER_IID),
            (225, "225-226", OTHER, OTHER_IID),
        ] {
            let mut states = json!({"invocation_binding_stable":true});
            for key in [
                "controller_before",
                "controller_after",
                "producer_before",
                "producer_after",
            ] {
                states[key] = json!({"invocation_id":id,"restarts":0,"active_state":"active"});
            }
            diagnostics.push(json!({"range":range,"status":"observed","producer_unit":unit,"expected_producer_invocation_id":id,"observation":states}));
            active.push(json!({"epoch":epoch,"phase":"diagnostic-qualification","producer":{"Id":unit,"InvocationID":id,"NRestarts":"0"}}));
        }
        let o = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"2026-10-22T23:57:52Z","cadence":{"routine_minimum_interval_enforced":true,"minimum_interval_seconds":1800,"observation_reason":"routine"},"mutation":{"producer_or_controller_signals_sent":false,"service_state_changed":false,"remote_mutations":false,"r2_mutations":false},"host_memory":{"conservative_available_kib":REQUIRED_MEMORY/1024},"replays":[],"diagnostic_replays":diagnostics});
        let sizes = [
            (201, 102605729507u64),
            (202, 101842225683),
            (206, 108774749680),
            (213, 125368013231),
            (214, 128213350837),
            (215, 128820081409),
            (216, 128977079203),
            (217, 129125423643),
            (218, 125325863645),
            (219, 128896280026),
            (220, 135699623364),
            (221, 137055363091),
            (222, 133175903649),
        ];
        let entries: Vec<_> = (201..=300)
            .map(|epoch| match sizes.iter().find(|(e, _)| *e == epoch) {
                Some((_, size)) => {
                    json!({"epoch":epoch,"state":"ready-pair","archive_length":size})
                }
                None => json!({"epoch":epoch,"state":"missing"}),
            })
            .collect();
        let f = json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","observer_sha256":"a".repeat(64),"sampled_at_utc":"2026-10-22T23:57:52Z","first_epoch":201,"last_epoch":300,"producer_mutations":false,"remote_mutations":false,"inventory":{"entries":entries},"active":active});
        (o, f)
    }
    #[test]
    fn fresh_complete_identity_stable_baseline_is_mandatory() {
        let (o, f) = baseline();
        let hash = "a".repeat(64);
        let now = utc("2026-10-23T00:08:00Z").unwrap();
        evidence(&o, &f, &hash, now).unwrap();
        assert!(evidence(&o, &f, &hash, now + 1801).is_err());
        for (ptr, value) in [
            ("/host_memory/conservative_available_kib", json!(0)),
            (
                "/cadence/observation_reason",
                json!("user-requested-status"),
            ),
            ("/mutation/remote_mutations", json!(true)),
            ("/diagnostic_replays/0/status", json!("unavailable")),
            (
                "/diagnostic_replays/1/observation/producer_after/restarts",
                json!(1),
            ),
        ] {
            let mut bad = o.clone();
            *bad.pointer_mut(ptr).unwrap() = value;
            assert!(evidence(&bad, &f, &hash, now).is_err(), "{ptr}");
        }
        for (ptr, value) in [
            ("/observer_sha256", json!("b".repeat(64))),
            ("/active/0/producer/InvocationID", json!("wrong")),
            ("/inventory/entries/0/archive_length", json!(1)),
            ("/remote_mutations", json!(true)),
        ] {
            let mut bad = f.clone();
            *bad.pointer_mut(ptr).unwrap() = value;
            assert!(evidence(&o, &bad, &hash, now).is_err(), "{ptr}");
        }
        let mut bad = f;
        bad["active"].as_array_mut().unwrap().pop();
        assert!(evidence(&o, &bad, &hash, now).is_err());
    }
    #[test]
    fn file_input_bounds_and_identity_reject_links_and_writable_peers() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("proof.json");
        fs::write(&p, b"{}").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        let uid = unsafe { libc::geteuid() };
        assert_eq!(read(&p, uid, false, 2).unwrap(), b"{}");
        assert!(read(&p, uid, false, 1).is_err());
        let link = t.path().join("link");
        fs::hard_link(&p, &link).unwrap();
        assert!(read(&p, uid, false, 2).is_err());
        fs::remove_file(&link).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o622)).unwrap();
        assert!(read(&p, uid, false, 2).is_err());
    }
}
