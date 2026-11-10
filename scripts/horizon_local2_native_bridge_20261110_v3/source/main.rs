//! Metadata-only bridge from genuine local2 launch and native process evidence.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
type R<T> = Result<T, Box<dyn std::error::Error>>;
const IMAGE: &str = "/usr/local/lib/jetstreamer/horizon-local2-native-bridge-20261110-v3/capture";
const BATCH: &str = "/var/lib/jetstreamer/cached-standard-input-qualification-20261110-v1/actual-three-local2-launch-v1";
const PATHS: &str = "/home/sol/.jetstreamer-private/local2-actual-owner-event-20261110-v1/EXACT_LOCAL2_RUN_PATHS.json";
const OUT: &str = "/var/lib/jetstreamer/local2-native-bridge-20261110-v3";
const THREAD: &str = "01a1af2a-9ce8-76a2-8939-b2112bd38f53";
const NODE: &str = "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65";
const WORKER: &str = "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819";
fn need(v: bool, m: &str) -> R<()> {
    if v { Ok(()) } else { Err(m.into()) }
}
fn s<'a>(v: &'a Value, k: &str) -> R<&'a str> {
    v[k].as_str()
        .ok_or_else(|| format!("missing string {k}").into())
}
fn n(v: &Value, k: &str) -> R<u64> {
    v[k].as_u64()
        .ok_or_else(|| format!("missing integer {k}").into())
}
fn sha(v: &[u8]) -> String {
    format!("{:x}", Sha256::digest(v))
}
fn now() -> R<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn ident(m: &fs::Metadata) -> Value {
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
        m.ctime_nsec()
    ])
}
fn raw(p: &Path) -> R<Vec<u8>> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(0x20000 | 0x80000)
        .open(p)?;
    let m = f.metadata()?;
    need(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == 0
            && m.mode() & 0o022 == 0
            && m.len() <= 16 << 20,
        "private root evidence identity/size",
    )?;
    let mut b = Vec::new();
    f.read_to_end(&mut b)?;
    need(
        ident(&m) == ident(&f.metadata()?) && ident(&m) == ident(&fs::symlink_metadata(p)?),
        "evidence changed",
    )?;
    Ok(b)
}
fn load(p: &Path) -> R<Value> {
    Ok(serde_json::from_slice(&raw(p)?)?)
}
fn bound(p: &Path) -> R<Value> {
    Ok(json!({"path":p,"sha256":sha(&raw(p)?)}))
}
fn write(p: &Path, v: &Value) -> R<Value> {
    let b = serde_json::to_vec_pretty(v)?;
    let tmp = p.with_extension(format!("tmp-{}", std::process::id()));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(0x20000 | 0x80000)
        .open(&tmp)?;
    f.write_all(&b)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    fs::hard_link(&tmp, p)?;
    fs::remove_file(&tmp)?;
    File::open(p.parent().ok_or("parent")?)?.sync_all()?;
    bound(p)
}
fn native(unit: &str) -> R<Value> {
    need(
        unit.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b)),
        "unit name",
    )?;
    let o=Command::new("/usr/bin/systemctl").args(["show",unit,"--no-pager","-pId,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Result,ExecMainStatus,ControlGroup,Job,Restart,MemoryHigh,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,ExecStart,ExecMainStartTimestamp,User,Group,WorkingDirectory,UMask,LimitNOFILE,Triggers"]).output()?;
    need(
        o.status.success() && o.stderr.is_empty() && o.stdout.len() < 65536,
        "native query",
    )?;
    let mut m = serde_json::Map::new();
    for r in std::str::from_utf8(&o.stdout)?.lines() {
        let (k, v) = r.split_once('=').ok_or("native delimiter")?;
        need(
            m.insert(k.into(), json!(v)).is_none(),
            "duplicate native key",
        )?;
    }
    Ok(Value::Object(m))
}
fn owner(v: &Value, original: &Value) -> R<()> {
    for k in [
        "Id",
        "InvocationID",
        "MainPID",
        "ControlPID",
        "NRestarts",
        "ActiveState",
        "SubState",
        "ExecMainStartTimestamp",
        "ControlGroup",
        "Job",
    ] {
        need(v[k] == original[k], "producer identity changed")?;
    }
    need(
        v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["NRestarts"] == "0"
            && v["ControlPID"] == "0"
            && s(v, "MainPID")?.parse::<u64>()? > 0
            && v["Job"] == "",
        "producer not active stable",
    )
}
fn process(pid: u64, unit: &str) -> R<Value> {
    let p = PathBuf::from(format!("/proc/{pid}"));
    let stat = fs::read_to_string(p.join("stat"))?;
    let fields = stat
        .rsplit_once(") ")
        .ok_or("proc stat")?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    need(fields.len() >= 20, "proc stat fields")?;
    let ticks: u64 = fields[19].parse()?;
    let exe = fs::read_link(p.join("exe"))?;
    let m = fs::metadata(p.join("exe"))?;
    let cmd = fs::read(p.join("cmdline"))?;
    let cg = fs::read_to_string(p.join("cgroup"))?;
    need(
        cg.lines().any(|r| r == format!("0::/system.slice/{unit}")),
        "process cgroup",
    )?;
    Ok(
        json!({"pid":pid,"start_ticks":ticks,"executable":exe,"executable_dev":m.dev(),"executable_ino":m.ino(),"executable_len":m.len(),"executable_mtime":m.mtime(),"executable_mtime_nsec":m.mtime_nsec(),"executable_ctime":m.ctime(),"executable_ctime_nsec":m.ctime_nsec(),"cmdline_sha256":sha(&cmd),"cgroup_sha256":sha(cg.as_bytes())}),
    )
}
fn image(id: &Value, expected: &str) -> R<Value> {
    let p = Path::new(s(id, "executable")?);
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(0x20000 | 0x80000)
        .open(p)?;
    let m = f.metadata()?;
    need(
        m.is_file() && m.nlink() == 1 && m.mode() & 0o022 == 0,
        "executable regular nonwritable",
    )?;
    let mut h = Sha256::new();
    let mut b = [0u8; 1 << 20];
    loop {
        let z = f.read(&mut b)?;
        if z == 0 {
            break;
        }
        h.update(&b[..z]);
    }
    need(
        format!("{:x}", h.finalize()) == expected
            && ident(&m) == ident(&f.metadata()?)
            && ident(&m) == ident(&fs::symlink_metadata(p)?),
        "full executable digest/identity",
    )?;
    need(
        id["executable_dev"] == m.dev()
            && id["executable_ino"] == m.ino()
            && id["executable_len"] == m.len(),
        "process image identity",
    )?;
    Ok(
        json!({"schema":"horizon-standard-replacement-image-hash-proof-v1","path":p,"sha256":expected,"stable_full_hash_passed":true,"dev":m.dev(),"ino":m.ino(),"len":m.len(),"mtime":m.mtime(),"mtime_nsec":m.mtime_nsec(),"ctime":m.ctime(),"ctime_nsec":m.ctime_nsec(),"recorded_unix_seconds":now()?}),
    )
}
fn start(original: &Value) -> R<u64> {
    let o = Command::new("/usr/bin/date")
        .args(["--date", s(original, "ExecMainStartTimestamp")?, "+%s"])
        .output()?;
    need(
        o.status.success() && o.stderr.is_empty(),
        "source start parse",
    )?;
    Ok(std::str::from_utf8(&o.stdout)?.trim().parse()?)
}
fn progress(line: &str, e: u64) -> R<Option<Value>> {
    let Some((_, rest)) = line.split_once("progress slot ") else {
        return Ok(None);
    };
    let mut fields = rest.split_whitespace();
    let slots = fields.next().ok_or("slot")?;
    let (slot, end) = slots.split_once('/').ok_or("slot slash")?;
    let slot: u64 = slot.parse()?;
    let end: u64 = end.parse()?;
    let mut tx = None;
    let mut accounts = None;
    for f in fields {
        if let Some(x) = f.strip_prefix("txs=") {
            tx = Some(x.parse::<u64>()?)
        }
        if let Some(x) = f.strip_prefix("accounts=") {
            accounts = Some(x.parse::<u64>()?)
        }
    }
    let tx = tx.ok_or("tx count")?;
    need(
        slot >= e * 432000 && slot < (e + 1) * 432000 && end == (e + 1) * 432000 - 1,
        "target epoch progress",
    )?;
    if tx == 0 {
        return Ok(None);
    };
    let timestamp = line
        .strip_prefix('[')
        .ok_or("log timestamp")?
        .split_whitespace()
        .next()
        .ok_or("log timestamp")?;
    need(
        timestamp.ends_with('Z') && timestamp.len() >= 20,
        "UTC progress timestamp",
    )?;
    let canonical = format!("{}Z", &timestamp[..19]);
    let o = Command::new("/usr/bin/date")
        .args(["--date", &canonical, "+%s"])
        .output()?;
    need(o.status.success(), "progress time parse")?;
    let recorded: u64 = std::str::from_utf8(&o.stdout)?.trim().parse()?;
    Ok(Some(
        json!({"epoch":e,"slot":slot,"terminal_slot":end,"transactions":tx,"account_updates":accounts.ok_or("account count")?,"recorded_unix_seconds":recorded,"source_line":line}),
    ))
}
fn log_event(log: &Path, argv: &Value, e: u64, iid: &str) -> R<(Value, Value)> {
    let a = argv.as_array().ok_or("launch argv")?;
    for k in ["StandardOutput", "StandardError"] {
        need(
            a.contains(&json!(format!("--property={k}=append:{}", log.display()))),
            "original append log binding",
        )?;
    }
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(0x20000 | 0x80000)
        .open(log)?;
    let m = f.metadata()?;
    need(
        m.is_file() && m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o077 == 0,
        "append log identity",
    )?;
    let offset = m.len().saturating_sub(1 << 20);
    f.seek(SeekFrom::Start(offset))?;
    let mut b = Vec::new();
    f.take(m.len() - offset).read_to_end(&mut b)?;
    let after = fs::symlink_metadata(log)?;
    need(
        after.dev() == m.dev() && after.ino() == m.ino() && after.len() >= m.len(),
        "append log replaced/truncated",
    )?;
    let text = std::str::from_utf8(&b)?;
    let latest = text
        .lines()
        .rev()
        .find_map(|line| match progress(line, e) {
            Ok(Some(v)) => Some(Ok(v)),
            Ok(None) => None,
            Err(err) => Some(Err(err)),
        })
        .ok_or("actual target progress absent")??;
    Ok((
        json!({"path":log,"device":m.dev(),"inode":m.ino(),"captured_offset":offset,"captured_end":m.len(),"captured_sha256":sha(&b),"captured_tail":text,"stdout_append_binding_verified":true,"producer_invocation_id":iid}),
        latest,
    ))
}
fn journal(unit: &str, iid: &str) -> R<Value> {
    let o = Command::new("/usr/bin/journalctl")
        .args([
            "--all",
            "--no-pager",
            "-ojson",
            "-u",
            unit,
            "_PID=1",
            &format!("INVOCATION_ID={iid}"),
        ])
        .output()?;
    need(
        o.status.success() && o.stderr.is_empty() && o.stdout.len() <= 1 << 20,
        "PID1 guard journal",
    )?;
    Ok(Value::Array(
        std::str::from_utf8(&o.stdout)?
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<Vec<Value>, _>>()?,
    ))
}
fn guard(p: &Value, original: &Value) -> R<Value> {
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        let service = native(s(p, "guard_unit")?)?;
        if service["ActiveState"] == "inactive"
            && service["Result"] == "success"
            && service["MainPID"] == "0"
            && service["ControlPID"] == "0"
            && service["ExecMainStatus"] == "0"
            && service["Job"] == ""
        {
            let gp = load(Path::new(s(&p["plan"], "path")?))?;
            let path = Path::new(s(&gp, "receipt_directory")?)
                .join(format!("sample-{}.json", s(&service, "InvocationID")?));
            let g = load(&path)?;
            let age = now()?
                .checked_sub(n(&g, "recorded_unix_seconds")?)
                .ok_or("future guard")?;
            need(
                age <= 45
                    && g["trip_reason"].is_null()
                    && g["producer_invocation_id"] == original["InvocationID"]
                    && g["plan_sha256"] == p["plan"]["sha256"],
                "guard sample identity/no trip/freshness",
            )?;
            let timer = native(s(p, "timer_unit")?)?;
            need(
                timer["ActiveState"] == "active"
                    && timer["InvocationID"] == p["timer_invocation_id"]
                    && timer["Triggers"] == p["guard_unit"],
                "guard timer identity",
            )?;
            let producer = native(s(original, "Id")?)?;
            owner(&producer, original)?;
            let j = journal(s(p, "guard_unit")?, s(&service, "InvocationID")?)?;
            if native(s(p, "guard_unit")?)? == service {
                return Ok(
                    json!({"receipt":bound(&path)?,"guard_service":service,"timer":timer,"actual_producer":producer,"journal":j,"recorded_unix_seconds":now()?}),
                );
            }
        }
        need(
            Instant::now() < deadline,
            "no genuine completed guard capture window",
        )?;
        std::thread::sleep(Duration::from_millis(50));
    }
}
fn capture(e: u64, paths: &Value, dir: &Path, guards_only: bool) -> R<Value> {
    let batch = Path::new(BATCH).join(format!("epoch{e}"));
    let original = load(&batch.join("ACTUAL_PRODUCER_NATIVE.json"))?;
    let unit = s(&original, "Id")?;
    let iid = s(&original, "InvocationID")?;
    need(
        unit == format!("horizon-qualify-{e}-replacement-local2-20261110-v1.service")
            && paths["producer_invocation_id"] == iid,
        "exact supported local2 owner",
    )?;
    let before = native(unit)?;
    owner(&before, &original)?;
    let protection = load(&batch.join("ACTUAL_GUARD_PROTECTION.json"))?;
    if guards_only {
        return write(
            &dir.join(format!("epoch{e}-current-guard.json")),
            &guard(&protection, &original)?,
        );
    }
    let admission = load(&batch.join("ACTUAL_REPLACEMENT_ADMISSION.json"))?;
    let input = load(Path::new(s(
        &admission["fresh_native_input_acceptance"],
        "path",
    )?))?;
    need(
        input["epoch"] == e && input["authentication_qualified"] == false,
        "genuine local preparation",
    )?;
    let prepared = load(Path::new(s(&input["preparation"], "path")?))?;
    let argv = load(&batch.join("ORIGINAL_PRODUCER_ARGV.json"))?;
    let cmd = prepared["producer_argv"]
        .as_array()
        .ok_or("prepared argv")?;
    need(
        cmd == argv.as_array().ok_or("original argv")?,
        "original producer equals native prepared recipe",
    )?;
    let node = prepared["producer_argv"]
        .as_array()
        .ok_or("node argv")?
        .iter()
        .position(|x| x.as_str().is_some_and(|x| x.ends_with("/jetstreamer-node")))
        .ok_or("node command")?;
    let producer_id = process(s(&before, "MainPID")?.parse()?, unit)?;
    let mut worker = None;
    for pid in fs::read_to_string(
        Path::new("/sys/fs/cgroup/system.slice")
            .join(unit)
            .join("cgroup.procs"),
    )?
    .split_whitespace()
    {
        let id = process(pid.parse()?, unit)?;
        if id["executable"] == paths["worker_executable"] {
            need(worker.is_none(), "multiple workers")?;
            worker = Some(id);
        }
    }
    let worker_id = worker.ok_or("exact actual worker missing")?;
    let node_hash = write(
        &dir.join(format!("epoch{e}-node-image.json")),
        &image(&producer_id, NODE)?,
    )?;
    let worker_hash = write(
        &dir.join(format!("epoch{e}-worker-image.json")),
        &image(&worker_id, WORKER)?,
    )?;
    let start = start(&original)?;
    let stop = load(Path::new(
        "/var/lib/jetstreamer/seven-standard-reserve-stop-20261110-v1/ORIGINAL_SEVEN_RESERVE_STOPS_AND_REPAIR_MODEL.json",
    ))?;
    let old = &stop["rows"][e.to_string()];
    let accepted = PathBuf::from(format!(
        "/var/lib/jetstreamer/cached-standard-input-qualification-20261110-v1/epoch{e}/ROOT_EXACT_CACHED_NODE_NEGATIVE_CAPABILITY_CONTROLS_ACCEPTED.json"
    ));
    let manifest = PathBuf::from(format!(
        "/usr/local/lib/jetstreamer/horizon-independent{e}-singleton-package-20261109-v1/preflight-{e}-v4.json"
    ));
    let m = load(&manifest)?;
    let after = native(unit)?;
    owner(&after, &original)?;
    need(
        process(n(&producer_id, "pid")?, unit)? == producer_id
            && process(n(&worker_id, "pid")?, unit)? == worker_id,
        "process changed through full hashes",
    )?;
    let launch = json!({"schema":"horizon-standard-replacement-native-launch-proof-v1","owner":"/root","primary_thread":THREAD,"admission":bound(&batch.join("ACTUAL_REPLACEMENT_ADMISSION.json"))?,"guard_protection":bound(&batch.join("ACTUAL_GUARD_PROTECTION.json"))?,"original_stop_event":admission["original_stop_event"],"source_start_unix_seconds":start,"source_start_native":original["ExecMainStartTimestamp"],"exact_input_and_capability_gates_passed":true,"input_acquisition":"sealed-local","fresh_effective_GCS_generation_probes_passed":false,"authentication_qualified":false,"qualified_local_input_validation_passed":true,"qualified_local_input_evidence":admission["fresh_native_input_acceptance"],"old_partial_path":old["original_archive"],"old_scratch_path":old["scratch"],"old_output_rename_performed":false,"node_sha256":NODE,"worker_sha256":WORKER,"recorded_unix_seconds":now()?,"producer_before":before,"producer_after":after,"run_directory":paths["run_directory"],"archive_path":paths["archive_path"],"scratch_path":paths["scratch_path"],"producer_command":{"path":producer_id["executable"],"argv":&cmd[node..]},"producer_working_directory":original["WorkingDirectory"],"producer_identity":producer_id,"worker_identity":worker_id,"exact_input_and_capability_evidence":bound(&accepted)?,"manifest_evidence":bound(&manifest)?,"manifest_fingerprint":m["manifest_fingerprint"],"node_image_hash_evidence":node_hash,"worker_image_hash_evidence":worker_hash});
    let launch_bound = write(&dir.join(format!("epoch{e}-launch.json")), &launch)?;
    let log = PathBuf::from(format!(
        "/home/sol/.jetstreamer-private/epoch{e}-standard-lane-20261109-v1/replacement-local2-20261110-v1/producer.log"
    ));
    let (source, progress) = log_event(&log, &argv, e, iid)?;
    let at = now()?;
    need(
        n(&progress, "recorded_unix_seconds")? >= start
            && n(&progress, "recorded_unix_seconds")? <= at,
        "target progress event clock",
    )?;
    let final_owner = native(unit)?;
    owner(&final_owner, &original)?;
    let phase = json!({"schema":"horizon-standard-replacement-phase-event-v1","owner":"/root","primary_thread":THREAD,"epoch":e,"phase":"replay","admission":bound(&batch.join("ACTUAL_REPLACEMENT_ADMISSION.json"))?,"launch_proof":launch_bound,"guard_protection":bound(&batch.join("ACTUAL_GUARD_PROTECTION.json"))?,"source_start_unix_seconds":start,"source_log":source,"no_new_resource_sample":true,"replay_launch_authorized":false,"recorded_unix_seconds":at,"producer_before":after,"producer_after":final_owner,"transaction_replay_claimed":true,"latest_target_progress":progress});
    let phase_bound = write(&dir.join(format!("epoch{e}-phase.json")), &phase)?;
    Ok(
        json!({"epoch":e,"phase":"replay","unit":unit,"invocation_id":iid,"main_pid":original["MainPID"],"original_start_unix_seconds":start,"original_start_native":original["ExecMainStartTimestamp"],"maximum_bootstrap_seconds":3600,"bootstrap_deadline_unix_seconds":start+3600,"admission":bound(&batch.join("ACTUAL_REPLACEMENT_ADMISSION.json"))?,"guard_protection":bound(&batch.join("ACTUAL_GUARD_PROTECTION.json"))?,"launch_proof":launch_bound,"phase_event":phase_bound,"first_guard_pid1_timer":bound(&batch.join("GENUINE_FIRST_GUARD_PID1_TIMER_PROOF.json"))?}),
    )
}
fn run() -> R<()> {
    let a = std::env::args().collect::<Vec<_>>();
    need(
        a.len() == 5 && matches!(a[1].as_str(), "capture" | "guards") && a[3] == "--self-sha256",
        "capture|guards GENERATION --self-sha256 SHA",
    )?;
    need(
        a[2].len() <= 64
            && a[2]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)),
        "generation",
    )?;
    need(
        fs::metadata("/proc/self")?.uid() == 0
            && fs::read_link("/proc/self/exe")? == Path::new(IMAGE),
        "sealed root image",
    )?;
    let mut own = File::open("/proc/self/exe")?;
    let mut h = Sha256::new();
    let mut b = [0u8; 1 << 20];
    loop {
        let z = own.read(&mut b)?;
        if z == 0 {
            break;
        }
        h.update(&b[..z]);
    }
    need(format!("{:x}", h.finalize()) == a[4], "self hash")?;
    let dir = Path::new(OUT).join(&a[2]);
    fs::create_dir(&dir)?;
    fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    let paths = load(Path::new(PATHS))?;
    let mut rows = Vec::new();
    for e in [166, 167, 168] {
        rows.push(capture(e, &paths[e.to_string()], &dir, a[1] == "guards")?);
    }
    let out = write(
        &dir.join("RESULT.json"),
        &json!({"schema":"horizon-local2-native-bridge-capture-v1","owner":"/root","recorded_unix_seconds":now()?,"mode":a[1],"rows":rows,"no_new_resource_sample":true,"no_replay_or_archive_authority":true}),
    )?;
    println!("{out}");
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("bridge capture failed: {e}");
        std::process::exit(1)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_warmup_wrong_epoch_and_missing_counters() {
        for l in [
            "[2026-11-10T19:55:00Z INFO x] progress slot 71712000/72143999 (0%) txs=0 accounts=1",
            "unrelated",
        ] {
            assert!(progress(l, 166).unwrap().is_none())
        }
        assert!(progress("[2026-11-10T19:55:00Z INFO x] progress slot 72144000/72575999 (0%) txs=1 accounts=1",166).is_err());
        assert!(
            progress(
                "[2026-11-10T19:55:00Z INFO x] progress slot 71712000/72143999 (0%) accounts=1",
                166
            )
            .is_err()
        );
    }
    #[test]
    fn positive_actual_marker_keeps_counters_and_clock() {
        let v=progress("[2026-11-10T19:55:00.123Z INFO x] progress slot 71712001/72143999 (0%) txs=42 accounts=100 slots_per_sec=1",166).unwrap().unwrap();
        assert_eq!(v["transactions"], 42);
        assert_eq!(v["slot"], 71712001);
        assert_eq!(v["account_updates"], 100);
        assert_eq!(v["recorded_unix_seconds"], 1794340500u64);
    }
    #[test]
    fn changed_identity_restart_and_queued_owner_reject() {
        let v = json!({"Id":"u","InvocationID":"i","MainPID":"1","ControlPID":"0","NRestarts":"0","ActiveState":"active","SubState":"running","ExecMainStartTimestamp":"time","ControlGroup":"c","Job":""});
        owner(&v, &v).unwrap();
        for (k, x) in [
            ("InvocationID", json!("other")),
            ("NRestarts", json!("1")),
            ("Job", json!("queued")),
            ("MainPID", json!("0")),
        ] {
            let mut b = v.clone();
            b[k] = x;
            assert!(owner(&b, &v).is_err());
        }
    }
}
