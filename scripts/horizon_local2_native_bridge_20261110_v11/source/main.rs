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
const IMAGE: &str = "/usr/local/lib/jetstreamer/horizon-local2-native-bridge-20261110-v11/capture";
const BATCH: &str = "/var/lib/jetstreamer/cached-standard-input-qualification-20261110-v1/actual-three-local2-launch-v1";
const PATHS: &str = "/home/sol/.jetstreamer-private/local2-actual-owner-event-20261110-v1/EXACT_LOCAL2_RUN_PATHS.json";
const OUT: &str = "/var/lib/jetstreamer/local2-native-bridge-20261110-v11";
const BATCH169: &str = "/var/lib/jetstreamer/cached-standard-input-qualification-20261110-v1/actual-next169-local2-launch-v1";
const BIRTH169: &str = "/home/sol/.jetstreamer-private/visible-primary-next-observer-210022-four-local2-20261110-v1/NEW169_BIRTH_BINDING.json";
const BIRTH169_SHA: &str = "0229a26367a9ca1e16afcbb3e2c75ee4b9c909d6a31e789708ddd14484d6efb2";
const STATUS169: &str = "/home/sol/.jetstreamer-private/next169-actual-owner-event-20261110-v1/ACTUAL169_OWNER_PHASE_EVENT.json";
const STATUS169_COMPLETE: &str = "/home/sol/.jetstreamer-private/next169-actual-owner-event-20261110-v1/ROOT_ACTUAL169_OWNER_STATUS_COMPLETE.json";
const STATUS169_COMPLETE_SHA: &str =
    "6ad759fdf0d482cd869a2c7e5b8074a6405850cd5a9e35e9ef509dcef3d9af8f";
const STATUS169_SHA: &str = "9c1131924df9837b7ac85b5a4ebc06a027e851ed199831976b7410df402de4db";
const FIRST169_SHA: &str = "684c32e27791f86d8a24a71086bcb7cf94448116ee29d8aca2ab45383434e474";
const PACKAGE169_SEAL_SHA: &str =
    "6949d2bfc76a58236db0648e1848096894a62ddbe2f0856e60e64e8f9f0476f7";
const IID169: &str = "81a6eee953d249a0a11ab123c81d63cc";
const PID169: u64 = 1123930;
const START169: u64 = 1794344383;
const GUARD: &str = "35dbd4826c8947f38d50dff049345e1c3d62450eb85e41e94e326880e1898fbc";
const BATCH170: &str = "/var/lib/jetstreamer/cached-standard-input-qualification-20261110-v1/actual-next170-local2-launch-v1";
const BIRTH170: &str = "/home/sol/.jetstreamer-private/visible-primary-next-observer-220022-five-local2-20261110-v1/NEW170_BIRTH_BINDING.json";
const BIRTH170_SHA: &str = "2dc50d13fc73603b1add35d38eda0e6b75dbb0423d90fb2689aacb4abf94f450";
const FIRST170_SHA: &str = "9eb1b6fff59c366cae212f8353b70634343f820bc57807fe539de808bfe6729c";
const PACKAGE170_SEAL_SHA: &str =
    "7c5477094ab14c267f287a76104524029f8a69ac3e489bbdb41fbe04e678e58b";
const IID170: &str = "350248d54a4f437bbb04b65319e6275f";
const PID170: u64 = 1145812;
const START170: u64 = 1794346477;
mod sixth;
mod supplement;
use sixth::{BATCH171, START171, package171_worker, paths171, validate171_original};
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
    need(
        p.is_absolute() && p.canonicalize()? == p,
        "canonical Root metadata path required",
    )?;
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
    Read::by_ref(&mut f)
        .take((16 << 20) + 1)
        .read_to_end(&mut b)?;
    need(
        b.len() as u64 == m.len(),
        "metadata length changed or exceeded bound",
    )?;
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
fn log_event(log: &Path, argv: &Value, e: u64, iid: &str) -> R<(Value, Option<Value>)> {
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
        .transpose()?;
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
    let batch = Path::new(batch_for(e)?).join(format!("epoch{e}"));
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
    if e == 171 {
        validate171_original(&original, paths, start(&original)?)?;
    }
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
    need(
        matches!(e, 169..=171) || worker.is_some(),
        "exact actual worker missing",
    )?;
    let worker_id = worker.unwrap_or(Value::Null);
    let node_hash = write(
        &dir.join(format!("epoch{e}-node-image.json")),
        &image(&producer_id, NODE)?,
    )?;
    let worker_image = if worker_id.is_null() {
        if e == 171 {
            package171_worker(e)?
        } else if e == 170 {
            package170_worker(e)?
        } else {
            package_worker(e)?
        }
    } else {
        image(&worker_id, WORKER)?
    };
    let worker_hash = write(
        &dir.join(format!("epoch{e}-worker-image.json")),
        &worker_image,
    )?;
    let start = start(&original)?;
    if e == 169 {
        validate169_original(&original, paths, start)?;
    } else if e == 170 {
        validate170_original(&original, paths, start)?;
    }
    let stop = load(Path::new(
        "/var/lib/jetstreamer/seven-standard-reserve-stop-20261110-v1/ORIGINAL_SEVEN_RESERVE_STOPS_AND_REPAIR_MODEL.json",
    ))?;
    let old = &stop["rows"][e.to_string()];
    let accepted = PathBuf::from(format!(
        "/var/lib/jetstreamer/cached-standard-input-qualification-20261110-v1/epoch{e}/ROOT_EXACT_CACHED_NODE_NEGATIVE_CAPABILITY_CONTROLS_ACCEPTED.json"
    ));
    let manifest = manifest_for(e)?;
    let m = load(&manifest)?;
    let after = native(unit)?;
    owner(&after, &original)?;
    need(
        process(n(&producer_id, "pid")?, unit)? == producer_id
            && (worker_id.is_null() || process(n(&worker_id, "pid")?, unit)? == worker_id),
        "process changed through full hashes",
    )?;
    let launch = json!({"schema":"horizon-standard-replacement-native-launch-proof-v1","owner":"/root","primary_thread":THREAD,"admission":bound(&batch.join("ACTUAL_REPLACEMENT_ADMISSION.json"))?,"guard_protection":bound(&batch.join("ACTUAL_GUARD_PROTECTION.json"))?,"original_stop_event":admission["original_stop_event"],"source_start_unix_seconds":start,"source_start_native":original["ExecMainStartTimestamp"],"exact_input_and_capability_gates_passed":true,"input_acquisition":"sealed-local","fresh_effective_GCS_generation_probes_passed":false,"authentication_qualified":false,"qualified_local_input_validation_passed":true,"qualified_local_input_evidence":admission["fresh_native_input_acceptance"],"old_partial_path":old["original_archive"],"old_scratch_path":old["scratch"],"old_output_rename_performed":false,"node_sha256":NODE,"worker_sha256":WORKER,"recorded_unix_seconds":now()?,"producer_before":before,"producer_after":after,"run_directory":paths["run_directory"],"archive_path":paths["archive_path"],"scratch_path":paths["scratch_path"],"producer_command":{"path":producer_id["executable"],"argv":&cmd[node..]},"producer_working_directory":original["WorkingDirectory"],"producer_identity":producer_id,"worker_identity":worker_id,"exact_input_and_capability_evidence":bound(&accepted)?,"manifest_evidence":bound(&manifest)?,"manifest_fingerprint":m["manifest_fingerprint"],"node_image_hash_evidence":node_hash,"worker_image_hash_evidence":worker_hash});
    let launch_bound = write(&dir.join(format!("epoch{e}-launch.json")), &launch)?;
    let log = log_for(e)?;
    let (source, progress) = log_event(&log, &argv, e, iid)?;
    let at = now()?;
    let phase_name = classify(e, progress.as_ref(), !worker_id.is_null(), start, at)?;
    let final_owner = native(unit)?;
    owner(&final_owner, &original)?;
    let phase = json!({"schema":"horizon-standard-replacement-phase-event-v1","owner":"/root","primary_thread":THREAD,"epoch":e,"phase":phase_name,"admission":bound(&batch.join("ACTUAL_REPLACEMENT_ADMISSION.json"))?,"launch_proof":launch_bound,"guard_protection":bound(&batch.join("ACTUAL_GUARD_PROTECTION.json"))?,"source_start_unix_seconds":start,"source_log":source,"no_new_resource_sample":true,"replay_launch_authorized":false,"recorded_unix_seconds":at,"producer_before":after,"producer_after":final_owner,"transaction_replay_claimed":phase_name=="replay","latest_target_progress":progress});
    let phase_bound = write(&dir.join(format!("epoch{e}-phase.json")), &phase)?;
    Ok(
        json!({"epoch":e,"phase":phase_name,"unit":unit,"invocation_id":iid,"main_pid":original["MainPID"],"original_start_unix_seconds":start,"original_start_native":original["ExecMainStartTimestamp"],"maximum_bootstrap_seconds":3600,"bootstrap_deadline_unix_seconds":start+3600,"admission":bound(&batch.join("ACTUAL_REPLACEMENT_ADMISSION.json"))?,"guard_protection":bound(&batch.join("ACTUAL_GUARD_PROTECTION.json"))?,"launch_proof":launch_bound,"phase_event":phase_bound,"first_guard_pid1_timer":bound(&batch.join("GENUINE_FIRST_GUARD_PID1_TIMER_PROOF.json"))?}),
    )
}
fn batch_for(e: u64) -> R<&'static str> {
    match e {
        166..=168 => Ok(BATCH),
        169 => Ok(BATCH169),
        170 => Ok(BATCH170),
        171 => Ok(BATCH171),
        _ => Err("unsupported bridge epoch".into()),
    }
}
fn hash_bound(b: &Value) -> R<Value> {
    let p = Path::new(s(b, "path")?);
    let bytes = raw(p)?;
    need(
        sha(&bytes) == s(b, "sha256")?,
        "separately bound source changed",
    )?;
    Ok(serde_json::from_slice(&bytes)?)
}
fn birth169() -> R<Value> {
    let b = raw(Path::new(BIRTH169))?;
    need(sha(&b) == BIRTH169_SHA, "exact169 birth changed")?;
    Ok(serde_json::from_slice(&b)?)
}
fn paths169() -> R<Value> {
    let birth = birth169()?;
    let run = Path::new(s(&birth, "run_directory")?);
    let original = &birth["native"];
    need(
        original["InvocationID"] == IID169
            && original["MainPID"] == "1123930"
            && birth["no_transaction_replay_claimed"] == true,
        "actual169 birth identity",
    )?;
    Ok(
        json!({"producer_invocation_id":IID169,"run_directory":run,"scratch_path":birth["scratch_path"],"archive_path":run.join("archives/epoch-169.jet"),"worker_executable":run.join("scratch/.historical-runtime/jetstreamer-historical-parent-ZPwt9F/bound-worker/historical-worker"),"birth_binding":{"path":BIRTH169,"sha256":BIRTH169_SHA}}),
    )
}
fn first169(first: &Value, sample: &Value) -> R<()> {
    need(
        sample["producer_invocation_id"] == IID169
            && sample["guard_sha256"] == GUARD
            && sample["producer_stop_enabled"] == true
            && sample["trip_reason"].is_null()
            && sample["worker_observation_error"].is_null()
            && sample["root_physical_observation_error"].is_null()
            && n(sample, "recorded_unix_seconds")? >= START169
            && n(sample, "recorded_unix_seconds")? <= START169 + 25
            && first["guard_service"]["Result"] == "success"
            && first["guard_service"]["ExecMainStatus"] == "0"
            && first["guard_service"]["TriggeredBy"] == first["timer"]["Id"],
        "genuine original169 first timer guard within25seconds required",
    )?;
    Ok(())
}
fn validate169_original(original: &Value, paths: &Value, start: u64) -> R<()> {
    let birth = birth169()?;
    owner(original, &birth["native"])?;
    need(
        start == START169
            && original["MainPID"] == "1123930"
            && original["InvocationID"] == IID169
            && paths["run_directory"] == birth["run_directory"]
            && paths["scratch_path"] == birth["scratch_path"],
        "exact169 original native/path/start binding",
    )?;
    let first_binding =
        bound(&Path::new(BATCH169).join("epoch169/GENUINE_FIRST_GUARD_PID1_TIMER_PROOF.json"))?;
    need(
        first_binding["sha256"] == FIRST169_SHA,
        "exact original169 first guard proof changed",
    )?;
    let first = hash_bound(&first_binding)?;
    let sample = hash_bound(&first["receipt"])?;
    first169(&first, &sample)?;
    let result = hash_bound(&birth["launch"])?;
    let rows = result["protected"]
        .as_array()
        .ok_or("birth protected launch rows")?;
    need(
        rows.len() == 1
            && rows[0]["epoch"] == 169
            && rows[0]["invocation_id"] == IID169
            && rows[0]["pid"] == PID169
            && rows[0]["transaction_replay_claimed"] == false
            && rows[0]["first_guard"] == first_binding
            && rows[0]["admission"]
                == bound(&Path::new(BATCH169).join("epoch169/ACTUAL_REPLACEMENT_ADMISSION.json"))?
            && rows[0]["protection"]
                == bound(&Path::new(BATCH169).join("epoch169/ACTUAL_GUARD_PROTECTION.json"))?
            && result["failed"].as_array().is_some_and(Vec::is_empty),
        "original genuine169 guarded launch result",
    )?;
    Ok(())
}
fn birth170() -> R<Value> {
    let b = raw(Path::new(BIRTH170))?;
    need(sha(&b) == BIRTH170_SHA, "exact169 birth changed")?;
    Ok(serde_json::from_slice(&b)?)
}
fn paths170() -> R<Value> {
    let birth = birth170()?;
    let run = Path::new(s(&birth, "run_directory")?);
    let original = &birth["native"];
    need(
        original["InvocationID"] == IID170
            && original["MainPID"] == "1145812"
            && birth["no_transaction_replay_claimed"] == true,
        "actual169 birth identity",
    )?;
    Ok(
        json!({"producer_invocation_id":IID170,"run_directory":run,"scratch_path":birth["scratch_path"],"archive_path":run.join("archives/epoch-170.jet"),"worker_executable":run.join("scratch/.historical-runtime/jetstreamer-historical-parent-fG8MXA/bound-worker/historical-worker"),"birth_binding":{"path":BIRTH170,"sha256":BIRTH170_SHA}}),
    )
}
fn first170(first: &Value, sample: &Value) -> R<()> {
    need(
        sample["producer_invocation_id"] == IID170
            && sample["guard_sha256"] == GUARD
            && sample["producer_stop_enabled"] == true
            && sample["trip_reason"].is_null()
            && sample["worker_observation_error"].is_null()
            && sample["root_physical_observation_error"].is_null()
            && n(sample, "recorded_unix_seconds")? >= START170
            && n(sample, "recorded_unix_seconds")? <= START170 + 25
            && first["guard_service"]["Result"] == "success"
            && first["guard_service"]["ExecMainStatus"] == "0"
            && first["guard_service"]["TriggeredBy"] == first["timer"]["Id"],
        "genuine original169 first timer guard within25seconds required",
    )?;
    Ok(())
}
fn validate170_original(original: &Value, paths: &Value, start: u64) -> R<()> {
    let birth = birth170()?;
    owner(original, &birth["native"])?;
    need(
        start == START170
            && original["MainPID"] == "1145812"
            && original["InvocationID"] == IID170
            && paths["run_directory"] == birth["run_directory"]
            && paths["scratch_path"] == birth["scratch_path"],
        "exact169 original native/path/start binding",
    )?;
    let first_binding =
        bound(&Path::new(BATCH170).join("epoch170/GENUINE_FIRST_GUARD_PID1_TIMER_PROOF.json"))?;
    need(
        first_binding["sha256"] == FIRST170_SHA,
        "exact original169 first guard proof changed",
    )?;
    let first = hash_bound(&first_binding)?;
    let sample = hash_bound(&first["receipt"])?;
    first170(&first, &sample)?;
    let result = hash_bound(&birth["launch"])?;
    let rows = result["protected"]
        .as_array()
        .ok_or("birth protected launch rows")?;
    need(
        rows.len() == 1
            && rows[0]["epoch"] == 170
            && rows[0]["invocation_id"] == IID170
            && rows[0]["pid"] == PID170
            && rows[0]["transaction_replay_claimed"] == false
            && rows[0]["first_guard"] == first_binding
            && rows[0]["admission"]
                == bound(&Path::new(BATCH170).join("epoch170/ACTUAL_REPLACEMENT_ADMISSION.json"))?
            && rows[0]["protection"]
                == bound(&Path::new(BATCH170).join("epoch170/ACTUAL_GUARD_PROTECTION.json"))?
            && result["failed"].as_array().is_some_and(Vec::is_empty),
        "original genuine169 guarded launch result",
    )?;
    Ok(())
}
fn classify(
    e: u64,
    progress: Option<&Value>,
    worker_present: bool,
    start: u64,
    at: u64,
) -> R<&'static str> {
    need(at >= start, "phase event before producer birth")?;
    if let Some(p) = progress {
        need(
            worker_present
                && n(p, "epoch")? == e
                && n(p, "transactions")? > 0
                && n(p, "recorded_unix_seconds")? >= start
                && n(p, "recorded_unix_seconds")? <= at,
            "actual current target progress and worker required",
        )?;
        Ok("replay")
    } else {
        need(
            matches!(e, 169..=171)
                && start == bootstrap_start(e)?
                && at
                    <= start
                        .checked_add(3600)
                        .ok_or("bootstrap deadline overflow")?,
            "only exact169/170/171 initial bootstrap can lack target progress",
        )?;
        Ok("bootstrap")
    }
}
fn package_worker_image(path: &Path, expected: &str) -> R<Value> {
    let m = fs::symlink_metadata(path)?;
    need(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && m.len() > 0
            && m.len() <= 64 << 20,
        "immutable Root package worker required",
    )?;
    let id = json!({"executable":path,"executable_dev":m.dev(),"executable_ino":m.ino(),"executable_len":m.len()});
    let mut proof = image(&id, expected)?;
    proof["evidence_role"] = json!("immutable-package-worker-during-bootstrap");
    proof["running_worker_identity_claimed"] = json!(false);
    Ok(proof)
}
fn package_worker(e: u64) -> R<Value> {
    need(e == 169, "only bootstrap169 package-worker route")?;
    let seal = bound(Path::new(
        "/usr/local/lib/jetstreamer/horizon-independent169-singleton-package-20261109-v1/deployment-seal-receipt.json",
    ))?;
    need(
        seal["sha256"] == PACKAGE169_SEAL_SHA,
        "exact original169 package seal changed",
    )?;
    let mut proof = package_worker_image(
        Path::new(
            "/usr/local/lib/jetstreamer/horizon-independent169-singleton-package-20261109-v1/jetstreamer-historical-worker-v1-5-6",
        ),
        WORKER,
    )?;
    proof["package_deployment_seal"] = seal;
    Ok(proof)
}
fn package170_worker(e: u64) -> R<Value> {
    need(e == 170, "only bootstrap169 package-worker route")?;
    let seal = bound(Path::new(
        "/usr/local/lib/jetstreamer/horizon-independent170-singleton-package-20261109-v1/deployment-seal-receipt.json",
    ))?;
    need(
        seal["sha256"] == PACKAGE170_SEAL_SHA,
        "exact original169 package seal changed",
    )?;
    let mut proof = package_worker_image(
        Path::new(
            "/usr/local/lib/jetstreamer/horizon-independent170-singleton-package-20261109-v1/jetstreamer-historical-worker-v1-5-6",
        ),
        WORKER,
    )?;
    proof["package_deployment_seal"] = seal;
    Ok(proof)
}
fn bootstrap_start(e: u64) -> R<u64> {
    match e {
        169 => Ok(START169),
        170 => Ok(START170),
        171 => Ok(START171),
        _ => Err("unsupported initial bootstrap epoch".into()),
    }
}
fn manifest_for(e: u64) -> R<PathBuf> {
    let _ = batch_for(e)?;
    let date = if e == 171 { "20261110" } else { "20261109" };
    Ok(PathBuf::from(format!(
        "/usr/local/lib/jetstreamer/horizon-independent{e}-singleton-package-{date}-v1/preflight-{e}-v4.json"
    )))
}
fn log_for(e: u64) -> R<PathBuf> {
    let _ = batch_for(e)?;
    let date = if e == 171 { "20261110" } else { "20261109" };
    Ok(PathBuf::from(format!(
        "/home/sol/.jetstreamer-private/epoch{e}-standard-lane-{date}-v1/replacement-local2-20261110-v1/producer.log"
    )))
}
fn epochs_for_mode(mode: &str) -> R<Vec<u64>> {
    match mode {
        "capture" | "guards" => Ok(vec![166, 167, 168]),
        "capture169" | "guards169" => Ok(vec![169]),
        "capture170" | "guards170" => Ok(vec![170]),
        "capture171" | "guards171" => Ok(vec![171]),
        "capture4" | "guards4" => Ok(vec![166, 167, 168, 169]),
        "capture5" | "guards5" => Ok(vec![166, 167, 168, 169, 170]),
        "capture6" | "guards6" => Ok(vec![166, 167, 168, 169, 170, 171]),
        _ => Err("unsupported bridge mode".into()),
    }
}
fn run() -> R<()> {
    let a = std::env::args().collect::<Vec<_>>();
    need(
        (a.len() == 5 || a.len() == 9) && epochs_for_mode(&a[1]).is_ok() && a[3] == "--self-sha256",
        "capture|guards|capture169|guards169|capture170|guards170|capture171|guards171|capture4|guards4|capture5|guards5|capture6|guards6 GENERATION --self-sha256 SHA",
    )?;
    let request = if a.len() == 9 {
        need(
            matches!(a[1].as_str(), "capture169" | "capture4")
                && a[5] == "--supplement-request"
                && a[7] == "--request-sha256",
            "supplement request ABI",
        )?;
        let path = Path::new(&a[6]);
        need(
            fs::symlink_metadata(path)?.mode() & 0o222 == 0,
            "normally sealed immutable supplement request required",
        )?;
        Some((
            json!({"path":path,"sha256":a[8]}),
            hash_bound(&json!({"path":path,"sha256":a[8]}))?,
        ))
    } else {
        None
    };
    need(
        !a[2].is_empty()
            && a[2].len() <= 64
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
    let epochs = epochs_for_mode(&a[1])?;
    for e in epochs {
        let exact = if e == 169 {
            paths169()?
        } else if e == 170 {
            paths170()?
        } else if e == 171 {
            paths171()?
        } else {
            paths[e.to_string()].clone()
        };
        rows.push(capture(e, &exact, &dir, a[1].starts_with("guards"))?);
    }

    if let Some((binding, request)) = request {
        let declaration = rows
            .iter_mut()
            .find(|r| r["epoch"] == 169)
            .ok_or("supplement169 row missing")?;
        let value = supplement::make(&binding, &request, declaration, &a[4], now()?)?;
        let receipt = write(&dir.join("epoch169-census-supplement.json"), &value)?;
        declaration["census_supplement"] = receipt;
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

#[cfg(test)]
mod bootstrap_tests {
    use super::*;
    #[test]
    fn genuine169_bootstrap_can_have_no_worker_and_no_target_progress() {
        assert_eq!(
            classify(169, None, false, START169, START169 + 300).unwrap(),
            "bootstrap"
        );
        assert_eq!(
            classify(169, None, true, START169, START169 + 300).unwrap(),
            "bootstrap"
        );
    }
    #[test]
    fn existing_replays_are_never_downgraded_to_bootstrap() {
        for e in [166, 167, 168] {
            assert!(classify(e, None, true, START169, START169 + 1).is_err());
        }
    }
    #[test]
    fn worker_presence_does_not_prove_target_replay() {
        assert_eq!(
            classify(169, None, true, START169, START169 + 100).unwrap(),
            "bootstrap"
        );
    }
    #[test]
    fn bootstrap_deadline_is_bound_to_original_start() {
        assert!(classify(169, None, false, START169, START169 + 3601).is_err());
        assert!(classify(169, None, false, START169 + 10, START169 + 20).is_err());
    }
    #[test]
    fn target_progress_requires_actual_worker_and_exact_epoch() {
        let mut p = json!({"epoch":169,"transactions":1,"recorded_unix_seconds":START169+10});
        assert!(classify(169, Some(&p), false, START169, START169 + 20).is_err());
        assert_eq!(
            classify(169, Some(&p), true, START169, START169 + 20).unwrap(),
            "replay"
        );
        p["epoch"] = json!(168);
        assert!(classify(169, Some(&p), true, START169, START169 + 20).is_err());
    }
    #[test]
    fn target_clock_cannot_predate_birth_or_follow_capture() {
        for at in [START169 - 1, START169 + 21] {
            let p = json!({"epoch":169,"transactions":1,"recorded_unix_seconds":at});
            assert!(classify(169, Some(&p), true, START169, START169 + 20).is_err());
        }
    }
    #[test]
    fn predecessor_warmup_never_enters_target_counters() {
        assert!(progress("[2026-11-10T21:04:21Z INFO x] warmup slot 73007830/73007999 (0%) txs=12 accounts=5",169).unwrap().is_none());
    }
    #[test]
    fn package_evidence_has_no_fabricated_running_worker_identity() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "bridge-v4-package-fixture-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("worker");
        fs::write(&path, b"fixture-worker").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        let value = package_worker_image(&path, &sha(b"fixture-worker")).unwrap();
        assert_eq!(value["stable_full_hash_passed"], true);
        assert_eq!(value["running_worker_identity_claimed"], false);
        assert!(value.get("pid").is_none());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(package_worker_image(&path, &sha(b"fixture-worker")).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn wrong_package_body_hash_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "bridge-v4-hash-fixture-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("worker");
        fs::write(&path, b"fixture-worker").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        assert!(package_worker_image(&path, &sha(b"other-worker")).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn original_three_batches_keep_their_exact_paths() {
        for e in [166, 167, 168] {
            assert_eq!(batch_for(e).unwrap(), BATCH);
        }
        assert_eq!(batch_for(169).unwrap(), BATCH169);
        assert_eq!(batch_for(170).unwrap(), BATCH170);
        assert_eq!(batch_for(171).unwrap(), BATCH171);
        assert!(batch_for(172).is_err());
    }
}

#[cfg(test)]
mod first_guard_tests {
    use super::*;
    fn fixture() -> (Value, Value) {
        (
            json!({"guard_service":{"Result":"success","ExecMainStatus":"0","TriggeredBy":"guard.timer"},"timer":{"Id":"guard.timer"}}),
            json!({"producer_invocation_id":IID169,"guard_sha256":GUARD,"producer_stop_enabled":true,"trip_reason":null,"worker_observation_error":null,"root_physical_observation_error":null,"recorded_unix_seconds":START169+25}),
        )
    }
    #[test]
    fn first_guard25second_bound_is_not_extended() {
        let (f, mut s) = fixture();
        assert!(first169(&f, &s).is_ok());
        s["recorded_unix_seconds"] = json!(START169 + 26);
        assert!(first169(&f, &s).is_err());
    }
    #[test]
    fn first_guard_must_follow_original_birth() {
        let (f, mut s) = fixture();
        s["recorded_unix_seconds"] = json!(START169 - 1);
        assert!(first169(&f, &s).is_err());
    }
    #[test]
    fn timer_driven_stop_enabled_no_trip_evidence_is_required() {
        let (mut f, mut s) = fixture();
        f["guard_service"]["TriggeredBy"] = json!("other.timer");
        assert!(first169(&f, &s).is_err());
        let (f, _) = fixture();
        s["producer_stop_enabled"] = json!(false);
        assert!(first169(&f, &s).is_err());
    }
}

#[cfg(test)]
mod fifth_tests {
    use super::*;
    #[test]
    fn fifth_bootstrap_keeps_its_actual_original_clock() {
        assert_eq!(
            classify(170, None, false, START170, START170 + 10).unwrap(),
            "bootstrap"
        );
        assert!(classify(170, None, false, START170, START170 + 3601).is_err());
        assert!(classify(170, None, false, START169, START170 + 10).is_err());
    }
    #[test]
    fn fifth_replay_requires_exact_target_and_running_worker() {
        let mut p = json!({"epoch":170,"transactions":2,"recorded_unix_seconds":START170+2});
        assert_eq!(
            classify(170, Some(&p), true, START170, START170 + 3).unwrap(),
            "replay"
        );
        assert!(classify(170, Some(&p), false, START170, START170 + 3).is_err());
        p["epoch"] = json!(169);
        assert!(classify(170, Some(&p), true, START170, START170 + 3).is_err());
    }
    #[test]
    fn fifth_first_guard_keeps_25second_timer_bound() {
        let f = json!({"guard_service":{"Result":"success","ExecMainStatus":"0","TriggeredBy":"g.timer"},"timer":{"Id":"g.timer"}});
        let mut p = json!({"producer_invocation_id":IID170,"guard_sha256":GUARD,"producer_stop_enabled":true,"trip_reason":null,"worker_observation_error":null,"root_physical_observation_error":null,"recorded_unix_seconds":START170+25});
        assert!(first170(&f, &p).is_ok());
        p["recorded_unix_seconds"] = json!(START170 + 26);
        assert!(first170(&f, &p).is_err());
    }
}
