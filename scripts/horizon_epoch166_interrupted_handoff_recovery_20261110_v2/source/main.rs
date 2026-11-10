//! Exact epoch166 interrupted metadata continuation. No service control or remote operation.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::Path,
    process::Command,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
mod data_guard_reader;
type R<T> = Result<T, Box<dyn std::error::Error>>;
const IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch166-interrupted-handoff-recovery-20261110-v2/recover";
const LEAF: &str = "/var/lib/jetstreamer/local2-data-guard-handoffs-20261110-v1/epoch166";
const SOURCE_OPERATOR: &str =
    "/usr/local/lib/jetstreamer/horizon-local2-data-guard-handoff-operator-20261110-v3/handoff";
unsafe extern "C" {
    fn geteuid() -> u32;
    fn flock(fd: i32, op: i32) -> i32;
}
fn need(ok: bool, message: &str) -> R<()> {
    if ok { Ok(()) } else { Err(message.into()) }
}
fn s<'a>(v: &'a Value, k: &str) -> R<&'a str> {
    v[k].as_str().ok_or_else(|| format!("missing {k}").into())
}
fn n(v: &Value, k: &str) -> R<u64> {
    v[k].as_u64()
        .ok_or_else(|| format!("missing integer {k}").into())
}
fn sha(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
fn now() -> R<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn hex(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn ident(m: &fs::Metadata) -> [u64; 11] {
    [
        m.dev(),
        m.ino(),
        m.uid().into(),
        m.gid().into(),
        m.mode().into(),
        m.nlink(),
        m.len(),
        m.mtime() as u64,
        m.mtime_nsec() as u64,
        m.ctime() as u64,
        m.ctime_nsec() as u64,
    ]
}
fn read(path: &Path) -> R<Vec<u8>> {
    need(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical bound file",
    )?;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(0x20000 | 0x80000)
        .open(path)?;
    let m = f.metadata()?;
    need(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.len() <= 32 << 20,
        "unsafe bounded Root file",
    )?;
    let mut raw = Vec::new();
    Read::by_ref(&mut f)
        .take((32 << 20) + 1)
        .read_to_end(&mut raw)?;
    need(
        raw.len() as u64 == m.len()
            && ident(&m) == ident(&f.metadata()?)
            && ident(&m) == ident(&fs::symlink_metadata(path)?),
        "bound file changed",
    )?;
    Ok(raw)
}
fn binding(path: &Path) -> R<Value> {
    Ok(json!({"path":path,"sha256":sha(&read(path)?)}))
}
fn bound(b: &Value) -> R<Value> {
    let raw = read(Path::new(s(b, "path")?))?;
    need(
        hex(s(b, "sha256")?) && sha(&raw) == s(b, "sha256")?,
        "bound digest differs",
    )?;
    Ok(serde_json::from_slice(&raw)?)
}
fn private(path: &Path) -> R<()> {
    let m = fs::symlink_metadata(path)?;
    need(
        path.canonicalize()? == path && m.is_dir() && m.uid() == 0 && m.mode() & 0o7777 == 0o700,
        "private Root directory required",
    )
}
fn mkdir(path: &Path) -> R<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    File::open(path.parent().ok_or("directory parent")?)?.sync_all()?;
    private(path)
}
fn save(path: &Path, v: &Value) -> R<Value> {
    private(path.parent().ok_or("receipt parent")?)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(0x20000 | 0x80000)
        .open(path)?;
    let mut raw = serde_json::to_vec_pretty(v)?;
    raw.push(b'\n');
    f.write_all(&raw)?;
    f.sync_all()?;
    File::open(path.parent().ok_or("receipt parent")?)?.sync_all()?;
    binding(path)
}
fn native(unit: &str) -> R<Value> {
    need(
        !unit.is_empty()
            && unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b)),
        "unsafe unit name",
    )?;
    let o=Command::new("/usr/bin/systemctl").args(["show",unit,"--no-pager","-pId,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Result,ExecMainStatus,ControlGroup,Job,Restart,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,ExecStart,ExecMainStartTimestamp,ExecMainStartTimestampMonotonic,Triggers,TriggeredBy,StartLimitIntervalUSec"]).output()?;
    need(
        o.status.success() && o.stderr.is_empty() && o.stdout.len() < 65536,
        "native unit query failed",
    )?;
    let mut out = serde_json::Map::new();
    for line in std::str::from_utf8(&o.stdout)?.lines() {
        let (k, v) = line.split_once('=').ok_or("native delimiter")?;
        need(
            out.insert(k.into(), json!(v)).is_none(),
            "duplicate native field",
        )?;
    }
    Ok(Value::Object(out))
}
fn owner(current: &Value, original: &Value) -> R<()> {
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
        need(
            current[k] == original[k],
            "producer identity or clock changed",
        )?;
    }
    need(
        current["ActiveState"] == "active"
            && current["SubState"] == "running"
            && current["NRestarts"] == "0"
            && current["ControlPID"] == "0"
            && current["Job"] == ""
            && s(current, "MainPID")?.parse::<u64>()? > 1,
        "producer not active and stable",
    )
}
fn timer(v: &Value, p: &Value) -> R<()> {
    need(
        v["Id"] == p["timer_unit"]
            && v["InvocationID"] == p["timer_invocation_id"]
            && v["LoadState"] == "loaded"
            && v["ActiveState"] == "active"
            && matches!(
                v["SubState"].as_str(),
                Some("waiting" | "running" | "elapsed")
            )
            && v["Triggers"] == p["guard_unit"]
            && v["Job"] == "",
        "protective timer not armed",
    )
}
fn journal(unit: &str) -> R<Value> {
    let o = Command::new("/usr/bin/journalctl")
        .args(["--all", "--no-pager", "-ojson", "-n80", "-u", unit])
        .output()?;
    need(
        o.status.success() && o.stderr.is_empty() && o.stdout.len() < 262144,
        "bounded PID1 journal failed",
    )?;
    let rows = std::str::from_utf8(&o.stdout)?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<Vec<Value>, _>>()?;
    need(rows.len() <= 80, "journal row bound")?;
    Ok(json!(rows))
}
fn command_current(v: &Value, a: &data_guard_reader::Accepted) -> R<()> {
    let image = s(&a.runtime, "path")?;
    let plan = s(&a.protection["plan"], "path")?;
    let plan_sha = s(&a.protection["plan"], "sha256")?;
    let image_sha = s(&a.runtime, "sha256")?;
    let prefix = format!(
        "{{ path={image} ; argv[]={image} {plan} --plan-sha256 {plan_sha} --self-sha256 {image_sha} ; ignore_errors=no ; "
    );
    need(
        s(v, "ExecStart")?.starts_with(&prefix)
            && v["MemoryMax"] == "1073741824"
            && v["MemorySwapMax"] == "0"
            && v["CPUQuotaPerSecUSec"] == "1s"
            && v["TasksMax"] == "256"
            && v["Restart"] == "no"
            && v["StartLimitIntervalUSec"] == "0",
        "new actual guard command or limits differ",
    )
}
fn capture(
    a: &data_guard_reader::Accepted,
    original: &Value,
    c: &data_guard_reader::Context<'_>,
) -> R<Option<(Value, Value)>> {
    let service = native(s(&a.protection, "guard_unit")?)?;
    if matches!(
        service["ActiveState"].as_str(),
        Some("active" | "activating" | "deactivating")
    ) || service["Job"] != ""
    {
        return Ok(None);
    }
    need(service["ActiveState"] != "failed", "guard service failed")?;
    if s(&service, "InvocationID")?.is_empty() {
        return Ok(None);
    }
    need(
        service["ActiveState"] == "inactive" && service["SubState"] == "dead",
        "guard has unexpected state",
    )?;
    let p = Path::new(s(&a.plan, "receipt_directory")?)
        .join(format!("sample-{}.json", s(&service, "InvocationID")?));
    let receipt = binding(&p)?;
    let g = bound(&receipt)?;
    data_guard_reader::sample(a, &g, c, now()?, true)?;
    command_current(&service, a)?;
    let t = native(s(&a.protection, "timer_unit")?)?;
    if t["Job"] != "" {
        return Ok(None);
    }
    timer(&t, &a.protection)?;
    need(
        service["TriggeredBy"] == t["Id"],
        "guard not bound to timer",
    )?;
    let producer = native(c.unit)?;
    owner(&producer, original)?;
    let v = json!({"receipt":receipt,"guard_service":service,"timer":t,"actual_producer":producer,"journal":journal(s(&a.protection,"guard_unit")?)?,"genuine_timer_driven_success":true,"recorded_unix_seconds":now()?});
    if native(s(&a.protection, "guard_unit")?)? != service {
        return Ok(None);
    }
    data_guard_reader::proof(a, &v, &g, c)?;
    Ok(Some((v, g)))
}
fn next_proof(
    a: &data_guard_reader::Accepted,
    original: &Value,
    c: &data_guard_reader::Context<'_>,
    seen: &BTreeSet<String>,
    deadline: Instant,
) -> R<(Value, Value)> {
    let mut last_heartbeat = Instant::now();
    while Instant::now() < deadline {
        if last_heartbeat.elapsed() >= Duration::from_secs(60) {
            eprintln!(
                "{} guard completion wait heartbeat: unit={} remaining_seconds={} next_on_expiry=fail_closed",
                now()?,
                s(&a.protection, "guard_unit")?,
                deadline.saturating_duration_since(Instant::now()).as_secs()
            );
            last_heartbeat = Instant::now();
        }
        if let Some((p, g)) = capture(a, original, c)?
            && !seen.contains(s(&g, "guard_invocation_id")?)
        {
            return Ok((p, g));
        }
        thread::sleep(Duration::from_millis(200));
    }
    Err("finite protective completion deadline expired".into())
}
fn self_seal(hash: &str) -> R<Value> {
    let image = Path::new(IMAGE);
    need(
        fs::read_link("/proc/self/exe")? == image
            && sha(&read(image)?) == hash
            && ident(&fs::metadata("/proc/self/exe")?) == ident(&fs::metadata(image)?),
        "actual deployed recovery image differs",
    )?;
    let b = binding(
        &image
            .parent()
            .ok_or("runtime parent")?
            .join("deployment-seal-receipt.json"),
    )?;
    let seal = bound(&b)?;
    let members = seal["members"].as_array().ok_or("sealed members")?;
    need(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["sealer_sha256"]
                == "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
            && seal["destination"]
                == image
                    .parent()
                    .ok_or("image parent")?
                    .to_str()
                    .ok_or("UTF8 parent")?
            && seal["replay_launch_authorized"] == false
            && seal["remote_mutations"] == false
            && members.len() == 1
            && members[0]["name"] == "recover"
            && members[0]["sha256"] == hash
            && members[0]["mode"] == "0555"
            && fs::metadata(image)?.mode() & 0o7777 == 0o555,
        "normal exact recovery seal required",
    )?;
    Ok(b)
}
fn target166() -> R<Value> {
    let rows: Vec<Value> = serde_json::from_str(include_str!("targets.json"))?;
    let selected = rows
        .iter()
        .filter(|r| r["epoch"] == 166)
        .collect::<Vec<_>>();
    need(selected.len() == 1, "exact original166 registry required")?;
    Ok(selected[0].clone())
}
fn run() -> R<()> {
    let argv: Vec<_> = env::args().collect();
    need(
        unsafe { geteuid() } == 0 && argv.len() == 3 && argv[1] == "--self-sha256" && hex(&argv[2]),
        "usage: recover --self-sha256 SHA; Root required",
    )?;
    let own_seal = self_seal(&argv[2])?;
    let iid = env::var("INVOCATION_ID")?;
    need(
        iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "actual recovery systemd IID required",
    )?;
    let lock=OpenOptions::new().read(true).write(true).custom_flags(0x20000|0x80000).open("/var/lib/jetstreamer/native16-compiler-suballocation-qualification-20261109-v1/native16-suballocation.lock")?;
    let lm = lock.metadata()?;
    need(
        lm.is_file()
            && lm.uid() == 0
            && lm.nlink() == 1
            && unsafe { flock(lock.as_raw_fd(), 2 | 4) } == 0,
        "serial native16 lease unavailable",
    )?;
    let leaf = Path::new(LEAF);
    private(leaf)?;
    need(
        !leaf
            .join("ROOT_ACTUAL_CONTINUOUS_GUARD_HANDOFF_COMPLETE.json")
            .exists(),
        "completed handoff already exists",
    )?;
    let out = leaf.join("recovery-v2");
    mkdir(&out)?;
    let target = target166()?;
    let original = bound(&target["native"])?;
    let original_protection = target["protection"].clone();
    let old = bound(&original_protection)?;
    let unit = s(&original, "Id")?;
    let producer_iid = s(&original, "InvocationID")?;
    let pid = s(&original, "MainPID")?.parse()?;
    let c = data_guard_reader::Context {
        epoch: 166,
        unit,
        iid: producer_iid,
        pid,
        start: n(&target, "original_start_unix_seconds")?,
        original_protection: &original_protection,
    };
    let mut accepted = data_guard_reader::registration(
        &serde_json::from_str::<Value>(include_str!("registration-binding.json"))?,
        now()?,
    )?;
    accepted.protection = bound(&binding(&leaf.join("NEW_GUARD_PROTECTION.json"))?)?;
    accepted.plan = bound(&accepted.protection["plan"])?;
    owner(&native(unit)?, &original)?;
    timer(
        &native(s(&accepted.protection, "timer_unit")?)?,
        &accepted.protection,
    )?;
    let (proof, _) = next_proof(
        &accepted,
        &original,
        &c,
        &BTreeSet::new(),
        Instant::now() + Duration::from_secs(45),
    )?;
    let fresh = save(&out.join("CURRENT_GENUINE_SUCCESSOR_PROOF.json"), &proof)?;
    let old_timer = native(s(&old, "timer_unit")?)?;
    let old_service = native(s(&old, "guard_unit")?)?;
    let producer = native(unit)?;
    owner(&producer, &original)?;
    let new_timer = native(s(&accepted.protection, "timer_unit")?)?;
    timer(&new_timer, &accepted.protection)?;
    let mut evidence = serde_json::Map::new();
    for name in [
        "OLD_LAST_GUARD_PID1_TIMER.json",
        "NEW_TIMER_COMPLETION_1.json",
        "NEW_TIMER_COMPLETION_2.json",
        "NEW_TIMER_COMPLETION_3.json",
        "NEW_GUARD_PROTECTION.json",
        "OLD_GUARD_STOP-ORIGINAL-ARGV.json",
        "OLD_GUARD_STOP-ORIGINAL-EXECUTION.json",
        "FAILED_HANDOFF_PRESERVED.json",
        "ROOT_SERIAL_NATIVE16_ALLOCATION.json",
        "ROOT_ACTUAL_OLD_TIMER_STOP_JOURNAL.jsonl",
    ] {
        evidence.insert(name.into(), binding(&leaf.join(name))?);
    }
    let old_service_journal = journal(s(&old, "guard_unit")?)?;
    let r = json!({"old_service_stop_journal":old_service_journal,"schema":"horizon-epoch166-interrupted-guard-handoff-recovery-v1","owner":"/root","primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53","epoch":166,"actual_original_operator_invocation_id":"a86193a9218a4dcf8933dda284db2201","actual_recovery_operator_invocation_id":iid,"source_operator":binding(Path::new(SOURCE_OPERATOR))?,"source_operator_deployment_seal":binding(&Path::new(SOURCE_OPERATOR).parent().ok_or("source operator parent")?.join("deployment-seal-receipt.json"))?,"recovery_operator":binding(Path::new(IMAGE))?,"recovery_operator_deployment_seal":own_seal,"retained_evidence":evidence,"current_new_guard_proof":fresh,"producer":producer,"old_timer_state":old_timer,"old_service_terminal":old_service,"new_timer":new_timer,"old_timer_deactivated_realtime_microseconds":1_794_352_200_575_066u64,"recorded_unix_seconds":now()?,"no_producer_control_operations":true,"no_guard_control_operations":true,"no_reset_failed":true,"remote_mutations":false,"resource_credit_bytes":0});
    let rb = save(
        &out.join("ROOT_ACTUAL_INTERRUPTED_WRITER_RECOVERY.json"),
        &r,
    )?;
    let completions = json!([
        evidence["NEW_TIMER_COMPLETION_1.json"],
        evidence["NEW_TIMER_COMPLETION_2.json"],
        evidence["NEW_TIMER_COMPLETION_3.json"]
    ]);
    let first = bound(&bound(&completions[0])?["receipt"])?;
    let last = bound(&bound(&completions[2])?["receipt"])?;
    let span = n(&last, "recorded_unix_seconds")?
        .checked_sub(n(&first, "recorded_unix_seconds")?)
        .ok_or("sustained clock")?;
    let h = json!({"schema":"horizon-local2-DATA-guard-continuous-handoff-v1","owner":"/root","primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53","epoch":166,"registration":serde_json::from_str::<Value>(include_str!("registration-binding.json"))?,"original_protection":original_protection,"new_protection":evidence["NEW_GUARD_PROTECTION.json"],"producer_before":original,"producer_after":producer,"genuine_new_timer_completions":completions,"old_last_guard_pid1_timer":evidence["OLD_LAST_GUARD_PID1_TIMER.json"],"old_timer_state":old_timer,"old_service_terminal":old_service,"new_timer":new_timer,"sustained_window_seconds":span,"recorded_unix_seconds":now()?,"no_guard_gap":true,"producer_restarts":0,"all_existing_files_and_prior_endings_retained":true,"raw_minimum_free_bytes":6_264_131_239_730u64,"complete_DATA_bytes":6_229_838_610_226u64,"resource_credit_bytes":0,"DATA_ending_bytes":0,"memory_promise_ending_bytes":0,"replay_admission_authorized":false,"remote_mutations":false,"interrupted_operator_recovery":rb});
    let candidate = save(&out.join("RECOVERED_HANDOFF_CANDIDATE.json"), &h)?;
    let checked = data_guard_reader::load_handoff(&candidate, &c, now()?)?;
    owner(&native(unit)?, &original)?;
    timer(
        &native(s(&checked.protection, "timer_unit")?)?,
        &checked.protection,
    )?;
    for (key, service) in [("timer_unit", false), ("guard_unit", true)] {
        data_guard_reader::current_old_terminal(
            &checked,
            &native(s(&old, key)?)?,
            &old[key],
            service,
        )?;
    }
    let final_binding = save(
        &leaf.join("ROOT_ACTUAL_CONTINUOUS_GUARD_HANDOFF_COMPLETE.json"),
        &h,
    )?;
    data_guard_reader::load_handoff(&final_binding, &c, now()?)?;
    println!(
        "{}",
        json!({"handoff":final_binding,"epoch":166,"guard_and_producer_control_operations":0,"resource_credit_bytes":0})
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_one_exact_target_is_available() {
        let t = target166().unwrap();
        assert_eq!(t["epoch"], 166);
        assert_eq!(
            t["native"]["sha256"],
            "cc754d04909426d6e761cb6d1706d1e1fb82b6a35b062daee7e4773a5064184a"
        );
    }
    #[test]
    fn recovery_cannot_accept_restarted_producer() {
        let a = json!({"Id":"p","InvocationID":"a","MainPID":"42","ControlPID":"0","NRestarts":"0","ActiveState":"active","SubState":"running","ExecMainStartTimestamp":"start","ControlGroup":"/p","Job":""});
        owner(&a, &a).unwrap();
        let mut b = a.clone();
        b["NRestarts"] = json!("1");
        assert!(owner(&b, &a).is_err());
    }
}
