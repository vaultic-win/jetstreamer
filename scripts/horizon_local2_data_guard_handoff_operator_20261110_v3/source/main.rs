//! One explicit local2 guard handoff. Never starts, stops, restarts or signals a producer.
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
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
mod data_guard_reader;
type R<T> = Result<T, Box<dyn std::error::Error>>;
const OUT: &str = "/var/lib/jetstreamer/local2-data-guard-handoffs-20261110-v1";
const IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-local2-data-guard-handoff-operator-20261110-v3/handoff";
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
const OLD_SHA: &str = "35dbd4826c8947f38d50dff049345e1c3d62450eb85e41e94e326880e1898fbc";
const NEW_SHA: &str = "7ecab4ad6b4f6adbc84dd4f6a717467d7eabafa309d06aca1f22fdd3cb6ce29b";
const FLOOR: u64 = 6_264_131_239_730;
const CAP: u64 = 309_237_645_312;
unsafe extern "C" {
    fn geteuid() -> u32;
    fn umask(mask: u32) -> u32;
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
fn terminal(v: &Value, unit: &Value, service: bool) -> R<()> {
    need(
        v["Id"] == *unit
            && matches!(v["LoadState"].as_str(), Some("loaded" | "not-found"))
            && v["ActiveState"] == "inactive"
            && v["SubState"] == "dead"
            && v["Job"] == "",
        "old guard not drained",
    )?;
    if service {
        need(
            v["MainPID"] == "0"
                && v["ControlPID"] == "0"
                && v["NRestarts"] == "0"
                && v["ControlGroup"] == "",
            "old guard still owns work",
        )?;
    }
    Ok(())
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
fn execute(leaf: &Path, label: &str, argv: &[String]) -> R<()> {
    need(!argv.is_empty(), "empty command")?;
    save(
        &leaf.join(format!("{label}-ORIGINAL-ARGV.json")),
        &json!(argv),
    )?;
    eprintln!("{} {label} starts", now()?);
    let o = Command::new(&argv[0]).args(&argv[1..]).output()?;
    eprintln!("{} {label} completed code={:?}", now()?, o.status.code());
    save(
        &leaf.join(format!("{label}-ORIGINAL-EXECUTION.json")),
        &json!({"code":o.status.code(),"stdout":String::from_utf8_lossy(&o.stdout),"stderr":String::from_utf8_lossy(&o.stderr),"recorded_unix_seconds":now()?}),
    )?;
    need(
        o.status.success(),
        "bounded command failed; original evidence retained",
    )
}
fn seal_plan(leaf: &Path, dest: &Path) -> R<Value> {
    need(
        sha(&read(Path::new(SEALER))?) == SEALER_SHA,
        "sealer changed",
    )?;
    let plan = leaf.join("guard-plan.json");
    let sp = leaf.join("SEAL-PLAN.json");
    save(
        &sp,
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":dest,"members":[{"source":plan,"name":"guard-plan.json","sha256":sha(&read(&plan)?),"mode":292}]}),
    )?;
    let previous = unsafe { umask(0o022) };
    let result = execute(
        leaf,
        "SEAL",
        &[
            SEALER.into(),
            sp.to_string_lossy().into_owned(),
            "--plan-sha256".into(),
            sha(&read(&sp)?),
            "--self-sha256".into(),
            SEALER_SHA.into(),
        ],
    );
    unsafe { umask(previous) };
    result?;
    let b = binding(&dest.join("guard-plan.json"))?;
    need(
        bound(&b)? == bound(&binding(&plan)?)?,
        "normally sealed guard plan differs",
    )?;
    Ok(b)
}
fn original_sample(g: &Value, p: &Value, c: &data_guard_reader::Context<'_>) -> R<()> {
    need(
        g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["guard_sha256"] == OLD_SHA
            && g["plan_sha256"] == p["plan"]["sha256"]
            && g["plan"] == p["plan"]["path"]
            && g["producer_invocation_id"] == c.iid
            && g["producer"]["invocation_id"] == c.iid
            && g["producer"]["pid"] == c.pid
            && g["producer"]["restarts"] == 0
            && g["producer_stop_enabled"] == true
            && g.get("trip_reason") == Some(&Value::Null)
            && g.get("worker_observation_error") == Some(&Value::Null)
            && g.get("root_physical_observation_error") == Some(&Value::Null)
            && g["minimum_free_bytes"] == FLOOR
            && g["maximum_root_physical_bytes"] == CAP
            && g["maximum_worker_vmas"] == 3_500_000
            && g["scratch_deleted"] == false
            && n(g, "available_bytes")? >= FLOOR
            && now()?
                .checked_sub(n(g, "recorded_unix_seconds")?)
                .is_some_and(|age| age <= 45),
        "last old guard does not protect current producer",
    )
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
    old: bool,
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
    if old {
        original_sample(&g, &a.protection, c)?;
    } else {
        data_guard_reader::sample(a, &g, c, now()?, true)?;
        command_current(&service, a)?;
    }
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
    old: bool,
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
        if let Some((p, g)) = capture(a, original, c, old)?
            && !seen.contains(s(&g, "guard_invocation_id")?)
        {
            return Ok((p, g));
        }
        thread::sleep(Duration::from_millis(200));
    }
    Err("finite protective completion deadline expired".into())
}
fn changed_argv(
    old: &[String],
    old_protection: &Value,
    newbase: &str,
    plan: &Value,
    runtime: &Value,
    state: &Path,
) -> R<Vec<String>> {
    need(
        old.len() >= 10
            && old[0] == "/usr/bin/systemd-run"
            && old.iter().any(|v| v == "--on-active=1s")
            && old.iter().any(|v| v == "--on-unit-inactive=5s")
            && old.iter().any(|v| v == "--timer-property=AccuracySec=1s"),
        "original guard argv timer policy differs",
    )?;
    let original_base = s(old_protection, "guard_unit")?
        .strip_suffix(".service")
        .ok_or("old guard suffix")?;
    let old_plan = s(&old_protection["plan"], "path")?;
    let old_hash = s(&old_protection["plan"], "sha256")?;
    let tail = old.len() - 6;
    need(
        old[tail + 1] == old_plan
            && old[tail + 2] == "--plan-sha256"
            && old[tail + 3] == old_hash
            && old[tail + 4] == "--self-sha256"
            && old[tail + 5] == OLD_SHA,
        "original guard exact trailing bindings differ",
    )?;
    let mut changed = old.to_vec();
    let mut counts = [0; 4];
    for v in &mut changed[..tail] {
        if *v == format!("--unit={original_base}") {
            *v = format!("--unit={newbase}");
            counts[0] += 1;
        } else if v.starts_with("--property=ReadWritePaths=") {
            *v = format!(
                "--property=ReadWritePaths={}",
                state.join("receipts").display()
            );
            counts[1] += 1;
        } else if v.starts_with("--property=StandardOutput=append:") {
            *v = format!(
                "--property=StandardOutput=append:{}/guard.stdout",
                state.display()
            );
            counts[2] += 1;
        } else if v.starts_with("--property=StandardError=append:") {
            *v = format!(
                "--property=StandardError=append:{}/guard.stderr",
                state.display()
            );
            counts[3] += 1;
        }
    }
    need(
        counts == [1, 1, 1, 1],
        "guard argv replacement must be exact and unique",
    )?;
    changed[tail] = s(runtime, "path")?.into();
    changed[tail + 1] = s(plan, "path")?.into();
    changed[tail + 3] = s(plan, "sha256")?.into();
    changed[tail + 5] = s(runtime, "sha256")?.into();
    changed.insert(tail, "--property=StartLimitIntervalSec=0".into());
    Ok(changed)
}
fn eligible_span(times: &[u64]) -> R<u64> {
    need(
        (3..=8).contains(&times.len()) && times.windows(2).all(|p| p[0] < p[1]),
        "three distinct increasing guard completions required",
    )?;
    let span = times
        .last()
        .ok_or("last")?
        .checked_sub(times[0])
        .ok_or("completion clock underflow")?;
    need(
        (20..=120).contains(&span),
        "genuine timer span outside20..120seconds",
    )?;
    Ok(span)
}
fn profile(epoch: u64) -> R<Value> {
    need((166..=172).contains(&epoch), "exact166..172 scope required")?;
    let rows: Vec<Value> = serde_json::from_str(include_str!("targets.json"))?;
    let selected = rows
        .iter()
        .filter(|r| r["epoch"] == epoch)
        .collect::<Vec<_>>();
    need(
        rows.len() == 7
            && rows
                .iter()
                .enumerate()
                .all(|(i, row)| row["epoch"] == 166 + i as u64)
            && selected.len() == 1,
        "exact seven-target registry required",
    )?;
    Ok(selected[0].clone())
}
fn transition(
    epoch: u64,
    leaf: &Path,
    reg: &Value,
    original: &Value,
    old_p: &Value,
    old_plan: &Value,
    original_protection: &Value,
) -> R<Value> {
    let unit = s(original, "Id")?;
    let iid = s(original, "InvocationID")?;
    let pid = s(original, "MainPID")?.parse()?;
    let target = profile(epoch)?;
    let original_start = n(&target, "original_start_unix_seconds")?;
    let c = data_guard_reader::Context {
        epoch,
        unit,
        iid,
        pid,
        start: original_start,
        original_protection,
    };
    let mut old = data_guard_reader::registration(reg, now()?)?;
    old.protection = old_p.clone();
    old.plan = old_plan.clone();
    owner(&native(unit)?, original)?;
    timer(&native(s(old_p, "timer_unit")?)?, old_p)?;
    let old_deadline = Instant::now() + Duration::from_secs(25);
    let (old_proof, old_sample) =
        next_proof(&old, original, &c, true, &BTreeSet::new(), old_deadline)?;
    let old_proof_binding = save(&leaf.join("OLD_LAST_GUARD_PID1_TIMER.json"), &old_proof)?;
    let mut gp = old_plan.clone();
    gp["receipt_directory"] = json!(leaf.join("receipts"));
    gp["data_fulfillment"] = json!({"contract":old.registration["contract"],"deployment_seal":old.registration["contract_deployment_seal"]});
    save(&leaf.join("guard-plan.json"), &gp)?;
    let dest = PathBuf::from(format!(
        "/usr/local/lib/jetstreamer/horizon-local2-DATA-guard-epoch{epoch}-{iid}-20261110-v1"
    ));
    let sealed_plan = seal_plan(leaf, &dest)?;
    let seal = binding(&dest.join("deployment-seal-receipt.json"))?;
    let newbase = format!("horizon-guard-replacement-{epoch}-local2-DATA-20261110-v1");
    let argv_value = bound(&target["original_guard_argv"])?;
    let original_argv = argv_value
        .as_array()
        .ok_or("original argv array")?
        .iter()
        .map(|s| {
            s.as_str()
                .map(str::to_owned)
                .ok_or_else(|| "original argv text".into())
        })
        .collect::<R<Vec<String>>>()?;
    need(
        original_argv.len() >= 6
            && sha(&read(Path::new(&original_argv[original_argv.len() - 6]))?) == OLD_SHA,
        "original selected guard image changed",
    )?;
    let argv = changed_argv(
        &original_argv,
        old_p,
        &newbase,
        &sealed_plan,
        &old.runtime,
        leaf,
    )?;
    owner(&native(unit)?, original)?;
    timer(&native(s(old_p, "timer_unit")?)?, old_p)?;
    need(
        now()?
            .checked_sub(n(&old_sample, "recorded_unix_seconds")?)
            .is_some_and(|age| age <= 35),
        "old proof too stale for new first completion",
    )?;
    execute(leaf, "NEW_GUARD_START", &argv)?;
    let mut new = data_guard_reader::registration(reg, now()?)?;
    let new_timer = native(&(newbase.clone() + ".timer"))?;
    new.protection = json!({"schema":"horizon-standard-live-peer-protection-v1","owner":"/root","epoch":epoch,"producer_unit":unit,"producer_invocation_id":iid,"admission":old_p["admission"],"plan":sealed_plan,"plan_deployment_seal":seal,"first_guard_sample":null,"guard_unit":newbase.clone()+".service","timer_unit":newbase.clone()+".timer","timer_invocation_id":new_timer["InvocationID"],"guard_runtime":new.runtime,"DATA_guard_registration":reg});
    new.plan = gp;
    timer(&new_timer, &new.protection)?;
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut proofs = Vec::new();
    let mut seen = BTreeSet::new();
    let mut times = Vec::new();
    while proofs.len() < 3
        || times
            .last()
            .zip(times.first())
            .is_some_and(|(last, first)| last - first < 20)
    {
        need(
            proofs.len() < 8,
            "too many timer completions before sustained window",
        )?;
        let (v, g) = next_proof(&new, original, &c, false, &seen, deadline)?;
        seen.insert(s(&g, "guard_invocation_id")?.into());
        times.push(n(&g, "recorded_unix_seconds")?);
        if proofs.is_empty() {
            new.protection["first_guard_sample"] = v["receipt"].clone();
        }
        eprintln!(
            "{} epoch{epoch} genuine successor completion {} at={} producer_unchanged=true",
            now()?,
            proofs.len() + 1,
            times.last().copied().unwrap_or(0)
        );
        proofs.push(save(
            &leaf.join(format!("NEW_TIMER_COMPLETION_{}.json", proofs.len() + 1)),
            &v,
        )?);
    }
    let span = eligible_span(&times)?;
    need(
        times[0]
            .checked_sub(n(&old_sample, "recorded_unix_seconds")?)
            .is_some_and(|age| age <= 45),
        "old last proof is not close to first new success",
    )?;
    let protection_binding = save(&leaf.join("NEW_GUARD_PROTECTION.json"), &new.protection)?;
    let overlap = native(s(old_p, "timer_unit")?)?;
    timer(&overlap, old_p)?;
    let overlap_when = now()?;
    let last = times.last().copied().ok_or("last completion")?;
    need(overlap_when >= last, "overlap chronology")?;
    owner(&native(unit)?, original)?;
    timer(&native(s(&new.protection, "timer_unit")?)?, &new.protection)?;
    // Only after all actual shared-reader sample/proof checks and sustained overlap may old guard stop.
    let stop_when = now()?;
    execute(
        leaf,
        "OLD_GUARD_STOP",
        &[
            "/usr/bin/systemctl".into(),
            "stop".into(),
            s(old_p, "timer_unit")?.into(),
            s(old_p, "guard_unit")?.into(),
        ],
    )?;
    let old_timer = native(s(old_p, "timer_unit")?)?;
    let old_service = native(s(old_p, "guard_unit")?)?;
    terminal(&old_timer, &old_p["timer_unit"], false)?;
    terminal(&old_service, &old_p["guard_unit"], true)?;
    let after = native(unit)?;
    owner(&after, original)?;
    let armed = native(s(&new.protection, "timer_unit")?)?;
    timer(&armed, &new.protection)?;
    let h = json!({"schema":"horizon-local2-DATA-guard-continuous-handoff-v1","owner":"/root","primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53","epoch":epoch,"registration":reg,"original_protection":original_protection,"new_protection":protection_binding,"producer_before":original,"producer_after":after,"genuine_new_timer_completions":proofs,"old_last_guard_pid1_timer":old_proof_binding,"old_timer_at_last_new_completion":overlap,"old_timer_overlap_recorded_unix_seconds":overlap_when,"old_guard_stop_started_unix_seconds":stop_when,"old_timer_state":old_timer,"old_service_terminal":old_service,"new_timer":armed,"sustained_window_seconds":span,"recorded_unix_seconds":now()?,"no_guard_gap":true,"producer_restarts":0,"all_existing_files_and_prior_endings_retained":true,"raw_minimum_free_bytes":FLOOR,"complete_DATA_bytes":6_229_838_610_226u64,"resource_credit_bytes":0,"DATA_ending_bytes":0,"memory_promise_ending_bytes":0,"replay_admission_authorized":false,"remote_mutations":false});
    let hb = save(
        &leaf.join("ROOT_ACTUAL_CONTINUOUS_GUARD_HANDOFF_COMPLETE.json"),
        &h,
    )?;
    data_guard_reader::load_handoff(&hb, &c, now()?)?;
    Ok(hb)
}
fn run() -> R<()> {
    let args: Vec<_> = env::args().collect();
    need(
        unsafe { geteuid() } == 0 && args.len() == 4 && args[2] == "--self-sha256" && hex(&args[3]),
        "usage: handoff EPOCH --self-sha256 SHA; Root required",
    )?;
    need(
        fs::read_link("/proc/self/exe")? == Path::new(IMAGE)
            && sha(&read(Path::new(IMAGE))?) == args[3]
            && ident(&fs::metadata("/proc/self/exe")?) == ident(&fs::metadata(IMAGE)?),
        "actual normally deployed self image differs",
    )?;
    let iid = env::var("INVOCATION_ID")?;
    need(
        iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "real systemd IID required",
    )?;
    let epoch = args[1].parse::<u64>()?;
    let target = profile(epoch)?;
    let reg: Value = serde_json::from_str(include_str!("registration-binding.json"))?;
    let accepted = data_guard_reader::registration(&reg, now()?)?;
    need(
        accepted.runtime["sha256"] == NEW_SHA,
        "exact qualified V5 image required",
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
    let parent = Path::new(OUT);
    if !parent.exists() {
        mkdir(parent)?;
    }
    private(parent)?;
    let leaf = parent.join(format!("epoch{epoch}"));
    mkdir(&leaf)?;
    mkdir(&leaf.join("receipts"))?;
    save(
        &leaf.join("ROOT_SERIAL_NATIVE16_ALLOCATION.json"),
        &json!({"owner":"/root","old_native_commitments_bytes":13_757_317_120u64,"one_serial_extra_guard_bytes":1u64<<30,"one_operator_bytes":1u64<<30,"total_bytes":15_904_800_768u64,"native16_limit_bytes":16u64<<30,"new_memory_or_DATA_promises_bytes":0,"all_original_promises_and_producers_retained":true,"actual_operator_invocation_id":iid,"epoch":epoch}),
    )?;
    let original = bound(&target["native"])?;
    let original_protection = target["protection"].clone();
    let old = bound(&original_protection)?;
    let admission = bound(&target["admission"])?;
    let first = bound(&target["first_guard"])?;
    let gp = bound(&old["plan"])?;
    need(
        old["schema"] == "horizon-standard-live-peer-protection-v1"
            && old["epoch"] == epoch
            && old["producer_unit"] == original["Id"]
            && old["producer_invocation_id"] == original["InvocationID"]
            && old["admission"] == target["admission"]
            && admission["producer_invocation_id"] == original["InvocationID"]
            && admission["producer_pid"].as_u64() == s(&original, "MainPID")?.parse::<u64>().ok()
            && first["actual_producer"]["InvocationID"] == original["InvocationID"]
            && gp["unit"] == original["Id"]
            && gp["invocation_id"] == original["InvocationID"]
            && gp["minimum_free_bytes"] == FLOOR
            && gp["maximum_root_physical_bytes"] == CAP
            && gp["maximum_worker_vmas"] == 3_500_000
            && gp.get("data_fulfillment").is_none(),
        "exact original admission/first guard/plan differs",
    )?;
    match transition(
        epoch,
        &leaf,
        &reg,
        &original,
        &old,
        &gp,
        &original_protection,
    ) {
        Ok(b) => println!(
            "{}",
            json!({"handoff":b,"epoch":epoch,"producer_unchanged":true,"resource_credit_bytes":0})
        ),
        Err(error) => {
            let old_still_armed = native(s(&old, "timer_unit")?)
                .and_then(|v| timer(&v, &old))
                .is_ok();
            let newbase = format!("horizon-guard-replacement-{epoch}-local2-DATA-20261110-v1");
            if old_still_armed && owner(&native(s(&original, "Id")?)?, &original).is_ok() {
                let state = native(&(newbase.clone() + ".timer"))?;
                if state["LoadState"] == "loaded" {
                    let cleanup = execute(
                        &leaf,
                        "FAILED_NEW_GUARD_DRAIN",
                        &[
                            "/usr/bin/systemctl".into(),
                            "stop".into(),
                            newbase.clone() + ".timer",
                            newbase.clone() + ".service",
                        ],
                    );
                    save(
                        &leaf.join("FAILED_NEW_GUARD_DRAIN_RESULT.json"),
                        &json!({"cleanup_succeeded":cleanup.is_ok(),"error":cleanup.err().map(|e|e.to_string()),"old_timer_still_armed":native(s(&old,"timer_unit")?)?,"new_timer":native(&(newbase.clone()+".timer"))?,"new_service":native(&(newbase+".service"))?,"producer":native(s(&original,"Id")?)?}),
                    )?;
                }
            }
            save(
                &leaf.join("FAILED_HANDOFF_PRESERVED.json"),
                &json!({"epoch":epoch,"error":error.to_string(),"recorded_unix_seconds":now()?,"producer_never_signaled_by_operator":true,"original_protection":original_protection}),
            )?;
            return Err(error);
        }
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_scope_cannot_expand() {
        for e in [0, 165, 173, 200] {
            assert!(profile(e).is_err());
        }
        for e in 166..=172 {
            assert_eq!(profile(e).unwrap()["epoch"], e);
        }
    }
    #[test]
    fn argv_transition_changes_only_declared_bindings_and_keeps_limits() {
        let oldp =
            json!({"guard_unit":"old.service","plan":{"path":"/old-plan","sha256":"a".repeat(64)}});
        let plan = json!({"path":"/new-plan","sha256":"b".repeat(64)});
        let runtime = json!({"path":"/new-image","sha256":NEW_SHA});
        let old = vec![
            "/usr/bin/systemd-run",
            "--unit=old",
            "--on-active=1s",
            "--on-unit-inactive=5s",
            "--timer-property=AccuracySec=1s",
            "--property=MemoryMax=1G",
            "--property=CPUQuota=100%",
            "--property=ReadWritePaths=/old-state",
            "--property=StandardOutput=append:/old-state/out",
            "--property=StandardError=append:/old-state/err",
            "/old-image",
            "/old-plan",
            "--plan-sha256",
            &"a".repeat(64),
            "--self-sha256",
            OLD_SHA,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let actual =
            changed_argv(&old, &oldp, "new", &plan, &runtime, Path::new("/state")).unwrap();
        assert!(actual.iter().any(|v| v == "--unit=new"));
        assert!(actual.iter().any(|v| v == "--property=MemoryMax=1G"));
        assert!(actual.iter().any(|v| v == "--property=CPUQuota=100%"));
        assert!(
            actual
                .iter()
                .any(|v| v == "--property=StartLimitIntervalSec=0")
        );
        assert_eq!(actual[actual.len() - 6], "/new-image");
        assert_eq!(actual[actual.len() - 1], NEW_SHA);
        let mut duplicate = old.clone();
        duplicate.insert(1, "--unit=old".into());
        assert!(
            changed_argv(
                &duplicate,
                &oldp,
                "new",
                &plan,
                &runtime,
                Path::new("/state")
            )
            .is_err()
        );
        let mut wrong = old;
        wrong[2] = "--on-active=2s".into();
        assert!(changed_argv(&wrong, &oldp, "new", &plan, &runtime, Path::new("/state")).is_err());
    }
    #[test]
    fn sustained_gate_requires_three_ordered_real_windows() {
        assert_eq!(eligible_span(&[1, 12, 23]).unwrap(), 22);
        for t in [
            vec![1, 23],
            vec![1, 1, 23],
            vec![1, 12, 20],
            vec![1, 12, 122],
            vec![23, 12, 1],
        ] {
            assert!(eligible_span(&t).is_err());
        }
    }
    #[test]
    fn changed_producer_is_never_accepted() {
        let old = json!({"Id":"u","InvocationID":"a","MainPID":"12","ControlPID":"0","NRestarts":"0","ActiveState":"active","SubState":"running","ExecMainStartTimestamp":"x","ControlGroup":"/a","Job":""});
        owner(&old, &old).unwrap();
        for (k, v) in [
            ("InvocationID", json!("b")),
            ("MainPID", json!("13")),
            ("NRestarts", json!("1")),
            ("Job", json!("pending")),
            ("ControlGroup", json!("/b")),
        ] {
            let mut changed = old.clone();
            changed[k] = v;
            assert!(owner(&changed, &old).is_err());
        }
    }
    #[test]
    fn missing_or_failed_new_proof_cannot_satisfy_gate() {
        assert!(eligible_span(&[]).is_err());
        assert!(eligible_span(&[10]).is_err());
        assert!(eligible_span(&[10, 30]).is_err());
    }
    #[test]
    fn only_exact_drained_old_scope_is_accepted() {
        let unit = json!("old.service");
        let v = json!({"Id":"old.service","LoadState":"not-found","ActiveState":"inactive","SubState":"dead","Job":"","MainPID":"0","ControlPID":"0","NRestarts":"0","ControlGroup":""});
        terminal(&v, &unit, true).unwrap();
        let mut active = v.clone();
        active["ActiveState"] = json!("active");
        assert!(terminal(&active, &unit, true).is_err());
        let mut owned = v;
        owned["ControlGroup"] = json!("/still-owned");
        assert!(terminal(&owned, &unit, true).is_err());
    }
}
