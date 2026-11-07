//! Exact epoch 199 append-file guard. Payloads remain plain JSON: native custody,
//! clocks and file offsets are separate evidence, never fabricated journal fields.
use super::*;
use crate::fleet::ordinary199 as exact;
use std::io::{Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd};

const ENROLLMENT: &str = "/home/sol/.jetstreamer-private/epoch199-backfill-current-preparation-20261102-v1/ACTUAL2258_R2_ENROLLMENT.json";
const ENROLLMENT_SHA: &str = "a2313858851adecca3ff2e144cb61d342cf6757c2dd1249ba0ab88f9770f6b80";
const DIRECTORY: &str = "/var/lib/jetstreamer/epoch199-backfill-20261102-v1/guard";
const STDOUT: &str = "/var/lib/jetstreamer/epoch199-backfill-20261102-v1/guard/guard.stdout.jsonl";
const STDERR: &str = "/var/lib/jetstreamer/epoch199-backfill-20261102-v1/guard/guard.stderr.log";
const FRAGMENT: &str =
    "/run/systemd/transient/jetstreamer-adaptive-reserve-epoch199-backfill-20261102-v1.service";
const FLOOR: u64 = 4_202_184_371_152;
const VMA: u64 = 3_000_000;
const RECORD_LIMIT: u64 = 65536;

pub(in crate::fleet::epoch186) fn enrollment(g: &GuardSpec) -> Result<exact::Proof> {
    enrollment_inner(g, None)
}
/// Carry the current request's selected context into exact enrollment validation.
pub(in crate::fleet::epoch186) fn enrollment_for_context(
    g: &GuardSpec,
    context: &crate::fleet::terminal199_context::Retained,
) -> Result<exact::Proof> {
    enrollment_inner(g, Some(context))
}
pub(in crate::fleet::epoch186) fn enrollment_for_plan(
    g: &GuardSpec,
    plan: &Value,
) -> Result<exact::Proof> {
    match exact::terminal_context(plan)? {
        Some(context) => enrollment_for_context(g, &context),
        None => enrollment(g),
    }
}
fn enrollment_inner(
    g: &GuardSpec,
    context: Option<&crate::fleet::terminal199_context::Retained>,
) -> Result<exact::Proof> {
    let b = g
        .plan
        .as_ref()
        .context("epoch199 append enrollment missing")?;
    ensure!(
        b.path == Path::new(ENROLLMENT)
            && b.sha256 == ENROLLMENT_SHA
            && g.unit == exact::GUARD
            && g.timer == exact::TIMER
            && g.sample.is_none()
            && g.stop_intent == Path::new(DIRECTORY).join("reserve-stop-intent.json")
            && g.stop_completion == Path::new(DIRECTORY).join("reserve-stop-completion.json"),
        "epoch199 append declaration changes exact scope, enrollment or trip paths"
    );
    let binding = serde_json::to_value(b)?;
    let p = match context {
        Some(context) => exact::load_for_context(&binding, context)?,
        None => exact::load(&binding)?,
    }
    .context("epoch199 append enrollment absent")?;
    ensure!(
        g.binary.path == p.enrollment.guard_program.path
            && g.binary.sha256 == p.enrollment.guard_program.sha256,
        "epoch199 append guard image differs from enrolled immutable image"
    );
    Ok(p)
}

/// Walk each component through directory FDs. Only root-owned, non-group/other
/// writable directories and a root-owned, singly linked regular file are allowed.
fn open_root(path: &Path) -> Result<fs::File> {
    ensure!(path.is_absolute(), "epoch199 append nonabsolute path");
    let mut fd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
        .open("/")?;
    let parts = path.components().collect::<Vec<_>>();
    ensure!(parts.len() > 1, "epoch199 append root path");
    for (i, part) in parts.iter().enumerate().skip(1) {
        let std::path::Component::Normal(name) = part else {
            anyhow::bail!("epoch199 append noncanonical path component")
        };
        let directory = i + 1 < parts.len();
        let name = std::ffi::CString::new(name.as_encoded_bytes())?;
        let raw = unsafe {
            libc::openat(
                fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK
                    | if directory { libc::O_DIRECTORY } else { 0 },
            )
        };
        ensure!(
            raw >= 0,
            "epoch199 append descriptor open failed: {}",
            std::io::Error::last_os_error()
        );
        fd = unsafe { fs::File::from_raw_fd(raw) };
        let m = fd.metadata()?;
        ensure!(
            m.uid() == 0
                && m.mode() & 0o022 == 0
                && if directory {
                    m.is_dir()
                } else {
                    m.is_file() && m.nlink() == 1
                },
            "epoch199 append descriptor custody differs"
        );
    }
    Ok(fd)
}
fn metadata(m: &fs::Metadata) -> Value {
    json!({"dev":m.dev(),"ino":m.ino(),"size":m.len(),"uid":m.uid(),"gid":m.gid(),
        "mode":m.mode(),"nlink":m.nlink(),"mtime_seconds":m.mtime(),"mtime_nanoseconds":m.mtime_nsec(),
        "ctime_seconds":m.ctime(),"ctime_nanoseconds":m.ctime_nsec()})
}
fn unchanged(path: &Path, f: &fs::File, before: &fs::Metadata) -> Result<()> {
    ensure!(
        identity(before) == identity(&f.metadata()?)
            && identity(before) == identity(&open_root(path)?.metadata()?),
        "epoch199 append file changed, rotated or truncated during read"
    );
    Ok(())
}
fn final_record(bytes: &[u8], file_size: u64) -> Result<(u64, &[u8])> {
    ensure!(
        !bytes.is_empty() && bytes.last() == Some(&b'\n'),
        "epoch199 append incomplete trailing record"
    );
    let at = bytes[..bytes.len() - 1]
        .iter()
        .rposition(|&c| c == b'\n')
        .map_or(0, |v| v + 1);
    let record = &bytes[at..];
    ensure!(
        record.len() > 1
            && record.len() as u64 <= RECORD_LIMIT
            && (at > 0 || bytes.len() as u64 == file_size),
        "epoch199 append final record exceeds bound or begins outside tail"
    );
    Ok((
        file_size
            .checked_sub(record.len() as u64)
            .context("epoch199 append offset overflow")?,
        record,
    ))
}
fn log_snapshot() -> Result<Value> {
    let path = Path::new(STDOUT);
    let mut f = open_root(path)?;
    let m = f.metadata()?;
    ensure!(
        m.len() > 0 && m.len() <= 1u64 << 40,
        "epoch199 append log size outside bound"
    );
    let length = m.len().min(RECORD_LIMIT * 2);
    f.seek(SeekFrom::Start(m.len() - length))?;
    let mut bytes = vec![0u8; length as usize];
    f.read_exact(&mut bytes)?;
    unchanged(path, &f, &m)?;
    let (offset, raw) = final_record(&bytes, m.len())?;
    // unique_json rejects duplicate object keys as well as trailing payloads.
    let payload = unique_json(raw)?;
    Ok(
        json!({"path":STDOUT,"identity":metadata(&m),"record_offset":offset,
        "record_length":raw.len(),"record_sha256":hex_lower(&Sha256::digest(raw)),
        "raw_record_utf8":std::str::from_utf8(raw)?,"payload":payload}),
    )
}
fn output_native() -> Result<Value> {
    let out = ProcessCommand::new("/usr/bin/systemctl")
        .args([
            "show",
            exact::GUARD,
            "--no-pager",
            "--property=StandardOutput,StandardError,FragmentPath,DropInPaths,Transient,TimeoutStartUSec,TimeoutStopUSec,UMask,OOMPolicy",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 65536,
        "epoch199 append stdout native query failed"
    );
    let mut row = serde_json::Map::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line
            .split_once('=')
            .context("epoch199 append stdout native framing")?;
        ensure!(
            row.insert(k.into(), json!(v)).is_none(),
            "epoch199 append duplicate stdout native field"
        );
    }
    let row = Value::Object(row);
    ensure!(
        row["StandardOutput"] == "append"
            && row["StandardError"] == "append"
            && row["FragmentPath"] == FRAGMENT
            && row["DropInPaths"] == ""
            && row["Transient"] == "yes"
            && row["TimeoutStartUSec"] == "5min"
            && row["TimeoutStopUSec"] == "30s"
            && row["UMask"] == "0077"
            && row["OOMPolicy"] == "stop",
        "epoch199 append live stdout destination, transient fragment or drop-ins differ"
    );
    Ok(row)
}
fn fragment_snapshot() -> Result<Value> {
    let path = Path::new(FRAGMENT);
    let mut f = open_root(path)?;
    let m = f.metadata()?;
    ensure!(
        m.len() > 0 && m.len() <= 65536,
        "epoch199 append transient fragment exceeds bound"
    );
    let mut bytes = Vec::with_capacity(m.len() as usize);
    Read::by_ref(&mut f).take(65537).read_to_end(&mut bytes)?;
    unchanged(path, &f, &m)?;
    let mut section = "";
    let mut stdout = None;
    let mut stderr = None;
    for line in std::str::from_utf8(&bytes)?.lines() {
        let line = line.trim();
        ensure!(
            !line.ends_with('\\') && !line.starts_with(".include"),
            "epoch199 append fragment has continuation or include"
        );
        if line.starts_with('[') {
            section = line;
            continue;
        }
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if section == "[Service]" {
            if let Some(value) = line.strip_prefix("StandardOutput=") {
                ensure!(
                    stdout.replace(value).is_none(),
                    "epoch199 append duplicate stdout assignment"
                );
            }
            if let Some(value) = line.strip_prefix("StandardError=") {
                ensure!(
                    stderr.replace(value).is_none(),
                    "epoch199 append duplicate stderr assignment"
                );
            }
        }
    }
    ensure!(
        stdout == Some(format!("append:{STDOUT}").as_str())
            && stderr == Some(format!("append:{STDERR}").as_str()),
        "epoch199 append exact installed file destinations differ"
    );
    Ok(json!({"path":FRAGMENT,"identity":metadata(&m),"sha256":hex_lower(&Sha256::digest(&bytes))}))
}
fn typed_micros(raw: &str) -> Result<u64> {
    let fields = raw.split_whitespace().collect::<Vec<_>>();
    ensure!(
        fields.len() == 2 && fields[0] == "t" && fields[1].bytes().all(|b| b.is_ascii_digit()),
        "epoch199 append native timestamp must be a typed unsigned microsecond value"
    );
    let v = fields[1].parse::<u64>()?;
    ensure!(v > 0, "epoch199 append native timestamp is zero");
    Ok(v)
}
fn clocks() -> Result<Value> {
    let object = format!(
        "/org/freedesktop/systemd1/unit/{}",
        exact::GUARD.replace('-', "_2d").replace('.', "_2e")
    );
    let mut row = serde_json::Map::new();
    for key in ["ExecMainStartTimestamp", "ExecMainExitTimestamp"] {
        let out = ProcessCommand::new("/usr/bin/busctl")
            .args([
                "get-property",
                "org.freedesktop.systemd1",
                &object,
                "org.freedesktop.systemd1.Service",
                key,
            ])
            .output()?;
        ensure!(
            out.status.success() && out.stdout.len() <= 4096,
            "epoch199 append native clock query failed"
        );
        let raw = std::str::from_utf8(&out.stdout)?.trim();
        row.insert(key.into(), json!({"raw":raw,"micros":typed_micros(raw)?}));
    }
    Ok(Value::Object(row))
}
fn family() -> Result<Value> {
    let mut row = serde_json::Map::new();
    for name in exact::FAMILY {
        row.insert(name.into(), unit(name)?);
    }
    Ok(Value::Object(row))
}
fn terminal(n: &Value) -> Result<()> {
    ensure!(
        n["Id"] == exact::GUARD
            && digest(string(n, "/InvocationID")?, 32)
            && n["ExecMainCode"] == "1"
            && n["MainPID"] == "0"
            && n["ControlPID"] == "0"
            && n["NRestarts"] == "0"
            && n["Result"] == "success"
            && n["ExecMainStatus"] == "0"
            && n["ActiveState"] == "inactive"
            && n["SubState"] == "dead"
            && n["MemoryAccounting"] == "yes"
            && n["MemoryHigh"] == "402653184"
            && n["MemoryMax"] == "536870912"
            && n["MemorySwapMax"] == "0"
            && n["CPUQuotaPerSecUSec"] == "1s"
            && n["TasksMax"] == "256",
        "epoch199 append needs the actual successful completed guard invocation"
    );
    Ok(())
}
fn payload_gate(payload: &Value, p: &exact::Enrollment, native: &Value) -> Result<()> {
    ensure!(
        payload.as_object().is_some_and(|o| o.len() == 7)
            && payload["armed"] == true
            && payload["trip"] == false
            && payload["minimum_free_bytes"] == FLOOR
            && payload["maximum_worker_vmas"] == VMA
            && number(payload, "/available_bytes")? >= FLOOR,
        "epoch199 append payload is unarmed, tripped or changes the exact floor/VMA policy"
    );
    for (role, owner) in [("controller", &p.controller), ("producer", &p.producer)] {
        let sample = &payload[role];
        let current = &native[&owner.unit];
        ensure!(
            sample["unit"] == owner.unit
                && sample["invocation_id"] == owner.invocation_id
                && sample["load_state"] == "loaded"
                && sample["active_state"] == "active"
                && sample["sub_state"] == "running"
                && sample["result"] == "success"
                && sample["restarts"] == 0
                && sample["control_group"] == format!("/system.slice/{}", owner.unit)
                && number(sample, "/main_pid")? == string(current, "/MainPID")?.parse::<u64>()?,
            "epoch199 append payload changes protected native owner"
        );
        match number(sample, "/worker_count")? {
            0 => ensure!(
                sample.get("worker_pid").is_some_and(Value::is_null)
                    && sample.get("worker_vmas").is_some_and(Value::is_null),
                "epoch199 append absent worker fields differ"
            ),
            1 => ensure!(
                number(sample, "/worker_pid")? > 1
                    && number(sample, "/worker_vmas")? > 0
                    && number(sample, "/worker_vmas")? <= VMA,
                "epoch199 append worker exceeds sealed VMA cap"
            ),
            _ => anyhow::bail!("epoch199 append more than one identifiable worker"),
        }
    }
    Ok(())
}
fn clock_window(clock: &Value, log: &Value, now: u64) -> Result<()> {
    for key in ["ExecMainStartTimestamp", "ExecMainExitTimestamp"] {
        ensure!(
            typed_micros(string(&clock[key], "/raw")?)? == number(&clock[key], "/micros")?,
            "epoch199 append parsed native clock differs"
        );
    }
    let start = number(&clock["ExecMainStartTimestamp"], "/micros")?;
    let exit = number(&clock["ExecMainExitTimestamp"], "/micros")?;
    ensure!(
        start <= exit
            && exit - start <= 300_000_000
            && exit / 1_000_000 <= now
            && now - exit / 1_000_000 <= 180,
        "epoch199 append completed fire is stale, future or exceeds native timeout"
    );
    let seconds = number(&log["identity"], "/mtime_seconds")?;
    let ns = number(&log["identity"], "/mtime_nanoseconds")?;
    ensure!(
        ns < 1_000_000_000,
        "epoch199 append mtime nanoseconds malformed"
    );
    let mtime = seconds
        .checked_mul(1_000_000_000)
        .and_then(|s| s.checked_add(ns))
        .context("epoch199 append mtime overflow")?;
    // Filesystem mtime may use the coarse kernel clock. Deliberately bound
    // that rounding to the enclosing one-second native window; never infer an
    // invocation ID or timestamp from the JSON payload itself.
    let lower = (start / 1_000_000)
        .checked_mul(1_000_000_000)
        .context("epoch199 append clock overflow")?;
    let upper = (exit / 1_000_000)
        .checked_add(1)
        .and_then(|s| s.checked_mul(1_000_000_000))
        .context("epoch199 append clock overflow")?;
    ensure!(
        mtime >= lower && mtime < upper,
        "epoch199 append final record was not written in current completed invocation window"
    );
    Ok(())
}
fn validate_snapshot(g: &GuardSpec, p: &exact::Proof, s: &Value) -> Result<()> {
    ensure!(
        s["schema"] == "jetstreamer-epoch199-append-guard-snapshot-v1"
            && s["enrollment"]
                == serde_json::to_value(g.plan.as_ref().context("epoch199 append plan")?)?
            && s["clock_rounding_window"] == "enclosing-native-second",
        "epoch199 append snapshot scope differs"
    );
    p.validate_native(&s["full_family"])?;
    terminal(&s["full_family"][exact::GUARD])?;
    let l = &s["log"];
    let raw = string(l, "/raw_record_utf8")?.as_bytes();
    let size = number(&l["identity"], "/size")?;
    ensure!(
        !raw.is_empty()
            && raw.last() == Some(&b'\n')
            && !raw[..raw.len() - 1].contains(&b'\n')
            && raw.len() as u64 <= RECORD_LIMIT
            && raw.len() > 1
            && size <= 1u64 << 40,
        "epoch199 append snapshot record is incomplete or exceeds bounds"
    );
    let offset = size
        .checked_sub(raw.len() as u64)
        .context("epoch199 append snapshot offset underflow")?;
    let record = raw;
    ensure!(
        l["path"] == STDOUT
            && l["record_offset"] == offset
            && l["record_length"] == record.len() as u64
            && l["record_sha256"] == hex_lower(&Sha256::digest(record))
            && l["payload"] == unique_json(record)?
            && l["identity"]["uid"] == 0
            && l["identity"]["nlink"] == 1
            && number(&l["identity"], "/mode")? & 0o022 == 0,
        "epoch199 append log descriptor, offset, bytes or payload differs"
    );
    ensure!(
        s["output_native"]["StandardOutput"] == "append"
            && s["output_native"]["StandardError"] == "append"
            && s["output_native"]["FragmentPath"] == FRAGMENT
            && s["output_native"]["DropInPaths"] == ""
            && s["output_native"]["Transient"] == "yes"
            && s["output_native"]["TimeoutStartUSec"] == "5min"
            && s["output_native"]["TimeoutStopUSec"] == "30s"
            && s["output_native"]["UMask"] == "0077"
            && s["output_native"]["OOMPolicy"] == "stop"
            && s["fragment"]["path"] == FRAGMENT
            && digest(string(&s["fragment"], "/sha256")?, 64),
        "epoch199 append output binding differs"
    );
    clock_window(&s["clock"], l, number(s, "/checked_unix_seconds")?)?;
    payload_gate(&l["payload"], &p.enrollment, &s["full_family"])
}

pub(super) fn load(
    g: &GuardSpec,
    native: &Value,
    owners: &[core::Owner],
    time: u64,
) -> Result<(Value, String, Value)> {
    let p = enrollment(g)?;
    let before = family()?;
    p.validate_native(&before)?;
    terminal(&before[exact::GUARD])?;
    ensure!(
        before[exact::GUARD]["InvocationID"] == native["InvocationID"]
            && before[exact::GUARD]["ExecStart"] == native["ExecStart"],
        "epoch199 append changed across native readers"
    );
    for owner in [&p.enrollment.controller, &p.enrollment.producer] {
        ensure!(
            owners
                .iter()
                .filter(|o| o.unit == owner.unit
                    && o.iid == owner.invocation_id
                    && before[&owner.unit]["MainPID"]
                        .as_str()
                        .and_then(|v| v.parse::<u64>().ok())
                        == Some(o.pid))
                .count()
                == 1,
            "epoch199 append protects a missing or foreign accounting owner"
        );
    }
    let clock = clocks()?;
    let output = output_native()?;
    let fragment = fragment_snapshot()?;
    let log = log_snapshot()?;
    ensure!(
        clock == clocks()?
            && output == output_native()?
            && fragment == fragment_snapshot()?
            && before == family()?
            && log == log_snapshot()?,
        "epoch199 append native invocation, output binding or fragment changed during read"
    );
    let proof = json!({"schema":"jetstreamer-epoch199-append-guard-snapshot-v1","enrollment":g.plan,
        "full_family":before,"clock":clock,"output_native":output,"fragment":fragment,"log":log,
        "clock_rounding_window":"enclosing-native-second","checked_unix_seconds":time});
    validate_snapshot(g, &p, &proof)?;
    absent(&g.stop_intent)?;
    absent(&g.stop_completion)?;
    Ok((
        proof["log"]["payload"].clone(),
        string(native, "/InvocationID")?.into(),
        proof,
    ))
}
fn log_pair(a: &Value, b: &Value, same_iid: bool) -> Result<()> {
    ensure!(a["path"] == b["path"], "epoch199 append log path changed");
    for key in ["dev", "ino", "uid", "gid", "mode", "nlink"] {
        ensure!(
            a["identity"][key] == b["identity"][key],
            "epoch199 append log custody or inode changed: {key}"
        );
    }
    if same_iid {
        ensure!(a == b, "epoch199 append same invocation changed log record");
    } else {
        ensure!(
            number(&b["identity"], "/size")? > number(&a["identity"], "/size")?
                && number(b, "/record_offset")? >= number(&a["identity"], "/size")?
                && (
                    number(&b["identity"], "/mtime_seconds")?,
                    number(&b["identity"], "/mtime_nanoseconds")?
                ) > (
                    number(&a["identity"], "/mtime_seconds")?,
                    number(&a["identity"], "/mtime_nanoseconds")?
                ),
            "epoch199 append refire rotated, truncated, rewrote or regressed log"
        );
    }
    Ok(())
}
/// Verify the previous final record is still present at its original offset in
/// the same current append descriptor. No whole-log scan or mutable copy is used.
fn prior_record_still_present(a: &Value, b: &Value) -> Result<()> {
    let mut f = open_root(Path::new(STDOUT))?;
    let before = f.metadata()?;
    ensure!(
        metadata(&before) == b["identity"],
        "epoch199 append log advanced after second snapshot"
    );
    let length = number(a, "/record_length")?;
    ensure!(
        length <= RECORD_LIMIT,
        "epoch199 append prior record exceeds bound"
    );
    f.seek(SeekFrom::Start(number(a, "/record_offset")?))?;
    let mut bytes = vec![0u8; length as usize];
    f.read_exact(&mut bytes)?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == a["record_sha256"],
        "epoch199 append prior record was rewritten or truncated"
    );
    unchanged(Path::new(STDOUT), &f, &before)
}
fn thin_pair(a: &Value, b: &Value, na: &Value, nb: &Value) -> Result<()> {
    let mut rows = [a.clone(), b.clone()];
    for (row, full) in rows.iter_mut().zip([na, nb]) {
        let native = &row["native"];
        ensure!(
            native["InvocationID"] == full["InvocationID"]
                && native["ExecStart"] == full["ExecStart"],
            "epoch199 append thin/native identity differs"
        );
        row.as_object_mut()
            .context("epoch199 append evidence object")?
            .remove("epoch199_append_continuity");
        let n = row["native"]
            .as_object_mut()
            .context("epoch199 append thin native object")?;
        n.remove("InvocationID");
        n.remove("ExecStart");
    }
    ensure!(
        rows[0] == rows[1],
        "epoch199 append another native property changed"
    );
    Ok(())
}
pub(in crate::fleet::epoch186) fn compare(
    g: &GuardSpec,
    guards: (&Value, &Value),
    evidence: (&Value, &Value),
    census: (
        &mut serde_json::Map<String, Value>,
        &mut serde_json::Map<String, Value>,
    ),
) -> Result<()> {
    let p = enrollment(g)?;
    let (a, b) = (
        &evidence.0["epoch199_append_continuity"],
        &evidence.1["epoch199_append_continuity"],
    );
    validate_snapshot(g, &p, a)?;
    validate_snapshot(g, &p, b)?;
    let mut typed = [guards.0.clone(), guards.1.clone()];
    for row in &mut typed {
        ensure!(
            row.as_object_mut()
                .context("epoch199 append typed proof")?
                .remove("iid")
                .and_then(|v| v.as_str().map(str::to_owned))
                .is_some_and(|iid| digest(&iid, 32)),
            "epoch199 append typed IID missing"
        );
    }
    ensure!(
        typed[0] == typed[1],
        "epoch199 append protected owners, floor or authority changed"
    );
    for key in [
        "enrollment",
        "output_native",
        "fragment",
        "clock_rounding_window",
    ] {
        ensure!(
            a[key] == b[key],
            "epoch199 append fixed source changed: {key}"
        );
    }
    let (fa, fb) = (&a["full_family"], &b["full_family"]);
    let (na, nb) = (&fa[exact::GUARD], &fb[exact::GUARD]);
    ensure!(
        guards.0["iid"] == na["InvocationID"] && guards.1["iid"] == nb["InvocationID"],
        "epoch199 append typed/native IID differs"
    );
    for name in exact::FAMILY {
        ensure!(
            census.0.get(name) == Some(&fa[name]) && census.1.get(name) == Some(&fb[name]),
            "epoch199 append snapshot is not exact complete accounting native census"
        );
    }
    ensure!(
        p.normalize_guard(fa, fb)? == *fa,
        "epoch199 append unrelated owner or timer policy changed"
    );
    let same = na["InvocationID"] == nb["InvocationID"];
    if same {
        ensure!(
            fa == fb && a["clock"] == b["clock"],
            "epoch199 append same IID changed native state"
        );
    } else {
        ensure!(
            number(&b["clock"]["ExecMainStartTimestamp"], "/micros")?
                > number(&a["clock"]["ExecMainExitTimestamp"], "/micros")?,
            "epoch199 append refire clock did not advance"
        );
    }
    ensure!(
        number(a, "/checked_unix_seconds")? <= number(b, "/checked_unix_seconds")?,
        "epoch199 append observation clock regressed"
    );
    log_pair(&a["log"], &b["log"], same)?;
    prior_record_still_present(&a["log"], &b["log"])?;
    thin_pair(evidence.0, evidence.1, na, nb)?;
    // Only the exact successfully completed guard and its own timer deadline are
    // normalized. Owners, historical failed4 debt and every other row stay raw.
    census.1.insert(g.unit.clone(), na.clone());
    census.1.insert(g.timer.clone(), fa[exact::TIMER].clone());
    Ok(())
}

#[cfg(test)]
#[path = "io_epoch199_append_tests.rs"]
mod tests;

pub(super) fn retained_snapshot(
    g: &GuardSpec,
    native: &Value,
    context_binding: &crate::fleet::terminal199_context::Bound,
) -> Result<Value> {
    let context = crate::fleet::terminal199_context::Retained::load(context_binding)?;
    let p = enrollment_for_context(g, &context)?;
    let before = family()?;
    context.validate_current_membership(&before)?;
    p.validate_native_retained(&before, &context)?;
    ensure!(
        before[exact::GUARD]["InvocationID"] == native["InvocationID"]
            && before[exact::GUARD]["ExecStart"] == native["ExecStart"],
        "retained199 guard native changed across readers"
    );
    absent(&g.stop_intent)?;
    absent(&g.stop_completion)?;
    let output = output_native()?;
    let fragment = fragment_snapshot()?;
    let free = crate::fleet::snapshot144::free_bytes()?;
    ensure!(
        free >= FLOOR,
        "retained199 original filesystem floor breached"
    );
    let after = family()?;
    p.normalize_guard_retained(&before, &after, &context)?;
    ensure!(
        output == output_native()? && fragment == fragment_snapshot()?,
        "retained199 guard installed outputs or immutable fragment changed"
    );
    context.revalidate_inputs()?;
    Ok(
        json!({"schema":"jetstreamer-original199-terminal-retained-guard-v1",
        "context":context_binding,"enrollment":p.binding,"full_family":after,
        "output_native":output,"fragment":fragment,"minimum_free_bytes":FLOOR,
        "available_bytes":free,"original_producer_gone":true,"no_live_owner_protection_claimed":true,
        "parent_memory_bytes_retained":192u64<<30,"controller_memory_bytes_retained":512u64<<20,
        "guard_memory_bytes_retained":512u64<<20,"DATA_bytes_retained":768u64<<30,
        "memory_credit_bytes":0,"DATA_credit_bytes":0}),
    )
}
pub(in crate::fleet::epoch186) fn validate_retained_snapshot(
    g: &GuardSpec,
    v: &Value,
) -> Result<()> {
    let context = crate::fleet::terminal199_context::Retained::load(&serde_json::from_value(
        v["context"].clone(),
    )?)?;
    let p = enrollment_for_context(g, &context)?;
    ensure!(
        v["schema"] == "jetstreamer-original199-terminal-retained-guard-v1"
            && v["enrollment"] == serde_json::to_value(&p.binding)?
            && v["minimum_free_bytes"] == FLOOR
            && number(v, "/available_bytes")? >= FLOOR
            && v["original_producer_gone"] == true
            && v["no_live_owner_protection_claimed"] == true
            && v["parent_memory_bytes_retained"] == 192u64 << 30
            && v["controller_memory_bytes_retained"] == 512u64 << 20
            && v["guard_memory_bytes_retained"] == 512u64 << 20
            && v["DATA_bytes_retained"] == 768u64 << 30
            && v["memory_credit_bytes"] == 0
            && v["DATA_credit_bytes"] == 0,
        "retained199 exact original guard custody or promises changed"
    );
    context.validate_current_membership(&v["full_family"])?;
    p.validate_native_retained(&v["full_family"], &context)?;
    ensure!(
        v["output_native"] == output_native()? && v["fragment"] == fragment_snapshot()?,
        "retained199 actual installed output/fragment differs"
    );
    absent(&g.stop_intent)?;
    absent(&g.stop_completion)?;
    Ok(())
}

#[cfg(test)]
pub(in crate::fleet::epoch186) fn retained_snapshot_for_continuity_test(
    g: &GuardSpec,
    native: &Value,
    context_binding: &crate::fleet::terminal199_context::Bound,
) -> Result<Value> {
    retained_snapshot(g, native, context_binding)
}
