//! Historical release and current guard evidence for one original epoch 185 owner.
//! Expired launch clocks are history only; none of these constructors grants work.
use super::*;
const GUARD_ROOT: &str = "/var/lib/jetstreamer/epoch185-cold-guard-v4";
const SEALER: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";

fn protected(path: &Path, cap: u64) -> Result<(BoundFile, Value)> {
    ancestors(path)?;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o7777 == 0o600
            && before.len() <= cap,
        "epoch 185 original guard receipt custody"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(cap + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.len()
            && identity(&before) == identity(&file.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(path)?),
        "epoch 185 original guard receipt changed during read"
    );
    let b = BoundFile {
        path: path.to_path_buf(),
        sha256: digest(&bytes),
    };
    Ok((b, serde_json::from_slice(&bytes)?))
}
fn normal(path: &Path, cap: u64) -> Result<(BoundFile, Value)> {
    ancestors(path)?;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o7222 == 0
            && before.len() <= cap,
        "epoch 185 original normal release custody"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(cap + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.len()
            && identity(&before) == identity(&file.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(path)?),
        "epoch 185 original normal release changed during read"
    );
    let b = BoundFile {
        path: path.to_path_buf(),
        sha256: digest(&bytes),
    };
    Ok((b, serde_json::from_slice(&bytes)?))
}
fn row_micros(row: &Value) -> Result<u64> {
    Ok(text(row, "__REALTIME_TIMESTAMP")?.parse::<u64>()?)
}
fn row_time(row: &Value) -> Result<u64> {
    Ok(row_micros(row)? / 1_000_000)
}
fn journal(actor: &str) -> Result<Vec<Value>> {
    // Bound the read itself, not only the already allocated command output.
    let mut child = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            "--all",
            "--no-pager",
            "--output=json",
            "-u",
            actor,
            "_PID=1",
            "_UID=0",
        ])
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env_remove("SYSTEMD_HOST")
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let mut bytes = Vec::new();
    let read = child
        .stdout
        .take()
        .context("epoch 185 manager journal pipe")?
        .take((8 << 20) + 1)
        .read_to_end(&mut bytes);
    if read.is_err() || bytes.len() > 8 << 20 {
        let _ = child.kill();
        let _ = child.wait();
        read?;
        anyhow::bail!("epoch 185 original manager journal exceeds bounded read");
    }
    ensure!(
        child.wait()?.success(),
        "epoch 185 original manager journal unavailable"
    );
    bytes
        .split(|c| *c == b'\n')
        .filter(|v| !v.is_empty())
        .map(|v| Ok(serde_json::from_slice(v)?))
        .collect()
}
fn main_start(rows: &[Value], spec: &Spec) -> Result<Value> {
    let starts = rows
        .iter()
        .filter(|r| {
            r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["UNIT"] == spec.actor_unit
                && [
                    "7d4958e842da4a758f6c1cdc7b36dcc5",
                    "39f53479d3a045ac8e11786248231fbf",
                ]
                .contains(&r["MESSAGE_ID"].as_str().unwrap_or(""))
        })
        .map(|r| Ok((row_micros(r)?, r)))
        .collect::<Result<Vec<_>>>()?;
    let latest = starts
        .iter()
        .max_by_key(|r| r.0)
        .context("epoch 185 original manager start absent")?
        .1;
    ensure!(
        latest["INVOCATION_ID"] == spec.expected_actor_invocation_id,
        "epoch 185 original owner was replaced by a later manager start"
    );
    let done = starts
        .iter()
        .filter(|(_, r)| {
            r["INVOCATION_ID"] == spec.expected_actor_invocation_id
                && r["MESSAGE_ID"] == "39f53479d3a045ac8e11786248231fbf"
                && r["JOB_TYPE"] == "start"
                && r["JOB_RESULT"] == "done"
        })
        .map(|(_, r)| *r)
        .collect::<Vec<_>>();
    ensure!(
        done.len() == 1,
        "epoch 185 original main execution is missing or duplicated"
    );
    // A later start of any invocation is never hidden by retained history.
    ensure!(
        row_micros(latest)? == row_micros(done[0])?,
        "epoch 185 original manager chronology changed after release"
    );
    Ok(done[0].clone())
}
fn original_clocks(
    token: &Value,
    ready: &Value,
    admission: &Value,
    guard: &Value,
    setup: u64,
) -> Result<()> {
    let started = number(ready, "started_at")?;
    let fire = number(guard, "sampled_at")?;
    let issued = number(token, "issued_at")?;
    let expires = number(token, "expires_at")?;
    let deadline = started
        .checked_add(setup)
        .context("epoch 185 original setup overflow")?;
    ensure!(
        (30..=600).contains(&setup)
            && started <= fire
            && fire <= issued
            && issued < expires
            && expires <= deadline
            && issued - fire <= 30
            && number(admission, "issued_at")? <= issued
            && expires <= number(admission, "expires_at")?,
        "epoch 185 original release exceeded setup, first-fire or admission clock"
    );
    Ok(())
}
fn accepted_bridge(
    value: &Value,
    kind: &str,
    spec: &Spec,
    ready: &Value,
    issued: u64,
) -> Result<()> {
    ensure!(
        value["schema"] == "horizon-epoch185-native-owner-enrollment-v4"
            && value["epoch"] == 185
            && value["kind"] == kind
            && value["actor_unit"] == spec.actor_unit
            && value["actor_invocation_id"] == spec.expected_actor_invocation_id
            && value["ready_pid"] == ready["pid"]
            && value["ready_start_ticks"] == ready["start_ticks"]
            && value["admission_sha256"] == spec.admission.sha256
            && value["restarts"] == 0
            && value["phase"] == "verification"
            && value["root_operator_owner"] == true
            && value["actual_start_pre_evidence_accepted"] == true
            && value["resource_credit_bytes"] == 0
            && value["numeric_delivery_eta_millis"]
                .as_u64()
                .is_some_and(|n| n > 0),
        "epoch 185 original typed acceptance crossed source, owner, ETA or authority"
    );
    let at = number(value, "sampled_at")?;
    ensure!(
        number(ready, "started_at")? <= at && at <= issued && issued - at <= 30,
        "epoch 185 typed acceptance was not fresh at original token issue"
    );
    read_json(&binding(&value["underlying_accepted_proof"])?, 4 * MIB)?;
    Ok(())
}
fn guard_receipt(value: &Value, spec: &Spec, envelope: &Value) -> Result<()> {
    ensure!(
        value["schema"] == "horizon-epoch185-native-guard-result-v4"
            && value["epoch"] == 185
            && value["actor_unit"] == spec.actor_unit
            && value["actor_invocation_id"] == spec.expected_actor_invocation_id
            && value["admission_sha256"] == spec.admission.sha256
            && value["timer_unit"] == envelope["timer_unit"]
            && value["timer_driven"] == true
            && value["success"] == true
            && value.get("failure") == Some(&Value::Null)
            && value["capacity_credit_bytes"] == 0
            && is_lower_hex(text(value, "guard_invocation_id")?, 32),
        "epoch 185 guard receipt has a trip, foreign owner or false authority"
    );
    let trigger = number(value, "timer_last_trigger_monotonic_micros")?;
    let begin = number(value, "guard_start_monotonic_micros")?;
    ensure!(
        trigger > 0 && trigger <= begin && begin - trigger <= 5_000_000,
        "epoch 185 guard did not follow a genuine first or periodic timer trigger"
    );
    Ok(())
}
fn released_clock(
    token: &Value,
    seal: &Value,
    first: &Value,
    start: &Value,
    now: u64,
) -> Result<u64> {
    let started = row_time(start)?;
    let issued = number(token, "issued_at")?;
    let sealed = number(seal, "created_unix_seconds")?;
    ensure!(
        issued <= sealed
            && sealed <= started
            && started < number(token, "expires_at")?
            && started <= now
            && started
                .checked_sub(number(first, "sampled_at")?)
                .is_some_and(|age| age <= 30),
        "epoch 185 original main execution missed its actual token deadline or first-fire freshness"
    );
    Ok(started)
}

pub(super) fn release(spec: &Spec, envelope: &Value, ready: &Value, now: u64) -> Result<Value> {
    let dir = Path::new(text(envelope, "token_root")?).join(&spec.expected_actor_invocation_id);
    let (token_bound, token) = normal(&dir.join("token.json"), 4 * MIB)?;
    let (seal_bound, seal) = normal(&dir.join("deployment-seal-receipt.json"), 4 * MIB)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == dir.to_string_lossy().as_ref()
            && seal["sealer_sha256"] == SEALER
            && is_lower_hex(text(&seal, "plan_sha256")?, 64),
        "epoch 185 release lacks exact normal Root seal"
    );
    let members = seal["members"]
        .as_array()
        .context("epoch 185 token seal members")?;
    ensure!(
        members.len() == 1
            && members[0]["name"] == "token.json"
            && members[0]["sha256"] == token_bound.sha256
            && members[0]["bytes"] == fs::symlink_metadata(&token_bound.path)?.len(),
        "epoch 185 normal token seal member or digest changed"
    );
    ensure!(
        token["schema"] == "horizon-epoch185-native-gate-v4"
            && token["epoch"] == 185
            && token["actor_unit"] == spec.actor_unit
            && token["actor_invocation_id"] == spec.expected_actor_invocation_id
            && token["admission_sha256"] == spec.admission.sha256
            && token["driver_sha256"] == DRIVER_SHA
            && token["ready_pid"] == ready["pid"]
            && token["ready_start_ticks"] == ready["start_ticks"]
            && token["ready_sha256"] == spec.ready.sha256
            && token["guard_unit"] == envelope["guard_unit"]
            && token["timer_unit"] == envelope["timer_unit"],
        "epoch 185 original token crossed readiness or deployment"
    );
    let guard = &token["guard_result"];
    guard_receipt(guard, spec, envelope)?;
    ensure!(
        guard["actor_pid"] == ready["pid"] && guard["actor_start_ticks"] == ready["start_ticks"],
        "epoch 185 first guard does not bind the original mapped ControlPID"
    );
    let first_path = Path::new(GUARD_ROOT).join(format!(
        "guard-{}.json",
        text(guard, "guard_invocation_id")?
    ));
    let (first_bound, first) = protected(&first_path, 4 * MIB)?;
    ensure!(
        first == *guard,
        "epoch 185 token first guard differs from the genuine original receipt"
    );
    let admission = read_json(&spec.admission, 4 * MIB)?;
    original_clocks(
        &token,
        ready,
        &admission,
        &first,
        number(envelope, "setup_deadline_seconds")?,
    )?;
    let rows = journal(&spec.actor_unit)?;
    let start = main_start(&rows, spec)?;
    let started = released_clock(&token, &seal, &first, &start, now)?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    ensure!(
        is_lower_hex(&boot, 32) && start["_BOOT_ID"] == boot,
        "epoch 185 release event belongs to a different native boot"
    );
    for key in [
        "task_acknowledgment",
        "status_readback",
        "fleet_enrollment",
        "current_reader_native_acceptance",
    ] {
        let b = binding(&token[key])?;
        let accepted = read_json(&b, 4 * MIB)?;
        accepted_bridge(&accepted, key, spec, ready, started)?;
    }
    Ok(
        json!({"token":token_bound,"token_value":token,"seal":seal_bound,"seal_value":seal,
        "first_guard":first_bound,"first_guard_value":first,"released_at":started,
        "actor_invocation_id":spec.expected_actor_invocation_id,"original_start_event":start}),
    )
}
pub(super) fn history(
    spec: &Spec,
    envelope: &Value,
    ready: &Value,
    mapped: &Value,
    native_guard: &Value,
    native_timer: &Value,
    now: u64,
) -> Result<Value> {
    let guard_id = text(native_guard, "InvocationID")?;
    ensure!(
        is_lower_hex(guard_id, 32),
        "epoch 185 current completed guard has no actual invocation"
    );
    let (bound, value) = protected(
        &Path::new(GUARD_ROOT).join(format!("guard-{guard_id}.json")),
        4 * MIB,
    )?;
    guard_receipt(&value, spec, envelope)?;
    let at = number(&value, "sampled_at")?;
    ensure!(
        at <= now
            && now - at <= 90
            && value["actor_pid"] == mapped["pid"]
            && value["actor_start_ticks"] == mapped["start_ticks"]
            && value["actor_pid"] != ready["pid"],
        "epoch 185 current guard is stale or still describes the pre-start ControlPID"
    );
    ensure!(
        value["guard_invocation_id"] == native_guard["InvocationID"]
            && text(native_timer, "LastTriggerUSecMonotonic")?.parse::<u64>()?
                == number(&value, "timer_last_trigger_monotonic_micros")?
            && text(native_guard, "ExecMainStartTimestampMonotonic")?.parse::<u64>()?
                == number(&value, "guard_start_monotonic_micros")?,
        "epoch 185 current successful guard receipt differs from actual native timer fire"
    );
    Ok(
        json!({"guard_unit":envelope["guard_unit"],"timer_unit":envelope["timer_unit"],"captured_at":now,
        "receipt":bound,"receipt_value":value,"native_guard":native_guard,"native_timer":native_timer}),
    )
}
fn terminal_native_shape(
    spec: &Spec,
    envelope: &Value,
    native_actor: &Value,
    native_guard: &Value,
    native_timer: &Value,
) -> Result<()> {
    ensure!(
        stage(native_actor, &spec.expected_actor_invocation_id)?.0 == "terminal",
        "epoch 185 terminal closure has no actual original terminal invocation"
    );
    ensure!(
        native_actor["MainPID"] == "0"
            && native_actor["ControlPID"] == "0"
            && text(native_actor, "Job")?.is_empty()
            && native_actor["NRestarts"] == "0",
        "epoch 185 terminal actor has a live, queued or restarted owner"
    );
    let guard = text(envelope, "guard_unit")?;
    let timer = text(envelope, "timer_unit")?;
    ensure!(
        native_guard["Id"] == guard
            && native_timer["Id"] == timer
            && native_guard["MainPID"] == "0"
            && native_guard["ControlPID"] == "0"
            && text(native_guard, "Job")?.is_empty()
            && text(native_timer, "Job")?.is_empty()
            && ["inactive", "failed"].contains(&text(native_guard, "ActiveState")?)
            && native_timer["ActiveState"] == "inactive"
            && native_timer["SubState"] == "dead",
        "epoch 185 terminal protective guard or timer is live or queued"
    );
    Ok(())
}
pub(super) fn terminal_context(
    spec: &Spec,
    envelope: &Value,
    ready: &Value,
    release: &Value,
    native: &BTreeMap<String, Value>,
    now: u64,
) -> Result<Value> {
    let native_actor = native
        .get(&spec.actor_unit)
        .context("epoch 185 terminal actor missing")?;
    let native_guard = native
        .get(text(envelope, "guard_unit")?)
        .context("epoch 185 terminal guard missing")?;
    let native_timer = native
        .get(text(envelope, "timer_unit")?)
        .context("epoch 185 terminal timer missing")?;
    terminal_native_shape(spec, envelope, native_actor, native_guard, native_timer)?;
    let guard = text(envelope, "guard_unit")?;
    let timer = text(envelope, "timer_unit")?;
    terminal_drained(&spec.actor_unit)?;
    terminal_drained(guard)?;
    terminal_drained(timer)?;
    let rows = journal(&spec.actor_unit)?;
    let start = main_start(&rows, spec)?;
    ensure!(
        start == release["original_start_event"],
        "epoch 185 terminal owner lost its exact original release"
    );
    let exits = rows
        .iter()
        .filter(|r| {
            r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["UNIT"] == spec.actor_unit
                && r["INVOCATION_ID"] == spec.expected_actor_invocation_id
                && ((r["COMMAND"] == "ExecStart"
                    && ["exited", "killed", "dumped"]
                        .contains(&r["EXIT_CODE"].as_str().unwrap_or("")))
                    || [
                        "9d1aaa27d60140bd96365438aad20286",
                        "d34d037fff1847e6ae669a370e694725",
                        "d9b373ed55a64feb8242e02dbe79a49c",
                    ]
                    .contains(&r["MESSAGE_ID"].as_str().unwrap_or("")))
        })
        .map(|r| Ok((row_micros(r)?, r)))
        .collect::<Result<Vec<_>>>()?;
    let (ended, event) = exits
        .iter()
        .max_by_key(|r| r.0)
        .context("epoch 185 original terminal manager event absent")?;
    ensure!(
        *ended >= row_micros(&start)? && *ended / 1_000_000 <= now,
        "epoch 185 terminal event predates release or is future"
    );
    Ok(
        json!({"schema":"horizon-epoch185-genuine-drained-terminal-context-v2","actor_unit":spec.actor_unit,
        "actor_invocation_id":spec.expected_actor_invocation_id,"original_start_event":start,
        "original_terminal_event":event,"terminal_at":ended / 1_000_000,"original_ready":spec.ready,
        "admission":spec.admission,"envelope":spec.envelope,"actor_source":spec.actor_source,
        "ready_value":ready,"release_token":release["token"],"release_seal":release["seal"],
        "guard_unit":guard,"timer_unit":timer,
        "terminal_actor_result":native_actor["Result"],"terminal_actor_exit_status":native_actor["ExecMainStatus"],
        "terminal_guard_result":native_guard["Result"],"terminal_guard_exit_status":native_guard["ExecMainStatus"],
        "actor_cgroup_drained":true,"guard_cgroup_drained":true,"timer_cgroup_drained":true,
        "timer_inactive":true,"cgroup_empty":true,"cgroup_populated":false,
        "memory_and_DATA_promises_retained":true,"resource_credit_bytes":0,"publication_authorized":false}),
    )
}
fn monotonic_micros() -> Result<u64> {
    let mut t: libc::timespec = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) } == 0 && t.tv_sec >= 0,
        "epoch 185 native guard monotonic clock unavailable"
    );
    (t.tv_sec as u64)
        .checked_mul(1_000_000)
        .and_then(|v| v.checked_add(t.tv_nsec as u64 / 1000))
        .context("epoch 185 monotonic clock overflow")
}
fn mapped_guard(spec: &Spec, envelope: &Value, native: &Value) -> Result<Value> {
    let main = text(native, "MainPID")?.parse::<u64>()?;
    let control = text(native, "ControlPID")?.parse::<u64>()?;
    let pid = match (main, control) {
        (p, 0) | (0, p) if p > 1 => p,
        _ => anyhow::bail!("epoch 185 in-flight guard has ambiguous process identity"),
    };
    ensure!(
        ["activating", "active"].contains(&text(native, "ActiveState")?)
            && ["start", "running"].contains(&text(native, "SubState")?),
        "epoch 185 guard is not genuinely in flight"
    );
    let image = BoundFile {
        path: PathBuf::from(DRIVER),
        sha256: DRIVER_SHA.into(),
    };
    read_immutable(&image, 8 << 20)?;
    let original = fs::metadata(DRIVER)?;
    let actual = fs::File::open(format!("/proc/{pid}/exe"))?.metadata()?;
    ensure!(
        (original.dev(), original.ino()) == (actual.dev(), actual.ino()),
        "epoch 185 in-flight guard mapped image changed"
    );
    let raw = fs::read(format!("/proc/{pid}/cmdline"))?;
    ensure!(
        !raw.is_empty() && raw.len() <= MIB as usize && raw.last() == Some(&0),
        "epoch 185 guard argv framing"
    );
    let argv = raw[..raw.len() - 1]
        .split(|c| *c == 0)
        .map(|s| Ok(std::str::from_utf8(s)?.to_owned()))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        argv == args(spec, true, false),
        "epoch 185 in-flight guard command changed"
    );
    let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    ensure!(
        cgroup.trim() == format!("0::/system.slice/{}", text(envelope, "guard_unit")?),
        "epoch 185 in-flight guard cgroup changed"
    );
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let uid = status
        .lines()
        .find_map(|s| s.strip_prefix("Uid:"))
        .context("epoch 185 guard UID absent")?;
    ensure!(
        uid.split_whitespace().collect::<Vec<_>>() == ["0", "0", "0", "0"],
        "epoch 185 in-flight guard is not Root"
    );
    for field in ["CapPrm:", "CapEff:", "CapBnd:"] {
        let caps = status
            .lines()
            .find_map(|s| s.strip_prefix(field))
            .context("epoch 185 guard process capability field absent")?;
        ensure!(
            u64::from_str_radix(caps.trim(), 16)? == 0x80002,
            "epoch 185 guard effective capability changed"
        );
    }
    ensure!(
        status.lines().any(|s| s
            .strip_prefix("NoNewPrivs:")
            .is_some_and(|v| v.trim() == "1")),
        "epoch 185 in-flight guard process privileges changed"
    );
    Ok(
        json!({"pid":pid,"start_ticks":ticks(pid)?,"path":DRIVER,"sha256":DRIVER_SHA,
        "mapped_device":actual.dev(),"mapped_inode":actual.ino(),"argv":argv,"cgroup":cgroup.trim()}),
    )
}
fn equal_present(actual: &Value, genuine: &Value) -> Result<()> {
    for (key, value) in actual
        .as_object()
        .context("epoch 185 discovered guard native properties")?
    {
        let expected = genuine
            .get(key)
            .with_context(|| format!("epoch 185 fresh guard omits discovered property {key}"))?;
        let same = if key == "ExecStart" {
            crate::pipeline_status::same_exec_start(
                value.as_str().context("epoch 185 discovered command")?,
                expected.as_str().context("epoch 185 fresh command")?,
            )
        } else {
            value == expected
        };
        ensure!(
            same,
            "epoch 185 discovered guard differs from actual native property {key}"
        );
    }
    Ok(())
}
pub(super) fn discover(
    aggregate: &Value,
    name: &str,
    actual: &Value,
    now: u64,
) -> Result<Option<Value>> {
    let event = &aggregate["registration_value"];
    if event["guard_unit"] != name {
        return Ok(None);
    }
    let task_binding = binding(&event["task"])?;
    let original = read_json(&task_binding, 4 * MIB)?;
    original_task(&original)?;
    let declared: Value = read_json(&binding(&original["spec"])?, 4 * MIB)?;
    ensure!(
        declared["native_spec"] == original["native_spec"] && aggregate["task"] == event["task"],
        "epoch 185 in-flight guard crossed original task source"
    );
    let spec: Spec = serde_json::from_value(declared["native_spec"].clone())?;
    let envelope = read_json(&spec.envelope, 4 * MIB)?;
    ensure!(
        envelope["guard_unit"] == name
            && event["actor_unit"] == spec.actor_unit
            && event["actor_invocation_id"] == spec.expected_actor_invocation_id
            && event["admission_sha256"] == spec.admission.sha256,
        "epoch 185 discovered guard is not the exact registered actor family"
    );
    let owner = unit(&spec.actor_unit)?;
    let (owner_stage, pid) = actor_policy(&spec, &envelope, &owner)?;
    ensure!(
        owner_stage == "running",
        "epoch 185 in-flight protective guard has no exact running owner"
    );
    ensure!(
        aggregate["stage"] == "running"
            && aggregate["guard_pending"] == false
            && aggregate["native"][&spec.actor_unit] == owner,
        "epoch 185 discovered guard crossed the retained actual running actor"
    );
    let mapped_actor = mapped(&spec, pid, false)?;
    let ready = ready(&spec, &envelope)?;
    let release = release(&spec, &envelope, &ready, now)?;
    let current = unit(name)?;
    equal_present(actual, &current)?;
    guard_policy(&spec, &envelope, &current, true, false)?;
    ensure!(
        current["Result"] == "success"
            && current["ExecMainStatus"] == "0"
            && text(&current, "TriggeredBy")?
                .split_whitespace()
                .any(|u| envelope["timer_unit"] == u),
        "epoch 185 in-flight guard has a reported failure or foreign trigger"
    );
    let timer = unit(text(&envelope, "timer_unit")?)?;
    timer_policy(&spec, &envelope, &timer, false, false)?;
    let mapped = mapped_guard(&spec, &envelope, &current)?;
    let iid = text(&current, "InvocationID")?;
    ensure!(
        is_lower_hex(iid, 32),
        "epoch 185 in-flight guard IID missing"
    );
    let trigger = text(&timer, "LastTriggerUSecMonotonic")?.parse::<u64>()?;
    let began = text(&current, "ExecMainStartTimestampMonotonic")?.parse::<u64>()?;
    ensure!(
        trigger > 0
            && trigger <= began
            && began - trigger <= 5_000_000
            && monotonic_micros()?
                .checked_sub(began)
                .is_some_and(|v| v <= 90_000_000),
        "epoch 185 in-flight guard lacks genuine fresh timer trigger"
    );
    // The previous successful history is re-read and compared; an in-flight
    // scope is authenticated ownership, never a claim that the new guard passed.
    let history = &aggregate["guard_history"];
    let previous_bound = binding(&history["receipt"])?;
    let previous_iid = text(&history["receipt_value"], "guard_invocation_id")?;
    ensure!(
        is_lower_hex(previous_iid, 32)
            && previous_iid != iid
            && previous_bound.path
                == Path::new(GUARD_ROOT).join(format!("guard-{previous_iid}.json"))
            && history["guard_unit"] == name
            && history["timer_unit"] == envelope["timer_unit"],
        "epoch 185 in-flight guard has no exact previous completed history namespace"
    );
    guard_policy(&spec, &envelope, &history["native_guard"], false, false)?;
    timer_policy(&spec, &envelope, &history["native_timer"], false, false)?;
    let (expected_bound, previous) = protected(&previous_bound.path, 4 * MIB)?;
    ensure!(
        expected_bound.path == previous_bound.path
            && expected_bound.sha256 == previous_bound.sha256
            && previous == history["receipt_value"],
        "epoch 185 prior successful guard history changed"
    );
    guard_receipt(&previous, &spec, &envelope)?;
    ensure!(
        history["native_guard"]["InvocationID"] == previous["guard_invocation_id"]
            && number(&previous, "sampled_at")? <= number(history, "captured_at")?
            && number(history, "captured_at")? <= now
            && text(&history["native_timer"], "LastTriggerUSecMonotonic")?.parse::<u64>()?
                == number(&previous, "timer_last_trigger_monotonic_micros")?
            && text(&history["native_guard"], "ExecMainStartTimestampMonotonic")?.parse::<u64>()?
                == number(&previous, "guard_start_monotonic_micros")?
            && number(&previous, "timer_last_trigger_monotonic_micros")? < trigger
            && number(&previous, "guard_start_monotonic_micros")? < began,
        "epoch 185 in-flight guard history is not a prior genuine successful fire"
    );
    ensure!(
        previous["actor_pid"] == mapped_actor["pid"]
            && previous["actor_start_ticks"] == mapped_actor["start_ticks"]
            && number(&previous, "sampled_at")? <= now
            && now - number(&previous, "sampled_at")? <= 90,
        "epoch 185 in-flight guard lost its actual runtime owner's recent successful protection"
    );
    let again = unit(name)?;
    let actor_after = unit(&spec.actor_unit)?;
    ensure!(
        again == current
            && actor_after == owner
            && unit(text(&envelope, "timer_unit")?)? == timer
            && ticks(number(&mapped_actor, "pid")?)? == number(&mapped_actor, "start_ticks")?
            && ticks(number(&mapped, "pid")?)? == number(&mapped, "start_ticks")?,
        "epoch 185 in-flight guard or actor changed during discovery authentication"
    );
    Ok(Some(
        json!({"schema":"horizon-epoch185-exact-inflight-guard-discovery-v2","unit":name,"invocation_id":iid,
        "actor_unit":spec.actor_unit,"actor_invocation_id":spec.expected_actor_invocation_id,
        "actor_pid":mapped_actor["pid"],"actor_start_ticks":mapped_actor["start_ticks"],
        "mapped_guard":mapped,"actual_native":current,"native_timer":timer,"last_successful_guard":history,
        "release_token":release["token"],"captured_at":now,"guard_success_not_claimed":true,
        "existing_guard_memory_already_charged_bytes":GUARD_MEMORY,"new_allocation_bytes":0,"resource_credit_bytes":0}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn clock_fixture() -> (Value, Value, Value, Value) {
        (
            json!({"issued_at":1010,"expires_at":1020}),
            json!({"started_at":1000}),
            json!({"issued_at":900,"expires_at":1600}),
            json!({"sampled_at":1009}),
        )
    }
    #[test]
    fn original_release_clocks_are_checked_at_release_not_refreshed_now() {
        let (t, r, a, g) = clock_fixture();
        original_clocks(&t, &r, &a, &g, 600).unwrap();
    }
    #[test]
    fn expired_or_late_token_never_becomes_a_fresh_release() {
        let (t, r, a, g) = clock_fixture();
        for (key, value) in [("issued_at", json!(1039)), ("expires_at", json!(1601))] {
            let mut bad = t.clone();
            bad[key] = value;
            assert!(original_clocks(&bad, &r, &a, &g, 600).is_err());
        }
        let mut bad = a;
        bad["expires_at"] = json!(1019);
        assert!(original_clocks(&t, &r, &bad, &g, 600).is_err());
    }
    #[test]
    fn release_after_original_setup_limit_is_rejected() {
        let (t, r, a, g) = clock_fixture();
        assert!(original_clocks(&t, &r, &a, &g, 10).is_err());
        let mut bad = t;
        bad["expires_at"] = json!(1031);
        assert!(original_clocks(&bad, &r, &a, &g, 30).is_err());
    }
    #[test]
    fn actual_present_fields_cannot_be_dropped_or_normalized_arbitrarily() {
        let v = json!({"Id":"guard.service","MainPID":"123"});
        equal_present(&v, &v).unwrap();
        assert!(equal_present(&v, &json!({"Id":"guard.service"})).is_err());
        let mut wrong = v.clone();
        wrong["MainPID"] = json!("124");
        assert!(equal_present(&v, &wrong).is_err());
    }
}

#[cfg(test)]
mod retained_provenance_tests {
    use super::*;
    fn spec() -> Spec {
        let b = || BoundFile {
            path: PathBuf::from("/test-only/source.json"),
            sha256: "a".repeat(64),
        };
        Spec {
            schema: "horizon-epoch185-native-startpre-spec-v1".into(),
            actor_unit: "horizon-qualify-185-capped-cold-test.service".into(),
            expected_actor_invocation_id: "b".repeat(32),
            envelope: b(),
            admission: b(),
            actor_source: b(),
            guard_source: b(),
            timer_source: b(),
            ready: b(),
            current_task_status: b(),
            mode: "current-owner".into(),
        }
    }
    fn started(s: &Spec, micros: u64) -> Value {
        json!({"_PID":"1","_UID":"0","UNIT":s.actor_unit,"INVOCATION_ID":s.expected_actor_invocation_id,
            "MESSAGE_ID":"39f53479d3a045ac8e11786248231fbf","JOB_TYPE":"start","JOB_RESULT":"done",
            "__REALTIME_TIMESTAMP":micros.to_string()})
    }
    #[test]
    fn original_started_event_requires_genuine_root_manager_and_completed_start_job() {
        let s = spec();
        let event = started(&s, 1_012_000_001);
        assert_eq!(main_start(std::slice::from_ref(&event), &s).unwrap(), event);
        for (key, bad) in [
            ("_UID", "1001"),
            ("_PID", "42"),
            ("JOB_TYPE", "stop"),
            ("JOB_RESULT", "failed"),
            ("INVOCATION_ID", "foreign"),
            ("UNIT", "foreign.service"),
        ] {
            let mut row = event.clone();
            row[key] = json!(bad);
            assert!(main_start(&[row], &s).is_err(), "{key}");
        }
    }
    #[test]
    fn replacement_start_even_in_the_same_second_cannot_hide_behind_old_started_event() {
        let s = spec();
        let original = started(&s, 1_012_000_001);
        let mut replacement = original.clone();
        replacement["__REALTIME_TIMESTAMP"] = json!("1012000002");
        replacement["INVOCATION_ID"] = json!("c".repeat(32));
        replacement["MESSAGE_ID"] = json!("7d4958e842da4a758f6c1cdc7b36dcc5");
        assert!(main_start(&[original, replacement], &s).is_err());
    }
    #[test]
    fn duplicate_completed_start_and_later_same_iid_restart_are_rejected() {
        let s = spec();
        let original = started(&s, 1_012_000_001);
        assert!(main_start(&[original.clone(), original.clone()], &s).is_err());
        let mut restart = original.clone();
        restart["__REALTIME_TIMESTAMP"] = json!("1012000002");
        restart["MESSAGE_ID"] = json!("7d4958e842da4a758f6c1cdc7b36dcc5");
        assert!(main_start(&[original, restart], &s).is_err());
    }
    #[test]
    fn actual_release_must_follow_normal_seal_and_precede_original_expiry() {
        let s = spec();
        let start = started(&s, 1_012_000_001);
        let token = json!({"issued_at":1010,"expires_at":1020});
        let seal = json!({"created_unix_seconds":1011});
        let first = json!({"sampled_at":1009});
        assert_eq!(
            released_clock(&token, &seal, &first, &start, 9999).unwrap(),
            1012
        );
        let mut expired = token.clone();
        expired["expires_at"] = json!(1012);
        assert!(released_clock(&expired, &seal, &first, &start, 9999).is_err());
        for sealed in [1009, 1013] {
            assert!(
                released_clock(
                    &token,
                    &json!({"created_unix_seconds":sealed}),
                    &first,
                    &start,
                    9999
                )
                .is_err()
            );
        }
        assert!(released_clock(&token, &seal, &first, &start, 1011).is_err());
    }
    #[test]
    fn first_guard_fresh_at_issue_cannot_expire_before_actual_release() {
        let s = spec();
        let start = started(&s, 1_040_000_001);
        let token = json!({"issued_at":1010,"expires_at":1050});
        let seal = json!({"created_unix_seconds":1011});
        let first = json!({"sampled_at":1009});
        assert!(released_clock(&token, &seal, &first, &start, 9999).is_err());
    }
    fn receipt(s: &Spec) -> Value {
        json!({"schema":"horizon-epoch185-native-guard-result-v4","epoch":185,"actor_unit":s.actor_unit,
            "actor_invocation_id":s.expected_actor_invocation_id,"admission_sha256":s.admission.sha256,
            "timer_unit":"horizon-guard-185-capped-cold-test.timer","timer_driven":true,"success":true,
            "failure":null,"capacity_credit_bytes":0,"guard_invocation_id":"c".repeat(32),
            "timer_last_trigger_monotonic_micros":1000000,"guard_start_monotonic_micros":1000001})
    }
    #[test]
    fn guard_trip_wrong_owner_admission_timer_or_credit_never_authenticates() {
        let s = spec();
        let e = json!({"timer_unit":"horizon-guard-185-capped-cold-test.timer"});
        let valid = receipt(&s);
        guard_receipt(&valid, &s, &e).unwrap();
        for (key, bad) in [
            ("success", json!(false)),
            ("failure", json!("trip")),
            ("actor_invocation_id", json!("d".repeat(32))),
            ("admission_sha256", json!("d".repeat(64))),
            ("timer_unit", json!("foreign.timer")),
            ("capacity_credit_bytes", json!(1)),
            ("guard_invocation_id", json!("")),
            ("timer_driven", json!(false)),
        ] {
            let mut row = valid.clone();
            row[key] = bad;
            assert!(guard_receipt(&row, &s, &e).is_err(), "{key}");
        }
        let mut missing = valid;
        missing.as_object_mut().unwrap().remove("failure");
        assert!(guard_receipt(&missing, &s, &e).is_err());
    }
    #[test]
    fn timer_fire_chronology_and_maximum_trigger_lag_remain_independent() {
        let s = spec();
        let e = json!({"timer_unit":"horizon-guard-185-capped-cold-test.timer"});
        for (trigger, start) in [(0, 1), (2, 1), (1, 5_000_002)] {
            let mut row = receipt(&s);
            row["timer_last_trigger_monotonic_micros"] = json!(trigger);
            row["guard_start_monotonic_micros"] = json!(start);
            assert!(guard_receipt(&row, &s, &e).is_err());
        }
    }
    #[test]
    fn unregistered_guard_discovery_returns_none_without_touching_native_state() {
        assert!(
            discover(
                &json!({"registration_value":{"guard_unit":"exact.service"}}),
                "foreign.service",
                &json!({}),
                1000
            )
            .unwrap()
            .is_none()
        );
        assert!(
            discover(
                &Value::Null,
                "horizon-guard-185-capped-cold-any.service",
                &json!({}),
                1000
            )
            .unwrap()
            .is_none()
        );
    }
    #[test]
    fn terminal_requires_drained_manager_shape_for_all_three_roles_without_inventing_timer_pids() {
        let s = spec();
        let e = json!({"guard_unit":"guard.service","timer_unit":"guard.timer"});
        let actor = json!({"InvocationID":s.expected_actor_invocation_id,"LoadState":"loaded","NRestarts":"0",
            "Restart":"no","ActiveState":"failed","SubState":"failed","MainPID":"0","ControlPID":"0","Job":""});
        let guard = json!({"Id":"guard.service","MainPID":"0","ControlPID":"0","Job":"","ActiveState":"failed","Result":"exit-code"});
        let timer = json!({"Id":"guard.timer","Job":"","ActiveState":"inactive","SubState":"dead"});
        terminal_native_shape(&s, &e, &actor, &guard, &timer).unwrap();
        assert!(timer.get("MainPID").is_none());
        for (key, value) in [
            ("MainPID", json!("44")),
            ("ControlPID", json!("44")),
            ("Job", json!("1")),
            ("InvocationID", json!("c".repeat(32))),
            ("NRestarts", json!("1")),
        ] {
            let mut bad = actor.clone();
            bad[key] = value;
            assert!(terminal_native_shape(&s, &e, &bad, &guard, &timer).is_err());
        }
        for (key, value) in [
            ("ActiveState", "active"),
            ("Job", "42"),
            ("Id", "foreign.timer"),
        ] {
            let mut bad = timer.clone();
            bad[key] = json!(value);
            assert!(terminal_native_shape(&s, &e, &actor, &guard, &bad).is_err());
        }
        let mut live = guard;
        live["MainPID"] = json!("44");
        assert!(terminal_native_shape(&s, &e, &actor, &live, &timer).is_err());
    }
}
