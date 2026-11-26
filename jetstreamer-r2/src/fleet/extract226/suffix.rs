//! Bind the closed 226 prefix, hold the next invocation in start-pre, and release it under its own guard.
use super::{drain, *};
use std::{
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    },
    thread,
    time::Instant,
};

const BASE: &str = "/var/lib/jetstreamer/horizon226-suffix-v1";
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-226-suffix-v1";
const UNIT: &str = "horizon-qualify-226-checkpoint-continuation-suffix-v1.service";
const GUARD: &str = "horizon-guard-226-checkpoint-continuation-suffix-v1.service";
const TIMER: &str = "horizon-guard-226-checkpoint-continuation-suffix-v1.timer";
const CADENCE: &str = "foundation-publication-cadence-v222.service";
const CADENCE_TIMER: &str = "foundation-publication-cadence-v222.timer";
const STATIC_SHA: &str = "ccaf287e2b82530f10d150c718b3a809171dbdcb2d09a58f8e60dd66d42145a6";
const CADENCE_SHA: &str = "a2c236119326ba07abb8ec3d00dff5a6f9389c586f82374224b92eb72f8c36d2";
const NODE: &str = "/run/foundation-epoch226-release.y35rokj7/jetstreamer-node";
const NODE_SHA: &str = "7e17105ad9429fccbeb53dcd38650adb3f469bc1d3fe797360afff2cc7379ded";
const WORKER_SHA: &str = "7a831420bb1498ddb0268309ce69f615c7f0c6d90cfab940896a03dc38b5336a";
const QUOTE: &str = "/var/lib/jetstreamer/horizon226-suffix-v1/capacity-epoch229-demotion-v2.py";
const QUOTE_SHA: &str = "660da318035766590447436f12e8088efcc9c13044082218f79177df05763333";
const LAYERED_QUOTE: &str = "/var/lib/jetstreamer/horizon226-suffix-v1/capacity-layered-v3.py";
const LAYERED_QUOTE_SHA: &str = "296edbce4b4ff305d59e33422d0716d8d8d107dec715ce671f3b1131c67f5049";
const THREAD: &str = "01a1f8f4-293b-7a91-a36e-2e7658bba721";

fn path(name: &str) -> PathBuf {
    Path::new(BASE).join(name)
}

fn document(p: &Path) -> Result<Value> {
    sealed_json(&private157::file_binding(p)?, p)
}

fn bytes(reference: &Value, expected: &Path, limit: u64) -> Result<Vec<u8>> {
    ensure!(
        reference["path"].as_str() == expected.to_str() && expected.canonicalize()? == expected,
        "epoch 226 sealed input path changed"
    );
    let info = expected.symlink_metadata()?;
    ensure!(
        info.is_file() && info.uid() == 0 && info.nlink() == 1 && info.mode() & 0o222 == 0,
        "epoch 226 input is not root sealed at {}",
        expected.display()
    );
    let raw = read_stable_bounded(expected, limit, "epoch 226 sealed suffix input")?;
    ensure!(
        reference["sha256"] == hex_lower(&Sha256::digest(&raw)),
        "epoch 226 input digest changed"
    );
    Ok(raw)
}

fn reference(p: &Path, raw: &[u8]) -> Value {
    json!({"path":p,"sha256":hex_lower(&Sha256::digest(raw))})
}

fn encode(value: &Value) -> Result<Vec<u8>> {
    let mut raw = serde_json::to_vec_pretty(value)?;
    raw.push(b'\n');
    Ok(raw)
}

fn write(p: &Path, raw: &[u8], mode: u32) -> Result<Value> {
    let parent = p.parent().context("suffix receipt parent")?;
    ensure!(
        parent.canonicalize()? == parent
            && parent.metadata()?.uid() == 0
            && parent.metadata()?.mode() & 0o022 == 0,
        "unsafe epoch 226 receipt parent"
    );
    let mut t = tempfile::NamedTempFile::new_in(parent)?;
    t.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    t.write_all(raw)?;
    t.as_file().sync_all()?;
    t.persist_noclobber(p)
        .map_err(|e| anyhow!("epoch 226 receipt already present: {e}"))?;
    File::open(parent)?.sync_all()?;
    Ok(reference(p, raw))
}

fn record(p: &Path, value: &Value) -> Result<Value> {
    write(p, &encode(value)?, 0o400)
}

fn registered_suffix_handler(source: &str) -> bool {
    let mut assignments = source
        .lines()
        .filter_map(|line| line.strip_prefix("diagnostic_handlers = "));
    let Some(handlers) = assignments.next() else {
        return false;
    };
    assignments.next().is_none()
        && handlers
            .strip_prefix('(')
            .and_then(|handlers| handlers.strip_suffix(')'))
            .is_some_and(|handlers| {
                handlers
                    .split(',')
                    .filter(|handler| handler.trim() == "diagnostic226_suffix")
                    .count()
                    == 1
            })
}

fn installed() -> Result<(Value, String)> {
    let static_path = path("static-prestart-qualification.json");
    let proof = sealed_json(
        &json!({"path":static_path,"sha256":STATIC_SHA}),
        &static_path,
    )?;
    let deployment_path = path("cadence-deployment.json");
    let deployment = sealed_json(
        &json!({"path":deployment_path,"sha256":CADENCE_SHA}),
        &deployment_path,
    )?;
    ensure!(
        proof["unit"] == UNIT
            && proof["guard_static_validation"]["validated"] == true
            && deployment["schema"] == "foundation-epoch226-suffix-cadence-deployment-v1",
        "epoch 226 deployment scope changed"
    );
    let controller = Path::new(drain::CYCLE_LOCK)
        .parent()
        .context("cadence directory")?;
    bytes(
        &deployment["installed"]["diagnostic226_suffix.py"],
        &controller.join("diagnostic226_suffix.py"),
        1 << 20,
    )?;
    for (name, hooks) in [
        (
            "cycle.py",
            &[
                "import diagnostic226_suffix",
                "diagnostic226_suffix.configuration()",
                "diagnostic226_suffix.register(plan)",
                "diagnostic226_suffix.owns(r)",
            ][..],
        ),
        (
            "native_binding_replays.py",
            &[
                "import diagnostic226_suffix",
                "any(handler.owns(r) for handler in diagnostic_handlers)",
            ][..],
        ),
    ] {
        let p = controller.join(name);
        let info = p.symlink_metadata()?;
        ensure!(
            p.canonicalize()? == p && info.is_file() && info.uid() == 0 && info.mode() & 0o222 == 0,
            "unsafe installed suffix cadence hook"
        );
        let text = fs::read_to_string(&p)?;
        ensure!(
            hooks.iter().all(|hook| text.matches(hook).count() == 1)
                && (name != "native_binding_replays.py" || registered_suffix_handler(&text)),
            "suffix cadence hook changed in {name}"
        );
    }
    bytes(&proof["prestart"], &path("pre-start.sh"), 4096)?;
    bytes(
        &json!({"path":drain::GUARD_IMAGE,"sha256":GUARD_SHA}),
        Path::new(drain::GUARD_IMAGE),
        4 << 20,
    )?;
    bytes(
        &json!({"path":NODE,"sha256":NODE_SHA}),
        Path::new(NODE),
        256 << 20,
    )?;
    let template = bytes(
        &proof["producer_template"],
        &path("producer.service.template"),
        1 << 16,
    )?;
    let guard_path = path("static-only/guard-plan.json");
    let guard = sealed_json(&proof["guard_plan_fixture"], &guard_path)?;
    ensure!(
        guard["unit"] == UNIT
            && guard["worker_root"] == ROOT
            && guard["minimum_free_bytes"] == SHARED_FLOOR
            && guard["maximum_root_physical_bytes"] == ROOT_CAP,
        "epoch 226 guard envelope changed"
    );
    Ok((guard, String::from_utf8(template)?))
}

fn service_args(template: &str, hash: &str) -> Result<Vec<String>> {
    ensure!(
        template.matches("__PLAN_SHA256__").count() == 1,
        "suffix plan hash placeholder changed"
    );
    let mut args = vec![
        format!("--unit={UNIT}"),
        "--slice=system.slice".into(),
        "--no-block".into(),
    ];
    let mut command = None;
    for line in template
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('['))
    {
        let (key, value) = line
            .split_once('=')
            .context("invalid sealed suffix service property")?;
        match key {
            "Description" => args.push(format!("--description={value}")),
            "Environment" => args.push(format!("--setenv={value}")),
            "ExecStart" => {
                ensure!(command.is_none(), "duplicate suffix executable");
                command = Some(value.replace("__PLAN_SHA256__", hash));
            }
            _ => args.push(format!("--property={line}")),
        }
    }
    args.push("--".into());
    args.extend(
        command
            .context("suffix executable missing")?
            .split_ascii_whitespace()
            .map(str::to_owned),
    );
    ensure!(
        args.windows(2).any(|p| p == ["--", NODE]),
        "epoch 226 suffix executable changed"
    );
    Ok(args)
}

fn source_template(template: &str, extraction: &drain::Source) -> Result<String> {
    let original = format!("{}/output", RETRY.root);
    ensure!(
        template
            .lines()
            .filter(|line| line.starts_with("ReadOnlyPaths="))
            .flat_map(|line| line
                .trim_start_matches("ReadOnlyPaths=")
                .split_ascii_whitespace())
            .filter(|path| *path == original.as_str())
            .count()
            == 1,
        "sealed epoch 226 prefix projection changed"
    );
    Ok(template.replace(&original, &format!("{}/output", extraction.profile.root)))
}

fn quote(extraction: &drain::Source) -> Result<&'static str> {
    let (path, sha) = if extraction.profile.unit == LAYERED_RETRY.unit {
        (LAYERED_QUOTE, LAYERED_QUOTE_SHA)
    } else {
        (QUOTE, QUOTE_SHA)
    };
    bytes(&json!({"path":path,"sha256":sha}), Path::new(path), 1 << 20)?;
    Ok(path)
}

fn start(args: &[String]) -> Result<()> {
    ensure!(
        ProcessCommand::new("/usr/bin/systemd-run")
            .arg("--quiet")
            .args(args)
            .status()?
            .success(),
        "systemd rejected the scoped epoch 226 unit"
    );
    Ok(())
}

fn make_root() -> Result<()> {
    let root = Path::new(ROOT);
    let parent = root.parent().context("suffix parent")?;
    ensure!(
        parent.canonicalize()? == parent
            && parent.metadata()?.uid() == 1000
            && parent.metadata()?.mode() & 0o022 == 0,
        "unsafe epoch 226 private parent"
    );
    fs::DirBuilder::new().mode(0o700).create(root)?;
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(root)?;
    let original = directory.metadata()?;
    ensure!(
        original.uid() == 0 && unsafe { libc::fchown(directory.as_raw_fd(), 1000, 1000) } == 0,
        "could not assign suffix root to uid 1000"
    );
    let current = root.symlink_metadata()?;
    ensure!(
        current.dev() == original.dev()
            && current.ino() == original.ino()
            && current.is_dir()
            && current.uid() == 1000
            && current.mode() & 0o777 == 0o700,
        "suffix root changed during assignment"
    );
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn monotonic_usec() -> Result<u64> {
    let mut time: libc::timespec = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } == 0,
        "monotonic clock unavailable"
    );
    Ok(u64::try_from(time.tv_sec)? * 1_000_000 + u64::try_from(time.tv_nsec)? / 1000)
}

fn next_timer(name: &str) -> Result<u64> {
    let object = format!(
        "/org/freedesktop/systemd1/unit/{}",
        name.replace('-', "_2d").replace('.', "_2e")
    );
    let result = ProcessCommand::new("/usr/bin/busctl")
        .args([
            "--system",
            "get-property",
            "org.freedesktop.systemd1",
            &object,
            "org.freedesktop.systemd1.Timer",
            "NextElapseUSecMonotonic",
        ])
        .output()?;
    ensure!(
        result.status.success(),
        "could not read next fire for {name}"
    );
    let raw = std::str::from_utf8(&result.stdout)?.trim();
    Ok(raw
        .strip_prefix("t ")
        .context("unexpected timer value")?
        .parse()?)
}

fn wait<T>(
    seconds: u64,
    description: &str,
    mut check: impl FnMut() -> Result<Option<T>>,
) -> Result<T> {
    let start = Instant::now();
    loop {
        if let Some(value) = check()? {
            return Ok(value);
        }
        ensure!(
            start.elapsed() < Duration::from_secs(seconds),
            "timed out waiting for {description}"
        );
        thread::sleep(Duration::from_millis(250));
    }
}

fn newest_sample(iid: &str, guard_plan: &Value, sub: &str, pid: u64) -> Result<Option<Value>> {
    let directory = path("guard-receipts");
    for file in fs::read_dir(&directory)? {
        let p = file?.path();
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let Some(guard_id) = name
            .strip_prefix("sample-")
            .and_then(|s| s.strip_suffix(".json"))
        else {
            continue;
        };
        let binding = private157::file_binding(&p)?;
        let sample = root_bound_json(&binding, &p, 0o022)?;
        if sample["producer_invocation_id"] != iid
            || sample["producer"]["sub"] != sub
            || sample["producer"]["pid"] != pid
        {
            continue;
        }
        ensure!(
            sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
                && sample["guard_invocation_id"] == guard_id
                && iid_is_valid(guard_id)
                && sample["guard_sha256"] == GUARD_SHA
                && sample["plan_sha256"] == guard_plan["sha256"]
                && sample["producer_stop_enabled"] == true
                && sample["trip_reason"].is_null()
                && sample["root_physical_observation_error"].is_null()
                && sample["worker_observation_error"].is_null()
                && sample["maximum_root_physical_bytes"] == ROOT_CAP,
            "epoch 226 live guard sample rejected"
        );
        return Ok(Some(binding));
    }
    Ok(None)
}

fn iid_is_valid(value: &str) -> bool {
    iid(&json!(value))
}

fn dormant() -> Result<Option<Value>> {
    let unit = drain::show(UNIT)?;
    if unit["ActiveState"] == "activating"
        && unit["SubState"] == "start-pre"
        && unit["MainPID"] == "0"
    {
        ensure!(
            iid(&unit["InvocationID"])
                && unit["ControlGroup"] == format!("/system.slice/{UNIT}")
                && unit["ControlPID"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .is_some_and(|p| p > 0),
            "epoch 226 dormant owner is invalid"
        );
        return Ok(Some(unit));
    }
    Ok(None)
}

fn check_cgroup(owner: &Value, memory_max: u64) -> Result<()> {
    let group = owner["ControlGroup"].as_str().context("suffix cgroup")?;
    let cg = Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/'));
    for (key, expect) in [
        ("memory.max", memory_max.to_string()),
        ("memory.high", (128u64 << 30).to_string()),
        ("memory.swap.max", "0".to_owned()),
        ("pids.max", "512".to_owned()),
        ("cpuset.cpus.effective", "16-23".to_owned()),
    ] {
        ensure!(
            fs::read_to_string(cg.join(key))?.trim() == expect,
            "epoch 226 cgroup {key} differs"
        );
    }
    let raw = fs::read_to_string(cg.join("cpu.max"))?;
    let limits = raw
        .split_ascii_whitespace()
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        limits.len() == 2 && limits[0] == 8 * limits[1],
        "epoch 226 CPU quota differs"
    );
    Ok(())
}

fn start_guard(guard_plan: &Value) -> Result<()> {
    let mut args = vec![
        format!("--unit={GUARD}"),
        "--on-active=1s".into(),
        "--on-unit-inactive=60s".into(),
        "--timer-property=AccuracySec=1s".into(),
        "--timer-property=RandomizedDelaySec=0".into(),
    ];
    for prop in [
        "Type=oneshot",
        "User=root",
        "UMask=0077",
        "Restart=no",
        "MemoryMax=1G",
        "MemorySwapMax=0",
        "CPUQuota=100%",
        "TasksMax=256",
        "TimeoutStartSec=90",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "PrivateNetwork=yes",
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE",
        "AmbientCapabilities=CAP_DAC_OVERRIDE CAP_SYS_PTRACE",
    ] {
        args.push(format!("--property={prop}"));
    }
    args.push(format!("--property=ReadWritePaths={BASE}/guard-receipts"));
    args.extend(
        [
            "--",
            drain::GUARD_IMAGE,
            &format!("{BASE}/guard-plan.json"),
            "--plan-sha256",
            guard_plan["sha256"]
                .as_str()
                .context("suffix guard digest")?,
            "--self-sha256",
            GUARD_SHA,
        ]
        .into_iter()
        .map(str::to_owned),
    );
    start(&args)
}

fn registration_receipt(id: &str, pid: u64, owner: &Value, token: &Value, sample: &Value) -> Value {
    json!({
        "schema": "jetstreamer-historical-performance-launch-receipt-v1",
        "kind": "epoch226-checkpoint-suffix",
        "epoch": 226,
        "unit": UNIT,
        "invocation_id": id,
        "main_pid": pid,
        "node_path": NODE,
        "run_root": ROOT,
        "bootstrap_slot": 98063464,
        "first_slot": 98063465,
        "last_slot": 98063999,
        "worker_sha256": WORKER_SHA,
        "launched": true,
        "entry_replay_requested": true,
        "source_prefix_retained": true,
        "canonical_epoch_publication_authorized": false,
        "remote_mutations": false,
        "r2_mutations": false,
        "admission": token["admission"],
        "plan": token["plan"],
        "guard_plan": token["guard_plan"],
        "launch_token": token,
        "active_guard": sample,
        "evidence": {"units": [{
            "unit": UNIT,
            "invocation_id": id,
            "main_pid": pid,
            "active_state": owner["ActiveState"],
            "sub_state": owner["SubState"],
            "load_state": owner["LoadState"],
            "result": owner["Result"],
            "restarts": 0,
        }]},
    })
}

fn registration(prestart: &Value, token: &Value) -> Result<Value> {
    let id = prestart["InvocationID"]
        .as_str()
        .context("suffix invocation id")?;
    let launch_token = sealed_json(token, &path(&format!("tokens/{id}/guard-admission.json")))?;
    let guard = &launch_token["guard_plan"];
    ensure!(
        launch_token["invocation_id"] == id && launch_token["unit"] == UNIT,
        "suffix token owner changed"
    );
    let (owner, sample) = wait(105, "active suffix owner and matching guard", || {
        let owner = drain::show(UNIT)?;
        if owner["ActiveState"] != "active" || owner["SubState"] != "running" {
            return Ok(None);
        }
        ensure!(
            owner["InvocationID"] == id
                && owner["NRestarts"] == "0"
                && owner["ControlGroup"] == format!("/system.slice/{UNIT}"),
            "suffix live owner changed"
        );
        let pid: u64 = owner["MainPID"]
            .as_str()
            .context("missing suffix pid")?
            .parse()?;
        if pid <= 1 || fs::read_link(format!("/proc/{pid}/exe"))? != Path::new(NODE) {
            return Ok(None);
        }
        Ok(newest_sample(id, guard, "running", pid)?.map(|sample| (owner, sample)))
    })?;
    let timer = drain::show(TIMER)?;
    ensure!(
        timer["ActiveState"] == "active"
            && timer["Unit"] == GUARD
            && timer["InvocationID"] == launch_token["guard_timer_invocation"]
            && next_timer(TIMER)? > monotonic_usec()?,
        "suffix lost its invocation's guard timer"
    );
    let pid: u64 = owner["MainPID"]
        .as_str()
        .context("missing suffix pid")?
        .parse()?;
    record(
        &path("cadence-registration.json"),
        &registration_receipt(id, pid, &owner, &launch_token, &sample),
    )
}

pub(crate) fn run() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    ensure!(
        unsafe { libc::geteuid() } == 0
            && args.len() == 3
            && matches!(args[2].as_str(), "--check" | "--apply"),
        "usage: jetstreamer-r2 launch-epoch226-suffix --check|--apply"
    );
    let (mut guard, template) = installed()?;
    let handoff_path = Path::new(drain::HANDOFF);
    if args[2] == "--check" {
        let handoff_present = handoff_path.try_exists()?;
        let extraction = if handoff_present {
            drain::source(&document(handoff_path)?)?
        } else {
            drain::latest()?
        };
        quote(extraction)?;
        service_args(&source_template(&template, extraction)?, &"a".repeat(64))?;
        println!(
            "{}",
            json!({"epoch":226,"static_launch_inputs_verified":true,"handoff_present":handoff_present,
            "extraction_unit":extraction.profile.unit,"extraction_drain_present":extraction.completion().is_file(),"launched":false})
        );
        return Ok(());
    }
    ensure!(
        env::var("CODEX_THREAD_ID").as_deref() == Ok(THREAD),
        "epoch 226 campaign controller changed"
    );
    let lock = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(drain::CYCLE_LOCK)?;
    let stat = lock.metadata()?;
    ensure!(
        stat.uid() == 0
            && stat.nlink() == 1
            && stat.mode() & 0o077 == 0
            && unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "fleet cadence is busy"
    );
    if path("cadence-registration.json").exists() {
        let registration = document(&path("cadence-registration.json"))?;
        ensure!(
            registration["unit"] == UNIT && registration["epoch"] == 226,
            "foreign suffix registration"
        );
        println!(
            "{}",
            private157::file_binding(&path("cadence-registration.json"))?
        );
        return Ok(());
    }
    let handoff = document(handoff_path)?;
    let source = private157::file_binding(handoff_path)?;
    let extraction = drain::source(&handoff)?;
    let quote = quote(extraction)?;
    let drain_path = extraction.completion();
    let released = document(&drain_path)?;
    ensure!(
        released["schema"] == "foundation-epoch226-extraction-success-drain-v1"
            && released["handoff"] == source
            && handoff["epoch"] == 226
            && handoff["stage"]["operation"] == "replay"
            && handoff["producer_unit"] == UNIT
            && handoff["run_root"] == ROOT
            && handoff["static"]["node"] == json!({"path":NODE,"sha256":NODE_SHA})
            && handoff["stage"]["worker"]["sha256"] == WORKER_SHA,
        "epoch 226 prefix handoff is incomplete or mismatched"
    );
    if path("native-prestart.json").exists() {
        let previous = document(&path("native-prestart.json"))?;
        let id = previous["InvocationID"]
            .as_str()
            .context("previous suffix invocation")?;
        ensure!(iid_is_valid(id), "invalid previous suffix invocation");
        let token = private157::file_binding(&path(&format!("tokens/{id}/guard-admission.json")))?;
        println!("{}", registration(&previous, &token)?);
        return Ok(());
    }
    ensure!(
        drain::show(CADENCE)?["ActiveState"] == "inactive"
            && drain::show(CADENCE_TIMER)?["ActiveState"] == "active"
            && next_timer(CADENCE_TIMER)?.saturating_sub(monotonic_usec()?) > 195_000_000,
        "suffix launch needs the next idle interval in the existing cadence"
    );
    for owner in [UNIT, GUARD, TIMER] {
        let before = drain::show(owner)?;
        ensure!(
            before["LoadState"] == "not-found"
                && before["ActiveState"] == "inactive"
                && before["Job"] == "",
            "epoch 226 suffix owner already exists"
        );
    }
    ensure!(
        !path("launch-intent.json").exists()
            && fs::read_dir(path("guard-receipts"))?.next().is_none(),
        "suffix launch already has an intent"
    );
    let output = ProcessCommand::new("/usr/bin/python3")
        .args(["-I", "-B", quote, "capacity-suffix226"])
        .output()?;
    ensure!(
        output.status.success(),
        "epoch 226 suffix capacity check failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let capacity: Value = serde_json::from_slice(&output.stdout)?;
    ensure!(
        capacity["epoch"] == 226
            && capacity["disk_shortfall_bytes"] == 0
            && capacity["memory_shortfall_bytes"] == 0
            && capacity["candidate_cap_bytes"] == ROOT_CAP
            && capacity["candidate_memory_max_bytes"] == ROOT_CAP
            && capacity["candidate_cpus"] == json!([16, 17, 18, 19, 20, 21, 22, 23])
            && capacity["extraction226_terminal"]["completion"]
                == private157::file_binding(&drain_path)?,
        "epoch 226 suffix capacity does not fit or changed ownership"
    );
    let floor = capacity["protected_disk_bytes"]
        .as_u64()
        .context("suffix protected floor")?;
    let minimum = floor
        .checked_add(ROOT_CAP)
        .context("suffix free-byte threshold overflow")?;
    ensure!(
        singleton227_admission::disk_free()? >= minimum,
        "epoch 226 suffix disk headroom changed"
    );
    let price = record(&path("accepted-capacity.json"), &capacity)?;
    let admission = json!({"schema":"jetstreamer-epoch226-scoped-repair-admission-v1","epoch":226,"operation":"replay",
        "stage_sha256":handoff["stage_sha256"],"node_sha256":NODE_SHA,"producer_unit":UNIT,"run_root":ROOT,"admitted":true,
        "complete_fleet_and_century_floor_bound":true,"actual_guard_and_owner_qualified":true,"exact_stage_scope_qualified":true,
        "original_native_source_evidence_accepted":true,"exact_worker_artifact_and_feature_scope_qualified":true,
        "protected_existing_floor_bytes":floor,"candidate_incremental_peak_bytes":ROOT_CAP,"recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "ordinary_replay_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"retirement_authorized":false,
        "runtime_promotion_authorized":false,"remote_mutations":false,"r2_mutations":false,"capacity":price,"handoff":source});
    let prepared = encode(&admission)?;
    let admission_ref = reference(&path("admission.json"), &prepared);
    let plan = encode(
        &json!({"schema":"jetstreamer-private-epoch226-scoped-repair-plan-v1","epoch":226,"producer_unit":UNIT,
        "node_sha256":NODE_SHA,"admission":admission_ref,"run_root":ROOT,"minimum_free_bytes":minimum,"stage":handoff["stage"]}),
    )?;
    let plan_ref = reference(&path("plan.json"), &plan);
    let launch = service_args(
        &source_template(&template, extraction)?,
        plan_ref["sha256"].as_str().context("pending plan digest")?,
    )?;
    let intent = record(
        &path("launch-intent.json"),
        &json!({"schema":"foundation-epoch226-suffix-launch-intent-v1",
        "handoff":source,"capacity":price,"admission":admission_ref,"plan":plan_ref,"producer_unit":UNIT,"work_released":false}),
    )?;
    make_root()?;
    start(&launch)?;
    let prestart = wait(12, "dormant suffix producer", dormant)?;
    let id = prestart["InvocationID"]
        .as_str()
        .context("suffix invocation")?;
    record(&path("native-prestart.json"), &prestart)?;
    let arm = (|| -> Result<Value> {
        check_cgroup(&prestart, ROOT_CAP)?;
        guard["invocation_id"] = json!(id);
        let guard_plan = record(&path("guard-plan.json"), &guard)?;
        start_guard(&guard_plan)?;
        let first = wait(28, "first suffix protection sample", || {
            newest_sample(id, &guard_plan, "start-pre", 0)
        })?;
        let timer = drain::show(TIMER)?;
        ensure!(
            timer["ActiveState"] == "active"
                && timer["Unit"] == GUARD
                && iid(&timer["InvocationID"])
                && next_timer(TIMER)? > monotonic_usec()?
                && dormant()?.as_ref().is_some_and(|p| p["InvocationID"] == id)
                && singleton227_admission::disk_free()? >= minimum,
            "epoch 226 first guard or protected space changed"
        );
        ensure!(
            write(&path("admission.json"), &prepared, 0o444)? == admission_ref
                && write(&path("plan.json"), &plan, 0o444)? == plan_ref,
            "epoch 226 prepared plan changed after arming guard"
        );
        let tokens = path(&format!("tokens/{id}"));
        fs::DirBuilder::new().mode(0o755).create(&tokens)?;
        fs::set_permissions(&tokens, fs::Permissions::from_mode(0o755))?;
        let token = json!({"schema":"foundation-epoch226-suffix-first-guard-v1","epoch":226,"unit":UNIT,"invocation_id":id,
            "launch_intent":intent,"first_guard":first,"guard_plan":guard_plan,"guard_timer_invocation":timer["InvocationID"],
            "admission":admission_ref,"plan":plan_ref,"canonical_epoch_publication_authorized":false});
        write(
            &tokens.join("guard-admission.json"),
            &encode(&token)?,
            0o444,
        )
    })();
    let token = match arm {
        Ok(token) => token,
        Err(error) => {
            // A partially synchronized token is a release. Leave that exact invocation under its armed guard.
            if path(&format!("tokens/{id}/guard-admission.json")).exists() {
                return Err(error);
            }
            if drain::show(UNIT)?["InvocationID"] == id {
                drain::stop(UNIT)?;
            }
            for name in [TIMER, GUARD] {
                if drain::show(name)?["LoadState"] != "not-found" {
                    drain::stop(name)?;
                }
            }
            return Err(error);
        }
    };
    println!("{}", registration(&prestart, &token)?);
    Ok(())
}

#[cfg(test)]
#[test]
fn suffix_launch_returns_to_the_controller_before_prestart_releases_the_node() -> Result<()> {
    let template = include_str!(
        "../../../../scripts/horizon_foundation_delivery247_20261124/epoch226_suffix.service.template"
    );
    let hash = "e".repeat(64);
    let args = service_args(template, &hash)?;
    assert!(args.contains(&"--no-block".to_owned()));
    assert!(
        args.iter()
            .any(|a| a.starts_with("--property=ExecStartPre=/usr/bin/bash "))
    );
    let split = args.iter().position(|a| a == "--").unwrap();
    assert_eq!(args[split + 1], NODE);
    assert_eq!(
        args.last().unwrap(),
        &format!("--checkpoint-continuation-plan-sha256={hash}")
    );
    Ok(())
}

#[cfg(test)]
#[test]
fn epoch226_suffix_handler_stays_registered_when_later_handlers_are_added() {
    assert!(registered_suffix_handler(
        "diagnostic_handlers = (diagnostic229_bank_delta, diagnostic226_suffix)"
    ));
    assert!(registered_suffix_handler(
        "diagnostic_handlers = (diagnostic229_bank_delta, diagnostic226_suffix, diagnostic296_meter)"
    ));
    assert!(!registered_suffix_handler(
        "diagnostic_handlers = (diagnostic229_bank_delta, diagnostic226_suffix_other)"
    ));
    assert!(!registered_suffix_handler(
        "diagnostic_handlers = (diagnostic226_suffix, diagnostic226_suffix)"
    ));
    assert!(!registered_suffix_handler(
        "diagnostic_handlers = (diagnostic226_suffix,)\ndiagnostic_handlers = ()"
    ));
}

#[cfg(test)]
#[test]
fn epoch226_suffix_registration_matches_the_fleet_validator() -> Result<()> {
    use crate::fleet::{BoundFile, DiagnosticClaim, validate_diagnostic_launch};

    let claim = DiagnosticClaim {
        epoch: 226,
        unit: UNIT.into(),
        invocation_id: "a".repeat(32),
        scratch_path: ROOT.into(),
        launch_receipt: BoundFile {
            path: path("cadence-registration.json"),
            sha256: "b".repeat(64),
        },
    };
    let owner = json!({
        "ActiveState": "active",
        "SubState": "running",
        "LoadState": "loaded",
        "Result": "success",
    });
    let receipt = registration_receipt(
        &claim.invocation_id,
        123,
        &owner,
        &Value::Null,
        &Value::Null,
    );
    validate_diagnostic_launch(&receipt, &claim)
}
