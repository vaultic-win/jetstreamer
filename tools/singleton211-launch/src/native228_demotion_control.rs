//! Finite epoch 228 controller. The actual worker remains blocked on its private
//! request pipe until an independent positive guard and a second complete fit.
#[path = "child_cleanup.rs"]
mod child_cleanup;
use super::*;
use child_cleanup::wait_for_cleanup;
use std::os::{fd::AsRawFd, unix::fs::FileTypeExt};
use std::process::{Child, ChildStdin, ChildStdout};
const GUARD_EXE: &str = "/var/lib/jetstreamer/horizon228-demotion-controls-v160-a1-qualified/guard";
const GUARD_SHA: &str = "98ae85499fd21fa294104a1ff05c21dc155c9aa14ea10a70a0b29302d853dbfb";
const PROTOCOL: &str =
    "/var/lib/jetstreamer/horizon228-demotion-controls-v160-a1-qualified/protocol";
const PROTOCOL_SHA: &str = "905e11ab36b4a576d327ac6a26d3b742e3bc012be4e9224dd64dbf8f20439c0d";
const RUNTIME: &str = "/run/horizon228-demotion-cold-v1";
const RECEIPTS: &str = "/var/lib/jetstreamer/horizon228-demotion-cold-guard-receipts-v1";
const BOOT_ACC: &str = "GfiRSgpC1qvH3uxVd9VAtYZ6qKM8fcdkyoyAkhF7izLq";
const SNAPSHOT_SHA: &str = "da26bd1b4b3b93be74c9dae28d1d982f821474333aa06e87f32dfa83342915f3";
const GEN_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
fn guard_image() -> Bound {
    Bound::new(GUARD_EXE, GUARD_SHA)
}
fn protocol_image() -> Bound {
    Bound::new(PROTOCOL, PROTOCOL_SHA)
}
fn worker_image() -> Bound {
    Bound::new(WORKER228, WORKER_DIGEST)
}
fn clean_directory(path: &Path, uid: u32) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && m.is_dir()
            && m.uid() == uid
            && m.gid() == uid
            && m.mode() & 0o777 == 0o700
            && fs::read_dir(path)?.next().is_none(),
        "private empty directory {}",
        path.display()
    );
    Ok(())
}
fn own_image(r: &Value) -> Result<()> {
    let b = binding(&r["controller_image"])?;
    b.artifact()?;
    ensure!(
        b.path.starts_with("/var/lib/jetstreamer")
            && b.path.file_name() == Some(std::ffi::OsStr::new("native-fit"))
            && fs::read_link("/proc/self/exe")? == b.path
            && metadata_identity(&fs::metadata("/proc/self/exe")?) == identity(&b.path)?,
        "controller mapped sealed native image"
    );
    Ok(())
}
fn sha_guard_files(r: &Value) -> Result<()> {
    ensure!(
        r["worker"] == json!(worker_image())
            && r["guard"] == json!(guard_image())
            && r["protocol"] == json!(protocol_image()),
        "controller deployment differs"
    );
    guard_image().artifact()?;
    protocol_image().artifact()?;
    worker_image().artifact()?;
    Ok(())
}
fn cpus(input: &str) -> Result<BTreeSet<u32>> {
    let mut result = BTreeSet::new();
    for part in input
        .split(|c: char| c == ',' || c.is_ascii_whitespace())
        .filter(|s| !s.is_empty())
    {
        let (a, b) = part.split_once('-').unwrap_or((part, part));
        let a = a.parse::<u32>()?;
        let b = b.parse::<u32>()?;
        ensure!(a <= b && b < 4096, "CPU range");
        for c in a..=b {
            ensure!(result.insert(c), "duplicate CPU");
        }
    }
    ensure!(!result.is_empty(), "empty affinity");
    Ok(result)
}
fn kernel_cpus(pid: u32) -> Result<BTreeSet<u32>> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    cpus(
        status
            .lines()
            .find_map(|s| s.strip_prefix("Cpus_allowed_list:"))
            .context("kernel CPU affinity")?,
    )
}
fn cpu_envelope(n: &mut Native, fit: &Value, r: &Value) -> Result<String> {
    let selected = cpus(text(r, "cpu_affinity")?)?;
    ensure!(
        selected.len() == 8
            && selected.is_subset(&cpus(
                fs::read_to_string("/sys/devices/system/cpu/online")?.trim()
            )?),
        "eight online CPUs required"
    );
    let owners = fit["actual_current_memory"]
        .as_object()
        .context("original owners")?;
    let mut sharing = BTreeMap::new();
    for unit in owners.keys() {
        let first = n.show(unit)?;
        let pid = text(&first, "MainPID")?.parse()?;
        let overlap: Vec<u32> = selected.intersection(&kernel_cpus(pid)?).copied().collect();
        if !overlap.is_empty() {
            sharing.insert(unit.clone(), overlap);
        }
        live::same_owner(&first, &n.show(unit)?)?;
    }
    ensure!(
        r["reviewed_cpu_overlap"] == json!(sharing),
        "epoch 228 CPU allocation changed"
    );
    Ok(selected
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" "))
}

fn producer_args(controller: &str, affinity: &str) -> Vec<String> {
    let mut args = vec![
        "--quiet".into(),
        "--wait".into(),
        "--pipe".into(),
        "--service-type=exec".into(),
        format!("--unit={COLD}"),
    ];
    for prop in [
        "User=ubuntu",
        "Group=ubuntu",
        "UMask=0077",
        "Restart=no",
        "KillMode=control-group",
        "Delegate=no",
        "MemoryHigh=120259084288",
        "MemoryMax=137438953472",
        "MemorySwapMax=0",
        "CPUQuota=800%",
        "TasksMax=512",
        "RuntimeMaxSec=2700",
        "TimeoutStopSec=30",
        "PrivateNetwork=yes",
        "PrivateDevices=yes",
        "PrivateTmp=yes",
        "ProtectHome=read-only",
        "ProtectSystem=strict",
        "ProtectControlGroups=yes",
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "RestrictAddressFamilies=AF_UNIX",
        "OOMPolicy=kill",
        "OOMScoreAdjust=1000",
        "LimitCORE=0",
        "UnsetEnvironment=AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN HORIZON_ACCESS_KEY_ID HORIZON_SECRET_ACCESS_KEY HORIZON_S3_ENDPOINT",
    ] {
        args.push(format!("--property={prop}"));
    }
    for prop in [
        format!("BindsTo={controller}"),
        format!("After={controller}"),
        format!("AllowedCPUs={affinity}"),
        format!("CPUAffinity={affinity}"),
        format!("WorkingDirectory={ROOT228}"),
        format!("ReadWritePaths={ROOT228}"),
    ] {
        args.push(format!("--property={prop}"));
    }
    for variable in [
        "SOLANA_RAYON_THREADS=8",
        "RAYON_NUM_THREADS=8",
        "JETSTREAMER_HISTORICAL_POH_THREADS=8",
        "TOKIO_WORKER_THREADS=8",
        "RUST_MIN_STACK=134217728",
    ] {
        args.push(format!("--setenv={variable}"));
    }
    args.push(WORKER228.into());
    args
}
fn guard_args(controller: &str, plan: &Bound) -> Vec<String> {
    let mut a = vec![
        "--quiet".into(),
        format!("--unit={}", GUARD228.trim_end_matches(".service")),
        "--on-active=1s".into(),
        "--on-unit-active=30s".into(),
        "--timer-property=AccuracySec=1ms".into(),
        "--timer-property=RandomizedDelaySec=0".into(),
        format!("--timer-property=BindsTo={controller}"),
        format!("--timer-property=After={controller}"),
    ];
    for v in [
        "Type=oneshot",
        "User=root",
        "Group=root",
        "UMask=0077",
        "Restart=no",
        "KillMode=control-group",
        "Delegate=no",
        "CPUQuota=100%",
        "MemoryMax=268435456",
        "MemorySwapMax=0",
        "TasksMax=64",
        "TimeoutStartSec=90",
        "PrivateNetwork=yes",
        "PrivateDevices=yes",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "ProtectControlGroups=yes",
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE",
        "RestrictAddressFamilies=AF_UNIX",
    ] {
        a.push(format!("--property={v}"));
    }
    a.push(format!("--property=ReadWritePaths={RECEIPTS}"));
    a.extend([
        GUARD_EXE.to_owned(),
        plan.path.to_string_lossy().into_owned(),
        "--plan-sha256".into(),
        plan.sha256.clone(),
        "--self-sha256".into(),
        GUARD_SHA.into(),
    ]);
    a
}

fn manager_journal(n: &mut Native, unit: &str, iid: &str) -> Result<Vec<Value>> {
    let u = format!("UNIT={unit}");
    let id = format!("INVOCATION_ID={iid}");
    let bytes = n.run(
        "/usr/bin/journalctl",
        &[
            "-b",
            "-o",
            "json",
            "--no-pager",
            "_PID=1",
            "_UID=0",
            &u,
            &id,
        ],
    )?;
    std::str::from_utf8(&bytes)?
        .lines()
        .map(|l| Ok(serde_json::from_str(l)?))
        .collect()
}
fn manager_observed(rows: &[Value], id: &str) -> bool {
    rows.iter().any(|r| r["MESSAGE_ID"] == id)
}
fn current_owner(n: &mut Native, initial: &Value) -> Result<Value> {
    let v = n.show(COLD)?;
    let iid = text(initial, "InvocationID")?;
    live::same_owner(initial, &v)?;
    live::finite_owner(&v, COLD, iid, COLD_MEMORY)?;
    gate::held_image(text(&v, "MainPID")?.parse()?, iid, COLD, WORKER228)?;
    Ok(v)
}
fn worker_sandbox(n: &mut Native, v: &Value, controller: &str, affinity: &str) -> Result<()> {
    for (k, want) in [
        ("Type", "exec"),
        ("User", "ubuntu"),
        ("Group", "ubuntu"),
        ("MemoryHigh", "120259084288"),
        ("TasksMax", "512"),
        ("CPUQuotaPerSecUSec", "8s"),
        ("PrivateNetwork", "yes"),
        ("ProtectHome", "read-only"),
        ("ProtectSystem", "strict"),
        ("NoNewPrivileges", "yes"),
        ("CapabilityBoundingSet", ""),
        ("ReadWritePaths", ROOT228),
        ("Transient", "yes"),
        ("DropInPaths", ""),
    ] {
        ensure!(v[k] == want, "epoch 228 worker {k}");
    }
    ensure!(
        text(v, "BindsTo")?
            .split_whitespace()
            .any(|u| u == controller)
            && cpus(text(v, "CPUAffinity")?)? == cpus(affinity)?
            && kernel_cpus(text(v, "MainPID")?.parse()?)? == cpus(affinity)?,
        "worker lifetime or CPU ownership differs"
    );
    let expected = format!("{{ path={WORKER228} ; argv[]={WORKER228} ; ignore_errors=no");
    ensure!(
        periodic::stable_command(text(v, "ExecStart")?)? == expected,
        "worker argv"
    );
    let props=n.run("/usr/bin/systemctl",&["show",COLD,"-p","PrivateDevices,ProtectControlGroups,OOMPolicy,WorkingDirectory,RestrictAddressFamilies,AmbientCapabilities"])?;
    let map = std::str::from_utf8(&props)?
        .lines()
        .filter_map(|l| l.split_once('='))
        .collect::<BTreeMap<_, _>>();
    for (k, a) in [
        ("PrivateDevices", "yes"),
        ("ProtectControlGroups", "yes"),
        ("WorkingDirectory", ROOT228),
        ("OOMPolicy", "kill"),
        ("RestrictAddressFamilies", "AF_UNIX"),
        ("AmbientCapabilities", ""),
    ] {
        ensure!(map.get(k) == Some(&a), "worker sandbox {k}");
    }
    Ok(())
}

fn original_pipes(pid: u32, reply: &ChildStdout, req: &ChildStdin) -> Result<Value> {
    let mut evidence = Vec::new();
    for (our, their) in [(req.as_raw_fd(), 0), (reply.as_raw_fd(), 1)] {
        let a = fs::metadata(format!("/proc/self/fd/{our}"))?;
        let b = fs::metadata(format!("/proc/{pid}/fd/{their}"))?;
        ensure!(
            a.file_type().is_fifo()
                && b.file_type().is_fifo()
                && (a.dev(), a.ino()) == (b.dev(), b.ino()),
            "foreign original worker pipe"
        );
        evidence.push(json!({"worker_fd":their,"device":a.dev(),"inode":a.ino()}));
    }
    ensure!(
        evidence[0]["inode"] != evidence[1]["inode"],
        "aliased protocol pipes"
    );
    Ok(json!(evidence))
}

fn first_guard(
    n: &mut Native,
    worker: &Value,
    plan: &Bound,
    timer_iid: &str,
    required: u64,
) -> Result<(Bound, Value)> {
    let until = Instant::now() + Duration::from_secs(80);
    loop {
        n.check()?;
        ensure!(
            !Path::new(RECEIPTS).join("stop-intent.json").try_exists()? && Instant::now() < until,
            "guard stopped worker or missed deadline"
        );
        let mut names = Vec::new();
        for e in fs::read_dir(RECEIPTS)? {
            let p = e?.path();
            if p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|s| s.starts_with("sample-") && s.ends_with(".json"))
            {
                names.push(p);
            }
        }
        if names.len() > 1 {
            bail!("missed original first guard");
        }
        if let Some(p) = names.pop() {
            let b = Bound::new(&p, hash(&p)?);
            let sample = b.json()?;
            let gid = text(&sample, "guard_invocation_id")?;
            ensure!(
                hex(gid, 32)
                    && p == Path::new(RECEIPTS).join(format!("sample-{gid}.json"))
                    && sample["guard_sha256"] == GUARD_SHA
                    && sample["plan_sha256"] == plan.sha256
                    && sample["producer_stop_enabled"] == true
                    && sample["trip_reason"].is_null()
                    && sample["root_physical_observation_error"].is_null()
                    && sample["worker_observation_error"].is_null()
                    && sample["root_physical_observation"]["exceeds_budget"] == false
                    && sample["native_main"]["sha256"] == WORKER_DIGEST
                    && sample["producer_invocation_id"] == worker["InvocationID"]
                    && sample["producer"]["pid"] == text(worker, "MainPID")?.parse::<u64>()?
                    && num(&sample, "available_bytes")? >= required,
                "first guard ownership or threshold"
            );
            let rows = manager_journal(n, GUARD228, gid)?;
            if !manager_observed(&rows, "7ad2d189f7e94e70a38c781354912448") {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            ensure!(
                manager_observed(&rows, "39f53479d3a045ac8e11786248231fbf")
                    && rows
                        .iter()
                        .all(|r| r.get("UNIT_RESULT").is_none_or(|v| v == "success")),
                "first guard not successful"
            );
            let timer = n.show(TIMER228)?;
            ensure!(
                timer["InvocationID"] == timer_iid
                    && timer["ActiveState"] == "active"
                    && timer["Unit"] == GUARD228,
                "original guard timer changed"
            );
            current_owner(n, worker)?;
            return Ok((b, sample));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn transcript(root: &Path, name: &str) -> Result<File> {
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join(name))?)
}
fn idle(n: &mut Native, unit: &str) -> Result<()> {
    let v = n.show(unit)?;
    ensure!(
        v["Id"] == unit
            && v["LoadState"] == "not-found"
            && v["ActiveState"] == "inactive"
            && v["Job"] == ""
            && !Path::new("/run/systemd/transient")
                .join(unit)
                .try_exists()?,
        "candidate name already installed {unit}"
    );
    Ok(())
}
fn checked_floor(fit: &Value, installed: Option<u64>) -> Result<(u64, u64)> {
    let cold = &fit["scenarios"]["cold"];
    ensure!(
        cold["fits"] == true,
        "epoch 228 cold funding failed: {}",
        cold["reason"]
    );
    let capacity = &cold["capacity"];
    let minimum = num(capacity, "protected_existing_floor_bytes")?;
    let quantum = 64u64 << 20;
    let floor = match installed {
        Some(v) => v,
        None => minimum.checked_add(quantum - 1).context("floor overflow")? / quantum * quantum,
    };
    let required = capacity::add(floor, COLD_DISK)?;
    ensure!(
        minimum > 0
            && minimum <= floor
            && num(capacity, "required_initial_free_bytes")? == capacity::add(minimum, COLD_DISK)?
            && required <= num(capacity, "observed_available_bytes")?,
        "installed guard floor or observed room changed"
    );
    Ok((floor, required))
}
fn wait_for(child: &mut Child, timeout: Duration) -> Result<std::process::ExitStatus> {
    if let Some(status) = wait_for_cleanup(child, timeout)? {
        return Ok(status);
    }
    child.kill()?;
    let _ = wait_for_cleanup(child, Duration::from_secs(5))?;
    bail!("protocol subprocess exceeded its deadline")
}
fn stop_original_timer(n: &mut Native, id: &str) -> Result<()> {
    let t = n.show(TIMER228)?;
    ensure!(
        hex(id, 32) && t["InvocationID"] == id && t["Unit"] == GUARD228,
        "timer replaced"
    );
    n.run("/usr/bin/systemctl", &["stop", TIMER228])?;
    let terminal = n.show(TIMER228)?;
    ensure!(
        terminal["ActiveState"] == "inactive" && terminal["Job"] == "",
        "timer did not stop"
    );
    Ok(())
}
fn started(n: &mut Native, manager: &mut Child) -> Result<Value> {
    let end = Instant::now() + Duration::from_secs(12);
    loop {
        n.check()?;
        let v = n.show(COLD)?;
        if v["ActiveState"] == "active" && v["SubState"] == "running" {
            return Ok(v);
        }
        ensure!(
            manager.try_wait()?.is_none() && Instant::now() < end,
            "held worker did not start"
        );
        std::thread::sleep(Duration::from_millis(60));
    }
}
fn exercise(n: &mut Native, r: &Value, source: &Bound) -> Result<Value> {
    own_image(r)?;
    sha_guard_files(r)?;
    let controller = text(r, "epoch228_controller_unit")?;
    let outer = n.show(controller)?;
    live::finite_owner(&outer, controller, text(&outer, "InvocationID")?, 512 << 20)?;
    ensure!(
        outer["MainPID"] == std::process::id().to_string()
            && outer["InvocationID"] == std::env::var("INVOCATION_ID")?
            && outer["Type"] == "exec",
        "controller must be original MainPID"
    );
    for unit in [COLD, GUARD228, TIMER228] {
        idle(n, unit)?;
    }
    for (path, uid) in [(ROOT228, 1000), (RUNTIME, 0), (RECEIPTS, 0)] {
        clean_directory(Path::new(path), uid)?;
    }
    let initial = evaluate(n, r, source, false)?;
    let initial_ref = save_json(&n.root, "initial-fit.json", &initial)?;
    let (floor, required) = checked_floor(&initial, None)?;
    let affinity = cpu_envelope(n, &initial, r)?;
    let mut manager = Command::new("/usr/bin/systemd-run")
        .args(producer_args(controller, &affinity))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(transcript(&n.root, "worker.stderr")?)
        .spawn()?;
    // The worker and timer have BindsTo on the outer controller. Any error
    // unwinds the private pipe handles before PID 1 stops that controller.
    let worker = started(n, &mut manager)?;
    current_owner(n, &worker)?;
    worker_sandbox(n, &worker, controller, &affinity)?;
    let iid = text(&worker, "InvocationID")?;
    let pid = text(&worker, "MainPID")?.parse::<u32>()?;
    let pipes = original_pipes(
        pid,
        manager.stdout.as_ref().context("response pipe")?,
        manager.stdin.as_ref().context("request pipe")?,
    )?;
    let start = manager_journal(n, COLD, iid)?;
    ensure!(
        manager_observed(&start, "39f53479d3a045ac8e11786248231fbf"),
        "worker manager start absent"
    );
    let launch = save_json(
        &n.root,
        "launch.json",
        &json!({"unit":COLD,"producer":worker,"controller":outer,"pipes":pipes,"initial_fit":initial_ref,"journal":start,"worker":worker_image()}),
    )?;
    let plan = save_json(
        &n.root,
        "guard-plan.json",
        &json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":COLD,"invocation_id":iid,"filesystem":"/","minimum_free_bytes":floor,"maximum_worker_vmas":3_500_000,"receipt_directory":RECEIPTS,"bounded_canary":null,"bounded_measurement":null,"worker_root":ROOT228,"native_main":{"executable":WORKER228,"sha256":WORKER_DIGEST,"main_pid":pid},"maximum_root_physical_bytes":300_000_000_000u64}),
    )?;
    let static_result: Value = serde_json::from_slice(&n.run(
        GUARD_EXE,
        &[
            plan.path.to_str().context("guard plan path")?,
            "--plan-sha256",
            &plan.sha256,
            "--self-sha256",
            GUARD_SHA,
            "--validate-plan-only",
        ],
    )?)?;
    ensure!(
        static_result["validated"] == true
            && static_result["plan_sha256"] == plan.sha256
            && static_result["self_sha256"] == GUARD_SHA,
        "guard rejected original plan"
    );
    let gargv = guard_args(controller, &plan);
    n.run(
        "/usr/bin/systemd-run",
        &gargv.iter().map(String::as_str).collect::<Vec<_>>(),
    )?;
    let timer = n.show(TIMER228)?;
    let timer_id = text(&timer, "InvocationID")?;
    ensure!(
        hex(timer_id, 32)
            && timer["Unit"] == GUARD228
            && timer["ActiveState"] == "active"
            && text(&timer, "BindsTo")?
                .split_whitespace()
                .any(|u| u == controller),
        "timer did not bind"
    );
    let (guard, sample) = first_guard(n, &worker, &plan, timer_id, required)?;
    let held = evaluate(n, r, source, true)?;
    let held_ref = save_json(&n.root, "held-fit.json", &held)?;
    ensure!(
        checked_floor(&held, Some(floor))? == (floor, required)
            && cpu_envelope(n, &held, r)? == affinity,
        "held booking changed"
    );
    live::same_owner(&outer, &held["controller"])?;
    live::same_owner(&worker, &held["producer"])?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let issued = now()?;
    let fleet = binding(&r["fleet"])?.json()?;
    let expires = [r, &fleet, &initial, &held]
        .into_iter()
        .map(|v| num(v, "recorded_unix_seconds"))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .min()
        .context("funding clock")?
        .checked_add(300)
        .context("clock overflow")?;
    ensure!(
        issued < expires
            && expires - issued <= 300
            && initial["boot_id"] == boot.trim()
            && held["boot_id"] == boot.trim()
            && num(&initial, "recorded_unix_seconds")? <= num(&sample, "recorded_unix_seconds")?
            && num(&sample, "recorded_unix_seconds")? <= num(&held, "recorded_unix_seconds")?,
        "stale funding"
    );
    let admission = save_json(
        &n.root,
        "admission.json",
        &json!({"schema":"epoch228-demotion-cold-admission-v1","unit":COLD,"worker_sha256":WORKER_DIGEST,"scratch_root":ROOT228,"producer_memory_bytes":COLD_MEMORY,"initial_fit":initial_ref,"source_fit":held_ref,"fleet":r["fleet"],"review":source,"reservation_ledger":r["reservation_ledger"],"protected_floor_bytes":floor,"required_free_bytes":required,"guard":guard_image(),"host_boot_id":boot.trim(),"issued_unix_seconds":issued,"expires_unix_seconds":expires,"producer_only_no_entries":true,"epoch228_completed_retry_memory_release":held["epoch228_completed_retry_memory_release"]}),
    )?;
    let release = json!({"schema":"epoch228-demotion-cold-release-v1","unit":COLD,"worker_pid":pid,"producer_iid":iid,"worker_sha256":WORKER_DIGEST,"guard_source":"f68492a79b280fa58b7526da1a013028c5fdf784","plan":plan,"first_guard":guard,"guard":guard_image(),"admission":admission,"required_free_bytes":required,"protected_floor_bytes":floor,"host_boot_id":boot.trim(),"issued_unix_seconds":issued,"expires_unix_seconds":expires});
    let durable = save_json(&n.root, "release.json", &release)?;
    let runtime = save_json(Path::new(RUNTIME), "release.json", &release)?;
    ensure!(durable.sha256 == runtime.sha256, "release copies differ");
    let utc = String::from_utf8(n.run(
        "/usr/bin/date",
        &["-u", "-d", &format!("@{issued}"), "+%Y-%m-%dT%H:%M:%SZ"],
    )?)?;
    let mut origin = json!({"schema":"jetstreamer-private-epoch228-demotion-native-input-running-v1","epoch":228,"unit":COLD,"invocation_id":iid,"main_pid":pid,"expected_exec_start":worker["ExecStart"],"controller":outer,"private_run_root":ROOT228,"test_sha256":WORKER_DIGEST,"snapshot_sha256":SNAPSHOT_SHA,"genesis_sha256":GEN_SHA,"accounts_hash":BOOT_ACC,"bootstrap_slot":98_495_291u64,"maximum_memory_bytes":COLD_MEMORY,"maximum_scratch_bytes":300_000_000_000u64,"launch":launch,"release":durable,"guard":guard,"guard_plan":plan,"admission":admission,"timer_invocation_id":timer_id,"recorded_unix_seconds":issued,"sampled_at_utc":utc.trim(),"public_sidecar_countdown_authorized":true,"ordinary_replay_claim":false,"replay_entries":0,"native_input_qualified":false});
    let protect = [
        "entry_replay",
        "replay_launch_authorized",
        "runtime_promotion_authorized",
        "full_epoch_qualified",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ];
    for k in protect {
        origin[k] = json!(false);
    }
    origin["fleet"] = r["fleet"].clone();
    origin["observer"] = r["observer"].clone();
    origin["resource_samples_taken"] = json!(0);
    let origin_ref = save_json(&n.root, "origin.json", &origin)?;
    eprintln!("HORIZON228_ORIGIN_SHA256={}", origin_ref.sha256);
    let auth = current_owner(n, &worker)?;
    worker_sandbox(n, &auth, controller, &affinity)?;
    ensure!(
        original_pipes(
            pid,
            manager.stdout.as_ref().context("reply")?,
            manager.stdin.as_ref().context("request")?
        )? == pipes
            && now()? < expires,
        "private held worker changed before protocol"
    );
    let mut peer = Command::new(PROTOCOL)
        .args(["--cold-held", &pid.to_string()])
        .stdin(manager.stdout.take().context("worker replies")?)
        .stdout(manager.stdin.take().context("worker requests")?)
        .stderr(transcript(&n.root, "protocol.stderr")?)
        .spawn()?;
    n.deadline = None;
    let status = wait_for(&mut peer, Duration::from_secs(2700))?;
    ensure!(status.success(), "protocol failed {status}");
    let proof_file = n.root.join("protocol.stderr");
    let proof = Bound::new(&proof_file, hash(&proof_file)?);
    let response = proof.sealed()?;
    ensure!(
        response["release"] == release
            && response["worker_pid"] == pid
            && response["snapshot_loaded"] == true
            && response["shutdown_acknowledged"] == true
            && response["replay_entries"] == 0
            && response["worker_sha256"] == WORKER_DIGEST
            && response["checkpoint"]["slot"] == 98_495_291
            && response["checkpoint"]["next_write_version"] == 113_087_684_591u64
            && response["checkpoint"]["writes"] == json!([]),
        "driver evidence differs"
    );
    // The worker acknowledges Shutdown before dropping its Bank and private
    // AccountsDb. Preserve validated protocol evidence before waiting for that
    // independent Linux process lifecycle.
    let ack = save_json(
        &n.root,
        "shutdown-ack.json",
        &json!({"schema":"horizon-guarded-worker-shutdown-ack-v1","unit":COLD,
            "invocation_id":iid,"worker_pid":pid,"worker":worker_image(),"origin":origin_ref,
            "release":durable,"protocol":protocol_image(),"protocol_proof":proof,
            "protocol_exit_code":status.code(),"shutdown_acknowledged":true,
            "recorded_unix_seconds":now()?,"worker_exit_code":null,
            "worker_drained":false,"native_cold_qualified":false,"resource_release_authorized":false}),
    )?;
    let close_wait = Instant::now();
    let manager_status = wait_for_cleanup(&mut manager, Duration::from_secs(300))?;
    let closed = save_json(
        &n.root,
        "launcher-close.json",
        &json!({
            "schema":"horizon-guarded-worker-launcher-close-v1","shutdown_ack":ack,
            "launcher_pid":manager.id(),"launcher_exit_code":manager_status.and_then(|s|s.code()),
            "launcher_exit_observed":manager_status.is_some(),"elapsed_millis":close_wait.elapsed().as_millis() as u64,
            "worker_exit_code":null,"resource_release_authorized":false
        }),
    )?;
    let manager_status = manager_status
        .context("guarded worker cleanup exceeded 300 seconds after acknowledged Shutdown")?;
    ensure!(
        manager_status.success(),
        "worker systemd-run failed {manager_status}"
    );
    let terminal = manager_journal(n, COLD, iid)?;
    ensure!(
        manager_observed(&terminal, "7ad2d189f7e94e70a38c781354912448")
            && !manager_observed(&terminal, "de5b426a63be47a7b6ac3eaac82e2f6f")
            && terminal
                .iter()
                .all(|r| r.get("UNIT_RESULT").is_none_or(|v| v == "success"))
            && !Path::new("/sys/fs/cgroup/system.slice")
                .join(COLD)
                .try_exists()?,
        "worker did not drain successfully"
    );
    stop_original_timer(n, timer_id)?;
    ensure!(
        !Path::new(RECEIPTS).join("stop-intent.json").try_exists()?,
        "guard issued stop"
    );
    Ok(
        json!({"schema":"horizon-epoch228-demotion-cold-controller-completed-v1","epoch":228,"unit":COLD,"producer_iid":iid,"worker_pid":pid,"origin":origin_ref,"release":durable,"protocol":protocol_image(),"worker":worker_image(),"protocol_proof":proof,"launcher_close":closed,"worker_exit_code":manager_status.code(),"protocol_exit_code":status.code(),"journal":terminal,"controller":outer,"timer_invocation_id":timer_id,"timer_stopped":true,"worker_drained":true,"native_cold_qualified":true,"replay_entries":0,"replay_launch_authorized":false,"r2_mutations":false}),
    )
}
pub fn run(review: &Path, sha256: &str, evidence: &Path) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0
            && evidence.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && evidence
                .file_name()
                .and_then(|v| v.to_str())
                .is_some_and(|s| s.starts_with("horizon228-demotion-live-")),
        "controller evidence namespace"
    );
    clean_directory(evidence, 0)?;
    let source = Bound::new(review, sha256);
    let r = source.sealed()?;
    let mut n = Native {
        root: evidence.to_owned(),
        counter: 0,
        deadline: Some(mono()?.checked_add(230_000_000).context("clock overflow")?),
    };
    let result = exercise(&mut n, &r, &source);
    match &result {
        Ok(v) => {
            let b = save_json(evidence, "completion.json", v)?;
            eprintln!("HORIZON228_COMPLETION_SHA256={}", b.sha256);
        }
        Err(e) => {
            save_json(
                evidence,
                "failure.json",
                &json!({"schema":"horizon-epoch228-demotion-cold-controller-failure-v1","review":source,"reason":format!("{e:#}"),"native_cold_qualified":false,"replay_launch_authorized":false,"r2_mutations":false}),
            )?;
        }
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prestart_and_held_floor_cover_scratch_and_exact_disk() {
        let c = |minimum: u64, available: u64| json!({"scenarios":{"cold":{"fits":true,"capacity":{"protected_existing_floor_bytes":minimum,"required_initial_free_bytes":minimum+COLD_DISK,"observed_available_bytes":available}}}});
        let rounded = 64 << 20;
        let f = c(7, rounded + COLD_DISK);
        assert_eq!(
            checked_floor(&f, None).unwrap(),
            (rounded, rounded + COLD_DISK)
        );
        assert!(checked_floor(&c(8, rounded + COLD_DISK - 1), Some(rounded)).is_err());
        assert!(checked_floor(&c(rounded + 1, 2 * rounded + COLD_DISK), Some(rounded)).is_err());
        assert!(checked_floor(&json!({"scenarios":{"cold":{"fits":false}}}), None).is_err());
    }
    #[test]
    fn worker_and_guard_stop_with_original_controller_and_keep_private_pipes() {
        let c = "horizon228-demotion-cold-control-v1.service";
        let a = producer_args(c, "0 1 2 3 4 5 6 7");
        assert_eq!(a.last().unwrap(), WORKER228);
        for p in [
            "--wait",
            "--pipe",
            "--service-type=exec",
            "--property=MemorySwapMax=0",
            "--property=PrivateNetwork=yes",
            &format!("--property=BindsTo={c}"),
            &format!("--property=ReadWritePaths={ROOT228}"),
        ] {
            assert!(a.iter().any(|v| v == p), "{p}");
        }
        let g = guard_args(c, &Bound::new("/var/lib/jetstreamer/plan", "a".repeat(64)));
        assert!(
            g.contains(&format!("--timer-property=BindsTo={c}"))
                && g.contains(&"--on-unit-active=30s".into())
                && g.contains(&format!("--property=ReadWritePaths={RECEIPTS}"))
                && g.contains(&GUARD_EXE.into())
        );
        assert!(cpus("1-3,3").is_err());
        assert_eq!(cpus("0-3,5 7").unwrap().len(), 6);
    }
}
