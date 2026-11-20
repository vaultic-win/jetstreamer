//! Genuine pretoken floor-trip qualification and explicit four-link retirement.
//! The generic standalone guard succeeds after stop; native265's failure is not this protocol.
use super::*;

pub(super) fn operation(v: &Value) -> Result<bool> {
    match v["operation"].as_str() {
        Some("qualify-guard") => Ok(true),
        Some("launch") => Ok(false),
        _ => bail!("explicit launch or qualify-guard operation required"),
    }
}

fn pristine_identity() -> Result<Value> {
    launch::pristine()?;
    Ok(json!({
        "root":metadata_identity(&fs::symlink_metadata(ROOT)?),
        "output":metadata_identity(&fs::symlink_metadata(Path::new(ROOT).join("output"))?),
        "genesis_placeholder":identity(&Path::new(ROOT).join("output/genesis.tar.bz2"))?
    }))
}

fn root_record(v: &Value) -> Result<()> {
    ensure!(
        v.as_object().is_some_and(|m| m.len() == 3),
        "pristine root record coverage"
    );
    for name in ["root", "output", "genesis_placeholder"] {
        let id: Identity = serde_json::from_value(v[name].clone())?;
        let placeholder = name == "genesis_placeholder";
        ensure!(
            id.0 > 0
                && id.1 > 0
                && id.3 == 1000
                && id.4 == if placeholder { 0o100400 } else { 0o40700 }
                && if placeholder {
                    id.2 == 0 && id.5 == 1
                } else {
                    id.5 >= 2
                },
            "invalid pristine root identity {name}"
        );
    }
    Ok(())
}

pub(super) fn held_capture(unit: &Value, startup: &Bound, p: &Value) -> Result<Value> {
    ensure!(operation(p)?, "not a protective-stop startup");
    let iid = text(unit, "InvocationID")?;
    let pid = text(unit, "MainPID")?.parse::<u64>()?;
    gate::held(pid, iid)?;
    absent(&Path::new(TOKENS).join(iid))?;
    let command = fs::read(format!("/proc/{pid}/cmdline"))?;
    let expected = [
        GATE,
        "gate",
        startup.path.to_str().context("startup path")?,
        &startup.sha256,
        text(&p["gate"], "sha256")?,
    ]
    .join("\0")
        + "\0";
    ensure!(command == expected.as_bytes(), "held command differs");
    let v = json!({"producer":unit,"recorded_monotonic_us":mono()?,
        "mapped_gate":p["gate"],"startup_plan":startup,"cmdline":expected,
        "cgroup_members":[pid],"children":[],"descendant_cgroups":[],
        "pristine_root":pristine_identity()?,"token_absent":true});
    gate::held(pid, iid)?;
    Ok(v)
}

fn killed(v: &Value, iid: &str) -> Result<()> {
    ensure!(hex(iid, 32), "terminal IID");
    for (k, expected) in [
        ("Id", UNIT),
        ("LoadState", "loaded"),
        ("InvocationID", iid),
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("Job", ""),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("ExecMainCode", "2"),
        ("ExecMainStatus", "15"),
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("Result", "success"),
    ] {
        ensure!(
            v[k] == expected,
            "not original protective SIGTERM terminal: {k}"
        );
    }
    Ok(())
}

pub(super) fn same_terminal(a: &Value, b: &Value) -> Result<()> {
    live::same_owner(a, b)?;
    for k in [
        "ControlPID",
        "Job",
        "ExecMainCode",
        "ExecMainStatus",
        "Restart",
        "KillMode",
        "Delegate",
        "MemoryMax",
        "MemoryHigh",
        "MemorySwapMax",
        "TasksMax",
        "FragmentPath",
        "DropInPaths",
    ] {
        ensure!(!a[k].is_null() && a[k] == b[k], "terminal changed {k}");
    }
    Ok(())
}

fn drained(pid: u64, iid: &str, root: &Value) -> Result<()> {
    ensure!(pid > 1 && hex(iid, 32), "drain identity");
    absent(&PathBuf::from(format!("/proc/{pid}")))?;
    absent(&Path::new(TOKENS).join(iid))?;
    let group = format!("/system.slice/{UNIT}");
    let path = Path::new("/sys/fs/cgroup").join(&group[1..]);
    match fs::symlink_metadata(&path) {
        Ok(_) => live::drained_tree(&path, &mut 1024)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        if !entry
            .file_name()
            .to_string_lossy()
            .bytes()
            .all(|b| b.is_ascii_digit())
        {
            continue;
        }
        match fs::read_to_string(entry.path().join("cgroup")) {
            Ok(v) => ensure!(
                !v.lines()
                    .any(|l| l == format!("0::{group}") || l.starts_with(&format!("0::{group}/"))),
                "qualification still owns a process"
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    ensure!(
        pristine_identity()? == *root,
        "qualification modified pristine root"
    );
    Ok(())
}

fn guard_terminal(v: &Value, gid: &str) -> Result<()> {
    ensure!(hex(gid, 32), "guard IID");
    for (k, expected) in [
        ("Id", GUARD_UNIT),
        ("LoadState", "loaded"),
        ("InvocationID", gid),
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("Job", ""),
        ("Result", "success"),
        ("ExecMainCode", "1"),
        ("ExecMainStatus", "0"),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("DropInPaths", ""),
        ("StartLimitIntervalUSec", "0"),
        ("MemoryMax", "268435456"),
        ("MemorySwapMax", "0"),
        ("TasksMax", "64"),
        ("Type", "oneshot"),
        ("User", "root"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("PrivateNetwork", "yes"),
        ("NoNewPrivileges", "yes"),
    ] {
        ensure!(
            v[k] == expected,
            "generic protective guard terminal differs {k}"
        );
    }
    Ok(())
}

fn timer_idle(v: &Value) -> Result<()> {
    ensure!(
        v["Id"] == TIMER
            && v["LoadState"] == "loaded"
            && v["ActiveState"] == "inactive"
            && v["SubState"] == "dead"
            && v["Unit"] == GUARD_UNIT
            && v["Job"] == ""
            && v["DropInPaths"] == "",
        "qualification timer not idle"
    );
    Ok(())
}

// All guard-origin observations must be the exact generic full211 protocol.
fn stop_records(
    c: &Value,
    gp: &Value,
    sample: &Value,
    intent: &Value,
    completion: &Value,
) -> Result<()> {
    let iid = text(c, "producer_invocation_id")?;
    let gid = text(c, "guard_invocation_id")?;
    let pid = num(c, "producer_main_pid")?;
    let plan = &c["guard_plan"];
    ensure!(
        hex(iid, 32) && hex(gid, 32) && iid != gid && pid > 1,
        "stop identities"
    );
    ensure!(
        gp["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && gp["unit"] == UNIT
            && gp["invocation_id"] == iid
            && gp["filesystem"] == "/"
            && gp["minimum_free_bytes"] == u64::MAX
            && gp["worker_root"] == ROOT
            && gp["maximum_root_physical_bytes"] == SCRATCH
            && gp["maximum_worker_vmas"] == 3500000
            && gp["receipt_directory"] == c["receipts"],
        "stop guard plan differs"
    );
    for k in ["native_main", "bounded_measurement", "bounded_canary"] {
        ensure!(
            gp.get(k).is_none_or(Value::is_null),
            "qualification exemption {k}"
        );
    }
    ensure!(
        sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && sample["plan"] == plan["path"]
            && sample["plan_sha256"] == plan["sha256"]
            && sample["guard_sha256"] == c["guard"]["sha256"]
            && sample["guard_invocation_id"] == gid
            && sample["producer_invocation_id"] == iid
            && sample["producer"]["invocation_id"] == iid
            && sample["producer"]["pid"] == pid
            && sample["producer"]["active"] == "active"
            && sample["producer"]["sub"] == "running"
            && sample["producer"]["load_state"] == "loaded"
            && sample["producer"]["result"] == "success"
            && sample["producer"]["restarts"] == 0
            && sample["producer"]["restart_policy"] == "no"
            && sample["producer"]["kill_mode"] == "control-group"
            && sample["producer"]["delegated"] == false
            && sample["producer"]["cgroup"] == format!("/system.slice/{UNIT}")
            && sample["producer_stop_enabled"] == true
            && sample["trip_reason"] == "filesystem-floor"
            && sample["minimum_free_bytes"] == u64::MAX
            && num(sample, "available_bytes")? < u64::MAX
            && sample["maximum_root_physical_bytes"] == SCRATCH
            && sample["maximum_worker_vmas"] == 3500000
            && sample["root_physical_observation"]["maximum_physical_bytes"] == SCRATCH
            && sample["root_physical_observation"]["exceeds_budget"] == false
            && num(
                &sample["root_physical_observation"],
                "conservative_physical_bytes"
            )? <= SCRATCH
            && sample["workers"] == json!([])
            && sample["bounded_measurement"] == false
            && sample["remote_mutations"] == false
            && sample["r2_mutations"] == false,
        "not a genuine held full211 floor stop sample"
    );
    for k in [
        "native_main",
        "worker_observation_error",
        "root_physical_observation_error",
        "canary_target_error",
        "target_handoff_error",
        "bounded_canary",
        "target_handoff",
    ] {
        ensure!(
            sample.get(k) == Some(&Value::Null),
            "missing/errored observation {k}"
        );
    }
    fresh(
        num(sample, "recorded_unix_seconds")?,
        num(c, "recorded_unix_seconds")?,
        60,
    )?;
    ensure!(
        intent["schema"] == "jetstreamer-horizon-standalone-stop-intent-v1"
            && intent["plan_sha256"] == plan["sha256"]
            && intent["producer_invocation_id"] == iid
            && intent["reason"] == "filesystem-floor"
            && intent["sample"] == *sample,
        "stop intent differs from original sample"
    );
    ensure!(
        completion["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
            && completion["plan_sha256"] == plan["sha256"]
            && completion["producer_invocation_id"] == iid
            && completion["intent"] == c["stop_intent"]["path"]
            && completion["scratch_deleted"] == false
            && completion["remote_mutations"] == false
            && completion["r2_mutations"] == false,
        "guard stop completion differs"
    );
    let t = &completion["terminal"];
    ensure!(
        t["invocation_id"] == iid
            && t["pid"] == 0
            && t["active"] == "inactive"
            && t["sub"] == "dead"
            && t["load_state"] == "loaded"
            && t["result"] == "success"
            && t["restarts"] == 0
            && t["restart_policy"] == "no"
            && t["kill_mode"] == "control-group"
            && t["delegated"] == false
            && t["cgroup"] == c["producer_terminal"]["ControlGroup"],
        "guard completion not original retained terminal"
    );
    killed(&c["producer_terminal"], iid)?;
    guard_terminal(&c["guard_terminal"], gid)
}

fn journal_time(
    rows: &Value,
    unit: &str,
    iid: &str,
    boot: &str,
    prefix: bool,
    message: &str,
) -> Result<u64> {
    let rows = rows.as_array().context("PID1 journal array")?;
    ensure!(!rows.is_empty() && rows.len() <= 128, "journal bounds");
    for r in rows {
        ensure!(
            r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["UNIT"] == unit
                && r["INVOCATION_ID"] == iid
                && r["_BOOT_ID"] == boot.replace('-', ""),
            "foreign PID1 journal row"
        );
    }
    let selected: Vec<_> = rows
        .iter()
        .filter(|r| {
            r["MESSAGE"].as_str().is_some_and(|m| {
                if prefix {
                    m.starts_with(message)
                } else {
                    m == message
                }
            })
        })
        .collect();
    ensure!(
        selected.len() == 1,
        "missing/duplicate PID1 event {message}"
    );
    Ok(text(selected[0], "__MONOTONIC_TIMESTAMP")?.parse()?)
}

fn ordering(c: &Value, p: &Value, producer: &Value, guard: &Value) -> Result<()> {
    let iid = text(c, "producer_invocation_id")?;
    let gid = text(c, "guard_invocation_id")?;
    let boot = text(c, "boot_id")?;
    let started = journal_time(
        producer,
        UNIT,
        iid,
        boot,
        true,
        &format!("Started {UNIT} -"),
    )?;
    let stopping = journal_time(
        producer,
        UNIT,
        iid,
        boot,
        true,
        &format!("Stopping {UNIT} -"),
    )?;
    let stopped = journal_time(
        producer,
        UNIT,
        iid,
        boot,
        false,
        &format!("{UNIT}: Deactivated successfully."),
    )?;
    let guard_start = journal_time(
        guard,
        GUARD_UNIT,
        gid,
        boot,
        true,
        &format!("Starting {GUARD_UNIT} -"),
    )?;
    let guard_end = journal_time(
        guard,
        GUARD_UNIT,
        gid,
        boot,
        false,
        &format!("{GUARD_UNIT}: Deactivated successfully."),
    )?;
    let held = num(&c["held"], "recorded_monotonic_us")?;
    let end = num(c, "recorded_monotonic_us")?;
    ensure!(
        num(p, "issued_monotonic_us")? <= started
            && started <= held
            && held < guard_start
            && guard_start < stopping
            && stopping < stopped
            && stopped < guard_end
            && guard_end <= end
            && end < num(p, "expires_monotonic_us")?,
        "protective stop ordering outside original startup window"
    );
    Ok(())
}

fn links(c: &Value, p: &Value, review: &Value) -> Result<Vec<(String, Bound)>> {
    let attempt = text(review, "attempt")?;
    ensure!(launch::safe_attempt(attempt), "attempt namespace");
    let startup = binding(&c["startup_plan"])?;
    let gp = binding(&c["guard_plan"])?;
    let guard = binding(&c["guard"])?;
    let producer = launch::package(attempt, "producer");
    let guard_package = launch::package(attempt, "guard-units");
    let receipts = launch::package(attempt, "guard-receipts");
    ensure!(
        startup.path == launch::package(attempt, "startup-plan").join("plan.json")
            && gp.path == launch::package(attempt, "guard-binding").join("guard-plan.json")
            && c["producer_package"] == json!(producer)
            && c["guard_package"] == json!(guard_package)
            && c["receipts"] == json!(receipts),
        "qualification package namespaces changed"
    );
    let expected = [
        (
            UNIT,
            producer.join(UNIT),
            launch::producer_template(
                &startup.path,
                &launch::cpus(review)?,
                text(&p["gate"], "sha256")?,
            ),
        ),
        (
            RETENTION,
            producer.join(RETENTION),
            launch::retention_template(),
        ),
        (
            GUARD_UNIT,
            guard_package.join(GUARD_UNIT),
            launch::guard_template(&guard, &gp.path, &receipts),
        ),
        (TIMER, guard_package.join(TIMER), launch::timer_template()),
    ];
    let mut out = Vec::new();
    for (unit, path, template) in expected {
        let b = Bound::new(path, digest(template.as_bytes()));
        b.bytes(true)?;
        trusted_parents(&b.path)?;
        out.push((unit.to_owned(), b));
    }
    Ok(out)
}

// Historical validation only: files and the captured proof graph; no current fleet/PID1 observation.
fn validate_capture(c: &Value, guard: &Bound, self_sha: &str) -> Result<Vec<(String, Bound)>> {
    no_authority(c)?;
    ensure!(
        c["schema"] == "horizon-singleton211-protective-stop-capture-v1"
            && c["gate"] == json!(Bound::new(GATE, self_sha))
            && c["guard"] == json!(guard)
            && c["token_absent"] == true
            && c["pristine_root_unchanged"] == true
            && c["original_process_gone"] == true
            && c["kernel_drained"] == true
            && c["actual_stop_observed"] == true
            && c["Main_acceptance_required"] == true,
        "invalid full211 qualification capture"
    );
    let startup = binding(&c["startup_plan"])?;
    let p = startup.sealed()?;
    ensure!(
        operation(&p)?
            && p["gate"] == c["gate"]
            && p["guard"] == c["guard"]
            && p["boot_id"] == c["boot_id"],
        "capture startup differs"
    );
    gate::plan(
        &p,
        self_sha,
        text(c, "boot_id")?,
        num(c, "recorded_monotonic_us")?,
    )?;
    let a = binding(&p["admission"])?.sealed()?;
    lifecycle::admission(&a, &p)?;
    ensure!(
        num(c, "recorded_unix_seconds")? >= num(&a, "recorded_unix_seconds")?
            && num(c, "recorded_unix_seconds")? <= num(&a, "expires_unix_seconds")?,
        "capture outside admission lease"
    );
    let review = binding(&a["review"])?.sealed()?;
    ensure!(
        operation(&review)?
            && review["guard"] == c["guard"]
            && review["source_publication"] == a["source_publication"],
        "capture review differs"
    );
    let iid = text(c, "producer_invocation_id")?;
    let pid = num(c, "producer_main_pid")?;
    let held = &c["held"];
    let command = [
        GATE,
        "gate",
        startup.path.to_str().context("startup path")?,
        &startup.sha256,
        self_sha,
    ]
    .join("\0")
        + "\0";
    ensure!(
        held["mapped_gate"] == c["gate"]
            && held["startup_plan"] == c["startup_plan"]
            && held["producer"]["InvocationID"] == iid
            && held["producer"]["MainPID"] == pid.to_string().as_str()
            && held["producer"]["ActiveState"] == "active"
            && held["producer"]["SubState"] == "running"
            && held["producer"]["Result"] == "success"
            && held["producer"]["ControlPID"] == "0"
            && held["producer"]["Job"] == ""
            && held["producer"]["ControlGroup"] == format!("/system.slice/{UNIT}")
            && held["cmdline"] == command
            && held["cgroup_members"] == json!([pid])
            && held["children"] == json!([])
            && held["descendant_cgroups"] == json!([])
            && held["token_absent"] == true
            && held["pristine_root"].is_object()
            && c["terminal_root"] == held["pristine_root"],
        "held process or pristine root proof differs"
    );
    launch::producer_properties(
        &held["producer"],
        &startup,
        &launch::cpus(&review)?,
        self_sha,
    )?;
    // Terminal retains the same effective sandbox and original loaded unit command.
    launch::producer_properties(
        &c["producer_terminal"],
        &startup,
        &launch::cpus(&review)?,
        self_sha,
    )?;
    root_record(&held["pristine_root"])?;
    let gp = binding(&c["guard_plan"])?.sealed()?;
    let receipts = Path::new(text(c, "receipts")?);
    for (field, name) in [
        (
            "sample",
            format!("sample-{}.json", text(c, "guard_invocation_id")?),
        ),
        ("stop_intent", "stop-intent.json".into()),
        ("stop_completion", "stop-completion.json".into()),
    ] {
        ensure!(
            binding(&c[field])?.path == receipts.join(name),
            "foreign guard record {field}"
        );
    }
    stop_records(
        c,
        &gp,
        &binding(&c["sample"])?.json()?,
        &binding(&c["stop_intent"])?.json()?,
        &binding(&c["stop_completion"])?.json()?,
    )?;
    ordering(
        c,
        &p,
        &binding(&c["producer_pid1"])?.json()?,
        &binding(&c["guard_pid1"])?.json()?,
    )?;
    timer_idle(&c["timer_terminal"])?;
    let links = links(c, &p, &review)?;
    let gr = binding(&c["guard_plan"])?;
    prepare::verify_pair(&gr, prepare::GUARD_ARG)?;
    prepare::guard_properties(&c["guard_terminal"], guard, &gr.path)?;
    for (unit, target) in &links {
        let captured = match unit.as_str() {
            GUARD_UNIT => &c["guard_terminal"],
            TIMER => &c["timer_terminal"],
            _ => continue,
        };
        ensure!(
            captured["FragmentPath"] == json!(target.path)
                || captured["FragmentPath"] == format!("/etc/systemd/system/{unit}"),
            "captured control fragment differs"
        );
    }
    ensure!(c["unit_files"] == json!(links), "unit file bindings differ");
    Ok(links)
}

fn journal(n: &mut Native, unit: &str, iid: &str, leaf: &str) -> Result<Bound> {
    let bytes = n.run(
        "/usr/bin/journalctl",
        &[
            "--all",
            "--no-pager",
            "--output=json",
            "--boot=0",
            "_PID=1",
            &format!("UNIT={unit}"),
            &format!("INVOCATION_ID={iid}"),
        ],
    )?;
    let rows: Vec<Value> = serde_json::Deserializer::from_slice(&bytes)
        .into_iter()
        .collect::<std::result::Result<_, _>>()?;
    save_json(&n.root, leaf, &json!(rows))
}

pub(super) fn capture_stop(
    n: &mut Native,
    held: &Value,
    startup: &Bound,
    guard_plan: &Bound,
    attempt: &str,
    peers: &mut peer_window::Window,
) -> Result<()> {
    let producer_package = launch::package(attempt, "producer");
    let guard_package = launch::package(attempt, "guard-units");
    let receipts = launch::package(attempt, "guard-receipts");
    let p = startup.sealed()?;
    let iid = text(&held["producer"], "InvocationID")?;
    let pid = text(&held["producer"], "MainPID")?.parse::<u64>()?;
    let guard = loop {
        n.check()?;
        absent(&Path::new(TOKENS).join(iid))?;
        let v = n.show(GUARD_UNIT)?;
        ensure!(
            v["ActiveState"] != "failed",
            "protective guard failed before completing stop"
        );
        if v["ActiveState"] == "inactive"
            && v["InvocationID"].as_str().is_some_and(|s| hex(s, 32))
            && v["MainPID"] == "0"
            && v["ControlPID"] == "0"
            && v["Job"] == ""
        {
            break v;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let gid = text(&guard, "InvocationID")?;
    guard_terminal(&guard, gid)?;
    let terminal = n.show(UNIT)?;
    killed(&terminal, iid)?;
    drained(pid, iid, &held["pristine_root"])?;
    n.run("/usr/bin/systemctl", &["stop", TIMER])?;
    let timer = n.show(TIMER)?;
    timer_idle(&timer)?;
    same_terminal(&terminal, &n.show(UNIT)?)?;
    guard_terminal(&n.show(GUARD_UNIT)?, gid)?;
    let record = |name: &str| -> Result<Bound> {
        let path = receipts.join(name);
        Ok(Bound::new(&path, hash(&path)?))
    };
    let producer_journal = journal(n, UNIT, iid, "qualification-producer-PID1.json")?;
    let guard_journal = journal(n, GUARD_UNIT, gid, "qualification-guard-PID1.json")?;
    let mut c = json!({"schema":"horizon-singleton211-protective-stop-capture-v1","gate":p["gate"],"guard":p["guard"],
        "boot_id":p["boot_id"],"producer_invocation_id":iid,"producer_main_pid":pid,"guard_invocation_id":gid,
        "startup_plan":startup,"guard_plan":guard_plan,"held":held,
        "sample":record(&format!("sample-{gid}.json"))?,"stop_intent":record("stop-intent.json")?,"stop_completion":record("stop-completion.json")?,
        "producer_terminal":terminal,"guard_terminal":guard,"timer_terminal":timer,
        "producer_pid1":producer_journal,"guard_pid1":guard_journal,"producer_package":producer_package,"guard_package":guard_package,"receipts":receipts,
        "terminal_root":pristine_identity()?,"token_absent":true,"pristine_root_unchanged":true,"original_process_gone":true,"kernel_drained":true,
        "actual_stop_observed":true,"Main_acceptance_required":true,"recorded_unix_seconds":now()?,"recorded_monotonic_us":mono()?});
    deny_authority(&mut c);
    let a = binding(&p["admission"])?.sealed()?;
    let review = binding(&a["review"])?.sealed()?;
    c["unit_files"] = json!(links(&c, &p, &review)?);
    validate_capture(&c, &binding(&p["guard"])?, text(&p["gate"], "sha256")?)?;
    drained(pid, iid, &held["pristine_root"])?;
    n.check()?;
    peers.verify(n)?;
    let out = save_json(&n.root, "protective-stop-capture.json", &c)?;
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}

pub(super) fn accepted(review: &Value, guard: &Bound, self_sha: &str) -> Result<()> {
    no_authority(review)?;
    ensure!(
        review["schema"] == "horizon-singleton211-protective-stop-qualification-v1"
            && review["Main_accepted"] == true
            && review["gate"] == json!(Bound::new(GATE, self_sha))
            && review["guard"] == json!(guard)
            && review["sandbox_permissions_verified"] == true,
        "protective-stop acceptance missing"
    );
    let capture_ref = binding(&review["capture"])?;
    let c = capture_ref.sealed()?;
    let links = validate_capture(&c, guard, self_sha)?;
    let retired = binding(&review["retirement"])?.sealed()?;
    no_authority(&retired)?;
    ensure!(
        retired["schema"] == "horizon-singleton211-qualification-unit-retirement-v1"
            && retired["capture"] == review["capture"]
            && retired["boot_id"] == c["boot_id"]
            && retired["unit_files"] == json!(links)
            && retired["sealed_packages_and_diagnostics_preserved"] == true
            && retired["producer_restarted"] == false
            && retired["all_four_links_removed"] == true
            && retired["kernel_drained"] == true
            && retired["token_absent"] == true
            && retired["pristine_root_unchanged"] == true,
        "qualification retirement binding missing"
    );
    let before = binding(&retired["before"])?.json()?;
    ensure!(
        before["capture"] == review["capture"]
            && before["unit_files"] == json!(links)
            && before["root"] == c["held"]["pristine_root"],
        "retirement before proof changed"
    );
    same_terminal(&c["producer_terminal"], &before["producer"])?;
    let after = retired["after"]
        .as_object()
        .context("retirement final census")?;
    ensure!(after.len() == 4, "retirement final census incomplete");
    for unit in [UNIT, GUARD_UNIT, TIMER, RETENTION] {
        let v = after.get(unit).context("missing retired unit")?;
        ensure!(
            v["Id"] == unit
                && v["LoadState"] == "not-found"
                && v["Job"] == ""
                && v["ActiveState"] == "inactive",
            "qualification unit not collected"
        );
    }
    Ok(())
}

pub(super) fn installed_link(unit: &str, target: &Bound) -> Result<Identity> {
    let path = Path::new("/etc/systemd/system").join(unit);
    let m = fs::symlink_metadata(&path)?;
    ensure!(
        m.file_type().is_symlink() && m.uid() == 0 && fs::read_link(&path)? == target.path,
        "foreign qualification link"
    );
    target.bytes(true)?;
    Ok(metadata_identity(&m))
}

pub(super) fn collect_retired(
    n: &mut Native,
    links: &[(String, Bound)],
) -> Result<BTreeMap<String, Value>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut after = BTreeMap::new();
        for (unit, target) in links {
            for root in ["/etc/systemd/system", "/run/systemd/system"] {
                absent(&Path::new(root).join(unit))?;
                absent(&Path::new(root).join(format!("{unit}.d")))?;
            }
            let v = n.show(unit)?;
            ensure!(
                v["Id"] == unit.as_str() && v["Job"] == "" && v["ActiveState"] == "inactive",
                "qualification unit acquired another owner"
            );
            if v["LoadState"] == "not-found" {
                after.insert(unit.clone(), v);
            } else {
                ensure!(
                    v["LoadState"] == "loaded"
                        && (v["FragmentPath"] == json!(target.path)
                            || v["FragmentPath"] == format!("/etc/systemd/system/{unit}")),
                    "unexpected cached definition"
                );
            }
        }
        if after.len() == 4 {
            return Ok(after);
        }
        ensure!(
            Instant::now() < deadline,
            "qualification remains cached; preserve diagnostics"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn retirement_intent(
    n: &mut Native,
    capture_ref: &Bound,
    c: &Value,
    links: &[(String, Bound)],
    dest: &Path,
) -> Result<Bound> {
    let path = dest.join("retirement-before.json");
    match fs::symlink_metadata(dest) {
        Ok(_) => {
            let b = Bound::new(&path, hash(&path)?);
            b.sealed()?;
            return Ok(b);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    let iid = text(c, "producer_invocation_id")?;
    let pid = num(c, "producer_main_pid")?;
    let initial = n.show(UNIT)?;
    killed(&initial, iid)?;
    same_terminal(&c["producer_terminal"], &initial)?;
    let current_guard = n.show(GUARD_UNIT)?;
    guard_terminal(&current_guard, text(c, "guard_invocation_id")?)?;
    same_terminal(&c["guard_terminal"], &current_guard)?;
    let current_timer = n.show(TIMER)?;
    timer_idle(&current_timer)?;
    ensure!(
        current_timer == c["timer_terminal"],
        "qualification timer changed after capture"
    );
    let retain = launch::retention(n, Path::new(text(c, "producer_package")?))?;
    drained(pid, iid, &c["held"]["pristine_root"])?;
    let mut identities = BTreeMap::new();
    for (unit, target) in links {
        identities.insert(unit.clone(), installed_link(unit, target)?);
        for dir in ["/etc/systemd/system", "/run/systemd/system"] {
            absent(&Path::new(dir).join(format!("{unit}.d")))?;
        }
        absent(&Path::new("/run/systemd/system").join(unit))?;
    }
    let before = save_json(
        &n.root,
        "retirement-before.json",
        &json!({"capture":capture_ref,"producer":initial,
        "guard":current_guard,"timer":current_timer,"retention":retain,"boot_id":c["boot_id"],
        "unit_files":links,"link_identities":identities,"root":c["held"]["pristine_root"],"remote_mutations":false}),
    )?;
    n.seal(dest, &[("retirement-before.json", before.clone())])?;
    Ok(Bound::new(path, before.sha256))
}
pub(super) fn retire_attempt(
    n: &mut Native,
    capture_ref: &Bound,
    c: &Value,
    self_sha: &str,
) -> Result<()> {
    let guard = binding(&c["guard"])?;
    ensure!(guard.path == Path::new(GUARD), "foreign guard deployment");
    let links = validate_capture(c, &guard, self_sha)?;
    ensure!(
        text(c, "boot_id")? == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        "qualification boot changed"
    );
    let iid = text(c, "producer_invocation_id")?;
    let pid = num(c, "producer_main_pid")?;
    // Serialize independent retirement invocations on their exact immutable capture.
    let lock = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&capture_ref.path)?;
    use std::os::fd::AsRawFd;
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "qualification retirement already in progress"
    );
    let startup = binding(&c["startup_plan"])?.sealed()?;
    let a = binding(&startup["admission"])?.sealed()?;
    let review = binding(&a["review"])?.sealed()?;
    let attempt = text(&review, "attempt")?;
    ensure!(
        launch::safe_attempt(attempt),
        "retirement attempt namespace"
    );
    let before = retirement_intent(
        n,
        capture_ref,
        c,
        &links,
        &launch::package(attempt, "retire-intent"),
    )?;
    let intent = before.sealed()?;
    ensure!(
        intent["capture"] == json!(capture_ref)
            && intent["boot_id"] == c["boot_id"]
            && intent["unit_files"] == json!(links)
            && intent["root"] == c["held"]["pristine_root"]
            && intent["timer"] == c["timer_terminal"]
            && intent["remote_mutations"] == false,
        "retirement intent belongs to another qualification"
    );
    same_terminal(&c["producer_terminal"], &intent["producer"])?;
    same_terminal(&c["guard_terminal"], &intent["guard"])?;
    drained(pid, iid, &c["held"]["pristine_root"])?;
    let active = n.show(RETENTION)?;
    let targets = &intent["link_identities"];
    let armed = active["ActiveState"] == "active";
    if armed {
        ensure!(
            hex(text(&intent["retention"], "InvocationID")?, 32) && active == intent["retention"],
            "retention was replaced or restarted"
        );
        same_terminal(&intent["producer"], &n.show(UNIT)?)?;
        same_terminal(&intent["guard"], &n.show(GUARD_UNIT)?)?;
        ensure!(
            n.show(TIMER)? == intent["timer"],
            "qualification timer changed before release"
        );
    } else {
        ensure!(
            active["ActiveState"] == "inactive" && active["Job"] == "",
            "ambiguous retention release"
        );
    }
    for (unit, target) in &links {
        for root in ["/etc/systemd/system", "/run/systemd/system"] {
            absent(&Path::new(root).join(format!("{unit}.d")))?;
        }
        absent(&Path::new("/run/systemd/system").join(unit))?;
        let path = Path::new("/etc/systemd/system").join(unit);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                ensure!(
                    armed && targets[unit.as_str()] == json!(installed_link(unit, target)?),
                    "qualification link or pinned retention was replaced"
                );
                fs::remove_file(path)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    File::open("/etc/systemd/system")?.sync_all()?;
    if armed {
        ensure!(
            n.show(RETENTION)? == intent["retention"],
            "retention changed before stop"
        );
        n.run("/usr/bin/systemctl", &["stop", RETENTION])?;
    }
    let after = collect_retired(n, &links)?;
    drained(pid, iid, &c["held"]["pristine_root"])?;
    let mut retired = json!({"schema":"horizon-singleton211-qualification-unit-retirement-v1","capture":capture_ref,"before":before,"boot_id":c["boot_id"],
        "unit_files":links,"after":after,"sealed_packages_and_diagnostics_preserved":true,"producer_restarted":false,
        "all_four_links_removed":true,"kernel_drained":true,"token_absent":true,"pristine_root_unchanged":true,
        "recorded_unix_seconds":now()?});
    deny_authority(&mut retired);
    let out = save_json(&n.root, "retirement-complete.json", &retired)?;
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn stop_fixture() -> (Value, Value, Value, Value, Value) {
        let iid = "a".repeat(32);
        let gid = "b".repeat(32);
        let plan = Bound::new("/var/lib/jetstreamer/guard/guard-plan.json", "c".repeat(64));
        let mut terminal = json!({"Id":UNIT,"LoadState":"loaded","InvocationID":iid,
            "MainPID":"0","ControlPID":"0","Job":"","NRestarts":"0","Restart":"no",
            "KillMode":"control-group","Delegate":"no","ExecMainCode":"2","ExecMainStatus":"15",
            "ActiveState":"inactive","SubState":"dead","Result":"success","ControlGroup":""});
        terminal["MemoryMax"] = json!(MEMORY.to_string());
        let guard = json!({"Id":GUARD_UNIT,"LoadState":"loaded","InvocationID":gid,
            "ActiveState":"inactive","SubState":"dead","MainPID":"0","ControlPID":"0","Job":"",
            "Result":"success","ExecMainCode":"1","ExecMainStatus":"0","NRestarts":"0","Restart":"no",
            "DropInPaths":"","StartLimitIntervalUSec":"0","MemoryMax":"268435456","MemorySwapMax":"0",
            "TasksMax":"64","Type":"oneshot","User":"root","ProtectSystem":"strict","ProtectHome":"read-only",
            "PrivateNetwork":"yes","NoNewPrivileges":"yes"});
        let c = json!({"producer_invocation_id":iid,"guard_invocation_id":gid,"producer_main_pid":42,
            "guard_plan":plan,"guard":Bound::new(GUARD,"d".repeat(64)),"receipts":"/receipts",
            "recorded_unix_seconds":100,"stop_intent":{"path":"/receipts/stop-intent.json"},
            "producer_terminal":terminal,"guard_terminal":guard});
        let gp = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":UNIT,
            "invocation_id":iid,"filesystem":"/","minimum_free_bytes":u64::MAX,"worker_root":ROOT,
            "maximum_root_physical_bytes":SCRATCH,"maximum_worker_vmas":3500000,"receipt_directory":"/receipts"});
        let sample = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1",
            "plan":plan.path,"plan_sha256":plan.sha256,"guard_sha256":c["guard"]["sha256"],
            "guard_invocation_id":gid,"producer_invocation_id":iid,"producer":{"invocation_id":iid,
                "pid":42,"active":"active","sub":"running","load_state":"loaded","result":"success",
                "restarts":0,"restart_policy":"no","kill_mode":"control-group","delegated":false,
                "cgroup":format!("/system.slice/{UNIT}")},"producer_stop_enabled":true,"trip_reason":"filesystem-floor",
            "minimum_free_bytes":u64::MAX,"available_bytes":1000,"maximum_root_physical_bytes":SCRATCH,
            "maximum_worker_vmas":3500000,"root_physical_observation":{"maximum_physical_bytes":SCRATCH,
                "exceeds_budget":false,"conservative_physical_bytes":8192},"workers":[],"bounded_measurement":false,
            "remote_mutations":false,"r2_mutations":false,"native_main":null,"worker_observation_error":null,
            "root_physical_observation_error":null,"canary_target_error":null,"target_handoff_error":null,
            "bounded_canary":null,"target_handoff":null,"recorded_unix_seconds":99});
        let intent = json!({"schema":"jetstreamer-horizon-standalone-stop-intent-v1","plan_sha256":plan.sha256,
            "producer_invocation_id":iid,"reason":"filesystem-floor","sample":sample});
        let completion = json!({"schema":"jetstreamer-horizon-standalone-stop-completion-v1","plan_sha256":plan.sha256,
            "producer_invocation_id":iid,"intent":"/receipts/stop-intent.json","scratch_deleted":false,
            "remote_mutations":false,"r2_mutations":false,"terminal":{"invocation_id":iid,"pid":0,
                "active":"inactive","sub":"dead","load_state":"loaded","result":"success","restarts":0,
                "restart_policy":"no","kill_mode":"control-group","delegated":false,"cgroup":""}});
        (c, gp, sample, intent, completion)
    }

    #[test]
    fn generic_guard_success_requires_original_stop_intent_and_completion() {
        let (c, gp, s, i, e) = stop_fixture();
        stop_records(&c, &gp, &s, &i, &e).unwrap();
        for (pointer, value) in [
            ("/trip_reason", json!("resume-stop-intent")),
            ("/producer/pid", json!(43)),
            ("/producer_stop_enabled", json!(false)),
            ("/workers", json!([[43, 20]])),
            ("/root_physical_observation/exceeds_budget", json!(true)),
            ("/native_main", json!({"main_pid":42})),
            ("/guard_sha256", json!("e".repeat(64))),
            ("/recorded_unix_seconds", json!(101)),
            ("/available_bytes", json!(u64::MAX)),
        ] {
            let mut bad = s.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            let mut intent = i.clone();
            intent["sample"] = bad.clone();
            assert!(
                stop_records(&c, &gp, &bad, &intent, &e).is_err(),
                "{pointer}"
            );
        }
        for key in [
            "worker_observation_error",
            "root_physical_observation_error",
            "native_main",
        ] {
            let mut bad = s.clone();
            bad.as_object_mut().unwrap().remove(key);
            assert!(
                stop_records(&c, &gp, &bad, &i, &e).is_err(),
                "missing {key}"
            );
        }
        for (key, value) in [
            ("schema", json!("horizon265-native-guard-stop-request-v1")),
            ("reason", json!("filesystem-floor-other")),
            ("sample", json!({})),
            ("producer_invocation_id", json!("f".repeat(32))),
        ] {
            let mut bad = i.clone();
            bad[key] = value;
            assert!(stop_records(&c, &gp, &s, &bad, &e).is_err(), "intent {key}");
        }
        for (pointer, value) in [
            ("/terminal/pid", json!(42)),
            ("/terminal/invocation_id", json!("f".repeat(32))),
            ("/intent", json!("/foreign/intent.json")),
            ("/scratch_deleted", json!(true)),
        ] {
            let mut bad = e.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                stop_records(&c, &gp, &s, &i, &bad).is_err(),
                "completion {pointer}"
            );
        }
        let mut bad = c.clone();
        bad["guard_terminal"]["Result"] = json!("exit-code");
        bad["guard_terminal"]["ExecMainStatus"] = json!("1");
        assert!(stop_records(&bad, &gp, &s, &i, &e).is_err());
    }

    #[test]
    fn clean_exit_timeout_and_replaced_producer_are_not_guard_stop() {
        let (c, _, _, _, _) = stop_fixture();
        let t = &c["producer_terminal"];
        let iid = text(&c, "producer_invocation_id").unwrap();
        killed(t, iid).unwrap();
        for (key, value) in [
            ("ExecMainCode", "1"),
            ("ExecMainStatus", "0"),
            ("Result", "timeout"),
            ("MainPID", "42"),
            ("ControlPID", "43"),
            ("Job", "22"),
            ("NRestarts", "1"),
            ("ActiveState", "failed"),
            ("InvocationID", "ffffffffffffffffffffffffffffffff"),
        ] {
            let mut bad = t.clone();
            bad[key] = json!(value);
            assert!(killed(&bad, iid).is_err(), "{key}");
        }
    }

    #[test]
    fn genuine_pid1_ordering_requires_unique_same_boot_events_in_original_window() {
        let (mut c, _, _, _, _) = stop_fixture();
        c["boot_id"] = json!("00000000-0000-0000-0000-000000000001");
        c["held"] = json!({"recorded_monotonic_us":120});
        c["recorded_monotonic_us"] = json!(180);
        let p = json!({"issued_monotonic_us":100,"expires_monotonic_us":200});
        let row = |unit: &str, iid: &Value, message: String, clock: &str| {
            json!({"_PID":"1","_UID":"0","UNIT":unit,
            "INVOCATION_ID":iid,"_BOOT_ID":"00000000000000000000000000000001","MESSAGE":message,"__MONOTONIC_TIMESTAMP":clock})
        };
        let producer = json!([
            row(
                UNIT,
                &c["producer_invocation_id"],
                format!("Started {UNIT} - full211."),
                "110"
            ),
            row(
                UNIT,
                &c["producer_invocation_id"],
                format!("Stopping {UNIT} - full211..."),
                "140"
            ),
            row(
                UNIT,
                &c["producer_invocation_id"],
                format!("{UNIT}: Deactivated successfully."),
                "150"
            )
        ]);
        let guard = json!([
            row(
                GUARD_UNIT,
                &c["guard_invocation_id"],
                format!("Starting {GUARD_UNIT} - guard..."),
                "130"
            ),
            row(
                GUARD_UNIT,
                &c["guard_invocation_id"],
                format!("{GUARD_UNIT}: Deactivated successfully."),
                "160"
            )
        ]);
        ordering(&c, &p, &producer, &guard).unwrap();
        for (pointer, value) in [
            ("/1/__MONOTONIC_TIMESTAMP", json!("129")),
            ("/2/__MONOTONIC_TIMESTAMP", json!("170")),
            ("/0/_PID", json!("42")),
            ("/1/_BOOT_ID", json!("f".repeat(32))),
            ("/2/INVOCATION_ID", json!("f".repeat(32))),
        ] {
            let mut bad = producer.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(ordering(&c, &p, &bad, &guard).is_err(), "{pointer}");
        }
        let mut duplicate = guard.clone();
        duplicate.as_array_mut().unwrap().push(guard[0].clone());
        assert!(ordering(&c, &p, &producer, &duplicate).is_err());
        c["recorded_monotonic_us"] = json!(200);
        assert!(ordering(&c, &p, &producer, &guard).is_err());
    }

    #[test]
    fn qualification_can_never_validate_a_replay_token_or_missing_acceptance() {
        assert!(operation(&json!({})).is_err());
        assert!(operation(&json!({"operation":"qualify-guard"})).unwrap());
        assert!(!operation(&json!({"operation":"launch"})).unwrap());
        assert!(
            gate::token(
                &json!({"operation":"qualify-guard"}),
                &Bound::new("/plan", "a".repeat(64)),
                &json!({}),
                &"b".repeat(32),
                42,
                100,
                100
            )
            .is_err()
        );
        assert!(
            accepted(
                &json!({}),
                &Bound::new(GUARD, "c".repeat(64)),
                &"d".repeat(64)
            )
            .is_err()
        );
    }

    #[test]
    fn pristine_identity_requires_complete_private_empty_root_shape() {
        let root = json!({"root":[1,2,4096,1000,0o40700,2,0,0,0,0],
            "output":[1,3,4096,1000,0o40700,2,0,0,0,0],
            "genesis_placeholder":[1,4,0,1000,0o100400,1,0,0,0,0]});
        root_record(&root).unwrap();
        assert!(root_record(&json!({})).is_err());
        for (pointer, value) in [
            ("/root/3", json!(0)),
            ("/output/4", json!(0o40755)),
            ("/genesis_placeholder/2", json!(1)),
            ("/genesis_placeholder/5", json!(2)),
        ] {
            let mut bad = root.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(root_record(&bad).is_err(), "{pointer}");
        }
    }
}
