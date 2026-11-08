use crate::*;
fn owned_sol(path: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    ensure!(
        unsafe { libc::chown(c.as_ptr(), 1001, 1003) } == 0,
        "sol private root ownership"
    );
    Ok(())
}
fn profile_child(
    r: &mut process::Runner<'_>,
    label: &str,
    mode: &str,
    spec: &Bound,
    sol: bool,
    work: &Path,
    control: &Path,
) -> Result<Value> {
    let mut c = Command::new("/usr/bin/systemd-run");
    c.args([
        "--wait",
        "--pipe",
        "--service-type=exec",
        "--unit",
        &format!("horizon-positive185-upstream-{}-{label}", r.iid),
    ]);
    let props = if sol {
        vec![
            "User=sol",
            "Group=horizon",
            "MemoryAccounting=yes",
            "MemoryHigh=51539607552",
            "MemoryMax=51539607552",
            "MemorySwapMax=0",
            "CPUQuota=400%",
            "TasksMax=1024",
            "RuntimeMaxSec=30",
            "TimeoutStopSec=2",
            "KillMode=control-group",
            "UMask=0077",
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ProtectHome=read-only",
            "PrivateTmp=yes",
            "PrivateDevices=yes",
            "PrivateNetwork=no",
            "CapabilityBoundingSet=",
            "AmbientCapabilities=",
            "LimitFSIZE=137438953472",
            "LimitCORE=0",
            "Environment=JETSTREAMER_ALLOW_CANDIDATE_RUNTIME=1",
        ]
    } else {
        vec![
            "User=root",
            "Group=root",
            "MemoryMax=512M",
            "MemorySwapMax=0",
            "CPUQuota=100%",
            "TasksMax=512",
            "RuntimeMaxSec=30",
            "NoNewPrivileges=yes",
            "PrivateNetwork=yes",
            "ProtectSystem=strict",
            "ProtectHome=read-only",
            "PrivateTmp=yes",
            "PrivateDevices=yes",
            "CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_SYS_PTRACE",
            "AmbientCapabilities=CAP_CHOWN CAP_DAC_OVERRIDE CAP_SYS_PTRACE",
            "LimitNOFILE=1048576:1048576",
        ]
    };
    c.arg("--property=Restart=no");
    for p in props {
        c.arg(format!("--property={p}"));
    }
    if sol {
        c.arg(format!("--property=WorkingDirectory={}", work.display()));
        c.arg(format!(
            "--property=ReadWritePaths={} {}",
            work.display(),
            control.display()
        ));
    }
    c.arg(&r.self_image.path).arg(mode).arg(&spec.path).args([
        "--request-sha256",
        &spec.sha256,
        "--self-sha256",
        &r.self_image.sha256,
    ]);
    let v = r.run(label, c, Duration::from_secs(35))?;
    process::stdout_json(&v)
}
pub fn qualify(v: &Value, r: &mut process::Runner<'_>) -> Result<()> {
    let reader_control = binding(&v["reader_lifecycle_control"])?;
    crate::persistent_reader::validate_control(r, &reader_control)?;
    let prior = binding(&v["original_v19_negative"])?;
    let p = storage::json(&prior)?;
    ensure!(
        p["schema"] == "horizon-epoch185-original-missing-token-negative-actual-acceptance-v1"
            && p["cgroup_absent_or_drained"] == true
            && p["all_four_artifact_directories_empty"] == true
            && p["no_main_useful_work_release_or_replay_claimed"] == true,
        "genuine original negative capability required"
    );
    let external_work = PathBuf::from(text(v, "profile_sol_run_root")?);
    let external_control = PathBuf::from(text(v, "profile_sol_control_root")?);
    for path in [&external_work, &external_control] {
        ensure!(
            path.parent() == Some(Path::new("/home/sol/.jetstreamer-private"))
                && path
                    .file_name()
                    .and_then(|x| x.to_str())
                    .is_some_and(|x| x.starts_with("epoch185-positive-profile-control-")),
            "fixed separate sol control namespace"
        );
        owned_sol(path)?;
    }
    let spec = storage::save(
        r.root,
        "kernel-control-only.json",
        &json!({"schema":"horizon-positive185-kernel-profile-control-only-v1","sol_run_root":external_work,"sol_control_root":external_control,"no_input_or_replay":true}),
    )?;
    let dest = Path::new("/usr/local/lib/jetstreamer").join(format!(
        "horizon-epoch185-positive-profile-control-{}",
        r.iid
    ));
    let sealed = seal(r, "profile-spec", &dest, &[("spec.json", spec)])?;
    let sb = binding(&sealed["members"]["spec.json"])?;
    let root_result = profile_child(
        r,
        "root-profile",
        "kernel-root-check",
        &sb,
        false,
        &external_work,
        &external_control,
    )?;
    ensure!(
        root_result["effective_CHOWN_DAC_OVERRIDE_SYS_PTRACE"] == true
            && n(&root_result, "actual_fd_soft_limit")? >= 1000000,
        "real Root envelope control"
    );
    let sol_result = profile_child(
        r,
        "sol-profile",
        "kernel-sol-check",
        &sb,
        true,
        &external_work,
        &external_control,
    )?;
    ensure!(
        sol_result["actual_private_work_control_writes_and_retirement_passed"] == true
            && sol_result["actual_sol_uid"] == 1001,
        "real sol namespace control"
    );
    let mut originals = Vec::new();
    for i in 0..8 {
        let name = format!("control-{i}.json");
        let b = storage::save(
            r.root,
            &name,
            &json!({"schema":"horizon-positive185-eight-file-kernel-control-only-v1","index":i,"not_an_operational_receipt":true}),
        )?;
        originals.push((name, b));
    }
    let members = originals
        .iter()
        .map(|(n, b)| (n.as_str(), b.clone()))
        .collect::<Vec<_>>();
    let view_dest = Path::new("/usr/local/lib/jetstreamer").join(format!(
        "horizon-epoch185-positive-final-views-profile-{}",
        r.iid
    ));
    let views = seal(r, "eight-views", &view_dest, &members)?;
    let mut c = Command::new("/usr/bin/systemd-run");
    c.args([
        "--wait",
        "--pipe",
        "--service-type=exec",
        "--unit",
        &format!("horizon-positive185-upstream-{}-sol-eight", r.iid),
    ]);
    for p in [
        "User=sol",
        "Group=horizon",
        "Restart=no",
        "MemoryMax=512M",
        "MemorySwapMax=0",
        "CPUQuota=100%",
        "TasksMax=64",
        "RuntimeMaxSec=5",
        "TimeoutStopSec=1",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "PrivateTmp=yes",
        "PrivateDevices=yes",
        "PrivateNetwork=yes",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
    ] {
        c.arg(format!("--property={p}"));
    }
    c.arg(FINAL)
        .args(["sol-read-check", "--self-sha256", FINAL_SHA]);
    for (name, _) in &originals {
        let b = binding(&views["members"][name])?;
        c.arg(&b.path).arg(&b.sha256);
    }
    let read_result =
        process::stdout_json(&r.run("actual-c71-sol-eight", c, Duration::from_secs(8))?)?;
    ensure!(
        read_result["actual_sol_uid"] == 1001
            && read_result["actual_horizon_gid"] == 1003
            && read_result["all_eight_exact_bound_files_read"] == true,
        "actual c71 eight-file sol read"
    );
    let proof = storage::save(
        r.root,
        "route-capability.json",
        &json!({"schema":"horizon-positive185-final-route-capability-v2","executor":fixed(FINAL,FINAL_SHA),"helper":fixed(HELPER,HELPER_SHA),"driver":fixed(DRIVER,DRIVER_SHA),"scope":"one-original-post-reader-release-attempt","original_setup_seconds":600,"all_raw_obligations_and_live_guards_preserved":true,"original_writer_custody_supported":true,"bounded_probe_only":true,"full_boundary_route_qualified":false,"retained_source_base_helper_sha256":"50b2b6636068811d1176f87f5d49b76206db785dcb1e0ac80023c517cefac07a","native_capture_image":fixed(NATIVE,NATIVE_SHA),"original_v19_negative":prior,"actual_persistent_reader_lifecycle_control":reader_control,"actual_root_profile":root_result,"actual_sol_profile":sol_result,"actual_c71_sol_eight_file_read":read_result,"actual_eight_file_control_package":views,"original_start_request_policy_source":process::bind_file(Path::new("/usr/local/lib/jetstreamer/horizon-positive185-start-request-policy-source-20261108-v2/start_request.rs"),1<<20)?,"original_start_request_policy_normal_seal":process::bind_file(Path::new("/usr/local/lib/jetstreamer/horizon-positive185-start-request-policy-source-20261108-v2/deployment-seal-receipt.json"),4<<20)?,"actual_start_request_common_control":process::bind_file(Path::new("/usr/local/lib/jetstreamer/horizon-positive185-start-request-common-control-20261108-v1/actual-held-reload-control.json"),4<<20)?,"start_request_common_control_normal_seal":process::bind_file(Path::new("/usr/local/lib/jetstreamer/horizon-positive185-start-request-common-control-20261108-v1/deployment-seal-receipt.json"),4<<20)?,"original_start_request_common_qualification":process::bind_file(Path::new("/usr/local/lib/jetstreamer/horizon-positive185-start-request-common-control-20261108-v1/completion.json"),4<<20)?,"metadata_control_not_native_input_or_positive_replay_capability":true,"fresh_admission_ready_task_fleet_reader_and_original_release_still_required":true,"publication_authorized":false}),
    )?;
    let route = storage::save(
        r.root,
        "qualified-route.json",
        &json!({"schema":"horizon-positive185-final-qualified-route-v1","purpose":"bounded_prefix_probe","helper":role(HELPER,HELPER_SHA)?,"driver":fixed(DRIVER,DRIVER_SHA),"driver_normal_seal":process::bind_file(&Path::new(DRIVER).with_file_name("deployment-seal-receipt.json"),16<<20)?,"capability_acceptance":{"path":Path::new("/usr/local/lib/jetstreamer").join(format!("horizon-epoch185-positive-qualified-route-{}/capability.json",r.iid)),"sha256":proof.sha256}}),
    )?;
    let dest = Path::new("/usr/local/lib/jetstreamer").join(format!(
        "horizon-epoch185-positive-qualified-route-{}",
        r.iid
    ));
    let result = seal(
        r,
        "route-capability",
        &dest,
        &[("capability.json", proof), ("route.json", route)],
    )?;
    println!("{}", result);
    Ok(())
}
fn replace(v: &Value, bindings: &Value) -> Result<Value> {
    if let Some(m) = v.as_object() {
        if m.len() == 1 && m.contains_key("$actual_root_binding") {
            let key = text(v, "$actual_root_binding")?;
            return bindings
                .get(key)
                .cloned()
                .with_context(|| format!("missing actual dynamic {key}"));
        }
        return Ok(Value::Object(
            m.iter()
                .map(|(k, v)| Ok((k.clone(), replace(v, bindings)?)))
                .collect::<Result<_>>()?,
        ));
    }
    if let Some(a) = v.as_array() {
        return Ok(json!(
            a.iter()
                .map(|x| replace(x, bindings))
                .collect::<Result<Vec<_>>>()?
        ));
    }
    Ok(v.clone())
}
fn published_members(root: &Path, dest: &Path, members: &[(&str, Bound)]) -> Value {
    let _ = root;
    json!(
        members
            .iter()
            .map(|(n, b)| (
                n.to_string(),
                json!({"path":dest.join(n),"sha256":b.sha256})
            ))
            .collect::<serde_json::Map<_, _>>()
    )
}
fn memory_available() -> Result<u64> {
    let s = fs::read_to_string("/proc/meminfo")?;
    let x = s
        .lines()
        .find(|x| x.starts_with("MemAvailable:"))
        .context("MemAvailable")?;
    Ok(x.split_whitespace()
        .nth(1)
        .context("MemAvailable amount")?
        .parse::<u64>()?
        * 1024)
}
fn filesystem() -> Result<(u64, u64)> {
    let p = c"/home/sol";
    let mut x = unsafe { std::mem::zeroed::<libc::statvfs>() };
    ensure!(
        unsafe { libc::statvfs(p.as_ptr(), &mut x) } == 0,
        "protected filesystem sample"
    );
    Ok((
        x.f_bavail
            .checked_mul(x.f_frsize)
            .context("free overflow")?,
        x.f_favail,
    ))
}
fn no_unbooked_native163(r: &mut process::Runner<'_>, raw: &Value) -> Result<()> {
    let name = "horizon-epoch163-native-input-20261106-v1.service";
    let observed = r.native(name)?;
    if observed["ActiveState"] == "active" || observed["ActiveState"] == "activating" {
        let rows = raw["active_peer_allocations"]
            .as_array()
            .context("complete raw allocations")?;
        ensure!(
            rows.iter()
                .any(|x| x["unit"] == name && x["invocation_id"] == observed["InvocationID"]),
            "native163 exists outside current185 typed projection: Root must qualify exact additive128GiB/40GiB phase accounting before alternate admission"
        );
    }
    Ok(())
}
pub fn start(v: &Value, r: &mut process::Runner<'_>) -> Result<()> {
    require_qualified_fleet_helper()?;
    let reader_control = binding(&v["reader_lifecycle_control"])?;
    crate::persistent_reader::validate_control(r, &reader_control)?;

    let pool_closure = binding(&v["normal_pool_closure"])?;
    let actual_pool = verify_closed_pool(r, &pool_closure)?;
    let assembly_bound = binding(&v["assembly"])?;
    let a: Assemble = serde_json::from_value(storage::json(&assembly_bound)?)?;
    generation(&a.generation)?;
    let manifest_bound = binding(&v["planner_manifest"])?;
    let manifest = storage::json(&manifest_bound)?;
    ensure!(
        manifest["program"] == json!(fixed(PLANNER, PLANNER_SHA))
            && manifest["complete_tuple"] == json!(a.complete_tuple)
            && manifest["profile"]["purpose"] == "bounded_native_probe"
            && manifest["admission_issued"] == false,
        "qualified positive planner actual manifest"
    );
    let output = manifest["outputs"].as_array().context("planner outputs")?;
    let find = |leaf: &str| -> Result<Bound> {
        let rows = output
            .iter()
            .filter(|b| {
                b["path"].as_str().is_some_and(|p| {
                    Path::new(p).file_name().and_then(|n| n.to_str()) == Some(leaf)
                })
            })
            .collect::<Vec<_>>();
        ensure!(rows.len() == 1, "exact planner output {leaf}");
        binding(rows[0])
    };
    let projection = storage::json(&find("RESOURCE_PLAN_NOT_ADMISSION.json")?)?;
    let templates = storage::json(&find("POSITIVE_TEMPLATES_UNISSUED.json")?)?;
    ensure!(
        projection["candidate_actor_memory_bytes"] == 48u64 << 30
            && projection["future_guard_memory_bytes"] == 256u64 << 20
            && projection["candidate_DATA_bytes"] == 549890031616u64
            && projection["normal_external_pool_bytes_counted_once"] == 6u64 << 30
            && projection["additional_QA_memory_bytes"] == 0
            && projection["admission_authorized"] == false,
        "unchanged exact positive resource projection"
    );
    let tuple = storage::json(&a.complete_tuple)?;
    let components = storage::json(&binding(&tuple["components"])?)?;
    let memory_bound = binding(&components["actual_memory_selection"])?;
    let data_bound = binding(&components["actual_DATA_selection"])?;
    let memory = storage::json(&memory_bound)?;
    let current = &memory["selection"]["request"]["current"];
    let reader_bound = binding(&memory["selection"]["request"]["current_reader"])?;
    let reader = storage::json(&reader_bound)?;
    ensure!(
        reader["image"] == json!(fixed(HELPER, HELPER_SHA))
            && now()?
                .checked_sub(n(&reader, "recorded_unix_seconds")?)
                .is_some_and(|x| x < 300),
        "genuine original helper13 reader fresh before admission"
    );
    let raw = storage::json(&binding(&reader["accounting"])?)?;
    no_unbooked_native163(r, &raw)?;
    let obs = storage::json(&binding(&current["observer"])?)?;
    let fleet = storage::json(&binding(&current["fleet"])?)?;
    let sample = utc(text(&fleet, "sampled_at_utc")?)?;
    let status = storage::json(&a.status_readback)?;
    let stamp = utc(text(&status["after_status"], "sampled_at_utc")?)?;
    let at = now()?;
    ensure!(
        at >= sample && at >= stamp && at + 900 < sample + 1800 && at + 900 < stamp + 1800,
        "original observer/status clock cannot fund600s setup and margin"
    );
    let total = n(&projection, "projected_total_memory_bytes")?;
    let host = n(&obs["host_memory"], "total_kib")?
        .checked_mul(1024)
        .context("host memory overflow")?;
    let available = memory_available()?;
    let minimum = n(
        &projection,
        "inherited_exporter_available_memory_floor_bytes",
    )?
    .checked_add(6u64 << 30)
    .and_then(|x| x.checked_add((48u64 << 30) + (256u64 << 20)))
    .context("available floor overflow")?;
    let (actual_free, inodes) = filesystem()?;
    let free = actual_free.min(n(&obs["filesystem"], "conservative_available_bytes")?);
    let data_floor = n(&projection, "minimum_free_bytes_for_future_template")?
        .checked_add(n(&projection, "candidate_DATA_bytes")?)
        .context("DATA floor overflow")?;
    let cpu = n(&projection, "projected_replay_plus_candidate_CPU_micros")? + 2_000_000;
    let mut cpus = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
    ensure!(
        unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut cpus) }
            == 0,
        "actual affinity"
    );
    let cores = unsafe { libc::CPU_COUNT(&cpus) } as u64;
    ensure!(
        total < host
            && available >= minimum
            && free >= data_floor
            && inodes >= 131072
            && cpu <= cores * 1_000_000,
        "fresh full resource admission failed"
    );
    for path in ["/proc/pressure/memory", "/proc/pressure/io"] {
        let s = fs::read_to_string(path)?;
        for line in s.lines().filter(|l| l.starts_with("full ")) {
            let x = line
                .split_whitespace()
                .find_map(|x| x.strip_prefix("avg10="))
                .context("PSI full avg10")?
                .parse::<f64>()?;
            ensure!(x <= 1.0, "actual full PSI exceeds one percent");
        }
    }
    let route_bound = binding(&v["qualified_route"])?;
    let route = storage::json(&route_bound)?;
    ensure!(
        route["purpose"] == "bounded_prefix_probe"
            && route["helper"]["image"] == json!(fixed(HELPER, HELPER_SHA)),
        "same-image qualified finite route"
    );
    let capability = storage::json(&binding(&route["capability_acceptance"])?)?;
    ensure!(
        capability["actual_persistent_reader_lifecycle_control"] == json!(reader_control),
        "route capability must bind this genuine reader lifecycle control"
    );
    let actor = text(&templates["envelope"]["plan"], "unit")?;
    let guard = text(&templates["envelope"], "guard_unit")?;
    let timer = text(&templates["envelope"], "timer_unit")?;
    for name in [actor, guard, timer] {
        let n = r.native(name)?;
        ensure!(
            n["ActiveState"] == "inactive" && n["InvocationID"] == "" && n["Job"] == "",
            "fresh dormant native family"
        );
        for dir in ["/etc/systemd/system", "/run/systemd/system"] {
            ensure!(
                Path::new(dir).join(name).symlink_metadata().is_err(),
                "no existing manager path"
            );
        }
    }
    let runroot = PathBuf::from(text(&templates["envelope"]["plan"], "run_root")?);
    let control = PathBuf::from(text(&templates["envelope"], "control_root")?);
    for p in [&runroot, &control] {
        owned_sol(p)?;
    }
    for p in [
        PathBuf::from(REGISTRY),
        PathBuf::from(text(&templates["envelope"], "guard_receipt_root")?),
    ] {
        if !p.try_exists()? {
            make_private(&p)?;
        }
    }
    let token_parent = PathBuf::from(text(&templates["envelope"], "token_root")?);
    if !token_parent.try_exists()? {
        fs::DirBuilder::new().mode(0o755).create(&token_parent)?;
    }
    let tm = fs::symlink_metadata(&token_parent)?;
    ensure!(
        token_parent.canonicalize()? == token_parent
            && tm.is_dir()
            && tm.uid() == 0
            && tm.gid() == 0
            && tm.mode() & 0o777 == 0o755,
        "immutable public token parent must be Root0755 for actual sol reads"
    );
    let log = control.join("private-stdout-stderr.log");
    let fd = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&log)?;
    ensure!(
        unsafe { libc::fchown(std::os::fd::AsRawFd::as_raw_fd(&fd), 1001, 1003) } == 0,
        "actual private actor log ownership"
    );
    fd.sync_all()?;
    let envelope_template = &templates["envelope"];
    let evidence_dest = Path::new(text(&envelope_template["admission"], "path")?)
        .parent()
        .context("evidence destination")?;
    let mut proofs = vec![
        ("current-full-reader.json", reader_bound),
        ("current-frame.json", binding(&current["frame"])?),
        ("typed-memory.json", memory_bound),
        ("typed-data.json", data_bound),
        ("fleet-owner.json", binding(&current["fleet"])?),
        ("status-readback.json", a.status_readback.clone()),
    ];
    let issued = now()?;
    let expires = issued
        .checked_add(a.useful_runtime_seconds + 720)
        .context("admission expiry overflow")?;
    ensure!(expires - issued <= 259800, "native finite duration");
    let acceptance = storage::save(
        r.root,
        "root-acceptance.json",
        &json!({"schema":"horizon-epoch185-independent-Root-positive-admission-acceptance-v1","epoch":185,"unit":actor,"issued_at":issued,"creation_deadline":issued+120,"actual_full_reader_accepted":true,"actual_raw_obligations_preserved":true,"all_independent_phases_counted_once":true,"resource_credit_bytes":0,"candidate_actor_memory_bytes":48u64<<30,"future_guard_memory_bytes":256u64<<20,"projected_memory_bytes":total,"host_total_bytes":host,"actual_MemAvailable_bytes":available,"minimum_available_memory_bytes":minimum,"actual_free_DATA_bytes":free,"required_DATA_bytes":data_floor,"actual_free_inodes":inodes,"actual_affinity_CPU_count":cores,"required_CPU_micros":cpu,"qualified_planner_manifest":manifest_bound,"original_complete_tuple":a.complete_tuple,"qualified_route":route_bound,"source_admission_checks":r.self_image,"ordinary_full_replay_authorized":false,"publication_authorized":false}),
    )?;
    proofs.push(("root-acceptance.json", acceptance));
    let proof_map = published_members(r.root, evidence_dest, &proofs);
    let mut bindings = json!({"admission.issued_at_original":issued,"admission.expires_at_original":expires,"root_acceptance.actual_full_reader_accepted":true,"root_acceptance.actual_raw_obligations_preserved":true});
    for (k, name) in [
        ("current_full_reader", "current-full-reader.json"),
        ("current_frame", "current-frame.json"),
        ("typed_memory", "typed-memory.json"),
        ("typed_data", "typed-data.json"),
        ("fleet_owner", "fleet-owner.json"),
        ("status_readback", "status-readback.json"),
        ("root_acceptance", "root-acceptance.json"),
    ] {
        bindings[format!("{k}.sha256")] = proof_map[name]["sha256"].clone();
    }
    let admission = storage::save(
        r.root,
        "admission.json",
        &replace(&templates["admission"], &bindings)?,
    )?;
    let admission_sha = admission.sha256.clone();
    proofs.push(("admission.json", admission));
    let evidence = seal(r, "evidence", evidence_dest, &proofs)?;
    bindings["materialized.admission.sha256"] = json!(admission_sha);
    let envelope = storage::save(
        r.root,
        "envelope.json",
        &replace(envelope_template, &bindings)?,
    )?;
    let envelope_dest = Path::new(text(envelope_template, "actor_service_path")?)
        .parent()
        .context("unit destination")?;
    let envelope_path = text(
        &templates["task_capture_spec"]["native_spec"]["envelope"],
        "path",
    )?;
    let envelope_package = Path::new(envelope_path)
        .parent()
        .context("envelope package")?;
    let envelope_seal = seal(
        r,
        "envelope",
        envelope_package,
        &[("envelope.json", envelope.clone())],
    )?;
    let mut unit_members = Vec::new();
    for (name, key) in [(actor, "actor"), (guard, "guard"), (timer, "timer")] {
        let raw = templates[key]
            .as_str()
            .context("unit text")?
            .replace("__ACTUAL_ENVELOPE_SHA256__", &envelope.sha256);
        ensure!(
            !raw.contains("__ACTUAL_"),
            "all exact unit bindings resolved"
        );
        unit_members.push((name, write_bytes(r.root, name, raw.as_bytes())?));
    }
    let unit_seal = seal(r, "units", envelope_dest, &unit_members)?;
    ensure!(
        now()? < issued + 120,
        "original creation window expired before manager mutation"
    );
    let before_timer = r.native(timer)?;
    ensure!(
        before_timer["LastTriggerUSecMonotonic"] == "0",
        "timer never triggered"
    );
    let timers_before = crate::timers::capture(r, "before")?;
    for (name, _) in &unit_members {
        std::os::unix::fs::symlink(
            envelope_dest.join(name),
            Path::new("/etc/systemd/system").join(name),
        )?;
    }
    let mut reload = Command::new("/usr/bin/systemctl");
    reload.arg("daemon-reload");
    r.run("one-reload", reload, Duration::from_secs(15))?;
    let timers_after = crate::timers::capture_after(r, "after", &timers_before)?;
    let audit = crate::timers::validate(&timers_before, &timers_after)?;
    storage::save(r.root, "original-timers-before.json", &timers_before)?;
    storage::save(r.root, "original-timers-after.json", &timers_after)?;
    storage::save(r.root, "original-reload-timer-audit.json", &audit)?;
    let ctx = storage::save(
        r.root,
        "original-activation-context.json",
        &json!({"schema":"horizon-positive185-original-upstream-activation-v1","assembly":assembly_bound,"planner_manifest":manifest_bound,"qualified_route":route_bound,"actor":actor,"guard":guard,"timer":timer,"run_root":runroot,"control_root":control,"envelope":envelope_seal["members"]["envelope.json"],"admission":evidence["members"]["admission.json"],"task_capture_template":templates["task_capture_spec"],"prelaunch_current":current,"issued_at":issued,"expires_at":expires,"generation":a.generation,"no_retry_or_clock_reset":true,"unit_seal":unit_seal,"normal_pool_closure":pool_closure,"actual_pool_revalidation":actual_pool}),
    )?;
    let mut start = Command::new("/usr/bin/systemctl");
    start.args(["--no-block", "start", actor]);
    r.run("start-one-original-actor", start, Duration::from_secs(5))?;
    storage::save(
        r.root,
        "original-automatic-follow-on.json",
        &json!({"activation":ctx,"original_setup600_not_renewed":true}),
    )?;
    crate::follow_on::continue_from_activation(&ctx, r)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dynamic_outputs_never_get_predicted_digests() {
        let template =
            json!({"bound":{"$actual_root_binding":"actual.sha256"},"retained":"unchanged"});
        assert!(replace(&template, &json!({})).is_err());
        let out = replace(&template, &json!({"actual.sha256":"a".repeat(64)})).unwrap();
        assert_eq!(out["bound"], "a".repeat(64));
        assert_eq!(out["retained"], "unchanged");
    }
    #[test]
    fn profile_namespace_rejects_old_missing_token_and_path_escape() {
        for x in ["missing-token-legacy", "positive-../escape", "positive bad"] {
            assert!(generation(x).is_err());
        }
        generation("positive-native-20261108-v1").unwrap();
    }
}
