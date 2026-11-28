//! Admit the exact workerless 226 archive assembly and register its live guard.
use super::{drain, suffix, *};
use horizon_singleton211_launch::native262::foundation_roster::{self, assembly226 as spec};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

const RELEASE: &str = "/var/lib/jetstreamer/horizon226-assembly-fleet-v1/acceptance.json";
const PRESTART: &str = "/var/lib/jetstreamer/horizon226-suffix-v1/pre-start.sh";
const PRESTART_SHA: &str = "14c316bf3fc8ff28800c9b7bb673f42f95995a2a2b1ac0b9654c36c0a83832e0";
const LEASE: &str = "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-226.lock";

fn path(name: &str) -> PathBuf {
    Path::new(spec::STATE).join(name)
}

fn static_inputs() -> Result<(Value, Value, Value)> {
    let preflight = sealed_json(
        &json!({"path":spec::PREFLIGHT.0,"sha256":spec::PREFLIGHT.1}),
        Path::new(spec::PREFLIGHT.0),
    )?;
    let source = json!({"path":spec::SOURCES.0,"sha256":spec::SOURCES.1});
    let handoff = sealed_json(&source, Path::new(spec::SOURCES.0))?;
    let guard_fixture = Path::new(spec::PREFLIGHT.0).with_file_name("guard-plan-fixture.json");
    let guard = sealed_json(&preflight["static_guard_plan"], &guard_fixture)?;
    ensure!(
        preflight["sources"] == source
            && preflight["unit"] == spec::UNIT
            && preflight["run_root"] == spec::ROOT
            && preflight["lease"] == LEASE
            && preflight["scope_sha256"] == handoff["stage_sha256"]
            && preflight["guard"] == json!({"path":drain::GUARD_IMAGE,"sha256":GUARD_SHA})
            && preflight["static_guard_check"]["plan_sha256"]
                == preflight["static_guard_plan"]["sha256"]
            && preflight["static_guard_check"]["validated"] == true
            && guard["unit"] == spec::UNIT
            && guard["worker_root"] == spec::ROOT
            && guard["minimum_free_bytes"] == SHARED_FLOOR
            && guard["maximum_root_physical_bytes"] == spec::CAP
            && handoff["stage"]["operation"] == "assemble",
        "epoch 226 assembly source or sandbox proof differs"
    );
    for (key, asset, limit) in [
        ("node", spec::NODE.0, 256 << 20),
        ("guard", drain::GUARD_IMAGE, 4 << 20),
    ] {
        suffix::bytes(&preflight[key], Path::new(asset), limit)?;
    }
    suffix::bytes(
        &json!({"path":PRESTART,"sha256":PRESTART_SHA}),
        Path::new(PRESTART),
        4096,
    )?;
    let archives = preflight["bound_archives"]
        .as_array()
        .context("assembly source archives")?;
    ensure!(
        archives.len() == 2,
        "epoch 226 assembly requires both segments"
    );
    for (item, label) in archives.iter().zip(["prefix", "suffix"]) {
        let evidence = &handoff["stage"][format!("{label}_archive")];
        let file = Path::new(
            item["path"]
                .as_str()
                .context("assembly source archive path")?,
        );
        let info = file.symlink_metadata()?;
        let stamp = json!([
            info.dev(),
            info.ino(),
            info.size(),
            info.mode(),
            info.uid(),
            info.nlink(),
            info.mtime_nsec() + info.mtime() * 1_000_000_000,
            info.ctime_nsec() + info.ctime() * 1_000_000_000
        ]);
        ensure!(
            info.is_file()
                && file.canonicalize()? == file
                && item["path"] == evidence["path"]
                && item["sha256"] == evidence["sha256"]
                && item["identity"] == stamp
                && handoff[format!("{label}_identity")] == stamp,
            "epoch 226 {label} archive changed after sandbox preflight"
        );
    }
    Ok((preflight, handoff, guard))
}

fn installed() -> Result<()> {
    let release = suffix::document(Path::new(RELEASE))?;
    let executable = env::current_exe()?;
    let control = Path::new(drain::CYCLE_LOCK)
        .parent()
        .context("Foundation controller path")?;
    ensure!(
        release["schema"] == "foundation-epoch226-private-assembly-fleet-release-v1"
            && release["assembly_only_no_replay"] == true
            && release["publication_authorized"] == false
            && release["preflight"] == json!({"path":spec::PREFLIGHT.0,"sha256":spec::PREFLIGHT.1})
            && release["fleet"] == private157::file_binding(&executable)?,
        "epoch 226 private assembly launcher is outside the accepted fleet release"
    );
    for name in [
        "cycle.py",
        "native_binding_replays.py",
        "diagnostic226_assembly.py",
    ] {
        suffix::bytes(&release["installed"][name], &control.join(name), 1 << 20)?;
    }
    Ok(())
}

fn argv(plan: &Value) -> Result<Vec<String>> {
    ensure!(
        plan["path"] == json!(path("plan.json")) && canonical_digest(&plan["sha256"]),
        "epoch 226 assembly plan reference changed"
    );
    Ok(vec![
        spec::NODE.0.into(),
        "226".into(),
        format!("{}/ledger", spec::ROOT),
        "--verify".into(),
        format!(
            "--checkpoint-continuation-plan={}",
            path("plan.json").display()
        ),
        format!(
            "--checkpoint-continuation-plan-sha256={}",
            plan["sha256"].as_str().context("plan digest")?
        ),
    ])
}

fn service_args(preflight: &Value, plan: &Value) -> Result<Vec<String>> {
    let mut inputs = Vec::new();
    for item in preflight["bound_archives"]
        .as_array()
        .context("archive paths")?
    {
        let source = Path::new(item["path"].as_str().context("source path")?);
        inputs.push(
            source
                .parent()
                .context("source parent")?
                .to_str()
                .context("source parent UTF-8")?,
        );
    }
    let mut args = vec![
        format!("--unit={}", spec::UNIT),
        "--slice=system.slice".into(),
        "--no-block".into(),
        "--description=Assemble the private full epoch 226 archive".into(),
    ];
    for property in [
        "Type=exec",
        "User=ubuntu",
        "Group=ubuntu",
        "UMask=0077",
        "Restart=no",
        "KillMode=control-group",
        "Delegate=no",
        "CPUQuota=800%",
        "MemoryHigh=137438953472",
        "MemorySwapMax=0",
        "TasksMax=512",
        "RuntimeMaxSec=14400",
        "TimeoutStartSec=180",
        "TimeoutStopSec=180",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "ProtectControlGroups=yes",
        "PrivateTmp=yes",
        "PrivateNetwork=yes",
        "NoNewPrivileges=yes",
        "RestrictAddressFamilies=AF_UNIX",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "UnsetEnvironment=HORIZON_S3_ENDPOINT HORIZON_ACCESS_KEY_ID HORIZON_SECRET_ACCESS_KEY HORIZON_PUBLIC_BASE_URL AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN",
    ] {
        args.push(format!("--property={property}"));
    }
    args.extend([
        format!("--property=AllowedCPUs={}", spec::CPUS),
        format!("--property=CPUAffinity={}", spec::CPUS),
        format!("--property=MemoryMax={}", spec::MEMORY),
        format!("--property=LimitFSIZE={}", spec::CAP),
        format!("--property=ReadWritePaths={} {LEASE}", spec::ROOT),
        format!(
            "--property=ReadOnlyPaths={} {}",
            spec::STATE,
            inputs.join(" ")
        ),
        format!(
            "--property=ExecStartPre=/usr/bin/bash {PRESTART} 60 {}/tokens",
            spec::STATE
        ),
        "--setenv=RUST_LOG=info".into(),
        "--setenv=RUST_MIN_STACK=134217728".into(),
        "--setenv=RAYON_NUM_THREADS=8".into(),
        "--setenv=TOKIO_WORKER_THREADS=8".into(),
        "--".into(),
    ]);
    args.extend(argv(plan)?);
    Ok(args)
}

fn sample(
    dir: &Path,
    id: &str,
    guard: &Value,
    state: &str,
    pid: u64,
) -> Result<Option<(Value, Value)>> {
    let Some(reference) = suffix::guard_sample(dir, id, guard, state, pid)? else {
        return Ok(None);
    };
    let path = Path::new(reference["path"].as_str().context("guard receipt path")?);
    let body = root_bound_json(&reference, path, 0o022)?;
    ensure!(
        body["workers"] == json!([]) && body["trip_reason"].is_null(),
        "epoch 226 assembly guard observed workers or a trip"
    );
    Ok(Some((reference, body)))
}

fn active_clock() -> Result<Value> {
    let clock = drain::show(spec::TIMER)?;
    ensure!(
        clock["ActiveState"] == "active"
            && clock["Unit"] == spec::GUARD_SERVICE
            && iid(&clock["InvocationID"])
            && suffix::next_timer(spec::TIMER)? > suffix::monotonic_usec()?,
        "epoch 226 private assembly guard timer is unavailable"
    );
    Ok(clock)
}

fn register(id: &str, token: &Value) -> Result<Value> {
    let token_path = path(&format!("tokens/{id}/guard-admission.json"));
    let release = sealed_json(token, &token_path)?;
    ensure!(
        release["invocation_id"] == id && release["unit"] == spec::UNIT,
        "epoch 226 assembly token belongs to another service"
    );
    let guard = &release["guard_plan"];
    let expected = argv(&release["plan"])?;
    let (pid, guard_sample) = suffix::wait(105, "assembly running and protected", || {
        let owner = drain::show(spec::UNIT)?;
        ensure!(
            owner["ActiveState"] != "failed",
            "epoch 226 assembly failed before enrollment"
        );
        if owner["ActiveState"] != "active" || owner["SubState"] != "running" {
            return Ok(None);
        }
        let pid: u64 = owner["MainPID"]
            .as_str()
            .context("assembly main PID")?
            .parse()?;
        let proc = PathBuf::from(format!("/proc/{pid}"));
        ensure!(
            owner["InvocationID"] == id
                && owner["NRestarts"] == "0"
                && pid > 1
                && owner["ControlGroup"] == format!("/system.slice/{}", spec::UNIT)
                && fs::read_link(proc.join("exe"))? == Path::new(spec::NODE.0)
                && fs::read(proc.join("cmdline"))? == (expected.join("\0") + "\0").as_bytes(),
            "epoch 226 assembly owner or arguments changed"
        );
        Ok(sample(&path("guard-receipts"), id, guard, "running", pid)?.map(|(r, _)| (pid, r)))
    })?;
    let clock = active_clock()?;
    ensure!(
        clock["InvocationID"] == release["guard_timer_invocation"],
        "epoch 226 guard timer replaced"
    );
    suffix::record(
        &path("cadence-registration.json"),
        &json!({
            "schema":spec::REGISTRATION_SCHEMA,"epoch":226,"unit":spec::UNIT,"invocation_id":id,"main_pid":pid,
            "node_path":spec::NODE.0,"node_sha256":spec::NODE.1,"run_root":spec::ROOT,"launched":true,
            "assembly_only_no_replay":true,"publication_authorized":false,"canonical_epoch_publication_authorized":false,
            "remote_mutations":false,"r2_mutations":false,"admission":release["admission"],"plan":release["plan"],
            "active_guard":guard_sample,"guard_plan":guard,"launch_token":release,
        }),
    )
}

pub(in crate::fleet) fn namespace(claim: &DiagnosticClaim) -> bool {
    claim.unit == spec::UNIT
}

pub(crate) fn resource_only(unit: &str) -> bool {
    unit == spec::UNIT
}

pub(in crate::fleet) fn matches_schema(row: &Value) -> bool {
    row["schema"] == spec::REGISTRATION_SCHEMA
}

pub(in crate::fleet) fn validate_launch(claim: &DiagnosticClaim, row: &Value) -> Result<()> {
    let root = Path::new(spec::ROOT);
    let plan = sealed_json(&row["plan"], &path("plan.json"))?;
    let admission = sealed_json(&row["admission"], &path("admission.json"))?;
    let roster = sealed_json(&admission["capacity"], &path("accepted-capacity.json"))?;
    let guard = sealed_json(&row["guard_plan"], &path("guard-plan.json"))?;
    let handoff = sealed_json(&admission["handoff"], Path::new(spec::SOURCES.0))?;
    let sample_path = Path::new(
        row["active_guard"]["path"]
            .as_str()
            .context("assembly guard receipt")?,
    );
    ensure!(
        sample_path.parent() == Some(path("guard-receipts").as_path()),
        "epoch 226 assembly guard receipt escaped its directory"
    );
    let sample = root_bound_json(&row["active_guard"], sample_path, 0o022)?;
    ensure!(
        claim.epoch == 226
            && namespace(claim)
            && claim.scratch_path == root
            && claim.launch_receipt.path == path("cadence-registration.json")
            && row["schema"] == spec::REGISTRATION_SCHEMA
            && row["epoch"] == 226
            && row["unit"] == spec::UNIT
            && row["run_root"] == spec::ROOT
            && row["invocation_id"] == claim.invocation_id
            && iid(&row["invocation_id"])
            && row["node_path"] == spec::NODE.0
            && row["node_sha256"] == spec::NODE.1
            && row["launched"] == true
            && row["assembly_only_no_replay"] == true
            && row["canonical_epoch_publication_authorized"] == false
            && row["publication_authorized"] == false
            && row["remote_mutations"] == false
            && row["r2_mutations"] == false
            && admission["schema"] == "jetstreamer-epoch226-scoped-repair-admission-v1"
            && admission["epoch"] == 226
            && admission["operation"] == "assemble"
            && admission["producer_unit"] == spec::UNIT
            && admission["run_root"] == spec::ROOT
            && admission["node_sha256"] == spec::NODE.1
            && admission["admitted"] == true
            && admission["handoff"]["sha256"] == spec::SOURCES.1
            && admission["stage_sha256"] == handoff["stage_sha256"]
            && plan["stage"] == handoff["stage"]
            && plan["admission"] == row["admission"]
            && plan["run_root"] == spec::ROOT
            && admission["ordinary_replay_authorized"] == false
            && admission["publication_authorized"] == false
            && roster["schema"] == spec::ROSTER_SCHEMA
            && roster["capacity"]["fits"] == true
            && roster["assembly_226_quote"]["sources"] == admission["handoff"]
            && roster["assembly_226_quote"]["assembly_only_no_replay"] == true
            && guard["unit"] == spec::UNIT
            && guard["worker_root"] == spec::ROOT
            && guard["invocation_id"] == row["invocation_id"]
            && guard["maximum_root_physical_bytes"] == spec::CAP
            && sample["producer_invocation_id"] == row["invocation_id"]
            && sample["plan_sha256"] == row["guard_plan"]["sha256"]
            && sample["producer"]["pid"] == row["main_pid"]
            && sample["producer_stop_enabled"] == true
            && sample["trip_reason"].is_null()
            && sample["workers"] == json!([])
            && iid(&row["launch_token"]["guard_timer_invocation"]),
        "epoch 226 assembly enrollment differs from its private launch"
    );
    Ok(())
}

pub(in crate::fleet) fn validate_live(claim: &DiagnosticClaim, current: &Value) -> Result<()> {
    let row = bound_json(&claim.launch_receipt)?;
    let pid = row["main_pid"].as_u64().context("assembly PID")?;
    let proc = PathBuf::from(format!("/proc/{pid}"));
    let clock = active_clock()?;
    let expected = argv(&row["plan"])?.join("\0") + "\0";
    ensure!(
        current["InvocationID"] == row["invocation_id"]
            && current["MainPID"] == pid.to_string()
            && current["ControlGroup"] == format!("/system.slice/{}", spec::UNIT)
            && fs::read_link(proc.join("exe"))? == Path::new(spec::NODE.0)
            && fs::read(proc.join("cmdline"))? == expected.as_bytes()
            && clock["InvocationID"] == row["launch_token"]["guard_timer_invocation"],
        "epoch 226 live assembly or timer changed"
    );
    suffix::check_cgroup(current, spec::MEMORY)
}

pub(crate) fn run() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    ensure!(
        unsafe { libc::geteuid() } == 0
            && args.len() == 3
            && matches!(args[2].as_str(), "--check" | "--apply"),
        "usage: jetstreamer-r2 launch-epoch226-assembly --check|--apply"
    );
    let (preflight, handoff, mut guard) = static_inputs()?;
    if args[2] == "--check" {
        service_args(
            &preflight,
            &json!({"path":path("plan.json"),"sha256":"a".repeat(64)}),
        )?;
        println!(
            "{}",
            json!({"epoch":226,"static_inputs_verified":true,"assembly_only_no_replay":true,"launched":false})
        );
        return Ok(());
    }
    ensure!(
        env::var("CODEX_THREAD_ID").as_deref() == Ok(suffix::THREAD),
        "Foundation controller changed"
    );
    let _lock = suffix::cadence_lock()?;
    installed()?;
    let registration = path("cadence-registration.json");
    if registration.try_exists()? {
        let recorded = suffix::document(&registration)?;
        ensure!(
            recorded["schema"] == spec::REGISTRATION_SCHEMA && recorded["unit"] == spec::UNIT,
            "foreign epoch 226 assembly registration"
        );
        println!("{}", private157::file_binding(&registration)?);
        return Ok(());
    }
    if path("native-prestart.json").try_exists()? {
        let previous = suffix::document(&path("native-prestart.json"))?;
        let id = previous["InvocationID"]
            .as_str()
            .context("previous assembly invocation")?;
        ensure!(
            iid(&previous["InvocationID"]),
            "invalid previous assembly invocation"
        );
        let token = private157::file_binding(&path(&format!("tokens/{id}/guard-admission.json")))?;
        println!("{}", register(id, &token)?);
        return Ok(());
    }
    ensure!(
        drain::show(suffix::CADENCE)?["ActiveState"] == "inactive"
            && drain::show(suffix::CADENCE_TIMER)?["ActiveState"] == "active"
            && suffix::next_timer(suffix::CADENCE_TIMER)?.saturating_sub(suffix::monotonic_usec()?)
                > 215_000_000,
        "epoch 226 assembly requires the next idle interval in the current cadence"
    );
    for name in [spec::UNIT, spec::GUARD_SERVICE, spec::TIMER] {
        let owner = drain::show(name)?;
        ensure!(
            owner["LoadState"] == "not-found"
                && owner["ActiveState"] == "inactive"
                && owner["Job"] == "",
            "epoch 226 assembly unit already exists: {name}"
        );
    }
    ensure!(
        !path("launch-intent.json").try_exists()?
            && fs::read_dir(path("guard-receipts"))?.next().is_none()
            && fs::read_dir(path("tokens"))?.next().is_none(),
        "epoch 226 assembly state is not fresh"
    );
    let roster = foundation_roster::quote_226_assembly()?;
    let fit = &roster["capacity"];
    ensure!(
        fit["fits"] == true
            && roster["schema"] == spec::ROSTER_SCHEMA
            && roster["assembly_226_quote"]["candidate_cpus"]
                == json!([16, 17, 18, 19, 20, 21, 22, 23]),
        "epoch 226 assembly does not fit the complete current roster"
    );
    let floor = fit["protected_existing_disk_bytes"]
        .as_u64()
        .context("assembly protected floor")?;
    let minimum = floor
        .checked_add(spec::CAP)
        .context("assembly minimum disk overflow")?;
    ensure!(
        singleton227_admission::disk_free()? >= minimum,
        "epoch 226 assembly disk headroom changed"
    );
    let roster_ref = suffix::record(&path("accepted-capacity.json"), &roster)?;
    let admission_path = path("admission.json");
    let prepared = suffix::encode(&json!({
        "schema":"jetstreamer-epoch226-scoped-repair-admission-v1","epoch":226,"operation":"assemble",
        "stage_sha256":handoff["stage_sha256"],"node_sha256":spec::NODE.1,"producer_unit":spec::UNIT,
        "run_root":spec::ROOT,"admitted":true,"complete_fleet_and_century_floor_bound":true,
        "actual_guard_and_owner_qualified":true,"exact_stage_scope_qualified":true,
        "original_native_source_evidence_accepted":true,"protected_existing_floor_bytes":floor,
        "candidate_incremental_peak_bytes":spec::CAP,
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "ordinary_replay_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,
        "retirement_authorized":false,"runtime_promotion_authorized":false,"remote_mutations":false,"r2_mutations":false,
        "capacity":roster_ref,"handoff":preflight["sources"],
    }))?;
    let admission_ref = suffix::reference(&admission_path, &prepared);
    let plan_path = path("plan.json");
    let plan = suffix::encode(&json!({
        "schema":"jetstreamer-private-epoch226-scoped-repair-plan-v1","epoch":226,"producer_unit":spec::UNIT,
        "node_sha256":spec::NODE.1,"admission":admission_ref,"run_root":spec::ROOT,
        "minimum_free_bytes":minimum,"stage":handoff["stage"],
    }))?;
    let plan_ref = suffix::reference(&plan_path, &plan);
    let intent = suffix::record(
        &path("launch-intent.json"),
        &json!({
            "schema":"foundation-epoch226-assembly-launch-intent-v1","producer_unit":spec::UNIT,
            "handoff":preflight["sources"],"capacity":roster_ref,"admission":admission_ref,"plan":plan_ref,"work_released":false,
        }),
    )?;
    suffix::start(&service_args(&preflight, &plan_ref)?)?;
    let held = suffix::wait(12, "private assembly held in prestart", || {
        suffix::dormant_owner(spec::UNIT)
    })?;
    let id = held["InvocationID"]
        .as_str()
        .context("assembly invocation")?;
    suffix::record(&path("native-prestart.json"), &held)?;
    let token_path = path(&format!("tokens/{id}/guard-admission.json"));
    let mut timer_id = None;
    let armed = (|| -> Result<Value> {
        suffix::check_cgroup(&held, spec::MEMORY)?;
        guard["invocation_id"] = json!(id);
        guard["receipt_directory"] = json!(path("guard-receipts"));
        let guard_plan = suffix::record(&path("guard-plan.json"), &guard)?;
        suffix::arm_guard(spec::STATE, spec::GUARD, Some(spec::GUARD_CPU), &guard_plan)?;
        let timer = active_clock()?;
        timer_id = timer["InvocationID"].as_str().map(str::to_owned);
        let first = suffix::wait(28, "first completed assembly guard", || {
            let result = drain::show(spec::GUARD_SERVICE)?;
            let reading = sample(&path("guard-receipts"), id, &guard_plan, "start-pre", 0)?;
            Ok(reading.and_then(|(reference, body)| {
                (result["ActiveState"] == "inactive"
                    && result["Result"] == "success"
                    && result["ExecMainStatus"] == "0"
                    && result["InvocationID"] == body["guard_invocation_id"])
                    .then_some(reference)
            }))
        })?;
        ensure!(
            suffix::dormant_owner(spec::UNIT)?
                .as_ref()
                .is_some_and(|p| p["InvocationID"] == id)
                && active_clock()?["InvocationID"] == timer["InvocationID"]
                && fs::read_dir(spec::ROOT)?.next().is_none()
                && singleton227_admission::disk_free()? >= minimum,
            "epoch 226 assembly changed while admission was held"
        );
        ensure!(
            suffix::write(&admission_path, &prepared, 0o444)? == admission_ref
                && suffix::write(&plan_path, &plan, 0o444)? == plan_ref,
            "epoch 226 assembly admission or stage plan changed"
        );
        let parent = token_path.parent().context("assembly token parent")?;
        fs::DirBuilder::new().mode(0o755).create(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o755))?;
        suffix::write(
            &token_path,
            &suffix::encode(&json!({
                "schema":"foundation-epoch226-assembly-first-guard-v1","epoch":226,"unit":spec::UNIT,
                "invocation_id":id,"launch_intent":intent,"first_guard":first,"guard_plan":guard_plan,
                "guard_timer_invocation":timer["InvocationID"],"admission":admission_ref,"plan":plan_ref,
                "canonical_epoch_publication_authorized":false,
            }))?,
            0o444,
        )
    })();
    let token = match armed {
        Ok(token) => token,
        Err(error) => {
            if !token_path.try_exists()? {
                if drain::show(spec::UNIT)?["InvocationID"] == id {
                    drain::stop(spec::UNIT)?;
                }
                if timer_id
                    .is_some_and(|i| drain::show(spec::TIMER).is_ok_and(|m| m["InvocationID"] == i))
                {
                    drain::stop(spec::TIMER)?;
                    if drain::show(spec::GUARD_SERVICE)?["LoadState"] != "not-found" {
                        drain::stop(spec::GUARD_SERVICE)?;
                    }
                }
            }
            return Err(error);
        }
    };
    println!("{}", register(id, &token)?);
    Ok(())
}
