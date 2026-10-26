//! Admitted extraction ownership and truthful status for epochs 225 and 226.
//! Operational metadata confers no runtime, archive or canonical sidecar authority.
use super::*;
use jetstreamer_horizon_observe::epoch225_extraction as c;
pub(super) const EVENT: &str = "jetstreamer-epoch225-extraction-handoff-event-v1";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionRequest {
    schema: String,
    plan: BoundFile,
    resource_basis: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleRequest {
    schema: String,
    plan: BoundFile,
    output: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceRequest {
    schema: String,
    observer: BoundFile,
    fleet: BoundFile,
    output_directory: PathBuf,
}
pub(super) fn capture_source() -> Result<()> {
    root()?;
    let (request, self_sha) = publication203::parsed_args("capture-epoch225-terminal-handoff")?;
    let r: SourceRequest = serde_json::from_value(bound_json(&request)?)?;
    ensure!(
        r.schema == "jetstreamer-epoch225-terminal-handoff-capture-request-v1"
            && r.output_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && r.output_directory
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-epoch225-terminal-handoff-")),
        "epoch 225 source capture namespace differs"
    );
    c::private(&r.output_directory)?;
    ensure!(
        fs::read_dir(&r.output_directory)?.next().is_none(),
        "epoch 225 source capture attempt not empty"
    );
    let o = bound_json(&r.observer)?;
    let f = bound_json(&r.fleet)?;
    let sampled = utc_seconds(text(&o, "recorded_at_utc")?)?;
    ensure!(
        o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && f["schema"] == SCHEMA
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["inventory"]["anomalies"] == 0
            && f["observer_sha256"] == r.observer.sha256
            && f["observer_receipt"].as_str() == r.observer.path.to_str()
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && sampled <= c::now()?
            && c::now()? - sampled <= 1800,
        "epoch 225 source capture needs the current coordinated fleet"
    );
    let owner = unit(c::OLD_UNIT)?;
    ensure!(
        owner == f["unit_census"][c::OLD_UNIT]
            && owner["MainPID"] == "0"
            && owner["NRestarts"] == "0"
            && owner["ActiveState"] == "inactive"
            && owner["SubState"] == "dead"
            && owner["Result"] == "success"
            && owner["ExecMainStatus"] == "0",
        "epoch 225 source producer is not the accepted terminal owner"
    );
    inactive_status::no_pending_owner_trigger(c::OLD_UNIT, false)?;
    let source = fs::symlink_metadata(c::ORIGINAL)?;
    let manifest_path = PathBuf::from(format!("{}.segment.json", c::ORIGINAL));
    let manifest = fs::symlink_metadata(&manifest_path)?;
    ensure!(
        source.is_file()
            && source.uid() == 1000
            && source.nlink() == 1
            && source.len() == 265610094371
            && source.mode() & 0o222 == 0
            && manifest.is_file()
            && manifest.uid() == 1000
            && manifest.nlink() == 1
            && manifest.mode() & 0o222 == 0
            && Path::new(c::ORIGINAL).canonicalize()? == Path::new(c::ORIGINAL)
            && manifest_path.canonicalize()? == manifest_path,
        "freeze the exact completed epoch 225 source and manifest before capturing custody; bytes and ownership must be retained"
    );
    let manifest_bound = BoundFile {
        path: manifest_path,
        sha256: c::MANIFEST_SHA.into(),
    };
    bound_json(&manifest_bound)?;
    let output = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            "--unit",
            c::OLD_UNIT,
            "_PID=1",
            "--output=json",
            "--no-pager",
            "--lines=4096",
        ])
        .output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 2 << 20,
        "epoch 225 source PID1 history unavailable"
    );
    let journal = serde_json::Deserializer::from_slice(&output.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|v| v["INVOCATION_ID"] == c::OLD_IID)
        .collect::<Vec<_>>();
    let props = r.output_directory.join("terminal-properties.json");
    let parsed = r.output_directory.join("manager-journal.json");
    c::persist(&props, &owner)?;
    c::persist(&parsed, &json!(journal))?;
    c::persist(
        &r.output_directory.join("manager-journal-raw.json"),
        &json!({"raw":std::str::from_utf8(&output.stdout)?,"sha256":hex_lower(&Sha256::digest(&output.stdout))}),
    )?;
    let profile = json!({"schema":"jetstreamer-epoch225-terminal-handoff-profile-v1",
        "original_launch":{"path":"/var/lib/jetstreamer/horizon-225-shrink-natural-root-launch-222936-v1/launch.json","sha256":"491baf3214515c8ad324d0d0de43a3fa680bb35892bfae32fd027b8ce6c6b071"},
        "source_manifest":manifest_bound,"terminal_properties":c::binding(&props)?,"manager_journal":c::binding(&parsed)?,"source_archive":c::ORIGINAL,
        "source_archive_bytes":265610094371u64,"source_archive_sha256":"77c0f95a020ceb6c45e323f4ce1bb48066fd0b379615bd5c9dbcb67f9082d6f9",
        "retained_disk_reservation_bytes":640u64<<30,"reclamation_credit_bytes":0,"phase":"terminal-retained","extractor":null});
    let path = r.output_directory.join("profile.json");
    c::persist(&path, &profile)?;
    let bound = fb(&c::binding(&path)?);
    terminal225_peer::Profile::load(&bound, &f)?;
    ensure!(
        unit(c::OLD_UNIT)? == owner
            && c::identity(&fs::symlink_metadata(c::ORIGINAL)?) == c::identity(&source),
        "epoch 225 source owner or custody changed during capture"
    );
    let source_idle = idle_source()?;
    c::persist(
        &r.output_directory.join("capture.json"),
        &json!({"schema":"jetstreamer-epoch225-terminal-handoff-capture-v1","request":request,
        "issuer_sha256":self_sha,"profile":bound,"source_identity":c::identity(&source),"source_idle":source_idle,"archive_body_reads":0,"new_resource_samples":0,"authority":c::denied()}),
    )
}
pub(super) fn validate_role() -> Result<()> {
    root()?;
    let (request, self_sha) = publication203::parsed_args("validate-epoch225-extraction-role")?;
    let r: RoleRequest = serde_json::from_value(bound_json(&request)?)?;
    let p = c::load(&cb(&r.plan))?;
    ensure!(
        r.schema == "jetstreamer-epoch225-extraction-role-validation-request-v1"
            && self_sha == p.admitter.sha256
            && r.output.file_name().is_some_and(|n| n == "validation.json")
            && r.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && r.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-epoch225-role-validation-")),
        "epoch 225 role validation request escaped its metadata scope"
    );
    c::qualified(&p)?;
    let unit_file = c::unit_binding(&p, &cb(&r.plan))?;
    c::persist(
        &r.output,
        &json!({"schema":"jetstreamer-epoch225-extraction-role-validation-v1","request":request,"plan":r.plan,
        "executable":p.executable,"source_qualification":p.qualification,"deployment_seal":p.deployment_seal,"guard":p.guard_executable,
        "guard_qualification":p.guard_qualification,"unit_file":unit_file,"issuer_sha256":self_sha,"archive_body_reads":0,"native_execution_started":false,
        "resource_admission_claimed":false,"authority":c::denied()}),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseRequest {
    schema: String,
    plan: BoundFile,
    guard_plan: BoundFile,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventRequest {
    schema: String,
    launch: BoundFile,
    observer: BoundFile,
    previous_fleet: BoundFile,
    output_directory: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusRequest {
    schema: String,
    mode: String,
    observer: BoundFile,
    fleet: BoundFile,
    launch: BoundFile,
    event: Option<BoundFile>,
    policy: BoundFile,
    estimate_receipt: PathBuf,
    receipt_directory: PathBuf,
}
fn cb(b: &BoundFile) -> c::Bound {
    c::Bound {
        path: b.path.clone(),
        sha256: b.sha256.clone(),
    }
}
fn fb(b: &c::Bound) -> BoundFile {
    BoundFile {
        path: b.path.clone(),
        sha256: b.sha256.clone(),
    }
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .with_context(|| format!("epoch 225 missing text: {k}"))
}
fn num(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .with_context(|| format!("epoch 225 missing integer: {k}"))
}
fn root() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "epoch 225 control requires root"
    );
    Ok(())
}
fn idle_source() -> Result<Value> {
    let directory = Path::new(c::ORIGINAL)
        .parent()
        .and_then(Path::parent)
        .context("epoch 225 source root missing")?;
    let scan =
        jetstreamer_horizon_observe::process_references::scan(Path::new("/proc"), directory)?;
    ensure!(
        scan.references.is_empty(),
        "epoch 225 completed source still has live process references"
    );
    Ok(serde_json::to_value(scan)?)
}
fn admitted(p: &c::Plan, b: &BoundFile) -> Result<(BoundFile, Value)> {
    let bound = fb(&c::binding(&p.admission)?);
    let v = bound_json(&bound)?;
    let unit_file = c::unit_binding(p, &cb(b))?;
    ensure!(
        v["schema"] == c::ADMISSION
            && v["unit_file"] == json!(unit_file)
            && v["plan"] == json!(b)
            && v["terminal_handoff"] == json!(p.terminal_handoff)
            && v["executable"] == json!(p.executable)
            && v["authority"] == c::denied(),
        "epoch 225 immutable admission differs"
    );
    Ok((bound, v))
}
pub(super) fn admit() -> Result<()> {
    root()?;
    let (request, self_sha) = publication203::parsed_args("admit-epoch225-prefix-extraction")?;
    let r: AdmissionRequest = serde_json::from_value(bound_json(&request)?)?;
    ensure!(
        r.schema == "jetstreamer-epoch225-extraction-admission-request-v1",
        "epoch 225 admission request differs"
    );
    let p = c::load(&cb(&r.plan))?;
    c::qualified(&p)?;
    ensure!(
        self_sha == p.admitter.sha256 && fs::read_link("/proc/self/exe")? == p.admitter.path,
        "epoch 225 admission issuer differs"
    );
    terminal225_peer::validate_profile(&fb(&p.terminal_handoff))?;
    c::private(&p.root)?;
    ensure!(
        fs::read_dir(&p.root)?.next().is_none(),
        "epoch 225 output attempt is not empty"
    );
    let capacity = maintenance_capacity::check_epoch225_extraction(
        &r.resource_basis,
        &fb(&p.terminal_handoff),
    )?;
    let unit_file = c::unit_binding(&p, &cb(&r.plan))?;
    let v = json!({"schema":c::ADMISSION,"epoch":225,"unit":p.unit,"retained_disk_reservation_bytes":640u64<<30,"reclamation_credit_bytes":0,
        "request":request,"issuer_sha256":self_sha,"plan":r.plan,
        "executable":p.executable,"terminal_handoff":p.terminal_handoff,"resource_basis":r.resource_basis,
        "unit_file":unit_file,"capacity":capacity,"maximum_output_bytes":c::OUTPUT,"memory_max_bytes":c::MEMORY,
        "admitted":true,"recorded_unix_seconds":c::now()?,"authority":c::denied()});
    c::admission(&p, &cb(&r.plan), &v, c::now()?)?;
    c::persist(&p.admission, &v)
}
fn protection(
    p: &c::Plan,
    guard: &BoundFile,
    iid: &str,
    floor: u64,
    minimum: u64,
) -> Result<Value> {
    let proof = c::latest_guard(p, &cb(guard), iid, floor)?;
    let gp = bound_json(guard)?;
    let completed = warmup223::completed_guard_binding(
        &p.guard_unit,
        Path::new(text(&gp, "receipt_directory")?),
        minimum,
        c::now()?,
    )?;
    ensure!(
        completed["binding"] == proof["binding"]
            && completed["history"]["executable"] == json!(p.guard_executable.path),
        "epoch 225 guard is not its latest authenticated PID1 completion"
    );
    completed_archive_phase::epoch225_extraction_guard_timer(&p.guard_unit)?;
    completed_archive_phase::epoch225_extraction_empty_controls(&p.guard_unit, true)?;
    let manager = &proof["manager"];
    for (key, value) in [
        ("MemoryMax", "1073741824"),
        ("MemorySwapMax", "0"),
        ("TasksMax", "256"),
        ("CPUQuotaPerSecUSec", "1s"),
        ("Type", "oneshot"),
        ("User", "root"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("PrivateNetwork", "yes"),
        ("NoNewPrivileges", "yes"),
        ("DropInPaths", ""),
        ("NeedDaemonReload", "no"),
    ] {
        ensure!(
            manager[key] == value,
            "epoch 225 protective guard control differs: {key}"
        );
    }
    ensure!(
        manager["ReadWritePaths"] == gp["receipt_directory"]
            && pipeline_status::same_exec_start(
                text(manager, "ExecStart")?,
                text(&completed["history"], "expected_exec_start")?
            ),
        "epoch 225 protective guard command or writable scope differs"
    );
    Ok(json!({"live":proof,"completed":completed}))
}
pub(super) fn release() -> Result<()> {
    root()?;
    let (request, self_sha) = publication203::parsed_args("release-epoch225-prefix-extraction")?;
    let r: ReleaseRequest = serde_json::from_value(bound_json(&request)?)?;
    ensure!(
        r.schema == "jetstreamer-epoch225-extraction-release-request-v1",
        "epoch 225 release request differs"
    );
    let p = c::load(&cb(&r.plan))?;
    c::qualified(&p)?;
    ensure!(
        self_sha == p.admitter.sha256,
        "epoch 225 release issuer differs"
    );
    terminal225_peer::validate_profile(&fb(&p.terminal_handoff))?;
    let (ab, a) = admitted(&p, &r.plan)?;
    let floor = c::admission(&p, &cb(&r.plan), &a, c::now()?)?;
    let waiting = bound_json(&fb(&c::binding(&p.root.join("waiting.json"))?))?;
    ensure!(
        waiting["schema"] == "jetstreamer-epoch225-extraction-waiting-v1"
            && waiting["plan"] == json!(r.plan)
            && waiting["admission"] == json!(ab)
            && waiting["archive_body_reads"] == 0,
        "epoch 225 waiting owner belongs to another admission"
    );
    let iid = text(&waiting["actor"]["manager"], "InvocationID")?;
    let pid = u32::try_from(num(&waiting["actor"], "pid")?)?;
    let actor = c::actor(&p, &cb(&r.plan), iid, pid)?;
    completed_archive_phase::epoch225_extraction_empty_controls(&p.unit, false)?;
    ensure!(
        actor == waiting["actor"],
        "epoch 225 native waiter was replaced"
    );
    let guard = protection(
        &p,
        &r.guard_plan,
        iid,
        floor,
        num(&a, "recorded_unix_seconds")?,
    )?;
    let source_idle = idle_source()?;
    // A new native waiter is already charged at the exact hard cap. Revalidate
    // the original admitted disk floor, latest guard and all previous owners;
    // never run another candidate admission that would charge this task twice.
    let required_free = floor
        .checked_add(c::OUTPUT)
        .and_then(|n| n.checked_add(c::METADATA))
        .context("epoch 225 pre-read output allocation overflow")?;
    ensure!(
        c::free(&p.root)? >= required_free,
        "epoch 225 pre-read output allocation no longer fits"
    );
    let previous = bound_json(&serde_json::from_value(
        a["resource_basis"]["fleet"].clone(),
    )?)?;
    let mut names: BTreeSet<String> = previous["unit_census"]
        .as_object()
        .context("epoch 225 complete prior census missing")?
        .keys()
        .cloned()
        .collect();
    names.extend([p.unit.clone(), p.guard_unit.clone()]);
    let mut units = census(&names, 201, 300)?;
    units.remove(&p.unit);
    units.remove(&p.guard_unit);
    let profile = terminal225_peer::Profile::load(&fb(&p.terminal_handoff), &previous)?;
    profile.current(&previous, &units)?;
    maintenance_capacity::current_owners(
        &profile.without(&previous)?,
        &profile.without_current(&previous, &units)?,
    )?;
    ensure!(
        c::actor(&p, &cb(&r.plan), iid, pid)? == actor,
        "epoch 225 waiter changed before release"
    );
    c::persist(
        &p.release,
        &json!({"schema":c::RELEASE,"request":request,"issuer_sha256":self_sha,"plan":r.plan,
        "admission":ab,"actor":actor,"guard_plan":r.guard_plan,"protection":guard,"source_idle":source_idle,"source_reads_authorized":true,
        "maximum_output_bytes":c::OUTPUT,"recorded_unix_seconds":c::now()?,"authority":c::denied()}),
    )
}
fn launch(b: &BoundFile) -> Result<(Value, c::Plan, BoundFile, Value)> {
    let l = bound_json(b)?;
    ensure!(
        l["schema"] == c::LAUNCH
            && l["epochs"] == json!([225, 226])
            && l["phase"] == "verification"
            && l["missing226_suffix_slots"] == 535
            && l["authority"] == c::denied(),
        "epoch 225 actual launch scope differs"
    );
    let plan: BoundFile = serde_json::from_value(l["plan"].clone())?;
    let p = c::load(&cb(&plan))?;
    c::qualified(&p)?;
    let (ab, a) = admitted(&p, &plan)?;
    ensure!(
        l["admission"] == json!(ab)
            && l["terminal_handoff"] == json!(p.terminal_handoff)
            && l["unit"] == p.unit
            && l["invocation_id"] == l["actor"]["manager"]["InvocationID"]
            && b.path == p.root.join("launch.json")
            && l["maximum_output_bytes"] == c::OUTPUT
            && l["memory_max_bytes"] == c::MEMORY,
        "epoch 225 launch binding differs"
    );
    let release = bound_json(&serde_json::from_value(l["release"].clone())?)?;
    ensure!(
        release["schema"] == c::RELEASE
            && release["plan"] == json!(plan)
            && release["admission"] == json!(ab)
            && release["actor"] == l["actor"]
            && release["issuer_sha256"] == p.admitter.sha256
            && release["guard_plan"] == l["guard_plan"]
            && release["source_reads_authorized"] == true
            && release["authority"] == c::denied(),
        "epoch 225 launch has no genuine released native owner"
    );
    Ok((l, p, plan, a))
}
fn current(l: &Value, p: &c::Plan, b: &BoundFile, a: &Value) -> Result<Value> {
    terminal225_peer::validate_profile(&fb(&p.terminal_handoff))?;
    let profile = bound_json(&fb(&p.terminal_handoff))?;
    let expected = bound_json(&serde_json::from_value(
        profile["terminal_properties"].clone(),
    )?)?;
    let old = c::manager(c::OLD_UNIT)?;
    ensure!(
        old["MainPID"] == "0"
            && old["NRestarts"] == "0"
            && old["ActiveState"] == "inactive"
            && old["SubState"] == "dead"
            && old["Result"] == "success"
            && old["ExecMainStatus"] == "0"
            && old["ControlGroup"] == ""
            && old["InvocationID"]
                .as_str()
                .is_some_and(|s| s.is_empty() || s == c::OLD_IID)
            && pipeline_status::same_exec_start(
                text(&old, "ExecStart")?,
                text(&expected, "ExecStart")?
            ),
        "epoch 225 original source regained an owner"
    );
    let actor = c::actor(
        p,
        &cb(b),
        text(l, "invocation_id")?,
        u32::try_from(num(&l["actor"], "pid")?)?,
    )?;
    completed_archive_phase::epoch225_extraction_empty_controls(&p.unit, false)?;
    ensure!(
        actor == l["actor"],
        "epoch 225 launch no longer owns this task"
    );
    protection(
        p,
        &serde_json::from_value(l["guard_plan"].clone())?,
        text(l, "invocation_id")?,
        num(&a["capacity"], "minimum_free_bytes")?,
        num(a, "recorded_unix_seconds")?,
    )?;
    let raw = unit(&p.unit)?;
    ensure!(
        raw["Id"] == p.unit
            && raw["InvocationID"] == l["invocation_id"]
            && raw["MainPID"] == actor["manager"]["MainPID"]
            && raw["NRestarts"] == "0"
            && raw["ActiveState"] == "active"
            && raw["SubState"] == "running"
            && pipeline_status::same_exec_start(
                text(&raw, "ExecStart")?,
                text(&actor["manager"], "ExecStart")?
            ),
        "epoch 225 raw campaign census differs from the proved native task"
    );
    Ok(raw)
}
pub(super) fn names(b: &BoundFile) -> Result<BTreeSet<String>> {
    let (_, p, _, _) = launch(b)?;
    Ok(BTreeSet::from([p.unit, p.guard_unit]))
}
pub(super) fn rows(b: &BoundFile, o: &Value) -> Result<Vec<Value>> {
    let (l, p, pb, a) = launch(b)?;
    let manager = c::manager(&p.unit)?;
    if manager["MainPID"] == "0"
        && manager["ActiveState"] == "inactive"
        && manager["SubState"] == "dead"
    {
        ensure!(
            manager["NRestarts"] == "0"
                && manager["Result"] == "success"
                && manager["ExecMainStatus"] == "0"
                && manager["InvocationID"]
                    .as_str()
                    .is_some_and(|s| s.is_empty() || Some(s) == l["invocation_id"].as_str())
                && pipeline_status::same_exec_start(
                    text(&manager, "ExecStart")?,
                    text(&l["actor"]["manager"], "ExecStart")?
                ),
            "epoch 225 extraction ended unsuccessfully or changed owner; preserve failure evidence"
        );
        let result = fb(&c::binding(&p.root.join("extraction.json"))?);
        let value = bound_json(&result)?;
        ensure!(
            value["schema"] == "jetstreamer-epoch225-prefix-extraction-result-v1"
                && value["launch"] == json!(b)
                && value["plan"] == json!(pb)
                && value["admission"] == l["admission"]
                && value["authority"] == c::denied()
                && value["result"]["epoch"] == 225
                && value["result"]["output_slot_count"] == 432000
                && value["result"]["source_archive_sha256"]
                    == "77c0f95a020ceb6c45e323f4ce1bb48066fd0b379615bd5c9dbcb67f9082d6f9"
                && value["result"]["source_manifest_sha256"] == c::MANIFEST_SHA
                && value["result"]["source_runtime_admission"] == "candidate"
                && value["result"]["epoch226_tail_is_private"] == true
                && value["result"]["independent_output_reread_passed"] == true
                && value["result"]["full_verification_passed"] == false
                && value["result"]["current_plugin_verification_passed"] == false
                && value["result"]["publication_authorized"] == false
                && value["candidate_identity"]
                    == c::identity(&fs::symlink_metadata(p.root.join("epoch-225.jet"))?),
            "epoch 225 successful terminal task has no unchanged private candidate evidence"
        );
        let out = ProcessCommand::new("/usr/bin/journalctl")
            .args([
                "--unit",
                &p.unit,
                "_PID=1",
                "--output=json",
                "--no-pager",
                "--lines=256",
            ])
            .output()?;
        ensure!(
            out.status.success() && out.stdout.len() <= 2 << 20,
            "epoch 225 terminal PID1 history unavailable"
        );
        let records = serde_json::Deserializer::from_slice(&out.stdout)
            .into_iter::<Value>()
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let events = singleton209_delivery::terminal_history_for(
            &records,
            &p.unit,
            text(&l, "invocation_id")?,
        )?;
        return Ok([225,226].into_iter().map(|epoch|json!({"epoch":epoch,"phase":"private-prefix-extraction-complete","live":false,
            "producer":manager,"launch":b,"result":result,"manager_events":events,"source_must_be_retained":true,
            "retained226_private_slots":431465,"missing226_suffix_slots":535,"ordinary_replay_claim":false,
            "archive_or_sidecar_completion_claimed":false,"authority":c::denied()})).collect());
    }
    let owner = current(&l, &p, &pb, &a)?;
    Ok([225,226].into_iter().map(|epoch|json!({"epoch":epoch,"phase":"private-prefix-extraction","wire_phase":"verification",
        "producer":owner,"live":true,"ordinary_replay_claim":false,"launch":b,"admission":l["admission"],"plan":pb,
        "sampled_at_utc":o["recorded_at_utc"],"retained226_private_slots":431465,"missing226_suffix_slots":535,
        "source_must_be_retained":true,"maximum_output_bytes":c::OUTPUT,"memory_max_bytes":c::MEMORY,
        "current_sidecar_eta_valid":false,"authority":c::denied()})).collect())
}
fn fleet_current(f: &Value, l: &Value, p: &c::Plan) -> Result<()> {
    let names = f["unit_census"]
        .as_object()
        .context("epoch 225 complete campaign census missing")?
        .keys()
        .cloned()
        .collect();
    let mut units = census(&names, 201, 300)?;
    ensure!(
        units
            .get(&p.unit)
            .is_some_and(|m| m["InvocationID"] == l["invocation_id"]
                && m["MainPID"] == l["actor"]["manager"]["MainPID"]),
        "epoch 225 census lost its exact task"
    );
    units.remove(&p.unit);
    units.remove(&p.guard_unit);
    let mut retained = f.clone();
    retained["active"]
        .as_array_mut()
        .context("epoch 225 active census missing")?
        .retain(|row| !matches!(row["epoch"].as_u64(), Some(225) | Some(226)));
    let profile = terminal225_peer::Profile::load(&fb(&p.terminal_handoff), &retained)?;
    profile.current(&retained, &units)?;
    maintenance_capacity::current_owners(
        &profile.without(&retained)?,
        &profile.without_current(&retained, &units)?,
    )
}
fn event_clock(e: &Value, l: &Value, o: &Value, previous: &Value, at: u64) -> Result<()> {
    let captured = num(l, "captured_unix_seconds")?;
    let sample = utc_seconds(text(o, "recorded_at_utc")?)?;
    ensure!(
        e["schema"] == EVENT
            && e["recorded_unix_seconds"] == captured
            && e["sampled_at_utc"] == publication203::utc(captured)?
            && sample < captured
            && captured <= at
            && at - captured <= 300
            && at - sample <= 1800
            && num(previous, "recorded_unix_seconds")? < captured,
        "epoch 225 handoff is stale, backdated or fabricated"
    );
    Ok(())
}
pub(super) fn prepare_event() -> Result<()> {
    root()?;
    let (request, self_sha) = publication203::parsed_args("prepare-epoch225-extraction-event")?;
    let r: EventRequest = serde_json::from_value(bound_json(&request)?)?;
    ensure!(
        r.schema == "jetstreamer-epoch225-extraction-event-request-v1"
            && r.output_directory.parent()
                == Some(Path::new("/var/lib/jetstreamer/horizon-campaign-fleet"))
            && r.output_directory
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("epoch225-extraction-event-")),
        "epoch 225 event namespace differs"
    );
    c::private(&r.output_directory)?;
    ensure!(
        fs::read_dir(&r.output_directory)?.next().is_none(),
        "epoch 225 event attempt not empty"
    );
    let (l, p, pb, a) = launch(&r.launch)?;
    current(&l, &p, &pb, &a)?;
    ensure!(
        a["resource_basis"]["observer"] == json!(r.observer)
            && a["resource_basis"]["fleet"] == json!(r.previous_fleet),
        "epoch 225 event substituted admitted resource evidence"
    );
    let o = bound_json(&r.observer)?;
    let previous = bound_json(&r.previous_fleet)?;
    let e = json!({"schema":EVENT,"request":request,"issuer_sha256":self_sha,"launch":r.launch,"observer":r.observer,"previous_fleet":r.previous_fleet,
        "recorded_unix_seconds":l["captured_unix_seconds"],"sampled_at_utc":publication203::utc(num(&l,"captured_unix_seconds")?)?,"authority":c::denied()});
    event_clock(&e, &l, &o, &previous, c::now()?)?;
    c::persist(&r.output_directory.join("event.json"), &e)?;
    let event = fb(&c::binding(&r.output_directory.join("event.json"))?);
    let gp = bound_json(&serde_json::from_value(l["guard_plan"].clone())?)?;
    let mut live_profile = bound_json(&fb(&p.terminal_handoff))?;
    live_profile["phase"] = json!("extractor-live");
    live_profile["extractor"] = json!({"unit":p.unit,"invocation_id":l["invocation_id"],"plan":pb,"admission":l["admission"],"launch":r.launch,
        "guard_unit":p.guard_unit,"guard_receipt_directory":gp["receipt_directory"],"guard_plan":l["guard_plan"],"guard_sha256":p.guard_executable.sha256,
        "maximum_output_bytes":c::OUTPUT,"memory_max_bytes":c::MEMORY});
    c::persist(&r.output_directory.join("live-profile.json"), &live_profile)?;
    let mut plan = bound_json(&serde_json::from_value(
        json!({"path":previous["plan"],"sha256":previous["plan_sha256"]}),
    )?)?;
    ensure!(
        plan["epoch225_extraction"].is_null(),
        "epoch 225 extraction owner already exists"
    );
    plan["epoch225_extraction"] = json!(r.launch);
    plan["metadata_event"] = json!(event);
    plan["previous_fleet"] = json!(r.previous_fleet);
    plan["admission_transition_guard"] = Value::Null;
    plan["output"] = json!(r.output_directory.join("fleet.json"));
    let tracked = plan["tracked_units"]
        .as_array_mut()
        .context("epoch 225 tracked census missing")?;
    for name in [&p.unit, &p.guard_unit] {
        if !tracked.iter().any(|v| v == name) {
            tracked.push(json!(name));
        }
    }
    c::persist(&r.output_directory.join("fleet-plan.json"), &plan)
}
fn plan_delta(mut old: Value, mut new: Value, unit: &str, guard: &str) -> Result<()> {
    ensure!(
        old["epoch225_extraction"].is_null(),
        "epoch 225 event cannot replace an existing task"
    );
    let mut tracked: BTreeSet<String> = serde_json::from_value(old["tracked_units"].clone())?;
    tracked.extend([unit.to_string(), guard.to_string()]);
    let actual: Vec<String> = serde_json::from_value(new["tracked_units"].clone())?;
    ensure!(
        actual.len() == tracked.len() && actual.into_iter().collect::<BTreeSet<_>>() == tracked,
        "epoch 225 event changed unrelated tracked units"
    );
    for key in [
        "epoch225_extraction",
        "tracked_units",
        "previous_fleet",
        "metadata_event",
        "admission_transition_guard",
        "output",
    ] {
        old.as_object_mut()
            .context("epoch 225 old plan")?
            .remove(key);
        new.as_object_mut()
            .context("epoch 225 new plan")?
            .remove(key);
    }
    ensure!(
        old == new,
        "epoch 225 event changed existing gates, policy, peers or history"
    );
    Ok(())
}
pub(super) fn event_predecessor(
    previous: &Value,
    p: &Plan,
    pb: &BoundFile,
    e: &Value,
    sample: &str,
    at: u64,
) -> Result<()> {
    let b: BoundFile = serde_json::from_value(e["launch"].clone())?;
    let (l, plan, plan_binding, a) = launch(&b)?;
    current(&l, &plan, &plan_binding, &a)?;
    let o = bound_json(&p.observer)?;
    event_clock(e, &l, &o, previous, at)?;
    ensure!(
        p.epoch225_extraction.as_ref() == Some(&b)
            && e["observer"] == json!(p.observer)
            && sample == text(&o, "recorded_at_utc")?
            && p.previous_fleet
                .as_ref()
                .is_some_and(|v| e["previous_fleet"] == json!(v))
            && a["resource_basis"]["observer"] == e["observer"]
            && a["resource_basis"]["fleet"] == e["previous_fleet"]
            && p.admission_transition_guard.is_none(),
        "epoch 225 event lost actual admission context"
    );
    let old = bound_json(&serde_json::from_value(
        json!({"path":previous["plan"],"sha256":previous["plan_sha256"]}),
    )?)?;
    plan_delta(old, bound_json(pb)?, &plan.unit, &plan.guard_unit)?;
    ensure!(
        e["authority"] == c::denied(),
        "epoch 225 event grants authority"
    );
    let r: EventRequest =
        serde_json::from_value(bound_json(&serde_json::from_value(e["request"].clone())?)?)?;
    ensure!(
        r.schema == "jetstreamer-epoch225-extraction-event-request-v1"
            && e["launch"] == json!(r.launch)
            && e["observer"] == json!(r.observer)
            && e["previous_fleet"] == json!(r.previous_fleet)
            && p.output == r.output_directory.join("fleet.json")
            && pb.path == r.output_directory.join("fleet-plan.json")
            && p.metadata_event
                .as_ref()
                .is_some_and(|v| v.path == r.output_directory.join("event.json")),
        "epoch 225 event output/request changed"
    );
    Ok(())
}
pub(super) fn event_census(
    previous: &Value,
    current_units: &BTreeMap<String, Value>,
    e: &Value,
) -> Result<()> {
    let b: BoundFile = serde_json::from_value(e["launch"].clone())?;
    let (l, p, pb, a) = launch(&b)?;
    current(&l, &p, &pb, &a)?;
    let mut peers = current_units.clone();
    for name in [&p.unit, &p.guard_unit] {
        peers
            .remove(name)
            .context("epoch 225 new task omitted from census")?;
        if let Some(old) = previous["unit_census"].get(name) {
            ensure!(
                old["MainPID"] == "0",
                "epoch 225 event replaced a live prior owner"
            );
            peers.insert(name.clone(), old.clone());
        }
    }
    let profile = terminal225_peer::Profile::load(&fb(&p.terminal_handoff), previous)?;
    profile.current(previous, &peers)?;
    maintenance_capacity::current_owners(
        &profile.without(previous)?,
        &profile.without_current(previous, &peers)?,
    )
}
fn status_clock(r: &StatusRequest, f: &Value, o: &Value, l: &Value, at: u64) -> Result<String> {
    let sample = utc_seconds(text(o, "recorded_at_utc")?)?;
    let captured = num(l, "captured_unix_seconds")?;
    ensure!(
        sample <= num(f, "recorded_unix_seconds")?
            && num(f, "recorded_unix_seconds")? <= at
            && at - sample <= 1800,
        "epoch 225 status resource evidence expired"
    );
    match (r.mode.as_str(), &r.event) {
        ("initial", Some(b)) => {
            let e = bound_json(b)?;
            let previous = bound_json(&serde_json::from_value(e["previous_fleet"].clone())?)?;
            event_clock(&e, l, o, &previous, at)?;
            ensure!(
                f["metadata_event"] == json!(b) && e["launch"] == json!(r.launch),
                "epoch 225 status borrowed another event"
            );
            ensure!(
                e["observer"] == json!(r.observer),
                "epoch 225 initial status borrowed another resource sample"
            );
            publication203::utc(captured)
        }
        ("observation", None) => {
            ensure!(
                captured <= sample,
                "epoch 225 status cannot backdate a new task"
            );
            publication203::utc(sample)
        }
        _ => bail!("epoch 225 status mode/event differs"),
    }
}
pub(super) async fn publish() -> Result<()> {
    root()?;
    let (request, self_sha) = publication203::parsed_args("status-publish-epoch225-extraction")?;
    let r: StatusRequest = serde_json::from_value(bound_json(&request)?)?;
    ensure!(
        r.schema == "jetstreamer-epoch225-extraction-status-request-v1",
        "epoch 225 status request differs"
    );
    let (l, p, pb, a) = launch(&r.launch)?;
    let actor = current(&l, &p, &pb, &a)?;
    let o = bound_json(&r.observer)?;
    let f = bound_json(&r.fleet)?;
    let fp = bound_json(&serde_json::from_value(
        json!({"path":f["plan"],"sha256":f["plan_sha256"]}),
    )?)?;
    ensure!(
        fp["epoch225_extraction"] == json!(r.launch),
        "epoch 225 status lost its fleet registration"
    );
    ensure!(
        f["schema"] == SCHEMA
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["observer_receipt"].as_str() == r.observer.path.to_str()
            && f["observer_sha256"] == r.observer.sha256
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && f["inventory"]["anomalies"] == 0,
        "epoch 225 status lacks accepted coordinated fleet"
    );
    for epoch in [225, 226] {
        ensure!(
            f["active"]
                .as_array()
                .context("epoch 225 active roster missing")?
                .iter()
                .filter(|row| row["epoch"] == epoch
                    && row["launch"] == json!(r.launch)
                    && row["producer"]["InvocationID"] == l["invocation_id"]
                    && row["phase"] == "private-prefix-extraction")
                .count()
                == 1,
            "epoch 225/226 task is not registered exactly once"
        );
    }
    let sample = status_clock(&r, &f, &o, &l, c::now()?)?;
    let policy = bound_json(&r.policy)?;
    ensure!(
        policy["launch"] == json!(r.launch)
            && policy["observer"] == json!(r.observer)
            && policy["sampled_at_utc"] == sample,
        "epoch 225 policy belongs to another sample/task"
    );
    let estimates = c::stage_policy(&policy)?;
    let complete_path = p.root.join("progress-source-validation-complete.json");
    let complete = if complete_path.try_exists()? {
        let phase = bound_json(&fb(&c::binding(&complete_path)?))?;
        ensure!(
            phase["schema"] == "jetstreamer-epoch225-extraction-phase-v1"
                && phase["phase"] == "source-validation-complete"
                && phase["launch"] == json!(r.launch)
                && phase["unit"] == p.unit
                && phase["invocation_id"] == l["invocation_id"]
                && phase["source_validation_complete"] == true
                && phase["authority"] == c::denied(),
            "epoch 225 phase proof belongs to another task"
        );
        num(&phase, "recorded_unix_millis")?
            <= utc_seconds(&sample)?
                .checked_mul(1000)
                .context("epoch 225 report clock overflow")?
    } else {
        false
    };
    ensure!(
        (policy["source_validation_complete"] == true) == complete,
        "epoch 225 source ETA must follow its actual durable phase evidence"
    );
    for b in policy["evidence"]
        .as_array()
        .context("epoch 225 planning evidence missing")?
    {
        bound_json(&serde_json::from_value(b.clone())?)?;
    }
    ensure!(
        policy["evidence"].as_array().is_some_and(|v| !v.is_empty()),
        "epoch 225 planning evidence empty"
    );
    terminal225_peer::validate_profile(&fb(&p.terminal_handoff))?;
    let origin = bound_json(&fb(&p.terminal_handoff))?;
    let original = bound_json(&serde_json::from_value(origin["original_launch"].clone())?)?;
    let elapsed = utc_seconds(&sample)?
        .checked_sub(utc_seconds(text(&original, "launch_utc")?)?)
        .and_then(|n| n.checked_mul(1000))
        .context("epoch 225 original elapsed clock differs")?;
    ensure!(
        r.receipt_directory == Path::new("/home/ubuntu/.jetstreamer-private/r2-status-receipts")
            && r.estimate_receipt
                .file_name()
                .is_some_and(|n| n == "estimate.json")
            && r.estimate_receipt.parent().and_then(Path::parent)
                == Some(Path::new("/var/lib/jetstreamer")),
        "epoch 225 status receipt namespace differs"
    );
    ensure!(
        r.estimate_receipt
            .parent()
            .and_then(Path::file_name)
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("horizon-epoch225-status-")),
        "epoch 225 estimate escaped its dedicated namespace"
    );
    c::private(r.estimate_receipt.parent().unwrap())?;
    let output = p.root.join("epoch-225.jet");
    let bytes = if output.try_exists()? {
        let id = regular_identity(&output)?;
        ensure!(
            id.length <= c::OUTPUT,
            "epoch 225 candidate size escaped admission"
        );
        id.length
    } else {
        0
    };
    ensure!(
        !p.root.join("epoch-226.jet").try_exists()?,
        "epoch 226 tail cannot be relabeled as a complete candidate"
    );
    let statuses = [225, 226]
        .into_iter()
        .map(|epoch| EpochStatus {
            epoch,
            jet_size_bytes: if epoch == 225 { bytes } else { 0 },
            elapsed_execution_millis: elapsed,
            estimated_remaining_millis: estimates[&epoch],
            sampled_at_utc: sample.clone(),
            phase: "verification".into(),
        })
        .collect::<Vec<_>>();
    let estimate = json!({"schema":"jetstreamer-epoch225-extraction-status-estimate-v1","request":request,"issuer_sha256":self_sha,"observer":r.observer,
        "fleet":r.fleet,"launch":r.launch,"policy":r.policy,"statuses":statuses,"missing226_suffix_slots":535,"authority":c::denied()});
    fleet_current(&f, &l, &p)?;
    if r.estimate_receipt.try_exists()? {
        ensure!(
            bound_json(&fb(&c::binding(&r.estimate_receipt)?))? == estimate,
            "epoch 225 estimate retry conflicts"
        );
    } else {
        c::persist(&r.estimate_receipt, &estimate)?;
    }
    let eb = fb(&c::binding(&r.estimate_receipt)?);
    current(&l, &p, &pb, &a)?;
    let config = r2_config_from_env()?;
    let s3 = s3_client(&config);
    preflight_status_receipt_write(&r.receipt_directory)?;
    for epoch in [225, 226] {
        ensure!(
            get_mutable_object(&s3, &config.bucket, &format!("epoch-{epoch}.jet.sha256"))
                .await?
                .is_none(),
            "epoch {epoch} sidecar already committed"
        );
    }
    for status in statuses {
        validate_epoch_status(&status, status.epoch)?;
        fleet_current(&f, &l, &p)?;
        ensure!(
            current(&l, &p, &pb, &a)? == actor,
            "epoch 225 task changed before publication"
        );
        let (etag, previous) = publish_epoch_status(&s3, &config, &status).await?;
        let receipt = StatusPublicationReceipt {
            schema: STATUS_RECEIPT_SCHEMA.into(),
            bucket: config.bucket.clone(),
            epoch: status.epoch,
            key: format!("epoch-{}.epoch-status.json", status.epoch),
            status,
            object_etag: etag,
            previous_object_etag: previous,
            observer_receipt: eb.path.clone(),
            observer_receipt_sha256: eb.sha256.clone(),
            controller_invocation_id: text(&l, "invocation_id")?.into(),
            producer_invocation_id: text(&l, "invocation_id")?.into(),
            authenticated_readback: true,
            verified_unix_seconds: c::now()?,
            pipeline_binding: None,
        };
        let path = status_receipt_path(&r.receipt_directory, &receipt.status);
        if path.try_exists()? {
            let old: StatusPublicationReceipt = serde_json::from_slice(&read_stable_bounded(
                &path,
                MAX_STATUS_BYTES,
                "epoch 225 existing status receipt",
            )?)?;
            ensure!(
                old.status == receipt.status
                    && old.object_etag == receipt.object_etag
                    && old.controller_invocation_id == receipt.controller_invocation_id
                    && old.authenticated_readback,
                "epoch 225 status receipt conflict"
            );
        } else {
            write_status_receipt(&r.receipt_directory, &receipt)?;
        }
    }
    Ok(())
}
pub(super) fn matches(
    r: &StatusPublicationReceipt,
    epoch: u64,
    o: &Value,
    units: &BTreeMap<String, Value>,
) -> bool {
    (|| -> Result<()> {
        ensure!(
            matches!(epoch, 225 | 226)
                && r.epoch == epoch
                && r.schema == STATUS_RECEIPT_SCHEMA
                && r.status.phase == "verification"
                && r.authenticated_readback
                && r.pipeline_binding.is_none(),
            "foreign extraction status"
        );
        let e = bound_json(&BoundFile {
            path: r.observer_receipt.clone(),
            sha256: r.observer_receipt_sha256.clone(),
        })?;
        ensure!(
            e["schema"] == "jetstreamer-epoch225-extraction-status-estimate-v1"
                && e["authority"] == c::denied()
                && e["statuses"]
                    .as_array()
                    .is_some_and(|s| s.contains(&json!(r.status))),
            "epoch 225 status estimate differs"
        );
        let request: StatusRequest =
            serde_json::from_value(bound_json(&serde_json::from_value(e["request"].clone())?)?)?;
        ensure!(
            request.schema == "jetstreamer-epoch225-extraction-status-request-v1"
                && e["observer"] == json!(request.observer)
                && e["fleet"] == json!(request.fleet)
                && bound_json(&request.observer)? == *o
                && e["launch"] == json!(request.launch)
                && e["policy"] == json!(request.policy),
            "epoch 225 status belongs to another observation"
        );
        let policy = bound_json(&request.policy)?;
        ensure!(
            policy["launch"] == json!(request.launch)
                && policy["observer"] == json!(request.observer)
                && policy["sampled_at_utc"] == r.status.sampled_at_utc
                && c::stage_policy(&policy)?[&epoch] == r.status.estimated_remaining_millis,
            "epoch 225 status no longer reproduces its immutable sidecar policy"
        );
        let (l, p, _, _) = launch(&request.launch)?;
        let owner = units
            .get(&p.unit)
            .context("epoch 225 current owner absent")?;
        ensure!(
            owner["InvocationID"] == l["invocation_id"]
                && owner["MainPID"] == l["actor"]["manager"]["MainPID"]
                && owner["ActiveState"] == "active"
                && owner["SubState"] == "running"
                && owner["NRestarts"] == "0"
                && r.producer_invocation_id == text(&l, "invocation_id")?
                && r.controller_invocation_id == r.producer_invocation_id,
            "epoch 225 status owner is no longer live"
        );
        Ok(())
    })()
    .is_ok()
}
#[cfg(test)]
mod tests {
    use super::*;
    fn b() -> BoundFile {
        BoundFile {
            path: "/sealed/evidence.json".into(),
            sha256: "a".repeat(64),
        }
    }
    fn request() -> StatusRequest {
        StatusRequest {
            schema: "jetstreamer-epoch225-extraction-status-request-v1".into(),
            mode: "observation".into(),
            observer: b(),
            fleet: b(),
            launch: b(),
            event: None,
            policy: b(),
            estimate_receipt: "/var/lib/jetstreamer/horizon-epoch225-status-test/estimate.json"
                .into(),
            receipt_directory: "/home/ubuntu/.jetstreamer-private/r2-status-receipts".into(),
        }
    }
    #[test]
    fn e225_status_event_clock_rejects_backdating_staleness_and_fake_sample() {
        let l = json!({"captured_unix_seconds":1100});
        let o = json!({"recorded_at_utc":publication203::utc(1000).unwrap()});
        let previous = json!({"recorded_unix_seconds":1010});
        let e = json!({"schema":EVENT,"recorded_unix_seconds":1100,"sampled_at_utc":publication203::utc(1100).unwrap()});
        event_clock(&e, &l, &o, &previous, 1101).unwrap();
        assert!(event_clock(&e, &l, &o, &previous, 1099).is_err());
        assert!(event_clock(&e, &l, &o, &previous, 1401).is_err());
        assert!(event_clock(&e, &l, &o, &json!({"recorded_unix_seconds":1100}), 1101).is_err());
        assert!(
            event_clock(
                &e,
                &l,
                &json!({"recorded_at_utc":publication203::utc(1100).unwrap()}),
                &previous,
                1101
            )
            .is_err()
        );
    }
    #[test]
    fn e225_status_routine_clock_cannot_reuse_old_observation_or_future_fleet() {
        let r = request();
        let o = json!({"recorded_at_utc":publication203::utc(1000).unwrap()});
        let f = json!({"recorded_unix_seconds":1001});
        let l = json!({"captured_unix_seconds":900});
        assert_eq!(
            status_clock(&r, &f, &o, &l, 1002).unwrap(),
            publication203::utc(1000).unwrap()
        );
        assert!(status_clock(&r, &f, &o, &json!({"captured_unix_seconds":1100}), 1002).is_err());
        assert!(status_clock(&r, &f, &o, &l, 3000).is_err());
        assert!(status_clock(&r, &json!({"recorded_unix_seconds":1003}), &o, &l, 1002).is_err());
    }
    #[test]
    fn e225_status_event_delta_preserves_gates_peers_and_failure_history() {
        let old = json!({"tracked_units":["peer.service"],"gates":{"225":{"state":"blocked-qualification","evidence":["failure"]}},
            "history":[{"failed":"preserved"}],"observer":{"sha256":"a".repeat(64)}});
        let mut new = old.clone();
        new["tracked_units"] = json!(["peer.service", "task.service", "guard.service"]);
        new["epoch225_extraction"] = json!(b());
        plan_delta(old.clone(), new.clone(), "task.service", "guard.service").unwrap();
        for (pointer, value) in [
            ("/gates/225/state", json!("remote-ready")),
            ("/history", json!([])),
            ("/observer/sha256", json!("b".repeat(64))),
            ("/tracked_units", json!(["task.service", "guard.service"])),
        ] {
            let mut bad = new.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                plan_delta(old.clone(), bad, "task.service", "guard.service").is_err(),
                "{pointer}"
            );
        }
        let mut replacement = old;
        replacement["epoch225_extraction"] = json!(b());
        assert!(plan_delta(replacement, new, "task.service", "guard.service").is_err());
    }
    #[test]
    fn e225_status_requests_cannot_import_wire_phase_or_skip_authority() {
        let mut v = json!({"schema":"jetstreamer-epoch225-extraction-status-request-v1","mode":"observation","observer":b(),"fleet":b(),"launch":b(),
            "event":null,"policy":b(),"estimate_receipt":"/private/estimate.json","receipt_directory":"/private/receipts"});
        assert!(serde_json::from_value::<StatusRequest>(v.clone()).is_ok());
        for key in [
            "phase",
            "skip_owner",
            "elapsed_execution_millis",
            "allow_complete226",
        ] {
            v[key] = json!("replay");
            assert!(serde_json::from_value::<StatusRequest>(v.clone()).is_err());
            v.as_object_mut().unwrap().remove(key);
        }
        let mut role = json!({"schema":"jetstreamer-epoch225-extraction-role-validation-request-v1","plan":b(),"output":"/private/validation.json"});
        assert!(serde_json::from_value::<RoleRequest>(role.clone()).is_ok());
        role["skip_qa"] = json!(true);
        assert!(serde_json::from_value::<RoleRequest>(role).is_err());
    }
}
