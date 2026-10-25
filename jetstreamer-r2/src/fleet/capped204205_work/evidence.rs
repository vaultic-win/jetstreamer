//! Small captured evidence only. No archive body, host sample or service action.
use super::*;

pub(super) fn bytes(b: &BoundFile, immutable: bool) -> Result<Vec<u8>> {
    bytes_limit(b, immutable, 16 << 20)
}
pub(super) fn executable(b: &BoundFile) -> Result<()> {
    bytes_limit(b, true, 256 << 20)?;
    Ok(())
}
fn bytes_limit(b: &BoundFile, immutable: bool, maximum: u64) -> Result<Vec<u8>> {
    ensure!(
        b.path.is_absolute()
            && b.path.canonicalize()? == b.path
            && canonical_digest(&json!(b.sha256)),
        "invalid capped evidence binding"
    );
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & (if immutable { 0o222 } else { 0o022 }) == 0,
        "capped evidence is writable by another owner or not sealed"
    );
    let raw = read_stable_bounded(&b.path, maximum, "capped work evidence")?;
    ensure!(
        hex_lower(&Sha256::digest(&raw)) == b.sha256,
        "capped evidence digest changed"
    );
    Ok(raw)
}
pub(super) fn bound(b: &BoundFile, immutable: bool) -> Result<Value> {
    Ok(serde_json::from_slice(&bytes(b, immutable)?)?)
}
fn exec_identity(value: &str) -> Option<&str> {
    value.split_once(" ; ignore_errors=").map(|v| v.0)
}
pub(super) fn expected_command(p: &Value, a: &Value, plan: &BoundFile) -> Result<String> {
    let node = string(&a["capability_evidence"]["producer"], "path")?;
    ensure!(
        a["capability_evidence"]["producer"]["sha256"] == p["node_sha256"],
        "capped admitted node package differs"
    );
    Ok(format!(
        "{{ path={node} ; argv[]={node} {} {}/ledger --verify --checkpoint-continuation-plan={} --checkpoint-continuation-plan-sha256={}",
        number(p, "epoch")?,
        string(p, "run_root")?,
        plan.path.display(),
        plan.sha256
    ))
}
pub(super) fn command_matches(expected: &str, current: &str) -> bool {
    exec_identity(current) == Some(expected)
}
pub(super) fn expected_guard_command(
    p: &Value,
    a: &Value,
    plan: &BoundFile,
    iid: &str,
) -> Result<String> {
    let control = string(&a["capability_evidence"]["control"], "path")?;
    ensure!(
        a["capability_evidence"]["control"]["sha256"] == p["guard_sha256"],
        "admitted guard executable differs"
    );
    Ok(format!(
        "{{ path={control} ; argv[]={control} guard {} --plan-sha256 {} --self-sha256 {} --producer-iid {iid}",
        plan.path.display(),
        plan.sha256,
        string(p, "guard_sha256")?
    ))
}

fn worker_start_ticks(worker: &Value) -> Result<u64> {
    // guard_core::start_time reads procfs field 22 and serializes its decimal
    // string directly. Keep this exact field-specific wire contract separate
    // from the strict JSON integer reader used by all byte/time counters.
    let decimal = string(worker, "start_time")?;
    let ticks: u64 = decimal
        .parse()
        .context("guard worker start time is not unsigned decimal ticks")?;
    ensure!(
        ticks > 0 && decimal == ticks.to_string(),
        "guard worker start time must be a canonical positive decimal string"
    );
    Ok(ticks)
}

pub(super) fn guard(
    p: &Value,
    l: &Value,
    g: &Value,
    census: &BTreeMap<String, Value>,
    sample: u64,
) -> Result<()> {
    let guard_name = string(p, "guard_unit")?;
    let current = census
        .get(guard_name)
        .context("capped guard omitted from census")?;
    let stamp = number(g, "recorded_unix_millis")?;
    ensure!(
        g["schema"] == "jetstreamer-capped204205-guard-heartbeat-v1"
            && g["epoch"] == p["epoch"]
            && g["plan_sha256"] == l["producer_plan"]["sha256"]
            && g["producer_unit"] == p["producer_unit"]
            && g["producer_invocation_id"] == l["invocation_id"]
            && g["guard_unit"] == p["guard_unit"]
            && g["guard_invocation_id"] == l["guard_invocation_id"]
            && g["guard_sha256"] == p["guard_sha256"]
            && g["producer_stop_enabled"] == true
            && g["trip"] == false
            && stamp <= sample
            && sample - stamp <= 60_000
            && live(current)
            && current["InvocationID"] == g["guard_invocation_id"]
            && g["phase"]["schema"] == "jetstreamer-capped204205-continuation-phase-v1"
            && g["phase"]["epoch"] == p["epoch"]
            && g["phase"]["invocation_id"] == l["invocation_id"]
            && g["phase"]["plan_sha256"] == l["producer_plan"]["sha256"]
            && number(&g["phase"], "started_unix_millis")? <= sample
            && sample - number(&g["phase"], "started_unix_millis")?
                <= number(p, "maximum_stage_millis")?,
        "capped guard is stale, tripped, replaced or detached from the actual producer stage"
    );
    let processes = &g["processes"];
    let workers = processes["workers"]
        .as_array()
        .context("guard worker census missing")?;
    let owner = census
        .get(string(p, "producer_unit")?)
        .context("guard producer census missing")?;
    ensure!(
        owner["MainPID"]
            .as_str()
            .and_then(|v| v.parse::<u64>().ok())
            == processes["main_pid"].as_u64()
            && number(processes, "total_process_rss_bytes")?
                <= number(p, "maximum_process_rss_bytes")?
            && workers.len() <= 1
            && (matches!(
                stage_from_guard(g)?,
                Stage::NativeRestore | Stage::SuffixExecution
            ) || workers.is_empty()),
        "capped guard process ownership or whole-lane bound changed"
    );
    for worker in workers {
        ensure!(
            number(worker, "vmas")? > 0
                && number(worker, "vmas")? <= number(p, "maximum_worker_vmas")?
                && number(worker, "pid")? > 1
                && worker_start_ticks(worker)? > 0
                && number(worker, "rss_bytes")? > 0,
            "capped worker PID, start time, RSS or VMA evidence is invalid"
        );
    }
    for key in [
        "maximum_root_physical_bytes",
        "maximum_process_rss_bytes",
        "maximum_worker_vmas",
    ] {
        ensure!(g[key] == p[key], "capped actual guard bound changed: {key}");
    }
    ensure!(
        g["minimum_free_bytes"] == p["protected_existing_floor_bytes"]
            && g["root_physical_observation"]["exceeds_budget"] == false
            && number(
                &g["root_physical_observation"],
                "conservative_physical_bytes"
            )? <= number(p, "maximum_root_physical_bytes")?
            && g["remote_mutations"] == false
            && g["r2_mutations"] == false,
        "capped actual guard reserve/physical proof differs"
    );
    Ok(())
}

pub(super) fn actor(epoch: u64, c: &Claim, l: &Value, a: &Actor) -> Result<()> {
    ensure!(!a.evidence.is_empty(), "downstream launch evidence absent");
    let v = bound(&a.evidence[0], true)?;
    actor_value(epoch, c, l, a, &v)?;
    let raw = bytes(&serde_json::from_value(v["manager_journal"].clone())?, true)?;
    ensure!(
        capture::manager_history(&raw, &a.unit, &a.invocation_id, false)? == a.started_unix_millis
            && number(&v, "main_pid")? > 1,
        "downstream launch lacks actual manager start and PID"
    );
    for b in &a.evidence {
        bound(b, true)?;
    }
    Ok(())
}
pub(super) fn actor_value(epoch: u64, c: &Claim, l: &Value, a: &Actor, v: &Value) -> Result<()> {
    let kind = match a.stage {
        Stage::FullVerification | Stage::BoundaryChecks => "full-verification",
        Stage::PluginVerification => "plugin-verification",
        Stage::LocalImport => "local-publication",
        Stage::Upload | Stage::Readback | Stage::SidecarCommit => "upload-readback",
        _ => bail!("downstream actor cannot claim private continuation stages"),
    };
    ensure!(
        pipeline_unit_range(kind, &a.unit)? == (epoch..=epoch)
            && id(&a.invocation_id)
            && !a.expected_exec_start.is_empty()
            && !a.evidence.is_empty(),
        "invalid capped downstream actor scope"
    );
    ensure!(
        v["schema"] == "jetstreamer-capped204205-downstream-launch-v1"
            && v["epoch"] == epoch
            && v["origin_launch"] == private157::binding(&c.launch)
            && v["origin_invocation_id"] == l["invocation_id"]
            && v["unit"] == a.unit
            && v["invocation_id"] == a.invocation_id
            && v["expected_exec_start"] == a.expected_exec_start
            && v["started_unix_millis"] == a.started_unix_millis,
        "downstream actor lacks actual source-bound launch evidence"
    );
    denied(v)
}

pub(super) fn generated_bytes(p: &Value, f: &Value) -> Result<u64> {
    let root = Path::new(string(p, "run_root")?);
    let epoch = number(p, "epoch")?;
    let paths = BTreeSet::from([
        PathBuf::from(string(&p["prefix_archive"], "path")?),
        root.join(format!("output/epoch-{epoch}-suffix.jet")),
        root.join(format!("output/epoch-{epoch}-checkpoint-restart-v4.jet")),
    ]);
    let output = root.join(format!("output/epoch-{epoch}-checkpoint-restart-v4.jet"));
    let mut current_output_bytes = 0;
    let mut seen = BTreeSet::new();
    let prefix = string(&p["prefix_archive"], "path")?;
    for row in f["generated_archives"]
        .as_array()
        .context("capped archive metadata missing")?
    {
        let path = PathBuf::from(string(row, "path")?);
        ensure!(
            paths.contains(&path) && seen.insert(path.clone()) && row["archive_body_read"] == false,
            "capped generated bytes include an unrelated/duplicate archive"
        );
        let n = number(row, "bytes")?;
        ensure!(
            number(row, "links")? == 1 && number(row, "inode")? > 0,
            "archive metadata has invalid identity/links"
        );
        if path == Path::new(prefix) {
            ensure!(
                n == number(p, "prefix_bytes")? && row["uid"] == 0,
                "frozen retained prefix size/owner differs"
            );
        }
        if path == output {
            current_output_bytes = n;
        }
    }
    ensure!(
        seen.contains(Path::new(prefix)),
        "retained original prefix byte proof missing"
    );
    Ok(current_output_bytes)
}

pub(super) fn inactive(
    p: &Value,
    l: &Value,
    f: &Value,
    census: &BTreeMap<String, Value>,
) -> Result<()> {
    let proof = bound(
        &serde_json::from_value(f["inactivity_snapshot"].clone())?,
        true,
    )?;
    inactive_value(p, l, f, census, &proof)?;
    let terminal = bound(
        &serde_json::from_value(proof["terminal_snapshot"].clone())?,
        true,
    )?;
    terminal_proof(p, l, &terminal)?;
    Ok(())
}
pub(super) fn inactive_value(
    p: &Value,
    l: &Value,
    f: &Value,
    census: &BTreeMap<String, Value>,
    proof: &Value,
) -> Result<()> {
    ensure!(
        proof["schema"] == "jetstreamer-capped204205-positive-inactivity-v1"
            && proof["epoch"] == p["epoch"]
            && proof["producer_invocation_id"] == l["invocation_id"]
            && proof["unit_census"] == serde_json::to_value(census)?
            && proof["sampled_at_utc"] == f["sampled_at_utc"]
            && proof["process_reference_census"]["references"]
                .as_array()
                .is_some_and(Vec::is_empty),
        "capped inactivity needs actual complete manager/cgroup/reference evidence"
    );
    if let Some(handoffs) = f.get("authenticated_other_host_handoffs") {
        ensure!(
            handoffs.as_array().is_some_and(Vec::is_empty),
            "authenticated other-host handoff prevents local inactive cleanup"
        );
    }
    let jobs = proof["pending_job_units"]
        .as_array()
        .context("pending job census missing")?;
    let scopes = census
        .keys()
        .filter(|name| capture::epoch_scope(number(p, "epoch").unwrap_or(0), name))
        .collect::<Vec<_>>();
    ensure!(
        !scopes.is_empty(),
        "capped inactivity has no closed owner roster"
    );
    let actors: Vec<Actor> = serde_json::from_value(
        f.get("downstream_actors")
            .cloned()
            .unwrap_or_else(|| json!([])),
    )?;
    let historical = historical_terminal::validate(number(p, "epoch")?, p, &actors, f, census)?;
    for name in scopes {
        ensure!(
            (idle(&census[name]) || historical.contains(name))
                && !jobs.iter().any(|v| v.as_str() == Some(name.as_str())),
            "capped owner is active/pending"
        );
        let group = &proof["cgroups"][name];
        ensure!(
            matches!(group["state"].as_str(), Some("absent" | "unpopulated")),
            "capped owner cgroup is populated or unknown"
        );
    }
    denied(proof)
}
pub(super) fn terminal_proof(p: &Value, l: &Value, v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-capped204205-terminal-v1"
            && v["epoch"] == p["epoch"]
            && v["unit"] == p["producer_unit"]
            && v["invocation_id"] == l["invocation_id"]
            && idle(&v["current_unit"])
            && v["manager_journal_complete"] == true
            && matches!(
                v["outcome"].as_str(),
                Some("natural_success" | "failed_or_stopped")
            ),
        "capped terminal identity/outcome missing"
    );
    let records = bytes(&serde_json::from_value(v["manager_journal"].clone())?, true)?;
    let success = v["outcome"] == "natural_success";
    capture::manager_history(
        &records,
        string(p, "producer_unit")?,
        string(l, "invocation_id")?,
        success,
    )?;
    capture::manager_terminal(
        &records,
        string(p, "producer_unit")?,
        string(l, "invocation_id")?,
    )?;
    if success {
        let result = bound(
            &serde_json::from_value(v["continuation_result"].clone())?,
            false,
        )?;
        ensure!(
            result["schema"] == "jetstreamer-capped204205-private-continuation-v1"
                && result["epoch"] == p["epoch"]
                && result["plan_sha256"] == l["producer_plan"]["sha256"]
                && result["producer_invocation_id"] == l["invocation_id"]
                && result["guard_invocation_id"] == l["guard_invocation_id"]
                && result["admission_sha256"] == l["admission"]["sha256"]
                && result["source_capture"] == p["source_capture"]
                && result["prefix_archive"] == p["prefix_archive"]
                && result["private_output"].as_str()
                    == Some(
                        Path::new(string(p, "run_root")?)
                            .join(format!(
                                "output/epoch-{}-checkpoint-restart-v4.jet",
                                number(p, "epoch")?
                            ))
                            .to_str()
                            .context("private output path encoding")?
                    )
                && result["slots_merged"] == 432000
                && result["source_archives"] == 2
                && result["provenance_version"] == 4
                && result["authority"]["canonical_sidecar_authorized"] == false
                && result["authority"]["publication_authorized"] == false,
            "private completion is not the exact actual V4 result"
        );
        for key in [
            "canonical_sidecar_authorized",
            "publication_authorized",
            "retirement_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            ensure!(
                result["authority"][key] == false,
                "private result grants unrelated authority: {key}"
            );
        }
        ensure!(
            result["independent_final_archive_verification_passed"] == false
                && result["current_plugin_verification_passed"] == false
                && result["independent_adjacent_boundary_receipts_still_required"] == true,
            "private V4 result cannot claim final archive or publication gates"
        );
    }
    denied(v)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Prepare {
    schema: String,
    previous_fleet: BoundFile,
    pub(super) original_plan: BoundFile,
    observer: BoundFile,
    claim: Claim,
    output_directory: PathBuf,
}
pub(super) fn prepare() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 7
            && args[3] == "--spec-sha256"
            && args[5] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: prepare-capped204205-fleet-status SPEC --spec-sha256 SHA --self-sha256 SHA"
    );
    let spec: Prepare = serde_json::from_value(bound(
        &BoundFile {
            path: args[2].clone().into(),
            sha256: args[4].clone(),
        },
        true,
    )?)?;
    ensure!(
        spec.schema == "jetstreamer-capped204205-fleet-status-spec-v1",
        "wrong capped fleet/status spec"
    );
    ensure!(
        hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == args[6],
        "capped adapter self hash differs"
    );
    let old = bound(&spec.original_plan, true)?;
    let prior = bound(&spec.previous_fleet, false)?;
    let observer = bound(&spec.observer, false)?;
    let i = read_inputs(&spec.claim)?;
    let census: BTreeMap<String, Value> =
        serde_json::from_value(i.frame["unit_census_after"].clone())?;
    let result = evaluate(
        &spec.claim,
        &i,
        &observer,
        &census,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    let (mut next, event) = derive_plan(&spec, &old, &prior, &i.frame)?;
    let event_path = spec.output_directory.join("event.json");
    capture::write_sealed(&event_path, &event)?;
    next["metadata_event"] = json!({"path":event_path,"sha256":capture::file_sha(&event_path)?});
    capture::write_sealed(&spec.output_directory.join("fleet-plan.json"), &next)?;
    capture::write_sealed(
        &spec.output_directory.join("claim.json"),
        &serde_json::to_value(&spec.claim)?,
    )?;
    capture::write_sealed(
        &spec.output_directory.join("status-estimate.json"),
        &json!({
        "schema":"jetstreamer-capped204205-status-estimate-v1","row":result.row,"status":result.status,
        "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    )?;
    Ok(())
}
pub(super) fn derive_plan(
    s: &Prepare,
    old: &Value,
    prior: &Value,
    frame: &Value,
) -> Result<(Value, Value)> {
    ensure!(
        old["schema"] == "jetstreamer-horizon-campaign-fleet-plan-v1"
            && prior["schema"] == SCHEMA
            && old["first_epoch"] == 201
            && old["last_epoch"] == 300
            && prior["first_epoch"] == 201
            && prior["last_epoch"] == 300
            && prior["plan"].as_str() == s.original_plan.path.to_str()
            && prior["plan_sha256"] == s.original_plan.sha256,
        "capped derivative lost the accepted raw predecessor"
    );
    let mut next = old.clone();
    ensure!(
        frame["previous_fleet"] == private157::binding(&s.previous_fleet),
        "captured frame and metadata transition have different accepted predecessors"
    );
    let mut tracked: BTreeSet<String> = serde_json::from_value(old["tracked_units"].clone())?;
    tracked.extend(
        prior["unit_census"]
            .as_object()
            .context("prior complete census missing")?
            .keys()
            .cloned(),
    );
    tracked.extend(
        frame["unit_census_after"]
            .as_object()
            .context("frame complete census missing")?
            .keys()
            .cloned(),
    );
    let mut claims = old
        .get("capped204205_work")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut history = old
        .get("capped204205_history")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    claims.retain(|v| {
        if v["epoch"] == s.claim.epoch {
            history.push(v.clone());
            false
        } else {
            true
        }
    });
    claims.push(serde_json::to_value(&s.claim)?);
    next["capped204205_work"] = json!(claims);
    next["capped204205_history"] = json!(history);
    next["tracked_units"] = json!(tracked);
    next["observer"] = private157::binding(&s.observer);
    next["previous_fleet"] = private157::binding(&s.previous_fleet);
    next["output"] = json!(s.output_directory.join("fleet.json"));
    next["admission_transition_guard"] = Value::Null;
    let event = json!({"schema":EVENT_SCHEMA,"original_plan":private157::binding(&s.original_plan),
        "previous_fleet":private157::binding(&s.previous_fleet),"observer":private157::binding(&s.observer),
        "sampled_at_utc":frame["sampled_at_utc"],
        "claim":s.claim,"preserved_history":true,"metadata_only":true,"resource_samples_taken":0,
        "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false});
    Ok((next, event))
}
#[cfg(test)]
pub(super) fn prepare_fixture(claim: Claim) -> Prepare {
    let b = |name: &str| BoundFile {
        path: Path::new("/fixture").join(name),
        sha256: "a".repeat(64),
    };
    Prepare {
        schema: "jetstreamer-capped204205-fleet-status-spec-v1".into(),
        previous_fleet: b("fleet.json"),
        original_plan: b("original-plan.json"),
        observer: b("observer.json"),
        claim,
        output_directory: "/fixture/output".into(),
    }
}

pub(super) fn event_predecessor(
    previous: &Value,
    plan: &Plan,
    plan_binding: &BoundFile,
    event: &Value,
    sample: &str,
    now: u64,
) -> Result<()> {
    ensure!(
        event["schema"] == EVENT_SCHEMA
            && event["metadata_only"] == true
            && event["resource_samples_taken"] == 0
            && event["previous_fleet"]
                == plan
                    .previous_fleet
                    .as_ref()
                    .map(private157::binding)
                    .unwrap_or(Value::Null)
            && event["observer"] == private157::binding(&plan.observer)
            && plan.admission_transition_guard.is_none(),
        "capped transition cannot borrow admission or another accepted predecessor"
    );
    denied(event)?;
    let original: BoundFile = serde_json::from_value(event["original_plan"].clone())?;
    ensure!(
        previous["plan"].as_str() == original.path.to_str()
            && previous["plan_sha256"] == original.sha256
            && previous["schema"] == SCHEMA
            && previous["first_epoch"] == 201
            && previous["last_epoch"] == 300,
        "capped metadata transition does not bind the original accepted raw plan"
    );
    let claim: Claim = serde_json::from_value(event["claim"].clone())?;
    let input = read_inputs(&claim)?;
    let at = utc_seconds(string(event, "sampled_at_utc")?)?;
    ensure!(
        utc_seconds(sample)? <= at
            && at <= now
            && now - at <= 1800
            && input.frame["sampled_at_utc"] == event["sampled_at_utc"],
        "capped metadata event is stale/future"
    );
    let spec = Prepare {
        schema: "jetstreamer-capped204205-fleet-status-spec-v1".into(),
        previous_fleet: serde_json::from_value(event["previous_fleet"].clone())?,
        original_plan: original,
        observer: serde_json::from_value(event["observer"].clone())?,
        claim,
        output_directory: plan_binding
            .path
            .parent()
            .context("derived capped plan parent")?
            .into(),
    };
    let old = bound(&spec.original_plan, true)?;
    let (mut expected, _) = derive_plan(&spec, &old, previous, &input.frame)?;
    let actual = bound(plan_binding, true)?;
    expected["metadata_event"] = actual["metadata_event"].clone();
    ensure!(
        actual == expected,
        "capped transition dropped or changed an unrelated owner, gate, history or plan field"
    );
    Ok(())
}

pub(super) async fn publish() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        matches!(args.len(), 5 | 6)
            && args[3] == "--plan-sha256"
            && (args.len() == 5 || args[5] == "--check-only")
            && unsafe { libc::geteuid() } == 0,
        "usage: publish-capped204205-status CLAIM --plan-sha256 SHA [--check-only]"
    );
    let c: Claim = serde_json::from_value(bound(
        &BoundFile {
            path: args[2].clone().into(),
            sha256: args[4].clone(),
        },
        true,
    )?)?;
    let i = read_inputs(&c)?;
    let f = &i.frame;
    let observer_binding: BoundFile = serde_json::from_value(f["observer"].clone())?;
    let observer = bound(&observer_binding, false)?;
    let names = f["unit_census_after"]
        .as_object()
        .context("capped census absent")?
        .keys()
        .cloned()
        .collect();
    let before = census(&names, 201, 300)?;
    let result = evaluate(
        &c,
        &i,
        &observer,
        &before,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    historical_terminal::current(f, &before)?;
    let status = result.status.context(
        "positively inactive epoch has no new countdown; use exact-owner inactive cleanup",
    )?;
    let directory = Path::new(string(&i.policy, "status_receipt_directory")?);
    let owner = &result.row["unit"];
    let binding = pipeline_status::Binding {
        unit: string(owner, "Id")?.into(),
        invocation_id: string(owner, "InvocationID")?.into(),
        expected_exec_start: string(&result.row, "expected_exec_start")?.into(),
        claim_phase: "capped204205-continuation".into(),
        origin_unit: string(&i.launch, "unit")?.into(),
        origin_invocation_id: string(&i.launch, "invocation_id")?.into(),
        model_path: c.eta_policy.path.clone(),
        model_sha256: c.eta_policy.sha256.clone(),
        fleet_path: c.frame.path.clone(),
        fleet_sha256: c.frame.sha256.clone(),
    };
    binding.validate(c.epoch, &status.phase)?;
    ensure!(
        census(&names, 201, 300)? == before,
        "capped owner changed before metadata publication"
    );
    let publisher_sha = hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?));
    ensure!(
        i.policy["publisher_sha256"] == publisher_sha,
        "sidecar ETA model is not bound to the actual reviewed publisher executable"
    );
    let estimate_path = Path::new(string(&i.policy, "estimate_receipt")?);
    ensure!(
        estimate_path.is_absolute()
            && estimate_path.extension().is_some_and(|s| s == "json")
            && !estimate_path.starts_with(Path::new(string(&i.plan, "run_root")?)),
        "estimate receipt must be a private metadata JSON path outside the producer root"
    );
    if args.len() == 6 {
        return Ok(());
    }
    let estimate = json!({"schema":"jetstreamer-capped204205-publish-estimate-v1",
        "claim":c,"observer":observer_binding,"row":result.row,"status":status,
        "publisher_sha256":publisher_sha,"replay_launch_authorized":false,
        "publication_authorized":false,"r2_mutations":false});
    match fs::symlink_metadata(estimate_path) {
        Ok(_) => ensure!(
            bound(
                &BoundFile {
                    path: estimate_path.into(),
                    sha256: capture::file_sha(estimate_path)?
                },
                true
            )? == estimate,
            "existing estimate receipt differs; preserve it and reconcile the current owner/model"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            capture::write_sealed(estimate_path, &estimate)?
        }
        Err(e) => return Err(e.into()),
    }
    let r2 = r2_config_from_env()?;
    let s3 = s3_client(&r2);
    ensure!(
        get_mutable_object(&s3, &r2.bucket, &format!("epoch-{}.jet.sha256", c.epoch))
            .await?
            .is_none(),
        "sidecar exists; reconcile the ready pair before any countdown update"
    );
    preflight_status_receipt_write(directory)?;
    let (etag, old) = publish_epoch_status(&s3, &r2, &status).await?;
    let receipt = StatusPublicationReceipt {
        schema: PIPELINE_STATUS_RECEIPT_SCHEMA.into(),
        bucket: r2.bucket,
        epoch: c.epoch,
        key: format!("epoch-{}.epoch-status.json", c.epoch),
        status,
        object_etag: etag,
        previous_object_etag: old,
        observer_receipt: c.frame.path,
        observer_receipt_sha256: c.frame.sha256,
        controller_invocation_id: String::new(),
        producer_invocation_id: String::new(),
        authenticated_readback: true,
        verified_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        pipeline_binding: Some(binding),
    };
    write_status_receipt(directory, &receipt)?;
    Ok(())
}
