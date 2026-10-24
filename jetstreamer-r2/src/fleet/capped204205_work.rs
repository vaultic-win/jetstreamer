//! Closed continuation ownership and sidecar estimates. The deployed observer
//! stays unchanged; unavailable replay telemetry never proves inactivity.
use super::*;
mod capture;
mod evidence;
#[cfg(test)]
mod tests;

pub(super) const EVENT_SCHEMA: &str = "jetstreamer-capped204205-fleet-transition-v1";
pub(super) const OBSERVER_SHA: &str =
    "78dc39c3b8cf3e4198e6d2b35348ba764fe1c2ceecbd12cc536090ae8315facd";
const WORKER_SHA: &str = "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc";

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
enum Stage {
    WaitingForGuard,
    PrefixValidation,
    NativeRestore,
    SuffixValidation,
    Assembly,
    FullVerification,
    PluginVerification,
    BoundaryChecks,
    LocalImport,
    Upload,
    Readback,
    SidecarCommit,
}
const STAGES: [Stage; 12] = [
    Stage::WaitingForGuard,
    Stage::PrefixValidation,
    Stage::NativeRestore,
    Stage::SuffixValidation,
    Stage::Assembly,
    Stage::FullVerification,
    Stage::PluginVerification,
    Stage::BoundaryChecks,
    Stage::LocalImport,
    Stage::Upload,
    Stage::Readback,
    Stage::SidecarCommit,
];
impl Stage {
    fn key(self) -> &'static str {
        match self {
            Self::WaitingForGuard => "waiting_for_guard",
            Self::PrefixValidation => "prefix_validation",
            Self::NativeRestore => "native_restore",
            Self::SuffixValidation => "suffix_validation",
            Self::Assembly => "assembly",
            Self::FullVerification => "full_verification",
            Self::PluginVerification => "plugin_verification",
            Self::BoundaryChecks => "boundary_checks",
            Self::LocalImport => "local_import",
            Self::Upload => "upload",
            Self::Readback => "readback",
            Self::SidecarCommit => "sidecar_commit",
        }
    }
    fn public_phase(self) -> &'static str {
        match self {
            Self::NativeRestore => "replay",
            Self::Upload | Self::SidecarCommit => "upload",
            Self::Readback => "readback",
            _ => "verification",
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Claim {
    pub epoch: u64,
    pub producer_plan: BoundFile,
    pub admission: BoundFile,
    pub launch: BoundFile,
    pub frame: BoundFile,
    pub eta_policy: BoundFile,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Actor {
    stage: Stage,
    unit: String,
    invocation_id: String,
    expected_exec_start: String,
    started_unix_millis: u64,
    evidence: Vec<BoundFile>,
}

struct Inputs {
    plan: Value,
    admission: Value,
    launch: Value,
    frame: Value,
    policy: Value,
}
struct Evaluation {
    row: Value,
    status: Option<EpochStatus>,
}

fn number(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .with_context(|| format!("capped work missing integer: {k}"))
}
fn string<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .with_context(|| format!("capped work missing string: {k}"))
}
fn id(v: &str) -> bool {
    v.len() == 32
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && v.bytes().any(|b| b != b'0')
}
fn profile(epoch: u64) -> Result<(&'static str, &'static str, u64, u64)> {
    Ok(match epoch {
        204 => (
            "horizon-qualify-204-shrink-root-prefix-resource-fcbf3992-v1.service",
            "448da7f2a3a34217afe7e115120b3cea",
            88_559_361,
            88_559_999,
        ),
        205 => (
            "horizon-qualify-205-shrink-root-prefix-resource-5c01bf93-v1.service",
            "373359a11aef4993a1a949e19ff617c3",
            88_991_050,
            88_991_999,
        ),
        _ => bail!("capped work is limited to epochs 204 and 205"),
    })
}
fn namespace(epoch: u64, name: &str) -> bool {
    matches!(epoch, 204 | 205)
        && name.starts_with(&format!("horizon-qualify-{epoch}-capped-continuation-"))
        && name.ends_with(".service")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
fn live(v: &Value) -> bool {
    v["LoadState"] == "loaded"
        && v["NRestarts"] == "0"
        && v["ActiveState"] == "active"
        && v["SubState"] == "running"
        && v["MainPID"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .is_some_and(|n| n > 1)
}
fn idle(v: &Value) -> bool {
    v["MainPID"] == "0"
        && v["NRestarts"] == "0"
        && matches!(v["ActiveState"].as_str(), Some("inactive" | "failed"))
        && matches!(v["SubState"].as_str(), Some("dead" | "failed" | "exited"))
        && matches!(v["LoadState"].as_str(), Some("loaded" | "not-found"))
}
fn denied(v: &Value) -> Result<()> {
    for k in [
        "replay_launch_authorized",
        "publication_authorized",
        "r2_mutations",
    ] {
        ensure!(
            v[k] == false,
            "capped work grants execution/publication authority: {k}"
        );
    }
    Ok(())
}

fn read_inputs(c: &Claim) -> Result<Inputs> {
    profile(c.epoch)?;
    Ok(Inputs {
        plan: evidence::bound(&c.producer_plan, true)?,
        admission: evidence::bound(&c.admission, true)?,
        launch: evidence::bound(&c.launch, true)?,
        frame: evidence::bound(&c.frame, true)?,
        policy: evidence::bound(&c.eta_policy, true)?,
    })
}
fn validate_origin(c: &Claim, i: &Inputs) -> Result<()> {
    let p = &i.plan;
    let a = &i.admission;
    let l = &i.launch;
    let (_, _, restart, end) = profile(c.epoch)?;
    let unit = string(p, "producer_unit")?;
    let iid = string(l, "invocation_id")?;
    ensure!(
        p["schema"] == "jetstreamer-capped204205-continuation-plan-v1"
            && p["epoch"] == c.epoch
            && namespace(c.epoch, unit)
            && p["worker"]["sha256"] == WORKER_SHA
            && a["schema"] == "jetstreamer-capped204205-continuation-admission-v1"
            && a["admitted"] == true
            && a["producer_plan"] == private157::binding(&c.producer_plan)
            && a["plan_sha256"] == c.producer_plan.sha256
            && a["epoch"] == c.epoch
            && a["producer_unit"] == p["producer_unit"]
            && a["guard_unit"] == p["guard_unit"]
            && a["node_sha256"] == p["node_sha256"]
            && a["guard_sha256"] == p["guard_sha256"]
            && l["schema"] == "jetstreamer-capped204205-continuation-launch-v1"
            && l["epoch"] == c.epoch
            && l["producer_plan"] == private157::binding(&c.producer_plan)
            && l["admission"] == private157::binding(&c.admission)
            && l["unit"] == p["producer_unit"]
            && l["guard_unit"] == p["guard_unit"]
            && id(iid)
            && l["node_sha256"] == p["node_sha256"]
            && l["guard_sha256"] == p["guard_sha256"]
            && l["restart_slot"] == restart
            && l["terminal_slot"] == end
            && number(l, "epoch_started_unix_millis")? <= number(l, "recorded_unix_millis")?
            && number(a, "recorded_unix_millis")? <= number(l, "recorded_unix_millis")?
            && number(l, "recorded_unix_millis")? - number(a, "recorded_unix_millis")? <= 900_000,
        "capped work lacks the actual exact admitted launch/source identities"
    );
    denied(l)?;
    for key in [
        "canonical_sidecar_authorized",
        "publication_authorized",
        "r2_mutations",
    ] {
        ensure!(a[key] == false, "admission grants final archive authority");
    }
    Ok(())
}
fn stage_from_guard(g: &Value) -> Result<Stage> {
    Ok(match string(&g["phase"], "stage")? {
        "waiting_for_guard" => Stage::WaitingForGuard,
        "prefix_validation" => Stage::PrefixValidation,
        "native_restore" => Stage::NativeRestore,
        "suffix_validation" => Stage::SuffixValidation,
        "assembly" | "complete" => Stage::Assembly,
        _ => bail!("unknown actual capped guard stage"),
    })
}

fn remaining(policy: &Value, stage: Stage, elapsed: u64) -> Result<u64> {
    ensure!(
        policy["schema"] == "jetstreamer-capped204205-sidecar-estimate-policy-v1"
            && !string(policy, "estimate_basis")?.trim().is_empty()
            && policy["sidecar_inclusive"] == true
            && policy["estimates_are_current_best_guesses"] == true,
        "capped ETA must be a documented current best guess through sidecar commit"
    );
    denied(policy)?;
    let allowances = policy["stage_allowance_millis"]
        .as_object()
        .context("capped stage allowances")?;
    ensure!(
        allowances.len() == STAGES.len()
            && STAGES.iter().all(|s| allowances
                .get(s.key())
                .and_then(Value::as_u64)
                .is_some_and(|n| n > 0)),
        "capped ETA omitted a required verification/upload/readback/sidecar stage"
    );
    let overrun = number(policy, "current_stage_overrun_remaining_millis")?;
    ensure!(
        overrun > 0,
        "capped ETA overrun guess must remain definite and positive"
    );
    let mut total = 0u64;
    for s in STAGES.into_iter().filter(|s| *s >= stage) {
        let allowance = number(&policy["stage_allowance_millis"], s.key())?;
        let value = if s == stage {
            allowance
                .checked_sub(elapsed)
                .filter(|n| *n > 0)
                .unwrap_or(overrun)
        } else {
            allowance
        };
        total = total
            .checked_add(value)
            .context("capped sidecar estimate overflow")?;
    }
    Ok(total)
}

fn evaluate(
    c: &Claim,
    i: &Inputs,
    observer: &Value,
    census: &BTreeMap<String, Value>,
    now: u64,
) -> Result<Evaluation> {
    validate_origin(c, i)?;
    let f = &i.frame;
    let p = &i.plan;
    let l = &i.launch;
    let sample = string(f, "sampled_at_utc")?;
    let sample_ms = number(f, "sampled_unix_millis")?;
    ensure!(
        sample_ms / 1000 == utc_seconds(sample)?,
        "metadata UTC and millisecond clocks differ"
    );
    let resource_ms = utc_seconds(string(observer, "recorded_at_utc")?)?
        .checked_mul(1000)
        .context("resource time overflow")?;
    let observed: BoundFile = serde_json::from_value(f["observer"].clone())?;
    let executable: BoundFile = serde_json::from_value(f["observer_executable"].clone())?;
    ensure!(
        executable.sha256 == OBSERVER_SHA
            && f["observer_source_revision"] == "3e9326815cf46d03ac9423d5bcf4c637774b7260"
            && evidence::bound(&observed, false)? == *observer,
        "capped work detached from deployed corrected observer provenance"
    );
    evidence::bytes(&executable, true)?;
    ensure!(
        f["schema"] == "jetstreamer-capped204205-work-frame-v1"
            && f["epoch"] == c.epoch
            && f["producer_plan_sha256"] == c.producer_plan.sha256
            && f["launch"] == private157::binding(&c.launch)
            && f["observer_executable_sha256"] == OBSERVER_SHA
            && observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && resource_ms <= sample_ms
            && resource_ms / 1000 <= now
            && now - resource_ms / 1000 <= 1800
            && sample_ms / 1000 <= now
            && now - sample_ms / 1000 <= 1800
            && f["unit_census_before"] == f["unit_census_after"]
            && f["unit_census_after"] == serde_json::to_value(census)?,
        "capped work frame is stale, changed, or detached from the coordinated complete census"
    );
    denied(f)?;
    let unit = string(p, "producer_unit")?;
    let producer = census
        .get(unit)
        .context("capped producer absent from census")?;
    let actors: Vec<Actor> = serde_json::from_value(f["downstream_actors"].clone())?;
    let mut active: Vec<(&str, &str, &str, Stage, u64)> = Vec::new();
    for (name, current) in census {
        ensure!(
            !capture::epoch_scope(c.epoch, name)
                || !live(current)
                || name == unit
                || name == string(p, "guard_unit")?
                || actors.iter().any(|a| a.unit == *name),
            "an unregistered live continuation/downstream owner holds this epoch"
        );
    }
    if live(producer) {
        ensure!(
            producer["InvocationID"] == l["invocation_id"]
                && pipeline_status::same_exec_start(
                    string(l, "expected_exec_start")?,
                    string(producer, "ExecStart")?
                ),
            "capped producer command or invocation changed"
        );
        let guard = evidence::bound(&serde_json::from_value(f["guard_snapshot"].clone())?, true)?;
        evidence::guard(p, l, &guard, census, sample_ms)?;
        let stage = stage_from_guard(&guard)?;
        active.push((
            unit,
            string(l, "invocation_id")?,
            string(l, "expected_exec_start")?,
            stage,
            number(&guard["phase"], "started_unix_millis")?,
        ));
    } else {
        ensure!(
            idle(producer),
            "capped producer is neither positively active nor terminal"
        );
    }
    for actor in &actors {
        evidence::actor(c.epoch, c, &i.launch, actor)?;
        let current = census
            .get(&actor.unit)
            .context("downstream owner omitted")?;
        if live(current) {
            ensure!(
                current["InvocationID"] == actor.invocation_id
                    && pipeline_status::same_exec_start(
                        &actor.expected_exec_start,
                        string(current, "ExecStart")?
                    ),
                "capped downstream owner changed"
            );
            active.push((
                &actor.unit,
                &actor.invocation_id,
                &actor.expected_exec_start,
                actor.stage,
                actor.started_unix_millis,
            ));
        } else {
            ensure!(idle(current), "downstream owner is pending or unknown");
        }
    }
    ensure!(
        active.len() <= 1,
        "capped continuation and downstream owners overlap"
    );
    let mut row = json!({"epoch":c.epoch,"launch":private157::binding(&c.launch),"frame":private157::binding(&c.frame),
        "producer_plan":private157::binding(&c.producer_plan),"eta_policy":private157::binding(&c.eta_policy),
        "origin_unit":unit,"origin_invocation_id":l["invocation_id"],"work_sampled_at_utc":sample,
        "ordinary_replay_claim":false,"full_epoch_verified":false,"publication_authorized":false,"r2_mutations":false,
        "private_qualification_only":true,"scratch_path":p["run_root"],"sampled_at_utc":observer["recorded_at_utc"],
        "live":!active.is_empty(),"positive_inactivity_confirmed":false,"current_sidecar_eta_valid":false});
    if let Some((name, iid, command, stage, started)) = active.first().copied() {
        ensure!(
            started <= sample_ms,
            "active capped stage started after sample"
        );
        let elapsed = sample_ms
            .checked_sub(number(l, "epoch_started_unix_millis")?)
            .context("epoch elapsed clock overflow")?;
        let eta = remaining(&i.policy, stage, sample_ms - started)?;
        sample_ms
            .checked_add(eta)
            .context("absolute sidecar ETA overflow")?;
        let generated = evidence::generated_bytes(p, f)?;
        let status = EpochStatus {
            epoch: c.epoch,
            jet_size_bytes: generated,
            elapsed_execution_millis: elapsed,
            estimated_remaining_millis: eta
                .checked_add(sample_ms % 1000)
                .context("sidecar alignment overflow")?,
            sampled_at_utc: sample.into(),
            phase: stage.public_phase().into(),
        };
        row["phase"] = json!("capped204205-continuation");
        row["unit"] = census[name].clone();
        row["current_stage"] = json!(stage);
        row["expected_exec_start"] = json!(command);
        row["invocation_id"] = json!(iid);
        row["status"] = serde_json::to_value(&status)?;
        row["current_sidecar_eta_valid"] = json!(true);
        Ok(Evaluation {
            row,
            status: Some(status),
        })
    } else {
        evidence::inactive(p, l, f, census)?;
        row["positive_inactivity_confirmed"] = json!(true);
        row["state"] = json!("blocked-qualification");
        row["next_action"] = json!(
            "Preserve actual terminal evidence and private artifacts; advance the next independently qualified stage or repair the failed stage"
        );
        Ok(Evaluation { row, status: None })
    }
}

pub(super) fn names(c: &Claim) -> Result<BTreeSet<String>> {
    let i = read_inputs(c)?;
    validate_origin(c, &i)?;
    let mut names = BTreeSet::from([
        string(&i.plan, "producer_unit")?.into(),
        string(&i.plan, "guard_unit")?.into(),
    ]);
    let (old, _, _, _) = profile(c.epoch)?;
    names.insert(old.into());
    for a in serde_json::from_value::<Vec<Actor>>(i.frame["downstream_actors"].clone())? {
        names.insert(a.unit);
    }
    Ok(names)
}

pub(super) fn rows(
    claims: &[Claim],
    observer: &Value,
    census: &BTreeMap<String, Value>,
    now: u64,
) -> Result<Vec<Value>> {
    let mut epochs = BTreeSet::new();
    claims
        .iter()
        .map(|c| {
            ensure!(epochs.insert(c.epoch), "duplicate capped epoch claim");
            Ok(evaluate(c, &read_inputs(c)?, observer, census, now)?.row)
        })
        .collect()
}

pub(super) fn status_matches(
    publication: &StatusPublicationReceipt,
    epoch: u64,
    rows: &[Value],
) -> bool {
    publication.pipeline_binding.as_ref().is_some_and(|b| {
        b.claim_phase == "capped204205-continuation"
            && rows.iter().any(|r| {
                r["epoch"] == epoch
                    && r["live"] == true
                    && r["current_sidecar_eta_valid"] == true
                    && r["unit"]["Id"] == b.unit
                    && r["unit"]["InvocationID"] == b.invocation_id
                    && r["frame"]["path"].as_str() == b.fleet_path.to_str()
                    && r["frame"]["sha256"] == b.fleet_sha256
                    && r["eta_policy"]["path"].as_str() == b.model_path.to_str()
                    && r["eta_policy"]["sha256"] == b.model_sha256
                    && r["origin_unit"] == b.origin_unit
                    && r["origin_invocation_id"] == b.origin_invocation_id
                    && r["status"]
                        == serde_json::to_value(&publication.status).unwrap_or(Value::Null)
            })
    })
}

pub(super) fn event_predecessor(
    previous: &Value,
    plan: &Plan,
    binding: &BoundFile,
    event: &Value,
    sample: &str,
    now: u64,
) -> Result<()> {
    evidence::event_predecessor(previous, plan, binding, event, sample, now)
}

pub(super) fn binding_scope(epoch: u64, unit: &str, phase: &str) -> Result<()> {
    profile(epoch)?;
    ensure!(
        matches!(phase, "replay" | "verification" | "upload" | "readback"),
        "illegal dashboard phase for capped work"
    );
    if namespace(epoch, unit) {
        ensure!(
            matches!(phase, "replay" | "verification"),
            "continuation cannot claim upload/readback"
        );
        return Ok(());
    }
    for kind in [
        "full-verification",
        "plugin-verification",
        "local-publication",
        "upload-readback",
    ] {
        if pipeline_unit_range(kind, unit).is_ok_and(|r| r == (epoch..=epoch)) {
            ensure!(
                if kind == "upload-readback" {
                    matches!(phase, "upload" | "readback")
                } else {
                    phase == "verification"
                },
                "downstream owner and public dashboard phase disagree"
            );
            return Ok(());
        }
    }
    bail!("capped status owner is outside its exact continuation/downstream scope")
}
pub(super) fn origin_scope(epoch: u64, unit: &str) -> Result<()> {
    ensure!(
        namespace(epoch, unit),
        "capped origin is not the exact original continuation namespace"
    );
    Ok(())
}

pub(super) fn capture() -> Result<()> {
    capture::run()
}
pub(super) fn prepare() -> Result<()> {
    evidence::prepare()
}
pub(super) async fn publish() -> Result<()> {
    evidence::publish().await
}
