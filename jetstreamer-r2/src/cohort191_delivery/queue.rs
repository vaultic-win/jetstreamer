//! Custody of the real persistent191 queue; waiting is a manager task, never
//! a fabricated live verifier. This module launches nothing and holds no R2 key.
use super::*;
pub(super) const PHASE: &str = "cohort191-delivery";
pub(super) const UNIT: &str = "horizon-cohort191-delivery-queue-20261023-v1.service";
const ROOT: &str = "/var/lib/jetstreamer/horizon-cohort191-delivery-queue-20261023-v1";
const PROGRAM: &str =
    "/usr/local/lib/jetstreamer/horizon-cohort191-delivery-tools-20261023-v1/jetstreamer-r2";
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    pub plan: Bound,
    pub state: Bound,
}
pub(super) fn scope(phase: &str, unit: &str) -> bool {
    phase == PHASE && unit == UNIT
}
pub(super) fn claim(c: &Claim) -> Result<()> {
    ensure!(
        scope(&c.phase, &c.unit)
            && (191..=194).contains(&c.epoch)
            && is_lower_hex(&c.invocation_id, 32)
            && c.program
                .as_ref()
                .is_some_and(|b| b.path == Path::new(PROGRAM) && is_lower_hex(&b.sha256, 64)),
        "191 queue claim is not the exact native manager"
    );
    Ok(())
}
fn same_bound(v: &Value, b: &Bound) -> Result<bool> {
    Ok(*v == serde_json::to_value(b)?)
}
fn stat(pid: u64) -> Result<u64> {
    ensure!(pid > 0, "191 queue zero PID");
    let text = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let tail = text.rsplit_once(") ").context("191 queue process stat")?.1;
    Ok(tail
        .split_whitespace()
        .nth(19)
        .context("191 queue start ticks")?
        .parse()?)
}
fn process(pid: u64, start: u64, unit: &str, program: &Bound) -> Result<()> {
    member(&program.path, &program.sha256)?;
    ensure!(
        stat(pid)? == start
            && fs::symlink_metadata(format!("/proc/{pid}"))?.uid() == 0
            && fs::read_link(format!("/proc/{pid}/exe"))? == program.path,
        "191 queue/native child PID, start or program changed"
    );
    let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    ensure!(
        cgroup
            .lines()
            .any(|s| s == format!("0::/system.slice/{unit}")),
        "191 native task escaped exact cgroup"
    );
    Ok(())
}
fn rows<'a>(v: &'a Value, name: &str) -> Result<&'a Vec<Value>> {
    v[name]
        .as_array()
        .with_context(|| format!("191 queue {name}"))
}
fn read_head() -> Result<(Bound, Value)> {
    let path = Path::new(ROOT).join("state.json");
    let bytes = read_stable_bounded(&path, 4 << 20, "191 queue current head")?;
    let b = Bound {
        path,
        sha256: hex_lower(&Sha256::digest(&bytes)),
    };
    let v = bound(&b, false)?;
    Ok((b, v))
}
fn eligible_snapshot<'a>(
    rows: &'a [(Bound, Value)],
    cutoff: u64,
) -> Result<Option<&'a (Bound, Value)>> {
    let cutoff = cutoff
        .checked_mul(1000)
        .context("191 queue cutoff overflow")?;
    let mut latest = None;
    let mut previous_revision = 0;
    let mut previous_time = 0;
    for row in rows {
        let revision = row.1["revision"].as_u64().context("191 revision number")?;
        let time = row.1["updated_unix_millis"]
            .as_u64()
            .context("191 revision time")?;
        ensure!(
            revision > previous_revision && time >= previous_time && time > 0,
            "191 queue history has duplicate/reordered/backdated revisions"
        );
        previous_revision = revision;
        previous_time = time;
        if time <= cutoff {
            latest = Some(row);
        }
    }
    Ok(latest)
}
fn selected_state(anchor: &Bound, cutoff: u64) -> Result<(Bound, Value, Bound, Value)> {
    let (head_bound, head) = read_head()?;
    let history = Path::new(ROOT).join("history");
    if !history.try_exists()? {
        ensure!(
            anchor.path == head_bound.path && anchor.sha256 == head_bound.sha256,
            "191 current-only queue anchor changed; capture a real historical revision"
        );
        return Ok((head_bound.clone(), head.clone(), head_bound, head));
    }
    let m = fs::symlink_metadata(&history)?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0 && history.canonicalize()? == history,
        "191 history namespace is not root-private"
    );
    let mut snapshots = Vec::new();
    for entry in fs::read_dir(&history)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .context("191 history name")?;
        if name.starts_with('.') {
            continue;
        }
        ensure!(
            snapshots.len() < 256 && name.starts_with("state-") && name.ends_with(".json"),
            "191 queue history scope/size differs"
        );
        let bytes = read_stable_bounded(&path, 4 << 20, "191 immutable queue revision")?;
        let b = Bound {
            path: path.clone(),
            sha256: hex_lower(&Sha256::digest(&bytes)),
        };
        let v = bound(&b, true)?;
        let revision = v["revision"].as_u64().context("191 history revision")?;
        ensure!(
            name == format!("state-{revision:06}.json"),
            "191 revision filename/body differs"
        );
        snapshots.push((b, v));
    }
    snapshots.sort_by_key(|(_, v)| v["revision"].as_u64().unwrap_or(0));
    let selected = eligible_snapshot(&snapshots, cutoff)?
        .context("191 no real queue revision exists at/before cutoff")?;
    // The sealed capture anchor names a real native snapshot or the actual
    // mutable head namespace; selection is independently performed at cutoff.
    if anchor.path != head_bound.path {
        ensure!(
            snapshots
                .iter()
                .any(|(b, _)| b.path == anchor.path && b.sha256 == anchor.sha256),
            "191 capture anchor is not an actual immutable native revision"
        );
    }
    ensure!(
        head["revision"].as_u64() >= selected.1["revision"].as_u64()
            && snapshots.iter().any(|(_, v)| *v == head),
        "191 current head is not a real persisted native revision"
    );
    Ok((selected.0.clone(), selected.1.clone(), head_bound, head))
}
fn task_shape(
    row: &Value,
    e: &jetstreamer_horizon_observe::cohort191_delivery_model::Epoch,
) -> Result<()> {
    use jetstreamer_horizon_observe::cohort191_delivery_model::Work::{Active, Complete, Queued};
    ensure!(row["epoch"] == e.epoch, "191 queue member order changed");
    let valid = match row["stage"].as_str() {
        Some("queued-full") => {
            matches!(e.full, Queued { .. })
                && matches!(e.plugin, Queued { .. })
                && matches!(e.upload, Queued { .. })
        }
        Some("full-verification") => {
            matches!(e.full, Active { .. })
                && matches!(e.plugin, Queued { .. })
                && matches!(e.upload, Queued { .. })
        }
        Some("queued-plugin") => {
            matches!(e.full, Complete)
                && matches!(e.plugin, Queued { .. })
                && matches!(e.upload, Queued { .. })
        }
        Some("plugin-verification") => {
            matches!(e.full, Complete)
                && matches!(e.plugin, Active { .. })
                && matches!(e.upload, Queued { .. })
        }
        Some("queued-upload") => {
            matches!(e.full, Complete)
                && matches!(e.plugin, Complete)
                && matches!(e.upload, Queued { .. })
        }
        Some("upload") => {
            matches!(e.full, Complete)
                && matches!(e.plugin, Complete)
                && matches!(e.upload, Active { .. })
        }
        Some("readback") => {
            matches!(e.full, Complete)
                && matches!(e.plugin, Complete)
                && matches!(e.upload, Complete)
                && matches!(e.readback, Active { .. })
        }
        Some("source-revalidation") => {
            matches!(e.full, Complete)
                && matches!(e.plugin, Complete)
                && matches!(e.upload, Complete)
                && matches!(e.readback, Complete)
                && matches!(e.source_revalidation_and_sidecar, Active { .. })
        }
        Some("ready") => e.authenticated_ready_pair,
        _ => false,
    };
    ensure!(
        valid,
        "191 native queue stage and numeric forecast disagree"
    );
    let active = matches!(
        row["stage"].as_str(),
        Some(
            "full-verification"
                | "plugin-verification"
                | "upload"
                | "readback"
                | "source-revalidation"
        )
    );
    ensure!(
        row["task_owner"].is_object() == active,
        "191 queued task invents a verifier or active task lacks its actual native child"
    );
    Ok(())
}
fn task_limits(entries: &[Value]) -> Result<()> {
    let verifiers = entries
        .iter()
        .filter(|r| {
            matches!(
                r["stage"].as_str(),
                Some("full-verification" | "plugin-verification")
            )
        })
        .count();
    let syncs = entries
        .iter()
        .filter(|r| {
            matches!(
                r["stage"].as_str(),
                Some("upload" | "readback" | "source-revalidation")
            )
        })
        .count();
    ensure!(
        verifiers <= 1 && syncs <= 1,
        "191 queue exceeds one native verifier/one serial uploader"
    );
    Ok(())
}
fn plan_shape(v: &Value, b: &Binding, p: &Capture) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-cohort191-delivery-queue-plan-v2"
            && v["unit"] == UNIT
            && v["root"] == ROOT
            && v["program"]["path"] == PROGRAM
            && is_lower_hex(v["program"]["sha256"].as_str().unwrap_or(""), 64)
            && p.source_batch
                .as_ref()
                .is_some_and(|s| same_bound(&v["source_batch"], s).unwrap_or(false))
            && p.public_batch
                .as_ref()
                .is_some_and(|s| same_bound(&v["public_batch"], s).unwrap_or(false))
            && p.source_revalidation_policy
                .as_ref()
                .is_some_and(|s| same_bound(&v["source_revalidation_policy"], s).unwrap_or(false)),
        "191 queue plan does not bind native imports/program/tail policy"
    );
    ensure!(
        b.plan.path.starts_with("/usr/local/lib/jetstreamer")
            && (b.state.path == Path::new(ROOT).join("state.json")
                || b.state.path.parent() == Some(Path::new(ROOT).join("history").as_path())),
        "191 queue plan/state namespace changed"
    );
    let slots = rows(v, "task_slots")?;
    let expected: Vec<_> = (191..=194).flat_map(|epoch|["full","plugin","sync"].map(move|stage|
        json!({"epoch":epoch,"stage":stage,"admission_path":Path::new(ROOT).join(format!("admissions/epoch-{epoch}-{stage}.json"))}))).collect();
    ensure!(
        *slots == expected,
        "191 queue task-slot scope/order/paths changed"
    );
    ensure!(
        rows(v, "imported_members")?
            .iter()
            .map(|m| m["epoch"].as_u64())
            .eq((191..=194).map(Some)),
        "191 queue import census changed"
    );
    Ok(())
}
fn child(
    p: &Capture,
    row: &Value,
    manager_iid: &str,
    plan: &Bound,
    cutoff: u64,
) -> Result<(Claim, Value)> {
    let epoch = row["epoch"].as_u64().context("191 queue child epoch")?;
    let stage = row["stage"].as_str().context("191 queue active stage")?;
    let phase = match stage {
        "full-verification" => "full-verification",
        "plugin-verification" => "plugin-verification",
        _ => "upload-readback",
    };
    let owner = &row["task_owner"];
    let program: Bound = serde_json::from_value(owner["program"].clone())?;
    let c = Claim {
        epoch,
        phase: phase.into(),
        unit: owner["unit"].as_str().context("191 task unit")?.into(),
        invocation_id: owner["invocation_id"]
            .as_str()
            .context("191 task IID")?
            .into(),
        expected_exec_start: owner["expected_exec_start"]
            .as_str()
            .context("191 task command")?
            .into(),
        program: Some(program.clone()),
    };
    phase_scope(&c)?;
    let u = fleet::unit(&c.unit)?;
    live(&u, &c)?;
    super::program(&c, &u)?;
    let pid = owner["pid"].as_u64().context("191 task PID")?;
    let start = owner["start_ticks"].as_u64().context("191 task start")?;
    ensure!(
        u["MainPID"].as_str().and_then(|s| s.parse::<u64>().ok()) == Some(pid),
        "191 task is not PID1's actual main process"
    );
    process(pid, start, &c.unit, &program)?;
    let start_ms = pipeline_status::manager_start(&c.unit, &c.invocation_id)?;
    ensure!(
        start_ms
            <= cutoff
                .checked_mul(1000)
                .context("191 child cutoff overflow")?,
        "191 actual child began after sample; no backdating"
    );
    let admission: Bound = serde_json::from_value(owner["admission"].clone())?;
    let a = bound(&admission, false)?;
    let kind = if phase == "full-verification" {
        "full"
    } else if phase == "plugin-verification" {
        "plugin"
    } else {
        "sync"
    };
    ensure!(
        admission.path == Path::new(ROOT).join(format!("admissions/epoch-{epoch}-{kind}.json"))
            && a["schema"] == "jetstreamer-cohort191-delivery-queue-admission-v2"
            && a["queue_invocation_id"] == manager_iid
            && same_bound(&a["queue_plan"], plan)?
            && a["epoch"] == epoch
            && a["stage"] == kind,
        "191 task admission belongs to another queue/epoch/stage"
    );
    let launch: Bound = serde_json::from_value(owner["launch_receipt"].clone())?;
    let l = bound(&launch, false)?;
    if kind != "sync" {
        let d: Bound = serde_json::from_value(a["dispatch_plan"].clone())?;
        let d = bound(&d, true)?;
        ensure!(
            d["schema"] == "jetstreamer-cohort191-verification-dispatch-plan-v1"
                && d["epoch"] == epoch
                && d["stage"] == kind
                && d["program"] == owner["program"]
                && p.source_batch
                    .as_ref()
                    .is_some_and(|s| same_bound(&d["source_batch"], s).unwrap_or(false))
                && p.public_batch
                    .as_ref()
                    .is_some_and(|s| same_bound(&d["public_batch"], s).unwrap_or(false))
                && l["schema"] == "jetstreamer-cohort191-verification-dispatch-launch-v1"
                && l["epoch"] == epoch
                && l["stage"] == kind
                && l["native_owner"]["Id"] == c.unit
                && l["native_owner"]["InvocationID"] == c.invocation_id
                && l["process_identity"]["pid"] == pid
                && l["process_identity"]["start_ticks"] == start,
            "191 verifier lacks its actual imported/native dispatcher launch"
        );
    } else {
        let sync: Bound = serde_json::from_value(a["sync_plan"].clone())?;
        let s = bound(&sync, true)?;
        ensure!(
            s["schema"] == "jetstreamer-cohort191-sync-plan-v2"
                && s["epoch"] == epoch
                && s["program"] == owner["program"]
                && same_bound(&s["queue_plan"], plan)?
                && s["queue_invocation_id"] == manager_iid
                && a["observer"] == s["observer"]
                && a["routine_completion"] == s["routine_completion"]
                && a["other_pending_os_growth_bytes"] == s["other_pending_os_growth_bytes"]
                && a["observer"].is_object()
                && a["routine_completion"].is_object()
                && a["other_pending_os_growth_bytes"].is_u64()
                && l["resource_admission"].is_object()
                && s["source_revalidation_policy"]
                    == serde_json::to_value(
                        p.source_revalidation_policy
                            .as_ref()
                            .context("191 queue tail policy")?
                    )?
                && l["sync_plan"] == serde_json::to_value(&sync)?
                && l["schema"] == "jetstreamer-cohort191-sync-launch-v2"
                && l["epoch"] == epoch
                && l["native_owner"]["Id"] == c.unit
                && l["native_owner"]["InvocationID"] == c.invocation_id
                && l["process_identity"]["pid"] == pid
                && l["process_identity"]["start_ticks"] == start,
            "191 uploader lacks its actual separately admitted native sync launch"
        );
        ensure!(
            sync_epoch(&c.phase, &c.unit) == Some(epoch) && program.path == Path::new(PROGRAM),
            "191 queue adopted another uploader namespace/program"
        );
        let expected = vec![
            PROGRAM.to_string(),
            "sync".into(),
            "/home/sol/horizon".into(),
            "--epochs".into(),
            format!("{epoch}-{epoch}"),
            "--receipt-directory".into(),
            "/home/sol/.jetstreamer-private/r2-receipts".into(),
            "--part-size-mib".into(),
            "64".into(),
            "--concurrency".into(),
            "2".into(),
        ];
        ensure!(
            l["exec_argv"] == json!(expected),
            "191 uploader launcher approved a different sync command"
        );
        let bytes = fs::read(format!("/proc/{pid}/cmdline"))?;
        ensure!(
            bytes.len() <= 8192 && bytes.last() == Some(&0),
            "191 actual sync argv framing"
        );
        let argv = bytes[..bytes.len() - 1]
            .split(|b| *b == 0)
            .map(|b| std::str::from_utf8(b).map(str::to_owned))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(
            argv == expected && stat(pid)? == start,
            "191 same-PID uploader exec transition differs from native launch"
        );
    }
    ensure!(
        pipeline_status::same_exec_start(
            &c.expected_exec_start,
            l["native_owner"]["ExecStart"]
                .as_str()
                .context("191 actual launcher command")?
        ),
        "191 actual native launcher command differs from queue owner binding"
    );
    Ok((c, u))
}
pub(super) fn observe(
    p: &Capture,
    forecast: &jetstreamer_horizon_observe::cohort191_delivery_model::Plan,
    census: &BTreeMap<String, Value>,
    cutoff: u64,
) -> Result<Option<Value>> {
    let Some(b) = &p.queue else {
        ensure!(
            !p.claims.iter().any(|c| c.phase == PHASE),
            "191 queue owner lacks queue bindings"
        );
        return Ok(None);
    };
    let plan = bound(&b.plan, true)?;
    plan_shape(&plan, b, p)?;
    let materialized: BTreeSet<_> = forecast
        .epochs
        .iter()
        .filter(|e| !e.authenticated_ready_pair)
        .map(|e| e.epoch)
        .collect();
    if materialized.is_empty() {
        return Ok(None);
    }
    plan_check(&b.plan, &materialized)?;
    let (selected_bound, state, head_bound, head) = selected_state(&b.state, cutoff)?;
    let working: Vec<_> = p.claims.iter().filter(|c| c.phase == PHASE).collect();
    ensure!(
        !working.is_empty() && working.len() == p.claims.len(),
        "191 queue cannot mix another owner for its managed members"
    );
    let owner = working[0];
    claim(owner)?;
    let u = census
        .get(UNIT)
        .context("191 queue absent from actual manager census")?;
    live(u, owner)?;
    super::program(owner, u)?;
    ensure!(
        working
            .iter()
            .all(|c| c.invocation_id == owner.invocation_id
                && c.expected_exec_start == owner.expected_exec_start)
            && state["schema"] == "jetstreamer-cohort191-delivery-queue-state-v2"
            && state["unit"] == UNIT
            && state["status"] == "managing"
            && state["invocation_id"] == owner.invocation_id
            && same_bound(&state["plan"], &b.plan)?
            && state["revision"].as_u64().is_some_and(|n| n > 0)
            && state["updated_unix_millis"]
                .as_u64()
                .is_some_and(|n| n > 0 && n <= cutoff.saturating_mul(1000)),
        "191 queue state is failed, stale-owner, future or foreign"
    );
    let expected = format!(
        "{{ path={PROGRAM} ; argv[]={PROGRAM} delivery-queue-191 {} --plan-sha256 {} --self-sha256 {}",
        b.plan.path.display(),
        b.plan.sha256,
        plan["program"]["sha256"]
            .as_str()
            .context("191 queue program SHA")?
    );
    ensure!(
        prefix(&Value::String(owner.expected_exec_start.clone())) == Some(expected.as_str())
            && owner
                .program
                .as_ref()
                .is_some_and(|b| same_bound(&plan["program"], b).unwrap_or(false)),
        "191 queue is not its exact sealed program/plan command"
    );
    ensure!(
        head["schema"] == state["schema"]
            && head["unit"] == UNIT
            && head["status"] == "managing"
            && head["plan"] == state["plan"]
            && head["invocation_id"] == state["invocation_id"]
            && head["manager_pid"] == state["manager_pid"]
            && head["manager_start_ticks"] == state["manager_start_ticks"]
            && head["updated_unix_millis"].as_u64().is_some_and(|t| t
                <= SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis())
                    .unwrap_or(0) as u64)
            && (head["revision"] == state["revision"]
                || head["updated_unix_millis"]
                    .as_u64()
                    .is_some_and(|t| t > cutoff.saturating_mul(1000))),
        "191 later native state is failed/replaced/backdated; do not hide a live queue failure"
    );
    let pid = state["manager_pid"]
        .as_u64()
        .context("191 queue manager PID")?;
    let start = state["manager_start_ticks"]
        .as_u64()
        .context("191 queue manager start")?;
    ensure!(
        u["MainPID"].as_str().and_then(|s| s.parse::<u64>().ok()) == Some(pid),
        "191 queue main PID changed"
    );
    process(pid, start, UNIT, owner.program.as_ref().unwrap())?;
    let procs = fs::read_to_string(format!("/sys/fs/cgroup/system.slice/{UNIT}/cgroup.procs"))?;
    let members = procs
        .split_whitespace()
        .map(str::parse::<u64>)
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    ensure!(
        members == BTreeSet::from([pid]),
        "191 queue has an unknown/unqualified child"
    );
    let entries = rows(&state, "epochs")?;
    ensure!(
        entries
            .iter()
            .map(|r| r["epoch"].as_u64())
            .eq((191..=194).map(Some)),
        "191 queue task census missing/duplicated"
    );
    task_limits(entries)?;
    let imported = rows(&plan, "imported_members")?;
    let mut verifiers = 0;
    let mut syncs = 0;
    let mut observations = BTreeMap::new();
    for ((row, e), imported) in entries.iter().zip(&forecast.epochs).zip(imported) {
        task_shape(row, e)?;
        ensure!(
            row["archive_sha256"] == imported["archive_sha256"]
                && row["archive_length"] == imported["archive_length"],
            "191 queue changed imported digest/length"
        );
        for (field, stage) in [("full_receipt", "full"), ("plugin_receipt", "plugin")] {
            if let Some(b) = p.gate_receipts.get(&e.epoch).and_then(|m| m.get(stage)) {
                ensure!(
                    same_bound(&row[field], b)?,
                    "191 queue/current gate receipt differs"
                );
            }
        }
        if e.authenticated_ready_pair {
            ensure!(
                p.ready_receipts.get(&e.epoch).is_some_and(|b| same_bound(
                    &row["ready_receipt"],
                    b
                )
                .unwrap_or(false)),
                "191 queue invented ready completion"
            );
        }
        if row["task_owner"].is_object() {
            let (c, u) = child(p, row, &owner.invocation_id, &b.plan, cutoff)?;
            if c.phase == "upload-readback" {
                syncs += 1;
                observations.insert(
                    e.epoch,
                    sync_observation(&c, &u, e, cutoff, p.source_revalidation_policy.as_ref())?,
                );
            } else {
                verifiers += 1;
            }
        }
    }
    ensure!(
        verifiers <= 1 && syncs <= 1,
        "191 queue exceeds its one verifier/one uploader envelope"
    );
    ensure!(
        bound(
            &selected_bound,
            selected_bound.path != Path::new(ROOT).join("state.json")
        )? == state
            && read_head()?.0.sha256 == head_bound.sha256
            && fleet::unit(UNIT)? == *u
            && stat(pid)? == start,
        "191 queue state/manager changed during capture"
    );
    Ok(Some(
        json!({"schema":"jetstreamer-cohort191-delivery-queue-observation-v2","plan":b.plan,"state":selected_bound,"current_head":head_bound,
        "post_cutoff_transition":if head["revision"] != state["revision"] {json!({"state":head,"backdated":false})} else {Value::Null},
        "revision":state["revision"],"manager":u,"manager_start_ticks":start,"epochs":entries,
        "sync_observations":observations,"resource_samples":0,"publication_authorized":false,"r2_mutations":false}),
    ))
}

pub(super) fn sync_epoch(phase: &str, unit: &str) -> Option<u64> {
    if phase != "upload-readback" {
        return None;
    }
    (191..=194).find(|e| unit == format!("horizon-r2-sync-{e}-native191-20261023-v1.service"))
}
/// Root caller uses this before admitting a real manager. Metadata validation
/// separately binds the actual queue PID/IID and every mutable task transition.
pub(super) fn plan_check(b: &Bound, materialized: &BTreeSet<u64>) -> Result<Value> {
    let v = bound(b, true)?;
    ensure!(
        v["schema"] == "jetstreamer-cohort191-delivery-queue-plan-v2"
            && v["unit"] == UNIT
            && v["root"] == ROOT
            && v["program"]["path"] == PROGRAM,
        "191 queue plan namespace/program differs"
    );
    let program: Bound = serde_json::from_value(v["program"].clone())?;
    member(&program.path, &program.sha256)?;
    let slots = rows(&v, "task_slots")?;
    let expected:Vec<_> = (191..=194).flat_map(|epoch|["full","plugin","sync"].map(move|stage|
        json!({"epoch":epoch,"stage":stage,"admission_path":Path::new(ROOT).join(format!("admissions/epoch-{epoch}-{stage}.json"))}))).collect();
    ensure!(
        *slots == expected,
        "191 queue task-slot scope/order differs"
    );
    let source: Bound = serde_json::from_value(v["source_batch"].clone())?;
    let public: Bound = serde_json::from_value(v["public_batch"].clone())?;
    let import = dispatch_import_check(&source, &public, materialized)?;
    let actual: Vec<_> = rows(&import, "public_members")?
        .iter()
        .map(|m| {
            json!({"epoch":m["epoch"],
        "archive_sha256":m["archive_sha256"],"archive_length":m["committed_archive"]["length"]})
        })
        .collect();
    ensure!(
        v["imported_members"] == json!(actual),
        "191 queue plan invented imported member digest/length"
    );
    let tail: Bound = serde_json::from_value(v["source_revalidation_policy"].clone())?;
    provisional_tail(&tail, 0, 0)?;
    Ok(v)
}
pub(super) fn admission_check(
    b: &Bound,
    plan: &Bound,
    iid: &str,
    epoch: u64,
    stage: &str,
) -> Result<Value> {
    ensure!(
        (191..=194).contains(&epoch)
            && matches!(stage, "full" | "plugin" | "sync")
            && is_lower_hex(iid, 32)
            && b.path == Path::new(ROOT).join(format!("admissions/epoch-{epoch}-{stage}.json")),
        "191 queue intake scope changed"
    );
    let v = bound(b, false)?;
    ensure!(
        v["schema"] == "jetstreamer-cohort191-delivery-queue-admission-v2"
            && v["queue_invocation_id"] == iid
            && same_bound(&v["queue_plan"], plan)?
            && v["epoch"] == epoch
            && v["stage"] == stage,
        "191 queue intake borrowed another invocation/step"
    );
    let field = if stage == "sync" {
        "sync_plan"
    } else {
        "dispatch_plan"
    };
    let task: Bound = serde_json::from_value(v[field].clone())?;
    let spec = bound(&task, true)?;
    ensure!(
        spec["epoch"] == epoch && (stage == "sync" || spec["stage"] == stage),
        "191 queue intake task differs"
    );
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jetstreamer_horizon_observe::cohort191_delivery_model::{Epoch, Work};
    fn queued() -> Epoch {
        Epoch {
            epoch: 191,
            full: Work::Queued {
                remaining_millis: 1,
            },
            plugin: Work::Queued {
                remaining_millis: 1,
            },
            boundary: Work::Complete,
            upload: Work::Queued {
                remaining_millis: 1,
            },
            readback: Work::Queued {
                remaining_millis: 1,
            },
            source_revalidation_and_sidecar: Work::Queued {
                remaining_millis: 1,
            },
            authenticated_ready_pair: false,
        }
    }
    #[test]
    fn real_queue_can_own_waiting_steps_but_cannot_invent_active_verifier_children() {
        let e = queued();
        let row = json!({"epoch":191,"stage":"queued-full","task_owner":null});
        task_shape(&row, &e).unwrap();
        let mut bad = row.clone();
        bad["task_owner"] = json!({"pid":1});
        assert!(task_shape(&bad, &e).is_err());
        let mut bad = row;
        bad["stage"] = json!("full-verification");
        assert!(task_shape(&bad, &e).is_err());
        let mut active = e;
        active.full = Work::Active {
            remaining_millis: 1,
        };
        assert!(task_shape(&bad, &active).is_err());
        bad["task_owner"] = json!({"pid":1});
        task_shape(&bad, &active).unwrap();
        // child() still independently validates actual PID1/proc/program/launch.
        bad["stage"] = json!("upload");
        assert!(task_shape(&bad, &active).is_err());
        bad["stage"] = json!("ready");
        assert!(task_shape(&bad, &active).is_err());
    }
    #[test]
    fn verifier_and_sync_overlap_is_bounded_independently() {
        let valid = vec![
            json!({"stage":"full-verification"}),
            json!({"stage":"readback"}),
            json!({"stage":"queued-full"}),
        ];
        task_limits(&valid).unwrap();
        let mut invalid = valid.clone();
        invalid.push(json!({"stage":"plugin-verification"}));
        assert!(task_limits(&invalid).is_err());
        let mut invalid = valid;
        invalid.push(json!({"stage":"source-revalidation"}));
        assert!(task_limits(&invalid).is_err());
    }
    #[test]
    fn selects_real_cutoff_revision_and_never_backdates_later_native_state() {
        let b = |n| Bound {
            path: format!("/history/{n}").into(),
            sha256: "a".repeat(64),
        };
        let revisions = vec![
            (b(1), json!({"revision":1,"updated_unix_millis":1000})),
            (b(2), json!({"revision":2,"updated_unix_millis":2001})),
            (b(3), json!({"revision":3,"updated_unix_millis":3000})),
        ];
        assert_eq!(
            eligible_snapshot(&revisions, 2).unwrap().unwrap().1["revision"],
            1
        );
        assert_eq!(
            eligible_snapshot(&revisions, 3).unwrap().unwrap().1["revision"],
            3
        );
        assert!(eligible_snapshot(&revisions, 0).unwrap().is_none());
        let mut bad = revisions.clone();
        bad[2].1["updated_unix_millis"] = json!(1500);
        assert!(eligible_snapshot(&bad, 3).is_err());
        let mut bad = revisions;
        bad[2].1["revision"] = json!(2);
        assert!(eligible_snapshot(&bad, 3).is_err());
    }
    #[test]
    fn queue_and_sync_namespaces_cannot_borrow_another_epoch_or_legacy_watcher() {
        assert!(scope(PHASE, UNIT));
        assert!(!scope("full-verification", UNIT));
        for epoch in 191..=194 {
            assert_eq!(
                sync_epoch(
                    "upload-readback",
                    &format!("horizon-r2-sync-{epoch}-native191-20261023-v1.service")
                ),
                Some(epoch)
            );
        }
        assert_eq!(
            sync_epoch(
                "upload-readback",
                "horizon-r2-sync-198-native191-20261023-v1.service"
            ),
            None
        );
        assert_eq!(
            sync_epoch(
                "upload-readback",
                "horizon-r2-progressive-epochs101-200-v21-rust-authenticated.service"
            ),
            None
        );
    }
}
