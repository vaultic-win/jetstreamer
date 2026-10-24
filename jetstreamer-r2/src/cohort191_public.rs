//! Actual native queue -> same coordinated observation -> four numeric statuses.
use super::*;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextPlan {
    schema: String,
    publisher: Bound,
    terminal: Bound,
    queue_plan: Bound,
    estimate_evidence: Bound,
    source_revalidation_policy: Bound,
    gate_tools: BTreeMap<String, GateTool>,
    boundary_budget_millis: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observe {
    schema: String,
    context: Bound,
    observer: Bound,
    output: PathBuf,
    #[serde(default)]
    native_handoff_event: bool,
}
fn queued(n: u64) -> Value {
    json!({"state":"queued","remaining_millis":n})
}
fn full_done(stage: &str) -> bool {
    !matches!(stage, "queued-full" | "full-verification")
}
fn plugin_done(stage: &str) -> bool {
    matches!(
        stage,
        "queued-upload" | "upload" | "readback" | "source-revalidation" | "ready"
    )
}
fn sum(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b)
        .context("191 verifier queue budget overflow")
}
fn verification(
    stage: &str,
    lane: u64,
    full: u64,
    plugin: u64,
    elapsed: Option<u64>,
) -> Result<(Value, Value, u64)> {
    ensure!(
        full > 0 && plugin > 0,
        "191 verifier budgets must be positive"
    );
    let complete = json!({"state":"complete"});
    match stage {
        "queued-full" => {
            let f = sum(lane, full)?;
            let p = sum(f, plugin)?;
            Ok((queued(f), queued(p), p))
        }
        "queued-plugin" => {
            let p = sum(lane, plugin)?;
            Ok((complete, queued(p), p))
        }
        "full-verification" | "plugin-verification" => {
            ensure!(
                lane == 0,
                "191 actual verifier overlaps unfinished serial predecessor"
            );
            let allowance = if stage == "full-verification" {
                full
            } else {
                plugin
            };
            let rem = tail_budget(
                allowance,
                600000,
                elapsed.context("191 active verifier clock missing")?,
            )?;
            let active = json!({"state":"active","remaining_millis":rem});
            if stage == "full-verification" {
                let p = sum(rem, plugin)?;
                Ok((active, queued(p), p))
            } else {
                Ok((complete, active, rem))
            }
        }
        "queued-upload" | "upload" | "readback" | "source-revalidation" | "ready" => {
            Ok((complete.clone(), complete, lane))
        }
        _ => bail!("191 unsupported native queue stage"),
    }
}
pub(super) fn run() -> Result<()> {
    let a: Vec<_> = env::args().collect();
    ensure!(
        unsafe { libc::geteuid() } == 0
            && a.len() == 7
            && a[1] == "observe-public191"
            && a[3] == "--plan-sha256"
            && a[5] == "--self-sha256",
        "observe-public191 PLAN --plan-sha256 SHA --self-sha256 SHA"
    );
    let pb = Bound {
        path: a[2].clone().into(),
        sha256: a[4].clone(),
    };
    let p: Observe = serde_json::from_value(bound(&pb, true)?)?;
    let ctx: ContextPlan = serde_json::from_value(bound(&p.context, true)?)?;
    ensure!(
        p.schema == "jetstreamer-cohort191-public-observation-plan-v1"
            && ctx.schema == "jetstreamer-cohort191-public-context-v1"
            && collected::is_program(&ctx.publisher.path)
            && ctx.publisher.sha256 == a[6]
            && fs::read_link("/proc/self/exe")? == ctx.publisher.path
            && ctx.boundary_budget_millis > 0,
        "191 public context/self differs"
    );
    member(&ctx.publisher.path, &ctx.publisher.sha256)?;
    let observer = bound(&p.observer, false)?;
    let resource_time = fleet::utc_seconds(
        observer["recorded_at_utc"]
            .as_str()
            .context("191 public sample time")?,
    )?;
    let (cutoff, native_event_clock) = if p.native_handoff_event {
        let event = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let (head, state) = queue::read_head()?;
        let revision = state["revision"].as_u64().context("191 native revision")?;
        let immutable_state = Bound {
            path: Path::new(
                "/var/lib/jetstreamer/horizon-cohort191-delivery-queue-20261023-v1/history",
            )
            .join(format!("state-{revision:06}.json")),
            sha256: head.sha256,
        };
        bound(&immutable_state, true)?;
        let clock = json!({"schema":"jetstreamer-cohort191-native-handoff-clock-v2","observer":p.observer,
            "recorded_unix_seconds":event,"sampled_at_utc":native_clock::utc(event)?,
            "queue_state":immutable_state,"recovery_anchor":{"path":"/var/lib/jetstreamer/horizon-cohort191-delivery-queue-20261023-v1/history/state-000003.json","sha256":"3e3d7ee6f52fdfca86504c1125e1d7d790a4277636d89e0fe1b4c4886acc2a7a"},"queue_plan":ctx.queue_plan,"queue_invocation_id":state["invocation_id"],
            "terminal":ctx.terminal,"resource_samples_taken":0,"publication_authorized":false,"r2_mutations":false});
        let path = p.output.with_extension("native-clock.json");
        fleet::persist(&path, &clock)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
        File::open(&path)?.sync_all()?;
        File::open(path.parent().context("191 event clock directory")?)?.sync_all()?;
        let b = Bound {
            sha256: hex_lower(&Sha256::digest(fs::read(&path)?)),
            path,
        };
        (event, Some(b))
    } else {
        (resource_time, None)
    };
    let terminal = bound(&ctx.terminal, false)?;
    jetstreamer_horizon_observe::cohort191_delivery_model::validate_terminal_transition(
        &terminal, cutoff,
    )?;
    let evidence = bound(&ctx.estimate_evidence, true)?;
    ensure!(
        ctx.estimate_evidence.sha256
            == "95beb37d053abc0b775ea54f4d4a3b479f1d39445fb4001934ab7ada75e36cff",
        "191 public estimate evidence changed"
    );
    let (head, _) = queue::read_head()?;
    let (selected, state, _, _) = queue::selected_state(&head, cutoff)?;
    let manager = fleet::unit(queue::UNIT)?;
    let iid = manager["InvocationID"]
        .as_str()
        .context("191 actual queue IID")?;
    let mut claims = vec![];
    let mut epochs = vec![];
    let mut gates = BTreeMap::new();
    let mut ready_receipts = BTreeMap::new();
    let mut verify_lane = 0;
    for row in state["epochs"]
        .as_array()
        .context("191 actual queue rows")?
    {
        let epoch = row["epoch"].as_u64().context("191 queue epoch")?;
        let stage = row["stage"].as_str().context("191 queue stage")?;
        let budget = evidence["per_epoch_budgets"]
            .as_array()
            .context("191 measured budgets")?
            .iter()
            .find(|r| r["epoch"] == epoch)
            .context("191 measured epoch budget")?;
        let d = &budget["stage_budgets_millis"];
        let n = |v: &Value| -> Result<u64> {
            let n = v.as_u64().context("191 positive numeric budget")?;
            ensure!(n > 0, "191 empty phase budget");
            Ok(n)
        };
        let elapsed = if matches!(stage, "full-verification" | "plugin-verification") {
            let owner = &row["task_owner"];
            let start = pipeline_status::manager_start(
                owner["unit"].as_str().context("191 verifier unit")?,
                owner["invocation_id"]
                    .as_str()
                    .context("191 verifier IID")?,
            )?;
            Some(
                cutoff
                    .checked_mul(1000)
                    .context("191 phase clock")?
                    .checked_sub(start)
                    .context("191 verifier started after sample")?,
            )
        } else {
            None
        };
        let (mut full, mut plugin, next_lane) = verification(
            stage,
            verify_lane,
            n(&d["full_millis"])?,
            n(&d["plugin_millis"])?,
            elapsed,
        )?;
        verify_lane = next_lane;
        let mut upload = queued(sum(n(&d["source_hash_millis"])?, n(&d["upload_millis"])?)?);
        let mut readback = queued(n(&d["readback_millis"])?);
        let mut tail = queued(n(&budget["source_revalidation_sidecar_millis"])?);
        let complete = json!({"state":"complete"});
        let mut receipts = BTreeMap::new();
        for (field, name, done) in [
            ("full_receipt", "full", full_done(stage)),
            ("plugin_receipt", "plugin", plugin_done(stage)),
        ] {
            if done {
                receipts.insert(
                    name.to_string(),
                    serde_json::from_value::<Bound>(row[field].clone())?,
                );
            }
        }
        if !receipts.is_empty() {
            gates.insert(epoch, receipts);
        }
        if matches!(stage, "upload" | "readback" | "source-revalidation") {
            let owner = &row["task_owner"];
            let c = Claim {
                epoch,
                phase: "upload-readback".into(),
                unit: owner["unit"].as_str().context("191 sync unit")?.into(),
                invocation_id: owner["invocation_id"]
                    .as_str()
                    .context("191 sync IID")?
                    .into(),
                expected_exec_start: owner["expected_exec_start"]
                    .as_str()
                    .context("191 sync argv")?
                    .into(),
                program: Some(serde_json::from_value(owner["program"].clone())?),
            };
            let u = fleet::unit(&c.unit)?;
            let actual =
                sync_progress(&c, &u, stage, cutoff, Some(&ctx.source_revalidation_policy))?;
            let active = json!({"state":"active","remaining_millis":actual["remaining_millis"]});
            if stage == "upload" {
                upload = active
            } else {
                upload = complete.clone();
                if stage == "readback" {
                    readback = active
                } else {
                    readback = complete.clone();
                    tail = active
                }
            }
        }
        let ready = stage == "ready";
        if ready {
            full = complete.clone();
            plugin = complete.clone();
            upload = complete.clone();
            readback = complete.clone();
            tail = complete.clone();
            ready_receipts.insert(epoch, serde_json::from_value(row["ready_receipt"].clone())?);
        } else {
            claims.push(Claim {
                epoch,
                phase: "cohort191-delivery".into(),
                unit: queue::UNIT.into(),
                invocation_id: iid.into(),
                expected_exec_start: manager["ExecStart"]
                    .as_str()
                    .context("191 actual queue argv")?
                    .into(),
                program: Some(ctx.publisher.clone()),
            });
        }
        epochs.push(json!({"epoch":epoch,"full":full,"plugin":plugin,"boundary":if ready{complete.clone()}else{queued(ctx.boundary_budget_millis)},"upload":upload,"readback":readback,"source_revalidation_and_sidecar":tail,"authenticated_ready_pair":ready}));
    }
    let forecast = json!({"schema":"jetstreamer-cohort191-delivery-forecast-v2","finalization":{"state":"complete"},"import":{"state":"complete"},"boundary_gates_sidecar":false,"epochs":epochs});
    let root = p.output.parent().context("191 public event root")?;
    ensure!(
        root.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && root
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-cohort191-delivery-events-")),
        "191 public event namespace"
    );
    let forecast_path = p.output.with_extension("forecast.json");
    fleet::persist(&forecast_path, &forecast)?;
    fs::set_permissions(&forecast_path, fs::Permissions::from_mode(0o400))?;
    let forecast_bound = Bound {
        sha256: hex_lower(&Sha256::digest(fs::read(&forecast_path)?)),
        path: forecast_path,
    };
    let cp = Capture {
        native_event_clock,
        schema: "jetstreamer-cohort191-delivery-capture-plan-v2".into(),
        observer: p.observer,
        forecast: forecast_bound,
        origins: serde_json::from_value(terminal["origins"].clone())?,
        claims,
        source_batch: Some(serde_json::from_value(terminal["source_batch"].clone())?),
        public_batch: Some(serde_json::from_value(terminal["public_batch"].clone())?),
        gate_receipts: gates,
        gate_tools: ctx.gate_tools,
        ready_receipts,
        queue: Some(queue::Binding {
            plan: ctx.queue_plan,
            state: selected,
        }),
        source_revalidation_policy: Some(ctx.source_revalidation_policy),
        native_pending_proof: None,
        native_terminal_proof: Some(ctx.terminal),
        output: p.output.clone(),
    };
    let path = p.output.with_extension("capture-plan.json");
    fleet::persist(&path, &serde_json::to_value(&cp)?)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
    let cp_bound = Bound {
        sha256: hex_lower(&Sha256::digest(fs::read(&path)?)),
        path,
    };
    let mut event = capture(&cp)?;
    event["capture_plan"] = json!(cp_bound);
    event["capture_program"] = json!(ctx.publisher.path);
    event["capture_self_sha256"] = json!(ctx.publisher.sha256);
    validate_event(&event, cutoff)?;
    fleet::persist(&p.output, &event)?;
    println!("{}", p.output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verifier_queue_uses_remaining_active_clock_and_actual_stage_budgets() {
        let (f, p, next) = verification("queued-full", 0, 1000000, 2000000, None).unwrap();
        assert_eq!(f["remaining_millis"], 1000000);
        assert_eq!(p["remaining_millis"], 3000000);
        assert_eq!(next, 3000000);
        let (f, p, next) =
            verification("full-verification", 0, 1000000, 2000000, Some(500000)).unwrap();
        assert_eq!(f["remaining_millis"], 600000);
        assert_eq!(p["remaining_millis"], 2600000);
        assert_eq!(next, 2600000);
        let (_, p, next) = verification("queued-full", next, 1000000, 2000000, None).unwrap();
        assert_eq!(p["remaining_millis"], 5600000);
        assert_eq!(next, 5600000);
        let (f, p, next) =
            verification("plugin-verification", 0, 1000000, 2000000, Some(500000)).unwrap();
        assert_eq!(f["state"], "complete");
        assert_eq!(p["remaining_millis"], 1500000);
        assert_eq!(next, 1500000);
        assert!(verification("plugin-verification", 1, 1000000, 2000000, Some(0)).is_err());
        assert!(verification("full-verification", 0, 1000000, 2000000, None).is_err());
    }
}
