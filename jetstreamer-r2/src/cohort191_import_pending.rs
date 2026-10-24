//! Exact finished producer -> still-active original importer metadata only.
//! Public import completion and every downstream admission remain independent.
use super::*;
const SCHEMA: &str = "jetstreamer-cohort191-import-pending-transition-v1";
const IMPORT_UNIT: &str = "jetstreamer-root-import-e191-194-t5-20261016-v2-r2-e191-194-2.service";
const IMPORT_IID: &str = "611c55c179654410a5dddce41fd6c019";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bootstrap {
    schema: String,
    program: Bound,
    source_batch: Bound,
    origins: BTreeMap<u64, Bound>,
    estimate_evidence: Bound,
    output: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observe {
    schema: String,
    bootstrap: Bound,
    observer: Bound,
    output: PathBuf,
}
fn actor_claims(state: &Value, source: &Bound) -> Result<Vec<Claim>> {
    let a = &state["assignments"]["lane-a"];
    ensure!(
        state["import_owner"] == "lane-a"
            && state["completed"]["191-194"].is_null()
            && a["phase"] == "importing"
            && a["import_unit"] == IMPORT_UNIT
            && a["unit"] == UNIT
            && a["pid"] == 2189644
            && a["first_epoch"] == 191
            && a["last_epoch"] == 194
            && a["receipt"].as_str() == source.path.to_str()
            && a["source_recovery"] != true
            && a["failure"].is_null(),
        "191 source is not the exact pending original import"
    );
    let u = fleet::unit(IMPORT_UNIT)?;
    ensure!(u["InvocationID"] == IMPORT_IID, "191 importer replaced");
    let expected = format!(
        "{{ path={DEPLOY}/jetstreamer-node ; argv[]={DEPLOY}/jetstreamer-node 191-194 /home/sol/horizon --verify --recover-staged-cohort-only --cohort-manifest={DEPLOY}/preflight-191-194-v4.json --cohort-manifest-fingerprint={FINGERPRINT} --source-cohort-receipt={} --publish-through-epoch=194",
        source.path.display()
    );
    ensure!(
        prefix(&u["ExecStart"]) == Some(expected.as_str()),
        "191 importer argv changed"
    );
    let claims: Vec<_> = (191..=194)
        .map(|epoch| Claim {
            epoch,
            phase: "local-publication".into(),
            unit: IMPORT_UNIT.into(),
            invocation_id: IMPORT_IID.into(),
            expected_exec_start: u["ExecStart"].as_str().unwrap().into(),
            program: Some(Bound {
                path: Path::new(DEPLOY).join("jetstreamer-node"),
                sha256: NODE_SHA.into(),
            }),
        })
        .collect();
    for c in &claims {
        phase_scope(c)?;
        live(&u, c)?;
        program(c, &u)?;
    }
    Ok(claims)
}
fn shape(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == SCHEMA
            && v["first_epoch"] == 191
            && v["last_epoch"] == 194
            && v["public_batch"].is_null()
            && v["importer"]["Id"] == IMPORT_UNIT
            && v["importer"]["InvocationID"] == IMPORT_IID
            && v["importer"]["ActiveState"] == "active"
            && v["importer"]["SubState"] == "running"
            && v["controller"]["InvocationID"] == CID
            && v["controller"]["ActiveState"] == "active"
            && v["controller"]["SubState"] == "running"
            && v["producer"]["MainPID"] == "0"
            && v["producer"]["ActiveState"] == "inactive"
            && v["producer"]["NRestarts"] == "0"
            && v["resource_samples"] == 0,
        "191 pending import proof acquired public completion or lost native ownership"
    );
    for role in ["controller", "importer"] {
        ensure!(
            v[role]["LoadState"] == "loaded"
                && v[role]["NRestarts"] == "0"
                && v[role]["MainPID"]
                    .as_str()
                    .is_some_and(|s| s.parse::<u64>().is_ok_and(|n| n > 0)),
            "191 pending native actor is absent/restarting"
        );
    }
    for flag in [
        "publication_authorized",
        "replay_launch_authorized",
        "r2_mutations",
        "archive_readiness_claimed",
        "public_import_verified",
        "verification_authorized",
        "upload_authorized",
        "local_retirement_authorized",
    ] {
        ensure!(v[flag] == false, "191 pending proof grants {flag}");
    }
    Ok(())
}
fn bootstrap(p: &Bootstrap, pb: &Bound, self_sha: &str) -> Result<Value> {
    ensure!(
        p.schema == "jetstreamer-cohort191-import-pending-capture-plan-v1"
            && p.program.path == fs::read_link("/proc/self/exe")?
            && p.program.sha256 == self_sha
            && p.output
                == Path::new(
                    "/var/lib/jetstreamer/horizon-cohort191-import-pending-20261024-v1/bootstrap.json"
                )
            && p.origins.keys().copied().eq(191..=194),
        "foreign191 import bootstrap"
    );
    member(&p.program.path, &p.program.sha256)?;
    let cutoff = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let history = inputs()?;
    let controller = fleet::unit(CONTROLLER)?;
    let lifecycle = controller_lifecycle(&controller, &history, cutoff, true)?;
    let producer = fleet::unit(UNIT)?;
    ensure!(
        producer["MainPID"] == "0"
            && producer["NRestarts"] == "0"
            && producer["ActiveState"] == "inactive"
            && (producer["InvocationID"] == IID
                || (producer["LoadState"] == "not-found" && producer["InvocationID"] == "")),
        "191 producer not exact terminal"
    );
    let end = manager_terminal(cutoff)?;
    let events = native_events(cutoff)?;
    let (state_bytes, state) = state_bytes()?;
    let claims = actor_claims(&state, &p.source_batch)?;
    let source = batch(
        &p.source_batch,
        false,
        &BTreeSet::from([191, 192, 193, 194]),
    )?;
    for (i, m) in source["outcome"]["members"]
        .as_array()
        .context("191 source members")?
        .iter()
        .enumerate()
    {
        let fields = cohort198_finalization::fields(
            events["closes"][i]["MESSAGE"]
                .as_str()
                .context("191 close")?,
            "horizon archive complete: ",
        )?;
        ensure!(
            m["committed_archive"]["length"] == cohort198_finalization::integer(&fields, "bytes")?,
            "191 native close/source length differs"
        );
    }
    for (e, b) in &p.origins {
        original(b, *e, cutoff)?;
    }
    let evidence = bound(&p.estimate_evidence, true)?;
    ensure!(
        p.estimate_evidence.sha256
            == "95beb37d053abc0b775ea54f4d4a3b479f1d39445fb4001934ab7ada75e36cff"
            && evidence["schema"] == "jetstreamer-cohort191-delivery-estimate-evidence-v1"
            && evidence["per_epoch_budgets"]
                .as_array()
                .is_some_and(|r| r.len() == 4),
        "191 missing measured delivery policy"
    );
    let importer = fleet::unit(IMPORT_UNIT)?;
    let v = json!({"schema":SCHEMA,"first_epoch":191,"last_epoch":194,"recorded_unix_seconds":cutoff,
        "capture_plan":pb,"capture_program":p.program.path,"capture_self_sha256":p.program.sha256,
        "source_batch":p.source_batch,"origins":p.origins,"estimate_evidence":p.estimate_evidence,
        "native_events":events,"producer":producer,"producer_terminal":end,"controller":controller,"controller_lifecycle":lifecycle,
        "importer":importer,"claims":claims,"controller_state":state,"controller_state_sha256":hex_lower(&Sha256::digest(&state_bytes)),
        "public_batch":null,"resource_samples":0,"publication_authorized":false,"replay_launch_authorized":false,"r2_mutations":false,
        "archive_readiness_claimed":false,"public_import_verified":false,"verification_authorized":false,"upload_authorized":false,"local_retirement_authorized":false});
    shape(&v)?;
    ensure!(
        fleet::unit(UNIT)? == v["producer"]
            && fleet::unit(CONTROLLER)? == v["controller"]
            && fleet::unit(IMPORT_UNIT)? == v["importer"]
            && super::state_bytes()?.0 == state_bytes
            && actor_claims(&state, &p.source_batch)?
                .iter()
                .all(|c| c.invocation_id == IMPORT_IID),
        "191 bootstrap raced actual owners"
    );
    Ok(v)
}
fn ratio(e: &Value, name: &str, bytes: u64) -> Result<u64> {
    let n = e["rates_millis_per_byte"][name]["numerator"]
        .as_u64()
        .context("191 measured rate numerator")?;
    let d = e["rates_millis_per_byte"][name]["denominator"]
        .as_u64()
        .context("191 measured rate denominator")?;
    ensure!(n > 0 && d > 0, "191 nonpositive measured rate");
    u64::try_from((u128::from(bytes) * u128::from(n)).div_ceil(u128::from(d)))
        .context("191 rate overflow")
}
fn observe(p: &Observe, self_sha: &str) -> Result<Value> {
    ensure!(
        p.schema == "jetstreamer-cohort191-import-pending-observation-plan-v1",
        "foreign191 pending observation"
    );
    let b = bound(&p.bootstrap, false)?;
    shape(&b)?;
    ensure!(
        b["capture_program"] == json!(fs::read_link("/proc/self/exe")?)
            && b["capture_self_sha256"] == self_sha,
        "191 pending bootstrap program changed"
    );
    ensure!(
        p.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && p.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-cohort191-delivery-events-")),
        "191 pending output namespace differs"
    );
    let source: Bound = serde_json::from_value(b["source_batch"].clone())?;
    let origins: BTreeMap<u64, Bound> = serde_json::from_value(b["origins"].clone())?;
    let evidence = bound(
        &serde_json::from_value(b["estimate_evidence"].clone())?,
        true,
    )?;
    let observer = bound(&p.observer, false)?;
    let cutoff = fleet::utc_seconds(
        observer["recorded_at_utc"]
            .as_str()
            .context("191 sample clock")?,
    )?;
    ensure!(
        b["recorded_unix_seconds"]
            .as_u64()
            .is_some_and(|t| t <= cutoff),
        "191 bootstrap captured after sample"
    );
    let (_, state) = state_bytes()?;
    let claims = actor_claims(&state, &source)?;
    let total = evidence["per_epoch_budgets"]
        .as_array()
        .context("191 budgets")?
        .iter()
        .map(|r| r["archive_length"].as_u64().context("191 length"))
        .collect::<Result<Vec<_>>>()?
        .iter()
        .try_fold(0u64, |a, n| a.checked_add(*n).context("191 byte overflow"))?;
    // Native recovery performs full bucket decode/chain validation without
    // plugin semantic-stream hashing, then a whole-file digest. Use comparable
    // measured full scans plus two padded hash passes as a provisional budget.
    let allowance = ratio(&evidence, "full_millis", total)?
        .checked_add(
            ratio(&evidence, "source_hash_millis", total)?
                .checked_mul(2)
                .context("191 import hash overflow")?,
        )
        .context("191 import allowance overflow")?;
    let started = pipeline_status::manager_start(IMPORT_UNIT, IMPORT_IID)?;
    let elapsed = cutoff
        .checked_mul(1000)
        .and_then(|t| t.checked_sub(started))
        .context("191 importer born after sample")?;
    let remaining = tail_budget(allowance, 600000, elapsed)?;
    let queued = |n| json!({"state":"queued","remaining_millis":n});
    let mut epochs = Vec::new();
    for row in evidence["per_epoch_budgets"].as_array().unwrap() {
        let s = &row["stage_budgets_millis"];
        epochs.push(json!({"epoch":row["epoch"],"full":queued(row["full_queue_completion_millis"].as_u64().context("191 full budget")?),
            "plugin":queued(row["plugin_queue_completion_millis"].as_u64().context("191 plugin budget")?),
            "boundary":queued(allowance.checked_mul(3).context("191 deferred boundary budget overflow")?),
            "upload":queued(s["source_hash_millis"].as_u64().context("191 source hash budget")?.checked_add(s["upload_millis"].as_u64().context("191 upload budget")?).context("191 upload overflow")?),
            "readback":queued(s["readback_millis"].as_u64().context("191 readback budget")?),"source_revalidation_and_sidecar":queued(row["source_revalidation_sidecar_millis"].as_u64().context("191 tail budget")?),"authenticated_ready_pair":false}));
    }
    let forecast = json!({"schema":"jetstreamer-cohort191-delivery-forecast-v2","finalization":{"state":"complete"},"import":{"state":"active","remaining_millis":remaining},"boundary_gates_sidecar":false,"epochs":epochs});
    let forecast_path = p
        .output
        .parent()
        .context("191 event parent")?
        .join(format!("forecast-{}.json", cutoff));
    fleet::persist(&forecast_path, &forecast)?;
    fs::set_permissions(&forecast_path, fs::Permissions::from_mode(0o400))?;
    let bytes = fs::read(&forecast_path)?;
    let cp = Capture {
        schema: "jetstreamer-cohort191-delivery-capture-plan-v2".into(),
        observer: p.observer.clone(),
        forecast: Bound {
            path: forecast_path,
            sha256: hex_lower(&Sha256::digest(&bytes)),
        },
        origins,
        claims,
        source_batch: Some(source),
        public_batch: None,
        gate_receipts: BTreeMap::new(),
        gate_tools: BTreeMap::new(),
        ready_receipts: BTreeMap::new(),
        queue: None,
        source_revalidation_policy: None,
        output: p.output.clone(),
    };
    let cp_path = p.output.with_extension("capture-plan.json");
    fleet::persist(&cp_path, &serde_json::to_value(&cp)?)?;
    fs::set_permissions(&cp_path, fs::Permissions::from_mode(0o400))?;
    let cp_bound = Bound {
        path: cp_path,
        sha256: hex_lower(&Sha256::digest(fs::read(
            p.output.with_extension("capture-plan.json"),
        )?)),
    };
    let mut v = capture(&cp)?;
    v["capture_plan"] = json!(cp_bound);
    v["capture_program"] = json!(fs::read_link("/proc/self/exe")?);
    v["capture_self_sha256"] = json!(self_sha);
    v["import_estimate"] = json!({"basis":b["estimate_evidence"],"allowance_millis":allowance,"elapsed_import_millis":elapsed,"remaining_import_millis":remaining,"overdue":elapsed>=allowance,"actual_importer_unit":IMPORT_UNIT,"actual_importer_invocation_id":IMPORT_IID,"progress_basis":"Measured144/198 padded whole-archive scan rates plus two hashes, original actual importer phase clock; positive explicit overrun growth. No public import/readiness or boundary pass claimed."});
    validate_event(&v, cutoff)?;
    Ok(v)
}
pub(super) fn run(observation: bool) -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 7
            && args[3] == "--plan-sha256"
            && args[5] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "native191 pending PLAN --plan-sha256 SHA --self-sha256 SHA"
    );
    member(&fs::read_link("/proc/self/exe")?, &args[6])?;
    let pb = Bound {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let value = bound(&pb, true)?;
    let (output, v) = if observation {
        let p: Observe = serde_json::from_value(value)?;
        let v = observe(&p, &args[6])?;
        (p.output, v)
    } else {
        let p: Bootstrap = serde_json::from_value(value)?;
        let v = bootstrap(&p, &pb, &args[6])?;
        (p.output, v)
    };
    ensure!(
        output.starts_with("/var/lib/jetstreamer")
            && output.extension().is_some_and(|s| s == "json"),
        "191 pending output outside private namespace"
    );
    fleet::persist(&output, &v)?;
    println!("{}", output.display());
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn proof() -> Value {
        let mut v = json!({"schema":SCHEMA,"first_epoch":191,"last_epoch":194,"public_batch":null,"resource_samples":0,
            "importer":{"Id":IMPORT_UNIT,"InvocationID":IMPORT_IID,"ActiveState":"active","SubState":"running","MainPID":"9","LoadState":"loaded","NRestarts":"0"},
            "controller":{"InvocationID":CID,"ActiveState":"active","SubState":"running","MainPID":"8","LoadState":"loaded","NRestarts":"0"},
            "producer":{"MainPID":"0","ActiveState":"inactive","NRestarts":"0"}});
        for flag in [
            "publication_authorized",
            "replay_launch_authorized",
            "r2_mutations",
            "archive_readiness_claimed",
            "public_import_verified",
            "verification_authorized",
            "upload_authorized",
            "local_retirement_authorized",
        ] {
            v[flag] = json!(false);
        }
        v
    }
    #[test]
    fn pending_shape_never_grants_import_completion_or_loses_actual_actor() {
        let v = proof();
        shape(&v).unwrap();
        for (pointer, value) in [
            ("/public_batch", json!({"path":"fake"})),
            ("/producer/MainPID", json!("1")),
            ("/importer/InvocationID", json!("replacement")),
            ("/importer/ActiveState", json!("inactive")),
            ("/controller/InvocationID", json!("replacement")),
            ("/controller/NRestarts", json!("1")),
            ("/importer/MainPID", json!("0")),
        ] {
            let mut bad = v.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(shape(&bad).is_err(), "{pointer}");
        }
        for flag in [
            "publication_authorized",
            "replay_launch_authorized",
            "r2_mutations",
            "archive_readiness_claimed",
            "public_import_verified",
            "verification_authorized",
            "upload_authorized",
            "local_retirement_authorized",
        ] {
            let mut bad = v.clone();
            bad[flag] = json!(true);
            assert!(shape(&bad).is_err(), "{flag}");
        }
    }
    #[test]
    fn measured_import_rate_and_overrun_stay_positive_without_inventing_progress() {
        let e = json!({"rates_millis_per_byte":{"plugin_millis":{"numerator":3,"denominator":2}}});
        assert_eq!(ratio(&e, "plugin_millis", 3).unwrap(), 5);
        assert!(ratio(&e, "unknown", 3).is_err());
        assert_eq!(tail_budget(1000, 100, 999).unwrap(), 100);
        assert_eq!(tail_budget(1000, 100, 1000).unwrap(), 100);
        assert_eq!(tail_budget(1000, 100, 1200).unwrap(), 300);
    }
    #[test]
    fn bootstrap_specs_cannot_import_future_resource_or_public_fields() {
        let b = json!({"path":"/bound","sha256":"a".repeat(64)});
        let v = json!({"schema":"jetstreamer-cohort191-import-pending-capture-plan-v1","program":b,"source_batch":b,"origins":{},"estimate_evidence":b,"output":"/output"});
        serde_json::from_value::<Bootstrap>(v.clone()).unwrap();
        for key in ["observer", "public_batch", "forecast", "ready_receipts"] {
            let mut bad = v.clone();
            bad[key] = b.clone();
            assert!(serde_json::from_value::<Bootstrap>(bad).is_err());
        }
    }
}
