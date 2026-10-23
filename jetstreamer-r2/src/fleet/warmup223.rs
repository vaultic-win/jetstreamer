//! Closed admission/ownership for the first16-slot failure-context experiment.
use super::*;
const HISTORICAL_UNIT: &str = "horizon-qualify-223-warmup-resource-a1f6239d-v3.service";
const UNIT: &str = "horizon-qualify-223-warmup-resource-5072b7ba-v4.service";
const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/qualification-223-v1625-prefix-warmup-5072b7ba-v4";
const RUNNER: &str = "/var/lib/jetstreamer/horizon-warmup223-resource-free-floor-v4/jetstreamer-epoch223-warmup-resource";
const RUNNER_SHA: &str = "5072b7ba0c0599a8290b197fcf74bea87ed823234fbd23c2953604f65b11b8db";
const PLAN: &str = "/var/lib/jetstreamer/horizon-warmup223-resource-free-floor-v4/actual-plan.json";
const PLAN_SHA: &str = "84bdae34da219005672d5cb92ecad0e6c13c14712cd3a199f9f2a272ea304216";
const STATE: &str = "/var/lib/jetstreamer/horizon-warmup223-admission-v4";
const OWNERS: [(&str, &str); 4] = [
    (
        "horizon-upload-203-v4-20261023-v1.service",
        "4a9d184a487540409e4edcd1ac353cf4",
    ),
    (
        "horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service",
        "4cd76ae1353a4411885b997f04306402",
    ),
    (
        "horizon-qualify-205-shrink-root-prefix-resource-5c01bf93-v1.service",
        "373359a11aef4993a1a949e19ff617c3",
    ),
    (
        "horizon-qualify-204-shrink-root-prefix-resource-fcbf3992-v1.service",
        "448da7f2a3a34217afe7e115120b3cea",
    ),
];
pub(super) fn scope(phase: &str, unit: &str) -> bool {
    phase == "private-warmup-reproduction" && matches!(unit, UNIT | HISTORICAL_UNIT)
}
fn command() -> String {
    format!(
        "{{ path={RUNNER} ; argv[]={RUNNER} {PLAN} --plan-sha256 {PLAN_SHA} --self-sha256 {RUNNER_SHA} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}"
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    observer: BoundFile,
    fleet: BoundFile,
}
fn delivery_complete(f: &Value) -> bool {
    f["inventory"]["entries"].as_array().is_some_and(|a| {
        a.iter()
            .filter(|r| r["epoch"] == 203 && r["state"] == "ready-pair")
            .count()
            == 1
    })
}
fn sample(spec: &Spec, o: &Value, f: &Value, now: u64) -> Result<u64> {
    let sampled = utc_seconds(
        o["recorded_at_utc"]
            .as_str()
            .context("warmup sample clock")?,
    )?;
    ensure!(
        spec.schema == "jetstreamer-private-warmup223-admission-spec-v1"
            && sampled <= now
            && now - sampled <= 1800
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && o["cadence"]["routine_minimum_interval_enforced"] == true
            && f["schema"] == SCHEMA
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["observer_receipt"].as_str() == spec.observer.path.to_str()
            && f["observer_sha256"] == spec.observer.sha256
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && f["inventory"]["anomalies"] == 0
            && f["active"]
                .as_array()
                .is_some_and(|a| a.len() == if delivery_complete(f) { 3 } else { 4 }),
        "warmup requires fresh accepted complete fleet"
    );
    ensure!(
        o["host_memory"]["conservative_available_kib"]
            .as_u64()
            .and_then(|n| n.checked_mul(1024))
            .is_some_and(|n| n >= 576u64 << 30)
            && o["filesystem"]["conservative_available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= 1_511_435_598_739),
        "warmup resource envelope does not fit"
    );
    ensure!(
        f["inventory"]["entries"]
            .as_array()
            .context("warmup inventory")?
            .iter()
            .filter(|r| r["epoch"] == 223 && r["state"] == "missing")
            .count()
            == 1,
        "warmup must not duplicate a staged or completed remote223"
    );
    for (name, iid) in OWNERS {
        if name == OWNERS[0].0 && delivery_complete(f) {
            continue;
        }
        let rows = f["active"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| {
                let u = if row["producer"].is_object() {
                    &row["producer"]
                } else {
                    &row["unit"]
                };
                u["Id"] == name && u["InvocationID"] == iid && u["NRestarts"] == "0"
            })
            .count();
        ensure!(rows == 1, "warmup protected fleet owner differs");
    }
    Ok(sampled)
}
fn names(f: &Value) -> Result<BTreeSet<String>> {
    let mut names = f["unit_census"]
        .as_object()
        .context("warmup census")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    names.insert(UNIT.into());
    Ok(names)
}
fn protected(f: &Value, c: &BTreeMap<String, Value>) -> Result<()> {
    for (name, iid) in OWNERS {
        let u = c.get(name).context("protected owner missing")?;
        if name == OWNERS[0].0 && delivery_complete(f) {
            ensure!(
                u["MainPID"] == "0" && u["ActiveState"] == "inactive",
                "completed203 uploader is still active"
            );
            continue;
        }
        ensure!(
            u["InvocationID"] == iid
                && u["NRestarts"] == "0"
                && (u["ActiveState"] == "active" || u["ActiveState"] == "activating")
                && u["MainPID"]
                    .as_str()
                    .and_then(|n| n.parse::<u64>().ok())
                    .is_some_and(|n| n > 0)
                && pipeline_status::same_exec_start(
                    f["unit_census"][name]["ExecStart"]
                        .as_str()
                        .context("prior command")?,
                    u["ExecStart"].as_str().context("current command")?
                ),
            "protected owner changed"
        );
    }
    for (name, u) in c {
        ensure!(
            !diagnostic_stage_running(u) || OWNERS.iter().any(|(n, _)| n == name) || name == UNIT,
            "unaccounted live warmup competitor:{name}"
        );
    }
    Ok(())
}
fn inputs(f: &Value) -> Result<()> {
    if delivery_complete(f) {
        let receipt = bound_json(&BoundFile {
            path: "/home/ubuntu/.jetstreamer-private/r2-receipts/epoch-203.r2.json".into(),
            sha256: "d4222cd99f521700c12bb8227722d1cbecf90c5c1f48d66a22b7bb65f20d26c4".into(),
        })?;
        ensure!(
            receipt["epoch"] == 203
                && receipt["remote_sha256_readback"] == true
                && receipt["archive_sha256"]
                    == "7efb3b28b2761cd646d20fa282d87c508249488fd0fb27ce8e033a1aed7d39ad",
            "completed203 receipt differs"
        );
    }
    let proof = bound_json(&BoundFile {
        path: "/var/lib/jetstreamer/horizon-cold223-input-proof-v1/input-proof.json".into(),
        sha256: "b0ee9a5136e075d0c1605573cc78e154a3059351e0e0f961068211f344c5387f".into(),
    })?;
    ensure!(
        proof["native_input_qualified"] == true
            && proof["entry_replay"] == false
            && proof["repair_closed"] == false,
        "warmup native input proof differs"
    );
    let cap = bound_json(&BoundFile {
        path: "/var/lib/jetstreamer/horizon-warmup223-parent-capability-v4/capability.json".into(),
        sha256: "51dbc6a75faad044e086ac8683057588392bff8124b5c30b64a8cc826af08d14".into(),
    })?;
    ensure!(
        cap["bindings"]["self_sha256"] == RUNNER_SHA
            && cap["worker_started"] == false
            && cap["input_hashes_and_private_paths_verified"] == true
            && cap["parent_planning_report"]["pre_worker_barrier_reached"] == true
            && cap["parent_planning_report"]["worker_spawned"] == false,
        "warmup input capability differs"
    );
    let p = bound_json(&BoundFile {
        path: PLAN.into(),
        sha256: PLAN_SHA.into(),
    })?;
    ensure!(
        p["unit"] == UNIT
            && p["run_root"] == ROOT
            && p["target_slot"] == 96_335_554u64
            && p["terminal_slot"] == 96_767_522u64,
        "warmup actual plan differs"
    );
    Ok(())
}
fn century_floor(f: &Value) -> Result<Value> {
    let binding = BoundFile {
        path: "/var/lib/jetstreamer/horizon-century-floor-032716-thirteen-v1/floor.json".into(),
        sha256: "b77b70205043c49d4c8ead819c7938e4eb461a43e5547d45af60ca0054e55271".into(),
    };
    let old = bound_json(&binding)?;
    let mut census = old["census"].as_array().context("century census")?.clone();
    let mut unique = BTreeSet::new();
    let mut sum = 0u64;
    for row in &census {
        let epoch = row["epoch"].as_u64().context("century epoch")?;
        ensure!(
            (200..=300).contains(&epoch) && epoch != 203 && unique.insert(epoch),
            "century census scope"
        );
        sum = sum
            .checked_add(
                row["jet_size_bytes"]
                    .as_u64()
                    .filter(|n| *n > 0)
                    .context("century size")?,
            )
            .context("century sum overflow")?;
    }
    ensure!(
        census.len() == 13
            && old["sample_count"] == 13
            && old["sum_jet_size_bytes"] == sum
            && old["floor_bytes"]
                == sum
                    .checked_mul(2)
                    .context("century floor overflow")?
                    .div_ceil(13),
        "prior century floor differs"
    );
    if delivery_complete(f) {
        sum = sum
            .checked_add(103_802_397_352)
            .context("new century sum overflow")?;
        census.push(json!({"epoch":203,"jet_size_bytes":103_802_397_352u64,"archive_sha256":"7efb3b28b2761cd646d20fa282d87c508249488fd0fb27ce8e033a1aed7d39ad",
            "r2_receipt_path":"/home/ubuntu/.jetstreamer-private/r2-receipts/epoch-203.r2.json","r2_receipt_sha256":"d4222cd99f521700c12bb8227722d1cbecf90c5c1f48d66a22b7bb65f20d26c4"}));
    }
    let floor = sum
        .checked_mul(2)
        .context("new century floor overflow")?
        .div_ceil(census.len() as u64);
    ensure!(
        floor <= 248_289_182_611,
        "new floor exceeds this candidate's protected floor"
    );
    Ok(
        json!({"schema":"horizon-century-floor-recomputation-v1","century_first_epoch":200,"century_last_epoch":300,
        "sample_count":census.len(),"sum_jet_size_bytes":sum,"floor_bytes":floor,"census":census,"previous_floor_evidence":private157::binding(&binding)}),
    )
}
pub(super) fn run(capture: bool) -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args(if capture {
        "capture-warmup223"
    } else {
        "admit-warmup223"
    })?;
    let spec: Spec = serde_json::from_value(bound_json(&binding)?)?;
    let o = bound_json(&spec.observer)?;
    let f = bound_json(&spec.fleet)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let sampled = sample(&spec, &o, &f, now)?;
    inputs(&f)?;
    let floor = century_floor(&f)?;
    let before = census(&names(&f)?, 201, 300)?;
    protected(&f, &before)?;
    let own = &before[UNIT];
    if capture {
        let ab: BoundFile = serde_json::from_value(private157::file_binding(
            &Path::new(STATE).join("admission.json"),
        )?)?;
        let a = bound_json(&ab)?;
        ensure!(
            a["schema"] == "jetstreamer-private-warmup223-admission-v1"
                && a["spec"] == private157::binding(&binding)
                && a["decision"] == "pass"
                && a["recorded_unix_seconds"]
                    .as_u64()
                    .is_some_and(|n| n <= now && now - n <= 1800),
            "warmup admission stale/foreign"
        );
        let claim = PipelineClaim {
            epoch: 223,
            phase: "private-warmup-reproduction".into(),
            unit: UNIT.into(),
            invocation_id: own["InvocationID"]
                .as_str()
                .context("warmup live iid")?
                .into(),
            expected_exec_start: command(),
            evidence: vec![],
        };
        sandbox(&claim, own)?;
        let after = census(&names(&f)?, 201, 300)?;
        protected(&f, &after)?;
        ensure!(
            after[UNIT]["InvocationID"] == own["InvocationID"]
                && after[UNIT]["MainPID"] == own["MainPID"],
            "warmup owner changed during capture"
        );
        private157::immutable_receipt(
            &Path::new(STATE).join("launch.json"),
            &json!({
            "schema":"jetstreamer-private-warmup223-launch-v1","epoch":223,"unit":UNIT,"invocation_id":claim.invocation_id,
            "expected_exec_start":command(),"admission":private157::binding(&ab),"worker_entry_start":96_335_539u64,"worker_entry_end_exclusive":96_335_555u64,
            "runner_sha256":RUNNER_SHA,"recorded_unix_seconds":now,"sampled_at_utc":publication203::utc(now)?,"self_sha256":self_sha,
            "observer":private157::binding(&spec.observer),"previous_fleet":private157::binding(&spec.fleet),"resource_samples_taken":0,
            "entry_replay":true,"ordinary_replay_claim":false,"current_sidecar_eta_valid":false,"repair_closed":false,
            "publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
        )?;
    } else {
        ensure!(
            own["MainPID"] == "0"
                && matches!(own["ActiveState"].as_str(), Some("inactive" | "failed")),
            "warmup owner already active"
        );
        // Guard receipts are immutable per guard invocation, not mutable latest files.
        let mut guards = Vec::new();
        for (index, name, root) in [
            (
                0,
                "horizon-ownroot225-protective-v1.service",
                "/var/lib/jetstreamer/horizon-ownroot225-rebased-guard-receipts-v1",
            ),
            (
                1,
                "horizon-prefix205-protective-v1.service",
                "/var/lib/jetstreamer/horizon-prefix205-guard-receipts-v1",
            ),
            (
                2,
                "horizon-prefix204-protective-v1.service",
                "/var/lib/jetstreamer/horizon-prefix204-guard-receipts-v1",
            ),
        ] {
            let gu = unit(name)?;
            let iid = gu["InvocationID"].as_str().context("guard iid")?;
            ensure!(
                iid.len() == 32 && iid.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid guard iid"
            );
            let path = Path::new(root).join(format!("sample-{iid}.json"));
            let b: BoundFile = serde_json::from_value(private157::file_binding(&path)?)?;
            publication203::guard(&bound_json(&b)?, index, sampled, now)?;
            guards.push(private157::binding(&b));
        }
        let after = census(&names(&f)?, 201, 300)?;
        protected(&f, &after)?;
        ensure!(
            after[UNIT]["MainPID"] == "0",
            "warmup was started during admission"
        );
        private157::immutable_receipt(
            &Path::new(STATE).join("admission.json"),
            &json!({
            "schema":"jetstreamer-private-warmup223-admission-v1","spec":private157::binding(&binding),"self_sha256":self_sha,
            "recorded_unix_seconds":now,"observer":private157::binding(&spec.observer),"fleet":private157::binding(&spec.fleet),"guards":guards,
            "decision":"pass","century_floor":floor,"maximum_new_memory_bytes":128u64<<30,"scratch_planning_bytes":300_000_000_000u64,
            "required_observed_free_bytes":1_511_435_598_739u64,"expected_exec_start":command(),"replay_launch_authorized":false,
            "publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
        )?;
    }
    println!(
        "warmup223 {} captured; no service or R2 mutation",
        if capture {
            "live ownership"
        } else {
            "admission"
        }
    );
    Ok(())
}
fn sandbox(c: &PipelineClaim, current: &Value) -> Result<()> {
    ensure!(
        scope(&c.phase, &c.unit)
            && c.epoch == 223
            && current["InvocationID"] == c.invocation_id
            && current["NRestarts"] == "0"
            && current["MainPID"]
                .as_str()
                .and_then(|n| n.parse::<u64>().ok())
                .is_some_and(|n| n > 0)
            && (current["ActiveState"] == "active" || current["ActiveState"] == "activating")
            && pipeline_status::same_exec_start(
                &command(),
                current["ExecStart"].as_str().context("warmup command")?
            ),
        "warmup live owner differs"
    );
    let out=ProcessCommand::new("systemctl").args(["show",UNIT,"--property=Type,User,Group,Restart,KillMode,Delegate,MemoryHigh,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,ProtectSystem,ProtectHome,ProtectControlGroups,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,ReadWritePaths,OOMPolicy,OOMScoreAdjust"]).output()?;
    ensure!(out.status.success(), "warmup sandbox unavailable");
    let text = std::str::from_utf8(&out.stdout)?;
    let fields = text
        .lines()
        .filter_map(|l| l.split_once('='))
        .collect::<BTreeMap<_, _>>();
    for (key, value) in [
        ("Type", "simple"),
        ("User", "ubuntu"),
        ("Group", "ubuntu"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("MemoryHigh", "120259084288"),
        ("MemoryMax", "137438953472"),
        ("MemorySwapMax", "0"),
        ("CPUQuotaPerSecUSec", "8s"),
        ("TasksMax", "512"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("ProtectControlGroups", "yes"),
        ("NoNewPrivileges", "yes"),
        ("CapabilityBoundingSet", "cap_dac_override"),
        ("AmbientCapabilities", "cap_dac_override"),
        ("ReadWritePaths", ROOT),
        ("OOMPolicy", "kill"),
        ("OOMScoreAdjust", "1000"),
    ] {
        ensure!(
            fields.get(key) == Some(&value),
            "warmup sandbox differs:{key}"
        );
    }
    Ok(())
}
pub(super) fn validate(c: &PipelineClaim) -> Result<()> {
    if c.unit == HISTORICAL_UNIT {
        let binding = BoundFile {
            path: "/var/lib/jetstreamer/horizon-warmup223-admission-v3/launch.json".into(),
            sha256: "742656ca51cc60e14800ab76b379de384d3341d26696f33c7c992de772eeba6d".into(),
        };
        ensure!(
            scope(&c.phase, &c.unit)
                && c.epoch == 223
                && c.invocation_id == "1fffc79d92ad458a9a4d334a48b40dfc"
                && c.evidence.as_slice() == std::slice::from_ref(&binding),
            "historical warmup claim differs"
        );
        let launch = bound_json(&binding)?;
        ensure!(
            launch["expected_exec_start"] == c.expected_exec_start,
            "historical warmup command differs"
        );
        // The immutable launch hash binds every original field. Its terminal
        // receipt remains available independently of the failed scratch tree.
        bound_json(&BoundFile {
            path: "/var/lib/jetstreamer/horizon-warmup223-terminal-v3/failure.json".into(),
            sha256: "7f1671b6f74946f2fc4f2b2fd13569b59c4015739889080dc395db2191c18c73".into(),
        })?;
        return Ok(());
    }
    ensure!(
        scope(&c.phase, &c.unit)
            && c.epoch == 223
            && c.evidence.len() == 1
            && c.evidence[0].path == Path::new(STATE).join("launch.json"),
        "warmup claim differs"
    );
    let r = bound_json(&c.evidence[0])?;
    ensure!(
        r["schema"] == "jetstreamer-private-warmup223-launch-v1"
            && r["invocation_id"] == c.invocation_id
            && r["unit"] == UNIT
            && r["runner_sha256"] == RUNNER_SHA
            && r["expected_exec_start"] == c.expected_exec_start
            && pipeline_status::same_exec_start(&command(), &c.expected_exec_start)
            && r["worker_entry_start"] == 96_335_539u64
            && r["worker_entry_end_exclusive"] == 96_335_555u64
            && r["entry_replay"] == true
            && r["ordinary_replay_claim"] == false
            && r["current_sidecar_eta_valid"] == false
            && r["repair_closed"] == false
            && r["publication_authorized"] == false
            && r["r2_mutations"] == false
            && r["remote_mutations"] == false,
        "warmup launch proof differs"
    );
    let ab: BoundFile = serde_json::from_value(r["admission"].clone())?;
    ensure!(
        ab.path == Path::new(STATE).join("admission.json"),
        "foreign warmup admission"
    );
    let a = bound_json(&ab)?;
    ensure!(
        a["decision"] == "pass" && a["schema"] == "jetstreamer-private-warmup223-admission-v1",
        "warmup not admitted"
    );
    Ok(())
}
pub(super) fn validate_live(c: &PipelineClaim, current: &Value) -> Result<()> {
    ensure!(
        c.unit == UNIT,
        "terminal historical warmup cannot become live"
    );
    validate(c)?;
    sandbox(c, current)?;
    let gu = unit("horizon-warmup223-protective-v4.service")?;
    let iid = gu["InvocationID"]
        .as_str()
        .context("warmup protective invocation")?;
    ensure!(
        iid.len() == 32 && iid.bytes().all(|b| b.is_ascii_hexdigit()),
        "warmup protective iid"
    );
    let binding: BoundFile = serde_json::from_value(private157::file_binding(
        &Path::new("/var/lib/jetstreamer/horizon-warmup223-guard-receipts-v4")
            .join(format!("sample-{iid}.json")),
    )?)?;
    let g = bound_json(&binding)?;
    let pb: BoundFile = serde_json::from_value(private157::file_binding(Path::new(
        "/var/lib/jetstreamer/horizon-warmup223-guard-v4/guard-plan.json",
    ))?)?;
    let p = bound_json(&pb)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["plan_sha256"] == pb.sha256
            && g["guard_sha256"]
                == "134904cf2e28ce3ede1dd85a6878e40a407443580d4e83a50cb30efc29fd28be"
            && g["producer_invocation_id"] == c.invocation_id
            && g["producer"]["invocation_id"] == c.invocation_id
            && g["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n <= now && now - n <= 120)
            && g.get("trip_reason").is_some_and(Value::is_null)
            && g.get("worker_observation_error")
                .is_some_and(Value::is_null)
            && g.get("root_physical_observation_error")
                .is_some_and(Value::is_null)
            && g["maximum_worker_vmas"] == 3_500_000
            && g["maximum_root_physical_bytes"].is_null()
            && p.get("maximum_root_physical_bytes").is_none()
            && p["unit"] == UNIT
            && p["invocation_id"] == c.invocation_id
            && p["worker_root"] == format!("{ROOT}/scratch")
            && g["minimum_free_bytes"] == 1_511_435_598_739u64
            && p["minimum_free_bytes"] == 1_511_435_598_739u64,
        "warmup external VMA/disk guard unavailable or tripped"
    );
    let out = ProcessCommand::new("systemctl")
        .args([
            "show",
            "horizon-warmup223-protective-v4.timer",
            "--property=ActiveState",
            "--value",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout == b"active\n",
        "warmup protective timer inactive"
    );
    Ok(())
}

pub(super) fn event_predecessor(
    previous: &Value,
    p: &Plan,
    proof: &Value,
    sampled: &str,
    now: u64,
) -> Result<()> {
    ensure!(
        p.first_epoch == 201
            && p.last_epoch == 300
            && p.admission_transition_guard.is_none()
            && previous["schema"] == SCHEMA
            && previous["sampled_at_utc"] == sampled
            && previous["observer_receipt"].as_str() == p.observer.path.to_str()
            && previous["observer_sha256"] == p.observer.sha256
            && proof["schema"] == "jetstreamer-private-warmup223-launch-v1"
            && proof["observer"] == private157::binding(&p.observer)
            && p.previous_fleet
                .as_ref()
                .is_some_and(|b| proof["previous_fleet"] == private157::binding(b))
            && proof["resource_samples_taken"] == 0,
        "warmup event cannot replace resource observation"
    );
    let clock = proof["recorded_unix_seconds"]
        .as_u64()
        .context("warmup event clock")?;
    ensure!(
        clock > utc_seconds(sampled)?
            && clock <= now
            && now - clock <= 300
            && previous["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n < clock),
        "warmup event stale or backdated"
    );
    let old: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: previous["plan"]
            .as_str()
            .context("prior warmup plan")?
            .into(),
        sha256: previous["plan_sha256"]
            .as_str()
            .context("prior warmup digest")?
            .into(),
    })?)?;
    let claims = p
        .pipeline_claims
        .iter()
        .filter(|c| c.phase == "private-warmup-reproduction" && c.unit == UNIT)
        .collect::<Vec<_>>();
    ensure!(
        claims.len() == 1,
        "warmup event needs exactly one new owner"
    );
    let claim = claims[0];
    validate(claim)?;
    ensure!(
        p.metadata_event.as_ref() == claim.evidence.first()
            && claim.invocation_id == proof["invocation_id"]
            && p.pipeline_claims.len() == old.pipeline_claims.len() + 1
            && !old.pipeline_claims.iter().any(|c| c.unit == UNIT)
            && old
                .pipeline_claims
                .iter()
                .all(|c| p.pipeline_claims.contains(c)),
        "warmup event changed pipeline history"
    );
    let mut tracks = old.tracked_units.iter().cloned().collect::<BTreeSet<_>>();
    tracks.insert(UNIT.into());
    ensure!(
        tracks == p.tracked_units.iter().cloned().collect::<BTreeSet<_>>()
            && p.diagnostics.len() == old.diagnostics.len()
            && old
                .diagnostics
                .iter()
                .all(|d| p.diagnostics.iter().any(|n| n.epoch == d.epoch
                    && n.unit == d.unit
                    && n.invocation_id == d.invocation_id
                    && n.scratch_path == d.scratch_path
                    && n.launch_receipt == d.launch_receipt)),
        "warmup event hid or changed prior owners"
    );
    for (epoch, gate) in &old.gates {
        let new = &p.gates[epoch];
        ensure!(
            new.state == gate.state
                && gate.evidence.iter().all(|e| new.evidence.contains(e))
                && (*epoch == 223 || new.next_action == gate.next_action),
            "warmup event changed unrelated work"
        );
    }
    ensure!(
        p.gates[&223].state == "failed-needs-repair",
        "warmup event cannot close failed223"
    );
    Ok(())
}
pub(super) fn event_census(p: &Plan, c: &BTreeMap<String, Value>) -> Result<()> {
    if let Some(binding) = &p.metadata_event {
        let proof = bound_json(binding)?;
        if proof["schema"] == "jetstreamer-private-warmup223-launch-v1" {
            let f = bound_json(
                p.previous_fleet
                    .as_ref()
                    .context("warmup event prior fleet")?,
            )?;
            protected(&f, c)?;
            let claim = p
                .pipeline_claims
                .iter()
                .find(|c| c.phase == "private-warmup-reproduction" && c.unit == UNIT)
                .context("warmup event claim")?;
            validate_live(claim, &c[UNIT])?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_v3_stays_recognized_but_cannot_be_resurrected() {
        assert!(scope("private-warmup-reproduction", HISTORICAL_UNIT));
        let claim = PipelineClaim {
            epoch: 223,
            phase: "private-warmup-reproduction".into(),
            unit: HISTORICAL_UNIT.into(),
            invocation_id: "1fffc79d92ad458a9a4d334a48b40dfc".into(),
            expected_exec_start: String::new(),
            evidence: vec![],
        };
        let error = validate_live(&claim, &json!({})).unwrap_err();
        assert!(error
            .to_string()
            .contains("historical warmup cannot become live"));
        assert!(validate(&claim).is_err());
    }
    fn fixture() -> (Spec, Value, Value) {
        let spec = Spec {
            schema: "jetstreamer-private-warmup223-admission-spec-v1".into(),
            observer: BoundFile {
                path: "/sealed/sample".into(),
                sha256: "a".repeat(64),
            },
            fleet: BoundFile {
                path: "/sealed/fleet".into(),
                sha256: "b".repeat(64),
            },
        };
        let o = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"2026-10-23T13:17:07Z",
            "cadence":{"routine_minimum_interval_enforced":true},"host_memory":{"conservative_available_kib":576u64<<20},
            "filesystem":{"conservative_available_bytes":1_511_435_598_739u64}});
        let active = OWNERS
            .iter()
            .map(|(name, iid)| json!({"unit":{"Id":name,"InvocationID":iid,"NRestarts":"0"}}))
            .collect::<Vec<_>>();
        let f = json!({"schema":SCHEMA,"first_epoch":201,"last_epoch":300,"observer_receipt":"/sealed/sample",
            "observer_sha256":"a".repeat(64),"sampled_at_utc":"2026-10-23T13:17:07Z",
            "inventory":{"anomalies":0,"entries":[{"epoch":223,"state":"missing"}]},"active":active});
        (spec, o, f)
    }
    #[test]
    fn admission_needs_fresh_complete_fleet_and_both_resource_budgets() {
        let (s, o, f) = fixture();
        let now = utc_seconds("2026-10-23T13:17:08Z").unwrap();
        sample(&s, &o, &f, now).unwrap();
        assert!(sample(&s, &o, &f, now + 1800).is_err());
        for pointer in [
            "/host_memory/conservative_available_kib",
            "/filesystem/conservative_available_bytes",
        ] {
            let mut bad = o.clone();
            *bad.pointer_mut(pointer).unwrap() = json!(0);
            assert!(sample(&s, &bad, &f, now).is_err());
        }
        let mut bad = f.clone();
        bad["active"].as_array_mut().unwrap().pop();
        assert!(sample(&s, &o, &bad, now).is_err());
        let mut bad = f.clone();
        bad["active"][0]["unit"]["InvocationID"] = json!("f".repeat(32));
        assert!(sample(&s, &o, &bad, now).is_err());
        let mut bad = f.clone();
        bad["inventory"]["entries"][0]["state"] = json!("ready-pair");
        assert!(sample(&s, &o, &bad, now).is_err());
    }
    #[test]
    fn private_warmup_cannot_borrow_other_epochs_or_native_input_phase() {
        assert_eq!(
            pipeline_unit_range("private-warmup-reproduction", UNIT).unwrap(),
            223..=223
        );
        assert!(!scope("private-cold-snapshot-verification", UNIT));
        assert!(!scope(
            "private-warmup-reproduction",
            "horizon-qualify-223-warmup-resource-foreign.service"
        ));
        let command = command();
        assert!(!command.contains("--storage-capability"));
        assert!(command.contains(PLAN_SHA));
        assert!(command.contains(RUNNER_SHA));
    }
    #[test]
    fn static_command_matches_live_display_metadata_but_preserves_exact_arguments() {
        let expected = command();
        let live = expected
            .replace(
                "start_time=[n/a]",
                "start_time=[Fri 2026-10-23 14:08:13 UTC]",
            )
            .replace("pid=0", "pid=3959253");
        assert!(pipeline_status::same_exec_start(&expected, &live));
        assert!(!pipeline_status::same_exec_start(
            &expected,
            &live.replace(PLAN_SHA, &"f".repeat(64))
        ));
    }
    #[test]
    fn completed203_is_released_only_after_ready_inventory_and_without_live_claim() {
        let (s, o, mut f) = fixture();
        let now = utc_seconds("2026-10-23T13:17:08Z").unwrap();
        f["inventory"]["entries"]
            .as_array_mut()
            .unwrap()
            .push(json!({"epoch":203,"state":"ready-pair"}));
        assert!(sample(&s, &o, &f, now).is_err());
        f["active"].as_array_mut().unwrap().remove(0);
        sample(&s, &o, &f, now).unwrap();
        f["inventory"]["entries"][1]["state"] = json!("archive-only");
        assert!(sample(&s, &o, &f, now).is_err());
    }
}
