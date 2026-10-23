pub(super) fn scope(phase: &str, name: &str) -> bool {
    phase == "private-warmup-reproduction" && name == UNIT
}
fn command() -> String {
    format!(
        "{{ path={RUNNER} ; argv[]={RUNNER} {PLAN} --plan-sha256 {PLAN_SHA} --self-sha256 {RUNNER_SHA} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}"
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Spec {
    schema: String,
    observer: BoundFile,
    fleet: BoundFile,
}
fn checked_sample(spec: &Spec, o: &Value, f: &Value, now: u64) -> Result<u64> {
    let stamp = utc_seconds(
        o["recorded_at_utc"]
            .as_str()
            .context("native20 resource clock")?,
    )?;
    ensure!(
        spec.schema == SPEC_SCHEMA
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && o["cadence"]["routine_minimum_interval_enforced"] == true
            && stamp <= now
            && now - stamp <= 1800
            && f["schema"] == SCHEMA
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["observer_receipt"].as_str() == spec.observer.path.to_str()
            && f["observer_sha256"] == spec.observer.sha256
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && f["inventory"]["anomalies"] == 0,
        "native20 needs fresh accepted full fleet"
    );
    ensure!(
        o["host_memory"]["conservative_available_kib"]
            .as_u64()
            .and_then(|n| n.checked_mul(1024))
            .is_some_and(|n| n >= INITIAL_MEMORY)
            && o["filesystem"]["conservative_available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= INITIAL_DISK),
        "native20 envelope does not fit"
    );
    ensure!(
        f["inventory"]["entries"]
            .as_array()
            .context("native20 inventory")?
            .iter()
            .filter(|r| r["epoch"] == 223 && r["state"] == "missing")
            .count()
            == 1,
        "native20 must not duplicate remote223"
    );
    checked_owners(f)?;
    if EXPECT_FULL227 {
        ensure!(
            o["vm_max_map_count"]
                .as_u64()
                .is_some_and(|n| n >= 4_194_304),
            "v2 sampled VMA envelope is insufficient"
        );
        super::full227_peer::sample_memory(o, f)?;
    }
    Ok(stamp)
}
fn active_unit(r: &Value) -> &Value {
    if r["producer"].is_object() {
        &r["producer"]
    } else {
        &r["unit"]
    }
}
fn checked_owners(f: &Value) -> Result<Option<PipelineClaim>> {
    if EXPECT_FULL227 {
        super::full227_peer::accepted(f)?;
        return Ok(None);
    }
    let rows = f["active"].as_array().context("native20 active census")?;
    ensure!(
        matches!(rows.len(), 3 | 4),
        "native20 envelope admits only three old replays and optional authenticated native207"
    );
    for (name, iid) in super::OWNERS.into_iter().skip(1) {
        ensure!(
            rows.iter()
                .filter(|r| {
                    let u = active_unit(r);
                    u["Id"] == name && u["InvocationID"] == iid && u["NRestarts"] == "0"
                })
                .count()
                == 1,
            "native20 protected old owner differs"
        );
    }
    let native = rows
        .iter()
        .filter(|r| active_unit(r)["Id"] == native207::UNIT)
        .collect::<Vec<_>>();
    if rows.len() == 3 {
        ensure!(native.is_empty(), "native20 protected old owner omitted");
        native207_terminal::find(f)?;
        return Ok(None);
    }
    ensure!(
        native.len() == 1
            && native[0]["epoch"] == 207
            && native[0]["phase"] == "private-cold-snapshot-verification",
        "native20 requires the registered native207 owner"
    );
    let p: super::super::Plan = serde_json::from_value(bound_json(&BoundFile {
        path: f["plan"].as_str().context("native20 fleet plan")?.into(),
        sha256: f["plan_sha256"]
            .as_str()
            .context("native20 plan SHA")?
            .into(),
    })?)?;
    let claims = p
        .pipeline_claims
        .iter()
        .filter(|c| c.unit == native207::UNIT)
        .collect::<Vec<_>>();
    ensure!(
        claims.len() == 1,
        "native20 native207 claim missing/duplicate"
    );
    let c: PipelineClaim = serde_json::from_value(serde_json::to_value(claims[0])?)?;
    ensure!(
        c.invocation_id == active_unit(native[0])["InvocationID"]
            && c.evidence
                == serde_json::from_value::<Vec<BoundFile>>(native[0]["evidence"].clone())?,
        "native20 native207 registered evidence differs"
    );
    native207::claim(&c)?;
    Ok(Some(c))
}
fn names(f: &Value) -> Result<BTreeSet<String>> {
    let mut n = f["unit_census"]
        .as_object()
        .context("native20 census")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    n.insert(UNIT.into());
    Ok(n)
}
fn protected(f: &Value, c: &BTreeMap<String, Value>) -> Result<()> {
    let native = checked_owners(f)?;
    for (name, iid) in super::OWNERS.into_iter().skip(1) {
        let u = c.get(name).context("native20 old owner missing")?;
        ensure!(
            u["InvocationID"] == iid
                && u["NRestarts"] == "0"
                && u["ActiveState"] == "active"
                && u["MainPID"]
                    .as_str()
                    .and_then(|n| n.parse::<u64>().ok())
                    .is_some_and(|n| n > 0)
                && pipeline_status::same_exec_start(
                    f["unit_census"][name]["ExecStart"]
                        .as_str()
                        .context("native20 prior command")?,
                    u["ExecStart"].as_str().context("native20 live command")?
                ),
            "native20 old owner changed"
        );
    }
    if EXPECT_FULL227 {
        super::full227_peer::protect(f, c)?;
    } else {
        let native_owner = c
            .get(native207::UNIT)
            .context("native20 native207 census missing")?;
        if let Some(native) = native {
            native207::live(&native, native_owner)?;
        } else {
            let (_, iid) = native207_terminal::find(f)?;
            native207_terminal::terminal_shape(native_owner, &iid)?;
        }
    }
    for (name, u) in c {
        ensure!(
            !diagnostic_stage_running(u)
                || name == UNIT
                || (!EXPECT_FULL227 && name == native207::UNIT)
                || (EXPECT_FULL227 && name == singleton227::UNIT)
                || super::OWNERS.iter().skip(1).any(|(n, _)| n == name),
            "unaccounted live native20 competitor:{name}"
        );
    }
    Ok(())
}
pub(super) fn event_protected(f: &Value, c: &BTreeMap<String, Value>) -> Result<()> {
    protected(f, c)
}
fn inputs() -> Result<()> {
    let p = bound_json(&BoundFile {
        path: PLAN.into(),
        sha256: PLAN_SHA.into(),
    })?;
    ensure!(
        p["unit"] == UNIT
            && p["run_root"] == ROOT
            && p["target_slot"] == 96_335_554u64
            && p["terminal_slot"] == 96_767_522u64
            && p["minimum_free_bytes"] == INITIAL_DISK
            && p["node"]["sha256"]
                == "99f643ff0dbbcd37d1fbc524a1c1088d7273c7fc91330df059d30d51b8b0fcd4",
        "native20 actual plan differs"
    );
    let proof = bound_json(&BoundFile {
        path: "/var/lib/jetstreamer/horizon-native223-input-proof-release-v1/input-proof.json"
            .into(),
        sha256: "a76a8e809e1c4fd102461620a45bf09021dd00a660b6a68834b0ec9086e7711a".into(),
    })?;
    ensure!(
        proof["native_input_qualified"] == true
            && proof["entry_replay"] == false
            && proof["repair_closed"] == false,
        "native20 input proof differs"
    );
    let cap = bound_json(&BoundFile {
        path: CAPABILITY_PATH.into(),
        sha256: CAPABILITY_SHA.into(),
    })?;
    ensure!(
        cap["bindings"]["self_sha256"] == RUNNER_SHA
            && cap["worker_started"] == false
            && cap["input_hashes_and_private_paths_verified"] == true
            && cap["parent_planning_report"]["pre_worker_barrier_reached"] == true
            && cap["parent_planning_report"]["runtime_profile"] == "solana-v1.6.20"
            && cap["worker_sha256"]
                == "52d6c86a8103b8965ca68ead96af471a7899a0a0e6e69c48989b39fd5d922f0c",
        "native20 exact capability differs"
    );
    if EXPECT_FULL227 {
        ensure!(
            cap["target_stop_protocol"] == "cooperative-resume-only",
            "v2 capability has wrong drain protocol"
        );
    }
    Ok(())
}
fn sandbox(c: &PipelineClaim, u: &Value) -> Result<()> {
    ensure!(
        scope(&c.phase, &c.unit)
            && c.epoch == 223
            && u["InvocationID"] == c.invocation_id
            && u["NRestarts"] == "0"
            && u["ActiveState"] == "active"
            && u["SubState"] == "running"
            && u["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|n| n > 0)
            && pipeline_status::same_exec_start(
                &command(),
                u["ExecStart"].as_str().context("native20 command")?
            ),
        "native20 owner differs"
    );
    let out=ProcessCommand::new("systemctl").args(["show",UNIT,"--property=Type,User,Group,Restart,KillMode,Delegate,MemoryHigh,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,ProtectSystem,ProtectHome,ProtectControlGroups,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,ReadWritePaths,OOMPolicy,OOMScoreAdjust"]).output()?;
    ensure!(out.status.success(), "native20 sandbox unavailable");
    let text = std::str::from_utf8(&out.stdout)?;
    let fields = text
        .lines()
        .filter_map(|l| l.split_once('='))
        .collect::<BTreeMap<_, _>>();
    for (k, v) in [
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
        ensure!(fields.get(k) == Some(&v), "native20 sandbox differs:{k}");
    }
    Ok(())
}
fn protective(c: &PipelineClaim) -> Result<(BoundFile, Value)> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let selection = super::guard_receipt::select(
        GUARD,
        Path::new(GUARD_RECEIPTS),
        now.saturating_sub(120),
        now,
        120,
    )?;
    let b = selection.binding;
    let g = selection.receipt;
    let pb: BoundFile = serde_json::from_value(private157::file_binding(Path::new(GUARD_PLAN))?)?;
    let p = bound_json(&pb)?;
    ensure!(
        g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["plan_sha256"] == pb.sha256
            && g["guard_sha256"] == GUARD_SHA
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
            && g["minimum_free_bytes"] == DISK_FLOOR
            && p["minimum_free_bytes"] == DISK_FLOOR,
        "native20 VMA/disk guard missing or tripped"
    );
    let out = ProcessCommand::new("systemctl")
        .args(["show", GUARD_TIMER, "--property=ActiveState", "--value"])
        .output()?;
    ensure!(
        out.status.success() && out.stdout == b"active\n",
        "native20 guard timer inactive"
    );
    Ok((b, selection.history))
}
fn launch_shape(c: &PipelineClaim, r: &Value) -> Result<()> {
    if EXPECT_FULL227 {
        ensure!(
            r["target_stop_protocol"] == "cooperative-resume-only",
            "v2 origin does not bind cooperative drain"
        );
    }
    ensure!(
        scope(&c.phase, &c.unit)
            && c.epoch == 223
            && r["schema"] == "jetstreamer-private-warmup223-launch-v1"
            && r["epoch"] == 223
            && r["unit"] == UNIT
            && r["invocation_id"] == c.invocation_id
            && r["runner_sha256"] == RUNNER_SHA
            && r["expected_exec_start"] == c.expected_exec_start
            && pipeline_status::same_exec_start(&command(), &c.expected_exec_start)
            && r["runtime_profile"] == "solana-v1.6.20"
            && r["worker_entry_start"] == 96_335_539u64
            && r["worker_entry_end_exclusive"] == 96_335_555u64
            && r["entry_replay"] == true
            && r["ordinary_replay_claim"] == false
            && r["current_sidecar_eta_valid"] == false
            && r["public_sidecar_countdown_authorized"] == true
            && r["resource_samples_taken"] == 0
            && r["repair_closed"] == false
            && r["publication_authorized"] == false
            && r["remote_mutations"] == false
            && r["r2_mutations"] == false
            && utc_seconds(
                r["sampled_at_utc"]
                    .as_str()
                    .context("native20 origin UTC")?
            )? == r["recorded_unix_seconds"]
                .as_u64()
                .context("native20 origin clock")?,
        "native20 launch identity or truthful authority differs"
    );
    Ok(())
}
pub(super) fn validate(c: &PipelineClaim) -> Result<()> {
    ensure!(
        c.evidence.len() == 1 && c.evidence[0].path == Path::new(STATE).join("launch.json"),
        "native20 launch evidence differs"
    );
    let r = bound_json(&c.evidence[0])?;
    launch_shape(c, &r)?;
    let ab: BoundFile = serde_json::from_value(r["admission"].clone())?;
    ensure!(
        ab.path == Path::new(STATE).join("admission.json"),
        "native20 foreign admission"
    );
    let a = bound_json(&ab)?;
    ensure!(
        a["schema"] == ADMISSION_SCHEMA
            && a["decision"] == "pass"
            && a["required_observed_free_bytes"] == INITIAL_DISK
            && a["minimum_available_memory_bytes"] == MEMORY_RESERVE
            && a["candidate_memory_bytes"] == 128u64 << 30,
        "native20 admission differs"
    );
    if EXPECT_FULL227 {
        super::full227_peer::validate_budget(&a["expanded_fleet_budget"])?;
    }
    let gb: BoundFile = serde_json::from_value(r["guard"].clone())?;
    let g = bound_json(&gb)?;
    super::guard_receipt::validate_history(&r["guard_history"], &g)?;
    ensure!(
        r["guard_history"]["unit"] == GUARD
            && r["guard_history"]["maximum_age_seconds"] == 120
            && g["producer_invocation_id"] == c.invocation_id,
        "native20 captured guard history names another owner"
    );
    let guards = a["guards"]
        .as_array()
        .context("native20 admission guard bindings")?;
    let histories = a["guard_history"]
        .as_array()
        .context("native20 admission guard history")?;
    ensure!(
        guards.len() == 3 && histories.len() == 3,
        "native20 admission guard history census differs"
    );
    for (index, history) in histories.iter().enumerate() {
        let b: BoundFile = serde_json::from_value(guards[index].clone())?;
        let guard = bound_json(&b)?;
        super::guard_receipt::validate_history(history, &guard)?;
        ensure!(
            history["maximum_age_seconds"] == 1800
                && guard["producer_invocation_id"] == super::OWNERS[index + 1].1,
            "native20 preserved guard history differs"
        );
    }
    Ok(())
}
pub(super) fn validate_live(c: &PipelineClaim, u: &Value) -> Result<()> {
    validate(c)?;
    sandbox(c, u)?;
    protective(c)?;
    Ok(())
}
pub(super) fn status_claim(v: &Value) -> Result<()> {
    validate(&serde_json::from_value(v.clone())?)
}
pub(super) fn status_jet_path() -> PathBuf {
    Path::new(ROOT).join("output/epoch-223.jet")
}
pub(super) fn run(capture: bool, binding: BoundFile, self_sha: String) -> Result<()> {
    let spec: Spec = serde_json::from_value(bound_json(&binding)?)?;
    let o = bound_json(&spec.observer)?;
    let f = bound_json(&spec.fleet)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let sampled = checked_sample(&spec, &o, &f, now)?;
    inputs()?;
    let floor = super::century_floor(&f)?;
    let before = census(&names(&f)?, 201, 300)?;
    protected(&f, &before)?;
    let own = &before[UNIT];
    if capture {
        let ab: BoundFile = serde_json::from_value(private157::file_binding(
            &Path::new(STATE).join("admission.json"),
        )?)?;
        let a = bound_json(&ab)?;
        ensure!(
            a["schema"] == ADMISSION_SCHEMA
                && a["spec"] == private157::binding(&binding)
                && a["decision"] == "pass"
                && a["recorded_unix_seconds"]
                    .as_u64()
                    .is_some_and(|n| n <= now && now - n <= 900),
            "native20 admission stale/foreign"
        );
        let claim = PipelineClaim {
            epoch: 223,
            phase: "private-warmup-reproduction".into(),
            unit: UNIT.into(),
            invocation_id: own["InvocationID"]
                .as_str()
                .context("native20 live IID")?
                .into(),
            expected_exec_start: command(),
            evidence: vec![],
        };
        sandbox(&claim, own)?;
        let (guard, guard_history) = protective(&claim)?;
        let after = census(&names(&f)?, 201, 300)?;
        protected(&f, &after)?;
        ensure!(
            after[UNIT]["InvocationID"] == own["InvocationID"]
                && after[UNIT]["MainPID"] == own["MainPID"],
            "native20 capture owner changed"
        );
        private157::immutable_receipt(
            &Path::new(STATE).join("launch.json"),
            &json!({"schema":"jetstreamer-private-warmup223-launch-v1","epoch":223,"unit":UNIT,"invocation_id":claim.invocation_id,"expected_exec_start":command(),"admission":private157::binding(&ab),"guard":private157::binding(&guard),"guard_history":guard_history,"runtime_profile":"solana-v1.6.20","target_stop_protocol":if EXPECT_FULL227{"cooperative-resume-only"}else{"resume-and-interrupt"},"worker_entry_start":96335539,"worker_entry_end_exclusive":96335555,"runner_sha256":RUNNER_SHA,"recorded_unix_seconds":now,"sampled_at_utc":publication203::utc(now)?,"self_sha256":self_sha,"observer":private157::binding(&spec.observer),"previous_fleet":private157::binding(&spec.fleet),"resource_samples_taken":0,"entry_replay":true,"ordinary_replay_claim":false,"current_sidecar_eta_valid":false,"public_sidecar_countdown_authorized":true,"repair_closed":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
        )?;
    } else {
        ensure!(
            own["MainPID"] == "0"
                && matches!(own["ActiveState"].as_str(), Some("inactive" | "failed")),
            "native20 already active"
        );
        let mut guards = Vec::new();
        let mut guard_map = BTreeMap::new();
        let mut guard_history = Vec::new();
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
            let selection =
                super::guard_receipt::select(name, Path::new(root), sampled, now, 1800)?;
            publication203::guard(&selection.receipt, index, sampled, now)?;
            guard_map.insert(
                super::OWNERS[index + 1].0.to_owned(),
                BoundFile {
                    path: selection.binding.path.clone(),
                    sha256: selection.binding.sha256.clone(),
                },
            );
            guards.push(private157::binding(&selection.binding));
            guard_history.push(selection.history);
        }
        let after = census(&names(&f)?, 201, 300)?;
        protected(&f, &after)?;
        ensure!(
            after[UNIT]["MainPID"] == "0",
            "native20 started during admission"
        );
        let expanded_budget = if EXPECT_FULL227 {
            let peer = super::full227_peer::guard(&f, sampled, now)?;
            let mut budget = super::full227_peer::budget(
                &f,
                &o,
                &guard_map,
                floor["floor_bytes"].as_u64().context("v2 century floor")?,
                sampled,
                now,
                &peer.receipt,
            )?;
            budget["full227_guard"] = private157::binding(&peer.binding);
            budget["full227_guard_history"] = peer.history;
            budget
        } else {
            Value::Null
        };
        if EXPECT_FULL227 {
            let final_census = census(&names(&f)?, 201, 300)?;
            protected(&f, &final_census)?;
            ensure!(
                final_census[UNIT]["MainPID"] == "0",
                "native20 started during expanded budget capture"
            );
        }
        private157::immutable_receipt(
            &Path::new(STATE).join("admission.json"),
            &json!({"schema":ADMISSION_SCHEMA,"spec":private157::binding(&binding),"self_sha256":self_sha,"recorded_unix_seconds":now,"observer":private157::binding(&spec.observer),"fleet":private157::binding(&spec.fleet),"guards":guards,"guard_history":guard_history,"expanded_fleet_budget":expanded_budget,"decision":"pass","century_floor":floor,"candidate_memory_bytes":128u64<<30,"scratch_planning_bytes":300_000_000_000u64,"required_observed_free_bytes":INITIAL_DISK,"protected_disk_floor_bytes":DISK_FLOOR,"minimum_available_memory_bytes":MEMORY_RESERVE,"required_initial_memory_bytes":if EXPECT_FULL227{expanded_budget["required_initial_memory_bytes"].clone()}else{json!(INITIAL_MEMORY)},"expected_exec_start":command(),"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
        )?;
    }
    println!(
        "native20 warmup {} captured; no service or R2 mutation",
        if capture { "ownership" } else { "admission" }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn launch() -> (PipelineClaim, Value) {
        let c = PipelineClaim {
            epoch: 223,
            phase: "private-warmup-reproduction".into(),
            unit: UNIT.into(),
            invocation_id: "1".repeat(32),
            expected_exec_start: command(),
            evidence: vec![],
        };
        let r = json!({"schema":"jetstreamer-private-warmup223-launch-v1","epoch":223,"unit":UNIT,"invocation_id":c.invocation_id,"runner_sha256":RUNNER_SHA,"expected_exec_start":command(),"runtime_profile":"solana-v1.6.20","target_stop_protocol":if EXPECT_FULL227{"cooperative-resume-only"}else{"resume-and-interrupt"},"worker_entry_start":96335539,"worker_entry_end_exclusive":96335555,"entry_replay":true,"ordinary_replay_claim":false,"current_sidecar_eta_valid":false,"public_sidecar_countdown_authorized":true,"resource_samples_taken":0,"repair_closed":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false,"sampled_at_utc":"2026-10-23T19:00:00Z","recorded_unix_seconds":1792782000u64});
        (c, r)
    }
    #[test]
    fn bounded_entry_origin_cannot_borrow_zero_entry_or_full_prefix_authority() {
        let (c, r) = launch();
        launch_shape(&c, &r).unwrap();
        for (key, value) in [
            ("entry_replay", json!(false)),
            ("worker_entry_end_exclusive", json!(96767523)),
            ("runtime_profile", json!("solana-v1.6.25")),
            ("resource_samples_taken", json!(1)),
            ("public_sidecar_countdown_authorized", json!(false)),
            ("repair_closed", json!(true)),
            ("publication_authorized", json!(true)),
            ("ordinary_replay_claim", json!(true)),
            ("remote_mutations", json!(true)),
            ("r2_mutations", json!(true)),
            ("invocation_id", json!("2".repeat(32))),
            ("sampled_at_utc", json!("2026-10-23T19:00:01Z")),
        ] {
            let mut bad = r.clone();
            bad[key] = value;
            assert!(launch_shape(&c, &bad).is_err(), "{key}");
        }
        assert_eq!(INITIAL_MEMORY, MEMORY_RESERVE + (128u64 << 30));
        assert_eq!(INITIAL_DISK, DISK_FLOOR + 300_000_000_000);
    }
    #[test]
    fn fixed_probe_envelope_rejects_added_lane_or_missing_native207_before_file_reads() {
        if EXPECT_FULL227 {
            for f in [
                json!({"active":[]}),
                json!({"active":[{},{},{}]}),
                json!({"active":[{},{},{},{}]}),
                json!({"active":[{},{},{},{},{}]}),
            ] {
                assert!(checked_owners(&f).is_err());
            }
            return;
        }
        let rows = super::super::OWNERS
            .iter()
            .skip(1)
            .map(|(name, iid)| json!({"producer":{"Id":name,"InvocationID":iid,"NRestarts":"0"}}))
            .collect::<Vec<_>>();
        assert!(checked_owners(&json!({"active":rows})).is_err());
        let mut extra = rows.clone();
        extra.push(json!({"unit":{"Id":native207::UNIT}}));
        extra.push(json!({"unit":{"Id":"full227.service"}}));
        assert!(
            checked_owners(&json!({"active":extra}))
                .err()
                .unwrap()
                .to_string()
                .contains("only three")
        );
        let mut unknown = rows;
        unknown.push(json!({"unit":{"Id":"full227.service"}}));
        assert!(
            checked_owners(&json!({"active":unknown}))
                .err()
                .unwrap()
                .to_string()
                .contains("native207")
        );
    }
}
