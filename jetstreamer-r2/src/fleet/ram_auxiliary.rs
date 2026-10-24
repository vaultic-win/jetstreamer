//! Explicit private epoch 203 comparison ownership, never a publication claim.
//! Launch receipts must come from an independently qualified launcher; tests in
//! this module establish policy only and are not operational attestations.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Claim {
    pub unit: String,
    pub invocation_id: String,
    pub run_root: PathBuf,
    pub launch_receipt: BoundFile,
}

pub(super) fn validate_census(
    claim: Option<&Claim>,
    units: &BTreeMap<String, Value>,
) -> Result<()> {
    for (name, unit) in units {
        if ram_entry_owner(name)
            && matches!(unit["ActiveState"].as_str(), Some("active" | "activating"))
        {
            ensure!(
                claim.is_some_and(|c| c.unit == *name && unit["InvocationID"] == c.invocation_id),
                "live RAM owner lacks explicit auxiliary claim or changed invocation"
            );
        }
    }
    Ok(())
}

pub(super) fn checked_launch(claim: &Claim) -> Result<Value> {
    pinned_guard_member(
        claim
            .launch_receipt
            .path
            .to_str()
            .context("non-UTF8 launch path")?,
        &claim.launch_receipt.sha256,
    )?;
    let launch = bound_json(&claim.launch_receipt)?;
    validate_launch(claim, &launch)?;
    let binary: BoundFile = serde_json::from_value(launch["supervisor_binary"].clone())?;
    let plan: BoundFile = serde_json::from_value(launch["supervisor_plan"].clone())?;
    let setpriv: BoundFile = serde_json::from_value(launch["setpriv"].clone())?;
    ensure!(
        binary
            .path
            .file_name()
            .is_some_and(|s| s == "jetstreamer-epoch203-ram-resource")
            && setpriv.path.file_name().is_some_and(|s| s == "setpriv"),
        "auxiliary executable basename differs"
    );
    for member in [&binary, &plan, &setpriv] {
        ensure!(
            member.path.starts_with("/var/lib/jetstreamer"),
            "auxiliary input outside sealed deployment"
        );
        pinned_guard_member(
            member.path.to_str().context("non-UTF8 member")?,
            &member.sha256,
        )?;
        ensure!(
            fs::symlink_metadata(&member.path)?.mode() & 0o222 == 0,
            "auxiliary deployment member remains writable"
        );
    }
    ensure!(
        binary.sha256 == launch["supervisor_sha256"]
            && plan.sha256 == launch["plan_sha256"]
            && setpriv.sha256 == "c8521137671653eb5d520ddc3c5f9cbf3b4534c79d1b7b03506ce272d5727549",
        "auxiliary deployed executable or plan differs"
    );
    let envelope = bound_json(&plan)?;
    ensure!(
        envelope["schema"] == "jetstreamer-private-epoch203-ram-supervisor-plan-v1"
            && envelope["runner"]["unit"] == claim.unit
            && envelope["runner"]["run_root"].as_str() == claim.run_root.to_str()
            && envelope["runner"]["schema"] == launch["supervisor_profile"]
            && envelope["runner"]["target_slot"] == launch["target_slot"]
            && envelope["runner"]["terminal_slot"] == launch["terminal_root_slot"]
            && envelope["auxiliary_contract"]["sha256"] == launch["auxiliary_contract_sha256"],
        "auxiliary launch differs from sealed supervisor plan"
    );
    let prefix = format!(
        "{{ path={} ; argv[]={} --reuid=1000 --regid=1000 --clear-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs {} {} --plan-sha256 {} --self-sha256 {} ; ignore_errors=no ;",
        setpriv.path.display(),
        setpriv.path.display(),
        binary.path.display(),
        plan.path.display(),
        plan.sha256,
        binary.sha256
    );
    let command = launch["expected_exec_start"]
        .as_str()
        .context("auxiliary command missing")?;
    ensure!(
        command.starts_with(&prefix)
            && command.ends_with(" }")
            && command.matches("{ path=").count() == 1
            && !command.contains('\n'),
        "auxiliary live command is not exact sealed supervisor invocation"
    );
    Ok(launch)
}

pub(super) fn validate_launch(claim: &Claim, launch: &Value) -> Result<()> {
    let family = match launch["worker_sha256"].as_str() {
        Some("3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a") => "baseline",
        Some("4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc") => "shrink",
        _ => anyhow::bail!("unbound RAM auxiliary worker"),
    };
    ensure!(
        claim
            .unit
            .starts_with(&format!("horizon-203-ram-resource-{family}-"))
            && claim.unit.ends_with(".service")
            && claim
                .unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            && claim.invocation_id.len() == 32
            && claim
                .invocation_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && claim.run_root.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
            && claim
                .run_root
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with(&format!("ram-resource-203-{family}-"))),
        "RAM auxiliary owner namespace differs"
    );
    ensure!(
        launch["schema"] == "jetstreamer-private-epoch203-ram-resource-launch-v1"
            && launch["launched"] == true
            && launch["simulated"] == false
            && launch["epoch"] == 203
            && launch["unit"] == claim.unit
            && launch["invocation_id"] == claim.invocation_id
            && launch["private_run_root"].as_str() == claim.run_root.to_str()
            && launch["supervisor_profile"] == "jetstreamer-private-epoch203-ram-bounded-runner-plan-v1"
            && launch["parent_sha256"] == "025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d"
            && launch["snapshot_sha256"] == "e45584858d0c825f095a43ff5e5909e62a68d197d39c042a76727454525228c4"
            && launch["target_slot"] == 87_720_000u64
            && launch["terminal_root_slot"] == 88_127_580u64
            && launch["solana_rayon_threads"] == 16
            && launch["filesystem_backend"] == "persistent-tmpfs"
            && launch["root_archive_scratch_increment_bytes"] == 0
            && launch["maximum_entry_replays"] == 4
            && launch["maximum_auxiliary_diagnostics"] == 1
            && canonical_digest(&launch["supervisor_sha256"])
            && canonical_digest(&launch["plan_sha256"])
            && canonical_digest(&launch["auxiliary_contract_sha256"])
            && launch["expected_exec_start"].as_str().is_some_and(|s| {
                s.starts_with("{ path=/var/lib/jetstreamer/")
                    && s.contains("/setpriv ; argv[]=")
                    && s.contains(" --clear-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs ")
                    && s.contains("/jetstreamer-epoch203-ram-resource ")
                    && s.contains(" --plan-sha256 ") && s.contains(" --self-sha256 ")
                    && !s.contains("--storage-capability")
            }),
        "RAM auxiliary launch is unbound or grants wrong scope"
    );
    for field in [
        "ordinary_replay_authorized",
        "full_cold_epoch_peak_qualified",
        "runtime_promotion_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "retirement_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            launch[field] == false,
            "RAM auxiliary grants unrelated authority: {field}"
        );
    }
    Ok(())
}

pub(super) fn validate_scope(plan: &Plan, observer: &Value, claim: &Claim) -> Result<()> {
    ensure!(
        (plan.first_epoch..=plan.last_epoch).contains(&203),
        "RAM auxiliary outside assignment"
    );
    ensure!(
        plan.admission_transition_guard.is_none(),
        "RAM auxiliary requires a new coordinated sample"
    );
    for replay in observer["replays"]
        .as_array()
        .context("observer replays missing")?
    {
        ensure!(
            !parse_observer_claim_range(observer_string(replay, &["range"])?)?.contains(&203),
            "RAM auxiliary overlaps ordinary replay"
        );
        for field in ["controller_after", "producer_after"] {
            ensure!(
                replay[field]["unit"] != claim.unit,
                "RAM auxiliary aliases ordinary owner"
            );
            ensure!(
                replay[field]["invocation_id"] != claim.invocation_id,
                "RAM auxiliary aliases ordinary invocation"
            );
        }
        let scratch = Path::new(observer_string(replay, &["scratch_path"])?);
        ensure!(
            !scratch.starts_with(&claim.run_root) && !claim.run_root.starts_with(scratch),
            "RAM auxiliary aliases ordinary scratch"
        );
    }
    let primary: Vec<_> = plan
        .diagnostics
        .iter()
        .filter(|d| diagnostic_scope(d).contains(&203))
        .collect();
    ensure!(
        primary.len() == 1
            && primary[0].epoch == 203
            && primary[0].unit == "horizon-qualify-203-root-prefix-resource-v1.service",
        "RAM auxiliary requires explicit primary 203 diagnostic"
    );
    for diagnostic in &plan.diagnostics {
        ensure!(
            diagnostic.unit != claim.unit
                && diagnostic.invocation_id != claim.invocation_id
                && !diagnostic.scratch_path.starts_with(&claim.run_root)
                && !claim.run_root.starts_with(&diagnostic.scratch_path),
            "RAM auxiliary aliases diagnostic ownership or scratch"
        );
    }
    ensure!(
        !plan
            .pipeline_claims
            .iter()
            .any(|p| p.epoch == 203 || p.unit == claim.unit),
        "RAM auxiliary overlaps delivery work"
    );
    Ok(())
}

pub(super) fn observe(
    claim: &Claim,
    launch: &Value,
    observer: &Value,
    current: &Value,
    active: &[Value],
) -> Result<Value> {
    observe_checked(claim, launch, observer, current, active, || {
        ensure!(
            claim.run_root.canonicalize()? == claim.run_root
                && claim.run_root.join("scratch").is_dir(),
            "RAM auxiliary scratch namespace changed"
        );
        Ok(())
    })
}

fn observe_checked(
    claim: &Claim,
    launch: &Value,
    observer: &Value,
    current: &Value,
    active: &[Value],
    storage_check: impl FnOnce() -> Result<()>,
) -> Result<Value> {
    let rows = observer
        .get("epoch203_ram_auxiliary")
        .and_then(Value::as_array)
        .context("observer auxiliary census missing")?;
    ensure!(
        rows.len() == 1,
        "observer auxiliary census must name exactly one owner"
    );
    let row = &rows[0];
    ensure!(
        row["range"] == "203-203"
            && row["producer_unit"] == claim.unit
            && row["expected_producer_invocation_id"] == claim.invocation_id
            && row["scratch_path"].as_str() == claim.run_root.join("scratch").to_str()
            && row["role"] == "epoch203-private-ram-comparison"
            && row["supervisor_profile"] == launch["supervisor_profile"]
            && row["worker_sha256"] == launch["worker_sha256"]
            && row["target_slot"] == launch["target_slot"]
            && row["terminal_root_slot"] == launch["terminal_root_slot"]
            && row["ordinary_replay_claim"] == false
            && row["current_sidecar_eta_valid"] == false
            && row["publication_authorized"] == false
            && row["r2_mutations"] == false,
        "observer auxiliary role or owner differs"
    );
    // A running Type=oneshot supervisor remains activating/start until exit.
    // This exception belongs only to the explicit, launch-bound auxiliary role.
    let live = current["ActiveState"] == "active" || current["ActiveState"] == "activating";
    if live {
        ensure!(
            current["Id"] == claim.unit
                && current["InvocationID"] == claim.invocation_id
                && auxiliary_live_phase(current)
                && current["NRestarts"] == "0"
                && current["ExecStart"] == launch["expected_exec_start"],
            "RAM auxiliary live command or invocation changed"
        );
        let observation = &row["observation"];
        ensure!(
            row["status"] == "observed" && observation["invocation_binding_stable"] == true,
            "live RAM auxiliary lacks stable resource observation"
        );
        for field in [
            "controller_before",
            "controller_after",
            "producer_before",
            "producer_after",
        ] {
            ensure!(
                observation[field]["unit"] == claim.unit
                    && observation[field]["invocation_id"] == claim.invocation_id
                    && auxiliary_live_binding(&observation[field], current),
                "RAM auxiliary observation binding changed"
            );
        }
        storage_check()?;
        let mut producers = BTreeSet::new();
        for entry in active {
            let producer = &entry["producer"];
            let id = producer["InvocationID"]
                .as_str()
                .context("active entry has no producer identity")?;
            ensure!(
                producer["ActiveState"] == "active" && producer["NRestarts"] == "0",
                "unbound primary entry in auxiliary census"
            );
            producers.insert(id);
        }
        ensure!(
            producers.len() == 3 && !producers.contains(claim.invocation_id.as_str()),
            "RAM comparison requires exact three distinct primary entry owners"
        );
    } else {
        ensure!(
            matches!(current["ActiveState"].as_str(), Some("inactive" | "failed")),
            "RAM auxiliary is transitioning or unreadable"
        );
        ensure!(
            current["MainPID"] == "0",
            "terminal RAM auxiliary retains a process"
        );
    }
    Ok(
        json!({"epoch":203,"phase":"private-ram-comparison","producer":current,
        "live":live,"unit":current,"expected_invocation_id":claim.invocation_id,
        "scratch_path":claim.run_root.join("scratch"),"launch_receipt":claim.launch_receipt.path,
        "launch_receipt_sha256":claim.launch_receipt.sha256,"observation":row,
        "sampled_at_utc":observer["recorded_at_utc"],"ordinary_replay_claim":false,
        "current_sidecar_eta_valid":false,"publication_authorized":false,"r2_mutations":false}),
    )
}

fn auxiliary_live_phase(current: &Value) -> bool {
    current["MainPID"]
        .as_str()
        .and_then(|s| s.parse::<u32>().ok())
        .is_some_and(|pid| pid > 0)
        && (current["ActiveState"] == "active" && current["SubState"] == "running"
            || current["Type"] == "oneshot"
                && current["ActiveState"] == "activating"
                && current["SubState"] == "start")
}

fn auxiliary_live_binding(observed: &Value, current: &Value) -> bool {
    auxiliary_live_phase(current)
        && current["NRestarts"] == "0"
        && observed["unit"] == current["Id"]
        && observed["invocation_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty() && current["InvocationID"] == id)
        && observed["active_state"] == current["ActiveState"]
        && observed["sub_state"] == current["SubState"]
        && observed["main_pid"].as_u64().is_some_and(|pid| {
            current["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                == Some(pid)
        })
        && observed["restarts"] == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // Policy fixtures only: never written or presented as real launch/capability evidence.
    fn fixture() -> (Claim, Value, Value, Value, Vec<Value>) {
        let claim = Claim {
            unit: "horizon-203-ram-resource-baseline-test.service".into(),
            invocation_id: "b".repeat(32),
            run_root: "/home/ubuntu/.jetstreamer-private/ram-resource-203-baseline-test".into(),
            launch_receipt: BoundFile {
                path: "/sealed/not-an-operational-receipt.json".into(),
                sha256: "c".repeat(64),
            },
        };
        let launch = json!({"schema":"jetstreamer-private-epoch203-ram-resource-launch-v1",
            "launched":true,"simulated":false,"epoch":203,"unit":claim.unit,
            "invocation_id":claim.invocation_id,"private_run_root":claim.run_root,
            "supervisor_profile":"jetstreamer-private-epoch203-ram-bounded-runner-plan-v1",
            "worker_sha256":"3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a",
            "parent_sha256":"025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d",
            "snapshot_sha256":"e45584858d0c825f095a43ff5e5909e62a68d197d39c042a76727454525228c4",
            "target_slot":87720000,"terminal_root_slot":88127580,"solana_rayon_threads":16,
            "filesystem_backend":"persistent-tmpfs","root_archive_scratch_increment_bytes":0,
            "maximum_entry_replays":4,"maximum_auxiliary_diagnostics":1,
            "supervisor_sha256":"d".repeat(64),"plan_sha256":"e".repeat(64),
            "auxiliary_contract_sha256":"f".repeat(64),
            "expected_exec_start":"{ path=/var/lib/jetstreamer/tools/setpriv ; argv[]=/var/lib/jetstreamer/tools/setpriv --reuid=1000 --regid=1000 --clear-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs /var/lib/jetstreamer/tools/jetstreamer-epoch203-ram-resource /sealed/plan --plan-sha256 x --self-sha256 y ; ignore_errors=no ; }",
            "ordinary_replay_authorized":false,"full_cold_epoch_peak_qualified":false,
            "runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,
            "publication_authorized":false,"retirement_authorized":false,
            "remote_mutations":false,"r2_mutations":false});
        let unit = json!({"Id":claim.unit,"InvocationID":claim.invocation_id,
            "ActiveState":"active","SubState":"running","NRestarts":"0",
            "ExecStart":launch["expected_exec_start"],"MainPID":"123"});
        let binding = json!({"unit":claim.unit,"invocation_id":claim.invocation_id,
            "active_state":"active","sub_state":"running","main_pid":123,"restarts":0});
        let observer = json!({"recorded_at_utc":"2026-10-21T05:29:36Z",
            "epoch203_ram_auxiliary":[{"range":"203-203","producer_unit":claim.unit,
                "expected_producer_invocation_id":claim.invocation_id,"scratch_path":claim.run_root.join("scratch"),
                "role":"epoch203-private-ram-comparison","supervisor_profile":launch["supervisor_profile"],
                "worker_sha256":launch["worker_sha256"],"target_slot":87720000,"terminal_root_slot":88127580,
                "ordinary_replay_claim":false,"current_sidecar_eta_valid":false,
                "publication_authorized":false,"r2_mutations":false,"status":"observed",
                "observation":{"invocation_binding_stable":true,"controller_before":binding,
                    "controller_after":binding,"producer_before":binding,"producer_after":binding}}]});
        // Legacy cohorts repeat the same producer over four epoch claims.
        let active = ["1", "2", "3", "1", "2"]
            .into_iter()
            .map(|id| {
                json!({
            "producer":{"InvocationID":id.repeat(32),"ActiveState":"active","NRestarts":"0"}})
            })
            .collect();
        (claim, launch, observer, unit, active)
    }

    #[test]
    fn exact_private_launch_never_authorizes_publication_or_a_capability_probe() {
        let (claim, launch, _, _, _) = fixture();
        validate_launch(&claim, &launch).unwrap();
        for (field, value) in [
            ("simulated", json!(true)),
            ("publication_authorized", json!(true)),
            ("epoch", json!(204)),
            ("target_slot", json!(87720001)),
            ("worker_sha256", json!("a".repeat(64))),
            ("filesystem_backend", json!("disk")),
            ("maximum_entry_replays", json!(5)),
            ("retirement_authorized", json!(true)),
            (
                "schema",
                json!("jetstreamer-private-epoch203-ram-supervisor-storage-capability-v1"),
            ),
            (
                "expected_exec_start",
                json!(format!(
                    "{} --storage-capability",
                    launch["expected_exec_start"].as_str().unwrap()
                )),
            ),
        ] {
            let mut wrong = launch.clone();
            wrong[field] = value;
            assert!(validate_launch(&claim, &wrong).is_err(), "{field}");
        }
    }

    #[test]
    fn tracked_ram_unit_is_not_an_explicit_auxiliary_claim() {
        let (claim, _, _, unit, _) = fixture();
        let mut units = BTreeMap::from([(claim.unit.clone(), unit)]);
        assert!(validate_census(None, &units).is_err());
        validate_census(Some(&claim), &units).unwrap();
        units.get_mut(&claim.unit).unwrap()["InvocationID"] = json!("a".repeat(32));
        assert!(validate_census(Some(&claim), &units).is_err());
    }

    #[test]
    fn auxiliary_scope_preserves_primary_and_rejects_ordinary_pipeline_and_history_aliases() {
        let (claim, _, _, _, _) = fixture();
        let make_plan = || {
            serde_json::from_value::<Plan>(json!({
            "schema":"jetstreamer-horizon-campaign-fleet-plan-v1","first_epoch":201,"last_epoch":300,
            "observer":{"path":"/observer","sha256":"a".repeat(64)},"previous_fleet":null,
            "output":"/output","status_receipt_directory":"/status","gates":{},"tracked_units":[],
            "diagnostics":[{"epoch":203,"unit":"horizon-qualify-203-root-prefix-resource-v1.service",
                "invocation_id":"1".repeat(32),"scratch_path":"/private/primary",
                "launch_receipt":{"path":"/launch","sha256":"a".repeat(64)}}]
        })).unwrap()
        };
        let observer = json!({"replays":[]});
        validate_scope(&make_plan(), &observer, &claim).unwrap();
        let mut plan = make_plan();
        plan.diagnostics.clear();
        assert!(validate_scope(&plan, &observer, &claim).is_err());
        let mut plan = make_plan();
        plan.diagnostics[0].scratch_path = claim.run_root.join("scratch");
        assert!(validate_scope(&plan, &observer, &claim).is_err());
        let mut plan = make_plan();
        plan.admission_transition_guard = Some(BoundFile {
            path: "/guard".into(),
            sha256: "a".repeat(64),
        });
        assert!(validate_scope(&plan, &observer, &claim).is_err());
        let ordinary = json!({"replays":[{"range":"203-203"}]});
        assert!(validate_scope(&make_plan(), &ordinary, &claim).is_err());
        let alias = json!({"replays":[{"range":"216-219","controller_after":{"unit":"ordinary","invocation_id":"a"},
            "producer_after":{"unit":"producer","invocation_id":"c"},"scratch_path":claim.run_root.join("scratch")}]});
        assert!(validate_scope(&make_plan(), &alias, &claim).is_err());
    }

    #[test]
    fn private_auxiliary_counts_distinct_owners_and_keeps_its_role_separate() {
        let (claim, launch, observer, unit, active) = fixture();
        let entry = observe_checked(&claim, &launch, &observer, &unit, &active, || Ok(())).unwrap();
        assert_eq!(entry["live"], true);
        assert_eq!(entry["phase"], "private-ram-comparison");
        for field in [
            "ordinary_replay_claim",
            "current_sidecar_eta_valid",
            "publication_authorized",
            "r2_mutations",
        ] {
            assert_eq!(entry[field], false);
        }
        let mut fifth = active;
        fifth.push(json!({"producer":{"InvocationID":"4".repeat(32),"ActiveState":"active","NRestarts":"0"}}));
        assert!(observe_checked(&claim, &launch, &observer, &unit, &fifth, || Ok(())).is_err());
        assert!(observe_checked(&claim, &launch, &observer, &unit, &[], || Ok(())).is_err());
        assert!(
            observe_checked(
                &claim,
                &launch,
                &observer,
                &unit,
                &fifth[..3],
                || anyhow::bail!("storage replaced")
            )
            .is_err()
        );
    }

    #[test]
    fn actual_oneshot_phase_is_live_only_for_exact_running_auxiliary_binding() {
        let (claim, launch, mut observer, mut unit, active) = fixture();
        unit["Type"] = json!("oneshot");
        unit["ActiveState"] = json!("activating");
        unit["SubState"] = json!("start");
        for field in [
            "controller_before",
            "controller_after",
            "producer_before",
            "producer_after",
        ] {
            let binding = &mut observer["epoch203_ram_auxiliary"][0]["observation"][field];
            binding["active_state"] = json!("activating");
            binding["sub_state"] = json!("start");
        }
        let result =
            observe_checked(&claim, &launch, &observer, &unit, &active, || Ok(())).unwrap();
        assert_eq!(result["live"], true);
        // Do not generalize the primary active/running gate.
        assert!(!live_binding(
            &observer["epoch203_ram_auxiliary"][0]["observation"]["producer_after"],
            &unit
        ));
        for (field, value) in [
            ("Type", "simple"),
            ("SubState", "start-pre"),
            ("SubState", "start-post"),
            ("SubState", "exited"),
            ("MainPID", "0"),
            ("MainPID", "124"),
            ("MainPID", "unreadable"),
            ("NRestarts", "1"),
            ("InvocationID", "replacement"),
        ] {
            let mut wrong = unit.clone();
            wrong[field] = json!(value);
            assert!(
                observe_checked(&claim, &launch, &observer, &wrong, &active, || Ok(())).is_err(),
                "{field}={value}"
            );
        }
        for field in [
            "controller_before",
            "controller_after",
            "producer_before",
            "producer_after",
        ] {
            let mut wrong = observer.clone();
            wrong["epoch203_ram_auxiliary"][0]["observation"][field]["main_pid"] = json!(124);
            assert!(
                observe_checked(&claim, &launch, &wrong, &unit, &active, || Ok(())).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn live_auxiliary_requires_exact_command_invocation_and_its_own_fresh_sample() {
        let (claim, launch, observer, unit, active) = fixture();
        for field in ["InvocationID", "ExecStart", "NRestarts", "SubState"] {
            let mut wrong = unit.clone();
            wrong[field] = json!("changed");
            assert!(
                observe_checked(&claim, &launch, &observer, &wrong, &active, || Ok(())).is_err(),
                "{field}"
            );
        }
        for field in [
            "producer_unit",
            "expected_producer_invocation_id",
            "worker_sha256",
            "status",
        ] {
            let mut wrong = observer.clone();
            wrong["epoch203_ram_auxiliary"][0][field] = json!("changed");
            assert!(
                observe_checked(&claim, &launch, &wrong, &unit, &active, || Ok(())).is_err(),
                "{field}"
            );
        }
        let mut wrong = observer.clone();
        wrong["epoch203_ram_auxiliary"][0]["observation"]["controller_before"]["invocation_id"] =
            json!("a".repeat(32));
        assert!(observe_checked(&claim, &launch, &wrong, &unit, &active, || Ok(())).is_err());
    }

    #[test]
    fn terminal_auxiliary_is_not_a_live_countdown_or_archive_completion() {
        let (claim, launch, observer, mut unit, active) = fixture();
        unit["ActiveState"] = json!("failed");
        unit["MainPID"] = json!("0");
        let entry = observe_checked(&claim, &launch, &observer, &unit, &active, || {
            panic!("terminal must not inspect scratch")
        })
        .unwrap();
        assert_eq!(entry["live"], false);
        assert_eq!(entry["current_sidecar_eta_valid"], false);
        unit["MainPID"] = json!("123");
        assert!(observe_checked(&claim, &launch, &observer, &unit, &active, || Ok(())).is_err());
    }
}
