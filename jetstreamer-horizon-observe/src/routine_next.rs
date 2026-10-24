//! Offline successor preparation for the explicitly bounded routine profiles.
//! No subprocesses, environment credentials, resource observation or deployment.
use super::*;
use std::os::unix::fs::DirBuilderExt;

const ROOT: &str = "/var/lib/jetstreamer/horizon-next-preparations-v1";
const OBSERVERS: &str = "/home/ubuntu/workspace/jetstreamer/.codex/tmp-readiness";
const ROOT_101: &str = "/var/lib/jetstreamer/horizon-next-preparations-101-200-v2";
const OBSERVERS_101: &str = "/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1";

fn utc_string(seconds: u64) -> Result<String> {
    let seconds: libc::time_t = seconds.try_into()?;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    ensure!(
        !unsafe { libc::gmtime_r(&seconds, &mut tm) }.is_null(),
        "UTC conversion failed"
    );
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    ))
}

pub(super) fn completion_bindings(p: &Plan, pb: &Bound, c: &Value) -> Result<()> {
    is_101(p)?;
    qualification141_status::completion(p, c)?;
    cohort191_delivery::completion(p, c)?;
    ensure!(
        c["schema"] == "jetstreamer-horizon-routine-cycle-completion-v1"
            && c["sampled_at_utc"] == p.sample_target_utc
            && c["plan"] == serde_json::to_value(pb)?
            && c["observer"]["path"].as_str() == p.observer.to_str()
            && c["fleet"]["path"].as_str() == p.fleet_output.to_str()
            && c["estimates"]["path"].as_str() == p.estimate_output.to_str()
            && c["model"]["path"].as_str()
                == p.cycle_directory.join("sealed/eta-model.json").to_str()
            && (c["fleet_plan"]["path"].as_str()
                == p.cycle_directory.join("sealed/fleet-plan.json").to_str()
                || public198::promoted(p, c)?
                || repair183_fleet_recovery::completed_plan(p, c)?
                || repair185_fleet_recovery::completed_plan(p, c)?
                || cohort191_gate_recovery::completed(p, c)?
                || cohort191_native_recovery::completed(p, c)?),
        "completion does not bind exact current cycle"
    );
    for flag in [
        "archive_mutations",
        "sidecar_mutations",
        "replay_launch_authorized",
        "deletions",
    ] {
        ensure!(c[flag] == false, "completion grants mutation: {flag}");
    }
    ensure!(
        c["new_resource_samples"] == 0
            && c["inventory"]["anomalies"] == 0
            && is_sha(c["self_sha256"].as_str().unwrap_or(""))
            && c["invocation_id"].as_str().is_some_and(|s| s.len() == 32
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
        "not a completed unambiguous metadata owner"
    );
    let bootstrap_count = if c["unestimated_bootstrap_epochs"].is_null() {
        0
    } else {
        let binding: Bound = serde_json::from_value(c["model"].clone())?;
        let model = bound_json(&binding, true)?;
        if c["unestimated_bootstrap_epochs"] == json!([183, 184]) {
            ensure!(
                repair183::bootstrap_model(p, &model),
                "unbound bootstrap omission"
            );
            2
        } else {
            ensure!(
                c["unestimated_bootstrap_epochs"] == json!([185])
                    && repair185::bootstrap_model(p, &model),
                "foreign bootstrap omission"
            );
            1
        }
    };
    ensure!(
        c["status_publications"]
            .as_array()
            .is_some_and(|a| a.len() + bootstrap_count == p.expected_epochs.len()),
        "completion status census differs"
    );
    Ok(())
}

pub(super) fn derive_next(
    p: &Plan,
    pb: &Bound,
    c: &Value,
    config: &Value,
) -> Result<(Plan, Value, PathBuf, PathBuf)> {
    completion_bindings(p, pb, c)?;
    let host101 = is_101(p)?;
    let next_time = utc_string(
        utc_seconds(&p.sample_target_utc)?
            .checked_add(1800)
            .context("time overflow")?,
    )?;
    let old_stamp = stamp(scheduled_target(p)?);
    let next_stamp = stamp(&next_time);
    let (observer_package, cycle_package, next_observer) = if host101 {
        let legacy_config = Path::new("/usr/local/lib/jetstreamer").join(format!(
            "horizon-control-seven-{}-{}-v1/observer-config.json",
            &old_stamp[9..13],
            &old_stamp[..8]
        ));
        let prepared_config = Path::new("/var/lib/jetstreamer").join(format!(
            "horizon-next-observer-101-200-{old_stamp}-{}/observer.json",
            generation_101(p)
        ));
        ensure!(
            p.observer == Path::new(OBSERVERS_101).join(format!("sample-{old_stamp}.json"))
                && ((p.epoch198_delivery.is_none() && p.observer_config.path == legacy_config)
                    || p.observer_config.path == prepared_config
                    || terminal141::matches(p)
                    || provisional141::candidate(p)),
            "101observer/config is outside its exact manual or prepared namespace"
        );
        (
            Path::new("/var/lib/jetstreamer").join(format!(
                "horizon-next-observer-101-200-{next_stamp}-{}",
                generation_101(p)
            )),
            Path::new("/var/lib/jetstreamer").join(format!(
                "horizon-routine-plan-101-200-{next_stamp}-{}",
                generation_101(p)
            )),
            Path::new(OBSERVERS_101).join(format!("sample-{next_stamp}.json")),
        )
    } else {
        let generation = p
            .observer
            .file_name()
            .and_then(|s| s.to_str())
            .and_then(|s| s.strip_prefix(&format!("horizon-live-resource-sample-{old_stamp}-v")))
            .and_then(|s| s.strip_suffix(".json"))
            .context("noncanonical observer generation")?;
        let n: u32 = generation.parse()?;
        ensure!(
            n > 0
                && n.to_string() == generation
                && p.observer.parent() == Some(Path::new(OBSERVERS))
                && p.observer_config.path
                    == Path::new("/var/lib/jetstreamer").join(format!(
                        "horizon-next-observer-{old_stamp}-v{n}/observer.json"
                    )),
            "observer config/output generation mismatch"
        );
        let n = n.checked_add(1).context("generation overflow")?;
        (
            Path::new("/var/lib/jetstreamer")
                .join(format!("horizon-next-observer-{next_stamp}-v{n}")),
            Path::new("/var/lib/jetstreamer").join(format!("horizon-routine-plan-{next_stamp}-v1")),
            Path::new(OBSERVERS).join(format!(
                "horizon-live-resource-sample-{next_stamp}-v{n}.json"
            )),
        )
    };
    ensure!(
        config["schema"] == "jetstreamer-horizon-live-resource-sample-config-v2"
            && config["output"].as_str() == p.observer.to_str()
            && config["not_before_utc"] == scheduled_target(p)?
            && config["minimum_interval_seconds"] == 1800
            && config
                .get("observation_reason")
                .is_none_or(|v| v == "routine")
            && config.get("epoch203_ram_auxiliary").is_none(),
        "not an unchanged ordinary routine config"
    );
    let mut next_config = config.clone();
    terminal141::next_config(p, &mut next_config)?;
    cohort191_delivery::next_config(p, &mut next_config)?;
    terminal185::config(p, &mut next_config)?;
    next_config["not_before_utc"] = json!(next_time);
    next_config["previous_sample"] = json!(p.observer);
    next_config["output"] = json!(next_observer);
    let observer_sha = sha(&encoded(&next_config)?);
    let mut next: Plan = serde_json::from_value(serde_json::to_value(p)?)?;
    cohort191_native_recovery::successor(p, c, &mut next)?;
    next.sample_target_utc = next_time;
    next.delayed_schedule_utc = None;
    next.observer = serde_json::from_value(next_config["output"].clone())?;
    next.observer_config = Bound {
        path: observer_package.join("observer.json"),
        sha256: observer_sha,
    };
    next.previous_observer = serde_json::from_value(c["observer"].clone())?;
    next.model_template = serde_json::from_value(c["model"].clone())?;
    next.fleet_template = serde_json::from_value(c["fleet_plan"].clone())?;
    next.previous_estimates = serde_json::from_value(c["estimates"].clone())?;
    next.previous_fleet = serde_json::from_value(c["fleet"].clone())?;
    next.cycle_unit = cycle_unit(&next)?;
    next.cycle_directory = if host101 {
        Path::new("/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2")
            .join(format!("{next_stamp}-{}", generation_101(&next)))
    } else {
        Path::new("/var/lib/jetstreamer/horizon-routine-cycles-v1").join(format!("{next_stamp}-v1"))
    };
    next.estimate_output = p
        .estimate_output
        .parent()
        .context("estimate parent")?
        .join(format!(
            "horizon-r2-status-estimates-{next_stamp}-cohort-gated-v5.json"
        ));
    next.fleet_output = if host101 {
        Path::new(FLEET_ROOT_101).join(format!("fleet-{next_stamp}.json"))
    } else {
        Path::new("/var/lib/jetstreamer/horizon-campaign-fleet")
            .join(format!("{next_stamp}-rust-v1/fleet-ledger.json"))
    };
    if let Some(scope) = &mut next.scope_101_200 {
        // Prior additions are already in the bound accepted fleet template.
        // Do not grow this bounded supplemental list forever across successors.
        scope.additional_tracked_units = vec![next.cycle_unit.clone()];
    }
    Ok((next, next_config, observer_package, cycle_package))
}

fn validate_folded_scope(p: &Plan, fleet_plan: &Value) -> Result<()> {
    if let Some(scope) = &p.scope_101_200 {
        let tracked = fleet_plan["tracked_units"]
            .as_array()
            .context("accepted fleet tracked census missing")?;
        ensure!(
            scope
                .additional_tracked_units
                .iter()
                .all(|u| tracked.iter().any(|v| v.as_str() == Some(u.as_str()))),
            "prior observational additions are absent from accepted fleet template"
        );
    }
    Ok(())
}
pub(super) fn encoded(value: &Value) -> Result<Vec<u8>> {
    let mut b = serde_json::to_vec_pretty(value)?;
    b.push(b'\n');
    Ok(b)
}
fn seal_plan(stage: &Path, source: &str, destination: &Path, name: &str, digest: &str) -> Value {
    json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":destination,
        "members":[{"source":stage.join(source),"name":name,"sha256":digest,"mode":256}]})
}

pub(super) fn validate_status(
    s: &Value,
    p: &Plan,
    observer: &Bound,
    estimate: &Value,
) -> Result<()> {
    ensure!(
        s["schema"] == "jetstreamer-horizon-r2-status-authenticated-publication-receipt-v1"
            && s["bucket"] == p.bucket
            && s["authenticated_readback"] == true
            && s["epoch"] == estimate["epoch"]
            && s["status"]["epoch"] == estimate["epoch"]
            && s["controller_invocation_id"] == estimate["expected_controller_invocation_id"]
            && s["producer_invocation_id"] == estimate["expected_producer_invocation_id"]
            && s["status"]["sampled_at_utc"] == p.sample_target_utc
            && s["status"]["phase"] == "replay"
            && s["status"]["elapsed_execution_millis"] == estimate["elapsed_execution_millis"]
            && s["status"]["estimated_remaining_millis"] == estimate["estimated_remaining_millis"]
            && s["observer_receipt"].as_str() == observer.path.to_str()
            && s["observer_receipt_sha256"] == observer.sha256,
        "status receipt does not reproduce accepted owner/estimate"
    );
    Ok(())
}

pub(super) fn prepare(
    p: &Plan,
    pb: &Bound,
    self_sha: &str,
    mode: &str,
    handoff_spec: Option<&Bound>,
) -> Result<()> {
    // A newly admitted metadata-only park can already be active while deriving
    // from an older accepted plan. Apply its separately sealed current-state
    // classification locally before validating that predecessor; never rewrite
    // the historical plan, observer, completion or growth obligations.
    let classified_predecessor = if mode == "--prepare-next-import191" {
        let v = bound_json(handoff_spec.context("191 import handoff absent")?, true)?;
        if let Some(b) = v.get("holding185_admission").filter(|v| !v.is_null()) {
            ensure!(
                v["schema"] == "jetstreamer-cohort191-import-pending-routine-handoff-v1"
                    && v["replay_launch_authorized"] == false
                    && v["publication_authorized"] == false
                    && v["r2_mutations"] == false,
                "191 import classification handoff grants authority"
            );
            let mut q: Plan = serde_json::from_value(serde_json::to_value(p)?)?;
            terminal185::admit_holding(&mut q, &serde_json::from_value(b.clone())?)?;
            Some(q)
        } else {
            None
        }
    } else {
        None
    };
    let p = classified_predecessor.as_ref().unwrap_or(p);
    let prefix_spec = if matches!(
        mode,
        "--prepare-next-prefix157"
            | "--prepare-next-prefix144"
            | "--prepare-next-completed144"
            | "--prepare-next-native144"
            | "--prepare-next-continuation144"
            | "--prepare-next-assembly144"
    ) {
        handoff_spec
    } else {
        None
    };
    let native_spec = if mode == "--prepare-next-native198" {
        handoff_spec
    } else {
        None
    };
    let rejection_spec = if mode == "--prepare-next-native141-rejection" {
        handoff_spec
    } else {
        None
    };
    let scans_spec = if mode == "--prepare-next-assembly144-scans" {
        handoff_spec
    } else {
        None
    };
    let acquisition_spec = if matches!(
        mode,
        "--prepare-next-native141-acquisition"
            | "--prepare-next-native141-all-acquisition"
            | "--prepare-next-native141-all-retry"
            | "--prepare-next-census141-poh"
    ) {
        handoff_spec
    } else {
        None
    };
    let transition191 = matches!(
        mode,
        "--prepare-next-delivery191" | "--prepare-next-import191"
    );
    let delivery_spec = if transition191
        || prefix_spec.is_some()
        || native_spec.is_some()
        || rejection_spec.is_some()
        || scans_spec.is_some()
        || acquisition_spec.is_some()
        || mode == "--prepare-next-publication144"
        || mode == "--prepare-next-original141"
        || mode == "--prepare-next-repair141"
        || mode == "--prepare-next-terminal185"
        || mode == "--prepare-next-memory152-rebind"
    {
        None
    } else {
        handoff_spec
    };
    let enable_terminal157 = mode == "--prepare-next-terminal157";
    let enable_private144 = mode == "--prepare-next-private144";
    let recover_controllers = mode == "--prepare-package-recovery";
    let pause157 = mode == "--prepare-runtime157-pause";
    // No new service/remote observations. Consume only root-private accepted
    // cycle artifacts; the later normal --check-only gate remains mandatory.
    let completion_path = p.cycle_directory.join("completion.json");
    let bytes = read_checked(&completion_path, LIMIT, 0, false)?;
    let completion: Value = serde_json::from_slice(&bytes)?;
    let config = bound_json(&p.observer_config, true)?;
    let (mut next, mut next_config, mut observer_package, mut cycle_package) =
        derive_next(p, pb, &completion, &config)?;
    publication144::upgrade_reader(&mut next);
    native144_recovery::consume(&mut next, &completion)?;
    public160_recovery::consume(&mut next, &completion)?;
    repair183_fleet_recovery::consume(&mut next, &completion)?;
    repair185_fleet_recovery::consume(&mut next, &completion)?;
    delivery160::consume(&mut next)?;
    if mode == "--prepare-next-public160-timing" {
        ensure!(
            handoff_spec.is_none(),
            "160 timing consumes exact existing calibration only"
        );
        public160_timing::enable(&mut next)?;
        prefix157::namespaces(&mut next, &mut observer_package, &mut cycle_package)?;
    }
    if mode == "--prepare-next-public160" {
        ensure!(
            handoff_spec.is_none(),
            "160 public handoff consumes exact event capture only"
        );
        public160::enable(&mut next)?;
        prefix157::namespaces(&mut next, &mut observer_package, &mut cycle_package)?;
    }
    assembly144_scans_recover::consume(&mut next, &completion)?;
    if completion.get("public198_promotion").is_some() {
        public198::consume(&mut next, &completion, &mut next_config)?;
        public198::namespaces(&mut next, &mut observer_package, &mut cycle_package)?;
    } else {
        delivery198::consume_recovery(&mut next)?;
    }
    let model = bound_json(&next.model_template, true)?;
    if mode == "--prepare-next-memory152-rebind" {
        memory152::enable(
            &mut next,
            &mut next_config,
            handoff_spec.context("152 rebind proof required")?,
        )?;
        prefix157::namespaces(&mut next, &mut observer_package, &mut cycle_package)?;
    }
    if transition191 {
        cohort191_delivery::enable(
            &mut next,
            &mut next_config,
            &model,
            handoff_spec.context("191 transition needs its actual sealed handoff spec")?,
            mode == "--prepare-next-import191",
        )?;
        prefix157::namespaces(&mut next, &mut observer_package, &mut cycle_package)?;
    }
    if mode == "--prepare-next-terminal185" {
        terminal185::enable(
            &mut next,
            &mut next_config,
            handoff_spec.context("185 terminal handoff required")?,
        )?;
        prefix157::namespaces(&mut next, &mut observer_package, &mut cycle_package)?;
    }
    controller_recovery::consume(&mut next, &model)?;
    if enable_terminal157 {
        terminal_handoff::enable(&mut next, &model)?;
    }
    terminal_handoff::consume(&mut next, &model)?;
    terminal_handoff::preflight(&next, &model)?;
    let fleet_plan = bound_json(&next.fleet_template, true)?;
    validate_folded_scope(p, &fleet_plan)?;
    let fleet = bound_json(&next.previous_fleet, false)?;
    let estimates = bound_json(&next.previous_estimates, false)?;
    let observer = bound_json(&next.previous_observer, false)?;
    validate_templates(&next, &model, &fleet_plan, &fleet, &estimates, &observer)?;
    let effective = private144::effective_model(
        &next,
        &delivery160::effective_model(
            &next,
            &delivery198::preparation_model(&next, &model, delivery_spec)?,
        )?,
    )?;
    let effective = repair183::effective_model(&next, &effective)?;
    let effective = repair185::effective_model(&next, &effective)?;
    let effective = cohort191_delivery::effective_model(&next, &effective)?;
    validate_observer_config(&next, &effective, &next_config)?;
    let entries = verify_estimates(p, &model, &next.previous_observer, &estimates)?;
    if (prefix_spec.is_none() && mode != "--prepare-next-original141")
        || mode == "--prepare-next-completed144"
    {
        latest_fleet_unchanged(&next, &fleet)?;
    }
    for tool in [&next.tools.sealer, &next.tools.estimator, &next.tools.r2] {
        tool_ok(tool)?;
    }
    for group in next.additional_gate_evidence.values() {
        for b in group {
            bound_json(b, false)?;
        }
    }
    let statuses = completion["status_publications"]
        .as_array()
        .context("status list")?;
    let mut seen = BTreeSet::new();
    for b in statuses {
        let b: Bound = serde_json::from_value(b.clone())?;
        let s = bound_json(&b, false)?;
        let epoch = s["epoch"].as_u64().context("status epoch")?;
        let estimate = entries
            .iter()
            .find(|e| e["epoch"] == epoch)
            .context("status estimate missing")?;
        validate_status(&s, p, &next.previous_observer, estimate)?;
        ensure!(
            p.expected_epochs.contains(&epoch)
                && seen.insert(epoch)
                && s["authenticated_readback"] == true
                && s["status"]["sampled_at_utc"] == p.sample_target_utc
                && s["observer_receipt"].as_str() == next.previous_observer.path.to_str()
                && s["observer_receipt_sha256"] == next.previous_observer.sha256,
            "status receipt is not the accepted observation"
        );
    }
    delivery198::validate_completed(p, &completion)?;
    delivery160::validate_completed(p, &completion)?;
    publication144::validate_completed(p, &completion)?;
    if mode == "--prepare-next-assembly144-reader" {
        ensure!(
            handoff_spec.is_none(),
            "reader-only migration cannot consume another handoff"
        );
        assembly144::upgrade_reader(&mut next)?;
        prefix157::namespaces(&mut next, &mut observer_package, &mut cycle_package)?;
        tool_ok(&next.tools.r2)?;
        validate_templates(&next, &model, &fleet_plan, &fleet, &estimates, &observer)?;
    }
    if mode == "--prepare-next-native141" {
        ensure!(
            handoff_spec.is_none(),
            "native141 consumes only its exact actual first guard"
        );
        native141::enable(&mut next)?;
        prefix157::namespaces(&mut next, &mut observer_package, &mut cycle_package)?;
        tool_ok(&next.tools.r2)?;
        validate_templates(&next, &model, &fleet_plan, &fleet, &estimates, &observer)?;
        native141::derive_fleet(&next, &mut fleet_plan.clone())?;
    }
    if mode == "--prepare-next-native141-rejection" {
        native141::enable_rejection(
            &mut next,
            rejection_spec.context("rejection handoff required")?,
        )?;
        prefix157::namespaces(&mut next, &mut observer_package, &mut cycle_package)?;
        tool_ok(&next.tools.r2)?;
        validate_templates(&next, &model, &fleet_plan, &fleet, &estimates, &observer)?;
        native141::derive_fleet(&next, &mut fleet_plan.clone())?;
    }
    if mode == "--prepare-next-assembly144-scans" {
        assembly144_scans::enable(&mut next, scans_spec.context("scan handoff required")?)?;
        prefix157::namespaces(&mut next, &mut observer_package, &mut cycle_package)?;
        tool_ok(&next.tools.r2)?;
        validate_templates(&next, &model, &fleet_plan, &fleet, &estimates, &observer)?;
        assembly144_scans::derive_fleet(&next, &mut fleet_plan.clone())?;
    }
    if mode == "--prepare-next-native141-acquisition" {
        native141::enable_acquisition(
            &mut next,
            acquisition_spec.context("acquisition handoff required")?,
        )?;
        prefix157::namespaces(&mut next, &mut observer_package, &mut cycle_package)?;
        tool_ok(&next.tools.r2)?;
        validate_templates(&next, &model, &fleet_plan, &fleet, &estimates, &observer)?;
        native141::derive_fleet(&next, &mut fleet_plan.clone())?;
    }
    if mode == "--prepare-next-native141-all-acquisition" {
        native141::enable_all_acquisition(
            &mut next,
            acquisition_spec.context("all-target acquisition handoff required")?,
        )?;
        prefix157::namespaces(&mut next, &mut observer_package, &mut cycle_package)?;
        tool_ok(&next.tools.r2)?;
        validate_templates(&next, &model, &fleet_plan, &fleet, &estimates, &observer)?;
        native141::derive_fleet(&next, &mut fleet_plan.clone())?;
    }
    if mode == "--prepare-next-native141-all-retry" {
        native141::enable_all_retry(
            &mut next,
            acquisition_spec.context("all-target retry handoff required")?,
        )?;
        prefix157::namespaces(&mut next, &mut observer_package, &mut cycle_package)?;
        tool_ok(&next.tools.r2)?;
        validate_templates(&next, &model, &fleet_plan, &fleet, &estimates, &observer)?;
        native141::derive_fleet(&next, &mut fleet_plan.clone())?;
    }
    if mode == "--prepare-next-census141-poh" {
        census141_poh::enable(
            &mut next,
            acquisition_spec.context("census PoH handoff required")?,
        )?;
        prefix157::namespaces(&mut next, &mut observer_package, &mut cycle_package)?;
        tool_ok(&next.tools.r2)?;
        validate_templates(&next, &model, &fleet_plan, &fleet, &estimates, &observer)?;
        census141_poh::derive_fleet(&next, &mut fleet_plan.clone())?;
    }
    if mode == "--prepare-next-publication144" {
        publication144::enable(
            &mut next,
            handoff_spec.context("publisher handoff required")?,
        )?;
        prefix157::namespaces(&mut next, &mut observer_package, &mut cycle_package)?;
        tool_ok(&next.tools.r2)?;
        validate_templates(&next, &model, &fleet_plan, &fleet, &estimates, &observer)?;
        publication144::derive_fleet(&next, &mut fleet_plan.clone())?;
    }
    if mode == "--prepare-next-repair141" {
        repair141_status::enable(
            &mut next,
            handoff_spec.context("repair141 cadence handoff required")?,
        )?;
        prefix157::namespaces(&mut next, &mut observer_package, &mut cycle_package)?;
        validate_observer_config(&next, &effective, &next_config)?;
        repair141_status::derive_fleet(&next, &mut fleet_plan.clone())?;
    }
    if mode == "--prepare-next-original141" {
        original141::enable(
            &mut next,
            &mut next_config,
            handoff_spec.context("original141 handoff required")?,
        )?;
        prefix157::namespaces(&mut next, &mut observer_package, &mut cycle_package)?;
        validate_observer_config(&next, &effective, &next_config)?;
        original141::derive_fleet(&next, &mut fleet_plan.clone())?;
    }
    if mode == "--prepare-next-controller-rebind" {
        ensure!(
            handoff_spec.is_none(),
            "controller recovery consumes only exact sealed host proof"
        );
        controller_rebind::enable(
            &mut next,
            &mut next_config,
            &mut observer_package,
            &mut cycle_package,
        )?;
        let model =
            repair185::effective_model(&next, &repair183::effective_model(&next, &effective)?)?;
        validate_observer_config(&next, &model, &next_config)?;
    }
    if mode == "--prepare-next-upload198" {
        ensure!(
            handoff_spec.is_none(),
            "upload198 is a separate exact migration"
        );
        public198::enable_upload(&mut next)?;
        public198::namespaces(&mut next, &mut observer_package, &mut cycle_package)?;
        public198::derive_fleet(&next, &mut fleet_plan.clone())?;
        tool_ok(&next.tools.r2)?;
    }
    if let Some(spec) = native_spec {
        public198::enable_native(&mut next, spec)?;
        public198::namespaces(&mut next, &mut observer_package, &mut cycle_package)?;
        public198::derive_fleet(&next, &mut fleet_plan.clone())?;
    }
    if let Some(spec) = prefix_spec {
        ensure!(
            !enable_terminal157 && !enable_private144 && !recover_controllers && !pause157,
            "prefix157 migration must be separate"
        );
        if mode == "--prepare-next-assembly144" {
            assembly144::enable(&mut next, &mut next_config, spec)?;
        } else if mode == "--prepare-next-continuation144" {
            continuation144::enable(&mut next, &mut next_config, spec)?;
        } else if mode == "--prepare-next-native144" {
            native144::enable(&mut next, &mut next_config, spec)?;
        } else if mode == "--prepare-next-completed144" {
            completed144::enable(&mut next, spec)?;
        } else if mode == "--prepare-next-prefix144" {
            prefix144::enable(&mut next, spec)?;
        } else {
            prefix157::enable(&mut next, spec)?;
        }
        prefix157::namespaces(&mut next, &mut observer_package, &mut cycle_package)?;
        let current_template = bound_json(&next.fleet_template, true)?;
        let current_fleet = bound_json(&next.previous_fleet, false)?;
        validate_templates(
            &next,
            &model,
            &current_template,
            &current_fleet,
            &estimates,
            &observer,
        )?;
        latest_fleet_unchanged(&next, &current_fleet)?;
        let effective =
            private144::effective_model(&next, &delivery198::effective_model(&next, &model)?)?;
        validate_observer_config(&next, &effective, &next_config)?;
        tool_ok(&next.tools.r2)?;
    }
    if pause157 {
        ensure!(
            !recover_controllers
                && !enable_terminal157
                && !enable_private144
                && delivery_spec.is_none(),
            "157pause requires separate transition"
        );
        runtime157::enable(
            &mut next,
            &mut next_config,
            &mut observer_package,
            &mut cycle_package,
            &model,
        )?;
        let effective = private144::effective_model(&next, &model)?;
        validate_templates(&next, &model, &fleet_plan, &fleet, &estimates, &observer)?;
        validate_observer_config(&next, &effective, &next_config)?;
        tool_ok(&next.tools.r2)?;
    }
    if recover_controllers {
        ensure!(
            !enable_terminal157 && !enable_private144 && delivery_spec.is_none(),
            "package recovery is a separate qualified transition"
        );
        controller_recovery::enable(
            &mut next,
            &mut next_config,
            &mut observer_package,
            &mut cycle_package,
            &model,
        )?;
        let effective =
            private144::effective_model(&next, &controller_recovery::model(&next, &model)?)?;
        validate_templates(&next, &model, &fleet_plan, &fleet, &estimates, &observer)?;
        validate_observer_config(&next, &effective, &next_config)?;
        tool_ok(&next.tools.r2)?;
    }
    if enable_private144 {
        ensure!(
            !enable_terminal157 && delivery_spec.is_none(),
            "separate diagnostic migration required"
        );
        private144::enable(&mut next, &mut next_config, &model)?;
        let effective =
            private144::effective_model(&next, &delivery198::effective_model(&next, &model)?)?;
        validate_observer_config(&next, &effective, &next_config)?;
    }
    if let Some(spec) = delivery_spec {
        ensure!(
            !enable_terminal157,
            "cannot combine separate handoff preparations"
        );
        delivery198::retime(&mut next, &mut next_config, spec)?;
        delivery198::enable(&mut next, &mut next_config, &model, &completion, spec)?;
        delivery198::namespaces(&mut next, &mut observer_package, &mut cycle_package)?;
        let effective =
            private144::effective_model(&next, &delivery198::effective_model(&next, &model)?)?;
        validate_templates(&next, &model, &fleet_plan, &fleet, &estimates, &observer)?;
        validate_observer_config(&next, &effective, &next_config)?;
        tool_ok(&next.tools.r2)?;
        delivery198::derive_fleet(&next, &mut fleet_plan.clone())?;
    }
    if mode == "--prepare-next-delivery160" {
        ensure!(
            handoff_spec.is_none(),
            "160 transition consumes exact sealed event proof only"
        );
        delivery160::enable(&mut next, &mut next_config, &model, &completion)?;
        prefix157::namespaces(&mut next, &mut observer_package, &mut cycle_package)?;
        tool_ok(&next.tools.r2)?;
        validate_templates(&next, &model, &fleet_plan, &fleet, &estimates, &observer)?;
        let effective = private144::effective_model(
            &next,
            &delivery160::effective_model(&next, &delivery198::effective_model(&next, &model)?)?,
        )?;
        validate_observer_config(&next, &effective, &next_config)?;
        delivery160::derive_fleet(&next, &mut fleet_plan.clone())?;
    }
    let host101 = is_101(p)?;
    let root = Path::new(if host101 { ROOT_101 } else { ROOT });
    let stage = root.join(format!(
        "{}-{}",
        stamp(&next.sample_target_utc),
        if host101 { generation_101(&next) } else { "v1" }
    ));
    private_dir(root)?;
    absent(&stage)?;
    fs::DirBuilder::new().mode(0o700).create(&stage)?;
    File::open(root)?.sync_all()?;
    let observer_source = write_new(&stage.join("observer.json"), &next_config)?;
    ensure!(
        observer_source.sha256 == next.observer_config.sha256,
        "observer serialization changed"
    );
    let cycle_source = write_new(
        &stage.join("cycle-plan.json"),
        &serde_json::to_value(&next)?,
    )?;
    let observer_seal = write_new(
        &stage.join("observer-seal-plan.json"),
        &seal_plan(
            &stage,
            "observer.json",
            &observer_package,
            "observer.json",
            &observer_source.sha256,
        ),
    )?;
    let cycle_seal = write_new(
        &stage.join("cycle-seal-plan.json"),
        &seal_plan(
            &stage,
            "cycle-plan.json",
            &cycle_package,
            "cycle-plan.json",
            &cycle_source.sha256,
        ),
    )?;
    let receipt = json!({"schema":if host101 { "jetstreamer-horizon-routine-next-preparation-101-200-v2" } else { "jetstreamer-horizon-routine-next-preparation-v1" },"self_sha256":self_sha,
        "current_plan":pb,"completion":{"path":completion_path,"sha256":sha(&bytes)},
        "next_sample_target_utc":next.sample_target_utc,"observer_source":observer_source,"cycle_source":cycle_source,
        "observer_seal_plan":observer_seal,"cycle_seal_plan":cycle_seal,
        "observer_destination":observer_package,"cycle_destination":cycle_package,
        "new_resource_samples":0,"service_state_changed":false,"remote_mutations":false,"r2_mutations":false,
        "replay_launch_authorized":false,"deployment_authorized":false,"preflight_required":true});
    let output = write_new(&stage.join("preparation.json"), &receipt)?;
    println!("{}", output.path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Plan, Bound, Value, Value) {
        let b = || json!({"path":"/evidence","sha256":"a".repeat(64)});
        let p:Plan=serde_json::from_value(json!({"schema":PLAN_SCHEMA,"sample_target_utc":"2026-10-21T07:29:36Z",
            "endpoint_sha256":"a".repeat(64),"bucket":BUCKET,
            "observer":format!("{OBSERVERS}/horizon-live-resource-sample-20261021T072936Z-v204.json"),
            "observer_config":{"path":"/var/lib/jetstreamer/horizon-next-observer-20261021T072936Z-v204/observer.json","sha256":"a".repeat(64)},
            "previous_observer":b(),"model_template":b(),"fleet_template":b(),"previous_estimates":b(),"previous_fleet":b(),
            "tools":{"sealer":b(),"estimator":b(),"r2":b()},"expected_epochs":[216],
            "cycle_directory":"/var/lib/jetstreamer/horizon-routine-cycles-v1/20261021T072936Z-v1",
            "cycle_unit":"horizon-routine-cycle-20261021T072936Z-v1.service",
            "estimate_output":"/estimates/horizon-r2-status-estimates-20261021T072936Z-cohort-gated-v5.json",
            "fleet_output":"/var/lib/jetstreamer/horizon-campaign-fleet/20261021T072936Z-rust-v1/fleet-ledger.json",
            "additional_gate_evidence":{"225":[b()]}})).unwrap();
        let pb = Bound {
            path: "/current-plan.json".into(),
            sha256: "b".repeat(64),
        };
        let c = json!({"schema":"jetstreamer-horizon-routine-cycle-completion-v1","sampled_at_utc":p.sample_target_utc,
            "plan":pb,"observer":{"path":p.observer,"sha256":"c".repeat(64)},
            "model":{"path":p.cycle_directory.join("sealed/eta-model.json"),"sha256":"d".repeat(64)},
            "fleet_plan":{"path":p.cycle_directory.join("sealed/fleet-plan.json"),"sha256":"e".repeat(64)},
            "fleet":{"path":p.fleet_output,"sha256":"f".repeat(64)},
            "estimates":{"path":p.estimate_output,"sha256":"a".repeat(64)},
            "archive_mutations":false,"sidecar_mutations":false,"replay_launch_authorized":false,"deletions":false,
            "new_resource_samples":0,"inventory":{"anomalies":0},"self_sha256":"a".repeat(64),"invocation_id":"b".repeat(32),"status_publications":[b()]});
        let config = json!({"schema":"jetstreamer-horizon-live-resource-sample-config-v2","not_before_utc":p.sample_target_utc,
            "minimum_interval_seconds":1800,"output":p.observer,"previous_sample":"/old-sample",
            "replays":[{"owner":"unchanged"}],"diagnostic_replays":[{"owner":"also-unchanged"}]});
        (p, pb, c, config)
    }

    fn fixture_101() -> (Plan, Bound, Value, Value) {
        let (mut p, pb, mut c, mut config) = fixture();
        p.schema = PLAN_SCHEMA_101.into();
        p.sample_target_utc = "2026-10-21T08:38:00Z".into();
        p.scope_101_200 = Some(Scope101200 {
            private144_observer: false,
            diagnostic_ranges: vec![DiagnosticClaim {
                range: "144".into(),
                controller_unit: "horizon-qualify-epoch144-loader-focus-20261016-v1.service".into(),
                producer_unit: "horizon-qualify-epoch144-loader-focus-20261016-v1.service".into(),
                expected_controller_invocation_id: "1".repeat(32),
                expected_producer_invocation_id: "1".repeat(32),
            }],
            additional_tracked_units: vec!["horizon-old-observational-helper.service".into()],
        });
        p.expected_epochs = vec![198];
        p.observer = Path::new(OBSERVERS_101).join("sample-20261021T083800Z.json");
        p.observer_config.path = PathBuf::from(
            "/usr/local/lib/jetstreamer/horizon-control-seven-0838-20261021-v1/observer-config.json",
        );
        p.cycle_directory = PathBuf::from(
            "/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2/20261021T083800Z-v2",
        );
        p.cycle_unit = cycle_unit(&p).unwrap();
        p.estimate_output =
            "/estimates/horizon-r2-status-estimates-20261021T083800Z-cohort-gated-v5.json".into();
        p.fleet_output = Path::new(FLEET_ROOT_101).join("fleet-20261021T083800Z.json");
        p.additional_gate_evidence = BTreeMap::from([("140".into(), vec![pb.clone()])]);
        c["sampled_at_utc"] = json!(p.sample_target_utc);
        c["observer"]["path"] = json!(p.observer);
        c["model"]["path"] = json!(p.cycle_directory.join("sealed/eta-model.json"));
        c["fleet_plan"]["path"] = json!(p.cycle_directory.join("sealed/fleet-plan.json"));
        c["fleet"]["path"] = json!(p.fleet_output);
        c["estimates"]["path"] = json!(p.estimate_output);
        config["not_before_utc"] = json!(p.sample_target_utc);
        config["output"] = json!(p.observer);
        (p, pb, c, config)
    }

    #[test]
    #[ignore = "requires root and exact accepted14:08/failed14:38/rebound guard host evidence; no sampling or writes"]
    fn host_package_recovery_preserves_genuine_history_and_producer_clocks() {
        let pb = Bound {
            path: "/var/lib/jetstreamer/horizon-routine-plan-101-200-20261021T140800Z-v2/cycle-plan.json".into(),
            sha256: "ea3f3e30094deabefbcd8a95385f95b34cb57f3c580c16caf8a6a87baecc62e4".into(),
        };
        let p: Plan = serde_json::from_slice(&bound_bytes(&pb, true).unwrap()).unwrap();
        let c: Value = serde_json::from_slice(
            &read_checked(&p.cycle_directory.join("completion.json"), LIMIT, 0, false).unwrap(),
        )
        .unwrap();
        let config = bound_json(&p.observer_config, true).unwrap();
        let (mut next, mut config, mut observer_package, mut cycle_package) =
            derive_next(&p, &pb, &c, &config).unwrap();
        let model = bound_json(&next.model_template, true).unwrap();
        let old_model = model.clone();
        let old_previous = serde_json::to_value(&next.previous_observer).unwrap();
        controller_recovery::enable(
            &mut next,
            &mut config,
            &mut observer_package,
            &mut cycle_package,
            &model,
        )
        .unwrap();
        let effective =
            private144::effective_model(&next, &controller_recovery::model(&next, &model).unwrap())
                .unwrap();
        let fleet = bound_json(&next.fleet_template, true).unwrap();
        let previous = bound_json(&next.previous_fleet, false).unwrap();
        let estimates = bound_json(&next.previous_estimates, false).unwrap();
        let old_observer = bound_json(&next.previous_observer, false).unwrap();
        validate_templates(&next, &model, &fleet, &previous, &estimates, &old_observer).unwrap();
        validate_observer_config(&next, &effective, &config).unwrap();
        assert_eq!(model, old_model);
        assert_eq!(
            serde_json::to_value(&next.previous_observer).unwrap(),
            old_previous
        );
        assert_eq!(next.sample_target_utc, "2026-10-21T15:08:00Z");
        assert!(next.epoch157_terminal_handoff.is_some());
        assert_eq!(controller_recovery::interval(&next).unwrap(), 3600);
        for (old, new) in model["ranges"]
            .as_array()
            .unwrap()
            .iter()
            .zip(effective["ranges"].as_array().unwrap())
        {
            assert_eq!(
                old["expected_producer_invocation_id"],
                new["expected_producer_invocation_id"]
            );
            assert_eq!(old["terminal_slot"], new["terminal_slot"]);
            assert_eq!(
                old["epoch_downstream_allowance_seconds"],
                new["epoch_downstream_allowance_seconds"]
            );
        }
    }

    #[test]
    fn successor_keeps_private144_mode_and_qualified_writer() {
        let (mut p, pb, c, config) = fixture_101();
        let scope = p.scope_101_200.as_mut().unwrap();
        scope.private144_observer = true;
        scope.diagnostic_ranges[0].expected_controller_invocation_id =
            private144::INVOCATION.into();
        scope.diagnostic_ranges[0].expected_producer_invocation_id = private144::INVOCATION.into();
        p.tools.r2 = Bound {
            path: private144::WRITER.into(),
            sha256: private144::WRITER_SHA.into(),
        };
        let (next, _, _, _) = derive_next(&p, &pb, &c, &config).unwrap();
        assert!(next.scope_101_200.unwrap().private144_observer);
        assert_eq!(next.tools.r2.path, Path::new(private144::WRITER));
        assert_eq!(next.tools.r2.sha256, private144::WRITER_SHA);
    }

    #[test]
    fn delayed_successor_uses_actual_time_without_repeating_recovery() {
        let (mut p, pb, mut c, config) = fixture_101();
        p.delayed_schedule_utc = Some(p.sample_target_utc.clone());
        p.sample_target_utc = "2026-10-21T08:39:58Z".into();
        c["sampled_at_utc"] = json!(p.sample_target_utc);
        let (next, cfg, _, _) = derive_next(&p, &pb, &c, &config).unwrap();
        assert_eq!(next.sample_target_utc, "2026-10-21T09:09:58Z");
        assert_eq!(cfg["not_before_utc"], next.sample_target_utc);
        assert!(next.delayed_schedule_utc.is_none());
        assert_eq!(cfg["previous_sample"], p.observer.to_str().unwrap());
    }

    #[test]
    fn successor_101_preserves_private_diagnostics_and_exact_u64_without_promoting_them() {
        let (p, pb, c, mut config) = fixture_101();
        config["replays"][0]["append_log"] = json!({"path":"/append/log",
            "device":u64::MAX-1,"inode":u64::MAX});
        let diagnostics =
            serde_json::to_value(&p.scope_101_200.as_ref().unwrap().diagnostic_ranges).unwrap();
        let (next, cfg, op, cp) = derive_next(&p, &pb, &c, &config).unwrap();
        assert_eq!(next.sample_target_utc, "2026-10-21T09:08:00Z");
        assert_eq!(next.schema, PLAN_SCHEMA_101);
        assert_eq!(next.expected_epochs, [198]);
        assert_eq!(
            next.observer,
            Path::new(OBSERVERS_101).join("sample-20261021T090800Z.json")
        );
        assert_eq!(
            next.fleet_output,
            Path::new(FLEET_ROOT_101).join("fleet-20261021T090800Z.json")
        );
        assert_eq!(
            next.cycle_directory,
            Path::new("/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2/20261021T090800Z-v2")
        );
        assert_eq!(
            next.cycle_unit,
            "horizon-routine-cycle-101-200-20261021T090800Z-v2.service"
        );
        assert_eq!(
            op,
            Path::new("/var/lib/jetstreamer/horizon-next-observer-101-200-20261021T090800Z-v2")
        );
        assert_eq!(
            cp,
            Path::new("/var/lib/jetstreamer/horizon-routine-plan-101-200-20261021T090800Z-v2")
        );
        let scope = next.scope_101_200.as_ref().unwrap();
        assert_eq!(
            serde_json::to_value(&scope.diagnostic_ranges).unwrap(),
            diagnostics
        );
        assert_eq!(
            scope.additional_tracked_units.as_slice(),
            std::slice::from_ref(&next.cycle_unit)
        );
        assert_eq!(cfg["replays"], config["replays"]);
        assert_eq!(
            cfg["replays"][0]["append_log"]["inode"].as_u64(),
            Some(u64::MAX)
        );
        let reread: Value = serde_json::from_slice(&encoded(&cfg).unwrap()).unwrap();
        assert_eq!(
            reread["replays"][0]["append_log"]["device"].as_u64(),
            Some(u64::MAX - 1)
        );
        assert_eq!(
            serde_json::to_value(&next.additional_gate_evidence).unwrap(),
            serde_json::to_value(&p.additional_gate_evidence).unwrap()
        );
        assert_eq!(
            next.fleet_template.path.to_str(),
            c["fleet_plan"]["path"].as_str()
        );
    }

    #[test]
    fn successor_101_requires_prior_observational_additions_in_accepted_template() {
        let (p, _, _, _) = fixture_101();
        assert!(validate_folded_scope(&p, &json!({"tracked_units":[]})).is_err());
        validate_folded_scope(
            &p,
            &json!({"tracked_units":["horizon-old-observational-helper.service"]}),
        )
        .unwrap();
    }

    #[test]
    fn successor_101_rejects_foreign_namespaces_and_profile_scope_mismatch() {
        let (mut p, pb, mut c, mut config) = fixture_101();
        p.observer_config.path =
            "/var/lib/jetstreamer/horizon-next-observer-20261021T083800Z-v204/observer.json".into();
        assert!(
            derive_next(&p, &pb, &c, &config)
                .unwrap_err()
                .to_string()
                .contains("101observer/config")
        );
        let (mut p, _, _, _) = fixture_101();
        p.observer =
            Path::new(OBSERVERS).join("horizon-live-resource-sample-20261021T083800Z-v204.json");
        c["observer"]["path"] = json!(p.observer);
        config["output"] = json!(p.observer);
        assert!(
            derive_next(&p, &pb, &c, &config)
                .unwrap_err()
                .to_string()
                .contains("101observer/config")
        );
        let (mut p, _, c, config) = fixture_101();
        p.scope_101_200 = None;
        assert!(derive_next(&p, &pb, &c, &config).is_err());
    }

    #[test]
    fn successor_101_accepts_its_prepared_namespace_but_never_out_of_band_reason() {
        let (mut p, pb, c, config) = fixture_101();
        p.observer_config.path =
            "/var/lib/jetstreamer/horizon-next-observer-101-200-20261021T083800Z-v2/observer.json"
                .into();
        derive_next(&p, &pb, &c, &config).unwrap();
        let mut wrong = config;
        wrong["observation_reason"] = json!("user-requested-status");
        assert!(derive_next(&p, &pb, &c, &wrong).is_err());
    }
    #[test]
    fn successor_is_exact_thirty_minute_immutable_binding_without_changing_gates() {
        let (p, pb, c, config) = fixture();
        let (next, cfg, op, cp) = derive_next(&p, &pb, &c, &config).unwrap();
        assert_eq!(next.sample_target_utc, "2026-10-21T07:59:36Z");
        assert_eq!(next.previous_observer.sha256, "c".repeat(64));
        assert_eq!(
            serde_json::to_value(next.additional_gate_evidence).unwrap(),
            serde_json::to_value(p.additional_gate_evidence).unwrap()
        );
        assert_eq!(cfg["replays"], config["replays"]);
        assert_eq!(cfg["diagnostic_replays"], config["diagnostic_replays"]);
        assert_eq!(next.observer_config.sha256, sha(&encoded(&cfg).unwrap()));
        assert_eq!(
            op,
            Path::new("/var/lib/jetstreamer/horizon-next-observer-20261021T075936Z-v205")
        );
        assert_eq!(
            cp,
            Path::new("/var/lib/jetstreamer/horizon-routine-plan-20261021T075936Z-v1")
        );
        assert_eq!(
            next.cycle_unit,
            "horizon-routine-cycle-20261021T075936Z-v1.service"
        );
    }
    #[test]
    fn completion_is_not_a_plan_status_countdown_or_foreign_partial_owner() {
        let (p, pb, c, config) = fixture();
        for (field, value) in [
            ("schema", json!("plan")),
            ("sampled_at_utc", json!("2026-10-21T07:59:36Z")),
            ("archive_mutations", json!(true)),
            ("new_resource_samples", json!(1)),
            ("status_publications", json!([])),
            ("invocation_id", json!("")),
        ] {
            let mut wrong = c.clone();
            wrong[field] = value;
            assert!(derive_next(&p, &pb, &wrong, &config).is_err(), "{field}");
        }
        let mut wrong = c.clone();
        wrong["plan"]["sha256"] = json!("f".repeat(64));
        assert!(derive_next(&p, &pb, &wrong, &config).is_err());
        let mut wrong = c;
        wrong["observer"]["path"] = json!("/foreign");
        assert!(derive_next(&p, &pb, &wrong, &config).is_err());
    }
    #[test]
    fn successor_never_borrows_a_different_generation_or_out_of_band_sample() {
        let (mut p, pb, c, config) = fixture();
        for (field, value) in [
            ("observation_reason", json!("user-requested-status")),
            ("minimum_interval_seconds", json!(1799)),
            ("epoch203_ram_auxiliary", json!({"unexpected":"handoff"})),
        ] {
            let mut wrong = config.clone();
            wrong[field] = value;
            assert!(derive_next(&p, &pb, &c, &wrong).is_err(), "{field}");
        }
        p.observer_config.path =
            "/var/lib/jetstreamer/horizon-next-observer-20261021T072936Z-v203/observer.json".into();
        assert!(derive_next(&p, &pb, &c, &config).is_err());
    }
    #[test]
    fn utc_successor_crosses_day_and_month_without_shortening_cadence() {
        let start = utc_seconds("2026-10-31T23:59:36Z").unwrap();
        assert_eq!(utc_string(start + 1800).unwrap(), "2026-11-01T00:29:36Z");
    }

    #[test]
    fn accepted_status_keeps_bucket_owner_clock_and_exact_positive_estimate() {
        let (p, _, _, _) = fixture();
        let observer = Bound {
            path: "/sample".into(),
            sha256: "d".repeat(64),
        };
        let e = json!({"epoch":216,"expected_controller_invocation_id":"a".repeat(32),
            "expected_producer_invocation_id":"b".repeat(32),"elapsed_execution_millis":123,"estimated_remaining_millis":456});
        let s = json!({"schema":"jetstreamer-horizon-r2-status-authenticated-publication-receipt-v1",
            "bucket":p.bucket,"epoch":216,"authenticated_readback":true,
            "controller_invocation_id":e["expected_controller_invocation_id"],"producer_invocation_id":e["expected_producer_invocation_id"],
            "observer_receipt":observer.path,"observer_receipt_sha256":observer.sha256,
            "status":{"epoch":216,"sampled_at_utc":p.sample_target_utc,"phase":"replay",
                "elapsed_execution_millis":123,"estimated_remaining_millis":456}});
        validate_status(&s, &p, &observer, &e).unwrap();
        for field in [
            "bucket",
            "controller_invocation_id",
            "producer_invocation_id",
            "observer_receipt_sha256",
            "authenticated_readback",
        ] {
            let mut wrong = s.clone();
            wrong[field] = json!("changed");
            assert!(
                validate_status(&wrong, &p, &observer, &e).is_err(),
                "{field}"
            );
        }
        for field in [
            "epoch",
            "sampled_at_utc",
            "phase",
            "elapsed_execution_millis",
            "estimated_remaining_millis",
        ] {
            let mut wrong = s.clone();
            wrong["status"][field] = json!("changed");
            assert!(
                validate_status(&wrong, &p, &observer, &e).is_err(),
                "{field}"
            );
        }
    }
}
