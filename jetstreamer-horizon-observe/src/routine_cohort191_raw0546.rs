//! Exact bridge from the real successful 05:16 provisional inventory to the
//! already recorded 05:46 resource sample. No synthetic final 05:16 receipt.
use super::*;
const ROOT: &str = "/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2/20261024T051600Z-memory152-rebind-guard-stopped185-import-pending191-repair141-v2";
const LEDGER_SHA: &str = "264ff27d8c2f6662d9ddab228ec2a7c97ae908a3b76cd3b55e45c354d5be21e9";
const RAW_SHA: &str = "ab43f79a41d4b252fdc5c6850c89315c0d95324c88de0c1274f821b3473633bc";
const CONFIG: &str =
    "/usr/local/lib/jetstreamer/horizon-observer-contingency-0546-20261024-v1/observer.json";
const CONFIG_SHA: &str = "86b89cbfa2408f21867cc9e2d169f3e911a50c7c690ac4a32d800d9fe3f47750";
fn file(path: PathBuf, immutable: bool) -> Result<Bound> {
    let bytes = read_checked(&path, LIMIT, 0, immutable)?;
    Ok(Bound {
        path,
        sha256: sha(&bytes),
    })
}
fn fixed(name: &str, digest: &str) -> Bound {
    Bound {
        path: Path::new(ROOT).join(name),
        sha256: digest.into(),
    }
}
pub(super) fn candidate(p: &Plan) -> bool {
    p.cohort191_raw0546.is_some()
        && p.sample_target_utc == "2026-10-24T05:46:00Z"
        && p.previous_fleet.path == Path::new(ROOT).join("public198-provisional-fleet.json")
}
fn child_success(b: &Bound) -> Result<Value> {
    let v = bound_json(b, false)?;
    ensure!(
        v["schema"] == "jetstreamer-horizon-routine-child-result-v1"
            && v["success"] == true
            && v["exit_code"] == 0
            && v["signal"].is_null(),
        "0516 retained child did not succeed"
    );
    Ok(v)
}
fn history() -> Result<Value> {
    let original = fixed(
        "intent.json",
        &file(Path::new(ROOT).join("intent.json"), false)?.sha256,
    );
    let intent = bound_json(&original, false)?;
    ensure!(
        intent["plan"]["sha256"]
            == "61d0de19d0e401d692565dcb32edc414fcacf9d261f23d0702016470faf3504b"
            && intent["invocation_id"] == "4116fa9b09124b56906ede24e25cbc2c"
            && intent["observer"]["sha256"]
                == "0db9966d4b29d38984e8a2d9d0938d61dfb005356195a29e63362ea7ca4e70f1",
        "0516 original identity changed"
    );
    let failure = fixed(
        "child-public198-fleet.json",
        "32a6f4f0fb82198ea13901b583b3716a23822e4f9df83261dbac0e1df600606c",
    );
    let f = bound_json(&failure, false)?;
    ensure!(
        f["success"] == false
            && f["exit_code"] == 1
            && f["stderr"]["text"]
                == "Error: unbound live producer horizon-full-verify-191-native191-20261023-v1.service; rebuild fleet plan and observer census\n",
        "0516 original failure changed"
    );
    let provisional = fixed("public198-provisional-fleet.json", LEDGER_SHA);
    let v = bound_json(&provisional, false)?;
    let read = fixed(
        "cohort191-native-event-recovery-v3/child-provisional-fleet.json",
        "131131e30634fb05aa3ba1133cdc51004ef5dc2960f027c983139446a12ff306",
    );
    let c = child_success(&read)?;
    ensure!(
        c["tool"]["sha256"] == "34f8500ffc64a7a07dd1933a73d0aaf9b5cdd8a1024c845a38e76d14550ad995",
        "0516 provisional reader changed"
    );
    let late = fixed(
        "child-cohort191-status-193.json",
        "5e2c5ca40865ae00bce1885c2b9e4fbecd8b3df4a2e7a48f8886f5a6978d7ddd",
    );
    let rejected = bound_json(&late, false)?;
    ensure!(
        rejected["success"] == false
            && rejected["exit_code"] == 1
            && rejected["stderr"]["text"]
                == "Error: pipeline status requires a fresh coordinated cycle\n",
        "0516 partial event publication failure changed"
    );
    let mut children = vec![];
    let mut statuses = vec![];
    for epoch in [152, 153, 155, 156, 183, 184, 141, 191, 192] {
        let name = if epoch == 141 {
            "child-repair141-publish.json".into()
        } else if epoch >= 191 {
            format!("child-cohort191-status-{epoch}.json")
        } else {
            format!("child-status-{epoch}.json")
        };
        let child = file(Path::new(ROOT).join(name), false)?;
        child_success(&child)?;
        children.push(child);
        let stamp = if epoch >= 191 {
            "20261024054503"
        } else {
            "20261024051600"
        };
        let receipt = file(
            Path::new("/home/sol/.jetstreamer-private/r2-status-receipts")
                .join(format!("epoch-{epoch}.status-{stamp}.json")),
            false,
        )?;
        let r = bound_json(&receipt, false)?;
        ensure!(
            r["epoch"] == epoch
                && r["authenticated_readback"] == true
                && r["status"]["epoch"] == epoch
                && r["observer_receipt_sha256"]
                    == "0db9966d4b29d38984e8a2d9d0938d61dfb005356195a29e63362ea7ca4e70f1",
            "0516 retained status is not authenticated original resource evidence"
        );
        statuses.push(receipt);
    }
    ledger(&v)?;
    Ok(
        json!({"original_intent":original,"original_failure":failure,"provisional_fleet":provisional,"successful_provisional_child":read,"failed_event_status":late,"successful_children":children,"successful_statuses":statuses,"canonical_previous_fleet":v["previous_fleet"],"new_resource_samples":0,"replay_status_republications":0,"fabricated_final_completion":false}),
    )
}
fn ledger(v: &Value) -> Result<()> {
    let t = utc_seconds("2026-10-24T05:16:00Z")?;
    ensure!(
        v["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && v["first_epoch"] == 101
            && v["last_epoch"] == 200
            && v["sampled_at_utc"] == "2026-10-24T05:16:00Z"
            && v["observer_sha256"]
                == "0db9966d4b29d38984e8a2d9d0938d61dfb005356195a29e63362ea7ca4e70f1"
            && v["plan_sha256"]
                == "b047ecdbca34111b0f25ac7b14486f0a9992ad578a958a8dccdccab8cc87ad1d"
            && v["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n >= t && n - t <= 1800)
            && v["inventory"]["anomalies"] == 0
            && v["producer_mutations"] == false
            && v["remote_mutations"] == false
            && v["publication_authorized"] == false,
        "0516 provisional ledger was not genuine, complete and fresh"
    );
    Ok(())
}
pub(super) fn canonical_predecessor(p: &Plan, v: &Value) -> Result<Option<Bound>> {
    if !candidate(p) {
        return Ok(None);
    }
    let proof = bound_json(p.cohort191_raw0546.as_ref().unwrap(), true)?;
    ensure!(
        proof["schema"] == "jetstreamer-exact191-raw0546-bridge-v2"
            && proof["history"] == history()?
            && p.previous_fleet.sha256 == LEDGER_SHA
            && p.previous_observer.sha256
                == "0db9966d4b29d38984e8a2d9d0938d61dfb005356195a29e63362ea7ca4e70f1"
            && p.observer == Path::new(OBSERVERS_101).join("sample-20261024T054600Z.json")
            && p.observer_config.path == Path::new(CONFIG)
            && p.observer_config.sha256 == CONFIG_SHA
            && proof["raw_observer"]["sha256"] == RAW_SHA
            && proof["raw_observer"]["path"].as_str() == p.observer.to_str()
            && p.cohort191_delivery
                .as_ref()
                .is_some_and(|s| !s.native_handoff_event && !s.import_pending),
        "0516 provisional bridge changed its actual sample, profile or history"
    );
    ledger(v)?;
    ensure!(
        v["plan"].as_str() == p.fleet_template.path.to_str()
            && v["plan_sha256"] == p.fleet_template.sha256,
        "0516 provisional template changed"
    );
    let canonical: Bound =
        serde_json::from_value(proof["history"]["canonical_previous_fleet"].clone())?;
    ensure!(
        canonical.path == Path::new(FLEET_ROOT_101).join("fleet-20261024T044600Z.json")
            && canonical.sha256
                == "6ad9e4521a06a038e0a0361b4093677af0f9a73d9ba5e964c3e9bc4a82c42ac1",
        "0516 bridge forks canonical history"
    );
    bound_json(&canonical, false)?;
    Ok(Some(canonical))
}
pub(super) fn prepare(p: &Plan, pb: &Bound) -> Result<()> {
    ensure!(
        pb.sha256 == "61d0de19d0e401d692565dcb32edc414fcacf9d261f23d0702016470faf3504b"
            && p.cycle_directory == Path::new(ROOT),
        "raw0546 bridge requires exact failed0516 plan"
    );
    let h = history()?;
    let raw = Bound {
        path: Path::new(OBSERVERS_101).join("sample-20261024T054600Z.json"),
        sha256: RAW_SHA.into(),
    };
    let observed = bound_json(&raw, false)?;
    let config = Bound {
        path: CONFIG.into(),
        sha256: CONFIG_SHA.into(),
    };
    let cfg = bound_json(&config, true)?;
    ensure!(
        observed["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && observed["recorded_at_utc"] == "2026-10-24T05:46:00Z"
            && cfg["output"].as_str() == raw.path.to_str()
            && cfg["previous_sample"].as_str() == p.observer.to_str()
            && cfg["not_before_utc"] == "2026-10-24T05:46:00Z",
        "raw0546 observer/config differs from actual armed cadence"
    );
    let package = delivery198::seal_values(
        p,
        "cohort191-raw0546-bridge",
        &[(
            "proof.json",
            json!({"schema":"jetstreamer-exact191-raw0546-bridge-v2","history":h,"raw_observer":raw,"observer_config":config,"new_resource_samples":0,"publication_authorized":false,"r2_mutations":false}),
        )],
    )?;
    let proof = file(package.join("proof.json"), true)?;
    let effective = fixed(
        "cohort191-native-event-recovery-plans/sealed/effective-plan.json",
        "7ac48ddaba6074f15455d69dfe7c7c788c044b33328a1c990eb846cfb95f3bbd",
    );
    let mut next: Plan = serde_json::from_value(bound_json(&effective, true)?)?;
    next.sample_target_utc = "2026-10-24T05:46:00Z".into();
    next.delayed_schedule_utc = None;
    next.cohort191_delivery
        .as_mut()
        .context("0546 public profile")?
        .native_handoff_event = false;
    next.cohort191_raw0546 = Some(proof);
    next.previous_observer = serde_json::from_value(
        bound_json(
            &fixed(
                "intent.json",
                &file(Path::new(ROOT).join("intent.json"), false)?.sha256,
            ),
            false,
        )?["observer"]
            .clone(),
    )?;
    next.observer = raw.path;
    next.observer_config = config;
    next.model_template = file(Path::new(ROOT).join("sealed/eta-model.json"), true)?;
    next.previous_estimates = file(p.estimate_output.clone(), false)?;
    next.previous_fleet = fixed("public198-provisional-fleet.json", LEDGER_SHA);
    let ledger = bound_json(&next.previous_fleet, false)?;
    next.fleet_template = Bound {
        path: ledger["plan"]
            .as_str()
            .context("0516 actual provisional plan")?
            .into(),
        sha256: ledger["plan_sha256"]
            .as_str()
            .context("0516 provisional plan hash")?
            .into(),
    };
    next.estimate_output = Path::new("/var/lib/jetstreamer-horizon-status-estimates-20261017-v1")
        .join("horizon-r2-status-estimates-20261024T054600Z-cohort-gated-v5.json");
    next.fleet_output = Path::new(FLEET_ROOT_101).join("fleet-20261024T054600Z.json");
    next.cycle_unit = cycle_unit(&next)?;
    next.cycle_directory = Path::new(ROOT)
        .parent()
        .unwrap()
        .join(format!("20261024T054600Z-{}", generation_101(&next)));
    if let Some(scope) = &mut next.scope_101_200 {
        scope.additional_tracked_units = vec![next.cycle_unit.clone()];
    }
    canonical_predecessor(&next, &ledger)?;
    let stage = Path::new("/var/lib/jetstreamer/horizon-cohort191-raw0546-plan-source-20261024-v1");
    absent(stage)?;
    fs::create_dir(stage)?;
    fs::set_permissions(stage, fs::Permissions::from_mode(0o700))?;
    File::open(stage.parent().unwrap())?.sync_all()?;
    let plan = write_new(
        &stage.join("cycle-plan.json"),
        &serde_json::to_value(&next)?,
    )?;
    println!("{} {}", plan.path.display(), plan.sha256);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bridge_rejects_stale_incomplete_or_mutating_provisional_ledger() {
        let valid = json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","first_epoch":101,"last_epoch":200,"sampled_at_utc":"2026-10-24T05:16:00Z","observer_sha256":"0db9966d4b29d38984e8a2d9d0938d61dfb005356195a29e63362ea7ca4e70f1","plan_sha256":"b047ecdbca34111b0f25ac7b14486f0a9992ad578a958a8dccdccab8cc87ad1d","recorded_unix_seconds":1792820741u64,"inventory":{"anomalies":0},"producer_mutations":false,"remote_mutations":false,"publication_authorized":false});
        ledger(&valid).unwrap();
        for key in [
            "recorded_unix_seconds",
            "inventory",
            "observer_sha256",
            "first_epoch",
            "remote_mutations",
        ] {
            let mut bad = valid.clone();
            bad[key] = json!("foreign");
            assert!(ledger(&bad).is_err());
        }
    }
}
