//! Exact stopped retry4 AccountsDb scope. Preserve the target inode and all
//! source, snapshot metadata, archive, owner, and completion-watcher evidence.
use super::retirement_evidence::*;
pub(super) use super::retirement_evidence::{leases, verify_campaign_lock, verify_image};
use super::*;
use std::collections::BTreeSet;

pub(super) const BASE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch168-retry4-closed-accounts-20261126-v1";
pub(super) const PROFILE: &[u8] = include_bytes!("profiles168_retry4.json");
pub(super) const CHECK_SCHEMA: &str = "horizon168-retry4-stopped-accounts-check-v1";
pub(super) const COMPLETE_SCHEMA: &str = "horizon168-retry4-stopped-accounts-complete-v1";
const IID: &str = "913443d7f9f44d7e9d3e0eec420acfab";
const PID: u64 = 916123;
const START_TICKS: u64 = 374640772;
const UNIT: &str = "horizon-qualify-168-full-metered-cold-v4-20261123.service";
const GUARD: &str = "horizon-guard-168-full-metered-cold-v4-20261123.service";
const TIMER: &str = "horizon-guard-168-full-metered-cold-v4-20261123.timer";
const PATH_UNIT: &str = "horizon-168-cold-retry4-committed.path";
const READ_UNIT: &str = "horizon-168-cold-retry4-committed.service";
const INODE: u64 = 105381896;
const CAP: u64 = 288 << 30;
const BOOT_SLOT: u64 = 72575704;
const BOOT_SHA: &str = "f1a8902dcb00eb59266a2f688d05f7d406af1999eb78956bfd0c46056571ad04";

fn validate_stop(
    e: &Value,
    recipe: &Value,
    admission: &Value,
    worker: &Value,
    intent: &Value,
    stop: &Value,
    plan: &Value,
) -> Result<()> {
    let record = &intent["sample"];
    let process = &record["producer"];
    let terminal = &stop["terminal"];
    let cgroup = format!("/system.slice/{UNIT}");
    for row in [admission, worker, intent, stop, record] {
        ensure!(
            row["producer_invocation_id"] == IID,
            "different retry4 invocation"
        );
    }
    for row in [admission, worker] {
        ensure!(
            row["producer_unit"] == UNIT
                && row["producer_pid"] == PID
                && row["start_ticks"] == START_TICKS
                && row["cgroup"] == cgroup,
            "different retry4 native incarnation"
        );
    }
    ensure!(
        worker["admission"] == e["admission"]
            && worker["worker_pid"] == recipe["original_worker_pid"]
            && worker["worker_start_ticks"] == recipe["original_worker_start_ticks"]
            && admission["source"] == recipe["prepared"]
            && admission["intent"] == recipe["start_intent"]
            && admission["actual_guard_plan"] == e["guard_plan"]
            && admission["timer_unit"] == TIMER
            && stop["intent"] == e["stop_intent"]["path"]
            && stop["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
            && intent["schema"] == "jetstreamer-horizon-standalone-stop-intent-v1"
            && plan["unit"] == UNIT
            && plan["invocation_id"] == IID
            && plan["filesystem"] == "/home/sol"
            && plan["maximum_root_physical_bytes"] == CAP
            && [intent, record, stop]
                .iter()
                .all(|row| row["plan_sha256"] == e["guard_plan"]["sha256"])
            && intent["reason"] == "root-physical-budget"
            && record["trip_reason"] == intent["reason"]
            && process["pid"] == PID
            && process["cgroup"] == cgroup
            && process["invocation_id"] == IID
            && record["workers"]
                .as_array()
                .is_some_and(|rows| { rows.len() == 1 && rows[0][0] == worker["worker_pid"] })
            && terminal["active"] == "inactive"
            && terminal["sub"] == "dead"
            && terminal["pid"] == 0
            && terminal["cgroup"] == cgroup
            && terminal["invocation_id"] == IID
            && terminal["kill_mode"] == "control-group"
            && terminal["delegated"] == false
            && terminal["restarts"] == 0
            && terminal["restart_policy"] == "no"
            && stop["scratch_deleted"] == false
            && stop["r2_mutations"] == false
            && stop["remote_mutations"] == false,
        "stopped retry4 journal, protection or drain binding differs"
    );
    Ok(())
}

fn validate_recipe(
    manifest: &Value,
    payload: &Value,
    prepared: &Value,
    namespace: &Value,
    intent: &Value,
) -> Result<()> {
    let scope = &manifest["scope"];
    let p = &scope["preserved"];
    let recipe = &manifest["recipe"];
    let expected_argv = &recipe["regular_node_argv"];
    let env = &payload["environment"];
    let profile_argv = prepared["profile"]["producer_argv"]
        .as_array()
        .context("producer argv")?;
    let expected = expected_argv.as_array().context("regular node argv")?;
    ensure!(
        payload["epoch"] == 168
            && payload["whole_root_cap"] == CAP
            && payload["producer_unit"] == UNIT
            && payload["guard_unit"] == "horizon-guard-168-full-metered-cold-v4-20261123"
            && payload["bootstrap"]["slot"] == BOOT_SLOT
            && payload["root_checkpoint"]["slot"] == 73007829
            && payload["bootstrap_file"]["sha256"] == BOOT_SHA
            && payload["bootstrap_file"]["path"] == p["source_bootstrap"]["path"]
            && payload["retained_terminal_partial"]["path"]
                == p["prior_diagnostic_archive"]["path"]
            && payload["genesis"]["path"] == p["genesis_source"]["path"]
            && payload["indexes"] == scope["indexes"]
            && payload["regular_node_argv"] == *expected_argv
            && profile_argv.ends_with(expected)
            && prepared["payload"] == scope["evidence"]["payload"]
            && prepared["profile"]["producer_unit"] == UNIT
            && namespace["prepared"] == recipe["prepared"]
            && namespace["dropin"] == manifest["subscriber"]["producer_dropin"]
            && namespace["unit"] == UNIT
            && intent["prepared"] == recipe["prepared"]
            && intent["producer_unit"] == UNIT
            && env["JETSTREAMER_CLEAR_ACCOUNTS_ON_START"] == "true"
            && env["JETSTREAMER_LOAD_FROM_DIR"] == "0"
            && env["JETSTREAMER_ROOT_COHORT_RESUME_RUN"].is_null()
            && env["JETSTREAMER_HISTORICAL_WORKER_V1_5_6"]
                == "/run/horizon-full168-cold-v4/jetstreamer-historical-worker-v1-5-6"
            && p["jetstreamer-node"]["sha256"] == prepared["node_sha256"]
            && p["jetstreamer-historical-worker-v1-5-6"]["sha256"] == prepared["worker_sha256"]
            && [
                "jetstreamer-node",
                "jetstreamer-historical-worker-v1-5-6",
                "preflight-168-v4.json"
            ]
            .iter()
            .all(|name| payload["members"][*name] == json!([p[*name]["path"], p[*name]["sha256"]])),
        "sealed retry4 cold recipe changed"
    );
    Ok(())
}

fn verify_watcher_state(state: &BTreeMap<String, String>) -> Result<()> {
    ensure!(
        state["Id"] == PATH_UNIT
            && state["ActiveState"] == "active"
            && state["SubState"] == "waiting"
            && state["Triggers"] == READ_UNIT,
        "retry4 subscriber is no longer waiting on its completion evidence"
    );
    Ok(())
}

fn subscriber(manifest: &Value, target: &Path) -> Result<()> {
    let profile = &manifest["subscriber"];
    let path_text = String::from_utf8(bound_bytes(&profile["path_unit"], 64 << 10)?)?;
    let unit_text = String::from_utf8(bound_bytes(&profile["service_unit"], 64 << 10)?)?;
    let watched = string(profile, "watched_glob")?;
    let directory = Path::new(watched)
        .parent()
        .context("watched receipt directory")?;
    let reader = string(&profile["reader"], "path")?;
    let seal = bound(&profile["seal"])?;
    let _ = bound(&profile["activation"])?;
    ensure!(
        watched.ends_with("/batch-*.json")
            && !directory.starts_with(target)
            && !target.starts_with(directory)
            && path_text
                .lines()
                .any(|line| line == format!("PathExistsGlob={watched}"))
            && path_text
                .lines()
                .any(|line| line == format!("Unit={READ_UNIT}"))
            && unit_text
                .lines()
                .any(|line| line == format!("ExecStart={reader} wait-record"))
            && unit_text
                .lines()
                .any(|line| line == "ProtectHome=read-only")
            && unit_text.lines().any(|line| line == "PrivateNetwork=yes")
            && seal["destination"]
                == Path::new(reader)
                    .parent()
                    .and_then(Path::to_str)
                    .context("reader package")?
            && seal["members"]
                .as_array()
                .is_some_and(|rows| rows.iter().any(|row| row["name"] == "terminal168"
                    && row["sha256"] == profile["reader"]["sha256"])),
        "completion watcher bindings changed"
    );
    bound_bytes(&profile["reader"], 4 << 20)?;
    bound_bytes(&profile["producer_dropin"], 64 << 10)?;
    verify_watcher_state(&unit(PATH_UNIT)?)?;
    closed(READ_UNIT)?;
    match fs::read_dir(directory) {
        Ok(entries) => {
            for entry in entries {
                ensure!(
                    !entry?
                        .file_name()
                        .to_str()
                        .is_some_and(|s| s.starts_with("batch-") && s.ends_with(".json")),
                    "retry4 completion evidence is newly actionable"
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn validate_retention(scope: &Value, target: &Path, report: &Value, prefix: &Value) -> Result<()> {
    let preserved = scope["preserved"].as_object().context("preserved files")?;
    for (name, row) in preserved {
        ensure!(
            !path(row)?.starts_with(target),
            "protected input inside AccountsDb: {name}"
        );
        open_input(row)?;
    }
    for row in scope["ancestors"]
        .as_object()
        .context("protected directories")?
        .values()
    {
        ensure!(
            !path(row)?.starts_with(target),
            "unexpected preserved directory"
        );
        let p = pinned_path(row)?;
        ensure!(p.symlink_metadata()?.is_dir(), "changed ancestor");
    }
    let archive = &preserved["prefix_archive"];
    let receipt_identity = &prefix["identity"];
    let scratch = &scope["ancestors"]["scratch"];
    let cohort = &preserved["cohort_state"];
    let rp = path(&scope["ancestors"]["run-916123-1795399774038214572"])?;
    ensure!(
        prefix["source"] == archive["path"]
            && prefix["source_sha256"] == archive["prior_sha256"]
            && prefix["first_slot"] == 72576000
            && prefix["last_complete_bucket_slot"] == 72998911
            && prefix["buckets"] == 3304
            && archive["identity"]
                == json!([
                    receipt_identity["device"],
                    receipt_identity["inode"],
                    receipt_identity["size"],
                    receipt_identity["mtime_ns"],
                    receipt_identity["ctime_ns"]
                ])
            && report["scratch"] == scratch["path"]
            && report["scratch_inode"] == scratch["identity"][1]
            && report["scratch_device"] == DEVICE
            && report["run_uid"] == UID
            && report["run_directory"] == rp.to_str().context("run path")?
            && report["source_commit"] == scope["evidence"]["producer_node_commit"]
            && report["node_sha256"] == preserved["jetstreamer-node"]["sha256"]
            && report["cohort_state_sha256"] == cohort["sha256"]
            && report["retained_prefix"] == scope["evidence"]["prefix_receipt"]
            && report["original_terminal"] == scope["evidence"]["stop_completion"]
            && report["stopped_payload"] == scope["evidence"]["payload"]
            && report["schema"] == "horizon-epoch168-retry4-cursor-free-scratch-review-v1"
            && report["local_scratch_retirement_authorized"] == false
            && report["resource_credit_bytes"] == 0
            && report["restarts_from_sealed_bootstrap"] == true
            && report["scratch_contains_replay_cursor"] == false
            && report["preserve_partial_archive_and_inputs"] == true
            && digest(cohort)? == cohort["sha256"],
        "retry4 prefix identity or source reconstruction changed"
    );
    bound(&report["node_capability"])?;
    let snapshots = target
        .parent()
        .context("runtime path")?
        .join("unpacked/snapshots");
    let mut names = fs::read_dir(&snapshots)?
        .map(|e| e.map(|v| v.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    names.sort();
    ensure!(
        names == ["72575704", "status_cache"]
            && path(&preserved["snapshot_bank"])? == snapshots.join("72575704/72575704")
            && path(&preserved["snapshot_status_cache"])? == snapshots.join("status_cache"),
        "retry4 native snapshot metadata changed"
    );
    for pair in scope["indexes"].as_array().context("retained indexes")? {
        open_input(&pair["source"])?;
        open_input(&pair["independent_trace_copy"])?;
    }
    Ok(())
}

pub(super) fn gates(p: &Value, manifest: &Value) -> Result<Value> {
    let scope = &manifest["scope"];
    let e = &scope["evidence"];
    let recipe = &manifest["recipe"];
    let target = Path::new(string(p, "target")?);
    let scratch = path(&scope["ancestors"]["scratch"])?;
    let run = path(&scope["ancestors"]["run-916123-1795399774038214572"])?;
    let cold = path(&scope["ancestors"]["cold-retry4-20261123"])?;
    let m = target.symlink_metadata()?;
    ensure!(
        scope["schema"] == "horizon-epoch168-retry4-accounts-retirement-source-scope-draft-v1"
            && scope["resource_credit_bytes"] == 0
            && scope["retirement_authorized"] == false
            && p["iid"] == IID
            && p["inode"] == INODE
            && target == path(&scope["scope"])?
            && target.starts_with(scratch.join(".historical-runtime"))
            && target.file_name().is_some_and(|n| n == "accounts-state")
            && m.is_dir()
            && m.dev() == DEVICE
            && m.ino() == INODE
            && m.uid() == UID
            && m.gid() == GID
            && m.mode() & 0o7777 == 0o700
            && target.canonicalize()? == target,
        "foreign retry4 AccountsDb scope"
    );
    ensure!(
        p["expected_bytes"] == scope["expected_allocated_bytes_from_existing_du"]
            && p["expected_entries"] == scope["expected_ledger_entries_excluding_target"]
            && ["0", "1", "2", "3"]
                .iter()
                .all(|name| p["shards"][*name] == scope["shards"][*name]["identity"][1]),
        "changed retry4 shard plan"
    );
    let worker = bound(&e["first_worker"])?;
    let observer = &worker["observer_row"];
    let log = &scope["preserved"]["producer_log"];
    ensure!(
        worker["worker_sha256"] == scope["preserved"]["bound_worker"]["expected_sha256"]
            && worker["worker_sha256"]
                == scope["preserved"]["jetstreamer-historical-worker-v1-5-6"]["sha256"]
            && observer["producer_unit"] == UNIT
            && observer["expected_producer_invocation_id"] == IID
            && Path::new(string(observer, "scratch_path")?) == scratch
            && observer["append_log"]["path"] == log["path"]
            && observer["append_log"]["device"] == log["identity"][0]
            && observer["append_log"]["inode"] == log["identity"][1],
        "retry4 worker scratch or append log custody changed"
    );
    validate_stop(
        e,
        recipe,
        &bound(&e["admission"])?,
        &worker,
        &bound(&e["stop_intent"])?,
        &bound(&e["stop_completion"])?,
        &bound(&e["guard_plan"])?,
    )?;
    validate_recipe(
        manifest,
        &bound(&e["payload"])?,
        &bound(&recipe["prepared"])?,
        &bound(&recipe["installed_namespace"])?,
        &bound(&recipe["start_intent"])?,
    )?;
    for name in [UNIT, GUARD, TIMER] {
        closed(name)?;
    }
    validate_retention(
        scope,
        target,
        &bound(&e["closed_source_review"])?,
        &bound(&e["prefix_receipt"])?,
    )?;
    witness_disjoint(target, &e["original_data_witness"])?;
    subscriber(manifest, target)?;
    let subscriber = &manifest["subscriber"];
    let allow = [
        path(&subscriber["path_unit"])?,
        path(&subscriber["producer_dropin"])?,
    ];
    let mut visited = BTreeSet::new();
    for root in [
        "/etc/systemd/system",
        "/run/systemd/transient",
        "/run/systemd/system",
        "/home/sol/.config/systemd/user",
    ] {
        staged_references(Path::new(root), &[target, run, cold], &allow, &mut visited)?;
    }
    Ok(
        json!({"owner":IID, "scope":target, "evidence":e, "recipe":recipe,
             "preserved":scope["preserved"], "subscriber":subscriber}),
    )
}

pub(super) fn check_inventory(
    p: &Value,
    manifest: &Value,
    ledger: &stopped_tree::Ledger,
    allocated: u64,
) -> Result<()> {
    check_appendvecs(p, ledger, allocated, CAP)?;
    ensure!(
        p["expected_bytes"] == allocated && p["expected_entries"] == (ledger.len() - 1) as u64,
        "enrolled retry4 AppendVec set changed"
    );
    let scope = &manifest["scope"];
    let inputs = &scope["preserved"];
    let payload = bound(&scope["evidence"]["payload"])?;
    for name in [
        "source_bootstrap",
        "bound_bootstrap",
        "bound_worker",
        "jetstreamer-node",
        "jetstreamer-historical-worker-v1-5-6",
        "preflight-168-v4.json",
    ] {
        let row = &inputs[name];
        let wanted = row["sha256"]
            .as_str()
            .or(row["expected_sha256"].as_str())
            .context("input digest")?;
        ensure!(
            digest(row)? == wanted,
            "retained input hash changed: {name}"
        );
    }
    ensure!(
        digest(&inputs["genesis_source"])? == payload["genesis"]["sha256"],
        "genesis changed"
    );
    let indexes = scope["indexes"].as_array().context("compact indexes")?;
    ensure!(indexes.len() == 3, "missing retry4 index pairs");
    for row in indexes {
        ensure!(
            digest(&row["source"])? == digest(&row["independent_trace_copy"])?,
            "original and independent indexes disagree"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn fixture() -> (Value, Value) {
        (
            serde_json::from_slice(PROFILE).unwrap(),
            serde_json::from_slice(include_bytes!("fixtures/retry4_native.json")).unwrap(),
        )
    }

    fn check_stop(manifest: &Value, source: &Value) -> Result<()> {
        validate_stop(
            &manifest["scope"]["evidence"],
            &manifest["recipe"],
            &source["admission"],
            &source["worker"],
            &source["intent"],
            &source["stop"],
            &source["plan"],
        )
    }

    fn check_recipe(manifest: &Value, source: &Value) -> Result<()> {
        validate_recipe(
            manifest,
            &source["payload"],
            &source["prepared"],
            &source["namespace"],
            &source["start"],
        )
    }

    #[test]
    fn requires_the_exact_stop_and_a_drained_owner() {
        let (manifest, source) = fixture();
        check_stop(&manifest, &source).unwrap();
        for (row, key, value) in [
            ("intent", "producer_invocation_id", json!("foreign")),
            ("worker", "worker_start_ticks", json!(0)),
            ("stop", "plan_sha256", json!("foreign")),
            ("stop", "scratch_deleted", json!(true)),
            ("plan", "maximum_root_physical_bytes", json!(512u64 << 30)),
        ] {
            let mut changed = source.clone();
            changed[row][key] = value;
            assert!(
                check_stop(&manifest, &changed).is_err(),
                "accepted {row}.{key}"
            );
        }
        let mut changed = source;
        changed["stop"]["terminal"]["pid"] = json!(PID);
        assert!(check_stop(&manifest, &changed).is_err());
    }

    #[test]
    fn requires_the_bound_cold_recipe() {
        let (manifest, source) = fixture();
        check_recipe(&manifest, &source).unwrap();
        for (key, value) in [
            ("JETSTREAMER_CLEAR_ACCOUNTS_ON_START", json!("false")),
            ("JETSTREAMER_LOAD_FROM_DIR", json!("1")),
            ("JETSTREAMER_ROOT_COHORT_RESUME_RUN", json!("/foreign")),
        ] {
            let mut changed = source.clone();
            changed["payload"]["environment"][key] = value;
            assert!(check_recipe(&manifest, &changed).is_err(), "accepted {key}");
        }
        let mut changed = source;
        changed["payload"]["regular_node_argv"][3] = json!("--no-verify");
        assert!(check_recipe(&manifest, &changed).is_err());
    }

    #[test]
    fn ancestor_allowance_cannot_hide_a_staged_scope_consumer() {
        let temporary = tempfile::tempdir().unwrap();
        let scan_root = temporary.path();
        let approved_unit = scan_root.join("approved.path");
        let foreign = scan_root.join("foreign.service");
        let cold = Path::new("/example/closed");
        let run = cold.join("run-123");
        let target = run.join("scratch/accounts-state");
        let scan = || {
            staged_references(
                scan_root,
                &[&target, &run, cold],
                &[&approved_unit],
                &mut BTreeSet::new(),
            )
        };
        fs::write(
            &approved_unit,
            "PathExists=/example/closed/evidence/batch.json",
        )
        .unwrap();
        fs::write(&foreign, "PathExists=/example/closed-sibling/evidence").unwrap();
        scan().unwrap();
        fs::write(
            &approved_unit,
            format!("PathExists={}/0/1.2", target.display()),
        )
        .unwrap();
        assert!(scan().is_err());
        fs::write(
            &approved_unit,
            "PathExists=/example/closed/evidence/batch.json",
        )
        .unwrap();
        fs::write(&foreign, format!("ReadOnlyPaths={}", run.display())).unwrap();
        assert!(scan().is_err());
    }

    #[test]
    fn rejects_replaced_preserved_file_and_path_alias() {
        let tmp = tempfile::tempdir().unwrap();
        let original = tmp.path().join("archive.jet");
        let alias = tmp.path().join("alias.jet");
        fs::write(&original, [0; 5]).unwrap();
        let row =
            json!({"path":original, "identity":identity(&original.metadata().unwrap()), "links":1});
        open_input(&row).unwrap();
        symlink(&original, &alias).unwrap();
        let mut elsewhere = row.clone();
        elsewhere["path"] = json!(alias);
        assert!(open_input(&elsewhere).is_err());
        fs::rename(&original, tmp.path().join("moved.jet")).unwrap();
        fs::write(&original, [0; 5]).unwrap();
        assert!(open_input(&row).is_err());
    }
}
