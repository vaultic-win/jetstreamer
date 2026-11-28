//! Exact pending-controller ownership after the retained 198 parent succeeds.
//! Observational only: no import launch, archive verification or publication.
use super::*;
use serde_json::json;
pub(super) const CONTROLLER: &str =
    "jetstreamer-epoch198-readerfix-singleton-20261019-v1-r2.service";
pub(super) const CONTROLLER_INVOCATION: &str = "02c5ac25b42f47c99776ba5b65b6f4a9";
const PRODUCER_INVOCATION: &str = "e5612ef00a5b4fcab04df2c13a6b35b0";
const SCRIPT: &str = "/usr/local/lib/jetstreamer/controller-epoch198-readerfix-singleton-20261019-v1/adaptive-root-cohort-sweep.py";
const SCRIPT_SHA: &str = "62592209a3fc2b659ea4bfb924bbcf34435b4228c87e56232eb6b962b907023e";
const COMMAND_SHA: &str = "d5c14bf6b156bc75ff4ac0f2d8fe6b3b6b9ba8dc669eda71045a566a9e03b803";
const STATE: &str =
    "/var/lib/jetstreamer-root-sweep-epoch198-readerfix-singleton-20261019-v1/state.json";
const CONFIG: &str = "0929b892242b85f08cbe3d5828b6f4650c81c4730e5fd81f8dfe3e38f096aadd";
const ARCHIVE: &str = "/home/sol/.jetstreamer-private/epoch198-readerfix-singleton-20261019-v1/lane-a/output/epoch-198.jet";
const RECOVERY: &str =
    "/usr/local/lib/jetstreamer/horizon-package-controller-first-fire-20261021-v1/first-fire.json";
const RECOVERY_SHA: &str = "baad8fedb7ae8ab271da2c34850b54f626b907424eeb6c9669947b7d6dce3444";
pub(super) const IMPORTER: &str =
    "jetstreamer-root-import-e198-readerfix-20261019-v1-r2-e198-198-2.service";
const IMPORT_IID: &str = "526647ab03104a1fb8f14303819d6cda";
const SOURCE_RECEIPT: &str = "/home/sol/.jetstreamer-private/epoch198-readerfix-singleton-20261019-v1/lane-a/private/destination-bfa4ff91eb1803c6a2d6240f014cc6508bb805e8bddd619ff64ab57cde1c5ed9/evidence/archive-batches/destination-000000000000fc00-0000000005dd0043/batch-68f31b6384a5d2299937e32ab47a799a993ad8a1c53f1e0b012ef9b8e5b2f047.json";
fn importer_command() -> String {
    format!(
        "{{ path=/usr/local/lib/jetstreamer/deploy-epoch198-readerfix-singleton-20261019-v1/jetstreamer-node ; argv[]=/usr/local/lib/jetstreamer/deploy-epoch198-readerfix-singleton-20261019-v1/jetstreamer-node 198 /home/sol/horizon --verify --recover-staged-cohort-only --cohort-manifest=/usr/local/lib/jetstreamer/deploy-epoch198-readerfix-singleton-20261019-v1/preflight-198-singleton-v4.json --cohort-manifest-fingerprint=sha256:2ac1c3bbb1d030f1bd1e8d7d19770e97d82153e9355d0bc18ca65ad9291b3d3b --source-cohort-receipt={SOURCE_RECEIPT} --publish-through-epoch=198"
    )
}
fn importing(state: &Value, importer: &Value) -> Result<()> {
    let a = &state["assignments"]["lane-a"];
    for (key, value) in [
        ("Id", IMPORTER),
        ("InvocationID", IMPORT_IID),
        ("MainPID", "3182197"),
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("NRestarts", "0"),
        ("Type", "exec"),
    ] {
        ensure!(importer[key] == value, "198 actual importer differs:{key}");
    }
    let command = importer_command();
    ensure!(
        importer["ExecStart"]
            .as_str()
            .and_then(|s| s.split_once(" ; ignore_errors="))
            .map(|(s, _)| s)
            == Some(command.as_str())
            && state["import_owner"] == "lane-a"
            && a["phase"] == "importing"
            && a["import_unit"] == IMPORTER
            && a["receipt"] == SOURCE_RECEIPT
            && a["source_evidence"]["receipt_sha256"]
                == "a1734902c86c333be889f3da731da662308b542fa2c72e2e63da566f941cd226"
            && a["source_evidence"]["members"]
                == json!([{"epoch":198,"archive_sha256":"4a1252a650f7b50f45326a07c0a58090b8c0174cf547099a16eeca45869f7ffb"}]),
        "198 importer command/source/owner differs"
    );
    Ok(())
}

pub(super) fn binding_matches(
    unit: &str,
    invocation: &str,
    origin: &str,
    origin_invocation: &str,
) -> bool {
    unit == CONTROLLER
        && invocation == CONTROLLER_INVOCATION
        && origin == cohort198_finalization::UNIT
        && origin_invocation == PRODUCER_INVOCATION
}

fn controller(current: &Value) -> Result<()> {
    for (key, value) in [
        ("Id", CONTROLLER),
        ("InvocationID", CONTROLLER_INVOCATION),
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("MainPID", "2939002"),
        ("NRestarts", "0"),
    ] {
        ensure!(
            current[key] == value,
            "198pending controller differs: {key}"
        );
    }
    let argv = current["ExecStart"]
        .as_str()
        .and_then(|s| s.split_once(" ; ignore_errors="))
        .map(|(s, _)| s)
        .context("198pending controller argv missing")?;
    ensure!(
        hex_lower(&Sha256::digest(argv.as_bytes())) == COMMAND_SHA,
        "198pending controller is not the exact sealed command"
    );
    Ok(())
}

fn immutable(path: &str, digest: &str) -> Result<()> {
    let path = Path::new(path);
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == 0
            && m.mode() & 0o222 == 0
            && path.canonicalize()? == path,
        "unsafe 198handoff immutable evidence"
    );
    ensure!(
        hex_lower(&Sha256::digest(read_stable_bounded(
            path,
            1 << 20,
            "198handoff immutable"
        )?)) == digest,
        "198handoff immutable digest differs"
    );
    Ok(())
}

pub(super) fn preflight(current: &Value) -> Result<()> {
    controller(current)?;
    immutable(SCRIPT, SCRIPT_SHA)?;
    immutable(RECOVERY, RECOVERY_SHA)?;
    cohort198_finalization::immutable_inputs()?;
    Ok(())
}

#[cfg(test)]
fn pending_state(state: &Value, producer: &Value) -> Result<()> {
    pending_state_with_manager(state, producer, None)
}
fn manager_terminal(record: &Value) -> Result<()> {
    ensure!(
        record["UNIT"] == cohort198_finalization::UNIT
            && record["INVOCATION_ID"] == PRODUCER_INVOCATION
            && record["_PID"] == "1"
            && record["_UID"] == "0"
            && record["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
            && record["MESSAGE"]
                == format!(
                    "{}: Deactivated successfully.",
                    cohort198_finalization::UNIT
                )
            && record["__REALTIME_TIMESTAMP"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|n| n > 0),
        "198 manager terminal proof differs"
    );
    Ok(())
}
#[cfg(test)]
fn pending_state_with_manager(
    state: &Value,
    producer: &Value,
    manager: Option<&Value>,
) -> Result<()> {
    owned_state(state, producer, manager, None)
}
fn owned_state(
    state: &Value,
    producer: &Value,
    manager: Option<&Value>,
    importer: Option<&Value>,
) -> Result<()> {
    let collected = producer["LoadState"] == "not-found";
    if collected {
        manager_terminal(manager.context("198 collected producer needs PID1 proof")?)?;
    }
    for (key, value) in [
        ("Id", cohort198_finalization::UNIT),
        ("LoadState", if collected { "not-found" } else { "loaded" }),
        (
            "InvocationID",
            if collected { "" } else { PRODUCER_INVOCATION },
        ),
        ("MainPID", "0"),
        ("NRestarts", "0"),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
    ] {
        ensure!(
            producer[key] == value,
            "198producer lacks clean retained terminal proof: {key}"
        );
    }
    ensure!(
        (producer["ActiveState"] == "inactive" && producer["SubState"] == "dead")
            || (producer["ActiveState"] == "active" && producer["SubState"] == "exited"),
        "198producer remains live or is not cleanly terminal"
    );
    let a = &state["assignments"]["lane-a"];
    if let Some(importer) = importer {
        importing(state, importer)?;
    }
    ensure!(
        state["schema"] == "jetstreamer-adaptive-root-cohort-sweep-v3"
            && state["configuration_sha256"] == CONFIG
            && (if importer.is_some() {
                state["import_owner"] == "lane-a"
            } else {
                state["import_owner"].is_null()
            })
            && state["assignments"]
                .as_object()
                .is_some_and(|a| a.len() == 1)
            && a["first_epoch"] == 198
            && a["last_epoch"] == 198
            && a["attempt"] == 1
            && a["unit"] == cohort198_finalization::UNIT
            && a["pid"] == 1165606
            && a["pid_start_time"] == 79845173
            && (if importer.is_some() {
                a["phase"] == "importing"
            } else {
                matches!(a["phase"].as_str(), Some("producer" | "staged"))
            })
            && a["source_recovery"] != true
            && a["failure"].is_null()
            && (if importer.is_some() {
                a["import_unit"] == IMPORTER
            } else {
                a["import_unit"].is_null()
            }),
        "198controller is not holding exact pending import; inspect actual importer/repair instead"
    );
    Ok(())
}

fn state_bytes() -> Result<Vec<u8>> {
    let path = Path::new(STATE);
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == 0
            && m.mode() & 0o077 == 0
            && path.canonicalize()? == path,
        "unsafe198controller state"
    );
    read_stable_bounded(path, 1 << 20, "198controller state")
}

pub(super) fn observe(current: &Value, sampled_seconds: u64) -> Result<Value> {
    preflight(current)?;
    let producer = fleet::unit(cohort198_finalization::UNIT)?;
    let bytes = state_bytes()?;
    let state: Value = serde_json::from_slice(&bytes)?;
    let manager = if producer["LoadState"] == "not-found" {
        let output = std::process::Command::new("/usr/bin/journalctl")
            .args([
                &format!("UNIT={}", cohort198_finalization::UNIT),
                &format!("INVOCATION_ID={PRODUCER_INVOCATION}"),
                "-g",
                "Deactivated successfully",
                "-n",
                "2",
                "--no-pager",
                "-o",
                "json",
            ])
            .output()?;
        ensure!(
            output.status.success() && output.stdout.len() <= 65536,
            "198 manager journal unreadable"
        );
        let records: Vec<Value> = std::str::from_utf8(&output.stdout)?
            .lines()
            .map(serde_json::from_str)
            .collect::<std::result::Result<_, _>>()?;
        ensure!(
            records.len() == 1,
            "198 manager success missing or duplicated"
        );
        Some(records[0].clone())
    } else {
        None
    };
    let importer = if state["assignments"]["lane-a"]["phase"] == "importing" {
        Some(fleet::unit(IMPORTER)?)
    } else {
        None
    };
    owned_state(&state, &producer, manager.as_ref(), importer.as_ref())?;
    let source_receipt = if importer.is_some() {
        let bytes = read_stable_bounded(
            Path::new(SOURCE_RECEIPT),
            1 << 20,
            "198 committed source receipt",
        )?;
        ensure!(
            hex_lower(&Sha256::digest(&bytes))
                == "a1734902c86c333be889f3da731da662308b542fa2c72e2e63da566f941cd226",
            "198 source receipt changed"
        );
        Some(hex_lower(&Sha256::digest(&bytes)))
    } else {
        None
    };
    let mut events = cohort198_finalization::journal_events(sampled_seconds)?;
    if let Some(manager) = &manager {
        let time = manager["__REALTIME_TIMESTAMP"]
            .as_str()
            .unwrap()
            .parse::<u64>()?;
        let close = events["events"][3]["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("198 archive close time")?
            .parse::<u64>()?;
        ensure!(
            close < time && time <= sampled_seconds * 1_000_000,
            "198 manager success outside archive handoff interval"
        );
    }
    let path = Path::new(ARCHIVE);
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file()
            && m.uid() == 1001
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && path.canonicalize()? == path
            && events["archive_close_bytes"].as_u64() == Some(m.len()),
        "198closed source archive absent/moved/changed; inspect actual import phase"
    );
    let archive = identity(&m);
    ensure!(
        fleet::unit(CONTROLLER)? == *current
            && fleet::unit(cohort198_finalization::UNIT)? == producer
            && (if let Some(importer) = &importer {
                fleet::unit(IMPORTER)? == *importer
            } else {
                true
            })
            && state_bytes()? == bytes
            && regular_identity(path)? == archive
            && fs::symlink_metadata(path)?.ctime() == m.ctime()
            && fs::symlink_metadata(path)?.ctime_nsec() == m.ctime_nsec(),
        "198pending import ownership/state/archive changed during proof"
    );
    events["schema"] = json!("jetstreamer-epoch198-controller-import-handoff-v1");
    events["producer"] = producer;
    events["producer_terminal_manager"] = json!(manager);
    events["importer"] = json!(importer);
    events["source_receipt_sha256"] = json!(source_receipt);
    events["controller_state"] = state;
    events["controller_state_sha256"] = json!(hex_lower(&Sha256::digest(&bytes)));
    events["controller_sha256"] = json!(SCRIPT_SHA);
    events["controller_argv_sha256"] = json!(COMMAND_SHA);
    events["controller_recovery"] = json!({"path":RECOVERY,"sha256":RECOVERY_SHA});
    events["jet_path"] = json!(path);
    events["jet_identity"] = json!({"device":archive.device,"inode":archive.inode,"length":archive.length,
        "modified_seconds":archive.modified_seconds,"modified_nanoseconds":archive.modified_nanoseconds});
    events["independent_full_verification_passed"] = json!(false);
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_importer_requires_exact_owner_command_source_and_state() {
        let (mut state, producer) = fixture();
        state["import_owner"] = json!("lane-a");
        let a = &mut state["assignments"]["lane-a"];
        a["phase"] = json!("importing");
        a["import_unit"] = json!(IMPORTER);
        a["receipt"] = json!(SOURCE_RECEIPT);
        a["source_evidence"] = json!({"receipt_sha256":"a1734902c86c333be889f3da731da662308b542fa2c72e2e63da566f941cd226","members":[{"epoch":198,"archive_sha256":"4a1252a650f7b50f45326a07c0a58090b8c0174cf547099a16eeca45869f7ffb"}]});
        let importer = json!({"Id":IMPORTER,"InvocationID":IMPORT_IID,"MainPID":"3182197","LoadState":"loaded","ActiveState":"active","SubState":"running","NRestarts":"0","Type":"exec","ExecStart":format!("{} ; ignore_errors=no }}", importer_command())});
        assert!(pending_state(&state, &producer).is_err());
        owned_state(&state, &producer, None, Some(&importer)).unwrap();
        for key in [
            "Id",
            "InvocationID",
            "MainPID",
            "ActiveState",
            "SubState",
            "NRestarts",
            "ExecStart",
        ] {
            let mut bad = importer.clone();
            bad[key] = json!("changed");
            assert!(
                owned_state(&state, &producer, None, Some(&bad)).is_err(),
                "{key}"
            );
        }
        for pointer in [
            "/import_owner",
            "/assignments/lane-a/phase",
            "/assignments/lane-a/import_unit",
            "/assignments/lane-a/source_evidence/receipt_sha256",
        ] {
            let mut bad = state.clone();
            *bad.pointer_mut(pointer).unwrap() = json!("changed");
            assert!(
                owned_state(&bad, &producer, None, Some(&importer)).is_err(),
                "{pointer}"
            );
        }
    }
    #[test]
    #[ignore = "requires root and exact retained 198 deployment; preflight only, no terminal event or handoff claimed"]
    fn host_controller_preflight_denies_terminal_or_publication_claims() {
        let current = fleet::unit(CONTROLLER).unwrap();
        preflight(&current).unwrap();
        assert_eq!(fleet::unit(CONTROLLER).unwrap(), current);
    }
    fn fixture() -> (Value, Value) {
        let state = json!({"schema":"jetstreamer-adaptive-root-cohort-sweep-v3","configuration_sha256":CONFIG,
            "import_owner":null,"assignments":{"lane-a":{"first_epoch":198,"last_epoch":198,"attempt":1,
                "unit":cohort198_finalization::UNIT,"pid":1165606,"pid_start_time":79845173,"phase":"producer","source_recovery":false}}});
        let producer = json!({"Id":cohort198_finalization::UNIT,"LoadState":"loaded","InvocationID":PRODUCER_INVOCATION,
            "MainPID":"0","NRestarts":"0","Result":"success","ExecMainStatus":"0","ActiveState":"inactive","SubState":"dead"});
        (state, producer)
    }
    #[test]
    fn pending_handoff_requires_exact_clean_parent_and_state() {
        let (mut state, producer) = fixture();
        pending_state(&state, &producer).unwrap();
        state["assignments"]["lane-a"]["phase"] = json!("staged");
        pending_state(&state, &producer).unwrap();
        for (key, value) in [
            ("InvocationID", json!("f".repeat(32))),
            ("MainPID", json!("1165606")),
            ("Result", json!("exit-code")),
            ("ExecMainStatus", json!("1")),
            ("LoadState", json!("not-found")),
        ] {
            let mut p = producer.clone();
            p[key] = value;
            assert!(pending_state(&state, &p).is_err(), "{key}");
        }
    }
    #[test]
    fn collected_owner_needs_exact_pid1_success_not_absence_alone() {
        let (state, mut producer) = fixture();
        producer["LoadState"] = json!("not-found");
        producer["InvocationID"] = json!("");
        assert!(pending_state(&state, &producer).is_err());
        let manager = json!({"UNIT":cohort198_finalization::UNIT,"INVOCATION_ID":PRODUCER_INVOCATION,"_PID":"1","_UID":"0","MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448","MESSAGE":format!("{}: Deactivated successfully.",cohort198_finalization::UNIT),"__REALTIME_TIMESTAMP":"1792613007929541"});
        pending_state_with_manager(&state, &producer, Some(&manager)).unwrap();
        for key in [
            "UNIT",
            "INVOCATION_ID",
            "_PID",
            "_UID",
            "MESSAGE_ID",
            "MESSAGE",
            "__REALTIME_TIMESTAMP",
        ] {
            let mut bad = manager.clone();
            bad[key] = json!("wrong");
            assert!(
                pending_state_with_manager(&state, &producer, Some(&bad)).is_err(),
                "{key}"
            );
        }
    }
    #[test]
    fn live_importer_failure_replacement_or_unbound_state_cannot_be_pending() {
        let (state, producer) = fixture();
        for (key, value) in [
            ("phase", json!("importing")),
            ("phase", json!("failed")),
            ("import_unit", json!("actual-import.service")),
            ("failure", json!("receipt absent")),
            ("attempt", json!(2)),
            ("pid", json!(123)),
        ] {
            let mut s = state.clone();
            s["assignments"]["lane-a"][key] = value;
            assert!(pending_state(&s, &producer).is_err(), "{key}");
        }
        let mut s = state.clone();
        s["import_owner"] = json!("lane-a");
        assert!(pending_state(&s, &producer).is_err());
        let mut s = state;
        s["configuration_sha256"] = json!("f".repeat(64));
        assert!(pending_state(&s, &producer).is_err());
    }
    #[test]
    fn binding_does_not_borrow_other_host_or_reset_producer_clock() {
        assert!(binding_matches(
            CONTROLLER,
            CONTROLLER_INVOCATION,
            cohort198_finalization::UNIT,
            PRODUCER_INVOCATION
        ));
        assert!(!binding_matches(
            CONTROLLER,
            CONTROLLER_INVOCATION,
            CONTROLLER,
            CONTROLLER_INVOCATION
        ));
        assert!(!binding_matches(
            cohort_finalization::CONTROLLER,
            cohort_finalization::CONTROLLER_INVOCATION,
            cohort_finalization::UNIT,
            cohort_finalization::PRODUCER_INVOCATION
        ));
        assert_eq!(
            cohort_finalization::handoff_scope(CONTROLLER).unwrap(),
            198..=198
        );
    }
}
