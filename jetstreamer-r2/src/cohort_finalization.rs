//! Observational handoff for one already-sealed legacy cohort. No replay,
//! verification or publication authority is obtained from these journal events.
use super::*;
use std::process::Command;

pub(super) const UNIT: &str =
    "jetstreamer-root-sweep-horizon-216-219-cached-v5-e216-219-lane-b-1.service";
const INVOCATION: &str = "95fb05d1b78349bcb907c1e930e7682e";
const PID: &str = "1480800";
const NODE: &str =
    "/var/lib/jetstreamer/horizon-contiguous-216-219-cached-3959e1b-881ac2b/jetstreamer-node";
const NODE_SHA: &str = "e7e142906d4b53ff222adefa498ea73aefb77d3b7f57eccbe14ab528805d206c";
const CHECKPOINT: &str = "historical checkpoint slot=95039999 bank_hash=2c243ReQxMaEwJgQ61VjaqEwjV7cWgJp93y4FrR9MLns accounts_hash=FZXGvpZJiVWodbLVAoJ6gpgPcG5b8LX7xHQkUP4FJzFn last_blockhash=4MaWCL7a9CgF9XrNHgt9TA5cryFkW8P7S6aCdCU8cXRW capitalization=503272341407852275 transactions=26664111051 tick_height=6082560000 complete=true writes=636 next_write_version=101208358166";
const COMPLETE: &str = "horizon archive complete: slots=432000 blocks=408622 txs=436819250 tx_updates=979749826 orphan_updates=175922765 epochs=1 buckets=3375 bytes=128896280026 (payload 820681288860 uncompressed)";
pub(super) const CONTROLLER: &str = "horizon-controller-216-219-cached-v5.service";
pub(super) const CONTROLLER_INVOCATION: &str = "2b6ded8d8baf4f72a5c8a91385f7c278";
pub(super) const PRODUCER_INVOCATION: &str = INVOCATION;
const SCRIPT: &str =
    "/var/lib/jetstreamer/horizon-controller-1f628c5/adaptive_root_cohort_sweep.py";
const SCRIPT_SHA: &str = "816fcaf4d69ff2d3cb564e75a64a926a3f6b8c057e0ce1863739fadebdb20d1b";
const STATE: &str = "/var/lib/jetstreamer/horizon-controller-state-216-219-v5/state.json";
const BATCH: &str = "/home/ubuntu/.jetstreamer-private/qualification-216-219-contiguous-v2/lane-b/private/destination-ed77489f5a6e060663ad1949ecb0c4f212cf1f3bdc24dc535989e8bb4ff0f707/evidence/archive-batches/destination-0000000000010301-0000000001456402/batch-2958b2841e8e4c0307c2478e81ffe63254355da59ed0e782d09b48eb4d744d54.json";
const BATCH_SHA: &str = "84edb7b4c90f8a78d218d3992b28831ea8279b51f1cfe3af9acbaea6993759dc";
const COMMIT: &str = "root-checkpoint cohort 216-219 published 4 archive(s) with checksums in transaction 2958b2841e8e4c0307c2478e81ffe63254355da59ed0e782d09b48eb4d744d54; receipt ";

pub(super) fn scope(unit: &str) -> Result<std::ops::RangeInclusive<u64>> {
    if unit == super::cohort198_finalization::UNIT {
        return Ok(198..=198);
    }
    ensure!(unit == UNIT, "unqualified producer-finalization owner");
    Ok(216..=219)
}
pub(super) fn handoff_scope(unit: &str) -> Result<std::ops::RangeInclusive<u64>> {
    if unit == super::cohort198_handoff::CONTROLLER {
        return Ok(198..=198);
    }
    ensure!(unit == CONTROLLER, "unqualified controller import handoff");
    Ok(216..=219)
}

fn handoff_state(controller: &Value, producer: &Value, state: &Value) -> Result<()> {
    for (key, value) in [
        ("Id", CONTROLLER),
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("MainPID", "1480721"),
        ("InvocationID", CONTROLLER_INVOCATION),
        ("NRestarts", "0"),
    ] {
        ensure!(
            controller[key] == value,
            "import handoff controller differs: {key}"
        );
    }
    for (key, value) in [
        ("Id", UNIT),
        ("LoadState", "loaded"),
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("MainPID", "0"),
        ("InvocationID", INVOCATION),
        ("NRestarts", "0"),
        ("Result", "success"),
    ] {
        ensure!(
            producer[key] == value,
            "import handoff producer is not cleanly terminal: {key}"
        );
    }
    let command = controller["ExecStart"]
        .as_str()
        .context("missing controller command")?;
    ensure!(
        command.starts_with(&format!("{{ path={SCRIPT} ; argv[]={SCRIPT} "))
            && command.contains(" --controller-id=horizon-216-219-cached-v5 ")
            && command.contains(&format!(" --controller-sha256={SCRIPT_SHA} "))
            && command.contains(" --first-epoch=216 --last-epoch=219 "),
        "not the exact import handoff command"
    );
    ensure!(
        state["schema"] == "jetstreamer-adaptive-root-cohort-sweep-v3"
            && state["configuration_sha256"]
                == "7058ef0b243b366277810d0b0ba5ed38ea13e003f3e2ce2f2d9308b39a901ebf"
            && state["import_owner"].is_null()
            && state["assignments"]["lane-b"]["first_epoch"] == 216
            && state["assignments"]["lane-b"]["last_epoch"] == 219
            && state["assignments"]["lane-b"]["unit"] == UNIT
            && matches!(
                state["assignments"]["lane-b"]["phase"].as_str(),
                Some("producer" | "staged")
            ),
        "controller no longer holds the bounded pending import handoff"
    );
    Ok(())
}

pub(super) fn observe_handoff(controller: &Value, sampled_seconds: u64) -> Result<Value> {
    if controller["Id"] == super::cohort198_handoff::CONTROLLER {
        return super::cohort198_handoff::observe(controller, sampled_seconds);
    }
    let producer = super::fleet::unit(UNIT)?;
    let state_meta = fs::symlink_metadata(STATE)?;
    ensure!(
        state_meta.is_file()
            && state_meta.uid() == 0
            && state_meta.nlink() == 1
            && state_meta.mode() & 0o077 == 0,
        "unsafe controller handoff state"
    );
    let state = read_stable_bounded(Path::new(STATE), 1 << 20, "controller handoff state")?;
    let state_value: Value = serde_json::from_slice(&state)?;
    handoff_state(controller, &producer, &state_value)?;
    for (path, expected, uid) in [(SCRIPT, SCRIPT_SHA, 0), (BATCH, BATCH_SHA, 1000)] {
        let meta = fs::symlink_metadata(path)?;
        ensure!(
            meta.is_file()
                && meta.uid() == uid
                && meta.nlink() == 1
                && meta.mode() & 0o022 == 0
                && (uid != 0 || meta.mode() & 0o222 == 0),
            "unsafe handoff evidence"
        );
        let bytes = read_stable_bounded(Path::new(path), 1 << 20, "handoff evidence")?;
        ensure!(
            hex_lower(&Sha256::digest(&bytes)) == expected,
            "handoff evidence digest differs"
        );
    }
    // The same immutable parent and final terminal events must precede the
    // coordinated sample; this does not authorize the pending import itself.
    immutable_node()?;
    let events = journal_events(sampled_seconds, true)?;
    ensure!(
        super::fleet::unit(UNIT)? == producer
            && read_stable_bounded(Path::new(STATE), 1 << 20, "controller handoff state")? == state,
        "handoff changed during evidence capture"
    );
    Ok(
        serde_json::json!({"schema":"jetstreamer-legacy216-controller-import-handoff-v1",
        "producer":producer,"controller_state":state_value,"terminal_events":events,
        "source_batch":{"path":BATCH,"sha256":BATCH_SHA},"controller_sha256":SCRIPT_SHA,
        "publication_authorized":false,"replay_launch_authorized":false,"r2_mutations":false}),
    )
}

fn validate_owner(current: &Value) -> Result<()> {
    for (key, value) in [
        ("Id", UNIT),
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("InvocationID", INVOCATION),
        ("MainPID", PID),
        ("NRestarts", "0"),
    ] {
        ensure!(current[key] == value, "finalization owner differs: {key}");
    }
    let command = current["ExecStart"]
        .as_str()
        .context("missing producer command")?;
    ensure!(command.starts_with(&format!("{{ path={NODE} ; argv[]={NODE} 216-219 "))
        && command.contains(" --root-checkpoint-cohort ")
        && command.contains(" --cohort-manifest-fingerprint=sha256:2297ef364cdd12c75413513530f23e27d51c9a315bcff47d2085cd6b4c9303dd ")
        && command.matches("{ path=").count() == 1,
        "finalization is not the sealed cohort command");
    Ok(())
}

fn terminal_events(records: &[Value], sampled_seconds: u64) -> Result<Value> {
    let mut selected = Vec::new();
    for marker in [CHECKPOINT, "snapshot verification complete", COMPLETE] {
        let mut matches = Vec::new();
        for record in records {
            if record["MESSAGE"]
                .as_str()
                .is_some_and(|s| s.contains(marker))
            {
                ensure!(
                    record["_SYSTEMD_INVOCATION_ID"] == INVOCATION
                        && record["_SYSTEMD_UNIT"] == UNIT
                        && record["_PID"] == PID
                        && record["_UID"] == "1000",
                    "unbound finalization journal event"
                );
                let stamp = record["__REALTIME_TIMESTAMP"]
                    .as_str()
                    .context("event timestamp missing")?
                    .parse::<u64>()?;
                ensure!(
                    stamp > 0 && stamp / 1_000_000 <= sampled_seconds,
                    "terminal event is after coordinated sample"
                );
                matches.push((stamp, record));
            }
        }
        // Earlier cohort members also logged snapshot verification. Select
        // the latest such event, but do not silently choose between duplicate
        // terminal checkpoint/archive records for the final epoch.
        if marker != "snapshot verification complete" {
            ensure!(
                matches.len() == 1,
                "terminal finalization marker missing or duplicated"
            );
        }
        matches.sort_by_key(|(stamp, _)| *stamp);
        selected.push(*matches.last().context("finalization marker absent")?);
    }
    ensure!(
        selected[0].0 < selected[1].0 && selected[1].0 < selected[2].0,
        "terminal checkpoint/verification/archive events are not ordered"
    );
    Ok(
        serde_json::json!({"schema":"jetstreamer-legacy216-finalization-events-v1",
        "unit":UNIT,"invocation_id":INVOCATION,"node_sha256":NODE_SHA,
        "events":selected.iter().map(|(_, r)| *r).collect::<Vec<_>>(),
        "terminal_slot":95039999,"replay_terminal_observed":true,
        "independent_full_verification_passed":false,"publication_authorized":false,
        "replay_launch_authorized":false,"r2_mutations":false}),
    )
}

pub(super) fn observe(current: &Value, sampled_seconds: u64) -> Result<Value> {
    if current["Id"] == super::cohort198_finalization::UNIT {
        return super::cohort198_finalization::observe(current, sampled_seconds);
    }
    validate_owner(current)?;
    immutable_node()?;
    journal_events(sampled_seconds, false)
}

fn immutable_node() -> Result<()> {
    let metadata = fs::symlink_metadata(NODE)?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.mode() & 0o222 == 0
            && metadata.nlink() == 1
            && Path::new(NODE).canonicalize()? == Path::new(NODE),
        "finalization node is not immutable"
    );
    let bytes = read_stable_bounded(Path::new(NODE), 128 << 20, "finalization node")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == NODE_SHA,
        "finalization node digest differs"
    );
    Ok(())
}

fn commit_event(records: &[Value], sampled_seconds: u64) -> Result<Value> {
    let matching: Vec<_> = records
        .iter()
        .filter(|v| {
            v["MESSAGE"]
                .as_str()
                .is_some_and(|m| m.contains(COMMIT) && m.contains(BATCH))
        })
        .collect();
    ensure!(
        matching.len() == 1,
        "exact committed batch journal event missing or duplicated"
    );
    let r = matching[0];
    let stamp = r["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("commit time missing")?
        .parse::<u64>()?;
    ensure!(
        r["_SYSTEMD_INVOCATION_ID"] == INVOCATION
            && r["_SYSTEMD_UNIT"] == UNIT
            && r["_PID"] == PID
            && r["_UID"] == "1000"
            && stamp > 0
            && stamp / 1_000_000 <= sampled_seconds,
        "source batch was not committed by the original producer before this sample"
    );
    Ok(r.clone())
}

fn journal_events(sampled_seconds: u64, require_commit: bool) -> Result<Value> {
    let output = Command::new("/usr/bin/journalctl").args([
        &format!("_SYSTEMD_INVOCATION_ID={INVOCATION}"),
        &format!("_SYSTEMD_UNIT={UNIT}"),
        "-g", "historical checkpoint slot=95039999|snapshot verification complete|horizon archive complete:|root-checkpoint cohort 216-219 published",
        "-n", "32", "--no-pager", "-o", "json",
    ]).output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 1 << 20,
        "finalization journal unavailable or oversized"
    );
    let records: Vec<Value> = std::str::from_utf8(&output.stdout)?
        .lines()
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    let mut proof = terminal_events(&records, sampled_seconds)?;
    if require_commit {
        let event = commit_event(&records, sampled_seconds)?;
        let complete = proof["events"][2]["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("archive close time missing")?
            .parse::<u64>()?;
        ensure!(
            event["__REALTIME_TIMESTAMP"]
                .as_str()
                .context("commit time missing")?
                .parse::<u64>()?
                > complete,
            "batch commit precedes archive close"
        );
        proof["source_commit_event"] = event;
    }
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn completed_producer_and_exact_pending_controller_are_both_required() {
        let controller = json!({"Id":CONTROLLER,"LoadState":"loaded","ActiveState":"active","SubState":"running",
            "MainPID":"1480721","InvocationID":CONTROLLER_INVOCATION,"NRestarts":"0",
            "ExecStart":format!("{{ path={SCRIPT} ; argv[]={SCRIPT} --first-epoch=216 --last-epoch=219 --controller-id=horizon-216-219-cached-v5 --controller-sha256={SCRIPT_SHA} --execute ; }}")});
        let producer = json!({"Id":UNIT,"LoadState":"loaded","ActiveState":"inactive","SubState":"dead",
            "MainPID":"0","InvocationID":INVOCATION,"NRestarts":"0","Result":"success"});
        let state = json!({"schema":"jetstreamer-adaptive-root-cohort-sweep-v3",
            "configuration_sha256":"7058ef0b243b366277810d0b0ba5ed38ea13e003f3e2ce2f2d9308b39a901ebf","import_owner":null,
            "assignments":{"lane-b":{"first_epoch":216,"last_epoch":219,"unit":UNIT,"phase":"producer"}}});
        handoff_state(&controller, &producer, &state).unwrap();
        for (field, value) in [
            ("ActiveState", json!("active")),
            ("InvocationID", json!("replacement")),
            ("Result", json!("exit-code")),
        ] {
            let mut bad = producer.clone();
            bad[field] = value;
            assert!(handoff_state(&controller, &bad, &state).is_err());
        }
        let mut bad = state.clone();
        bad["import_owner"] = json!("lane-b");
        assert!(handoff_state(&controller, &producer, &bad).is_err());
        bad = state.clone();
        bad["assignments"]["lane-b"]["phase"] = json!("importing");
        assert!(handoff_state(&controller, &producer, &bad).is_err());
        let mut bad_controller = controller.clone();
        bad_controller["NRestarts"] = json!("1");
        assert!(handoff_state(&bad_controller, &producer, &state).is_err());
        assert!(handoff_scope(UNIT).is_err());
        assert!(handoff_scope(CONTROLLER).unwrap().contains(&219));
    }
    fn records() -> Vec<Value> {
        [CHECKPOINT, "snapshot verification complete", COMPLETE]
            .into_iter()
            .enumerate()
            .map(|(i, message)| {
                json!({"MESSAGE":message,"_SYSTEMD_INVOCATION_ID":INVOCATION,
                "_SYSTEMD_UNIT":UNIT,"_PID":PID,"_UID":"1000",
                "__REALTIME_TIMESTAMP":((i as u64 + 10)*1_000_000).to_string()})
            })
            .collect()
    }
    #[test]
    fn committed_handoff_cannot_be_backdated_to_an_earlier_resource_sample() {
        let mut r = records();
        let mut commit = r[2].clone();
        commit["MESSAGE"] = json!(format!("{COMMIT}{BATCH} is durable"));
        commit["__REALTIME_TIMESTAMP"] = json!("13000000");
        r.push(commit);
        assert!(commit_event(&r, 12).is_err());
        commit_event(&r, 13).unwrap();
        let mut bad = r.clone();
        bad[3]["_SYSTEMD_INVOCATION_ID"] = json!("replacement");
        assert!(commit_event(&bad, 13).is_err());
    }
    #[test]
    fn only_exact_sealed_final_cohort_events_establish_observational_handoff() {
        let r = records();
        let proof = terminal_events(&r, 12).unwrap();
        assert_eq!(proof["publication_authorized"], false);
        assert_eq!(proof["independent_full_verification_passed"], false);
        for (field, value) in [
            ("_PID", json!("other")),
            ("_SYSTEMD_INVOCATION_ID", json!("replacement")),
            ("_UID", json!("0")),
            ("MESSAGE", json!("horizon archive complete: partial")),
            ("__REALTIME_TIMESTAMP", json!("13000000")),
        ] {
            let mut bad = r.clone();
            bad[2][field] = value;
            assert!(terminal_events(&bad, 12).is_err());
        }
        let mut duplicate = r.clone();
        duplicate.push(r[2].clone());
        assert!(terminal_events(&duplicate, 12).is_err());
        let mut unordered = r.clone();
        unordered[1]["__REALTIME_TIMESTAMP"] = json!("9000000");
        assert!(terminal_events(&unordered, 12).is_err());
        assert!(scope(UNIT).unwrap().contains(&219));
        assert!(scope("jetstreamer-root-sweep-other-e216-219-lane-b-1.service").is_err());
    }
    #[test]
    fn partial_or_restarted_producer_is_not_a_finalization_owner() {
        let mut current = json!({"Id":UNIT,"LoadState":"loaded","ActiveState":"active",
            "SubState":"running","InvocationID":INVOCATION,"MainPID":PID,"NRestarts":"0",
            "ExecStart":format!("{{ path={NODE} ; argv[]={NODE} 216-219 --verify --root-checkpoint-cohort --cohort-manifest-fingerprint=sha256:2297ef364cdd12c75413513530f23e27d51c9a315bcff47d2085cd6b4c9303dd ; }}")});
        validate_owner(&current).unwrap();
        current["NRestarts"] = json!("1");
        assert!(validate_owner(&current).is_err());
        current["NRestarts"] = json!("0");
        current["MainPID"] = json!("0");
        assert!(validate_owner(&current).is_err());
    }
}
