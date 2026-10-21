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

pub(super) fn scope(unit: &str) -> Result<std::ops::RangeInclusive<u64>> {
    ensure!(unit == UNIT, "unqualified producer-finalization owner");
    Ok(216..=219)
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
    validate_owner(current)?;
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
    let output = Command::new("/usr/bin/journalctl").args([
        &format!("_SYSTEMD_INVOCATION_ID={INVOCATION}"),
        &format!("_SYSTEMD_UNIT={UNIT}"),
        "-g", "historical checkpoint slot=95039999|snapshot verification complete|horizon archive complete:",
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
    terminal_events(&records, sampled_seconds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
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
