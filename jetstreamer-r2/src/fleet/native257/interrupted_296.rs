use super::*;

const ROOT: &str = "/home/ubuntu/.codex/diagnostics";
const INVOCATION: &str = "5d84409726e04264976c77a4f3874e02";
const UNIT: &str = "horizon-qualify-296-rooted-singleton-v1.service";
const TERMINAL: &str = "/var/lib/jetstreamer/horizon296-guarded-singleton-v1/terminal.json";

fn recorded(relative_path: &str, sha256: &str) -> BoundFile {
    BoundFile {
        path: Path::new(ROOT).join(relative_path),
        sha256: sha256.into(),
    }
}

/// Reconcile the first routine sample after the epoch 296 worker exited
/// between observation and fleet reconciliation.
pub(in crate::fleet) fn failed_296_observer_predecessor(
    fleet: &BoundFile,
    previous: &Value,
    observer: &BoundFile,
    observation: &Value,
) -> Result<bool> {
    let accepted = recorded(
        "horizon-foundation-seven-lane-v330/fleet.json",
        "3e37e96480efb5d068c1e19a23daa120ed1525999e375a40bff22ce1d0f598bb",
    );
    let resumed = recorded(
        "horizon-resume-observer-20261120-v332.json",
        "ab73f6b9c0481dd06c4ab59535f7ee3ed39c5c2e7934c52421b09551dceaa43f",
    );
    if fleet != &accepted || observer != &resumed {
        return Ok(false);
    }

    let initial = recorded(
        "horizon-resume-observer-20261120-v330.json",
        "cfedd949dd233fce4b6f9593ad1fa1b60ba15096f861e2c9083283339a93d74e",
    );
    let interrupted = recorded(
        "horizon-resume-observer-20261120-v331.json",
        "49fc85550fe145f60f78db98aff3af69019643308be6d59344806320cc6d7016",
    );
    let cutoff = bound_json(&recorded(
        "horizon-foundation-seven-lane-v331/interrupted-epoch296-cutoff.json",
        "b64635e393731f2ae712ebe696f802cdf3f399f1b26ac49f6b618eb15214e005",
    ))?;
    let terminal_ref = BoundFile {
        path: TERMINAL.into(),
        sha256: "2dd34c57a0faa24b33cd4ac39ae1d0fe3fae69633b3dad0c45ec95e54bc4383c".into(),
    };
    let initial_sample = bound_json(&initial)?;
    let interrupted_sample = bound_json(&interrupted)?;
    let terminal = bound_json(&terminal_ref)?;
    ensure!(
        cutoff["schema"] == "foundation-epoch296-ended-during-fleet-reconciliation-v1"
            && cutoff["previous_fleet"] == private157::binding(fleet)
            && cutoff["observer"] == private157::binding(&interrupted)
            && cutoff["terminal"] == private157::binding(&terminal_ref)
            && cutoff["producer_invocation_id"] == INVOCATION
            && cutoff["status_keys_authentication_passed"] == true
            && cutoff["archive_publication_authorized"] == false
            && terminal["schema"] == "foundation-epoch296-first-batch-semantic-failure-v1"
            && terminal["epoch"] == 296
            && terminal["invocation_id"] == INVOCATION
            && terminal["guard_drained"] == true
            && terminal["archive_publication_authorized"] == false
            && previous["observer_receipt"].as_str() == initial.path.to_str()
            && previous["observer_sha256"] == initial.sha256
            && previous["sampled_at_utc"] == initial_sample["recorded_at_utc"]
            && *observation == bound_json(&resumed)?,
        "different epoch 296 failure or accepted observation"
    );
    let is_failed_replay = |replay: &Value| {
        replay["range"] == "296-296"
            && replay["invocation_binding_stable"] == true
            && replay["producer_after"]["unit"] == UNIT
            && replay["producer_after"]["invocation_id"] == INVOCATION
    };
    ensure!(
        interrupted_sample["replays"]
            .as_array()
            .context("missing interrupted replay rows")?
            .iter()
            .filter(|replay| is_failed_replay(replay))
            .count()
            == 1
            && !observation["replays"]
                .as_array()
                .context("missing resumed replay rows")?
                .iter()
                .any(|replay| replay["range"] == "296-296"),
        "epoch 296 replay does not close across the interrupted sample"
    );
    for (reference, earlier, later) in [
        (&initial, &initial_sample, &interrupted_sample),
        (&interrupted, &interrupted_sample, observation),
    ] {
        let cadence = &later["cadence"];
        ensure!(
            later["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
                && cadence["previous_sample"].as_str() == reference.path.to_str()
                && cadence["previous_sample_sha256"] == reference.sha256
                && cadence["previous_sample_recorded_at_utc"] == earlier["recorded_at_utc"]
                && cadence["routine_minimum_interval_enforced"] == true
                && num(cadence, "observed_interval_seconds")? >= 1800,
            "broken routine observation link after the epoch 296 failure"
        );
    }
    Ok(true)
}

#[cfg(test)]
#[test]
#[ignore = "requires the exact accepted Foundation fleet and root-owned interruption receipts"]
fn epoch296_failure_observer_chain_is_bound() -> Result<()> {
    let fleet = recorded(
        "horizon-foundation-seven-lane-v330/fleet.json",
        "3e37e96480efb5d068c1e19a23daa120ed1525999e375a40bff22ce1d0f598bb",
    );
    let observer = recorded(
        "horizon-resume-observer-20261120-v332.json",
        "ab73f6b9c0481dd06c4ab59535f7ee3ed39c5c2e7934c52421b09551dceaa43f",
    );
    let previous = bound_json(&fleet)?;
    let mut observation = bound_json(&observer)?;
    assert!(failed_296_observer_predecessor(
        &fleet,
        &previous,
        &observer,
        &observation
    )?);
    let mut wrong_observer = observer.clone();
    wrong_observer.sha256 = "0".repeat(64);
    assert!(!failed_296_observer_predecessor(
        &fleet,
        &previous,
        &wrong_observer,
        &observation
    )?);
    observation["cadence"]["previous_sample_sha256"] = Value::Null;
    assert!(failed_296_observer_predecessor(&fleet, &previous, &observer, &observation).is_err());
    Ok(())
}
