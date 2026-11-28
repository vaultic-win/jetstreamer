//! Close the exact Original225 broker and extraction guard after the prefix is sealed.
use super::*;
use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};

pub(super) const HANDOFF: &str = "/var/lib/jetstreamer/horizon226-suffix-v1/source-handoff.json";
pub(super) const CYCLE_LOCK: &str =
    "/var/lib/jetstreamer/horizon-seven-publication-controller-v222/cycle.lock";
pub(super) const GUARD_IMAGE: &str =
    "/var/lib/jetstreamer/horizon251-published-guard-20261118-v1/horizon251-standalone-guard";
const SUCCESS_ID: &str = "7ad2d189f7e94e70a38c781354912448";
const INTENT_SCHEMA: &str = "foundation-epoch226-extraction-success-drain-intent-v1";
const COMPLETION_SCHEMA: &str = "foundation-epoch226-extraction-success-drain-v1";

pub(super) struct Source {
    pub(super) profile: &'static Profile,
    launch_sha: &'static str,
    guard: &'static str,
    timer: &'static str,
    timer_id: &'static str,
}

const V2: Source = Source {
    profile: &RETRY,
    launch_sha: "4826797399fcd448e82bddb975cf31101d958df17126dc29013a9282e3bcf66c",
    guard: "horizon-guard-226-checkpoint-continuation-extract-v2.service",
    timer: "horizon-guard-226-checkpoint-continuation-extract-v2.timer",
    timer_id: "4bd82a58917b4c6dbbd3702391950200",
};
const V3: Source = Source {
    profile: &LAYERED_RETRY,
    launch_sha: "30f1fd1a0009ff63c22f1aac39438caf570acaddfaf90bd656331e2895294df8",
    guard: "horizon-guard-226-checkpoint-continuation-extract-v3.service",
    timer: "horizon-guard-226-checkpoint-continuation-extract-v3.timer",
    timer_id: "8b7e93251e7b4491873cf33ac5bc759d",
};

impl Source {
    pub(super) fn launch(&self) -> Value {
        json!({"path":Path::new(self.profile.state).join("fleet-launch.json"), "sha256":self.launch_sha})
    }

    pub(super) fn completion(&self) -> PathBuf {
        Path::new(self.profile.state).join("control/success-drain-completion.json")
    }
}

pub(super) fn latest() -> Result<&'static Source> {
    let path = Path::new(V3.profile.state).join("fleet-launch.json");
    if path.try_exists()? {
        sealed_json(&V3.launch(), &path)?;
        Ok(&V3)
    } else {
        Ok(&V2)
    }
}

pub(super) fn source(handoff: &Value) -> Result<&'static Source> {
    [&V2, &V3]
        .into_iter()
        .find(|source| handoff["launch"] == source.launch())
        .context("epoch 226 handoff does not identify a qualified extraction")
}

pub(super) fn show(name: &str) -> Result<Value> {
    let result = ProcessCommand::new("/usr/bin/systemctl").args([
        "show", "--no-pager", "--property=Id,LoadState,ActiveState,SubState,InvocationID,Job,MainPID,ControlPID,ControlGroup,NRestarts,Result,ExecMainStatus,ExecStart,Type,Restart,Unit,FragmentPath",
        name,
    ]).output()?;
    let mut properties = serde_json::Map::new();
    for row in std::str::from_utf8(&result.stdout)?.lines() {
        let (key, value) = row.split_once('=').context("malformed manager property")?;
        ensure!(
            properties.insert(key.into(), value.into()).is_none(),
            "duplicate manager property"
        );
    }
    let properties = Value::Object(properties);
    ensure!(
        properties["Id"] == name
            && (result.status.success() || properties["LoadState"] == "not-found"),
        "epoch 226 could not observe {name}"
    );
    Ok(properties)
}

fn quiet_service(unit_name: &str, row: &Value) -> bool {
    matches!(row["ActiveState"].as_str(), Some("inactive" | "failed"))
        && row["MainPID"] == "0"
        && row["ControlPID"] == "0"
        && row["ControlGroup"] == ""
        && row["Job"] == ""
        && !Path::new("/sys/fs/cgroup/system.slice")
            .join(unit_name)
            .exists()
}

fn exact_success(source: &Source, handoff: &Value, launch: &Value) -> Result<Value> {
    let original = &handoff["terminal"];
    let unit = source.profile.unit;
    let now = show(unit)?;
    ensure!(
        quiet_service(unit, &now)
            && now["ActiveState"] == "inactive"
            && now["SubState"] == "dead"
            && now["ExecMainStatus"] == "0"
            && now["Result"] == "success"
            && now["NRestarts"] == "0"
            && (now["InvocationID"] == "" || now["InvocationID"] == launch["invocation_id"]),
        "epoch 226 extraction has no clean terminal manager state"
    );
    let invocation = launch["invocation_id"]
        .as_str()
        .context("extraction invocation")?;
    let result = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            "-b",
            "--no-pager",
            "-o",
            "json",
            "_PID=1",
            "_UID=0",
            &format!("UNIT={unit}"),
            &format!("INVOCATION_ID={invocation}"),
            &format!("MESSAGE_ID={SUCCESS_ID}"),
        ])
        .output()?;
    let mut rows = std::str::from_utf8(&result.stdout)?.lines();
    let event: Value = serde_json::from_str(rows.next().context("missing PID 1 success")?)?;
    ensure!(
        result.status.success()
            && rows.next().is_none()
            && event["__CURSOR"] == original["pid1_cursor"]
            && event["__REALTIME_TIMESTAMP"] == original["terminal_unix_microseconds"]
            && event["INVOCATION_ID"] == invocation
            && event["UNIT"] == unit,
        "epoch 226 PID 1 success differs from the sealed prefix handoff"
    );
    Ok(now)
}

fn authenticate_owners(source: &Source, launch: &Value) -> Result<Value> {
    let profile = source.profile;
    let timer = show(source.timer)?;
    let guard = show(source.guard)?;
    let broker = show(profile.broker)?;
    ensure!(
        timer["Job"] == ""
            && (timer["ActiveState"] == "inactive"
                || (timer["ActiveState"] == "active"
                    && timer["Unit"] == source.guard
                    && timer["InvocationID"] == source.timer_id)),
        "epoch 226 extraction timer changed owner"
    );
    if guard["LoadState"] != "not-found" {
        let plan_hash = launch["guard_plan"]["sha256"]
            .as_str()
            .context("guard plan digest")?;
        let args = format!(
            "argv[]={GUARD_IMAGE} {}/guard-plan.json --plan-sha256 {plan_hash} --self-sha256 {GUARD_SHA} ;",
            profile.state
        );
        ensure!(
            guard["ExecStart"]
                .as_str()
                .is_some_and(|s| s.contains(&args))
                && guard["Restart"] == "no",
            "epoch 226 extraction guard command no longer matches its launch"
        );
    } else {
        ensure!(
            quiet_service(source.guard, &guard),
            "epoch 226 missing guard has live state"
        );
    }
    if !quiet_service(profile.broker, &broker) {
        let budget = launch["broker_range_budget_bytes"]
            .as_u64()
            .context("broker range budget")?
            .to_string();
        let effective = exact_process(
            &broker,
            profile.broker,
            &launch["broker_invocation_id"],
            &[BROKER_IMAGE, profile.unit, &budget],
            BROKER_SHA,
            &launch["broker_memory_max"],
        )?;
        ensure!(
            broker["Job"] == ""
                && effective["pid"] == launch["broker_pid"]
                && effective["single_process_cgroup"] == true,
            "epoch 226 broker ownership changed"
        );
    }
    Ok(json!({"timer":timer, "guard":guard, "broker":broker}))
}

pub(super) fn stop(name: &str) -> Result<()> {
    ensure!(
        ProcessCommand::new("/usr/bin/systemctl")
            .args(["stop", "--", name])
            .status()?
            .success(),
        "epoch 226 could not stop exact auxiliary unit {name}"
    );
    Ok(())
}

pub(crate) fn run() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    ensure!(
        matches!(args.len(), 5 | 6)
            && args[2] == HANDOFF
            && args[3] == "--handoff-sha256"
            && args.get(5).is_none_or(|arg| arg == "--apply")
            && unsafe { libc::geteuid() } == 0,
        "usage: jetstreamer-r2 drain-epoch226-extraction {HANDOFF} --handoff-sha256 HEX [--apply]"
    );
    let apply = args.len() == 6;
    let reference = json!({"path":HANDOFF, "sha256":args[4]});
    let handoff = sealed_json(&reference, Path::new(HANDOFF))?;
    let source = source(&handoff)?;
    let profile = source.profile;
    let state = Path::new(profile.state);
    let original = source.launch();
    let launch_record = sealed_json(&original, &state.join("fleet-launch.json"))?;
    let claim = DiagnosticClaim {
        epoch: 226,
        unit: profile.unit.into(),
        invocation_id: launch_record["invocation_id"]
            .as_str()
            .context("extraction launch invocation")?
            .into(),
        scratch_path: profile.root.into(),
        launch_receipt: serde_json::from_value(original.clone())?,
    };
    launch(&claim, &launch_record)?;
    ensure!(
        handoff["schema"] == "foundation-epoch226-suffix-handoff-v1"
            && handoff["epoch"] == 226
            && handoff["launch"] == original
            && handoff["stage"]["operation"] == "replay"
            && handoff["work_started"] == false
            && handoff["admission_issued"] == false
            && canonical_digest(&handoff["stage_sha256"]),
        "epoch 226 extraction success does not bind the prepared suffix"
    );
    let _lock = if apply {
        let f = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(CYCLE_LOCK)?;
        let stat = f.metadata()?;
        ensure!(
            stat.is_file()
                && stat.uid() == 0
                && stat.nlink() == 1
                && stat.mode() & 0o077 == 0
                && unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "epoch 226 extraction drain could not lock the campaign cadence"
        );
        Some(f)
    } else {
        None
    };
    let producer = exact_success(source, &handoff, &launch_record)?;
    let intent_path = state.join("control/success-drain-intent.json");
    let complete_path = source.completion();
    let before = authenticate_owners(source, &launch_record)?;
    if !apply {
        println!(
            "{}",
            json!({"epoch":226, "handoff":reference, "producer":producer,
            "exact_auxiliary_units": [source.timer, source.guard, profile.broker], "local_mutations":false})
        );
        return Ok(());
    }
    if !intent_path.exists() {
        private157::immutable_receipt(
            &intent_path,
            &json!({"schema":INTENT_SCHEMA,
            "handoff":reference, "original_launch":original, "producer":producer, "before":before}),
        )?;
    }
    let intent = private157::file_binding(&intent_path)?;
    let saved = sealed_json(&intent, &intent_path)?;
    ensure!(
        saved["schema"] == INTENT_SCHEMA
            && saved["handoff"] == reference
            && saved["original_launch"] == original,
        "epoch 226 foreign drain intent"
    );
    if !complete_path.exists() {
        if before["timer"]["ActiveState"] != "inactive" {
            stop(source.timer)?;
        }
        let after_timer = authenticate_owners(source, &launch_record)?;
        ensure!(
            after_timer["timer"]["ActiveState"] == "inactive",
            "epoch 226 timer is still active"
        );
        if after_timer["guard"]["LoadState"] != "not-found" {
            stop(source.guard)?;
        }
        let after_guard = authenticate_owners(source, &launch_record)?;
        ensure!(
            quiet_service(source.guard, &after_guard["guard"]),
            "epoch 226 guard is still active"
        );
        if !quiet_service(profile.broker, &after_guard["broker"]) {
            stop(profile.broker)?;
        }
    }
    let after = authenticate_owners(source, &launch_record)?;
    ensure!(
        after["timer"]["ActiveState"] == "inactive"
            && quiet_service(source.guard, &after["guard"])
            && quiet_service(profile.broker, &after["broker"]),
        "epoch 226 auxiliary state did not drain"
    );
    if !complete_path.exists() {
        private157::immutable_receipt(
            &complete_path,
            &json!({"schema":COMPLETION_SCHEMA,
            "epoch":226, "intent":intent, "handoff":reference, "producer":producer, "after":after,
            "prefix_retained":true, "suffix_started":false, "remote_mutations":false}),
        )?;
    }
    let completion = private157::file_binding(&complete_path)?;
    let saved = sealed_json(&completion, &complete_path)?;
    ensure!(
        saved["schema"] == COMPLETION_SCHEMA
            && saved["intent"] == intent
            && saved["handoff"] == reference,
        "epoch 226 foreign drain completion"
    );
    println!("{completion}");
    Ok(())
}

#[cfg(test)]
#[test]
#[ignore = "reads the live Foundation extraction and its sealed launch; no mutations"]
fn authenticates_the_auxiliaries_and_rejects_a_live_extraction() -> Result<()> {
    let state = Path::new(V3.profile.state);
    let launch = sealed_json(&V3.launch(), &state.join("fleet-launch.json"))?;
    let owners = authenticate_owners(&V3, &launch)?;
    assert_eq!(owners["timer"]["InvocationID"], V3.timer_id);
    assert_eq!(
        owners["broker"]["InvocationID"],
        launch["broker_invocation_id"]
    );
    assert_eq!(show(V3.profile.unit)?["ActiveState"], "active");
    let failure = exact_success(&V3, &Value::Null, &launch).unwrap_err();
    assert!(
        failure
            .to_string()
            .contains("no clean terminal manager state")
    );
    Ok(())
}

#[cfg(test)]
#[test]
fn extraction_source_requires_a_matching_path_and_digest() -> Result<()> {
    for known in [&V2, &V3] {
        assert_eq!(
            source(&json!({"launch":known.launch()}))?.completion(),
            known.completion()
        );
    }
    let mut mixed = V3.launch();
    mixed["sha256"] = json!(V2.launch_sha);
    assert!(source(&json!({"launch": mixed})).is_err());
    Ok(())
}
