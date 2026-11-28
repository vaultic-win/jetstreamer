//! The original cold diagnostic completed with both processes reaped. Its entire
//! reservation and protective timer are retained; the same-sample observer still
//! reports the worker that was genuinely running at the scheduled cutoff.
use super::*;

const PROOF: &str = "/var/lib/jetstreamer/horizon-native266-terminal-proof-v161-cold-a1/proof.json";
const CUSTODY: &str =
    "/home/ubuntu/.codex/diagnostics/horizon266-original-terminal-v161-v1/private-custody.json";
const SPEC_SHA: &str = "af53ca6af1d4f6f73a6f6dc8d7a36c5f5ab6ed92c871c0b11fac625a04b98a05";
const OBSERVER_SHA: &str = "6136dedbae503a38bc2b74db0ba32cbaa835e6b61b882c14817ad48eafcccb60";
const FLEET_SHA: &str = "82b0bbdf68c4040b061e24693a35de6e787cf5a5b34bf993e8548f531d9ff8d8";
fn proof_binding() -> Bound {
    Bound::new(
        PROOF,
        "7affafddf177c057661d73b339a1e7453a9e6330b7722cf26a789088661c1658",
    )
}
fn bound_proof(fleet: &Value) -> Result<Value> {
    let gate = one(rows(fleet, "epochs")?.iter().filter(|v| v["epoch"] == 266))?;
    let reference = proof_binding();
    ensure!(
        rows(gate, "gate_evidence")?
            .iter()
            .filter(|b| **b == json!(reference))
            .count()
            == 1,
        "native266 accepted terminal proof absent or duplicated"
    );
    reference.sealed()
}
pub(super) fn roster(
    f: &Value,
    observer: &Value,
    diagnostics: &[&Value],
    handoff: &Value,
    accounting: &Value,
    boot: &str,
) -> Result<()> {
    let proof = bound_proof(f)?;
    let original = Bound::new(
        CUSTODY,
        "882eb3d1760a36cfc1bd60bf8cf5e843cddd85663c21ec4134721dad241372d1",
    )
    .json()?;
    let spec = binding(&proof["capture_spec"])?;
    ensure!(
        spec.sha256 == SPEC_SHA && spec.path == Path::new(PROOF).with_file_name("spec.json"),
        "native266 terminal capture plan"
    );
    let plan = spec.sealed()?;
    ensure!(
        plan["running_origin"] == json!(origin())
            && plan["output"] == PROOF
            && plan["fleet"] == proof["fleet"]
            && plan["observer"] == proof["observer"]
            && plan["fleet"]["sha256"] == FLEET_SHA
            && plan["observer"]["sha256"] == OBSERVER_SHA
            && proof["schema"] == "jetstreamer-private-epoch266-native-terminal-proof-v1"
            && proof["epoch"] == 266
            && proof["unit"] == UNIT266
            && proof["invocation_id"] == IID
            && proof["main_pid"] == 2_563_315
            && proof["boot_id"] == boot
            && proof["running_origin"] == json!(origin())
            && original["handoff"] == accounting["startup_handoff"]
            && proof["native_result"] == original["native_result"]["data"]
            && proof["terminal_unix_microseconds"] == 1_795_230_719_673_012u64
            && proof["terminal_monotonic_microseconds"] == 375_792_795_531u64
            && proof["cause"] == "bootstrap checkpoint verified"
            && proof["repair_backlog_retained"] == false
            && proof["native_input_qualified"] == true
            && proof["resource_samples_taken"] == 0
            && proof["resource_release_authorized"] == false
            && proof["ordinary_replay_claim"] == false,
        "native266 terminal capture or original custody differs"
    );
    no_authority(&proof)?;
    let result = &proof["native_result"];
    ensure!(
        result["schema"] == "horizon266-exact-worker-cold-input-result-v1"
            && result["worker_pid"] == 2_563_592
            && result["worker_reaped"] == true
            && result["worker_shutdown_acknowledged"] == true
            && result["full_accounts_commitment_verified"] == true
            && result["bootstrap_slot"] == 114_910_768
            && result["entry_replay"] == false
            && result["full_epoch_qualified"] == false,
        "native266 private result scope"
    );
    live::same_owner(&proof["terminal_manager"], &f["unit_census"][UNIT266])?;
    if f["observer_sha256"] == OBSERVER_SHA {
        ensure!(
            f["metadata_event"] == json!(proof_binding())
                && f["previous_fleet"] == proof["fleet"]
                && f["observer_receipt"] == proof["observer"]["path"]
                && f["new_resource_samples"] == 0,
            "native266 retained resource sample is not the terminal metadata event"
        );
        observation(
            one(diagnostics.iter().copied())?,
            handoff,
            &accounting["original"]["tmpfs_charged_within_producer"],
        )
    } else {
        ensure!(
            diagnostics.is_empty(),
            "native266 retired diagnostic still present"
        );
        completed_observer(f, observer)
    }
}

pub(crate) fn live_owner(manager: &Value, fleet: &Value) -> Result<()> {
    let proof = bound_proof(fleet)?;
    let original = &proof["terminal_manager"];
    live::same_owner(original, manager)?;
    for key in [
        "ControlPID",
        "Job",
        "ExecMainCode",
        "ExecMainStatus",
        "ExecMainStartTimestampMonotonic",
        "Restart",
        "KillMode",
        "Delegate",
        "TriggeredBy",
        "MemoryMax",
        "MemoryHigh",
        "MemorySwapMax",
        "TasksMax",
    ] {
        ensure!(
            original.get(key).is_some() && manager[key] == original[key],
            "native266 retained terminal field {key}"
        );
    }
    ensure!(
        manager["Id"] == UNIT266
            && manager["InvocationID"] == IID
            && manager["LoadState"] == "loaded"
            && manager["ActiveState"] == "inactive"
            && manager["SubState"] == "dead"
            && manager["MainPID"] == "0"
            && manager["ControlPID"] == "0"
            && manager["NRestarts"] == "0"
            && manager["Job"] == ""
            && manager["ExecMainCode"] == "1"
            && manager["ExecMainStatus"] == "0"
            && manager["Result"] == "success"
            && manager["MemoryMax"] == "192000000000"
            && manager["MemorySwapMax"] == "0"
            && manager["KillMode"] == "control-group"
            && manager["Delegate"] == "no",
        "native266 original terminal owner"
    );
    for (pid, ticks) in [(2_563_315, 37_399_871), (2_563_592, 37_400_994)] {
        if Path::new(&format!("/proc/{pid}")).try_exists()? {
            ensure!(
                native257::process_ticks(pid)? != ticks,
                "native266 original process still present"
            );
        }
    }
    live::verify_drained_group(UNIT266)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires the sealed original epoch 266 terminal and accepted fleet event"]
    fn original_terminal_event_preserves_reservation_and_kernel_drain() {
        let base = Bound::new(
            "/var/lib/jetstreamer/horizon-native257-current-bookings-v161-ops-v1/review.json",
            "b6b44c8e6e4ad8eed7ae9346d792ec9539e8935a7f460c69882f47b560260c3e",
        )
        .sealed()
        .unwrap();
        let evidence = Path::new(
            "/home/ubuntu/.codex/diagnostics/horizon266-original-terminal-event-v161-v2/completion.json",
        );
        let result = Bound::new(
            evidence,
            "c29ae381dfdbe065fdfd481f63d763884d7839345fc086c9ce9b78887f3bd13c",
        )
        .json()
        .unwrap();
        assert_eq!(result["terminal"], json!(proof_binding()));
        assert_eq!(result["predecessor"], base["fleet"]);
        let f = binding(&result["fleet"]).unwrap().json().unwrap();
        let o = binding(&result["observer"]).unwrap().json().unwrap();
        let (mut bookings, _, _) = admission::reservations(&base).unwrap();
        let boot = text(&base, "boot_id").unwrap();
        finalization::validate_roster(&f, &o, &bookings, boot, true).unwrap();
        let proof = proof_binding().sealed().unwrap();
        live_owner(&proof["terminal_manager"], &f).unwrap();
        let mut duplicate = f.clone();
        let row = rows(&duplicate, "pipelines")
            .unwrap()
            .iter()
            .find(|v| pipeline(v))
            .unwrap()
            .clone();
        duplicate["active"].as_array_mut().unwrap().push(row);
        assert!(validate(&duplicate, &o, &bookings, boot).is_err());
        bookings
            .iter_mut()
            .find(|r| r.unit == UNIT266)
            .unwrap()
            .maximum_memory_bytes = 0;
        assert!(validate(&f, &o, &bookings, boot).is_err());
    }
}

const DIAG: &str = "/home/ubuntu/.codex/diagnostics";
const TERMINAL_FLEET: &str = "ba5ad60de5e81500e685dd0c7efd7adacddbbedc9d423604d15af2d22485672c";

fn schedule(version: u32) -> Result<(Value, Value, Bound)> {
    // Each change of observed owners starts with a separately sealed plan.
    // Later cycles may move the clock and output paths of that plan only.
    let (first, family, state_family, wrapper_sha) = match version {
        162..=165 => (
            162,
            "native266-terminal",
            "three-live-20261120",
            "8922361e1c68eb82dff5dc11a486ce7aefbc7ed55b0ed8140448c83aac6fa2f2",
        ),
        166..=169 => (
            166,
            "staged247-fadfe2d4",
            "staged247-fadfe2d4",
            "18a729074b169499b334b3852fe436af338f9158a4258ad4456a8c668a762f7c",
        ),
        170..=176 => (
            170,
            "staged247-full228",
            "staged247-full228",
            "6aa1ac996b00f7c1b31e2980be61a0e8003abc2ec3b3871074a09b46d7fc7278",
        ),
        177.. => (
            177,
            "staged247-stopped228",
            "staged247-stopped228",
            "0dd7f37b0909a592f32b4c70624bcf2fdc5a3a56ed18828abfe025aac8c4dad8",
        ),
        _ => bail!("native266 observer predates terminal admission"),
    };
    let root_for = |n| {
        PathBuf::from(format!(
            "/var/lib/jetstreamer/horizon-resume-cycle-v{n}-{family}-v1"
        ))
    };
    let base = root_for(first);
    let base_wrapper = Bound::new(base.join("wrapper-plan.json"), wrapper_sha);
    let mut w = base_wrapper.sealed()?;
    let base_cfg = binding(&w["config"])?;
    ensure!(
        base_cfg.path == base.join("config.json"),
        "observer base config namespace"
    );
    let mut cfg = base_cfg.sealed()?;
    ensure!(
        w.get("native266_handoff").is_none()
            && cfg["native_input_diagnostics"] == json!([])
            && cfg["minimum_interval_seconds"] == 1800,
        "native266 retired diagnostic schedule differs"
    );
    if version == first {
        return Ok((cfg, w, base_wrapper));
    }
    let root = root_for(version);
    let wp = root.join("wrapper-plan.json");
    let actual = Bound::new(&wp, hash(&wp)?);
    let aw = actual.sealed()?;
    let next = binding(&aw["config"])?;
    ensure!(
        next.path == root.join("config.json"),
        "native266 successor config namespace"
    );
    let nc = next.sealed()?;
    for key in ["previous_sample", "output", "not_before_utc"] {
        cfg[key] = nc[key].clone();
    }
    for key in ["config", "deployment", "state_directory"] {
        w[key] = aw[key].clone();
    }
    ensure!(
        w == aw
            && cfg == nc
            && text(&w, "state_directory")?
                == format!("{DIAG}/horizon-terminal-aware-cycle-v{version}-{state_family}-v1")
            && text(&w, "deployment")?
                == format!(
                    "/var/lib/jetstreamer/horizon-terminal-aware-cycle-v{version}-{state_family}-v1"
                ),
        "native266 sealed successor changed other original observer owners"
    );
    Ok((cfg, w, actual))
}
fn completed_observer(f: &Value, o: &Value) -> Result<()> {
    let output = text(f, "observer_receipt")?;
    let root = format!("{DIAG}/horizon-resume-observer-20261120-v");
    let version: u32 = output
        .strip_prefix(&root)
        .and_then(|s| s.strip_suffix(".json"))
        .context("native266 routine output namespace")?
        .parse()?;
    let (cfg, w, plan) = schedule(version)?;
    ensure!(
        output == format!("{root}{version}.json")
            && cfg["output"] == output
            && cfg["previous_sample"] == format!("{root}{}.json", version - 1),
        "native266 retired observer path"
    );
    let previous = binding(&f["previous_fleet"])?.json()?;
    ensure!(
        bound_proof(&previous)? == proof_binding().sealed()?
            && previous["unit_census"][UNIT266]["InvocationID"] == IID
            && previous["unit_census"][UNIT266]["ActiveState"] == "inactive",
        "native266 terminal predecessor"
    );
    let cadence = &o["cadence"];
    if f["metadata_event"].is_object() {
        ensure!(
            previous["observer_sha256"] == f["observer_sha256"]
                && previous["observer_receipt"] == output
                && f["new_resource_samples"] == 0,
            "native266 later event replaced its scheduled observation"
        );
    } else if matches!(version, 164 | 193) && previous["observer_receipt"] != cfg["previous_sample"]
    {
        let prior = binding(&f["previous_fleet"])?;
        ensure!(
            f["admission_transition_guard"].is_null(),
            "observer gap requires a routine fleet"
        );
        native266::validate_observer_predecessor(&prior.path, &prior.sha256, Path::new(output), o)?;
    } else {
        ensure!(
            previous["observer_sha256"] == cadence["previous_sample_sha256"]
                && previous["observer_receipt"] == cfg["previous_sample"]
                && (version != 162 || f["previous_fleet"]["sha256"] == TERMINAL_FLEET),
            "native266 next routine predecessor"
        );
    }
    ensure!(
        o["recorded_at_utc"] == f["sampled_at_utc"]
            && cadence["previous_sample"] == cfg["previous_sample"]
            && cadence["configured_not_before_utc"] == cfg["not_before_utc"]
            && cadence["routine_minimum_interval_enforced"] == true
            && cadence["observation_reason"] == "routine"
            && num(cadence, "observed_interval_seconds")? >= 1800,
        "native266 retired observation cadence"
    );
    let state = PathBuf::from(text(&w, "state_directory")?);
    let completion = state.join("completion.json");
    let done = Bound::new(&completion, hash(&completion)?).json()?;
    ensure!(
        done["schema"] == "horizon-terminal-aware-observation-v1"
            && done["observer_output"] == output
            && done["observer_exit_code"] == 0
            && done["omitted_owners_unchanged"] == true
            && done["omitted_owner_reservations_retained"] == true
            && done["finalization_owner_reservations_retained"] == true
            && done["native_input_diagnostics"] == json!([])
            && done.get("native266_handoff") == Some(&Value::Null)
            && done["resource_release_authorized"] == false,
        "native266 omitted diagnostic clock or funding"
    );
    let prescreen = binding(&done["prescreen"])?;
    let effective = binding(&done["effective_config"])?;
    ensure!(
        prescreen.path == state.join("prescreen.json")
            && effective.path == state.join("effective-config.json"),
        "native266 observation custody"
    );
    let before = prescreen.json()?;
    let sealed = Bound::new(
        Path::new(text(&w, "deployment")?).join("config.json"),
        &effective.sha256,
    )
    .sealed()?;
    ensure!(
        before["plan"] == json!(plan)
            && before["native_input_diagnostics"] == json!([])
            && before.get("native266_handoff") == Some(&Value::Null)
            && before["previous_sample_sha256"] == cadence["previous_sample_sha256"]
            && sealed == effective.json()?
            && sealed["native_input_diagnostics"] == json!([])
            && sealed["output"] == output
            && sealed["previous_sample"] == cfg["previous_sample"]
            && sealed["not_before_utc"] == cfg["not_before_utc"],
        "native266 scheduled terminal diagnostic removal not authenticated"
    );
    Ok(())
}

#[cfg(test)]
mod schedule_tests {
    use super::*;

    #[test]
    #[ignore = "requires the sealed Foundation observer schedules and completed v183 fleet"]
    fn staged_uploader_schedules_authenticate_the_retired_worker() -> Result<()> {
        for version in [165, 166, 169, 170, 176, 177, 183] {
            let (config, wrapper, _) = schedule(version)?;
            assert_eq!(config["native_input_diagnostics"], json!([]));
            assert!(wrapper.get("native266_handoff").is_none());
            assert_eq!(
                config["output"],
                format!("{DIAG}/horizon-resume-observer-20261120-v{version}.json")
            );
        }
        let fleet = Bound::new(
            format!("{DIAG}/horizon-fleet-takeover-v183-20261120-v1/fleet-v1.json"),
            "d45a956802a7d5f78ee3ee4e993f83eff2e695b8e56fc26754859db631764fce",
        )
        .json()?;
        let mut observer = Bound::new(
            text(&fleet, "observer_receipt")?,
            text(&fleet, "observer_sha256")?,
        )
        .json()?;
        completed_observer(&fleet, &observer)?;
        observer["cadence"]["previous_sample_sha256"] = json!("0".repeat(64));
        assert!(completed_observer(&fleet, &observer).is_err());
        Ok(())
    }

    #[test]
    #[ignore = "requires the real sealed v162 terminal-aware observer deployment"]
    fn original_v162_schedule_authenticates_only_the_removed_native_diagnostic() {
        let (cfg, wrapper, _) = schedule(162).unwrap();
        assert_eq!(cfg["native_input_diagnostics"], json!([]));
        assert_eq!(rows(&cfg, "replays").unwrap().len(), 6);
        assert_eq!(rows(&cfg, "diagnostic_replays").unwrap().len(), 1);
        assert!(wrapper.get("native266_handoff").is_none());
        let prior = Bound::new(
            "/var/lib/jetstreamer/horizon-resume-cycle-v162-native266-intake-v1/config.json",
            "3aebc4697dfd6f846fbb007cc6a960896220e3b58054ccb28517e5a3877204e3",
        )
        .sealed()
        .unwrap();
        let mut expected = prior.clone();
        let diagnostic = one(rows(&expected, "native_input_diagnostics").unwrap().iter()).unwrap();
        assert_eq!(diagnostic["unit"], UNIT266);
        assert_eq!(diagnostic["expected_invocation_id"], IID);
        expected["native_input_diagnostics"] = json!([]);
        assert_eq!(expected, cfg);
        let f = Bound::new(
            "/home/ubuntu/.codex/diagnostics/horizon266-original-terminal-event-v161-v2/fleet.json",
            TERMINAL_FLEET,
        )
        .json()
        .unwrap();
        let raw = binding(&proof_binding().sealed().unwrap()["observer"])
            .unwrap()
            .json()
            .unwrap();
        let prior = Bound::new(
            "/var/lib/jetstreamer/horizon-native257-current-bookings-v161-ops-v1/review.json",
            "b6b44c8e6e4ad8eed7ae9346d792ec9539e8935a7f460c69882f47b560260c3e",
        )
        .sealed()
        .unwrap();
        let (book, _, _) = admission::reservations(&prior).unwrap();
        let boot = text(&prior, "boot_id").unwrap();
        let mut missing = raw.clone();
        missing["diagnostic_replays"]
            .as_array_mut()
            .unwrap()
            .retain(|d| !super::super::diagnostic(d));
        assert!(validate(&f, &missing, &book, boot).is_err());
        let mut duplicate = raw.clone();
        let d = one(rows(&raw, "diagnostic_replays")
            .unwrap()
            .iter()
            .filter(|v| super::super::diagnostic(v)))
        .unwrap();
        duplicate["diagnostic_replays"]
            .as_array_mut()
            .unwrap()
            .push(d.clone());
        assert!(validate(&f, &duplicate, &book, boot).is_err());
    }

    #[test]
    #[ignore = "requires the completed scheduled v162 observer and its actual fleet"]
    fn actual_v162_scheduled_omission_rejects_a_substituted_diagnostic() {
        let path = Path::new(
            "/home/ubuntu/.codex/diagnostics/horizon-fleet-takeover-v162-20261120-v1/fleet-v1.json",
        );
        let f = Bound::new(path, hash(path).unwrap()).json().unwrap();
        let o = Bound::new(
            text(&f, "observer_receipt").unwrap(),
            text(&f, "observer_sha256").unwrap(),
        )
        .json()
        .unwrap();
        let prior = Bound::new(
            "/var/lib/jetstreamer/horizon-native257-current-bookings-v161-ops-v1/review.json",
            "b6b44c8e6e4ad8eed7ae9346d792ec9539e8935a7f460c69882f47b560260c3e",
        )
        .sealed()
        .unwrap();
        let (book, _, _) = admission::reservations(&prior).unwrap();
        let boot = text(&prior, "boot_id").unwrap();
        validate(&f, &o, &book, boot).unwrap();
        let old = binding(&proof_binding().sealed().unwrap()["observer"])
            .unwrap()
            .json()
            .unwrap();
        let d = one(rows(&old, "diagnostic_replays")
            .unwrap()
            .iter()
            .filter(|v| super::super::diagnostic(v)))
        .unwrap();
        let mut extra = o.clone();
        extra["diagnostic_replays"]
            .as_array_mut()
            .unwrap()
            .push(d.clone());
        assert!(validate(&f, &extra, &book, boot).is_err());
    }
}
