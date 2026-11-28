//! Register the existing guarded Foundation diagnostics in the fleet census.
use super::{BoundFile, DiagnosticClaim, bound_json};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{fs, os::unix::fs::MetadataExt, path::Path};

struct Scope {
    epoch: u64,
    unit: &'static str,
    attempt: &'static str,
    state: &'static str,
    kind: &'static str,
}

const PREDECESSOR_266_UNIT: &str = "horizon-qualify-266-original-predecessor-v1.service";
const PREDECESSOR_266_PROFILE: &str =
    "/var/lib/jetstreamer/horizon266-original-predecessor-static-v1/profile.json";
const PREDECESSOR_266_PROFILE_SHA: &str =
    "7ed80c05ae0e1c706a271452d9b0dcb516c651fd0f97a2ec3f1c61a477a30f21";
const PREDECESSOR_266_PREFLIGHT: &str =
    "/var/lib/jetstreamer/horizon266-original-predecessor-runtime-v1/preflight.json";
const PREDECESSOR_266_PREFLIGHT_SHA: &str =
    "de5680f4fc6634529348c9701f639a66cf333c7296f69a7645dc97f1297bc4ae";
const PREDECESSOR_266_CUSTODY: &str =
    "/var/lib/jetstreamer/horizon266-predecessor-intake-stage-v1/custody.json";
const PREDECESSOR_266_CUSTODY_SHA: &str =
    "afd03e2258229848a2878f1c2ff75b424ebf810b79fec65788c75ac5111a5959";
const PREDECESSOR_266_RELEASE_SCHEMA: &str =
    "foundation-epoch266-original-predecessor-guard-release-fit-v1";
const WINDOW_266_UNIT: &str = "horizon-qualify-checkpoint-continuation-266-window-114936474-v1.service";
const WINDOW_266_ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-266-window-114936474-v1";
const WINDOW_266_STATE: &str = "horizon266-window-114929698-114936474-runtime-v1";
const WINDOW_266_PROFILE_SHA: &str =
    "f7562054a31277bc38747652f9a79e6967b393d8713499e6998841390cb4c5d6";
const WINDOW_266_PREFLIGHT_SHA: &str =
    "9043e168fd2322c6c5e098bee42a40f69507fa9db7afd791ad59577354f3bed1";
const WINDOW_266_CUSTODY_SHA: &str =
    "98c28740a2bdb0f707624a07046fa8a316dd37ea225f31770cf410d5fd0b7001";

const NEXT_V1627_230_UNIT: &str = "horizon-qualify-230-next-v1627-99468089-v1.service";
const NEXT_V1627_230_STATE: &str = "horizon230-next-v1627-window-runtime-v1";
const NEXT_V1627_230_PROFILE_SHA: &str =
    "f289cdf8e6c6d85f387a2deac22c2c7ef19fcb1b4b98bc75230162a2cbf71447";
const NEXT_V1627_230_PREFLIGHT_SHA: &str =
    "c54b1b9fc120a920e23d220b3d223565b7e0a5cd92f6206103c426b545431c48";

const SCOPES: &[Scope] = &[
    Scope {
        epoch: 230,
        unit: "horizon-qualify-230-short-gap-v1.service",
        attempt: "short-gap-v1",
        state: "horizon230-short-gap-runtime-v1",
        kind: "epoch230-private-short-gap",
    },
    Scope {
        epoch: 230,
        unit: "horizon-qualify-230-middle-hourly-first-v1.service",
        attempt: "middle-hourly-first-v1",
        state: "horizon230-middle-hourly-first-runtime-v1",
        kind: "epoch230-private-first-hourly-window",
    },
    Scope {
        epoch: 230,
        unit: "horizon-qualify-230-middle-hourly-second-v1.service",
        attempt: "middle-hourly-second-v1",
        state: "horizon230-middle-hourly-second-runtime-v1",
        kind: "epoch230-private-second-hourly-window",
    },
    Scope {
        epoch: 230,
        unit: "horizon-qualify-230-first-7871-v1.service",
        attempt: "first-7871-v1",
        state: "horizon230-first-7871-runtime-v1",
        kind: "epoch230-private-first-7871-window",
    },
    Scope {
        epoch: 230,
        unit: "horizon-qualify-230-v1627-window-v1.service",
        attempt: "v1627-window-v1",
        state: "horizon230-v1627-replay-runtime-v1",
        kind: "epoch230-private-v1627-window",
    },
    Scope {
        epoch: 230,
        unit: "horizon-qualify-230-adjacent-99445304-v1.service",
        attempt: "adjacent-99445304-v1",
        state: "horizon230-adjacent-99445304-runtime-v1",
        kind: "epoch230-private-adjacent-99445304-window",
    },
    Scope {
        epoch: 230,
        unit: NEXT_V1627_230_UNIT,
        attempt: "next-v1627-99468089-v1",
        state: NEXT_V1627_230_STATE,
        kind: "epoch230-private-next-v1627-window",
    },
    Scope {
        epoch: 258,
        unit: "horizon-qualify-258-native-restore-v1.service",
        attempt: "native-restore-v1",
        state: "horizon258-native-restore-runtime-v1",
        kind: "epoch258-private-native-restore",
    },
    Scope {
        epoch: 260,
        unit: "horizon-qualify-260-native-restore-v1.service",
        attempt: "native-restore-v1",
        state: "horizon260-native-restore-runtime-v1",
        kind: "epoch260-private-native-restore",
    },
    Scope {
        epoch: 266,
        unit: "horizon-qualify-266-hourly-overlap-114929697-v1.service",
        attempt: "hourly-overlap-114929697-v1",
        state: "horizon266-hourly-overlap-114929697-runtime-v1",
        kind: "epoch266-private-hourly-overlap",
    },
    Scope {
        epoch: 266,
        unit: PREDECESSOR_266_UNIT,
        attempt: "original-predecessor-v1",
        state: "horizon266-original-predecessor-runtime-v1",
        kind: "epoch266-private-original-predecessor",
    },
    Scope {
        epoch: 266,
        unit: WINDOW_266_UNIT,
        attempt: "window-114936474-v1",
        state: WINDOW_266_STATE,
        kind: "epoch266-private-hourly-window",
    },
    Scope {
        epoch: 296,
        unit: "horizon-qualify-296-loader-upgrade-focused-v2.service",
        attempt: "loader-upgrade-focused-v2",
        state: "horizon296-loader-upgrade-focused-v2",
        kind: "epoch296-private-loader-upgrade-diagnostic",
    },
    Scope {
        epoch: 296,
        unit: "horizon-qualify-296-loader-log-v3.service",
        attempt: "loader-log-v3",
        state: "horizon296-loader-log-v3",
        kind: "epoch296-private-loader-log-diagnostic",
    },
    Scope {
        epoch: 296,
        unit: "horizon-qualify-296-feature-account-v4.service",
        attempt: "feature-account-v4",
        state: "horizon296-feature-account-v4",
        kind: "epoch296-private-feature-account-qualification",
    },
];

pub(super) fn contains(unit: &str) -> bool {
    SCOPES.iter().any(|scope| scope.unit == unit)
}

pub(crate) fn resource_only(unit: &str) -> bool {
    SCOPES
        .iter()
        .any(|scope| scope.unit == unit && scope.epoch != 230)
}

fn run_root(scope: &Scope) -> String {
    if scope.unit == WINDOW_266_UNIT {
        WINDOW_266_ROOT.into()
    } else {
        format!(
            "/home/ubuntu/.jetstreamer-private/qualification-{}-{}",
            scope.epoch, scope.attempt
        )
    }
}

pub(super) fn launch_matches(claim: &DiagnosticClaim, launch: &Value) -> Option<bool> {
    let scope = SCOPES
        .iter()
        .find(|scope| scope.unit == claim.unit || launch["kind"] == scope.kind)?;
    let root = run_root(scope);
    let registration = format!(
        "/var/lib/jetstreamer/{}/cadence-registration.json",
        scope.state
    );
    Some(
        claim.epoch == scope.epoch
            && claim.unit == scope.unit
            && claim.scratch_path == Path::new(&root)
            && claim.launch_receipt.path == Path::new(&registration)
            && launch["schema"] == "jetstreamer-historical-performance-launch-receipt-v1"
            && launch["kind"] == scope.kind
            && launch["epoch"] == scope.epoch
            && launch["unit"] == scope.unit
            && launch["run_root"] == root
            && launch["invocation_id"] == claim.invocation_id
            && launch["canonical_epoch_publication_authorized"] == false,
    )
}

fn predecessor_profile(bound: &BoundFile) -> bool {
    bound.path == Path::new(PREDECESSOR_266_PROFILE) && bound.sha256 == PREDECESSOR_266_PROFILE_SHA
}

fn evidence(registration: &Value, key: &str) -> Result<Value> {
    let bound: BoundFile = serde_json::from_value(registration[key].clone())?;
    let meta = fs::symlink_metadata(&bound.path)?;
    ensure!(
        bound.path.canonicalize()? == bound.path
            && meta.is_file()
            && meta.uid() == 0
            && meta.nlink() == 1
            && (meta.mode() & 0o077 == 0
                || (registration["unit"] == WINDOW_266_UNIT
                    && matches!(key, "node_plan" | "admission")
                    && bound.path == Path::new(&format!("/var/lib/jetstreamer/horizon266-window-admitted-v1/{key}.json"))
                    && meta.mode() & 0o777 == 0o444)
                || (key == "profile"
                    && predecessor_profile(&bound)
                    && meta.mode() & 0o777 == 0o444)),
        "focused Foundation evidence custody changed for {key}"
    );
    bound_json(&bound)
}

pub(super) fn check_bindings(claim: &DiagnosticClaim, launch: &Value) -> Result<()> {
    let metadata = fs::symlink_metadata(&claim.launch_receipt.path)?;
    ensure!(
        claim.launch_receipt.path.canonicalize()? == claim.launch_receipt.path
            && metadata.is_file()
            && metadata.uid() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o222 == 0,
        "focused Foundation launch receipt custody changed"
    );
    let profile = evidence(launch, "profile")?;
    let admission = evidence(launch, "admission")?;
    let plan = evidence(launch, "guard_plan")?;
    let guard = evidence(launch, "active_guard")?;
    let manager = &launch["evidence"]["units"][0];
    ensure!(
        profile["epoch"] == claim.epoch
            && profile["unit"] == claim.unit
            && profile["run_root"] == launch["run_root"]
            && profile["node"]["path"] == launch["node_path"]
            && profile["worker"] == launch["worker"]
            && profile["publication_authorized"] == false
            && admission["profile"] == launch["profile"]
            && admission["admitted"] == true
            && admission["publication_authorized"] == false
            && plan["unit"] == claim.unit
            && plan["invocation_id"] == launch["invocation_id"]
            && plan["worker_root"] == launch["run_root"]
            && guard["producer_invocation_id"] == launch["invocation_id"]
            && guard["plan_sha256"] == launch["guard_plan"]["sha256"]
            && guard["producer"]["pid"] == launch["main_pid"]
            && manager["main_pid"] == launch["main_pid"]
            && guard["producer_stop_enabled"] == true
            && guard["trip_reason"].is_null(),
        "focused Foundation launch and admission bindings differ"
    );
    if claim.unit == NEXT_V1627_230_UNIT {
        let state = format!("/var/lib/jetstreamer/{NEXT_V1627_230_STATE}");
        ensure!(
            launch["profile"]["path"] == format!("{state}/profile.json")
                && launch["profile"]["sha256"] == NEXT_V1627_230_PROFILE_SHA
                && profile["schema"] == "foundation-epoch230-next-v1627-profile-v1"
                && profile["replay_bounds"]["first_slot"] == 99_468_090
                && profile["replay_bounds"]["last_slot"] == 99_476_782
                && admission["schema"] == "foundation-epoch230-focused-admission-v1"
                && admission["preflight"]["path"] == format!("{state}/preflight.json")
                && admission["preflight"]["sha256"] == NEXT_V1627_230_PREFLIGHT_SHA
                && plan["receipt_directory"] == format!("{state}/guard-receipts"),
            "epoch 230 v1.6.27 continuation bindings differ"
        );
    }
    if claim.epoch == 266 {
        let release = evidence(launch, "guard_release_fit")?;
        let release_schema = if claim.unit == PREDECESSOR_266_UNIT {
            check_predecessor_scope(launch, &profile, &admission, &plan)?;
            let custody = evidence(launch, "bootstrap_custody")?;
            ensure!(
                custody["schema"] == "foundation-epoch266-predecessor-input-custody-v1"
                    && custody["epoch"] == 266
                    && custody["profile"] == launch["profile"]
                    && custody["input"]["path"] == profile["bootstrap"]["path"]
                    && custody["input"]["sha256"] == profile["bootstrap"]["sha256"]
                    && custody["input"]["generation"] == profile["bootstrap"]["generation"]
                    && custody["input"]["bytes"] == profile["bootstrap"]["bytes"]
                    && custody["whole_file_sha256_rechecked"] == true
                    && custody["actual_readonly_projection_verified"] == true
                    && custody["copy_only"] == true
                    && custody["replay_launch_authorized"] == false
                    && custody["publication_authorized"] == false,
                "epoch 266 predecessor bootstrap custody differs"
            );
            PREDECESSOR_266_RELEASE_SCHEMA
        } else if claim.unit == WINDOW_266_UNIT {
            check_window_scope(launch, &profile, &admission, &plan)?;
            ensure!(release["node_plan"] == launch["node_plan"], "epoch 266 released plan differs");
            "foundation-epoch266-private-window-guard-release-fit-v1"
        } else {
            ensure!(
                launch["lossless_restore"] == profile["restore_receipt"],
                "epoch 266 overlap restore binding differs"
            );
            "foundation-epoch266-hourly-overlap-guard-release-fit-v1"
        };
        ensure!(
            (profile["diagnostic_only"] == true
                || (claim.unit == WINDOW_266_UNIT && profile["private"] == true))
                && launch["diagnostic_only"] == true
                && launch["predecessor_native_tuple_qualified"] == false
                && launch["cursor_normalization_qualified"] == false
                && release["schema"] == release_schema
                && release["invocation_id"] == launch["invocation_id"]
                && release["roster"] == admission["roster"]
                && release["guard_plan"] == launch["guard_plan"]
                && release["publication_authorized"] == false,
            "epoch 266 diagnostic-only or guard release binding differs"
        );
    }
    Ok(())
}

fn check_window_scope(
    launch: &Value,
    profile: &Value,
    admission: &Value,
    guard: &Value,
) -> Result<()> {
    let native_plan = evidence(launch, "node_plan")?;
    let custody = evidence(launch, "bootstrap_custody")?;
    let mut expected_plan = profile["node_plan_inputs"].clone();
    expected_plan["admission"] = launch["admission"].clone();
    expected_plan["minimum_free_bytes"] = admission["minimum_free_bytes"].clone();
    ensure!(
        launch["profile"]["path"] == format!("/var/lib/jetstreamer/{WINDOW_266_STATE}/profile.json")
            && launch["profile"]["sha256"] == WINDOW_266_PROFILE_SHA
            && profile["schema"] == "foundation-epoch266-private-window-runtime-profile-v1"
            && profile["first_slot"] == 114_929_698
            && profile["last_slot"] == 114_936_474
            && launch["bootstrap_custody"] == profile["bootstrap_custody"]
            && launch["bootstrap_custody"]["sha256"] == WINDOW_266_CUSTODY_SHA
            && custody["copy_drained"] == true
            && custody["bootstrap_slot"] == 114_929_697
            && custody["whole_file_sha256_rechecked"] == true
            && custody["input"]["sha256"] == native_plan["snapshot"]["sha256"]
            && admission["schema"] == "foundation-epoch266-private-window-admission-v1"
            && admission["preflight"]["path"] == format!("/var/lib/jetstreamer/{WINDOW_266_STATE}/preflight.json")
            && admission["preflight"]["sha256"] == WINDOW_266_PREFLIGHT_SHA
            && native_plan == expected_plan
            && guard["minimum_free_bytes"] == admission["minimum_free_bytes"]
            && guard["maximum_root_physical_bytes"] == profile["guarded_whole_tree_cap_bytes"]
            && guard["maximum_worker_vmas"] == 3_500_000
            && guard["receipt_directory"] == format!("/var/lib/jetstreamer/{WINDOW_266_STATE}/guard-receipts"),
        "private epoch 266 hourly window bindings differ"
    );
    Ok(())
}

fn check_predecessor_scope(
    launch: &Value,
    profile: &Value,
    admission: &Value,
    plan: &Value,
) -> Result<()> {
    let profile_ref: BoundFile = serde_json::from_value(launch["profile"].clone())?;
    ensure!(
        predecessor_profile(&profile_ref)
            && profile["schema"] == "foundation-epoch266-original-predecessor-runtime-profile-v1"
            && profile["bootstrap_slot"] == 114_910_768
            && profile["first_replay_slot"] == 114_910_769
            && profile["first_output_slot"] == 114_912_000
            && profile["last_slot"] == 114_923_430
            && profile["expected_executed_positions"] == 12_662
            && profile["expected_output_positions"] == 11_431
            && profile["persistent_archive"]
                == "/home/ubuntu/.jetstreamer-private/qualification-266-original-predecessor-v1/work/output/epoch-266-through-114923430.jet"
            && admission["preflight"]["path"] == PREDECESSOR_266_PREFLIGHT
            && admission["preflight"]["sha256"] == PREDECESSOR_266_PREFLIGHT_SHA
            && launch["bootstrap_custody"]["path"] == PREDECESSOR_266_CUSTODY
            && launch["bootstrap_custody"]["sha256"] == PREDECESSOR_266_CUSTODY_SHA
            && plan["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && plan["filesystem"] == "/"
            && plan["minimum_free_bytes"] == profile["guard_floor_bytes"]
            && plan["maximum_root_physical_bytes"] == profile["guarded_whole_tree_cap_bytes"]
            && plan["maximum_worker_vmas"] == 3_500_000
            && plan["receipt_directory"]
                == "/var/lib/jetstreamer/horizon266-original-predecessor-runtime-v1/guard-receipts",
        "epoch 266 predecessor profile, admission or guard scope differs"
    );
    Ok(())
}

pub(super) fn check_live(claim: &DiagnosticClaim, current: &Value) -> Result<()> {
    let launch = bound_json(&claim.launch_receipt)?;
    let profile = evidence(&launch, "profile")?;
    let pid = launch["main_pid"]
        .as_u64()
        .context("focused Foundation PID")?;
    let node = launch["node_path"]
        .as_str()
        .context("focused Foundation node")?;
    let argv = if claim.unit == WINDOW_266_UNIT {
        let plan: BoundFile = serde_json::from_value(launch["node_plan"].clone())?;
        format!(
            "{node} 266 {WINDOW_266_ROOT}/ledger --verify --checkpoint-continuation-plan={} --checkpoint-continuation-plan-sha256={}",
            plan.path.display(), plan.sha256
        )
    } else {
        profile["argv"]
            .as_array()
            .context("focused Foundation argv")?
            .iter()
            .map(|arg| arg.as_str().context("focused Foundation argument"))
            .collect::<Result<Vec<_>>>()?
            .join(" ")
    };
    let command = format!(
        "{{ path={node} ; argv[]={argv} ; ignore_errors=no ; "
    );
    ensure!(
        current["MainPID"] == pid.to_string()
            && current["ControlGroup"] == format!("/system.slice/{}", claim.unit)
            && current["ExecStart"]
                .as_str()
                .is_some_and(|value| value.starts_with(&command))
            && fs::read_link(format!("/proc/{pid}/exe"))? == Path::new(node),
        "focused Foundation live command or executable differs"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_the_registered_scope_can_claim_a_focused_invocation() {
        for scope in SCOPES {
            let mut claim = DiagnosticClaim {
                epoch: scope.epoch,
                unit: scope.unit.into(),
                invocation_id: "a".repeat(32),
                scratch_path: run_root(scope).into(),
                launch_receipt: BoundFile {
                    path: format!(
                        "/var/lib/jetstreamer/{}/cadence-registration.json",
                        scope.state
                    )
                    .into(),
                    sha256: "b".repeat(64),
                },
            };
            let launch = json!({
                "schema":"jetstreamer-historical-performance-launch-receipt-v1",
                "kind":scope.kind,"epoch":scope.epoch,"unit":scope.unit,
                "run_root":claim.scratch_path,"invocation_id":claim.invocation_id,
                "canonical_epoch_publication_authorized":false
            });
            assert_eq!(launch_matches(&claim, &launch), Some(true));
            assert_eq!(resource_only(&claim.unit), scope.epoch != 230);
            claim.unit = format!("horizon-perf-epoch{}-alias@v1.service", scope.epoch);
            assert_eq!(launch_matches(&claim, &launch), Some(false));
        }
    }
    #[test]
    fn predecessor_scope_requires_its_sealed_profile_and_exact_private_window() {
        let launch = json!({
            "profile":{"path":PREDECESSOR_266_PROFILE,"sha256":PREDECESSOR_266_PROFILE_SHA},
            "bootstrap_custody":{"path":PREDECESSOR_266_CUSTODY,"sha256":PREDECESSOR_266_CUSTODY_SHA}
        });
        let profile = json!({
            "schema":"foundation-epoch266-original-predecessor-runtime-profile-v1",
            "bootstrap_slot":114_910_768,"first_replay_slot":114_910_769,
            "first_output_slot":114_912_000,"last_slot":114_923_430,
            "expected_executed_positions":12_662,"expected_output_positions":11_431,
            "persistent_archive":"/home/ubuntu/.jetstreamer-private/qualification-266-original-predecessor-v1/work/output/epoch-266-through-114923430.jet",
            "guard_floor_bytes":3_770_104_987_645u64,"guarded_whole_tree_cap_bytes":16u64<<30,
        });
        let admission = json!({"preflight":{"path":PREDECESSOR_266_PREFLIGHT,
                                            "sha256":PREDECESSOR_266_PREFLIGHT_SHA}});
        let plan = json!({
            "schema":"jetstreamer-horizon-standalone-guard-plan-v1","filesystem":"/",
            "minimum_free_bytes":3_770_104_987_645u64,"maximum_root_physical_bytes":16u64<<30,
            "maximum_worker_vmas":3_500_000,
            "receipt_directory":"/var/lib/jetstreamer/horizon266-original-predecessor-runtime-v1/guard-receipts",
        });
        check_predecessor_scope(&launch, &profile, &admission, &plan).unwrap();
        let mut wrong_output = profile.clone();
        wrong_output["first_output_slot"] = json!(114_910_769);
        assert!(check_predecessor_scope(&launch, &wrong_output, &admission, &plan).is_err());
        let mut wrong_profile = launch.clone();
        wrong_profile["profile"]["sha256"] = json!("a".repeat(64));
        assert!(check_predecessor_scope(&wrong_profile, &profile, &admission, &plan).is_err());
        let mut wrong_admission = admission.clone();
        wrong_admission["preflight"]["sha256"] = json!("b".repeat(64));
        assert!(check_predecessor_scope(&launch, &profile, &wrong_admission, &plan).is_err());
        let mut wrong_plan = plan.clone();
        wrong_plan["minimum_free_bytes"] = json!(1);
        assert!(check_predecessor_scope(&launch, &profile, &admission, &wrong_plan).is_err());
    }
}
