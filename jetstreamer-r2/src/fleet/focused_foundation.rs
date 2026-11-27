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

pub(super) fn launch_matches(claim: &DiagnosticClaim, launch: &Value) -> Option<bool> {
    let scope = SCOPES
        .iter()
        .find(|scope| scope.unit == claim.unit || launch["kind"] == scope.kind)?;
    let root = format!(
        "/home/ubuntu/.jetstreamer-private/qualification-{}-{}",
        scope.epoch, scope.attempt
    );
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

fn evidence(registration: &Value, key: &str) -> Result<Value> {
    let bound: BoundFile = serde_json::from_value(registration[key].clone())?;
    let meta = fs::symlink_metadata(&bound.path)?;
    ensure!(
        bound.path.canonicalize()? == bound.path
            && meta.is_file()
            && meta.uid() == 0
            && meta.nlink() == 1
            && meta.mode() & 0o077 == 0,
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
    let args = profile["argv"]
        .as_array()
        .context("focused Foundation argv")?
        .iter()
        .map(|arg| arg.as_str().context("focused Foundation argument"))
        .collect::<Result<Vec<_>>>()?;
    let command = format!(
        "{{ path={node} ; argv[]={args} ; ignore_errors=no ; ",
        args = args.join(" ")
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
                scratch_path: format!(
                    "/home/ubuntu/.jetstreamer-private/qualification-{}-{}",
                    scope.epoch, scope.attempt
                )
                .into(),
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
}
