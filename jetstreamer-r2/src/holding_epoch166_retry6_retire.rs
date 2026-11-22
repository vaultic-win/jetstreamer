//! Exact old166 retry6 partial-only retirement after complete holding custody.
//! A distinct route: old166/169 profiles, scratch and canonical archives are unchanged.
use super::*;
use std::{
    collections::BTreeMap,
    ffi::CString,
    os::fd::{AsRawFd, FromRawFd},
};

const SOURCE: &str = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry6-20261110-v1/private/destination-d53ec84bc26887772d067cda9258daa995dc2541cb1e81e71b72376b619ffe51/work/root-cohort-166-166/run-689067-1794918104133897328/archives/epoch-166.jet";
const RUN: &str = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry6-20261110-v1/private/destination-d53ec84bc26887772d067cda9258daa995dc2541cb1e81e71b72376b619ffe51/work/root-cohort-166-166/run-689067-1794918104133897328";
const DESTINATION: &str = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry6-20261110-v1/private/destination-d53ec84bc26887772d067cda9258daa995dc2541cb1e81e71b72376b619ffe51";
const SHA: &str = "c6edc4b47bb905fe8825f09155edcbc217d9ea44246a3a3b4d8deb4387384e85";
const LENGTH: u64 = 56_173_984_550;
const ALLOCATED: u64 = 56_174_063_616;
const INODE: u64 = 103678035;
const ELIGIBILITY: &str =
    "/usr/local/lib/jetstreamer/horizon-closed166-retry6-holding-plan-20261119-v1/eligibility.json";
const ELIGIBILITY_SHA: &str = "6d7243eb5912b92d96367f57c94633be768937158d16a07923669ea972e79a97";
const INSPECTION: &str =
    "/var/lib/jetstreamer/epoch166-retry6-holding-review-20261119-v1/INSPECTION.json";
const INSPECTION_SHA: &str = "c2eb4c497d23b0be00468eedc6eb8445659beb188c5bbe58bb8ec1845b6b7c7f";
const PARK_PLAN: &str =
    "/usr/local/lib/jetstreamer/horizon-closed166-retry6-holding-plan-20261119-v1/plan.json";
const PARK_PLAN_SHA: &str = "a835a7adf66726ffbdc07eb13def1b917a9de799ff3dc9062ad7441cd182c640";
const MAPPING: &str = "/usr/local/lib/jetstreamer/horizon-node02-holding-20261023-v1/mapping.json";
const MAPPING_SHA: &str = "61f7601f78a7aa1f71394a020cbbb28aa9dbd85de858f139def1c989f2b2a89e";
const PARK: &str = "horizon-closed166-retry6-park-20261119-v1.service";
const PARK_IID: &str = "afc04ba6096f4826836919c2020dcdc6";
const PARK_START: &str = "/var/lib/jetstreamer/root0832-holding166-event-20261119-v1/EVENT.json";
const PARK_START_SHA: &str = "d5beb401ed0e015f371a7123fa34c6772f2d7f88b854d4cb1a01c4c8b2f0a0bb";
const PRODUCER: &str = "horizon-qualify-166-replacement-local3retry6-20261110-v1.service";
const GUARD: &str = "horizon-guard-replacement-166-local3retry6-20261110-v1";
const MUTATION_LOCK: &str = "/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock";
const EPOCH_LOCK: &str = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry6-20261110-v1/private/destination-d53ec84bc26887772d067cda9258daa995dc2541cb1e81e71b72376b619ffe51/locks/epoch-166.lock";
const QUARANTINE: &str = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/retirements/epoch166-retry6-c6edc4b47bb905fe8825f09155edcbc217d9ea44246a3a3b4d8deb4387384e85.jet";
const STATE_SHA: &str = "ef63e2a2e443375f84b1c851c8d0ffc51454d3ef0f5bea03124f8ce3cd73e47a";
const LIFECYCLE: &str =
    "/usr/local/lib/jetstreamer/horizon-holding166-retry6-retirement-20261119-v2";
// Runtime sealing precedes census/review, and check receipts precede execution
// plans. Keep their immutable versioned bundles separate from the runtime.
const EVIDENCE_ROOT: &str = "/var/lib/jetstreamer/holding166-retry6-retirement-evidence";
const RUN_INODE: u64 = 103678018;
const SCRATCH_INODE: u64 = 103678021;
const STATE_INODE: u64 = 103678019;
const EPOCH_LOCK_INODE: u64 = 103678014;
const MTIME_SEC: i64 = 1795004048;
const MTIME_NSEC: i64 = 625036367;
const INSPECTION_SCHEMA: &str = "horizon-epoch166-retry6-closed-prefix-inspection-v1";
const RUNTIME_PACKAGE_ROOT: Option<&str> = None;
const ADDITIONAL_COMPILED: &[(&str, &str, &str)] = &[];
const ORIGINAL_NODE: (&str, &str) = super::INDEPENDENT_166_NODE;
macro_rules! profile {
    (epoch $prefix:literal, $suffix:literal) => {
        concat!($prefix, "166-", profile!("", ""), $suffix)
    };
    ($prefix:literal, $suffix:literal) => {
        concat!($prefix, "retry6", $suffix)
    };
}
fn validate_transfer_provenance(proof: &Value, iid: &str) -> Result<()> {
    let start = bound(&binding(PARK_START, PARK_START_SHA))?;

    ensure!(
        proof["schema"] == "horizon-closed166-retry6-park-terminal-v1"
            && proof["unit"] == PARK
            && proof["park_plan"] == serde_json::to_value(binding(PARK_PLAN, PARK_PLAN_SHA))?
            && start["schema"] == "horizon-exact-holding166-start-event-v1"
            && start["native"]["Id"] == PARK
            && start["native"]["InvocationID"] == PARK_IID
            && start["plan"] == proof["park_plan"]
            && start["image"] == proof["helper"],
        "foreign park terminal evidence"
    );
    ensure!(iid == PARK_IID, "foreign original park invocation");
    Ok(())
}
fn validate_terminal_custody(_: &Retire, _: &Value) -> Result<()> {
    // This pre-existing terminal schema recorded the helper, plan and transfer identity.
    // The independent exact_custody and remote checks bind its original archive.
    Ok(())
}
include!("holding_epoch166_prior_inspection.rs");
include!("holding_epoch166_partial_retire.rs");
