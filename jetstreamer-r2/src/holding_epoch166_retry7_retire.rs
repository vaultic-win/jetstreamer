//! Private archive retirement for one previously stopped epoch 166 invocation.
use super::*;
use std::{
    collections::BTreeMap,
    ffi::CString,
    os::fd::{AsRawFd, FromRawFd},
};
const SOURCE: &str = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/private/destination-2d43fd7f2cb337f324aafbe7404d605eca42c04a38fb91405c81cf8e62022c9b/work/root-cohort-166-166/run-1450368-1795028473959689559/archives/epoch-166.jet";
const RUN: &str = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/private/destination-2d43fd7f2cb337f324aafbe7404d605eca42c04a38fb91405c81cf8e62022c9b/work/root-cohort-166-166/run-1450368-1795028473959689559";
const DESTINATION: &str = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/private/destination-2d43fd7f2cb337f324aafbe7404d605eca42c04a38fb91405c81cf8e62022c9b";
const SHA: &str = "cc3eb610625824a178a802a316dc24a3dfbb81c967c81560417a8c3491f93544";
const LENGTH: u64 = 13817409670;
const ALLOCATED: u64 = 13817438208;
const INODE: u64 = 104071284;
const INSPECTION: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch166-retry7-prefix-inspection-20261120-v1/review-j3d6YK/INSPECTION.json";
const INSPECTION_SHA: &str = "28ee08c1a0c7d0c09c4c0f1ce48c507914c2a6dab010e4333dcb50a5c091b6ee";
const ELIGIBILITY: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch166-retry7-prefix-sealed-20261120-v1/eligibility.json";
const ELIGIBILITY_SHA: &str = "d74bae98c056c2659d91e68aeac30227b2202ca56991ed5716ddf587935fea04";
const PARK_PLAN: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch166-retry7-prefix-sealed-20261120-v1/plan.json";
const PARK_PLAN_SHA: &str = "42fd3696a139af6321756ae923303e4ba9c0b19bd4396e9dd50f7620b73bd91f";
const MAPPING: &str = "/usr/local/lib/jetstreamer/horizon-node02-holding-20261023-v1/mapping.json";
const MAPPING_SHA: &str = "61f7601f78a7aa1f71394a020cbbb28aa9dbd85de858f139def1c989f2b2a89e";
pub(super) const PARK: &str = "horizon-closed166-retry7-park-20261120-v1.service";
const PRODUCER: &str = "horizon-qualify-166-replacement-local3retry7-20261110-v1.service";
const GUARD: &str = "horizon-guard-replacement-166-local3retry7-20261110-v1";
const MUTATION_LOCK: &str = "/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock";
const EPOCH_LOCK: &str = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/private/destination-2d43fd7f2cb337f324aafbe7404d605eca42c04a38fb91405c81cf8e62022c9b/locks/epoch-166.lock";
const QUARANTINE: &str = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/retirements/epoch166-retry7-cc3eb610625824a178a802a316dc24a3dfbb81c967c81560417a8c3491f93544.jet";
const STATE_SHA: &str = "ef63e2a2e443375f84b1c851c8d0ffc51454d3ef0f5bea03124f8ce3cd73e47a";
const LIFECYCLE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch166-retry7-retirement-runtime-20261125-v2";
const EVIDENCE_ROOT: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch166-retry7-prefix-retirement-evidence-20261120-v1";
const RUN_INODE: u64 = 104071228;
const SCRATCH_INODE: u64 = 104071236;
const STATE_INODE: u64 = 104071234;
const EPOCH_LOCK_INODE: u64 = 104071217;
const INSPECTION_SCHEMA: &str = "horizon-epoch166-stopped-prefix-inspection-v1";
const ATTEMPT: &str = "7";
const PARK_START: &str = "/var/lib/jetstreamer/horizon_runtime_data/root0145-zero-recovery-20261120-v1/RETRY7_PARK_START.json";
const MTIME_SEC: i64 = 1795050666;
const MTIME_NSEC: i64 = 976233534;
const RUNTIME_PACKAGE_ROOT: Option<&str> = Some("/var/lib/jetstreamer/horizon_runtime_data");
const ADDITIONAL_COMPILED: &[(&str, &str, &str)] = &[];
const ORIGINAL_NODE: (&str, &str) = super::INDEPENDENT_166_NODE;
const HOLDING_IMAGE_FIELD: &str = "qualified_image";
const PARK_IID: &str = "43c97d29898648948fdbdfb6339597c7";
const PARK_FRAGMENT: &str =
    "/run/systemd/transient/horizon-closed166-retry7-park-20261120-v1.service";
const PARK_START_TIME: &str = "Fri 2026-11-20 02:10:00 UTC";
const PARK_STOP_TIME: &str = "Fri 2026-11-20 02:22:48 UTC";
const PARK_PID: &str = "2376291";
const PARK_START_MONOTONIC: &str = "3487262069055";
const PARK_EXIT_MONOTONIC: &str = "3488029248842";

include!("holding_epoch166_serial_park.rs");
macro_rules! profile {
    (epoch $prefix:literal, $suffix:literal) => {
        concat!($prefix, "166-", profile!("", ""), $suffix)
    };
    ($prefix:literal, $suffix:literal) => {
        concat!($prefix, "retry7", $suffix)
    };
}
const BOOKING: &str = "/var/lib/jetstreamer/horizon_runtime_data/root0145-zero-recovery-20261120-v1/PARK_SERIAL_ADMISSION.json";
const BOOKING_SHA: &str = "6a9ec7435903516e7c0f8a4531fd6d6de184e0f16eccb40d01cc32c0cd6918a1";
fn validate_profile_rows(proof: &Value, iid: &str, start: &Value, booking: &Value) -> Result<()> {
    validate_rows(proof, iid, start, booking)
}
include!("holding_epoch166_partial_terminal.rs");
include!("holding_epoch166_prior_inspection.rs");
include!("holding_epoch166_partial_retire.rs");
