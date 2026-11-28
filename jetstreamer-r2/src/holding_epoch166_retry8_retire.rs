//! Private archive retirement for one previously stopped epoch 166 invocation.
use super::*;
use std::{
    collections::BTreeMap,
    ffi::CString,
    os::fd::{AsRawFd, FromRawFd},
};
const SOURCE: &str = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry8-20261110-v1/private/destination-f5ca2c2ad058437c08aaf6b1f7ce14a26791e7ff9d9fb375ce654c014d85a2c3/work/root-cohort-166-166/run-1746683-1795053006864315025/archives/epoch-166.jet";
const RUN: &str = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry8-20261110-v1/private/destination-f5ca2c2ad058437c08aaf6b1f7ce14a26791e7ff9d9fb375ce654c014d85a2c3/work/root-cohort-166-166/run-1746683-1795053006864315025";
const DESTINATION: &str = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry8-20261110-v1/private/destination-f5ca2c2ad058437c08aaf6b1f7ce14a26791e7ff9d9fb375ce654c014d85a2c3";
const SHA: &str = "b9570bb82bf9f905f7725e03f08bca368d17581bce11327ec2536270202955f2";
const LENGTH: u64 = 55516564111;
const ALLOCATED: u64 = 55516639232;
const INODE: u64 = 106109795;
const INSPECTION: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch166-retry8-prefix-inspection-20261120-v1/review-Egryw0/INSPECTION.json";
const INSPECTION_SHA: &str = "4c5320af48484e3167843cf1d5d6e7f644c9bd3ee345d7945d3623eb1c923b0c";
const ELIGIBILITY: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch166-retry8-prefix-sealed-20261120-v1/eligibility.json";
const ELIGIBILITY_SHA: &str = "3d1f81679952856402653425c1fcb74e1a5282bb6d254933f5d6d0b865aebd6b";
const PARK_PLAN: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch166-retry8-prefix-sealed-20261120-v1/plan.json";
const PARK_PLAN_SHA: &str = "28aff64a531f04664eddd455f9ff38fc306a55a36f0d48991ff8f5a74e0275ef";
const MAPPING: &str = "/usr/local/lib/jetstreamer/horizon-node02-holding-20261023-v1/mapping.json";
const MAPPING_SHA: &str = "61f7601f78a7aa1f71394a020cbbb28aa9dbd85de858f139def1c989f2b2a89e";
pub(super) const PARK_UNIT: &str = "horizon-closed166-retry8-park-20261120-v1.service";
const PARK: &str = PARK_UNIT;
const PRODUCER: &str = "horizon-qualify-166-replacement-local3retry8-20261110-v1.service";
const GUARD: &str = "horizon-guard-replacement-166-local3retry8-20261110-v1";
const MUTATION_LOCK: &str = "/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock";
const EPOCH_LOCK: &str = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry8-20261110-v1/private/destination-f5ca2c2ad058437c08aaf6b1f7ce14a26791e7ff9d9fb375ce654c014d85a2c3/locks/epoch-166.lock";
const QUARANTINE: &str = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/retirements/epoch166-retry8-b9570bb82bf9f905f7725e03f08bca368d17581bce11327ec2536270202955f2.jet";
const STATE_SHA: &str = "ef63e2a2e443375f84b1c851c8d0ffc51454d3ef0f5bea03124f8ce3cd73e47a";
const LIFECYCLE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch166-retry8-retirement-runtime-20261124-v5";
const EVIDENCE_ROOT: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch166-retry8-prefix-retirement-evidence-20261120-v1";
const RUN_INODE: u64 = 106109769;
const SCRATCH_INODE: u64 = 106109776;
const STATE_INODE: u64 = 106109771;
const EPOCH_LOCK_INODE: u64 = 106109762;
const INSPECTION_SCHEMA: &str = "horizon-epoch166-stopped-prefix-inspection-v1";
const ATTEMPT: &str = "8";
const PARK_START: &str = "/var/lib/jetstreamer/horizon_runtime_data/root0145-zero-recovery-20261120-v1/RETRY8_PARK_START.json";
const MTIME_SEC: i64 = 1795137923;
const MTIME_NSEC: i64 = 495231379;
const RUNTIME_PACKAGE_ROOT: Option<&str> = Some("/var/lib/jetstreamer/horizon_runtime_data");
const ADDITIONAL_COMPILED: &[(&str, &str, &str)] = &[];
const ORIGINAL_NODE: (&str, &str) = super::INDEPENDENT_166_NODE;
const HOLDING_IMAGE_FIELD: &str = "qualified_image";
const PARK_IID: &str = "d2c2c0d054294e149f4b9395459c6d36";
const PARK_FRAGMENT: &str =
    "/run/systemd/transient/horizon-closed166-retry8-park-20261120-v1.service";
const PARK_START_TIME: &str = "Fri 2026-11-20 02:22:48 UTC";
const PARK_STOP_TIME: &str = "Fri 2026-11-20 03:18:25 UTC";

const PARK_PID: &str = "2380956";
const PARK_START_MONOTONIC: &str = "3488029346047";
const PARK_EXIT_MONOTONIC: &str = "3491366285204";

include!("holding_epoch166_serial_park.rs");
macro_rules! profile {
    (epoch $prefix:literal, $suffix:literal) => {
        concat!($prefix, "166-", profile!("", ""), $suffix)
    };
    ($prefix:literal, $suffix:literal) => {
        concat!($prefix, "retry8", $suffix)
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
