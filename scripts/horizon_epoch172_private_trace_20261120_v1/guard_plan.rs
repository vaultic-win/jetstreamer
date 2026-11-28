//! Exact raw-DATA/v1.5.6 guard contract. The sealed standard guard charges the whole
//! original tree, scans its actual cgroup and signals only its bound producer invocation.
use anyhow::{Result, ensure};
use serde_json::{Value, json};

#[cfg(feature = "epoch171")]
#[path = "route171.rs"]
pub mod route;
#[cfg(not(feature = "epoch171"))]
#[path = "route172.rs"]
pub mod route;
pub use route::*;
pub const WORKER_SHA: &str = "b0219574172b54b251b4f2feda6285ca3b6bee5f2830a0d46e69ee8ea2275541";
pub const WORKER_BYTES: u64 = 9_376_224;
pub const WORKER_SOURCE: &str = "f07bab4fdcaeca7efcf189aa62a518eeda3f2f3b";
pub const WORKER_TREE: &str = "dd0dda905451b27845a3c83989878e44ee98ee72";
pub const WORKER_FEATURE: &str = "historical-per-byte-logging";
pub const GUARD: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry9-recovery-20261120-v1/guard-v1/guard";
pub const GUARD_SHA: &str = "b2271db6f25696612c388297db3a10852f7911560887f67dcb404392d91f7016";
// The retained 288-GiB booking survives. This diagnostic enforces a smaller
// whole-tree ceiling to fit alongside 168's existing raw HOME floor.
pub const CAP: u64 = 96 << 30;
pub const VMA: u64 = 3_500_000;
// Current higher protected floors from the accepted epochs 166/167/170 route are applied
// by the caller. Even a malconfigured admission cannot use less than the old 172 contract.
pub const ORIGINAL_GUARD_FLOOR: u64 = 6_264_131_239_730;
pub fn iid(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && s.bytes().any(|b| b != b'0')
}
pub fn plan(id: &str, floor: u64) -> Result<Value> {
    ensure!(
        iid(id) && floor >= ORIGINAL_GUARD_FLOOR,
        "invalid invocation or raw protected HOME floor"
    );
    Ok(
        json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":UNIT,"invocation_id":id,"filesystem":"/home/sol","minimum_free_bytes":floor,"worker_root":LANE,"maximum_worker_vmas":VMA,"maximum_root_physical_bytes":CAP,"receipt_directory":RECEIPTS}),
    )
}
pub fn first_sample(s: &Value, id: &str, pid: u64, plan_sha: &str, floor: u64) -> Result<()> {
    let r = &s["root_physical_observation"];
    let producer = &s["producer"];
    ensure!(
        s["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && iid(id)
            && s["producer_invocation_id"] == id
            && producer["invocation_id"] == id
            && producer["pid"] == pid
            && pid > 1
            && producer["active"] == "active"
            && producer["sub"] == "running"
            && producer["cgroup"] == format!("/system.slice/{UNIT}")
            && producer["restarts"] == 0,
        "guard producer identity"
    );
    ensure!(
        s["guard_sha256"] == GUARD_SHA
            && s["plan_sha256"] == plan_sha
            && s["trip_reason"].is_null()
            && s["worker_observation_error"].is_null()
            && s["root_physical_observation_error"].is_null()
            && s["producer_stop_enabled"] == true
            && s["maximum_worker_vmas"] == VMA
            && s["maximum_root_physical_bytes"] == CAP
            && s["minimum_free_bytes"] == floor
            && s["available_bytes"].as_u64().is_some_and(|v| v >= floor),
        "guard raw capacity or trip"
    );
    ensure!(
        r["exceeds_budget"] == false
            && r["maximum_physical_bytes"] == CAP
            && r["conservative_physical_bytes"]
                .as_u64()
                .is_some_and(|v| v > 0 && v <= CAP)
            && s["workers"].as_array().is_some_and(|w| w.is_empty())
            && s.get("DATA_fulfillment").is_none()
            && s["bounded_measurement"] == false
            && s["bounded_canary"].is_null()
            && s["native_main"].is_null()
            && s["r2_mutations"] == false
            && s["remote_mutations"] == false,
        "guard root budget or pre-payload state"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plans_pin_entire_root_and_exact_actor() {
        let p = plan("11111111111111111111111111111111", ORIGINAL_GUARD_FLOOR).unwrap();
        assert_eq!(p["unit"], UNIT);
        assert_eq!(p["worker_root"], LANE);
        assert_eq!(p["maximum_root_physical_bytes"], CAP);
        assert!(p.get("data_fulfillment").is_none());
        assert!(plan("00000000000000000000000000000000", ORIGINAL_GUARD_FLOOR).is_err());
        assert!(plan("11111111111111111111111111111111", ORIGINAL_GUARD_FLOOR - 1).is_err());
    }
    #[test]
    fn raw_guard_requires_exact_actor_tree_and_unreleased_payload() {
        let id = "0123456789abcdef0123456789abcdef";
        let hash = "b".repeat(64);
        let floor = ORIGINAL_GUARD_FLOOR;
        let valid = json!({
            "schema":"jetstreamer-horizon-standalone-guard-sample-v1","producer_invocation_id":id,
            "producer":{"invocation_id":id,"pid":43,"active":"active","sub":"running","cgroup":format!("/system.slice/{UNIT}"),"restarts":0},
            "guard_sha256":GUARD_SHA,"plan_sha256":hash,"trip_reason":null,"worker_observation_error":null,
            "root_physical_observation_error":null,"producer_stop_enabled":true,"maximum_worker_vmas":VMA,
            "maximum_root_physical_bytes":CAP,"minimum_free_bytes":floor,"available_bytes":floor+1,
            "root_physical_observation":{"exceeds_budget":false,"maximum_physical_bytes":CAP,"conservative_physical_bytes":1},
            "workers":[],"bounded_measurement":false,"bounded_canary":null,"native_main":null,"r2_mutations":false,"remote_mutations":false
        });
        assert!(first_sample(&valid, id, 43, &hash, floor).is_ok());
        for (field, value) in [
            ("trip_reason", json!("filesystem-floor")),
            ("workers", json!([[45, 200]])),
            ("available_bytes", json!(floor - 1)),
            ("producer_stop_enabled", json!(false)),
            ("DATA_fulfillment", json!({"resource_credit_bytes":1})),
            ("maximum_root_physical_bytes", json!(CAP + 1)),
        ] {
            let mut v = valid.clone();
            v[field] = value;
            assert!(first_sample(&v, id, 43, &hash, floor).is_err(), "{field}");
        }
        assert!(first_sample(&valid, id, 44, &hash, floor).is_err());
        assert!(
            first_sample(&valid, "11111111111111111111111111111111", 43, &hash, floor).is_err()
        );
    }
}
