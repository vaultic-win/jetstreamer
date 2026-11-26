//! Identity shared by the staged delivery RSS observer and its fleet consumer.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

pub const CURRENT257_UNIT: &str = "horizon-upload-257-current-reader-v1.service";
pub const CURRENT257_DIRECTORY: &str = "/var/lib/jetstreamer/horizon257-current-reader-delivery-v1";
pub const CURRENT257_IMAGE: &str =
    "/var/lib/jetstreamer/horizon247-public-images-88315624-v1/jetstreamer-r2";
pub const CURRENT257_IMAGE_SHA: &str =
    "206cd7c558fff3992a14607c18363522a4f54b9840d6bd96ad0dfc86e22344ff";
pub const CURRENT257_MEMORY_CAP: u64 = 32 << 30;
pub const CURRENT257_START_TICKS: u64 = 78_209_038;
pub const RETRY257_UNIT: &str = "horizon-upload-257-current-reader-v2.service";
pub const RETRY257_DIRECTORY: &str = "/var/lib/jetstreamer/horizon257-current-reader-delivery-v2";
pub const RETRY257_MEMORY_CAP: u64 = 64 << 30;

pub const UNIT: &str = "horizon-upload-247-staged-680e1173-v1.service";
pub const IID: &str = "3e08307874db424886cd8c46b3ecfba6";
pub const PID: u32 = 2149076;
pub const TICKS: u64 = 34618254;
pub const CAP: u64 = 10 << 30;
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon247-public-images-680e1173-v1/jetstreamer-r2";
pub const IMAGE_SHA: &str = "89ee0047fca4b46840230472b2a85aa518cfde6e7a556b20ed43eccf14607571";
pub const BOOKING: (&str, &str) = (
    "/home/ubuntu/.codex/diagnostics/horizon-upload-247-staged-680e1173-v1/booking.json",
    "f2716aa9619500bed9e722e9a5de23c80f57203d137f6b937d27ba1a9972919e",
);
pub const LAUNCH: (&str, &str) = (
    "/home/ubuntu/.codex/diagnostics/horizon-upload-247-staged-680e1173-v1/launch.json",
    "0ae7be456361ec2a5870b8ae0907a463cf750ecd07de0b2f45b7252c807e1380",
);
pub const CLAIM: (&str, &str) = (
    "/home/ubuntu/.codex/diagnostics/horizon-upload-247-staged-680e1173-v1/pipeline-claim.json",
    "8ef94d868ee29e47f9777aaaa9ba941df11d176334984e5a00f2e713c4a05b80",
);
pub const PLAN: (&str, &str) = (
    "/var/lib/jetstreamer/horizon247-public-reader-680e1173-v1/epoch-247-plan.json",
    "e9e7234224b04ab9ae03bfa7459344bec37a6bb241c84e98a7e8dbcaa29bdd1e",
);

pub struct Endpoint<'a> {
    pub unit: &'a str,
    pub iid: &'a str,
    pub pid: u32,
    pub ticks: u64,
    pub image: &'a str,
    pub image_sha: &'a str,
    pub cap: u64,
}
pub fn validate(row: &Value) -> Result<()> {
    for (key, (path, sha)) in [
        ("booking", BOOKING),
        ("launch", LAUNCH),
        ("claim", CLAIM),
        ("plan", PLAN),
    ] {
        ensure!(
            row["staged_owner"][key] == json!({"path":path,"sha256":sha}),
            "staged 247 source differs: {key}"
        );
    }
    validate_endpoints(
        row,
        &Endpoint {
            unit: UNIT,
            iid: IID,
            pid: PID,
            ticks: TICKS,
            image: IMAGE,
            image_sha: IMAGE_SHA,
            cap: CAP,
        },
    )
}
pub fn validate_endpoints(row: &Value, owner: &Endpoint<'_>) -> Result<()> {
    validate_delivery_endpoints(row, owner, "247-247")
}

pub fn validate_delivery_endpoints(row: &Value, owner: &Endpoint<'_>, range: &str) -> Result<()> {
    ensure!(
        row["range"] == range
            && row["phase"] == "upload-readback"
            && row["resource_only"] == true
            && row["delivery_resource_only"] == true
            && row["entry_replay"] == false
            && row["ordinary_replay_claim"] == false
            && row["invocation_binding_stable"] == true
            && row["useful_work"]["sufficient_for_rates"] == false,
        "unqualified staged 247 delivery telemetry"
    );
    let mut previous = None;
    for suffix in ["before", "after"] {
        let p = &row[format!("producer_{suffix}")];
        let image = &row[format!("mapped_image_{suffix}")];
        ensure!(
            p == &row[format!("controller_{suffix}")]
                && p["unit"] == owner.unit
                && p["invocation_id"] == owner.iid
                && p["main_pid"] == owner.pid
                && p["control_group"] == format!("/system.slice/{}", owner.unit)
                && p["active_state"] == "active"
                && p["sub_state"] == "running"
                && p["restarts"] == 0
                && p["cgroup"]["gauges"]["memory.max"] == owner.cap
                && p["cgroup"]["gauges"]["memory.swap.max"] == 0,
            "staged 247 endpoints differ"
        );
        let rss = &p["rss"];
        ensure!(
            rss["census_stable"] == true
                && rss["error"].is_null()
                && rss["aggregate_rss_bytes"].as_u64().is_some_and(|v| v > 0)
                && rss["processes"].as_array().is_some_and(|v| v
                    .iter()
                    .filter(|item| item["pid"] == owner.pid && item["start_ticks"] == owner.ticks)
                    .count()
                    == 1),
            "staged 247 RSS census missing"
        );
        ensure!(
            image["executable"] == owner.image
                && image["sha256"] == owner.image_sha
                && image["pid"] == owner.pid
                && image["mapped_inode"].as_u64().is_some_and(|v| v > 0)
                && image["mapped_device"].as_u64().is_some_and(|v| v > 0),
            "staged 247 mapped image differs"
        );
        let ident = (&image["mapped_inode"], &image["mapped_device"]);
        ensure!(
            previous.is_none_or(|v| v == ident),
            "staged 247 mapped inode replaced"
        );
        previous = Some(ident);
    }
    Ok(())
}

pub fn validate_sample(row: &Value, owner: &super::successor247::Owner) -> Result<()> {
    use super::successor247::{HARD, IMAGE, IMAGE_SHA, UNIT};
    ensure!(
        row["successor_owner"] == owner.proof,
        "successor RSS proof differs"
    );
    let ticks = row["producer_before"]["rss"]["processes"]
        .as_array()
        .context("successor samples")?
        .iter()
        .find(|r| r["pid"] == owner.pid)
        .and_then(|r| r["start_ticks"].as_u64())
        .filter(|x| *x > 0)
        .context("successor start ticks")?;
    validate_endpoints(
        row,
        &Endpoint {
            unit: UNIT,
            iid: &owner.iid,
            pid: owner.pid,
            ticks,
            image: IMAGE,
            image_sha: IMAGE_SHA,
            cap: HARD,
        },
    )
}
