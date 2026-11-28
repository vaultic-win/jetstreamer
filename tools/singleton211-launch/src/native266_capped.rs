//! First-guard admission for epoch 266's capped worker on its own bounded tmpfs.
use super::*;

#[path = "../../horizon266-native-input/src/capped_site.rs"]
mod site;
pub(crate) use site::{GUARD_UNIT, UNIT};
use site::{ROOT, TOKENS, WORKER, WORKER_SHA};
mod profile {
    pub(super) use super::site::ROOT;
    pub(super) const FILESYSTEM: &str = "/var/lib/jetstreamer";
}
use profile::FILESYSTEM;
mod tmpfs {
    pub(crate) const BYTES: u64 = 128 << 30;
    pub(crate) const INODES: u64 = 1_048_576;
    const SOURCE: &str = "horizon266-capped-native-cold";
    include!("../../horizon261-native-input/src/mount.rs");
}
const INPUT: &str = site::HARNESS;
const INPUT_SHA: &str = "72f04be574d9f81a0d0e610392ae9b53aed171029c2ea0e81bfd34a4919f9bac";
const GUARD: &str =
    "/var/lib/jetstreamer/horizon266-capped-native-input-v200-a1/horizon266-native-guard";
const GUARD_SHA: &str = "e21d62171ad35efdba9c83e86da25092ff7d2ad9a88507b86eb9bf51d9b8072a";
const PACKET: &str = "/var/lib/jetstreamer/horizon266-capped-cold-inputs-v200-a2/inputs.json";
const PACKET_SHA: &str = "124212ab9f62ae6ea30998b02955a0530b2b56de3c2a1339a3b5204b6fe53a8a";
const LAUNCHER: &str =
    "/var/lib/jetstreamer/horizon266-capped-launch-v201-a1/horizon-native266-capped-launch";
const TIMER: &str = "horizon-native266-capped-protective-v1.timer";
const RETENTION: &str = "horizon-native266-capped-retention.target";
const MEMORY: u64 = 192_000_000_000;
const ROOT_CAP: u64 = 124 << 30;
const DISK_RECEIPTS: u64 = 256 << 20;
const CONTROLLER_MEMORY: u64 = 256 << 20;
const PRODUCER_SANDBOX: &str = "WorkingDirectory=/run/horizon266-capped-native-cold-v1\nInaccessiblePaths=/tmp /var/tmp /dev/shm\nPrivateDevices=yes\nProtectControlGroups=yes\nRestrictAddressFamilies=AF_UNIX\nOOMPolicy=kill\nOOMScoreAdjust=1000\nAmbientCapabilities=\nStandardOutput=journal\nStandardError=journal\nLogRateLimitIntervalSec=30s\nLogRateLimitBurst=100\n";

pub(super) fn checked_review(r: &Value) -> Result<()> {
    let acceptance = Bound::new(
        "/home/ubuntu/.codex/diagnostics/horizon266-capped-fit-check-v201-a1/completion.json",
        "acd8bff7ee1e5a9d8e8ac890a0f69aa99e26222abbe08eb2f439aa98e902b2f3",
    );
    ensure!(
        r["capped_cold_fit"] == json!(acceptance)
            && r["guard"] == json!(Bound::new(GUARD, GUARD_SHA))
            && r["epoch"] == 266
            && text(r, "attempt")?.starts_with("capped-"),
        "unregistered capped profile"
    );
    let fit = binding(&acceptance.json()?["measurement"])?.json()?;
    ensure!(
        fit["admission_authorized"] == false
            && fit["producer_started"] == false
            && fit["assessment"]["capacity"]["remaining_228"] == 86_926_258_176u64,
        "capped source qualification differs"
    );
    Ok(())
}

mod funding {
    use super::*;
    pub(super) fn current(n: &mut Native, r: &Value, held: bool) -> Result<Value> {
        checked_review(r)?;
        let controller = text(r, "controller_unit")?;
        let iid = std::env::var("INVOCATION_ID")?;
        let owner = n.show(controller)?;
        ensure!(
            fs::read_to_string("/proc/self/cgroup")?.trim()
                == format!("0::/system.slice/{controller}")
                && text(&owner, "MainPID")?.parse::<u32>()? == std::process::id()
                && owner["Type"] == "exec",
            "unexpected controller"
        );
        live::finite_owner(&owner, controller, &iid, CONTROLLER_MEMORY)?;
        let fleet = binding(&r["fleet"])?;
        let f = fleet.json()?;
        let trace = native266_full::peer261::trace().json()?;
        ensure!(
            r["reservation_ledger"] == trace["original_ledger"]
                && r["observer"]
                    == json!(Bound::new(
                        text(&f, "observer_receipt")?,
                        text(&f, "observer_sha256")?
                    ))
                && units::affinity(r)? == "32 33 34 35 36 37 38 39"
                && r["control_units"]
                    == json!([{"unit":controller,"maximum_memory_bytes":CONTROLLER_MEMORY}]),
            "capped epoch 266 census, controls or CPUs differ"
        );
        let device = fs::metadata(FILESYSTEM)?.dev();
        let mount = pristine(device)?;
        let mut v = native266_full::capped_cold::assess(n, &fleet, controller, held)?;
        let uploader = &v["uploader"];
        let pid = text(uploader, "MainPID")?;
        let affinity = fs::read_to_string(format!("/proc/{pid}/status"))?;
        ensure!(
            affinity
                .lines()
                .find_map(|s| s.strip_prefix("Cpus_allowed_list:"))
                .map(str::trim)
                == Some("48-55")
                && uploader["AllowedCPUs"] == "48-55"
                && uploader["CPUQuotaPerSecUSec"] == "4s"
                && r["reviewed_cpu_overlap"] == json!({}),
            "uploader CPU reservation differs"
        );
        if held {
            let actor = n.show(UNIT)?;
            let invocation = text(&actor, "InvocationID")?;
            live::finite_owner(&actor, UNIT, invocation, MEMORY)?;
            gate::held_image(text(&actor, "MainPID")?.parse()?, invocation, UNIT, HARNESS)?;
        }
        let after = n.show(controller)?;
        live::same_owner(&owner, &after)?;
        live::finite_owner(&after, controller, &iid, CONTROLLER_MEMORY)?;
        ensure!(
            fs::metadata(FILESYSTEM)?.dev() == device && pristine(device)? == mount,
            "scratch or receipt device changed"
        );
        v["controller"] = after;
        v["disk_device"] = json!(device);
        v["disk_filesystem"] = json!(FILESYSTEM);
        v["tmpfs"] = mount;
        v["boot_id"] = json!(fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim());
        n.check()?;
        Ok(v)
    }
}
include!("native266_common.rs");

#[cfg(test)]
mod capped_tests {
    use super::*;
    #[test]
    fn original_guard_and_plain_attempt_cannot_select_capped_funding() {
        let original = json!({"epoch":266,"attempt":"capped-stop","guard":Bound::new(super::super::native266::UNIT,"a".repeat(64))});
        assert!(checked_review(&original).is_err());
        assert_ne!(UNIT, crate::native266::UNIT);
        assert!(
            PRODUCER_SANDBOX
                .lines()
                .any(|line| line == format!("WorkingDirectory={ROOT}"))
        );
        assert!(tmpfs::mount_row(&format!("9 1 0:9 / {ROOT} rw,nosuid,nodev,noexec - tmpfs horizon266-capped-native-cold rw,noswap"),libc::makedev(0,9),true).is_ok());
        assert!(tmpfs::mount_row(&format!("9 1 0:9 / {ROOT} rw,nosuid,nodev,noexec - tmpfs horizon266-native-cold rw,noswap"),libc::makedev(0,9),true).is_err());
    }
}
