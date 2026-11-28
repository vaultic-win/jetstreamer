//! Device-aware fleet admission for the bounded epoch 261 bootstrap.
use super::*;
mod funding;
use native257::{process_ticks, publication};
mod first_guard {
    include!("../../native265-launch/src/first_guard.rs");
}
mod handoff {
    include!("native257/handoff.rs");
}
mod mount_proof;
mod retire {
    include!("native257/retire.rs");
}
mod startup {
    include!("native257/startup.rs");
}
mod stop {
    include!("../../native265-launch/src/qualification.rs");
}
mod units {
    include!("native257/units.rs");
}
#[cfg(test)]
use mount_proof::sample_fixture;
use mount_proof::{check_devices, check_mount_sample};
mod profile {
    pub(super) const ROOT: &str = "/run/horizon261-native-cold-v1";
    pub(super) const FILESYSTEM: &str = "/var/lib/jetstreamer";
}
#[path = "../../horizon261-native-input/src/tmpfs.rs"]
mod tmpfs;
use profile::{FILESYSTEM, ROOT};

pub(super) const UNIT: &str = "horizon-261-native-input-20261120-v1.service";
pub(super) const GUARD_UNIT: &str = "horizon-native261-protective-v1.service";
const TIMER: &str = "horizon-native261-protective-v1.timer";
pub(super) const MEMORY: u64 = 192_000_000_000;
const ROOT_CAP: u64 = 124 << 30;
pub(super) const DISK_RECEIPTS: u64 = 256 << 20;
const GUARD_MEMORY: u64 = 256 << 20;
pub(super) const CONTROLLER_MEMORY: u64 = 256 << 20;
const INPUT: &str =
    "/var/lib/jetstreamer/horizon261-native-input-tmpfs-20261120-v1/horizon261-native-input";
const INPUT_SHA: &str = "b657cbaa98f543bb40fd9d01786ae0747ef30f4d2ed4727d81469461ea02d899";
const GUARD: &str =
    "/var/lib/jetstreamer/horizon261-native-guard-tmpfs-20261120-v1/horizon261-native-guard";
const GUARD_SHA: &str = "b11fc491490a797ae874d4406e68dd01bdcd5486b486a8b44e3635e66fce8f51";
const PACKET: &str =
    "/var/lib/jetstreamer/horizon261-bootstrap-measure-3cbb2796-v137-v1/inputs.json";
const PACKET_SHA: &str = "9d36d766ab81ac0f831dc1af81198bef3f67ec7ad47f05d1541629d0916bf385";
const WORKER: &str = "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-historical-worker-v1-7-15";
const WORKER_SHA: &str = "c3b2c33420bcf6b6809d7f0b43309e7d57d2791a88e2d4074d21d4f636c521e4";
const LAUNCHER: &str =
    "/var/lib/jetstreamer/horizon261-native-launch-tmpfs-20261122-v10/horizon-native261-launch";

const TOKEN_SCHEMA: &str = "horizon-native261-first-guard-token-v1";
const PLAN_SCHEMA: &str = "horizon-native261-startup-plan-v1";
const HANDOFF_SCHEMA: &str = "horizon-native261-guarded-startup-v1";
const ADMISSION_SCHEMA: &str = "horizon-native261-current-fleet-admission-v1";
const STOP_INTENT: &str = "horizon261-native-guard-stop-intent-v1";
const PREPARED_SCHEMA: &str = "horizon-native261-prepared-units-v1";
const PLAN_PREFIX: &str = "horizon-native261-startup-plan-";
const PLAN_SHA_ENV: &str = "JETSTREAMER_EPOCH261_STARTUP_PLAN_SHA256";
const GUARD_SHA_ENV: &str = "HORIZON261_GUARD_PLAN_SHA256";
const PLAN_ENV: &str = "JETSTREAMER_EPOCH261_STARTUP_PLAN";

const EPOCH: u64 = 261;
const RETENTION_DESCRIPTION_EPOCH: u64 = EPOCH;
const RETENTION: &str = "horizon-native261-terminal-retention.target";
const TOKENS: &str = "/var/lib/jetstreamer/horizon-native261-startup-tokens";
const SLOT: u64 = 112_751_208;
const SNAPSHOT_SHA: &str = "5e84f74696d1f3100650e134fb91487d3e083c374a3262b05f67378b9b1c8256";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const HARNESS: &str = INPUT;
const HARNESS_SHA: &str = INPUT_SHA;
const RESERVATION: u64 = DISK_RECEIPTS;
const SCRATCH: u64 = ROOT_CAP;
const EXPECTED_FILESYSTEM: &str = FILESYSTEM;
const PRODUCER_SANDBOX: &str = "WorkingDirectory=/run/horizon261-native-cold-v1\nInaccessiblePaths=/tmp /var/tmp /dev/shm\nPrivateDevices=yes\nProtectControlGroups=yes\nRestrictAddressFamilies=AF_UNIX\nOOMPolicy=kill\nOOMScoreAdjust=1000\nAmbientCapabilities=\n";
const STOP_CAPTURE: &str = "horizon-native261-protective-stop-capture-v1";

const STOP_ACCEPTED: &str = "horizon-native261-protective-stop-qualification-v1";

const STOP_RETIRED: &str = "horizon-native261-qualification-unit-retirement-v1";

const STOP_REQUEST: &str = "horizon261-native-guard-stop-request-v1";

const PRIOR_PREPARATION: (&str, &str) = (
    "/var/lib/jetstreamer/horizon-native261-prepared-host-stop-1259df1f-v1/prepared.json",
    "71de86ca05fd28b38d6f1127ce04a0216f80444c6982cd0c962d9b795a4bdaf0",
);
const PRIOR_LAUNCHER: (&str, &str) = (
    "/var/lib/jetstreamer/horizon261-native-launch-tmpfs-20261120-v3/horizon-native261-launch",
    "12b14dad4e1465bc22a6466adee317f3059ae66e54106a81c4758b724646a2ba",
);
const PRIOR_LAUNCHER_COMMIT: &str = "1259df1ff730e684a7b09c05c93d0d82cc3694ff";

const V151_PREPARED: (&str, &str) = (
    "/var/lib/jetstreamer/horizon-native261-prepared-early-guard-v151-v1/prepared.json",
    "b13dddcb78f037901ce0307deca903de10b3f2ff83a4f2f97b9a90902f90bf81",
);
const V151_GATE: (&str, &str) = (
    "/var/lib/jetstreamer/horizon261-native-launch-tmpfs-20261120-v5/horizon-native261-launch",
    "4fc9b06ff47a39ccf7c93b20683f2ecab8a95b6bb3b548d5aec12e3ba323ea17",
);
const V151_GATE_COMMIT: &str = "52df886711c0f700335dd952f73b6379bf513fbc";
const V153_PREPARED: (&str, &str) = (
    "/var/lib/jetstreamer/horizon-native261-prepared-zetted-guard-f648ab35-v153-v1/prepared.json",
    "913d18e9daec9fc23b0a8f6211e498f94f4921cc5c96327b578cd4446cd2154d",
);
const V153_GATE: (&str, &str) = (
    "/var/lib/jetstreamer/horizon261-native-launch-tmpfs-20261120-v7/horizon-native261-launch",
    "80ab4ea99b965f619c1f51b5d64a78389d3d15864f30944fa0876e10d4a140d8",
);
const V153_GATE_COMMIT: &str = "f648ab3547ddef529cb8e2e0de1f30787b8fd87f";

const V160_PREPARED: (&str, &str) = (
    "/var/lib/jetstreamer/horizon-native261-prepared-guard-access-v160-a1/prepared.json",
    "df461018cec8480d1fbe3f48d4379eec615ce3854a1e87891ea43d5707d782c9",
);
const V160_GATE: (&str, &str) = (
    "/var/lib/jetstreamer/horizon261-native-launch-tmpfs-20261121-v9/horizon-native261-launch",
    "16624841facc6c8a37341bffbe692702abfab2cb219832d306c378f2e1008f71",
);
const V160_GATE_COMMIT: &str = "af744d6c80105f3be3242121f04df2beb70ddee7";
pub(super) fn registered_preparation(reference: &Bound, gate: &Bound, commit: &Value) -> bool {
    [
        (V151_PREPARED, V151_GATE, V151_GATE_COMMIT),
        (V153_PREPARED, V153_GATE, V153_GATE_COMMIT),
        (V160_PREPARED, V160_GATE, V160_GATE_COMMIT),
    ]
    .iter()
    .any(|(prepared, launcher, revision)| {
        reference == &Bound::new(prepared.0, prepared.1)
            && gate == &Bound::new(launcher.0, launcher.1)
            && commit == *revision
    })
}
pub(super) fn stop_window(census_us: u64) -> Result<u64> {
    // Include the mandatory pre-start census, the existing five-second peer margin,
    // and five seconds for the one-second first guard, sealing and manager work.
    Ok(census_us
        .checked_add(10_000_000)
        .context("261 pre-start budget overflow")?
        .max(30_000_000))
}

fn permits_predecessor(reference: &Bound, gate: &Bound, source: &Value) -> bool {
    reference == &Bound::new(PRIOR_PREPARATION.0, PRIOR_PREPARATION.1)
        && gate == &Bound::new(PRIOR_LAUNCHER.0, PRIOR_LAUNCHER.1)
        && *source == PRIOR_LAUNCHER_COMMIT
        || registered_preparation(reference, gate, source)
}

include!("native261/controller.rs");

#[cfg(test)]
mod v151_window_tests {
    use super::*;
    #[test]
    fn prepared_guard_access_graph_accepts_only_the_v9_launcher() {
        let reference = Bound::new(V160_PREPARED.0, V160_PREPARED.1);
        let gate = Bound::new(V160_GATE.0, V160_GATE.1);
        let new = Bound::new(LAUNCHER, "e".repeat(64));
        let roles = |image: &Bound, commit: &str| json!({"artifacts":[{"role":"launcher","artifact":image,"source_commit":commit},{"role":"harness","artifact":Bound::new(HARNESS,HARNESS_SHA),"source_commit":"a".repeat(40)},{"role":"guard","artifact":Bound::new(GUARD,GUARD_SHA),"source_commit":"b".repeat(40)}]});
        let current = roles(&new, &"c".repeat(40));
        let previous = roles(&gate, V160_GATE_COMMIT);
        prepared_transition(&reference, &gate, &new, &previous, &current).unwrap();
        assert!(
            prepared_transition(
                &reference,
                &gate,
                &new,
                &roles(&gate, V153_GATE_COMMIT),
                &current
            )
            .is_err()
        );
        assert!(
            prepared_transition(
                &Bound::new(V153_PREPARED.0, V153_PREPARED.1),
                &gate,
                &new,
                &previous,
                &current
            )
            .is_err()
        );
    }
    #[test]
    fn v153_preparation_requires_its_original_controller() {
        let prepared = Bound::new(V153_PREPARED.0, V153_PREPARED.1);
        let gate = Bound::new(V153_GATE.0, V153_GATE.1);
        assert!(registered_preparation(
            &prepared,
            &gate,
            &json!(V153_GATE_COMMIT)
        ));
        assert!(!registered_preparation(
            &prepared,
            &gate,
            &json!(V151_GATE_COMMIT)
        ));
        let unrelated = Bound::new(V151_PREPARED.0, V151_PREPARED.1);
        assert!(!registered_preparation(
            &unrelated,
            &gate,
            &json!(V153_GATE_COMMIT)
        ));
    }

    #[test]
    fn only_the_original_v151_preparation_and_unchanged_images_transfer() {
        let evidence: Value =
            serde_json::from_str(include_str!("fixtures/native261-v151-window.json")).unwrap();
        let reference = binding(&evidence["preparation"]).unwrap();
        let previous = binding(&evidence["preparation_gate"]).unwrap();
        let current = Bound::new(LAUNCHER, "c".repeat(64));
        let roles = |gate: &Bound, commit: &str| {
            json!({"artifacts":[
            {"role":"launcher","artifact":gate,"source_commit":commit},
            {"role":"guard","artifact":Bound::new(GUARD,GUARD_SHA),"source_commit":"9d9967df60eeb17d862ec08c9d5254de1cb3e248"},
            {"role":"harness","artifact":Bound::new(INPUT,INPUT_SHA),"source_commit":"9d9967df60eeb17d862ec08c9d5254de1cb3e248"}]})
        };
        let old = roles(&previous, V151_GATE_COMMIT);
        let new = roles(&current, &"d".repeat(40));
        prepared_transition(&reference, &previous, &current, &old, &new).unwrap();
        let other = Bound::new(&reference.path, "a".repeat(64));
        assert!(prepared_transition(&other, &previous, &current, &old, &new).is_err());
        assert!(
            prepared_transition(
                &reference,
                &previous,
                &current,
                &roles(&previous, &"b".repeat(40)),
                &new
            )
            .is_err()
        );
        let mut altered = new;
        altered["artifacts"][1]["artifact"]["sha256"] = json!("e".repeat(64));
        assert!(prepared_transition(&reference, &previous, &current, &old, &altered).is_err());
        assert_eq!(stop_window(100).unwrap(), 30_000_000);
        assert!(stop_window(u64::MAX).is_err());
    }
}

include!("native261/preparation_tests.rs");
