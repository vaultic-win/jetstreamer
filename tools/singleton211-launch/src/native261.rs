//! Device-aware fleet admission for the bounded epoch 261 bootstrap.
use super::*;
mod funding;
mod profile {
    pub(super) const ROOT: &str = "/run/horizon261-native-cold-v1";
    pub(super) const FILESYSTEM: &str = "/var/lib/jetstreamer";
}
#[path = "../../horizon261-native-input/src/tmpfs.rs"]
mod tmpfs;
use profile::{FILESYSTEM, ROOT};

const UNIT: &str = "horizon-261-native-input-20261120-v1.service";
const GUARD_UNIT: &str = "horizon-native261-protective-v1.service";
const TIMER: &str = "horizon-native261-protective-v1.timer";
const MEMORY: u64 = 192_000_000_000;
const ROOT_CAP: u64 = 124 << 30;
const DISK_RECEIPTS: u64 = 256 << 20;
const GUARD_MEMORY: u64 = 256 << 20;
const CONTROLLER_MEMORY: u64 = 256 << 20;
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
    "/var/lib/jetstreamer/horizon261-native-launch-tmpfs-20261120-v1/horizon-native261-launch";

fn pristine(disk: u64) -> Result<Value> {
    let mount = tmpfs::observe(true)?;
    ensure!(
        mount.device != disk
            && mount.bytes == 0
            && mount.free_inodes >= tmpfs::INODES - 1
            && fs::read_dir(ROOT)?.next().is_none(),
        "261 scratch must be an independent empty tmpfs"
    );
    Ok(
        json!({"root":ROOT,"device":mount.device,"inode":mount.inode,"bytes":tmpfs::BYTES,
        "inodes":tmpfs::INODES,"free_inodes":mount.free_inodes,"used_bytes":mount.bytes,
        "maximum_root_physical_bytes":ROOT_CAP,"minimum_free_bytes":tmpfs::BYTES-ROOT_CAP,
        "minimum_free_inodes":4096,"charged_within_memory_max":true}),
    )
}

fn review_scope(n: &mut Native, r: &Value, self_sha: &str) -> Result<()> {
    no_authority(r)?;
    ensure!(
        r["schema"] == "horizon-native261-launch-review-v1"
            && r["epoch"] == 261
            && r["Main_accepted"] == true
            && r["single_campaign_controller_confirmed"] == true
            && matches!(
                r["operation"].as_str(),
                Some("native-cold" | "qualify-guard")
            )
            && launch::safe_attempt(text(r, "attempt")?)
            && r["guard"] == json!(Bound::new(GUARD, GUARD_SHA)),
        "unaccepted 261 review"
    );
    let pid = num(r, "main_controller_pid")?;
    ensure!(
        pid > 1 && r["main_controller_start_ticks"] == native257::process_ticks(pid)?,
        "changed campaign controller"
    );
    let source = binding(&r["source_publication"])?.sealed()?;
    native257::publication::validate_native(
        n,
        &source,
        &Bound::new(GUARD, GUARD_SHA),
        self_sha,
        false,
        &native257::publication::SourceProfile {
            epoch: 261,
            harness: Bound::new(INPUT, INPUT_SHA),
            worker: Bound::new(WORKER, WORKER_SHA),
        },
    )?;
    let verified: Value = serde_json::from_slice(&n.run(INPUT, &["--validate-inputs"])?)?;
    ensure!(
        verified["schema"] == "horizon261-sealed-input-validation-v1"
            && verified["input_packet_sha256"] == PACKET_SHA
            && verified["bootstrap_slot"] == 112_751_208
            && verified["measured_identities_accepted"] == true
            && verified["worker_started"] == false
            && verified["replay_launch_authorized"] == false,
        "261 measured input validation differs"
    );
    Ok(())
}

fn evaluate(n: &mut Native, r: &Value, source: &Bound) -> Result<Value> {
    let initial = funding::current(n, r)?;
    let context = json!({"epoch":261,"boot_id":initial["boot_id"],"review":source,
        "actual_current_memory":initial["actual_current_memory"]});
    let mut peers = peer_window::capture(n, r, &context)?;
    n.deadline = Some(n.deadline.context("admission clock")?.min(peers.limit));
    let current = funding::current(n, r)?;
    ensure!(
        current["tmpfs"] == initial["tmpfs"]
            && current["disk_device"] == initial["disk_device"]
            && current["boot_id"] == initial["boot_id"],
        "capacity devices or boot changed"
    );
    peers.verify(n)?;
    let issued = now()?;
    let clock = mono()?;
    let remaining = peers
        .limit
        .checked_sub(clock)
        .context("original guards expired")?
        / 1_000_000;
    let valid = remaining.min(60);
    ensure!(valid > 0, "no current owner guard window remains");
    n.check()?;
    let mut value = json!({"schema":"horizon-native261-current-fleet-admission-v1","epoch":261,"mode":"native-cold",
        "operation":r["operation"],"unit":UNIT,"guard_unit":GUARD_UNIT,"timer":TIMER,"admitted":true,
        "harness":Bound::new(INPUT,INPUT_SHA),"guard":Bound::new(GUARD,GUARD_SHA),
        "worker":Bound::new(WORKER,WORKER_SHA),"input_packet":Bound::new(PACKET,PACKET_SHA),
        "maximum_memory_bytes":MEMORY,"maximum_root_physical_bytes":ROOT_CAP,"candidate_incremental_peak_bytes":DISK_RECEIPTS,
        "protected_existing_floor_bytes":current["capacity"]["protected_existing_floor_bytes"],
        "disk_filesystem":FILESYSTEM,"disk_device":current["disk_device"],"tmpfs":current["tmpfs"],
        "boot_id":current["boot_id"],"source_publication":r["source_publication"],"review":source,"fleet":r["fleet"],
        "observer":r["observer"],"reservation_ledger":r["reservation_ledger"],"century":r["century"],
        "actual_current_memory":current["actual_current_memory"],"capacity":current,"cpu_affinity":r["cpu_affinity"],
        "peer_window":peers.receipt,"original_peer_deadline_monotonic_us":peers.limit,
        "issued_unix_seconds":issued,"expires_unix_seconds":issued.checked_add(valid).context("admission expiry")?,
        "guard_token_issued":false,"scratch_release_authorized":false});
    deny_authority(&mut value);
    Ok(value)
}
/// Write a short-lived admission only after the original guarded owner census and
/// both live devices agree. The controller still needs the candidate's actual first fire.
pub fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 6 && args[1] == "admit",
        "usage: horizon-native261-launch admit REVIEW SHA256 SELF_SHA256 NEW_EVIDENCE_DIRECTORY"
    );
    let launcher = Bound::new(LAUNCHER, &args[4]);
    ensure!(
        unsafe { libc::geteuid() } == 0 && fs::canonicalize("/proc/self/exe")? == launcher.path,
        "sealed epoch 261 controller required"
    );
    launcher.artifact()?;
    let source = Bound::new(&args[2], &args[3]);
    let review = source.sealed()?;
    let root = PathBuf::from(&args[5]);
    ensure!(
        root.parent() == Some(Path::new(FILESYSTEM))
            && root
                .file_name()
                .and_then(|x| x.to_str())
                .is_some_and(|x| x.starts_with("horizon-native261-execution-")),
        "261 evidence namespace"
    );
    trusted_parents(&root)?;
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    let mut n = Native {
        root,
        counter: 0,
        deadline: Some(
            mono()?
                .checked_add(180_000_000)
                .context("controller deadline")?,
        ),
    };
    let result = (|| -> Result<()> {
        review_scope(&mut n, &review, &args[4])?;
        let admission = evaluate(&mut n, &review, &source)?;
        let b = save_json(&n.root, "admission.json", &admission)?;
        println!("{}", serde_json::to_string(&b)?);
        Ok(())
    })();
    if let Err(ref err) = result {
        save_json(
            &n.root,
            "failure.json",
            &json!({"error":format!("{err:#}"),"guard_token_issued":false,"remote_mutations":false}),
        )?;
    }
    result
}
