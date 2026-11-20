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
    "/var/lib/jetstreamer/horizon261-native-launch-tmpfs-20261120-v3/horizon-native261-launch";

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

fn review_scope(n: &mut Native, r: &Value, self_sha: &str, prepare_only: bool) -> Result<()> {
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
    native257::controller_scope(r)?;
    units::affinity(r)?;
    let source = binding(&r["source_publication"])?.sealed()?;
    native257::publication::validate_native(
        n,
        &source,
        &Bound::new(GUARD, GUARD_SHA),
        self_sha,
        prepare_only,
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

fn evaluate(n: &mut Native, r: &Value, source: &Bound) -> Result<(Value, peer_window::Window)> {
    let initial = funding::current(n, r, false)?;
    let context = json!({"epoch":261,"boot_id":initial["boot_id"],"review":source,
        "actual_current_memory":initial["actual_current_memory"]});
    let mut peers = peer_window::capture(n, r, &context)?;
    n.deadline = Some(n.deadline.context("admission clock")?.min(peers.limit));
    let current = funding::current(n, r, false)?;
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
    Ok((value, peers))
}
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
fn check_sandbox(v: &Value) -> Result<()> {
    ensure!(
        v["PrivateDevices"] == "yes"
            && v["WorkingDirectory"] == ROOT
            && v["ProtectControlGroups"] == "yes"
            && v["RestrictAddressFamilies"] == "AF_UNIX"
            && v["OOMPolicy"] == "kill"
            && v["OOMScoreAdjust"] == "1000"
            && v["AmbientCapabilities"] == ""
            && text(v, "InaccessiblePaths")?
                .split_whitespace()
                .collect::<BTreeSet<_>>()
                == BTreeSet::from(["/tmp", "/var/tmp", "/dev/shm"]),
        "261 producer sandbox changed"
    );
    Ok(())
}
fn prepared_transition(
    _: &Bound,
    gate: &Bound,
    current: &Bound,
    old: &Value,
    new: &Value,
) -> Result<()> {
    let prepared = publication::prepared_artifacts(old)?;
    ensure!(
        gate == current
            && prepared["launcher"]["artifact"] == json!(gate)
            && prepared == publication::prepared_artifacts(new)?,
        "prepared 261 images or source changed"
    );
    Ok(())
}
fn refreshed_capacity(n: &mut Native, r: &Value, held: bool) -> Result<Value> {
    let mut latest = funding::current(n, r, held)?;
    latest["protected_existing_floor_bytes"] =
        latest["capacity"]["protected_existing_floor_bytes"].clone();
    Ok(latest)
}
fn package(attempt: &str, kind: &str) -> PathBuf {
    PathBuf::from(format!(
        "/var/lib/jetstreamer/horizon-native261-{kind}-{attempt}"
    ))
}
fn qualify(r: &Value) -> Result<bool> {
    match r["operation"].as_str() {
        Some("qualify-guard") => Ok(true),
        Some("native-cold") => Ok(false),
        _ => bail!("unknown native261 operation"),
    }
}
fn prestart(r: &Value) -> Result<()> {
    let qual = qualify(r)?;
    let lifecycle = binding(&r["prestart_qualification"])?.sealed()?;
    ensure!(
        lifecycle["schema"] == "horizon-native261-prestart-qualification-v1"
            && lifecycle["Main_accepted"] == true
            && lifecycle["harness"] == json!(Bound::new(HARNESS, HARNESS_SHA))
            && lifecycle["guard"] == r["guard"]
            && lifecycle["source_publication"] == r["source_publication"]
            && lifecycle["complete_live_terminal_and_inactive_consumers_accepted"] == true
            && lifecycle["first_guard_required_before_snapshot"] == true
            && lifecycle["native_runtime_qualified"] == false,
        "native prestart lifecycle missing"
    );
    no_authority(&lifecycle)?;
    for k in [
        "fleet",
        "observer",
        "inactive_status",
        "terminal_retention",
        "startup_gate",
    ] {
        binding(&lifecycle["evidence"][k])?.sealed()?;
    }
    if !qual {
        let qualification = binding(&r["protective_stop_qualification"])?.sealed()?;
        stop::accepted(&qualification)?;
        retire::validate_capture(&binding(&qualification["capture"])?.sealed()?)?;
        let retirement = binding(&qualification["retirement"])?.sealed()?;
        ensure!(
            retirement["capture"] == qualification["capture"]
                && retirement["all_four_links_removed"] == true
                && retirement["kernel_drained"] == true
                && retirement["token_absent"] == true
                && retirement["after"]
                    .as_object()
                    .is_some_and(|v| v.len() == 4),
            "incomplete qualification retirement"
        );
    }
    Ok(())
}
/// Authenticate the original on-host startup graph without taking another resource sample.
pub fn validate_saved_handoff(path: &Path, sha: &str) -> Result<Value> {
    ensure!(
        path.starts_with("/var/lib/jetstreamer"),
        "handoff namespace"
    );
    trusted_parents(path)?;
    let h = Bound::new(path, sha).json()?;
    handoff::reopen(&h)?;
    Ok(h)
}
pub fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 4 && args[1] == "validate-handoff" {
        let h = validate_saved_handoff(Path::new(&args[2]), &args[3])?;
        println!(
            "{}",
            json!({"epoch":261,"invocation_id":h["invocation_id"],"historical_startup_accepted":true,"entry_replay":false,"admission_authorized":false})
        );
        return Ok(());
    }
    ensure!(
        args.len() == 6
            && matches!(
                args[1].as_str(),
                "prepare" | "admit" | "launch" | "qualify-guard" | "retire-qualification"
            ),
        "usage: horizon-native261-launch prepare|admit|launch|qualify-guard|retire-qualification REVIEW_OR_CAPTURE SHA256 SELF_SHA256 NEW_EVIDENCE_DIRECTORY"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0
            && fs::canonicalize("/proc/self/exe")? == Path::new(LAUNCHER)
            && hex(&args[4], 64)
            && hash(Path::new("/proc/self/exe"))? == args[4],
        "sealed launcher identity"
    );
    let rf = Bound::new(&args[2], &args[3]);
    let r = rf.sealed()?;
    let root = PathBuf::from(&args[5]);
    ensure!(
        root.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && root
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-native261-execution-")),
        "execution namespace"
    );
    absent(&root)?;
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
    let result = (|| {
        if args[1] == "retire-qualification" {
            return retire::run(&mut n, &rf, &r);
        }
        review_scope(&mut n, &r, &args[4], args[1] == "prepare")?;
        if args[1] == "prepare" {
            return units::prepare(&mut n, &r, &rf, &args[4]);
        }
        ensure!(
            args[1] == "admit" || (args[1] == "qualify-guard") == qualify(&r)?,
            "operation mismatch"
        );
        if args[1] != "admit" {
            prestart(&r)?;
        }
        let (a, peers) = evaluate(&mut n, &r, &rf)?;
        if args[1] == "admit" {
            println!(
                "{}",
                serde_json::to_string(&save_json(&n.root, "admission.json", &a)?)?
            );
            Ok(())
        } else {
            startup::run(&mut n, &r, &args[4], &a, Some(peers))
        }
    })();
    if let Err(ref e) = result {
        let _ = save_json(
            &n.root,
            "failure.json",
            &json!({"error":format!("{e:#}"),"automatic_retry":false,"remote_mutations":false}),
        );
    }
    result
}

const STOP_CAPTURE: &str = "horizon-native261-protective-stop-capture-v1";

const STOP_ACCEPTED: &str = "horizon-native261-protective-stop-qualification-v1";

const STOP_RETIRED: &str = "horizon-native261-qualification-unit-retirement-v1";

const STOP_REQUEST: &str = "horizon261-native-guard-stop-request-v1";
