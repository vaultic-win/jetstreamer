//! Root control of the measured epoch 257 bootstrap. Its worker never executes entries.
use super::*;
#[path = "../../native265-launch/src/first_guard.rs"]
mod first_guard;
mod handoff;
mod legacy;
use legacy::prepared_transition;
mod retire;
mod startup;
#[cfg(test)]
#[path = "native257/stop_sandbox.rs"]
mod stop_sandbox;
mod units;
const EXPECTED_FILESYSTEM: &str = ROOT;
#[path = "../../native265-launch/src/qualification.rs"]
mod stop;

pub(crate) mod publication;

pub(super) const UNIT: &str = "horizon-257-native-input-20261120-v1.service";
pub(super) const GUARD_UNIT: &str = "horizon-native257-protective-v1.service";
pub(super) const TIMER: &str = "horizon-native257-protective-v1.timer";
const RETENTION: &str = "horizon-native257-terminal-retention.target";
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/native-input257-selected-20261120-v1";
const TOKENS: &str = "/var/lib/jetstreamer/horizon-native257-startup-tokens";
pub(super) const HARNESS: &str =
    "/var/lib/jetstreamer/horizon257-native-input-limited-20261120-v1/horizon257-native-input";
const HARNESS_SHA: &str = "b8f52e2de7bf4f6232ea66137bb148bb6fb5b3342ce354379f4c237c70c39fce";
const ORIGINAL_GUARD: &str =
    "/var/lib/jetstreamer/horizon257-native-guard-limited-20261120-v1/horizon257-native-guard";
const ORIGINAL_GUARD_SHA: &str = "cd20c10244bb4a3a9818a6e459163be1f596165e859b2783f76a2507b8425369";
const GUARD: &str =
    "/var/lib/jetstreamer/horizon257-native-guard-reap-v219/horizon257-native-guard";
const GUARD_SHA: &str = "858ca59d690c42ddcce78f06c1d95cfa566f1cb240f5f378d55ec490eeea6543";

/// Original handoffs bind the first guard in their startup plan. Later
/// handoffs also carry its identity for historical sample and journal readers.
pub fn saved_guard(handoff: &Value) -> Result<(&'static str, &'static str)> {
    match handoff.get("guard") {
        None => Ok((ORIGINAL_GUARD, ORIGINAL_GUARD_SHA)),
        Some(value) if *value == json!(Bound::new(GUARD, GUARD_SHA)) => Ok((GUARD, GUARD_SHA)),
        _ => bail!("unregistered epoch 257 guard"),
    }
}
const WORKER: &str = "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-historical-worker-v1-7-15";
const WORKER_SHA: &str = "c3b2c33420bcf6b6809d7f0b43309e7d57d2791a88e2d4074d21d4f636c521e4";
const PACKET: &str =
    "/var/lib/jetstreamer/horizon257-native-bootstrap-inputs-20261120-v1/inputs.json";
const PACKET_SHA: &str = "d325e670fecbd4073ca86bd52afefd99ac992c7d0392de1a3e82c9dcb3e1d40f";
const SNAPSHOT_SHA: &str = "3e2b236f2cba29fbfe40f39f133fe9c845df9280e3fc6dd1cb70e4e018a4744d";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const MEMORY: u64 = 120_000_000_000;
const SCRATCH: u64 = 160_000_000_000;
const RESERVATION: u64 = 256_000_000_000;
const SLOT: u64 = 111_022_755;
const LAUNCHER: &str =
    "/var/lib/jetstreamer/horizon257-native-launch-closed266-v21/horizon-native257-launch";
fn package(attempt: &str, kind: &str) -> PathBuf {
    PathBuf::from(format!(
        "/var/lib/jetstreamer/horizon-native257-{kind}-{attempt}"
    ))
}
fn qualify(r: &Value) -> Result<bool> {
    match r["operation"].as_str() {
        Some("qualify-guard") => Ok(true),
        Some("native-cold") => Ok(false),
        _ => bail!("unknown native257 operation"),
    }
}
pub(super) fn controller_scope(r: &Value) -> Result<()> {
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    ensure!(r["boot_id"] == boot.trim(), "boot changed");
    fresh(num(r, "recorded_unix_seconds")?, now()?, 300)?;
    let pid = num(r, "main_controller_pid")?;
    ensure!(
        pid > 1 && r["main_controller_start_ticks"] == process_ticks(pid)?,
        "campaign controller replaced"
    );
    Ok(())
}
fn review_scope(n: &mut Native, r: &Value, self_sha: &str, prepare_only: bool) -> Result<()> {
    no_authority(r)?;
    ensure!(
        r["schema"] == "horizon-native257-launch-review-v1"
            && r["epoch"] == 257
            && r["Main_accepted"] == true
            && r["single_campaign_controller_confirmed"] == true
            && launch::safe_attempt(text(r, "attempt")?)
            && r["guard"] == json!(Bound::new(GUARD, GUARD_SHA)),
        "unaccepted launch review"
    );
    controller_scope(r)?;
    units::affinity(r)?;
    qualify(r)?;
    publication::validate(
        n,
        &binding(&r["source_publication"])?.sealed()?,
        &Bound::new(GUARD, GUARD_SHA),
        self_sha,
        prepare_only,
    )?;
    let inputs: Value = serde_json::from_slice(&n.run(HARNESS, &["--validate-inputs"])?)?;
    ensure!(
        inputs["schema"] == "horizon257-sealed-input-validation-v1"
            && inputs["input_packet_sha256"] == PACKET_SHA
            && inputs["bootstrap_slot"] == SLOT
            && inputs["measured_identities_accepted"] == true
            && inputs["worker_started"] == false,
        "positive measured inputs changed"
    );
    Ok(())
}
pub(super) fn process_ticks(pid: u64) -> Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    Ok(stat
        .rsplit_once(')')
        .context("proc stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("process start missing")?
        .parse()?)
}
pub(super) fn selected_scenario(r: &Value, fit: &Value) -> Result<&'static str> {
    match (r["full211_capacity"].as_str(), fit.get("full211_handoff")) {
        (Some("full211-booked"), Some(h)) if *h == json!(full211_peer::handoff()) => {
            Ok("limited_native257_with_booked_full211")
        }
        (Some("preserve-full211"), None) => Ok("limited_native257_and_ordinary211"),
        (Some("native257-first"), None) => Ok("limited_native257"),
        _ => bail!("review must select the observed full211 booking disposition"),
    }
}
// A sealed startup plan and guard keep the same floor across every subsequent
// firing. Restore the live full211 allocation credit to its nominal growth
// sum before choosing that floor, including when an inherited floor dominates.
fn startup_floor(c: &Value, scenario: &str) -> Result<u64> {
    let retained = capacity::add(
        num(c, "retained_disk_growth_bytes")?,
        num(c, "allocation_credit_taken_bytes")?,
    )?;
    let nominal = capacity::add(num(c, "century_floor_bytes")?, retained)?;
    let mut floor = num(c, "protected_existing_floor_bytes")?.max(nominal);
    if scenario == "limited_native257_and_ordinary211" {
        floor = capacity::add(floor, super::SCRATCH)?;
    }
    let required = capacity::add(floor, RESERVATION)?;
    let free = num(c, "observed_available_bytes")?;
    ensure!(
        free >= required,
        "native257 nominal floor plus reservation requires {required} bytes, observed {free}"
    );
    Ok(floor)
}

fn current(n: &mut Native, r: &Value, held: bool) -> Result<(Value, Value)> {
    if r.get("closed266_booking").is_some() {
        return native266_full::closed266_for257::current(n, r, held);
    }
    let rf = binding(&r["resource_review"])?;
    let rr = rf.sealed()?;
    for key in [
        "boot_id",
        "fleet",
        "observer",
        "reservation_ledger",
        "century",
        "native265_runtime_growth_release",
        "control_units",
    ] {
        ensure!(rr[key] == r[key], "fleet review binding changed: {key}");
    }
    let fit = native257_fit::evaluate(n, &rr, &rf, held)?;
    let scenario = selected_scenario(r, &fit)?;
    let selected = &fit["scenarios"][scenario];
    ensure!(
        fit["actual_scratch_present"] == true && selected["fits"] == true,
        "current fit failed for {scenario}: {}",
        selected["reason"]
    );
    let floor = startup_floor(&selected["capacity"], scenario)?;
    let cpu = units::cpu_sharing(n, r)?;
    let mut cap = json!({"protected_existing_floor_bytes":floor,"cpu":cpu,"selected_scenario":scenario,"capacity":selected["capacity"],
        "actual_current_memory":fit["actual_current_memory"],"resource_review":rf,"full211_capacity":r["full211_capacity"]});
    if let Some(h) = fit.get("full211_handoff") {
        cap["full211_handoff"] = h.clone();
    }
    Ok((fit, cap))
}
fn admit(
    n: &mut Native,
    r: &Value,
    rf: &Bound,
    select: bool,
) -> Result<(Value, Option<peer_window::Window>)> {
    let qual = qualify(r)?;
    let lifecycle = binding(&r["prestart_qualification"])?.sealed()?;
    ensure!(
        lifecycle["schema"] == "horizon-native257-prestart-qualification-v1"
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
    let (fit, cap) = current(n, r, false)?;
    let fit = save_json(&n.root, "original-fit.json", &fit)?;
    let window = if select && r.get("closed266_booking").is_none() {
        let scope = json!({"epoch":257, "boot_id":r["boot_id"], "actual_current_memory":cap["actual_current_memory"], "review":rf});
        Some(peer_window::select(n, r, &scope)?)
    } else {
        None
    };
    let issued = now()?;
    let mut a = json!({"schema":"horizon-native257-current-fleet-admission-v1","epoch":257,"mode":"native-cold",
        "operation":r["operation"],"unit":UNIT,"maximum_memory_bytes":MEMORY,"candidate_incremental_peak_bytes":RESERVATION,
        "maximum_root_physical_bytes":SCRATCH,"protected_existing_floor_bytes":cap["protected_existing_floor_bytes"],
        "capacity":cap,"original_fit":fit,"actual_current_memory":cap["actual_current_memory"],"admitted":true,
        "harness":Bound::new(HARNESS,HARNESS_SHA),"guard":r["guard"],"worker":Bound::new(WORKER,WORKER_SHA),
        "input_packet":Bound::new(PACKET,PACKET_SHA),"boot_id":r["boot_id"],"source_publication":r["source_publication"],
        "observer":r["observer"],"fleet":r["fleet"],"review":rf,"cpu_affinity":r["cpu_affinity"],"issued_unix_seconds":issued,
        "expires_unix_seconds":issued.checked_add(60).context("clock")?});
    deny_authority(&mut a);
    Ok((a, window))
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
            json!({"epoch":257,"invocation_id":h["invocation_id"],"historical_startup_accepted":true,"entry_replay":false,"admission_authorized":false})
        );
        return Ok(());
    }
    ensure!(
        args.len() == 6
            && matches!(
                args[1].as_str(),
                "prepare" | "admit" | "launch" | "qualify-guard" | "retire-qualification"
            ),
        "usage: horizon-native257-launch prepare|admit|launch|qualify-guard|retire-qualification REVIEW_OR_CAPTURE SHA256 SELF_SHA256 NEW_EVIDENCE_DIRECTORY"
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
                .is_some_and(|s| s.starts_with("horizon-native257-execution-")),
        "execution namespace"
    );
    absent(&root)?;
    trusted_parents(&root)?;
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    let mut n = Native {
        root,
        counter: 0,
        deadline: None,
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
        let (a, window) = admit(&mut n, &r, &rf, args[1] == "qualify-guard")?;
        if args[1] == "admit" {
            println!(
                "{}",
                serde_json::to_string(&save_json(&n.root, "admission.json", &a)?)?
            );
            Ok(())
        } else {
            startup::run(&mut n, &r, &args[4], &a, window)
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

const STOP_CAPTURE: &str = "horizon-native257-protective-stop-capture-v1";

const STOP_ACCEPTED: &str = "horizon-native257-protective-stop-qualification-v1";

const STOP_RETIRED: &str = "horizon-native257-qualification-unit-retirement-v1";

const STOP_REQUEST: &str = "horizon257-native-guard-stop-request-v1";

const EPOCH: u64 = 257;
const TOKEN_SCHEMA: &str = "horizon-native257-first-guard-token-v1";
const PLAN_SCHEMA: &str = "horizon-native257-startup-plan-v1";
const HANDOFF_SCHEMA: &str = "horizon-native257-guarded-startup-v1";
const ADMISSION_SCHEMA: &str = "horizon-native257-current-fleet-admission-v1";
const STOP_INTENT: &str = "horizon257-native-guard-stop-intent-v1";
const PREPARED_SCHEMA: &str = "horizon-native257-prepared-units-v1";
const PLAN_PREFIX: &str = "horizon-native257-startup-plan-";
const PLAN_SHA_ENV: &str = "JETSTREAMER_EPOCH257_STARTUP_PLAN_SHA256";
const GUARD_SHA_ENV: &str = "HORIZON257_GUARD_PLAN_SHA256";
const PLAN_ENV: &str = "JETSTREAMER_EPOCH257_STARTUP_PLAN";

// Preserve the bytes of already sealed 257 definitions.
const RETENTION_DESCRIPTION_EPOCH: u64 = 265;
const PRODUCER_SANDBOX: &str = "PrivateTmp=yes\n";
fn check_sandbox(_: &Value) -> Result<()> {
    Ok(())
}
fn check_devices(_: &Value, _: &Value) -> Result<()> {
    Ok(())
}
fn check_mount_sample(_: &Value, _: &Value) -> Result<()> {
    Ok(())
}
#[cfg(test)]
fn sample_fixture(_: &mut Value, _: &mut Value) {}
fn refreshed_capacity(n: &mut Native, r: &Value, held: bool) -> Result<Value> {
    Ok(current(n, r, held)?.1)
}

#[cfg(test)]
mod floor_tests {
    use super::*;

    #[test]
    fn v148_full211_reallocation_preserves_the_sealed_nominal_floor() {
        let c = |credit: u64, free: u64| {
            let growth = 3_802_005_871_200u64 - credit;
            let floor = 3_908_104_436_088u64.max(280_581_611_288 + growth);
            json!({"century_floor_bytes":280_581_611_288u64,"retained_disk_growth_bytes":growth,
                   "protected_existing_floor_bytes":floor,"allocation_credit_taken_bytes":credit,
                   "observed_available_bytes":free})
        };
        let nominal = 4_082_587_482_488;
        let required = nominal + RESERVATION;
        for credit in [136_545_972_224, 136_545_968_128, 200_000_000_000, 0] {
            let scenario = "limited_native257_with_booked_full211";
            assert_eq!(
                startup_floor(&c(credit, required), scenario).unwrap(),
                nominal
            );
            assert!(startup_floor(&c(credit, required - 1), scenario).is_err());
        }
    }

    #[test]
    fn inherited_and_combined_floors_and_overflow_remain_protected() {
        let mut c = json!({"century_floor_bytes":10,"retained_disk_growth_bytes":20,
                           "protected_existing_floor_bytes":100,"allocation_credit_taken_bytes":5,
                           "observed_available_bytes":u64::MAX});
        assert_eq!(startup_floor(&c, "limited_native257").unwrap(), 100);
        assert_eq!(
            startup_floor(&c, "limited_native257_and_ordinary211").unwrap(),
            100 + super::super::SCRATCH
        );
        c["retained_disk_growth_bytes"] = json!(u64::MAX);
        assert!(startup_floor(&c, "limited_native257").is_err());
    }
}
