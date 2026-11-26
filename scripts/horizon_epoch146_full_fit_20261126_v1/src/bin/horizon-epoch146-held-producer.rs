//! Hold the exact epoch 146 payload until its registered producer has a protective guard.
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, Read},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{self, Command},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const UNIT: &str = "horizon-qualify-146-full-local-20261126-v1.service";
const GROUP: &str = "0::/system.slice/horizon-qualify-146-full-local-20261126-v1.service";
const RUN: &str = "/home/sol/.jetstreamer-private/epoch146-standard-lane-20261122-v1/full-local-v1";
const NODE: &str = "/usr/local/lib/jetstreamer/deploy-epochs144-147-upgradeable-loader-20261016-v1/jetstreamer-node";
const WORKER: &str = "/usr/local/lib/jetstreamer/deploy-epochs144-147-upgradeable-loader-20261016-v1/jetstreamer-historical-worker-v1-4-25";
const NODE_SHA: &str = "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65";
const WORKER_SHA: &str = "2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8";
const PROFILE: &str = "/run/horizon-epoch146-full-local/payload.json";
const PERMIT: &str = "/run/horizon-epoch146-full-local/state/permit.json";
const GUARD_RECORD: &str = "/run/horizon-epoch146-full-local/state/first-guard.json";
const BOOTSTRAP: &str = "snapshot-63054846-GWh8TCBRBCPxYQ9zwQSv8zuLEGUP4xvQsN1jMYfoXqmt.tar.zst";
const GIB: u64 = 1 << 30;
const HOLD: Duration = Duration::from_secs(320);
const GUARD_MAX_AGE: u64 = 120;

fn string<'a>(item: &'a Value, key: &str) -> Result<&'a str> {
    item[key].as_str().with_context(|| format!("missing {key}"))
}

fn text_sha(input: &str, size: usize) -> bool {
    input.len() == size
        && input
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && input.bytes().any(|b| b != b'0')
}

type Stamp = (u64, u64, u64, i64, i64);

fn metadata_stamp(meta: &fs::Metadata) -> Stamp {
    (
        meta.dev(),
        meta.ino(),
        meta.len(),
        meta.ctime(),
        meta.ctime_nsec(),
    )
}

fn file_hash(path: &Path, expected: &str, length: u64, owner: Option<u32>) -> Result<Stamp> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let initial = file.metadata()?;
    ensure!(
        initial.is_file()
            && initial.len() == length
            && initial.nlink() == 1
            && owner.is_none_or(|uid| initial.uid() == uid)
            && (!matches!(owner, Some(0)) || initial.mode() & 0o222 == 0),
        "wrong file type or ownership {}",
        path.display()
    );
    let mut hash = Sha256::new();
    let bytes = io::copy(&mut (&mut file).take(length + 1), &mut hash)?;
    ensure!(
        bytes == length
            && format!("{:x}", hash.finalize()) == expected
            && metadata_stamp(&initial) == metadata_stamp(&file.metadata()?)
            && metadata_stamp(&initial) == metadata_stamp(&fs::symlink_metadata(path)?),
        "changed input {}",
        path.display()
    );
    Ok(metadata_stamp(&initial))
}

fn doc(path: &Path, expect: Option<&str>, trusted: bool) -> Result<Option<Value>> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let before = file.metadata()?;
    ensure!(
        before.is_file()
            && (1..=1 << 20).contains(&before.len())
            && (!trusted || before.uid() == 0 && before.mode() & 0o222 == 0 && before.nlink() == 1),
        "untrusted JSON {}",
        path.display()
    );
    let mut raw = Vec::new();
    (&mut file).take(before.len() + 1).read_to_end(&mut raw)?;
    ensure!(
        expect.is_none_or(|sha| format!("{:x}", Sha256::digest(&raw)) == sha)
            && raw.len() as u64 == before.len()
            && metadata_stamp(&before) == metadata_stamp(&file.metadata()?)
            && metadata_stamp(&before) == metadata_stamp(&fs::symlink_metadata(path)?),
        "changed JSON {}",
        path.display()
    );
    Ok(Some(serde_json::from_slice(&raw)?))
}

fn expected_argv() -> Vec<String> {
    vec![
        NODE.into(), "146".into(), format!("{RUN}/ledger"), "--verify".into(),
        "--root-checkpoint-cohort".into(), format!("--cohort-manifest={RUN}/inputs/preflight-146-v4.json"),
        "--cohort-manifest-fingerprint=sha256:4f7a8842b2f68a7837a06cc050f2cfa7c5b1a2cf5f184dcfd2190dc8d5f644f8".into(),
        format!("--snapshot-archive={RUN}/inputs/{BOOTSTRAP}"),
    ]
}

fn validate_profile(profile: &Value) -> Result<()> {
    let state = &profile["producer"]["properties"];
    let guard = &profile["guard"]["properties"];
    ensure!(
        profile["schema"] == "horizon-epoch146-full-native-guard-and-producer-projection-v1"
            && profile["epoch"] == 146
            && profile["producer"]["unit"] == UNIT
            && profile["native_argv"] == json!(expected_argv())
            && profile["root_checkpoints"] == json!([63072070, 63503456])
            && profile["replay_slots_inclusive"] == json!([63054847, 63503999])
            && profile["archive_slots_inclusive"] == json!([63072000, 63503999])
            && profile["requires_invocation_bound_guard_before_exec"] == true
            && profile["requires_status_owner_and_fleet_registration"] == true
            && profile["production_launch_authorized"] == false
            && text_sha(string(profile, "prestart_quote_sha256")?, 64)
            && profile["source_inputs"]["node"]["sha256"] == NODE_SHA
            && profile["source_inputs"]["worker"]["sha256"] == WORKER_SHA
            && profile["native_environment"]["JETSTREAMER_HISTORICAL_WORKER_V1_4_25"] == WORKER
            && profile["native_environment"]["JETSTREAMER_VERIFY_SNAPSHOTS"] == "1"
            && profile["native_environment"]["JETSTREAMER_SKIP_SNAPSHOT_VERIFY"] == "0"
            && profile["native_environment"]["JETSTREAMER_ENFORCE_ARCHIVE_HASH"] == "1"
            && state["CPUQuota"] == "625%"
            && state["MemoryMax"] == "73014444032"
            && state["MemorySwapMax"] == "0"
            && state["Restart"] == "no"
            && guard["unit"] == UNIT
            && guard["worker_root"] == RUN
            && guard["filesystem"] == "/home/sol"
            && guard["maximum_root_physical_bytes"] == 288 * GIB
            && guard["maximum_worker_vmas"] == 3_500_000,
        "different epoch 146 replay, resource or guard profile"
    );
    Ok(())
}

fn readonly(path: &Path) -> Result<bool> {
    let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let mut buffer = std::mem::MaybeUninit::uninit();
    ensure!(
        unsafe { libc::statvfs(name.as_ptr(), buffer.as_mut_ptr()) } == 0,
        "statvfs {}: {}",
        path.display(),
        io::Error::last_os_error()
    );
    Ok(unsafe { buffer.assume_init() }.f_flag & libc::ST_RDONLY != 0)
}

fn verify_runtime() -> Result<u64> {
    ensure!(
        unsafe { libc::geteuid() } == 1001
            && unsafe { libc::getegid() } == 1003
            && fs::read_to_string("/proc/self/cgroup")?.trim() == GROUP,
        "wrong native producer identity"
    );
    let cg = Path::new("/sys/fs/cgroup").join(GROUP.trim_start_matches("0::/"));
    let cpu = fs::read_to_string(cg.join("cpu.max"))?;
    let parts: Vec<u64> = cpu
        .split_whitespace()
        .map(str::parse)
        .collect::<Result<_, _>>()?;
    ensure!(
        parts.len() == 2
            && parts[1] > 0
            && 4 * u128::from(parts[0]) == 25 * u128::from(parts[1])
            && fs::read_to_string(cg.join("memory.max"))?
                .trim()
                .parse::<u64>()?
                == 68 * GIB
            && fs::read_to_string(cg.join("memory.swap.max"))?.trim() == "0",
        "changed accounting cgroup limits"
    );
    let proc = fs::read_to_string("/proc/self/stat")?;
    Ok(proc
        .rsplit_once(')')
        .context("invalid native stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("missing native start ticks")?
        .parse()?)
}

fn verify_projected_inputs(profile: &Value) -> Result<Vec<(PathBuf, Stamp)>> {
    let mut inputs = vec![
        (
            PathBuf::from(NODE),
            file_hash(Path::new(NODE), NODE_SHA, 47_753_136, Some(0))?,
        ),
        (
            PathBuf::from(WORKER),
            file_hash(Path::new(WORKER), WORKER_SHA, 12_509_984, Some(0))?,
        ),
    ];
    let root = Path::new(RUN);
    let device = fs::metadata(root)?.dev();
    ensure!(
        fs::metadata("/home/sol")?.dev() == device
            && fs::metadata(root.join("ledger"))?.dev() == device
            && fs::metadata(root.join("private"))?.dev() == device
            && !readonly(root)?,
        "wrong production writable mount"
    );
    for (path, hash, length, owner) in [
        (
            root.join("inputs").join(BOOTSTRAP),
            string(&profile["bootstrap"], "sha256")?,
            4_459_684_282,
            1001,
        ),
        (
            root.join("inputs/preflight-146-v4.json"),
            string(&profile["cohort_manifest"], "sha256")?,
            12_714,
            0,
        ),
        (
            root.join("ledger/genesis.tar.bz2"),
            string(&profile["source_inputs"]["genesis"], "sha256")?,
            20_144,
            0,
        ),
    ] {
        ensure!(readonly(&path)?, "writable native input {}", path.display());
        let identity = file_hash(&path, hash, length, Some(owner))?;
        inputs.push((path, identity));
    }
    Ok(inputs)
}

struct Held<'a> {
    iid: &'a str,
    pid: u32,
    start_ticks: u64,
    ready_at: u64,
}

fn validate_permit(
    permit: &Value,
    guard: &Value,
    profile: &Value,
    held: &Held<'_>,
    now: u64,
) -> Result<()> {
    let Held {
        iid,
        pid,
        start_ticks,
        ready_at,
    } = *held;
    let plan = &profile["guard"]["properties"];
    ensure!(
        permit["schema"] == "horizon-epoch146-full-producer-permit-v1"
            && permit["producer_invocation_id"] == iid
            && permit["producer_pid"] == pid
            && permit["producer_start_ticks"] == start_ticks
            && permit["worker_ready_unix_seconds"] == ready_at
            && permit["prestart_quote_sha256"] == profile["prestart_quote_sha256"]
            && text_sha(string(permit, "prestart_quote_sha256")?, 64)
            && text_sha(string(permit, "writer_enrollment_sha256")?, 64)
            && permit["guard_plan_sha256"] == guard["plan_sha256"]
            && text_sha(string(guard, "plan_sha256")?, 64)
            && guard["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && guard["producer_invocation_id"] == iid
            && guard["producer"]["pid"] == pid
            && guard["producer_stop_enabled"] == true
            && guard["producer"]["active"] == "active"
            && guard["producer"]["sub"] == "running"
            && guard["workers"].as_array().is_some_and(Vec::is_empty)
            && guard["root_physical_observation"]["conservative_physical_bytes"]
                .as_u64()
                .zip(plan["maximum_root_physical_bytes"].as_u64())
                .is_some_and(|(used, cap)| used <= cap)
            && text_sha(string(guard, "guard_invocation_id")?, 32)
            && text_sha(string(permit, "guard_timer_invocation_id")?, 32)
            && guard["self_sha256"]
                .as_str()
                .or(guard["guard_sha256"].as_str())
                == profile["guard"]["binary"]["sha256"].as_str()
            && guard["trip_reason"].is_null()
            && guard["worker_observation_error"].is_null()
            && guard["root_physical_observation_error"].is_null()
            && guard["maximum_root_physical_bytes"] == plan["maximum_root_physical_bytes"]
            && guard["maximum_worker_vmas"] == plan["maximum_worker_vmas"]
            && guard["minimum_free_bytes"] == plan["minimum_free_bytes"]
            && guard["minimum_free_bytes"]
                .as_u64()
                .zip(guard["available_bytes"].as_u64())
                .is_some_and(|(floor, available)| available >= floor)
            && guard["recorded_unix_seconds"]
                .as_u64()
                .filter(|when| *when >= ready_at)
                .and_then(|when| now.checked_sub(when))
                .is_some_and(|age| age <= GUARD_MAX_AGE),
        "unprotected or foreign native replay permit"
    );
    Ok(())
}

fn main() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if let [mode, path, sha] = args.as_slice()
        && mode == "--validate-static"
    {
        ensure!(text_sha(sha, 64), "invalid profile digest");
        let profile = doc(Path::new(path), Some(sha), false)?.context("missing static profile")?;
        validate_profile(&profile)?;
        println!(
            "{}",
            json!({"validated":true,"producer_invoked":false,"profile_sha256":sha})
        );
        return Ok(());
    }
    let [sha] = args.as_slice() else {
        bail!("usage: horizon-epoch146-held-producer PROFILE_SHA256");
    };
    let start = Instant::now();
    ensure!(text_sha(sha, 64), "invalid native profile digest");
    let iid = env::var("INVOCATION_ID")?;
    ensure!(text_sha(&iid, 32), "invalid native invocation");
    let ticks = verify_runtime()?;
    let profile = doc(Path::new(PROFILE), Some(sha), true)?.context("missing producer profile")?;
    validate_profile(&profile)?;
    let inputs = verify_projected_inputs(&profile)?;
    let pid = process::id();
    let ready_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let held = Held {
        iid: &iid,
        pid,
        start_ticks: ticks,
        ready_at,
    };
    println!(
        "{}",
        json!({"phase":"worker-ready","epoch":146,"producer_invocation_id":iid,
                  "producer_pid":pid,"producer_start_ticks":ticks,"worker_ready_unix_seconds":ready_at,"profile_sha256":sha})
    );
    let deadline = start + HOLD;
    let mut heartbeat = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if let Some(permit) = doc(Path::new(PERMIT), None, true)? {
            let guard_sha = string(&permit, "guard_receipt_sha256")?;
            ensure!(text_sha(guard_sha, 64), "invalid guard sample digest");
            let guard = doc(Path::new(GUARD_RECORD), Some(guard_sha), true)?
                .context("missing bound guard sample")?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            validate_permit(&permit, &guard, &profile, &held, now)?;
            ensure!(
                verify_runtime()? == ticks && Instant::now() < deadline,
                "held generation changed"
            );
            for (path, identity) in &inputs {
                ensure!(
                    metadata_stamp(&fs::symlink_metadata(path)?) == *identity,
                    "sealed input changed while held {}",
                    path.display()
                );
            }
            let environment: std::collections::BTreeMap<String, String> =
                serde_json::from_value(profile["native_environment"].clone())?;
            println!(
                "{}",
                json!({"phase":"protected-release","epoch":146,"producer_invocation_id":iid,
                                  "guard_receipt_sha256":guard_sha})
            );
            return Err(Command::new(NODE)
                .args(&expected_argv()[1..])
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", "/home/sol")
                .env("INVOCATION_ID", &iid)
                .envs(environment)
                .exec()
                .into());
        }
        if Instant::now() >= heartbeat {
            println!(
                "{}",
                json!({"phase":"waiting-for-protective-guard","epoch":146,
                          "producer_invocation_id":iid,"remaining_seconds":deadline.saturating_duration_since(Instant::now()).as_secs()})
            );
            heartbeat += Duration::from_secs(60);
        }
        thread::sleep(Duration::from_millis(200));
    }
    bail!("producer release window expired")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn permit_case() -> (Value, Value, Value) {
        let digest = "a".repeat(64);
        let mut profile = json!({"prestart_quote_sha256":digest});
        profile["guard"] = json!({
            "properties":{"maximum_root_physical_bytes":288 * GIB,"maximum_worker_vmas":3_500_000,"minimum_free_bytes":9113207738261u64},
            "binary":{"sha256":digest}
        });
        let permit = json!({
            "schema":"horizon-epoch146-full-producer-permit-v1",
            "producer_invocation_id":"b".repeat(32),"producer_pid":42,"producer_start_ticks":23,"worker_ready_unix_seconds":499,
            "prestart_quote_sha256":digest,"writer_enrollment_sha256":digest,"guard_plan_sha256":digest,
            "guard_timer_invocation_id":"c".repeat(32)
        });
        let guard = json!({
            "schema":"jetstreamer-horizon-standalone-guard-sample-v1",
            "producer_invocation_id":"b".repeat(32),"producer":{"pid":42,"active":"active","sub":"running"},
            "guard_sha256":digest,"guard_invocation_id":"d".repeat(32),
            "producer_stop_enabled":true,"plan_sha256":digest,"workers":[],
            "root_physical_observation":{"conservative_physical_bytes":16},
            "maximum_root_physical_bytes":288 * GIB,"maximum_worker_vmas":3_500_000,
            "minimum_free_bytes":9113207738261u64,"available_bytes":9435416489984u64,
            "recorded_unix_seconds":500u64
        });
        (permit, guard, profile)
    }

    #[test]
    fn accepts_exact_fresh_protection_for_only_the_supplied_owner() {
        let (permit, guard, profile) = permit_case();
        let iid = "b".repeat(32);
        let held = Held {
            iid: &iid,
            pid: 42,
            start_ticks: 23,
            ready_at: 499,
        };
        assert!(validate_permit(&permit, &guard, &profile, &held, 614).is_ok());
        assert!(
            validate_permit(
                &permit,
                &guard,
                &profile,
                &Held {
                    start_ticks: 24,
                    ..held
                },
                614
            )
            .is_err()
        );
        assert!(validate_permit(&permit, &guard, &profile, &held, 621).is_err());
    }

    #[test]
    fn rejects_trip_missing_capped_tree_or_cpu_borrowed_guard() {
        let (permit, guard, profile) = permit_case();
        let iid = "b".repeat(32);
        let held = Held {
            iid: &iid,
            pid: 42,
            start_ticks: 23,
            ready_at: 499,
        };
        for (key, value) in [
            ("trip_reason", json!("home-floor")),
            ("recorded_unix_seconds", json!(498)),
            ("guard_invocation_id", json!("0".repeat(32))),
            ("producer_stop_enabled", json!(false)),
            ("workers", json!([[82, 32]])),
            (
                "root_physical_observation",
                json!({"conservative_physical_bytes":289 * GIB}),
            ),
            ("minimum_free_bytes", json!(9000u64)),
        ] {
            let mut foreign = guard.clone();
            foreign[key] = value;
            assert!(validate_permit(&permit, &foreign, &profile, &held, 614).is_err());
        }
    }
}
