//! One-shot, exact-invocation admission and first-guard launch for the epoch 239 native import.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const IMPORT_UNIT: &str = "horizon-import-239-current-20261117-v3.service";
const GUARD_UNIT: &str = "horizon-import-239-protective-20261117-v3.service";
const TIMER_UNIT: &str = "horizon-import-239-protective-20261117-v3.timer";
const IMPORT_PACKAGE: &str = "/var/lib/jetstreamer/horizon239-current-import-runtime-20261117-v3";
const IMPORT_SERVICE_SHA: &str = "eb95b43a389fc94ca6b8ed10761b7672cb963aadb9957d7dc16b56b899d63a64";
const PREPARATION_SHA: &str = "fe72b2037e408618af9d3b75cb5dce0e339fe7f5ac65f9bf991f14b0c5dc3983";
const NATIVE_PROOF: &str =
    "/var/lib/jetstreamer/horizon239-native-probe-proof-20261117-v2/accepted-result.json";
const NATIVE_PROOF_SHA: &str = "f7bd838986cc0f2e125ca6db7a66d4a9a597be823e57bc1f1112aa895dc18d40";
const NATIVE_PROBE_BINARY_SHA: &str =
    "a4b0283540f269b0b37365ae3d10d7d62cb8fd6687c1e305fd6422c5473b1ed5";
const LEASE_SCOPE: &str = "/home/ubuntu/.jetstreamer-private/destination-cc16e4ac982549c49990203164025f5c92247f275e6530e0654ed82c45a07519";
const PRIVATE: &str =
    "/home/ubuntu/.jetstreamer-private/qualification-239-general-shrink-debt-budget506-e3f15eb2-v1";
const ARCHIVE: &str = "/home/ubuntu/.jetstreamer-private/qualification-239-general-shrink-debt-budget506-e3f15eb2-v1/output/epoch-239.jet";
const SIDECAR: &str = "/home/ubuntu/.jetstreamer-private/qualification-239-general-shrink-debt-budget506-e3f15eb2-v1/output/epoch-239.jet.sha256";
const ARCHIVE_SHA: &str = "d530332035fa1765f4f222c3df6ff9aa5825817c2be5ff0dc27f7f1d37c88189";
const ARCHIVE_BYTES: u64 = 161_186_911_272;
const HASH_REPORT: &str =
    "/home/ubuntu/.codex/diagnostics/horizon-239-private-archive-hash-20261117.txt";
const GUARD_BINARY: &str = "/var/lib/jetstreamer/horizon239-current-import-guard-20261117-v4/jetstreamer-horizon-standalone-guard";
const GUARD_SHA: &str = "f2ac0a5ba99438238425a5b44105f48bcef4961b6b5b4987a0fb8819c7f455b3";
const R2_BINARY: &str =
    "/var/lib/jetstreamer/horizon-status240243-cleanup-production-SDK2451-v1/jetstreamer-r2";
const R2_SHA: &str = "2e718f08c3cd072c40f79dbb85f35fd59864aedc26782fcfd89a031a7ff67c07";
const SEALER: &str =
    "/var/lib/jetstreamer/horizon-live-observe-a1afd55-v147/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "96521c2edb8d0d3add79da92eed6b5f4fc3c3fed7eb5eea49cedcc3cc779ae24";
const OPERATOR_RUNTIME: &str = "/var/lib/jetstreamer/horizon239-current-import-operator-20261117-v3/horizon-epoch239-import-operator";
const STATE: &str = "/var/lib/jetstreamer/horizon239-current-import-operator-state-20261117-v3";
const GUARD_PACKAGE: &str = "/var/lib/jetstreamer/horizon239-current-import-protective-20261117-v3";
const TOKENS: &str = "/var/lib/jetstreamer/horizon239-current-import-tokens-20261117-v3";
const RECEIPTS: &str =
    "/var/lib/jetstreamer/horizon239-current-import-protective-receipts-20261117-v3";
const ROOT_CAP: u64 = 206_158_430_208;
const FLOOR: u64 = 2_000_000_000_000;
const THREE_REPLAY_OBLIGATION: u64 = 980_221_169_664;
const IMPORT_MEMORY_MAX: u64 = 68_719_476_736;
const GUARD_MEMORY_MAX: u64 = 1_073_741_824;
const LIVE: [(&str, &str); 3] = [
    ("247-247", "horizon-qualify-247-reboot-20261117-v2.service"),
    ("248-248", "horizon-qualify-248-reboot-20261117-v1.service"),
    ("249-249", "horizon-qualify-249-reboot-20261117-v1.service"),
];

fn digest(path: &Path, maximum: u64) -> Result<String> {
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file() && before.nlink() == 1 && before.len() <= maximum,
        "unsafe pin {}",
        path.display()
    );
    let mut file = File::open(path)?;
    let mut h = Sha256::new();
    let mut buffer = [0u8; 1 << 20];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        h.update(&buffer[..n]);
    }
    let after = fs::symlink_metadata(path)?;
    ensure!(
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec(),
        "pin changed {}",
        path.display()
    );
    Ok(format!("{:x}", h.finalize()))
}

fn command(program: &str, args: &[&str]) -> Result<String> {
    let result = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("run {program}"))?;
    ensure!(
        result.status.success(),
        "{program} {:?}: {}",
        args,
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(String::from_utf8(result.stdout)?)
}

fn fields(unit: &str) -> Result<BTreeMap<String, String>> {
    let raw = command(
        "/usr/bin/systemctl",
        &[
            "show",
            unit,
            "--property=Id,LoadState,ActiveState,SubState,InvocationID,NRestarts,Result,MainPID,Restart,KillMode,Delegate,ControlGroup,ExecMainStartTimestamp",
        ],
    )?;
    raw.lines()
        .map(|line| {
            let (k, v) = line.split_once('=').context("malformed systemctl output")?;
            Ok((k.to_owned(), v.to_owned()))
        })
        .collect()
}

fn field<'a>(row: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    Ok(row.get(key).context("missing systemctl field")?)
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn timestamp_seconds(value: &str) -> Result<u64> {
    let out = command("/usr/bin/date", &["-u", "-d", value, "+%s"])?;
    Ok(out.trim().parse()?)
}

fn available_bytes() -> Result<u64> {
    let path = CString::new("/")?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } == 0,
        "statvfs failed"
    );
    let stat = unsafe { stat.assume_init() };
    stat.f_bavail
        .checked_mul(stat.f_frsize)
        .context("free space overflow")
}

fn total_memory_bytes() -> Result<u64> {
    let text = fs::read_to_string("/proc/meminfo")?;
    let line = text
        .lines()
        .find(|s| s.starts_with("MemTotal:"))
        .context("missing MemTotal")?;
    let kib: u64 = line
        .split_whitespace()
        .nth(1)
        .context("bad MemTotal")?
        .parse()?;
    kib.checked_mul(1024).context("memory overflow")
}

fn private_json(path: &Path, maximum: u64) -> Result<Value> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && meta.uid() == 0
            && meta.mode() & 0o022 == 0
            && meta.len() <= maximum,
        "unsafe private JSON {}",
        path.display()
    );
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn check_static() -> Result<()> {
    for (path, sha, max) in [
        (
            format!("{IMPORT_PACKAGE}/{IMPORT_UNIT}"),
            IMPORT_SERVICE_SHA,
            1 << 20,
        ),
        (
            format!("{IMPORT_PACKAGE}/preparation.json"),
            PREPARATION_SHA,
            1 << 20,
        ),
        (NATIVE_PROOF.to_owned(), NATIVE_PROOF_SHA, 1 << 20),
        (
            format!("{IMPORT_PACKAGE}/horizon-epoch239-import-source"),
            NATIVE_PROBE_BINARY_SHA,
            4 << 20,
        ),
        (GUARD_BINARY.to_owned(), GUARD_SHA, 4 << 20),
        (R2_BINARY.to_owned(), R2_SHA, 64 << 20),
        (SEALER.to_owned(), SEALER_SHA, 4 << 20),
    ] {
        ensure!(
            digest(Path::new(&path), max)? == sha,
            "pinned input changed: {path}"
        );
    }
    let proof = private_json(Path::new(NATIVE_PROOF), 1 << 20)?;
    ensure!(
        proof["schema"] == "horizon-epoch239-native-namespace-proof-v2"
            && proof["all_masks_read_only"] == true
            && proof["source_and_destination_same_device"] == true
            && proof["source_and_destination_mounts_writable"] == true
            && proof["lease_mount_writable"] == true
            && proof["lease_scope"] == LEASE_SCOPE
            && proof["import_unit_sha256"] == IMPORT_SERVICE_SHA
            && proof["probe_binary_sha256"] == NATIVE_PROBE_BINARY_SHA
            && proof["preparation_sha256"] == PREPARATION_SHA
            && proof["probe_result"] == "success"
            && proof["probe_exit_status"] == 0
            && proof["mask_count"] == 1572
            && proof["archive_mutations"] == false
            && proof["remote_mutations"] == false,
        "native import namespace proof rejected"
    );
    let source = private_json(
        Path::new(&format!("{IMPORT_PACKAGE}/preparation.json")),
        1 << 20,
    )?;
    ensure!(
        source["source"]["archive"]["sha256"] == ARCHIVE_SHA
            && source["source"]["archive"]["bytes"] == ARCHIVE_BYTES
            && source["unit_sha256"] == IMPORT_SERVICE_SHA
            && source["unit"] == IMPORT_UNIT
            && source["read_only_masks"]
                .as_array()
                .is_some_and(|masks| masks.len() == 1572 && !masks.iter().any(|p| p == LEASE_SCOPE))
            && source["first_guard_token_directory"] == TOKENS,
        "import preparation changed"
    );
    let meta = fs::symlink_metadata(ARCHIVE)?;
    ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && meta.uid() == 1000
            && meta.mode() & 0o222 == 0
            && meta.len() == ARCHIVE_BYTES
            && source["source"]["archive"]["device"] == meta.dev()
            && source["source"]["archive"]["inode"] == meta.ino(),
        "native archive identity changed"
    );
    ensure!(
        fs::read_to_string(SIDECAR)? == format!("{ARCHIVE_SHA}  epoch-239.jet\n"),
        "native sidecar changed"
    );
    let report = fs::symlink_metadata(HASH_REPORT)?;
    ensure!(
        report.is_file()
            && report.nlink() == 1
            && report.uid() == 0
            && report.mode() & 0o022 == 0
            && fs::read_to_string(HASH_REPORT)? == format!("{ARCHIVE_SHA}  {ARCHIVE}\n"),
        "independent native archive hash report changed"
    );
    ensure!(
        !Path::new("/home/ubuntu/horizon/epoch-239.jet").exists()
            && !Path::new("/home/ubuntu/horizon/epoch-239.jet.sha256").exists(),
        "canonical epoch 239 already present"
    );
    Ok(())
}

fn no_other_public_importer() -> Result<()> {
    let units = command(
        "/usr/bin/systemctl",
        &[
            "list-units",
            "--type=service",
            "--state=running",
            "--no-legend",
            "--plain",
            "--no-pager",
        ],
    )?;
    for line in units.lines() {
        let unit = line.split_whitespace().next().unwrap_or("");
        ensure!(
            !unit.starts_with("horizon-import-") && !unit.starts_with("horizon-publish-"),
            "another public importer is running: {unit}"
        );
    }
    Ok(())
}

fn inspect(observer_path: &Path, observer_sha: &str) -> Result<Value> {
    check_static()?;
    no_other_public_importer()?;
    ensure!(
        digest(observer_path, 4 << 20)? == observer_sha,
        "observer hash changed"
    );
    let observer = private_json(observer_path, 4 << 20)?;
    ensure!(
        observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && observer["replays"].as_array().is_some_and(|a| a.len() == 3),
        "observer range census rejected"
    );
    let observed_at = timestamp_seconds(
        observer["recorded_at_utc"]
            .as_str()
            .context("observer timestamp")?,
    )?;
    let current = now()?;
    ensure!(
        observed_at <= current && current - observed_at <= 1800,
        "observer is stale"
    );
    for (range, unit) in LIVE {
        let item = observer["replays"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["range"] == range)
            .context("missing live range")?;
        ensure!(
            item["invocation_binding_stable"] == true
                && item["useful_work"]["sufficient_for_rates"] == true
                && item["controller_after"]["restarts"] == 0
                && item["producer_after"]["restarts"] == 0,
            "unstable replay {range}"
        );
        let id = item["controller_after"]["invocation_id"]
            .as_str()
            .context("observer invocation")?;
        ensure!(
            id == item["producer_after"]["invocation_id"]
                && item["controller_after"]["unit"] == unit,
            "observer owner mismatch"
        );
        let live = fields(unit)?;
        ensure!(
            field(&live, "InvocationID")? == id
                && field(&live, "ActiveState")? == "active"
                && field(&live, "SubState")? == "running"
                && field(&live, "NRestarts")? == "0",
            "live replay changed: {unit}"
        );
    }
    let total = total_memory_bytes()?;
    let obligation = THREE_REPLAY_OBLIGATION + IMPORT_MEMORY_MAX + GUARD_MEMORY_MAX;
    ensure!(obligation < total, "import memory admission exceeds host");
    let free = available_bytes()?;
    ensure!(
        free >= FLOOR + ARCHIVE_BYTES + 16_000_000_000,
        "import disk admission failed"
    );
    let remote: Value = serde_json::from_str(&command(
        R2_BINARY,
        &["inventory", "/home/ubuntu/horizon", "--epochs", "239-239"],
    )?)?;
    ensure!(
        remote["ready_pairs"] == 0
            && remote["missing"] == 1
            && remote["anomalies"] == 0
            && remote["entries"][0]["state"] == "missing",
        "R2 epoch 239 is no longer missing"
    );
    let prior = fields("horizon-import-239-current-20261117-v2.service")?;
    let prior_timer = fields("horizon-import-239-protective-20261117-v2.timer")?;
    ensure!(
        field(&prior, "ActiveState")? == "failed"
            && field(&prior, "Result")? == "exit-code"
            && field(&prior, "NRestarts")? == "0"
            && field(&prior_timer, "ActiveState")? == "inactive",
        "prior lease-failed importer or timer is not safely stopped"
    );
    let importer = fields(IMPORT_UNIT)?;
    ensure!(
        field(&importer, "LoadState")? == "not-found"
            && field(&importer, "ActiveState")? == "inactive",
        "new importer is already installed or active"
    );
    Ok(
        json!({"schema":"horizon239-native-import-main-admission-v1", "issued_unix_seconds":current,
        "expires_unix_seconds":current+120,"epoch":239,"Main_accepted":true,"observer":{"path":observer_path,"sha256":observer_sha},
        "native_proof":{"path":NATIVE_PROOF,"sha256":NATIVE_PROOF_SHA},"r2_inventory":remote,
        "live_replay_count":3,"retained_replay_memory_obligation_bytes":THREE_REPLAY_OBLIGATION,
        "candidate_import_memory_max_bytes":IMPORT_MEMORY_MAX,"guard_memory_max_bytes":GUARD_MEMORY_MAX,
        "memory_obligation_after_bytes":obligation,"host_memory_total_bytes":total,
        "available_disk_bytes":free,"minimum_free_bytes":FLOOR,
        "import_unit":IMPORT_UNIT,"guard_unit":GUARD_UNIT,"timer_unit":TIMER_UNIT,
        "prior_lease_failed_attempt_stopped":true,
        "source_archive":{"path":ARCHIVE,"sha256":ARCHIVE_SHA,"bytes":ARCHIVE_BYTES,"device":fs::metadata(ARCHIVE)?.dev(),"inode":fs::metadata(ARCHIVE)?.ino()},
        "archive_mutations":false,"remote_mutations":false,"r2_mutations":false}),
    )
}

fn write_new(path: &Path, value: &Value, mode: u32) -> Result<String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    let bytes = serde_json::to_vec_pretty(value)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    File::open(path.parent().context("parent")?)?.sync_all()?;
    Ok(format!(
        "{:x}",
        Sha256::digest([bytes.as_slice(), b"\n"].concat())
    ))
}

fn write_text(path: &Path, text: &str, mode: u32) -> Result<String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    File::open(path.parent().context("parent")?)?.sync_all()?;
    Ok(format!("{:x}", Sha256::digest(text.as_bytes())))
}

fn directory(path: &Path, mode: u32) -> Result<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    File::open(path.parent().context("directory parent")?)?.sync_all()?;
    Ok(())
}

fn seal(plan: &Path, plan_sha: &str) -> Result<()> {
    let old = unsafe { libc::umask(0o022) };
    let result = command(
        SEALER,
        &[
            plan.to_str().context("plan path")?,
            "--plan-sha256",
            plan_sha,
            "--self-sha256",
            SEALER_SHA,
        ],
    );
    unsafe { libc::umask(old) };
    result?;
    Ok(())
}

fn start_guard(actual_id: &str) -> Result<(String, String)> {
    let state = Path::new(STATE);
    let receipts = Path::new(RECEIPTS);
    directory(receipts, 0o700)?;
    let plan = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":IMPORT_UNIT,
        "invocation_id":actual_id,"filesystem":"/","minimum_free_bytes":FLOOR,
        "worker_root":PRIVATE,"maximum_worker_vmas":3_500_000,
        "maximum_root_physical_bytes":ROOT_CAP,"receipt_directory":RECEIPTS});
    let plan_path = state.join("guard-plan.json");
    let plan_sha = write_new(&plan_path, &plan, 0o600)?;
    let service = format!(
        "[Unit]\nDescription=Exact epoch 239 native import disk and VMA guard\n[Service]\nType=oneshot\nUser=root\nUMask=0077\nRestart=no\nMemoryMax=1073741824\nMemorySwapMax=0\nCPUQuota=100%\nTasksMax=256\nTimeoutStartSec=90\nProtectSystem=strict\nProtectHome=read-only\nPrivateNetwork=yes\nNoNewPrivileges=yes\nCapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE\nAmbientCapabilities=CAP_DAC_OVERRIDE CAP_SYS_PTRACE\nReadWritePaths={RECEIPTS}\nExecStart={GUARD_BINARY} {GUARD_PACKAGE}/guard-plan.json --plan-sha256 {plan_sha} --self-sha256 {GUARD_SHA}\n"
    );
    let timer = format!(
        "[Unit]\nDescription=Exact epoch 239 native import protective timer\n[Timer]\nOnActiveSec=1s\nOnUnitInactiveSec=60s\nAccuracySec=1s\nRandomizedDelaySec=0\nUnit={GUARD_UNIT}\n"
    );
    let service_path = state.join(GUARD_UNIT);
    let timer_path = state.join(TIMER_UNIT);
    let service_sha = write_text(&service_path, &service, 0o600)?;
    let timer_sha = write_text(&timer_path, &timer, 0o600)?;
    let seal_plan = json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":GUARD_PACKAGE,
        "members":[
            {"source":plan_path,"name":"guard-plan.json","sha256":plan_sha,"mode":292},
            {"source":service_path,"name":GUARD_UNIT,"sha256":service_sha,"mode":292},
            {"source":timer_path,"name":TIMER_UNIT,"sha256":timer_sha,"mode":292}]});
    let seal_path = state.join("guard-seal-plan.json");
    let seal_sha = write_new(&seal_path, &seal_plan, 0o600)?;
    seal(&seal_path, &seal_sha)?;
    command(
        "/usr/bin/systemctl",
        &["link", &format!("{GUARD_PACKAGE}/{GUARD_UNIT}")],
    )?;
    command(
        "/usr/bin/systemctl",
        &["link", &format!("{GUARD_PACKAGE}/{TIMER_UNIT}")],
    )?;
    command("/usr/bin/systemctl", &["daemon-reload"])?;
    command("/usr/bin/systemctl", &["start", TIMER_UNIT])?;
    Ok((plan_sha, seal_sha))
}

fn verify_first_guard_sample(
    sample: &Value,
    actual_id: &str,
    guard_id: &str,
    plan_sha: &str,
    admission_time: u64,
) -> Result<()> {
    ensure!(
        sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && sample["guard_invocation_id"] == guard_id
            && sample["producer_invocation_id"] == actual_id
            && sample["plan_sha256"] == plan_sha
            && sample["guard_sha256"] == GUARD_SHA
            && sample["trip_reason"].is_null()
            && sample["worker_observation_error"].is_null()
            && sample["root_physical_observation_error"].is_null()
            && sample["root_physical_observation"]["exceeds_budget"] == false
            && sample["root_physical_observation"]["maximum_physical_bytes"] == ROOT_CAP
            && sample["maximum_root_physical_bytes"] == ROOT_CAP
            && sample["minimum_free_bytes"] == FLOOR
            && sample["available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= FLOOR)
            && sample["producer"]["invocation_id"] == actual_id
            && sample["producer"]["active"] == "activating"
            && sample["producer"]["sub"] == "start-pre"
            && sample["producer"]["restarts"] == 0
            && sample["producer_stop_enabled"] == true
            && sample["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n >= admission_time && n <= admission_time + 50),
        "first guard sample rejected"
    );
    Ok(())
}

fn first_guard(
    actual_id: &str,
    plan_sha: &str,
    admission_time: u64,
    deadline: Instant,
) -> Result<(String, Value, String)> {
    loop {
        ensure!(
            Instant::now() < deadline,
            "first guard deadline expired before token"
        );
        let importer = fields(IMPORT_UNIT)?;
        ensure!(
            field(&importer, "InvocationID")? == actual_id
                && field(&importer, "ActiveState")? == "activating"
                && field(&importer, "SubState")? == "start-pre"
                && field(&importer, "NRestarts")? == "0",
            "importer left guarded start-pre"
        );
        let guard = fields(GUARD_UNIT)?;
        let gid = field(&guard, "InvocationID")?.to_owned();
        if gid.len() == 32
            && field(&guard, "Result")? == "success"
            && field(&guard, "ActiveState")? == "inactive"
            && field(&guard, "NRestarts")? == "0"
        {
            let sample_path = PathBuf::from(format!("{RECEIPTS}/sample-{gid}.json"));
            if sample_path.exists() {
                let sample_sha = digest(&sample_path, 1 << 20)?;
                let sample = private_json(&sample_path, 1 << 20)?;
                verify_first_guard_sample(&sample, actual_id, &gid, plan_sha, admission_time)?;
                let timer = fields(TIMER_UNIT)?;
                ensure!(
                    field(&timer, "ActiveState")? == "active",
                    "protective timer inactive"
                );
                return Ok((gid, sample, sample_sha));
            }
        }
        thread::sleep(Duration::from_millis(300));
    }
}

fn issue_token(
    actual_id: &str,
    admission_sha: &str,
    guard_id: &str,
    sample: &Value,
    sample_sha: &str,
    plan_sha: &str,
) -> Result<String> {
    let parent = Path::new(TOKENS);
    directory(parent, 0o755)?;
    let source = Path::new(STATE).join("guard-admission.json");
    let token = json!({"schema":"horizon239-native-import-real-first-guard-token-v1",
        "actual_import_invocation_id":actual_id,"admission":{"path":format!("{STATE}/admission.json"),"sha256":admission_sha},
        "guard_plan":{"path":format!("{GUARD_PACKAGE}/guard-plan.json"),"sha256":plan_sha},
        "first_guard_invocation_id":guard_id,
        "first_guard_sample":{"path":format!("{RECEIPTS}/sample-{guard_id}.json"),"sha256":sample_sha},
        "first_guard_available_bytes":sample["available_bytes"],
        "importer_start_pre_verified":true,"timer_active_verified":true,
        "remote_mutations":false,"r2_mutations":false});
    let token_sha = write_new(&source, &token, 0o600)?;
    let destination = format!("{TOKENS}/{actual_id}");
    let seal_plan = json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":destination,
        "members":[{"source":source,"name":"guard-admission.json","sha256":token_sha,"mode":292}]});
    let plan_path = Path::new(STATE).join("token-seal-plan.json");
    let plan_sha = write_new(&plan_path, &seal_plan, 0o600)?;
    seal(&plan_path, &plan_sha)?;
    ensure!(
        digest(
            Path::new(&format!("{TOKENS}/{actual_id}/guard-admission.json")),
            1 << 20
        )? == token_sha,
        "sealed token differs from first-guard evidence"
    );
    Ok(token_sha)
}

fn launch(observer: &Path, observer_sha: &str) -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "operator must run as root");
    ensure!(
        fs::canonicalize("/proc/self/exe")? == Path::new(OPERATOR_RUNTIME),
        "unsealed operator executable"
    );
    let admission = inspect(observer, observer_sha)?;
    let state = Path::new(STATE);
    directory(state, 0o700)?;
    let admission_sha = write_new(&state.join("admission.json"), &admission, 0o600)?;
    command(
        "/usr/bin/systemctl",
        &["link", &format!("{IMPORT_PACKAGE}/{IMPORT_UNIT}")],
    )?;
    command("/usr/bin/systemctl", &["daemon-reload"])?;
    command("/usr/bin/systemctl", &["start", "--no-block", IMPORT_UNIT])?;
    let started = Instant::now();
    let actual_id = loop {
        ensure!(
            started.elapsed() < Duration::from_secs(8),
            "importer did not enter start-pre"
        );
        let row = fields(IMPORT_UNIT)?;
        if field(&row, "ActiveState")? == "activating" && field(&row, "SubState")? == "start-pre" {
            let id = field(&row, "InvocationID")?;
            if id.len() == 32 && field(&row, "NRestarts")? == "0" {
                break id.to_owned();
            }
        }
        thread::sleep(Duration::from_millis(200));
    };
    let deadline = started + Duration::from_secs(50);
    let (guard_plan_sha, guard_seal_sha) = start_guard(&actual_id)?;
    let (guard_id, sample, sample_sha) = first_guard(
        &actual_id,
        &guard_plan_sha,
        admission["issued_unix_seconds"]
            .as_u64()
            .context("admission time")?,
        deadline,
    )?;
    ensure!(
        Instant::now() < deadline,
        "operator deadline expired before token seal"
    );
    let token_sha = issue_token(
        &actual_id,
        &admission_sha,
        &guard_id,
        &sample,
        &sample_sha,
        &guard_plan_sha,
    )?;
    let handoff = json!({"schema":"horizon239-native-import-guarded-startup-v1","recorded_unix_seconds":now()?,
        "import_unit":IMPORT_UNIT,"actual_import_invocation_id":actual_id,"guard_unit":GUARD_UNIT,
        "guard_invocation_id":guard_id,"timer_unit":TIMER_UNIT,
        "admission_sha256":admission_sha,"guard_plan_sha256":guard_plan_sha,
        "guard_seal_plan_sha256":guard_seal_sha,"first_guard_sample_sha256":sample_sha,
        "token_sha256":token_sha,"first_guard_before_native_import":true,
        "remote_mutations":false,"r2_mutations":false});
    write_new(&state.join("guarded-startup-handoff.json"), &handoff, 0o600)?;
    println!("{}", serde_json::to_string(&handoff)?);
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    ensure!(
        args.len() == 5 && (args[1] == "inspect" || args[1] == "launch"),
        "usage: operator <inspect|launch> OBSERVER_PATH OBSERVER_SHA SELF_SHA"
    );
    ensure!(unsafe { libc::geteuid() } == 0, "operator must run as root");
    unsafe { libc::umask(0o077) };
    let executable = fs::canonicalize("/proc/self/exe")?;
    ensure!(
        digest(&executable, 16 << 20)? == args[4],
        "operator self hash changed"
    );
    let observer = Path::new(&args[2]);
    if args[1] == "inspect" {
        println!(
            "{}",
            serde_json::to_string_pretty(&inspect(observer, &args[3])?)?
        );
        Ok(())
    } else {
        launch(observer, &args[3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_profile_preserves_import_scope_and_budget() {
        assert_eq!(
            IMPORT_UNIT,
            "horizon-import-239-current-20261117-v3.service"
        );
        assert_eq!(GUARD_SHA.len(), 64);
        assert!(THREE_REPLAY_OBLIGATION + IMPORT_MEMORY_MAX + GUARD_MEMORY_MAX < 1_212_136_964_096);
        assert!(ROOT_CAP > ARCHIVE_BYTES);
        assert_eq!(FLOOR, 2_000_000_000_000);
        assert_eq!(LIVE.len(), 3);
    }

    #[test]
    fn token_gate_rejects_trips_foreign_invocations_and_late_samples() {
        let id = "a".repeat(32);
        let gid = "b".repeat(32);
        let plan = "c".repeat(64);
        let good = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1",
            "guard_invocation_id":gid,"producer_invocation_id":id,"plan_sha256":plan,
            "guard_sha256":GUARD_SHA,"trip_reason":null,"worker_observation_error":null,
            "root_physical_observation_error":null,
            "root_physical_observation":{"exceeds_budget":false,"maximum_physical_bytes":ROOT_CAP},
            "maximum_root_physical_bytes":ROOT_CAP,"minimum_free_bytes":FLOOR,"available_bytes":FLOOR,
            "producer":{"invocation_id":id,"active":"activating","sub":"start-pre","restarts":0},
            "producer_stop_enabled":true,"recorded_unix_seconds":1020});
        assert!(verify_first_guard_sample(&good, &id, &gid, &plan, 1000).is_ok());
        for (pointer, bad) in [
            ("/trip_reason", json!("filesystem-floor")),
            ("/producer_invocation_id", json!("d".repeat(32))),
            ("/guard_invocation_id", json!("e".repeat(32))),
            ("/root_physical_observation/exceeds_budget", json!(true)),
            ("/worker_observation_error", json!("unreadable maps")),
            ("/available_bytes", json!(FLOOR - 1)),
            ("/producer/sub", json!("running")),
            ("/recorded_unix_seconds", json!(1051)),
        ] {
            let mut changed = good.clone();
            *changed.pointer_mut(pointer).unwrap() = bad;
            assert!(
                verify_first_guard_sample(&changed, &id, &gid, &plan, 1000).is_err(),
                "{pointer}"
            );
        }
    }
}
