//! One-shot, exact-invocation admission and first-guard launch for the epoch 244 native import.
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

const IMPORT_UNIT: &str = "horizon-import-244-current-20261117-v1.service";
const FAILED_IMPORT_ID: &str = "f9298e2a08564da69e0dfbec86149438";
const FAILED_GUARD_ID: &str = "6a714c5e14d44367b7a1bfd675b9776e";
const OLD_GUARD_UNIT: &str = "horizon-import-244-protective-20261117-v1.service";
const OLD_TIMER_UNIT: &str = "horizon-import-244-protective-20261117-v1.timer";
const GUARD_UNIT: &str = "horizon-import-244-protective-20261117-v2.service";
const TIMER_UNIT: &str = "horizon-import-244-protective-20261117-v2.timer";
const IMPORT_PACKAGE: &str = "/var/lib/jetstreamer/horizon244-current-import-runtime-20261117-v1";
const IMPORT_SERVICE_SHA: &str = "4cb7866d90e6cccd209364de9efba47a95fcf57431058e56a4d0f5291bb8a76a";
const PREPARATION_SHA: &str = "0a0002e099629b3905d5ba192c1caeaf0bf27e50e00be482a00452943bc692bd";
const NATIVE_PROOF: &str =
    "/var/lib/jetstreamer/horizon244-native-probe-proof-20261117-v1/accepted-result.json";
const NATIVE_PROOF_SHA: &str = "4132f4685aadb5bf38ecdde4db1b19e70cdfa575d911f45f73693b21156f9af1";
const NATIVE_PROBE_BINARY_SHA: &str =
    "fb910b443194a0b2773f2bae9268f51680cb3630f553c9d021604f5978214a3f";
const LEASE_SCOPE: &str = "/home/ubuntu/.jetstreamer-private/destination-cc16e4ac982549c49990203164025f5c92247f275e6530e0654ed82c45a07519";
const PRIVATE: &str =
    "/home/ubuntu/.jetstreamer-private/qualification-244-general-shrink-debt-budget506-e3f15eb2-v2";
const ARCHIVE: &str = "/home/ubuntu/.jetstreamer-private/qualification-244-general-shrink-debt-budget506-e3f15eb2-v2/output/epoch-244.jet";
const SIDECAR: &str = "/home/ubuntu/.jetstreamer-private/qualification-244-general-shrink-debt-budget506-e3f15eb2-v2/output/epoch-244.jet.sha256";
const ARCHIVE_SHA: &str = "4b50748ef0e458cf71da050acb3b7e3751e5d1918db8cd0bd40f80b0deccbe27";
const ARCHIVE_BYTES: u64 = 175_862_403_401;
const HASH_REPORT: &str =
    "/home/ubuntu/.codex/diagnostics/horizon-244-private-archive-hash-20261117.txt";
const GUARD_BINARY: &str = "/var/lib/jetstreamer/horizon244-current-import-guard-20261117-v2/jetstreamer-horizon-standalone-guard";
const GUARD_SHA: &str = "f8c9e2ae06833eefb053ef59698716fdd67afae2decb85237c7fd969233a19fb";
const R2_BINARY: &str =
    "/var/lib/jetstreamer/horizon-status240243-cleanup-production-SDK2451-v1/jetstreamer-r2";
const R2_SHA: &str = "2e718f08c3cd072c40f79dbb85f35fd59864aedc26782fcfd89a031a7ff67c07";
const SEALER: &str =
    "/var/lib/jetstreamer/horizon-live-observe-a1afd55-v147/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "96521c2edb8d0d3add79da92eed6b5f4fc3c3fed7eb5eea49cedcc3cc779ae24";
const OPERATOR_RUNTIME: &str = "/var/lib/jetstreamer/horizon244-current-import-operator-20261117-v7/horizon-epoch244-import-operator";
const STATE: &str = "/var/lib/jetstreamer/horizon244-current-import-operator-state-20261117-v2";
const GUARD_PACKAGE: &str = "/var/lib/jetstreamer/horizon244-current-import-protective-20261117-v2";
const TOKENS: &str = "/var/lib/jetstreamer/horizon244-current-import-tokens-20261117-v1";
const RECEIPTS: &str =
    "/var/lib/jetstreamer/horizon244-current-import-protective-receipts-20261117-v2";
const ROOT_CAP: u64 = 240_000_000_000;
const FLOOR: u64 = 2_000_000_000_000;
const THREE_REPLAY_OBLIGATION: u64 = 980_221_169_664;
const IMPORT_MEMORY_MAX: u64 = 68_719_476_736;
const GUARD_MEMORY_MAX: u64 = 1_073_741_824;
const MINIMUM_HOST_MEMORY_RESERVE: u64 = 64 * 1024 * 1024 * 1024;
const VERIFIER_TRANSITIONS: [(&str, &str, &str, &str, &str, &str); 2] = [
    (
        "horizon-full-verify-239-current-20261117-v1.service",
        "208d2a07f4d34cdc9a125aaae3487ec3",
        "horizon-full-verify-239-current-20261117-v2.service",
        "7c0afd0381fe4a5b80e699c0d5fec88b",
        "/home/ubuntu/.jetstreamer-private/verification-239-current-20261117-v2/full/receipts/epoch-239.full.ok",
        "6ff8a6be80712b258577c027bf3512274a9c7d9f326b77a5cb07906205125302",
    ),
    (
        "horizon-plugin-verify-239-current-20261117-v1.service",
        "21d503ce8c38402a922b6235f778537d",
        "horizon-plugin-verify-239-current-20261117-v2.service",
        "3398bff4b3154fb8935358d3b8a48375",
        "/home/ubuntu/.jetstreamer-private/verification-239-current-20261117-v2/plugin/receipts/epoch-239.plugin.ok",
        "853c8a3f7448a75afbeea1fdf6b6e6e4f0001e970162bc2ad3b05e01d29f3c5b",
    ),
];
const VERIFIER_MEMORY_MAX: u64 = 68_719_476_736;
const EPOCH239_ARCHIVE_SHA: &str =
    "d530332035fa1765f4f222c3df6ff9aa5825817c2be5ff0dc27f7f1d37c88189";
const VERIFIER_SCRIPT_SHA: &str =
    "ad8ab9a04394797ae4ee4ff7b65297bd3c75e4997d32be0948757f43ddbc8dfe";
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
            "--property=Id,LoadState,ActiveState,SubState,InvocationID,NRestarts,Result,MainPID,Restart,KillMode,Delegate,ControlGroup,ExecMainStartTimestamp,MemoryMax,FragmentPath,UnitFileState",
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

fn concurrent_verifier_memory_max_bytes() -> Result<u64> {
    let mut total = 0_u64;
    for (old_unit, old_id, current_unit, current_id, receipt, verifier_sha) in VERIFIER_TRANSITIONS
    {
        let old = fields(old_unit)?;
        ensure!(
            field(&old, "InvocationID")? == old_id
                && field(&old, "ActiveState")? == "failed"
                && field(&old, "Result")? == "exit-code"
                && field(&old, "MainPID")? == "0"
                && field(&old, "NRestarts")? == "0",
            "superseded verifier changed: {old_unit}"
        );
        let current = fields(current_unit)?;
        ensure!(
            field(&current, "NRestarts")? == "0"
                && field(&current, "MemoryMax")? == VERIFIER_MEMORY_MAX.to_string(),
            "current verifier identity or cap changed: {current_unit}"
        );
        match field(&current, "ActiveState")? {
            "active" | "activating" => {
                ensure!(
                    field(&current, "InvocationID")? == current_id
                        && field(&current, "Result")? == "success",
                    "current verifier failed: {current_unit}"
                );
                total = total
                    .checked_add(VERIFIER_MEMORY_MAX)
                    .context("verifier memory overflow")?;
            }
            "inactive" => {
                let id = field(&current, "InvocationID")?;
                ensure!(
                    (id.is_empty() || id == current_id)
                        && field(&current, "SubState")? == "dead"
                        && field(&current, "Result")? == "success",
                    "current verifier ended unsuccessfully: {current_unit}"
                );
                let path = Path::new(receipt);
                let meta = fs::symlink_metadata(path)?;
                ensure!(
                    meta.is_file()
                        && meta.uid() == 0
                        && meta.nlink() == 1
                        && meta.mode() & 0o077 == 0
                        && meta.len() <= 256
                        && fs::read_to_string(path)?
                            == format!(
                                "{EPOCH239_ARCHIVE_SHA} {verifier_sha} {VERIFIER_SCRIPT_SHA}\n"
                            ),
                    "current verifier completion receipt changed: {current_unit}"
                );
            }
            state => anyhow::bail!("unresolved verifier state {current_unit}: {state}"),
        }
    }
    Ok(total)
}

fn admitted_memory_obligation(total: u64, verifier_max: u64) -> Result<u64> {
    let obligation = THREE_REPLAY_OBLIGATION
        .checked_add(IMPORT_MEMORY_MAX)
        .and_then(|value| value.checked_add(GUARD_MEMORY_MAX))
        .and_then(|value| value.checked_add(verifier_max))
        .context("memory obligation overflow")?;
    ensure!(
        obligation
            .checked_add(MINIMUM_HOST_MEMORY_RESERVE)
            .is_some_and(|reserved| reserved <= total),
        "import memory admission lacks host reserve"
    );
    Ok(obligation)
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

fn observer_json(path: &Path, expected_sha256: &str) -> Result<Value> {
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file()
            && before.nlink() == 1
            && (before.uid() == 0 || before.uid() == 1000)
            && before.mode() & 0o022 == 0
            && before.len() <= 4 << 20,
        "unsafe observer receipt {}",
        path.display()
    );
    let bytes = fs::read(path)?;
    ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == expected_sha256,
        "observer hash changed"
    );
    let after = fs::symlink_metadata(path)?;
    ensure!(
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec(),
        "observer identity changed"
    );
    Ok(serde_json::from_slice(&bytes)?)
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
            format!("{IMPORT_PACKAGE}/horizon-epoch244-import-source"),
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
        proof["schema"] == "horizon-epoch244-native-namespace-proof-v1"
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
            && proof["mask_count"] == 1574
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
                .is_some_and(|masks| masks.len() == 1574 && !masks.iter().any(|p| p == LEASE_SCOPE))
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
        fs::read_to_string(SIDECAR)? == format!("{ARCHIVE_SHA}  epoch-244.jet\n"),
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
        !Path::new("/home/ubuntu/horizon/epoch-244.jet").exists()
            && !Path::new("/home/ubuntu/horizon/epoch-244.jet.sha256").exists(),
        "canonical epoch 244 already present"
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

fn failed_import_state(
    importer: &BTreeMap<String, String>,
    guard: &BTreeMap<String, String>,
    timer: &BTreeMap<String, String>,
) -> Result<()> {
    ensure!(
        field(importer, "LoadState")? == "loaded"
            && field(importer, "ActiveState")? == "failed"
            && field(importer, "SubState")? == "failed"
            && field(importer, "InvocationID")? == FAILED_IMPORT_ID
            && field(importer, "Result")? == "signal"
            && field(importer, "MainPID")? == "0"
            && field(importer, "NRestarts")? == "0"
            && field(importer, "ExecMainStartTimestamp")?.is_empty()
            && field(importer, "FragmentPath")? == format!("/etc/systemd/system/{IMPORT_UNIT}")
            && field(importer, "UnitFileState")? == "linked",
        "failed import identity or pre-native boundary changed"
    );
    ensure!(
        field(guard, "InvocationID")? == FAILED_GUARD_ID
            && field(guard, "ActiveState")? == "failed"
            && field(guard, "Result")? == "exit-code",
        "failed first guard changed"
    );
    ensure!(
        field(timer, "ActiveState")? == "inactive" && field(timer, "SubState")? == "dead",
        "old protective timer remains active"
    );
    Ok(())
}

fn failed_import_retry_gate(
    importer: &BTreeMap<String, String>,
    guard: &BTreeMap<String, String>,
    timer: &BTreeMap<String, String>,
) -> Result<()> {
    failed_import_state(importer, guard, timer)?;
    ensure!(
        fs::read_link(format!("/etc/systemd/system/{IMPORT_UNIT}"))?
            == Path::new(&format!("{IMPORT_PACKAGE}/{IMPORT_UNIT}")),
        "installed import unit link changed"
    );
    ensure!(!Path::new(TOKENS).exists(), "old import token exists");
    let log = fs::symlink_metadata(format!("{PRIVATE}/output/import-244.log"))?;
    ensure!(
        log.is_file() && log.len() == 0,
        "native import output exists"
    );
    Ok(())
}

fn inspect(observer_path: &Path, observer_sha: &str) -> Result<Value> {
    check_static()?;
    no_other_public_importer()?;
    let observer = observer_json(observer_path, observer_sha)?;
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
    let verifier_max = concurrent_verifier_memory_max_bytes()?;
    let obligation = admitted_memory_obligation(total, verifier_max)?;
    let free = available_bytes()?;
    ensure!(
        free >= FLOOR + ARCHIVE_BYTES + 16_000_000_000,
        "import disk admission failed"
    );
    let remote: Value = serde_json::from_str(&command(
        R2_BINARY,
        &["inventory", "/home/ubuntu/horizon", "--epochs", "244-244"],
    )?)?;
    ensure!(
        remote["ready_pairs"] == 0
            && remote["missing"] == 1
            && remote["anomalies"] == 0
            && remote["entries"][0]["state"] == "missing",
        "R2 epoch 244 is no longer missing"
    );
    failed_import_retry_gate(
        &fields(IMPORT_UNIT)?,
        &fields(OLD_GUARD_UNIT)?,
        &fields(OLD_TIMER_UNIT)?,
    )?;
    Ok(
        json!({"schema":"horizon244-native-import-main-admission-v1", "issued_unix_seconds":current,
        "expires_unix_seconds":current+120,"epoch":244,"Main_accepted":true,"observer":{"path":observer_path,"sha256":observer_sha},
        "native_proof":{"path":NATIVE_PROOF,"sha256":NATIVE_PROOF_SHA},"r2_inventory":remote,
        "live_replay_count":3,"retained_replay_memory_obligation_bytes":THREE_REPLAY_OBLIGATION,
        "candidate_import_memory_max_bytes":IMPORT_MEMORY_MAX,"guard_memory_max_bytes":GUARD_MEMORY_MAX,
        "concurrent_verifier_memory_max_bytes":verifier_max,
        "minimum_host_memory_reserve_bytes":MINIMUM_HOST_MEMORY_RESERVE,
        "memory_obligation_after_bytes":obligation,"host_memory_total_bytes":total,
        "available_disk_bytes":free,"minimum_free_bytes":FLOOR,
        "import_unit":IMPORT_UNIT,"failed_import_invocation_id":FAILED_IMPORT_ID,
        "guard_unit":GUARD_UNIT,"timer_unit":TIMER_UNIT,
        "namespace_probe_completed":true,
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
        "[Unit]\nDescription=Exact epoch 244 native import disk and VMA guard\n[Service]\nType=oneshot\nUser=root\nUMask=0077\nRestart=no\nMemoryMax=1073741824\nMemorySwapMax=0\nCPUQuota=100%\nTasksMax=256\nTimeoutStartSec=90\nProtectSystem=strict\nProtectHome=read-only\nPrivateNetwork=yes\nNoNewPrivileges=yes\nCapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE\nAmbientCapabilities=CAP_DAC_OVERRIDE CAP_SYS_PTRACE\nReadWritePaths={RECEIPTS}\nExecStart={GUARD_BINARY} {GUARD_PACKAGE}/guard-plan.json --plan-sha256 {plan_sha} --self-sha256 {GUARD_SHA}\n"
    );
    let timer = format!(
        "[Unit]\nDescription=Exact epoch 244 native import protective timer\n[Timer]\nOnActiveSec=1s\nOnUnitInactiveSec=60s\nAccuracySec=1s\nRandomizedDelaySec=0\nUnit={GUARD_UNIT}\n"
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
    let token = json!({"schema":"horizon244-native-import-real-first-guard-token-v1",
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
    command("/usr/bin/systemctl", &["reset-failed", IMPORT_UNIT])?;
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
            if id.len() == 32 && id != FAILED_IMPORT_ID && field(&row, "NRestarts")? == "0" {
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
    let handoff = json!({"schema":"horizon244-native-import-guarded-startup-v1","recorded_unix_seconds":now()?,
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
            "horizon-import-244-current-20261117-v1.service"
        );
        assert_eq!(GUARD_SHA.len(), 64);
        assert!(THREE_REPLAY_OBLIGATION + IMPORT_MEMORY_MAX + GUARD_MEMORY_MAX < 1_212_136_964_096);
        assert!(ROOT_CAP > ARCHIVE_BYTES);
        assert_eq!(FLOOR, 2_000_000_000_000);
        assert_eq!(LIVE.len(), 3);
    }

    #[test]
    fn concurrent_239_verifiers_block_import_until_capacity_is_released() {
        let host_total = 1_212_136_964_096;
        let two_verifiers = 2 * 68_719_476_736;
        assert!(admitted_memory_obligation(host_total, two_verifiers).is_err());
        assert!(admitted_memory_obligation(host_total, 0).is_ok());
    }

    #[test]
    fn retry_requires_exact_failed_pre_native_invocation() {
        let importer: BTreeMap<String, String> = [
            ("LoadState", "loaded"),
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("InvocationID", FAILED_IMPORT_ID),
            ("Result", "signal"),
            ("MainPID", "0"),
            ("NRestarts", "0"),
            ("ExecMainStartTimestamp", ""),
            (
                "FragmentPath",
                "/etc/systemd/system/horizon-import-244-current-20261117-v1.service",
            ),
            ("UnitFileState", "linked"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let guard: BTreeMap<String, String> = [
            ("InvocationID", FAILED_GUARD_ID),
            ("ActiveState", "failed"),
            ("Result", "exit-code"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let timer: BTreeMap<String, String> = [("ActiveState", "inactive"), ("SubState", "dead")]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        assert!(failed_import_state(&importer, &guard, &timer).is_ok());
        for (key, bad) in [
            ("InvocationID", "different"),
            ("Result", "exit-code"),
            ("MainPID", "42"),
            ("ExecMainStartTimestamp", "Tue 2026-11-17 11:47:33 UTC"),
            ("UnitFileState", "enabled"),
        ] {
            let mut changed = importer.clone();
            changed.insert(key.to_owned(), bad.to_owned());
            assert!(
                failed_import_state(&changed, &guard, &timer).is_err(),
                "{key}"
            );
        }
        let mut changed_guard = guard.clone();
        changed_guard.insert("InvocationID".into(), "different".into());
        assert!(failed_import_state(&importer, &changed_guard, &timer).is_err());
        let mut changed_timer = timer.clone();
        changed_timer.insert("ActiveState".into(), "active".into());
        assert!(failed_import_state(&importer, &guard, &changed_timer).is_err());
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

    #[test]
    fn observer_receipt_accepts_owner_only_file_and_rejects_writable_file() {
        let path = std::env::temp_dir().join(format!(
            "horizon244-observer-test-{}-{}",
            std::process::id(),
            now().unwrap()
        ));
        let bytes = br#"{"schema":"jetstreamer-horizon-live-resource-sample-v2"}"#;
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let digest = format!("{:x}", Sha256::digest(bytes));
        assert!(observer_json(&path, &digest).is_ok());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(observer_json(&path, &digest).is_err());
        fs::remove_file(path).unwrap();
    }
}
