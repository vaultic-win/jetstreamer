// Shared compile-time-profile exact-generation download engine.
// The SDK transports bytes; Rust owns admission binding, limits and integrity.
#[allow(dead_code)]
mod epoch141_ledger_common;
use {
    anyhow::{Context, Result, ensure},
    base64::{Engine, engine::general_purpose::STANDARD},
    epoch141_ledger_common::{
        bound_file, drop_cli_identity, identity, observe_gcloud_object, sha,
        validate_object_metadata, write_receipt,
    },
    md5::Md5,
    profile::*,
    serde::Deserialize,
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    std::{
        collections::BTreeMap,
        env,
        ffi::CString,
        fs::{self, File, OpenOptions},
        io::Read,
        os::unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            process::CommandExt,
        },
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    },
};

const SLACK: u64 = 64 * 1024 * 1024;
const GCLOUD: &str = "/usr/lib/google-cloud-sdk/bin/gcloud";
const CLOUD_CONFIG: &str = "/home/sol/.config/gcloud";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundInput {
    path: PathBuf,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    gcloud_sha256: String,
    metadata_receipt: BoundInput,
    admission_receipt: BoundInput,
    staging_directory: PathBuf,
    output_receipt: PathBuf,
    stop_intent: PathBuf,
    stop_completion: PathBuf,
    initial_guard_receipt: PathBuf,
    minimum_free_bytes: u64,
    maximum_runtime_seconds: u64,
}

fn free_bytes(path: &Path) -> Result<u64> {
    let name = CString::new(path.as_os_str().as_encoded_bytes())?;
    let mut state = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(name.as_ptr(), state.as_mut_ptr()) } == 0,
        "cannot measure actual free space"
    );
    let state = unsafe { state.assume_init() };
    state
        .f_bavail
        .checked_mul(state.f_frsize)
        .context("free-byte overflow")
}

fn private_parent(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "nonabsolute path");
    let parent = path.parent().context("missing parent")?;
    ensure!(parent.canonicalize()? == parent, "noncanonical parent");
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "parent must be root-private"
    );
    Ok(())
}

fn validate_metadata_receipt(metadata: &Value) -> Result<()> {
    ensure!(
        metadata["schema"] == METADATA_SCHEMA
            && metadata["epoch"] == EPOCH
            && metadata["download_performed"] == false,
        "wrong metadata authority"
    );
    validate_object_metadata(&metadata["metadata"], &OBJECT)
}

fn validate_admission_receipt(admission: &Value, now: u64) -> Result<()> {
    ensure!(
        admission["admitted"] == true,
        "admission receipt did not pass"
    );
    if EPOCH == 144 {
        ensure!(
            admission["schema"] == "jetstreamer-epoch144-snapshot-admission-receipt-v1"
                && admission["epoch"] == 144
                && admission["download_only"] == true
                && admission["native_restore_authorized"] == false
                && admission["replay_launch_authorized"] == false
                && admission["publication_authorized"] == false
                && admission["remote_mutations"] == false
                && admission["r2_mutations"] == false
                && admission["protected_existing_floor_bytes"] == 4_740_696_923_590u64
                && admission["candidate_incremental_peak_bytes"] == SIZE + SLACK
                && admission["recorded_unix_seconds"]
                    .as_u64()
                    .is_some_and(|n| n <= now && now - n <= 1800),
            "wrong or stale snapshot-only144 admission authority"
        );
    } else {
        ensure!(
            admission["schema"] == "jetstreamer-historical-performance-admission-receipt-v1",
            "wrong legacy admission authority"
        );
    }
    Ok(())
}

fn validate_plan(plan: &Plan, executable: &Path, executable_sha256: &str) -> Result<()> {
    ensure!(plan.schema == PLAN_SCHEMA, "wrong plan schema");
    ensure!(
        (60..=172800).contains(&plan.maximum_runtime_seconds),
        "invalid runtime bound"
    );
    // Current sealed century floor. Admission must add every older live growth
    // claim; this lower bound alone never substitutes for that admission.
    ensure!(
        plan.minimum_free_bytes >= 205_211_459_014,
        "stop floor below verified century floor"
    );
    if EPOCH == 144 {
        ensure!(
            plan.minimum_free_bytes >= 4_740_696_923_590,
            "144 transfer stop floor dropped older growth protection"
        );
    }
    for p in [
        &plan.output_receipt,
        &plan.stop_intent,
        &plan.stop_completion,
        &plan.initial_guard_receipt,
    ] {
        private_parent(p)?;
        ensure!(
            !p.try_exists()? && fs::symlink_metadata(p).is_err(),
            "output already exists"
        );
    }
    let parent = plan
        .staging_directory
        .parent()
        .context("missing staging parent")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        plan.staging_directory.is_absolute()
            && parent.canonicalize()? == parent
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o777 == 0o711,
        "SDK staging parent must be canonical root-owned 0711"
    );
    ensure!(
        fs::symlink_metadata(&plan.staging_directory).is_err(),
        "staging directory must be a fresh no-clobber attempt"
    );
    ensure!(
        plan.output_receipt != plan.stop_intent
            && plan.output_receipt != plan.stop_completion
            && plan.stop_intent != plan.stop_completion
            && !plan.output_receipt.starts_with(&plan.staging_directory)
            && !plan.stop_intent.starts_with(&plan.staging_directory)
            && !plan.stop_completion.starts_with(&plan.staging_directory),
        "overlapping output paths"
    );
    ensure!(
        !plan
            .initial_guard_receipt
            .starts_with(&plan.staging_directory)
            && [
                &plan.output_receipt,
                &plan.stop_intent,
                &plan.stop_completion
            ]
            .iter()
            .all(|p| **p != plan.initial_guard_receipt),
        "guard receipt overlaps other outputs"
    );
    let metadata: Value = serde_json::from_slice(&bound_file(
        &plan.metadata_receipt.path,
        &plan.metadata_receipt.sha256,
        65536,
        false,
    )?)?;
    validate_metadata_receipt(&metadata)?;
    let admission: Value = serde_json::from_slice(&bound_file(
        &plan.admission_receipt.path,
        &plan.admission_receipt.sha256,
        4 * 1024 * 1024,
        false,
    )?)?;
    validate_admission_receipt(
        &admission,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    let required = plan
        .minimum_free_bytes
        .checked_add(SIZE + SLACK)
        .context("admission overflow")?;
    ensure!(
        admission["evidence"]["minimum_free_bytes"]
            .as_u64()
            .is_some_and(|n| n >= required)
            && admission["evidence"]["available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= required),
        "admission did not protect full compressed transfer above all older growth/floor"
    );
    let filesystem = Path::new(
        admission["evidence"]["filesystem"]
            .as_str()
            .context("admission filesystem missing")?,
    );
    ensure!(
        filesystem.canonicalize()? == filesystem && fs::metadata(filesystem)?.dev() == m.dev(),
        "admission filesystem differs from staging"
    );
    let files = admission["evidence"]["files"]
        .as_array()
        .context("admission file census missing")?;
    for (path, digest) in [
        (executable, executable_sha256),
        (
            plan.metadata_receipt.path.as_path(),
            plan.metadata_receipt.sha256.as_str(),
        ),
    ] {
        ensure!(
            files
                .iter()
                .any(|file| file["path"].as_str() == path.to_str()
                    && file["sha256"].as_str() == Some(digest)),
            "admission does not bind exact downloader and metadata receipt"
        );
    }
    Ok(())
}

/// Keep the child unreaped until its entire disposable process group is killed.
/// WNOWAIT prevents PID/PGID reuse between completion observation and cleanup.
struct OwnedDownload(Option<Child>);

impl OwnedDownload {
    fn exited(&self) -> Result<bool> {
        let child = self.0.as_ref().context("child already reaped")?;
        let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        let code = unsafe {
            libc::waitid(
                libc::P_PID,
                child.id(),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        ensure!(
            code == 0,
            "waitid failed: {}",
            std::io::Error::last_os_error()
        );
        Ok(unsafe { info.si_pid() } != 0)
    }

    fn finish(&mut self) -> Result<std::process::ExitStatus> {
        let child = self.0.as_mut().context("child already reaped")?;
        let result = unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
        ensure!(
            result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH),
            "cannot terminate owned SDK process group"
        );
        let status = child.wait()?;
        self.0 = None;
        Ok(status)
    }
}

impl Drop for OwnedDownload {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0
            && unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) } == 0
        {
            let _ = child.wait();
        }
        // If CAP_KILL is missing, do not block forever in Drop. Exit and let
        // the required systemd KillMode=control-group clean the service up.
    }
}

fn configure_sdk(command: &mut Command) {
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/home/sol")
        .env("LANG", "C.UTF-8")
        .env("CLOUDSDK_CONFIG", CLOUD_CONFIG)
        .env("CLOUDSDK_CORE_DISABLE_PROMPTS", "1")
        .env("CLOUDSDK_CORE_DISABLE_FILE_LOGGING", "1")
        .env("CLOUDSDK_STORAGE_PROCESS_COUNT", "1")
        .env("CLOUDSDK_STORAGE_THREAD_COUNT", "1")
        .env("CLOUDSDK_STORAGE_SLICED_OBJECT_DOWNLOAD_THRESHOLD", "0")
        .env(
            "CLOUDSDK_STORAGE_SLICED_OBJECT_DOWNLOAD_MAX_COMPONENTS",
            "1",
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    drop_cli_identity(command);
}

fn staged_bytes(directory: &Path) -> Result<u64> {
    let mut bytes = 0u64;
    let mut count = 0;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let m = fs::symlink_metadata(entry.path())?;
        ensure!(m.is_file() && m.nlink() == 1, "unsafe SDK staging member");
        count += 1;
        ensure!(count <= 4, "SDK staging file-count bound exceeded");
        bytes = bytes
            .checked_add(m.len())
            .context("staging length overflow")?;
    }
    Ok(bytes)
}

fn guard(plan: &Plan, start: Instant) -> Result<()> {
    guard_snapshot(plan, start).map(|_| ())
}

fn guard_snapshot(plan: &Plan, start: Instant) -> Result<(u64, u64)> {
    ensure!(
        start.elapsed().as_secs() < plan.maximum_runtime_seconds,
        "download runtime bound reached"
    );
    let available = free_bytes(&plan.staging_directory)?;
    ensure!(
        available >= plan.minimum_free_bytes,
        "protected actual-free-space stop floor reached"
    );
    let staged = staged_bytes(&plan.staging_directory)?;
    ensure!(
        staged <= SIZE + SLACK,
        "download staging byte bound exceeded"
    );
    Ok((available, staged))
}

fn digest_reader(
    mut input: impl Read,
    mut guard: impl FnMut() -> Result<()>,
) -> Result<(u64, String, String, String)> {
    let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI);
    let mut crc_digest = crc.digest();
    let mut md5 = Md5::new();
    let mut sha256 = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = vec![0; 4 * 1024 * 1024];
    loop {
        guard()?;
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(count as u64)
            .context("input byte overflow")?;
        ensure!(
            bytes <= SIZE,
            "compressed input exceeds exact generation length"
        );
        crc_digest.update(&buffer[..count]);
        md5.update(&buffer[..count]);
        sha256.update(&buffer[..count]);
    }
    Ok((
        bytes,
        STANDARD.encode(crc_digest.finalize().to_be_bytes()),
        STANDARD.encode(md5.finalize()),
        format!("{:x}", sha256.finalize()),
    ))
}

fn create_staging(path: &Path) -> Result<File> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    let directory = File::open(path)?;
    ensure!(
        unsafe { libc::fchown(std::os::fd::AsRawFd::as_raw_fd(&directory), 1001, 1003) } == 0,
        "cannot assign SDK staging directory"
    );
    File::open(path.parent().context("missing staging parent")?)?.sync_all()?;
    Ok(directory)
}

fn freeze_input(
    directory: &File,
    destination: &Path,
    expected_size: u64,
) -> Result<(File, fs::Metadata)> {
    // Freeze the directory before opening/hashing the file. Existing SDK children
    // were killed while the leader still held its PID/PGID, before being reaped.
    ensure!(
        unsafe { libc::fchown(std::os::fd::AsRawFd::as_raw_fd(directory), 0, 0) } == 0,
        "cannot freeze staging directory"
    );
    directory.sync_all()?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(destination)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.uid() == 1001 && m.len() == expected_size,
        "downloaded file has unsafe identity or wrong length"
    );
    ensure!(
        unsafe { libc::fchown(std::os::fd::AsRawFd::as_raw_fd(&file), 0, 0) } == 0,
        "cannot freeze downloaded file owner"
    );
    file.set_permissions(fs::Permissions::from_mode(0o444))?;
    file.sync_all()?;
    directory.sync_all()?;
    let before_hash = file.metadata()?;
    Ok((file, before_hash))
}

fn download(plan: &Plan, invocation: &str, plan_sha256: &str, self_sha256: &str) -> Result<()> {
    let parent = plan
        .staging_directory
        .parent()
        .context("missing staging parent")?;
    let required = plan
        .minimum_free_bytes
        .checked_add(SIZE + SLACK)
        .context("admission sum overflow")?;
    ensure!(
        free_bytes(parent)? >= required,
        "insufficient free bytes above protected growth/floor"
    );
    bound_file(
        Path::new(GCLOUD),
        &plan.gcloud_sha256,
        16 * 1024 * 1024,
        false,
    )?;
    let before = observe_gcloud_object(&OBJECT)?;
    validate_object_metadata(&serde_json::from_slice::<Value>(&before)?, &OBJECT)?;
    bound_file(
        Path::new(GCLOUD),
        &plan.gcloud_sha256,
        16 * 1024 * 1024,
        false,
    )?;
    let directory = create_staging(&plan.staging_directory)?;
    let destination = plan.staging_directory.join(FILENAME);
    let mut command = Command::new(GCLOUD);
    command
        .args([
            "storage",
            "cp",
            "--no-clobber",
            "--quiet",
            "--account=sam.johnson@anza.xyz",
            "--billing-project=principal-lane-200702",
            URI,
        ])
        .arg(&destination);
    configure_sdk(&mut command);
    let start = Instant::now();
    let mut child = OwnedDownload(Some(
        command
            .spawn()
            .context("spawn exact-generation SDK transfer")?,
    ));
    let mut initial_guard_recorded = false;
    loop {
        let (available, staged) = match guard_snapshot(plan, start) {
            Ok(sample) => sample,
            Err(error) => {
                // Intent is durable before stopping the one owned download group.
                // Drop still stops the group if writing the intent itself fails.
                write_receipt(
                    &plan.stop_intent,
                    &json!({
                        "schema":STOP_INTENT_SCHEMA,
                        "invocation_id":invocation,"plan_sha256":plan_sha256,
                        "child_pid":child.0.as_ref().context("missing child")?.id(),
                        "reason":error.to_string(),"partial_preserved":true,
                        "replay_launch_authorized":false,"r2_mutations":false
                    }),
                )?;
                child.finish()?;
                write_receipt(
                    &plan.stop_completion,
                    &json!({
                        "schema":STOP_COMPLETION_SCHEMA,
                        "invocation_id":invocation,"plan_sha256":plan_sha256,
                        "owned_child_reaped":true,"partial_preserved":true,
                        "replay_launch_authorized":false,"r2_mutations":false
                    }),
                )?;
                return Err(error);
            }
        };
        if !initial_guard_recorded {
            write_receipt(
                &plan.initial_guard_receipt,
                &json!({
                    "schema":INITIAL_GUARD_SCHEMA,
                    "invocation_id":invocation,"plan_sha256":plan_sha256,"self_sha256":self_sha256,
                    "child_pid":child.0.as_ref().context("missing child")?.id(),
                    "available_bytes":available,
                    "minimum_free_bytes":plan.minimum_free_bytes,
                    "staged_bytes":staged,
                    "maximum_staged_bytes":SIZE + SLACK,
                    "maximum_runtime_seconds":plan.maximum_runtime_seconds,
                    "guard_interval_seconds":1,"trip":false,
                    "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                    "replay_launch_authorized":false,"publication_authorized":false,
                    "remote_mutations":false,"r2_mutations":false
                }),
            )?;
            initial_guard_recorded = true;
            println!(
                "exact-generation owned download guard armed; private initial receipt durable"
            );
        }
        if child.exited()? {
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }
    ensure!(
        child.finish()?.success(),
        "generation-bound SDK download failed; private partial preserved"
    );
    let (mut file, before_hash) = freeze_input(&directory, &destination, SIZE)?;
    let (bytes, crc32c, md5, sha256) = digest_reader(&mut file, || guard(plan, start))?;
    ensure!(
        bytes == SIZE && crc32c == CRC && md5 == MD5,
        "compressed generation integrity mismatch"
    );
    ensure!(
        identity(&before_hash) == identity(&file.metadata()?)
            && identity(&before_hash) == identity(&fs::symlink_metadata(&destination)?),
        "compressed input changed during verification"
    );
    let after = observe_gcloud_object(&OBJECT)?;
    validate_object_metadata(&serde_json::from_slice::<Value>(&after)?, &OBJECT)?;
    bound_file(
        Path::new(GCLOUD),
        &plan.gcloud_sha256,
        16 * 1024 * 1024,
        false,
    )?;
    guard(plan, start)?;
    ensure!(
        identity(&before_hash) == identity(&file.metadata()?)
            && identity(&before_hash) == identity(&fs::symlink_metadata(&destination)?),
        "verified source changed before receipt"
    );
    write_receipt(
        &plan.output_receipt,
        &json!({
            "schema":RECEIPT_SCHEMA,"epoch":EPOCH,
            "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            "invocation_id":invocation,"plan_sha256":plan_sha256,"self_sha256":self_sha256,
            "uri":URI,"generation":GENERATION,"path":destination,"bytes":bytes,
            "crc32c_base64":crc32c,"md5_base64":md5,"sha256":sha256,
            "device":before_hash.dev(),"inode":before_hash.ino(),
            "uid":before_hash.uid(),"mode":"0444","links":before_hash.nlink(),
            "metadata_before_sha256":sha(&before),"metadata_after_sha256":sha(&after),
            "admission_receipt_sha256":plan.admission_receipt.sha256,
            "minimum_free_bytes":plan.minimum_free_bytes,"elapsed_seconds":start.elapsed().as_secs(),
            "compressed_input_verified":true,"source_completeness_proven":false,
            "live_state_proven":false,"replay_launch_authorized":false,
            "publication_authorized":false,"remote_mutations":false,"r2_mutations":false
        }),
    )?;
    Ok(())
}

fn run() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "download wrapper must run as root"
    );
    let mut arguments = env::args().skip(1);
    let mut values = BTreeMap::new();
    while let Some(key) = arguments.next() {
        ensure!(
            ["--plan", "--plan-sha256", "--self-sha256"].contains(&key.as_str()),
            "unknown option"
        );
        let value = arguments.next().context("missing option value")?;
        ensure!(values.insert(key, value).is_none(), "duplicate option");
    }
    ensure!(
        values.len() == 3,
        "require --plan, --plan-sha256 and --self-sha256"
    );
    let executable = Path::new("/proc/self/exe").read_link()?;
    bound_file(
        &executable,
        &values["--self-sha256"],
        64 * 1024 * 1024,
        true,
    )?;
    let plan: Plan = serde_json::from_slice(&bound_file(
        Path::new(&values["--plan"]),
        &values["--plan-sha256"],
        65536,
        true,
    )?)?;
    validate_plan(&plan, &executable, &values["--self-sha256"])?;
    let invocation = env::var("INVOCATION_ID").context("persistent systemd invocation required")?;
    ensure!(
        invocation.len() == 32
            && invocation
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid invocation ID"
    );
    download(
        &plan,
        &invocation,
        &values["--plan-sha256"],
        &values["--self-sha256"],
    )?;
    println!("exact compressed generation verified; private no-clobber receipt written");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admission_authority_is_profile_specific_and144_is_fresh_download_only() {
        let legacy = json!({"schema":"jetstreamer-historical-performance-admission-receipt-v1","admitted":true});
        if EPOCH != 144 {
            validate_admission_receipt(&legacy, 10000).unwrap();
            return;
        }
        assert!(validate_admission_receipt(&legacy, 10000).is_err());
        let good = json!({"schema":"jetstreamer-epoch144-snapshot-admission-receipt-v1","admitted":true,
            "epoch":144,"download_only":true,"native_restore_authorized":false,"replay_launch_authorized":false,
            "publication_authorized":false,"remote_mutations":false,"r2_mutations":false,
            "protected_existing_floor_bytes":4740696923590u64,"candidate_incremental_peak_bytes":SIZE+SLACK,
            "recorded_unix_seconds":9000});
        validate_admission_receipt(&good, 10000).unwrap();
        for (key, value) in [
            ("epoch", json!(140)),
            ("download_only", json!(false)),
            ("native_restore_authorized", json!(true)),
            ("replay_launch_authorized", json!(true)),
            ("r2_mutations", json!(true)),
            ("publication_authorized", json!(true)),
            ("protected_existing_floor_bytes", json!(1)),
            ("candidate_incremental_peak_bytes", json!(1)),
            ("recorded_unix_seconds", json!(10001)),
            ("recorded_unix_seconds", json!(1)),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(validate_admission_receipt(&bad, 10000).is_err(), "{key}");
        }
    }

    #[test]
    fn metadata_receipt_cannot_borrow_another_object_or_profile_authority() {
        let value = json!({"schema":METADATA_SCHEMA,"epoch":EPOCH,"download_performed":false,
            "metadata":{"bucket":OBJECT.bucket,"name":OBJECT.name,"generation":GENERATION,
            "size":SIZE,"crc32c_hash":CRC,"md5_hash":MD5,"storage_url":URI}});
        validate_metadata_receipt(&value).unwrap();
        for (key, other) in [
            ("schema", json!("another-profile")),
            ("epoch", json!(EPOCH + 1)),
            ("download_performed", json!(true)),
            ("metadata", json!({})),
        ] {
            let mut bad = value.clone();
            bad[key] = other;
            assert!(validate_metadata_receipt(&bad).is_err(), "{key}");
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(validate_metadata_receipt(&missing).is_err(), "missing{key}");
        }
        for key in [
            "name",
            "generation",
            "storage_url",
            "crc32c_hash",
            "md5_hash",
        ] {
            let mut bad = value.clone();
            bad["metadata"][key] = json!("substituted");
            assert!(validate_metadata_receipt(&bad).is_err(), "{key}");
        }
    }

    #[test]
    fn immutable_profile_binds_exact_filename_generation_hashes_and_distinct_schemas() {
        assert_eq!(SIZE, OBJECT.size);
        assert_eq!(GENERATION, OBJECT.generation);
        assert_eq!(CRC, OBJECT.crc);
        assert_eq!(MD5, OBJECT.md5);
        assert_eq!(URI, OBJECT.uri);
        assert_eq!(OBJECT.name.rsplit('/').next(), Some(FILENAME));
        assert_eq!(
            URI,
            format!("gs://{}/{}#{}", OBJECT.bucket, OBJECT.name, GENERATION)
        );
        let schemas = [
            PLAN_SCHEMA,
            METADATA_SCHEMA,
            RECEIPT_SCHEMA,
            STOP_INTENT_SCHEMA,
            STOP_COMPLETION_SCHEMA,
            INITIAL_GUARD_SCHEMA,
        ];
        assert_eq!(
            schemas
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            schemas.len()
        );
        if EPOCH == 140 {
            assert_eq!(GENERATION, "1634786631155900");
            assert_eq!(SIZE, 2_741_858_751);
            assert_eq!(CRC, "wif3BA==");
            assert_eq!(MD5, "bEVjbHoOexfklmZRKtsfSw==");
            assert!(
                schemas
                    .iter()
                    .all(|s| s.starts_with("jetstreamer-epoch140-snapshot-"))
            );
        } else if EPOCH == 144 {
            assert_eq!(GENERATION, "1634786788446253");
            assert_eq!(SIZE, 2_569_233_422);
            assert_eq!(CRC, "K4VB8A==");
            assert_eq!(MD5, "9XLFNdvEJOFXo9YPOsNBOA==");
            assert!(
                schemas
                    .iter()
                    .all(|s| s.starts_with("jetstreamer-epoch144-snapshot-"))
            );
        } else {
            assert_eq!(EPOCH, 141);
            assert_eq!(GENERATION, "1634789748052739");
            assert_eq!(SIZE, 189_943_475_031);
            assert!(
                schemas
                    .iter()
                    .all(|s| s.starts_with("jetstreamer-epoch141-ledger-"))
            );
        }
    }

    #[test]
    fn independent_digest_vectors_and_stop_propagation() {
        let (length, crc, md5, sha256) = digest_reader(&b"123456789"[..], || Ok(())).unwrap();
        assert_eq!(length, 9);
        assert_eq!(crc, "4waSgw=="); // CRC32C 0xe3069283 in network byte order.
        assert_eq!(md5, "JfnnlDI7RTiF9RgfG2JNCw==");
        assert_eq!(
            sha256,
            "15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225"
        );
        assert!(digest_reader(&b"preserve"[..], || anyhow::bail!("stop")).is_err());
    }

    #[test]
    fn sdk_transfer_is_sequential_and_slicing_is_disabled() {
        let mut command = Command::new("/usr/bin/true");
        configure_sdk(&mut command);
        let environment: BTreeMap<_, _> = command
            .get_envs()
            .map(|(k, v)| (k.to_str().unwrap(), v.unwrap().to_str().unwrap()))
            .collect();
        for (key, value) in [
            ("CLOUDSDK_STORAGE_PROCESS_COUNT", "1"),
            ("CLOUDSDK_STORAGE_THREAD_COUNT", "1"),
            ("CLOUDSDK_STORAGE_SLICED_OBJECT_DOWNLOAD_THRESHOLD", "0"),
            (
                "CLOUDSDK_STORAGE_SLICED_OBJECT_DOWNLOAD_MAX_COMPONENTS",
                "1",
            ),
            ("CLOUDSDK_CONFIG", CLOUD_CONFIG),
        ] {
            assert_eq!(environment.get(key), Some(&value));
        }
    }

    #[test]
    fn staged_links_directories_and_large_lengths_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("one");
        fs::write(&path, b"abc").unwrap();
        assert_eq!(staged_bytes(directory.path()).unwrap(), 3);
        std::os::unix::fs::symlink(&path, directory.path().join("link")).unwrap();
        assert!(staged_bytes(directory.path()).is_err());
    }

    #[test]
    fn guard_rejects_expired_time_exhausted_space_and_oversized_sparse_input() {
        let directory = tempfile::tempdir().unwrap();
        let bound = || BoundInput {
            path: PathBuf::from("/unused"),
            sha256: "0".repeat(64),
        };
        let mut plan = Plan {
            schema: "test".into(),
            gcloud_sha256: "0".repeat(64),
            metadata_receipt: bound(),
            admission_receipt: bound(),
            staging_directory: directory.path().to_owned(),
            output_receipt: PathBuf::from("/unused-receipt"),
            stop_intent: PathBuf::from("/unused-intent"),
            stop_completion: PathBuf::from("/unused-completion"),
            initial_guard_receipt: PathBuf::from("/unused-guard"),
            minimum_free_bytes: 0,
            maximum_runtime_seconds: 60,
        };
        guard(&plan, Instant::now()).unwrap();
        plan.maximum_runtime_seconds = 0;
        assert!(
            guard(&plan, Instant::now())
                .unwrap_err()
                .to_string()
                .contains("runtime")
        );
        plan.maximum_runtime_seconds = 60;
        plan.minimum_free_bytes = u64::MAX;
        assert!(
            guard(&plan, Instant::now())
                .unwrap_err()
                .to_string()
                .contains("free-space")
        );
        plan.minimum_free_bytes = 0;
        let file = File::create(directory.path().join("oversized-sparse")).unwrap();
        file.set_len(SIZE + SLACK + 1).unwrap();
        assert!(
            guard(&plan, Instant::now())
                .unwrap_err()
                .to_string()
                .contains("byte bound")
        );
    }

    #[test]
    #[ignore = "root minimal-capability sandbox only; kills its own UID1001 child"]
    fn root_sdk_drop_and_owned_group_kill_reap() {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let mut command = Command::new("/usr/bin/sleep");
        command.arg("30");
        configure_sdk(&mut command);
        let mut child = OwnedDownload(Some(command.spawn().unwrap()));
        let pid = child.0.as_ref().unwrap().id();
        let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        assert!(
            status
                .lines()
                .any(|line| line == "Uid:\t1001\t1001\t1001\t1001")
        );
        assert!(
            status
                .lines()
                .any(|line| line == "Gid:\t1003\t1003\t1003\t1003")
        );
        assert!(
            status
                .lines()
                .any(|line| line.starts_with("Groups:") && line.split_whitespace().count() == 1)
        );
        assert_eq!(unsafe { libc::getpgid(pid as i32) }, pid as i32);
        assert!(
            status
                .lines()
                .any(|line| line == "CapEff:\t0000000000000000")
        );
        assert!(
            status
                .lines()
                .any(|line| line == "CapAmb:\t0000000000000000")
        );
        assert_eq!(child.finish().unwrap().signal(), Some(9));
        assert!(child.0.is_none());
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }

    #[test]
    #[ignore = "root sandbox with explicit fresh filesystem probe root; disposable 9-byte fixture only"]
    fn root_actual_filesystem_copy_freeze_digest_and_receipt() {
        use std::io::Write;
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let root = PathBuf::from(env::var("JETSTREAMER_EPOCH141_PATH_PROBE_ROOT").unwrap());
        assert!(root.is_absolute());
        assert_eq!(root.canonicalize().unwrap(), root);
        let m = fs::symlink_metadata(&root).unwrap();
        assert!(m.is_dir() && m.uid() == 0 && m.mode() & 0o777 == 0o711);
        assert!(fs::read_dir(&root).unwrap().next().is_none());
        let source = root.join("source.fixture");
        let mut fixture = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o444)
            .open(&source)
            .unwrap();
        fixture.write_all(b"123456789").unwrap();
        fixture
            .set_permissions(fs::Permissions::from_mode(0o444))
            .unwrap();
        fixture.sync_all().unwrap();
        let staging = root.join("staging");
        let directory = create_staging(&staging).unwrap();
        assert_eq!(fs::metadata(&staging).unwrap().uid(), 1001);
        let destination = staging.join("rocksdb.tar.bz2");
        let mut command = Command::new("/usr/bin/cp");
        command.arg(&source).arg(&destination);
        configure_sdk(&mut command);
        let mut child = OwnedDownload(Some(command.spawn().unwrap()));
        let start = Instant::now();
        while !child.exited().unwrap() {
            assert!(start.elapsed() < Duration::from_secs(10));
            thread::sleep(Duration::from_millis(10));
        }
        assert!(child.finish().unwrap().success());
        assert_eq!(fs::metadata(&destination).unwrap().uid(), 1001);
        let (mut file, before) = freeze_input(&directory, &destination, 9).unwrap();
        let (bytes, crc, md5, sha256) = digest_reader(&mut file, || Ok(())).unwrap();
        assert_eq!(bytes, 9);
        assert_eq!(crc, "4waSgw==");
        assert_eq!(md5, "JfnnlDI7RTiF9RgfG2JNCw==");
        assert_eq!(
            sha256,
            "15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225"
        );
        assert_eq!(before.uid(), 0);
        assert_eq!(before.mode() & 0o777, 0o444);
        assert_eq!(before.nlink(), 1);
        assert_eq!(identity(&before), identity(&file.metadata().unwrap()));
        assert_eq!(
            identity(&before),
            identity(&fs::symlink_metadata(&destination).unwrap())
        );
        assert_eq!(fs::metadata(&staging).unwrap().uid(), 0);
        assert_eq!(fs::metadata(&staging).unwrap().mode() & 0o777, 0o700);
        let receipts = root.join("receipts");
        fs::create_dir(&receipts).unwrap();
        fs::set_permissions(&receipts, fs::Permissions::from_mode(0o700)).unwrap();
        let receipt = receipts.join("probe.json");
        write_receipt(
            &receipt,
            &json!({
                "schema":"jetstreamer-epoch141-ledger-download-path-probe-v1",
                "invocation_id":env::var("INVOCATION_ID").unwrap(),
                "root":root,"device":before.dev(),"inode":before.ino(),
                "fixture_bytes":bytes,"sha256":sha256,"crc32c_base64":crc,"md5_base64":md5,
                "source_transfer_performed":false,"replay_launch_authorized":false,
                "publication_authorized":false,"remote_mutations":false,"r2_mutations":false
            }),
        )
        .unwrap();
        assert!(write_receipt(&receipt, &json!({"overwrite":true})).is_err());
    }

    #[test]
    fn owned_group_completion_is_observed_without_reaping_and_drop_reaps() {
        let mut command = Command::new("/usr/bin/true");
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = OwnedDownload(Some(command.spawn().unwrap()));
        let start = Instant::now();
        while !child.exited().unwrap() {
            assert!(start.elapsed() < Duration::from_secs(5));
            thread::sleep(Duration::from_millis(10));
        }
        assert!(child.exited().unwrap()); // WNOWAIT retained the same owned child.
        assert!(child.finish().unwrap().success());
        assert!(child.0.is_none());
    }
}
