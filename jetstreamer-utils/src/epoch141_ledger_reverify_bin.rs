//! Reverify a frozen epoch 141 transfer after a terminal post-download failure.
//! Never downloads, changes the source, retries replay, or publishes an archive.
mod epoch141_ledger_common;
use {
    anyhow::{Context, Result, ensure},
    base64::{Engine, engine::general_purpose::STANDARD},
    epoch141_ledger_common::*,
    md5::Md5,
    serde::Deserialize,
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    std::{
        collections::BTreeMap,
        env,
        ffi::CString,
        fs::{self, File, OpenOptions},
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
        process::Command,
        time::{Instant, SystemTime, UNIX_EPOCH},
    },
};

const GCLOUD: &str = "/usr/lib/google-cloud-sdk/bin/gcloud";
const OWNER: &str = "horizon-epoch141-ledger-source-download-20261020-v1.service";
const OWNER_IID: &str = "f629505db361470babeaaef64f07f10b";
const INPUT: &str =
    "/home/sol/.jetstreamer-private/epoch141-ledger-source-20261020-v1/download/rocksdb.tar.bz2";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    gcloud_sha256: String,
    original_download_plan: Bound,
    original_initial_guard: Bound,
    input: PathBuf,
    expected_device: u64,
    expected_inode: u64,
    output_receipt: PathBuf,
    minimum_free_bytes: u64,
    maximum_runtime_seconds: u64,
}

fn properties() -> Result<BTreeMap<String, String>> {
    let output = Command::new("/usr/bin/systemctl")
        .args(["show", OWNER, "--no-pager", "--no-ask-password", "--property=Id,LoadState,ActiveState,SubState,Result,InvocationID,NRestarts,MainPID,ControlPID"])
        .env("LC_ALL", "C").output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 16384,
        "cannot bind original terminal owner"
    );
    let mut result = BTreeMap::new();
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let (key, value) = line.split_once('=').context("invalid owner property")?;
        ensure!(
            result.insert(key.to_string(), value.to_string()).is_none(),
            "duplicate owner property"
        );
    }
    validate_terminal(&result)?;
    Ok(result)
}

fn validate_terminal(owner: &BTreeMap<String, String>) -> Result<()> {
    for (key, expected) in [
        ("Id", OWNER),
        ("LoadState", "loaded"),
        ("InvocationID", OWNER_IID),
        ("ActiveState", "failed"),
        ("SubState", "failed"),
        ("Result", "exit-code"),
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("NRestarts", "0"),
    ] {
        ensure!(
            owner.get(key).map(String::as_str) == Some(expected),
            "original owner {key} mismatch"
        );
    }
    Ok(())
}

fn validate_frozen(
    m: &fs::Metadata,
    expected_device: u64,
    expected_inode: u64,
    expected_size: u64,
) -> Result<()> {
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o444
            && m.dev() == expected_device
            && m.ino() == expected_inode
            && m.len() == expected_size,
        "frozen input identity mismatch"
    );
    Ok(())
}

fn open_frozen(plan: &Plan) -> Result<(File, fs::Metadata)> {
    ensure!(
        plan.input == Path::new(INPUT) && plan.input.canonicalize()? == plan.input,
        "wrong frozen source path"
    );
    let parent = plan.input.parent().context("source parent missing")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "source directory is not frozen"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&plan.input)?;
    let before = file.metadata()?;
    validate_frozen(&before, plan.expected_device, plan.expected_inode, SIZE)?;
    ensure!(
        identity(&before) == identity(&fs::symlink_metadata(&plan.input)?),
        "source path differs from open file"
    );
    Ok((file, before))
}

fn unchanged(file: &File, path: &Path, before: &fs::Metadata) -> Result<()> {
    ensure!(
        identity(before) == identity(&file.metadata()?)
            && identity(before) == identity(&fs::symlink_metadata(path)?),
        "frozen input changed during recovery"
    );
    Ok(())
}

fn validate_plan(plan: &Plan) -> Result<()> {
    ensure!(
        plan.schema == "jetstreamer-epoch141-ledger-reverify-plan-v1",
        "wrong reverify schema"
    );
    ensure!(
        (60..=43200).contains(&plan.maximum_runtime_seconds)
            && plan.minimum_free_bytes >= 205_211_459_014,
        "invalid recovery resource bounds"
    );
    ensure!(
        plan.output_receipt.is_absolute()
            && plan.output_receipt != plan.input
            && !plan
                .output_receipt
                .starts_with(plan.input.parent().context("missing parent")?),
        "unsafe output path"
    );
    let parent = plan
        .output_receipt
        .parent()
        .context("receipt parent missing")?;
    ensure!(
        parent.canonicalize()? == parent,
        "noncanonical receipt parent"
    );
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o7777 == 0o700
            && fs::symlink_metadata(&plan.output_receipt)
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "receipt parent unsafe or output exists"
    );
    let original: Value = serde_json::from_slice(&bound_file(
        &plan.original_download_plan.path,
        &plan.original_download_plan.sha256,
        65536,
        true,
    )?)?;
    ensure!(
        original["schema"] == "jetstreamer-epoch141-ledger-download-plan-v1"
            && original["gcloud_sha256"] == plan.gcloud_sha256
            && original["staging_directory"].as_str() == plan.input.parent().and_then(Path::to_str),
        "original download plan mismatch"
    );
    ensure!(
        original["minimum_free_bytes"]
            .as_u64()
            .is_some_and(|n| plan.minimum_free_bytes >= n),
        "recovery weakens original protected-growth floor"
    );
    let guard: Value = serde_json::from_slice(&bound_file(
        &plan.original_initial_guard.path,
        &plan.original_initial_guard.sha256,
        65536,
        false,
    )?)?;
    ensure!(
        guard["schema"] == "jetstreamer-epoch141-ledger-download-initial-guard-v1"
            && guard["invocation_id"] == OWNER_IID
            && guard["plan_sha256"] == plan.original_download_plan.sha256
            && guard["trip"] == false,
        "original guard binding mismatch"
    );
    ensure!(
        original["initial_guard_receipt"].as_str() == plan.original_initial_guard.path.to_str(),
        "original guard path mismatch"
    );
    // Bind the prior authenticated generation observation and fresh-admission evidence.
    let bound = |name: &str| -> Result<Value> {
        let path = Path::new(
            original[name]["path"]
                .as_str()
                .context("original evidence path missing")?,
        );
        let digest = original[name]["sha256"]
            .as_str()
            .context("original evidence digest missing")?;
        Ok(serde_json::from_slice(&bound_file(
            path,
            digest,
            4 * 1024 * 1024,
            false,
        )?)?)
    };
    let metadata = bound("metadata_receipt")?;
    ensure!(
        metadata["schema"] == "jetstreamer-epoch141-ledger-metadata-receipt-v1"
            && metadata["download_performed"] == false,
        "wrong original metadata evidence"
    );
    validate_metadata(&metadata["metadata"])?;
    let admission = bound("admission_receipt")?;
    ensure!(
        admission["schema"] == "jetstreamer-historical-performance-admission-receipt-v1"
            && admission["admitted"] == true,
        "original transfer admission not proven"
    );
    // Never manufacture the missing original success receipt or bypass a stop intent.
    for key in ["output_receipt", "stop_intent", "stop_completion"] {
        let p = Path::new(
            original[key]
                .as_str()
                .context("original output path missing")?,
        );
        ensure!(
            p != plan.output_receipt
                && fs::symlink_metadata(p).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "original success/stop evidence present or overlapping"
        );
    }
    Ok(())
}

fn guard(plan: &Plan, start: Instant) -> Result<u64> {
    ensure!(
        start.elapsed().as_secs() < plan.maximum_runtime_seconds,
        "verification runtime exceeded"
    );
    let name = CString::new(plan.input.as_os_str().as_encoded_bytes())?;
    let mut state = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(name.as_ptr(), state.as_mut_ptr()) } == 0,
        "cannot read free space"
    );
    let state = unsafe { state.assume_init() };
    let free = state
        .f_bavail
        .checked_mul(state.f_frsize)
        .context("free space overflow")?;
    ensure!(
        free >= plan.minimum_free_bytes,
        "verification protected-space floor crossed"
    );
    Ok(free)
}

fn hash_input(
    mut file: impl Read,
    maximum: u64,
    mut guard: impl FnMut() -> Result<()>,
) -> Result<(u64, String, String, String)> {
    let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI);
    let mut crc_digest = crc.digest();
    let mut md5 = Md5::new();
    let mut sha256 = Sha256::new();
    let mut count = 0u64;
    let mut buffer = vec![0; 4 * 1024 * 1024];
    loop {
        guard()?;
        let bytes = file.read(&mut buffer)?;
        if bytes == 0 {
            break;
        }
        count = count
            .checked_add(bytes as u64)
            .context("verification length overflow")?;
        ensure!(count <= maximum, "input exceeds verification bound");
        crc_digest.update(&buffer[..bytes]);
        md5.update(&buffer[..bytes]);
        sha256.update(&buffer[..bytes]);
    }
    Ok((
        count,
        STANDARD.encode(crc_digest.finalize().to_be_bytes()),
        STANDARD.encode(md5.finalize()),
        format!("{:x}", sha256.finalize()),
    ))
}

fn run() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "reverification requires root"
    );
    let mut args = env::args().skip(1);
    let mut values = BTreeMap::new();
    while let Some(key) = args.next() {
        ensure!(
            ["--plan", "--plan-sha256", "--self-sha256", "--check-only"].contains(&key.as_str()),
            "unknown option"
        );
        let value = if key == "--check-only" {
            "true".to_string()
        } else {
            args.next().context("missing argument value")?
        };
        ensure!(values.insert(key, value).is_none(), "duplicate argument");
    }
    for key in ["--plan", "--plan-sha256", "--self-sha256"] {
        ensure!(values.contains_key(key), "missing required argument {key}");
    }
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
    validate_plan(&plan)?;
    let owner_before = properties()?;
    let (mut file, before) = open_frozen(&plan)?;
    bound_file(
        Path::new(GCLOUD),
        &plan.gcloud_sha256,
        16 * 1024 * 1024,
        false,
    )?;
    let start = Instant::now();
    let free_before = guard(&plan, start)?;
    if values.contains_key("--check-only") {
        ensure!(
            owner_before == properties()?,
            "original owner changed during local check"
        );
        println!("local recovery gates passed; no SDK invocation, scan, receipt or mutation");
        return Ok(());
    }
    let invocation = env::var("INVOCATION_ID").context("persistent systemd invocation required")?;
    ensure!(
        invocation.len() == 32
            && invocation
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid recovery invocation"
    );
    let metadata_before = observe_gcloud()?;
    validate_metadata(&serde_json::from_slice::<Value>(&metadata_before)?)?;
    let (bytes, crc32c, md5, sha256) =
        hash_input(&mut file, SIZE, || guard(&plan, start).map(|_| ()))?;
    ensure!(
        bytes == SIZE && crc32c == CRC && md5 == MD5,
        "compressed generation integrity mismatch"
    );
    let metadata_after = observe_gcloud()?;
    validate_metadata(&serde_json::from_slice::<Value>(&metadata_after)?)?;
    bound_file(
        Path::new(GCLOUD),
        &plan.gcloud_sha256,
        16 * 1024 * 1024,
        false,
    )?;
    unchanged(&file, &plan.input, &before)?;
    let owner_after = properties()?;
    ensure!(
        owner_before == owner_after,
        "original download owner changed during recovery"
    );
    let free_after = guard(&plan, start)?;
    file.sync_all()?;
    File::open(plan.input.parent().context("input parent missing")?)?.sync_all()?;
    validate_plan(&plan)?;
    unchanged(&file, &plan.input, &before)?;
    write_receipt(
        &plan.output_receipt,
        &json!({
            "schema":"jetstreamer-epoch141-ledger-reverification-receipt-v1", "epoch":141,
            "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            "invocation_id":invocation,"plan_sha256":values["--plan-sha256"],"self_sha256":values["--self-sha256"],
            "original_owner_before":owner_before,"original_owner_after":owner_after,
            "original_download_plan_sha256":plan.original_download_plan.sha256,
            "original_initial_guard_sha256":plan.original_initial_guard.sha256,
            "path":plan.input,"uri":URI,"generation":GENERATION,"bytes":bytes,
            "crc32c_base64":crc32c,"md5_base64":md5,"sha256":sha256,"device":before.dev(),"inode":before.ino(),
            "uid":before.uid(),"mode":"0444","links":before.nlink(),"identity":identity(&before),
            "metadata_before_sha256":sha(&metadata_before),"metadata_after_sha256":sha(&metadata_after),
            "minimum_free_bytes":plan.minimum_free_bytes,"available_bytes_before":free_before,"available_bytes_after":free_after,
            "elapsed_seconds":start.elapsed().as_secs(),"compressed_input_verified":true,
            "download_performed":false,"source_modified":false,"source_completeness_proven":false,"live_state_proven":false,
            "replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false
        }),
    )?;
    println!("frozen epoch141 generation independently reverified; no download or source mutation");
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
    fn independent_hash_vectors_bounds_and_guard_failure() {
        let (n, crc, md5, sha) = hash_input(&b"123456789"[..], 9, || Ok(())).unwrap();
        assert_eq!(
            (n, crc.as_str(), md5.as_str(), sha.as_str()),
            (
                9,
                "4waSgw==",
                "JfnnlDI7RTiF9RgfG2JNCw==",
                "15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225"
            )
        );
        assert!(hash_input(&b"123456789"[..], 8, || Ok(())).is_err());
        assert!(hash_input(&b"abc"[..], 3, || anyhow::bail!("guard stopped")).is_err());
    }
    #[test]
    fn terminal_owner_cannot_be_replaced_restarted_or_running() {
        let good: BTreeMap<String, String> = [
            ("Id", OWNER),
            ("LoadState", "loaded"),
            ("InvocationID", OWNER_IID),
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("MainPID", "0"),
            ("ControlPID", "0"),
            ("NRestarts", "0"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        validate_terminal(&good).unwrap();
        for (key, value) in [
            ("InvocationID", "replacement"),
            ("NRestarts", "1"),
            ("MainPID", "1"),
            ("ControlPID", "1"),
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("Result", "success"),
        ] {
            let mut bad = good.clone();
            bad.insert(key.into(), value.into());
            assert!(validate_terminal(&bad).is_err());
        }
    }
    #[test]
    fn frozen_input_requires_exact_inode_owner_mode_links_and_length() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source");
        fs::write(&path, b"abc").unwrap();
        let m = fs::metadata(&path).unwrap();
        assert!(validate_frozen(&m, m.dev(), m.ino(), 3).is_err());
        assert!(validate_frozen(&m, m.dev(), m.ino() + 1, 3).is_err());
        assert!(validate_frozen(&m, m.dev(), m.ino(), 4).is_err());
    }

    #[test]
    fn open_input_and_path_replacement_are_independently_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source");
        fs::write(&path, b"abc").unwrap();
        let file = File::open(&path).unwrap();
        let before = file.metadata().unwrap();
        unchanged(&file, &path, &before).unwrap();
        fs::rename(&path, directory.path().join("retained-original")).unwrap();
        fs::write(&path, b"abc").unwrap();
        assert!(unchanged(&file, &path, &before).is_err());
        let file = File::open(&path).unwrap();
        let before = file.metadata().unwrap();
        fs::write(&path, b"changed").unwrap();
        assert!(unchanged(&file, &path, &before).is_err());
    }
}
