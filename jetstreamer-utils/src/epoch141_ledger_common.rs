//! Shared exact epoch 141 source metadata, identity and durable-receipt gates.
use {
    anyhow::{Context, Result, ensure},
    serde_json::Value,
    sha2::{Digest, Sha256},
    std::{
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::{
            fs::{MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
        path::Path,
        process::{Child, Command, ExitStatus, Stdio},
        thread,
        time::{Duration, Instant},
    },
};

pub(super) const BUCKET: &str = "mainnet-beta-ledger-us-ny5";
pub(super) const NAME: &str = "60911751/rocksdb.tar.bz2";
pub(super) const GENERATION: &str = "1634789748052739";
pub(super) const SIZE: u64 = 189_943_475_031;
pub(super) const CRC: &str = "6seTSA==";
pub(super) const MD5: &str = "EAYCyVn1bOWJ0TbSdb/I0g==";
pub(super) const URI: &str =
    "gs://mainnet-beta-ledger-us-ny5/60911751/rocksdb.tar.bz2#1634789748052739";
pub(super) const FROZEN_INPUT: &str =
    "/home/sol/.jetstreamer-private/epoch141-ledger-source-20261020-v1/download/rocksdb.tar.bz2";
pub(super) const FROZEN_SHA: &str =
    "7af478aec31809cebdeae761d44c19bb90bf06e15d2430813b3b0fe691e6a70b";
pub(super) const MAX_METADATA: u64 = 16 * 1024;

// Metadata-only sibling executables do not consume an offline source receipt.
#[allow(dead_code)]
pub(super) fn validate_reverification(receipt: &Value) -> Result<()> {
    ensure!(
        receipt["schema"] == "jetstreamer-epoch141-ledger-reverification-receipt-v1"
            && receipt["epoch"] == 141
            && receipt["compressed_input_verified"] == true
            && receipt["path"] == FROZEN_INPUT
            && receipt["bytes"] == SIZE
            && receipt["sha256"] == FROZEN_SHA
            && receipt["uri"] == URI
            && receipt["generation"] == GENERATION
            && receipt["crc32c_base64"] == CRC
            && receipt["md5_base64"] == MD5
            && receipt["source_modified"] == false
            && receipt["download_performed"] == false,
        "wrong compressed-source verification"
    );
    Ok(())
}

pub(super) fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(super) fn is_sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(super) fn identity(m: &fs::Metadata) -> (u64, u64, u64, u32, u32, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.uid(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

pub(super) fn bound_file(
    path: &Path,
    digest: &str,
    maximum: u64,
    immutable: bool,
) -> Result<Vec<u8>> {
    ensure!(is_sha(digest), "invalid supplied SHA-256");
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical input path"
    );
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let before = input.metadata()?;
    ensure!(
        before.is_file()
            && before.nlink() == 1
            && before.uid() == 0
            && before.mode() & if immutable { 0o222 } else { 0o022 } == 0
            && before.len() <= maximum,
        "unsafe bound input identity"
    );
    let mut bytes = Vec::new();
    (&mut input).take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.len() && sha(&bytes) == digest,
        "bound input hash/length mismatch"
    );
    ensure!(
        identity(&before) == identity(&input.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(path)?),
        "bound input changed"
    );
    Ok(bytes)
}

pub(super) fn exact_number(value: &Value, expected: u64) -> bool {
    value.as_u64() == Some(expected) || value.as_str() == Some(expected.to_string().as_str())
}

pub(super) fn hash_alias(value: &Value, raw: &str, normalized: &str, expected: &str) -> Result<()> {
    let found: Vec<_> = [raw, normalized]
        .into_iter()
        .filter_map(|k| value.get(k))
        .collect();
    ensure!(
        !found.is_empty() && found.iter().all(|v| v.as_str() == Some(expected)),
        "missing or conflicting {normalized}"
    );
    Ok(())
}

pub(super) fn validate_metadata(value: &Value) -> Result<()> {
    validate_object_metadata(value, &LEDGER_OBJECT)
}

/// Compile-time exact object identity; never supplied by an operational plan.
pub(super) struct ObjectSpec {
    pub bucket: &'static str,
    pub name: &'static str,
    pub generation: &'static str,
    pub size: u64,
    pub crc: &'static str,
    pub md5: &'static str,
    pub uri: &'static str,
}

pub(super) const LEDGER_OBJECT: ObjectSpec = ObjectSpec {
    bucket: BUCKET,
    name: NAME,
    generation: GENERATION,
    size: SIZE,
    crc: CRC,
    md5: MD5,
    uri: URI,
};

pub(super) fn validate_object_metadata(value: &Value, object: &ObjectSpec) -> Result<()> {
    ensure!(
        value.is_object() && value["bucket"] == object.bucket && value["name"] == object.name,
        "wrong ledger object"
    );
    ensure!(
        exact_number(&value["generation"], object.generation.parse()?)
            && exact_number(&value["size"], object.size),
        "ledger generation/length mismatch"
    );
    hash_alias(value, "crc32c", "crc32c_hash", object.crc)?;
    hash_alias(value, "md5Hash", "md5_hash", object.md5)?;
    let id = format!("{}/{}/{}", object.bucket, object.name, object.generation);
    ensure!(
        value.get("id").is_some() || value.get("storage_url").is_some(),
        "generation identity missing"
    );
    if let Some(actual) = value.get("id") {
        ensure!(actual.as_str() == Some(&id), "raw object identity mismatch");
    }
    if let Some(actual) = value.get("storage_url") {
        ensure!(
            actual.as_str() == Some(object.uri),
            "versioned URL mismatch"
        );
    }
    Ok(())
}

pub(super) fn capture<R: Read>(mut pipe: R) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    (&mut pipe)
        .take(MAX_METADATA + 1)
        .read_to_end(&mut output)?;
    Ok(output)
}

pub(super) fn drop_cli_identity(command: &mut Command) {
    // pre_exec runs after Command's built-in UID/GID operations. Perform this
    // complete ordered drop here, while the parent still has its capabilities.
    unsafe {
        command.pre_exec(|| {
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(1003) != 0
                || libc::setuid(1001) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

pub(super) fn wait_bounded(child: &mut Child, timeout: Duration) -> Result<ExitStatus> {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if start.elapsed() >= timeout {
            // CAP_KILL is required when this root parent owns a UID 1001 child
            // under a minimal capability bounding set. Reap before returning.
            child
                .kill()
                .context("kill timed-out unprivileged SDK child (requires CAP_KILL)")?;
            child.wait()?;
            anyhow::bail!("generation-bound metadata lookup timed out");
        }
        thread::sleep(Duration::from_millis(25));
    }
}

pub(super) fn observe_gcloud() -> Result<Vec<u8>> {
    observe_gcloud_object(&LEDGER_OBJECT)
}

pub(super) fn observe_gcloud_object(object: &ObjectSpec) -> Result<Vec<u8>> {
    let mut command = Command::new("/usr/lib/google-cloud-sdk/bin/gcloud");
    command
        .args([
            "storage",
            "objects",
            "describe",
            object.uri,
            "--account=sam.johnson@anza.xyz",
            "--billing-project=principal-lane-200702",
            "--format=json",
            "--quiet",
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/home/sol")
        .env("LANG", "C.UTF-8")
        .env("CLOUDSDK_CONFIG", "/home/sol/.config/gcloud")
        .env("CLOUDSDK_CORE_DISABLE_PROMPTS", "1")
        .env("CLOUDSDK_CORE_DISABLE_FILE_LOGGING", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    drop_cli_identity(&mut command);
    let mut child = command
        .spawn()
        .context("spawn generation-bound metadata lookup")?;
    let stdout = child.stdout.take().context("stdout unavailable")?;
    let stderr = child.stderr.take().context("stderr unavailable")?;
    let out = thread::spawn(move || capture(stdout));
    let err = thread::spawn(move || capture(stderr));
    let status = wait_bounded(&mut child, Duration::from_secs(60))?;
    let output = out
        .join()
        .map_err(|_| anyhow::anyhow!("stdout reader panicked"))??;
    let errors = err
        .join()
        .map_err(|_| anyhow::anyhow!("stderr reader panicked"))??;
    ensure!(
        output.len() as u64 <= MAX_METADATA && errors.len() as u64 <= MAX_METADATA,
        "metadata output bound exceeded"
    );
    // Never forward credential-related CLI stderr, tokens, or login URLs.
    ensure!(
        status.success(),
        "generation-bound metadata lookup failed ({status})"
    );
    Ok(output)
}

pub(super) fn write_receipt(path: &Path, value: &Value) -> Result<()> {
    ensure!(path.is_absolute(), "output must be absolute");
    let parent = path.parent().context("output parent missing")?;
    ensure!(
        parent.canonicalize()? == parent,
        "noncanonical output parent"
    );
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "output parent must be root-private"
    );
    let directory = File::open(parent)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    output.write_all(&bytes)?;
    output.sync_all()?;
    directory.sync_all()?;
    Ok(())
}
