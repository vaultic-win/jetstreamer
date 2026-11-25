//! Restore the encrypted epoch 228 ext4 guest into a private verification mount.
use super::*;
use std::time::{Duration, Instant};

pub(super) const ACTION: &str = "holding-foundation-228-ext4-restore-check";
const UNIT: &str = "horizon-restore-228-ext4-check-v1.service";
const VOLUME: &str = "/tmp/epoch228-ext4-restore";
const MEMBER: &str = "private.ext4";
const MEMORY_MAX: u64 = 128 << 30;
const VOLUME_BYTES: u64 = 110 << 30;
const MAX_ALLOCATED: u64 = 105_000_000_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    mapping: Bound,
    custody: Bound,
    admission: Bound,
}

struct PinnedObject<'a> {
    key: &'a str,
    etag: &'a str,
    length: u64,
    sha: &'a str,
    marker: &'a str,
    manifest: Vec<u8>,
}

fn pinned(custody: &Value) -> Result<PinnedObject<'_>> {
    let manifest = &custody["manifest"];
    let object_key = manifest["object_key"]
        .as_str()
        .context("missing holding key")?;
    let etag = custody["object_etag"]
        .as_str()
        .filter(|v| !v.is_empty())
        .context("missing holding ETag")?;
    let length = manifest["length"]
        .as_u64()
        .context("missing holding length")?;
    let sha = manifest["sha256"]
        .as_str()
        .context("missing holding SHA-256")?;
    let marker = custody["manifest_key"]
        .as_str()
        .context("missing holding manifest key")?;
    let manifest_bytes = serde_json::to_vec(manifest)?;
    let marker_sha = hex_lower(&Sha256::digest(&manifest_bytes));
    ensure!(
        custody["schema"] == "foundation-epoch228-ext4-custody-v1"
            && custody["bucket"] == BUCKET
            && custody["remote_sha256_readback"] == true
            && custody["remote_authenticated_decryption_verified"] == true
            && custody["r2_plaintext_sha256_matches_staged_sparse_bundle"] == true
            && custody["staging"]["path"] == COMPLETION
            && custody["staging"]["sha256"] == COMPLETION_SHA
            && custody["publication_authorized"] == false
            && custody["local_retirement_authorized"] == false
            && manifest["schema"] == "foundation-epoch228-ext4-holding-manifest-v1"
            && manifest["host"] == host::HOST
            && manifest["prefix"] == SUBPREFIX
            && manifest["epoch"] == 228
            && manifest["format"] == FORMAT
            && manifest["clear_sparse_bundle_length"] == CLEAR_LEN
            && manifest["clear_sparse_bundle_sha256"] == CLEAR_SHA
            && manifest["guest_length"] == GUEST_LEN
            && manifest["guest_sha256"] == GUEST_SHA
            && manifest["canonical_archive"] == false
            && manifest["publication_authorized"] == false
            && manifest["local_retirement_authorized"] == false
            && (CLEAR_LEN..=CLEAR_LEN + (16 << 20)).contains(&length)
            && object_key == key(sha)?
            && custody["manifest_sha256"] == marker_sha
            && marker == manifest_key(&marker_sha)?,
        "foreign or unverified epoch 228 R2 custody"
    );
    Ok(PinnedObject {
        key: object_key,
        etag,
        length,
        sha,
        marker,
        manifest: manifest_bytes,
    })
}

async fn check_remote(client: &Client, object: &PinnedObject<'_>) -> Result<()> {
    let owner = get_mutable_object(client, BUCKET, &format!("{}owner.json", host::PREFIX))
        .await?
        .context("missing Foundation holding owner")?;
    ensure!(
        owner.bytes == owner_bytes()?,
        "foreign Foundation holding prefix"
    );
    let manifest = get_mutable_object(client, BUCKET, object.marker)
        .await?
        .context("missing epoch 228 holding manifest")?;
    ensure!(
        manifest.bytes == object.manifest,
        "epoch 228 authenticated manifest differs"
    );
    let found = head_archive(client, BUCKET, object.key)
        .await?
        .context("missing epoch 228 holding object")?;
    remote_matches(
        &found,
        object.key,
        object.length,
        object.sha,
        Some(object.etag),
    )
}

fn check_mount(mountinfo: &str) -> Result<()> {
    let mut mounts = mountinfo.lines().filter_map(|line| {
        let (fields, fs) = line.split_once(" - ")?;
        let mut fields = fields.split_whitespace().skip(4);
        (fields.next()? == VOLUME).then(|| (fields.next().unwrap_or_default(), fs))
    });
    let (options, fs) = mounts.next().context("epoch 228 restore mount absent")?;
    let mut fs = fs.split_whitespace();
    ensure!(
        mounts.next().is_none()
            && fs.next() == Some("tmpfs")
            && fs
                .nth(1)
                .is_some_and(|flags| flags.split(',').any(|flag| flag == "noswap"))
            && ["rw", "noexec", "nosuid", "nodev"]
                .iter()
                .all(|flag| options.split(',').any(|opt| opt == *flag)),
        "epoch 228 restore requires its private writable no-swap tmpfs"
    );
    Ok(())
}

fn memory_limit(group: &Path, name: &str) -> Result<u64> {
    Ok(fs::read_to_string(group.join(name))?.trim().parse()?)
}

fn check_memory(group: &Path, protected: u64) -> Result<()> {
    ensure!(
        memory_limit(group, "memory.max")? == MEMORY_MAX
            && memory_limit(group, "memory.swap.max")? == 0,
        "epoch 228 restore cgroup limits differ from its admission"
    );
    let remaining = MEMORY_MAX
        .checked_sub(memory_limit(group, "memory.current")?)
        .context("epoch 228 restore exceeded its cgroup booking")?;
    let available: u64 = fs::read_to_string("/proc/meminfo")?
        .lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))
        .and_then(|n| n.split_whitespace().next())
        .context("missing host MemAvailable")?
        .parse()?;
    ensure!(
        available.saturating_mul(1024).saturating_sub(remaining) >= protected,
        "epoch 228 restore would consume protected host memory"
    );
    Ok(())
}

fn expand_sparse(clear: ChildStdout, directory: &Path, group: &Path, protected: u64) -> Result<()> {
    let mut decoder = Command::new("/usr/bin/zstd")
        .args(["-q", "-d", "-c"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut unpack = Command::new("/usr/bin/tar")
        .args([
            "--extract",
            "--file=-",
            "--keep-old-files",
            "--numeric-owner",
            "--same-owner",
            "--same-permissions",
            "--xattrs",
            "--acls",
            "--directory",
        ])
        .arg(directory)
        .args(["--", MEMBER])
        .stdin(
            decoder
                .stdout
                .take()
                .context("missing decompressor output")?,
        )
        .spawn()?;
    let mut last_check = Instant::now();
    let clear_result = copy_verified_plaintext(
        clear,
        decoder.stdin.take().context("missing decompressor input")?,
        CLEAR_LEN,
        CLEAR_SHA,
        || {
            if last_check.elapsed() >= Duration::from_secs(15) {
                check_memory(group, protected)?;
                last_check = Instant::now();
            }
            Ok(())
        },
    );
    let decoded = decoder.wait();
    let unpacked = unpack.wait();
    clear_result?;
    ensure!(
        decoded?.success() && unpacked?.success(),
        "epoch 228 sparse extraction failed"
    );
    Ok(())
}

fn verify_guest(directory: &Path) -> Result<Value> {
    let file_path = directory.join(MEMBER);
    ensure!(
        fs::read_dir(directory)?
            .collect::<std::io::Result<Vec<_>>>()?
            .len()
            == 1,
        "epoch 228 restore emitted unexpected files"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&file_path)?;
    let info = file.metadata()?;
    let blocks = info
        .blocks()
        .checked_mul(512)
        .context("ext4 allocation overflow")?;
    ensure!(
        info.is_file()
            && info.uid() == 0
            && info.gid() == 0
            && info.nlink() == 1
            && info.mode() & 0o7777 == 0o600
            && info.len() == GUEST_LEN
            && blocks <= MAX_ALLOCATED,
        "restored epoch 228 image metadata differs"
    );
    let mut hash = Sha256::new();
    let length = std::io::copy(&mut file, &mut hash)?;
    let digest = hex_lower(&hash.finalize());
    ensure!(
        length == GUEST_LEN && digest == GUEST_SHA,
        "restored epoch 228 guest bytes differ"
    );
    let check = Command::new("/usr/sbin/e2fsck")
        .args(["-f", "-n"])
        .arg(&file_path)
        .output()?;
    ensure!(
        check.status.success(),
        "restored epoch 228 ext4 check failed: {}",
        String::from_utf8_lossy(&check.stderr)
    );
    let mut check_digest = Sha256::new();
    check_digest.update(check.stdout);
    check_digest.update(check.stderr);
    Ok(
        json!({"bytes":length,"allocated_bytes":blocks,"sha256":digest,
        "e2fsck_exit_status":0,"e2fsck_output_sha256":hex_lower(&check_digest.finalize())}),
    )
}

pub(super) async fn run(client: &Client, value: Value, spec: &Bound) -> Result<()> {
    let plan: Plan = serde_json::from_value(value)?;
    mapping(&plan.mapping)?;
    ensure!(
        plan.schema == "foundation-epoch228-ext4-restore-check-v1",
        "foreign epoch 228 restore plan"
    );
    let invocation = env::var("INVOCATION_ID")?;
    let group = format!("/system.slice/{UNIT}");
    ensure!(
        fs::read_to_string("/proc/self/cgroup")?.trim() == format!("0::{group}")
            && invocation.len() == 32
            && invocation.bytes().all(|v| v.is_ascii_hexdigit())
            && fs::read_link("/proc/self/ns/mnt")? != fs::read_link("/proc/1/ns/mnt")?,
        "epoch 228 restore must run in its admitted service and mount namespace"
    );
    let group_path = Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/'));
    let admission = saved(&plan.admission)?;
    let admitted_at = admission["recorded_unix_seconds"]
        .as_u64()
        .context("missing restore time")?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    ensure!(
        admission["schema"] == "foundation-epoch228-ext4-restore-admission-v1"
            && admission["unit"] == UNIT
            && admission["boot_id"] == boot.trim()
            && admission["custody"] == serde_json::to_value(&plan.custody)?
            && admission["memory_max_bytes"] == MEMORY_MAX
            && admission["tmpfs_bytes"] == VOLUME_BYTES
            && admission["local_retirement_authorized"] == false
            && clock()?
                .checked_sub(admitted_at)
                .is_some_and(|age| age <= 300),
        "foreign or stale epoch 228 restore admission"
    );
    let protected = admission["protected_host_memory_bytes"]
        .as_u64()
        .filter(|v| *v > 0)
        .context("missing protected host memory")?;
    check_memory(&group_path, protected)?;
    let directory = Path::new(VOLUME);
    private(directory)?;
    check_mount(&fs::read_to_string("/proc/self/mountinfo")?)?;
    ensure!(
        fs::read_dir(directory)?.next().is_none() && available(directory)? == VOLUME_BYTES,
        "epoch 228 restore requires an empty, exactly sized tmpfs"
    );

    let custody = saved(&plan.custody)?;
    let object = pinned(&custody)?;
    check_remote(client, &object).await?;
    let streaming_group = group_path.clone();
    read_decrypted(
        client,
        RemoteReadSpec {
            bucket: BUCKET,
            key: object.key,
            etag: object.etag,
            expected_length: object.length,
            expected_sha256: object.sha,
            concurrency: 2,
        },
        &key_file(false)?,
        move |clear| expand_sparse(clear, directory, &streaming_group, protected),
    )
    .await?;
    check_memory(&group_path, protected)?;
    let guest = verify_guest(directory)?;
    check_remote(client, &object).await?;
    check_memory(&group_path, protected)?;
    let receipt_path = receipt(
        &format!("ext4-228-restore-check-{}.json", spec.sha256),
        &json!({
            "schema":"foundation-epoch228-ext4-restore-check-receipt-v1","epoch":228,
            "spec":spec,"admission":plan.admission,"custody":plan.custody,"unit":UNIT,"invocation_id":invocation,
            "object_key":object.key,"object_etag":object.etag,"cipher_sha256":object.sha,"cipher_bytes":object.length,
            "restore_storage":"private-service-tmpfs","restored_guest":guest,"remote_decryption_authenticated":true,
            "publication_authorized":false,"local_retirement_authorized":false
        }),
    )?;
    println!("{}", receipt_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_requires_one_noswap_tmpfs_at_exact_destination() {
        let valid = format!(
            "12 1 0:11 / {VOLUME} rw,nosuid,nodev,noexec - tmpfs tmpfs rw,size=115343360k,noswap\n"
        );
        assert!(check_mount(&valid).is_ok());
        assert!(check_mount(&valid.replace(",noswap", "")).is_err());
        assert!(check_mount(&valid.replace(VOLUME, "/tmp/different-volume")).is_err());
        assert!(check_mount(&format!("{valid}{valid}")).is_err());
    }
}
