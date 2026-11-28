//! Restore and compare one closed epoch 292 bundle inside its service's private tmpfs.
use super::*;
use std::{
    cell::Cell,
    process::Command,
    time::{Duration, Instant},
};

pub(super) const ACTION: &str = "holding-foundation-292-appendvec-restore-compare-ram";
const UNIT: &str = "horizon-restore-292-appendvec-ram-v308.service";
const DIRECTORY: &str = "/tmp/epoch292-appendvec-restore";
const MEMORY_MAX: u64 = 72 << 30;
const VOLUME_SIZE: u64 = 69 << 30;
const MAX_AGE_SECONDS: u64 = 300;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    mapping: Bound,
    custody: Bound,
    admission: Bound,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Admission {
    schema: String,
    unit: String,
    custody: Bound,
    boot_id: String,
    fit: Bound,
    recorded_unix_seconds: u64,
    memory_max_bytes: u64,
    tmpfs_bytes: u64,
}

fn limit(path: &Path, name: &str) -> Result<u64> {
    let value = fs::read_to_string(path.join(name))?;
    Ok(value.trim().parse()?)
}

fn check_memory(group: &Path, protected: u64) -> Result<()> {
    ensure!(
        limit(group, "memory.max")? == MEMORY_MAX && limit(group, "memory.swap.max")? == 0,
        "292 restore service memory bounds differ"
    );
    let growth = MEMORY_MAX
        .checked_sub(limit(group, "memory.current")?)
        .context("292 restore service exceeds its memory booking")?;
    let memory = fs::read_to_string("/proc/meminfo")?;
    let available_kib = memory
        .lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))
        .and_then(|value| value.split_whitespace().next())
        .context("missing 292 restore MemAvailable")?
        .parse::<u64>()?;
    ensure!(
        available_kib.saturating_mul(1024).saturating_sub(growth) >= protected,
        "292 restore would consume protected host memory"
    );
    Ok(())
}

fn check_mount(mountinfo: &str, access: &str) -> Result<()> {
    let mut rows = mountinfo.lines().filter_map(|line| {
        let (mount, filesystem) = line.split_once(" - ")?;
        let mut fields = mount.split_whitespace().skip(4);
        let path = fields.next()?;
        let options = fields.next()?;
        (path == DIRECTORY).then_some((options, filesystem))
    });
    let (options, filesystem) = rows.next().context("292 restore needs a dedicated mount")?;
    let mut filesystem = filesystem.split_whitespace();
    let private = options.split(',').collect::<BTreeSet<_>>();
    ensure!(
        rows.next().is_none()
            && filesystem.next() == Some("tmpfs")
            && filesystem
                .nth(1)
                .is_some_and(|v| v.split(',').any(|o| o == "noswap"))
            && [access, "nosuid", "nodev", "noexec"]
                .iter()
                .all(|flag| private.contains(flag)),
        "292 restore needs the exact private no-swap tmpfs with access {access}"
    );
    Ok(())
}

fn boot_id() -> Result<String> {
    Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned())
}

fn admitted_memory(admission: &Admission, custody: &Bound) -> Result<u64> {
    let age = clock()?.checked_sub(admission.recorded_unix_seconds);
    ensure!(
        admission.schema == "foundation-epoch292-appendvec-ram-restore-admission-v1"
            && admission.unit == UNIT
            && admission.boot_id == boot_id()?
            && admission.custody.path == custody.path
            && admission.custody.sha256 == custody.sha256
            && admission.memory_max_bytes == MEMORY_MAX
            && admission.tmpfs_bytes == VOLUME_SIZE
            && age.is_some_and(|seconds| seconds <= MAX_AGE_SECONDS),
        "stale or foreign 292 RAM restore admission"
    );
    let fit = saved(&admission.fit)?;
    ensure!(
        fit["schema"] == "foundation-epoch292-appendvec-ram-restore-fit-v1"
            && fit["unit"] == UNIT
            && fit["boot_id"] == admission.boot_id
            && fit["recorded_unix_seconds"] == admission.recorded_unix_seconds
            && fit["all_live_owners_and_growth_bound"] == true
            && fit["restore_memory_max_bytes"] == MEMORY_MAX
            && fit["local_retirement_authorized"] == false
            && fit["publication_authorized"] == false,
        "foreign 292 RAM restore fit"
    );
    let ceiling = fit["host_memory_protected_bytes"]
        .as_u64()
        .context("292 fit is missing its host memory floor")?;
    let available = fit["host_mem_available_bytes"]
        .as_u64()
        .context("292 fit is missing its available memory")?;
    ensure!(
        ceiling > 0 && available.saturating_sub(MEMORY_MAX) >= ceiling,
        "292 recorded RAM restore does not fit"
    );
    Ok(ceiling)
}

pub(super) async fn restore_and_compare(client: &Client, value: Value, spec: &Bound) -> Result<()> {
    let plan: Plan = serde_json::from_value(value)?;
    ensure!(
        plan.schema == "foundation-epoch292-appendvec-ram-restore-plan-v1",
        "foreign 292 RAM restore plan"
    );
    mapping(&plan.mapping)?;
    let group_name = format!("/system.slice/{UNIT}");
    let invocation = env::var("INVOCATION_ID")?;
    ensure!(
        fs::read_to_string("/proc/self/cgroup")?.trim() == format!("0::{group_name}")
            && invocation.len() == 32
            && invocation.bytes().all(|b| b.is_ascii_hexdigit())
            && fs::read_link("/proc/self/ns/mnt")? != fs::read_link("/proc/1/ns/mnt")?,
        "292 restore is outside its isolated service"
    );
    let group = Path::new("/sys/fs/cgroup").join(group_name.trim_start_matches('/'));
    let admission: Admission = serde_json::from_value(saved(&plan.admission)?)?;
    let protected = admitted_memory(&admission, &plan.custody)?;
    check_memory(&group, protected)?;
    let last_check = Cell::new(Instant::now());
    let check = |force| -> Result<()> {
        if force || last_check.get().elapsed() >= Duration::from_secs(15) {
            check_memory(&group, protected)?;
            last_check.set(Instant::now());
        }
        Ok(())
    };

    let receipt_value = saved(&plan.custody)?;
    let custody = validate_custody(&receipt_value)?;
    let metadata = &receipt_value["manifest"]["restore_metadata"];
    let source = Path::new(metadata["source"].as_str().context("292 source tree")?);
    tree::require_read_only(source)?;
    let directory = Path::new(DIRECTORY);
    private(directory)?;
    check_mount(&fs::read_to_string("/proc/self/mountinfo")?, "rw")?;
    ensure!(
        fs::read_dir(directory)?.next().is_none() && available(directory)? == VOLUME_SIZE,
        "292 restore volume must be empty and exactly sized"
    );
    let mount = fs::metadata(directory)?;
    check_remote(client, &receipt_value, &custody).await?;
    let restored = restore_blob_guarded(
        client,
        BlobRestore {
            key: custody.object,
            etag: custody.etag,
            sha: &custody.body.sha256,
            length: custody.body.length,
            directory,
            minimum: METADATA_RESERVE,
        },
        || check(false),
        || check(true),
    )
    .await?;
    ensure!(
        Command::new("/usr/bin/mount")
            .args(["-o", "remount,ro,nosuid,nodev,noexec,noswap", DIRECTORY])
            .status()?
            .success(),
        "292 restore volume could not be sealed read-only"
    );
    check_mount(&fs::read_to_string("/proc/self/mountinfo")?, "ro")?;
    let sealed = fs::metadata(directory)?;
    ensure!(
        (sealed.dev(), sealed.ino()) == (mount.dev(), mount.ino()),
        "292 restore mount changed while sealing it"
    );
    check(true)?;
    let (comparison, proof) = tree::compare(&restored, &custody.body, metadata)?;
    let remote = check_remote(client, &receipt_value, &custody).await?;
    native_checksum(&remote, &proof, custody.body.length)?;
    check(true)?;
    let output = receipt(
        &format!("appendvec292-ram-comparison-{}.json", spec.sha256),
        &json!({
            "schema":"foundation-epoch292-appendvec-ram-comparison-v1","epoch":292,
            "spec":spec,"custody":plan.custody,"admission":plan.admission,
            "unit":UNIT,"invocation_id":invocation,"object_key":custody.object,
            "object_etag":custody.etag,"sha256":custody.body.sha256,"length":custody.body.length,
            "remote_sha256_readback":true,"compressed_bundle_restored":true,
            "restore_storage":"private-service-tmpfs","ephemeral_validation_only":true,
            "comparison":comparison,"source_retirement_authorized":false,"publication_authorized":false
        }),
    )?;
    println!("{}", output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_must_be_private_exact_tmpfs_with_swap_disabled() {
        let row = format!("77 52 0:57 / {DIRECTORY} rw,nosuid,nodev,noexec - tmpfs tmpfs rw,size=72351744k,noswap");
        check_mount(&row, "rw").unwrap();
        check_mount(&row.replace(" rw,", " ro,"), "ro").unwrap();
        for invalid in [
            row.replace(",noswap", ""),
            row.replace(",noexec", ""),
            row.replace(" - tmpfs ", " - ext4 "),
            row.replace(DIRECTORY, "/other"),
            format!("{row}\n{row}"),
        ] {
            assert!(check_mount(&invalid, "rw").is_err(), "{invalid}");
        }
        assert!(check_mount(&row, "ro").is_err());
    }
}
