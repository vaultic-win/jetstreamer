//! Private restore-only resource measurement for the exact epoch 225 bootstrap.
//! No entries, archive, sidecar, runtime promotion, or publication authority.
#[allow(dead_code)]
#[path = "../historical.rs"]
mod historical;
use historical::{
    HistoricalCheckpoint, HistoricalInitialization, HistoricalRuntimeClient,
    SOLANA_V1_6_20_CANDIDATE, SnapshotInitialization, WorkerSpawn,
};
use jetstreamer_node::archive_checksum::*;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use solana_hash::Hash;
use std::{
    env, fs,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    str::FromStr,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
const SLOT: u64 = 97_199_617;
const ACCOUNTS: &str = "HE57JmgvEeZjBKN8cfTLrmyCbUnptJ9PWjUdTzgxSSdi";
const SNAPSHOT: &str = "094d3b28c39403580fbac083cdad67cc008b255dd375d611217103750d0f412d";
const SNAPSHOT_SIZE: u64 = 10_177_204_112;
const WORKER: &str = "f39140b9a9659e7c6e8207076a2d0c560a6b69df42cc92e19a421cf46c2b761c";
const GENESIS: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
// Protect currently sealed older-growth claims, century floor, full epoch 213 reservation of 384 GiB
// and this diagnostic 256 GiB. A fresh whole-host admission remains independent.
const MINIMUM_FREE: u64 = 3_185_678_193_366;
const MAX_SCRATCH: u64 = 256 * 1024 * 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    unit: String,
    worker: PathBuf,
    snapshot: PathBuf,
    ledger_directory: PathBuf,
    run_root: PathBuf,
    scratch_directory: PathBuf,
    output: PathBuf,
    minimum_free_bytes: u64,
}
fn require(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

fn digest(value: &str) -> Result<[u8; 32], String> {
    require(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "expected 64 lowercase hexadecimal characters",
    )?;
    let mut result = [0; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(result)
}

fn bound_bytes(
    path: &Path,
    expected: &str,
    limit: u64,
    immutable: bool,
) -> Result<Vec<u8>, String> {
    require(
        path.is_absolute() && fs::canonicalize(path).map_err(|e| e.to_string())? == path,
        "evidence path must be absolute and canonical",
    )?;
    let mut file = open_regular_nofollow(path).map_err(|e| e.to_string())?;
    let before = archive_file_identity(&file).map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    require(
        metadata.nlink() == 1 && metadata.len() <= limit,
        "evidence link count or size mismatch",
    )?;
    if immutable {
        require(
            metadata.uid() == 0 && metadata.mode() & 0o222 == 0,
            "sealed evidence must be root-owned and non-writable",
        )?;
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    require(
        bytes.len() as u64 == metadata.len(),
        "evidence length changed",
    )?;
    require(
        <[u8; 32]>::from(Sha256::digest(&bytes)) == digest(expected)?,
        "evidence SHA-256 mismatch",
    )?;
    require(
        archive_file_identity(&file).map_err(|e| e.to_string())? == before
            && path_matches_archive_identity(path, before).map_err(|e| e.to_string())?,
        "evidence identity changed",
    )?;
    Ok(bytes)
}

fn free_bytes(path: &Path) -> Result<u64, String> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let mut value = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(path.as_ptr(), value.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let value = unsafe { value.assume_init() };
    value
        .f_bavail
        .checked_mul(value.f_frsize)
        .ok_or_else(|| "free-space arithmetic overflow".to_owned())
}

fn validate_private_directory(path: &Path) -> Result<(), String> {
    require(
        path.is_absolute() && fs::canonicalize(path).map_err(|e| e.to_string())? == path,
        "private directory must be absolute and canonical",
    )?;
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    require(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "private directory ownership or mode mismatch",
    )
}

fn validate_plan(plan: &Plan) -> Result<(), String> {
    require(
        plan.schema == "jetstreamer-private-epoch225-bootstrap-resource-plan-v1"
            && plan
                .unit
                .starts_with("horizon-qualify-225-bootstrap-resource-")
            && plan.unit.ends_with(".service")
            && plan
                .unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "wrong scope or service",
    )?;
    require(
        plan.run_root.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
            && plan
                .run_root
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("bootstrap-resource-225-"))
            && plan.scratch_directory == plan.run_root.join("scratch")
            && plan.output == plan.run_root.join("receipts/resource.json")
            && plan.minimum_free_bytes >= MINIMUM_FREE,
        "wrong private paths or resource floor",
    )?;
    require(
        plan.snapshot.file_name().and_then(|s| s.to_str())
            == Some("snapshot-97199617-HE57JmgvEeZjBKN8cfTLrmyCbUnptJ9PWjUdTzgxSSdi.tar.zst"),
        "wrong snapshot",
    )?;
    Ok(())
}
fn validate_checkpoint(actual: &HistoricalCheckpoint, initial_cursor: u64) -> Result<(), String> {
    require(
        actual.slot == SLOT
            && actual.accounts_hash
                == Hash::from_str(ACCOUNTS)
                    .map_err(|e| e.to_string())?
                    .to_bytes()
            && actual.slot_complete
            && actual.tick_height == (SLOT + 1) * 64
            && actual.writes.is_empty()
            && actual.next_write_version == initial_cursor
            && actual.bank_hash != [0; 32]
            && actual.last_blockhash != [0; 32],
        "native checkpoint does not match snapshot identity or emitted writes",
    )?;
    Ok(())
}
fn cgroup_path(unit: &str, membership: &str) -> Result<PathBuf, String> {
    let mut paths = membership.lines().filter_map(|l| l.strip_prefix("0::"));
    let path = paths.next().ok_or("no unified cgroup")?;
    require(
        paths.next().is_none() && path == format!("/system.slice/{unit}"),
        "foreign cgroup",
    )?;
    Ok(Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/')))
}
fn cgroup_metrics(path: &Path) -> Result<serde_json::Value, String> {
    let number = |name: &str| -> Result<u64, String> {
        fs::read_to_string(path.join(name))
            .map_err(|e| e.to_string())?
            .trim()
            .parse()
            .map_err(|e| format!("{e}"))
    };
    let events = fs::read_to_string(path.join("memory.events")).map_err(|e| e.to_string())?;
    Ok(
        json!({"memory_current_bytes":number("memory.current")?,"memory_peak_bytes":number("memory.peak")?,
        "memory_events":events,"cpu_stat":fs::read_to_string(path.join("cpu.stat")).map_err(|e|e.to_string())?,
        "io_stat":fs::read_to_string(path.join("io.stat")).map_err(|e|e.to_string())?}),
    )
}
fn scratch_metrics(root: &Path) -> Result<serde_json::Value, String> {
    let mut pending = vec![(root.to_path_buf(), 0)];
    let (mut physical, mut apparent, mut files, mut directories, mut symlinks) = (
        fs::symlink_metadata(root)
            .map_err(|e| e.to_string())?
            .blocks()
            .checked_mul(512)
            .ok_or("block overflow")?,
        0u64,
        0u64,
        0u64,
        0u64,
    );
    while let Some((directory, depth)) = pending.pop() {
        require(
            depth <= 64 && files + directories + symlinks <= 4_000_000,
            "scratch scan bound",
        )?;
        directories += 1;
        for entry in fs::read_dir(directory).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let meta = fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
            physical = physical
                .checked_add(meta.blocks().checked_mul(512).ok_or("block overflow")?)
                .ok_or("physical overflow")?;
            require(
                physical <= MAX_SCRATCH,
                "diagnostic scratch exceeds 256 GiB",
            )?;
            if meta.is_dir() {
                pending.push((entry.path(), depth + 1));
            } else if meta.file_type().is_symlink() {
                symlinks += 1;
            } else if meta.is_file() {
                files += 1;
                apparent = apparent
                    .checked_add(meta.len())
                    .ok_or("apparent overflow")?;
                require(
                    physical <= MAX_SCRATCH,
                    "diagnostic scratch exceeds 256 GiB",
                )?;
            } else {
                return Err("unexpected scratch object".into());
            }
            require(
                files + directories + symlinks + pending.len() as u64 <= 4_000_000,
                "scratch entry bound",
            )?;
        }
    }
    Ok(
        json!({"physical_bytes":physical,"apparent_bytes":apparent,"regular_files":files,
        "directories":directories,"symlinks_not_followed":symlinks,"full_cold_epoch_peak_qualified":false}),
    )
}
fn execute(plan_path: &Path, plan_sha: &str, self_sha: &str) -> Result<(), String> {
    require(
        unsafe { libc::geteuid() } != 0,
        "run as isolated replay user",
    )?;
    require(
        !cfg!(any(
            feature = "epoch224-v1-6-25-diagnostic",
            feature = "epoch224-v1-6-25-qualification"
        )),
        "wrong diagnostic runtime build",
    )?;
    bound_bytes(
        &fs::read_link("/proc/self/exe").map_err(|e| e.to_string())?,
        self_sha,
        256 << 20,
        true,
    )?;
    let plan: Plan = serde_json::from_slice(&bound_bytes(plan_path, plan_sha, 1 << 20, true)?)
        .map_err(|e| e.to_string())?;
    validate_plan(&plan)?;
    let invocation = env::var("INVOCATION_ID").map_err(|e| e.to_string())?;
    require(
        invocation.len() == 32
            && invocation
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "missing canonical invocation",
    )?;
    let cgroup = cgroup_path(
        &plan.unit,
        &fs::read_to_string("/proc/self/cgroup").map_err(|e| e.to_string())?,
    )?;
    for path in [
        &plan.run_root,
        &plan.scratch_directory,
        plan.output.parent().unwrap(),
    ] {
        validate_private_directory(path)?;
    }
    require(
        fs::read_dir(&plan.scratch_directory)
            .map_err(|e| e.to_string())?
            .next()
            .is_none(),
        "scratch not empty",
    )?;
    require(
        fs::symlink_metadata(&plan.output).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "output exists",
    )?;
    bound_bytes(&plan.worker, WORKER, 256 << 20, true)?;
    require(
        plan.ledger_directory.is_absolute()
            && fs::canonicalize(&plan.ledger_directory).map_err(|e| e.to_string())?
                == plan.ledger_directory,
        "noncanonical sealed ledger",
    )?;
    let ledger = fs::symlink_metadata(&plan.ledger_directory).map_err(|e| e.to_string())?;
    require(
        ledger.is_dir() && ledger.uid() == 0 && ledger.mode() & 0o222 == 0,
        "ledger not immutable",
    )?;
    require(
        fs::symlink_metadata(plan.ledger_directory.join("genesis.bin"))
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "genesis shadow",
    )?;
    let genesis = plan.ledger_directory.join("genesis.tar.bz2");
    bound_bytes(&genesis, GENESIS, 10 << 20, true)?;
    let before_free = free_bytes(&plan.scratch_directory)?;
    require(
        before_free >= plan.minimum_free_bytes,
        "fresh free-space admission failed",
    )?;
    let before = cgroup_metrics(&cgroup)?;
    let before_failure = before.clone();
    let started = Instant::now();
    let outcome = (|| -> Result<serde_json::Value, String> {
        let mut client = HistoricalRuntimeClient::spawn(
            SOLANA_V1_6_20_CANDIDATE,
            WorkerSpawn {
                executable: plan.worker.clone(),
                initialization: HistoricalInitialization::SnapshotArchive(SnapshotInitialization {
                    ledger_path: plan.ledger_directory.clone(),
                    archive_path: plan.snapshot.clone(),
                    expected_slot: SLOT,
                    expected_accounts_hash: Hash::from_str(ACCOUNTS)
                        .map_err(|e| e.to_string())?
                        .to_bytes(),
                    expected_archive_sha256: Some(digest(SNAPSHOT)?),
                    expected_archive_size: Some(SNAPSHOT_SIZE),
                    scratch_parent: Some(plan.scratch_directory.clone()),
                }),
            },
        )
        .map_err(|e| e.to_string())?;
        require(
            client.executable_sha256() == digest(WORKER)?,
            "executed worker mismatch",
        )?;
        let initial_cursor = client.initialized().next_write_version;
        let checkpoint = client.freeze_checkpoint(SLOT).map_err(|e| e.to_string())?;
        validate_checkpoint(&checkpoint, initial_cursor)?;
        // The child has no replay entries and waits on IPC. Capture before shutdown
        // can retire its temporary AccountsDb. No pause/replay authority is added.
        let scratch = scratch_metrics(&plan.scratch_directory)?;
        let loaded = cgroup_metrics(&cgroup)?;
        let restore_millis = started.elapsed().as_millis();
        client.shutdown().map_err(|e| e.to_string())?;
        bound_bytes(&genesis, GENESIS, 10 << 20, true)?;
        let receipt = json!({"schema":"jetstreamer-private-epoch225-bootstrap-resource-v1",
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e|e.to_string())?.as_secs(),
        "unit":plan.unit,"invocation_id":invocation,"probe_sha256":self_sha,
        "plan":{"path":plan_path,"sha256":plan_sha},"worker":{"path":plan.worker,"sha256":WORKER},
        "snapshot":{"path":plan.snapshot,"sha256":SNAPSHOT,"bytes":SNAPSHOT_SIZE},
        "native_checkpoint":{"slot":checkpoint.slot,"bank_hash":Hash::new_from_array(checkpoint.bank_hash).to_string(),
            "accounts_hash":Hash::new_from_array(checkpoint.accounts_hash).to_string(),
            "last_blockhash":Hash::new_from_array(checkpoint.last_blockhash).to_string(),
            "capitalization":checkpoint.capitalization,"transaction_count":checkpoint.transaction_count,
            "tick_height":checkpoint.tick_height,"slot_complete":checkpoint.slot_complete,
            "write_count":checkpoint.writes.len(),"next_write_version":checkpoint.next_write_version},
        "resources":{"before":before,"loaded":loaded,"after_shutdown":cgroup_metrics(&cgroup)?,
            "scratch_before_shutdown":scratch,"restore_and_checkpoint_millis":restore_millis,
            "available_bytes_before":before_free,"available_bytes_after":free_bytes(&plan.scratch_directory)?},
        "assessment":{"accounts_hash_matches_snapshot":true,"external_bank_hash_comparison_performed":false,
            "full_cold_epoch_peak_qualified":false,"replay_entries_sent":0,"archive_created":false},
        "authority":{"ordinary_replay_authorized":false,"canonical_sidecar_authorized":false,
            "runtime_promotion_authorized":false,"publication_authorized":false,
            "local_retirement_authorized":false,"remote_mutations":false,"r2_mutations":false}});
        Ok(receipt)
    })();
    let receipt = match outcome {
        Ok(receipt) => receipt,
        Err(error) => {
            // Capture counters while this persistent parent/cgroup still
            // exists. Never give a failed restore the success receipt name.
            let failure = json!({"schema":"jetstreamer-private-epoch225-bootstrap-resource-failure-v1",
                "unit":plan.unit,"invocation_id":invocation,"probe_sha256":self_sha,
                "plan":{"path":plan_path,"sha256":plan_sha},"error":error,
                "elapsed_millis":started.elapsed().as_millis(),"before":before_failure,
                "after_failure":cgroup_metrics(&cgroup).map_err(|e|e.to_string()),
                "scratch_after_child_cleanup":scratch_metrics(&plan.scratch_directory).map_err(|e|e.to_string()),
                "ordinary_replay_authorized":false,"full_cold_epoch_peak_qualified":false,
                "publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
            if let Err(preserve_error) = write_receipt(
                &plan.output.parent().unwrap().join("failure.json"),
                &failure,
            ) {
                return Err(format!(
                    "{error}; failure receipt could not be preserved: {preserve_error}"
                ));
            }
            return Err(error);
        }
    };
    write_receipt(&plan.output, &receipt)?;
    println!(
        "private225bootstrap resource measurement passed: {}",
        plan.output.display()
    );
    Ok(())
}

fn write_receipt(path: &Path, receipt: &serde_json::Value) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(receipt).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| e.to_string())?;
    output
        .write_all(&bytes)
        .and_then(|_| output.sync_all())
        .map_err(|e| e.to_string())?;
    File::open(path.parent().ok_or("receipt parent missing")?)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(())
}
fn main() {
    let args: Vec<String> = env::args().collect();
    let result = if args.len() == 6 && args[2] == "--plan-sha256" && args[4] == "--self-sha256" {
        execute(Path::new(&args[1]), &args[3], &args[5])
    } else {
        Err("usage: jetstreamer-epoch225-bootstrap-resource PLAN --plan-sha256 HEX --self-sha256 HEX".into())
    };
    if let Err(error) = result {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failure_evidence_is_private_and_never_clobbered() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("failure.json");
        let value = json!({"publication_authorized":false,"full_cold_epoch_peak_qualified":false});
        write_receipt(&path, &value).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o400);
        assert!(write_receipt(&path, &json!({"changed":true})).is_err());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&fs::read(&path).unwrap()).unwrap(),
            value
        );
    }
    #[test]
    fn plan_cannot_expand_scope_or_reduce_reserve() {
        let root = PathBuf::from("/home/ubuntu/.jetstreamer-private/bootstrap-resource-225-test");
        let original = Plan {
            schema: "jetstreamer-private-epoch225-bootstrap-resource-plan-v1".into(),
            unit: "horizon-qualify-225-bootstrap-resource-test.service".into(),
            worker: "/var/lib/worker".into(),
            snapshot:
                "/var/lib/snapshot-97199617-HE57JmgvEeZjBKN8cfTLrmyCbUnptJ9PWjUdTzgxSSdi.tar.zst"
                    .into(),
            ledger_directory: "/var/lib/sealed-ledger".into(),
            run_root: root.clone(),
            scratch_directory: root.join("scratch"),
            output: root.join("receipts/resource.json"),
            minimum_free_bytes: MINIMUM_FREE,
        };
        validate_plan(&original).unwrap();
        let mut bad = original;
        bad.minimum_free_bytes -= 1;
        assert!(validate_plan(&bad).is_err());
        bad.minimum_free_bytes = MINIMUM_FREE;
        bad.output = "/home/ubuntu/horizon/epoch-225.jet".into();
        assert!(validate_plan(&bad).is_err());
        bad.output = root.join("receipts/resource.json");
        bad.snapshot = "/var/lib/snapshot-97199618-other.tar.zst".into();
        assert!(validate_plan(&bad).is_err());
    }
    fn checkpoint() -> HistoricalCheckpoint {
        HistoricalCheckpoint {
            slot: SLOT,
            bank_hash: [1; 32],
            accounts_hash: Hash::from_str(ACCOUNTS).unwrap().to_bytes(),
            last_blockhash: [2; 32],
            capitalization: 1,
            transaction_count: 1,
            tick_height: (SLOT + 1) * 64,
            slot_complete: true,
            writes: vec![],
            next_write_version: 123,
        }
    }
    #[test]
    fn snapshot_scope_and_no_replay_cursor_are_required() {
        validate_checkpoint(&checkpoint(), 123).unwrap();
        let changes: [fn(&mut HistoricalCheckpoint); 6] = [
            |v| v.slot += 1,
            |v| v.accounts_hash[0] ^= 1,
            |v| v.slot_complete = false,
            |v| v.tick_height += 1,
            |v| v.next_write_version += 1,
            |v| v.bank_hash = [0; 32],
        ];
        for mutate in changes {
            let mut v = checkpoint();
            mutate(&mut v);
            assert!(validate_checkpoint(&v, 123).is_err());
        }
    }
    #[test]
    fn membership_cannot_select_another_service() {
        assert!(cgroup_path("target.service", "0::/system.slice/target.service\n").is_ok());
        for bad in [
            "0::/system.slice/other.service",
            "0::/system.slice/../target.service",
            "0::/system.slice/target.service\n0::/system.slice/target.service",
        ] {
            assert!(cgroup_path("target.service", bad).is_err());
        }
    }
    #[test]
    fn measurement_does_not_follow_symlinks() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("file"), b"hello").unwrap();
        std::os::unix::fs::symlink("/etc", d.path().join("outside")).unwrap();
        let m = scratch_metrics(d.path()).unwrap();
        assert_eq!(m["regular_files"], 1);
        assert_eq!(m["symlinks_not_followed"], 1);
    }
    #[test]
    fn source_evidence_binding_is_nofollow_and_bounded() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("evidence");
        fs::write(&p, b"test").unwrap();
        let sha = format!("{:x}", Sha256::digest(b"test"));
        assert!(bound_bytes(&p, &sha, 4, false).is_ok());
        assert!(bound_bytes(&p, &sha, 3, false).is_err());
        assert!(bound_bytes(&p, &"0".repeat(64), 4, false).is_err());
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(bound_bytes(&link, &sha, 4, false).is_err());
    }
}
