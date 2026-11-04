//! Shared gates for fixed census-only and complete-retention executables.
//! No download, native liveness, replay or publication authority.
// The shared module includes SDK helpers used by the download/reverify siblings;
// this offline census deliberately never calls those helpers.
#[allow(dead_code)]
#[path = "epoch141_ledger_common.rs"]
mod epoch141_ledger_common;
#[path = "epoch141_protection_transition.rs"]
mod epoch141_protection_transition;

use {
    anyhow::{Context, Result, ensure},
    epoch141_ledger_common::{
        FROZEN_INPUT as INPUT, FROZEN_SHA as SOURCE_SHA, GENERATION, SIZE, URI, bound_file,
        identity, is_sha, validate_reverification as validate_source, write_receipt,
    },
    jetstreamer_utils::{
        horizon_ledger_bzip::{census_bound_bzip2_guarded, collect_bound_bzip2_guarded},
        horizon_ledger_tar::CollectionLimits,
    },
    serde::Deserialize,
    serde_json::{Value, json},
    std::{
        collections::BTreeMap,
        env,
        ffi::CString,
        fs,
        os::unix::fs::MetadataExt,
        path::{Path, PathBuf},
        time::{Instant, SystemTime, UNIX_EPOCH},
    },
};

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
    source_verification: Bound,
    admission_manifest: Bound,
    admission_receipt: PathBuf,
    initial_guard_receipt: PathBuf,
    output_receipt: PathBuf,
    archive_root: PathBuf,
    minimum_free_bytes: u64,
    maximum_runtime_seconds: u64,
    maximum_files: usize,
    maximum_file_bytes: u64,
    maximum_total_bytes: u64,
    maximum_trailer_bytes: u64,
    retention: Option<Retention>,
    #[serde(default)]
    protection_transition: Option<Bound>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Retention {
    complete_census: Bound,
    destination: PathBuf,
    incremental_peak_bytes: u64,
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn validate_census(plan: &Plan, receipt: &Value, device: u64, inode: u64) -> Result<Value> {
    let retention = plan
        .retention
        .as_ref()
        .context("missing retention policy")?;
    ensure!(
        receipt["schema"] == "jetstreamer-epoch141-ledger-census-receipt-v1"
            && receipt["epoch"] == 141
            && receipt["input"] == INPUT
            && receipt["uri"] == URI
            && receipt["generation"] == GENERATION
            && receipt["source_verification_sha256"] == plan.source_verification.sha256
            && receipt["files_retained"] == false
            && receipt["source_modified"] == false
            && receipt["download_performed"] == false
            && receipt["source_completeness_proven"] == false
            && receipt["live_state_proven"] == false
            && receipt["replay_launch_authorized"] == false
            && receipt["publication_authorized"] == false
            && receipt["remote_mutations"] == false
            && receipt["r2_mutations"] == false,
        "wrong complete-census source/profile binding"
    );
    let census = &receipt["census"];
    let collection = &census["collection"];
    ensure!(
        census["compressed_sha256"] == SOURCE_SHA
            && census["compressed_bytes"] == SIZE
            && census["input_device"] == device
            && census["input_inode"] == inode
            && census["cloud_generation_authenticated"] == false
            && census["resource_admission_proven"] == false
            && census["publication_authorized"] == false
            && collection["archive_root"].as_str() == plan.archive_root.to_str()
            && collection["files_retained"] == false
            && collection["source_completeness_proven"] == false
            && collection["live_state_resolved"] == false
            && collection["publication_authorized"] == false,
        "wrong complete-census compressed identity or authority"
    );
    let files = collection["files"]
        .as_array()
        .context("missing complete file census")?;
    ensure!(
        !files.is_empty() && files.len() <= plan.maximum_files,
        "census file-count bound"
    );
    let mut total = 0u64;
    let mut peak = 64 * 1024 * 1024u64;
    let mut previous = "";
    for file in files {
        let name = file["name"].as_str().context("missing census basename")?;
        let bytes = file["bytes"].as_u64().context("missing census length")?;
        ensure!(
            !name.is_empty()
                && name.len() <= 255
                && name > previous
                && Path::new(name).components().count() == 1
                && Path::new(name)
                    .components()
                    .all(|c| matches!(c, std::path::Component::Normal(_)))
                && bytes <= plan.maximum_file_bytes
                && file["sha256"].as_str().is_some_and(is_sha),
            "invalid census member"
        );
        previous = name;
        total = total.checked_add(bytes).context("census total overflow")?;
        // Budget regular output allocation conservatively; this is not a claim
        // that logical bytes exactly predict filesystem physical consumption.
        peak = peak
            .checked_add(
                bytes
                    .div_ceil(4096)
                    .checked_mul(4096)
                    .context("census allocation overflow")?,
            )
            .context("census peak overflow")?;
    }
    ensure!(
        total > 0
            && total <= plan.maximum_total_bytes
            && collection["total_bytes"] == total
            && retention.incremental_peak_bytes >= peak
            && retention.incremental_peak_bytes <= 16 * 1024 * 1024 * 1024 * 1024u64,
        "unadmitted complete retention footprint"
    );
    // Only the parser's exact complete result may succeed after extraction.
    // This also compares CURRENT/MANIFEST/WAL bindings, not only SST digests.
    Ok(census.clone())
}

fn validate_destination(plan: &Plan, retention: &Retention, device: u64) -> Result<()> {
    let path = &retention.destination;
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == *path
            && m.is_dir()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o7777 == 0o700
            && m.dev() == device
            && !path.starts_with(Path::new(INPUT).parent().unwrap())
            && !Path::new(INPUT).starts_with(path)
            && !plan.output_receipt.starts_with(path)
            && !plan.initial_guard_receipt.starts_with(path)
            && !retention.complete_census.path.starts_with(path)
            && !plan.source_verification.path.starts_with(path)
            && !plan.admission_manifest.path.starts_with(path)
            && !plan.admission_receipt.starts_with(path)
            && fs::read_dir(path)?.next().is_none(),
        "retention needs a separate empty canonical root-private same-filesystem directory"
    );
    Ok(())
}

fn validate_bounds(plan: &Plan, retain: bool) -> Result<()> {
    ensure!(
        if retain {
            plan.schema == "jetstreamer-epoch141-ledger-collection-plan-v1"
                && plan.retention.is_some()
        } else {
            plan.schema == "jetstreamer-epoch141-ledger-census-plan-v1" && plan.retention.is_none()
        },
        "wrong fixed executable profile or plan schema"
    );
    ensure!(
        (plan.minimum_free_bytes >= 5_153_013_784_006
            || (retain
                && plan.retention.is_some()
                && plan.protection_transition.is_some()
                && plan.minimum_free_bytes >= 205_211_459_014))
            && (60..=43200).contains(&plan.maximum_runtime_seconds)
            && (1..=100_000).contains(&plan.maximum_files)
            && (1..=512 * 1024 * 1024 * 1024).contains(&plan.maximum_file_bytes)
            && (1..=16 * 1024 * 1024 * 1024 * 1024).contains(&plan.maximum_total_bytes)
            && (512..=16 * 1024 * 1024).contains(&plan.maximum_trailer_bytes),
        "unsafe census bounds"
    );
    ensure!(
        plan.archive_root == Path::new("rocksdb"),
        "unqualified archive root"
    );
    ensure!(
        plan.output_receipt.is_absolute()
            && plan.admission_receipt.is_absolute()
            && plan.output_receipt != plan.admission_receipt
            && !plan
                .output_receipt
                .starts_with(Path::new(INPUT).parent().unwrap()),
        "unsafe output scope"
    );
    ensure!(
        plan.initial_guard_receipt != plan.output_receipt
            && plan.initial_guard_receipt != plan.admission_receipt
            && plan.initial_guard_receipt.parent() == plan.output_receipt.parent(),
        "unsafe initial guard path"
    );
    let parent = plan
        .output_receipt
        .parent()
        .context("missing output parent")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o7777 == 0o700,
        "unsafe output parent"
    );
    ensure!(
        fs::symlink_metadata(&plan.output_receipt)
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "output already exists"
    );
    Ok(())
}

fn validate_admission(
    plan: &Plan,
    receipt: &Value,
    manifest: &Value,
    executable: &Path,
    executable_sha: &str,
) -> Result<()> {
    ensure!(
        receipt["schema"] == "jetstreamer-historical-performance-admission-receipt-v1"
            && receipt["admitted"] == true
            && receipt["manifest"].as_str() == plan.admission_manifest.path.to_str()
            && receipt["manifest_sha256"] == plan.admission_manifest.sha256
            && receipt["services_started"] == false
            && receipt["services_installed"] == false
            && receipt["remote_mutations"] == false
            && receipt["r2_mutations"] == false,
        "wrong exact admission binding"
    );
    let required_free = plan
        .minimum_free_bytes
        .checked_add(
            plan.retention
                .as_ref()
                .map_or(0, |r| r.incremental_peak_bytes),
        )
        .context("admission peak overflow")?;
    ensure!(
        manifest["schema"] == "jetstreamer-historical-performance-admission-v1"
            && manifest["filesystem"] == "/home/sol"
            && manifest["minimum_free_bytes"]
                .as_u64()
                .is_some_and(|n| n >= required_free)
            && receipt["evidence"]["minimum_free_bytes"] == manifest["minimum_free_bytes"]
            && receipt["evidence"]["filesystem"] == "/home/sol",
        "wrong admission envelope"
    );
    let files = manifest["files"]
        .as_array()
        .context("missing admission file census")?;
    ensure!(
        files
            .iter()
            .any(|f| f["path"].as_str() == executable.to_str()
                && f["sha256"] == executable_sha
                && f["uid"] == 0
                && f["mode"] == "0555"),
        "admission lacks exact census executable"
    );
    ensure!(
        receipt["evidence"]["files"]
            .as_array()
            .context("missing admitted file census")?
            .iter()
            .any(|f| f["path"].as_str() == executable.to_str() && f["sha256"] == executable_sha),
        "admission did not observe exact executable"
    );
    Ok(())
}

fn guard(plan: &Plan, start: Instant) -> Result<u64> {
    ensure!(
        start.elapsed().as_secs() < plan.maximum_runtime_seconds,
        "census runtime exceeded"
    );
    let path = CString::new(INPUT)?;
    let mut state = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), state.as_mut_ptr()) } == 0,
        "cannot read available bytes"
    );
    let state = unsafe { state.assume_init() };
    let free = state
        .f_bavail
        .checked_mul(state.f_frsize)
        .context("free byte overflow")?;
    ensure!(
        free >= plan.minimum_free_bytes,
        "census protected-space floor crossed"
    );
    Ok(free)
}

pub(crate) fn run(retain: bool) -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "census requires root");
    let mut args = env::args().skip(1);
    let mut values = BTreeMap::new();
    while let Some(key) = args.next() {
        ensure!(
            [
                "--plan",
                "--plan-sha256",
                "--self-sha256",
                "--admission-sha256",
                "--check-only"
            ]
            .contains(&key.as_str()),
            "unknown option"
        );
        let value = if key == "--check-only" {
            "true".into()
        } else {
            args.next().context("missing value")?
        };
        ensure!(values.insert(key, value).is_none(), "duplicate argument");
    }
    for key in [
        "--plan",
        "--plan-sha256",
        "--self-sha256",
        "--admission-sha256",
    ] {
        ensure!(values.contains_key(key), "missing argument {key}");
    }
    let executable = fs::read_link("/proc/self/exe")?;
    bound_file(
        &executable,
        &values["--self-sha256"],
        64 * 1024 * 1024,
        true,
    )?;
    let plan_bytes = bound_file(
        Path::new(&values["--plan"]),
        &values["--plan-sha256"],
        65536,
        true,
    )?;
    let plan: Plan = serde_json::from_slice(&plan_bytes)?;
    validate_bounds(&plan, retain)?;
    let source: Value = serde_json::from_slice(&bound_file(
        &plan.source_verification.path,
        &plan.source_verification.sha256,
        65536,
        false,
    )?)?;
    validate_source(&source)?;
    // Source integrity is permanent; its old scheduling reservations are not.
    // A complete-retention transition must independently prove the new envelope.
    let source_floor = source["minimum_free_bytes"]
        .as_u64()
        .context("missing source protected floor")?;
    ensure!(
        plan.minimum_free_bytes >= source_floor || (retain && plan.protection_transition.is_some()),
        "weakened source protected floor"
    );
    let input = Path::new(INPUT);
    let before = fs::symlink_metadata(input)?;
    ensure!(
        serde_json::to_value(identity(&before))? == source["identity"]
            && before.gid() == 0
            && input.canonicalize()? == input,
        "source identity differs from verification"
    );
    let expected_census = if let Some(retention) = &plan.retention {
        let receipt: Value = serde_json::from_slice(&bound_file(
            &retention.complete_census.path,
            &retention.complete_census.sha256,
            32 * 1024 * 1024,
            false,
        )?)?;
        let expected = validate_census(&plan, &receipt, before.dev(), before.ino())?;
        validate_destination(&plan, retention, before.dev())?;
        Some(expected)
    } else {
        None
    };
    let manifest: Value = serde_json::from_slice(&bound_file(
        &plan.admission_manifest.path,
        &plan.admission_manifest.sha256,
        4 * 1024 * 1024,
        true,
    )?)?;
    let admission: Value = serde_json::from_slice(&bound_file(
        &plan.admission_receipt,
        &values["--admission-sha256"],
        4 * 1024 * 1024,
        false,
    )?)?;
    validate_admission(
        &plan,
        &admission,
        &manifest,
        &executable,
        &values["--self-sha256"],
    )?;
    if let Some(transition) = &plan.protection_transition {
        ensure!(retain, "protection transition is retention-only");
        let retained = plan.retention.as_ref().context("missing retention")?;
        epoch141_protection_transition::validate(
            &transition.path,
            &transition.sha256,
            &plan.source_verification.sha256,
            &retained.complete_census.sha256,
            source_floor,
            plan.minimum_free_bytes,
            &manifest,
            now()?,
        )?;
    }
    let m = fs::symlink_metadata(&plan.admission_receipt)?;
    let age = now()?
        .checked_sub(u64::try_from(m.mtime())?)
        .context("future admission timestamp")?;
    ensure!(age <= 300, "admission is older than 300 seconds");
    let start = Instant::now();
    let free_before = guard(&plan, start)?;
    if values.contains_key("--check-only") {
        println!("ledger local bindings passed; no scan, output or mutation");
        return Ok(());
    }
    let invocation = env::var("INVOCATION_ID").context("systemd invocation required")?;
    ensure!(
        invocation.len() == 32 && is_sha(&format!("{invocation}{invocation}")),
        "invalid invocation"
    );
    write_receipt(
        &plan.initial_guard_receipt,
        &json!({
            "schema":if retain {"jetstreamer-epoch141-ledger-collection-initial-guard-v1"}
                else {"jetstreamer-epoch141-ledger-census-initial-guard-v1"}, "epoch":141,
            "invocation_id":invocation,"plan_sha256":values["--plan-sha256"],
            "self_sha256":values["--self-sha256"],"admission_receipt_sha256":values["--admission-sha256"],
            "protection_transition_sha256":plan.protection_transition.as_ref().map(|p| &p.sha256),
            "available_bytes":free_before,"minimum_free_bytes":plan.minimum_free_bytes,
            "trip":false,"files_retained":false,"retention_planned":retain,"publication_authorized":false,
            "remote_mutations":false,"r2_mutations":false
        }),
    )?;
    let mut last_guard = Instant::now();
    let limits = CollectionLimits {
        maximum_files: plan.maximum_files,
        maximum_file_bytes: plan.maximum_file_bytes,
        maximum_total_bytes: plan.maximum_total_bytes,
        maximum_trailer_bytes: plan.maximum_trailer_bytes,
    };
    let callback = || {
        if last_guard.elapsed().as_secs() >= 1 {
            guard(&plan, start)?;
            last_guard = Instant::now();
        }
        Ok(())
    };
    let census = if let Some(retention) = &plan.retention {
        collect_bound_bzip2_guarded(
            input,
            SIZE,
            SOURCE_SHA,
            SIZE,
            &plan.archive_root,
            &retention.destination,
            limits,
            callback,
        )?
    } else {
        census_bound_bzip2_guarded(
            input,
            SIZE,
            SOURCE_SHA,
            SIZE,
            &plan.archive_root,
            limits,
            callback,
        )?
    };
    let free_after = guard(&plan, start)?;
    ensure!(
        identity(&before) == identity(&fs::symlink_metadata(input)?),
        "source identity changed"
    );
    ensure!(
        census.collection.files_retained == retain,
        "wrong file retention profile"
    );
    if let Some(expected) = expected_census {
        let mut actual = serde_json::to_value(&census)?;
        actual["collection"]["files_retained"] = false.into();
        ensure!(
            actual == expected,
            "retained collection differs from complete prior census"
        );
        let retention = plan.retention.as_ref().unwrap();
        bound_file(
            &retention.complete_census.path,
            &retention.complete_census.sha256,
            32 * 1024 * 1024,
            false,
        )?;
    }
    bound_file(
        Path::new(&values["--plan"]),
        &values["--plan-sha256"],
        65536,
        true,
    )?;
    validate_bounds(&plan, retain)?;
    write_receipt(
        &plan.output_receipt,
        &json!({
            "schema":if retain {"jetstreamer-epoch141-ledger-collection-receipt-v1"}
                else {"jetstreamer-epoch141-ledger-census-receipt-v1"}, "epoch":141,
            "recorded_unix_seconds":now()?, "invocation_id":invocation,
            "self_sha256":values["--self-sha256"], "plan_sha256":values["--plan-sha256"],
            "source_verification_sha256":plan.source_verification.sha256,
            "protection_transition_sha256":plan.protection_transition.as_ref().map(|p| &p.sha256),
            "admission_manifest_sha256":plan.admission_manifest.sha256,
            "admission_receipt_sha256":values["--admission-sha256"], "input":INPUT,
            "uri":URI, "generation":GENERATION, "census":census,
            "available_bytes_before":free_before,"available_bytes_after":free_after,
            "minimum_free_bytes":plan.minimum_free_bytes,"elapsed_seconds":start.elapsed().as_secs(),
            "source_modified":false,"download_performed":false,"files_retained":retain,
            "retained_directory":plan.retention.as_ref().map(|r| &r.destination),
            "prior_complete_census_sha256":plan.retention.as_ref().map(|r| &r.complete_census.sha256),
            "source_completeness_proven":false,"live_state_proven":false,
            "replay_launch_authorized":false,"publication_authorized":false,
            "remote_mutations":false,"r2_mutations":false
        }),
    )?;
    println!("complete private ledger result durable; no native/replay/publication authority");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::epoch141_ledger_common::{CRC, MD5};
    use super::*;

    fn plan() -> Plan {
        Plan {
            schema: "jetstreamer-epoch141-ledger-census-plan-v1".into(),
            source_verification: Bound {
                path: "/proof/source.json".into(),
                sha256: "1".repeat(64),
            },
            admission_manifest: Bound {
                path: "/proof/admission.json".into(),
                sha256: "2".repeat(64),
            },
            admission_receipt: "/proof/admitted.json".into(),
            initial_guard_receipt: "/result/initial-guard.json".into(),
            output_receipt: "/result/census.json".into(),
            archive_root: "rocksdb".into(),
            minimum_free_bytes: 5_153_013_784_006,
            maximum_runtime_seconds: 60,
            maximum_files: 100,
            maximum_file_bytes: 1024,
            maximum_total_bytes: 4096,
            maximum_trailer_bytes: 4096,
            retention: None,
            protection_transition: None,
        }
    }

    #[test]
    fn rejects_source_transport_identity_or_digest_mismatch() {
        let good = json!({"schema":"jetstreamer-epoch141-ledger-reverification-receipt-v1",
            "epoch":141,"compressed_input_verified":true,"path":INPUT,"bytes":SIZE,
            "sha256":SOURCE_SHA,"uri":URI,"generation":GENERATION,"crc32c_base64":CRC,
            "md5_base64":MD5,"source_modified":false,"download_performed":false});
        validate_source(&good).unwrap();
        for key in good.as_object().unwrap().keys() {
            let mut changed = good.clone();
            changed[key] = Value::Null;
            assert!(validate_source(&changed).is_err(), "accepted missing {key}");
        }
        let mut changed = good;
        changed["generation"] = "1634789748052740".into();
        assert!(validate_source(&changed).is_err());
    }

    #[test]
    #[ignore = "root-only disposable retention-directory policy qualification"]
    fn retention_destination_requires_private_empty_disjoint_same_filesystem() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("retained");
        fs::create_dir(&destination).unwrap();
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o700)).unwrap();
        let device = fs::symlink_metadata(&destination).unwrap().dev();
        let mut p = plan();
        p.retention = Some(Retention {
            complete_census: Bound {
                path: "/proof/census.json".into(),
                sha256: "4".repeat(64),
            },
            destination: destination.clone(),
            incremental_peak_bytes: 8192,
        });
        validate_destination(&p, p.retention.as_ref().unwrap(), device).unwrap();
        assert!(validate_destination(&p, p.retention.as_ref().unwrap(), device ^ 1).is_err());
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validate_destination(&p, p.retention.as_ref().unwrap(), device).is_err());
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o700)).unwrap();
        let link = root.path().join("link");
        symlink(&destination, &link).unwrap();
        p.retention.as_mut().unwrap().destination = link;
        assert!(validate_destination(&p, p.retention.as_ref().unwrap(), device).is_err());
        p.retention.as_mut().unwrap().destination = destination.clone();
        p.output_receipt = destination.join("result.json");
        assert!(validate_destination(&p, p.retention.as_ref().unwrap(), device).is_err());
        p.output_receipt = "/result/collection.json".into();
        fs::write(destination.join("preserved-partial"), b"diagnostic").unwrap();
        assert!(validate_destination(&p, p.retention.as_ref().unwrap(), device).is_err());
        assert_eq!(
            fs::read(destination.join("preserved-partial")).unwrap(),
            b"diagnostic"
        );
    }

    #[test]
    fn retention_requires_exact_prior_census_and_full_incremental_admission() {
        let mut p = plan();
        p.schema = "jetstreamer-epoch141-ledger-collection-plan-v1".into();
        p.retention = Some(Retention {
            complete_census: Bound {
                path: "/proof/census.json".into(),
                sha256: "4".repeat(64),
            },
            destination: "/private/retained".into(),
            incremental_peak_bytes: 64 * 1024 * 1024 + 8192,
        });
        assert!(
            validate_bounds(&p, false)
                .unwrap_err()
                .to_string()
                .contains("profile")
        );
        assert!(
            validate_bounds(&plan(), true)
                .unwrap_err()
                .to_string()
                .contains("profile")
        );
        let files = json!([
            {"name":"CURRENT", "bytes":11,"sha256":"5".repeat(64)},
            {"name":"MANIFEST-1","bytes":8,"sha256":"6".repeat(64)}
        ]);
        let census = json!({"compressed_sha256":SOURCE_SHA,"compressed_bytes":SIZE,
            "input_device":64512,"input_inode":10,"cloud_generation_authenticated":false,
            "resource_admission_proven":false,"publication_authorized":false,
            "collection":{"archive_root":"rocksdb","files_retained":false,"files":files,
                "total_bytes":19,"current_manifest":"MANIFEST-1","wal_files":[],
                "source_completeness_proven":false,"live_state_resolved":false,"publication_authorized":false}});
        let good = json!({"schema":"jetstreamer-epoch141-ledger-census-receipt-v1","epoch":141,
            "input":INPUT,"uri":URI,"generation":GENERATION,
            "source_verification_sha256":p.source_verification.sha256,"files_retained":false,
            "source_modified":false,"download_performed":false,"source_completeness_proven":false,
            "live_state_proven":false,"replay_launch_authorized":false,"publication_authorized":false,
            "remote_mutations":false,"r2_mutations":false,"census":census});
        assert_eq!(validate_census(&p, &good, 64512, 10).unwrap(), census);
        for key in good.as_object().unwrap().keys() {
            let mut changed = good.clone();
            changed[key] = Value::Null;
            assert!(
                validate_census(&p, &changed, 64512, 10).is_err(),
                "accepted missing {key}"
            );
        }
        for key in census.as_object().unwrap().keys() {
            let mut changed = good.clone();
            changed["census"][key] = Value::Null;
            assert!(
                validate_census(&p, &changed, 64512, 10).is_err(),
                "accepted missing {key}"
            );
        }
        for (pointer, value) in [
            ("/census/collection/files/1/name", json!("../MANIFEST-1")),
            ("/census/collection/files/1/name", json!("CURRENT")),
            ("/census/collection/files/0/bytes", json!(1025)),
            ("/census/collection/files/0/sha256", json!("bad")),
            ("/census/collection/files_retained", json!(true)),
            ("/census/collection/total_bytes", json!(20)),
        ] {
            let mut changed = good.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate_census(&p, &changed, 64512, 10).is_err(),
                "accepted {pointer}"
            );
        }
        assert!(validate_census(&p, &good, 64512, 11).is_err());
        p.retention.as_mut().unwrap().incremental_peak_bytes -= 1;
        assert!(validate_census(&p, &good, 64512, 10).is_err());
    }

    #[test]
    fn admission_requires_exact_manifest_binary_and_envelope() {
        let plan = plan();
        let executable = Path::new("/sealed/census");
        let hash = "3".repeat(64);
        let files = json!([{"path":executable,"sha256":hash,"uid":0,"mode":"0555"}]);
        let manifest = json!({"schema":"jetstreamer-historical-performance-admission-v1",
            "filesystem":"/home/sol","minimum_free_bytes":plan.minimum_free_bytes,"files":files});
        let good = json!({"schema":"jetstreamer-historical-performance-admission-receipt-v1",
            "admitted":true,"manifest":plan.admission_manifest.path,
            "manifest_sha256":plan.admission_manifest.sha256,"services_started":false,
            "services_installed":false,"remote_mutations":false,"r2_mutations":false,
            "evidence":{"filesystem":"/home/sol","minimum_free_bytes":plan.minimum_free_bytes,"files":files}});
        validate_admission(&plan, &good, &manifest, executable, &hash).unwrap();
        for key in good.as_object().unwrap().keys() {
            let mut changed = good.clone();
            changed[key] = Value::Null;
            assert!(
                validate_admission(&plan, &changed, &manifest, executable, &hash).is_err(),
                "accepted missing {key}"
            );
        }
        for key in ["files", "minimum_free_bytes", "filesystem", "schema"] {
            let mut changed = manifest.clone();
            changed[key] = Value::Null;
            assert!(validate_admission(&plan, &good, &changed, executable, &hash).is_err());
        }
        assert!(validate_admission(&plan, &good, &manifest, executable, &"4".repeat(64)).is_err());
        assert!(validate_admission(&plan, &good, &manifest, Path::new("/wrong"), &hash).is_err());
        let mut retaining = plan;
        retaining.retention = Some(Retention {
            complete_census: Bound {
                path: "/proof/census.json".into(),
                sha256: "4".repeat(64),
            },
            destination: "/private/retained".into(),
            incremental_peak_bytes: 8192,
        });
        assert!(validate_admission(&retaining, &good, &manifest, executable, &hash).is_err());
        let mut admitted = good;
        let mut manifest = manifest;
        manifest["minimum_free_bytes"] = (retaining.minimum_free_bytes + 8192).into();
        admitted["evidence"]["minimum_free_bytes"] = manifest["minimum_free_bytes"].clone();
        validate_admission(&retaining, &admitted, &manifest, executable, &hash).unwrap();
    }

    #[test]
    fn limits_fail_before_any_source_or_output_access() {
        let mut p = plan();
        p.maximum_runtime_seconds = 0;
        assert!(
            validate_bounds(&p, false)
                .unwrap_err()
                .to_string()
                .contains("bounds")
        );
        let mut p = plan();
        p.maximum_files = 100_001;
        assert!(
            validate_bounds(&p, false)
                .unwrap_err()
                .to_string()
                .contains("bounds")
        );
        let mut p = plan();
        p.minimum_free_bytes -= 1;
        assert!(
            validate_bounds(&p, false)
                .unwrap_err()
                .to_string()
                .contains("bounds")
        );
        let mut p = plan();
        p.maximum_runtime_seconds = 0;
        assert!(
            guard(&p, Instant::now())
                .unwrap_err()
                .to_string()
                .contains("runtime")
        );
    }

    #[test]
    fn lower_protection_requires_explicit_retention_transition_not_census() {
        let mut p = plan();
        p.minimum_free_bytes = 4_740_696_923_590;
        p.protection_transition = Some(Bound {
            path: "/proof/transition.json".into(),
            sha256: "5".repeat(64),
        });
        assert!(
            validate_bounds(&p, false)
                .unwrap_err()
                .to_string()
                .contains("bounds")
        );
        p.schema = "jetstreamer-epoch141-ledger-collection-plan-v1".into();
        p.retention = Some(Retention {
            complete_census: Bound {
                path: "/proof/census.json".into(),
                sha256: "4".repeat(64),
            },
            destination: "/private/retained".into(),
            incremental_peak_bytes: 8192,
        });
        // Resource shape passes, but the synthetic output parent is absent.
        assert!(
            !validate_bounds(&p, true)
                .unwrap_err()
                .to_string()
                .contains("bounds")
        );
        p.protection_transition = None;
        assert!(
            validate_bounds(&p, true)
                .unwrap_err()
                .to_string()
                .contains("bounds")
        );
    }
}
