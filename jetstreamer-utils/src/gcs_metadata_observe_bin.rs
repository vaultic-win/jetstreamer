use {
    anyhow::{Context, Result, ensure},
    serde::{Deserialize, Serialize},
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    std::{
        collections::BTreeMap,
        env,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            process::CommandExt,
        },
        path::{Path, PathBuf},
        process::{Command, Output},
        time::{SystemTime, UNIX_EPOCH},
    },
};

const PLAN_SCHEMA: &str = "jetstreamer-gcs-metadata-observation-plan-v1";
const RECEIPT_SCHEMA: &str = "jetstreamer-private-configured-gcs-metadata-reobservation-v1";
const CAPABILITY_SCHEMA: &str = "jetstreamer-private-configured-complete-span-capability-v1";
const LEGACY_EPOCH203_CAPABILITY_SCHEMA: &str =
    "jetstreamer-private-focused-tail-node-capability-v2";
const RESTORE_SCHEMA: &str = "jetstreamer-bound-gcs-snapshot-restore-v1";
const MAX_PLAN_BYTES: u64 = 1024 * 1024;
const MAX_EVIDENCE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_GCLOUD_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    epoch: u64,
    capability: EvidencePlan,
    restore: EvidencePlan,
    retained_input_audit: EvidencePlan,
    snapshot: PathBuf,
    output: PathBuf,
    remote_object: RemoteObject,
    gcloud: GcloudPlan,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidencePlan {
    path: PathBuf,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RemoteObject {
    bucket: String,
    name: String,
    generation: String,
    storage_url: String,
    size: u64,
    crc32c_hash: String,
    md5_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GcloudPlan {
    executable: PathBuf,
    executable_sha256: String,
    config_directory: PathBuf,
    account: String,
    billing_project: String,
    sdk_version: String,
    core_version: String,
    run_uid: u32,
    run_gid: u32,
}

#[derive(Debug)]
struct Arguments {
    plan: PathBuf,
    plan_sha256: String,
    self_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
struct FileIdentity {
    path: String,
    device: u64,
    inode: u64,
    link_count: u64,
    uid: u32,
    gid: u32,
    mode: String,
    size: u64,
    mtime_ns: i128,
    sha256: String,
}

fn usage(program: &str) -> String {
    format!("usage: {program} --plan PATH --plan-sha256 HEX --self-sha256 HEX")
}

fn parse_arguments_from<I>(arguments: I) -> Result<Arguments>
where
    I: IntoIterator<Item = String>,
{
    let mut arguments = arguments.into_iter();
    let program = arguments
        .next()
        .unwrap_or_else(|| "jetstreamer-gcs-metadata-observe".into());
    let mut values = BTreeMap::<String, PathBuf>::new();
    while let Some(flag) = arguments.next() {
        ensure!(
            matches!(flag.as_str(), "--plan" | "--plan-sha256" | "--self-sha256"),
            "{}\nunknown option {flag}",
            usage(&program)
        );
        let value = arguments
            .next()
            .with_context(|| format!("missing value for {flag}"))?;
        ensure!(
            values.insert(flag, PathBuf::from(value)).is_none(),
            "duplicate option"
        );
    }
    let take = |name: &str| -> Result<PathBuf> {
        values
            .get(name)
            .cloned()
            .with_context(|| format!("missing {name}"))
    };
    Ok(Arguments {
        plan: take("--plan")?,
        plan_sha256: take("--plan-sha256")?.to_string_lossy().into_owned(),
        self_sha256: take("--self-sha256")?.to_string_lossy().into_owned(),
    })
}

fn parse_arguments() -> Result<Arguments> {
    let arguments = env::args_os()
        .map(|value| {
            value
                .into_string()
                .map_err(|_| anyhow::anyhow!("arguments must be valid UTF-8"))
        })
        .collect::<Result<Vec<_>>>()?;
    parse_arguments_from(arguments)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn exact_file(
    path: &Path,
    expected_uid: u32,
    immutable: bool,
    max_bytes: Option<u64>,
) -> Result<(FileIdentity, Vec<u8>)> {
    ensure!(
        path.is_absolute(),
        "path is not absolute: {}",
        path.display()
    );
    ensure!(
        path.canonicalize()? == path,
        "path is not exact: {}",
        path.display()
    );
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file() && !before.file_type().is_symlink(),
        "not a regular file: {}",
        path.display()
    );
    ensure!(before.nlink() == 1, "file is not singly linked");
    ensure!(before.uid() == expected_uid, "unexpected file owner");
    if immutable {
        ensure!(before.mode() & 0o222 == 0, "file is writable");
    }
    if let Some(limit) = max_bytes {
        ensure!(before.len() <= limit, "file is too large");
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let opened = file.metadata()?;
    let mut bytes = Vec::with_capacity(usize::try_from(before.len()).unwrap_or(0));
    file.read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let current = fs::symlink_metadata(path)?;
    let stable = |metadata: &fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
        )
    };
    ensure!(
        stable(&before) == stable(&opened)
            && stable(&before) == stable(&after)
            && stable(&before) == stable(&current),
        "file changed while reading: {}",
        path.display()
    );
    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    Ok((
        FileIdentity {
            path: path.display().to_string(),
            device: before.dev(),
            inode: before.ino(),
            link_count: before.nlink(),
            uid: before.uid(),
            gid: before.gid(),
            mode: format!("{:04o}", before.mode() & 0o7777),
            size: before.len(),
            mtime_ns: i128::from(before.mtime()) * 1_000_000_000 + i128::from(before.mtime_nsec()),
            sha256,
        },
        bytes,
    ))
}

fn exact_file_identity(path: &Path, expected_uid: u32, immutable: bool) -> Result<FileIdentity> {
    ensure!(
        path.is_absolute(),
        "path is not absolute: {}",
        path.display()
    );
    ensure!(
        path.canonicalize()? == path,
        "path is not exact: {}",
        path.display()
    );
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file() && !before.file_type().is_symlink(),
        "not a regular file: {}",
        path.display()
    );
    ensure!(before.nlink() == 1, "file is not singly linked");
    ensure!(before.uid() == expected_uid, "unexpected file owner");
    if immutable {
        ensure!(before.mode() & 0o222 == 0, "file is writable");
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let opened = file.metadata()?;
    let current = fs::symlink_metadata(path)?;
    let stable = |metadata: &fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
        )
    };
    ensure!(
        stable(&before) == stable(&opened) && stable(&before) == stable(&current),
        "file changed while opening: {}",
        path.display()
    );
    Ok(FileIdentity {
        path: path.display().to_string(),
        device: before.dev(),
        inode: before.ino(),
        link_count: before.nlink(),
        uid: before.uid(),
        gid: before.gid(),
        mode: format!("{:04o}", before.mode() & 0o7777),
        size: before.len(),
        mtime_ns: i128::from(before.mtime()) * 1_000_000_000 + i128::from(before.mtime_nsec()),
        sha256: String::new(),
    })
}

fn read_bound_json(
    path: &Path,
    digest: &str,
    uid: u32,
    immutable: bool,
) -> Result<(FileIdentity, Value)> {
    ensure!(is_sha256(digest), "invalid evidence SHA-256");
    let (identity, bytes) = exact_file(path, uid, immutable, Some(MAX_EVIDENCE_BYTES))?;
    ensure!(identity.sha256 == digest, "evidence SHA-256 mismatch");
    Ok((identity, serde_json::from_slice(&bytes)?))
}

fn read_plan(path: &Path, expected_sha256: &str) -> Result<(Plan, FileIdentity)> {
    ensure!(is_sha256(expected_sha256), "invalid plan SHA-256");
    let (identity, bytes) = exact_file(path, 0, true, Some(MAX_PLAN_BYTES))?;
    ensure!(identity.sha256 == expected_sha256, "plan SHA-256 mismatch");
    let plan: Plan = serde_json::from_slice(&bytes).context("invalid plan JSON")?;
    validate_plan(&plan)?;
    Ok((plan, identity))
}

fn validate_plan(plan: &Plan) -> Result<()> {
    ensure!(plan.schema == PLAN_SCHEMA, "plan schema mismatch");
    ensure!(
        (203..=212).contains(&plan.epoch),
        "epoch is outside approved range"
    );
    for digest in [
        &plan.capability.sha256,
        &plan.restore.sha256,
        &plan.retained_input_audit.sha256,
        &plan.gcloud.executable_sha256,
    ] {
        ensure!(is_sha256(digest), "plan contains an invalid SHA-256");
    }
    ensure!(plan.gcloud.run_uid > 0, "gcloud must run unprivileged");
    ensure!(plan.remote_object.size > 0, "remote object size is zero");
    ensure!(
        plan.remote_object.storage_url
            == format!(
                "gs://{}/{}#{}",
                plan.remote_object.bucket, plan.remote_object.name, plan.remote_object.generation
            ),
        "remote object identity is inconsistent"
    );
    let output_parent = plan.output.parent().context("output has no parent")?;
    ensure!(
        output_parent == Path::new("/home/ubuntu/.jetstreamer-private/campaign-state"),
        "output parent is not canonical"
    );
    let output_name = plan
        .output
        .file_name()
        .and_then(|name| name.to_str())
        .context("output filename is invalid")?;
    let output_prefix = format!("epoch{}-gcs-metadata-reobservation-", plan.epoch);
    ensure!(
        output_name.starts_with(&output_prefix) && output_name.ends_with(".json"),
        "output filename is not canonical"
    );
    let output_suffix = &output_name[output_prefix.len()..output_name.len() - ".json".len()];
    ensure!(
        !output_suffix.is_empty()
            && output_suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "output filename suffix is invalid"
    );
    Ok(())
}

fn validate_capability(value: &Value, epoch: u64) -> Result<()> {
    if epoch == 203
        && value.get("schema").and_then(Value::as_str) == Some(LEGACY_EPOCH203_CAPABILITY_SCHEMA)
    {
        ensure!(
            value.pointer("/probe/epoch").and_then(Value::as_u64) == Some(203),
            "legacy epoch-203 capability epoch mismatch"
        );
        ensure!(
            value
                .pointer("/probe/bootstrap_slot")
                .and_then(Value::as_u64)
                == Some(87_695_515)
                && value
                    .pointer("/probe/output_slot_start")
                    .and_then(Value::as_u64)
                    == Some(87_696_000)
                && value
                    .pointer("/probe/terminal_slot")
                    .and_then(Value::as_u64)
                    == Some(88_559_361),
            "legacy epoch-203 capability range mismatch"
        );
        ensure!(
            value
                .pointer("/attestation/exact_node_tail_planner_capability_passed")
                .and_then(Value::as_bool)
                == Some(true)
                && value
                    .pointer("/attestation/full_replay_authorized")
                    .and_then(Value::as_bool)
                    == Some(false)
                && value
                    .pointer("/attestation/fresh_epoch203_specific_resource_admission_passed")
                    .and_then(Value::as_bool)
                    == Some(false),
            "legacy epoch-203 capability attestation mismatch"
        );
        ensure!(
            value
                .pointer("/probe/worker_spawned")
                .and_then(Value::as_bool)
                == Some(false)
                && value
                    .pointer("/probe/archive_created")
                    .and_then(Value::as_bool)
                    == Some(false)
                && value
                    .pointer("/probe/canonical_sidecar_created")
                    .and_then(Value::as_bool)
                    == Some(false),
            "legacy epoch-203 capability unexpectedly reached replay"
        );
        return Ok(());
    }

    ensure!(value.get("schema").and_then(Value::as_str) == Some(CAPABILITY_SCHEMA));
    ensure!(value.get("epoch").and_then(Value::as_u64) == Some(epoch));
    ensure!(
        value
            .pointer("/plan/complete_epoch_span_covered")
            .and_then(Value::as_bool)
            == Some(true)
    );
    ensure!(
        value
            .pointer("/probe/replay_started")
            .and_then(Value::as_bool)
            == Some(false)
    );
    ensure!(
        value
            .pointer("/assessment/exact_node_complete_span_planner_capability_passed")
            .and_then(Value::as_bool)
            == Some(true)
    );
    ensure!(
        value
            .pointer("/assessment/full_replay_authorized")
            .and_then(Value::as_bool)
            == Some(false)
    );
    Ok(())
}

fn snapshot_identity_from_restore(
    value: &Value,
    snapshot: &Path,
    remote: &RemoteObject,
) -> Result<(u32, FileIdentity)> {
    ensure!(value.get("schema").and_then(Value::as_str) == Some(RESTORE_SCHEMA));
    ensure!(
        value.get("destination").and_then(Value::as_str)
            == Some(snapshot.to_string_lossy().as_ref())
    );
    ensure!(
        value.get("versioned_uri").and_then(Value::as_str) == Some(remote.storage_url.as_str())
    );
    let generation_matches = value
        .get("generation")
        .and_then(|generation| {
            generation
                .as_str()
                .map(str::to_owned)
                .or_else(|| generation.as_u64().map(|number| number.to_string()))
        })
        .is_some_and(|generation| generation == remote.generation);
    ensure!(generation_matches, "restore generation mismatch");
    let file = value
        .get("file")
        .and_then(Value::as_object)
        .context("restore lacks file")?;
    ensure!(file.get("size").and_then(Value::as_u64) == Some(remote.size));
    ensure!(file.get("crc32c_base64").and_then(Value::as_str) == Some(remote.crc32c_hash.as_str()));
    ensure!(file.get("md5_base64").and_then(Value::as_str) == Some(remote.md5_hash.as_str()));
    let uid = file
        .get("uid")
        .and_then(Value::as_u64)
        .and_then(|uid| u32::try_from(uid).ok())
        .context("restore file uid is invalid")?;
    let identity = exact_file_identity(snapshot, uid, false)?;
    for (key, observed) in [
        ("device", identity.device),
        ("inode", identity.inode),
        ("size", identity.size),
        ("uid", u64::from(identity.uid)),
    ] {
        ensure!(file.get(key).and_then(Value::as_u64) == Some(observed));
    }
    ensure!(
        file.get("mtime_ns").and_then(Value::as_i64).map(i128::from) == Some(identity.mtime_ns)
    );
    let restore_mode = file
        .get("mode")
        .and_then(Value::as_u64)
        .context("restore file mode is invalid")?;
    ensure!(restore_mode == u64::from(u32::from_str_radix(&identity.mode, 8)?));
    Ok((uid, identity))
}

fn exact_directory(path: &Path, uid: u32, writable: bool) -> Result<()> {
    ensure!(path.is_absolute(), "directory path is not absolute");
    ensure!(path.canonicalize()? == path, "directory path is not exact");
    let metadata = fs::symlink_metadata(path)?;
    ensure!(metadata.is_dir(), "not a directory: {}", path.display());
    ensure!(metadata.uid() == uid, "unexpected directory owner");
    ensure!(metadata.mode() & 0o002 == 0, "directory is world-writable");
    if !writable {
        ensure!(metadata.mode() & 0o222 == 0, "directory is writable");
    }
    Ok(())
}

fn run_gcloud(plan: &GcloudPlan, arguments: &[String]) -> Result<Output> {
    let output = Command::new(&plan.executable)
        .args(arguments)
        .env_clear()
        .env("HOME", "/home/ubuntu")
        .env("CLOUDSDK_CONFIG", &plan.config_directory)
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .uid(plan.run_uid)
        .gid(plan.run_gid)
        .output()
        .with_context(|| format!("failed to run {}", plan.executable.display()))?;
    ensure!(
        output.stdout.len() <= MAX_GCLOUD_OUTPUT_BYTES
            && output.stderr.len() <= MAX_GCLOUD_OUTPUT_BYTES,
        "gcloud output exceeded bound"
    );
    ensure!(
        output.status.success(),
        "gcloud failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(output)
}

fn write_receipt(path: &Path, value: &Value) -> Result<String> {
    ensure!(!path.exists(), "output already exists");
    let parent = path.parent().context("output has no parent")?;
    exact_directory(parent, 0, true)?;
    ensure!(
        fs::symlink_metadata(parent)?.permissions().mode() & 0o077 == 0,
        "output parent is not owner-only"
    );
    let bytes = [serde_json::to_vec_pretty(value)?, b"\n".to_vec()].concat();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    File::open(parent)?.sync_all()?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

fn execute(arguments: Arguments) -> Result<Value> {
    ensure!(unsafe { libc::geteuid() } == 0, "must run as root");
    let executable = fs::read_link("/proc/self/exe")?;
    let (self_identity, _) = exact_file(&executable, 0, true, None)?;
    ensure!(is_sha256(&arguments.self_sha256));
    ensure!(
        self_identity.sha256 == arguments.self_sha256,
        "self SHA-256 mismatch"
    );
    let (plan, plan_identity) = read_plan(&arguments.plan, &arguments.plan_sha256)?;

    let (capability_identity, capability) =
        read_bound_json(&plan.capability.path, &plan.capability.sha256, 0, true)?;
    validate_capability(&capability, plan.epoch)?;
    let (restore_identity, restore) = read_bound_json(
        &plan.restore.path,
        &plan.restore.sha256,
        plan.gcloud.run_uid,
        false,
    )?;
    let (audit_identity, _) = read_bound_json(
        &plan.retained_input_audit.path,
        &plan.retained_input_audit.sha256,
        0,
        true,
    )?;
    let (_, snapshot_identity) =
        snapshot_identity_from_restore(&restore, &plan.snapshot, &plan.remote_object)?;
    ensure!(
        snapshot_identity.gid == plan.gcloud.run_gid,
        "snapshot group does not match planned replay group"
    );

    let (gcloud_identity, _) =
        exact_file(&plan.gcloud.executable, plan.gcloud.run_uid, false, None)?;
    ensure!(gcloud_identity.sha256 == plan.gcloud.executable_sha256);
    exact_directory(&plan.gcloud.config_directory, plan.gcloud.run_uid, true)?;

    let account_output = run_gcloud(
        &plan.gcloud,
        &[
            "config".into(),
            "get-value".into(),
            "account".into(),
            "--quiet".into(),
        ],
    )?;
    ensure!(
        String::from_utf8(account_output.stdout)?.trim() == plan.gcloud.account,
        "effective gcloud account mismatch"
    );
    let version_output = run_gcloud(&plan.gcloud, &["version".into(), "--format=json".into()])?;
    let version: Value = serde_json::from_slice(&version_output.stdout)?;
    ensure!(
        version.get("Google Cloud SDK").and_then(Value::as_str)
            == Some(plan.gcloud.sdk_version.as_str())
            && version.get("core").and_then(Value::as_str)
                == Some(plan.gcloud.core_version.as_str()),
        "gcloud version mismatch"
    );
    let describe_output = run_gcloud(
        &plan.gcloud,
        &[
            "storage".into(),
            "objects".into(),
            "describe".into(),
            plan.remote_object.storage_url.clone(),
            format!("--account={}", plan.gcloud.account),
            format!("--billing-project={}", plan.gcloud.billing_project),
            "--format=json(bucket,name,generation,storage_url,size,crc32c_hash,md5_hash)".into(),
        ],
    )?;
    let remote: RemoteObject = serde_json::from_slice(&describe_output.stdout)?;
    ensure!(remote == plan.remote_object, "GCS metadata mismatch");

    let receipt = json!({
        "schema": RECEIPT_SCHEMA,
        "recorded_unix_seconds": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "epoch": plan.epoch,
        "configuration": {"path": plan_identity.path, "sha256": plan_identity.sha256},
        "effective_reader": {
            "uid": plan.gcloud.run_uid,
            "gid": plan.gcloud.run_gid,
            "cloudsdk_config": plan.gcloud.config_directory,
            "account": plan.gcloud.account,
            "billing_project": plan.gcloud.billing_project,
            "gcloud": gcloud_identity,
            "gcloud_version": version,
        },
        "remote_object": remote,
        "retained_bootstrap": {
            "path": snapshot_identity.path,
            "device": snapshot_identity.device,
            "inode": snapshot_identity.inode,
            "link_count": snapshot_identity.link_count,
            "uid": snapshot_identity.uid,
            "gid": snapshot_identity.gid,
            "mode": snapshot_identity.mode,
            "size": snapshot_identity.size,
            "mtime_ns": snapshot_identity.mtime_ns,
            "full_sha256_reread_passed": false,
        },
        "bound_evidence": [capability_identity, restore_identity, audit_identity],
        "assessment": {
            "exact_generation_reobserved": true,
            "remote_size_crc32c_md5_match_restore_receipt": true,
            "complete_span_planner_capability_bound": true,
            "fresh_local_bootstrap_full_reread_passed": false,
            "immutable_epoch_package_ready": false,
            "fresh_resource_admission_passed": false,
            "launch_authorized": false,
            "publication_authorized": false,
            "r2_upload_authorized": false,
        },
        "mutations": {
            "new_replay_launched": false,
            "local_files_deleted": false,
            "remote_mutations": false,
            "r2_mutations": false,
        },
        "observer": self_identity,
    });
    let receipt_sha256 = write_receipt(&plan.output, &receipt)?;
    Ok(json!({
        "receipt": plan.output,
        "sha256": receipt_sha256,
        "exact_generation_reobserved": true,
        "launch_authorized": false,
        "remote_mutations": false,
        "r2_mutations": false,
    }))
}

fn main() {
    let result = parse_arguments().and_then(execute);
    match result {
        Ok(value) => println!(
            "{}",
            serde_json::to_string(&value).expect("serialize result")
        ),
        Err(error) => {
            eprintln!("error: {error:#}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote() -> RemoteObject {
        RemoteObject {
            bucket: "bucket".into(),
            name: "123/snapshot.tar.zst".into(),
            generation: "456".into(),
            storage_url: "gs://bucket/123/snapshot.tar.zst#456".into(),
            size: 1,
            crc32c_hash: "abcd==".into(),
            md5_hash: "efgh==".into(),
        }
    }

    fn plan() -> Plan {
        Plan {
            schema: PLAN_SCHEMA.into(),
            epoch: 211,
            capability: EvidencePlan { path: "/capability".into(), sha256: "a".repeat(64) },
            restore: EvidencePlan { path: "/restore".into(), sha256: "b".repeat(64) },
            retained_input_audit: EvidencePlan { path: "/audit".into(), sha256: "c".repeat(64) },
            snapshot: "/snapshot".into(),
            output: "/home/ubuntu/.jetstreamer-private/campaign-state/epoch211-gcs-metadata-reobservation-20261016-v1.json".into(),
            remote_object: remote(),
            gcloud: GcloudPlan {
                executable: "/gcloud".into(),
                executable_sha256: "d".repeat(64),
                config_directory: "/config".into(),
                account: "account@example.com".into(),
                billing_project: "project".into(),
                sdk_version: "1".into(),
                core_version: "2".into(),
                run_uid: 1000,
                run_gid: 1000,
            },
        }
    }

    #[test]
    fn validates_exact_remote_identity() {
        validate_plan(&plan()).unwrap();
        let mut bad = plan();
        bad.remote_object.storage_url = "gs://bucket/other#456".into();
        assert!(validate_plan(&bad).is_err());
    }

    #[test]
    fn rejects_out_of_scope_epoch_and_output() {
        let mut bad = plan();
        bad.epoch = 213;
        assert!(validate_plan(&bad).is_err());
        let mut bad = plan();
        bad.epoch = 202;
        assert!(validate_plan(&bad).is_err());
        let mut bad = plan();
        bad.output = "/tmp/output.json".into();
        assert!(validate_plan(&bad).is_err());
        let mut bad = plan();
        bad.output =
            "/home/ubuntu/.jetstreamer-private/campaign-state/epoch211-gcs-metadata-reobservation-.json"
                .into();
        assert!(validate_plan(&bad).is_err());
        let mut bad = plan();
        bad.output =
            "/home/ubuntu/.jetstreamer-private/campaign-state/epoch211-gcs-metadata-reobservation-bad.name.json"
                .into();
        assert!(validate_plan(&bad).is_err());
    }

    #[test]
    fn accepts_epoch_203_and_unique_canonical_output() {
        let mut current = plan();
        current.epoch = 203;
        current.output =
            "/home/ubuntu/.jetstreamer-private/campaign-state/epoch203-gcs-metadata-reobservation-20261017T042500Z-v1.json"
                .into();
        validate_plan(&current).unwrap();
    }

    #[test]
    fn parses_strict_arguments() {
        let arguments = parse_arguments_from([
            "observer".into(),
            "--plan".into(),
            "/plan".into(),
            "--plan-sha256".into(),
            "a".repeat(64),
            "--self-sha256".into(),
            "b".repeat(64),
        ])
        .unwrap();
        assert_eq!(arguments.plan, PathBuf::from("/plan"));
        assert!(
            parse_arguments_from([
                "observer".into(),
                "--plan".into(),
                "/plan".into(),
                "--unknown".into(),
                "x".into(),
            ])
            .is_err()
        );
    }

    #[test]
    fn capability_requires_all_stop_gates() {
        let mut value = json!({
            "schema": CAPABILITY_SCHEMA,
            "epoch": 211,
            "plan": {"complete_epoch_span_covered": true},
            "probe": {"replay_started": false},
            "assessment": {
                "exact_node_complete_span_planner_capability_passed": true,
                "full_replay_authorized": false
            }
        });
        validate_capability(&value, 211).unwrap();
        value["assessment"]["full_replay_authorized"] = Value::Bool(true);
        assert!(validate_capability(&value, 211).is_err());
    }

    #[test]
    fn accepts_only_the_exact_legacy_epoch203_capability() {
        let mut value = json!({
            "schema": LEGACY_EPOCH203_CAPABILITY_SCHEMA,
            "probe": {
                "epoch": 203,
                "bootstrap_slot": 87_695_515_u64,
                "output_slot_start": 87_696_000_u64,
                "terminal_slot": 88_559_361_u64,
                "worker_spawned": false,
                "archive_created": false,
                "canonical_sidecar_created": false
            },
            "attestation": {
                "exact_node_tail_planner_capability_passed": true,
                "full_replay_authorized": false,
                "fresh_epoch203_specific_resource_admission_passed": false
            }
        });
        validate_capability(&value, 203).unwrap();
        assert!(validate_capability(&value, 204).is_err());
        value["probe"]["terminal_slot"] = Value::from(88_559_360_u64);
        assert!(validate_capability(&value, 203).is_err());
    }

    #[test]
    fn accepts_legacy_restore_file_identity_without_gid_or_link_count() {
        let directory = tempfile::tempdir().unwrap();
        let snapshot = directory.path().join("snapshot.tar.zst");
        fs::write(&snapshot, b"snapshot").unwrap();
        fs::set_permissions(&snapshot, fs::Permissions::from_mode(0o600)).unwrap();
        let metadata = fs::symlink_metadata(&snapshot).unwrap();
        let remote = RemoteObject {
            size: metadata.len(),
            ..remote()
        };
        let restore = json!({
            "schema": RESTORE_SCHEMA,
            "destination": snapshot,
            "versioned_uri": remote.storage_url,
            "generation": 456,
            "file": {
                "device": metadata.dev(),
                "inode": metadata.ino(),
                "size": metadata.len(),
                "mtime_ns": i128::from(metadata.mtime()) * 1_000_000_000
                    + i128::from(metadata.mtime_nsec()),
                "mode": 0o600,
                "uid": metadata.uid(),
                "crc32c_base64": remote.crc32c_hash,
                "md5_base64": remote.md5_hash,
            }
        });
        let (_, identity) = snapshot_identity_from_restore(&restore, &snapshot, &remote).unwrap();
        assert_eq!(identity.link_count, 1);
        assert_eq!(identity.gid, metadata.gid());
    }
}
