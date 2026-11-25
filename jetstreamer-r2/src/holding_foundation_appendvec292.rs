//! Byte custody for the exact closed epoch 292 sparse AccountsDb bundle.
//! Archive publication and original-tree retirement have separate gates.
use super::*;
use horizon_singleton211_launch::foundation_holding_capacity as capacity;
#[path = "holding_foundation_appendvec292_tree.rs"]
mod tree;

const PARK: &str = "holding-foundation-292-appendvec-park";
const ADMIT: &str = "holding-foundation-292-appendvec-admit-restore";
const RESTORE: &str = "holding-foundation-292-appendvec-restore";
pub(super) const CHECK_TREE: &str = "holding-foundation-292-appendvec-check-tree";
const STAGING_UNIT: &str = "foundation-292-closed-appendvec-staging-v304.service";
const STAGING_INVOCATION: &str = "6979fb77543c406d9f016656303e86cc";
const BUNDLE: &str = "/var/lib/jetstreamer/horizon292-closed-appendvec-staging-v304/bundle/epoch-292-closed-appendvecs.pax.zst";
const SHA: &str = "9cb709a85c40aa2f9b0fc0892eea320eecce120c90e5f2f005235d5132b91477";
const BYTES: u64 = 67_427_276_780;
const FILES: u64 = 249_167;
const LOGICAL_BYTES: u64 = 463_145_631_744;
const PHYSICAL_BYTES: u64 = 432_056_471_552;
const STAGING_START_SHA: &str = "eddcd58162706f2445d3fb20717cd180b32279ff1fe5894e6f8608fb2ab3cb4c";
const RESTORE_METADATA_SHA: &str =
    "3816233ef8a5e99b60b3618c9e4b211f5bfe7e0bc22ff6086b2552ff16e2563b";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParkPlan {
    schema: String,
    mapping: Bound,
    staging_terminal: Bound,
    restore_metadata: Bound,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreAdmissionPlan {
    schema: String,
    mapping: Bound,
    custody: Bound,
    resource_basis: Value,
}

pub(super) fn command(action: &str) -> bool {
    matches!(action, PARK | ADMIT | RESTORE | CHECK_TREE)
}

pub(super) fn check_tree(value: Value, spec: &Bound) -> Result<()> {
    tree::run(value, spec)
}

fn validate_terminal(stage: &Value) -> Result<()> {
    let manager = &stage["manager_terminal"];
    ensure!(
        stage["schema"] == "foundation-epoch292-closed-appendvec-stage-terminal-v1"
            && stage["epoch"] == 292
            && stage["staging_start_sha256"] == STAGING_START_SHA
            && stage["path"] == BUNDLE
            && stage["length"] == BYTES
            && stage["sha256"] == SHA
            && stage["stable_source_metadata"] == true
            && stage["local_retirement_authorized"] == false
            && manager["_PID"] == "1"
            && manager["UNIT"] == STAGING_UNIT
            && manager["INVOCATION_ID"] == STAGING_INVOCATION
            && manager["MESSAGE"] == format!("{STAGING_UNIT}: Deactivated successfully."),
        "292 bundle has no exact successful staging invocation"
    );
    Ok(())
}

fn validate_metadata(metadata: &Value) -> Result<()> {
    ensure!(
        metadata["schema"] == "foundation-epoch292-appendvec-restore-metadata-v1"
            && metadata["epoch"] == 292
            && metadata["regular_members"] == FILES
            && metadata["logical_bytes"] == LOGICAL_BYTES
            && metadata["allocated_bytes"] == PHYSICAL_BYTES
            && metadata["extended_attribute_count"] == 0
            && metadata["local_retirement_authorized"] == false,
        "foreign sparse-tree restore metadata"
    );
    Ok(())
}

fn closed_source() -> Result<FileIdentity> {
    let path = Path::new(BUNDLE);
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && metadata.is_file()
            && metadata.len() == BYTES
            && metadata.mode() & 0o7777 == 0o400
            && metadata.uid() == 1000
            && metadata.gid() == 1000
            && metadata.nlink() == 1,
        "292 staging bundle identity or permissions differ"
    );
    let result = std::process::Command::new("systemctl")
        .args([
            "show",
            STAGING_UNIT,
            "-p",
            "ActiveState",
            "-p",
            "MainPID",
            "-p",
            "ControlGroup",
        ])
        .output()?;
    let state = std::str::from_utf8(&result.stdout)?;
    ensure!(
        result.status.success()
            && ["ActiveState=inactive", "MainPID=0", "ControlGroup="]
                .iter()
                .all(|field| state.lines().any(|line| line == *field))
            && !Path::new("/sys/fs/cgroup/system.slice")
                .join(STAGING_UNIT)
                .exists(),
        "292 staging producer must be closed"
    );
    regular_identity(path)
}

async fn park(client: &Client, plan: ParkPlan, spec: &Bound) -> Result<()> {
    ensure!(
        plan.schema == "foundation-epoch292-appendvec-park-v1"
            && plan.restore_metadata.sha256 == RESTORE_METADATA_SHA,
        "foreign 292 bundle custody scope"
    );
    validate_terminal(&saved(&plan.staging_terminal)?)?;
    let metadata = saved(&plan.restore_metadata)?;
    validate_metadata(&metadata)?;
    let identity = closed_source()?;
    let before = no_references(Path::new(BUNDLE))?;
    let proof = hash_and_etag(Path::new(BUNDLE), identity, DEFAULT_PART_SIZE)?;
    ensure!(proof.sha256_hex == SHA, "292 sealed bundle digest differs");
    let key = key(SHA)?;
    let manifest = json!({"schema":"foundation-epoch292-appendvec-manifest-v1","host":host::HOST,
        "prefix":SUBPREFIX,"epoch":292,"format":"gnu-sparse-pax-zstd","length":BYTES,
        "sha256":SHA,"object_key":key,"restore_metadata":metadata,
        "restore_metadata_evidence":plan.restore_metadata,"staging_terminal":plan.staging_terminal,
        "canonical_archive":false,"publication_authorized":false,"local_retirement_authorized":false});
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let manifest_sha = hex_lower(&Sha256::digest(&manifest_bytes));
    let manifest_key = manifest_key(&manifest_sha)?;
    claim_owner(client, host::PREFIX, &owner_bytes()?).await?;
    let transport = Park {
        schema: "transport-only".into(),
        mapping: plan.mapping,
        eligibility: spec.clone(),
        source: BUNDLE.into(),
        length: BYTES,
        sha256: SHA.into(),
    };
    let remote = verified_blob(client, &key, &transport, identity, &proof).await?;
    ensure!(
        closed_source()? == identity,
        "292 bundle changed during custody"
    );
    let after = no_references(Path::new(BUNDLE))?;
    ensure!(
        hash_and_etag(Path::new(BUNDLE), identity, DEFAULT_PART_SIZE)?.sha256_hex == SHA,
        "292 bundle changed after R2 readback"
    );
    small_create(client, &manifest_key, &manifest_bytes).await?;
    let final_remote = head_archive(client, BUCKET, &key)
        .await?
        .context("292 holding object disappeared")?;
    remote_matches(&final_remote, &key, BYTES, SHA, Some(&remote.etag))?;
    native_checksum(&final_remote, &proof, BYTES)?;
    let output = receipt(
        &format!("appendvec292-custody-{}.json", spec.sha256),
        &json!({
            "schema":"foundation-epoch292-appendvec-custody-v1","host":host::HOST,"bucket":BUCKET,
            "prefix":SUBPREFIX,"epoch":292,"object_key":key,"object_etag":remote.etag,
            "manifest_key":manifest_key,"manifest_sha256":manifest_sha,"manifest":manifest,
            "park_spec":spec,"remote_sha256_readback":true,"local_source_revalidated":true,
            "reference_census_before":before,"reference_census_after":after,
            "publication_authorized":false,"local_retirement_authorized":false
        }),
    )?;
    println!("{}", output.display());
    Ok(())
}

fn validate_custody(custody: &Value) -> Result<(&str, &str, &str)> {
    let manifest = &custody["manifest"];
    let object = custody["object_key"].as_str().context("292 object key")?;
    let etag = custody["object_etag"]
        .as_str()
        .filter(|s| !s.is_empty())
        .context("292 ETag")?;
    let remote_manifest = custody["manifest_key"]
        .as_str()
        .context("292 manifest key")?;
    let manifest_sha = hex_lower(&Sha256::digest(serde_json::to_vec(manifest)?));
    ensure!(
        custody["schema"] == "foundation-epoch292-appendvec-custody-v1"
            && custody["host"] == host::HOST
            && custody["bucket"] == BUCKET
            && custody["prefix"] == SUBPREFIX
            && custody["epoch"] == 292
            && custody["remote_sha256_readback"] == true
            && custody["local_source_revalidated"] == true
            && custody["local_retirement_authorized"] == false
            && custody["publication_authorized"] == false
            && object == key(SHA)?
            && custody["manifest_sha256"] == manifest_sha
            && remote_manifest == manifest_key(&manifest_sha)?
            && manifest["schema"] == "foundation-epoch292-appendvec-manifest-v1"
            && manifest["host"] == host::HOST
            && manifest["prefix"] == SUBPREFIX
            && manifest["epoch"] == 292
            && manifest["sha256"] == SHA
            && manifest["length"] == BYTES
            && manifest["object_key"] == object
            && manifest["format"] == "gnu-sparse-pax-zstd"
            && manifest["restore_metadata_evidence"]["sha256"] == RESTORE_METADATA_SHA
            && manifest["canonical_archive"] == false
            && manifest["publication_authorized"] == false
            && manifest["local_retirement_authorized"] == false,
        "foreign or unverified 292 custody"
    );
    validate_metadata(&manifest["restore_metadata"])?;
    let metadata: Bound = serde_json::from_value(manifest["restore_metadata_evidence"].clone())?;
    ensure!(
        saved(&metadata)? == manifest["restore_metadata"],
        "292 restore metadata changed"
    );
    Ok((object, etag, remote_manifest))
}

fn restore_bytes_remaining() -> Result<u64> {
    restore_remaining(BYTES, SHA)?
        .checked_add(METADATA_RESERVE)
        .context("292 restore budget overflow")
}

fn admit(plan: RestoreAdmissionPlan, spec: &Bound) -> Result<()> {
    ensure!(
        plan.schema == "foundation-epoch292-appendvec-admit-restore-v1",
        "foreign 292 restore admission plan"
    );
    mapping(&plan.mapping)?;
    validate_custody(&saved(&plan.custody)?)?;
    let reservation = capacity::check(&plan.resource_basis, restore_bytes_remaining()?)?;
    let output = receipt(
        &format!("appendvec292-restore-admission-{}.json", spec.sha256),
        &json!({
            "schema":"foundation-epoch292-appendvec-restore-admission-v1","custody":plan.custody,
            "resource_basis":plan.resource_basis,"capacity":reservation,"recorded_unix_seconds":clock()?,
            "restore_only":true,"local_retirement_authorized":false
        }),
    )?;
    println!("{}", output.display());
    Ok(())
}

async fn check_remote(
    client: &Client,
    custody: &Value,
    object: &str,
    etag: &str,
    manifest: &str,
) -> Result<RemoteArchive> {
    let owner = get_mutable_object(client, BUCKET, &format!("{}owner.json", host::PREFIX))
        .await?
        .context("Foundation holding owner absent")?;
    ensure!(
        owner.bytes == owner_bytes()?,
        "foreign Foundation holding owner"
    );
    let remote_manifest = get_mutable_object(client, BUCKET, manifest)
        .await?
        .context("292 remote manifest absent")?;
    ensure!(
        remote_manifest.bytes == serde_json::to_vec(&custody["manifest"])?,
        "292 remote manifest differs"
    );
    let remote = head_archive(client, BUCKET, object)
        .await?
        .context("292 remote bundle absent")?;
    remote_matches(&remote, object, BYTES, SHA, Some(etag))?;
    Ok(remote)
}

async fn restore(client: &Client, plan: RestoreSpec, spec: &Bound) -> Result<()> {
    ensure!(
        plan.schema == "foundation-epoch292-appendvec-restore-v1",
        "foreign 292 restore plan"
    );
    let custody = saved(&plan.custody)?;
    let (object, etag, manifest) = validate_custody(&custody)?;
    let admission = saved(&plan.admission)?;
    let age = clock()?.checked_sub(
        admission["recorded_unix_seconds"]
            .as_u64()
            .context("292 restore admission time")?,
    );
    ensure!(
        admission["schema"] == "foundation-epoch292-appendvec-restore-admission-v1"
            && admission["custody"] == serde_json::to_value(&plan.custody)?
            && admission["restore_only"] == true
            && admission["local_retirement_authorized"] == false
            && age.is_some_and(|seconds| seconds <= 900),
        "stale or unrelated 292 restore admission"
    );
    let floor = admission["capacity"]["minimum_free_bytes"]
        .as_u64()
        .context("292 restore capacity floor")?;
    let transport_floor = floor
        .checked_add(METADATA_RESERVE)
        .context("292 restore metadata floor overflow")?;
    let basis = &admission["resource_basis"];
    let lease = capacity::RestoreLease::start(
        basis,
        &serde_json::to_value(&plan.custody)?,
        restore_bytes_remaining()?,
        floor,
    )?;
    let check = |force| -> Result<()> {
        if let Some(lease) = &lease {
            lease.renew(force, restore_bytes_remaining)?;
        } else if force {
            let current = capacity::check(basis, restore_bytes_remaining()?)?;
            ensure!(
                current["minimum_free_bytes"]
                    .as_u64()
                    .is_some_and(|value| value <= floor),
                "292 restore safety floor increased"
            );
        }
        Ok(())
    };
    check_remote(client, &custody, object, etag, manifest).await?;
    let directory = Path::new(STATE).join("restores");
    let restored = restore_blob_guarded(
        client,
        BlobRestore {
            key: object,
            etag,
            sha: SHA,
            length: BYTES,
            directory: &directory,
            minimum: transport_floor,
        },
        || check(false),
        || check(true),
    )
    .await?;
    let proof = hash_and_etag_checked(
        &restored,
        regular_identity(&restored)?,
        DEFAULT_PART_SIZE,
        |_| check(false),
    )?;
    ensure!(
        proof.sha256_hex == SHA,
        "restored 292 compressed bytes differ"
    );
    let remote = check_remote(client, &custody, object, etag, manifest).await?;
    native_checksum(&remote, &proof, BYTES)?;
    check(true)?;
    let output = receipt(
        &format!("appendvec292-restored-{}.json", spec.sha256),
        &json!({
            "schema":"foundation-epoch292-appendvec-byte-restoration-v1","destination":restored,
            "custody":plan.custody,"admission":plan.admission,"spec":spec,
            "object_key":object,"object_etag":etag,"length":BYTES,"sha256":SHA,
            "remote_sha256_readback":true,"compressed_bundle_restored":true,
            "complete_tree_restore_verified":false,"publication_authorized":false,"local_retirement_authorized":false
        }),
    )?;
    println!("{}", output.display());
    Ok(())
}

pub(super) async fn run(action: &str, value: Value, spec: &Bound) -> Result<()> {
    if action == ADMIT {
        return admit(serde_json::from_value(value)?, spec);
    }
    let r2 = r2_config_from_env()?;
    ensure!(r2.bucket == BUCKET, "foreign 292 holding bucket");
    let client = s3_client(&r2);
    match action {
        PARK => park(&client, serde_json::from_value(value)?, spec).await,
        RESTORE => restore(&client, serde_json::from_value(value)?, spec).await,
        _ => bail!("unknown 292 holding action"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appendvec292_rejects_foreign_invocation_and_body() {
        let stage = json!({"schema":"foundation-epoch292-closed-appendvec-stage-terminal-v1",
            "epoch":292,"staging_start_sha256":STAGING_START_SHA,"path":BUNDLE,"length":BYTES,"sha256":SHA,
            "stable_source_metadata":true,"local_retirement_authorized":false,
            "manager_terminal":{"_PID":"1","UNIT":STAGING_UNIT,"INVOCATION_ID":STAGING_INVOCATION,
                "MESSAGE":format!("{STAGING_UNIT}: Deactivated successfully.")}});
        validate_terminal(&stage).unwrap();
        for (label, value) in [
            ("sha256", json!("foreign")),
            ("length", json!(BYTES - 1)),
            ("local_retirement_authorized", json!(true)),
        ] {
            let mut altered = stage.clone();
            altered[label] = value;
            assert!(validate_terminal(&altered).is_err(), "{label}");
        }
        let mut altered = stage;
        altered["manager_terminal"]["INVOCATION_ID"] = json!("foreign");
        assert!(validate_terminal(&altered).is_err());
    }
}
