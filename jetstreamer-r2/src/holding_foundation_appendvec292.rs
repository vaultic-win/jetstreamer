//! Byte custody for the exact closed epoch 292 sparse AccountsDb bundle.
//! Archive publication and original-tree retirement have separate gates.
use super::*;
use horizon_singleton211_launch::foundation_holding_capacity as capacity;
#[path = "holding_foundation_appendvec292_ram.rs"]
mod ram;
#[path = "holding_foundation_appendvec292_tree.rs"]
mod tree;

const PARK: &str = "holding-foundation-292-appendvec-park";
const ADMIT: &str = "holding-foundation-292-appendvec-admit-restore";
const RESTORE: &str = "holding-foundation-292-appendvec-restore";
pub(super) const CHECK_TREE: &str = "holding-foundation-292-appendvec-check-tree";
const STAGING_UNIT: &str = "foundation-292-closed-appendvec-staging-v308.service";
const STAGING_INVOCATION: &str = "607061952a134ceca2ebf87f3838e3bc";
const STAGING_PID: &str = "1180521";
const STAGING_TERMINAL: &str =
    "/var/lib/jetstreamer/horizon292-closed-appendvec-staging-v308/staging-terminal.json";
const BUNDLE: &str = "/var/lib/jetstreamer/horizon292-closed-appendvec-staging-v308/bundle/epoch-292-closed-appendvecs.pax.zst";
const CAP: u64 = 68 << 30;
const TRUNCATED_SHA: &str = "0d18a622f286c936246e29ce0e5818bcf48e06295113c19c58267acbad030f04";
const FILES: u64 = 249_167;
const LOGICAL_BYTES: u64 = 463_145_631_744;
const PHYSICAL_BYTES: u64 = 432_056_471_552;
const STAGING_START_SHA: &str = "05f9ea6221c08de8991036312640271e4861e6a8010f0c8f8069b4cad90d1776";
const STAGING_INTENT_SHA: &str = "94c0a538a02ba4b59f6cc2202880c6e20797e01fa10282c6a0f3b3d9cb8c2381";
const ORIGINAL_FAILURE_SHA: &str =
    "242676ccd61cf7ea6d483a392d5955994cb545719c3dca91798b2a94871b75bb";
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

struct Body {
    length: u64,
    sha256: String,
}

impl Body {
    fn restore_bytes_remaining(&self) -> Result<u64> {
        restore_remaining(self.length, &self.sha256)?
            .checked_add(METADATA_RESERVE)
            .context("292 restore budget overflow")
    }
}

struct Custody<'a> {
    object: &'a str,
    etag: &'a str,
    manifest_key: &'a str,
    body: Body,
}

pub(super) fn command(action: &str) -> bool {
    matches!(action, PARK | ADMIT | RESTORE | CHECK_TREE | ram::ACTION)
}

pub(super) fn check_tree(value: Value, spec: &Bound) -> Result<()> {
    tree::run(value, spec)
}

fn validate_terminal(stage: &Value) -> Result<Body> {
    let manager = &stage["manager_terminal"];
    let length = stage["length"]
        .as_u64()
        .context("missing 292 completed bundle length")?;
    let sha256 = stage["sha256"]
        .as_str()
        .context("missing 292 completed bundle SHA-256")?;
    let events = stage["stage_events"]
        .as_array()
        .context("missing 292 completed staging events")?;
    let expected_events = [
        format!("compressed_bytes={length} sha256={sha256} stable_metadata=true"),
        format!("verified local closed epoch 292 bundle {BUNDLE}"),
    ];
    ensure!(
        stage["schema"] == "foundation-epoch292-closed-appendvec-restage-terminal-v1"
            && stage["epoch"] == 292
            && stage["staging_start_sha256"] == STAGING_START_SHA
            && stage["staging_intent_sha256"] == STAGING_INTENT_SHA
            && stage["original_stage_failure_sha256"] == ORIGINAL_FAILURE_SHA
            && stage["path"] == BUNDLE
            && 0 < length
            && length < CAP
            && digest(sha256)
            && sha256 != TRUNCATED_SHA
            && sha256.bytes().any(|b| b != b'0')
            && stage["stable_source_metadata"] == true
            && stage["local_retirement_authorized"] == false
            && manager["_PID"] == "1"
            && manager["UNIT"] == STAGING_UNIT
            && manager["INVOCATION_ID"] == STAGING_INVOCATION
            && manager["MESSAGE"] == format!("{STAGING_UNIT}: Deactivated successfully.")
            && events.len() == expected_events.len()
            && events.iter().zip(expected_events).all(|(event, message)| {
                event["_PID"] == STAGING_PID
                    && event["_SYSTEMD_INVOCATION_ID"] == STAGING_INVOCATION
                    && event["MESSAGE"] == message
            }),
        "292 bundle has no exact successful staging invocation"
    );
    Ok(Body {
        length,
        sha256: sha256.to_owned(),
    })
}

fn staged_body(binding: &Bound) -> Result<Body> {
    ensure!(
        binding.path == Path::new(STAGING_TERMINAL),
        "foreign 292 staging terminal path"
    );
    validate_terminal(&saved(binding)?)
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

fn closed_source(length: u64) -> Result<FileIdentity> {
    let path = Path::new(BUNDLE);
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && metadata.is_file()
            && metadata.len() == length
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
    let body = staged_body(&plan.staging_terminal)?;
    let metadata = saved(&plan.restore_metadata)?;
    validate_metadata(&metadata)?;
    let identity = closed_source(body.length)?;
    let before = no_references(Path::new(BUNDLE))?;
    let proof = hash_and_etag(Path::new(BUNDLE), identity, DEFAULT_PART_SIZE)?;
    ensure!(
        proof.sha256_hex == body.sha256,
        "292 sealed bundle digest differs"
    );
    let key = key(&body.sha256)?;
    let manifest = json!({"schema":"foundation-epoch292-appendvec-manifest-v1","host":host::HOST,
        "prefix":SUBPREFIX,"epoch":292,"format":"gnu-sparse-pax-zstd","length":body.length,
        "sha256":body.sha256,"object_key":key,"restore_metadata":metadata,
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
        length: body.length,
        sha256: body.sha256.clone(),
    };
    let remote = verified_blob(client, &key, &transport, identity, &proof).await?;
    ensure!(
        closed_source(body.length)? == identity,
        "292 bundle changed during custody"
    );
    let after = no_references(Path::new(BUNDLE))?;
    ensure!(
        hash_and_etag(Path::new(BUNDLE), identity, DEFAULT_PART_SIZE)?.sha256_hex == body.sha256,
        "292 bundle changed after R2 readback"
    );
    small_create(client, &manifest_key, &manifest_bytes).await?;
    let final_remote = head_archive(client, BUCKET, &key)
        .await?
        .context("292 holding object disappeared")?;
    remote_matches(
        &final_remote,
        &key,
        body.length,
        &body.sha256,
        Some(&remote.etag),
    )?;
    native_checksum(&final_remote, &proof, body.length)?;
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

fn validate_custody(custody: &Value) -> Result<Custody<'_>> {
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
    let stage: Bound = serde_json::from_value(manifest["staging_terminal"].clone())?;
    let body = staged_body(&stage)?;
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
            && object == key(&body.sha256)?
            && custody["manifest_sha256"] == manifest_sha
            && remote_manifest == manifest_key(&manifest_sha)?
            && manifest["schema"] == "foundation-epoch292-appendvec-manifest-v1"
            && manifest["host"] == host::HOST
            && manifest["prefix"] == SUBPREFIX
            && manifest["epoch"] == 292
            && manifest["sha256"] == body.sha256
            && manifest["length"] == body.length
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
    Ok(Custody {
        object,
        etag,
        manifest_key: remote_manifest,
        body,
    })
}

fn admit(plan: RestoreAdmissionPlan, spec: &Bound) -> Result<()> {
    ensure!(
        plan.schema == "foundation-epoch292-appendvec-admit-restore-v1",
        "foreign 292 restore admission plan"
    );
    mapping(&plan.mapping)?;
    let receipt_value = saved(&plan.custody)?;
    let custody = validate_custody(&receipt_value)?;
    let reservation = capacity::check(
        &plan.resource_basis,
        custody.body.restore_bytes_remaining()?,
    )?;
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
    receipt: &Value,
    custody: &Custody<'_>,
) -> Result<RemoteArchive> {
    let owner = get_mutable_object(client, BUCKET, &format!("{}owner.json", host::PREFIX))
        .await?
        .context("Foundation holding owner absent")?;
    ensure!(
        owner.bytes == owner_bytes()?,
        "foreign Foundation holding owner"
    );
    let remote_manifest = get_mutable_object(client, BUCKET, custody.manifest_key)
        .await?
        .context("292 remote manifest absent")?;
    ensure!(
        remote_manifest.bytes == serde_json::to_vec(&receipt["manifest"])?,
        "292 remote manifest differs"
    );
    let remote = head_archive(client, BUCKET, custody.object)
        .await?
        .context("292 remote bundle absent")?;
    remote_matches(
        &remote,
        custody.object,
        custody.body.length,
        &custody.body.sha256,
        Some(custody.etag),
    )?;
    Ok(remote)
}

async fn restore(client: &Client, plan: RestoreSpec, spec: &Bound) -> Result<()> {
    ensure!(
        plan.schema == "foundation-epoch292-appendvec-restore-v1",
        "foreign 292 restore plan"
    );
    let receipt_value = saved(&plan.custody)?;
    let custody = validate_custody(&receipt_value)?;
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
        custody.body.restore_bytes_remaining()?,
        floor,
    )?;
    let check = |force| -> Result<()> {
        if let Some(lease) = &lease {
            lease.renew(force, || custody.body.restore_bytes_remaining())?;
        } else if force {
            let current = capacity::check(basis, custody.body.restore_bytes_remaining()?)?;
            ensure!(
                current["minimum_free_bytes"]
                    .as_u64()
                    .is_some_and(|value| value <= floor),
                "292 restore safety floor increased"
            );
        }
        Ok(())
    };
    check_remote(client, &receipt_value, &custody).await?;
    let directory = Path::new(STATE).join("restores");
    let restored = restore_blob_guarded(
        client,
        BlobRestore {
            key: custody.object,
            etag: custody.etag,
            sha: &custody.body.sha256,
            length: custody.body.length,
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
        proof.sha256_hex == custody.body.sha256,
        "restored 292 compressed bytes differ"
    );
    let remote = check_remote(client, &receipt_value, &custody).await?;
    native_checksum(&remote, &proof, custody.body.length)?;
    check(true)?;
    let output = receipt(
        &format!("appendvec292-restored-{}.json", spec.sha256),
        &json!({
            "schema":"foundation-epoch292-appendvec-byte-restoration-v1","destination":restored,
            "custody":plan.custody,"admission":plan.admission,"spec":spec,
            "object_key":custody.object,"object_etag":custody.etag,"length":custody.body.length,"sha256":custody.body.sha256,
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
        ram::ACTION => ram::restore_and_compare(&client, value, spec).await,
        _ => bail!("unknown 292 holding action"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appendvec292_rejects_foreign_invocation_and_body() {
        let length = CAP - 1024;
        let sha256 = "a".repeat(64);
        let stage = json!({
            "schema": "foundation-epoch292-closed-appendvec-restage-terminal-v1",
            "epoch": 292,
            "staging_start_sha256": STAGING_START_SHA,
            "staging_intent_sha256": STAGING_INTENT_SHA,
            "original_stage_failure_sha256": ORIGINAL_FAILURE_SHA,
            "path": BUNDLE,
            "length": length,
            "sha256": sha256,
            "stable_source_metadata": true,
            "local_retirement_authorized": false,
            "manager_terminal": {
                "_PID": "1", "UNIT": STAGING_UNIT, "INVOCATION_ID": STAGING_INVOCATION,
                "MESSAGE": format!("{STAGING_UNIT}: Deactivated successfully.")
            },
            "stage_events": [
                {
                    "_PID": STAGING_PID, "_SYSTEMD_INVOCATION_ID": STAGING_INVOCATION,
                    "MESSAGE": format!("compressed_bytes={length} sha256={sha256} stable_metadata=true")
                },
                {
                    "_PID": STAGING_PID, "_SYSTEMD_INVOCATION_ID": STAGING_INVOCATION,
                    "MESSAGE": format!("verified local closed epoch 292 bundle {BUNDLE}")
                }
            ]
        });
        let body = validate_terminal(&stage).unwrap();
        assert_eq!(body.length, length);
        assert_eq!(body.sha256, sha256);
        for (label, value) in [
            ("sha256", json!("b".repeat(64))),
            ("length", json!(length - 1)),
            ("staging_intent_sha256", json!("foreign")),
            ("stage_events", json!([stage["stage_events"][0]])),
            ("local_retirement_authorized", json!(true)),
        ] {
            let mut altered = stage.clone();
            altered[label] = value;
            assert!(validate_terminal(&altered).is_err(), "{label}");
        }
        let mut altered = stage.clone();
        altered["sha256"] = json!(TRUNCATED_SHA);
        altered["stage_events"][0]["MESSAGE"] = json!(format!(
            "compressed_bytes={length} sha256={TRUNCATED_SHA} stable_metadata=true"
        ));
        assert!(validate_terminal(&altered).is_err());
        let mut altered = stage.clone();
        altered["stage_events"][0]["_SYSTEMD_INVOCATION_ID"] = json!("foreign");
        assert!(validate_terminal(&altered).is_err());
        let mut altered = stage;
        altered["manager_terminal"]["INVOCATION_ID"] = json!("foreign");
        assert!(validate_terminal(&altered).is_err());
    }
}
