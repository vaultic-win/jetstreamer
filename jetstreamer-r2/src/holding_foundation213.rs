//! Exact Foundation custody/byte restoration, never local retirement or resume.
use super::*;
use jetstreamer_horizon_observe::foundation_holding213_review as review;
use std::os::fd::AsRawFd;

const STATE: &str = "/home/ubuntu/.jetstreamer-private/r2-holding-foundation-node-01-v1";
const PROBE: &str =
    "/var/lib/jetstreamer/horizon-foundation-holding-probe-input-v1/genesis.tar.bz2";
const PROBE_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const METADATA_RESERVE: u64 = 16 * 1024 * 1024;
const MAX_RECEIPT_BYTES: usize = 8 * 1024 * 1024;
const MAX_ADDITIONAL: u64 = review::LENGTH + 2 * METADATA_RESERVE;

#[derive(Clone, Copy, Deserialize, Serialize, Debug, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum Artifact {
    GenesisProbe,
    Prefix213,
}
impl Artifact {
    fn source(self) -> &'static Path {
        Path::new(match self {
            Self::GenesisProbe => PROBE,
            Self::Prefix213 => review::SOURCE,
        })
    }
    fn sha(self) -> &'static str {
        match self {
            Self::GenesisProbe => PROBE_SHA,
            Self::Prefix213 => review::SOURCE_SHA,
        }
    }
    fn length(self) -> u64 {
        match self {
            Self::GenesisProbe => 20144,
            Self::Prefix213 => review::LENGTH,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParkSpec {
    schema: String,
    mapping: Bound,
    artifact: Artifact,
    accepted_fleet: Option<Bound>,
    transport_qualification: Option<Bound>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmitSpec {
    schema: String,
    mapping: Bound,
    custody: Bound,
    resource_basis: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreSpec {
    schema: String,
    mapping: Bound,
    custody: Bound,
    admission: Bound,
}
fn mapping_binding(b: &Bound) -> Result<()> {
    ensure!(
        b.path == Path::new(review::MAPPING) && b.sha256 == review::MAPPING_SHA,
        "foreign Foundation mapping binding"
    );
    review::validate_host_mapping()
}
pub(super) fn command(s: &str) -> bool {
    matches!(
        s,
        "holding-foundation213-park"
            | "holding-foundation213-admit-restore"
            | "holding-foundation213-restore"
    )
}
fn key(sha: &str) -> Result<String> {
    ensure!(
        sha == review::SOURCE_SHA || sha == PROBE_SHA,
        "unregistered Foundation artifact"
    );
    Ok(format!("{}objects/{sha}.blob", review::PREFIX))
}
fn owner() -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(
        &json!({"schema":"jetstreamer-horizon-holding-owner-v2","host":review::HOST,"prefix":review::PREFIX}),
    )?)
}
fn clock() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn durable_receipt(path: &Path, value: &Value) -> Result<()> {
    let serialized = serialized_receipt_length(value)?;
    eprintln!(
        "Foundation receipt serialized_bytes={serialized} maximum_receipt_bytes={MAX_RECEIPT_BYTES} metadata_reserve_per_phase_bytes={METADATA_RESERVE}"
    );
    persist_with_limit(path, value, MAX_RECEIPT_BYTES as u64)?;
    // The shared no-clobber helper syncs bytes before publishing. Complete
    // this adapter's durability contract after its final chmod and rename.
    fs::File::open(path)?.sync_all()?;
    fs::File::open(path.parent().context("Foundation receipt parent")?)?.sync_all()?;
    Ok(())
}
fn serialized_receipt_length(value: &Value) -> Result<u64> {
    let length = serde_json::to_vec_pretty(value)?
        .len()
        .checked_add(1)
        .context("Foundation receipt size overflow")?;
    ensure!(
        length <= MAX_RECEIPT_BYTES,
        "Foundation receipt serialized bytes {length} exceed its reserved maximum {MAX_RECEIPT_BYTES}"
    );
    Ok(length as u64)
}
fn receipt_bound(b: &Bound) -> Result<Value> {
    evidence_with_limit(b, true, MAX_RECEIPT_BYTES as u64)
}
fn metadata_budget() -> Value {
    json!({"per_phase_reservation_bytes":METADATA_RESERVE,"total_reservation_bytes":2*METADATA_RESERVE,
        "maximum_receipt_bytes":MAX_RECEIPT_BYTES,"full_before_after_censuses_preserved":true})
}
fn source_identity(a: Artifact) -> Result<FileIdentity> {
    let path = a.source();
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "aliased Foundation source"
    );
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.len() == a.length(),
        "Foundation source identity differs"
    );
    match a {
        Artifact::GenesisProbe => ensure!(
            m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o444,
            "probe must be an immutable dedicated public-genesis copy"
        ),
        Artifact::Prefix213 => ensure!(
            m.uid() == 1000
                && m.gid() == 1000
                && m.mode() & 0o7777 == 0o600
                && m.dev() == 66305
                && m.ino() == 18063496
                && m.mtime() == 1791629969
                && m.ctime() == 1791629969,
            "old213 prefix must match its original preserved identity"
        ),
    }
    regular_identity(path)
}
fn no_authority(v: &Value) -> Result<()> {
    for field in [
        "local_retirement_authorized",
        "canonical_publication_authorized",
        "runtime_checkpoint_qualified",
        "job_resume_authorized",
        "replay_launch_authorized",
    ] {
        ensure!(
            v[field] == false,
            "Foundation custody grants forbidden authority:{field}"
        );
    }
    Ok(())
}
fn qualification(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-foundation-holding-restore-v1"
            && v["host"] == review::HOST
            && v["prefix"] == review::PREFIX
            && v["artifact"] == "genesis-probe"
            && v["sha256"] == PROBE_SHA
            && v["length"] == 20144
            && v["restoration_complete"] == true
            && v["remote_sha256_readback"] == true
            && v["owner_checked"] == true
            && v["staging_only"] == true
            && v["object_key"] == key(PROBE_SHA)?
            && v["mapping"] == json!({"path":review::MAPPING,"sha256":review::MAPPING_SHA}),
        "exact Foundation public-genesis park/readback/restore qualification required first"
    );
    no_authority(v)
}
fn review_for_park(p: &ParkSpec) -> Result<Value> {
    match p.artifact {
        Artifact::GenesisProbe => {
            ensure!(
                p.accepted_fleet.is_none() && p.transport_qualification.is_none(),
                "probe cannot borrow prefix qualification metadata"
            );
            let refs = no_references(p.artifact.source())?;
            Ok(
                json!({"profile":"public-genesis-transport-probe","reference_census":refs,"closed_reference_census_passed":true}),
            )
        }
        Artifact::Prefix213 => {
            let q = p
                .transport_qualification
                .as_ref()
                .context("Foundation transport not qualified")?;
            qualification(&receipt_bound(q)?)?;
            let f = p
                .accepted_fleet
                .as_ref()
                .context("Foundation prefix requires the accepted ready213 fleet")?;
            let r = review::inspect(&f.path, &f.sha256, false)?;
            ensure!(
                r["closed_reference_census_passed"] == true
                    && r["staged_references_cleared"] == true
                    && r["lineage_and_remote_ready_evidence_validated"] == true
                    && r["eligible_for_local_retirement"] == false,
                "Foundation old213 prefix has live/new-staged references or invalid lineage"
            );
            Ok(r)
        }
    }
}
fn manifest(a: Artifact, metadata: &fs::Metadata) -> Result<Vec<u8>> {
    let mut v = json!({"schema":"jetstreamer-foundation-holding-manifest-v1","host":review::HOST,"prefix":review::PREFIX,
        "artifact":a,"object_key":key(a.sha())?,"length":a.length(),"sha256":a.sha(),
        "name":a.source().file_name().unwrap().to_str().context("artifact filename")?,
        "uid":metadata.uid(),"gid":metadata.gid(),"mode":metadata.mode()&0o7777,
        "canonical_archive":false,"canonical_publication_authorized":false,"restore_before_historical_consumer_reuse":true});
    if a == Artifact::Prefix213 {
        let bytes = review::segment_bytes()?;
        v["segment"] = json!({"name":"epoch-213-through-92447542.jet.segment.json","sha256":review::SEGMENT_SHA,
            "length":bytes.len(),"raw_base64":BASE64_STANDARD.encode(bytes),"uid":0,"gid":0,"mode":0o600});
        v["completed_continuation_restore_dependency"] =
            json!({"path":review::CONTINUATION,"sha256":review::CONTINUATION_SHA});
    }
    Ok(serde_json::to_vec(&v)?)
}
fn artifact_manifest(v: &Value, a: Artifact) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-foundation-holding-manifest-v1"
            && v["host"] == review::HOST
            && v["prefix"] == review::PREFIX
            && v["artifact"] == serde_json::to_value(a)?
            && v["object_key"] == key(a.sha())?
            && v["length"] == a.length()
            && v["sha256"] == a.sha()
            && v["name"].as_str() == a.source().file_name().and_then(|n| n.to_str())
            && v["canonical_archive"] == false
            && v["canonical_publication_authorized"] == false
            && v["restore_before_historical_consumer_reuse"] == true,
        "foreign/malformed Foundation manifest"
    );
    if a == Artifact::Prefix213 {
        let seg = &v["segment"];
        let raw =
            BASE64_STANDARD.decode(seg["raw_base64"].as_str().context("raw segment missing")?)?;
        ensure!(
            seg["name"] == "epoch-213-through-92447542.jet.segment.json"
                && seg["sha256"] == review::SEGMENT_SHA
                && seg["length"] == 1809
                && raw.len() == 1809
                && hex_lower(&Sha256::digest(&raw)) == review::SEGMENT_SHA
                && seg["uid"] == 0
                && seg["gid"] == 0
                && seg["mode"] == 0o600
                && v["completed_continuation_restore_dependency"]
                    == json!({"path":review::CONTINUATION,"sha256":review::CONTINUATION_SHA}),
            "raw original prefix segment not preserved exactly"
        );
        ensure!(
            v["uid"] == 1000 && v["gid"] == 1000 && v["mode"] == 0o600,
            "old213 original permission metadata differs"
        );
    } else {
        ensure!(
            v.get("segment").is_none()
                && v.get("completed_continuation_restore_dependency").is_none()
                && v["uid"] == 0
                && v["gid"] == 0
                && v["mode"] == 0o444,
            "probe cannot carry a prefix/foreign restoration set"
        );
    }
    Ok(())
}
fn custody(c: &Value) -> Result<Artifact> {
    let a: Artifact = serde_json::from_value(c["artifact"].clone())?;
    ensure!(
        c["schema"] == "jetstreamer-foundation-holding-custody-v1"
            && c["host"] == review::HOST
            && c["prefix"] == review::PREFIX
            && c["bucket"] == BUCKET
            && c["source"].as_str() == a.source().to_str()
            && c["object_key"] == key(a.sha())?
            && c["sha256"] == a.sha()
            && c["length"] == a.length()
            && c["remote_sha256_readback"] == true
            && c["local_source_revalidated"] == true
            && c["owner_checked"] == true
            && c["object_etag"].as_str().is_some_and(|s| !s.is_empty())
            && c["mapping"] == json!({"path":review::MAPPING,"sha256":review::MAPPING_SHA}),
        "foreign Foundation custody"
    );
    no_authority(c)?;
    artifact_manifest(&c["manifest"], a)?;
    let sha = hex_lower(&Sha256::digest(serde_json::to_vec(&c["manifest"])?));
    ensure!(
        c["manifest_sha256"] == sha
            && c["manifest_key"] == format!("{}manifests/{sha}.json", review::PREFIX),
        "Foundation custody manifest digest/key differs"
    );
    Ok(a)
}
async fn park(client: &Client, p: &ParkSpec, spec: &Bound) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-foundation-holding-park-plan-v1",
        "foreign Foundation park plan"
    );
    mapping_binding(&p.mapping)?;
    let before = review_for_park(p)?;
    let a = p.artifact;
    let id = source_identity(a)?;
    let proof = hash_and_etag(a.source(), id, DEFAULT_PART_SIZE)?;
    ensure!(
        proof.sha256_hex == a.sha(),
        "Foundation source digest differs"
    );
    let md = fs::symlink_metadata(a.source())?;
    let artifact_key = key(a.sha())?;
    claim_owner(client, review::PREFIX, &owner()?).await?;
    let payload = Park {
        schema: "transport-only".into(),
        mapping: p.mapping.clone(),
        eligibility: spec.clone(),
        source: a.source().to_path_buf(),
        length: a.length(),
        sha256: a.sha().into(),
    };
    let remote = verified_blob(client, &artifact_key, &payload, id, &proof).await?;
    ensure!(
        source_identity(a)? == id
            && hash_and_etag(a.source(), id, DEFAULT_PART_SIZE)?.sha256_hex == a.sha(),
        "Foundation source changed after complete remote readback"
    );
    let after = review_for_park(p)?;
    let bytes = manifest(a, &md)?;
    let manifest_sha = hex_lower(&Sha256::digest(&bytes));
    let manifest_key = format!("{}manifests/{manifest_sha}.json", review::PREFIX);
    small_create(client, &manifest_key, &bytes).await?;
    let final_remote = head_archive(client, BUCKET, &artifact_key)
        .await?
        .context("Foundation blob disappeared")?;
    remote_matches(
        &final_remote,
        &artifact_key,
        a.length(),
        a.sha(),
        Some(&remote.etag),
    )?;
    native_checksum(&final_remote, &proof, a.length())?;
    let receipt = json!({"schema":"jetstreamer-foundation-holding-custody-v1","host":review::HOST,"bucket":BUCKET,"prefix":review::PREFIX,
        "artifact":a,"mapping":p.mapping,"spec":spec,"source":a.source(),"length":a.length(),"sha256":a.sha(),
        "object_key":artifact_key,"object_etag":remote.etag,"manifest_key":manifest_key,"manifest_sha256":manifest_sha,
        "manifest":serde_json::from_slice::<Value>(&bytes)?,"remote_sha256_readback":true,"local_source_revalidated":true,"owner_checked":true,
        "reference_census_before":before,"reference_census_after":after,"historical_consumers_require_restore_before_reuse":true,
        "local_retirement_authorized":false,"canonical_publication_authorized":false,"runtime_checkpoint_qualified":false,
        "job_resume_authorized":false,"replay_launch_authorized":false});
    custody(&receipt)?;
    let path = Path::new(STATE)
        .join("receipts")
        .join(format!("custody-{}.json", spec.sha256));
    durable_receipt(&path, &receipt)?;
    println!("{}", path.display());
    Ok(())
}
fn restore_credit(a: Artifact) -> Result<u64> {
    let directory = Path::new(STATE).join("restores");
    private(&directory)?;
    for (name, complete) in [
        (format!("{}.blob", a.sha()), true),
        (format!(".{}.partial", a.sha()), false),
    ] {
        let path = directory.join(name);
        match fs::symlink_metadata(&path) {
            Ok(md) => {
                let id = regular_identity(&path)?;
                ensure!(
                    md.is_file()
                        && md.uid() == 0
                        && md.nlink() == 1
                        && matches!(md.mode() & 0o777, 0o400 | 0o600)
                        && id.length <= a.length(),
                    "unsafe existing Foundation restore bytes"
                );
                if complete {
                    ensure!(
                        id.length == a.length()
                            && hash_and_etag(&path, id, DEFAULT_PART_SIZE)?.sha256_hex == a.sha(),
                        "conflicting complete restored bytes"
                    );
                }
                let physical = md
                    .blocks()
                    .checked_mul(512)
                    .context("restore allocation overflow")?;
                return additional_bytes(a.length(), id.length, physical);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(a.length())
}
fn additional_bytes(length: u64, logical: u64, physical: u64) -> Result<u64> {
    ensure!(
        logical <= length,
        "restore partial is longer than its artifact"
    );
    Ok(length - logical.min(physical))
}
fn restore_reservation(remaining: u64) -> Result<u64> {
    remaining
        .checked_add(2 * METADATA_RESERVE)
        .context("Foundation metadata reservation overflow")
}
fn write_floor(minimum: u64) -> Result<u64> {
    minimum
        .checked_add(METADATA_RESERVE)
        .context("Foundation metadata floor overflow")
}
fn metadata_space(minimum: u64, free: u64) -> Result<()> {
    ensure!(
        free >= minimum
            .checked_add(MAX_RECEIPT_BYTES as u64 + 65536)
            .context("Foundation metadata write floor overflow")?,
        "Foundation metadata publication would consume its protected floor"
    );
    Ok(())
}
fn admission(v: &Value, custody_binding: &Bound, a: Artifact) -> Result<()> {
    let at = v["recorded_unix_seconds"]
        .as_u64()
        .context("Foundation admission clock")?;
    let now = clock()?;
    ensure!(
        v["schema"] == "jetstreamer-foundation-holding-restore-admission-v1"
            && v["host"] == review::HOST
            && v["prefix"] == review::PREFIX
            && v["artifact"] == serde_json::to_value(a)?
            && v["custody"] == serde_json::to_value(custody_binding)?
            && v["restore_only"] == true
            && v["local_retirement_authorized"] == false
            && at <= now
            && now - at <= 900
            && v["admissions_must_be_serialized_until_restore_complete"] == true,
        "stale/foreign Foundation restore admission"
    );
    ensure!(
        v["metadata_budget"] == metadata_budget(),
        "Foundation admission uses a foreign metadata budget"
    );
    let current = fleet::foundation_holding_capacity(&v["resource_basis"], 0)?;
    ensure!(
        current["minimum_free_bytes"]
            .as_u64()
            .zip(v["capacity"]["minimum_free_bytes"].as_u64())
            .is_some_and(|(new, old)| new <= old),
        "Foundation protected growth/floors increased after admission"
    );
    Ok(())
}
fn admit(p: &AdmitSpec, spec: &Bound) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-foundation-holding-restore-admission-plan-v1",
        "foreign Foundation restoration plan"
    );
    mapping_binding(&p.mapping)?;
    let c = receipt_bound(&p.custody)?;
    let a = custody(&c)?;
    let data_remaining = restore_credit(a)?;
    let remaining = restore_reservation(data_remaining)?;
    ensure!(
        remaining <= MAX_ADDITIONAL,
        "oversized Foundation restore claim"
    );
    let capacity = fleet::foundation_holding_capacity(&p.resource_basis, remaining)?;
    let receipt = json!({"schema":"jetstreamer-foundation-holding-restore-admission-v1","host":review::HOST,"prefix":review::PREFIX,
        "mapping":p.mapping,"artifact":a,"custody":p.custody,"spec":spec,"resource_basis":p.resource_basis,"capacity":capacity,
        "recorded_unix_seconds":clock()?,"restore_only":true,"admissions_must_be_serialized_until_restore_complete":true,
        "local_retirement_authorized":false,"replay_launch_authorized":false,"r2_mutations":false,"metadata_budget":metadata_budget()});
    serialized_receipt_length(&receipt)?;
    admission(&receipt, &p.custody, a)?;
    let path = Path::new(STATE)
        .join("receipts")
        .join(format!("restore-admission-{}.json", spec.sha256));
    if path.try_exists()? {
        let old: Value = serde_json::from_slice(&read_stable_bounded(
            &path,
            MAX_RECEIPT_BYTES as u64,
            "Foundation existing admission",
        )?)?;
        ensure!(
            old["spec"] == serde_json::to_value(spec)?,
            "conflicting Foundation admission"
        );
        admission(&old, &p.custody, a)?;
    } else {
        durable_receipt(&path, &receipt)?;
    }
    let protected = write_floor(
        receipt["capacity"]["minimum_free_bytes"]
            .as_u64()
            .context("Foundation admitted metadata floor")?,
    )?
    .checked_add(data_remaining)
    .context("Foundation post-admission space overflow")?;
    ensure!(
        available(Path::new(STATE))? >= protected,
        "Foundation admission publication consumed reserved restoration space"
    );
    println!("{}", path.display());
    Ok(())
}
fn preserve_segment(c: &Value, a: Artifact) -> Result<Option<PathBuf>> {
    if a != Artifact::Prefix213 {
        return Ok(None);
    }
    let segment = &c["manifest"]["segment"];
    let bytes = BASE64_STANDARD.decode(
        segment["raw_base64"]
            .as_str()
            .context("segment restoration bytes missing")?,
    )?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == review::SEGMENT_SHA && bytes.len() == 1809,
        "invalid raw segment restore"
    );
    let directory = Path::new(STATE).join("restores");
    private(&directory)?;
    let path = directory.join(format!("{}.segment.json", a.sha()));
    if path.try_exists()? {
        ensure!(
            read_stable_bounded(&path, 16384, "restored raw segment")? == bytes,
            "conflicting restored segment"
        );
    } else {
        let mut tmp = tempfile::Builder::new()
            .prefix(".foundation-segment.")
            .tempfile_in(&directory)?;
        tmp.as_file_mut().write_all(&bytes)?;
        tmp.as_file_mut()
            .set_permissions(fs::Permissions::from_mode(0o400))?;
        persist_noclobber(tmp, &path)?;
    }
    fs::File::open(&path)?.sync_all()?;
    fs::File::open(&directory)?.sync_all()?;
    Ok(Some(path))
}
async fn restore(client: &Client, p: &RestoreSpec, spec: &Bound) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-foundation-holding-restore-plan-v1",
        "foreign Foundation restore plan"
    );
    mapping_binding(&p.mapping)?;
    let c = receipt_bound(&p.custody)?;
    let a = custody(&c)?;
    let admitted = receipt_bound(&p.admission)?;
    admission(&admitted, &p.custody, a)?;
    let expected_owner = owner()?;
    ensure!(
        get_mutable_object(client, BUCKET, &format!("{}owner.json", review::PREFIX))
            .await?
            .is_some_and(|v| v.bytes == expected_owner),
        "Foundation holding owner is missing/different"
    );
    let mk = c["manifest_key"]
        .as_str()
        .context("Foundation manifest key")?;
    let remote_manifest = get_mutable_object(client, BUCKET, mk)
        .await?
        .context("Foundation manifest missing")?;
    ensure!(
        hex_lower(&Sha256::digest(&remote_manifest.bytes)) == c["manifest_sha256"]
            && serde_json::from_slice::<Value>(&remote_manifest.bytes)? == c["manifest"],
        "remote Foundation manifest differs"
    );
    let artifact_key = key(a.sha())?;
    let etag = c["object_etag"]
        .as_str()
        .context("Foundation custody ETag")?;
    let remote = head_archive(client, BUCKET, &artifact_key)
        .await?
        .context("Foundation object missing")?;
    remote_matches(&remote, &artifact_key, a.length(), a.sha(), Some(etag))?;
    let minimum = admitted["capacity"]["minimum_free_bytes"]
        .as_u64()
        .context("Foundation restore floor")?;
    let directory = Path::new(STATE).join("restores");
    let destination = restore_blob(
        client,
        BlobRestore {
            key: &artifact_key,
            etag,
            sha: a.sha(),
            length: a.length(),
            directory: &directory,
            minimum: write_floor(minimum)?,
        },
        || admission(&admitted, &p.custody, a),
    )
    .await?;
    metadata_space(minimum, available(Path::new(STATE))?)?;
    let segment = preserve_segment(&c, a)?;
    let proof = hash_and_etag(
        &destination,
        regular_identity(&destination)?,
        DEFAULT_PART_SIZE,
    )?;
    ensure!(
        proof.sha256_hex == a.sha(),
        "Foundation restored digest differs"
    );
    let current = head_archive(client, BUCKET, &artifact_key)
        .await?
        .context("Foundation object disappeared")?;
    remote_matches(&current, &artifact_key, a.length(), a.sha(), Some(etag))?;
    native_checksum(&current, &proof, a.length())?;
    admission(&admitted, &p.custody, a)?;
    let receipt = json!({"schema":"jetstreamer-foundation-holding-restore-v1","host":review::HOST,"prefix":review::PREFIX,
        "mapping":p.mapping,"artifact":a,"custody":p.custody,"admission":p.admission,"spec":spec,"sha256":a.sha(),"length":a.length(),
        "object_key":artifact_key,"object_etag":etag,"destination":destination,"raw_segment_destination":segment,"original_file_metadata":c["manifest"],
        "restoration_complete":true,"remote_sha256_readback":true,"owner_checked":true,"staging_only":true,"local_source_mutated":false,
        "local_retirement_authorized":false,"canonical_publication_authorized":false,"runtime_checkpoint_qualified":false,
        "job_resume_authorized":false,"replay_launch_authorized":false});
    no_authority(&receipt)?;
    let path = Path::new(STATE)
        .join("receipts")
        .join(format!("restore-{}.json", spec.sha256));
    metadata_space(minimum, available(Path::new(STATE))?)?;
    durable_receipt(&path, &receipt)?;
    ensure!(
        available(Path::new(STATE))? >= minimum,
        "Foundation metadata consumed protected free space"
    );
    println!("{}", path.display());
    Ok(())
}
pub(super) async fn run(action: &str, v: Value, spec: &Bound) -> Result<()> {
    ensure!(command(action), "unknown Foundation action");
    review::validate_host_mapping()?;
    private(Path::new(STATE))?;
    private(&Path::new(STATE).join("receipts"))?;
    private(&Path::new(STATE).join("restores"))?;
    let root_device = fs::metadata("/")?.dev();
    ensure!(
        fs::metadata(STATE)?.dev() == root_device
            && fs::metadata(Path::new(STATE).join("restores"))?.dev() == root_device,
        "Foundation restore state must use the admitted root filesystem"
    );
    let lock_path = Path::new(STATE).join("transition.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(action == "holding-foundation213-park")
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(lock_path)?;
    let m = lock.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o777 == 0o600
            && unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "Foundation transition already owned/unsafe"
    );
    if action == "holding-foundation213-admit-restore" {
        return admit(&serde_json::from_value(v)?, spec);
    }
    let r2 = r2_config_from_env()?;
    ensure!(r2.bucket == BUCKET, "foreign Foundation bucket");
    let client = s3_client(&r2);
    match action {
        "holding-foundation213-park" => park(&client, &serde_json::from_value(v)?, spec).await,
        "holding-foundation213-restore" => {
            restore(&client, &serde_json::from_value(v)?, spec).await
        }
        _ => bail!("unsupported Foundation operation"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn prefix_manifest_fixture() -> Value {
        let raw = include_bytes!("../tests/fixtures/foundation213/prefix.segment.json");
        json!({"schema":"jetstreamer-foundation-holding-manifest-v1","host":review::HOST,"prefix":review::PREFIX,
            "artifact":"prefix213","object_key":key(review::SOURCE_SHA).unwrap(),"length":review::LENGTH,"sha256":review::SOURCE_SHA,
            "name":"epoch-213-through-92447542.jet","uid":1000,"gid":1000,"mode":0o600,"canonical_archive":false,
            "canonical_publication_authorized":false,"restore_before_historical_consumer_reuse":true,
            "completed_continuation_restore_dependency":{"path":review::CONTINUATION,"sha256":review::CONTINUATION_SHA},
            "segment":{"name":"epoch-213-through-92447542.jet.segment.json","sha256":review::SEGMENT_SHA,"length":1809,
                "raw_base64":BASE64_STANDARD.encode(raw),"uid":0,"gid":0,"mode":0o600}})
    }
    fn custody_fixture(manifest: Value) -> Value {
        let a: Artifact = serde_json::from_value(manifest["artifact"].clone()).unwrap();
        let sha = hex_lower(&Sha256::digest(serde_json::to_vec(&manifest).unwrap()));
        json!({"schema":"jetstreamer-foundation-holding-custody-v1","host":review::HOST,"prefix":review::PREFIX,"bucket":BUCKET,
            "artifact":a,"source":a.source(),"object_key":key(a.sha()).unwrap(),"sha256":a.sha(),"length":a.length(),"remote_sha256_readback":true,
            "local_source_revalidated":true,"owner_checked":true,"object_etag":"fixture-1","mapping":{"path":review::MAPPING,"sha256":review::MAPPING_SHA},
            "manifest":manifest,"manifest_sha256":sha,"manifest_key":format!("{}manifests/{sha}.json",review::PREFIX),
            "local_retirement_authorized":false,"canonical_publication_authorized":false,"runtime_checkpoint_qualified":false,
            "job_resume_authorized":false,"replay_launch_authorized":false})
    }
    #[test]
    fn only_two_exact_public_artifacts_and_the_user_namespace_are_addressable() {
        assert!(
            key(review::SOURCE_SHA)
                .unwrap()
                .starts_with("foundation_node_01/objects/")
        );
        assert!(key(PROBE_SHA).unwrap().ends_with(".blob"));
        assert!(key("953e8c9efbdfc0dc49e4f066d30046e3b44e1a13e065b340a5bcc7b093632261").is_err());
        assert!(key("../epoch-213.jet").is_err());
        assert_eq!(Artifact::Prefix213.source(), Path::new(review::SOURCE));
        assert_ne!(
            owner().unwrap(),
            super::super::owner_bytes(&super::super::Mapping {
                schema: "jetstreamer-horizon-host-holding-prefix-v2".into(),
                host: "dev-samjohnson".into(),
                prefix: "node_02/".into(),
                user_provided_prefix: true,
                authorization_reference: "test".into()
            })
            .unwrap()
        );
    }
    #[test]
    fn plans_cannot_enable_retirement_or_select_arbitrary_paths() {
        let b = json!({"path":review::MAPPING,"sha256":review::MAPPING_SHA});
        let mut p = json!({"schema":"jetstreamer-foundation-holding-park-plan-v1","mapping":b,"artifact":"prefix213","accepted_fleet":null,"transport_qualification":null});
        assert!(serde_json::from_value::<ParkSpec>(p.clone()).is_ok());
        for field in ["source", "delete_local", "overwrite", "prefix"] {
            p[field] = json!(true);
            assert!(serde_json::from_value::<ParkSpec>(p.clone()).is_err());
            p.as_object_mut().unwrap().remove(field);
        }
        p["artifact"] = json!("canonical213");
        assert!(serde_json::from_value::<ParkSpec>(p).is_err());
    }
    #[test]
    fn raw_segment_identity_and_noncanonical_scope_are_not_optional() {
        let mut v = json!({"schema":"jetstreamer-foundation-holding-manifest-v1","host":review::HOST,"prefix":review::PREFIX,
            "artifact":"prefix213","object_key":key(review::SOURCE_SHA).unwrap(),"length":review::LENGTH,"sha256":review::SOURCE_SHA,
            "name":"epoch-213-through-92447542.jet","uid":1000,"gid":1000,"mode":0o600,"canonical_archive":false,
            "canonical_publication_authorized":false,"restore_before_historical_consumer_reuse":true});
        assert!(artifact_manifest(&v, Artifact::Prefix213).is_err());
        v["canonical_archive"] = json!(true);
        assert!(artifact_manifest(&v, Artifact::Prefix213).is_err());
    }
    #[test]
    fn complete_prefix_custody_preserves_raw_bytes_and_denies_cross_scope_or_retirement() {
        let manifest = prefix_manifest_fixture();
        artifact_manifest(&manifest, Artifact::Prefix213).unwrap();
        let original = custody_fixture(manifest);
        assert_eq!(custody(&original).unwrap(), Artifact::Prefix213);
        for pointer in [
            "/prefix",
            "/source",
            "/mapping/sha256",
            "/object_key",
            "/manifest_sha256",
            "/local_retirement_authorized",
            "/manifest/segment/raw_base64",
            "/manifest/completed_continuation_restore_dependency/sha256",
            "/manifest/canonical_archive",
            "/sha256",
        ] {
            let mut bad = original.clone();
            *bad.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(custody(&bad).is_err(), "{pointer}");
        }
        let mut bad = original;
        bad["artifact"] = json!("genesis-probe");
        assert!(custody(&bad).is_err());
    }
    #[test]
    fn partial_restore_credit_uses_allocated_bytes_and_never_logical_holes() {
        assert_eq!(additional_bytes(100, 100, 0).unwrap(), 100);
        assert_eq!(additional_bytes(100, 40, 64).unwrap(), 60);
        assert_eq!(additional_bytes(100, 80, 32).unwrap(), 68);
        assert_eq!(additional_bytes(100, 100, 128).unwrap(), 0);
        assert!(additional_bytes(100, 101, 128).is_err());
    }
    #[test]
    fn durable_private_receipt_retries_preserve_evidence_and_reject_conflicting_bytes() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("receipt.json");
        let original = json!({"artifact":"prefix213","sha256":review::SOURCE_SHA,
            "reference_census_before":{"sample":1},"reference_census_after":{"sample":2}});
        durable_receipt(&path, &original).unwrap();
        let before = fs::read(&path).unwrap();
        let mut retry = original.clone();
        retry["reference_census_before"] = json!({"sample":3});
        durable_receipt(&path, &retry).unwrap();
        assert_eq!(fs::read(&path).unwrap(), before);
        retry["sha256"] = json!(PROBE_SHA);
        assert!(durable_receipt(&path, &retry).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(fs::metadata(path).unwrap().mode() & 0o222, 0);
    }
    #[test]
    fn exact_boundary_keeps_metadata_above_the_live_floor() {
        let floor = 2000;
        let data = 125;
        let admitted = floor + restore_reservation(data).unwrap();
        // Even a maximum-sized admission leaves the full guarded stream plus
        // its metadata floor. The segment and final receipt have their own gap.
        let after_admission = admitted - MAX_RECEIPT_BYTES as u64;
        assert!(after_admission >= write_floor(floor).unwrap() + data);
        let after_data = after_admission - data;
        metadata_space(floor, after_data).unwrap();
        let after_segment = after_data - 4096;
        metadata_space(floor, after_segment).unwrap();
        assert!(after_segment - MAX_RECEIPT_BYTES as u64 > floor);
        assert!(metadata_space(floor, floor + 16384).is_err());
        let threshold = floor + MAX_RECEIPT_BYTES as u64 + 65536;
        metadata_space(floor, threshold).unwrap();
        assert!(metadata_space(floor, threshold - 1).is_err());
        assert!(write_floor(u64::MAX).is_err());
        assert!(restore_reservation(u64::MAX).is_err());
    }
    #[test]
    fn full_257_owner_before_after_censuses_fit_without_discarding_evidence() {
        let census = (0..257).map(|n| (format!("historical-owner-{n}.service"),
            json!({"Id":format!("historical-owner-{n}.service"),"InvocationID":format!("{n:032x}"),
                "MainPID":"0","NRestarts":"0","ActiveState":"inactive","SubState":"dead",
                "ExecStart":format!("{{ path=/var/lib/jetstreamer/retained-owner-{n}/runner ; argv[]={}; ignore_errors=no }}","x".repeat(2048))})))
            .collect::<serde_json::Map<_,_>>();
        let value = json!({"schema":"real-scale-evidence-fixture","metadata_budget":metadata_budget(),
            "capacity":{"unit_census_before":census,"unit_census_after":census}});
        let length = serialized_receipt_length(&value).unwrap();
        assert!(length > 1 << 20);
        assert!(length < MAX_RECEIPT_BYTES as u64);
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("full-census.json");
        durable_receipt(&path, &value).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), length);
        let read: Value = serde_json::from_slice(
            &read_stable_bounded(&path, MAX_RECEIPT_BYTES as u64, "full-census fixture").unwrap(),
        )
        .unwrap();
        assert_eq!(read, value);
        assert_eq!(
            read["capacity"]["unit_census_before"]
                .as_object()
                .unwrap()
                .len(),
            257
        );
        assert_eq!(
            read["capacity"]["unit_census_after"]
                .as_object()
                .unwrap()
                .len(),
            257
        );
        durable_receipt(&path, &value).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(path).unwrap()).unwrap(),
            value
        );
    }
    #[test]
    fn oversized_receipt_fails_before_creating_any_publication_or_staging_file() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("oversized.json");
        let oversized = json!({"full_evidence":"x".repeat(MAX_RECEIPT_BYTES)});
        assert!(durable_receipt(&path, &oversized).is_err());
        assert!(!path.exists());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }
    #[test]
    fn foundation_probe_qualification_cannot_grant_checkpoint_or_park_another_host() {
        let mut q = json!({"schema":"jetstreamer-foundation-holding-restore-v1","host":review::HOST,"prefix":review::PREFIX,
            "artifact":"genesis-probe","sha256":PROBE_SHA,"length":20144,"restoration_complete":true,"remote_sha256_readback":true,
            "owner_checked":true,"staging_only":true,"object_key":key(PROBE_SHA).unwrap(),
            "mapping":{"path":review::MAPPING,"sha256":review::MAPPING_SHA},"local_retirement_authorized":false,
            "canonical_publication_authorized":false,"runtime_checkpoint_qualified":false,"job_resume_authorized":false,"replay_launch_authorized":false});
        qualification(&q).unwrap();
        q["prefix"] = json!("node_02/");
        assert!(qualification(&q).is_err());
        q["prefix"] = json!(review::PREFIX);
        q["runtime_checkpoint_qualified"] = json!(true);
        assert!(qualification(&q).is_err());
    }
}
