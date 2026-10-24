//! Append-only custody and separately scoped backed partial136 retirement. No
//! canonical sidecar, runtime checkpoint or job-resume authority.
use super::*;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
#[path = "holding_epoch136.rs"]
mod epoch136;
#[path = "holding_epoch185.rs"]
mod epoch185;

const HOST: &str = "dev-samjohnson";
const STATE: &str = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1";
const BUCKET: &str = "solana-archive-with-accounts-data";
const BASE_RESERVE: u64 = 3_572_465_819_078;
const MAX_FILE: u64 = DEFAULT_PART_SIZE * 10_000;
const GENESIS_PROBE_ROOT: &str =
    "/var/lib/jetstreamer/horizon-holding-public-genesis-probe-20261023-v1";
const GENESIS_PROBE_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const GENESIS_PROBE_FLOOR: u64 = 205_211_459_014;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Mapping {
    schema: String,
    host: String,
    prefix: String,
    user_provided_prefix: bool,
    authorization_reference: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Park {
    schema: String,
    mapping: Bound,
    eligibility: Bound,
    source: PathBuf,
    length: u64,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Restore {
    schema: String,
    mapping: Bound,
    custody: Bound,
    admission: Bound,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreAdmission {
    schema: String,
    mapping: Bound,
    custody: Bound,
    capacity_completion: Bound,
}

fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn prefix(p: &str) -> bool {
    p.len() <= 160
        && p.ends_with('/')
        && !p.starts_with('/')
        && p[..p.len().saturating_sub(1)].split('/').all(|s| {
            !s.is_empty()
                && s != "."
                && s != ".."
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        })
}
fn mapping(m: &Mapping) -> Result<()> {
    ensure!(
        m.schema == "jetstreamer-horizon-host-holding-prefix-v2"
            && m.host == HOST
            && prefix(&m.prefix)
            && m.user_provided_prefix
            && !m.authorization_reference.trim().is_empty(),
        "holding requires this hosts explicit user-provided prefix mapping"
    );
    Ok(())
}
fn owner_bytes(m: &Mapping) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(
        &json!({"schema":"jetstreamer-horizon-holding-owner-v2","host":HOST,"prefix":m.prefix}),
    )?)
}
fn bound(b: &Bound) -> Result<Value> {
    evidence(b, true)
}
fn evidence(b: &Bound, immutable: bool) -> Result<Value> {
    ensure!(
        digest(&b.sha256) && b.path.is_absolute() && b.path.canonicalize()? == b.path,
        "invalid holding evidence binding"
    );
    let metadata = fs::symlink_metadata(&b.path)?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == 0
            && metadata.mode() & if immutable { 0o222 } else { 0o022 } == 0
            && metadata.len() <= 1 << 20,
        "holding evidence must be sealed root-owned regular bytes"
    );
    let before = regular_identity(&b.path)?;
    let bytes = fs::read(&b.path)?;
    ensure!(
        regular_identity(&b.path)? == before && hex_lower(&Sha256::digest(&bytes)) == b.sha256,
        "holding evidence changed or digest differs"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn private(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && m.is_dir()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o777 == 0o700,
        "unsafe holding private directory"
    );
    Ok(())
}
fn persist(path: &Path, v: &Value) -> Result<()> {
    let parent = path.parent().context("holding receipt parent")?;
    private(parent)?;
    if fs::symlink_metadata(path).is_ok() {
        let before = regular_identity(path)?;
        ensure!(
            before.length <= 1 << 20,
            "oversized existing custody receipt"
        );
        let old: Value = serde_json::from_slice(&fs::read(path)?)?;
        let evidence = |value: &Value| {
            let mut value = value.clone();
            if let Some(fields) = value.as_object_mut() {
                fields.remove("reference_census_before");
                fields.remove("reference_census_after");
            }
            value
        };
        ensure!(
            regular_identity(path)? == before && evidence(&old) == evidence(v),
            "conflicting existing custody receipt"
        );
        return Ok(());
    }
    let mut temp = tempfile::Builder::new()
        .prefix(".holding-receipt.")
        .tempfile_in(parent)?;
    serde_json::to_writer_pretty(temp.as_file_mut(), v)?;
    temp.as_file_mut().write_all(b"\n")?;
    temp.as_file_mut()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    persist_noclobber(temp, path)
}
fn object_key(m: &Mapping, sha: &str) -> Result<String> {
    mapping(m)?;
    ensure!(digest(sha), "invalid holding content digest");
    Ok(format!("{}objects/{sha}.blob", m.prefix))
}
fn source_scope(p: &Park, e: &Value) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-horizon-holding-park-plan-v2"
            && digest(&p.sha256)
            && p.length > 0
            && p.length <= MAX_FILE
            && p.source.is_absolute()
            && !p.source.components().any(|c| matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            ))
            && p.source.starts_with("/home/sol/.jetstreamer-private"),
        "foreign holding source or plan"
    );
    for component in p.source.components() {
        ensure!(
            !matches!(
                component.as_os_str().to_str(),
                Some(".ssh" | ".config" | "credentials" | "logs" | "keychain")
            ),
            "credentials/configuration/logs are forbidden in holding"
        );
    }
    let name = p
        .source
        .file_name()
        .and_then(|s| s.to_str())
        .context("holding source name")?
        .to_ascii_lowercase();
    ensure!(
        !name.ends_with(".log")
            && !name.ends_with(".pem")
            && !name.ends_with(".key")
            && !name.ends_with(".epoch-status.json")
            && !name.ends_with(".sha256"),
        "forbidden holding source class"
    );
    ensure!(
        e["schema"] == "jetstreamer-horizon-holding-eligibility-v2"
            && e["host"] == HOST
            && e["source"].as_str() == p.source.to_str()
            && e["length"] == p.length
            && e["sha256"] == p.sha256
            && e["closed"] == true
            && e["content_class"] == "public-chain-artifact"
            && e["credentials_config_and_logs_excluded"] == true
            && e["canonical_archive"] == false
            && e["local_retirement_authorized"] == false,
        "holding needs reviewed closed public-chain eligibility; canonical archives retain normal gates"
    );
    Ok(())
}
fn source(p: &Park, e: &Value) -> Result<FileIdentity> {
    source_scope(p, e)?;
    ensure!(p.source.canonicalize()? == p.source, "holding source alias");
    let identity = regular_identity(&p.source)?;
    ensure!(identity.length == p.length, "holding source length differs");
    Ok(identity)
}
fn no_references(path: &Path) -> Result<Value> {
    let scan = jetstreamer_horizon_observe::process_references::scan(Path::new("/proc"), path)?;
    ensure!(
        scan.references.is_empty(),
        "holding source has live process references: {:?}",
        scan.references
    );
    Ok(serde_json::to_value(scan)?)
}
async fn small_create(client: &Client, key: &str, bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() <= MAX_STATUS_BYTES as usize,
        "holding manifest too large"
    );
    if let Some(old) = get_mutable_object(client, BUCKET, key).await? {
        ensure!(
            old.bytes == bytes,
            "holding key is already owned by different bytes"
        );
        return Ok(());
    }
    let put = client
        .put_object()
        .bucket(BUCKET)
        .key(key)
        .if_none_match("*")
        .content_md5(BASE64_STANDARD.encode(Md5::digest(bytes)))
        .content_type("application/json")
        .body(ByteStream::from(bytes.to_vec()))
        .send()
        .await;
    let read = get_mutable_object(client, BUCKET, key).await?;
    ensure!(
        read.as_ref().is_some_and(|r| r.bytes == bytes),
        "holding conditional create/readback failed: {:?}",
        put.err()
    );
    Ok(())
}
async fn owner(client: &Client, m: &Mapping) -> Result<()> {
    mapping(m)?;
    let key = format!("{}owner.json", m.prefix);
    let bytes = owner_bytes(m)?;
    if let Some(old) = get_mutable_object(client, BUCKET, &key).await? {
        ensure!(
            old.bytes == bytes,
            "holding prefix belongs to a different owner"
        );
        return Ok(());
    }
    let list = client
        .list_objects_v2()
        .bucket(BUCKET)
        .prefix(&m.prefix)
        .max_keys(1)
        .send()
        .await?;
    ensure!(
        list.contents().is_empty() && list.is_truncated() != Some(true),
        "unmapped nonempty holding prefix; resolve ownership before any write"
    );
    small_create(client, &key, &bytes).await
}
fn remote_matches(
    r: &RemoteArchive,
    key: &str,
    length: u64,
    sha: &str,
    etag: Option<&str>,
) -> Result<()> {
    ensure!(
        r.length == length
            && r.metadata_sha256.as_deref() == Some(sha)
            && etag.is_none_or(|expected| r.etag == expected),
        "holding remote identity differs: {key}"
    );
    Ok(())
}
fn native_checksum(remote: &RemoteArchive, proof: &LocalProof, length: u64) -> Result<()> {
    if let Some(checksum) = remote.composite_sha256.as_deref() {
        ensure!(
            remote.checksum_type == Some(ChecksumType::Composite)
                && composite_checksum_matches(
                    checksum,
                    &proof.composite_sha256,
                    length.div_ceil(DEFAULT_PART_SIZE)
                ),
            "holding native composite SHA-256 differs"
        );
    }
    Ok(())
}
fn manifest_bytes(
    m: &Mapping,
    p: &Park,
    key: &str,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(
        &json!({"schema":"jetstreamer-horizon-holding-manifest-v2",
        "host":HOST,"prefix":m.prefix,"object_key":key,"length":p.length,"sha256":p.sha256,
        "name":p.source.file_name().context("artifact name")?.to_str().context("non-UTF8 artifact name")?,
        "uid":uid,"gid":gid,"mode":mode&0o777,"eligibility_sha256":p.eligibility.sha256,
        "canonical_archive":false,"canonical_publication_authorized":false} ),
    )?)
}
async fn park(client: &Client, m: &Mapping, p: &Park) -> Result<()> {
    let e = bound(&p.eligibility)?;
    let identity = source(p, &e)?;
    let first = no_references(&p.source)?;
    let proof = hash_and_etag(&p.source, identity, DEFAULT_PART_SIZE)?;
    ensure!(
        proof.sha256_hex == p.sha256,
        "holding source digest differs"
    );
    let md = fs::symlink_metadata(&p.source)?;
    let key = object_key(m, &p.sha256)?;
    owner(client, m).await?;
    let existing = head_archive(client, BUCKET, &key).await?;
    if let Some(r) = &existing {
        remote_matches(r, &key, p.length, &p.sha256, None)?;
    } else {
        let (etag, _) = upload_object(
            client,
            BUCKET,
            ObjectUpload {
                key: &key,
                epoch: None,
                path: &p.source,
                identity,
                length: p.length,
                sha256: &p.sha256,
                format: "cold-holding-v2",
            },
            DEFAULT_PART_SIZE,
            2,
            false,
        )
        .await?;
        ensure!(
            etag == proof.multipart_etag,
            "holding multipart ETag differs from local proof"
        );
    }
    let remote = head_archive(client, BUCKET, &key)
        .await?
        .context("holding blob missing after upload")?;
    remote_matches(&remote, &key, p.length, &p.sha256, None)?;
    native_checksum(&remote, &proof, p.length)?;
    verify_remote_sha256(client, BUCKET, &key, &remote.etag, p.length, &p.sha256, 2).await?;
    ensure!(
        source(p, &e)? == identity
            && hash_and_etag(&p.source, identity, DEFAULT_PART_SIZE)?.sha256_hex == p.sha256,
        "holding source changed after remote verification"
    );
    let second = no_references(&p.source)?;
    let manifest = manifest_bytes(m, p, &key, md.uid(), md.gid(), md.mode())?;
    let manifest_sha = hex_lower(&Sha256::digest(&manifest));
    let manifest_key = format!("{}manifests/{manifest_sha}.json", m.prefix);
    // Manifest is a holding-only commit marker, published after whole readback.
    small_create(client, &manifest_key, &manifest).await?;
    let final_remote = head_archive(client, BUCKET, &key)
        .await?
        .context("holding blob disappeared")?;
    remote_matches(&final_remote, &key, p.length, &p.sha256, Some(&remote.etag))?;
    native_checksum(&final_remote, &proof, p.length)?;
    let receipt = json!({"schema":"jetstreamer-horizon-holding-custody-v2","host":HOST,"bucket":BUCKET,
        "prefix":m.prefix,"mapping":p.mapping,"source":p.source,"length":p.length,"sha256":p.sha256,
        "object_key":key,"object_etag":remote.etag,"manifest_key":manifest_key,"manifest_sha256":manifest_sha,
        "manifest":serde_json::from_slice::<Value>(&manifest)?,"eligibility":p.eligibility,
        "remote_sha256_readback":true,"local_source_revalidated":true,
        "reference_census_before":first,"reference_census_after":second,
        "local_retirement_authorized":false,"canonical_publication_authorized":false,
        "runtime_checkpoint_qualified":false,"job_resume_authorized":false,"replay_launch_authorized":false});
    persist(
        &Path::new(STATE)
            .join("receipts")
            .join(format!("custody-{manifest_sha}.json")),
        &receipt,
    )?;
    Ok(())
}

fn custody(c: &Value, m: &Mapping) -> Result<(String, String, String, u64)> {
    let sha = c["sha256"].as_str().context("custody digest")?;
    let length = c["length"].as_u64().context("custody length")?;
    let key = object_key(m, sha)?;
    let etag = c["object_etag"].as_str().context("custody ETag")?;
    let manifest_sha = c["manifest_sha256"]
        .as_str()
        .context("custody manifest digest")?;
    ensure!(
        c["schema"] == "jetstreamer-horizon-holding-custody-v2"
            && c["host"] == HOST
            && c["bucket"] == BUCKET
            && c["prefix"] == m.prefix
            && c["object_key"] == key
            && c["remote_sha256_readback"] == true
            && c["local_source_revalidated"] == true
            && c["local_retirement_authorized"] == false
            && c["canonical_publication_authorized"] == false
            && c["runtime_checkpoint_qualified"] == false
            && c["job_resume_authorized"] == false
            && c["replay_launch_authorized"] == false
            && length > 0
            && length <= MAX_FILE
            && !etag.is_empty()
            && digest(manifest_sha)
            && c["manifest_key"] == format!("{}manifests/{manifest_sha}.json", m.prefix),
        "foreign holding custody"
    );
    let manifest = serde_json::to_vec(&c["manifest"])?;
    ensure!(
        hex_lower(&Sha256::digest(&manifest)) == manifest_sha
            && c["manifest"]["schema"] == "jetstreamer-horizon-holding-manifest-v2"
            && c["manifest"]["host"] == HOST
            && c["manifest"]["prefix"] == m.prefix
            && c["manifest"]["object_key"] == key
            && c["manifest"]["sha256"] == sha
            && c["manifest"]["length"] == length
            && c["manifest"]["canonical_archive"] == false,
        "holding manifest binding differs"
    );
    Ok((key, etag.to_owned(), sha.to_owned(), length))
}
fn restore_admission(a: &Value, minimum: u64, now: u64) -> Result<()> {
    let recorded = a["recorded_unix_seconds"]
        .as_u64()
        .context("holding admission clock")?;
    ensure!(
        a["schema"] == "jetstreamer-horizon-holding-restore-admission-v2"
            && a["host"] == HOST
            && a["restore_only"] == true
            && a["all_live_growth_and_century_floor_protected"] == true
            && minimum >= BASE_RESERVE
            && recorded <= now
            && now - recorded <= 900,
        "holding restore requires fresh complete-growth admission"
    );
    let completion: Bound = serde_json::from_value(a["capacity_completion"].clone())?;
    ensure!(
        completion
            .path
            .starts_with("/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2")
            && completion
                .path
                .file_name()
                .is_some_and(|s| s == "completion.json"),
        "foreign holding capacity completion"
    );
    let c = evidence(&completion, false)?;
    let fb: Bound = serde_json::from_value(c["fleet"].clone())?;
    ensure!(
        fb.path.parent()
            == Some(Path::new(
                "/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1"
            )),
        "foreign holding admission fleet"
    );
    let f = evidence(&fb, false)?;
    restore_basis(a, &c, &f, minimum, now)?;
    // No newer routine or phase event may be silently omitted from admission.
    let recorded = f["recorded_unix_seconds"]
        .as_u64()
        .context("holding fleet event clock")?;
    for entry in fs::read_dir(fb.path.parent().unwrap())? {
        let path = entry?.path();
        if path == fb.path || path.extension().is_none_or(|s| s != "json") {
            continue;
        }
        let v: Value = serde_json::from_slice(&read_stable_bounded(
            &path,
            16 << 20,
            "holding latest fleet",
        )?)?;
        if v["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && v["first_epoch"] == 101
            && v["last_epoch"] == 200
        {
            let at = fleet::utc_seconds(
                v["sampled_at_utc"]
                    .as_str()
                    .context("holding fleet sample clock")?,
            )?;
            let old = fleet::utc_seconds(
                f["sampled_at_utc"]
                    .as_str()
                    .context("holding basis clock")?,
            )?;
            ensure!(
                at < old
                    || (at == old
                        && v["recorded_unix_seconds"]
                            .as_u64()
                            .context("candidate event clock")?
                            < recorded),
                "newer fleet invalidates holding restore admission"
            );
        }
    }
    restore_owners(a)
}
fn restore_basis(a: &Value, c: &Value, f: &Value, minimum: u64, now: u64) -> Result<()> {
    let sampled = fleet::utc_seconds(
        c["sampled_at_utc"]
            .as_str()
            .context("holding capacity clock")?,
    )?;
    let budget = &c["capacity_decision"]["capped186_budget"];
    ensure!(
        c["schema"] == "jetstreamer-horizon-routine-cycle-completion-v1"
            && f["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && f["first_epoch"] == 101
            && f["last_epoch"] == 200
            && f["sampled_at_utc"] == c["sampled_at_utc"]
            && f["observer_receipt"] == c["observer"]["path"]
            && f["observer_sha256"] == c["observer"]["sha256"]
            && budget["valid"] == true
            && budget["all_current_protected_bytes"]
                .as_u64()
                .is_some_and(|n| minimum >= n)
            && sampled <= now
            && now - sampled <= 1800,
        "holding restore omits live growth or accepted fresh fleet"
    );
    let expected = fleet_owners(f)?;
    let mut declared = std::collections::BTreeMap::new();
    for row in a["owners"].as_array().context("holding declared census")? {
        let name = row["unit"].as_str().context("declared holding unit")?;
        let iid = row["invocation_id"]
            .as_str()
            .context("declared holding identity")?;
        ensure!(
            declared.insert(name.to_owned(), iid.to_owned()).is_none(),
            "duplicate holding owner"
        );
    }
    ensure!(
        !expected.is_empty() && expected == declared,
        "holding restore owner census is incomplete or foreign"
    );
    Ok(())
}
fn fleet_owners(f: &Value) -> Result<std::collections::BTreeMap<String, String>> {
    let mut expected = std::collections::BTreeMap::new();
    let mut insert = |unit: &Value| -> Result<()> {
        let name = unit["Id"].as_str().context("holding fleet unit")?;
        let iid = unit["InvocationID"]
            .as_str()
            .context("holding fleet identity")?;
        ensure!(
            unit["ActiveState"] == "active"
                && unit["SubState"] == "running"
                && unit["NRestarts"] == "0",
            "holding fleet owner not live"
        );
        if let Some(old) = expected.insert(name.to_owned(), iid.to_owned()) {
            ensure!(old == iid, "ambiguous holding owner");
        }
        Ok(())
    };
    for row in f["active"]
        .as_array()
        .context("holding active fleet census")?
    {
        if row["producer"].is_object() {
            insert(&row["producer"])?;
            if row["controller"].is_object() {
                insert(&row["controller"])?;
            } else {
                ensure!(
                    row["ordinary_replay_claim"] == false
                        && f["diagnostics"]
                            .as_array()
                            .context("private holding census")?
                            .iter()
                            .any(|d| d["live"] == true
                                && d["unit"]["Id"] == row["producer"]["Id"]
                                && d["unit"]["InvocationID"] == row["producer"]["InvocationID"]),
                    "controllerless holding owner lacks its live private diagnostic binding"
                );
            }
        } else if row["unit"].is_object() {
            insert(&row["unit"])?;
        } else {
            bail!("unrecognized active holding owner shape");
        }
    }
    for row in f["diagnostics"]
        .as_array()
        .context("holding diagnostic census")?
        .iter()
        .filter(|r| r["live"] == true)
    {
        insert(&row["unit"])?;
    }
    ensure!(!expected.is_empty(), "empty holding fleet owner census");
    Ok(expected)
}

fn admission_bytes(minimum: u64, length: u64, free: u64) -> Result<u64> {
    ensure!(
        minimum >= BASE_RESERVE && length > 0 && length <= MAX_FILE,
        "invalid holding restore resource bounds"
    );
    let required = minimum
        .checked_add(length)
        .context("holding admission overflow")?;
    ensure!(
        free >= required,
        "holding restore needs {required} free bytes, has {free}; protected growth/floor {minimum}, restore {length}, deficit {}",
        required.saturating_sub(free)
    );
    Ok(required)
}

fn admit_restore(m: &Mapping, p: &RestoreAdmission, spec: &Bound) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-horizon-holding-restore-admission-plan-v2",
        "foreign holding restore admission plan"
    );
    let supplied: Mapping = serde_json::from_value(bound(&p.mapping)?)?;
    mapping(&supplied)?;
    ensure!(
        supplied.host == m.host && supplied.prefix == m.prefix,
        "holding admission mapping changed"
    );
    let c = bound(&p.custody)?;
    let (_, _, _, length) = custody(&c, m)?;
    let completion = evidence(&p.capacity_completion, false)?;
    let fleet: Bound = serde_json::from_value(completion["fleet"].clone())?;
    let f = evidence(&fleet, false)?;
    let minimum =
        completion["capacity_decision"]["capped186_budget"]["all_current_protected_bytes"]
            .as_u64()
            .context("holding complete protected-growth budget missing")?
            .max(BASE_RESERVE);
    let owners: Vec<_> = fleet_owners(&f)?
        .into_iter()
        .map(|(unit, invocation_id)| json!({"unit":unit,"invocation_id":invocation_id}))
        .collect();
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut a = json!({"schema":"jetstreamer-horizon-holding-restore-admission-v2",
        "host":HOST,"prefix":m.prefix,"restore_only":true,
        "all_live_growth_and_century_floor_protected":true,"minimum_free_bytes":minimum,
        "custody_sha256":p.custody.sha256,"restore_bytes":length,"owners":owners,
        "capacity_completion":p.capacity_completion,"recorded_unix_seconds":now,
        "spec":{"path":spec.path,"sha256":spec.sha256},"mapping":p.mapping,
        "remote_mutations":false,"r2_mutations":false,"local_retirement_authorized":false,
        "replay_launch_authorized":false,"job_resume_authorized":false,"new_resource_samples":0});
    // This validates the accepted clock, exact complete owner census, no newer
    // fleet and actual live owner metadata before any resource grant is written.
    restore_admission(&a, minimum, now)?;
    let observer: Bound = serde_json::from_value(completion["observer"].clone())?;
    let o = evidence(&observer, false)?;
    ensure!(
        o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && o["recorded_at_utc"] == completion["sampled_at_utc"],
        "holding admission observer clock differs"
    );
    let sampled_free = o["filesystem"]["conservative_available_bytes"]
        .as_u64()
        .context("holding sampled free-space missing")?;
    let required = admission_bytes(minimum, length, sampled_free)?;
    let directory = Path::new(STATE).join("restores");
    private(&directory)?;
    let current_free = available(&directory)?;
    admission_bytes(minimum, length, current_free)?;
    restore_admission(
        &a,
        minimum,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    a["required_initial_free_bytes"] = json!(required);
    a["sampled_free_bytes"] = json!(sampled_free);
    a["current_free_bytes"] = json!(current_free);
    a["admitted"] = json!(true);
    let destination = Path::new(STATE)
        .join("receipts")
        .join(format!("restore-admission-{}.json", spec.sha256));
    // Admission clocks are not idempotently rewritten. A retry needs a newly
    // sealed plan if a prior successful admission has already been persisted.
    ensure!(
        !destination.try_exists()?,
        "holding admission output already exists"
    );
    persist(&destination, &a)?;
    println!("{}", destination.display());
    Ok(())
}
fn restore_owners(a: &Value) -> Result<()> {
    let units = a["owners"]
        .as_array()
        .context("holding restore owner census")?;
    ensure!(
        !units.is_empty() && units.len() <= 64,
        "empty/oversized holding owner census"
    );
    for row in units {
        let name = row["unit"].as_str().context("holding owner unit")?;
        let iid = row["invocation_id"]
            .as_str()
            .context("holding owner identity")?;
        // Bind live owner metadata without taking another resource sample.
        let out = std::process::Command::new("/usr/bin/systemctl")
            .args([
                "show",
                name,
                "--no-pager",
                "--property=InvocationID,MainPID,ActiveState,SubState,NRestarts",
            ])
            .output()?;
        ensure!(
            out.status.success() && out.stdout.len() <= 8192,
            "holding owner metadata unavailable"
        );
        let fields: std::collections::BTreeMap<_, _> = std::str::from_utf8(&out.stdout)?
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect();
        ensure!(
            fields.get("InvocationID") == Some(&iid)
                && fields.get("ActiveState") == Some(&"active")
                && fields.get("SubState") == Some(&"running")
                && fields.get("NRestarts") == Some(&"0")
                && fields
                    .get("MainPID")
                    .and_then(|p| p.parse::<u64>().ok())
                    .is_some_and(|p| p > 0),
            "holding owner changed during admission"
        );
    }
    Ok(())
}
fn available(path: &Path) -> Result<u64> {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let mut out = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(c.as_ptr(), out.as_mut_ptr()) } == 0,
        "holding restore statvfs failed"
    );
    let out = unsafe { out.assume_init() };
    out.f_bavail
        .checked_mul(out.f_frsize)
        .context("holding free-space overflow")
}
struct FloorWriter<'a> {
    file: &'a mut File,
    directory: &'a Path,
    minimum_free_bytes: u64,
}
impl Write for FloorWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let free = available(self.directory).map_err(std::io::Error::other)?;
        let required = self
            .minimum_free_bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| std::io::Error::other("holding reserve overflow"))?;
        if free < required {
            return Err(std::io::Error::other(
                "holding restore reached protected reserve",
            ));
        }
        self.file.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}
fn rename_noreplace(source: &Path, destination: &Path) -> Result<()> {
    let a = std::ffi::CString::new(source.as_os_str().as_encoded_bytes())?;
    let b = std::ffi::CString::new(destination.as_os_str().as_encoded_bytes())?;
    ensure!(
        unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                a.as_ptr(),
                libc::AT_FDCWD,
                b.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
        "holding destination conflict: {}",
        std::io::Error::last_os_error()
    );
    File::open(destination.parent().context("restore parent")?)?.sync_all()?;
    Ok(())
}
async fn restore(client: &Client, m: &Mapping, p: &Restore) -> Result<()> {
    let supplied: Mapping = serde_json::from_value(bound(&p.mapping)?)?;
    mapping(&supplied)?;
    ensure!(
        supplied.prefix == m.prefix && supplied.host == m.host,
        "restore mapping changed"
    );
    ensure!(
        p.schema == "jetstreamer-horizon-holding-restore-plan-v2",
        "foreign restore plan"
    );
    let c = bound(&p.custody)?;
    let (_, _, _, length) = custody(&c, m)?;
    // Restoration consumes space. A separate fresh admission remains mandatory.
    let a = bound(&p.admission)?;
    let minimum = a["minimum_free_bytes"]
        .as_u64()
        .context("restore reserve")?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    restore_admission(&a, minimum, now)?;
    ensure!(
        a["custody_sha256"] == p.custody.sha256 && a["restore_bytes"] == length,
        "restore admission covers different artifact"
    );
    restore_into(
        client,
        m,
        RestoreTarget {
            custody: &p.custody,
            content: &c,
            owners: &a,
            directory: Path::new(STATE).join("restores"),
            receipt_directory: Path::new(STATE).join("receipts"),
            minimum,
            genesis_probe: false,
        },
    )
    .await
}

fn genesis_probe_scope(c: &Value, minimum: u64) -> Result<()> {
    ensure!(
        c["sha256"] == GENESIS_PROBE_SHA
            && c["length"] == 20144
            && c["source"]
                == "/home/sol/.jetstreamer-private/holding-public-genesis-fixture-20261023-v1/genesis.tar.bz2"
            && minimum == GENESIS_PROBE_FLOOR,
        "root holding probe is restricted to the isolated public genesis fixture"
    );
    Ok(())
}

async fn restore_genesis_probe(client: &Client, m: &Mapping, p: &RestoreAdmission) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-horizon-holding-root-genesis-probe-plan-v2",
        "foreign root holding probe plan"
    );
    let supplied: Mapping = serde_json::from_value(bound(&p.mapping)?)?;
    mapping(&supplied)?;
    ensure!(
        supplied.host == m.host && supplied.prefix == m.prefix,
        "root holding probe mapping changed"
    );
    let c = bound(&p.custody)?;
    custody(&c, m)?;
    genesis_probe_scope(&c, GENESIS_PROBE_FLOOR)?;
    let completion = evidence(&p.capacity_completion, false)?;
    ensure!(
        completion["capacity_decision"]["capped186_budget"]["century_floor_bytes"]
            == GENESIS_PROBE_FLOOR,
        "root probe must retain the current accepted century floor"
    );
    let fleet: Bound = serde_json::from_value(completion["fleet"].clone())?;
    let f = evidence(&fleet, false)?;
    let owners: Vec<_> = fleet_owners(&f)?
        .into_iter()
        .map(|(unit, invocation_id)| json!({"unit":unit,"invocation_id":invocation_id}))
        .collect();
    let protected =
        completion["capacity_decision"]["capped186_budget"]["all_current_protected_bytes"]
            .as_u64()
            .context("root probe complete fleet budget missing")?
            .max(BASE_RESERVE);
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    // Reuse complete-fleet freshness/identity validation, but this is NOT an
    // admission to restore on home. No restored byte is written on that volume.
    let a = json!({"schema":"jetstreamer-horizon-holding-restore-admission-v2",
        "host":HOST,"restore_only":true,"all_live_growth_and_century_floor_protected":true,
        "capacity_completion":p.capacity_completion,"owners":owners,"recorded_unix_seconds":now});
    restore_admission(&a, protected, now)?;
    let root = Path::new(GENESIS_PROBE_ROOT);
    private(root)?;
    let directory = root.join("restores");
    let receipt_directory = root.join("receipts");
    private(&directory)?;
    private(&receipt_directory)?;
    ensure!(
        fs::symlink_metadata(root)?.dev() == fs::symlink_metadata("/")?.dev()
            && fs::symlink_metadata(root)?.dev() != fs::symlink_metadata(STATE)?.dev(),
        "root holding probe must use the separate OS filesystem"
    );
    ensure!(
        available(root)?
            >= GENESIS_PROBE_FLOOR
                .checked_add(20144)
                .context("probe space overflow")?,
        "OS volume cannot fit the fixed probe above its century-sized reserve"
    );
    restore_into(
        client,
        m,
        RestoreTarget {
            custody: &p.custody,
            content: &c,
            owners: &a,
            directory,
            receipt_directory,
            minimum: GENESIS_PROBE_FLOOR,
            genesis_probe: true,
        },
    )
    .await
}

struct RestoreTarget<'a> {
    custody: &'a Bound,
    content: &'a Value,
    owners: &'a Value,
    directory: PathBuf,
    receipt_directory: PathBuf,
    minimum: u64,
    genesis_probe: bool,
}

async fn restore_into(client: &Client, m: &Mapping, target: RestoreTarget<'_>) -> Result<()> {
    let RestoreTarget {
        custody: custody_binding,
        content: c,
        owners: a,
        directory,
        receipt_directory,
        minimum,
        genesis_probe,
    } = target;
    let (key, etag, sha, length) = custody(c, m)?;
    if genesis_probe {
        genesis_probe_scope(c, minimum)?;
    }
    let expected_owner = owner_bytes(m)?;
    ensure!(
        get_mutable_object(client, BUCKET, &format!("{}owner.json", m.prefix))
            .await?
            .is_some_and(|r| r.bytes == expected_owner),
        "holding restore owner missing or different"
    );
    let manifest_key = c["manifest_key"].as_str().context("holding manifest key")?;
    let manifest = get_mutable_object(client, BUCKET, manifest_key)
        .await?
        .context("holding manifest missing")?;
    ensure!(
        hex_lower(&Sha256::digest(&manifest.bytes)) == c["manifest_sha256"].as_str().unwrap()
            && serde_json::from_slice::<Value>(&manifest.bytes)? == c["manifest"],
        "remote holding manifest differs"
    );
    let remote = head_archive(client, BUCKET, &key)
        .await?
        .context("holding object missing")?;
    remote_matches(&remote, &key, length, &sha, Some(&etag))?;
    private(&directory)?;
    let destination = directory.join(format!("{sha}.blob"));
    let partial = directory.join(format!(".{sha}.partial"));
    if destination.try_exists()? {
        let id = regular_identity(&destination)?;
        ensure!(
            id.length == length
                && hash_and_etag(&destination, id, DEFAULT_PART_SIZE)?.sha256_hex == sha,
            "conflicting restored holding object"
        );
    } else {
        let mut file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&partial)
        {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&partial)?,
            Err(e) => return Err(e.into()),
        };
        let existing = regular_identity(&partial)?;
        let mode = file.metadata()?.mode() & 0o777;
        ensure!(
            existing == identity(&file.metadata()?)
                && existing.length <= length
                && file.metadata()?.uid() == 0
                && matches!(mode, 0o400 | 0o600),
            "unsafe partial holding restore"
        );
        let physical = file
            .metadata()?
            .blocks()
            .checked_mul(512)
            .context("partial block overflow")?;
        ensure!(
            available(&directory)?
                >= minimum
                    .checked_add(length - existing.length.min(physical))
                    .context("restore space overflow")?,
            "holding restore would consume protected space"
        );
        // Interrupted restores reuse one private partial, re-read from zero,
        // and verify every byte again. They never create another full copy.
        if mode == 0o400 {
            ensure!(
                existing.length == length
                    && hash_and_etag(&partial, existing, DEFAULT_PART_SIZE)?.sha256_hex == sha,
                "incomplete/conflicting sealed partial restore"
            );
        } else {
            file.seek(SeekFrom::Start(0))?;
            let mut guarded = FloorWriter {
                file: &mut file,
                directory: &directory,
                minimum_free_bytes: minimum,
            };
            read_remote_sha256_resumable(
                client,
                RemoteReadSpec {
                    bucket: BUCKET,
                    key: &key,
                    etag: &etag,
                    expected_length: length,
                    expected_sha256: &sha,
                    concurrency: 2,
                },
                &mut guarded,
            )
            .await?;
            file.set_len(length)?;
            file.sync_all()?;
            file.set_permissions(fs::Permissions::from_mode(0o400))?;
            file.sync_all()?;
        }
        restore_owners(a)?;
        ensure!(
            regular_identity(&partial)? == identity(&file.metadata()?),
            "holding partial changed before commit"
        );
        rename_noreplace(&partial, &destination)?;
    }
    let remote = head_archive(client, BUCKET, &key)
        .await?
        .context("holding object disappeared after restore")?;
    remote_matches(&remote, &key, length, &sha, Some(&etag))?;
    let proof = hash_and_etag(
        &destination,
        regular_identity(&destination)?,
        DEFAULT_PART_SIZE,
    )?;
    ensure!(proof.sha256_hex == sha, "restored holding digest differs");
    native_checksum(&remote, &proof, length)?;
    persist(
        &receipt_directory.join(format!("restore-{sha}.json")),
        &json!({
        "schema":if genesis_probe {"jetstreamer-horizon-holding-root-genesis-probe-v2"} else {"jetstreamer-horizon-holding-restore-v2"},"host":HOST,"custody":custody_binding,
        "object_key":key,"object_etag":etag,"length":length,"sha256":sha,"destination":destination,
        "remote_sha256_readback":true,"local_source_revalidated":true,
        "staging_only":true,"original_file_metadata":c["manifest"],
        "root_genesis_transport_probe_only":genesis_probe,"minimum_free_bytes":minimum,
        "capacity_completion":a["capacity_completion"],"owners":a["owners"],
        "local_retirement_authorized":false,"canonical_publication_authorized":false,
        "runtime_checkpoint_qualified":false,"job_resume_authorized":false,"replay_launch_authorized":false}),
    )?;
    Ok(())
}

pub(super) async fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 7 && args[3] == "--spec-sha256" && args[5] == "--self-sha256",
        "usage: holding-park|holding-restore|holding-admit-restore|holding-restore-genesis-probe|holding-inspect136|holding-disable136-retry|holding-check-retire136|holding-retire136|holding-diagnose185-references|holding-reconcile185-staged|holding-inspect185|holding-check-retire185|holding-retire185 SPEC --spec-sha256 HEX --self-sha256 HEX"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "holding requires sealed root orchestration"
    );
    let own = fs::read_link("/proc/self/exe")?;
    let md = fs::symlink_metadata(&own)?;
    ensure!(
        md.is_file()
            && md.uid() == 0
            && md.mode() & 0o222 == 0
            && hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == args[6],
        "holding executable not sealed/bound"
    );
    let spec = Bound {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let v = bound(&spec)?;
    let map: Bound = serde_json::from_value(v["mapping"].clone())?;
    let m: Mapping = serde_json::from_value(bound(&map)?)?;
    mapping(&m)?; // Must pass before credentials, listing or first remote write.
    private(Path::new(STATE))?;
    private(&Path::new(STATE).join("receipts"))?;
    let mut lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(Path::new(STATE).join("transition.lock"))?;
    use std::os::fd::AsRawFd;
    ensure!(
        lock.metadata()?.is_file()
            && lock.metadata()?.nlink() == 1
            && lock.metadata()?.uid() == 0
            && lock.metadata()?.mode() & 0o777 == 0o600
            && unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "holding transition is occupied"
    );
    // Keep the descriptor alive through all uploads, receipts and restoration.
    lock.flush()?;
    if args[1] == "holding-diagnose185-references" {
        return epoch185::diagnose(&m, &serde_json::from_value(v)?, &spec);
    }
    if args[1] == "holding-reconcile185-staged" {
        return epoch185::reconcile(&m,v,&spec);
    }
    if args[1] == "holding-inspect185" {
        return epoch185::inspect(&m, &serde_json::from_value(v)?, &spec);
    }
    if args[1] == "holding-inspect136" {
        return epoch136::inspect(&m, &serde_json::from_value(v)?, &spec);
    }
    if args[1] == "holding-disable136-retry" {
        return epoch136::disable_retry(&m, v, &spec);
    }
    if args[1] == "holding-admit-restore" {
        return admit_restore(&m, &serde_json::from_value(v)?, &spec);
    }
    let r2 = r2_config_from_env()?;
    ensure!(r2.bucket == BUCKET, "foreign holding bucket");
    let client = s3_client(&r2);
    match args[1].as_str() {
        "holding-park" => park(&client, &m, &serde_json::from_value(v)?).await,
        "holding-restore" => restore(&client, &m, &serde_json::from_value(v)?).await,
        "holding-restore-genesis-probe" => {
            restore_genesis_probe(&client, &m, &serde_json::from_value(v)?).await
        }
        "holding-check-retire185" => epoch185::retire_local(&client, &m, v, &spec, true).await,
        "holding-retire185" => epoch185::retire_local(&client, &m, v, &spec, false).await,
        "holding-check-retire136" => epoch136::retire_local(&client, &m, v, &spec, true).await,
        "holding-retire136" => epoch136::retire_local(&client, &m, v, &spec, false).await,
        _ => bail!("unsupported holding action"),
    }
}

#[cfg(test)]
#[path = "holding_tests.rs"]
mod tests;
