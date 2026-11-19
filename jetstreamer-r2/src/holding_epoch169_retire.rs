//! Exact old epoch169 local2 partial retirement after authenticated holding custody.
//! No canonical archive, publication or replay authority is derived here.
use super::*;
use serde_json::json;

const SOURCE: &str = "/home/sol/.jetstreamer-private/epoch169-standard-lane-20261109-v1/replacement-local2-20261110-v1/private/destination-99fd88ae3977469031317185e462e9adc14336d9b131d4b9afdcf5f5d91203fa/work/root-cohort-169-169/run-1123930-1794344387009889404/archives/epoch-169.jet";
const SHA: &str = "33f3b6d1622bb516ce90cc6a5b535038b2403b6056ddb15c49feaa0c70fb742f";
const LENGTH: u64 = 56_565_561_764;
const ALLOCATED: u64 = 56_565_645_312;
const ELIGIBILITY: &str =
    "/usr/local/lib/jetstreamer/horizon-closed169-local2-holding-plan-20261119-v1/eligibility.json";
const ELIGIBILITY_SHA: &str = "07a47c92e85c115d6ca33e1b9a79f5f3bbc2a8bdb7750b0aab0160c1eff92ec6";
const INSPECTION: &str =
    "/var/lib/jetstreamer/epoch169-local2-holding-review-20261119-v1/INSPECTION.json";
const INSPECTION_SHA: &str = "1e64267d9d34edd6faeda2d303e977395a5288754bfe3e60b6d087f2ed8cefa6";
const LANE: &str = "/home/sol/.jetstreamer-private/epoch169-standard-lane-20261109-v1";
const PRESERVED: &str = "/home/sol/.jetstreamer-private/epoch169-standard-lane-20261109-v1/replacement-local3retry3-20261110-v1/private/destination-38c4a95916e3838cfac5b3b009c534b860f6bbb242dc1c7889c59c38983a2596/work/root-cohort-169-169/run-3176567-1794619297050201147/archives/epoch-169.jet";
const SEED: &str = "/usr/local/lib/jetstreamer/horizon-original-slot-data-witness-set-20261118-v6/witness-set.json";
const SEED_SHA: &str = "8eb041519cba5c3f6368cb1432be9e289489ce1acdc28aa8b49f3d6ec7f382ee";
const PARK: &str = "horizon-closed169-local2-park-20261119-v1.service";
const PARK_IID: &str = "3bc22adcd63a4b3fa2bcddad22260e4c";
const QUARANTINE: &str = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/retirements/epoch169-local2-33f3b6d1622bb516ce90cc6a5b535038b2403b6056ddb15c49feaa0c70fb742f.jet";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Retire {
    schema: String,
    mapping: Bound,
    eligibility: Bound,
    custody: Bound,
    prior_check: Option<Bound>,
}

fn local_mutation_lock() -> Result<File> {
    let path = Path::new("/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock");
    let md = fs::symlink_metadata(path)?;
    ensure!(
        md.is_file()
            && md.dev() == 64512
            && md.ino() == 101135013
            && md.uid() == 1001
            && md.gid() == 1003
            && md.mode() & 0o7777 == 0o600
            && md.nlink() == 1
            && path.canonicalize()? == path,
        "169 shared local mutation lock changed"
    );
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    use std::os::fd::AsRawFd;
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "169 shared local mutation lock is occupied"
    );
    Ok(file)
}

fn source_identity(path: &Path) -> Result<FileIdentity> {
    let id = regular_identity(path)?;
    let md = fs::symlink_metadata(path)?;
    ensure!(
        id.device == 64512
            && id.inode == 105710021
            && id.length == LENGTH
            && md.uid() == 1001
            && md.gid() == 1003
            && md.mode() & 0o7777 == 0o600
            && md.nlink() == 1
            && md.blocks().checked_mul(512) == Some(ALLOCATED),
        "169 exact immutable source identity changed"
    );
    Ok(id)
}

fn terminal(unit: &str, iid: &str, result: &str) -> Result<Value> {
    let output = std::process::Command::new("/usr/bin/systemctl")
        .args(["show", unit, "-pId,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,Job,Result,ExecMainStatus,Restart,TriggeredBy"])
        .output()?;
    ensure!(output.status.success(), "169 terminal unit unavailable");
    let mut map = serde_json::Map::new();
    for line in String::from_utf8(output.stdout)?.lines() {
        let (key, value) = line.split_once('=').context("169 native unit row")?;
        ensure!(!map.contains_key(key), "duplicate 169 native property");
        map.insert(key.into(), json!(value));
    }
    let row = Value::Object(map);
    let closed = if result == "success" {
        (row["ActiveState"] == "inactive" && row["SubState"] == "dead")
            || (row["ActiveState"] == "active" && row["SubState"] == "exited")
    } else {
        row["ActiveState"] == "failed" && row["SubState"] == "failed"
    };
    ensure!(
        row["Id"] == unit
            && row["InvocationID"] == iid
            && closed
            && row["Result"] == result
            && row["ExecMainStatus"] == if result == "success" { "0" } else { "1" }
            && row["MainPID"] == "0"
            && row["ControlPID"] == "0"
            && row["Job"] == ""
            && row["Restart"] == "no"
            && row["TriggeredBy"] == "",
        "169 producer or holding unit is not the exact closed invocation"
    );
    Ok(row)
}

fn closed_owners() -> Result<Value> {
    let mut rows = Vec::new();
    for generation in ["local2", "local3retry3"] {
        for unit in [
            format!("horizon-qualify-169-replacement-{generation}-20261110-v1.service"),
            format!("horizon-guard-replacement-169-{generation}-20261110-v1.service"),
            format!("horizon-guard-replacement-169-{generation}-20261110-v1.timer"),
        ] {
            let output = std::process::Command::new("/usr/bin/systemctl")
                .args([
                    "show",
                    &unit,
                    "-pId,ActiveState,SubState,MainPID,ControlPID,Job,InvocationID",
                ])
                .output()?;
            ensure!(
                output.status.success() && output.stderr.is_empty(),
                "169 closed-owner query failed"
            );
            let mut fields = serde_json::Map::new();
            for line in String::from_utf8(output.stdout)?.lines() {
                let (k, v) = line.split_once('=').context("169 unit field")?;
                ensure!(
                    fields.insert(k.into(), json!(v)).is_none(),
                    "duplicate 169 native field"
                );
            }
            let v = Value::Object(fields);
            ensure!(
                v["Id"] == unit
                    && v["ActiveState"] == "inactive"
                    && v["SubState"] == "dead"
                    && v["Job"] == ""
                    && (v["MainPID"].is_null() || v["MainPID"] == "0")
                    && (v["ControlPID"].is_null() || v["ControlPID"] == "0"),
                "169 owner has restarted or remains queued"
            );
            rows.push(v);
        }
    }
    Ok(json!(rows))
}
fn protected_paths(seed: &Value, source: &Path, quarantine: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for slot in seed["slots"].as_array().context("witness slots")? {
        for member in slot["members"].as_array().context("witness members")? {
            let path = PathBuf::from(member.as_str().context("witness path")?);
            ensure!(
                path.is_absolute()
                    && !path.starts_with(source.parent().context("source parent")?)
                    && !path.starts_with(quarantine.parent().context("quarantine parent")?),
                "169 mutation would alter a live witness ancestor"
            );
            paths.push(path);
        }
    }
    ensure!(
        paths.len() == 12,
        "all twelve live witness members required"
    );
    Ok(paths)
}
fn preserved() -> Result<Value> {
    let seed = bound(&Bound {
        path: SEED.into(),
        sha256: SEED_SHA.into(),
    })?;
    let paths = protected_paths(&seed, Path::new(SOURCE), Path::new(QUARANTINE))?;
    let mut witnesses = Vec::new();
    for path in paths {
        let id = regular_identity(&path)?;
        witnesses.push(json!({"path":path,"identity":id}));
    }
    let id = regular_identity(Path::new(PRESERVED))?;
    let md = fs::symlink_metadata(PRESERVED)?;
    ensure!(
        id.device == 64512
            && id.inode == 105709699
            && id.length == 63_726_031_450
            && md.uid() == 1001
            && md.gid() == 1003
            && md.mode() & 0o7777 == 0o600
            && md.nlink() == 1
            && md.blocks() == 124465088,
        "newer169 retained partial differs"
    );
    Ok(json!({"newer_partial":id,"witnesses":witnesses}))
}
fn closure(path: &Path) -> Result<Value> {
    let owners = closed_owners()?;
    let park = terminal(PARK, PARK_IID, "success")?;
    let processes = no_references(Path::new(LANE))?;
    let quarantine_processes = no_references(path)?;
    let staged = jetstreamer_horizon_observe::dev_cache_check::sol_staged_path_references(path)?;
    ensure!(
        staged["references"] == json!([]),
        "169 source has staged relaunch references"
    );
    // Parent references could launch another reader of this retained run.
    let staged_parent = jetstreamer_horizon_observe::dev_cache_check::sol_staged_path_references(
        Path::new(SOURCE).parent().unwrap().parent().unwrap(),
    )?;
    ensure!(
        staged_parent["references"] == json!([]),
        "169 old run has staged consumers"
    );
    Ok(
        json!({"owners":owners,"park":park,"processes":processes,"quarantine_processes":quarantine_processes,
        "staged":staged,"staged_parent":staged_parent,"preserved":preserved()?}),
    )
}

fn exact_custody(c: &Value) -> Result<()> {
    ensure!(
        c["source"] == SOURCE
            && c["sha256"] == SHA
            && c["length"] == LENGTH
            && c["eligibility"]["path"] == ELIGIBILITY
            && c["eligibility"]["sha256"] == ELIGIBILITY_SHA
            && c["mapping"]["path"]
                == "/usr/local/lib/jetstreamer/horizon-node02-holding-20261023-v1/mapping.json"
            && c["manifest"]["uid"] == 1001
            && c["manifest"]["gid"] == 1003
            && c["manifest"]["mode"] == 0o600,
        "169 custody does not bind the exact closed source"
    );
    Ok(())
}

async fn remote(client: &Client, m: &Mapping, c: &Value) -> Result<RemoteArchive> {
    let (key, etag, sha, length) = custody(c, m)?;
    exact_custody(c)?;
    let owner = owner_bytes(m)?;
    ensure!(
        get_mutable_object(client, BUCKET, &format!("{}owner.json", m.prefix))
            .await?
            .is_some_and(|o| o.bytes == owner),
        "169 holding owner differs"
    );
    let manifest = get_mutable_object(
        client,
        BUCKET,
        c["manifest_key"].as_str().context("169 manifest key")?,
    )
    .await?
    .context("169 holding manifest absent")?;
    ensure!(
        hex_lower(&Sha256::digest(&manifest.bytes)) == c["manifest_sha256"]
            && serde_json::from_slice::<Value>(&manifest.bytes)? == c["manifest"],
        "169 holding manifest differs"
    );
    let blob = head_archive(client, BUCKET, &key)
        .await?
        .context("169 held blob absent")?;
    remote_matches(&blob, &key, length, &sha, Some(&etag))?;
    Ok(blob)
}

fn record(path: &Path) -> Result<Option<Value>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
        Ok(md) => {
            ensure!(
                md.is_file()
                    && md.uid() == 0
                    && md.nlink() == 1
                    && md.mode() & 0o222 == 0
                    && md.len() <= 1 << 20,
                "unsafe 169 transition record"
            );
            let id = regular_identity(path)?;
            let bytes = fs::read(path)?;
            ensure!(regular_identity(path)? == id, "169 record changed");
            Ok(Some(serde_json::from_slice(&bytes)?))
        }
    }
}

fn transition_shape(intent: bool, moved: bool, unlink: bool, complete: bool) -> Result<()> {
    ensure!(!moved || intent, "169 moved without intent");
    ensure!(!unlink || moved, "169 unlink without moved proof");
    ensure!(!complete || unlink, "169 completion without unlink intent");
    Ok(())
}

// Only this closed-input retirement uses the wider CPU envelope. Hash all three
// required digests over the same immutable part bytes, with at most three active
// hashers and one 64 MiB buffer. Preserve the ordinary proof's identity checks.
fn parallel_hash(path: &Path, expected: FileIdentity, part_size: u64) -> Result<LocalProof> {
    ensure!(
        part_size > 0 && part_size <= DEFAULT_PART_SIZE,
        "invalid bounded hash part size"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(
        identity(&file.metadata()?) == expected,
        "archive changed before hashing"
    );
    let mut whole = Sha256::new();
    let mut combined_md5 = Md5::new();
    let mut combined_sha256 = Sha256::new();
    let mut remaining = expected.length;
    let mut parts = 0u64;
    let mut buffer = vec![0u8; usize::try_from(part_size.min(remaining))?];
    while remaining > 0 {
        let count = usize::try_from(remaining.min(part_size))?;
        file.read_exact(&mut buffer[..count])?;
        let bytes = &buffer[..count];
        let (md5, sha256) = std::thread::scope(|scope| -> Result<_> {
            let whole_worker = scope.spawn(|| whole.update(bytes));
            let md5_worker = scope.spawn(|| Md5::digest(bytes));
            let part_sha256 = Sha256::digest(bytes);
            whole_worker
                .join()
                .map_err(|_| anyhow::anyhow!("whole-file hasher panicked"))?;
            let part_md5 = md5_worker
                .join()
                .map_err(|_| anyhow::anyhow!("part MD5 hasher panicked"))?;
            Ok((part_md5, part_sha256))
        })?;
        combined_md5.update(md5);
        combined_sha256.update(sha256);
        parts += 1;
        remaining -= count as u64;
    }
    ensure!(
        identity(&file.metadata()?) == expected,
        "archive changed while hashing"
    );
    ensure!(
        regular_identity(path)? == expected,
        "archive namespace changed while hashing"
    );
    Ok(LocalProof {
        sha256_hex: format!("{:x}", whole.finalize()),
        multipart_etag: format!("{:x}-{parts}", combined_md5.finalize()),
        composite_sha256: BASE64_STANDARD.encode(combined_sha256.finalize()),
    })
}

pub(super) async fn run(
    client: &Client,
    m: &Mapping,
    p: &Retire,
    spec: &Bound,
    check: bool,
) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-horizon-holding-retire169-plan-v1"
            && p.eligibility.path == Path::new(ELIGIBILITY)
            && p.eligibility.sha256 == ELIGIBILITY_SHA,
        "foreign 169 retirement scope"
    );
    let _mutation_lock = local_mutation_lock()?;
    let supplied: Mapping = serde_json::from_value(bound(&p.mapping)?)?;
    mapping(&supplied)?;
    ensure!(
        supplied.host == m.host && supplied.prefix == m.prefix,
        "169 mapping changed"
    );
    let e = bound(&p.eligibility)?;
    ensure!(
        e["schema"] == "jetstreamer-horizon-holding-eligibility-v2"
            && e["source"] == SOURCE
            && e["sha256"] == SHA
            && e["length"] == LENGTH
            && e["closed"] == true
            && e["canonical_archive"] == false
            && e["inspection"]["path"] == INSPECTION
            && e["inspection"]["sha256"] == INSPECTION_SHA,
        "169 closed eligibility changed"
    );
    let inspected = bound(&Bound {
        path:
            "/usr/local/lib/jetstreamer/horizon-holding169-retirement-20261119-v1/inspection.json"
                .into(),
        sha256: INSPECTION_SHA.into(),
    })?;
    ensure!(
        inspected["source"] == SOURCE
            && inspected["sha256"] == SHA
            && inspected["length"] == LENGTH
            && inspected["source_stable"] == true
            && inspected["native_consumers_clear"] == true
            && inspected["source_identity"][0] == 64512
            && inspected["source_identity"][1] == 105710021,
        "169 native source inspection differs"
    );
    let retained_before = preserved()?;
    let c = bound(&p.custody)?;
    ensure!(
        c["mapping"] == serde_json::to_value(&p.mapping)?
            && c["eligibility"] == serde_json::to_value(&p.eligibility)?,
        "169 custody plan bindings differ"
    );
    let _ = remote(client, m, &c).await?;
    let root = Path::new(STATE).join("retirements");
    private(&root)?;
    let source = Path::new(SOURCE);
    let quarantine = Path::new(QUARANTINE);
    let intent_path = root.join("epoch169-intent.json");
    let moved_path = root.join("epoch169-moved.json");
    let unlink_path = root.join("epoch169-unlink-intent.json");
    let completion_path = root.join("epoch169-completion.json");
    let descriptor = json!({"schema":"jetstreamer-holding-retire169-intent-v1",
        "source":SOURCE,"quarantine":QUARANTINE,"sha256":SHA,"length":LENGTH,
        "eligibility":p.eligibility,"custody":p.custody,"mapping":p.mapping,
        "canonical_archive":false,"remote_mutations":false,"r2_mutations":false});
    let expected_moved = json!({"schema":"jetstreamer-holding-retire169-moved-v1",
        "intent":descriptor,"local_sha256":SHA,
        "local_multipart_etag":c["object_etag"]});
    let expected_unlink = json!({"schema":"jetstreamer-holding-retire169-unlink-intent-v1",
        "moved":expected_moved,"authenticated_custody_revalidated":true});
    let expected_completion = json!({"schema":"jetstreamer-holding-retire169-completion-v1",
        "intent":descriptor,"source_absent":true,"quarantine_absent":true,
        "retired_censused_physical_bytes":ALLOCATED,"actual_free_delta_claimed":false,
        "authenticated_custody_revalidated":true,"remote_mutations":false,"r2_mutations":false});
    let old_intent = record(&intent_path)?;
    let old_moved = record(&moved_path)?;
    let old_unlink = record(&unlink_path)?;
    let old_completion = record(&completion_path)?;
    ensure!(
        old_intent.as_ref().is_none_or(|v| v == &descriptor),
        "169 intent differs"
    );
    ensure!(
        old_moved.as_ref().is_none_or(|v| v == &expected_moved),
        "169 moved proof differs"
    );
    ensure!(
        old_unlink.as_ref().is_none_or(|v| v == &expected_unlink),
        "169 unlink intent differs"
    );
    ensure!(
        old_completion
            .as_ref()
            .is_none_or(|v| v == &expected_completion),
        "169 completion differs"
    );
    transition_shape(
        old_intent.is_some(),
        old_moved.is_some(),
        old_unlink.is_some(),
        old_completion.is_some(),
    )?;
    ensure!(
        !old_moved.is_some() || !source.exists(),
        "169 moved record conflicts with original source"
    );
    ensure!(
        source.exists() || !quarantine.exists() || old_intent.is_some(),
        "169 quarantine has no durable intent"
    );
    let current = if source.exists() { source } else { quarantine };
    ensure!(
        old_completion.is_none() || !current.exists(),
        "169 source reappeared after completion"
    );
    if old_completion.is_some() {
        println!("{}", completion_path.display());
        return Ok(());
    }
    if current.exists() {
        ensure!(
            !(source.exists() && quarantine.exists()),
            "169 duplicate transition source"
        );
        let id = source_identity(current)?;
        let proof = parallel_hash(current, id, DEFAULT_PART_SIZE)?;
        ensure!(
            proof.sha256_hex == SHA && proof.multipart_etag == c["object_etag"],
            "169 local source differs from authenticated custody"
        );
        let _ = closure(current)?;
        let _ = remote(client, m, &c).await?;
    } else {
        ensure!(
            old_unlink.is_some(),
            "169 source absent without unlink intent"
        );
    }
    let check_path = Path::new(STATE)
        .join("receipts")
        .join(format!("retire169-check-{}.json", spec.sha256));
    if check {
        ensure!(
            p.prior_check.is_none() && current.exists(),
            "169 check requires original source"
        );
        persist(
            &check_path,
            &json!({"schema":"jetstreamer-holding-retire169-check-v1",
            "descriptor":descriptor,"checked":true,"data_removed":false,
            "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()}),
        )?;
        println!("{}", check_path.display());
        return Ok(());
    }
    let prior = bound(
        p.prior_check
            .as_ref()
            .context("169 retirement requires prior check")?,
    )?;
    let at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        prior["schema"] == "jetstreamer-holding-retire169-check-v1"
            && prior["descriptor"] == descriptor
            && prior["checked"] == true
            && prior["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t <= at && at - t <= 900),
        "169 prior check stale or foreign"
    );
    if old_intent.is_none() {
        persist(&intent_path, &descriptor)?;
    }
    if current == source {
        ensure!(
            preserved()? == retained_before,
            "retained witness or newer partial changed before rename"
        );
        rename_noreplace(source, quarantine)?;
        ensure!(
            preserved()? == retained_before,
            "retained witness or newer partial changed after rename"
        );
        source_identity(quarantine)?;
    }
    if quarantine.exists() {
        let id = source_identity(quarantine)?;
        let proof = parallel_hash(quarantine, id, DEFAULT_PART_SIZE)?;
        ensure!(
            proof.sha256_hex == SHA && proof.multipart_etag == c["object_etag"],
            "169 quarantined bytes differ"
        );
        ensure!(
            proof.sha256_hex == expected_moved["local_sha256"]
                && proof.multipart_etag == expected_moved["local_multipart_etag"],
            "169 moved local proof differs"
        );
        if old_moved.is_none() {
            persist(&moved_path, &expected_moved)?;
        }
        let _ = closure(quarantine)?;
        let _ = remote(client, m, &c).await?;
        if old_unlink.is_none() {
            persist(&unlink_path, &expected_unlink)?;
        }
        ensure!(
            !source.exists() && source_identity(quarantine)? == id,
            "169 source reappeared or quarantine replaced"
        );
        ensure!(
            preserved()? == retained_before,
            "retained witness or newer partial changed before unlink"
        );
        fs::remove_file(quarantine)?;
        File::open(root)?.sync_all()?;
    }
    ensure!(
        !source.exists() && !quarantine.exists(),
        "169 local source remains"
    );
    ensure!(
        preserved()? == retained_before,
        "retained witness or newer partial changed after unlink"
    );
    let _ = remote(client, m, &c).await?;
    if old_completion.is_none() {
        persist(&completion_path, &expected_completion)?;
    }
    println!("{}", completion_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parallel_proof_matches_serial_across_part_boundaries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input");
        for length in [0, 1, 63, 64, 65, 1007, 65537] {
            let bytes: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
            fs::write(&path, &bytes).unwrap();
            let id = regular_identity(&path).unwrap();
            for part_size in [63, 64, 1007, 65536, DEFAULT_PART_SIZE] {
                let serial = hash_and_etag(&path, id, part_size).unwrap();
                let parallel = parallel_hash(&path, id, part_size).unwrap();
                assert_eq!(parallel.sha256_hex, serial.sha256_hex);
                assert_eq!(parallel.multipart_etag, serial.multipart_etag);
                assert_eq!(parallel.composite_sha256, serial.composite_sha256);
                assert_eq!(parallel.sha256_hex, format!("{:x}", Sha256::digest(&bytes)));
            }
        }
        let id = regular_identity(&path).unwrap();
        assert!(parallel_hash(&path, id, 0).is_err());
        assert!(parallel_hash(&path, id, DEFAULT_PART_SIZE + 1).is_err());
        fs::write(&path, b"changed").unwrap();
        assert!(parallel_hash(&path, id, DEFAULT_PART_SIZE).is_err());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(parallel_hash(&link, regular_identity(&path).unwrap(), DEFAULT_PART_SIZE).is_err());
    }

    #[test]
    #[ignore = "bounded native throughput qualification; 128 MiB temporary input"]
    fn parallel_hash_throughput() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input");
        let bytes: Vec<u8> = (0..128usize * 1024 * 1024)
            .map(|i| (i % 251) as u8)
            .collect();
        fs::write(&path, &bytes).unwrap();
        let id = regular_identity(&path).unwrap();
        for round in 0..3 {
            let start = std::time::Instant::now();
            let serial = hash_and_etag(&path, id, DEFAULT_PART_SIZE).unwrap();
            let serial_seconds = start.elapsed().as_secs_f64();
            let start = std::time::Instant::now();
            let parallel = parallel_hash(&path, id, DEFAULT_PART_SIZE).unwrap();
            let parallel_seconds = start.elapsed().as_secs_f64();
            assert_eq!(serial.sha256_hex, parallel.sha256_hex);
            assert_eq!(serial.multipart_etag, parallel.multipart_etag);
            assert_eq!(serial.composite_sha256, parallel.composite_sha256);
            println!(
                "{}",
                json!({"round":round,"bytes":id.length,"serial_seconds":serial_seconds,
                "parallel_seconds":parallel_seconds,"all_three_digests_match":true})
            );
        }
    }

    #[test]
    fn retirement_accepts_the_manifest_written_by_the_holding_producer() {
        let mapping = Mapping {
            schema: "jetstreamer-horizon-host-holding-prefix-v2".into(),
            host: HOST.into(),
            prefix: "node_02/".into(),
            user_provided_prefix: true,
            authorization_reference: "test fixture".into(),
        };
        let plan = Park {
            schema: "jetstreamer-horizon-holding-park-plan-v2".into(),
            mapping: Bound {
                path: "/usr/local/lib/jetstreamer/horizon-node02-holding-20261023-v1/mapping.json"
                    .into(),
                sha256: "a".repeat(64),
            },
            eligibility: Bound {
                path: ELIGIBILITY.into(),
                sha256: ELIGIBILITY_SHA.into(),
            },
            source: SOURCE.into(),
            length: LENGTH,
            sha256: SHA.into(),
        };
        let manifest: Value = serde_json::from_slice(
            &manifest_bytes(
                &mapping,
                &plan,
                &object_key(&mapping, SHA).unwrap(),
                1001,
                1003,
                0o100600,
            )
            .unwrap(),
        )
        .unwrap();
        let mut receipt = json!({"source":SOURCE,"sha256":SHA,"length":LENGTH,
            "eligibility":plan.eligibility,"mapping":plan.mapping,"manifest":manifest});
        exact_custody(&receipt).unwrap();
        for bad_mode in [0o100600, 0o444, 0o644, 0o400] {
            receipt["manifest"]["mode"] = json!(bad_mode);
            assert!(exact_custody(&receipt).is_err());
        }
    }

    #[test]
    fn retention_scope_rejects_any_live_witness_namespace_mutation() {
        let mut v = json!({"slots":[{"members":(0..12).map(|i|format!("/tmp/keep/p{i}")).collect::<Vec<_>>()}]});
        protected_paths(&v, Path::new(SOURCE), Path::new(QUARANTINE)).unwrap();
        v["slots"][0]["members"][0] = json!(SOURCE);
        assert!(protected_paths(&v, Path::new(SOURCE), Path::new(QUARANTINE)).is_err());
        v["slots"][0]["members"][0] = json!(Path::new(SOURCE).parent().unwrap().join("sibling"));
        assert!(protected_paths(&v, Path::new(SOURCE), Path::new(QUARANTINE)).is_err());
        v["slots"][0]["members"][0] = json!(QUARANTINE);
        assert!(protected_paths(&v, Path::new(SOURCE), Path::new(QUARANTINE)).is_err());
        v["slots"][0]["members"].as_array_mut().unwrap().remove(0);
        assert!(protected_paths(&v, Path::new(SOURCE), Path::new(QUARANTINE)).is_err());
    }

    #[test]
    fn retirement_markers_require_durable_predecessors() {
        for (intent, moved, unlink, complete) in [
            (false, false, false, false),
            (true, false, false, false),
            (true, true, false, false),
            (true, true, true, false),
            (true, true, true, true),
        ] {
            transition_shape(intent, moved, unlink, complete).unwrap();
        }
        for state in [
            (false, true, false, false),
            (true, false, true, false),
            (true, true, false, true),
        ] {
            assert!(transition_shape(state.0, state.1, state.2, state.3).is_err());
        }
    }
}
