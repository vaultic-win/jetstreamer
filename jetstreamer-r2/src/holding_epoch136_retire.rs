//! Exact failed 136 partial retirement after authenticated cold custody. This is
//! not canonical archive retirement or a portable runtime checkpoint.
use super::*;

const ARTIFACT_SHA: &str = "2122223b4e468bbd97cdf4562f2c079f4dcbcb81515152f781730af5bb47540f";
const ARTIFACT_ETAG: &str = "2ac69e5548618a7a92e60dfedf0a0de6-1486";
const INSPECTION: &str =
    "/usr/local/lib/jetstreamer/horizon-node02-holding-epoch136-20261023-v1/eligibility.json";
const INSPECTION_SHA: &str = "52706b06140a65c6495bebce32ecdcb93daa791585a1596133cd09000afa3572";
const MASK_ROOT: &str =
    "/var/lib/jetstreamer/horizon-terminal136-controller-retirement-20261023-v1";
const CONFIG_SHA: &str = "104025f3fec6c25b011415802c4c53ce54c4c2b0d5d93a1882e908177d16148a";
const QUARANTINE: &str = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/retirements/epoch136-2122223b4e468bbd97cdf4562f2c079f4dcbcb81515152f781730af5bb47540f.partial";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Retire {
    schema: String,
    mapping: Bound,
    terminal: Bound,
    qualification: Bound,
    inspection: Bound,
    custody: Bound,
    controller_mask: Bound,
    capacity_completion: Bound,
    prior_check: Option<Bound>,
}

fn scope(p: &Retire, m: &Mapping, e: &Value, c: &Value) -> Result<FileIdentity> {
    ensure!(
        p.schema == "jetstreamer-horizon-holding-retire136-plan-v2"
            && p.inspection.path == Path::new(INSPECTION)
            && p.inspection.sha256 == INSPECTION_SHA
            && p.controller_mask.path == Path::new(MASK_ROOT).join("completion.json"),
        "foreign 136 partial retirement scope"
    );
    let (_, etag, sha, length) = custody(c, m)?;
    ensure!(
        sha == ARTIFACT_SHA
            && etag == ARTIFACT_ETAG
            && length == LENGTH
            && c["source"] == SOURCE
            && c["mapping"] == serde_json::to_value(&p.mapping)?
            && c["eligibility"] == serde_json::to_value(&p.inspection)?
            && c["manifest"]["uid"] == 1001
            && c["manifest"]["gid"] == 1003
            && c["manifest"]["mode"] == 0o600
            && e["schema"] == "jetstreamer-horizon-holding-eligibility-v2"
            && e["host"] == HOST
            && e["epoch"] == 136
            && e["source"] == SOURCE
            && e["length"] == LENGTH
            && e["sha256"] == ARTIFACT_SHA
            && e["multipart_etag"] == ARTIFACT_ETAG
            && e["closed"] == true
            && e["artifact_kind"] == "retained-failed-partial-archive"
            && e["canonical_archive"] == false
            && e["local_retirement_authorized"] == false
            && e["failure_repaired"] == false
            && e["job_resume_authorized"] == false
            && e["original_failure"]["path"] == FAILURE
            && e["original_failure"]["sha256"] == FAILURE_SHA,
        "136 retirement requires the exact failed partial and whole-readback holding custody"
    );
    let old = &e["source_identity"];
    ensure!(
        old["device"] == 64512
            && old["inode"] == 99352633
            && old["length"] == LENGTH
            && old["links"] == 1
            && old["uid"] == 1001
            && old["gid"] == 1003
            && old["mode"] == 0o600
            && old["mtime_seconds"] == 1792326715
            && old["mtime_nanoseconds"] == 284967280
            && old["ctime_seconds"] == 1792326715
            && old["ctime_nanoseconds"] == 284967280,
        "136 inspection identity differs"
    );
    Ok(FileIdentity {
        device: 64512,
        inode: 99352633,
        length: LENGTH,
        modified_seconds: 1792326715,
        modified_nanoseconds: 284967280,
    })
}

fn masked(p: &Retire) -> Result<Value> {
    let proof = bound(&p.controller_mask)?;
    ensure!(
        proof["schema"] == "jetstreamer-terminal136-controller-retirement-v2"
            && proof["host"] == HOST
            && proof["controller"] == CONTROLLER
            && proof["masked"] == true
            && proof["original_bytes_retained"] == true
            && proof["config_sha256"] == CONFIG_SHA
            && proof["replay_data_removed"] == false
            && proof["producer_signalled"] == false
            && proof["remote_mutations"] == false
            && proof["retained"].as_str()
                == Some(
                    Path::new(MASK_ROOT)
                        .join("original-controller.service.txt")
                        .to_str()
                        .unwrap()
                ),
        "136 obsolete controller has no exact configuration retirement proof"
    );
    let intent = Bound {
        path: Path::new(MASK_ROOT).join("intent.json"),
        sha256: proof["intent_sha256"]
            .as_str()
            .context("136 mask intent digest")?
            .into(),
    };
    let intent = bound(&intent)?;
    ensure!(
        intent["schema"] == "jetstreamer-terminal136-controller-retirement-intent-v2"
            && intent["operation"] == "copy-config-and-atomic-mask-exchange"
            && intent["controller"] == CONTROLLER
            && intent["config_sha256"] == CONFIG_SHA,
        "136 mask intent differs"
    );
    let config = Path::new(MASK_ROOT).join("original-controller.service.txt");
    let id = regular_identity(&config)?;
    let md = fs::symlink_metadata(&config)?;
    ensure!(
        config.canonicalize()? == config
            && md.uid() == 0
            && md.mode() & 0o222 == 0
            && md.nlink() == 1
            && id.length <= 1 << 20
            && hex_lower(&Sha256::digest(fs::read(&config)?)) == CONFIG_SHA
            && regular_identity(&config)? == id,
        "136 original configuration is not retained"
    );
    let original = Path::new("/etc/systemd/system").join(CONTROLLER);
    ensure!(
        fs::symlink_metadata(&original)?.file_type().is_symlink()
            && fs::read_link(&original)? == Path::new("/dev/null"),
        "136 controller mask disappeared"
    );
    let controller = terminal_unit(CONTROLLER)?;
    ensure!(
        controller["LoadState"] == "masked",
        "136 old controller is not masked in manager"
    );
    let producer = terminal_unit(PRODUCER)?;
    Ok(json!({"proof":p.controller_mask,"controller":controller,"producer":producer}))
}

fn no_replacement(f: &Value) -> Result<()> {
    let rows = f["epochs"].as_array().context("136 fleet epoch census")?;
    let rows: Vec<_> = rows.iter().filter(|r| r["epoch"] == 136).collect();
    ensure!(
        rows.len() == 1
            && matches!(
                rows[0]["state"].as_str(),
                Some("failed-needs-repair" | "blocked-qualification")
            ),
        "136 has a replacement, delivery stage or ready archive"
    );
    ensure!(
        !f["active"]
            .as_array()
            .context("136 fleet active census")?
            .iter()
            .any(|r| r["epoch"] == 136),
        "136 active replacement owner exists"
    );
    for key in ["diagnostics", "pipelines"] {
        ensure!(
            !f[key]
                .as_array()
                .context("136 downstream census")?
                .iter()
                .any(|r| {
                    r["live"] == true
                        && (r["epoch"] == 136
                            || r["scope_first_epoch"]
                                .as_u64()
                                .zip(r["scope_last_epoch"].as_u64())
                                .is_some_and(|(first, last)| first <= 136 && last >= 136))
                }),
            "136 live replacement/downstream stage exists"
        );
    }
    Ok(())
}

fn basis(p: &Retire) -> Result<Value> {
    let c = evidence(&p.capacity_completion, false)?;
    let fb: Bound = serde_json::from_value(c["fleet"].clone())?;
    let f = evidence(&fb, false)?;
    no_replacement(&f)?;
    let owners: Vec<_> = fleet_owners(&f)?
        .into_iter()
        .map(|(unit, invocation_id)| json!({"unit":unit,"invocation_id":invocation_id}))
        .collect();
    let minimum = c["capacity_decision"]["capped186_budget"]["all_current_protected_bytes"]
        .as_u64()
        .context("136 complete protection basis")?
        .max(BASE_RESERVE);
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    // Read-only reuse of complete-fleet freshness, latest-ledger and owner
    // validation. Retirement allocates no archive and grants no restore budget.
    let view = json!({"schema":"jetstreamer-horizon-holding-restore-admission-v2","host":HOST,
        "restore_only":true,"all_live_growth_and_century_floor_protected":true,
        "recorded_unix_seconds":now,"capacity_completion":p.capacity_completion,"owners":owners});
    restore_admission(&view, minimum, now)?;
    let names = f["unit_census"]
        .as_object()
        .context("136 complete unit census")?
        .keys()
        .cloned()
        .collect();
    let current = fleet::census(&names, 101, 200)?;
    for (name, unit) in &current {
        if unit["ActiveState"] == "activating"
            || unit["MainPID"]
                .as_str()
                .and_then(|p| p.parse::<u64>().ok())
                .is_some_and(|p| p > 0)
        {
            let old = &f["unit_census"][name];
            ensure!(
                old["InvocationID"] == unit["InvocationID"]
                    && old["MainPID"] == unit["MainPID"]
                    && old["NRestarts"] == unit["NRestarts"]
                    && unit["NRestarts"] == "0",
                "live campaign owner changed since 136 retirement basis"
            );
        }
    }
    Ok(
        json!({"capacity_completion":p.capacity_completion,"fleet":fb,"current_unit_census":current}),
    )
}

fn no_sidecars() -> Result<()> {
    for suffix in ["jet.sha256", "sha256"] {
        ensure!(
            fs::symlink_metadata(Path::new(SOURCE).with_extension(suffix))
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "136 partial has a canonical sidecar or unreadable adjacent path"
        );
    }
    Ok(())
}

fn references(p: &Retire) -> Result<Value> {
    let mask = masked(p)?;
    no_sidecars()?;
    let processes = no_references(Path::new(LANE))?;
    let quarantine_processes = no_references(Path::new(QUARANTINE))?;
    let staged =
        jetstreamer_horizon_observe::dev_cache_check::sol_staged_path_references(Path::new(LANE))?;
    let quarantine_staged =
        jetstreamer_horizon_observe::dev_cache_check::sol_staged_path_references(
            Path::new(QUARANTINE)
                .parent()
                .context("136 quarantine parent")?,
        )?;
    ensure!(
        staged["references"] == json!([]) && quarantine_staged["references"] == json!([]),
        "136 partial still has staged consumers"
    );
    Ok(
        json!({"mask":mask,"processes":processes,"quarantine_processes":quarantine_processes,
            "staged":staged,"quarantine_staged":quarantine_staged}),
    )
}

async fn remote(client: &Client, m: &Mapping, c: &Value) -> Result<RemoteArchive> {
    let (key, etag, sha, length) = custody(c, m)?;
    let owner = owner_bytes(m)?;
    ensure!(
        get_mutable_object(client, BUCKET, &format!("{}owner.json", m.prefix))
            .await?
            .is_some_and(|o| o.bytes == owner),
        "136 holding owner differs"
    );
    let manifest = get_mutable_object(
        client,
        BUCKET,
        c["manifest_key"].as_str().context("136 manifest key")?,
    )
    .await?
    .context("136 holding manifest absent")?;
    ensure!(
        hex_lower(&Sha256::digest(&manifest.bytes)) == c["manifest_sha256"].as_str().unwrap()
            && serde_json::from_slice::<Value>(&manifest.bytes)? == c["manifest"],
        "136 holding manifest differs"
    );
    let blob = head_archive(client, BUCKET, &key)
        .await?
        .context("136 held blob absent")?;
    remote_matches(&blob, &key, length, &sha, Some(&etag))?;
    ensure!(
        head_archive(client, BUCKET, "epoch-136.jet")
            .await?
            .is_none()
            && get_mutable_object(client, BUCKET, "epoch-136.jet.sha256")
                .await?
                .is_none(),
        "136 canonical delivery appeared; reconcile before partial retirement"
    );
    Ok(blob)
}

#[derive(Debug, Eq, PartialEq)]
enum LocalState {
    Original,
    Quarantined,
    Absent,
}

fn maybe_identity(path: &Path) -> Result<Option<FileIdentity>> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            ensure!(
                path.canonicalize()? == path,
                "136 local lifecycle path is aliased"
            );
            Ok(Some(regular_identity(path)?))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn local_state(
    source: &Path,
    quarantine: &Path,
    expected: FileIdentity,
    intent: bool,
    unlink_intent: bool,
) -> Result<LocalState> {
    ensure!(intent, "136 retirement has no matching durable intent");
    match (maybe_identity(source)?, maybe_identity(quarantine)?) {
        (Some(id), None) => {
            ensure!(id == expected, "136 source identity changed");
            Ok(LocalState::Original)
        }
        (None, Some(id)) => {
            ensure!(id == expected, "136 quarantine identity changed");
            Ok(LocalState::Quarantined)
        }
        (None, None) => {
            ensure!(
                unlink_intent,
                "unexplained 136 local absence before unlink intent"
            );
            Ok(LocalState::Absent)
        }
        (Some(_), Some(_)) => bail!("conflicting 136 source and quarantine both exist"),
    }
}

fn stage(source: &Path, quarantine: &Path, expected: FileIdentity) -> Result<()> {
    private(quarantine.parent().context("136 quarantine parent")?)?;
    ensure!(
        regular_identity(source)? == expected,
        "136 source changed before quarantine"
    );
    ensure!(
        fs::metadata(source.parent().context("136 source parent")?)?.dev()
            == fs::metadata(quarantine.parent().unwrap())?.dev(),
        "136 quarantine must share source filesystem"
    );
    rename_noreplace(source, quarantine)?;
    File::open(source.parent().unwrap())?.sync_all()?;
    ensure!(
        regular_identity(quarantine)? == expected,
        "136 quarantined identity differs"
    );
    Ok(())
}

fn verified_quarantine(
    path: &Path,
    expected: FileIdentity,
    sha: &str,
    etag: &str,
) -> Result<LocalProof> {
    ensure!(
        regular_identity(path)? == expected,
        "136 quarantine changed"
    );
    let proof = hash_and_etag(path, expected, DEFAULT_PART_SIZE)?;
    ensure!(
        proof.sha256_hex == sha && proof.multipart_etag == etag,
        "136 quarantined bytes differ from held custody"
    );
    Ok(proof)
}

fn unlink(source: &Path, quarantine: &Path, expected: FileIdentity) -> Result<()> {
    private(quarantine.parent().context("136 quarantine parent")?)?;
    ensure!(
        maybe_identity(source)?.is_none(),
        "136 source reappeared; preserve both copies"
    );
    ensure!(
        regular_identity(quarantine)? == expected,
        "136 quarantine replaced before unlink"
    );
    fs::remove_file(quarantine)?;
    File::open(quarantine.parent().unwrap())?.sync_all()?;
    ensure!(
        maybe_identity(quarantine)?.is_none(),
        "136 quarantine remains after unlink"
    );
    Ok(())
}

fn read_record(path: &Path) -> Result<Option<Value>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
        Ok(md) => {
            ensure!(
                md.uid() == unsafe { libc::geteuid() }
                    && md.mode() & 0o222 == 0
                    && md.nlink() == 1
                    && path.canonicalize()? == path
                    && md.len() <= 1 << 20,
                "unsafe 136 transition record"
            );
            let id = regular_identity(path)?;
            let bytes = fs::read(path)?;
            ensure!(
                regular_identity(path)? == id,
                "136 transition record changed during read"
            );
            Ok(Some(serde_json::from_slice(&bytes)?))
        }
    }
}

fn exact_record(path: &Path, descriptor: &Value) -> Result<bool> {
    if let Some(record) = read_record(path)? {
        ensure!(
            record == *descriptor,
            "136 transition record conflicts with exact custody"
        );
        Ok(true)
    } else {
        Ok(false)
    }
}

fn marker_chain(intent: bool, moved: bool, unlink: bool, completion: bool) -> Result<()> {
    ensure!(!moved || intent, "136 moved record has no parent intent");
    ensure!(
        !unlink || moved,
        "136 unlink intent lacks verified moved bytes"
    );
    ensure!(
        !completion || unlink,
        "136 completion lacks a prior unlink intent"
    );
    Ok(())
}

fn moved_record(descriptor: &Value, expected: FileIdentity, proof: &LocalProof) -> Value {
    json!({"schema":"jetstreamer-holding-retire136-moved-v2","intent":descriptor,
        "quarantine_identity":{"device":expected.device,"inode":expected.inode,"length":expected.length,
        "mtime_seconds":expected.modified_seconds,"mtime_nanoseconds":expected.modified_nanoseconds},
        "local_sha256":proof.sha256_hex,"local_multipart_etag":proof.multipart_etag,
        "local_composite_sha256":proof.composite_sha256})
}

fn moved_proof(
    record: &Value,
    descriptor: &Value,
    expected: FileIdentity,
    sha: &str,
    etag: &str,
) -> Result<LocalProof> {
    let composite = record["local_composite_sha256"]
        .as_str()
        .context("136 retained composite proof")?;
    let proof = LocalProof {
        sha256_hex: sha.into(),
        multipart_etag: etag.into(),
        composite_sha256: composite.into(),
    };
    ensure!(
        BASE64_STANDARD.decode(composite)?.len() == 32
            && moved_record(descriptor, expected, &proof) == *record,
        "136 moved proof is foreign or incomplete"
    );
    Ok(proof)
}

fn record_sha(path: &Path) -> Result<String> {
    ensure!(
        read_record(path)?.is_some(),
        "136 transition record is absent"
    );
    let id = regular_identity(path)?;
    let bytes = read_stable_bounded(path, 1 << 20, "136 transition bytes")?;
    ensure!(
        regular_identity(path)? == id,
        "136 transition bytes changed"
    );
    Ok(hex_lower(&Sha256::digest(&bytes)))
}

fn unlink_record(descriptor: &Value, moved_sha: &str) -> Value {
    json!({"schema":"jetstreamer-holding-retire136-unlink-intent-v2","intent":descriptor,
        "moved_sha256":moved_sha,"authenticated_custody_revalidated":true})
}

fn completed_record(descriptor: &Value, unlink: &Value, inspection: &Value) -> Value {
    json!({"schema":"jetstreamer-holding-retire136-completion-v2","intent":descriptor,
        "unlink_intent":unlink,"source_absent":true,"quarantine_absent":true,
        "retired_censused_physical_bytes":inspection["source_identity"]["physical_bytes"],
        "actual_free_space_delta_claimed":false,"authenticated_custody_revalidated":true,
        "failure_repaired":false,"canonical_archive":false,"runtime_checkpoint_qualified":false,
        "job_resume_authorized":false,"replay_launch_authorized":false,"publication_authorized":false,
        "remote_mutations":false,"r2_mutations":false})
}

fn original_permissions(path: &Path) -> Result<()> {
    let md = fs::symlink_metadata(path)?;
    ensure!(
        md.uid() == 1001 && md.gid() == 1003 && md.mode() & 0o7777 == 0o600 && md.nlink() == 1,
        "136 partial permissions or links changed"
    );
    Ok(())
}

pub(super) async fn run(
    client: &Client,
    m: &Mapping,
    p: &Retire,
    spec: &Bound,
    check: bool,
) -> Result<()> {
    let supplied: Mapping = serde_json::from_value(bound(&p.mapping)?)?;
    mapping(&supplied)?;
    ensure!(
        supplied.host == m.host && supplied.prefix == m.prefix,
        "136 retirement mapping changed"
    );
    let common = Inspect {
        schema: "jetstreamer-horizon-holding-inspect136-plan-v2".into(),
        mapping: p.mapping.clone(),
        terminal: p.terminal.clone(),
        qualification: p.qualification.clone(),
    };
    super::scope(&common, m, &bound(&p.terminal)?, &bound(&p.qualification)?)?;
    let inspection = bound(&p.inspection)?;
    let c = bound(&p.custody)?;
    let expected = scope(p, m, &inspection, &c)?;
    let _ = basis(p)?;
    let _ = references(p)?;
    let remote_before = remote(client, m, &c).await?;
    let root = Path::new(STATE).join("retirements");
    private(&root)?;
    ensure!(
        fs::metadata(&root)?.dev() == expected.device,
        "136 quarantine is on another filesystem"
    );
    let descriptor = json!({"schema":"jetstreamer-holding-retire136-intent-v2","host":HOST,
        "epoch":136,"source":SOURCE,"quarantine":QUARANTINE,"sha256":ARTIFACT_SHA,"length":LENGTH,
        "multipart_etag":ARTIFACT_ETAG,"source_identity":inspection["source_identity"],
        "mapping":p.mapping,"custody":p.custody,"inspection":p.inspection,"terminal":p.terminal,
        "qualification":p.qualification,"controller_mask":p.controller_mask,
        "canonical_archive":false,"failure_repaired":false,"runtime_checkpoint_qualified":false,
        "job_resume_authorized":false,"replay_launch_authorized":false,"publication_authorized":false,
        "remote_mutations":false,"r2_mutations":false});
    let intent = root.join("epoch136-intent.json");
    let moved = root.join("epoch136-moved.json");
    let unlink_intent = root.join("epoch136-unlink-intent.json");
    let completion = root.join("epoch136-completion.json");
    let recorded_intent = exact_record(&intent, &descriptor)?;
    let old_moved = read_record(&moved)?;
    if let Some(record) = &old_moved {
        let proof = moved_proof(record, &descriptor, expected, ARTIFACT_SHA, ARTIFACT_ETAG)?;
        native_checksum(&remote_before, &proof, LENGTH)?;
    }
    let old_unlink = read_record(&unlink_intent)?;
    if let Some(record) = &old_unlink {
        ensure!(
            old_moved.is_some() && *record == unlink_record(&descriptor, &record_sha(&moved)?),
            "136 unlink intent differs"
        );
    }
    let old_completion = read_record(&completion)?;
    if let Some(record) = &old_completion {
        ensure!(
            *record
                == completed_record(
                    &descriptor,
                    old_unlink
                        .as_ref()
                        .context("136 completion without unlink intent")?,
                    &inspection
                ),
            "136 completion differs"
        );
    }
    marker_chain(
        recorded_intent,
        old_moved.is_some(),
        old_unlink.is_some(),
        old_completion.is_some(),
    )?;
    let original = maybe_identity(Path::new(SOURCE))?;
    let quarantine = maybe_identity(Path::new(QUARANTINE))?;
    if !recorded_intent {
        ensure!(
            original == Some(expected) && quarantine.is_none(),
            "136 source absent or conflicting before first intent"
        );
        let failure = bound(&Bound {
            path: FAILURE.into(),
            sha256: FAILURE_SHA.into(),
        })?;
        ensure!(
            retained_source(&failure)?.0 == expected,
            "136 original provenance differs"
        );
    }
    let state = local_state(
        Path::new(SOURCE),
        Path::new(QUARANTINE),
        expected,
        recorded_intent || original == Some(expected),
        old_unlink.is_some(),
    )?;
    ensure!(
        old_completion.is_none() || state == LocalState::Absent,
        "136 source or quarantine reappeared after completed retirement"
    );
    if check {
        ensure!(
            p.prior_check.is_none(),
            "136 check cannot borrow another check"
        );
        let path = match state {
            LocalState::Original => Some(Path::new(SOURCE)),
            LocalState::Quarantined => Some(Path::new(QUARANTINE)),
            LocalState::Absent => None,
        };
        if let Some(path) = path {
            original_permissions(path)?;
            let proof = verified_quarantine(path, expected, ARTIFACT_SHA, ARTIFACT_ETAG)?;
            original_permissions(path)?;
            native_checksum(&remote_before, &proof, LENGTH)?;
            let again = remote(client, m, &c).await?;
            native_checksum(&again, &proof, LENGTH)?;
        }
        let _ = basis(p)?;
        let _ = references(p)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let path = Path::new(STATE)
            .join("receipts")
            .join(format!("retire136-check-{}.json", spec.sha256));
        persist(
            &path,
            &json!({"schema":"jetstreamer-holding-retire136-check-v2","descriptor":descriptor,
            "spec":{"path":spec.path,"sha256":spec.sha256},"checked":true,"recorded_unix_seconds":now,
            "source_identity_verified":original == Some(expected),"quarantine_identity_verified":quarantine == Some(expected),
            "capacity_completion":p.capacity_completion,"data_removed":false,"remote_mutations":false,"r2_mutations":false}),
        )?;
        println!("{}", path.display());
        return Ok(());
    }
    let prior = bound(
        p.prior_check
            .as_ref()
            .context("136 retirement requires a sealed successful check")?,
    )?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        prior["schema"] == "jetstreamer-holding-retire136-check-v2"
            && prior["checked"] == true
            && prior["descriptor"] == descriptor
            && prior["data_removed"] == false
            && prior["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t <= now && now - t <= 900),
        "136 prior capability check is stale or foreign"
    );
    if !recorded_intent {
        persist(&intent, &descriptor)?;
    }
    if state == LocalState::Original {
        stage(Path::new(SOURCE), Path::new(QUARANTINE), expected)?;
    }
    let unlink_descriptor;
    if state != LocalState::Absent {
        original_permissions(Path::new(QUARANTINE))?;
        let proof =
            verified_quarantine(Path::new(QUARANTINE), expected, ARTIFACT_SHA, ARTIFACT_ETAG)?;
        original_permissions(Path::new(QUARANTINE))?;
        native_checksum(&remote_before, &proof, LENGTH)?;
        let moved_descriptor = moved_record(&descriptor, expected, &proof);
        if !exact_record(&moved, &moved_descriptor)? {
            persist(&moved, &moved_descriptor)?;
        }
        let _ = basis(p)?;
        let _ = references(p)?;
        no_references(Path::new(QUARANTINE))?;
        let again = remote(client, m, &c).await?;
        native_checksum(&again, &proof, LENGTH)?;
        unlink_descriptor = unlink_record(&descriptor, &record_sha(&moved)?);
        if !exact_record(&unlink_intent, &unlink_descriptor)? {
            persist(&unlink_intent, &unlink_descriptor)?;
        }
        unlink(Path::new(SOURCE), Path::new(QUARANTINE), expected)?;
    } else {
        unlink_descriptor = old_unlink.context("136 absent recovery lacks unlink intent")?;
    }
    let _ = basis(p)?;
    let _ = references(p)?;
    let remote_after = remote(client, m, &c).await?;
    let final_moved = read_record(&moved)?.context("136 completed retirement lacks moved proof")?;
    native_checksum(
        &remote_after,
        &moved_proof(
            &final_moved,
            &descriptor,
            expected,
            ARTIFACT_SHA,
            ARTIFACT_ETAG,
        )?,
        LENGTH,
    )?;
    ensure!(
        local_state(
            Path::new(SOURCE),
            Path::new(QUARANTINE),
            expected,
            true,
            true
        )? == LocalState::Absent,
        "136 source or quarantine reappeared"
    );
    let finished = completed_record(&descriptor, &unlink_descriptor, &inspection);
    if !exact_record(&completion, &finished)? {
        persist(&completion, &finished)?;
    }
    println!("{}", completion.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy_fixture() -> (Retire, Mapping, Value, Value) {
        let binding = |path: &str, sha: &str| Bound {
            path: path.into(),
            sha256: sha.into(),
        };
        let m = Mapping {
            schema: "jetstreamer-horizon-host-holding-prefix-v2".into(),
            host: HOST.into(),
            prefix: "node_02/".into(),
            user_provided_prefix: true,
            authorization_reference: "isolated fixture only".into(),
        };
        let p = Retire {
            schema: "jetstreamer-horizon-holding-retire136-plan-v2".into(),
            mapping: binding("/sealed/mapping.json", &"a".repeat(64)),
            terminal: binding(TERMINAL, TERMINAL_SHA),
            qualification: binding(QUALIFICATION, QUALIFICATION_SHA),
            inspection: binding(INSPECTION, INSPECTION_SHA),
            custody: binding("/sealed/custody.json", &"b".repeat(64)),
            controller_mask: binding(&format!("{MASK_ROOT}/completion.json"), &"c".repeat(64)),
            capacity_completion: binding("/accepted/completion.json", &"d".repeat(64)),
            prior_check: None,
        };
        let park = Park {
            schema: "jetstreamer-horizon-holding-park-plan-v2".into(),
            mapping: p.mapping.clone(),
            eligibility: p.inspection.clone(),
            source: SOURCE.into(),
            length: LENGTH,
            sha256: ARTIFACT_SHA.into(),
        };
        let key = object_key(&m, ARTIFACT_SHA).unwrap();
        let bytes = manifest_bytes(&m, &park, &key, 1001, 1003, 0o600).unwrap();
        let manifest_sha = hex_lower(&Sha256::digest(&bytes));
        let c = json!({"schema":"jetstreamer-horizon-holding-custody-v2","host":HOST,"bucket":BUCKET,
            "prefix":m.prefix,"source":SOURCE,"mapping":p.mapping,"eligibility":p.inspection,
            "length":LENGTH,"sha256":ARTIFACT_SHA,"object_key":key,"object_etag":ARTIFACT_ETAG,
            "manifest_key":format!("node_02/manifests/{manifest_sha}.json"),"manifest_sha256":manifest_sha,
            "manifest":serde_json::from_slice::<Value>(&bytes).unwrap(),"remote_sha256_readback":true,
            "local_source_revalidated":true,"local_retirement_authorized":false,
            "canonical_publication_authorized":false,"runtime_checkpoint_qualified":false,
            "job_resume_authorized":false,"replay_launch_authorized":false});
        let e = json!({"schema":"jetstreamer-horizon-holding-eligibility-v2","host":HOST,"epoch":136,
            "source":SOURCE,"length":LENGTH,"sha256":ARTIFACT_SHA,"multipart_etag":ARTIFACT_ETAG,
            "closed":true,"artifact_kind":"retained-failed-partial-archive","canonical_archive":false,
            "local_retirement_authorized":false,"failure_repaired":false,"job_resume_authorized":false,
            "original_failure":{"path":FAILURE,"sha256":FAILURE_SHA},
            "source_identity":{"device":64512,"inode":99352633,"length":LENGTH,"links":1,
            "uid":1001,"gid":1003,"mode":0o600,"mtime_seconds":1792326715,"mtime_nanoseconds":284967280,
            "ctime_seconds":1792326715,"ctime_nanoseconds":284967280,"physical_bytes":99719081984u64}});
        (p, m, e, c)
    }

    #[test]
    fn custody_and_partial_scope_cannot_borrow_canonical_or_unverified_data() {
        let (p, m, e, c) = policy_fixture();
        scope(&p, &m, &e, &c).unwrap();
        for (key, value) in [
            ("remote_sha256_readback", json!(false)),
            ("local_source_revalidated", json!(false)),
            ("object_etag", json!("changed-etag")),
            ("sha256", json!("e".repeat(64))),
            ("canonical_publication_authorized", json!(true)),
            ("job_resume_authorized", json!(true)),
        ] {
            let mut bad = c.clone();
            bad[key] = value;
            assert!(scope(&p, &m, &e, &bad).is_err(), "{key}");
        }
        let mut missing = c.clone();
        missing
            .as_object_mut()
            .unwrap()
            .remove("remote_sha256_readback");
        assert!(scope(&p, &m, &e, &missing).is_err());
        for (key, value) in [
            ("epoch", json!(137)),
            ("canonical_archive", json!(true)),
            ("local_retirement_authorized", json!(true)),
            ("artifact_kind", json!("verified-complete-archive")),
        ] {
            let mut bad = e.clone();
            bad[key] = value;
            assert!(scope(&p, &m, &bad, &c).is_err(), "{key}");
        }
    }

    #[test]
    fn marker_chain_and_moved_proof_reject_missing_or_changed_frontiers() {
        marker_chain(false, false, false, false).unwrap();
        marker_chain(true, true, true, true).unwrap();
        assert!(marker_chain(false, true, false, false).is_err());
        assert!(marker_chain(true, false, true, false).is_err());
        assert!(marker_chain(true, true, false, true).is_err());
        let (_root, _s, _q, id, sha, etag) = fixture();
        let proof = LocalProof {
            sha256_hex: ARTIFACT_SHA.into(),
            multipart_etag: ARTIFACT_ETAG.into(),
            composite_sha256: BASE64_STANDARD.encode([9u8; 32]),
        };
        let descriptor = json!({"custody":"fixture"});
        let record = moved_record(&descriptor, id, &proof);
        moved_proof(&record, &descriptor, id, ARTIFACT_SHA, ARTIFACT_ETAG).unwrap();
        let mut bad = record.clone();
        bad["local_sha256"] = json!(sha);
        assert!(moved_proof(&bad, &descriptor, id, ARTIFACT_SHA, ARTIFACT_ETAG).is_err());
        bad = record.clone();
        bad["local_multipart_etag"] = json!(etag);
        assert!(moved_proof(&bad, &descriptor, id, ARTIFACT_SHA, ARTIFACT_ETAG).is_err());
        bad = record;
        bad["local_composite_sha256"] = json!("");
        assert!(moved_proof(&bad, &descriptor, id, ARTIFACT_SHA, ARTIFACT_ETAG).is_err());
    }
    fn fixture() -> (
        tempfile::TempDir,
        PathBuf,
        PathBuf,
        FileIdentity,
        String,
        String,
    ) {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let source = root.path().join("source.jet");
        let dir = root.path().join("private-quarantine");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let quarantine = dir.join("retained.partial");
        fs::write(&source, b"retained failed public-chain prefix").unwrap();
        let id = regular_identity(&source).unwrap();
        let proof = hash_and_etag(&source, id, DEFAULT_PART_SIZE).unwrap();
        (
            root,
            source,
            quarantine,
            id,
            proof.sha256_hex,
            proof.multipart_etag,
        )
    }
    #[test]
    fn every_local_transition_retries_without_replacing_data() {
        let (_root, s, q, id, sha, etag) = fixture();
        assert!(local_state(&s, &q, id, false, false).is_err());
        assert_eq!(
            local_state(&s, &q, id, true, false).unwrap(),
            LocalState::Original
        );
        stage(&s, &q, id).unwrap();
        assert_eq!(
            local_state(&s, &q, id, true, false).unwrap(),
            LocalState::Quarantined
        );
        assert!(local_state(&s, &q, id, false, false).is_err());
        verified_quarantine(&q, id, &sha, &etag).unwrap();
        assert_eq!(
            local_state(&s, &q, id, true, true).unwrap(),
            LocalState::Quarantined
        );
        unlink(&s, &q, id).unwrap();
        assert!(local_state(&s, &q, id, true, false).is_err());
        assert_eq!(
            local_state(&s, &q, id, true, true).unwrap(),
            LocalState::Absent
        );
    }
    #[test]
    fn durable_recovery_after_each_local_frontier_preserves_exact_receipts() {
        for stop_after in 0..=5 {
            let (root, s, q, id, sha, etag) = fixture();
            let intent = root.path().join("intent.json");
            let moved = root.path().join("moved.json");
            let unlink_intent = root.path().join("unlink.json");
            let complete = root.path().join("complete.json");
            let descriptor =
                json!({"fixture_source":s,"fixture_quarantine":q,"sha256":sha,"etag":etag});
            if stop_after >= 1 {
                persist(&intent, &descriptor).unwrap();
            }
            if stop_after >= 2 {
                stage(&s, &q, id).unwrap();
            }
            let proof_path = if stop_after >= 2 { &q } else { &s };
            let proof = verified_quarantine(proof_path, id, &sha, &etag).unwrap();
            let moved_value = moved_record(&descriptor, id, &proof);
            if stop_after >= 3 {
                persist(&moved, &moved_value).unwrap();
            }
            let unlink_value = if stop_after >= 3 {
                Some(unlink_record(&descriptor, &record_sha(&moved).unwrap()))
            } else {
                None
            };
            if stop_after >= 4 {
                persist(&unlink_intent, unlink_value.as_ref().unwrap()).unwrap();
            }
            if stop_after >= 5 {
                unlink(&s, &q, id).unwrap();
            }
            let had_intent = exact_record(&intent, &descriptor).unwrap();
            let old_moved = read_record(&moved).unwrap();
            let old_unlink = read_record(&unlink_intent).unwrap();
            marker_chain(had_intent, old_moved.is_some(), old_unlink.is_some(), false).unwrap();
            if !had_intent {
                persist(&intent, &descriptor).unwrap();
            }
            let state = local_state(&s, &q, id, true, old_unlink.is_some()).unwrap();
            if state == LocalState::Original {
                stage(&s, &q, id).unwrap();
            }
            if state != LocalState::Absent {
                let proof = verified_quarantine(&q, id, &sha, &etag).unwrap();
                let value = moved_record(&descriptor, id, &proof);
                if !exact_record(&moved, &value).unwrap() {
                    persist(&moved, &value).unwrap();
                }
                let value = unlink_record(&descriptor, &record_sha(&moved).unwrap());
                if !exact_record(&unlink_intent, &value).unwrap() {
                    persist(&unlink_intent, &value).unwrap();
                }
                unlink(&s, &q, id).unwrap();
            }
            let retained = read_record(&moved).unwrap().unwrap();
            moved_proof(&retained, &descriptor, id, &sha, &etag).unwrap();
            assert_eq!(
                read_record(&unlink_intent).unwrap().unwrap(),
                unlink_record(&descriptor, &record_sha(&moved).unwrap())
            );
            let finished = completed_record(
                &descriptor,
                &read_record(&unlink_intent).unwrap().unwrap(),
                &json!({"source_identity":{"physical_bytes":4096}}),
            );
            persist(&complete, &finished).unwrap();
            let bytes = fs::read(&complete).unwrap();
            assert!(exact_record(&complete, &finished).unwrap());
            persist(&complete, &finished).unwrap();
            assert_eq!(fs::read(&complete).unwrap(), bytes);
            assert_eq!(
                local_state(&s, &q, id, true, true).unwrap(),
                LocalState::Absent
            );
        }
    }
    #[test]
    fn conflicting_quarantine_changed_bytes_and_reappearing_source_are_preserved() {
        let (_root, s, q, id, sha, etag) = fixture();
        fs::write(&q, b"conflict").unwrap();
        assert!(stage(&s, &q, id).is_err());
        assert_eq!(fs::read(&q).unwrap(), b"conflict");
        assert!(local_state(&s, &q, id, true, false).is_err());
        fs::remove_file(&q).unwrap();
        stage(&s, &q, id).unwrap();
        assert!(verified_quarantine(&q, id, &sha, "changed-etag").is_err());
        assert!(verified_quarantine(&q, id, &"a".repeat(64), &etag).is_err());
        fs::write(&s, b"new-source").unwrap();
        assert!(unlink(&s, &q, id).is_err());
        assert_eq!(fs::read(&s).unwrap(), b"new-source");
        assert!(q.exists());
    }
    #[test]
    fn changed_inode_and_symlink_never_select_a_different_file() {
        let (_root, s, q, id, _sha, _etag) = fixture();
        let target = s.with_extension("other");
        fs::write(&target, b"other").unwrap();
        fs::remove_file(&s).unwrap();
        std::os::unix::fs::symlink(&target, &s).unwrap();
        assert!(local_state(&s, &q, id, true, false).is_err());
        assert!(stage(&s, &q, id).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"other");
    }
    #[test]
    fn live_replacement_and_downstream_claims_deny_retirement() {
        let f = json!({"epochs":[{"epoch":136,"state":"failed-needs-repair"}],
            "active":[],"diagnostics":[],"pipelines":[]});
        no_replacement(&f).unwrap();
        for state in ["remote-ready", "live-replay", "post-replay-pipeline"] {
            let mut bad = f.clone();
            bad["epochs"][0]["state"] = json!(state);
            assert!(no_replacement(&bad).is_err());
        }
        for key in ["active", "diagnostics", "pipelines"] {
            let mut bad = f.clone();
            bad[key] = json!([{"epoch":136,"live":true}]);
            assert!(no_replacement(&bad).is_err(), "{key}");
        }
        let mut queued = f.clone();
        queued["diagnostics"] =
            json!([{"live":true,"epoch":135,"scope_first_epoch":135,"scope_last_epoch":137}]);
        assert!(no_replacement(&queued).is_err());
    }
}
