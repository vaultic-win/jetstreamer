//! Exact failed185 partial retirement after authenticated cold custody. This is
//! not canonical archive retirement or a portable runtime checkpoint.
use super::*;

const QUARANTINE: &str = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/retirements/epoch185-stopped-20261024.partial";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Retire {
    schema: String,
    mapping: Bound,
    guard_intent: Bound,
    guard_completion: Bound,
    qualification: Bound,
    deployment: Bound,
    inspection: Bound,
    custody: Bound,

    capacity_completion: Bound,
    prior_check: Option<Bound>,
    #[serde(default)]
    closed_growth_disposition: Option<Bound>,
}

fn scope(p: &Retire, m: &Mapping, e: &Value, c: &Value) -> Result<FileIdentity> {
    ensure!(
        p.schema == "jetstreamer-horizon-holding-retire185-plan-v2",
        "foreign185 retirement scope"
    );
    let (_, etag, sha, length) = custody(c, m)?;
    ensure!(
        length == LENGTH
            && c["source"] == SOURCE
            && c["mapping"] == serde_json::to_value(&p.mapping)?
            && c["eligibility"] == serde_json::to_value(&p.inspection)?
            && c["manifest"]["uid"] == 1001
            && c["manifest"]["gid"] == 1003
            && c["manifest"]["mode"] == 0o600
            && e["schema"] == "jetstreamer-horizon-holding-eligibility-v2"
            && e["host"] == HOST
            && e["epoch"] == 185
            && e["source"] == SOURCE
            && e["length"] == LENGTH
            && e["sha256"] == sha
            && e["multipart_etag"] == etag
            && e["closed"] == true
            && e["content_class"] == "public-chain-artifact"
            && e["credentials_config_and_logs_excluded"] == true
            && e["replay_launch_authorized"] == false
            && e["remote_mutations"] == false
            && e["r2_mutations"] == false
            && e["artifact_kind"] == "retained-failed-partial-archive"
            && e["interrupted_container_unvalidated"] == true
            && e["valid_prefix_established"] == false
            && e["canonical_archive"] == false
            && e["local_retirement_authorized"] == false
            && e["failure_repaired"] == false
            && e["job_resume_authorized"] == false
            && e["runtime_checkpoint_qualified"] == false
            && e["publication_authorized"] == false
            && e["guard_intent"] == serde_json::to_value(&p.guard_intent)?
            && e["guard_completion"] == serde_json::to_value(&p.guard_completion)?
            && e["qualification"] == serde_json::to_value(&p.qualification)?
            && e["deployment"] == serde_json::to_value(&p.deployment)?,
        "185 retirement requires exact interrupted bytes and whole-readback custody"
    );
    let old = &e["source_identity"];
    ensure!(
        old["device"] == 64512
            && old["inode"] == 100270097
            && old["length"] == LENGTH
            && old["links"] == 1
            && old["uid"] == 1001
            && old["gid"] == 1003
            && old["mode"] == 0o600
            && old["mtime_seconds"] == 1792801929
            && old["mtime_nanoseconds"] == 171229060
            && old["ctime_seconds"] == 1792801929
            && old["ctime_nanoseconds"] == 171229060,
        "185 inspection identity differs"
    );
    Ok(FileIdentity {
        device: 64512,
        inode: 100270097,
        length: LENGTH,
        modified_seconds: 1792801929,
        modified_nanoseconds: 171229060,
    })
}

fn no_replacement(f: &Value) -> Result<()> {
    let rows = f["epochs"].as_array().context("185 fleet epoch census")?;
    let rows: Vec<_> = rows.iter().filter(|r| r["epoch"] == 185).collect();
    ensure!(
        rows.len() == 1
            && matches!(
                rows[0]["state"].as_str(),
                Some("failed-needs-repair" | "blocked-qualification")
            ),
        "185 has a replacement, delivery stage or ready archive"
    );
    ensure!(
        !f["active"]
            .as_array()
            .context("185 fleet active census")?
            .iter()
            .any(|r| r["epoch"] == 185),
        "185 active replacement owner exists"
    );
    for key in ["diagnostics", "pipelines"] {
        ensure!(
            !f[key]
                .as_array()
                .context("185 downstream census")?
                .iter()
                .any(|r| {
                    r["live"] == true
                        && (r["epoch"] == 185
                            || r["scope_first_epoch"]
                                .as_u64()
                                .zip(r["scope_last_epoch"].as_u64())
                                .is_some_and(|(first, last)| first <= 185 && last >= 185))
                }),
            "185 live replacement/downstream stage exists"
        );
    }
    Ok(())
}

fn mutation_lock() -> Result<File> {
    use std::os::fd::AsRawFd;
    let path = Path::new("/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock");
    ensure!(path.canonicalize()? == path, "185 mutation lock alias");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && matches!(m.uid(), 0 | 1001)
            && m.mode() & 0o777 == 0o600
            && unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "185 shared local mutation lock occupied or unsafe"
    );
    Ok(file)
}

fn original_claims(c: &Value) -> Result<Vec<Bound>> {
    let mut epochs = std::collections::BTreeSet::new();
    let mut bindings = Vec::new();
    for row in c["original_claim_bindings"]
        .as_array()
        .context("185 original claims")?
    {
        let epoch = row["epoch"].as_u64().context("original claim epoch")?;
        let bytes = row["retained_growth_bytes"]
            .as_u64()
            .context("retained growth bytes")?;
        ensure!(
            matches!(epoch, 141 | 185)
                && epochs.insert(epoch)
                && bytes > 0
                && (epoch != 185 || bytes >= 824_633_720_832),
            "missing, duplicate or released185/141 original claim"
        );
        bindings.push(serde_json::from_value(row["binding"].clone())?);
    }
    ensure!(
        epochs == std::collections::BTreeSet::from([141, 185]),
        "185/141 original claims incomplete"
    );
    Ok(bindings)
}

fn capacity_shape(c: &Value, f: &Value, now: u64) -> Result<()> {
    let at = c["recorded_unix_seconds"]
        .as_u64()
        .context("185 capacity clock")?;
    let sampled = fleet::utc_seconds(f["sampled_at_utc"].as_str().context("185 fleet clock")?)?;
    ensure!(
        c["schema"] == "jetstreamer-horizon-holding-retire185-capacity-v2"
            && c["host"] == HOST
            && c["pressure_relief_only"] == true
            && c["new_launch_authorized"] == false
            && c["restore_authorized"] == false
            && c["growth_claims_released"] == false
            && c["pre_retirement_free_space_credit"] == 0
            && c["epoch185_original_growth_claim_retained"] == true
            && c["epoch141_original_growth_claim_retained"] == true
            && c["all_live_staged_and_retained_growth_claims_preserved"] == true
            && c["guard_completion"]["path"]
                == Path::new(GUARD_ROOT)
                    .join("completion.json")
                    .to_str()
                    .unwrap()
            && c["guard_completion"]["sha256"] == COMPLETION_SHA
            && c["retained185_physical_bytes"] == 56_206_397_440u64
            && c["all_current_protected_bytes"]
                .as_u64()
                .is_some_and(|n| n >= 3_503_746_342_342)
            && c["original_claim_bindings"]
                .as_array()
                .is_some_and(|a| !a.is_empty())
            && f["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && f["first_epoch"] == 101
            && f["last_epoch"] == 200
            && c["sampled_at_utc"] == f["sampled_at_utc"]
            && sampled >= 1792801960
            && sampled <= now
            && now - sampled <= 1800
            && at >= sampled
            && at <= now
            && now - at <= 900,
        "185 pressure relief requires fresh post-stop claims without release or restore credit"
    );
    original_claims(c)?;
    no_replacement(f)?;
    Ok(())
}

fn after_growth_original_claims(c: &Value) -> Result<Vec<Bound>> {
    let mut epochs = std::collections::BTreeSet::new();
    let mut bindings = Vec::new();
    for row in c["original_claim_bindings"]
        .as_array()
        .context("185 closed-growth original claims")?
    {
        let epoch = row["epoch"].as_u64().context("185 original epoch")?;
        ensure!(
            matches!(epoch, 141 | 185) && epochs.insert(epoch),
            "185 closed-growth original binding duplicate or foreign"
        );
        let b: Bound = serde_json::from_value(row["binding"].clone())?;
        if epoch == 185 {
            ensure!(
                row["retained_growth_bytes"] == 0
                    && row["original_growth_bytes"] == 824_633_720_832u64
                    && b.path
                        == Path::new(
                            "/usr/local/lib/jetstreamer/horizon-epoch185-full-admission-20261023-v2/admission-manifest.json"
                        )
                    && b.sha256
                        == "c2074a168945f30e2a9a83464f8d07e94e835bbb504e0a84c5cdf91323a71cb9",
                "185 closed-growth binding is not exact original768GiB-to0 disposition"
            );
        } else {
            ensure!(
                row["retained_growth_bytes"] == 549_755_813_888u64
                    && b.path
                        == Path::new(
                            "/var/lib/jetstreamer/horizon-original141-capped-root-admission-20261023-v1/admission.json"
                        )
                    && b.sha256
                        == "945561bbf6dc282cbc0375cb84d777abace765956f61e8cd1e35863056ca5b3b",
                "141 original whole-root cap/binding cannot be reduced by185 retirement"
            );
        }
        bindings.push(b);
    }
    ensure!(
        epochs == std::collections::BTreeSet::from([141, 185]),
        "185 closed-growth original claims incomplete"
    );
    Ok(bindings)
}
fn after_growth_projection_claims(view: &Value) -> Result<()> {
    let rows = view["projected_reservation_rows"]
        .as_array()
        .context("185 retirement typed claim rows")?;
    let original141: Vec<_> = rows
        .iter()
        .filter(|r| r["claim_key"] == "epoch141/e639f007d482464f8a251455659d2ede")
        .collect();
    ensure!(
        original141.len() == 1
            && original141[0]["epoch"] == 141
            && original141[0]["producer_invocation_id"] == "e639f007d482464f8a251455659d2ede"
            && original141[0]["outstanding_bytes"] == 549_755_813_888u64,
        "185 retirement projection must preserve exact original141 whole-root cap"
    );
    Ok(())
}
fn after_growth_capacity_shape(c: &Value, f: &Value, now: u64, projection: &Bound) -> Result<()> {
    let at = c["recorded_unix_seconds"]
        .as_u64()
        .context("185 closed-growth capacity clock")?;
    let sampled = fleet::utc_seconds(
        f["sampled_at_utc"]
            .as_str()
            .context("185 closed-growth fleet clock")?,
    )?;
    ensure!(
        c["schema"] == "jetstreamer-horizon-holding-retire185-closed-growth-capacity-v2"
            && c["host"] == HOST
            && c["pressure_relief_only"] == true
            && c["new_launch_authorized"] == false
            && c["restore_authorized"] == false
            && c["growth_claims_released"] == false
            && c["pre_retirement_free_space_credit"] == 0
            && c["epoch185_original_growth_claim_retained"] == false
            && c["epoch185_original_growth_binding_retained"] == true
            && c["epoch141_original_growth_claim_retained"] == true
            && c["all_live_staged_and_retained_growth_claims_preserved"] == true
            && c["closed_growth_disposition"] == serde_json::to_value(projection)?
            && c["guard_completion"]
                == json!({"path":Path::new(GUARD_ROOT).join("completion.json"),"sha256":COMPLETION_SHA})
            && c["retained185_physical_bytes"] == 56_206_397_440u64
            && c["all_current_protected_bytes"]
                .as_u64()
                .is_some_and(|n| n >= 3_503_746_342_342)
            && f["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && f["first_epoch"] == 101
            && f["last_epoch"] == 200
            && c["sampled_at_utc"] == f["sampled_at_utc"]
            && sampled >= 1792801960
            && sampled <= now
            && now - sampled <= 1800
            && at >= sampled
            && at <= now
            && now - at <= 900,
        "185 post-closure pressure relief requires exact closed disposition and every other claim preserved"
    );
    after_growth_original_claims(c)?;
    no_replacement(f)
}
fn basis(p: &Retire, m: &Mapping) -> Result<Value> {
    let c = evidence(&p.capacity_completion, false)?;
    let fb: Bound = serde_json::from_value(c["fleet"].clone())?;
    ensure!(
        fb.path.parent()
            == Some(Path::new(
                "/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1"
            )),
        "foreign185 capacity fleet"
    );
    let f = evidence(&fb, false)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let disposition = if let Some(projection) = &p.closed_growth_disposition {
        let view = growth::retired_after_closure_basis(m, &p.mapping, projection)?;
        after_growth_projection_claims(&view)?;
        after_growth_capacity_shape(&c, &f, now, projection)?;
        Some(view)
    } else {
        capacity_shape(&c, &f, now)?;
        None
    };
    let bindings = if disposition.is_some() {
        after_growth_original_claims(&c)?
    } else {
        original_claims(&c)?
    };
    for b in bindings {
        let _ = evidence(&b, false)?;
    }
    // Reject omitted later phase events as well as newer normal observations.
    for entry in fs::read_dir(fb.path.parent().unwrap())? {
        let path = entry?.path();
        if path == fb.path || path.extension().is_none_or(|s| s != "json") {
            continue;
        }
        let v: Value =
            serde_json::from_slice(&read_stable_bounded(&path, 16 << 20, "185 latest fleet")?)?;
        if v["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && v["first_epoch"] == 101
            && v["last_epoch"] == 200
        {
            let at = fleet::utc_seconds(
                v["sampled_at_utc"]
                    .as_str()
                    .context("185 candidate clock")?,
            )?;
            let old = fleet::utc_seconds(f["sampled_at_utc"].as_str().unwrap())?;
            ensure!(
                at < old
                    || (at == old
                        && v["recorded_unix_seconds"]
                            .as_u64()
                            .context("185 event clock")?
                            < f["recorded_unix_seconds"]
                                .as_u64()
                                .context("185 basis clock")?),
                "newer fleet invalidates185 retirement"
            );
        }
    }
    let owners: Vec<_> = fleet_owners(&f)?
        .into_iter()
        .map(|(unit, invocation_id)| json!({"unit":unit,"invocation_id":invocation_id}))
        .collect();
    restore_owners(&json!({"owners":owners}))?;
    let names = f["unit_census"]
        .as_object()
        .context("185 complete census")?
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
                "185 live fleet changed"
            );
        }
    }
    // No free-space-above-protected-growth condition: this only removes authenticated closed bytes.
    let mut basis = json!({"capacity_completion":p.capacity_completion,"fleet":fb,"current_unit_census":current});
    if let Some(view) = disposition {
        basis["closed_growth_disposition"] = view;
    }
    Ok(basis)
}

fn no_sidecars() -> Result<()> {
    for suffix in ["jet.sha256", "sha256"] {
        ensure!(
            fs::symlink_metadata(Path::new(SOURCE).with_extension(suffix))
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "185 partial has a canonical sidecar or unreadable adjacent path"
        );
    }
    Ok(())
}

fn references(_p: &Retire) -> Result<Value> {
    let terminal = closed_references()?;
    no_sidecars()?;
    let processes = no_references(Path::new(LANE))?;
    let quarantine_processes = no_references(Path::new(QUARANTINE))?;
    let staged =
        jetstreamer_horizon_observe::dev_cache_check::sol_staged_path_references(Path::new(LANE))?;
    let quarantine_staged =
        jetstreamer_horizon_observe::dev_cache_check::sol_staged_path_references(
            Path::new(QUARANTINE)
                .parent()
                .context("185 quarantine parent")?,
        )?;
    ensure!(
        staged["references"] == json!([]) && quarantine_staged["references"] == json!([]),
        "185 partial still has staged consumers"
    );
    Ok(
        json!({"terminal":terminal,"processes":processes,"quarantine_processes":quarantine_processes,
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
        "185 holding owner differs"
    );
    let manifest = get_mutable_object(
        client,
        BUCKET,
        c["manifest_key"].as_str().context("185 manifest key")?,
    )
    .await?
    .context("185 holding manifest absent")?;
    ensure!(
        hex_lower(&Sha256::digest(&manifest.bytes)) == c["manifest_sha256"].as_str().unwrap()
            && serde_json::from_slice::<Value>(&manifest.bytes)? == c["manifest"],
        "185 holding manifest differs"
    );
    let blob = head_archive(client, BUCKET, &key)
        .await?
        .context("185 held blob absent")?;
    remote_matches(&blob, &key, length, &sha, Some(&etag))?;
    ensure!(
        head_archive(client, BUCKET, "epoch-185.jet")
            .await?
            .is_none()
            && get_mutable_object(client, BUCKET, "epoch-185.jet.sha256")
                .await?
                .is_none(),
        "185 canonical delivery appeared; reconcile before partial retirement"
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
                "185 local lifecycle path is aliased"
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
    ensure!(intent, "185 retirement has no matching durable intent");
    match (maybe_identity(source)?, maybe_identity(quarantine)?) {
        (Some(id), None) => {
            ensure!(id == expected, "185 source identity changed");
            Ok(LocalState::Original)
        }
        (None, Some(id)) => {
            ensure!(id == expected, "185 quarantine identity changed");
            Ok(LocalState::Quarantined)
        }
        (None, None) => {
            ensure!(
                unlink_intent,
                "unexplained185 local absence before unlink intent"
            );
            Ok(LocalState::Absent)
        }
        (Some(_), Some(_)) => bail!("conflicting185 source and quarantine both exist"),
    }
}

fn stage(source: &Path, quarantine: &Path, expected: FileIdentity) -> Result<()> {
    private(quarantine.parent().context("185 quarantine parent")?)?;
    ensure!(
        regular_identity(source)? == expected,
        "185 source changed before quarantine"
    );
    ensure!(
        fs::metadata(source.parent().context("185 source parent")?)?.dev()
            == fs::metadata(quarantine.parent().unwrap())?.dev(),
        "185 quarantine must share source filesystem"
    );
    rename_noreplace(source, quarantine)?;
    File::open(source.parent().unwrap())?.sync_all()?;
    ensure!(
        regular_identity(quarantine)? == expected,
        "185 quarantined identity differs"
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
        "185 quarantine changed"
    );
    let proof = hash_and_etag(path, expected, DEFAULT_PART_SIZE)?;
    ensure!(
        proof.sha256_hex == sha && proof.multipart_etag == etag,
        "185 quarantined bytes differ from held custody"
    );
    Ok(proof)
}

fn unlink(source: &Path, quarantine: &Path, expected: FileIdentity) -> Result<()> {
    private(quarantine.parent().context("185 quarantine parent")?)?;
    ensure!(
        maybe_identity(source)?.is_none(),
        "185 source reappeared; preserve both copies"
    );
    ensure!(
        regular_identity(quarantine)? == expected,
        "185 quarantine replaced before unlink"
    );
    fs::remove_file(quarantine)?;
    File::open(quarantine.parent().unwrap())?.sync_all()?;
    ensure!(
        maybe_identity(quarantine)?.is_none(),
        "185 quarantine remains after unlink"
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
                "unsafe185 transition record"
            );
            let id = regular_identity(path)?;
            let bytes = fs::read(path)?;
            ensure!(
                regular_identity(path)? == id,
                "185 transition record changed during read"
            );
            Ok(Some(serde_json::from_slice(&bytes)?))
        }
    }
}

fn exact_record(path: &Path, descriptor: &Value) -> Result<bool> {
    if let Some(record) = read_record(path)? {
        ensure!(
            record == *descriptor,
            "185 transition record conflicts with exact custody"
        );
        Ok(true)
    } else {
        Ok(false)
    }
}

fn marker_chain(intent: bool, moved: bool, unlink: bool, completion: bool) -> Result<()> {
    ensure!(!moved || intent, "185 moved record has no parent intent");
    ensure!(
        !unlink || moved,
        "185 unlink intent lacks verified moved bytes"
    );
    ensure!(
        !completion || unlink,
        "185 completion lacks a prior unlink intent"
    );
    Ok(())
}

fn moved_record(descriptor: &Value, expected: FileIdentity, proof: &LocalProof) -> Value {
    json!({"schema":"jetstreamer-holding-retire185-moved-v2","intent":descriptor,
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
        .context("185 retained composite proof")?;
    let proof = LocalProof {
        sha256_hex: sha.into(),
        multipart_etag: etag.into(),
        composite_sha256: composite.into(),
    };
    ensure!(
        BASE64_STANDARD.decode(composite)?.len() == 32
            && moved_record(descriptor, expected, &proof) == *record,
        "185 moved proof is foreign or incomplete"
    );
    Ok(proof)
}

fn record_sha(path: &Path) -> Result<String> {
    ensure!(
        read_record(path)?.is_some(),
        "185 transition record is absent"
    );
    let id = regular_identity(path)?;
    let bytes = read_stable_bounded(path, 1 << 20, "185 transition bytes")?;
    ensure!(
        regular_identity(path)? == id,
        "185 transition bytes changed"
    );
    Ok(hex_lower(&Sha256::digest(&bytes)))
}

fn unlink_record(descriptor: &Value, moved_sha: &str) -> Value {
    json!({"schema":"jetstreamer-holding-retire185-unlink-intent-v2","intent":descriptor,
        "moved_sha256":moved_sha,"authenticated_custody_revalidated":true})
}

fn completed_record(descriptor: &Value, unlink: &Value, inspection: &Value) -> Value {
    json!({"schema":"jetstreamer-holding-retire185-completion-v2","intent":descriptor,
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
        "185 partial permissions or links changed"
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
        "185 retirement mapping changed"
    );
    let common = Inspect {
        schema: "jetstreamer-horizon-holding-inspect185-plan-v2".into(),
        mapping: p.mapping.clone(),
        guard_intent: p.guard_intent.clone(),
        guard_completion: p.guard_completion.clone(),
        qualification: p.qualification.clone(),
        deployment: p.deployment.clone(),
    };
    super::scope(
        &common,
        m,
        &evidence(&p.guard_intent, false)?,
        &evidence(&p.guard_completion, false)?,
        &bound(&p.qualification)?,
    )?;
    let _deployment = bound(&p.deployment)?;
    let _mutation_lock = mutation_lock()?;
    let inspection = bound(&p.inspection)?;
    let c = bound(&p.custody)?;
    let expected = scope(p, m, &inspection, &c)?;
    let artifact_sha = inspection["sha256"].as_str().context("185 digest")?;
    let artifact_etag = inspection["multipart_etag"].as_str().context("185 etag")?;
    let _ = basis(p, m)?;
    let _ = references(p)?;
    let remote_before = remote(client, m, &c).await?;
    let root = Path::new(STATE).join("retirements");
    private(&root)?;
    ensure!(
        fs::metadata(&root)?.dev() == expected.device,
        "185 quarantine is on another filesystem"
    );
    let mut descriptor = json!({"schema":"jetstreamer-holding-retire185-intent-v2","host":HOST,
        "epoch":185,"source":SOURCE,"quarantine":QUARANTINE,"sha256":artifact_sha,"length":LENGTH,
        "multipart_etag":artifact_etag,"source_identity":inspection["source_identity"],
        "mapping":p.mapping,"custody":p.custody,"inspection":p.inspection,"guard_intent":p.guard_intent,"guard_completion":p.guard_completion,
        "qualification":p.qualification,"deployment":p.deployment,
        "canonical_archive":false,"failure_repaired":false,"runtime_checkpoint_qualified":false,
        "job_resume_authorized":false,"replay_launch_authorized":false,"publication_authorized":false,
        "remote_mutations":false,"r2_mutations":false});
    if let Some(projection) = &p.closed_growth_disposition {
        descriptor["closed_growth_disposition"] = serde_json::to_value(projection)?;
    }
    let intent = root.join("epoch185-intent.json");
    let moved = root.join("epoch185-moved.json");
    let unlink_intent = root.join("epoch185-unlink-intent.json");
    let completion = root.join("epoch185-completion.json");
    let recorded_intent = exact_record(&intent, &descriptor)?;
    let old_moved = read_record(&moved)?;
    if let Some(record) = &old_moved {
        let proof = moved_proof(record, &descriptor, expected, artifact_sha, artifact_etag)?;
        native_checksum(&remote_before, &proof, LENGTH)?;
    }
    let old_unlink = read_record(&unlink_intent)?;
    if let Some(record) = &old_unlink {
        ensure!(
            old_moved.is_some() && *record == unlink_record(&descriptor, &record_sha(&moved)?),
            "185 unlink intent differs"
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
                        .context("185 completion without unlink intent")?,
                    &inspection
                ),
            "185 completion differs"
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
            "185 source absent or conflicting before first intent"
        );
        ensure!(
            retained_source()?.0 == expected,
            "185 original provenance differs"
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
        "185 source or quarantine reappeared after completed retirement"
    );
    if check {
        ensure!(
            p.prior_check.is_none(),
            "185 check cannot borrow another check"
        );
        let path = match state {
            LocalState::Original => Some(Path::new(SOURCE)),
            LocalState::Quarantined => Some(Path::new(QUARANTINE)),
            LocalState::Absent => None,
        };
        if let Some(path) = path {
            original_permissions(path)?;
            let proof = verified_quarantine(path, expected, artifact_sha, artifact_etag)?;
            original_permissions(path)?;
            native_checksum(&remote_before, &proof, LENGTH)?;
            let again = remote(client, m, &c).await?;
            native_checksum(&again, &proof, LENGTH)?;
        }
        let _ = basis(p, m)?;
        let _ = references(p)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let path = Path::new(STATE)
            .join("receipts")
            .join(format!("retire185-check-{}.json", spec.sha256));
        persist(
            &path,
            &json!({"schema":"jetstreamer-holding-retire185-check-v2","descriptor":descriptor,
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
            .context("185 retirement requires a sealed successful check")?,
    )?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        prior["schema"] == "jetstreamer-holding-retire185-check-v2"
            && prior["checked"] == true
            && prior["descriptor"] == descriptor
            && prior["data_removed"] == false
            && prior["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t <= now && now - t <= 900),
        "185 prior capability check is stale or foreign"
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
            verified_quarantine(Path::new(QUARANTINE), expected, artifact_sha, artifact_etag)?;
        original_permissions(Path::new(QUARANTINE))?;
        native_checksum(&remote_before, &proof, LENGTH)?;
        let moved_descriptor = moved_record(&descriptor, expected, &proof);
        if !exact_record(&moved, &moved_descriptor)? {
            persist(&moved, &moved_descriptor)?;
        }
        let _ = basis(p, m)?;
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
        unlink_descriptor = old_unlink.context("185 absent recovery lacks unlink intent")?;
    }
    let _ = basis(p, m)?;
    let _ = references(p)?;
    let remote_after = remote(client, m, &c).await?;
    let final_moved = read_record(&moved)?.context("185 completed retirement lacks moved proof")?;
    native_checksum(
        &remote_after,
        &moved_proof(
            &final_moved,
            &descriptor,
            expected,
            artifact_sha,
            artifact_etag,
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
        "185 source or quarantine reappeared"
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
    #[test]
    fn custody_scope_never_borrows_other_bytes_or_promotes_interrupted_container() {
        let b = Bound {
            path: "/sealed/fixture.json".into(),
            sha256: "a".repeat(64),
        };
        let p = Retire {
            schema: "jetstreamer-horizon-holding-retire185-plan-v2".into(),
            mapping: b.clone(),
            guard_intent: b.clone(),
            guard_completion: b.clone(),
            qualification: b.clone(),
            deployment: b.clone(),
            inspection: b.clone(),
            custody: b.clone(),
            capacity_completion: b.clone(),
            prior_check: None,
            closed_growth_disposition: None,
        };
        let m = Mapping {
            schema: "jetstreamer-horizon-host-holding-prefix-v2".into(),
            host: HOST.into(),
            prefix: "node_02/".into(),
            user_provided_prefix: true,
            authorization_reference: "fixture".into(),
        };
        let sha = "b".repeat(64);
        let key = object_key(&m, &sha).unwrap();
        let manifest = json!({"schema":"jetstreamer-horizon-holding-manifest-v2","host":HOST,"prefix":m.prefix,
            "object_key":key,"sha256":sha,"length":LENGTH,"canonical_archive":false,"uid":1001,"gid":1003,"mode":0o600});
        let msh = hex_lower(&Sha256::digest(serde_json::to_vec(&manifest).unwrap()));
        let c = json!({"schema":"jetstreamer-horizon-holding-custody-v2","host":HOST,"bucket":BUCKET,"prefix":m.prefix,
            "source":SOURCE,"mapping":b,"eligibility":b,"sha256":sha,"length":LENGTH,"object_key":key,
            "object_etag":"fixture-etag","manifest":manifest,"manifest_sha256":msh,
            "manifest_key":format!("{}manifests/{msh}.json",m.prefix),"remote_sha256_readback":true,
            "local_source_revalidated":true,"local_retirement_authorized":false,"canonical_publication_authorized":false,
            "runtime_checkpoint_qualified":false,"job_resume_authorized":false,"replay_launch_authorized":false});
        let e = json!({"schema":"jetstreamer-horizon-holding-eligibility-v2","host":HOST,"epoch":185,
            "source":SOURCE,"length":LENGTH,"sha256":sha,"multipart_etag":"fixture-etag","closed":true,
            "content_class":"public-chain-artifact","credentials_config_and_logs_excluded":true,
            "artifact_kind":"retained-failed-partial-archive","interrupted_container_unvalidated":true,
            "valid_prefix_established":false,"canonical_archive":false,"local_retirement_authorized":false,
            "failure_repaired":false,"job_resume_authorized":false,"runtime_checkpoint_qualified":false,
            "publication_authorized":false,"replay_launch_authorized":false,"remote_mutations":false,"r2_mutations":false,
            "guard_intent":b,"guard_completion":b,"qualification":b,"deployment":b,
            "source_identity":{"device":64512,"inode":100270097,"length":LENGTH,"links":1,"uid":1001,"gid":1003,
                "mode":0o600,"mtime_seconds":1792801929,"mtime_nanoseconds":171229060,
                "ctime_seconds":1792801929,"ctime_nanoseconds":171229060}});
        scope(&p, &m, &e, &c).unwrap();
        for (k, v) in [
            ("source", json!("/other/epoch-185.jet")),
            ("sha256", json!("c".repeat(64))),
            ("valid_prefix_established", json!(true)),
            ("job_resume_authorized", json!(true)),
            ("canonical_archive", json!(true)),
            ("closed", json!(false)),
            ("credentials_config_and_logs_excluded", json!(false)),
        ] {
            let mut bad = e.clone();
            bad[k] = v;
            assert!(scope(&p, &m, &bad, &c).is_err(), "{k}");
        }
        let mut bad = e.clone();
        bad["source_identity"]["inode"] = json!(1);
        assert!(scope(&p, &m, &bad, &c).is_err());
        for k in ["remote_sha256_readback", "local_source_revalidated"] {
            let mut bad = c.clone();
            bad[k] = json!(false);
            assert!(scope(&p, &m, &e, &bad).is_err(), "{k}");
        }
    }
    #[test]
    fn fresh_pressure_relief_never_releases_growth_or_admits_restore() {
        let f = json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","first_epoch":101,"last_epoch":200,
            "sampled_at_utc":"2026-10-24T00:56:00Z","epochs":[{"epoch":185,"state":"failed-needs-repair"}],
            "active":[],"diagnostics":[],"pipelines":[]});
        let c = json!({"schema":"jetstreamer-horizon-holding-retire185-capacity-v2","host":HOST,
            "sampled_at_utc":f["sampled_at_utc"],"recorded_unix_seconds":1792803360u64,
            "pressure_relief_only":true,"new_launch_authorized":false,"restore_authorized":false,
            "growth_claims_released":false,"pre_retirement_free_space_credit":0,
            "epoch185_original_growth_claim_retained":true,"epoch141_original_growth_claim_retained":true,
            "all_live_staged_and_retained_growth_claims_preserved":true,
            "guard_completion":{"path":Path::new(GUARD_ROOT).join("completion.json"),"sha256":COMPLETION_SHA},
            "retained185_physical_bytes":56_206_397_440u64,"all_current_protected_bytes":3_503_746_342_342u64,
            "original_claim_bindings":[
                {"epoch":185,"retained_growth_bytes":824_633_720_832u64,"binding":{"path":"/sealed/original185.json","sha256":"a".repeat(64)}},
                {"epoch":141,"retained_growth_bytes":1,"binding":{"path":"/sealed/original141.json","sha256":"b".repeat(64)}}]});
        capacity_shape(&c, &f, 1792803360).unwrap();
        for (k, v) in [
            ("growth_claims_released", json!(true)),
            ("restore_authorized", json!(true)),
            ("pre_retirement_free_space_credit", json!(1)),
            ("epoch141_original_growth_claim_retained", json!(false)),
            ("original_claim_bindings", json!([])),
            ("all_current_protected_bytes", json!(0)),
        ] {
            let mut bad = c.clone();
            bad[k] = v;
            assert!(capacity_shape(&bad, &f, 1792803360).is_err(), "{k}");
        }
        assert!(capacity_shape(&c, &f, 1792805161).is_err());
        assert!(capacity_shape(&c, &f, 1792803359).is_err());
        for (key, value) in [("epoch", json!(185)), ("retained_growth_bytes", json!(0))] {
            let mut bad = c.clone();
            bad["original_claim_bindings"][1][key] = value;
            assert!(capacity_shape(&bad, &f, 1792803360).is_err(), "{key}");
        }
        let mut reduced = c.clone();
        reduced["original_claim_bindings"][0]["retained_growth_bytes"] = json!(824_633_720_831u64);
        assert!(capacity_shape(&reduced, &f, 1792803360).is_err());
    }
    #[test]
    fn opt_in_closed_growth_capacity_preserves_original_binding_and141_whole_cap() {
        let projection = Bound {
            path: "/sealed/closed-view-plan.json".into(),
            sha256: "c".repeat(64),
        };
        let f = json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","first_epoch":101,"last_epoch":200,
            "sampled_at_utc":"2026-10-24T00:56:00Z","epochs":[{"epoch":185,"state":"failed-needs-repair"}],
            "active":[],"diagnostics":[],"pipelines":[]});
        let c = json!({"schema":"jetstreamer-horizon-holding-retire185-closed-growth-capacity-v2","host":HOST,
            "sampled_at_utc":f["sampled_at_utc"],"recorded_unix_seconds":1792803360u64,
            "pressure_relief_only":true,"new_launch_authorized":false,"restore_authorized":false,
            "growth_claims_released":false,"pre_retirement_free_space_credit":0,
            "epoch185_original_growth_claim_retained":false,"epoch185_original_growth_binding_retained":true,
            "epoch141_original_growth_claim_retained":true,"all_live_staged_and_retained_growth_claims_preserved":true,
            "closed_growth_disposition":projection,
            "guard_completion":{"path":Path::new(GUARD_ROOT).join("completion.json"),"sha256":COMPLETION_SHA},
            "retained185_physical_bytes":56_206_397_440u64,"all_current_protected_bytes":3_503_746_342_342u64,
            "original_claim_bindings":[
                {"epoch":185,"retained_growth_bytes":0,"original_growth_bytes":824_633_720_832u64,
                 "binding":{"path":"/usr/local/lib/jetstreamer/horizon-epoch185-full-admission-20261023-v2/admission-manifest.json","sha256":"c2074a168945f30e2a9a83464f8d07e94e835bbb504e0a84c5cdf91323a71cb9"}},
                {"epoch":141,"retained_growth_bytes":549_755_813_888u64,
                 "binding":{"path":"/var/lib/jetstreamer/horizon-original141-capped-root-admission-20261023-v1/admission.json","sha256":"945561bbf6dc282cbc0375cb84d777abace765956f61e8cd1e35863056ca5b3b"}}]});
        after_growth_capacity_shape(&c, &f, 1792803360, &projection).unwrap();
        assert!(capacity_shape(&c, &f, 1792803360).is_err());
        for (key, value) in [
            ("epoch185_original_growth_claim_retained", json!(true)),
            ("epoch141_original_growth_claim_retained", json!(false)),
            ("pre_retirement_free_space_credit", json!(1)),
            ("growth_claims_released", json!(true)),
            ("new_launch_authorized", json!(true)),
            ("restore_authorized", json!(true)),
            ("closed_growth_disposition", json!({})),
            ("all_current_protected_bytes", json!(0)),
        ] {
            let mut bad = c.clone();
            bad[key] = value;
            assert!(
                after_growth_capacity_shape(&bad, &f, 1792803360, &projection).is_err(),
                "{key}"
            );
        }
        for (row, key, value) in [
            (0, "retained_growth_bytes", json!(1)),
            (0, "original_growth_bytes", json!(1)),
            (1, "retained_growth_bytes", json!(513_768_747_008u64)),
            (1, "epoch", json!(185)),
        ] {
            let mut bad = c.clone();
            bad["original_claim_bindings"][row][key] = value;
            assert!(after_growth_capacity_shape(&bad, &f, 1792803360, &projection).is_err());
        }
        assert!(after_growth_capacity_shape(&c, &f, 1792804261, &projection).is_err());
        let rows = json!({"projected_reservation_rows":[{"claim_key":"epoch141/e639f007d482464f8a251455659d2ede",
            "epoch":141,"producer_invocation_id":"e639f007d482464f8a251455659d2ede","outstanding_bytes":549_755_813_888u64}]});
        after_growth_projection_claims(&rows).unwrap();
        let mut reduced = rows.clone();
        reduced["projected_reservation_rows"][0]["outstanding_bytes"] = json!(1);
        assert!(after_growth_projection_claims(&reduced).is_err());
        assert!(after_growth_projection_claims(&json!({"projected_reservation_rows":[]})).is_err());
    }
    #[test]
    fn retirement_plan_cannot_select_paths_or_release_claims() {
        let b = json!({"path":"/sealed/fixture.json","sha256":"a".repeat(64)});
        let p = json!({"schema":"jetstreamer-horizon-holding-retire185-plan-v2",
            "mapping":b,"guard_intent":b,"guard_completion":b,"qualification":b,"deployment":b,
            "inspection":b,"custody":b,"capacity_completion":b,"prior_check":null});
        assert!(
            serde_json::from_value::<Retire>(p.clone())
                .unwrap()
                .closed_growth_disposition
                .is_none()
        );
        for key in ["source", "quarantine", "scratch", "release_growth_claims"] {
            let mut bad = p.clone();
            bad[key] = json!(true);
            assert!(serde_json::from_value::<Retire>(bad).is_err(), "{key}");
        }
    }
    #[allow(clippy::type_complexity)]
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
        let f = json!({"epochs":[{"epoch":185,"state":"failed-needs-repair"}],
            "active":[],"diagnostics":[],"pipelines":[]});
        no_replacement(&f).unwrap();
        for state in ["remote-ready", "live-replay", "post-replay-pipeline"] {
            let mut bad = f.clone();
            bad["epochs"][0]["state"] = json!(state);
            assert!(no_replacement(&bad).is_err());
        }
        for key in ["active", "diagnostics", "pipelines"] {
            let mut bad = f.clone();
            bad[key] = json!([{"epoch":185,"live":true}]);
            assert!(no_replacement(&bad).is_err(), "{key}");
        }
        let mut queued = f.clone();
        queued["diagnostics"] =
            json!([{"live":true,"epoch":183,"scope_first_epoch":183,"scope_last_epoch":186}]);
        assert!(no_replacement(&queued).is_err());
    }
}
