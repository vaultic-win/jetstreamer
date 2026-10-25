//! One preserved forensic old203 partial. No canonical archive or resume authority.
use super::foundation213::retirement as journal;
use super::*;
use jetstreamer_horizon_observe::foundation_holding213_review as host;
use std::os::fd::AsRawFd;
const SOURCE: &str =
    "/home/ubuntu/.jetstreamer-private/root-prefix-resource-203-v1/output/epoch-203-prefix.jet";
const SHA: &str = "bf8ebe7694c51ad7a9acdb0368ab7cb1a646d870291e219c30f4eb2de06e00fc";
const LENGTH: u64 = 81_739_258_626;
const STATE: &str = "/home/ubuntu/.jetstreamer-private/r2-holding-foundation-node-01-v1";
const PRESERVATION: &str =
    "/var/lib/jetstreamer/horizon-203-stopped-scratch-retire-receipts-v2/completion.json";
const PRESERVATION_SHA: &str = "d5f580866c2d9457951627da1433891bb15285555b1765b513e99cc20c8a1202";
const UNIT: &str = "jetstreamer-foundation203-partial-v1.service";
const PROFILE: &str = "foundation-old203-forensic-partial-v1";
const METADATA: u64 = 64 << 20;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    mapping: Bound,
    resource_basis: Value,
    admissions_must_be_serialized_until_phase_complete: bool,
    #[serde(default)]
    custody: Option<Bound>,
    #[serde(default)]
    restoration: Option<Bound>,
    #[serde(default)]
    original_retirement: Option<Bound>,
}
pub(super) fn command(s: &str) -> bool {
    matches!(
        s,
        "holding-foundation203-park"
            | "holding-foundation203-restore"
            | "holding-foundation203-retire-original"
            | "holding-foundation203-retire-restored"
    )
}
fn key() -> String {
    format!("{}objects/{SHA}.blob", host::PREFIX)
}
fn restore_dir() -> PathBuf {
    Path::new(STATE).join("foundation203-restores")
}
fn restored() -> PathBuf {
    restore_dir().join(format!("{SHA}.blob"))
}
fn owner() -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(
        &json!({"schema":"jetstreamer-horizon-holding-owner-v2","host":host::HOST,"prefix":host::PREFIX}),
    )?)
}
fn bound_value(b: &Bound) -> Value {
    json!({"path":b.path,"sha256":b.sha256})
}
fn link(p: &Spec, action: &str) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-foundation203-plan-v1"
            && p.admissions_must_be_serialized_until_phase_complete
            && p.mapping.path == Path::new(host::MAPPING)
            && p.mapping.sha256 == host::MAPPING_SHA,
        "foreign holding203 plan or host"
    );
    let shape = (
        p.custody.is_some(),
        p.restoration.is_some(),
        p.original_retirement.is_some(),
    );
    ensure!(
        match action {
            "holding-foundation203-park" => shape == (false, false, false),
            "holding-foundation203-restore" => shape == (true, false, false),
            "holding-foundation203-retire-original" => shape == (true, true, false),
            "holding-foundation203-retire-restored" => shape == (true, true, true),
            _ => false,
        },
        "holding203 phase bindings differ"
    );
    Ok(())
}
fn write(path: &Path, v: &Value) -> Result<Bound> {
    persist_with_limit(path, v, 8 << 20)?;
    File::open(path)?.sync_all()?;
    File::open(path.parent().context("holding203 receipt parent")?)?.sync_all()?;
    let bytes = read_stable_bounded(path, 8 << 20, "holding203 receipt")?;
    Ok(Bound {
        path: path.into(),
        sha256: hex_lower(&Sha256::digest(bytes)),
    })
}
fn record(b: &Bound) -> Result<Value> {
    evidence_with_limit(b, true, 8 << 20)
}
fn file_stamp(m: &fs::Metadata) -> Value {
    json!({"bytes":m.len(),"ctime":[m.ctime(),m.ctime_nsec()],"device":m.dev(),"gid":m.gid(),"inode":m.ino(),"links":m.nlink(),"mode":m.mode(),"mtime":[m.mtime(),m.mtime_nsec()],"uid":m.uid()})
}
fn original_id() -> Value {
    json!({"device":66305,"inode":22833838,"length":LENGTH,"uid":1000,"gid":1000,"mode":0o644,"nlink":1,"mtime":1792575305i64,"mtime_ns":168598802i64})
}
fn identity_at(path: &Path, expected: &Value, initial: bool) -> Result<FileIdentity> {
    ensure!(path.canonicalize()? == path, "holding203 aliased source");
    let md = fs::symlink_metadata(path)?;
    ensure!(
        md.is_file() && journal::id(&md) == *expected,
        "holding203 source replaced"
    );
    if initial {
        ensure!(
            md.ctime() == 1792575305 && md.ctime_nsec() == 168598802,
            "holding203 original changed before custody/retirement"
        );
    }
    regular_identity(path)
}
fn hash_at(path: &Path, expected: &Value, initial: bool) -> Result<LocalProof> {
    let id = identity_at(path, expected, initial)?;
    let proof = hash_and_etag(path, id, DEFAULT_PART_SIZE)?;
    ensure!(
        proof.sha256_hex == SHA && identity_at(path, expected, initial)? == id,
        "holding203 content changed"
    );
    Ok(proof)
}
fn preservation() -> Result<Value> {
    let p = record(&Bound {
        path: PRESERVATION.into(),
        sha256: PRESERVATION_SHA.into(),
    })?;
    ensure!(
        p["schema"] == "jetstreamer-epoch203-disk-scratch-completion-v1"
            && p["scratch_empty"] == true
            && p["original_root_preserved"] == true
            && p["partial_archive_and_inputs_preserved"] == true
            && p["archive_deletion_authorized"] == false,
        "holding203 preservation evidence differs"
    );
    let entries = p["preserved_artifacts"]
        .as_array()
        .context("holding203 preserved set absent")?;
    let selected = entries
        .iter()
        .filter(|v| v["path"] == SOURCE)
        .collect::<Vec<_>>();
    ensure!(
        selected.len() == 1
            && selected[0]["sha256"] == SHA
            && selected[0]["identity"]["inode"] == 22833838
            && selected[0]["identity"]["bytes"] == LENGTH,
        "holding203 preserved partial substituted"
    );
    // Every other preserved artifact stays at its exact original identity. No
    // snapshot, failure journal, ledger input or runtime package is a target.
    for entry in entries.iter().filter(|v| v["path"] != SOURCE) {
        let path = Path::new(
            entry["path"]
                .as_str()
                .context("holding203 preserved path")?,
        );
        ensure!(
            path.canonicalize()? == path
                && file_stamp(&fs::symlink_metadata(path)?) == entry["identity"],
            "holding203 nonselected evidence changed"
        );
    }
    Ok(p)
}
fn own_unit(action: &str, spec: &Bound) -> Result<Value> {
    let fields = "Id,User,Group,Type,ActiveState,SubState,InvocationID,MainPID,NRestarts,Restart,MemoryMax,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec,TimeoutStartUSec,NoNewPrivileges,ProtectSystem,ProtectHome,ReadWritePaths,ExecStart,ExecStartPre,ExecStartPost,ExecStop,ExecStopPost,ExecCondition,OnSuccess,OnFailure,TriggeredBy";
    let out = std::process::Command::new("/usr/bin/systemctl")
        .args(["show", UNIT, "--no-pager", &format!("--property={fields}")])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 65536,
        "holding203 bounded tool properties unavailable"
    );
    let mut v = serde_json::Map::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, x) = line.split_once('=').context("holding203 tool properties")?;
        ensure!(
            v.insert(k.into(), json!(x)).is_none(),
            "duplicate tool property"
        );
    }
    let v = Value::Object(v);
    let iid = env::var("INVOCATION_ID")?;
    ensure!(
        digest(&spec.sha256)
            && iid.len() == 32
            && iid.bytes().all(|c| c.is_ascii_hexdigit())
            && v["Id"] == UNIT
            && v["User"] == "root"
            && v["Group"] == "root"
            && v["Type"] == "oneshot"
            && v["ActiveState"] == "activating"
            && v["SubState"] == "start"
            && v["InvocationID"] == iid
            && v["MainPID"].as_str().and_then(|n| n.parse::<u32>().ok())
                == Some(std::process::id())
            && v["Restart"] == "no"
            && v["NRestarts"] == "0"
            && v["MemoryMax"] == "6442450944"
            && v["MemorySwapMax"] == "0"
            && v["TasksMax"] == "256"
            && v["CPUQuotaPerSecUSec"] == "2s"
            && v["TimeoutStartUSec"] == "30min"
            && v["NoNewPrivileges"] == "yes"
            && v["ProtectSystem"] == "strict"
            && v["ProtectHome"] == "read-only"
            && v["ReadWritePaths"]
                == format!("{STATE} {}", Path::new(SOURCE).parent().unwrap().display())
            && [
                "ExecStartPre",
                "ExecStartPost",
                "ExecStop",
                "ExecStopPost",
                "ExecCondition",
                "OnSuccess",
                "OnFailure",
                "TriggeredBy"
            ]
            .iter()
            .all(|k| v[*k] == ""),
        "holding203 tool is not the exact bounded nonrestarting invocation"
    );
    let args: Vec<_> = env::args().collect();
    let own = fs::read_link("/proc/self/exe")?;
    let expected = format!(
        "{{ path={} ; argv[]={own_path} {action} {} --spec-sha256 {} --self-sha256 {}",
        own.display(),
        spec.path.display(),
        spec.sha256,
        args[6],
        own_path = own.display()
    );
    ensure!(
        v["ExecStart"]
            .as_str()
            .and_then(|s| s.split_once(" ; ignore_errors="))
            .is_some_and(|(s, _)| s == expected),
        "holding203 tool command differs"
    );
    Ok(v)
}
fn gates(p: &Spec, action: &str, spec: &Bound, restoring: bool) -> Result<Value> {
    let tool = own_unit(action, spec)?;
    let preserved = preservation()?;
    let closure = fleet::foundation_holding203_check(&p.resource_basis, restoring)?;
    let restored_references = no_references(&restored())?;
    ensure!(
        own_unit(action, spec)? == tool,
        "holding203 tool identity changed"
    );
    Ok(
        json!({"tool":tool,"admissions_must_be_serialized_until_phase_complete":true,"preservation_receipt":{"path":PRESERVATION,"sha256":PRESERVATION_SHA},"restored_references":restored_references,"preserved_artifact_count":preserved["preserved_artifacts"].as_array().unwrap().len(),"eligibility":closure}),
    )
}
fn manifest() -> Value {
    json!({"schema":"jetstreamer-foundation203-manifest-v1","profile":PROFILE,"host":host::HOST,"prefix":host::PREFIX,"source":SOURCE,"length":LENGTH,"sha256":SHA,"original_identity":original_id(),"preservation":{"path":PRESERVATION,"sha256":PRESERVATION_SHA},"canonical_archive":false,"runtime_checkpoint_qualified":false,"job_resume_authorized":false})
}
fn authority(v: &Value) -> Result<()> {
    for k in [
        "canonical_publication_authorized",
        "runtime_checkpoint_qualified",
        "job_resume_authorized",
        "local_retirement_authorized",
    ] {
        ensure!(
            v[k] == false,
            "holding203 receipt grants forbidden authority:{k}"
        );
    }
    Ok(())
}
fn custody(c: &Value, p: &Spec) -> Result<()> {
    ensure!(
        c["schema"] == "jetstreamer-foundation203-custody-v1"
            && c["mapping"] == bound_value(&p.mapping)
            && c["manifest"] == manifest()
            && c["object_key"] == key()
            && c["remote_sha256_readback"] == true
            && c["source_revalidated"] == true
            && c["owner_checked"] == true
            && c["object_etag"].as_str().is_some_and(|x| !x.is_empty()),
        "holding203 custody is incomplete or foreign"
    );
    authority(c)
}
async fn remote(client: &Client, c: &Value) -> Result<()> {
    let own = get_mutable_object(client, BUCKET, &format!("{}owner.json", host::PREFIX))
        .await?
        .context("holding203 owner absent")?;
    ensure!(own.bytes == owner()?, "holding203 owner changed");
    let bytes = serde_json::to_vec(&manifest())?;
    let expected_key = format!(
        "{}manifests/{}.json",
        host::PREFIX,
        hex_lower(&Sha256::digest(&bytes))
    );
    ensure!(
        c["manifest_key"] == expected_key,
        "holding203 manifest key differs"
    );
    let m = get_mutable_object(client, BUCKET, &expected_key)
        .await?
        .context("holding203 manifest absent")?;
    ensure!(m.bytes == bytes, "holding203 manifest changed");
    let k = key();
    let r = head_archive(client, BUCKET, &k)
        .await?
        .context("holding203 object absent")?;
    remote_matches(&r, &k, LENGTH, SHA, c["object_etag"].as_str())?;
    verify_remote_sha256(client, BUCKET, &k, &r.etag, LENGTH, SHA, 2).await?;
    Ok(())
}
fn restoration(r: &Value, p: &Spec, c: &Value) -> Result<()> {
    ensure!(
        r["schema"] == "jetstreamer-foundation203-restoration-v1"
            && r["custody"]
                == bound_value(p.custody.as_ref().context("holding203 custody missing")?)
            && r["mapping"] == bound_value(&p.mapping)
            && r["destination"] == restored().to_string_lossy().as_ref()
            && r["manifest"] == manifest()
            && r["object_etag"] == c["object_etag"]
            && r["whole_file_sha256_verified"] == true
            && r["restoration_complete"] == true
            && r["staging_only"] == true
            && r["restored_identity"].is_object(),
        "holding203 complete recoverable restoration absent"
    );
    authority(r)
}
async fn park(client: &Client, p: &Spec, spec: &Bound, action: &str) -> Result<()> {
    let before = gates(p, action, spec, false)?;
    let id = identity_at(Path::new(SOURCE), &original_id(), true)?;
    let proof = hash_at(Path::new(SOURCE), &original_id(), true)?;
    claim_owner(client, host::PREFIX, &owner()?).await?;
    let k = key();
    let payload = Park {
        schema: PROFILE.into(),
        mapping: p.mapping.clone(),
        eligibility: spec.clone(),
        source: SOURCE.into(),
        length: LENGTH,
        sha256: SHA.into(),
    };
    let r = verified_blob(client, &k, &payload, id, &proof).await?;
    hash_at(Path::new(SOURCE), &original_id(), true)?;
    let after = gates(p, action, spec, false)?;
    let bytes = serde_json::to_vec(&manifest())?;
    let mk = format!(
        "{}manifests/{}.json",
        host::PREFIX,
        hex_lower(&Sha256::digest(&bytes))
    );
    small_create(client, &mk, &bytes).await?;
    let receipt = json!({"schema":"jetstreamer-foundation203-custody-v1","mapping":p.mapping,"manifest":manifest(),"object_key":k,"object_etag":r.etag,"manifest_key":mk,
        "remote_sha256_readback":true,"source_revalidated":true,"owner_checked":true,"before":before,"after":after,"spec":spec,
        "canonical_publication_authorized":false,"runtime_checkpoint_qualified":false,"job_resume_authorized":false,"local_retirement_authorized":false});
    custody(&receipt, p)?;
    let b = write(
        &Path::new(STATE)
            .join("receipts")
            .join(format!("foundation203-custody-{}.json", spec.sha256)),
        &receipt,
    )?;
    println!("{}", b.path.display());
    Ok(())
}
async fn restore(client: &Client, p: &Spec, spec: &Bound, action: &str) -> Result<()> {
    let cb = p.custody.as_ref().context("holding203 custody absent")?;
    let c = record(cb)?;
    custody(&c, p)?;
    let before = gates(p, action, spec, true)?;
    remote(client, &c).await?;
    let minimum = before["eligibility"]["capacity"]["minimum_free_bytes"]
        .as_u64()
        .context("holding203 protected floor absent")?
        .checked_add(METADATA)
        .context("holding203 metadata overflow")?;
    let k = key();
    let dir = restore_dir();
    let path = restore_blob(
        client,
        BlobRestore {
            key: &k,
            etag: c["object_etag"].as_str().context("holding203 etag")?,
            sha: SHA,
            length: LENGTH,
            directory: &dir,
            minimum,
        },
        || {
            gates(p, action, spec, false)?;
            Ok(())
        },
    )
    .await?;
    let md = fs::symlink_metadata(&path)?;
    ensure!(
        md.uid() == 0 && md.gid() == 0 && md.mode() & 0o7777 == 0o400,
        "holding203 restore ownership differs"
    );
    let restored_id = journal::id(&md);
    hash_at(&path, &restored_id, false)?;
    let after = gates(p, action, spec, false)?;
    remote(client, &c).await?;
    let receipt = json!({"schema":"jetstreamer-foundation203-restoration-v1","mapping":p.mapping,"custody":cb,"destination":path,"manifest":manifest(),"object_etag":c["object_etag"],
        "restored_identity":restored_id,"whole_file_sha256_verified":true,"restoration_complete":true,"staging_only":true,"before":before,"after":after,"spec":spec,
        "canonical_publication_authorized":false,"runtime_checkpoint_qualified":false,"job_resume_authorized":false,"local_retirement_authorized":false});
    restoration(&receipt, p, &c)?;
    let b = write(
        &Path::new(STATE)
            .join("receipts")
            .join(format!("foundation203-restoration-{}.json", spec.sha256)),
        &receipt,
    )?;
    println!("{}", b.path.display());
    Ok(())
}
#[path = "holding_foundation203_retire.rs"]
mod retirement;
pub(super) async fn run(action: &str, v: Value, spec: &Bound) -> Result<()> {
    let p: Spec = serde_json::from_value(v)?;
    link(&p, action)?;
    host::validate_host_mapping()?;
    private(Path::new(STATE))?;
    private(&Path::new(STATE).join("receipts"))?;
    // Provisioning/sealing owns this private directory. Never create arbitrary
    // roots, borrow another host or share a restoration with another profile.
    private(&restore_dir())?;
    let root_device = fs::metadata("/")?.dev();
    ensure!(
        fs::metadata(STATE)?.dev() == root_device
            && fs::metadata(restore_dir())?.dev() == root_device,
        "holding203 state or restoration escaped admitted root filesystem"
    );
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(Path::new(STATE).join("transition.lock"))?;
    let m = lock.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.mode() & 0o777 == 0o600
            && unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "holding203 transition already owned"
    );
    let r2 = r2_config_from_env()?;
    ensure!(r2.bucket == BUCKET, "holding203 foreign bucket");
    let client = s3_client(&r2);
    match action {
        "holding-foundation203-park" => park(&client, &p, spec, action).await,
        "holding-foundation203-restore" => restore(&client, &p, spec, action).await,
        _ => retirement::run(&client, &p, spec, action).await,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn spec() -> Spec {
        Spec {
            schema: "jetstreamer-foundation203-plan-v1".into(),
            mapping: Bound {
                path: host::MAPPING.into(),
                sha256: host::MAPPING_SHA.into(),
            },
            resource_basis: json!({}),
            admissions_must_be_serialized_until_phase_complete: true,
            custody: None,
            restoration: None,
            original_retirement: None,
        }
    }
    #[test]
    fn exact_profile_never_borrows_other_host_source_or_phase_authority() {
        let mut p = spec();
        link(&p, "holding-foundation203-park").unwrap();
        assert!(link(&p, "holding-foundation203-retire-original").is_err());
        p.mapping.path = "/home/sol/mapping.json".into();
        assert!(link(&p, "holding-foundation203-park").is_err());
        let v = original_id();
        assert_eq!(v["inode"], 22833838);
        assert_eq!(v["length"], LENGTH);
        assert!(!command("holding-foundation203-retire-tree"));
    }
    #[test]
    fn restoration_and_custody_cannot_gain_retirement_or_resume_authority() {
        let p = spec();
        let mut c = json!({"schema":"jetstreamer-foundation203-custody-v1","mapping":p.mapping,"manifest":manifest(),"object_key":key(),"object_etag":"etag","remote_sha256_readback":true,"source_revalidated":true,"owner_checked":true,
            "canonical_publication_authorized":false,"runtime_checkpoint_qualified":false,"job_resume_authorized":false,"local_retirement_authorized":false});
        custody(&c, &p).unwrap();
        for field in [
            "remote_sha256_readback",
            "source_revalidated",
            "owner_checked",
        ] {
            let mut bad = c.clone();
            bad[field] = json!(false);
            assert!(custody(&bad, &p).is_err());
        }
        c["local_retirement_authorized"] = json!(true);
        assert!(custody(&c, &p).is_err());
    }
    fn evidence() -> Bound {
        Bound {
            path: "/sealed/receipt.json".into(),
            sha256: "a".repeat(64),
        }
    }
    #[test]
    fn source_and_restored_retirement_require_different_complete_bound_phases() {
        let mut p = spec();
        p.custody = Some(evidence());
        link(&p, "holding-foundation203-restore").unwrap();
        assert!(link(&p, "holding-foundation203-retire-original").is_err());
        p.restoration = Some(evidence());
        link(&p, "holding-foundation203-retire-original").unwrap();
        assert!(link(&p, "holding-foundation203-retire-restored").is_err());
        p.original_retirement = Some(evidence());
        link(&p, "holding-foundation203-retire-restored").unwrap();
        assert!(link(&p, "holding-foundation203-retire-original").is_err());
        p.admissions_must_be_serialized_until_phase_complete = false;
        assert!(link(&p, "holding-foundation203-retire-restored").is_err());
    }
    #[test]
    fn no_plan_can_select_another_source_or_turn_holding_into_a_checkpoint() {
        let mut value = json!({"schema":"jetstreamer-foundation203-plan-v1","mapping":evidence(),"resource_basis":{},"admissions_must_be_serialized_until_phase_complete":true});
        serde_json::from_value::<Spec>(value.clone()).unwrap();
        for (key, v) in [
            ("source", json!("/other/archive.jet")),
            ("sha256", json!("f".repeat(64))),
            ("job_resume_authorized", json!(true)),
            ("artifact", json!("prefix213")),
        ] {
            value[key] = v;
            assert!(
                serde_json::from_value::<Spec>(value.clone()).is_err(),
                "{key}"
            );
            value.as_object_mut().unwrap().remove(key);
        }
    }
    #[test]
    fn complete_restoration_is_bound_to_exact_custody_destination_and_file_proof() {
        let mut p = spec();
        p.custody = Some(evidence());
        let c = json!({"object_etag":"etag"});
        let r = json!({"schema":"jetstreamer-foundation203-restoration-v1","mapping":p.mapping,"custody":p.custody,"destination":restored(),"manifest":manifest(),"object_etag":"etag",
            "restored_identity":{"length":LENGTH,"uid":0,"gid":0,"mode":0o400,"nlink":1,"inode":999},
            "whole_file_sha256_verified":true,"restoration_complete":true,"staging_only":true,
            "canonical_publication_authorized":false,"runtime_checkpoint_qualified":false,"job_resume_authorized":false,"local_retirement_authorized":false});
        restoration(&r, &p, &c).unwrap();
        for (path, v) in [
            ("/custody/sha256", json!("f".repeat(64))),
            ("/destination", json!(SOURCE)),
            ("/manifest/sha256", json!("f".repeat(64))),
            ("/object_etag", json!("other")),
            ("/whole_file_sha256_verified", json!(false)),
            ("/restoration_complete", json!(false)),
            ("/staging_only", json!(false)),
            ("/job_resume_authorized", json!(true)),
        ] {
            let mut bad = r.clone();
            *bad.pointer_mut(path).unwrap() = v;
            assert!(restoration(&bad, &p, &c).is_err(), "{path}");
        }
    }
}
