//! Exact stopped epoch166 partial and generated-index retirement.
//! The incomplete archive requires authenticated holding custody. The old
//! observer's producer log, scratch path, and all other retry inputs survive.
use super::*;

const RETRY4: &str = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry4-20261110-v1";
const RETRY1: &str = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3-retry1-20261112-v1";
const ORIGINAL: &str = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1";
const ARCHIVE: &str = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry4-20261110-v1/private/destination-b4e2b6004dd0e2b4dc8c3020c195b763d5b2abcb0824cf35dafec6c9c2eaf61f/work/root-cohort-166-166/run-3455726-1794673967150051149/archives/epoch-166.jet";
const INDEX165: &str = "165/epoch-165-bafyreibtqc7jzj5pyctcpa5a6cwqm5r3nzbx2nlhesvwau3merpsonx76i-mainnet-slot-to-cid.index";
const INDEX166_SLOT: &str = "166/epoch-166-bafyreibiiohrh4nfurrukccpyjdwu3c5a5ym4y5nqhkntxez734kdtlafe-mainnet-slot-to-cid.index";
const INDEX166_CID: &str = "166/epoch-166-bafyreibiiohrh4nfurrukccpyjdwu3c5a5ym4y5nqhkntxez734kdtlafe-mainnet-cid-to-offset-and-size.index";
const ARCHIVE_SHA: &str = "dcbd56bd3eb9ba79c04c193e4c98d6ccc38dc8b2d85bf1a451321348554750bb";
const SLOT165_SHA: &str = "ce8778e9da2f309ce9872a1db794b48ab5a31ff6fdf90ee42c657ea8ec29889a";
const SLOT166_SHA: &str = "230bffbd50eac3f7a45d5b60f6f3a260a3cc1e0eb0f9f9a14e7ffa564256658f";
const CID166_SHA: &str = "faf457fe25a5fcef1451942a6118f91b39d0d352488257b01de8f80b8783b49b";
const ELIGIBILITY: &str = "/var/lib/jetstreamer/peer170-completed167-native-operation-zero166-20261116-v2/terminal170-0825-v1/cycle0127-host-disk-audit-v1/holding166-v1/ELIGIBILITY.json";
const ELIGIBILITY_SHA: &str = "23efef7609b4f24f22decb777b36dd08a92781ce2636baeae91bd70d9d8f2ab7";
const TERMINAL: &str =
    "/var/lib/jetstreamer/root0348-oneowner-cycle-20261116-v1/TERMINAL166_EVENT.json";
const TERMINAL_SHA: &str = "0fb4f358747aefaaf5f34e93cfce8156a21cd0abc33138151456f258e2217231";
const MAPPING: &str = "/usr/local/lib/jetstreamer/horizon-node02-holding-20261023-v1/mapping.json";
const MAPPING_SHA: &str = "61f7601f78a7aa1f71394a020cbbb28aa9dbd85de858f139def1c989f2b2a89e";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Retire166 {
    schema: String,
    mapping: Bound,
    eligibility: Bound,
    terminal: Bound,
    custody: Bound,
    prior_check: Option<Bound>,
}

struct Member {
    path: PathBuf,
    identity: FileIdentity,
    sha256: &'static str,
    held: bool,
}

fn member(
    path: PathBuf,
    inode: u64,
    length: u64,
    seconds: i64,
    nanos: i64,
    sha256: &'static str,
    held: bool,
) -> Member {
    Member {
        path,
        identity: FileIdentity {
            device: 64512,
            inode,
            length,
            modified_seconds: seconds,
            modified_nanoseconds: nanos,
        },
        sha256,
        held,
    }
}

fn members() -> Vec<Member> {
    let retry4 = Path::new(RETRY4).join("output/compact-indexes");
    let retry1 = Path::new(RETRY1).join("output/compact-indexes");
    vec![
        member(
            ARCHIVE.into(),
            103678008,
            84062771182,
            1794800811,
            338281827,
            ARCHIVE_SHA,
            true,
        ),
        member(
            retry4.join(INDEX165),
            104071173,
            15490506,
            1794674169,
            502423230,
            SLOT165_SHA,
            false,
        ),
        member(
            retry4.join(INDEX166_SLOT),
            104071176,
            15281271,
            1794674173,
            215440464,
            SLOT166_SHA,
            false,
        ),
        member(
            retry4.join(INDEX166_CID),
            104071177,
            4196268262,
            1794674220,
            29657736,
            CID166_SHA,
            false,
        ),
        member(
            retry1.join(INDEX165),
            103677956,
            15490506,
            1794506754,
            548971328,
            SLOT165_SHA,
            false,
        ),
        member(
            retry1.join(INDEX166_SLOT),
            103677964,
            15281271,
            1794506757,
            417985500,
            SLOT166_SHA,
            false,
        ),
        member(
            retry1.join(INDEX166_CID),
            103677966,
            4196268262,
            1794506791,
            699154272,
            CID166_SHA,
            false,
        ),
    ]
}

fn retained_indexes() -> Vec<Member> {
    let original = Path::new(ORIGINAL).join("output/compact-indexes");
    vec![
        member(
            original.join(INDEX165),
            103874563,
            15490506,
            1794243343,
            78506412,
            SLOT165_SHA,
            false,
        ),
        member(
            original.join(INDEX166_SLOT),
            103874565,
            15281271,
            1794243346,
            912522298,
            SLOT166_SHA,
            false,
        ),
        member(
            original.join(INDEX166_CID),
            103874566,
            4196268262,
            1794243380,
            322660847,
            CID166_SHA,
            false,
        ),
    ]
}

fn local_mutation_lock() -> Result<File> {
    let path = Path::new("/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock");
    let md = fs::symlink_metadata(path)?;
    ensure!(
        md.is_file()
            && md.uid() == 1001
            && md.gid() == 1003
            && md.mode() & 0o7777 == 0o600
            && md.nlink() == 1
            && path.canonicalize()? == path,
        "166 shared local mutation lock changed"
    );
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    use std::os::fd::AsRawFd;
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "166 shared local mutation lock is occupied"
    );
    Ok(file)
}

fn absent(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e.into()),
        Ok(_) => Ok(false),
    }
}

fn record(path: &Path) -> Result<Option<Value>> {
    if absent(path)? {
        return Ok(None);
    }
    let md = fs::symlink_metadata(path)?;
    ensure!(
        md.is_file()
            && md.uid() == 0
            && md.mode() & 0o222 == 0
            && md.nlink() == 1
            && md.len() <= 1 << 20
            && path.canonicalize()? == path,
        "unsafe 166 retirement record: {}",
        path.display()
    );
    let id = regular_identity(path)?;
    let bytes = fs::read(path)?;
    ensure!(
        regular_identity(path)? == id,
        "166 retirement record changed"
    );
    Ok(Some(serde_json::from_slice(&bytes)?))
}

fn stopped(name: &str) -> Result<()> {
    let output = std::process::Command::new("/usr/bin/systemctl")
        .args([
            "show",
            name,
            "--no-pager",
            "--property=Id,ActiveState,MainPID,Job,NRestarts",
        ])
        .output()?;
    ensure!(
        output.status.success() && output.stdout.len() < 4096,
        "166 owner census failed"
    );
    let text = std::str::from_utf8(&output.stdout)?;
    let terminal = if name.ends_with(".timer") {
        true
    } else {
        text.contains("MainPID=0\n") && text.contains("NRestarts=0\n")
    };
    ensure!(
        text.contains("ActiveState=inactive\n") && text.contains("Job=\n") && terminal,
        "166 old owner or guard is still launchable: {name}: {text}"
    );
    Ok(())
}

fn static_scope(p: &Retire166, m: &Mapping, e: &Value, t: &Value, c: &Value) -> Result<String> {
    ensure!(
        p.schema == "jetstreamer-horizon-holding-retire166-plan-v1"
            && m.host == HOST
            && m.prefix == "node_02/"
            && p.mapping.path == Path::new(MAPPING)
            && p.mapping.sha256 == MAPPING_SHA
            && p.eligibility.path == Path::new(ELIGIBILITY)
            && p.eligibility.sha256 == ELIGIBILITY_SHA
            && p.terminal.path == Path::new(TERMINAL)
            && p.terminal.sha256 == TERMINAL_SHA
            && e["schema"] == "jetstreamer-horizon-holding-eligibility-v2"
            && e["epoch"] == 166
            && e["generation"] == "local3retry4"
            && e["source"] == ARCHIVE
            && e["sha256"] == ARCHIVE_SHA
            && e["length"] == 84062771182u64
            && e["closed"] == true
            && e["canonical_archive"] == false
            && e["local_retirement_authorized"] == false
            && t["epoch"] == 166
            && t["original_invocation_id"] == "58778e77980e4a15828c3be837e447aa"
            && t["resource_credit_bytes"] == 0
            && c["source"] == ARCHIVE
            && c["sha256"] == ARCHIVE_SHA
            && c["eligibility"] == serde_json::to_value(&p.eligibility)?
            && c["mapping"] == serde_json::to_value(&p.mapping)?,
        "166 retirement scope or source lineage differs"
    );
    let (key, _, sha, length) = custody(c, m)?;
    ensure!(
        sha == ARCHIVE_SHA
            && length == 84062771182u64
            && key == format!("node_02/objects/{ARCHIVE_SHA}.blob")
            && e["source_identity"]["device"] == 64512
            && e["source_identity"]["inode"] == 103678008
            && e["source_identity"]["links"] == 1,
        "166 held archive identity differs"
    );
    Ok(key)
}

async fn remote(client: &Client, m: &Mapping, c: &Value, key: &str) -> Result<RemoteArchive> {
    let expected_owner = owner_bytes(m)?;
    ensure!(
        get_mutable_object(client, BUCKET, &format!("{}owner.json", m.prefix))
            .await?
            .is_some_and(|v| v.bytes == expected_owner),
        "166 holding owner differs"
    );
    let manifest = get_mutable_object(
        client,
        BUCKET,
        c["manifest_key"].as_str().context("166 manifest key")?,
    )
    .await?
    .context("166 held manifest absent")?;
    ensure!(
        hex_lower(&Sha256::digest(&manifest.bytes)) == c["manifest_sha256"].as_str().unwrap()
            && serde_json::from_slice::<Value>(&manifest.bytes)? == c["manifest"],
        "166 held manifest differs"
    );
    let remote = head_archive(client, BUCKET, key)
        .await?
        .context("166 held blob absent")?;
    remote_matches(
        &remote,
        key,
        84062771182,
        ARCHIVE_SHA,
        Some(c["object_etag"].as_str().context("166 custody ETag")?),
    )?;
    Ok(remote)
}

fn no_consumers(m: &Member) -> Result<()> {
    no_references(&m.path)?;
    let staged = jetstreamer_horizon_observe::dev_cache_check::sol_staged_path_references(&m.path)?;
    ensure!(
        staged["references"] == json!([]),
        "166 member has staged unit reference: {}",
        m.path.display()
    );
    Ok(())
}

fn verify(m: &Member, expected_etag: Option<&str>, retiring: bool) -> Result<()> {
    ensure!(
        m.path.canonicalize()? == m.path,
        "166 member path is aliased"
    );
    let md = fs::symlink_metadata(&m.path)?;
    ensure!(
        md.uid() == 1001
            && md.gid() == 1003
            && md.mode() & 0o7777 == 0o600
            && md.nlink() == 1
            && regular_identity(&m.path)? == m.identity,
        "166 member identity changed: {}",
        m.path.display()
    );
    if retiring {
        no_consumers(m)?;
    }
    let proof = hash_and_etag(&m.path, m.identity, DEFAULT_PART_SIZE)?;
    ensure!(
        proof.sha256_hex == m.sha256
            && expected_etag.is_none_or(|etag| proof.multipart_etag == etag)
            && regular_identity(&m.path)? == m.identity,
        "166 member bytes changed: {}",
        m.path.display()
    );
    if retiring {
        no_consumers(m)?;
    }
    Ok(())
}

fn basis(p: &Retire166) -> Value {
    json!({
        "schema": "jetstreamer-holding-retire166-basis-v1",
        "mapping": p.mapping, "eligibility": p.eligibility,
        "terminal": p.terminal, "custody": p.custody,
        "members": members().iter().map(|m| json!({
            "path": m.path, "identity": m.identity, "sha256": m.sha256, "held": m.held
        })).collect::<Vec<_>>(),
        "retained_original_indexes": retained_indexes().iter().map(|m| json!({
            "path": m.path, "identity": m.identity, "sha256": m.sha256
        })).collect::<Vec<_>>(),
        "observer_log_and_scratch_preserved": true,
        "canonical_publication_authorized": false,
        "remote_mutations": false
    })
}

pub(super) async fn run(
    client: &Client,
    m: &Mapping,
    p: &Retire166,
    spec: &Bound,
    check: bool,
) -> Result<()> {
    let _shared_lock = local_mutation_lock()?;
    let mapped: Mapping = serde_json::from_value(bound(&p.mapping)?)?;
    mapping(&mapped)?;
    ensure!(
        mapped.host == m.host && mapped.prefix == m.prefix,
        "166 mapping changed"
    );
    let e = bound(&p.eligibility)?;
    let t = evidence(&p.terminal, false)?;
    let c = bound(&p.custody)?;
    let key = static_scope(p, m, &e, &t, &c)?;
    stopped("horizon-qualify-166-replacement-local3retry4-20261110-v1.service")?;
    stopped("horizon-guard-replacement-166-local3retry4-20261110-v1.service")?;
    stopped("horizon-guard-replacement-166-local3retry4-20261110-v1.timer")?;
    ensure!(
        absent(Path::new(&format!("{ARCHIVE}.sha256")))?
            && absent(Path::new(ARCHIVE).with_extension("sha256").as_path())?,
        "166 incomplete archive acquired a sidecar"
    );
    let held = remote(client, m, &c, &key).await?;
    for retained in retained_indexes() {
        verify(&retained, None, false)?;
    }
    let root = Path::new(STATE).join("receipts");
    private(&root)?;
    let intent_path = root.join("retire166-intent-v1.json");
    let completion_path = root.join("retire166-completion-v1.json");
    let intent = basis(p);
    let old_intent = record(&intent_path)?;
    if let Some(v) = &old_intent {
        ensure!(*v == intent, "166 retirement intent conflicts");
    }
    let all = members();
    for (i, member) in all.iter().enumerate() {
        if absent(&member.path)? {
            ensure!(
                old_intent.is_some(),
                "166 member absent before retirement intent"
            );
            continue;
        }
        verify(
            member,
            if member.held {
                Some(c["object_etag"].as_str().context("166 ETag")?)
            } else {
                None
            },
            true,
        )?;
        if member.held {
            let proof = hash_and_etag(&member.path, member.identity, DEFAULT_PART_SIZE)?;
            native_checksum(&held, &proof, member.identity.length)?;
        }
        ensure!(i < 7, "166 member census escaped fixed set");
    }
    if check {
        ensure!(p.prior_check.is_none(), "166 check borrowed a prior check");
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let check_path = root.join(format!("retire166-check-{}.json", spec.sha256));
        persist(
            &check_path,
            &json!({
                "schema": "jetstreamer-holding-retire166-check-v1",
                "basis": intent, "recorded_unix_seconds": now,
                "custody_readback_and_remote_head_verified": true,
                "all_present_or_intent_accounted": true,
                "data_removed": false, "remote_mutations": false
            }),
        )?;
        println!("{}", check_path.display());
        return Ok(());
    }
    let prior = bound(
        p.prior_check
            .as_ref()
            .context("166 execution needs a sealed check")?,
    )?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        prior["schema"] == "jetstreamer-holding-retire166-check-v1"
            && prior["basis"] == intent
            && prior["custody_readback_and_remote_head_verified"] == true
            && prior["all_present_or_intent_accounted"] == true
            && prior["data_removed"] == false
            && prior["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t <= now && now - t <= 900),
        "166 retirement check is stale or foreign"
    );
    if old_intent.is_none() {
        persist(&intent_path, &intent)?;
    }
    for (i, member) in all.iter().enumerate() {
        let receipt_path = root.join(format!("retire166-member-{i}-v1.json"));
        let receipt = json!({
            "schema": "jetstreamer-holding-retire166-member-v1",
            "intent": intent, "index": i,
            "path": member.path, "identity": member.identity,
            "sha256": member.sha256, "held": member.held,
            "source_absent": true, "remote_mutations": false
        });
        if let Some(v) = record(&receipt_path)? {
            ensure!(
                v == receipt && absent(&member.path)?,
                "166 member receipt conflicts"
            );
            continue;
        }
        if !absent(&member.path)? {
            verify(
                member,
                if member.held {
                    Some(c["object_etag"].as_str().context("166 ETag")?)
                } else {
                    None
                },
                true,
            )?;
            if member.held {
                let proof = hash_and_etag(&member.path, member.identity, DEFAULT_PART_SIZE)?;
                native_checksum(&held, &proof, member.identity.length)?;
            }
            fs::remove_file(&member.path)?;
            File::open(member.path.parent().context("166 member parent")?)?.sync_all()?;
        }
        ensure!(absent(&member.path)?, "166 member survived retirement");
        persist(&receipt_path, &receipt)?;
    }
    ensure!(
        all.iter().all(|m| absent(&m.path).unwrap_or(false)),
        "166 retirement incomplete"
    );
    for retained in retained_indexes() {
        verify(&retained, None, false)?;
    }
    let _ = remote(client, m, &c, &key).await?;
    persist(
        &completion_path,
        &json!({
            "schema": "jetstreamer-holding-retire166-completion-v1",
            "intent": intent, "members_retired": 7,
            "observer_log_and_scratch_preserved": true,
            "actual_free_space_delta_claimed": false,
            "replay_launch_authorized": false, "remote_mutations": false
        }),
    )?;
    println!("{}", completion_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_set_has_one_held_archive_and_six_generated_indexes() {
        let files = members();
        assert_eq!(files.len(), 7);
        assert_eq!(files.iter().filter(|m| m.held).count(), 1);
        assert_eq!(files[0].path, Path::new(ARCHIVE));
        assert!(
            files
                .iter()
                .all(|m| m.path.starts_with(RETRY4) || m.path.starts_with(RETRY1))
        );
        assert!(files.iter().all(|m| !m.path.ends_with("producer.log")));
        assert_eq!(
            files.iter().map(|m| m.identity.length).sum::<u64>(),
            92516851260
        );
    }

    #[test]
    fn scope_rejects_crossed_custody_and_terminal() {
        let mapping = Bound {
            path: MAPPING.into(),
            sha256: MAPPING_SHA.into(),
        };
        let eligibility = Bound {
            path: ELIGIBILITY.into(),
            sha256: ELIGIBILITY_SHA.into(),
        };
        let terminal = Bound {
            path: TERMINAL.into(),
            sha256: TERMINAL_SHA.into(),
        };
        let p = Retire166 {
            schema: "jetstreamer-horizon-holding-retire166-plan-v1".into(),
            mapping: mapping.clone(),
            eligibility: eligibility.clone(),
            terminal,
            custody: Bound {
                path: "/tmp/fixture-custody.json".into(),
                sha256: ARCHIVE_SHA.into(),
            },
            prior_check: None,
        };
        let m = Mapping {
            schema: "jetstreamer-horizon-host-holding-prefix-v2".into(),
            host: HOST.into(),
            prefix: "node_02/".into(),
            user_provided_prefix: true,
            authorization_reference: "fixture".into(),
        };
        let manifest = json!({
            "schema": "jetstreamer-horizon-holding-manifest-v2", "host": HOST,
            "prefix": m.prefix, "object_key": format!("node_02/objects/{ARCHIVE_SHA}.blob"),
            "sha256": ARCHIVE_SHA, "length": 84062771182u64, "canonical_archive": false
        });
        let manifest_sha = hex_lower(&Sha256::digest(serde_json::to_vec(&manifest).unwrap()));
        let mut c = json!({
            "schema": "jetstreamer-horizon-holding-custody-v2", "host": HOST,
            "bucket": BUCKET, "prefix": "node_02/", "mapping": mapping,
            "source": ARCHIVE, "sha256": ARCHIVE_SHA, "length": 84062771182u64,
            "object_key": format!("node_02/objects/{ARCHIVE_SHA}.blob"), "object_etag": "fixture-etag",
            "manifest": manifest, "manifest_sha256": manifest_sha,
            "manifest_key": format!("node_02/manifests/{manifest_sha}.json"),
            "eligibility": eligibility, "remote_sha256_readback": true,
            "local_source_revalidated": true, "local_retirement_authorized": false,
            "canonical_publication_authorized": false, "runtime_checkpoint_qualified": false,
            "job_resume_authorized": false, "replay_launch_authorized": false
        });
        let e = json!({
            "schema": "jetstreamer-horizon-holding-eligibility-v2", "epoch": 166,
            "generation": "local3retry4", "source": ARCHIVE, "sha256": ARCHIVE_SHA,
            "length": 84062771182u64, "closed": true, "canonical_archive": false,
            "local_retirement_authorized": false,
            "source_identity": {"device": 64512, "inode": 103678008, "links": 1}
        });
        let t = json!({"epoch":166,"original_invocation_id":"58778e77980e4a15828c3be837e447aa","resource_credit_bytes":0});
        assert!(static_scope(&p, &m, &e, &t, &c).is_ok());
        c["source"] = json!("/tmp/crossed.jet");
        assert!(static_scope(&p, &m, &e, &t, &c).is_err());
        c["source"] = json!(ARCHIVE);
        let mut crossed = e.clone();
        crossed["source_identity"]["inode"] = json!(1);
        assert!(static_scope(&p, &m, &crossed, &t, &c).is_err());
    }
}
