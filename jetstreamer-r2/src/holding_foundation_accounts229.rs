//! Encrypted custody for the exact closed Foundation epoch 229 account bundle.
use super::*;
use std::os::unix::fs::DirBuilderExt;

pub(super) const ACTION: &str = "holding-foundation-229-accounts-park";
pub(super) const RECHECK: &str = "holding-foundation-229-accounts-recheck";
pub(super) const RESTORE: &str = "holding-foundation-229-accounts-restore";
const STAGE: (&str, &str) = (
    "/var/lib/jetstreamer/horizon229-v1-accounts-custody-v1/staged.json",
    "02df82d70e4dba36d440da2ab54b56381718647c120318f121b41b475217abc6",
);
const ORIGINAL_RETIREMENT: (&str, &str) = (
    "/var/lib/jetstreamer/horizon229-v1-accounts-retirement-v1/completion.json",
    "c27744e703d1fc4045453c2c3f129f812b486b63828f036f550856f14fe9e82f",
);
const CRYPTO_PROOF: (&str, &str) = (
    "/var/lib/jetstreamer/horizon229-holding-crypto-preflight-v1/completion.json",
    "9cf6d7047ff1ab24579382d90af69cfb28c8833cd65fc81ede686d8bcb478417",
);
const SOURCE: &str =
    "/var/lib/jetstreamer/horizon229-v1-accounts-custody-v1/epoch-229-closed-accounts.pax.zst";
const CLEAR_BYTES: u64 = 29_287_415_590;
const CLEAR_SHA: &str = "67787eef74f004504b443892637f9d30ace339e344b41793de88a364e6fb1de5";
const CIPHER_OVERHEAD: u64 = 16 << 20;
const UNIT: &str = "foundation-229-holding-custody-v1.service";
const RESTORE_UNIT: &str = "foundation-229-holding-restore-v1.service";
const KEY_ROOT: &str = "/var/lib/jetstreamer/horizon229-holding-custody-v1";
const PARK_PLAN: &str = "/var/lib/jetstreamer/horizon229-holding-custody-v1/park.json";
const RECHECK_PLAN: &str =
    "/var/lib/jetstreamer/horizon229-holding-custody-v1/park-recheck-v1.json";
const TMPFS: &str = "/tmp/foundation-229-custody";
const TMPFS_BYTES: u64 = 32 << 30;
const MEMORY_BYTES: u64 = 64 << 30;
const FORMAT: &str = "openpgp-aes256-gnu-sparse-pax-zstd-accounts";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    mapping: Bound,
    stage: Bound,
    original_retirement: Bound,
    crypto_proof: Bound,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecheckPlan {
    schema: String,
    mapping: Bound,
    park_plan: Bound,
    custody: Bound,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestorePlan {
    schema: String,
    mapping: Bound,
    custody_plan: Bound,
    admission: Bound,
}

fn expected_receipt(binding: &Bound, scope: (&str, &str)) -> Result<Value> {
    ensure!(
        binding.path == Path::new(scope.0) && binding.sha256 == scope.1,
        "foreign epoch 229 custody evidence"
    );
    saved(binding)
}

fn stage_admission(plan: &Plan) -> Result<Value> {
    let stage = expected_receipt(&plan.stage, STAGE)?;
    let retired = expected_receipt(&plan.original_retirement, ORIGINAL_RETIREMENT)?;
    let crypto = expected_receipt(&plan.crypto_proof, CRYPTO_PROOF)?;
    let admission: Bound = serde_json::from_value(crypto["admission"].clone())?;
    ensure!(
        admission.path
            == Path::new(
                "/var/lib/jetstreamer/horizon229-holding-crypto-preflight-v1/admission.json"
            ),
        "foreign epoch 229 crypto admission"
    );
    let checked = evidence(&admission, false)?;
    ensure!(
        stage["schema"] == "foundation-epoch229-locally-checked-accounts-stage-v1"
            && stage["epoch"] == 229
            && stage["bundle"] == SOURCE
            && stage["length"] == CLEAR_BYTES
            && stage["sha256"] == CLEAR_SHA
            && stage["full_sparse_comparison_matches"] == true
            && retired["epoch"] == 229
            && retired["empty_root_retained"] == true
            && retired["verified_allocated_bytes_removed"] == 153_204_084_736u64
            && crypto["schema"] == "foundation-epoch229-encrypted-holding-preflight-completion-v1"
            && crypto["epoch"] == 229
            && crypto["closed_bundle"] == SOURCE
            && crypto["remote_mutations"] == false,
        "epoch 229 sparse-stage and prior cleanup evidence differs"
    );
    ensure!(
        checked["source"] == SOURCE && checked["sha256"] == CLEAR_SHA,
        "foreign epoch 229 crypto source"
    );
    Ok(checked)
}

fn validate_source(plan: &Plan) -> Result<Stamp> {
    let checked = stage_admission(plan)?;
    let path = Path::new(SOURCE);
    private(path.parent().context("epoch 229 bundle parent")?)?;
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && meta.is_file()
            && meta.uid() == 0
            && meta.nlink() == 1
            && (meta.mode() & 0o7777) == 0o400
            && meta.len() == CLEAR_BYTES,
        "unsafe epoch 229 sparse source"
    );
    let stamp = Stamp::of(&meta);
    ensure!(
        checked["source_identity"] == crypto_stamp(&stamp),
        "epoch 229 source differs from the authenticated crypto preflight"
    );
    Ok(stamp)
}

fn crypto_stamp(stamp: &Stamp) -> Value {
    json!([
        stamp.device,
        stamp.inode,
        stamp.length,
        stamp.mtime_ns,
        stamp.ctime_ns
    ])
}

fn admitted_scope(unit: &str) -> Result<()> {
    let membership = fs::read_to_string("/proc/self/cgroup")?;
    let group = Path::new("/sys/fs/cgroup/system.slice").join(unit);
    ensure!(
        is_lower_hex(&env::var("INVOCATION_ID")?, 32)
            && membership.trim() == format!("0::/system.slice/{unit}")
            && fs::read_to_string(group.join("memory.max"))?.trim() == MEMORY_BYTES.to_string()
            && fs::read_to_string(group.join("memory.swap.max"))?.trim() == "0",
        "epoch 229 custody is outside its admitted memory scope"
    );
    Ok(())
}

fn tmpfs_scope(root: &Path) -> Result<()> {
    private(root)?;
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    let mut matching = mounts.lines().filter_map(|line| {
        let (details, source) = line.split_once(" - ")?;
        let mut fields = details.split_whitespace().skip(4);
        (Path::new(fields.next()?) == root).then(|| (fields.next(), source))
    });
    let (flags, source) = matching.next().context("missing epoch 229 private tmpfs")?;
    let flags = flags.context("missing epoch 229 tmpfs flags")?;
    let flags = flags.split(',').collect::<BTreeSet<_>>();
    let mut source = source.split_whitespace();
    ensure!(
        matching.next().is_none()
            && ["rw", "nosuid", "nodev", "noexec"]
                .into_iter()
                .all(|flag| flags.contains(flag))
            && source.next() == Some("tmpfs")
            && source.next().is_some()
            && source
                .next()
                .is_some_and(|opts| opts.split(',').any(|flag| flag == "noswap")),
        "epoch 229 custody mount is not private bounded tmpfs"
    );
    let c_path = std::ffi::CString::new(root.as_os_str().as_encoded_bytes())?;
    let mut vfs = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(c_path.as_ptr(), vfs.as_mut_ptr()) } == 0,
        "epoch 229 tmpfs capacity read failed"
    );
    let vfs = unsafe { vfs.assume_init() };
    ensure!(
        vfs.f_blocks.checked_mul(vfs.f_frsize) == Some(TMPFS_BYTES)
            && vfs.f_bavail.saturating_mul(vfs.f_frsize) >= CLEAR_BYTES + CIPHER_OVERHEAD
            && fs::read_dir(root)?.next().is_none(),
        "epoch 229 private tmpfs is occupied or outside the qualified cap"
    );
    Ok(())
}

fn wire_marker(spec: &Bound, wire_sha: &str) -> Result<String> {
    ensure!(
        digest(wire_sha) && digest(&spec.sha256),
        "invalid custody digest"
    );
    Ok(format!(
        "accounts229-encrypted-intent-{}-{wire_sha}.json",
        spec.sha256
    ))
}

fn intent(spec: &Bound, object: &str, wire_sha: &str, length: u64) -> Value {
    json!({"schema":"foundation-epoch229-encrypted-object-intent-v1","epoch":229,
        "plan":spec,"object_key":object,"wire_sha256":wire_sha,"length":length,
        "clear_bundle_sha256":CLEAR_SHA,"clear_bundle_length":CLEAR_BYTES,"format":FORMAT})
}

fn recovery_intent(spec: &Bound, object: &str, wire_sha: &str, length: u64) -> Result<Bound> {
    let name = wire_marker(spec, wire_sha)?;
    let mut bytes = serde_json::to_vec_pretty(&intent(spec, object, wire_sha, length))?;
    bytes.push(b'\n');
    Ok(Bound {
        path: Path::new(STATE).join("receipts").join(name),
        sha256: hex_lower(&Sha256::digest(bytes)),
    })
}

fn encrypted_object_key() -> String {
    format!("{SUBPREFIX}encrypted-accounts229/{CLEAR_SHA}.blob")
}

fn encrypted_manifest(key: &str, etag: &str, wire_sha: &str, length: u64) -> Value {
    json!({
        "schema":"foundation-epoch229-encrypted-accounts-manifest-v1","epoch":229,
        "object_key":key,"object_etag":etag,"format":FORMAT,"length":length,
        "sha256":wire_sha,"clear_bundle_sha256":CLEAR_SHA,"clear_bundle_length":CLEAR_BYTES,
        "canonical_archive":false,"publication_authorized":false
    })
}

async fn park(client: &Client, plan: Plan, spec: &Bound, before: Stamp, home: &Path) -> Result<()> {
    let object_key = encrypted_object_key();
    let existing = head_archive(client, BUCKET, &object_key).await?;
    let key_file = openpgp::key_file(
        Path::new(KEY_ROOT),
        "accounts-custody.key",
        existing.is_none(),
    )?;
    let (remote, wire_sha) = if let Some(remote) = existing {
        let sha = remote
            .metadata_sha256
            .as_deref()
            .context("missing encrypted custody SHA-256")?;
        saved(&recovery_intent(spec, &object_key, sha, remote.length)?)
            .context("existing encrypted object has no matching local intent")?;
        claim_owner(client, host::PREFIX, &owner_bytes()?).await?;
        let sha = sha.to_owned();
        (remote, sha)
    } else {
        let file = tempfile::NamedTempFile::new_in(TMPFS)?;
        let source = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(SOURCE)?;
        ensure!(
            Stamp::of(&source.metadata()?) == before,
            "epoch 229 input changed before encryption"
        );
        openpgp::encrypt(openpgp::gpg(home, &key_file)?, source, file.reopen()?)?;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o400))?;
        file.as_file().sync_all()?;
        openpgp::verify_encrypted_file(
            openpgp::gpg(home, &key_file)?,
            File::open(file.path())?,
            CLEAR_BYTES,
            CLEAR_SHA,
        )?;
        ensure!(
            validate_source(&plan)? == before,
            "epoch 229 input changed during encryption"
        );
        let identity = regular_identity(file.path())?;
        ensure!(
            (CLEAR_BYTES..=CLEAR_BYTES + CIPHER_OVERHEAD).contains(&identity.length),
            "epoch 229 unexpected ciphertext length"
        );
        let proof = hash_and_etag(file.path(), identity, DEFAULT_PART_SIZE)?;
        let sha = &proof.sha256_hex;
        receipt(
            &wire_marker(spec, sha)?,
            &intent(spec, &object_key, sha, identity.length),
        )?;
        claim_owner(client, host::PREFIX, &owner_bytes()?).await?;
        let (etag, _) = upload_object(
            client,
            BUCKET,
            ObjectUpload {
                key: &object_key,
                epoch: None,
                path: file.path(),
                identity,
                length: identity.length,
                sha256: sha,
                format: FORMAT,
            },
            DEFAULT_PART_SIZE,
            2,
            false,
        )
        .await?;
        ensure!(
            etag == proof.multipart_etag,
            "epoch 229 ciphertext multipart receipt differs"
        );
        let remote = head_archive(client, BUCKET, &object_key)
            .await?
            .context("epoch 229 ciphertext was not committed")?;
        remote_matches(&remote, &object_key, identity.length, sha, Some(&etag))?;
        native_checksum(&remote, &proof, identity.length)?;
        (remote, sha.to_owned())
    };
    let length = remote.length;
    ensure!(
        (CLEAR_BYTES..=CLEAR_BYTES + CIPHER_OVERHEAD).contains(&length),
        "epoch 229 remote ciphertext length differs"
    );
    remote_matches(&remote, &object_key, length, &wire_sha, Some(&remote.etag))?;
    // The upload's temporary ciphertext has been dropped. Use the same
    // bounded volume for a complete authenticated restore of the bundle.
    let restored = tempfile::NamedTempFile::new_in(TMPFS)?;
    let plain_file = restored.reopen()?;
    openpgp::read_decrypted(
        client,
        RemoteReadSpec {
            bucket: BUCKET,
            key: &object_key,
            etag: &remote.etag,
            expected_length: length,
            expected_sha256: &wire_sha,
            concurrency: 2,
        },
        openpgp::gpg(home, &key_file)?,
        move |plain| {
            openpgp::copy_verified_plaintext(
                plain,
                &plain_file,
                CLEAR_BYTES,
                CLEAR_SHA,
                || Ok(()),
            )?;
            plain_file.sync_all()?;
            Ok(())
        },
    )
    .await?;
    let restored_identity = regular_identity(restored.path())?;
    let restored_proof = hash_and_etag(restored.path(), restored_identity, DEFAULT_PART_SIZE)?;
    ensure!(
        restored_identity.length == CLEAR_BYTES && restored_proof.sha256_hex == CLEAR_SHA,
        "epoch 229 restored local bundle differs"
    );
    let final_remote = head_archive(client, BUCKET, &object_key)
        .await?
        .context("epoch 229 ciphertext disappeared during verification")?;
    remote_matches(
        &final_remote,
        &object_key,
        length,
        &wire_sha,
        Some(&remote.etag),
    )?;
    ensure!(
        validate_source(&plan)? == before,
        "epoch 229 source changed during transfer"
    );
    no_references(Path::new(SOURCE))?;
    let manifest = encrypted_manifest(&object_key, &remote.etag, &wire_sha, length);
    let bytes = serde_json::to_vec(&manifest)?;
    let manifest_sha = hex_lower(&Sha256::digest(&bytes));
    let marker = manifest_key(&manifest_sha)?;
    small_create(client, &marker, &bytes).await?;
    let result = receipt(
        &format!("accounts229-custody-{}.json", spec.sha256),
        &json!({
            "schema":"foundation-epoch229-encrypted-accounts-custody-v1","epoch":229,"bucket":BUCKET,
            "plan":spec,"source":SOURCE,"original_identity":before,"manifest":manifest,
            "manifest_key":marker,"manifest_sha256":manifest_sha,"stage":plan.stage,
            "remote_sha256_readback":true,"remote_authenticated_decryption_verified":true,
            "restored_bundle_reread_verified":true,
            "local_source_revalidated":true,"publication_authorized":false,"local_retirement_authorized":false
        }),
    )?;
    println!("{}", result.display());
    Ok(())
}

fn custody_manifest(custody: &Value) -> Result<(&str, &str, u64)> {
    let manifest = &custody["manifest"];
    let etag = manifest["object_etag"]
        .as_str()
        .context("missing custody ETag")?;
    let wire_sha = manifest["sha256"]
        .as_str()
        .context("missing ciphertext SHA-256")?;
    let length = manifest["length"]
        .as_u64()
        .context("missing ciphertext length")?;
    let (part_digest, part_count) = etag.split_once('-').context("missing multipart ETag")?;
    ensure!(
        (CLEAR_BYTES..=CLEAR_BYTES + CIPHER_OVERHEAD).contains(&length)
            && digest(wire_sha)
            && is_lower_hex(part_digest, 32)
            && part_count == length.div_ceil(DEFAULT_PART_SIZE).to_string()
            && *manifest == encrypted_manifest(&encrypted_object_key(), etag, wire_sha, length),
        "epoch 229 encrypted manifest identity differs"
    );
    Ok((etag, wire_sha, length))
}

fn accepted_custody(plan: &RecheckPlan) -> Result<(Plan, Value, Stamp)> {
    ensure!(
        plan.schema == "foundation-epoch229-encrypted-accounts-recheck-plan-v1"
            && plan.park_plan.path == Path::new(PARK_PLAN)
            && digest(&plan.park_plan.sha256)
            && plan.custody.path
                == Path::new(STATE).join("receipts").join(format!(
                    "accounts229-custody-{}.json",
                    plan.park_plan.sha256
                )),
        "foreign epoch 229 recheck plan or custody path"
    );
    let park_plan: Plan = serde_json::from_value(saved(&plan.park_plan)?)?;
    ensure!(
        park_plan.schema == "foundation-epoch229-accounts-park-v1"
            && serde_json::to_value(&park_plan.mapping)? == serde_json::to_value(&plan.mapping)?,
        "epoch 229 custody scope differs"
    );
    let checked = stage_admission(&park_plan)?;
    let custody = saved(&plan.custody)?;
    let original: Stamp = serde_json::from_value(custody["original_identity"].clone())?;
    ensure!(
        custody["schema"] == "foundation-epoch229-encrypted-accounts-custody-v1"
            && custody["epoch"] == 229
            && custody["bucket"] == BUCKET
            && custody["plan"] == serde_json::to_value(&plan.park_plan)?
            && custody["source"] == SOURCE
            && checked["source_identity"] == crypto_stamp(&original)
            && original.uid == 0
            && original.gid == 0
            && original.links == 1
            && original.mode == 0o400
            && original.length == CLEAR_BYTES
            && custody["stage"] == serde_json::to_value(&park_plan.stage)?
            && custody["remote_sha256_readback"] == true
            && custody["remote_authenticated_decryption_verified"] == true
            && custody["restored_bundle_reread_verified"] == true
            && custody["local_source_revalidated"] == true
            && custody["publication_authorized"] == false
            && custody["local_retirement_authorized"] == false,
        "epoch 229 custody did not prove a complete authenticated restoration"
    );
    Ok((park_plan, custody, original))
}

async fn authenticate(client: &Client, plan: &RecheckPlan, custody: &Value) -> Result<()> {
    let (etag, wire_sha, length) = custody_manifest(&custody)?;
    let key = encrypted_object_key();
    let bytes = serde_json::to_vec(&custody["manifest"])?;
    let manifest_sha = hex_lower(&Sha256::digest(&bytes));
    let marker = manifest_key(&manifest_sha)?;
    ensure!(
        custody["manifest_key"] == marker && custody["manifest_sha256"] == manifest_sha,
        "epoch 229 content-addressed manifest differs"
    );
    saved(&recovery_intent(&plan.park_plan, &key, wire_sha, length)?)?;
    let owner = get_mutable_object(client, BUCKET, &format!("{}owner.json", host::PREFIX))
        .await?
        .context("missing Foundation holding owner")?;
    ensure!(
        owner.bytes == owner_bytes()?,
        "foreign Foundation holding owner"
    );
    let manifest = get_mutable_object(client, BUCKET, &marker)
        .await?
        .context("missing epoch 229 holding manifest")?;
    ensure!(
        manifest.bytes == bytes,
        "authenticated epoch 229 manifest bytes differ"
    );
    let object = head_archive(client, BUCKET, &key)
        .await?
        .context("missing epoch 229 ciphertext")?;
    remote_matches(&object, &key, length, wire_sha, Some(etag))?;
    Ok(())
}

fn custody_client() -> Result<Client> {
    let r2 = r2_config_from_env()?;
    ensure!(r2.bucket == BUCKET, "foreign epoch 229 holding bucket");
    Ok(s3_client(&r2))
}

pub(super) async fn recheck(value: Value, spec: &Bound) -> Result<()> {
    let plan: RecheckPlan = serde_json::from_value(value)?;
    let (park_plan, custody, before) = accepted_custody(&plan)?;
    openpgp::key_file(Path::new(KEY_ROOT), "accounts-custody.key", false)?;
    authenticate(&custody_client()?, &plan, &custody).await?;
    ensure!(
        validate_source(&park_plan)? == before,
        "epoch 229 source changed during recheck"
    );
    no_references(Path::new(SOURCE))?;
    println!(
        "{}",
        json!({
            "schema":"foundation-epoch229-encrypted-accounts-recheck-v1","epoch":229,
            "spec":spec,"custody":plan.custody,"manifest":custody["manifest"],
            "manifest_key":custody["manifest_key"],"manifest_sha256":custody["manifest_sha256"],
            "source_identity":before,
            "authenticated_manifest_and_object_match":true,"recorded_unix_seconds":clock()?,
            "remote_mutations":false,"local_retirement_authorized":false,"publication_authorized":false
        })
    );
    Ok(())
}

fn restore_floor(admission: &Value, plan: &RestorePlan, root: &Path) -> Result<(u64, bool)> {
    let at = admission["recorded_unix_seconds"]
        .as_u64()
        .context("missing restore booking clock")?;
    ensure!(
        admission["schema"] == "foundation-epoch229-encrypted-restore-admission-v1"
            && admission["custody_plan"] == serde_json::to_value(&plan.custody_plan)?
            && admission["staging_path"] == json!(root)
            && admission["reserved_output_bytes"] == CLEAR_BYTES + CIPHER_OVERHEAD
            && clock()?.checked_sub(at).is_some_and(|age| age <= 900),
        "invalid or stale epoch 229 restore booking"
    );
    match admission["mode"].as_str() {
        Some("tmpfs-proof") => {
            tmpfs_scope(root)?;
            Ok((0, true))
        }
        Some("disk") => {
            let roster: Bound = serde_json::from_value(admission["roster"].clone())?;
            let fit = saved(&roster)?;
            let sampled = fit["recorded_unix_seconds"]
                .as_u64()
                .context("missing fit clock")?;
            ensure!(
                clock()?.checked_sub(sampled).is_some_and(|age| age <= 900)
                    && fit["filesystem_device"] == fs::metadata(root)?.dev()
                    && fit["schema"] == "foundation-epoch256-full-replay-roster-binding-v1",
                "restore disk budget does not bind the current Foundation filesystem"
            );
            let floor = fit["capacity"]["protected_existing_disk_bytes"]
                .as_u64()
                .filter(|floor| *floor > 0)
                .context("missing protected existing disk budget")?;
            Ok((floor, false))
        }
        _ => bail!("unknown epoch 229 restore booking mode"),
    }
}

pub(super) async fn restore(value: Value, spec: &Bound) -> Result<()> {
    let plan: RestorePlan = serde_json::from_value(value)?;
    ensure!(
        plan.schema == "foundation-epoch229-encrypted-restore-plan-v1"
            && plan.custody_plan.path == Path::new(RECHECK_PLAN),
        "foreign epoch 229 restore plan"
    );
    let checks: RecheckPlan = serde_json::from_value(saved(&plan.custody_plan)?)?;
    ensure!(
        serde_json::to_value(&plan.mapping)? == serde_json::to_value(&checks.mapping)?,
        "epoch 229 restore mapping differs"
    );
    let (_, custody, _) = accepted_custody(&checks)?;
    admitted_scope(RESTORE_UNIT)?;
    let root = Path::new(STATE).join("restores/accounts229");
    private(&root)?;
    let (floor, tmpfs_proof) = restore_floor(&saved(&plan.admission)?, &plan, &root)?;
    let key_file = openpgp::key_file(Path::new(KEY_ROOT), "accounts-custody.key", false)?;
    let client = custody_client()?;
    authenticate(&client, &checks, &custody).await?;
    let (etag, wire_sha, length) = custody_manifest(&custody)?;
    let target = root.join("epoch-229-closed-accounts.pax.zst");
    if retirement::absent(&target)? {
        ensure!(
            available(&root)?
                >= floor
                    .checked_add(CLEAR_BYTES + CIPHER_OVERHEAD)
                    .context("private restore requirement overflow")?,
            "epoch 229 compressed bundle does not fit above protected disk"
        );
        let home = tempfile::Builder::new().prefix(".gpg-").tempdir_in(&root)?;
        let pending = tempfile::NamedTempFile::new_in(&root)?;
        let output = pending.reopen()?;
        let staging = root.clone();
        openpgp::read_decrypted(
            &client,
            RemoteReadSpec {
                bucket: BUCKET,
                key: &encrypted_object_key(),
                etag,
                expected_length: length,
                expected_sha256: wire_sha,
                concurrency: 2,
            },
            openpgp::gpg(home.path(), &key_file)?,
            move |clear| {
                openpgp::copy_verified_plaintext(clear, &output, CLEAR_BYTES, CLEAR_SHA, || {
                    ensure!(
                        available(&staging)? >= floor + (1 << 20),
                        "restore crossed protected floor"
                    );
                    Ok(())
                })?;
                output.sync_all()?;
                Ok(())
            },
        )
        .await?;
        let id = regular_identity(pending.path())?;
        let proof = hash_and_etag(pending.path(), id, DEFAULT_PART_SIZE)?;
        ensure!(
            id.length == CLEAR_BYTES && proof.sha256_hex == CLEAR_SHA,
            "restored body changed"
        );
        authenticate(&client, &checks, &custody).await?;
        ensure!(
            available(&root)? >= floor,
            "restore crossed protected floor"
        );
        pending
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o400))?;
        pending.as_file().sync_all()?;
        pending.persist_noclobber(&target)?;
        File::open(&root)?.sync_all()?;
    } else {
        let m = fs::symlink_metadata(&target)?;
        let id = regular_identity(&target)?;
        ensure!(
            m.uid() == 0
                && m.nlink() == 1
                && m.mode() & 0o7777 == 0o400
                && id.length == CLEAR_BYTES
                && hash_and_etag(&target, id, DEFAULT_PART_SIZE)?.sha256_hex == CLEAR_SHA
                && available(&root)? >= floor,
            "existing restore bytes or capacity differ"
        );
    }
    let result = receipt(
        &format!("accounts229-restore-{}.json", spec.sha256),
        &json!({
            "schema":"foundation-epoch229-encrypted-restore-completion-v1","epoch":229,"spec":spec,
            "custody":checks.custody,"staged_output":target,"plaintext_bytes":CLEAR_BYTES,
            "plaintext_sha256":CLEAR_SHA,"tmpfs_proof":tmpfs_proof,
            "remote_identity_and_plaintext_verified":true,"staging_only":true,
            "remote_mutations":false,"local_retirement_authorized":false,"publication_authorized":false
        }),
    )?;
    println!("{}", result.display());
    Ok(())
}

pub(super) async fn run(value: Value, spec: &Bound) -> Result<()> {
    let plan: Plan = serde_json::from_value(value)?;
    ensure!(
        plan.schema == "foundation-epoch229-accounts-park-v1",
        "foreign epoch 229 encrypted custody plan"
    );
    mapping(&plan.mapping)?;
    let before = validate_source(&plan)?;
    no_references(Path::new(SOURCE))?;
    admitted_scope(UNIT)?;
    tmpfs_scope(Path::new(TMPFS))?;
    let home = Path::new(TMPFS).join("gpg");
    fs::DirBuilder::new().mode(0o700).create(&home)?;
    let r2 = r2_config_from_env()?;
    ensure!(r2.bucket == BUCKET, "foreign epoch 229 holding bucket");
    park(&s3_client(&r2), plan, spec, before, &home).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_requires_the_exact_ciphertext_intent() {
        let spec = Bound {
            path: "/var/lib/jetstreamer/custody-test.json".into(),
            sha256: "0".repeat(64),
        };
        let object = format!("{SUBPREFIX}encrypted-accounts229/{CLEAR_SHA}.blob");
        let valid = recovery_intent(&spec, &object, CLEAR_SHA, CLEAR_BYTES).unwrap();
        let altered_length = recovery_intent(&spec, &object, CLEAR_SHA, CLEAR_BYTES + 1).unwrap();
        assert_eq!(valid.path, altered_length.path);
        assert_ne!(valid.sha256, altered_length.sha256);
        let altered_sha = recovery_intent(&spec, &object, &"f".repeat(64), CLEAR_BYTES).unwrap();
        assert_ne!(valid.path, altered_sha.path);
        assert!(recovery_intent(&spec, &object, "../foreign", CLEAR_BYTES).is_err());
    }

    #[test]
    fn recheck_requires_the_exact_content_addressed_ciphertext() {
        let etag = format!(
            "{}-{}",
            "a".repeat(32),
            CLEAR_BYTES.div_ceil(DEFAULT_PART_SIZE)
        );
        let mut custody = json!({"manifest": encrypted_manifest(
            &encrypted_object_key(), &etag, CLEAR_SHA, CLEAR_BYTES
        )});
        assert_eq!(
            custody_manifest(&custody).unwrap(),
            (etag.as_str(), CLEAR_SHA, CLEAR_BYTES)
        );
        custody["manifest"]["object_key"] = json!("epoch-229.jet");
        assert!(custody_manifest(&custody).is_err());
        custody["manifest"]["object_key"] = json!(encrypted_object_key());
        custody["manifest"]["object_etag"] = json!("W/\"weak\"");
        assert!(custody_manifest(&custody).is_err());
    }
}
