//! Pack and preserve one exact closed epoch 288 AccountsDb shard.
use super::*;
use appendvec292::tree;
use horizon_singleton211_launch::native262::foundation_roster::holding288::{
    ACCOUNTS_CENSUS_SHA, ACCOUNTS_ROOT as STATE288, ACCOUNTS_ROSTER_SCHEMA, ACCOUNTS_UNIT as UNIT,
    CPUS, MEMORY_BYTES, RECEIPT_BYTES, TMPFS, TMPFS_BYTES,
};
use std::os::unix::fs::DirBuilderExt;
use std::process::{Command, Stdio};

pub(super) const CHECK: &str = "holding-foundation-288-accounts-check";
pub(super) const PARK: &str = "holding-foundation-288-accounts-park";
const FORMAT: &str = "openpgp-aes256-gnu-sparse-pax-zstd-epoch288-shard";
const MAX_BUNDLE: u64 = 72 << 30;
const CIPHER_OVERHEAD: u64 = 1 << 30;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectPlan {
    schema: String,
    mapping: Bound,
    shard: u8,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParkPlan {
    schema: String,
    mapping: Bound,
    admission: Bound,
}

struct Shard {
    source: PathBuf,
    root: PathBuf,
    number: u8,
    binding: Bound,
    expected: Value,
    closed: Value,
}

struct Census {
    names: Vec<String>,
    receipt: Value,
}

pub(super) fn command(action: &str) -> bool {
    matches!(action, CHECK | PARK)
}

impl Shard {
    fn open(number: u8) -> Result<Self> {
        ensure!(number < 4, "epoch 288 shard is outside the closed source");
        let binding = Bound {
            path: Path::new(STATE288).join("shard-census.json"),
            sha256: ACCOUNTS_CENSUS_SHA.into(),
        };
        let original = saved(&binding)?;
        let closed = saved(&partial288::source_proof())?;
        let root: PathBuf = serde_json::from_value(original["source"].clone())?;
        let metadata = root.symlink_metadata()?;
        let expected = original["shards"][usize::from(number)].clone();
        ensure!(
            original["schema"] == "foundation-epoch288-full-accounts-shard-census-v1"
                && original["epoch"] == 288
                && original["producer_terminal"] == closed["terminal"]
                && original["custody_established"] == false
                && original["retirement_authorized"] == false
                && root.canonicalize()? == root
                && metadata.is_dir()
                && original["source_device"] == metadata.dev()
                && original["source_inode"] == metadata.ino()
                && expected["shard"] == number.to_string(),
            "epoch 288 shard census differs from the stopped producer"
        );
        let source = root.join(number.to_string());
        Ok(Self {
            source,
            root,
            number,
            binding,
            expected,
            closed,
        })
    }

    fn snapshot(&self) -> Result<Census> {
        let retained = self.closed["source"]["path"]
            .as_str()
            .context("missing 288 archive path")?;
        partial288::verify_stopped(&self.closed, Path::new(retained))?;
        no_references(&self.source)?;
        census(&self.source, self.number, &self.expected, &self.binding)
    }
}

fn census(source: &Path, number: u8, expected: &Value, binding: &Bound) -> Result<Census> {
    let directory = source.symlink_metadata()?;
    let directory_identity = Stamp::of(&directory);
    ensure!(
        source.canonicalize()? == source
            && directory.is_dir()
            && directory.dev()
                == source
                    .parent()
                    .context("missing shard parent")?
                    .metadata()?
                    .dev()
            && (directory.uid(), directory.gid(), directory.mode() & 0o7777) == (1000, 1000, 0o700),
        "epoch 288 shard directory differs from stopped scratch"
    );
    tree::require_no_xattrs(source)?;
    let mut members = fs::read_dir(source)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    members.sort_unstable();
    let mut names = Vec::with_capacity(members.len());
    let mut hash = Sha256::new();
    let mut length = 0u64;
    let mut allocated = 0u64;
    let mut largest = 0;
    for leaf in members {
        let name = leaf
            .to_str()
            .filter(|name| tree::appendvec_name(name))
            .context("foreign epoch 288 shard member")?;
        let path = source.join(name);
        let meta = path.symlink_metadata()?;
        let stamp = Stamp::of(&meta);
        ensure!(
            meta.is_file()
                && stamp.device == directory.dev()
                && (stamp.uid, stamp.gid, stamp.mode, stamp.links) == (1000, 1000, 0o600, 1),
            "epoch 288 shard member is not a single regular worker file"
        );
        tree::require_no_xattrs(&path)?;
        hash.update(serde_json::to_vec(&json!([name, stamp, meta.blocks()]))?);
        hash.update(b"\n");
        length = length
            .checked_add(stamp.length)
            .context("shard logical byte overflow")?;
        allocated = allocated
            .checked_add(
                meta.blocks()
                    .checked_mul(512)
                    .context("shard member allocation overflow")?,
            )
            .context("shard allocated byte overflow")?;
        largest = largest.max(stamp.length);
        names.push(format!("{number}/{name}"));
    }
    ensure!(
        Stamp::of(&source.symlink_metadata()?) == directory_identity
            && expected["entries"] == names.len()
            && expected["logical_bytes"] == length
            && expected["allocated_file_bytes"] == allocated
            && expected["largest_member_bytes"] == largest,
        "epoch 288 shard membership, sizes or allocation changed"
    );
    Ok(Census {
        names,
        receipt: json!({
            "schema":"foundation-epoch288-closed-shard-inspection-v1","epoch":288,"shard":number,
            "source":source,"source_census":binding,"directory_identity":directory_identity,
            "entries":expected["entries"],"logical_bytes":length,"allocated_bytes":allocated,
            "largest_member_bytes":largest,"ordered_member_identity_sha256":hex_lower(&hash.finalize()),
            "remote_mutations":false,"retirement_authorized":false,"publication_authorized":false,
        }),
    })
}

pub(super) fn check(value: Value) -> Result<()> {
    let plan: InspectPlan = serde_json::from_value(value)?;
    ensure!(
        plan.schema == "foundation-epoch288-shard-inspection-plan-v1",
        "foreign 288 shard inspection"
    );
    mapping(&plan.mapping)?;
    println!("{}", Shard::open(plan.shard)?.snapshot()?.receipt);
    Ok(())
}

fn archive_member_list(
    root: &Path,
    number: u8,
    census: &Census,
) -> Result<tempfile::NamedTempFile> {
    let mut membership = tempfile::NamedTempFile::new_in(root)?;
    write!(membership, "{number}\0")?;
    for member in &census.names {
        membership.write_all(member.as_bytes())?;
        membership.write_all(b"\0")?;
    }
    membership.flush()?;
    Ok(membership)
}

fn stage_bundle(shard: &Shard, expected: &Census, tmpfs: &Path) -> Result<tempfile::NamedTempFile> {
    tree::verify_tools()?;
    let members = archive_member_list(tmpfs, shard.number, expected)?;
    let mut file = tempfile::NamedTempFile::new_in(tmpfs)?;
    let mut tar = Command::new(tree::TAR)
        .env_clear()
        .env("LC_ALL", "C")
        .current_dir(&shard.root)
        .args([
            "--format=pax",
            "--pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime",
            "--atime-preserve=system",
            "--sparse",
            "--numeric-owner",
            "--no-recursion",
            "--null",
            "--verbatim-files-from",
            "-T",
        ])
        .arg(members.path())
        .args(["-cf", "-"])
        .stdout(Stdio::piped())
        .spawn()?;
    let mut zstd = match Command::new(tree::ZSTD)
        .env_clear()
        .args(["-q", "-T1", "-3", "-c"])
        .stdin(tar.stdout.take().context("missing epoch 288 tar stream")?)
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            let _ = tar.kill();
            let _ = tar.wait();
            return Err(error.into());
        }
    };
    let copied = (|| -> Result<u64> {
        let stream = zstd
            .stdout
            .take()
            .context("missing epoch 288 compressed stream")?;
        let length = std::io::copy(&mut stream.take(MAX_BUNDLE + 1), file.as_file_mut())?;
        ensure!(
            (1..=MAX_BUNDLE).contains(&length),
            "epoch 288 shard bundle exceeds its admitted size"
        );
        Ok(length)
    })();
    if copied.is_err() {
        let _ = zstd.kill();
        let _ = tar.kill();
    }
    let zstd_status = zstd.wait()?;
    let tar_status = tar.wait()?;
    let length = copied?;
    ensure!(
        zstd_status.success() && tar_status.success() && file.as_file().metadata()?.len() == length,
        "epoch 288 shard staging failed"
    );
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    file.as_file().sync_all()?;
    Ok(file)
}

fn exact_archive_members(bundle: &Path, census: &Census, number: u8) -> Result<()> {
    let mut decoder = Command::new(tree::ZSTD)
        .env_clear()
        .args(["-qdc", "--"])
        .arg(bundle)
        .stdout(Stdio::piped())
        .spawn()?;
    let response = Command::new(tree::TAR)
        .env_clear()
        .env("LC_ALL", "C")
        .args(["--list", "--file=-"])
        .stdin(
            decoder
                .stdout
                .take()
                .context("missing epoch 288 listing input")?,
        )
        .output();
    if response.is_err() {
        let _ = decoder.kill();
    }
    let decoded = decoder.wait()?;
    let response = response?;
    let mut lines = std::str::from_utf8(&response.stdout)?.lines();
    let directory = format!("{number}/");
    ensure!(
        decoded.success()
            && response.status.success()
            && lines.next() == Some(directory.as_str())
            && lines.eq(census.names.iter().map(String::as_str)),
        "epoch 288 sparse bundle membership differs"
    );
    Ok(())
}

fn wire_intent(
    source: &Bound,
    key: &str,
    wire_sha: &str,
    length: u64,
    clear_sha: &str,
    clear_length: u64,
) -> Result<(String, Value)> {
    ensure!(
        digest(wire_sha) && digest(clear_sha) && digest(&source.sha256),
        "invalid epoch 288 shard identity"
    );
    Ok((
        format!("accounts288-intent-{}-{wire_sha}.json", source.sha256),
        json!({
            "schema":"foundation-epoch288-encrypted-shard-intent-v1","epoch":288,"source":source,
            "object_key":key,"ciphertext_sha256":wire_sha,"ciphertext_length":length,
            "plaintext_sha256":clear_sha,"plaintext_length":clear_length
        }),
    ))
}

pub(super) async fn park(value: Value, spec: &Bound) -> Result<()> {
    let plan: ParkPlan = serde_json::from_value(value)?;
    mapping(&plan.mapping)?;
    ensure!(
        plan.schema == "foundation-epoch288-shard-park-plan-v1"
            && plan.admission.path == Path::new(STATE288).join("admission.json"),
        "foreign 288 shard park"
    );
    let admission = saved(&plan.admission)?;
    let roster: Bound = serde_json::from_value(admission["roster"].clone())?;
    let fit = saved(&roster)?;
    let cap = &fit["capacity"];
    let source: Bound = serde_json::from_value(admission["source"].clone())?;
    let expected = saved(&source)?;
    let at = fit["recorded_unix_seconds"]
        .as_u64()
        .context("missing 288 shard fit time")?;
    let number = u8::try_from(
        expected["shard"]
            .as_u64()
            .context("missing admitted 288 shard")?,
    )?;
    ensure!(
        admission["schema"] == "foundation-epoch288-shard-custody-admission-v1"
            && admission["unit"] == UNIT
            && admission["publication_authorized"] == false
            && admission["retirement_authorized"] == false
            && fit["schema"] == ACCOUNTS_ROSTER_SCHEMA
            && fit["accounts_288_custody_quote"]["source"] == json!(source)
            && fit["accounts_288_custody_quote"]["producer_unit"] == UNIT
            && clock()?.checked_sub(at).is_some_and(|age| age <= 900)
            && cap["fits"] == true
            && cap["candidate_total_memory_bytes"] == MEMORY_BYTES
            && cap["candidate_disk_bytes"] == RECEIPT_BYTES,
        "epoch 288 shard lacks an admitted complete fleet fit"
    );
    let shard = Shard::open(number)?;
    let before = shard.snapshot()?;
    ensure!(
        before.receipt == expected
            && fit["filesystem_device"] == expected["directory_identity"]["device"],
        "epoch 288 shard identity changed before packing"
    );
    accounts229::admitted_scope(UNIT, MEMORY_BYTES)?;
    let process_status = fs::read_to_string("/proc/self/status")?;
    ensure!(
        process_status.lines().any(|line| line
            .strip_prefix("Cpus_allowed_list:")
            .is_some_and(|v| v.trim() == CPUS)),
        "epoch 288 shard escaped its admitted CPUs"
    );
    let floor = cap["required_disk_bytes"]
        .as_u64()
        .context("missing 288 protected disk floor")?;
    ensure!(
        available(&shard.source)? >= floor,
        "epoch 288 shard receipts cross the protected disk floor"
    );
    let tmpfs = Path::new(TMPFS);
    accounts229::tmpfs_scope(tmpfs, TMPFS_BYTES, 2 * MAX_BUNDLE + CIPHER_OVERHEAD)?;
    let bundle = stage_bundle(&shard, &before, tmpfs)?;
    let body = regular_identity(bundle.path())?;
    let proof = hash_and_etag(bundle.path(), body, DEFAULT_PART_SIZE)?;
    let clear_sha = &proof.sha256_hex;
    exact_archive_members(bundle.path(), &before, number)?;
    tree::compare_payload(bundle.path(), &shard.root, body)?;
    ensure!(
        shard.snapshot()?.receipt == expected,
        "epoch 288 shard changed during bundle qualification"
    );
    let stamp = Stamp::of(&bundle.path().symlink_metadata()?);
    let home = tmpfs.join("gpg");
    fs::DirBuilder::new().mode(0o700).create(&home)?;
    let config = r2_config_from_env()?;
    ensure!(
        config.bucket == BUCKET,
        "foreign epoch 288 shard holding bucket"
    );
    let client = s3_client(&config);
    let key = format!("{SUBPREFIX}encrypted-accounts288/shard-{number}-{clear_sha}.blob");
    let key_name = format!("accounts-shard-{number}.key");
    let (remote, wire_sha) = openpgp::park(
        &client,
        openpgp::Park {
            object_key: &key,
            source_path: bundle.path(),
            before: &stamp,
            clear_sha,
            cipher_overhead: CIPHER_OVERHEAD,
            key_root: Path::new(STATE288),
            key_name: &key_name,
            tmpfs,
            format: FORMAT,
        },
        &home,
        |sha, len| {
            let (name, value) = wire_intent(&source, &key, sha, len, clear_sha, stamp.length)?;
            receipt(&name, &value)?;
            Ok(())
        },
        |sha, len| {
            let (name, value) = wire_intent(&source, &key, sha, len, clear_sha, stamp.length)?;
            let mut bytes = serde_json::to_vec_pretty(&value)?;
            bytes.push(b'\n');
            Ok(Bound {
                path: Path::new(STATE).join("receipts").join(name),
                sha256: hex_lower(&Sha256::digest(bytes)),
            })
        },
        || Ok(Stamp::of(&bundle.path().symlink_metadata()?)),
    )
    .await?;
    ensure!(
        shard.snapshot()?.receipt == expected,
        "epoch 288 shard changed during remote readback"
    );
    let manifest = json!({
        "schema":"foundation-epoch288-encrypted-shard-manifest-v1","epoch":288,"shard":number,
        "format":FORMAT,"object_key":key,"object_etag":remote.etag,
        "ciphertext_sha256":wire_sha,"ciphertext_length":remote.length,
        "plaintext_sha256":clear_sha,"plaintext_length":body.length,"source":source,
        "ordered_members_verified":true,"every_member_compared_before_upload":true,
        "canonical_archive":false,"resumable_checkpoint":false
    });
    let bytes = serde_json::to_vec(&manifest)?;
    let sha = hex_lower(&Sha256::digest(&bytes));
    let marker = manifest_key(&sha)?;
    small_create(&client, &marker, &bytes).await?;
    println!("{}", receipt(&format!("accounts288-custody-{}.json", spec.sha256), &json!({
        "schema":"foundation-epoch288-encrypted-shard-custody-v1","epoch":288,"shard":number,
        "plan":spec,"admission":plan.admission,"bucket":BUCKET,"manifest":manifest,
        "manifest_key":marker,"manifest_sha256":sha,"invocation_id":env::var("INVOCATION_ID")?,
        "remote_ciphertext_sha256_verified":true,"remote_authenticated_decryption_verified":true,
        "restored_archive_reread_verified":true,"source_revalidated":true,
        "publication_authorized":false,"local_retirement_authorized":false,
    }))?.display());
    Ok(())
}
