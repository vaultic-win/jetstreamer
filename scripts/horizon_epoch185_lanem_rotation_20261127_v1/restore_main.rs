//! Recover the exact closed lane-M partial to a private same-filesystem path.
//! The transfer is read-only in R2 and never overwrites an existing local name.
use anyhow::{Context, Result, ensure};
use aws_credential_types::{Credentials, provider::SharedCredentialsProvider};
use aws_sdk_s3::{Client, config::BehaviorVersion};
use aws_types::region::Region;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, Write},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::Path,
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const BUCKET: &str = "solana-archive-with-accounts-data";
const STATE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch185-lanem-main-holding-20261127-v1";
const SOURCE: &str = "/home/sol/.jetstreamer-private/epochs175-200-20260922-v1/lane-m/private/destination-1046bb4e16672cd81d120ecccbaaa9e559f9fcdaffc50e978ee4ce228c77732e/work/root-cohort-185-185/run-722680-1790806113840176891/archives/epoch-185.jet";
const HASH: &str = "40dd56a324dc5e3abb3766a95c8189a02c7b7ace61cf2c9bc0f665c4dbc2415d";
const LENGTH: u64 = 54_996_291_524;
const PEAK: u64 = 110_009_360_264;
const SLOT: u64 = 123_350_028_052;
const UNIT: &str = "horizon-closed185-lanem-main-restore-20261127-v1.service";

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn read_json(path: &Path, hash: &str, max: u64, mutable_mode: bool) -> Result<Value> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical evidence"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && (mutable_mode || m.mode() & 0o222 == 0)
            && m.len() <= max,
        "unsealed evidence"
    );
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    ensure!(sha(&bytes) == hash, "changed evidence");
    Ok(serde_json::from_slice(&bytes)?)
}
fn bound(row: &Value, path: &Path, max: u64, allow_write: bool) -> Result<Value> {
    ensure!(
        row["path"].as_str() == path.to_str(),
        "different evidence path"
    );
    read_json(
        path,
        row["sha256"].as_str().context("missing bound SHA")?,
        max,
        allow_write,
    )
}
fn avail(path: &Path) -> Result<u64> {
    let c = CString::new(path.as_os_str().as_bytes())?;
    let mut stat = std::mem::MaybeUninit::uninit();
    ensure!(
        unsafe { libc::statvfs(c.as_ptr(), stat.as_mut_ptr()) } == 0,
        "statvfs failed"
    );
    let st = unsafe { stat.assume_init() };
    st.f_bavail
        .checked_mul(st.f_frsize)
        .context("capacity overflow")
}
fn require_space(available: u64, floor: u64, remaining: u64) -> Result<()> {
    ensure!(
        available >= floor.checked_add(remaining).context("capacity overflow")?,
        "insufficient funded restore space"
    );
    Ok(())
}
fn lock(path: &Path, inode: u64, uid: u32) -> Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && m.dev() == 64512
            && m.ino() == inode
            && m.uid() == uid
            && m.mode() & 0o7777 == 0o600
            && m.nlink() == 1,
        "different lock"
    );
    ensure!(
        unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "busy operation lock"
    );
    Ok(f)
}
fn scratch(dir: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_TMPFILE)
        .open(dir)?)
}

fn link_noreplace(file: &File, destination: &Path) -> Result<()> {
    // AT_SYMLINK_FOLLOW permits an O_TMPFILE descriptor to be linked by its
    // unprivileged owner too. No name exists until all bytes are verified.
    let source = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
    let target = CString::new(destination.as_os_str().as_bytes())?;
    if unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    File::open(destination.parent().context("missing parent")?)?.sync_all()?;
    Ok(())
}
fn properties(unit: &str) -> Result<Value> {
    let out = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            "--all",
            "-p",
            "Id,ActiveState,InvocationID,MainPID",
            unit,
        ])
        .output()?;
    ensure!(out.status.success(), "missing owner {unit}");
    let text = String::from_utf8(out.stdout)?;
    let mut d = json!({});
    for s in text.lines() {
        let (k, v) = s.split_once('=').context("invalid native property")?;
        d[k] = json!(v)
    }
    Ok(d)
}
fn owners(fleet: &Value) -> Result<()> {
    let rows = fleet["actual_executing_replays"]
        .as_array()
        .context("no fleet replay list")?;
    ensure!(
        fleet["schema"] == "horizon-Root-complete-fleet-operational-review-v1"
            && fleet["active_producer_count"].as_u64() == Some(rows.len() as u64),
        "incomplete replay roster"
    );
    // These identities invalidate the fit when a producer is replaced during recovery.
    for row in rows {
        let u = &row["unit"];
        let name = u["Id"].as_str().context("missing owner unit")?;
        let live = properties(name)?;
        ensure!(
            live["ActiveState"] == "active"
                && live["InvocationID"] == u["InvocationID"]
                && live["MainPID"] == u["MainPID"],
            "owner changed: {name}"
        );
    }
    Ok(())
}
fn storage_guard(receipt: &Value, fleet: &Value, dir: &Path, remaining: u64) -> Result<()> {
    owners(fleet)?;
    let stamp = receipt["floor_bytes"].as_u64().context("missing floor")?;
    ensure!(stamp >= 3_572_465_819_078, "floor below campaign base");
    require_space(avail(dir)?, stamp, remaining)
}
fn s3() -> Result<Client> {
    let url = url::Url::parse(&env::var("HORIZON_S3_ENDPOINT")?)?;
    ensure!(
        url.scheme() == "https"
            && url
                .host_str()
                .is_some_and(|h| h.ends_with(".r2.cloudflarestorage.com"))
            && url.path().trim_matches('/') == BUCKET
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none(),
        "foreign R2 endpoint"
    );
    let endpoint = url.origin().ascii_serialization();
    let credentials = Credentials::new(
        env::var("HORIZON_ACCESS_KEY_ID")?,
        env::var("HORIZON_SECRET_ACCESS_KEY")?,
        None,
        None,
        "horizon-private-restore",
    );
    Ok(Client::from_conf(
        aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("auto"))
            .credentials_provider(SharedCredentialsProvider::new(credentials))
            .endpoint_url(endpoint)
            .force_path_style(true)
            .build(),
    ))
}
async fn check_small(
    client: &Client,
    key: &str,
    pinned: &str,
    expected: &Value,
    digest: Option<&str>,
) -> Result<()> {
    let result = client
        .get_object()
        .bucket(BUCKET)
        .key(key)
        .if_match(pinned)
        .send()
        .await?;
    ensure!(
        result.e_tag() == Some(pinned)
            && result.content_length().is_some_and(|n| n > 0 && n < 16384),
        "changed small holding object"
    );
    let data = result.body.collect().await?.into_bytes();
    ensure!(
        serde_json::from_slice::<Value>(&data)? == *expected
            && digest.is_none_or(|s| sha(&data) == s),
        "owner or manifest differs"
    );
    Ok(())
}
fn valid_checksum(file: &mut File, length: u64, expected: &str) -> Result<()> {
    file.rewind()?;
    let digest = Command::new("/usr/bin/sha256sum")
        .arg("-")
        .stdin(file.try_clone()?)
        .output()?;
    ensure!(
        file.metadata()?.len() == length
            && digest.status.success()
            && digest.stdout == format!("{expected}  -\n").as_bytes(),
        "restored payload failed readback"
    );
    Ok(())
}
fn install(dir: &Path, destination: &Path, mut file: File) -> Result<()> {
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 0 && m.dev() == fs::metadata(dir)?.dev(),
        "unsafe unnamed staging inode"
    );
    valid_checksum(&mut file, LENGTH, HASH)?;
    ensure!(
        unsafe { libc::fchown(file.as_raw_fd(), 1001, 1003) } == 0,
        "restore ownership failed"
    );
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    let ts = [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
        libc::timespec {
            tv_sec: 1_790_979_327,
            tv_nsec: 119_986_061,
        },
    ];
    ensure!(
        unsafe { libc::futimens(file.as_raw_fd(), ts.as_ptr()) } == 0,
        "restore timestamp failed"
    );
    file.sync_all()?;
    link_noreplace(&file, destination)
}
async fn receive(
    client: &Client,
    key: &str,
    etag: &str,
    length: u64,
    hash_expected: &str,
    f: &mut File,
    mut guard: impl FnMut(u64, u64) -> Result<()>,
) -> Result<()> {
    let reply = client
        .get_object()
        .bucket(BUCKET)
        .key(key)
        .if_match(etag)
        .send()
        .await?;
    ensure!(
        reply.e_tag() == Some(etag) && reply.content_length() == Some(length as i64),
        "wrong blob response"
    );
    let mut body = reply.body;
    let mut bytes = 0u64;
    let mut hash = Sha256::new();

    while let Some(chunk) = body.next().await {
        let chunk = chunk?;
        let count = bytes
            .checked_add(chunk.len() as u64)
            .context("byte overflow")?;
        ensure!(count <= length, "overlong blob");
        guard(bytes, chunk.len() as u64)?;
        f.write_all(&chunk)?;
        hash.update(&chunk);
        bytes = count;
    }
    ensure!(
        bytes == length && format!("{:x}", hash.finalize()) == hash_expected,
        "incomplete or corrupt remote object"
    );
    Ok(())
}

async fn qualify(self_sha: &str) -> Result<()> {
    const GENESIS: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
    const LENGTH: u64 = 20144;
    let dir = Path::new(STATE).join("restore-fixture");
    let custody = read_json(
        Path::new(
            "/usr/local/lib/jetstreamer/horizon-node02-holding-custody-20261023-v1/custody.json",
        ),
        "749435d6a63400446a85ef1b39062077f682311b796135c058af8cf465b64629",
        1 << 20,
        false,
    )?;
    ensure!(
        unsafe { libc::geteuid() } == 0
            && sha(&fs::read("/proc/self/exe")?) == self_sha
            && dir.canonicalize()? == dir
            && custody["sha256"] == GENESIS
            && custody["length"] == LENGTH
            && custody["remote_sha256_readback"] == true,
        "unexpected qualification"
    );
    let live = properties("horizon-closed185-lanem-main-restore-fixture-20261127-v1.service")?;
    ensure!(
        live["MainPID"] == std::process::id().to_string()
            && live["InvocationID"].as_str() == Some(&env::var("INVOCATION_ID")?),
        "unexpected qualification unit"
    );
    let client = s3()?;
    let key = format!("node_02/objects/{GENESIS}.blob");
    let pin = format!(
        "\"{}\"",
        custody["object_etag"]
            .as_str()
            .context("fixture pin")?
            .trim_matches('"')
    );
    let manifest = custody["manifest_key"]
        .as_str()
        .context("fixture manifest")?;
    let mh = client
        .head_object()
        .bucket(BUCKET)
        .key(manifest)
        .send()
        .await?;
    check_small(
        &client,
        manifest,
        mh.e_tag().context("manifest ETag")?,
        &custody["manifest"],
        custody["manifest_sha256"].as_str(),
    )
    .await?;
    let oh = client
        .head_object()
        .bucket(BUCKET)
        .key("node_02/owner.json")
        .send()
        .await?;
    check_small(&client,"node_02/owner.json",oh.e_tag().context("owner ETAg")?,&json!({"schema":"jetstreamer-horizon-holding-owner-v2","host":"dev-samjohnson","prefix":"node_02/"}),None).await?;
    let negative = client
        .get_object()
        .bucket(BUCKET)
        .key(&key)
        .if_match("\"deliberately-wrong-qualification-pin\"")
        .send()
        .await;
    ensure!(
        negative
            .as_ref()
            .err()
            .and_then(|e| e.raw_response())
            .is_some_and(|r| r.status().as_u16() == 412),
        "conditional GET unexpectedly accepted"
    );
    let mut f = scratch(&dir)?;
    receive(
        &client,
        &key,
        &pin,
        LENGTH,
        GENESIS,
        &mut f,
        |bytes, chunk| {
            ensure!(bytes + chunk <= LENGTH, "fixture overflow");
            Ok(())
        },
    )
    .await?;
    f.sync_all()?;
    valid_checksum(&mut f, LENGTH, GENESIS)?;
    let destination = dir.join("qualified-genesis.data");
    link_noreplace(&f, &destination)?;
    ensure!(
        link_noreplace(&f, &destination).is_err(),
        "second projection unexpectedly succeeded"
    );
    let reopened = fs::symlink_metadata(&destination)?;
    ensure!(
        reopened.ino() == f.metadata()?.ino() && reopened.nlink() == 1,
        "fixture scope"
    );
    println!(
        "{}",
        json!({"unit":live,"object":key,"etag":pin,"length":LENGTH,"sha256":GENESIS,"manifest_verified":true,"full_local_readback":true,"conditional_get_mismatch_status":412,"no_clobber":true,"interrupted_anonymous_staging_is_discarded":true,"path":destination,"remote_mutations":false})
    );
    Ok(())
}

async fn run() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if let [mode, sha] = args.as_slice()
        && mode == "--qualify"
    {
        return qualify(sha).await;
    }
    let [admission, plan_sha, self_sha] = args.as_slice() else {
        anyhow::bail!("expected restore admission path, SHA and image SHA")
    };
    ensure!(
        unsafe { libc::geteuid() } == 0 && sha(&fs::read("/proc/self/exe")?) == *self_sha,
        "untrusted image"
    );
    let live = properties(UNIT)?;
    ensure!(
        live["MainPID"] == std::process::id().to_string()
            && live["InvocationID"].as_str() == Some(&env::var("INVOCATION_ID")?),
        "unexpected native restore service"
    );
    let state = Path::new(STATE);
    let src = Path::new(SOURCE);
    let dir = src.parent().context("missing archive parent")?;
    let plan_path = Path::new(admission);
    ensure!(
        plan_path.parent() == Some(state)
            && plan_path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("RESTORE_ADMISSION_"),
        "foreign admission"
    );
    let plan = read_json(plan_path, plan_sha, 1 << 20, false)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let issued = plan["recorded_unix_seconds"]
        .as_u64()
        .context("missing admission time")?;
    ensure!(
        plan["schema"] == "horizon-lanem185-main-restore-admission-v1"
            && plan["source"] == SOURCE
            && plan["sha256"] == HASH
            && plan["length"] == LENGTH
            && plan["serial_restore_reservation"] == SLOT
            && plan["two_copy_peak"] == PEAK
            && plan["restore_before_consumer"] == true
            && issued <= now
            && now - issued <= 120,
        "unfunded or stale restore plan"
    );
    let fleet_path = Path::new(plan["fleet"]["path"].as_str().context("missing fleet")?);
    ensure!(
        fleet_path.parent().and_then(Path::parent) == state.parent()
            && fleet_path.file_name().unwrap() == "ROOT_COMPLETE_OPERATIONAL_FLEET.json",
        "foreign fleet"
    );
    let fleet = bound(&plan["fleet"], fleet_path, 64 << 20, true)?;
    let expected = bound(
        &plan["expected"],
        &state.join("package/EXPECTED.json"),
        1 << 20,
        false,
    )?;
    ensure!(
        expected["source"] == SOURCE && expected["sha256"] == HASH && expected["length"] == LENGTH,
        "different selected object"
    );
    let native = Path::new(
        expected["custody_path"]
            .as_str()
            .context("missing custody path")?,
    );
    let custody = bound(&plan["custody"], native, 1 << 20, false)?;
    ensure!(
        custody["remote_sha256_readback"] == true
            && custody["local_source_revalidated"] == true
            && [
                "source",
                "length",
                "sha256",
                "object_key",
                "manifest_key",
                "manifest",
                "manifest_sha256"
            ]
            .iter()
            .all(|k| expected[*k] == custody[*k]),
        "incomplete custody"
    );
    let terminal = bound(
        &plan["retirement"],
        &state.join("LOCAL_RETIREMENT_COMPLETE.json"),
        1 << 20,
        false,
    )?;
    ensure!(
        terminal["operation"]["inode"] == 104005633
            && terminal["operation"]["sha256"] == HASH
            && terminal["source_absent"] == true,
        "foreign retirement"
    );
    let remote = bound(
        &plan["remote"],
        Path::new(
            plan["remote"]["path"]
                .as_str()
                .context("missing remote receipt")?,
        ),
        1 << 20,
        false,
    )?;
    ensure!(
        remote["phase"] == "accepted"
            && remote["authenticated"] == true
            && remote["remote_mutations"] == false,
        "unvalidated remote"
    );
    let _holding = lock(
        Path::new(
            "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/transition.lock",
        ),
        95818311,
        0,
    )?;
    let _mutation = lock(
        Path::new("/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock"),
        101135013,
        1001,
    )?;
    let _epoch = lock(
        &dir.ancestors()
            .nth(4)
            .context("missing lane")?
            .join("locks/epoch-185.lock"),
        101717370,
        1001,
    )?;
    ensure!(dir.canonicalize()? == dir, "archive parent changed");
    let client = s3()?;
    let owner = json!({"schema":"jetstreamer-horizon-holding-owner-v2","host":"dev-samjohnson","prefix":"node_02/"});
    check_small(
        &client,
        "node_02/owner.json",
        remote["owner"]["etag"]
            .as_str()
            .context("missing owner ETag")?,
        &owner,
        None,
    )
    .await?;
    check_small(
        &client,
        expected["manifest_key"]
            .as_str()
            .context("missing manifest")?,
        remote["manifest"]["etag"]
            .as_str()
            .context("missing manifest ETag")?,
        &expected["manifest"],
        expected["manifest_sha256"].as_str(),
    )
    .await?;
    let key = format!("node_02/objects/{HASH}.blob");
    ensure!(expected["object_key"] == key, "foreign object");
    let etag = remote["blob"]["etag"]
        .as_str()
        .context("missing pinned blob ETag")?;
    ensure!(
        etag.trim_matches('"')
            == custody["object_etag"]
                .as_str()
                .context("missing custody ETag")?
                .trim_matches('"'),
        "ETag differs from custody"
    );
    let head = || {
        client
            .head_object()
            .bucket(BUCKET)
            .key(&key)
            .if_match(etag)
            .send()
    };
    let check_head =
        |response: &aws_sdk_s3::operation::head_object::HeadObjectOutput| -> Result<()> {
            ensure!(
                response.e_tag() == Some(etag)
                    && response.content_length() == Some(LENGTH as i64)
                    && response
                        .metadata()
                        .and_then(|m| m.get("sha256"))
                        .is_some_and(|v| v == HASH),
                "blob changed"
            );
            Ok(())
        };
    check_head(&head().await?)?;
    if src.try_exists()? {
        let mut f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(src)?;
        let m = f.metadata()?;
        ensure!(
            m.is_file()
                && m.nlink() == 1
                && m.uid() == 1001
                && m.gid() == 1003
                && m.mode() & 0o7777 == 0o600
                && (m.mtime(), m.mtime_nsec()) == (1_790_979_327, 119_986_061),
            "conflicting local destination"
        );
        storage_guard(&plan, &fleet, dir, 0)?;
        valid_checksum(&mut f, LENGTH, HASH)?;
        let live = fs::symlink_metadata(src)?;
        ensure!(
            live.dev() == m.dev() && live.ino() == m.ino() && live.nlink() == 1,
            "restored destination changed"
        );
    } else {
        storage_guard(&plan, &fleet, dir, PEAK)?;
        let mut f = scratch(dir)?;
        let mut checked = Instant::now();
        receive(&client, &key, etag, LENGTH, HASH, &mut f, |bytes, next| {
            if checked.elapsed() >= Duration::from_secs(8) {
                storage_guard(&plan, &fleet, dir, PEAK - bytes)?;
                checked = Instant::now();
            }
            require_space(
                avail(dir)?,
                plan["floor_bytes"].as_u64().context("floor")?,
                next,
            )
        })
        .await?;
        f.sync_all()?;
        storage_guard(&plan, &fleet, dir, PEAK - LENGTH)?;
        check_head(&head().await?)?;
        install(dir, src, f)?;
    }
    check_head(&head().await?)?;
    println!(
        "{}",
        json!({"source":SOURCE,"sha256":HASH,"bytes":LENGTH,"etag":etag,"invocation":env::var("INVOCATION_ID")?,"admission_sha256":plan_sha,"full_local_readback":true,"canonical_publication":false})
    );
    Ok(())
}
fn main() -> Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn available_after_every_charge() {
        assert!(require_space(200, 120, 80).is_ok());
        assert!(require_space(200, 120, 81).is_err());
        assert!(require_space(1, u64::MAX, 1).is_err());
    }
    #[test]
    fn projection_never_overwrites_and_full_readback_rejects_damage() {
        let d = tempfile::tempdir().unwrap();
        let mut f = scratch(d.path()).unwrap();
        let b = d.path().join("original");
        f.write_all(b"correct").unwrap();
        fs::write(&b, b"foreign").unwrap();
        assert!(link_noreplace(&f, &b).is_err());
        assert_eq!(fs::read(&b).unwrap(), b"foreign");
        assert!(valid_checksum(&mut f, 7, &sha(b"correct")).is_ok());
        assert!(valid_checksum(&mut f, 6, &sha(b"correct")).is_err());
        assert!(valid_checksum(&mut f, 7, &sha(b"changed")).is_err());
        fs::remove_file(&b).unwrap();
        link_noreplace(&f, &b).unwrap();
        assert_eq!(fs::read(&b).unwrap(), b"correct");
    }
}
