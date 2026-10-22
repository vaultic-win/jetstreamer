// Shared fixed-profile compressed bootstrap engine; never restores or replays.
#[allow(dead_code)]
mod epoch141_ledger_common;
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use epoch141_ledger_common::{
    bound_file, capture, identity, sha, validate_object_metadata, write_receipt,
};
use md5::Md5;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use profile::{
    EPOCH, FILENAME, MINIMUM_PROTECTED_FREE, OBJECT, PLAN_SCHEMA, PROTECTED_FLEET, RECEIPT_SCHEMA,
};
mod bootstrap227_protection;

const GCLOUD: &str = "/home/linuxbrew/.linuxbrew/share/google-cloud-sdk/bin/gcloud";
const SLACK: u64 = 64 * 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    #[serde(default)]
    fleet: Option<Bound>,
    schema: String,
    gcloud_sha256: String,
    observer: PathBuf,
    observer_sha256: String,
    minimum_free_bytes: u64,
    staging_directory: PathBuf,
    receipt: PathBuf,
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn free_bytes(path: &Path) -> Result<u64> {
    let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let mut v = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(name.as_ptr(), v.as_mut_ptr()) } == 0,
        "statvfs failed"
    );
    let v = unsafe { v.assume_init() };
    v.f_bavail
        .checked_mul(v.f_frsize)
        .context("free-byte overflow")
}
fn sdk_digest(expected: &str) -> Result<()> {
    ensure!(
        epoch141_ledger_common::is_sha(expected),
        "invalid SDK SHA-256"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(GCLOUD)?;
    let before = f.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 1000
            && before.nlink() == 1
            && before.mode() & 0o022 == 0
            && before.len() <= 1024 * 1024,
        "unsafe SDK launcher"
    );
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)?;
    ensure!(
        sha(&bytes) == expected
            && identity(&before) == identity(&f.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(GCLOUD)?),
        "SDK launcher changed"
    );
    Ok(())
}
struct Owned(Option<Child>);
impl Owned {
    fn finished(&self) -> Result<bool> {
        let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        ensure!(
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.0.as_ref().context("missing child")?.id(),
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            } == 0,
            "waitid failed"
        );
        Ok(unsafe { info.si_pid() } != 0)
    }
    fn finish(&mut self) -> Result<std::process::ExitStatus> {
        let child = self.0.as_mut().context("missing child")?;
        ensure!(
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) } == 0
                || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH),
            "SDK process-group kill failed"
        );
        let status = child.wait()?;
        self.0 = None;
        Ok(status)
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0
            && unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) } == 0
        {
            let _ = child.wait();
        }
    }
}
fn command(args: &[&str]) -> Command {
    let mut c = Command::new(GCLOUD);
    c.args(args)
        .args([
            "--account=sam.johnson@anza.xyz",
            "--billing-project=principal-lane-200702",
            "--quiet",
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("CLOUDSDK_CONFIG", "/home/ubuntu/.config/gcloud")
        .env("CLOUDSDK_CORE_DISABLE_PROMPTS", "1")
        .env("CLOUDSDK_CORE_DISABLE_FILE_LOGGING", "1")
        .env("CLOUDSDK_STORAGE_PROCESS_COUNT", "1")
        .env("CLOUDSDK_STORAGE_THREAD_COUNT", "1")
        .env("CLOUDSDK_STORAGE_SLICED_OBJECT_DOWNLOAD_THRESHOLD", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        c.pre_exec(|| {
            if libc::setpgid(0, 0) != 0
                || libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(1000) != 0
                || libc::setuid(1000) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    c
}
fn metadata() -> Result<Value> {
    let child = command(&[
        "storage",
        "objects",
        "describe",
        OBJECT.uri,
        "--format=json",
    ])
    .stdout(Stdio::piped())
    .spawn()?;
    let mut owned = Owned(Some(child));
    let stdout = owned.0.as_mut().unwrap().stdout.take().unwrap();
    let reader = thread::spawn(move || capture(stdout));
    let start = Instant::now();
    while !owned.finished()? {
        ensure!(
            start.elapsed() < Duration::from_secs(60),
            "SDK metadata timeout"
        );
        thread::sleep(Duration::from_millis(100));
    }
    ensure!(
        owned.finish()?.success(),
        "SDK metadata failed; credential output suppressed"
    );
    let bytes = reader
        .join()
        .map_err(|_| anyhow::anyhow!("metadata reader panicked"))??;
    ensure!(bytes.len() <= 16 * 1024, "metadata exceeds bound");
    let value = serde_json::from_slice(&bytes)?;
    validate_object_metadata(&value, &OBJECT)?;
    Ok(value)
}
fn admission(observer: &Value, plan: &Plan, time: u64) -> Result<()> {
    ensure!(
        observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2",
        "wrong observer schema"
    );
    if PROTECTED_FLEET {
        bootstrap227_protection::validate_observer(observer)?;
    } else {
        ensure!(
            plan.fleet.is_none(),
            "legacy223 does not accept a protected fleet extension"
        );
    }
    let timestamp = utc_seconds(
        observer["recorded_at_utc"]
            .as_str()
            .context("observer timestamp missing")?,
    )?;
    ensure!(
        timestamp <= time && time - timestamp <= 1800,
        "stale observer"
    );
    ensure!(
        plan.minimum_free_bytes >= MINIMUM_PROTECTED_FREE,
        "protected floor reduced"
    );
    let required = plan
        .minimum_free_bytes
        .checked_add(OBJECT.size + SLACK)
        .context("capacity overflow")?;
    ensure!(
        observer["filesystem"]["conservative_available_bytes"]
            .as_u64()
            .is_some_and(|n| n >= required),
        "observer lacks transfer headroom"
    );
    Ok(())
}
fn utc_seconds(value: &str) -> Result<u64> {
    ensure!(
        value.len() == 20 && value.is_ascii(),
        "noncanonical UTC timestamp"
    );
    let text = std::ffi::CString::new(value)?;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let end = unsafe { libc::strptime(text.as_ptr(), c"%Y-%m-%dT%H:%M:%SZ".as_ptr(), &mut tm) };
    ensure!(
        !end.is_null() && unsafe { *end } == 0,
        "invalid UTC timestamp"
    );
    let seconds = unsafe { libc::timegm(&mut tm) };
    ensure!(
        seconds >= 0
            && format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                tm.tm_year + 1900,
                tm.tm_mon + 1,
                tm.tm_mday,
                tm.tm_hour,
                tm.tm_min,
                tm.tm_sec
            ) == value,
        "noncanonical UTC date"
    );
    Ok(seconds as u64)
}
fn check_directory(path: &Path, mode: u32) -> Result<()> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical directory"
    );
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o777 == mode,
        "wrong directory ownership/mode"
    );
    Ok(())
}
fn guard(plan: &Plan, start: Instant) -> Result<()> {
    ensure!(
        start.elapsed() < Duration::from_secs(7200),
        "transfer runtime limit"
    );
    ensure!(
        free_bytes(&plan.staging_directory)? >= plan.minimum_free_bytes,
        "protected free-space floor reached"
    );
    let mut total = 0u64;
    let mut count = 0;
    for e in fs::read_dir(&plan.staging_directory)? {
        let m = fs::symlink_metadata(e?.path())?;
        ensure!(m.is_file() && m.nlink() == 1, "unsafe staging member");
        total = total
            .checked_add(m.len())
            .context("staging size overflow")?;
        count += 1;
    }
    ensure!(
        total <= OBJECT.size + SLACK && count <= 4,
        "staging capacity exceeded"
    );
    Ok(())
}
fn hashes(
    mut f: impl Read,
    size: u64,
    mut guard: impl FnMut() -> Result<()>,
) -> Result<(String, String, String)> {
    let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI);
    let mut c = crc.digest();
    let mut m = Md5::new();
    let mut s = Sha256::new();
    let mut b = vec![0; 4 * 1024 * 1024];
    let mut length = 0u64;
    loop {
        guard()?;
        let n = f.read(&mut b)?;
        if n == 0 {
            break;
        }
        length += n as u64;
        ensure!(length <= size, "input too long");
        c.update(&b[..n]);
        m.update(&b[..n]);
        s.update(&b[..n]);
    }
    ensure!(length == size, "input truncated");
    Ok((
        STANDARD.encode(c.finalize().to_be_bytes()),
        STANDARD.encode(m.finalize()),
        format!("{:x}", s.finalize()),
    ))
}
fn validate_fleet_binding(p: &Plan, observer: &Value) -> Result<()> {
    if !PROTECTED_FLEET {
        ensure!(
            p.fleet.is_none(),
            "legacy223 does not accept a protected fleet extension"
        );
        return Ok(());
    }
    let bound = p
        .fleet
        .as_ref()
        .context("protected input requires complete fleet evidence")?;
    let fleet: Value =
        serde_json::from_slice(&bound_file(&bound.path, &bound.sha256, 8 << 20, true)?)?;
    bootstrap227_protection::validate_fleet(&fleet, observer, &p.observer, &p.observer_sha256)
}
fn check_only(args: &[String]) -> Result<bool> {
    ensure!(
        args.len() == 3 || (PROTECTED_FLEET && args.len() == 4 && args[3] == "--check-only"),
        "usage: PLAN PLAN_SHA256 SELF_SHA256 [--check-only (protected profiles only)]"
    );
    Ok(args.len() == 4)
}
fn run() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let args: Vec<_> = env::args().skip(1).collect();
    let check_only = check_only(&args)?;
    bound_file(
        &fs::read_link("/proc/self/exe")?,
        &args[2],
        64 * 1024 * 1024,
        true,
    )?;
    let p: Plan = serde_json::from_slice(&bound_file(Path::new(&args[0]), &args[1], 65536, true)?)?;
    ensure!(p.schema == PLAN_SCHEMA, "wrong plan schema");
    let invocation = env::var("INVOCATION_ID").context("persistent systemd invocation required")?;
    ensure!(
        invocation.len() == 32
            && invocation
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "invalid invocation"
    );
    let observer: Value = serde_json::from_slice(&bound_file(
        &p.observer,
        &p.observer_sha256,
        4 * 1024 * 1024,
        false,
    )?)?;
    admission(&observer, &p, now()?)?;
    check_directory(
        p.staging_directory
            .parent()
            .context("staging parent missing")?,
        0o711,
    )?;
    check_directory(p.receipt.parent().context("receipt parent missing")?, 0o700)?;
    ensure!(
        fs::symlink_metadata(&p.receipt).is_err()
            && fs::symlink_metadata(&p.staging_directory).is_err(),
        "outputs must be absent"
    );
    ensure!(
        !p.receipt.starts_with(&p.staging_directory),
        "receipt overlaps staging"
    );
    validate_fleet_binding(&p, &observer)?;
    // Both protected fixed inputs share this immutable lease and the same
    // older-producer growth reservation; they must never spend it concurrently.
    let _lease = if PROTECTED_FLEET {
        Some(bootstrap227_protection::lease(Path::new(
            "/var/lib/jetstreamer/horizon-bootstrap227-transfer-lease-v1/transfer.lock",
        ))?)
    } else {
        None
    };
    sdk_digest(&p.gcloud_sha256)?;
    let before_metadata = metadata()?;
    admission(&observer, &p, now()?)?;
    let required = p
        .minimum_free_bytes
        .checked_add(OBJECT.size + SLACK)
        .context("capacity overflow")?;
    ensure!(
        free_bytes(p.staging_directory.parent().unwrap())? >= required,
        "insufficient actual transfer headroom"
    );
    if check_only {
        println!(
            "compressed-bootstrap preflight passed; no download, restore, replay or publication performed"
        );
        return Ok(());
    }
    fs::create_dir(&p.staging_directory)?;
    fs::set_permissions(&p.staging_directory, fs::Permissions::from_mode(0o700))?;
    let directory = File::open(&p.staging_directory)?;
    use std::os::fd::AsRawFd;
    ensure!(
        unsafe { libc::fchown(directory.as_raw_fd(), 1000, 1000) } == 0,
        "cannot assign staging"
    );
    File::open(p.staging_directory.parent().unwrap())?.sync_all()?;
    let destination = p.staging_directory.join(FILENAME);
    let start = Instant::now();
    let mut child = Owned(Some(
        command(&[
            "storage",
            "cp",
            OBJECT.uri,
            destination.to_str().context("nonUTF8 path")?,
        ])
        .spawn()?,
    ));
    while !child.finished()? {
        guard(&p, start)?;
        thread::sleep(Duration::from_secs(1));
    }
    ensure!(
        child.finish()?.success(),
        "SDK download failed; credentials suppressed"
    );
    ensure!(
        unsafe { libc::fchown(directory.as_raw_fd(), 0, 0) } == 0,
        "cannot freeze staging"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&destination)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.uid() == 1000 && m.len() == OBJECT.size,
        "unexpected downloaded file"
    );
    ensure!(
        unsafe { libc::fchown(file.as_raw_fd(), 0, 0) } == 0,
        "cannot freeze file"
    );
    file.set_permissions(fs::Permissions::from_mode(0o400))?;
    file.sync_all()?;
    directory.sync_all()?;
    let initial = identity(&file.metadata()?);
    let (crc, md5, sha256) = hashes(&mut file, OBJECT.size, || guard(&p, start))?;
    ensure!(
        crc == OBJECT.crc && md5 == OBJECT.md5,
        "download hashes mismatch"
    );
    sdk_digest(&p.gcloud_sha256)?;
    let after_metadata = metadata()?;
    guard(&p, start)?;
    ensure!(
        initial == identity(&file.metadata()?)
            && initial == identity(&fs::symlink_metadata(&destination)?),
        "input changed"
    );
    validate_fleet_binding(&p, &observer)?;
    let mut receipt = json!({"schema":RECEIPT_SCHEMA,"epoch":EPOCH,"recorded_unix_seconds":now()?,"invocation_id":invocation,"plan_sha256":args[1],"self_sha256":args[2],"observer_sha256":p.observer_sha256,"gcloud_sha256":p.gcloud_sha256,"path":destination,"size":OBJECT.size,"sha256":sha256,"crc32c_base64":crc,"md5_base64":md5,"generation":OBJECT.generation,"uri":OBJECT.uri,"before_metadata":before_metadata,"after_metadata":after_metadata,"minimum_free_bytes":p.minimum_free_bytes,"file_identity":initial,"compressed_input_verified":true,"native_restore_authorized":false,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
    if let Some(fleet) = &p.fleet {
        receipt["fleet_receipt"] = json!(fleet.path);
        receipt["fleet_sha256"] = json!(fleet.sha256);
    }
    write_receipt(&p.receipt, &receipt)?;
    println!("compressed bootstrap prepared; restore/replay/publication remain unauthorized");
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn check_only_is_explicit_and_never_available_to_legacy223() {
        let mut args = vec!["plan".to_owned(), "hash".to_owned(), "self".to_owned()];
        assert!(!check_only(&args).unwrap());
        args.push("--check-only".to_owned());
        if PROTECTED_FLEET {
            assert!(check_only(&args).unwrap());
        } else {
            assert!(check_only(&args).is_err());
        }
        args[3] = "--allow-replay".to_owned();
        assert!(check_only(&args).is_err());
        assert!(check_only(&[]).is_err());
        args.push("extra".to_owned());
        assert!(check_only(&args).is_err());
    }
    #[test]
    fn bytes_are_hashed_without_relaxing_length() {
        let (c, m, s) = hashes(&b"abc"[..], 3, || Ok(())).unwrap();
        assert_eq!(c, "Nks/tw==");
        assert_eq!(m, "kAFQmDzST7DWlj99KOF/cg==");
        assert_eq!(s, sha(b"abc"));
        assert!(hashes(&b"abc"[..], 2, || Ok(())).is_err());
        assert!(hashes(&b"abc"[..], 4, || Ok(())).is_err());
        assert!(hashes(&b"abc"[..], 3, || anyhow::bail!("floor")).is_err());
    }
    #[test]
    fn metadata_binds_exact_generation_and_hashes() {
        let mut m = json!({"bucket":OBJECT.bucket,"name":OBJECT.name,"generation":OBJECT.generation,"size":OBJECT.size,"crc32c_hash":OBJECT.crc,"md5_hash":OBJECT.md5,"storage_url":OBJECT.uri});
        validate_object_metadata(&m, &OBJECT).unwrap();
        m["generation"] = json!("1631874643386185");
        assert!(validate_object_metadata(&m, &OBJECT).is_err());
    }
    #[test]
    fn metadata_rejects_other_objects_missing_hashes_and_conflicting_aliases() {
        let correct = json!({"bucket":OBJECT.bucket,"name":OBJECT.name,"generation":OBJECT.generation,"size":OBJECT.size,"crc32c_hash":OBJECT.crc,"md5_hash":OBJECT.md5,"storage_url":OBJECT.uri});
        for (key, value) in [
            ("bucket", json!("other-bucket")),
            ("name", json!("other-snapshot.tar.zst")),
            ("size", json!(OBJECT.size + 1)),
            ("crc32c_hash", json!("AAAAAA==")),
            ("md5_hash", json!("AAAAAAAAAAAAAAAAAAAAAA==")),
            ("storage_url", json!(format!("{}0", OBJECT.uri))),
            ("crc32c", json!("AAAAAA==")),
            ("md5Hash", json!("AAAAAAAAAAAAAAAAAAAAAA==")),
        ] {
            let mut wrong = correct.clone();
            wrong[key] = value;
            assert!(validate_object_metadata(&wrong, &OBJECT).is_err(), "{key}");
        }
        for key in ["crc32c_hash", "md5_hash", "generation", "storage_url"] {
            let mut missing = correct.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(validate_object_metadata(&missing, &OBJECT).is_err(), "{key}");
        }
    }
    #[test]
    fn protected_profile_requires_fleet_and_legacy_cannot_opt_in() {
        let mut p = Plan {
            fleet: None,
            schema: String::new(),
            gcloud_sha256: String::new(),
            observer: PathBuf::new(),
            observer_sha256: String::new(),
            minimum_free_bytes: MINIMUM_PROTECTED_FREE,
            staging_directory: PathBuf::new(),
            receipt: PathBuf::new(),
        };
        if PROTECTED_FLEET {
            assert!(validate_fleet_binding(&p, &Value::Null).is_err());
        } else {
            validate_fleet_binding(&p, &Value::Null).unwrap();
            p.fleet = Some(Bound {
                path: PathBuf::from("/unread/foreign-fleet.json"),
                sha256: "a".repeat(64),
            });
            assert!(validate_fleet_binding(&p, &Value::Null).is_err());
        }
    }
    #[test]
    fn admission_requires_fresh_v2_complete_transfer_headroom() {
        let mut p = Plan {
            fleet: None,
            schema: String::new(),
            gcloud_sha256: String::new(),
            observer: PathBuf::new(),
            observer_sha256: String::new(),
            minimum_free_bytes: MINIMUM_PROTECTED_FREE,
            staging_directory: PathBuf::new(),
            receipt: PathBuf::new(),
        };
        let mut v = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"1970-01-01T02:46:40Z","filesystem":{"conservative_available_bytes":p.minimum_free_bytes+OBJECT.size+SLACK}});
        if PROTECTED_FLEET {
            v = bootstrap227_protection::observer_fixture(v);
        }
        admission(&v, &p, 10000).unwrap();
        assert!(admission(&v, &p, 11801).is_err());
        assert!(admission(&v, &p, 9999).is_err());
        v["filesystem"]["conservative_available_bytes"] =
            json!(p.minimum_free_bytes + OBJECT.size + SLACK - 1);
        assert!(admission(&v, &p, 10000).is_err());
        p.minimum_free_bytes = 1;
        assert!(admission(&v, &p, 10000).is_err());
    }
    #[test]
    fn observer_timestamp_matches_actual_v2_shape() {
        assert_eq!(utc_seconds("2026-10-21T18:59:36Z").unwrap(), 1792609176);
        for wrong in [
            "2026-02-30T18:59:36Z",
            "2026-10-21T18:59:36+00:00",
            "2026-10-21T18:59:36Zx",
            "2026-10-21T18:59:60Z",
        ] {
            assert!(utc_seconds(wrong).is_err(), "{wrong}");
        }
    }
    #[test]
    fn plan_cannot_override_object_or_execution_identity() {
        let value = json!({"schema":PLAN_SCHEMA,"gcloud_sha256":"0".repeat(64),"observer":"/sealed/observer.json","observer_sha256":"1".repeat(64),"minimum_free_bytes":MINIMUM_PROTECTED_FREE,"staging_directory":"/staging/attempt","receipt":"/receipts/result.json"});
        serde_json::from_value::<Plan>(value.clone()).unwrap();
        for key in [
            "uri",
            "generation",
            "gcloud",
            "cloudsdk_config",
            "uid",
            "replay_launch_authorized",
        ] {
            let mut wrong = value.clone();
            wrong[key] = json!("override");
            assert!(serde_json::from_value::<Plan>(wrong).is_err(), "{key}");
        }
    }
    #[test]
    fn staging_guard_rejects_symlinks_oversize_and_runtime_expiry() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let p = Plan {
            fleet: None,
            schema: String::new(),
            gcloud_sha256: String::new(),
            observer: PathBuf::new(),
            observer_sha256: String::new(),
            minimum_free_bytes: 0,
            staging_directory: directory.path().to_path_buf(),
            receipt: PathBuf::new(),
        };
        guard(&p, Instant::now()).unwrap();
        symlink("/dev/null", directory.path().join("wrong")).unwrap();
        assert!(guard(&p, Instant::now()).is_err());
        fs::remove_file(directory.path().join("wrong")).unwrap();
        let input = File::create(directory.path().join("large")).unwrap();
        input.set_len(OBJECT.size + SLACK + 1).unwrap();
        assert!(guard(&p, Instant::now()).is_err());
        input.set_len(0).unwrap();
        assert!(guard(&p, Instant::now() - Duration::from_secs(7201)).is_err());
    }
    #[test]
    #[ignore = "root-only owned process-group cleanup qualification"]
    fn owned_process_group_is_killed_before_reaping() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let mut cmd = Command::new("/bin/sleep");
        cmd.arg("60");
        unsafe {
            cmd.pre_exec(|| {
                if libc::setpgid(0, 0) != 0
                    || libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(1000) != 0
                    || libc::setuid(1000) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut owned = Owned(Some(cmd.spawn().unwrap()));
        let pid = owned.0.as_ref().unwrap().id();
        let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        assert!(
            status
                .lines()
                .any(|line| line == "Uid:\t1000\t1000\t1000\t1000")
        );
        assert!(!owned.finished().unwrap());
        assert!(!owned.finish().unwrap().success());
        assert!(owned.0.is_none());
        assert!(fs::metadata(format!("/proc/{pid}")).is_err());
    }
}
