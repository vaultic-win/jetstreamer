//! Resource-admitted read-only hash of one old partial. No transfer or deletion.
use anyhow::{Context, Result, ensure};
use horizon_epoch157_laned_closed_partial::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Component, Path},
    process::Command,
    time::{Duration, Instant},
};

fn stamp(m: &fs::Metadata) -> Value {
    json!({"device":m.dev(),"inode":m.ino(),"uid":m.uid(),"gid":m.gid(),"mode":m.mode()&0o7777,"length":m.len(),"links":m.nlink(),"mtime_seconds":m.mtime(),"mtime_nanoseconds":m.mtime_nsec(),"ctime_seconds":m.ctime(),"ctime_nanoseconds":m.ctime_nsec()})
}
fn directory(path: &Path) -> Result<File> {
    ensure!(path.is_absolute(), "absolute directory required");
    let mut dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    for component in path.components() {
        match component {
            Component::RootDir => (),
            Component::Normal(name) => {
                let name = CString::new(name.as_bytes())?;
                let fd = unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                ensure!(
                    fd >= 0,
                    "directory anchor failed: {}",
                    std::io::Error::last_os_error()
                );
                dir = unsafe { File::from_raw_fd(fd) };
            }
            _ => anyhow::bail!("noncanonical directory"),
        }
    }
    Ok(dir)
}
fn file_at(dir: &File, name: &str) -> Result<File> {
    let name = CString::new(name)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    ensure!(
        fd >= 0,
        "anchored file unavailable: {}",
        std::io::Error::last_os_error()
    );
    Ok(unsafe { File::from_raw_fd(fd) })
}
struct Lease {
    pin: Value,
    dir: File,
    lock: File,
}
impl Lease {
    fn acquire(pin: &Value) -> Result<Self> {
        let dir = directory(Path::new(pin["root"].as_str().context("controller root")?))?;
        ensure!(
            stamp(&dir.metadata()?) == pin["root_identity"],
            "controller root changed"
        );
        let lock = file_at(&dir, "controller.lock")?;
        ensure!(
            stamp(&lock.metadata()?) == pin["lock_identity"],
            "controller lock changed"
        );
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "existing creator lease occupied"
        );
        let lease = Self {
            pin: pin.clone(),
            dir,
            lock,
        };
        lease.check()?;
        Ok(lease)
    }
    fn check(&self) -> Result<()> {
        let p = Path::new(self.pin["root"].as_str().context("controller root")?);
        ensure!(
            stamp(&directory(p)?.metadata()?) == self.pin["root_identity"]
                && stamp(&self.dir.metadata()?) == self.pin["root_identity"],
            "controller root replacement"
        );
        ensure!(
            stamp(&self.lock.metadata()?) == self.pin["lock_identity"]
                && stamp(&file_at(&self.dir, "controller.lock")?.metadata()?)
                    == self.pin["lock_identity"],
            "controller lock replacement"
        );
        let mut state = file_at(&self.dir, "state.json")?;
        ensure!(
            stamp(&state.metadata()?) == self.pin["state_identity"],
            "controller state identity changed"
        );
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut state)
            .take((1 << 20) + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= 1 << 20
                && sha(&bytes) == self.pin["state"]["sha256"]
                && stamp(&state.metadata()?) == self.pin["state_identity"]
                && stamp(&file_at(&self.dir, "state.json")?.metadata()?)
                    == self.pin["state_identity"],
            "controller state changed"
        );
        let value: Value = serde_json::from_slice(&bytes)?;
        ensure!(
            value["schema"] == "jetstreamer-adaptive-root-cohort-sweep-v3"
                && value["manifest_fingerprint"]
                    == "sha256:e3234f4207c549525edf9c85a867bba8dbb30eea667a188184aecbdef94d58e5",
            "original family state changed"
        );
        if p.ends_with("jetstreamer-root-sweep-epochs151-173-20260923-v91")
            || p.ends_with("jetstreamer-root-sweep-epochs151-173-20261001-v92-r2")
        {
            let a = &value["assignments"]["lane-d"];
            ensure!(
                a["unit"] == PRODUCER
                    && a["pid"] == 642701
                    && a["pid_start_time"] == 353584446
                    && a["first_epoch"] == 157
                    && a["last_epoch"] == 157
                    && a["phase"] == "producer",
                "exact157 producer assignment changed"
            );
        }
        Ok(())
    }
}
const KEYS: &str = "Id,LoadState,ActiveState,SubState,MainPID,ControlPID,Job,InvocationID,ControlGroup,FragmentPath,Triggers,TriggeredBy,OnSuccess,OnFailure,ExecStart,ExecStartPre,ExecStartPost,ExecCondition,ExecStop,ExecStopPost,ExecReload";
fn missing_owner(v: &Value) -> Result<()> {
    ensure!(
        v["Id"] == PRODUCER
            && v["LoadState"] == "not-found"
            && v["ActiveState"] == "inactive"
            && v["SubState"] == "dead"
            && v["MainPID"] == "0"
            && v["ControlPID"] == "0",
        "original owner still present"
    );
    for key in [
        "Job",
        "InvocationID",
        "ControlGroup",
        "FragmentPath",
        "Triggers",
        "TriggeredBy",
        "OnSuccess",
        "OnFailure",
    ] {
        ensure!(v[key] == "", "owner dispatch/reference remains: {key}");
    }
    for key in [
        "ExecStart",
        "ExecStartPre",
        "ExecStartPost",
        "ExecCondition",
        "ExecStop",
        "ExecStopPost",
        "ExecReload",
    ] {
        ensure!(
            v.get(key).is_none_or(|x| x == ""),
            "cached command remains: {key}"
        );
    }
    Ok(())
}
fn original_absent() -> Result<()> {
    match fs::read("/proc/642701/stat") {
        Ok(bytes) => {
            ensure!(bytes.len() <= 65536, "proc stat bound");
            let s = std::str::from_utf8(&bytes)?;
            let ticks = s
                .rsplit_once(')')
                .context("proc framing")?
                .1
                .split_whitespace()
                .nth(19)
                .context("start ticks")?
                .parse::<u64>()?;
            ensure!(ticks != 353584446, "original producer survives");
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    match fs::symlink_metadata(Path::new("/sys/fs/cgroup/system.slice").join(PRODUCER)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => anyhow::bail!("original cgroup reappeared"),
    }
}
fn native() -> Result<Value> {
    let o = Command::new("/usr/bin/systemctl")
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
        .env_remove("SYSTEMD_BUS_ADDRESS")
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env_remove("SYSTEMD_HOST")
        .args([
            "show",
            "--all",
            "--no-pager",
            PRODUCER,
            &format!("--property={KEYS}"),
        ])
        .output()?;
    ensure!(
        o.status.success() && o.stderr.is_empty() && o.stdout.len() <= 65536,
        "native query failed"
    );
    let mut fields = serde_json::Map::new();
    for line in std::str::from_utf8(&o.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("native field")?;
        ensure!(
            KEYS.split(',').any(|x| x == k) && fields.insert(k.into(), json!(v)).is_none(),
            "unexpected/duplicate native key"
        );
    }
    let v = Value::Object(fields);
    missing_owner(&v)?;
    original_absent()?;
    Ok(v)
}
fn fixed_metadata() -> Result<Value> {
    let cohort = format!("{RUN}/cohort-state.json");
    let bytes = small(Path::new(&cohort), false)?;
    ensure!(
        sha(&bytes) == "adf94e5dfdc9eeac826334a65f2e6026a140b04bc5fc34c8123f97513d2ada3d",
        "original cohort evidence changed"
    );
    bound(
        SNAPSHOT_UNIT,
        "aa26da82c373f4e8e6df6e22a665683478507097dd4b199569b4845fd1095666",
    )?;
    bound(
        "/usr/local/lib/jetstreamer/restore-bound-gcs-snapshot-20261011-v2.py",
        "38a2b4bf9d3e854694e114caaf04ca92599dc131ce2db4d407962c190d7c325a",
    )?;
    Ok(
        json!({"cohort":{"path":cohort,"sha256":sha(&bytes)},"snapshot_identity":preserved_snapshot()?,"snapshot_service":SNAPSHOT_UNIT,"snapshot_reader_preserved":true}),
    )
}
fn references() -> Result<Value> {
    let processes =
        jetstreamer_horizon_observe::process_references::scan(Path::new("/proc"), Path::new(RUN))?;
    let archive = jetstreamer_horizon_observe::dev_cache_check::sol_staged_path_references(
        Path::new(SOURCE),
    )?;
    let run =
        jetstreamer_horizon_observe::dev_cache_check::sol_staged_path_references(Path::new(RUN))?;
    Ok(json!({"processes":processes,"archive_staged":archive,"run_staged":run}))
}
fn references_clear(v: &Value) -> bool {
    v["processes"]["references"] == json!([])
        && v["archive_staged"]["references"] == json!([])
        && v["run_staged"]["references"] == json!([SNAPSHOT_UNIT])
}
fn review_creators() -> Result<Value> {
    let v: Value = serde_json::from_slice(&bound(REVIEW_PATH, REVIEW_SHA)?)?;
    let creators = v["creators"].as_array().context("creator evidence")?;
    ensure!(
        creators.len() == 9 && v["historical_invocation_not_inferred"] == true,
        "incomplete creator protocol review"
    );
    for c in creators {
        ensure!(
            c["lock_before_controller"] == true && c["lock_held_through_run_and_close"] == true,
            "creator protocol unfenced"
        );
        let p = c["path"].as_str().context("creator path")?;
        bound(p, c["sha256"].as_str().context("creator hash")?)?;
        ensure!(
            fs::symlink_metadata(p)?.mode() & 0o7777 == 0o555,
            "creator no longer immutable"
        );
    }
    Ok(v)
}
fn main() -> Result<()> {
    let started = Instant::now();
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        unsafe { libc::geteuid() } == 0
            && args.len() == 3
            && args[1] == "--self-sha256"
            && digest(&args[2]),
        "root; --self-sha256 HEX required"
    );
    ensure!(
        sha(&fs::read("/proc/self/exe")?) == args[2],
        "running image digest changed"
    );
    eprintln!(
        "{}",
        json!({"at":now()?,"epoch":157,"phase":"closure-check-start","elapsed_seconds":started.elapsed().as_secs(),"archive_bytes_read":0})
    );
    empty_root(
        Path::new(INSPECTION)
            .parent()
            .context("inspection parent")?,
    )?;
    let before = exact_source()?;
    let fixed_before = fixed_metadata()?;
    let review = review_creators()?;
    let pins: Value = serde_json::from_slice(&bound(PINS_PATH, PINS_SHA)?)?;
    let controllers = pins["controllers"].as_array().context("controller pins")?;
    ensure!(
        controllers.len() == 7,
        "all seven original family controllers required"
    );
    // Existing read-only descriptors only. No lock creation, replacement or state write.
    let leases = controllers
        .iter()
        .map(Lease::acquire)
        .collect::<Result<Vec<_>>>()?;
    let native_before = native()?;
    let refs_before = references()?;
    let clean = references_clear(&refs_before);
    let mut archive_sha = None;
    if clean {
        eprintln!(
            "{}",
            json!({"at":now()?,"epoch":157,"phase":"hash-start","elapsed_seconds":started.elapsed().as_secs(),"archive_bytes_read":0,"archive_length":LENGTH})
        );
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(SOURCE)?;
        ensure!(
            identity(&file.metadata()?) == before,
            "source changed before hash"
        );
        let mut hash = Sha256::new();
        let mut buffer = vec![0; 1 << 20];
        let mut total = 0u64;
        let mut last_report = Instant::now();
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            total = total
                .checked_add(n as u64)
                .context("hash length overflow")?;
            ensure!(total <= LENGTH, "source grew");
            hash.update(&buffer[..n]);
            if last_report.elapsed() >= Duration::from_secs(60) {
                let at = now()?;
                eprintln!(
                    "{}",
                    json!({"at":at,"epoch":157,"phase":"hash-progress","elapsed_seconds":started.elapsed().as_secs(),"archive_bytes_read":total,"archive_length":LENGTH,"last_substantive_progress_unix":at,"verification_complete":false})
                );
                last_report = Instant::now();
            }
        }
        ensure!(
            total == LENGTH && identity(&file.metadata()?) == before,
            "source changed while hashing"
        );
        archive_sha = Some(format!("{:x}", hash.finalize()));
        eprintln!(
            "{}",
            json!({"at":now()?,"epoch":157,"phase":"hash-complete-revalidating-closure","elapsed_seconds":started.elapsed().as_secs(),"archive_bytes_read":total,"verification_complete":false})
        );
    }
    let native_after = native()?;
    let refs_after = references()?;
    for lease in &leases {
        lease.check()?;
    }
    ensure!(
        exact_source()? == before
            && fixed_metadata()? == fixed_before
            && native_after == native_before,
        "source/closure/preserved metadata changed"
    );
    review_creators()?;
    let evidence = json!({"schema":SCHEMA,"owner":"/root","recorded_unix_seconds":now()?,"source":SOURCE,"length":LENGTH,"source_identity":before,"snapshot_identity":fixed_before["snapshot_identity"],"sha256":archive_sha,"source_stable":true,"native_consumers_clear":clean&&references_clear(&refs_after),"native_owner":native_after,"references_before":refs_before,"references_after":refs_after,"preserved_metadata":fixed_before,"creator_pins":{"path":PINS_PATH,"sha256":PINS_SHA},"creator_protocol_review":{"path":REVIEW_PATH,"sha256":REVIEW_SHA,"review":review},"creator_fence_held_across_hash":true,"controller_count":leases.len(),"original_producer":PRODUCER,"original_pid":642701,"original_start_ticks":353584446,"original_process_absent":true,"historical_stop_proven":false,"original_invocation_id":null,"closure_basis":"exact-seven-controller-leases-and-current-no-owner","complete_transitive_consumer_graph_qualified":false,"holding_custody_exists":false,"local_retirement_authorized":false,"canonical_publication_authorized":false,"replay_launch_authorized":false,"resource_credit_bytes":0,"remote_mutations":false,"inspection_image_sha256":args[2]});
    println!("{}", save(Path::new(INSPECTION), &evidence)?);
    eprintln!(
        "{}",
        json!({"at":now()?,"epoch":157,"phase":"inspection-complete","elapsed_seconds":started.elapsed().as_secs(),"native_consumers_clear":evidence["native_consumers_clear"],"local_retirement_authorized":false})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn lease_fixture() -> (tempfile::TempDir, Value) {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("controller.lock"), b"").unwrap();
        let state = serde_json::to_vec(&json!({
            "schema":"jetstreamer-adaptive-root-cohort-sweep-v3",
            "manifest_fingerprint":"sha256:e3234f4207c549525edf9c85a867bba8dbb30eea667a188184aecbdef94d58e5"
        })).unwrap();
        fs::write(dir.path().join("state.json"), &state).unwrap();
        let pin = json!({"root":dir.path(),
            "root_identity":stamp(&fs::metadata(dir.path()).unwrap()),
            "lock_identity":stamp(&fs::metadata(dir.path().join("controller.lock")).unwrap()),
            "state_identity":stamp(&fs::metadata(dir.path().join("state.json")).unwrap()),
            "state":{"sha256":sha(&state)}});
        (dir, pin)
    }
    #[test]
    fn existing_creator_lease_excludes_competitor_without_changing_bytes() {
        let (dir, pin) = lease_fixture();
        let lease = Lease::acquire(&pin).unwrap();
        assert!(Lease::acquire(&pin).is_err());
        lease.check().unwrap();
        assert_eq!(fs::read(dir.path().join("controller.lock")).unwrap(), b"");
        drop(lease);
        assert!(Lease::acquire(&pin).is_ok());
    }
    #[test]
    fn replaced_lock_is_rejected_even_while_original_descriptor_is_held() {
        let (dir, pin) = lease_fixture();
        let lease = Lease::acquire(&pin).unwrap();
        fs::rename(
            dir.path().join("controller.lock"),
            dir.path().join("old.lock"),
        )
        .unwrap();
        fs::write(dir.path().join("controller.lock"), b"").unwrap();
        assert!(lease.check().is_err());
    }
    fn missing() -> Value {
        json!({"Id":PRODUCER,"LoadState":"not-found","ActiveState":"inactive","SubState":"dead","MainPID":"0","ControlPID":"0","Job":"","InvocationID":"","ControlGroup":"","FragmentPath":"","Triggers":"","TriggeredBy":"","OnSuccess":"","OnFailure":""})
    }
    #[test]
    fn unloaded_defaults_do_not_prove_historical_success() {
        assert!(missing_owner(&missing()).is_ok());
        let mut v = missing();
        v["InvocationID"] = json!("unverified");
        assert!(missing_owner(&v).is_err());
    }
    #[test]
    fn cached_command_or_job_blocks() {
        for key in ["ExecStart", "Job", "Triggers", "ControlGroup"] {
            let mut v = missing();
            v[key] = json!("retained");
            assert!(missing_owner(&v).is_err());
        }
    }
    #[test]
    fn snapshot_exception_is_exact_and_does_not_allow_archive_reader() {
        let mut v = json!({"processes":{"references":[]},"archive_staged":{"references":[]},"run_staged":{"references":[SNAPSHOT_UNIT]}});
        assert!(references_clear(&v));
        v["archive_staged"]["references"] = json!([SNAPSHOT_UNIT]);
        assert!(!references_clear(&v));
    }
}
