//! Retire explicitly selected obsolete local files after complete R2 delivery.
//! This is not a canonical-archive verifier: obsolete partial bodies need not
//! equal the complete archive. The operator must establish epoch association and
//! absence of staged dependencies before authorizing the exact immutable plan.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::fd::AsRawFd,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(feature = "anza-parked-183")]
mod anza_parked_183;

const HOME_ROOT: &str = if cfg!(feature = "anza-parked-183") {
    "/home/sol"
} else {
    "/home/ubuntu"
};
const LIMIT: u64 = 16 << 20;
const EPOCH246_BOOTSTRAP: &str = "/var/lib/jetstreamer/horizon246-bootstrap-copy1636-work-v2/projection/bootstrap/snapshot-106271618-6LSJUywaryX8vRn53cbWqLJiTwBCCb3wnNTPevWfqtQD.tar.zst";
const EPOCH246_BOOTSTRAP_SHA: &str =
    "c5abfce5d852b78860d22d71f1ce57f6752f45bb428257a73e037895ec6a03e7";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
struct Stamp {
    dev: u64,
    ino: u64,
    len: u64,
    blocks: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    epoch: u64,
    path: PathBuf,
    identity: Stamp,
    reason: String,
    #[serde(default)]
    external_bootstrap_review: Option<Bound>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapReview {
    schema: String,
    epoch: u64,
    path: PathBuf,
    identity: Stamp,
    snapshot_sha256: String,
    no_staged_consumers_confirmed: bool,
    original_copy_completion: Bound,
    evidence: Vec<Bound>,
    inactive_units: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    epoch: u64,
    receipt: Bound,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    obsolete_local_files_authorized: bool,
    no_staged_consumers_confirmed: bool,
    remote_mutations: bool,
    inventory_binary: Bound,
    proofs: Vec<Proof>,
    targets: Vec<Target>,
    inactive_units: Vec<String>,
    audit: PathBuf,
    #[cfg(feature = "anza-parked-183")]
    holding_custody: Bound,
}
fn stamp(m: &fs::Metadata) -> Stamp {
    Stamp {
        dev: m.dev(),
        ino: m.ino(),
        len: m.len(),
        blocks: m.blocks(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
        nlink: m.nlink(),
        mtime: m.mtime(),
        mtime_ns: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
    }
}
fn exact(path: &Path) -> Result<fs::Metadata> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "aliased/relative path: {}",
        path.display()
    );
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file() && m.nlink() == 1,
        "not a singly linked regular file: {}",
        path.display()
    );
    Ok(m)
}
fn digest(path: &Path) -> Result<String> {
    // The kernel's own executable handle is deliberately a procfs magic link.
    // All ordinary evidence paths still refuse symlinks.
    let mut f = if path == Path::new("/proc/self/exe") {
        File::open(path)?
    } else {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?
    };
    let mut h = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}
fn bound(b: &Bound, limit: u64) -> Result<Vec<u8>> {
    let before = stamp(&exact(&b.path)?);
    ensure!(before.len <= limit, "oversized evidence");
    let bytes = fs::read(&b.path)?;
    ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == b.sha256 && stamp(&exact(&b.path)?) == before,
        "changed evidence: {}",
        b.path.display()
    );
    Ok(bytes)
}
fn ready(epoch: u64, receipt: &Value, inventory: &Value) -> Result<()> {
    let entries = inventory["entries"]
        .as_array()
        .context("missing inventory entries")?;
    let matching: Vec<_> = entries.iter().filter(|e| e["epoch"] == epoch).collect();
    ensure!(matching.len() == 1, "ambiguous/missing remote epoch");
    let e = matching[0];
    ensure!(
        inventory["schema"] == "jetstreamer-horizon-r2-inventory-v1" && e["state"] == "ready-pair",
        "remote pair not ready"
    );
    let sha = receipt["archive_sha256"]
        .as_str()
        .context("receipt SHA missing")?;
    ensure!(
        sha.len() == 64
            && sha
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "bad SHA"
    );
    ensure!(
        receipt["schema"] == "jetstreamer-horizon-r2-receipt-v1"
            && receipt["bucket"] == "solana-archive-with-accounts-data"
            && receipt["epoch"] == epoch
            && receipt["remote_sha256_readback"] == true
            && receipt["archive_key"] == format!("epoch-{epoch}.jet")
            && receipt["checksum_key"] == format!("epoch-{epoch}.jet.sha256"),
        "receipt lacks whole-object delivery proof"
    );
    ensure!(
        receipt["archive_length"].as_u64().is_some_and(|n| n > 0)
            && receipt["archive_etag"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
        "incomplete receipt"
    );
    ensure!(
        receipt["archive_length"] == e["archive_length"]
            && receipt["archive_etag"] == e["archive_etag"]
            && e["sidecar_sha256"] == sha
            && e["archive_metadata_sha256"] == sha,
        "remote pair differs from durable receipt"
    );
    Ok(())
}
fn check_target(t: &Target) -> Result<()> {
    #[cfg(feature = "anza-parked-183")]
    let scope = anza_parked_183::is_target(t);
    #[cfg(not(feature = "anza-parked-183"))]
    let scope = (201..=300).contains(&t.epoch);
    ensure!(
        scope && !t.reason.trim().is_empty(),
        "invalid target authorization"
    );
    ensure!(
        ordinary_private_path(&t.path) || external_bootstrap_path(t.epoch, &t.path),
        "target outside private data"
    );
    ensure!(
        stamp(&exact(&t.path)?) == t.identity,
        "target changed: {}",
        t.path.display()
    );
    ensure!(t.identity.len > 1 << 20, "retain compact metadata");
    if external_bootstrap_path(t.epoch, &t.path) {
        let binding = t
            .external_bootstrap_review
            .as_ref()
            .context("external bootstrap needs Main review")?;
        let metadata = exact(&binding.path)?;
        ensure!(
            metadata.uid() == 0 && metadata.mode() & 0o222 == 0,
            "external review must be sealed"
        );
        let review: BootstrapReview = serde_json::from_slice(&bound(binding, LIMIT)?)?;
        validate_bootstrap_review(t, &review)?;
        for evidence in &review.evidence {
            bound(evidence, LIMIT)?;
        }
        let completion: Value =
            serde_json::from_slice(&bound(&review.original_copy_completion, LIMIT)?)?;
        ensure!(
            completion["schema"] == "horizon246-guarded-exact-Rust-sealer-copy1024-completion-v1"
                && completion["Main_accepted_copy_only"] == true
                && completion["snapshot"]["path"] == EPOCH246_BOOTSTRAP
                && completion["snapshot"]["sha256"] == EPOCH246_BOOTSTRAP_SHA
                && completion["snapshot"]["bytes"] == t.identity.len,
            "external bootstrap differs from original copy evidence"
        );
        inactive(&review.inactive_units)?;
    } else {
        ensure!(
            t.external_bootstrap_review.is_none(),
            "external review on ordinary private target"
        );
    }
    Ok(())
}

fn ordinary_private_path(path: &Path) -> bool {
    let private = Path::new(HOME_ROOT).join(".jetstreamer-private");
    path.starts_with(&private) && !path.starts_with(private.join("r2-receipts"))
}
fn external_bootstrap_path(epoch: u64, path: &Path) -> bool {
    epoch == 246 && path == Path::new(EPOCH246_BOOTSTRAP)
}
fn validate_bootstrap_review(t: &Target, r: &BootstrapReview) -> Result<()> {
    ensure!(
        r.schema == "horizon246-obsolete-bootstrap-main-review-v1"
            && r.epoch == 246
            && r.path == t.path
            && r.identity == t.identity
            && r.snapshot_sha256 == EPOCH246_BOOTSTRAP_SHA
            && r.no_staged_consumers_confirmed
            && t.identity.uid == 0
            && t.identity.len == 13110128323
            && !r.evidence.is_empty(),
        "invalid external bootstrap review"
    );
    for required in [
        "horizon-qualify-246-general-shrink-debt-budget506-e3f15eb2-v1.service",
        "horizon-qualify-246-bootstrap-copy1636-v2.service",
        "horizon-monitor-246-bootstrap-copy1636-v2.service",
        "horizon-monitor-246-bootstrap-copy1636-v2.timer",
    ] {
        ensure!(
            r.inactive_units.iter().any(|u| u == required),
            "missing historical bootstrap consumer {required}"
        );
    }
    Ok(())
}
fn inactive(units: &[String]) -> Result<()> {
    for unit in units {
        ensure!(
            unit.ends_with(".service") || unit.ends_with(".timer"),
            "invalid unit"
        );
        ensure!(
            unit.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.@-".contains(&b)),
            "unsafe unit name"
        );
        let o = Command::new("/usr/bin/systemctl")
            .args(["show", unit, "-p", "ActiveState", "-p", "MainPID"])
            .output()?;
        ensure!(o.status.success(), "cannot inspect unit {unit}");
        let s = String::from_utf8(o.stdout)?;
        ensure!(
            s.lines()
                .any(|s| s == "ActiveState=inactive" || s == "ActiveState=failed")
                && !s
                    .lines()
                    .any(|s| s.starts_with("MainPID=") && s != "MainPID=0"),
            "unit is live: {unit}"
        );
    }
    Ok(())
}
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}
fn scan_consumers(targets: &[Target]) -> Result<()> {
    let me = std::process::id().to_string();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let pid = entry.file_name();
        let pid = pid.to_string_lossy();
        if pid == me || !pid.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let root = entry.path();
        let check = || -> Result<()> {
            for name in ["cmdline", "maps"] {
                let data = fs::read(root.join(name))?;
                for t in targets {
                    ensure!(
                        !contains(&data, t.path.as_os_str().as_bytes()),
                        "PID {pid} references {} in {name}",
                        t.path.display()
                    );
                    #[cfg(feature = "anza-parked-183")]
                    ensure!(
                        name != "maps" || !anza_parked_183::has_mapping(&data, t),
                        "PID {pid} maps the selected archive inode"
                    );
                }
            }
            for name in ["cwd", "root", "exe"] {
                match fs::read_link(root.join(name)) {
                    Ok(p) => {
                        for t in targets {
                            ensure!(p != t.path, "PID {pid} uses {}", t.path.display());
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
            for fd in fs::read_dir(root.join("fd"))? {
                let fd = fd?;
                match fs::metadata(fd.path()) {
                    Ok(m) => {
                        for t in targets {
                            ensure!(
                                (m.dev(), m.ino()) != (t.identity.dev, t.identity.ino),
                                "PID {pid} has {} open",
                                t.path.display()
                            );
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
            Ok(())
        };
        if let Err(e) = check()
            && root.exists()
        {
            return Err(e);
        }
    }
    Ok(())
}
fn event(log: &mut File, v: Value) -> Result<()> {
    serde_json::to_writer(&mut *log, &v)?;
    log.write_all(b"\n")?;
    log.sync_all()?;
    Ok(())
}
fn remove_exact(t: &Target) -> Result<()> {
    check_target(t)?;
    unlink_identity(&t.path, &t.identity)
}
fn unlink_identity(path: &Path, expected: &Stamp) -> Result<()> {
    let parent = path.parent().context("no parent")?;
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)?;
    let projected = PathBuf::from(format!(
        "/proc/self/fd/{}/{}",
        dir.as_raw_fd(),
        path.file_name().unwrap().to_string_lossy()
    ));
    ensure!(
        stamp(&fs::symlink_metadata(&projected)?) == *expected,
        "changed directory entry"
    );
    let name = std::ffi::CString::new(path.file_name().unwrap().as_bytes())?;
    ensure!(
        unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } == 0,
        "unlink failed: {}",
        std::io::Error::last_os_error()
    );
    dir.sync_all()?;
    Ok(())
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 4 || args.len() == 5,
        "usage: horizon-retire-completed PLAN PLAN_SHA256 SELF_SHA256 [--check-only]"
    );
    let check_only = args.len() == 5;
    ensure!(!check_only || args[4] == "--check-only", "unknown argument");
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "requires root for complete consumer inspection"
    );
    ensure!(
        digest(Path::new("/proc/self/exe"))? == args[3],
        "self digest mismatch"
    );
    let plan_path = PathBuf::from(&args[1]);
    let pm = exact(&plan_path)?;
    ensure!(
        pm.uid() == 0 && pm.mode() & 0o022 == 0,
        "plan not immutable root-owned evidence"
    );
    let bytes = bound(
        &Bound {
            path: plan_path,
            sha256: args[2].clone(),
        },
        LIMIT,
    )?;
    let p: Plan = serde_json::from_slice(&bytes)?;
    ensure!(
        p.schema == "horizon-retire-completed-v1"
            && p.obsolete_local_files_authorized
            && p.no_staged_consumers_confirmed
            && !p.remote_mutations,
        "unauthorized plan"
    );
    ensure!(
        !p.targets.is_empty() && !p.proofs.is_empty(),
        "empty selection"
    );
    let mut paths = BTreeSet::new();
    let mut epochs = BTreeSet::new();
    for t in &p.targets {
        ensure!(paths.insert(&t.path), "duplicate target");
        epochs.insert(t.epoch);
        check_target(t)?;
        if external_bootstrap_path(t.epoch, &t.path) {
            ensure!(
                digest(&t.path)? == EPOCH246_BOOTSTRAP_SHA,
                "external bootstrap content changed"
            );
            check_target(t)?;
        }
    }
    let proof_epochs: BTreeSet<_> = p.proofs.iter().map(|x| x.epoch).collect();
    ensure!(
        proof_epochs == epochs && p.proofs.len() == epochs.len(),
        "proof/target epoch mismatch"
    );
    let receipts = Path::new(HOME_ROOT).join(".jetstreamer-private/r2-receipts");
    #[cfg(feature = "anza-parked-183")]
    let _holding_locks = anza_parked_183::lock_original_owners()?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(receipts.join("local-mutation.lock"))?;
    ensure!(
        lock.metadata()?.is_file() && lock.metadata()?.nlink() == 1,
        "unsafe lock"
    );
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "mutation lock busy"
    );
    #[cfg(feature = "anza-parked-183")]
    anza_parked_183::verify(&p, &lock)?;
    let bm = exact(&p.inventory_binary.path)?;
    ensure!(
        bm.uid() == 0
            && bm.mode() & 0o022 == 0
            && digest(&p.inventory_binary.path)? == p.inventory_binary.sha256,
        "unqualified inventory binary"
    );
    inactive(&p.inactive_units)?;
    scan_consumers(&p.targets)?;
    let horizon = Path::new(HOME_ROOT).join("horizon");
    let output = Command::new(&p.inventory_binary.path)
        .env("TOKIO_WORKER_THREADS", "2")
        .arg("inventory")
        .arg(horizon)
        .arg("--epochs")
        .arg(format!(
            "{}-{}",
            epochs.first().unwrap(),
            epochs.last().unwrap()
        ))
        .arg("--receipt-directory")
        .arg(receipts)
        .output()?;
    ensure!(
        output.status.success(),
        "authenticated inventory failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    ensure!(output.stdout.len() <= LIMIT as usize, "oversized inventory");
    let inventory: Value = serde_json::from_slice(&output.stdout)?;
    for proof in &p.proofs {
        let r: Value = serde_json::from_slice(&bound(&proof.receipt, LIMIT)?)?;
        ready(proof.epoch, &r, &inventory)?;
    }
    inactive(&p.inactive_units)?;
    scan_consumers(&p.targets)?;
    for t in &p.targets {
        check_target(t)?;
    }
    if check_only {
        println!(
            "checked {} exact files, {} verified R2 epochs; no deletion",
            p.targets.len(),
            epochs.len()
        );
        return Ok(());
    }
    ensure!(
        p.audit.is_absolute()
            && p.audit.parent().context("audit parent")?.canonicalize()?
                == p.audit.parent().unwrap(),
        "aliased audit path"
    );
    let mut log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p.audit)?;
    event(
        &mut log,
        json!({"event":"authorized","plan_sha256":args[2],"self_sha256":args[3],"unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"inventory":inventory}),
    )?;
    File::open(p.audit.parent().unwrap())?.sync_all()?;
    let mut bytes = 0;
    for t in &p.targets {
        #[cfg(feature = "anza-parked-183")]
        anza_parked_183::check_owners()?;
        inactive(&p.inactive_units)?;
        scan_consumers(std::slice::from_ref(t))?;
        event(
            &mut log,
            json!({"event":"intent","epoch":t.epoch,"path":t.path,"identity":t.identity,"reason":t.reason}),
        )?;
        remove_exact(t)?;
        bytes += t.identity.blocks * 512;
        event(
            &mut log,
            json!({"event":"removed","epoch":t.epoch,"path":t.path,"allocated_bytes":t.identity.blocks*512}),
        )?;
    }
    event(
        &mut log,
        json!({"event":"complete","allocated_bytes_removed":bytes,"remote_mutations":false}),
    )?;
    println!(
        "removed {} files, {} allocated bytes; receipt {}",
        p.targets.len(),
        bytes,
        p.audit.display()
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e:#}");
        std::process::exit(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn external_route_is_one_epoch_one_file_and_never_metadata() {
        assert!(external_bootstrap_path(246, Path::new(EPOCH246_BOOTSTRAP)));
        for path in [
            "/var/lib/jetstreamer/other/snapshot.tar.zst",
            "/var/lib/jetstreamer/horizon246-bootstrap-copy1636-work-v2/projection/bootstrap/deployment-seal-receipt.json",
            "/var/lib/jetstreamer/horizon246-bootstrap-copy1636-work-v2/projection/bootstrap",
        ] {
            assert!(!external_bootstrap_path(246, Path::new(path)));
        }
        assert!(!external_bootstrap_path(247, Path::new(EPOCH246_BOOTSTRAP)));
        let home = Path::new(HOME_ROOT);
        assert!(ordinary_private_path(
            &home.join(".jetstreamer-private/old/archive")
        ));
        assert!(!ordinary_private_path(
            &home.join(".jetstreamer-private/r2-receipts/epoch-246.r2.json")
        ));
    }

    #[test]
    fn external_review_requires_exact_identity_and_complete_inactive_consumer_set() {
        let mut r: BootstrapReview = serde_json::from_value(json!({
            "schema":"horizon246-obsolete-bootstrap-main-review-v1", "epoch":246,
            "path":EPOCH246_BOOTSTRAP,"snapshot_sha256":EPOCH246_BOOTSTRAP_SHA,
            "identity":{"dev":1,"ino":2,"len":13110128323u64,"blocks":25605744,
                "uid":0,"gid":0,"mode":33060,"nlink":1,"mtime":1,"mtime_ns":0,"ctime":1,"ctime_ns":0},
            "no_staged_consumers_confirmed":true,
            "original_copy_completion":{"path":"/completion","sha256":"a".repeat(64)},
            "evidence":[{"path":"/review","sha256":"b".repeat(64)}],
            "inactive_units":["horizon-qualify-246-general-shrink-debt-budget506-e3f15eb2-v1.service",
                "horizon-qualify-246-bootstrap-copy1636-v2.service","horizon-monitor-246-bootstrap-copy1636-v2.service",
                "horizon-monitor-246-bootstrap-copy1636-v2.timer"]
        })).unwrap();
        let t = Target {
            epoch: 246,
            path: EPOCH246_BOOTSTRAP.into(),
            identity: r.identity.clone(),
            reason: "obsolete".into(),
            external_bootstrap_review: None,
        };
        validate_bootstrap_review(&t, &r).unwrap();
        r.identity.ino += 1;
        assert!(validate_bootstrap_review(&t, &r).is_err());
        r.identity = t.identity.clone();
        r.no_staged_consumers_confirmed = false;
        assert!(validate_bootstrap_review(&t, &r).is_err());
        r.no_staged_consumers_confirmed = true;
        r.inactive_units.pop();
        assert!(validate_bootstrap_review(&t, &r).is_err());
    }
    #[test]
    fn running_executable_can_be_hashed() {
        assert_eq!(
            digest(Path::new("/proc/self/exe")).unwrap(),
            digest(&std::env::current_exe().unwrap()).unwrap()
        );
    }
    fn pair() -> (Value, Value) {
        let sha = "a".repeat(64);
        (
            json!({"schema":"jetstreamer-horizon-r2-receipt-v1","bucket":"solana-archive-with-accounts-data","epoch":202,"remote_sha256_readback":true,"archive_key":"epoch-202.jet","checksum_key":"epoch-202.jet.sha256","archive_length":100,"archive_etag":"etag","archive_sha256":sha}),
            json!({"schema":"jetstreamer-horizon-r2-inventory-v1","entries":[{"epoch":202,"state":"ready-pair","archive_length":100,"archive_etag":"etag","sidecar_sha256":sha,"archive_metadata_sha256":sha}]}),
        )
    }
    #[test]
    fn authentic_complete_pair() {
        let (r, i) = pair();
        ready(202, &r, &i).unwrap();
    }
    #[test]
    fn no_readback_rejected() {
        let (mut r, i) = pair();
        r["remote_sha256_readback"] = json!(false);
        assert!(ready(202, &r, &i).is_err());
    }
    #[test]
    fn remote_changes_rejected() {
        for field in [
            "archive_length",
            "archive_etag",
            "sidecar_sha256",
            "archive_metadata_sha256",
            "state",
        ] {
            let (r, mut i) = pair();
            i["entries"][0][field] = json!("changed");
            assert!(ready(202, &r, &i).is_err(), "{field}");
        }
    }
    #[test]
    fn wrong_epoch_and_duplicate_rejected() {
        let (r, mut i) = pair();
        assert!(ready(203, &r, &i).is_err());
        let e = i["entries"][0].clone();
        i["entries"].as_array_mut().unwrap().push(e);
        assert!(ready(202, &r, &i).is_err());
    }
    #[test]
    fn aliases_and_hardlinks_rejected() {
        let p = std::env::temp_dir().join(format!("retire-test-{}", std::process::id()));
        fs::create_dir(&p).unwrap();
        let f = p.join("data");
        fs::write(&f, b"test").unwrap();
        exact(&f).unwrap();
        let link = p.join("link");
        std::os::unix::fs::symlink(&f, &link).unwrap();
        assert!(exact(&link).is_err());
        fs::remove_file(&link).unwrap();
        fs::hard_link(&f, &link).unwrap();
        assert!(exact(&f).is_err());
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn deletion_rejects_changed_file_and_preserves_neighbor() {
        let p = std::env::temp_dir().join(format!("retire-unlink-test-{}", std::process::id()));
        fs::create_dir(&p).unwrap();
        let f = p.join("selected");
        let other = p.join("preserved");
        fs::write(&f, b"old").unwrap();
        fs::write(&other, b"evidence").unwrap();
        let before = stamp(&exact(&f).unwrap());
        fs::write(&f, b"changed content").unwrap();
        assert!(unlink_identity(&f, &before).is_err());
        assert_eq!(fs::read(&f).unwrap(), b"changed content");
        unlink_identity(&f, &stamp(&exact(&f).unwrap())).unwrap();
        assert!(!f.exists());
        assert_eq!(fs::read(&other).unwrap(), b"evidence");
        fs::remove_dir_all(p).unwrap();
    }
}
