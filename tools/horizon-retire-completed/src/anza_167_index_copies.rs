//! Retire exact duplicate compact indexes left by three stopped retries.
//! The original index is a live DATA witness and must remain in place.
use super::anza_stopped_167::{definitions, lock, properties, scan_run_references};
use super::*;
use std::collections::BTreeMap;
pub(super) const REVIEW: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch167-closed-retry-indexes-20261127-v1/REVIEW.json";
const REVIEW_SHA: &str = "6a2d8823aea7b40e8f55533fd4391f31408c8f0d70a6b27f717c110441c64e57";
const INDEX_SHA: &str = "213661ab71d1a0b40b5ae208356eaede8ae392a1a675a7775659f5268166f5be";
const LANE: &str = "/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1";
const INDEX: &str = "output/compact-indexes/167/epoch-167-bafyreienhstqouv46ysqm2r5dqeixnhmil3qem77x76q5hicq4egi3uzhi-mainnet-cid-to-offset-and-size.index";
const ATTEMPTS: [&str; 3] = [
    "replacement-local3-retry1-20261112-v1",
    "replacement-local3retry2-20261110-v1",
    "replacement-local3retry3-20261110-v1",
];
#[derive(Deserialize)]
struct Owner {
    attempt: PathBuf,
    iid: String,
    lock: EpochLock,
    admission: Bound,
    guard: Bound,
    stop: Bound,
    units: Vec<BTreeMap<String, String>>,
}
#[derive(Deserialize)]
struct EpochLock {
    path: PathBuf,
    inode: u64,
}
#[derive(Deserialize)]
struct Review {
    retained: Target,
    targets: Vec<Target>,
    owners: Vec<Owner>,
    digest_receipt: Bound,
    owner_lineage: Bound,
    content_sha256: String,
}
fn evidence(b: &Bound) -> Result<Value> {
    Ok(serde_json::from_slice(&bound(b, LIMIT)?)?)
}
fn entry_present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
fn unchanged(t: &Target) -> Result<()> {
    ensure!(
        stamp(&exact(&t.path)?) == t.identity,
        "reviewed index changed: {}",
        t.path.display()
    );
    Ok(())
}
fn scope(root: &Path, t: &Target, kept: &Target) -> bool {
    t.epoch == 167
        && t.path == root.join(INDEX)
        && t.identity.dev == 64512
        && t.identity.nlink == 1
        && t.identity.ino != kept.identity.ino
        && t.identity.len == kept.identity.len
}
fn controls(r: &Review, tokens: &[String]) -> Result<()> {
    unchanged(&r.retained)?;
    for o in &r.owners {
        for expected in &o.units {
            let unit = expected.get("Id").context("missing unit")?;
            let keys = expected
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(",");
            ensure!(
                properties(unit, &keys)? == *expected,
                "stopped owner changed: {unit}"
            );
        }
    }
    definitions(&[], tokens)?;
    scan_run_references(tokens)?;
    scan_consumers(&r.targets)
}
// Keep the per-index intent across a crash between unlink and the completion receipt.
fn marker(dir: &Path, name: &str, v: &Value) -> Result<()> {
    let path = dir.join(name);
    if path.try_exists()? {
        let m = exact(&path)?;
        ensure!(
            m.uid() == 0
                && m.mode() & 0o7777 == 0o400
                && m.len() < 16384
                && serde_json::from_slice::<Value>(&fs::read(&path)?)? == *v,
            "changed marker {name}"
        );
        return Ok(());
    }
    let tmp = dir.join(format!(".{name}.{}", std::process::id()));
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o400)
        .open(&tmp)?;
    serde_json::to_writer(&mut f, v)?;
    f.sync_all()?;
    let src = std::ffi::CString::new(tmp.as_os_str().as_bytes())?;
    let dst = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            src.as_ptr(),
            libc::AT_FDCWD,
            dst.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).context("publish index receipt");
    }
    File::open(dir)?.sync_all()?;
    Ok(())
}
pub(super) fn run(bytes: &[u8], review_sha: &str, image: &str, check_only: bool) -> Result<()> {
    ensure!(review_sha == REVIEW_SHA, "unregistered review");
    let r: Review = serde_json::from_slice(bytes)?;
    let dir = Path::new(REVIEW).parent().context("review directory")?;
    let dm = dir.symlink_metadata()?;
    let elf = dir.join("tools/retire");
    ensure!(
        dir.canonicalize()? == dir
            && dm.is_dir()
            && dm.uid() == 0
            && dm.mode() & 0o7777 == 0o700
            && fs::read_link("/proc/self/exe")? == elf
            && stamp(&exact(&elf)?) == stamp(&fs::metadata("/proc/self/exe")?)
            && digest(&elf)? == image,
        "unexpected deployment"
    );
    let _operation = lock(
        Path::new("/run/horizon-epoch171-to136-g1.operation.lock"),
        26,
        3453440,
        0,
        0,
    )?;
    let _mutation = lock(
        Path::new("/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock"),
        64512,
        101135013,
        1001,
        1003,
    )?;
    let lane = Path::new(LANE);
    ensure!(
        r.retained.path == lane.join(INDEX)
            && r.content_sha256 == INDEX_SHA
            && r.targets.len() == 3
            && r.owners.len() == 3,
        "incomplete index scope"
    );
    let hashes = evidence(&r.digest_receipt)?;
    let history = evidence(&r.owner_lineage)?;
    ensure!(
        hashes["same_bytes_across_six"] == true
            && hashes["retained_source"] == json!(r.retained.path)
            && hashes["sha256_by_path"][r.retained.path.to_str().unwrap()] == INDEX_SHA,
        "unverified retained index"
    );
    let mut leases = Vec::new();
    let mut tokens = Vec::new();
    for ((o, t), attempt) in r.owners.iter().zip(&r.targets).zip(ATTEMPTS) {
        ensure!(
            o.attempt == lane.join(attempt)
                && scope(&o.attempt, t, &r.retained)
                && o.lock.path.starts_with(o.attempt.join("private"))
                && o.lock.path.ends_with("locks/epoch-167.lock")
                && o.units.len() == 3
                && hashes["sha256_by_path"][t.path.to_str().context("index path")?] == INDEX_SHA,
            "wrong retry index or lease"
        );
        leases.push(lock(&o.lock.path, 64512, o.lock.inode, 1001, 1003)?);
        tokens.push(o.attempt.to_str().context("owner path")?.to_owned());
        let a = evidence(&o.admission)?;
        let g = evidence(&o.guard)?;
        let s = evidence(&o.stop)?;
        ensure!(
            a["epoch"] == 167
                && a["fresh_admission_passed"] == true
                && a["producer_invocation_id"] == o.iid
                && g["producer_invocation_id"] == o.iid
                && s["producer_invocation_id"] == o.iid
                && s["terminal"]["pid"] == 0
                && s["plan_sha256"] == g["plan"]["sha256"]
                && history["owners"]
                    .as_array()
                    .is_some_and(|rows| rows
                        .iter()
                        .any(|v| v["producer_stop"]["INVOCATION_ID"] == o.iid
                            && v["index"] == json!(t.path)
                            && v["pid_from_run"] == a["producer_pid"])),
            "unbound historic producer"
        );
    }
    controls(&r, &tokens)?;
    let check = json!({"review":review_sha,"image":image,"content_sha256":INDEX_SHA,"retained_inode":r.retained.identity.ino,"targets":r.targets.iter().map(|t|t.identity.ino).collect::<Vec<_>>()});
    if check_only {
        for t in &r.targets {
            unchanged(t)?;
        }
        ensure!(
            digest(&r.retained.path)? == INDEX_SHA,
            "retained index failed full readback"
        );
        controls(&r, &tokens)?;
        for t in &r.targets {
            unchanged(t)?;
        }
        marker(dir, "CHECK.json", &check)?;
        return Ok(());
    }
    ensure!(
        dir.join("CHECK.json").try_exists()?,
        "independent check required"
    );
    marker(dir, "CHECK.json", &check)?;
    for t in &r.targets {
        let ino = t.identity.ino;
        let note = json!({"check":check,"path":t.path,"identity":t.identity});
        let intent = format!("{ino}.intent.json");
        let parent = t.path.parent().context("index parent")?;
        ensure!(parent.canonicalize()? == parent, "index parent moved");
        let exists = entry_present(&t.path)?;
        if exists {
            unchanged(t)?;
        } else {
            ensure!(
                dir.join(&intent).try_exists()?,
                "missing index without intent"
            );
        }
        controls(&r, &tokens)?;
        marker(dir, &intent, &note)?;
        if exists {
            unlink_identity(&t.path, &t.identity)?;
        }
        ensure!(!entry_present(&t.path)?, "index remains");
        unchanged(&r.retained)?;
        marker(dir, &format!("{ino}.complete.json"), &note)?;
    }
    controls(&r, &tokens)?;
    let total: u64 = r.targets.iter().map(|t| t.identity.blocks * 512).sum();
    marker(
        dir,
        "COMPLETE.json",
        &json!({"allocated_bytes_removed":total,"check":check,"retained":r.retained.path,"remote_mutations":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dangling_index_entry_is_present() {
        let dir = std::env::temp_dir().join(format!("index-link-test-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("index");
        assert!(!entry_present(&path).unwrap());
        std::os::unix::fs::symlink("missing", &path).unwrap();
        assert!(entry_present(&path).unwrap());
        fs::remove_file(path).unwrap();
        fs::remove_dir(dir).unwrap();
    }
    #[test]
    #[ignore = "requires root-owned markers"]
    fn completion_markers_reject_a_different_index_after_retry() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let dir =
            std::env::temp_dir().join(format!("index-retire-marker-test-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let v = json!({"ino":1234});
        marker(&dir, "proof.json", &v).unwrap();
        marker(&dir, "proof.json", &v).unwrap();
        assert!(marker(&dir, "proof.json", &json!({"ino":4321})).is_err());
        fs::remove_file(dir.join("proof.json")).unwrap();
        fs::remove_dir(dir).unwrap();
    }
}
