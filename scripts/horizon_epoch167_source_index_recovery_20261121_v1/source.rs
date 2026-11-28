use super::*;
pub const BASE: &str = "epoch167-source-index-recovery-20261121-v1";
pub const PKG: &str = "epoch167-local-index-successor-20261121-v1";
pub const PROFILE: &str = "b161542cd001c85245e115204698650ad0adf9de598f54b957f95f761b54d938";
pub const UNIT: &str = "horizon-qualify-167-source-index-v1-20261121.service";
pub const TIMER: &str = "horizon-guard-167-source-index-v1-20261121.timer";
pub const LANE: &str = "/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1";
pub const ATTEMPT: &str = "replacement-source-index-v1-20261121";
pub const INPUTS: &str = "/usr/local/lib/jetstreamer/horizon-standard-local-input167-20261110-v1";
pub const SOURCE: &str = "snapshot-72143703-CJEQdfn6zGqx4da6wL7CqgDhNAEij9tCPz7CrY9ZWH1a.tar.zst";
pub const OLD: &str = "epoch167-retry8-recovery-20261120-v1";

pub const EPOCH: u64 = 167;
pub const CAP: u64 = 512 << 30;
pub const PREVIOUS_GUARD_ARGV: &str =
    "4fbff52bb7cf7f7443cd7466289494b23c1b32c8c433e6ecf196356f6f8fc76f";
pub fn node() -> PathBuf {
    rt(PKG).join("deployment/jetstreamer-node")
}
pub fn worker_image() -> PathBuf {
    rt(PKG).join("deployment/jetstreamer-historical-worker-v1-5-6")
}
pub fn node_arg() -> String {
    "/usr/local/lib/jetstreamer/horizon-independent167-singleton-package-20261109-v1/jetstreamer-node".into()
}

pub fn profile() -> Result<Value> {
    Ok(doc(&rt(PKG).join("successor-profile.json"), Some(PROFILE))?.0)
}

pub fn files() -> Result<Value> {
    let p = profile()?;
    ensure!(
        p["fresh_attempt"] == json!(run())
            && p["guard_worker_root"] == LANE
            && p["producer_unit"] == UNIT
            && p["guard_timer"] == TIMER,
        "different successor profile"
    );
    let stable =
        rt("epoch168-full-metered-20261121-v1/STABLE_167_168_ROOTS_BEFORE_DATA_WITNESS.json");
    let (roots, rr) = doc(
        &stable,
        Some("57d99faeaed6817dc1afc29dec368039ae4cb4f1cbad28df2075b894d397321d"),
    )?;
    let root = run();
    let m = fs::symlink_metadata(&root)?;
    let id = &roots["normal167"][0];
    ensure!(
        id["path"] == json!(root)
            && id["inode"] == m.ino()
            && id["device"] == m.dev()
            && root.canonicalize()? == root
            && m.uid() == 1001
            && m.gid() == 1003
            && m.mode() & 0o7777 == 0o700,
        "precreated root changed"
    );
    let g = rt(OLD).join("preparation/epoch167/local3retry8/guard-state/receipts");
    let (stopped, sr) = doc(
        &g.join("stop-completion.json"),
        Some("dd49198b1e1e159326a85791257b8b46b4623b404264daab3dda2f31d26df5f9"),
    )?;
    let (trip, tr) = doc(
        &g.join("sample-0bc5f960281f4c5782a30f91c8e4af35.json"),
        Some("1059dfcf081918da05c70bbb351e401ee12525123510d051f88b6d99a03488bb"),
    )?;
    ensure!(
        stopped["producer_invocation_id"] == "93e60160c9164d3781a5b544fc2a48b4"
            && stopped["scratch_deleted"] == false
            && trip["trip_reason"] == "DATA-fulfillment-observation-failed",
        "different 167 stop"
    );
    let old = "horizon-qualify-167-replacement-local3retry8-20261110-v1.service";
    let mgr = native(old)?;
    ensure!(
        mgr["MainPID"] == "0"
            && mgr["Job"] == ""
            && members(old)?.is_empty()
            && mgr["ActiveState"] == "inactive",
        "old producer still present"
    );
    let snapshot = Path::new(INPUTS).join(SOURCE);
    let snap = fs::symlink_metadata(&snapshot)?;
    ensure!(
        snap.is_file()
            && snap.uid() == 0
            && snap.mode() & 0o222 == 0
            && snapshot.canonicalize()? == snapshot
            && snap.len() == 2_022_614_652,
        "untrusted original snapshot"
    );
    Ok(
        json!({"predecessor_stop":sr,"predecessor_sample":tr,"stable_roots":rr,"root":id,
        "snapshot":{"path":snapshot,"device":snap.dev(),"inode":snap.ino(),"length":snap.len(),"ctime":[snap.ctime(),snap.ctime_nsec()],"sha256":p["source_snapshot_sha256"],"generation":p["source_snapshot_generation"]}}),
    )
}

fn owned_directory(path: &Path) -> Result<()> {
    if !path.try_exists()? {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        std::os::unix::fs::chown(path, Some(1001), Some(1003))?;
        File::open(path.parent().context("directory parent")?)?.sync_all()?;
    }
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && m.is_dir()
            && m.uid() == 1001
            && m.gid() == 1003
            && m.mode() & 0o7777 == 0o700,
        "foreign staging directory"
    );
    Ok(())
}
pub fn prepare() -> Result<Value> {
    let receipt = base().join("PREPARED.json");
    let baseline = files()?;
    if receipt.try_exists()? {
        let (v, b) = doc(&receipt, None)?;
        ensure!(v["baseline"] == baseline, "staging witness changed");
        return Ok(b);
    }
    ensure!(
        native(UNIT)?["LoadState"] == "not-found" && members(UNIT)?.is_empty(),
        "successor already active"
    );
    let p = profile()?;
    for entry in p["bindings"].as_array().context("profile bindings")? {
        ensure!(
            file_digest(Path::new(st(entry, "path")?))? == st(entry, "sha256")?,
            "unqualified profile member"
        );
    }
    let snap = Path::new(INPUTS).join(SOURCE);
    ensure!(
        file_digest(&snap)? == p["source_snapshot_sha256"],
        "original snapshot hash"
    );
    let original = rt(PKG).join("successor-mounted-profile-result.json");
    let (test, qa) = doc(
        &original,
        Some("d595abdbde8bd81231ece97e9b85d66b0d6ca577cbcd41b9095ee0a4f216d216"),
    )?;
    ensure!(
        test["production_profile_sha256"] == PROFILE,
        "different normal native QA"
    );
    for child in ["output", "private", "config"] {
        owned_directory(&run().join(child))?
    }
    let output = run().join("output/genesis.tar.bz2");
    if !output.try_exists()? {
        let data = raw(&Path::new(INPUTS).join("genesis.tar.bz2"), 1 << 20)?;
        let mut f = tempfile::NamedTempFile::new_in(run().join("output"))?;
        f.write_all(&data)?;
        f.as_file()
            .set_permissions(fs::Permissions::from_mode(0o444))?;
        f.as_file().sync_all()?;
        f.persist_noclobber(&output)?;
        File::open(output.parent().unwrap())?.sync_all()?;
    }
    ensure!(
        file_digest(&output)? == "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
        "staged genesis"
    );
    let log = run().join("producer.log");
    if !log.try_exists()? {
        let f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&log)?;
        std::os::unix::fs::fchown(&f, Some(1001), Some(1003))?;
        f.sync_all()?;
        File::open(run())?.sync_all()?;
    }
    let m = fs::symlink_metadata(&log)?;
    ensure!(
        m.is_file() && m.uid() == 1001 && m.nlink() == 1 && m.len() == 0,
        "already used producer log"
    );
    ensure!(baseline == files()?, "inputs changed during validation");
    record(
        "PREPARED.json",
        &json!({"schema":"horizon-167-index-source-preparation-v1","epoch":167,"baseline":baseline,"profile":PROFILE,"native_profile_qualification":qa,"replay_launch_authorized":false}),
    )
}

pub fn prepare_log() -> Result<Value> {
    let (_, prep) = doc(&base().join("PREPARED.json"), None)?;
    let p = run().join("producer.log");
    ensure!(
        native(UNIT)?["LoadState"] == "not-found"
            && members(UNIT)?.is_empty()
            && !base().join("START_INTENT.json").try_exists()?
            && p.canonicalize()? == p,
        "new producer log occupied"
    );
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && (m.dev(), m.ino(), m.nlink(), m.len(), m.mode() & 0o7777)
                == (64512, 107675655, 1, 0, 0o600)
            && [(1001, 1003), (0, 0)].contains(&(m.uid(), m.gid())),
        "unexpected new empty log"
    );
    ensure!(
        unsafe { libc::fcntl(f.as_raw_fd(), libc::F_SETLEASE, libc::F_WRLCK) } == 0,
        "new log already opened"
    );
    std::os::unix::fs::fchown(&f, Some(0), Some(0))?;
    f.sync_all()?;
    ensure!(
        unsafe { libc::fcntl(f.as_raw_fd(), libc::F_SETLEASE, libc::F_UNLCK) } == 0,
        "log lease"
    );
    ensure!(
        same(
            &p,
            &Path::new("/proc/self/fd").join(f.as_raw_fd().to_string())
        )?,
        "log pathname replaced"
    );
    let proof = json!({"schema":"horizon-167-observer-append-file-before-launch-v1","prepared":prep,"path":p,"device":m.dev(),"inode":m.ino(),"uid":0,"gid":0,"mode":384,"initial_bytes":0});
    if base().join("OBSERVER_LOG.json").try_exists()? {
        let (v, b) = doc(&base().join("OBSERVER_LOG.json"), None)?;
        ensure!(v == proof, "foreign observer anchor");
        return Ok(b);
    }
    record("OBSERVER_LOG.json", &proof)
}
pub fn ready() -> Result<Value> {
    let (v, b) = doc(&base().join("PREPARED.json"), None)?;
    ensure!(
        v["baseline"] == files()?
            && !base()
                .join("ACTUAL_ADMISSION_AND_PROTECTION.json")
                .try_exists()?,
        "prepared source changed"
    );
    let output = run().join("output");
    ensure!(
        fs::read_dir(&output)?.count() == 1
            && file_digest(&output.join("genesis.tar.bz2"))?
                == "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945"
            && fs::read_dir(run().join("private"))?.next().is_none(),
        "occupied successor inputs"
    );
    let log = fs::symlink_metadata(run().join("producer.log"))?;
    ensure!(
        log.is_file() && log.uid() == 0 && log.gid() == 0 && log.nlink() == 1 && log.len() == 0,
        "changed staged append log"
    );
    let (o, _) = doc(&base().join("OBSERVER_LOG.json"), None)?;
    ensure!(
        o["inode"] == log.ino() && o["device"] == log.dev() && o["prepared"] == b,
        "observer log anchor changed"
    );
    Ok(b)
}
pub fn index_selected() -> Result<()> {
    let p = run().join("producer.log");
    let mut f = File::open(&p)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && same(
                &p,
                &Path::new("/proc/self/fd").join(f.as_raw_fd().to_string())
            )?,
        "different 167 log"
    );
    let mut b = Vec::new();
    (&mut f).take(512 << 10).read_to_end(&mut b)?;
    ensure!(String::from_utf8_lossy(&b).contains("Using digest-pinned local slot-ranges index for epoch 167: /home/sol/.jetstreamer-private/public-method-20261120/167-source-index/qualified-v1/epoch-167-slot-ranges.raw"),"native 167 source selection absent");
    Ok(())
}
