//! Synchronous consumer for receiver.py. On publication the native uploader
//! replaces this process, keeping both the receiver's claim and its death signal.
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    env,
    fs::{self, File, OpenOptions},
    io::Write,
    os::{
        fd::{AsRawFd, BorrowedFd},
        unix::{
            fs::{FileExt, MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
const RT: &str = "/var/lib/jetstreamer/horizon_runtime_data";
/// The operator compiles each approved source and reader as one immutable profile.
struct PublicationProfile {
    epoch: u64,
    producer: &'static str,
    producer_iid: &'static str,
    unit: &'static str,
    terminal: &'static str,
    live_sha: &'static str,
    lock: (u64, u64),
    delivery: &'static str,
    reader: &'static str,
    reader_sha: &'static str,
    boundaries: &'static str,
    boundaries_sha: &'static str,
}

#[cfg(all(feature = "cold167", not(feature = "source167")))]
compile_error!("cold167 requires the source167 singleton profile");
#[cfg(all(feature = "cold170", not(feature = "retry170")))]
compile_error!("cold170 requires the retry170 singleton profile");
#[cfg(any(
    feature = "cold168",
    feature = "source167",
    feature = "retry170",
    feature = "full172"
))]
#[cfg_attr(feature = "cold167", path = "cold167_profile.rs")]
#[cfg_attr(feature = "cold168", path = "cold168_profile.rs")]
#[cfg_attr(feature = "cold170", path = "cold170_profile.rs")]
mod peer_profile;

#[cfg(not(any(
    feature = "retry10",
    feature = "metered168",
    feature = "cold168",
    feature = "source167",
    feature = "retry170",
    feature = "full172"
)))]
const PROFILE: PublicationProfile = PublicationProfile {
    epoch: 166,
    producer: "horizon-qualify-independent-cold166-20261120-v1.service",
    producer_iid: "fa16ee2f14fe44ecbc37c59e197553ac",
    unit: "horizon-publish-166-committed.service",
    terminal: "epoch166-terminal-20261121-v1",
    live_sha: "23817cd4c05aee995728b4413ff36c26ef72df5a9795df9691a2d699039d30fe",
    lock: (64512, 93717107),
    delivery: "epoch166-committed-delivery-20261121-v1",
    reader: "producer-publication-inputs-20261121-v1/qualified-reader/qualification.json",
    reader_sha: "edc8d365190a1e2fd6630a3b3905bd7e6d88e776e4a97a5bfbff791fc9242f05",
    boundaries: "producer-publication-inputs-20261121-v1/epoch-expectations/bindings.json",
    boundaries_sha: "c036debc456c8f27907825636c09b1939d3a82f0265bc3179a9eaecfdec0dab0",
};

#[cfg(feature = "retry10")]
#[path = "../horizon_epoch166_retry10_delivery_20261121_v1/generation.rs"]
mod generation;

#[cfg(feature = "retry10")]
const PROFILE: PublicationProfile = PublicationProfile {
    epoch: 166,
    producer: generation::PRODUCER_UNIT,
    producer_iid: generation::PRODUCER_IID,
    unit: "horizon-publish-166-retry10-committed.service",
    terminal: generation::TERMINAL_ROOT,
    live_sha: generation::LIVE_SHA,
    lock: (64512, 93782040),
    delivery: "epoch166-retry10-delivery-20261121-v1",
    reader: "epoch166-retry10-delivery-20261121-v1/qualified-reader/qualification.json",
    reader_sha: env!("HORIZON_READER_QUALIFICATION_SHA256"),
    boundaries: "producer-publication-inputs-20261121-v1/epoch-expectations/bindings.json",
    boundaries_sha: "c036debc456c8f27907825636c09b1939d3a82f0265bc3179a9eaecfdec0dab0",
};
#[cfg(any(
    feature = "cold168",
    feature = "source167",
    feature = "retry170",
    feature = "full172"
))]
const PROFILE: PublicationProfile = PublicationProfile {
    epoch: peer_profile::EPOCH,
    producer: peer_profile::ORIGIN,
    producer_iid: peer_profile::GENERATION,
    unit: peer_profile::UNIT,
    terminal: peer_profile::DELIVERY,
    live_sha: peer_profile::LIVE,
    lock: peer_profile::LOCK,
    delivery: peer_profile::DELIVERY,
    reader: reader_transition::PREVIOUS_PATH,
    reader_sha: reader_transition::PREVIOUS_SHA,
    boundaries: "epoch168-current-delivery-20261121-v1/epoch-expectations/bindings.json",
    boundaries_sha: "b31b09549161b515da4d254662545ed11dbd2b0d33cb9263072485cbd6985488",
};
#[cfg(feature = "metered168")]
const PROFILE: PublicationProfile = PublicationProfile {
    epoch: 168,
    producer: "horizon-qualify-168-full-metered-20261121-v1.service",
    producer_iid: "9cebb1d022124fb08588e93e055d5446",
    unit: "horizon-publish-168-metered-committed.service",
    terminal: "epoch168-current-delivery-20261121-v1",
    live_sha: "11c7cbb269258849d637259fad7a005f3e1255fbeaac99e3239f089495164ac7",
    lock: (64512, 109323419),
    delivery: "epoch168-current-delivery-20261121-v1",
    reader: "epoch166-retry10-delivery-20261121-v1/qualified-reader/qualification.json",
    reader_sha: env!("HORIZON_READER_QUALIFICATION_SHA256"),
    boundaries: "epoch168-current-delivery-20261121-v1/epoch-expectations/bindings.json",
    boundaries_sha: "b31b09549161b515da4d254662545ed11dbd2b0d33cb9263072485cbd6985488",
};
const UPLOADER: &str = "epoch145-publication-20261121-v1/uploader-tools/jetstreamer-r2";
const ELF: &str = "eb448ede557144f04446dbe00a2d2ec7ad88c934a7a227797d0569a15307a904";
const PAIR: &str = "producer-paired-publication-qa-20261121-v1/QUALIFIED.json";
const PAIR_SHA: &str = "4c1bb7a950f2cd9803b2ecc116a3f88d3d8d4ce250057c11e3b046b8dea8d4b6";
const BOUNDED_READER_SHA: &str = "c715952c42ac45b2ebce0a104fee239ff0e5374e18ca2613a569a8f4e91bc36a";
const BOUNDED_PAIR: &str =
    "fast-range-residency-20261121-v1/archive-publication-58709604/ordinary/QUALIFIED.json";
const BOUNDED_PAIR_SHA: &str = "cd357ec5b130887d41961aa7803acb50e833bdbc2dd1f8ebba23252a87b5d3a4";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Handoff {
    epoch: u64,
    directory: PathBuf,
    transaction_id: String,
    sha256: String,
    terminal_sha256: String,
    receipt_sha256: String,
    archive_fd: i32,
    sidecar_fd: i32,
    receipt_fd: i32,
    epoch_lock_fd: i32,
}
struct Authority {
    root: PathBuf,
    live_sha: String,
    lock: (u64, u64),
    run: PathBuf,
}
fn rt(p: &str) -> PathBuf {
    Path::new(RT).join(p)
}
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn small(f: &File, limit: u64) -> Result<Vec<u8>> {
    let n = f.metadata()?.len();
    ensure!(n > 0 && n <= limit, "incorrect bounded file length");
    let mut v = vec![0; usize::try_from(n)?];
    f.read_exact_at(&mut v, 0)?;
    Ok(v)
}
fn regular(p: &Path) -> Result<File> {
    ensure!(
        p.is_absolute() && p.canonicalize()? == p,
        "noncanonical path {}",
        p.display()
    );
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(p)?;
    let m = f.metadata()?;
    let n = fs::symlink_metadata(p)?;
    ensure!(
        m.is_file() && m.nlink() == 1 && (m.dev(), m.ino()) == (n.dev(), n.ino()),
        "file identity changed"
    );
    Ok(f)
}
fn document(p: &Path, digest: &str, private_writable: bool) -> Result<Value> {
    let f = regular(p)?;
    let m = f.metadata()?;
    ensure!(
        m.uid() == 0
            && m.gid() == 0
            && (m.mode() & 0o222 == 0 || private_writable && m.mode() & 0o777 == 0o600),
        "root proof mode or owner"
    );
    let v = small(&f, 4 << 20)?;
    ensure!(
        hex(digest, 64) && sha(&v) == digest,
        "proof digest mismatch {}",
        p.display()
    );
    Ok(serde_json::from_slice(&v)?)
}
fn bound(v: &Value) -> Result<Value> {
    document(
        Path::new(v["path"].as_str().context("proof path")?),
        v["sha256"].as_str().context("proof sha")?,
        false,
    )
}
fn inherited(raw: i32, path: &Path, lease: bool) -> Result<File> {
    ensure!(
        raw >= 3 && unsafe { libc::fcntl(raw, libc::F_GETFD) } == 0,
        "missing inheritable descriptor"
    );
    let f: File = unsafe { BorrowedFd::borrow_raw(raw) }
        .try_clone_to_owned()?
        .into();
    let n = fs::symlink_metadata(path)?;
    let m = f.metadata()?;
    ensure!(
        path.canonicalize()? == path
            && fs::read_link(format!("/proc/self/fd/{raw}"))? == path
            && n.is_file()
            && n.nlink() == 1
            && n.uid() == 1001
            && n.gid() == 1003
            && (m.dev(), m.ino(), m.len()) == (n.dev(), n.ino(), n.len()),
        "source descriptor differs from canonical name"
    );
    ensure!(
        unsafe { libc::fcntl(raw, libc::F_GETFL) } & libc::O_ACCMODE == libc::O_RDONLY,
        "source descriptor grants write access"
    );
    if lease {
        ensure!(
            unsafe { libc::fcntl(raw, libc::F_GETLEASE) } == libc::F_RDLCK,
            "source lease lost"
        );
    }
    Ok(f)
}
fn root_dir(p: &Path) -> Result<()> {
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.canonicalize()? == p
            && m.is_dir()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o777 == 0o700,
        "invalid private publication directory"
    );
    Ok(())
}
fn scope(h: &Handoff, source: &Path, a: &Authority) -> Result<u64> {
    let epoch = PROFILE.epoch;
    ensure!(
        h.epoch == epoch
            && h.directory == source
            && source.canonicalize()? == source
            && hex(&h.transaction_id, 64)
            && hex(&h.sha256, 64),
        "wrong singleton source"
    );
    let mut death = 0;
    ensure!(
        unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &mut death) } == 0 && death == libc::SIGKILL,
        "receiver lifetime not bound"
    );
    ensure!(
        BTreeSet::from([h.archive_fd, h.sidecar_fd, h.receipt_fd, h.epoch_lock_fd]).len() == 4,
        "repeated descriptor"
    );
    root_dir(&a.root)?;
    let live_path = a.root.join("LIVE.json");
    let live = document(
        &live_path,
        &a.live_sha,
        !cfg!(any(
            feature = "cold167",
            feature = "cold168",
            feature = "cold170"
        )),
    )?;
    #[cfg(any(
        feature = "cold168",
        feature = "source167",
        feature = "retry170",
        feature = "full172"
    ))]
    ensure!(
        live["schema"] == peer_profile::LIVE_SCHEMA,
        "wrong singleton live schema"
    );
    let term = document(
        &a.root.join("TERMINAL_SUCCESS.json"),
        &h.terminal_sha256,
        false,
    )?;
    ensure!(
        live["epoch"] == PROFILE.epoch
            && term["schema"] == format!("terminal{epoch}-success-v1")
            && term["epoch"] == PROFILE.epoch
            && live["native"]["manager"]["Id"] == PROFILE.producer
            && live["native"]["manager"]["InvocationID"] == PROFILE.producer_iid
            && term["producer_unit"] == PROFILE.producer
            && term["producer_invocation_id"] == PROFILE.producer_iid
            && term["source_admission"] == live["admission"]
            && term[format!("terminal_{epoch}_disposition")] == "node-published-local-cohort"
            && term["live"] == json!({"path":live_path,"sha256":a.live_sha})
            && term["transaction_id"] == h.transaction_id
            && term["canonical_r2_verified"] == false,
        "wrong original live/terminal authority"
    );
    let manager = &term["manager_terminal"];
    ensure!(
        manager["_PID"] == "1"
            && manager["UNIT"] == PROFILE.producer
            && manager["INVOCATION_ID"] == PROFILE.producer_iid
            && manager["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
            && manager["_BOOT_ID"] == live["boot_id"].as_str().context("boot")?.replace('-', ""),
        "foreign producer termination"
    );
    let batches = Path::new(
        live["private_batch_receipts"]["path"]
            .as_str()
            .context("batch path")?,
    );
    for (path, k) in [(source, "output"), (batches, "private_batch_receipts")] {
        let m = fs::symlink_metadata(path)?;
        ensure!(
            path.canonicalize()? == path
                && m.is_dir()
                && m.uid() == 1001
                && m.gid() == 1003
                && m.mode() & 0o777 == 0o700
                && live[k] == json!({"path":path,"device":m.dev(),"inode":m.ino()}),
            "committed namespace changed"
        );
    }
    let path = source.join(format!("epoch-{epoch}.jet"));
    let archive = inherited(h.archive_fd, &path, true)?;
    let sidecar = inherited(
        h.sidecar_fd,
        &source.join(format!("epoch-{epoch}.jet.sha256")),
        true,
    )?;
    let rp = batches.join(format!("batch-{}.json", h.transaction_id));
    let receipt = inherited(h.receipt_fd, &rp, true)?;
    let lockpath = batches
        .ancestors()
        .nth(3)
        .context("lock scope")?
        .join(format!("locks/epoch-{epoch}.lock"));
    let lock = inherited(h.epoch_lock_fd, &lockpath, false)?;
    let lm = lock.metadata()?;
    ensure!(
        (lm.dev(), lm.ino()) == a.lock && lm.mode() & 0o777 == 0o600,
        "wrong publication lock"
    );
    let parent = unsafe { libc::getppid() }.to_string();
    let locks = fs::read_to_string(format!("/proc/self/fdinfo/{}", h.epoch_lock_fd))?;
    ensure!(
        locks.lines().any(|l| {
            let w: Vec<_> = l.split_whitespace().collect();
            w.len() == 9
                && w[0] == "lock:"
                && w[2..5] == ["FLOCK", "ADVISORY", "WRITE"]
                && w[5] == parent
                && w[7..9] == ["0", "EOF"]
        }),
        "receiver lacks original exclusive claim"
    );
    let m = archive.metadata()?;
    ensure!(
        m.len() > 0
            && term["local_archive"]
                == json!({"path":path,"device":m.dev(),"inode":m.ino(),"size":m.len(),"sha256":h.sha256})
            && term["committed_receipt"] == json!({"path":rp,"sha256":h.receipt_sha256}),
        "terminal archive or batch identity changed"
    );
    ensure!(
        small(&sidecar, 1024)? == format!("{}  epoch-{epoch}.jet\n", h.sha256).as_bytes(),
        "sidecar mismatch"
    );
    let bytes = small(&receipt, 32 << 20)?;
    ensure!(sha(&bytes) == h.receipt_sha256, "batch digest differs");
    let b: Value = serde_json::from_slice(&bytes)?;
    let ms = b["outcome"]["members"]
        .as_array()
        .context("committed members")?;
    ensure!(
        b["schema"] == "jetstreamer-root-cohort-publication-receipt-v2"
            && b["epochs"] == json!([epoch])
            && b["transaction_id"] == h.transaction_id
            && b["manifest_fingerprint"] == live["manifest_fingerprint"]
            && b["outcome"]["kind"] == "committed"
            && ms.len() == 1
            && ms[0]["epoch"] == PROFILE.epoch
            && ms[0]["archive_sha256"] == h.sha256,
        "nonmatching singleton commit"
    );
    for (file, k) in [
        (&archive, "committed_archive"),
        (&sidecar, "committed_checksum"),
    ] {
        let m = file.metadata()?;
        let v = &ms[0][k];
        ensure!(
            v["device"] == m.dev()
                && v["inode"] == m.ino()
                && v["length"] == m.len()
                && v["uid"] == m.uid()
                && v["gid"] == m.gid(),
            "batch member length or identity mismatch"
        );
    }
    Ok(m.len())
}

fn on_home(p: &Path, floor: u64) -> Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    ensure!(
        fs::metadata(p)?.dev() == fs::metadata("/home/sol")?.dev(),
        "scratch is outside HOME filesystem"
    );
    let p = std::ffi::CString::new(p.as_os_str().as_bytes())?;
    let mut raw = std::mem::MaybeUninit::uninit();
    ensure!(
        unsafe { libc::statvfs(p.as_ptr(), raw.as_mut_ptr()) } == 0,
        "cannot measure HOME"
    );
    let s = unsafe { raw.assume_init() };
    let free = s
        .f_bavail
        .checked_mul(s.f_frsize)
        .context("filesystem byte count")?;
    ensure!(
        floor > 0 && free >= floor,
        "admitted HOME floor unavailable"
    );
    Ok(free)
}
fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let parent = path.parent().context("reader plan directory")?;
    let mut pending = tempfile::NamedTempFile::new_in(parent)?;
    pending
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    pending.write_all(data)?;
    pending.as_file().sync_all()?;
    pending.persist_noclobber(path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn admit(
    a: &Authority,
    hash: &str,
    h: &Handoff,
    length: u64,
    iid: &str,
    sync: bool,
) -> Result<u64> {
    root_dir(&a.run)?;
    let v = document(&a.run.join("admission.json"), hash, false)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let recorded = v["recorded_unix_seconds"]
        .as_u64()
        .context("capacity observation time")?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    ensure!(
        v["schema"]
            == format!(
                "horizon-epoch{}-committed-publication-admission-v1",
                PROFILE.epoch
            )
            && v["operation"] == "current-reader-sync-retain-local"
            && (!sync || v["publication_authorized"] == true)
            && v["boot_id"] == boot.trim()
            && v["unit"] == PROFILE.unit
            && v["invocation_id"] == iid
            && v["epoch"] == PROFILE.epoch
            && v["source_directory"] == json!(h.directory)
            && v["transaction_id"] == h.transaction_id
            && v["terminal_sha256"] == h.terminal_sha256
            && v["archive_bytes"] == length
            && v["archive_sha256"] == h.sha256
            && recorded <= now
            && now - recorded <= 180
            && now
                <= v["valid_until_unix_seconds"]
                    .as_u64()
                    .context("admission expiration")?,
        "publication admission differs from this owner, source or clock"
    );
    let observed = bound(&v["capacity"])?;
    let floor = observed["protected_bytes"]
        .as_u64()
        .context("protected HOME floor")?;
    ensure!(
        v["minimum_free_bytes"] == floor
            && observed["observed_unix_seconds"] == recorded
            && observed["invocation_id"] == iid
            && observed["available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= floor)
            && observed["all_existing_commitments_retained"] == true,
        "fresh admission lacks its complete HOME capacity evidence"
    );
    on_home(&a.run, floor)?;
    Ok(floor)
}
#[cfg(any(
    feature = "cold168",
    feature = "source167",
    feature = "retry170",
    feature = "full172",
    feature = "transition_reader"
))]
mod reader_transition;

fn ordinary_pair(qpath: &Path, qualification_sha: &str, _q: &Value) -> Result<Value> {
    #[cfg(any(
        feature = "cold168",
        feature = "source167",
        feature = "retry170",
        feature = "full172",
        feature = "transition_reader"
    ))]
    if qualification_sha == reader_transition::HTTP_RETRY_READER_SHA {
        return reader_transition::http_retry_pair(qpath, _q);
    }
    let paired = if qualification_sha == BOUNDED_READER_SHA {
        let pair = document(&rt(BOUNDED_PAIR), BOUNDED_PAIR_SHA, false)?;
        ensure!(
            pair["reader"] == json!({"path":qpath, "sha256":qualification_sha})
                && pair["uploader"] == json!({"path":rt(UPLOADER), "sha256":ELF})
                && pair["threads"] == 1,
            "qualified archive reader and one-worker uploader pairing changed"
        );
        pair
    } else {
        document(&rt(PAIR), PAIR_SHA, true)?
    };
    ensure!(
        paired["schema"]
            == "horizon-ordinary-uploader-and-current-reader-loopback-qualification-v1"
            && paired["slot_count"] == 432000
            && paired["ordinary_readback_type"] == "HashOnly",
        "ordinary publication proof missing"
    );
    Ok(paired)
}

fn prepare(a: &Authority, len: u64, floor: u64) -> Result<(PathBuf, String)> {
    #[cfg(any(
        feature = "cold168",
        feature = "source167",
        feature = "retry170",
        feature = "full172",
        feature = "transition_reader"
    ))]
    let (qpath, qualification_sha, q) = reader_transition::current()?;
    #[cfg(not(any(
        feature = "cold168",
        feature = "source167",
        feature = "retry170",
        feature = "full172",
        feature = "transition_reader"
    )))]
    let (qpath, qualification_sha, q) = {
        let path = rt(PROFILE.reader);
        let q = document(&path, PROFILE.reader_sha, false)?;
        (path, PROFILE.reader_sha, q)
    };
    let bindings = document(&rt(PROFILE.boundaries), PROFILE.boundaries_sha, false)?;
    let key = PROFILE.epoch.to_string();
    let b = &bindings[&key];
    let e = bound(b)?;
    ensure!(
        e["schema"] == "horizon-current-reader-epoch-expectation-v1"
            && e["epoch"] == PROFILE.epoch
            && q["source_artifact_correspondence_accepted"] == true
            && q["full_and_plugin_capabilities_accepted"] == true,
        "reader proof or independent epoch expectation mismatch"
    );
    let paired = ordinary_pair(&qpath, qualification_sha, &q)?;
    let seal = bound(&paired["uploader_seal"])?;
    ensure!(
        seal["members"]
            .as_array()
            .context("uploader seal")?
            .iter()
            .any(|v| v["name"] == "jetstreamer-r2" && v["sha256"] == ELF),
        "uploader seal changed"
    );
    let scratch = a.run.join("scratch");
    let receipts = a.run.join("receipts");
    for path in [&scratch, &receipts] {
        root_dir(path)?;
        on_home(path, floor)?;
    }
    let plan = json!({
        "schema": "horizon-current-reader-plan-v1",
        "repository": "/home/sol/workspace/jetstreamer",
        "origin_url": "git@github-matt-vaultic:vaultic-win/jetstreamer.git",
        "reader_commit": q["reader_commit"],
        "full_verifier": q["full_verifier"],
        "pipeline": q["pipeline"],
        "qualification": {"path": qpath, "sha256": qualification_sha},
        "scratch_directory": scratch,
        "threads": 1,
        "maximum_archive_bytes": len,
        "minimum_free_bytes": floor,
        "epoch_expectations": {(key): b},
    });
    let data = serde_json::to_vec_pretty(&plan)?;
    let path = a.run.join("current-reader-plan.json");
    let digest = sha(&data);
    if path.try_exists()? {
        ensure!(
            document(&path, &digest, false)? == plan,
            "conflicting existing reader plan"
        );
    } else {
        write_new(&path, &data)?;
    }
    Ok((path, digest))
}
fn arguments(source: &Path, run: &Path, plan: &Path, sha: &str) -> Vec<std::ffi::OsString> {
    let mut v = vec![
        "sync".into(),
        source.as_os_str().to_owned(),
        "--epochs".into(),
        format!("{0}-{0}", PROFILE.epoch).into(),
        "--receipt-directory".into(),
        run.join("receipts").into_os_string(),
        "--current-reader-plan".into(),
        plan.as_os_str().to_owned(),
        "--current-reader-plan-sha256".into(),
        sha.into(),
    ];
    v.extend(["--concurrency", "1", "--part-size-mib", "8"].map(Into::into));
    v
}
fn main() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "receiver consumer runs in root-owned publication unit"
    );
    let args: Vec<String> = env::args().skip(1).collect();
    let [mode, admission_sha, dir] = args.as_slice() else {
        anyhow::bail!("usage: prepare|sync ADMISSION_SHA RECEIVER_SOURCE")
    };
    ensure!(
        mode == "prepare"
            || mode == "sync"
            || (cfg!(publisher_fixture) && mode == "dispatch-fixture"),
        "invalid mode"
    );
    let iid = env::var("INVOCATION_ID")?;
    ensure!(hex(&iid, 32), "native invocation missing");
    #[cfg(not(publisher_fixture))]
    let a = {
        ensure!(
            fs::read_to_string("/proc/self/cgroup")?.trim()
                == format!("0::/system.slice/{}", PROFILE.unit),
            "wrong publication owner"
        );
        Authority {
            root: rt(PROFILE.terminal),
            live_sha: PROFILE.live_sha.into(),
            lock: PROFILE.lock,
            run: rt(PROFILE.delivery).join(format!("run-{iid}")),
        }
    };
    #[cfg(publisher_fixture)]
    let a = {
        ensure!(
            mode == "prepare" || mode == "dispatch-fixture",
            "qualification cannot publish"
        );
        Authority {
            root: env::var("FIXTURE_AUTHORITY")?.into(),
            live_sha: env::var("FIXTURE_LIVE_SHA")?,
            lock: serde_json::from_str(&env::var("FIXTURE_LOCK")?)?,
            run: env::var("FIXTURE_PUBLICATION")?.into(),
        }
    };
    let source = Path::new(dir);
    let h: Handoff = serde_json::from_str(&env::var("HORIZON_SOURCE_HANDOFF")?)?;
    let len = scope(&h, source, &a)?;
    let floor = admit(&a, admission_sha, &h, len, &iid, mode == "sync")?;
    let (plan, digest) = prepare(&a, len, floor)?;
    let argv = arguments(source, &a.run, &plan, &digest);
    let exe = rt(UPLOADER);
    let mut f = regular(&exe)?;
    let m = f.metadata()?;
    ensure!(
        m.uid() == 0 && m.gid() == 0 && m.mode() & 0o777 == 0o555 && m.len() < 128 << 20,
        "unsealed uploader"
    );
    let mut hash = Sha256::new();
    std::io::copy(&mut f, &mut hash)?;
    ensure!(
        format!("{:x}", hash.finalize()) == ELF,
        "uploader executable differs"
    );
    ensure!(
        scope(&h, source, &a)? == len
            && admit(&a, admission_sha, &h, len, &iid, mode == "sync")? == floor,
        "claim or capacity changed before dispatch"
    );
    if mode == "prepare" {
        println!(
            "{}",
            json!({"epoch":PROFILE.epoch,"archive_bytes":len,"transaction":h.transaction_id,"source":source,"plan":plan,"plan_sha256":digest,"uploader":exe,"arguments":argv.iter().map(|x|x.to_string_lossy()).collect::<Vec<_>>(),"r2_mutations":false})
        );
        return Ok(());
    }
    // Replace the receiver's child, preserving its parent-death SIGKILL and
    // all four descriptor claims until the native uploader returns.
    let mut uploader = Command::new(format!("/proc/self/fd/{}", f.as_raw_fd()));
    uploader.args(argv).env_remove("HORIZON_SOURCE_HANDOFF");
    #[cfg(publisher_fixture)]
    {
        // Exercise the real exec boundary without authorizing remote access.
        ensure!(
            mode == "dispatch-fixture"
                && fs::read_link("/proc/self/ns/net")? != fs::read_link("/proc/1/ns/net")?,
            "dispatch fixture requires a private network"
        );
        uploader
            .env("HORIZON_S3_ENDPOINT", "invalid-fixture-endpoint")
            .env_remove("HORIZON_ACCESS_KEY_ID")
            .env_remove("HORIZON_SECRET_ACCESS_KEY");
    }
    Err(uploader.exec().into())
}
