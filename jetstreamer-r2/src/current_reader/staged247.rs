//! Reuse the original authenticated scratch inode only after its owner failed.
//! A fresh ordered R2 stream must equal it byte for byte before plugin playback.
use super::*;
use jetstreamer_horizon_observe::staged247_rss as staged;
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

const UNIT: &str = "horizon-upload-247-singleton-20261119-v1.service";
const IID: &str = "69218e2e0924497ea595a1227a6c31db";
const PREPARATION: &str =
    "/home/ubuntu/.codex/diagnostics/horizon247-staged-recovery-20261120-v1/preparation.json";
const PREP_SHA: &str = "fb6f14b5fedac0aa306e4270f0ca8c65823cb863c1df21bccae82abba98072da";
const INPUT: &str = "/home/ubuntu/.jetstreamer-private/qualification-247-reboot-20261117-v2/output";
const STATE: &str = "/home/ubuntu/.jetstreamer-private/current-reader-delivery-247-20261119-v2";
const SCRATCH: &str = "/home/ubuntu/.jetstreamer-private/current-reader-delivery-247-20261119-v2/playback/epoch-247-1439838-1795133811334956924/readback/epoch-247.jet";
const PLAN: &str =
    "/var/lib/jetstreamer/horizon-reader-delivery247-251-db1c31fe-20261119-v2/epoch-247-plan.json";
const PLAN_SHA: &str = "cea94f810e84239475726eb49ad1bcd24d058ab91e96f10fb01def2fcbc7472d";
const PUBLIC_PLAN: &str =
    "/var/lib/jetstreamer/horizon247-public-reader-6e644028-v1/epoch-247-plan.json";
const PUBLIC_PIPELINE: &str =
    "/var/lib/jetstreamer/horizon247-public-images-6e644028-v1/horizon_pipeline";
const PUBLIC_QUALIFICATION: &str =
    "/var/lib/jetstreamer/horizon247-public-reader-6e644028-v1/main-acceptance.json";
const PUBLIC_READER: &str = "6e644028374dc98f1b25dc82d774b67c3a31c736";
const CURRENT_PLAN: &str =
    "/var/lib/jetstreamer/horizon247-public-reader-680e1173-v1/epoch-247-plan.json";
const CURRENT_PIPELINE: &str =
    "/var/lib/jetstreamer/horizon247-public-images-680e1173-v1/horizon_pipeline";
const CURRENT_VERIFIER: &str =
    "/var/lib/jetstreamer/horizon247-public-images-680e1173-v1/verify_archive";
const CURRENT_QUALIFICATION: &str =
    "/var/lib/jetstreamer/horizon247-public-reader-680e1173-v1/main-acceptance.json";
const CURRENT_READER: &str = "680e1173010ad9a12060b2de98f16ddbf36e8975";
const BENCH_PLAN: &str =
    "/var/lib/jetstreamer/horizon247-public-reader-99f30641-v1/epoch-247-plan.json";
const BENCH_PIPELINE: &str =
    "/var/lib/jetstreamer/horizon247-public-images-99f30641-v1/horizon_pipeline";
const BENCH_VERIFIER: &str =
    "/var/lib/jetstreamer/horizon247-public-images-99f30641-v1/verify_archive";
const BENCH_QUALIFICATION: &str =
    "/var/lib/jetstreamer/horizon247-public-reader-99f30641-v1/main-acceptance.json";
const BENCH_READER: &str = "99f306410aa59a41394e9c4bf379143fb2a4ada1";
const BOUNDED_PLAN: &str =
    "/var/lib/jetstreamer/horizon247-public-reader-cf4d45a5-v1/epoch-247-plan.json";
const BOUNDED_PIPELINE: &str =
    "/var/lib/jetstreamer/horizon247-public-images-cf4d45a5-v1/horizon_pipeline";
const BOUNDED_VERIFIER: &str =
    "/var/lib/jetstreamer/horizon247-public-images-cf4d45a5-v1/verify_archive";
const BOUNDED_QUALIFICATION: &str =
    "/var/lib/jetstreamer/horizon247-public-reader-cf4d45a5-v1/main-acceptance.json";
const BOUNDED_READER: &str = "cf4d45a51820022fa8d2e4f63ca3e8bce261844d";
const PUBLISHED_PLAN: &str =
    "/var/lib/jetstreamer/horizon247-public-reader-fadfe2d4-v1/epoch-247-plan.json";
const PUBLISHED_PIPELINE: &str =
    "/var/lib/jetstreamer/horizon247-public-images-fadfe2d4-v1/horizon_pipeline";
const PUBLISHED_VERIFIER: &str =
    "/var/lib/jetstreamer/horizon247-public-images-fadfe2d4-v1/verify_archive";
const PUBLISHED_QUALIFICATION: &str =
    "/var/lib/jetstreamer/horizon247-public-reader-fadfe2d4-v1/main-acceptance.json";
pub(super) const PUBLISHED_READER: &str = "fadfe2d4a3784ba0f955d1b7a26a15f57ff593e0";
const LIMITED_PLAN: &str =
    "/var/lib/jetstreamer/horizon247-public-reader-58709604-v1/epoch-247-plan.json";
const LIMITED_PIPELINE: &str =
    "/var/lib/jetstreamer/horizon247-public-images-58709604-v1/horizon_pipeline";
const LIMITED_VERIFIER: &str =
    "/var/lib/jetstreamer/horizon247-public-images-58709604-v1/verify_archive";
const LIMITED_QUALIFICATION: &str =
    "/var/lib/jetstreamer/horizon247-public-reader-58709604-v1/main-acceptance.json";
pub(super) const LIMITED_READER: &str = "58709604dfa4c97336c2e1f6fac53b862ed6f17f";
#[path = "staged247_published.rs"]
mod published_owner;
pub(super) fn published_reader(plan: &Plan) -> bool {
    [
        (
            PUBLISHED_READER,
            PUBLISHED_QUALIFICATION,
            PUBLISHED_PIPELINE,
            PUBLISHED_VERIFIER,
        ),
        (
            LIMITED_READER,
            LIMITED_QUALIFICATION,
            LIMITED_PIPELINE,
            LIMITED_VERIFIER,
        ),
    ]
    .iter()
    .any(|(rev, acceptance, pipeline, verifier)| {
        plan.reader_commit == *rev
            && plan.qualification.path == Path::new(acceptance)
            && plan.pipeline.path == Path::new(pipeline)
            && plan.full_verifier.path == Path::new(verifier)
    })
}
pub(super) const BUDGET: u64 = 64 << 20;
const LOG: &str =
    "/home/ubuntu/.codex/diagnostics/horizon247-delivery-admission-20261119-v1/operation.log";
const BUCKET: &str = "solana-archive-with-accounts-data";
const ETAG: &str = "c1be2474b6c9ba8d0ac11405a97ebee3-2688";
const SHA: &str = "0533b69ef3377b59c485893fa1386cc632dd7489da6ec721eeb7dcfeaacd2116";
const LENGTH: u64 = 180370916960;

#[derive(Clone, Debug, PartialEq, Serialize)]
struct Stamp {
    device: u64,
    inode: u64,
    length: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    mtime_ns: i128,
    ctime_ns: i128,
}
impl Stamp {
    fn from(m: &fs::Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            length: m.len(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode() & 0o7777,
            links: m.nlink(),
            mtime_ns: i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec()),
            ctime_ns: i128::from(m.ctime()) * 1_000_000_000 + i128::from(m.ctime_nsec()),
        }
    }
    fn check(&self, path: &Path) -> Result<()> {
        let m = fs::symlink_metadata(path)?;
        ensure!(
            path.canonicalize()? == path && m.is_file() && Self::from(&m) == *self,
            "retained file identity changed: {}",
            path.display()
        );
        Ok(())
    }
}
const COPY: Stamp = Stamp {
    device: 66305,
    inode: 87557157,
    length: LENGTH,
    uid: 0,
    gid: 0,
    mode: 0o400,
    links: 1,
    mtime_ns: 1795175215924973980,
    ctime_ns: 1795175215984974184,
};
const ARCHIVE: Stamp = Stamp {
    device: 66305,
    inode: 508595,
    length: LENGTH,
    uid: 1000,
    gid: 1000,
    mode: 0o440,
    links: 1,
    mtime_ns: 1795100590357758381,
    ctime_ns: 1795104378317034604,
};
const SIDECAR: Stamp = Stamp {
    device: 66305,
    inode: 5021874,
    length: 80,
    uid: 1000,
    gid: 1000,
    mode: 0o440,
    links: 1,
    mtime_ns: 1795104378316642995,
    ctime_ns: 1795104378317479494,
};

fn saved_inputs() -> Result<()> {
    ARCHIVE.check(&Path::new(INPUT).join("epoch-247.jet"))?;
    SIDECAR.check(&Path::new(INPUT).join("epoch-247.jet.sha256"))?;
    COPY.check(Path::new(SCRATCH))?;
    let dir = Path::new(SCRATCH).parent().context("scratch parent")?;
    private_directory(dir)?;
    ensure!(
        fs::read_dir(dir)?.collect::<io::Result<Vec<_>>>()?.len() == 1,
        "unexpected playback sibling"
    );
    Ok(())
}

fn failed<'a>(rows: &'a [Value], unit: &str, iid: &str) -> Result<&'a Value> {
    let failures: Vec<_> = rows
        .iter()
        .filter(|r| r["MESSAGE_ID"] == "d9b373ed55a64feb8242e02dbe79a49c")
        .collect();
    ensure!(
        failures.len() == 1
            && rows
                .iter()
                .all(|r| r["_PID"] == "1" && r["INVOCATION_ID"] == iid && r["UNIT"] == unit)
            && matches!(
                failures[0]["UNIT_RESULT"].as_str(),
                Some(
                    "exit-code"
                        | "signal"
                        | "core-dump"
                        | "timeout"
                        | "oom-kill"
                        | "watchdog"
                        | "resources"
                        | "protocol"
                )
            ),
        "missing exact unsuccessful uploader result for {unit} {iid}"
    );
    Ok(failures[0])
}
fn failed_owner(unit: &str, iid: &str) -> Result<Value> {
    let output = Command::new("/usr/bin/journalctl")
        .args([
            "--quiet",
            "--no-pager",
            "--output=json",
            "--output-fields=_PID,UNIT,INVOCATION_ID,MESSAGE_ID,UNIT_RESULT",
            "--lines=64",
            "_PID=1",
            &format!("UNIT={unit}"),
            &format!("INVOCATION_ID={iid}"),
        ])
        .output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 256 * 1024,
        "systemd result unavailable for {unit}"
    );
    let rows = std::str::from_utf8(&output.stdout)?
        .lines()
        .map(serde_json::from_str)
        .collect::<serde_json::Result<Vec<_>>>()?;
    let result = failed(&rows, unit, iid)?.clone();
    drained(unit, iid)?;
    Ok(result)
}
fn drained(unit: &str, iid: &str) -> Result<()> {
    use std::collections::BTreeMap;
    let s = Command::new("/usr/bin/systemctl")
        .args(["show", unit, "--property=Id,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,NRestarts,Restart,Job"])
        .output()?;
    let state = std::str::from_utf8(&s.stdout)?
        .lines()
        .map(|l| l.split_once('=').context("invalid unit property"))
        .collect::<Result<BTreeMap<_, _>>>()?;
    ensure!(
        state.get("Id") == Some(&unit)
            && matches!(
                (state.get("ActiveState"), state.get("SubState")),
                (Some(&"failed"), Some(&"failed")) | (Some(&"inactive"), Some(&"dead"))
            )
            && (s.status.success()
                || (s.status.code() == Some(4) && state.get("LoadState") == Some(&"not-found")))
            && ["MainPID", "ControlPID", "NRestarts"]
                .iter()
                .all(|k| state.get(k) == Some(&"0"))
            && state.get("Job") == Some(&"")
            && state.get("Restart") == Some(&"no")
            && state
                .get("InvocationID")
                .is_some_and(|value| value.is_empty() || *value == iid),
        "uploader {unit} is not drained"
    );
    let p = Path::new("/sys/fs/cgroup/system.slice")
        .join(unit)
        .join("cgroup.events");
    match fs::read_to_string(&p) {
        Ok(s) => ensure!(
            s.lines().any(|l| l == "populated 0"),
            "uploader cgroup {unit} populated"
        ),
        Err(e) if e.kind() == io::ErrorKind::NotFound => ensure!(
            !p.parent().unwrap().try_exists()?,
            "unreadable uploader cgroup {unit}"
        ),
        Err(e) => return Err(e.into()),
    }
    Ok(())
}
// Both successors follow the same registered staged uploader.
fn requires_staged_terminal(plan: &Path) -> bool {
    [BENCH_PLAN, BOUNDED_PLAN, PUBLISHED_PLAN, LIMITED_PLAN]
        .iter()
        .any(|p| plan == Path::new(p))
}

// Only the qualified public reader and its acceptance change. Keep the exact
// original epoch evidence, retained verifier, repository, policy and disk bounds.
fn public_plan(path: &Path, original: &Value, next: &Value) -> Result<()> {
    let mut expected = original.clone();
    let (commit, files): (_, &[(&str, &str)]) = if path == Path::new(PUBLIC_PLAN) {
        (
            PUBLIC_READER,
            &[
                ("pipeline", PUBLIC_PIPELINE),
                ("qualification", PUBLIC_QUALIFICATION),
            ],
        )
    } else if path == Path::new(CURRENT_PLAN) {
        (
            CURRENT_READER,
            &[
                ("pipeline", CURRENT_PIPELINE),
                ("full_verifier", CURRENT_VERIFIER),
                ("qualification", CURRENT_QUALIFICATION),
            ],
        )
    } else if path == Path::new(BENCH_PLAN) {
        (
            BENCH_READER,
            &[
                ("pipeline", BENCH_PIPELINE),
                ("full_verifier", BENCH_VERIFIER),
                ("qualification", BENCH_QUALIFICATION),
            ],
        )
    } else if path == Path::new(PUBLISHED_PLAN) {
        (
            PUBLISHED_READER,
            &[
                ("pipeline", PUBLISHED_PIPELINE),
                ("full_verifier", PUBLISHED_VERIFIER),
                ("qualification", PUBLISHED_QUALIFICATION),
            ],
        )
    } else if path == Path::new(LIMITED_PLAN) {
        (
            LIMITED_READER,
            &[
                ("pipeline", LIMITED_PIPELINE),
                ("full_verifier", LIMITED_VERIFIER),
                ("qualification", LIMITED_QUALIFICATION),
            ],
        )
    } else {
        ensure!(
            path == Path::new(BOUNDED_PLAN),
            "unregistered epoch 247 recovery plan"
        );
        (
            BOUNDED_READER,
            &[
                ("pipeline", BOUNDED_PIPELINE),
                ("full_verifier", BOUNDED_VERIFIER),
                ("qualification", BOUNDED_QUALIFICATION),
            ],
        )
    };
    for &(field, registered_path) in files {
        let bound: Bound = serde_json::from_value(next[field].clone())?;
        ensure!(
            bound.path == Path::new(registered_path) && hex(&bound.sha256, 64),
            "foreign public {field}"
        );
        expected[field] = serde_json::to_value(bound)?;
    }
    expected["reader_commit"] = json!(commit);
    ensure!(
        next == &expected,
        "epoch 247 public plan changed retained policy or evidence"
    );
    Ok(())
}

pub(crate) fn config(c: &crate::Config) -> Result<()> {
    ensure!(
        c.command == crate::Command::Sync
            && c.epochs == std::collections::BTreeSet::from([247])
            && c.directory == Path::new(INPUT)
            && c.receipt_directory.as_deref() == Some(Path::new(STATE).join("receipts").as_path())
            && c.current_reader_plan.as_deref().is_some_and(|p| [
                PUBLIC_PLAN,
                CURRENT_PLAN,
                BENCH_PLAN,
                BOUNDED_PLAN,
                PUBLISHED_PLAN,
                LIMITED_PLAN
            ]
            .iter()
            .any(|registered| p == Path::new(registered)))
            && c.current_reader_plan_sha256
                .as_deref()
                .is_some_and(|sha| hex(sha, 64))
            && c.concurrency == 2
            && !c.overwrite_existing
            && !c.delete_local
            && !c.repair_orphaned_archive
            && c.legacy_part_size.is_none()
            && c.part_size == crate::DEFAULT_PART_SIZE,
        "invalid epoch 247 staged recovery scope"
    );
    let original = bound_json(&Bound {
        path: PLAN.into(),
        sha256: PLAN_SHA.into(),
    })?;
    let path = c
        .current_reader_plan
        .as_deref()
        .context("missing public plan path")?;
    let next = bound_json(&Bound {
        path: path.into(),
        sha256: c
            .current_reader_plan_sha256
            .clone()
            .context("missing public plan digest")?,
    })?;
    public_plan(path, &original, &next)
}
pub(crate) fn object(bucket: &str, key: &str, remote: Option<&crate::RemoteArchive>) -> Result<()> {
    let r = remote.context("staged 247 object missing")?;
    ensure!(
        bucket == BUCKET
            && key == "epoch-247.jet"
            && r.etag == ETAG
            && r.length == LENGTH
            && r.metadata_sha256.as_deref() == Some(SHA),
        "staged object differs from original authenticated identity"
    );
    Ok(())
}
// These original producer receipts are root-writable (0600). Their sealed
// preparation pins the exact bytes. Recheck the path and descriptor on each read.
fn read_private(path: &Path, limit: u64) -> Result<(Vec<u8>, Stamp)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    let stamp = Stamp::from(&metadata);
    ensure!(
        metadata.is_file()
            && stamp.uid == 0
            && stamp.gid == 0
            && stamp.mode == 0o600
            && stamp.links == 1
            && stamp.length > 0
            && stamp.length <= limit,
        "invalid private evidence file"
    );
    stamp.check(path)?;
    let mut bytes = Vec::new();
    (&file).take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == stamp.length && Stamp::from(&file.metadata()?) == stamp,
        "private evidence changed while reading"
    );
    stamp.check(path)?;
    Ok((bytes, stamp))
}

fn readback_events(raw: &[u8]) -> Result<()> {
    let mut started = false;
    let mut verified = false;
    for line in raw.split(|&b| b == b'\n').filter(|l| l.starts_with(b"{")) {
        let row: Value = serde_json::from_slice(line)?;
        match row["event"].as_str() {
            Some("r2-readback-start") => {
                ensure!(
                    !started
                        && row["key"] == "epoch-247.jet"
                        && row["expected_etag"] == ETAG
                        && row["expected_sha256"] == SHA
                        && row["hashed_bytes"] == 0
                        && row["total_bytes"] == LENGTH
                        && row["whole_file_sha256_verified"] == false,
                    "invalid original readback start"
                );
                started = true;
            }
            Some("r2-readback-verified") => {
                ensure!(
                    started
                        && !verified
                        && row["key"] == "epoch-247.jet"
                        && row["hashed_bytes"] == LENGTH
                        && row["total_bytes"] == LENGTH
                        && row["whole_file_sha256_verified"] == true,
                    "invalid original readback verification"
                );
                verified = true;
            }
            _ => {}
        }
    }
    ensure!(verified, "missing original whole readback");
    Ok(())
}

#[derive(Clone)]
pub(crate) struct Retained {
    complete: Arc<AtomicBool>,
    _lock: Arc<File>,
    log: Stamp,
    log_sha256: String,
    failed_manager_event: Value,
    staged_manager_event: Option<Value>,
    published_manager_event: Option<Value>,
}
impl Retained {
    pub(crate) fn open(plan: &Path) -> Result<Self> {
        use std::os::fd::AsRawFd;
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "private recovery requires root"
        );
        let binding = Bound {
            path: PREPARATION.into(),
            sha256: PREP_SHA.into(),
        };
        let info = bound_json(&binding)?;
        ensure!(
            info["unit"]["InvocationID"] == IID
                && info["unit"]["Id"] == UNIT
                && info["readback_archive"] == SCRATCH
                && info["original_native_log"] == LOG
                && info["original_local_archive"]
                    == Path::new(INPUT).join("epoch-247.jet").to_str().unwrap()
                && info["remote_object_at_fleet_sample"]["archive_etag"] == ETAG
                && info["remote_object_at_fleet_sample"]["archive_metadata_sha256"] == SHA,
            "original 247 provenance differs"
        );
        for k in ["local_acceptance", "local_plugin", "reader_plan"] {
            let b: Bound = serde_json::from_value(info[k].clone())?;
            bound_file(&b)?;
        }
        for k in ["terminal", "drain"] {
            let bound: Bound = serde_json::from_value(info[k].clone())?;
            let (bytes, _) = read_private(&bound.path, 1024 * 1024)?;
            ensure!(
                format!("{:x}", Sha256::digest(&bytes)) == bound.sha256,
                "original {k} digest mismatch"
            );
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(PREPARATION)?;
        ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "concurrent staged 247 recovery"
        );
        let failed_manager_event = failed_owner(UNIT, IID)?;
        let staged_manager_event = if requires_staged_terminal(plan) {
            for (path, sha) in [staged::BOOKING, staged::CLAIM, staged::LAUNCH, staged::PLAN] {
                bound_file(&Bound {
                    path: path.into(),
                    sha256: sha.into(),
                })?;
            }
            Some(failed_owner(staged::UNIT, staged::IID)?)
        } else {
            None
        };
        let published_manager_event = if plan == Path::new(LIMITED_PLAN) {
            Some(published_owner::terminal()?)
        } else {
            None
        };
        saved_inputs()?;
        let (bytes, log) = read_private(Path::new(LOG), 16 << 20)?;
        ensure!(
            log.device == 66305 && log.inode == 14049358,
            "replaced original native log"
        );
        readback_events(&bytes)?;
        Ok(Self {
            log,
            failed_manager_event,
            staged_manager_event,
            published_manager_event,
            log_sha256: format!("{:x}", Sha256::digest(&bytes)),
            complete: Arc::new(AtomicBool::new(false)),
            _lock: Arc::new(file),
        })
    }
    pub(super) fn stream(&self) -> Result<Sink> {
        saved_inputs()?;
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(SCRATCH)?;
        ensure!(
            Stamp::from(&f.metadata()?) == COPY,
            "retained descriptor changed"
        );
        Ok(Sink::Compare {
            file: f,
            bytes: 0,
            owner: Box::new(self.clone()),
        })
    }
    pub(super) fn verify_object(&self, remote: &RemoteObject) -> Result<()> {
        ensure!(
            remote.bucket == BUCKET
                && remote.key == "epoch-247.jet"
                && remote.etag == ETAG
                && remote.sha256 == SHA
                && remote.length == LENGTH,
            "wrong retained playback object"
        );
        Ok(())
    }
    pub(crate) fn proof(&self) -> Result<Value> {
        ensure!(
            self.complete.load(Ordering::Acquire),
            "fresh compared readback missing"
        );
        drained(UNIT, IID)?;
        if self.staged_manager_event.is_some() {
            drained(staged::UNIT, staged::IID)?;
        }
        saved_inputs()?;
        self.log.check(Path::new(LOG))?;
        let mut proof = json!({
            "original_unit": UNIT, "original_invocation_id": IID,
            "original_systemd_failure":self.failed_manager_event,
            "preparation": {"path":PREPARATION, "sha256":PREP_SHA},
            "original_verified_readback_log": {"path":LOG, "sha256":self.log_sha256, "identity":self.log},
            "readback_path":SCRATCH, "readback_identity":COPY,
            "source_identity":ARCHIVE, "source_sidecar_identity":SIDECAR,
            "fresh_authenticated_stream_compared_bytes":LENGTH, "byte_equality_from_zero":true
        });
        if let Some(event) = &self.staged_manager_event {
            proof["prior_staged_uploader"] =
                json!({"unit":staged::UNIT, "invocation_id":staged::IID, "systemd_failure":event});
        }
        if let Some(event) = &self.published_manager_event {
            published_owner::check_drained()?;
            proof["prior_published_uploader"] = event.clone();
        }
        Ok(proof)
    }
}
pub(crate) enum Sink {
    HashOnly,
    Compare {
        file: File,
        bytes: u64,
        owner: Box<Retained>,
    },
}
fn compare<W: Read>(reader: &mut W, mut bytes: &[u8]) -> io::Result<()> {
    let mut buf = [0u8; 16 * 1024];
    while !bytes.is_empty() {
        let n = bytes.len().min(buf.len());
        reader.read_exact(&mut buf[..n])?;
        if bytes[..n] != buf[..n] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "retained R2 readback byte mismatch",
            ));
        }
        bytes = &bytes[n..];
    }
    Ok(())
}
impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::HashOnly => Ok(buf.len()),
            Self::Compare { file, bytes, .. } => {
                let next = bytes
                    .checked_add(buf.len() as u64)
                    .filter(|v| *v <= LENGTH)
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "oversized 247 stream")
                    })?;
                compare(file, buf)?;
                *bytes = next;
                Ok(buf.len())
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::HashOnly | Self::Compare { .. } => Ok(()),
        }
    }
}
fn finish_stream(reader: &mut impl Read, received: u64, expected: u64) -> Result<()> {
    ensure!(
        received == expected && reader.read(&mut [0])? == 0,
        "incomplete retained readback"
    );
    Ok(())
}
impl Sink {
    pub(crate) fn sync_all(&mut self) -> Result<()> {
        match self {
            Self::HashOnly => (),
            Self::Compare { file, bytes, owner } => {
                finish_stream(file, *bytes, LENGTH)?;
                ensure!(
                    Stamp::from(&file.metadata()?) == COPY,
                    "changed retained readback"
                );
                saved_inputs()?;
                owner.complete.store(true, Ordering::Release);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_successor_preserves_original_evidence_and_registered_images() {
        let original = json!({"reader_commit":"old","pipeline":null,"qualification":null,"threads":2,
            "epoch_expectations":{"247":"original"},"full_verifier":"sealed"});
        let mut next = original.clone();
        next["reader_commit"] = json!(PUBLIC_READER);
        next["pipeline"] = json!({"path":PUBLIC_PIPELINE,"sha256":"a".repeat(64)});
        next["qualification"] = json!({"path":PUBLIC_QUALIFICATION,"sha256":"b".repeat(64)});
        public_plan(Path::new(PUBLIC_PLAN), &original, &next).unwrap();
        for path in [
            "/reader_commit",
            "/pipeline/path",
            "/qualification/path",
            "/pipeline/sha256",
            "/qualification/sha256",
            "/threads",
            "/epoch_expectations/247",
            "/full_verifier",
        ] {
            let mut other = next.clone();
            *other.pointer_mut(path).unwrap() = json!("foreign");
            assert!(
                public_plan(Path::new(PUBLIC_PLAN), &original, &other).is_err(),
                "{path}"
            );
        }
        next["unknown"] = json!(1);
        assert!(public_plan(Path::new(PUBLIC_PLAN), &original, &next).is_err());
    }
    #[test]
    fn current_successor_requires_both_rebuilt_readers_and_preserved_layout() {
        let original = json!({"reader_commit":PUBLIC_READER,"threads":2,"epoch_expectations":{"247":"retained"}});
        let mut next = original.clone();
        next["reader_commit"] = json!(CURRENT_READER);
        for (k, path) in [
            ("pipeline", CURRENT_PIPELINE),
            ("qualification", CURRENT_QUALIFICATION),
            ("full_verifier", CURRENT_VERIFIER),
        ] {
            next[k] = json!({"path":path,"sha256":"a".repeat(64)});
        }
        public_plan(Path::new(CURRENT_PLAN), &original, &next).unwrap();
        assert!(public_plan(Path::new(PUBLIC_PLAN), &original, &next).is_err());
        for (pointer, value) in [
            ("/full_verifier/path", json!(PUBLIC_PIPELINE)),
            ("/threads", json!(3)),
            ("/epoch_expectations/247", json!("changed")),
        ] {
            let mut changed = next.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(public_plan(Path::new(CURRENT_PLAN), &original, &changed).is_err());
        }
    }
    #[test]
    fn benchmark_reader_requires_exact_source_images_and_original_epoch_layout() {
        let original = json!({"reader_commit":CURRENT_READER, "threads":2, "epoch_expectations":{"247":"original"}});
        let mut next = original.clone();
        next["reader_commit"] = json!(BENCH_READER);
        for (key, path) in [
            ("pipeline", BENCH_PIPELINE),
            ("full_verifier", BENCH_VERIFIER),
            ("qualification", BENCH_QUALIFICATION),
        ] {
            next[key] = json!({"path":path,"sha256":"a".repeat(64)});
        }
        let path = Path::new(BENCH_PLAN);
        public_plan(path, &original, &next).unwrap();
        assert!(public_plan(Path::new(CURRENT_PLAN), &original, &next).is_err());
        for (pointer, wrong) in [
            ("/pipeline/path", json!(CURRENT_PIPELINE)),
            ("/full_verifier/path", json!(CURRENT_VERIFIER)),
            ("/qualification/path", json!(CURRENT_QUALIFICATION)),
            ("/reader_commit", json!(CURRENT_READER)),
            ("/threads", json!(1)),
            ("/epoch_expectations/247", json!("foreign")),
        ] {
            let mut other = next.clone();
            *other.pointer_mut(pointer).unwrap() = wrong;
            assert!(public_plan(path, &original, &other).is_err());
        }
        next["features"] = json!(["other"]);
        assert!(public_plan(path, &original, &next).is_err());
    }

    #[test]
    fn bounded_reader_pins_images_layout_and_actual_staged_predecessor() {
        let original = json!({"reader_commit":BENCH_READER, "threads":2, "epoch_expectations":{"247":"original"}});
        let mut next = original.clone();
        next["reader_commit"] = json!(BOUNDED_READER);
        for (key, path) in [
            ("pipeline", BOUNDED_PIPELINE),
            ("full_verifier", BOUNDED_VERIFIER),
            ("qualification", BOUNDED_QUALIFICATION),
        ] {
            next[key] = json!({"path":path,"sha256":"a".repeat(64)});
        }
        let path = Path::new(BOUNDED_PLAN);
        assert!(requires_staged_terminal(path));
        assert!(requires_staged_terminal(Path::new(BENCH_PLAN)));
        assert!(!requires_staged_terminal(Path::new(CURRENT_PLAN)));
        public_plan(path, &original, &next).unwrap();
        assert!(public_plan(Path::new(BENCH_PLAN), &original, &next).is_err());
        for (pointer, wrong) in [
            ("/pipeline/path", json!(BENCH_PIPELINE)),
            ("/full_verifier/path", json!(BENCH_VERIFIER)),
            ("/qualification/path", json!(BENCH_QUALIFICATION)),
            ("/reader_commit", json!(BENCH_READER)),
            ("/threads", json!(1)),
            ("/epoch_expectations/247", json!("foreign")),
        ] {
            let mut other = next.clone();
            *other.pointer_mut(pointer).unwrap() = wrong;
            assert!(public_plan(path, &original, &other).is_err());
        }
        next["features"] = json!(["other"]);
        assert!(public_plan(path, &original, &next).is_err());
    }

    #[test]
    fn published_reader_pins_images_layout_and_actual_staged_predecessor() {
        let original = json!({"reader_commit":BENCH_READER, "threads":2, "epoch_expectations":{"247":"original"}});
        let mut next = original.clone();
        next["reader_commit"] = json!(PUBLISHED_READER);
        for (key, path) in [
            ("pipeline", PUBLISHED_PIPELINE),
            ("full_verifier", PUBLISHED_VERIFIER),
            ("qualification", PUBLISHED_QUALIFICATION),
        ] {
            next[key] = json!({"path":path,"sha256":"a".repeat(64)});
        }
        let path = Path::new(PUBLISHED_PLAN);
        assert!(requires_staged_terminal(path));
        assert!(requires_staged_terminal(Path::new(BENCH_PLAN)));
        assert!(!requires_staged_terminal(Path::new(CURRENT_PLAN)));
        public_plan(path, &original, &next).unwrap();
        assert!(public_plan(Path::new(BENCH_PLAN), &original, &next).is_err());
        for (pointer, wrong) in [
            ("/pipeline/path", json!(BENCH_PIPELINE)),
            ("/full_verifier/path", json!(BENCH_VERIFIER)),
            ("/qualification/path", json!(BENCH_QUALIFICATION)),
            ("/reader_commit", json!(BENCH_READER)),
            ("/threads", json!(1)),
            ("/epoch_expectations/247", json!("foreign")),
        ] {
            let mut other = next.clone();
            *other.pointer_mut(pointer).unwrap() = wrong;
            assert!(public_plan(path, &original, &other).is_err());
        }
        next["features"] = json!(["other"]);
        assert!(public_plan(path, &original, &next).is_err());
    }

    #[test]
    fn limited_reader_preserves_the_original_two_worker_layout_and_predecessor() {
        let original = json!({"reader_commit":BENCH_READER, "threads":2, "epoch_expectations":{"247":"original"}});
        let mut next = original.clone();
        next["reader_commit"] = json!(LIMITED_READER);
        for (key, path) in [
            ("pipeline", LIMITED_PIPELINE),
            ("full_verifier", LIMITED_VERIFIER),
            ("qualification", LIMITED_QUALIFICATION),
        ] {
            next[key] = json!({"path":path,"sha256":"a".repeat(64)});
        }
        let path = Path::new(LIMITED_PLAN);
        assert!(requires_staged_terminal(path));
        assert!(requires_staged_terminal(Path::new(BENCH_PLAN)));
        assert!(!requires_staged_terminal(Path::new(CURRENT_PLAN)));
        public_plan(path, &original, &next).unwrap();
        assert!(public_plan(Path::new(BENCH_PLAN), &original, &next).is_err());
        for (pointer, wrong) in [
            ("/pipeline/path", json!(BENCH_PIPELINE)),
            ("/full_verifier/path", json!(BENCH_VERIFIER)),
            ("/qualification/path", json!(BENCH_QUALIFICATION)),
            ("/reader_commit", json!(BENCH_READER)),
            ("/threads", json!(1)),
            ("/epoch_expectations/247", json!("foreign")),
        ] {
            let mut other = next.clone();
            *other.pointer_mut(pointer).unwrap() = wrong;
            assert!(public_plan(path, &original, &other).is_err());
        }
        next["features"] = json!(["other"]);
        assert!(public_plan(path, &original, &next).is_err());
    }

    #[test]
    fn staged_failure_requires_its_own_unsuccessful_manager_invocation() {
        let row = json!({"_PID":"1","UNIT":staged::UNIT,"INVOCATION_ID":staged::IID,"MESSAGE_ID":"d9b373ed55a64feb8242e02dbe79a49c","UNIT_RESULT":"exit-code"});
        let rows = std::slice::from_ref(&row);
        failed(rows, staged::UNIT, staged::IID).unwrap();
        assert!(failed(rows, UNIT, IID).is_err());
        assert!(failed(rows, staged::UNIT, IID).is_err());
        for (key, value) in [("UNIT_RESULT", "success"), ("MESSAGE_ID", "started")] {
            let mut other = row.clone();
            other[key] = json!(value);
            assert!(failed(&[other], staged::UNIT, staged::IID).is_err());
        }
    }
    #[test]
    fn staged_remote_identity_requires_the_recorded_key_bucket_digest_length_and_etag() {
        let r = crate::RemoteArchive {
            length: LENGTH,
            etag: ETAG.into(),
            metadata_sha256: Some(SHA.into()),
            composite_sha256: None,
            checksum_type: None,
            multipart_part_size: Some(crate::DEFAULT_PART_SIZE),
        };
        object(BUCKET, "epoch-247.jet", Some(&r)).unwrap();
        assert!(object(BUCKET, "epoch-247.jet", None).is_err());
        assert!(object("foreign", "epoch-247.jet", Some(&r)).is_err());
        assert!(object(BUCKET, "epoch-248.jet", Some(&r)).is_err());
        let mut wrong = r;
        wrong.length -= 1;
        assert!(object(BUCKET, "epoch-247.jet", Some(&wrong)).is_err());
        wrong.length = LENGTH;
        wrong.etag = "changed".into();
        assert!(object(BUCKET, "epoch-247.jet", Some(&wrong)).is_err());
        wrong.etag = ETAG.into();
        wrong.metadata_sha256 = None;
        assert!(object(BUCKET, "epoch-247.jet", Some(&wrong)).is_err());
    }
    #[test]
    fn failed_result_rejects_live_successful_reused_and_ambiguous_invocations() {
        let r = json!({"_PID":"1","UNIT":UNIT,"INVOCATION_ID":IID,"MESSAGE_ID":"d9b373ed55a64feb8242e02dbe79a49c","UNIT_RESULT":"exit-code"});
        failed(std::slice::from_ref(&r), UNIT, IID).unwrap();
        assert!(failed(&[], UNIT, IID).is_err());
        assert!(failed(&[r.clone(), r.clone()], UNIT, IID).is_err());
        for (k, v) in [
            ("_PID", "4"),
            ("UNIT", "other.service"),
            ("INVOCATION_ID", "different"),
            ("UNIT_RESULT", "success"),
            ("MESSAGE_ID", "started"),
        ] {
            let mut bad = r.clone();
            bad[k] = json!(v);
            assert!(failed(&[bad], UNIT, IID).is_err());
        }
    }
    #[test]
    fn comparison_requires_exact_order_and_fails_on_short_or_different_retained_bytes() {
        let original = (0..50000).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        let mut reader = io::Cursor::new(&original);
        for part in original.chunks(827) {
            compare(&mut reader, part).unwrap();
        }
        assert_eq!(reader.position(), original.len() as u64);
        let mut bad = original.clone();
        bad[39999] ^= 1;
        assert!(compare(&mut io::Cursor::new(&original), &bad).is_err());
        assert!(compare(&mut io::Cursor::new(&original[..49000]), &original).is_err());
        assert!(compare(&mut io::Cursor::new(&original), &original[827..]).is_err());
    }
    #[test]
    fn final_comparison_requires_declared_length_and_eof() {
        assert!(finish_stream(&mut io::empty(), 5, 5).is_ok());
        assert!(finish_stream(&mut io::empty(), 4, 5).is_err());
        assert!(finish_stream(&mut io::Cursor::new([0]), 5, 5).is_err());
    }
    #[test]
    fn historical_readback_requires_exact_start_and_completed_hash_in_order() {
        let start = json!({"event":"r2-readback-start","key":"epoch-247.jet","expected_etag":ETAG,
            "expected_sha256":SHA,"hashed_bytes":0,"total_bytes":LENGTH,"whole_file_sha256_verified":false});
        let end = json!({"event":"r2-readback-verified","key":"epoch-247.jet","hashed_bytes":LENGTH,
            "total_bytes":LENGTH,"whole_file_sha256_verified":true});
        assert!(readback_events(format!("{start}\n{end}").as_bytes()).is_ok());
        for text in [
            start.to_string(),
            end.to_string(),
            format!("{end}\n{start}"),
            format!("{start}\n{end}\n{end}"),
            format!("{start}\n{end}").replace(ETAG, "changed"),
            format!("{start}\n{end}").replace(&LENGTH.to_string(), "8192"),
        ] {
            assert!(readback_events(text.as_bytes()).is_err());
        }
    }
    #[test]
    fn stamped_inode_rejects_alias_permission_mutation_and_replacement() -> Result<()> {
        let d = tempfile::tempdir()?;
        let p = d.path().join("body");
        fs::write(&p, b"archive")?;
        let stamp = Stamp::from(&fs::symlink_metadata(&p)?);
        stamp.check(&p)?;
        fs::hard_link(&p, d.path().join("alias"))?;
        assert!(stamp.check(&p).is_err());
        fs::remove_file(d.path().join("alias"))?;
        let current = Stamp::from(&fs::symlink_metadata(&p)?);
        fs::set_permissions(&p, fs::Permissions::from_mode(0o400))?;
        assert!(current.check(&p).is_err());
        fs::rename(&p, d.path().join("retained"))?;
        fs::write(&p, b"archive")?;
        assert!(stamp.check(&p).is_err());
        Ok(())
    }
}
