//! Positive terminal evidence for the three original peers whose natural ends
//! can intersect a long read-only 145 verification.
use super::*;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    io::{Read, Seek, SeekFrom},
};

const HISTORY: &str = "root084959-live166167170-20261121-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json";
const HISTORY_SHA: &str = "350020d2dcef311ec3a469250273b8a8bc79286d8bf4b96a6c2db8f7c994ee57";
const NATIVE: &str = "epoch166-receiver-20261121-v1/receiver-v1/native";
const NATIVE_SHA: &str = "dea7acbfa01d0beae046549823ebce48e7086a7276349b4530ed35c04a2d4efb";
const GROUPS: [&str; 3] = [
    "actual_executing_replays",
    "actual_active_bootstraps",
    "actual_active_private_diagnostics",
];
pub struct Peer {
    pub epoch: u64,
    pub unit: &'static str,
    pub iid: &'static str,
    processes: [(u32, u64); 2],
    lane: &'static str,
    log_inode: u64,
    destination: &'static str,
    archive_dir: u64,
    receipt_dir: u64,
    fingerprint: &'static str,
}
pub const PEERS: [Peer; 3] = [
    Peer {
        epoch: 167,
        unit: "horizon-qualify-167-replacement-local3retry8-20261110-v1.service",
        iid: "93e60160c9164d3781a5b544fc2a48b4",
        processes: [(2472615, 349632179), (2472715, 349633725)],
        lane: "epoch167-standard-lane-20261109-v1/replacement-local3retry8-20261110-v1",
        log_inode: 107692718,
        destination: "destination-45a8a8957b3398c11ec7a9a954433f05790fbeb013a4aa14f0460bcc38d890dd",
        archive_dir: 107692716,
        receipt_dir: 107692731,
        fingerprint: "3f28743306031e8a407f6f9302224101f05c70ac6db496e194c9dbc6b71c249b",
    },
    Peer {
        epoch: 169,
        unit: "horizon-qualify-169-focused-20261120-v4.service",
        iid: "0dfa0d36fbc246c28443a1c90a82c9cb",
        processes: [(3031007, 353303886), (3031352, 353306046)],
        lane: "epoch169-focused-diagnostic-20261117-v1/attempt-g4",
        log_inode: 114704379,
        destination: "",
        archive_dir: 0,
        receipt_dir: 0,
        fingerprint: "",
    },
    Peer {
        epoch: 170,
        unit: "horizon-qualify-170-replacement-local3retry9-20261110-v1.service",
        iid: "8d120ed88adc4afb9485fb3f61dfa29c",
        processes: [(2619210, 350635451), (2619350, 350637076)],
        lane: "epoch170-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/replacement-local3retry9-20261110-v1",
        log_inode: 112725412,
        destination: "destination-c018e39a6bd8cb4276f96c2b2a053258ef7fc7cb9aba1ed2517da203600a90f8",
        archive_dir: 112725202,
        receipt_dir: 112726001,
        fingerprint: "a18e763167b4cd47833f89627209ea7b5e08e55de16152df612e2c0d9be05890",
    },
];
#[derive(Debug)]
pub struct Pending(pub u64);
impl std::fmt::Display for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "original epoch {} is crossing its authenticated native owner boundary",
            self.0
        )
    }
}
impl std::error::Error for Pending {}
#[derive(Default)]
pub struct Transitions {
    closed: RefCell<BTreeMap<u64, Value>>,
    read_only: bool,
}
pub fn rows(fleet: &Value) -> Result<impl Iterator<Item = &Value>> {
    let mut rows = Vec::new();
    for key in GROUPS {
        rows.extend(
            fleet[key]
                .as_array()
                .context("missing native roster group")?,
        );
    }
    Ok(rows.into_iter())
}
fn original_processes(p: &Peer) -> [bool; 2] {
    p.processes
        .map(|(pid, start)| native::ticks(pid).ok() == Some(start))
}
fn marker(log: &str, p: &Peer, dir: &Path) -> Result<(String, PathBuf)> {
    let prefix = format!(
        "root-checkpoint cohort {0}-{0} published 1 archive(s) with checksums in transaction ",
        p.epoch
    );
    let mut entries = log
        .lines()
        .filter_map(|line| line.split_once(&prefix).map(|(_, v)| v));
    let entry = entries
        .next()
        .context("missing original local singleton commit")?;
    ensure!(
        entries.next().is_none(),
        "more than one original singleton commit"
    );
    let (tx, rest) = entry
        .split_once("; receipt ")
        .context("malformed original commit message")?;
    let path = dir.join(format!("batch-{tx}.json"));
    ensure!(
        custody::hex(tx, 64) && rest.strip_suffix(" is durable") == path.to_str(),
        "foreign original batch path"
    );
    Ok((tx.into(), path))
}
fn committed(p: &Peer) -> Result<Value> {
    let lane = Path::new("/home/sol/.jetstreamer-private").join(p.lane);
    let output = lane.join("output");
    let batches = lane
        .join("private")
        .join(p.destination)
        .join("evidence/archive-batches")
        .join(format!("destination-{:016x}-{:016x}", 64512, p.archive_dir));
    for (path, ino) in [(&output, p.archive_dir), (&batches, p.receipt_dir)] {
        let m = fs::symlink_metadata(path)?;
        ensure!(
            path.canonicalize()? == *path
                && m.is_dir()
                && (m.dev(), m.ino(), m.uid(), m.gid(), m.mode() & 0o777)
                    == (64512, ino, 1001, 1003, 0o700),
            "original singleton namespace changed"
        );
    }
    let path = lane.join("producer.log");
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)?;
    let m = f.metadata()?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && m.nlink() == 1
            && (m.dev(), m.ino(), m.uid(), m.gid(), m.mode() & 0o777)
                == (64512, p.log_inode, 0, 0, 0o600),
        "original producer log changed"
    );
    f.seek(SeekFrom::Start(m.len().saturating_sub(256 << 10)))?;
    let mut tail = Vec::new();
    f.take(256 << 10).read_to_end(&mut tail)?;
    let (tx, receipt) = marker(&String::from_utf8_lossy(&tail), p, &batches)?;
    for path in [
        &receipt,
        &output.join(format!("epoch-{}.jet", p.epoch)),
        &output.join(format!("epoch-{}.jet.sha256", p.epoch)),
    ] {
        let m = fs::symlink_metadata(path)?;
        ensure!(
            path.canonicalize()? == *path
                && m.is_file()
                && m.nlink() == 1
                && m.dev() == 64512
                && m.uid() == 1001
                && m.gid() == 1003,
            "original committed member was replaced"
        );
    }
    let helper = Path::new(RUNTIME).join(NATIVE);
    let id = custody::frozen_identity(&helper)?;
    let program = File::open(&helper)?;
    ensure!(
        custody::identity(&program.metadata()?) == id && id.mode & 0o777 == 0o555,
        "native committed reader changed"
    );
    let mut hasher = sha2::Sha256::new();
    std::io::copy(&mut &program, &mut hasher)?;
    ensure!(
        format!("{:x}", hasher.finalize()) == NATIVE_SHA,
        "native committed reader digest"
    );
    let result = native_commit(
        &program,
        p.epoch,
        &tx,
        &receipt,
        p.fingerprint,
        &output,
        Path::new("/home/sol/horizon"),
    )?;
    Ok(
        json!({"committed":result,"receipt":receipt,"root_log_inode":p.log_inode,"native_sha256":NATIVE_SHA}),
    )
}
fn native_commit(
    program: &File,
    epoch: u64,
    tx: &str,
    receipt: &Path,
    fingerprint: &str,
    output: &Path,
    distinct: &Path,
) -> Result<Value> {
    let checked = Command::new(format!("/proc/self/fd/{}", program.as_raw_fd()))
        .uid(1001)
        .gid(1003)
        .env_clear()
        .args([
            "admit",
            &epoch.to_string(),
            receipt.to_str().context("receipt path")?,
            fingerprint,
            distinct.to_str().context("distinct target")?,
        ])
        .output()?;
    ensure!(
        checked.status.success(),
        "original owner cohort validation failed: {}",
        String::from_utf8_lossy(&checked.stderr)
    );
    let result: Value = serde_json::from_slice(&checked.stdout)?;
    ensure!(
        result["transaction"] == tx
            && result["source"] == json!(output)
            && result["uid"] == 1001
            && result["archive"] == json!(output.join(format!("epoch-{}.jet", epoch)))
            && result["sidecar"] == json!(output.join(format!("epoch-{}.jet.sha256", epoch)))
            && result["sha256"]
                .as_str()
                .is_some_and(|s| custody::hex(s, 64)),
        "cohort proof is for a different singleton"
    );
    Ok(result)
}
fn original(p: &Peer) -> Result<(Value, Bound, Value)> {
    let history: Value = serde_json::from_slice(&custody::bytes(
        &Bound {
            path: Path::new(RUNTIME).join(HISTORY),
            sha256: HISTORY_SHA.into(),
        },
        32 << 20,
        false,
    )?)?;
    let old = rows(&history)?
        .find(|r| r["epoch"] == p.epoch)
        .context("original peer missing from pinned census")?;
    ensure!(
        old["unit"]["Id"] == p.unit
            && old["unit"]["InvocationID"] == p.iid
            && old["unit"]["MainPID"] == p.processes[0].0.to_string(),
        "original producer binding changed"
    );
    let a: Bound = serde_json::from_value(old["admission"].clone())?;
    let av = custody::evidence(&a)?;
    ensure!(
        av["producer_unit"] == p.unit
            && av["producer_invocation_id"] == p.iid
            && av["producer_pid"] == p.processes[0].0,
        "foreign original admission"
    );
    let guard = if let Some(b) = old.get("guard_protection") {
        let b: Bound = serde_json::from_value(b.clone())?;
        custody::evidence(&b)?
    } else {
        old["guard_timer"].clone()
    };
    Ok((old.clone(), a, guard))
}

fn terminal(p: &Peer, manager: &Value) -> Result<Value> {
    ensure!(
        p.epoch == 169 || manager["ActiveState"] == "inactive",
        "original singleton failed before a successful commit"
    );
    let (old, a, guard) = original(p)?;
    let lines = capacity::run(
        "/usr/bin/journalctl",
        &[
            "--no-pager",
            "-ojson",
            "--output-fields=UNIT,INVOCATION_ID,MESSAGE_ID,EXIT_CODE,EXIT_STATUS,_BOOT_ID,MESSAGE",
            "_PID=1",
            &format!("UNIT={}", p.unit),
            &format!("INVOCATION_ID={}", p.iid),
        ],
        "10",
    )?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    let events = lines
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| v["UNIT"] == p.unit && v["INVOCATION_ID"] == p.iid && v["_BOOT_ID"] == boot)
        .collect::<Vec<_>>();
    let exit = events.iter().find(|v| {
        v["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
            || p.epoch == 169
                && v["MESSAGE_ID"] == "98e322203f7a4ed290d09fe03c09fe15"
                && v["EXIT_CODE"]
                    .as_str()
                    .is_some_and(|s| matches!(s, "exited" | "killed" | "dumped"))
                && v["EXIT_STATUS"].as_str().is_some_and(|s| s != "0")
    });
    let Some(exit) = exit else {
        return Err(Pending(p.epoch).into());
    };
    let proof = if p.epoch == 169 {
        let path = Path::new("/home/sol/.jetstreamer-private")
            .join(p.lane)
            .join("producer.log");
        let mut log = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)?;
        let meta = log.metadata()?;
        ensure!(
            path.canonicalize()? == path
                && (meta.dev(), meta.ino(), meta.uid(), meta.gid(), meta.nlink())
                    == (64512, p.log_inode, 1001, 1003, 1)
                && old["service_owned_stdout"]
                    == json!({"path":path,"device":64512,"inode":p.log_inode}),
            "original diagnostic log changed"
        );
        log.seek(SeekFrom::Start(meta.len().saturating_sub(64 << 10)))?;
        let mut tail = Vec::new();
        log.take(64 << 10).read_to_end(&mut tail)?;
        ensure!(
            !tail.is_empty(),
            "missing original focused diagnostic output"
        );
        json!({"diagnostic_only":true,"archive_ready":false,"log":path,"log_inode":p.log_inode,"tail_sha256":custody::sha(&tail)})
    } else {
        match committed(p) {
            Ok(proof) => proof,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                    || error.to_string() == "missing original local singleton commit" =>
            {
                return Err(Pending(p.epoch).into());
            }
            Err(error) => return Err(error),
        }
    };
    Ok(
        json!({"epoch":p.epoch,"unit":p.unit,"invocation":p.iid,"processes":p.processes,"admission":a,"guard":guard,"terminal":exit,
        "source":proof,"resource_credit_bytes":0,"archive_publication_authorized":false}),
    )
}
fn retained(p: &Peer, manager: &Value) -> Result<Value> {
    let home = Path::new(RUNTIME).join("epoch145-semantic-continuity-20261121-v1/peer-terminals");
    custody::private_directory(&home)?;
    let path = home.join(format!("epoch-{}-{}.json", p.epoch, p.iid));
    if !path.try_exists()? {
        let proof = terminal(p, manager)?;
        let value = json!({"schema":"horizon-145-qualified-original-peer-terminal-v1","history_sha256":HISTORY_SHA,
            "boot":fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),"peer":proof});
        let mut tmp = tempfile::NamedTempFile::new_in(&home)?;
        serde_json::to_writer_pretty(tmp.as_file_mut(), &value)?;
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o400))?;
        tmp.as_file().sync_all()?;
        tmp.persist_noclobber(&path)?;
        File::open(&home)?.sync_all()?;
    }
    let (bound, v) = joint_candidate::immutable(&path)?;
    ensure!(
        v["schema"] == "horizon-145-qualified-original-peer-terminal-v1"
            && v["history_sha256"] == HISTORY_SHA
            && v["boot"] == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim()
            && v["peer"]["epoch"] == p.epoch
            && v["peer"]["unit"] == p.unit
            && v["peer"]["invocation"] == p.iid
            && v["peer"]["processes"] == json!(p.processes)
            && v["peer"]["resource_credit_bytes"] == 0
            && v["peer"]["archive_publication_authorized"] == false,
        "foreign cached native original terminal evidence"
    );
    Ok(json!(bound))
}
impl Transitions {
    pub fn new(read_only: bool) -> Self {
        Self {
            read_only,
            ..Self::default()
        }
    }
    pub fn closed(&self, epoch: u64) -> bool {
        self.closed.borrow().contains_key(&epoch)
    }
    pub fn receipts(&self) -> Value {
        json!(*self.closed.borrow())
    }
    pub fn rapid_check(&self) -> Result<()> {
        #[cfg(early145_only)]
        crate::early166::rapid(self.closed(166))?;
        for p in &PEERS {
            if !self.closed(p.epoch) && original_processes(p) != [true, true] {
                return Err(Pending(p.epoch).into());
            }
        }
        Ok(())
    }
    /// PID1 can start draining an original while the slower live census is
    /// reading its service or timer. Retry only under that original manager
    /// identity, and run the complete census again before thawing.
    pub fn check_crossing(&self) -> Result<()> {
        #[cfg(early145_only)]
        if !self.closed(166) && crate::early166::inspect()?.is_some() {
            return Err(Pending(166).into());
        }
        self.rapid_check()?;
        for p in PEERS.iter().filter(|p| !self.closed(p.epoch)) {
            let manager = joint_candidate::show(p.unit, "Id,InvocationID,ActiveState")?;
            if manager["Id"] == p.unit
                && manager["InvocationID"] == p.iid
                && matches!(
                    manager["ActiveState"].as_str(),
                    Some("deactivating" | "inactive" | "failed")
                )
            {
                return Err(Pending(p.epoch).into());
            }
        }
        Ok(())
    }
    pub fn reconcile(&self) -> Result<()> {
        #[cfg(early145_only)]
        if !self.closed(166)
            && let Some(proof) = crate::early166::inspect()?
        {
            self.closed.borrow_mut().insert(166, proof);
        }
        for p in &PEERS {
            let alive = original_processes(p);
            if alive == [true, true] {
                ensure!(!self.closed(p.epoch), "terminated original reappeared");
                continue;
            }
            let manager = joint_candidate::show(
                p.unit,
                "Id,InvocationID,ActiveState,MainPID,ControlPID,Job,ControlGroup,NRestarts",
            )?;
            ensure!(
                manager["Id"] == p.unit
                    && (manager["InvocationID"] == p.iid || manager["InvocationID"] == "")
                    && (manager["MainPID"] == "0"
                        || manager["MainPID"] == p.processes[0].0.to_string()),
                "foreign native peer generation"
            );
            if alive != [false, false]
                || manager["MainPID"] != "0"
                || manager["ControlPID"] != "0"
                || manager["Job"] != ""
                || !matches!(manager["ActiveState"].as_str(), Some("inactive" | "failed"))
                || Path::new("/sys/fs/cgroup/system.slice")
                    .join(p.unit)
                    .try_exists()?
            {
                return Err(Pending(p.epoch).into());
            }
            if !self.closed(p.epoch) {
                let proof = if self.read_only {
                    terminal(p, &manager)?
                } else {
                    retained(p, &manager)?
                };
                self.closed.borrow_mut().insert(p.epoch, proof);
            }
        }
        Ok(())
    }
    pub fn projected(&self, fleet: &Value) -> Result<Value> {
        let mut v = fleet.clone();
        for key in GROUPS {
            v[key]
                .as_array_mut()
                .context("native fleet rows")?
                .retain(|r| !r["epoch"].as_u64().is_some_and(|e| self.closed(e)));
        }
        Ok(v)
    }
    pub fn names(&self, names: &BTreeSet<String>) -> BTreeSet<String> {
        names
            .iter()
            .filter(|s| !self.unit_closed(s))
            .cloned()
            .collect()
    }
    pub fn unit_closed(&self, u: &str) -> bool {
        (cfg!(early145_only) && u == closed166::NODE && self.closed(166))
            || PEERS.iter().any(|p| p.unit == u && self.closed(p.epoch))
    }
}
use sha2::Digest;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_receipt_must_match_its_original_singleton_and_directory() {
        let peer = &PEERS[0];
        let dir = Path::new("/fixture");
        let tx = "a".repeat(64);
        let line = format!(
            "root-checkpoint cohort 167-167 published 1 archive(s) with checksums in transaction {tx}; receipt /fixture/batch-{tx}.json is durable"
        );
        assert_eq!(marker(&line, peer, dir).unwrap().0, tx);
        assert!(marker(&line, &PEERS[2], dir).is_err());
        assert!(marker(&format!("{line}\n{line}"), peer, dir).is_err());
        assert!(marker(&line, peer, Path::new("/other")).is_err());
    }
    #[test]
    fn reconcile_only_projects_positively_closed_originals() {
        let state = Transitions::default();
        let mut fleet = json!({});
        for key in GROUPS {
            fleet[key] = json!([]);
        }
        fleet[GROUPS[0]] = json!([{"epoch":167},{"epoch":169},{"epoch":170},{"epoch":172}]);
        for (closed, expected) in [
            (167, vec![169, 170, 172]),
            (169, vec![170, 172]),
            (170, vec![172]),
        ] {
            state
                .closed
                .borrow_mut()
                .insert(closed, json!({"proof":closed}));
            let projection = state.projected(&fleet).unwrap();
            let retained = rows(&projection)
                .unwrap()
                .map(|r| r["epoch"].as_u64().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(retained, expected);
            assert!(continuity::roster(&retained.into_iter().collect()));
        }
    }
    #[test]
    #[ignore = "requires native authority, original producers, and paid source-user cohort fixtures"]
    fn committed_167_and_170_and_stopped_child() {
        let q = PathBuf::from(std::env::var("QA_RUNTIME").unwrap());
        let state = Transitions::default();
        state.reconcile().unwrap();
        state.rapid_check().unwrap();
        assert!(state.closed.borrow().is_empty());
        for p in &PEERS {
            let (row, admission, guard) = original(p).unwrap();
            assert_eq!(row["epoch"], p.epoch);
            assert!(admission.path.is_absolute());
            if p.epoch == 169 {
                assert_eq!(row["service_owned_stdout"]["inode"], p.log_inode);
                assert_eq!(guard["Id"], "horizon-guard-169-focused-20261120-v4.timer");
            } else {
                assert_eq!(guard["producer_invocation_id"], p.iid);
            }
        }
        let prog = File::open(Path::new(RUNTIME).join(NATIVE)).unwrap();
        for p in [&PEERS[0], &PEERS[2]] {
            let local: Value = serde_json::from_slice(
                &fs::read(q.join(format!("fixture-{}.json", p.epoch))).unwrap(),
            )
            .unwrap();
            let batch = Path::new(local["path"].as_str().unwrap());
            let source = Path::new(local["source"].as_str().unwrap());
            let target = source.parent().unwrap().join("staged");
            let proof = native_commit(
                &prog,
                p.epoch,
                local["transaction_id"].as_str().unwrap(),
                batch,
                p.fingerprint,
                source,
                &target,
            )
            .unwrap();
            assert_eq!(proof["sha256"], local["sha256"]);
            let altered = native_commit(
                &prog,
                p.epoch,
                "wrong",
                batch,
                p.fingerprint,
                source,
                &target,
            )
            .unwrap_err();
            assert!(altered.to_string().contains("different singleton"));
            assert!(
                native_commit(
                    &prog,
                    p.epoch,
                    local["transaction_id"].as_str().unwrap(),
                    batch,
                    &"0".repeat(64),
                    source,
                    &target
                )
                .unwrap_err()
                .to_string()
                .contains("fingerprint")
            );
        }
        let mut child = Command::new("/usr/bin/sleep").arg("15").spawn().unwrap();
        let pid = child.id();
        let ticks = native::ticks(pid).unwrap();
        assert_eq!(unsafe { libc::kill(pid as i32, libc::SIGSTOP) }, 0);
        for _ in 0..100 {
            if fs::read_to_string(format!("/proc/{pid}/status"))
                .unwrap()
                .contains("State:\tT")
            {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let mut attempts = 0u64;
        let result = while_stopped(pid, ticks, Instant::now() + Duration::from_secs(90), || {
            attempts += 1;
            if attempts < 3 {
                return Err(Pending(167).into());
            }
            Ok(json!({"pid":pid,"ticks":ticks}))
        })
        .unwrap();
        assert_eq!(attempts, 3);
        assert_eq!(result["pid"], pid);
        assert_eq!(native::ticks(pid).unwrap(), ticks);
        child.kill().unwrap();
        child.wait().unwrap();
    }
}
