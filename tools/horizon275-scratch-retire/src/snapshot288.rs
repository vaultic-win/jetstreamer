//! Retire only the byte-proven bound bootstrap copy of the stopped epoch 288 run.
use super::*;
use std::{ffi::CString, os::unix::ffi::OsStrExt as _};

const PROOF: &str =
    "/var/lib/jetstreamer/horizon288-full-v303/bootstrap-duplicate-qualification-v325.json";
const PROOF_SHA: &str = "b4f4105a5f8edc087abff3e4422b1ccbcebea9e63092b125fccfe876b75c44c6";
const PROFILE: &str = "/var/lib/jetstreamer/horizon288-full-v303/profile.json";
const PROFILE_SHA: &str = "936c08cb53612b85d63f0b9fae0315f761538ef78689dbb19e62aa8cb095bd37";
const STATE: &str = "/var/lib/jetstreamer/horizon288-bootstrap-retirement-v327";
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/qualification-288-root-v303";
const UNIT: &str = "horizon-qualify-288-root-singleton-v303.service";
const GUARD: &str = "horizon-288-full-protective-v303.service";
const TIMER: &str = "horizon-288-full-protective-v303.timer";
const INVOCATION: &str = "e3823449247b42948e3cf620bffa019d";
const COPY_BYTES: u64 = 20_078_043_136;
const SNAPSHOT: &str = "snapshot-124415782-ApsjgCndKc38Wv37guZpxbR7MuTs5WATjVtm3MeGSPM6.tar.zst";

#[derive(Deserialize)]
struct Asset {
    path: PathBuf,
    sha256: String,
    #[serde(flatten)]
    stamp: Stamp,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
struct Stamp {
    device: u64,
    inode: u64,
    logical_bytes: u64,
    physical_bytes: u64,
    uid: u32,
    mode: u32,
    links: u64,
    mtime_ns: i64,
    ctime_ns: i64,
}

impl Stamp {
    fn of(m: &Metadata) -> Result<Self> {
        let nanos = |seconds: i64, subsecond: i64| {
            seconds
                .checked_mul(1_000_000_000)
                .and_then(|n| n.checked_add(subsecond))
                .context("timestamp overflow")
        };
        Ok(Self {
            device: m.dev(),
            inode: m.ino(),
            logical_bytes: m.len(),
            physical_bytes: m.blocks().checked_mul(512).context("allocation overflow")?,
            uid: m.uid(),
            mode: m.mode(),
            links: m.nlink(),
            mtime_ns: nanos(m.mtime(), m.mtime_nsec())?,
            ctime_ns: nanos(m.ctime(), m.ctime_nsec())?,
        })
    }

    fn at(&self, path: &Path) -> Result<()> {
        ensure!(
            Self::of(&path.symlink_metadata()?)? == *self,
            "asset changed: {path:?}"
        );
        Ok(())
    }
}

fn lookup_receipt(path: &Path) -> Result<Option<(Binding, Value)>> {
    match path.symlink_metadata() {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        result => {
            let mode = result?;
            ensure!(
                mode.uid() == 0 && mode.mode() & 0o222 == 0,
                "writable receipt"
            );
        }
    }
    let sha256 = digest(&mut open_regular(path)?)?;
    let value = read_bound(path, &sha256, JSON_LIMIT)?;
    Ok(Some((
        Binding {
            path: path.into(),
            sha256,
        },
        value,
    )))
}

fn closed() -> Result<()> {
    for unit in [UNIT, GUARD, TIMER] {
        terminal_unit(unit)?;
    }
    let response = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            UNIT,
            "-p",
            "InvocationID,MainPID,ControlPID,ControlGroup,LoadState,SubState",
        ])
        .output()?;
    let text = std::str::from_utf8(&response.stdout)?;
    ensure!(
        response.status.success()
            && [
                "InvocationID=",
                "MainPID=0",
                "ControlPID=0",
                "ControlGroup=",
                "LoadState=not-found",
                "SubState=dead"
            ]
            .into_iter()
            .all(|field| text.lines().any(|line| line == field)),
        "original producer is no longer the collected terminal unit"
    );
    Ok(())
}

fn run_path(copy: &Path) -> Result<&Path> {
    let parent = copy.parent().context("missing bootstrap copy parent")?;
    let worker = parent.parent().context("missing historical parent")?;
    let scratch = worker
        .parent()
        .and_then(Path::parent)
        .context("missing scratch parent")?;
    let run = scratch.parent().context("missing run parent")?;
    ensure!(
        run.starts_with(Path::new(ROOT).join("state"))
            && run.ends_with("root-cohort-288-288/run-750660-1795547371821978162")
            && scratch == run.join("scratch")
            && worker == scratch.join(".historical-runtime/jetstreamer-historical-parent-wIfdSb")
            && copy == worker.join("bound-bootstrap").join(SNAPSHOT),
        "wrong duplicate path"
    );
    Ok(run)
}

pub(super) fn run(apply: bool, self_sha: &str) -> Result<()> {
    let state = Path::new(STATE);
    let mode = state.symlink_metadata()?;
    ensure!(
        state.canonicalize()? == state
            && mode.is_dir()
            && mode.uid() == 0
            && mode.mode() & 0o077 == 0,
        "unsafe receipt directory"
    );
    let proof: Value = read_bound(Path::new(PROOF), PROOF_SHA, JSON_LIMIT)?;
    let terminal = value(&proof["terminal"])?;
    let exit = value(&terminal["native_exit"])?;
    let registration = value(&terminal["registration"])?;
    let profile: Value = read_bound(Path::new(PROFILE), PROFILE_SHA, JSON_LIMIT)?;
    let stop = &exit["stop_receipts"]["completion"];
    let stop_intent = &exit["stop_receipts"]["intent"];
    ensure!(
        proof["schema"] == "foundation-epoch288-stopped-bootstrap-duplicate-v325"
            && proof["epoch"] == 288
            && proof["bytes_match"] == true
            && proof["retired"] == false
            && proof["publication_authorized"] == false
            && terminal["epoch"] == 288
            && terminal["root_preserved"] == true
            && terminal["publication_authorized"] == false
            && terminal["producer"]["Id"] == UNIT
            && terminal["producer"] == exit["producer"]
            && terminal["producer"]["LoadState"] == "not-found"
            && terminal["guard_drained"]["ActiveState"] == "inactive"
            && terminal["timer_drained"]["ActiveState"] == "inactive"
            && registration["producer"] == UNIT
            && registration["invocation_id"] == INVOCATION
            && stop["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
            && stop["producer_invocation_id"] == INVOCATION
            && stop["scratch_deleted"] == false
            && stop["terminal"]["load_state"] == "not-found"
            && stop["terminal"]["pid"] == 0
            && stop["plan_sha256"] == stop_intent["plan_sha256"]
            && stop_intent["producer_invocation_id"] == INVOCATION
            && stop_intent["reason"] == "root-physical-budget",
        "qualification does not bind the original stopped producer"
    );
    let pin: Asset = serde_json::from_value(proof["pin"].clone())?;
    let copy: Asset = serde_json::from_value(proof["duplicate"].clone())?;
    let run = run_path(&copy.path)?;
    ensure!(
        pin.path
            == Path::new("/home/ubuntu/.jetstreamer-private/epoch288-pinned-root-v303")
                .join(SNAPSHOT)
            && profile["snapshot"]["path"].as_str() == pin.path.to_str()
            && profile["snapshot"]["sha256"] == pin.sha256
            && profile["snapshot"]["device"] == pin.stamp.device
            && profile["snapshot"]["inode"] == pin.stamp.inode
            && profile["snapshot"]["bytes"] == pin.stamp.logical_bytes
            && pin.stamp.uid == 0
            && pin.stamp.mode & 0o222 == 0
            && copy.stamp.uid == 1000
            && copy.stamp.physical_bytes == COPY_BYTES
            && copy.stamp.device == pin.stamp.device
            && copy.stamp.inode != pin.stamp.inode
            && copy.stamp.logical_bytes == pin.stamp.logical_bytes
            && copy.sha256 == pin.sha256,
        "copy and sealed input do not match the qualified profile"
    );

    let archive = run.join("archives/epoch-288.jet");
    let bank = copy
        .path
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("jetstreamer-historical-v1.8.11-y3aKJ1/accounts-state");
    let bank_mode = bank.symlink_metadata()?;
    let archive_stamp = Stamp::of(&open_regular(&archive)?.metadata()?)?;
    let bank_stamp = Stamp::of(&bank_mode)?;
    ensure!(
        bank_mode.is_dir()
            && bank.canonicalize()? == bank
            && bank_stamp.inode == 54691869
            && archive_stamp.inode == 42147904
            && archive_stamp.logical_bytes == 6659827189,
        "changed partial archive or evolved bank directory"
    );
    let check_path = state.join("check.json");
    let intent_path = state.join("intent.json");
    let completion_path = state.join("completion.json");
    let copy_parent = copy.path.parent().context("bootstrap parent")?;
    ensure!(
        copy_parent.canonicalize()? == copy_parent,
        "noncanonical bootstrap parent"
    );
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(copy_parent)?;
    let parent_identity = identity(&parent.metadata()?);
    ensure!(
        parent_identity.0 == copy.stamp.device && parent_identity.1 == 42149337,
        "bootstrap parent no longer matches the stopped run"
    );
    let relative = PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd())).join(SNAPSHOT);
    let stable = || -> Result<()> {
        pin.stamp.at(&pin.path)?;
        archive_stamp.at(&archive)?;
        bank_stamp.at(&bank)?;
        Ok(())
    };
    stable()?;
    closed()?;
    let anchors = json!({
        "epoch":288, "qualification_sha256":PROOF_SHA, "self_sha256":self_sha,
        "producer_invocation_id":INVOCATION, "copy":copy.path, "snapshot":pin.path,
        "archive":archive, "archive_stamp":archive_stamp, "bank":bank, "bank_stamp":bank_stamp,
    });
    if !apply {
        ensure!(
            lookup_receipt(&intent_path)?.is_none() && lookup_receipt(&completion_path)?.is_none(),
            "retirement already started"
        );
        pin.stamp.at(&pin.path)?;
        copy.stamp.at(&relative)?;
        ensure!(
            digest(&mut open_regular(&pin.path)?)? == pin.sha256
                && digest(&mut open_regular(&copy.path)?)? == copy.sha256,
            "bootstrap bytes changed since qualification"
        );
        copy.stamp.at(&relative)?;
        stable()?;
        let schedule = scheduled(run, &copy.path)?;
        let consumers = process_references::scan(Path::new("/proc"), &copy.path)?;
        ensure!(
            consumers.inspected_processes > 0 && consumers.references.is_empty(),
            "live bootstrap copy reference"
        );
        closed()?;
        copy.stamp.at(&relative)?;
        let receipt = write_json(
            &check_path,
            &json!({"anchors":anchors, "scheduled":schedule, "consumers":consumers}),
        )?;
        println!("{}", serde_json::to_string(&receipt)?);
        return Ok(());
    }

    let _cycle = lock(CYCLE_LOCK)?;
    let _mutation = lock(LOCAL_LOCK)?;
    let (check_ref, check) = lookup_receipt(&check_path)?.context("missing check-only evidence")?;
    ensure!(check["anchors"] == anchors, "check-only evidence changed");
    closed()?;
    assert_no_nested_mount(&copy.path)?;
    let pending = lookup_receipt(&intent_path)?;
    let present = match relative.symlink_metadata() {
        Ok(_) => {
            copy.stamp.at(&relative)?;
            true
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound && pending.is_some() => false,
        Err(e) => return Err(e).context("unexplained bootstrap absence or read failure"),
    };
    let intent = if let Some((binding, previous)) = pending {
        ensure!(
            previous["anchors"] == anchors
                && previous["check"] == serde_json::to_value(&check_ref)?
                && previous["allocated_bytes"] == COPY_BYTES,
            "foreign retirement intent"
        );
        binding
    } else {
        let schedule = scheduled(run, &copy.path)?;
        let consumers = process_references::scan(Path::new("/proc"), &copy.path)?;
        ensure!(
            consumers.inspected_processes > 0 && consumers.references.is_empty(),
            "live bootstrap copy reference"
        );
        write_json(
            &intent_path,
            &json!({
                "anchors":anchors, "check":check_ref, "allocated_bytes":COPY_BYTES,
                "free_before_bytes":available(Path::new(ROOT))?, "scheduled":schedule, "consumers":consumers,
            }),
        )?
    };
    if let Some((binding, previous)) = lookup_receipt(&completion_path)? {
        ensure!(
            !present && previous["intent"] == serde_json::to_value(&intent)?,
            "retirement completion disagrees with disk"
        );
        println!("{}", serde_json::to_string(&binding)?);
        return Ok(());
    }
    let schedule = scheduled(run, &copy.path)?;
    let consumers = process_references::scan(Path::new("/proc"), &copy.path)?;
    ensure!(
        consumers.inspected_processes > 0 && consumers.references.is_empty(),
        "live bootstrap copy reference"
    );
    stable()?;
    closed()?;
    ensure!(
        copy_parent.canonicalize()? == copy_parent
            && identity(&copy_parent.symlink_metadata()?) == parent_identity,
        "bootstrap parent changed"
    );
    if present {
        copy.stamp.at(&relative)?;
        let name = CString::new(Path::new(SNAPSHOT).as_os_str().as_bytes())?;
        let rc = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) };
        ensure!(
            rc == 0,
            "retire exact bootstrap copy: {}",
            io::Error::last_os_error()
        );
    }
    parent.sync_all()?;
    stable()?;
    ensure!(
        copy.path
            .symlink_metadata()
            .is_err_and(|e| e.kind() == io::ErrorKind::NotFound),
        "bootstrap copy may still exist"
    );
    let result = write_json(
        &completion_path,
        &json!({
            "intent":intent, "epoch":288, "allocated_bytes_removed":COPY_BYTES,
            "free_after_bytes":available(Path::new(ROOT))?, "scheduled":schedule, "consumers":consumers,
            "original_snapshot_retained":true, "partial_archive_retained":true, "evolved_bank_retained":true,
            "r2_mutations":false, "remote_mutations":false, "publication_authorized":false,
        }),
    )?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_run_and_neighboring_bootstrap_files() {
        let run = Path::new(ROOT)
            .join("state/destination/work/root-cohort-288-288/run-750660-1795547371821978162");
        let parent = run.join(
            "scratch/.historical-runtime/jetstreamer-historical-parent-wIfdSb/bound-bootstrap",
        );
        assert_eq!(run_path(&parent.join(SNAPSHOT)).unwrap(), run);
        assert!(run_path(&parent.join("another-snapshot")).is_err());
        assert!(run_path(&run.join("scratch/alternate/bound-bootstrap").join(SNAPSHOT)).is_err());
    }

    #[test]
    fn rejects_changed_or_replaced_asset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snapshot");
        fs::write(&path, b"original").unwrap();
        let stamp = Stamp::of(&path.symlink_metadata().unwrap()).unwrap();
        stamp.at(&path).unwrap();
        fs::write(&path, b"changed length").unwrap();
        assert!(stamp.at(&path).is_err());
        fs::rename(&path, dir.path().join("old")).unwrap();
        fs::write(&path, b"original").unwrap();
        assert!(stamp.at(&path).is_err());
    }
}
