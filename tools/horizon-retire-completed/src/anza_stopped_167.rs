//! Retire the two sealed, superseded epoch 167 private prefixes.
use super::*;
use std::collections::BTreeMap;

pub(super) const REVIEW: &str = "/var/lib/jetstreamer/horizon_runtime_data/closed167-retry57-prefix-retirement-20261125-v1/REVIEW.json";
const REVIEW_SHA: &str = "0f6be01db825f091d89295acd2bff1c1d3567349591c026f9c32c90439aaee59";
const AUDIT: &str = "/var/lib/jetstreamer/horizon_runtime_data/closed167-retry57-prefix-retirement-20261125-v1/retired.jsonl";
const CAMPAIGN_LOCK: &str = "/run/horizon-epoch171-to136-g1.operation.lock";
const MUTATION_LOCK: &str = "/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock";
const MANAGER: &str = "/usr/bin/systemctl";
const PROPERTIES: &str = "Id,FragmentPath,DropInPaths,LoadState,UnitFileState,ActiveState,SubState,ControlPID,MainPID,Job,Triggers,TriggeredBy,NeedDaemonReload,ControlGroup";

#[derive(Deserialize)]
struct Prefix {
    target: Target,
    sha256: String,
    final_slot: u64,
    evidence: Vec<Bound>,
}

#[derive(Deserialize)]
struct Lock {
    path: PathBuf,
    device: u64,
    inode: u64,
}

#[derive(Deserialize)]
struct Retirement {
    schema: String,
    remote_mutations: bool,
    actual_reclaimed_bytes: u64,
    targets: Vec<Prefix>,
    original_locks: Vec<Lock>,
    preserved: Vec<Preserved>,
    native_units: BTreeMap<String, BTreeMap<String, String>>,
    definitions: Vec<Bound>,
    screens: Vec<Bound>,
    direct_archive_references: Vec<Reference>,
    guard_evidence: Vec<Bound>,
    other_evidence: Vec<Bound>,
    hashed_bodies: Bound,
    fleet: Bound,
    successor: Value,
}

#[derive(Deserialize)]
struct Reference {
    path: PathBuf,
    sha256: String,
    classification: ReferenceKind,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ReferenceKind {
    HistoricNativeInventory,
    HistoricalReclamationDelta,
    HistoricClosedAccountsTool,
}

#[derive(Deserialize)]
struct Preserved {
    path: PathBuf,
    identity: Stamp,
}

fn lock(path: &Path, dev: u64, ino: u64, uid: u32, gid: u32) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && (
                m.dev(),
                m.ino(),
                m.uid(),
                m.gid(),
                m.nlink(),
                m.mode() & 0o7777
            ) == (dev, ino, uid, gid, 1, 0o600)
            && stamp(&exact(path)?) == stamp(&m),
        "different lock at {}",
        path.display()
    );
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "lock held at {}",
        path.display()
    );
    Ok(file)
}

fn properties(unit: &str, names: &str) -> Result<BTreeMap<String, String>> {
    let output = Command::new(MANAGER)
        .args(["show", unit, "-p", names])
        .output()?;
    ensure!(
        output.status.success() && output.stderr.is_empty(),
        "cannot inspect {unit}"
    );
    let mut props = BTreeMap::new();
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let (key, value) = line.split_once('=').context("invalid manager property")?;
        ensure!(
            props.insert(key.into(), value.into()).is_none(),
            "duplicate manager property"
        );
    }
    Ok(props)
}

fn no_cgroup_processes(group: &str) -> Result<()> {
    if group.is_empty() {
        return Ok(());
    }
    let path = Path::new("/sys/fs/cgroup")
        .join(group.strip_prefix('/').context("relative control group")?)
        .join("cgroup.events");
    match fs::read_to_string(path) {
        Ok(events) => ensure!(
            events.lines().any(|s| s == "populated 0"),
            "old control group is populated: {group}"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn manager_states(plan: &Retirement) -> Result<()> {
    for (unit, expected) in &plan.native_units {
        ensure!(
            &properties(unit, PROPERTIES)? == expected,
            "changed historical manager {unit}"
        );
        no_cgroup_processes(expected.get("ControlGroup").map_or("", String::as_str))?;
    }
    let expected = &plan.successor["unit"];
    let unit = expected["Id"].as_str().context("missing successor unit")?;
    let keys = [
        "ActiveState",
        "ControlGroup",
        "InvocationID",
        "Job",
        "MainPID",
        "SubState",
    ];
    let current = properties(unit, &keys.join(","))?;
    ensure!(
        keys.iter()
            .all(|key| current.get(*key).is_some_and(|v| expected[*key] == *v))
            && current["ActiveState"] == "active"
            && current["SubState"] == "running",
        "qualified epoch 167 successor changed"
    );
    let proc = PathBuf::from("/proc").join(&current["MainPID"]);
    let stat = fs::read_to_string(proc.join("stat"))?;
    let (_, trailing) = stat
        .rsplit_once(") ")
        .context("invalid successor proc stat")?;
    let ticks: u64 = trailing
        .split_whitespace()
        .nth(19)
        .context("no start ticks")?
        .parse()?;
    ensure!(
        plan.successor["start_ticks"] == ticks
            && fs::read_to_string(proc.join("cgroup"))?.trim()
                == format!("0::{}", current["ControlGroup"]),
        "epoch 167 successor process identity changed"
    );
    let guard = &plan.successor["guard_timer"];
    let name = guard["Id"]
        .as_str()
        .context("missing incumbent guard timer")?;
    let timer = properties(name, "ActiveState,InvocationID,Job,Triggers")?;
    ensure!(
        ["ActiveState", "InvocationID", "Triggers"]
            .iter()
            .all(|key| guard[*key] == timer[*key])
            && timer["ActiveState"] == "active"
            && timer["Job"].is_empty(),
        "epoch 167 successor guard changed"
    );
    Ok(())
}

fn file_stamp(t: &Target) -> Result<()> {
    ensure!(
        t.epoch == 167
            && t.external_bootstrap_review.is_none()
            && ordinary_private_path(&t.path)
            && stamp(&exact(&t.path)?) == t.identity,
        "stopped prefix identity changed: {}",
        t.path.display()
    );
    Ok(())
}

fn read_bounded_json(r: &Bound) -> Result<Value> {
    Ok(serde_json::from_slice(&bound(r, LIMIT)?)?)
}

fn checked_hash(b: &Bound) -> Result<()> {
    let before = stamp(&exact(&b.path)?);
    ensure!(
        before.len <= 64 << 20 && digest(&b.path)? == b.sha256 && stamp(&exact(&b.path)?) == before,
        "changed consumer evidence {}",
        b.path.display()
    );
    Ok(())
}

fn check_preserved(plan: &Retirement) -> Result<()> {
    for old in &plan.preserved {
        ensure!(
            stamp(&exact(&old.path)?) == old.identity,
            "preserved bootstrap or Bank changed: {}",
            old.path.display()
        );
    }
    Ok(())
}

fn definitions(plan: &Retirement, tokens: &[String]) -> Result<()> {
    let mut scan = Command::new("/usr/bin/rg");
    scan.args([
        "--threads",
        "1",
        "--hidden",
        "--no-ignore",
        "--files-with-matches",
        "--fixed-strings",
    ]);
    for token in tokens {
        scan.args(["-e", token]);
    }
    let roots = [
        "/etc/systemd/system",
        "/run/systemd/system",
        "/run/systemd/transient",
        "/usr/lib/systemd/system",
        "/run/systemd/generator",
        "/run/systemd/generator.early",
        "/run/systemd/generator.late",
        "/etc/cron.d",
    ];
    scan.args(roots.iter().filter(|p| Path::new(p).is_dir()));
    let output = scan.output()?;
    ensure!(
        matches!(output.status.code(), Some(0 | 1)) && output.stderr.is_empty(),
        "installed consumer scan failed"
    );
    for path in std::str::from_utf8(&output.stdout)?.lines() {
        ensure!(
            plan.definitions.iter().any(|b| b.path == Path::new(path)),
            "new installed consumer {path}"
        );
    }
    for definition in &plan.definitions {
        checked_hash(definition)?;
    }
    Ok(())
}

fn exited(proc: &Path) -> Result<bool> {
    match fs::read_to_string(proc.join("status")) {
        Ok(status) => Ok(status
            .lines()
            .find_map(|line| line.strip_prefix("State:"))
            .and_then(|state| state.split_whitespace().next())
            .is_some_and(|state| matches!(state, "Z" | "X" | "x"))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !proc.exists() => Ok(true),
        Err(e) => Err(e).context("cannot establish process exit"),
    }
}

fn scan_run_references(strong: &[String]) -> Result<()> {
    let me = std::process::id().to_string();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.as_bytes();
        if name == me.as_bytes() || !name.iter().all(u8::is_ascii_digit) {
            continue;
        }
        for kind in ["cmdline", "mountinfo"] {
            let p = entry.path().join(kind);
            let bytes = match fs::read(&p) {
                Ok(bytes) => bytes,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && !entry.path().exists() => {
                    continue;
                }
                Err(e) if kind == "mountinfo" && e.raw_os_error() == Some(libc::EINVAL) => {
                    ensure!(
                        exited(&entry.path())?,
                        "cannot inspect live mount namespace: {}",
                        p.display()
                    );
                    continue;
                }
                Err(e) => return Err(e).with_context(|| format!("cannot scan {}", p.display())),
            };
            ensure!(
                strong.iter().all(|term| !contains(&bytes, term.as_bytes())),
                "PID {:?} has a stopped-run reference in {kind}",
                entry.file_name()
            );
        }
    }
    Ok(())
}

pub(super) fn run(bytes: &[u8], sha: &str, image: &str, check_only: bool) -> Result<()> {
    ensure!(sha == REVIEW_SHA, "different stopped-prefix review digest");
    let plan: Retirement = serde_json::from_slice(bytes)?;
    ensure!(
        plan.schema == "horizon-closed167-stopped-prefix-retirement-v1"
            && !plan.remote_mutations
            && plan.actual_reclaimed_bytes == 0
            && plan.targets.len() == 2
            && plan.original_locks.len() == 2,
        "different stopped-prefix review"
    );
    let audit = Path::new(AUDIT);
    ensure!(
        fs::symlink_metadata(audit).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "an audit already exists or is inaccessible"
    );
    let _campaign = lock(Path::new(CAMPAIGN_LOCK), 26, 3453440, 0, 0)?;
    let _historical = plan
        .original_locks
        .iter()
        .map(|l| lock(&l.path, l.device, l.inode, 1001, 1003))
        .collect::<Result<Vec<_>>>()?;
    let _mutation = lock(Path::new(MUTATION_LOCK), 64512, 101135013, 1001, 1003)?;
    let hashed = read_bounded_json(&plan.hashed_bodies)?;
    let fleet = read_bounded_json(&plan.fleet)?;
    ensure!(
        fleet["epochs"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|r| r["epoch"] == 167
                && r["state"] == "executing"
                && r["current_replay"] == plan.successor
                && r["current_replay"]["measured_progress"] == true)),
        "missing measured successor in reviewed fleet"
    );
    let mut unique = BTreeSet::new();
    let mut allocated = 0;
    for p in &plan.targets {
        let t = &p.target;
        file_stamp(t)?;
        let path = t.path.to_str().context("non-UTF-8 prefix path")?;
        ensure!(
            unique.insert(&t.path)
                && hashed["digests"][path] == p.sha256
                && plan.successor["last_progress"]["slot"]
                    .as_u64()
                    .is_some_and(|slot| slot > p.final_slot)
                && p.final_slot < 72_575_999,
            "missing stable hash or superseding replay progress"
        );
        for ev in &p.evidence {
            checked_hash(ev)?;
        }
        allocated += t.identity.blocks * 512;
    }
    ensure!(
        hashed["allocated_bytes"] == allocated,
        "different reviewed allocation"
    );
    for ev in plan.guard_evidence.iter().chain(&plan.other_evidence) {
        checked_hash(ev)?;
    }
    for reference in &plan.direct_archive_references {
        let filename = reference.path.file_name().and_then(|p| p.to_str());
        ensure!(
            match reference.classification {
                ReferenceKind::HistoricNativeInventory => filename == Some("prepared.json"),
                ReferenceKind::HistoricalReclamationDelta =>
                    matches!(filename, Some("current.json" | "delta.json")),
                ReferenceKind::HistoricClosedAccountsTool => matches!(
                    filename,
                    Some("profiles.json" | "QUALIFICATION.json" | "CHECK.json")
                ),
            },
            "invalid historical archive reference"
        );
        checked_hash(&Bound {
            path: reference.path.clone(),
            sha256: reference.sha256.clone(),
        })?;
    }
    let screen = read_bounded_json(&plan.screens[0])?;
    checked_hash(&plan.screens[1])?;
    let strings =
        |key: &str| -> Result<Vec<String>> { Ok(serde_json::from_value(screen[key].clone())?) };
    let strong = strings("strong_tokens")?;
    let tokens = strings("tokens")?;
    ensure!(
        !strong.is_empty() && strong.iter().all(|s| !s.is_empty() && tokens.contains(s)),
        "incomplete historical consumer paths"
    );
    definitions(&plan, &tokens)?;
    check_preserved(&plan)?;
    manager_states(&plan)?;
    scan_run_references(&strong)?;
    for p in &plan.targets {
        scan_consumers(std::slice::from_ref(&p.target))?;
    }
    if check_only {
        println!("checked 2 stopped epoch 167 prefixes, {allocated} allocated bytes; no deletion");
        return Ok(());
    }
    let mut log = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(audit)?;
    event(
        &mut log,
        json!({"event":"authorized","review_sha256":sha,"self_sha256":image,"fleet":plan.fleet.path,
        "unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"remote_mutations":false}),
    )?;
    File::open(audit.parent().context("missing audit parent")?)?.sync_all()?;
    for p in &plan.targets {
        let t = &p.target;
        manager_states(&plan)?;
        definitions(&plan, &tokens)?;
        scan_run_references(&strong)?;
        scan_consumers(std::slice::from_ref(t))?;
        file_stamp(t)?;
        event(
            &mut log,
            json!({"event":"intent","path":t.path,"identity":t.identity,"sha256":p.sha256,"final_slot":p.final_slot}),
        )?;
        unlink_identity(&t.path, &t.identity)?;
        event(
            &mut log,
            json!({"event":"removed","path":t.path,"allocated_bytes":t.identity.blocks*512}),
        )?;
    }
    check_preserved(&plan)?;
    event(
        &mut log,
        json!({"event":"complete","allocated_bytes_removed":allocated,"remote_mutations":false}),
    )?;
    println!(
        "removed 2 files, {allocated} allocated bytes; receipt {}",
        audit.display()
    );
    Ok(())
}
