//! Reconcile the booked epoch 252 replay into a durable local delivery input.
use super::*;
use std::{
    fs::File,
    io::{ErrorKind, Write},
    os::fd::AsRawFd,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
};

const PREPARATION: &str =
    "/var/lib/jetstreamer/horizon252-current-reader-preparation-v1/preparation.json";
const PREPARATION_SHA: &str = "072823b7e12bb1d0a2277958427f233b7789af58712ea6c867a3722429ae5d05";
const REGISTRATION: &str =
    "/var/lib/jetstreamer/horizon252-regional-full-guard-v1/cadence-registration.json";
const REGISTRATION_SHA: &str = "c73710d47b6876370b332ca36369eeeeb7793cd78e3e0ed60877739efb0a921a";
const DIRECTORY: &str = "/var/lib/jetstreamer/horizon252-local-delivery-handoff-v1";
const GUARD: &str = "horizon-252-regional-singleton-protective-v1.service";
const TIMER: &str = "horizon-252-regional-singleton-protective-v1.timer";
const TIMER_INVOCATION: &str = "17828784c625471783bd33f044d5560f";

fn properties(unit: &str, fields: &str) -> Result<Value> {
    let output = command("/usr/bin/systemctl", &["show", unit, "-p", fields])?;
    let mut properties = serde_json::Map::new();
    for line in std::str::from_utf8(&output)?.lines() {
        let (key, value) = line.split_once('=').context("malformed manager field")?;
        ensure!(
            properties.insert(key.into(), json!(value)).is_none(),
            "duplicate manager field"
        );
    }
    ensure!(
        fields.split(',').all(|key| properties.contains_key(key)),
        "incomplete manager properties for {unit}"
    );
    Ok(Value::Object(properties))
}

fn timer_needs_stop(timer: &Value) -> Result<bool> {
    ensure!(timer["Job"] == "", "epoch 252 timer has a queued job");
    match timer["ActiveState"].as_str() {
        Some("active") => {
            ensure!(
                timer["Unit"] == GUARD && timer["InvocationID"] == TIMER_INVOCATION,
                "epoch 252 timer was replaced"
            );
            Ok(true)
        }
        Some("inactive") => {
            ensure!(
                (timer["Unit"] == GUARD
                    || timer["LoadState"] == "not-found" && timer["Unit"] == "")
                    && (timer["InvocationID"] == "" || timer["InvocationID"] == TIMER_INVOCATION),
                "foreign inactive epoch 252 timer"
            );
            Ok(false)
        }
        _ => anyhow::bail!("epoch 252 timer state is unstable"),
    }
}

fn timer() -> Result<Value> {
    properties(TIMER, "LoadState,ActiveState,InvocationID,Unit,Job")
}

fn guard_drained(guard: &Value) -> bool {
    matches!(guard["ActiveState"].as_str(), Some("inactive" | "failed"))
        && guard["MainPID"] == "0"
        && guard["ControlPID"] == "0"
        && guard["ControlGroup"] == ""
        && guard["Job"] == ""
        && !Path::new("/sys/fs/cgroup/system.slice")
            .join(GUARD)
            .exists()
}

fn pinned_json(path: &str, digest: &str) -> Result<Value> {
    let (bytes, _) = read_bound(Path::new(path), 1 << 20, 0)?;
    ensure!(
        sha256(&bytes) == digest,
        "epoch 252 input changed at {path}"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

fn prepare() -> Result<Value> {
    let preparation = pinned_json(PREPARATION, PREPARATION_SHA)?;
    let registration = pinned_json(REGISTRATION, REGISTRATION_SHA)?;
    let reader = &preparation["read_plan"];
    let plan = pinned_json(
        reader["path"].as_str().context("reader plan path")?,
        reader["sha256"].as_str().context("reader plan digest")?,
    )?;
    ensure!(
        preparation["schema"] == "foundation-epoch252-current-reader-preparation-v1"
            && preparation["epoch"] == 252
            && preparation["publication_authorized"] == false
            && preparation["producer_registration"]
                == json!({"path":REGISTRATION,"sha256":REGISTRATION_SHA})
            && registration["schema"] == "foundation-epoch252-replay-cadence-registration-v1"
            && registration["epoch"] == 252
            && registration["producer"] == EPOCH_252.unit
            && registration["invocation_id"] == EPOCH_252.invocation
            && plan["schema"] == "horizon-current-reader-plan-v1"
            && plan["threads"] == 8
            && plan["epoch_expectations"]["252"] == preparation["independent_boundary"],
        "epoch 252 registration or delivery preparation differs"
    );
    Ok(preparation)
}

fn receipt_lock(dir: &Path) -> Result<File> {
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => File::open(dir.parent().context("handoff parent")?)?.sync_all()?,
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let meta = fs::symlink_metadata(dir)?;
    ensure!(
        dir.canonicalize()? == dir && meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o077 == 0,
        "epoch 252 handoff directory custody"
    );
    let lock = OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(dir.join("lock"))?;
    let meta = lock.metadata()?;
    ensure!(
        meta.is_file() && meta.uid() == 0 && meta.nlink() == 1 && meta.mode() & 0o077 == 0,
        "epoch 252 handoff lock custody"
    );
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "epoch 252 handoff is already being reconciled"
    );
    Ok(lock)
}

fn persist(path: &Path, body: &[u8]) -> Result<()> {
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(&temporary)?;
    file.write_all(body)?;
    file.sync_all()?;
    // The root-private directory and its lock serialize every writer.
    ensure!(!path.exists(), "epoch 252 terminal handoff already exists");
    fs::rename(temporary, path)?;
    File::open(path.parent().context("handoff parent")?)?.sync_all()?;
    Ok(())
}

pub(super) fn run() -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "epoch 252 handoff requires root"
    );
    let preparation = prepare()?;
    let terminal = collect(&EPOCH_252)?;
    if terminal["state"] == "replay-active" {
        return Ok(terminal);
    }
    ensure!(
        terminal["state"] == "local-cohort-committed",
        "uncommitted source"
    );
    let dir = Path::new(DIRECTORY);
    let _lock = receipt_lock(dir)?;
    // Check the source again under the handoff lock before touching its guard timer.
    ensure!(collect(&EPOCH_252)? == terminal, "epoch 252 source changed");
    if timer_needs_stop(&timer()?)? {
        command("/usr/bin/systemctl", &["stop", TIMER])?;
    }
    let stopped = timer()?;
    ensure!(
        !timer_needs_stop(&stopped)?,
        "epoch 252 guard timer is still active"
    );
    let guard = properties(GUARD, "ActiveState,MainPID,ControlPID,ControlGroup,Job")?;
    if !guard_drained(&guard) {
        return Ok(json!({
            "epoch":252,"state":"terminal-guard-draining","unit":EPOCH_252.unit,
            "invocation_id":EPOCH_252.invocation,"publication_authorized":false
        }));
    }
    ensure!(
        collect(&EPOCH_252)? == terminal,
        "epoch 252 source changed after guard drain"
    );
    let path: PathBuf = dir.join("completion.json");
    let record = json!({
        "schema":"foundation-epoch252-local-delivery-handoff-v1","epoch":252,
        "preparation":{"path":PREPARATION,"sha256":PREPARATION_SHA},
        "terminal":terminal,"timer":stopped,"guard":guard,
        "read_plan":preparation["read_plan"],"independent_boundary":preparation["independent_boundary"],
        "uploader":preparation["uploader"],"fresh_fleet_admission_pending":true,
        "fresh_target_inventory_pending":true,"publication_authorized":false
    });
    if !path.exists() {
        persist(&path, &serde_json::to_vec_pretty(&record)?)?;
    }
    let (bytes, _) = read_bound(&path, 1 << 20, 0)?;
    let saved: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        saved["schema"] == record["schema"]
            && saved["terminal"] == record["terminal"]
            && saved["preparation"] == record["preparation"]
            && saved["publication_authorized"] == false,
        "retained epoch 252 handoff differs from the committed source"
    );
    Ok(json!({
        "epoch":252,"state":"delivery-input-ready","unit":EPOCH_252.unit,
        "invocation_id":EPOCH_252.invocation,"publication_authorized":false,
        "completion":{"path":path,"sha256":sha256(&bytes)}
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_original_active_timer_can_be_stopped() {
        let mut active = json!({
            "LoadState":"loaded","ActiveState":"active","InvocationID":TIMER_INVOCATION,
            "Unit":GUARD,"Job":""
        });
        assert!(timer_needs_stop(&active).unwrap());
        active["InvocationID"] = json!("replacement");
        assert!(timer_needs_stop(&active).is_err());
        active["InvocationID"] = json!(TIMER_INVOCATION);
        active["Job"] = json!("opening");
        assert!(timer_needs_stop(&active).is_err());
        let absent = json!({
            "LoadState":"not-found","ActiveState":"inactive","InvocationID":"","Unit":"","Job":""
        });
        assert!(!timer_needs_stop(&absent).unwrap());
    }
}
