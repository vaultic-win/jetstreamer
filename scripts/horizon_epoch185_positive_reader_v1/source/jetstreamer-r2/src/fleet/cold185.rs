//! Exact epoch 185 native pre-start task ownership. No service or archive mutation.
use super::*;
use std::os::unix::fs::OpenOptionsExt;
pub(in crate::fleet) mod enrollment;
pub(in crate::fleet) mod lifecycle;
pub(in crate::fleet) mod native;
mod native_empty_hooks;
pub(in crate::fleet) mod task_status_bridge;
pub(in crate::fleet) mod readable_evidence;

pub(in crate::fleet) const TASK_SCHEMA: &str = "horizon-epoch185-genuine-native-startpre-task-v1";
pub(in crate::fleet) const DRIVER: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch185-guarded-adapter-v10/epoch185-guarded-cold";
pub(in crate::fleet) const DRIVER_SHA: &str =
    "0a7dddaaa5ae049a6a9f6ca103fd8463987d6aff52397a4ece09a43387107e1a";
pub(in crate::fleet) const PACKAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch185-cohesive-capped-inputs-20261105-v3";
pub(in crate::fleet) const ROOT: &str =
    "/var/lib/jetstreamer/horizon-epoch185-native-startpre-registrations-20261105-v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskSpec {
    schema: String,
    native_spec: Value,
    output: PathBuf,
}

pub(in crate::fleet) fn capture_native(spec: &Value, now: u64) -> Result<Value> {
    native::capture(spec, now)
}

pub(in crate::fleet) fn load(task: &BoundFile, now: u64) -> Result<Value> {
    let original = native::read_json(task, 4 << 20)?;
    ensure!(
        original["schema"] == TASK_SCHEMA && original["no_replay_or_publication_or_credit"] == true,
        "epoch 185 original task proof schema or authority changed"
    );
    let spec: BoundFile = serde_json::from_value(original["spec"].clone())?;
    let declared: TaskSpec = serde_json::from_value(native::read_json(&spec, 4 << 20)?)?;
    ensure!(
        declared.schema == "horizon-epoch185-native-startpre-task-capture-v1"
            && declared.native_spec == original["native_spec"],
        "epoch 185 task source crossed"
    );
    native::original_task(&original)?;
    let mut selected = declared.native_spec;
    selected["mode"] = json!("current-owner");
    let current = capture_native(&selected, now)?;
    ensure!(
        current["actor_unit"] == original["actor_unit"]
            && current["actor_invocation_id"] == original["actor_invocation_id"]
            && current["ready_binding"] == original["ready_binding"]
            && current["ready_sha256"] == original["ready_sha256"],
        "epoch 185 task current owner or original readiness changed"
    );
    let mut value = current;
    value["recorded_unix_seconds"] = original["recorded_unix_seconds"].clone();
    value["original_setup_deadline_unix_seconds"] =
        original["original_setup_deadline_unix_seconds"].clone();
    value["schema"] = json!(TASK_SCHEMA);
    value["spec"] = json!(spec);
    value["task"] = json!(task);
    value["original_task_proof"] = original;
    value["source_bindings"]["task"] = json!(task);
    value["source_bindings"]["spec"] = json!(spec);
    Ok(value)
}

pub(in crate::fleet) fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

pub(in crate::fleet) fn parsed(command: &str) -> Result<(BoundFile, String)> {
    let args = env::args().collect::<Vec<_>>();
    ensure!(
        args.len() == 7
            && args[1] == command
            && args[3] == "--spec-sha256"
            && args[5] == "--self-sha256"
            && is_lower_hex(&args[4], 64)
            && is_lower_hex(&args[6], 64)
            && unsafe { libc::geteuid() } == 0,
        "epoch 185 exact Root command arguments"
    );
    ensure!(
        !env::vars_os()
            .any(|(k, _)| k.to_string_lossy().starts_with("LD_") || k == "GLIBC_TUNABLES"),
        "epoch 185 metadata helper loader override"
    );
    let self_binding = BoundFile {
        path: fs::read_link("/proc/self/exe")?,
        sha256: args[6].clone(),
    };
    native::read_immutable(&self_binding, 256 << 20)?;
    Ok((
        BoundFile {
            path: PathBuf::from(&args[2]),
            sha256: args[4].clone(),
        },
        args[6].clone(),
    ))
}

pub(in crate::fleet) fn persist(output: &Path, value: &Value) -> Result<()> {
    let parent = output.parent().context("epoch 185 output parent")?;
    ensure!(
        parent.parent() == Some(Path::new(ROOT))
            && parent
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| is_lower_hex(s, 32))
            && [
                "task.json",
                "registration.json",
                "fleet-acceptance.json",
                "reader-acceptance.json",
                "task-acknowledgment.json",
                "status-readback.json",
                "readable-task-acknowledgment.json",
                "readable-status-readback.json",
                "readable-fleet-acceptance.json",
                "readable-reader-acceptance.json"
            ]
            .iter()
            .any(|name| output.file_name().and_then(|s| s.to_str()) == Some(*name)),
        "epoch 185 exact native receipt namespace"
    );
    let meta = fs::symlink_metadata(parent)?;
    ensure!(
        meta.is_dir()
            && meta.uid() == 0
            && meta.mode() & 0o7777 == 0o700
            && parent.canonicalize()? == parent,
        "epoch 185 native receipt custody"
    );
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    ensure!(
        bytes.len() <= 4 << 20,
        "epoch 185 native receipt exceeds bound"
    );
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(output)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub(crate) fn capture_task() -> Result<()> {
    let (binding, self_sha) = parsed("capture-cold185-startpre-task")?;
    let spec: TaskSpec = serde_json::from_value(native::read_json(&binding, 4 << 20)?)?;
    ensure!(
        spec.schema == "horizon-epoch185-native-startpre-task-capture-v1"
            && spec.native_spec["mode"] == "task-start-pre",
        "epoch 185 capture spec scope"
    );
    let mut proof = capture_native(&spec.native_spec, now()?)?;
    ensure!(
        proof["stage"] == "start-pre",
        "epoch 185 initial task must be genuine start-pre"
    );
    ensure!(
        spec.output
            .parent()
            .and_then(Path::file_name)
            .and_then(|s| s.to_str())
            == proof["actor_invocation_id"].as_str(),
        "epoch 185 task output IID changed"
    );
    proof["schema"] = json!(TASK_SCHEMA);
    proof["spec"] = json!(binding);
    proof["source_bindings"]["spec"] = json!(binding);
    proof["native_spec"] = spec.native_spec;
    proof["self_sha256"] = json!(self_sha);
    proof["no_replay_or_publication_or_credit"] = json!(true);
    persist(&spec.output, &proof)?;
    println!(
        "{}",
        json!({"task": spec.output, "epoch": 185, "stage": "start-pre", "publication_authorized": false})
    );
    Ok(())
}

pub(crate) fn enroll() -> Result<()> {
    enrollment::run()
}
pub(crate) fn prove_fleet() -> Result<()> {
    enrollment::capture_fleet_acceptance()
}

/// Capture immutable same-invocation release or terminal retention evidence.
pub(crate) fn capture_lifecycle() -> Result<()> {
    lifecycle::capture()
}
