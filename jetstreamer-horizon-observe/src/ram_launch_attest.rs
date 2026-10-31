//! Collect actual live RAM-supervisor/first-worker evidence onto durable disk.
//! Never starts, signals, retries, mounts, deletes or accesses remote storage.
use {
    crate::ram_artifact_retention::{Bound, bound_json, hash_file, properties},
    anyhow::{Context, Result, ensure},
    serde::Deserialize,
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    std::{
        env,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    },
};

const PROFILE: &str = "jetstreamer-private-epoch203-ram-bounded-runner-plan-v1";
const BASELINE: &str = "3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a";
const SHRINK: &str = "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc";
const PARENT: &str = "025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d";
const SNAPSHOT: &str = "e45584858d0c825f095a43ff5e5909e62a68d197d39c042a76727454525228c4";
const SETPRIV: &str = "c8521137671653eb5d520ddc3c5f9cbf3b4534c79d1b7b03506ce272d5727549";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    unit: String,
    invocation_id: String,
    run_root: PathBuf,
    worker_sha256: String,
    supervisor_binary: Bound,
    supervisor_plan: Bound,
    setpriv: Bound,
    first_worker: Bound,
    output: PathBuf,
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn binding(b: &Bound) -> Value {
    json!({"path":b.path,"sha256":b.sha256})
}
fn immutable(b: &Bound) -> Result<()> {
    ensure!(
        hex(&b.sha256, 64)
            && b.path.is_absolute()
            && b.path.canonicalize()? == b.path
            && b.path.starts_with("/var/lib/jetstreamer"),
        "unsealed executable scope"
    );
    let (sha, m) = hash_file(&b.path, 256 << 20)?;
    ensure!(
        sha == b.sha256 && m.uid() == 0 && m.mode() & 0o222 == 0,
        "mutable or mismatching executable"
    );
    Ok(())
}
fn validate_scope(p: &Plan, e: &Value) -> Result<&'static str> {
    let worker = p.worker_sha256.as_str();
    let family = match worker {
        BASELINE => "baseline",
        SHRINK => "shrink",
        _ => anyhow::bail!("unknown worker"),
    };
    ensure!(
        p.schema == "jetstreamer-private-epoch203-ram-launch-attest-plan-v1"
            && p.unit
                .starts_with(&format!("horizon-203-ram-resource-{family}-"))
            && p.unit.ends_with(".service")
            && p.unit.len() <= 255
            && p.unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            && hex(&p.invocation_id, 32),
        "invalid collector owner"
    );
    ensure!(
        p.run_root.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
            && p.run_root
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with(&format!("ram-resource-203-{family}-"))
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)))
            && p.first_worker.path == p.run_root.join("receipts/ram-guard-first-worker.json"),
        "wrong RAM evidence scope"
    );
    ensure!(
        p.supervisor_binary
            .path
            .file_name()
            .is_some_and(|s| s == "jetstreamer-epoch203-ram-resource")
            && p.setpriv.path.file_name().is_some_and(|s| s == "setpriv")
            && p.setpriv.sha256 == SETPRIV,
        "wrong supervisor or privilege drop"
    );
    ensure!(
        e["schema"] == "jetstreamer-private-epoch203-ram-supervisor-plan-v1"
            && e["runner"]["schema"] == PROFILE
            && e["runner"]["unit"] == p.unit
            && e["runner"]["run_root"].as_str() == p.run_root.to_str()
            && e["runner"]["target_slot"] == 87_720_000u64
            && e["runner"]["terminal_slot"] == 88_127_580u64
            && e["runner"]["node"]["sha256"] == PARENT
            && e["runner"]["snapshot"].as_str().is_some_and(|s| Path::new(s).is_absolute()
                && Path::new(s).file_name().is_some_and(|n| n=="snapshot-87695515-CYEr1vEwJyh2d4SSmnmYPYYj6EPhrDWTAJJCuzF2VhLX.tar.zst"))
            && e["runner"]["worker"].as_str().is_some_and(|s|Path::new(s).is_absolute())
            && e["runner"]["minimum_free_bytes"] == 575_472_100_463u64
            && e["runner"]["maximum_runtime_seconds"] == 21_600
            && hex(e["auxiliary_contract"]["sha256"].as_str().unwrap_or(""), 64),
        "supervisor envelope differs"
    );
    ensure!(
        p.output.file_name().is_some_and(|s| s == "launch.json")
            && p.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && p.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-203-ram-launch-")
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))),
        "output is not private durable launch metadata"
    );
    Ok(worker_family_digest(family))
}
fn worker_family_digest(family: &str) -> &'static str {
    if family == "baseline" {
        BASELINE
    } else {
        SHRINK
    }
}

fn validate_live(p: &Plan, unit: &std::collections::BTreeMap<String, String>) -> Result<u32> {
    for (key, value) in [
        ("Id", p.unit.as_str()),
        ("InvocationID", p.invocation_id.as_str()),
        ("LoadState", "loaded"),
        ("Type", "oneshot"),
        ("ActiveState", "activating"),
        ("SubState", "start"),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("User", "root"),
        ("Group", "root"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
    ] {
        ensure!(
            unit.get(key).map(String::as_str) == Some(value),
            "wrong live collector binding: {key}"
        );
    }
    let pid: u32 = unit.get("MainPID").context("PID absent")?.parse()?;
    ensure!(pid > 1, "no supervisor process");
    ensure!(
        unit.get("ControlGroup") == Some(&format!("/system.slice/{}", p.unit)),
        "wrong supervisor cgroup"
    );
    let prefix = format!(
        "{{ path={} ; argv[]={} --reuid=1000 --regid=1000 --clear-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs {} {} --plan-sha256 {} --self-sha256 {} ; ignore_errors=no ;",
        p.setpriv.path.display(),
        p.setpriv.path.display(),
        p.supervisor_binary.path.display(),
        p.supervisor_plan.path.display(),
        p.supervisor_plan.sha256,
        p.supervisor_binary.sha256
    );
    let command = unit.get("ExecStart").context("command absent")?;
    ensure!(
        command.starts_with(&prefix)
            && command.ends_with(" }")
            && command.matches("{ path=").count() == 1
            && !command.contains('\n')
            && !command.contains("--storage-capability"),
        "not the exact entry supervisor command"
    );
    Ok(pid)
}
fn validate_proof(p: &Plan, e: &Value, v: &Value, pid: u32, worker: &str, now: u64) -> Result<()> {
    let at = v["written_unix_seconds"]
        .as_u64()
        .context("proof time absent")?;
    ensure!(
        at <= now && now - at <= 120,
        "first-worker proof is stale/future"
    );
    ensure!(
        v["schema"] == "jetstreamer-private-epoch203-ram-guard-first-worker-v1"
            && v["unit"] == p.unit
            && v["invocation_id"] == p.invocation_id
            && v["supervisor_pid"] == pid
            && v["run_root"].as_str() == p.run_root.to_str()
            && v["node"] == e["runner"]["node"]["path"]
            && v["worker_sha256"] == worker
            && v["owned_process_census_verified"] == true
            && v["pre_target_worker_observed"] == true,
        "unbound guard first-worker proof"
    );
    let child = v["child_pid"].as_u64().context("child absent")?;
    let wp = v["worker_pid"].as_u64().context("worker absent")?;
    ensure!(
        child > 1
            && wp > 1
            && child != wp
            && child != u64::from(pid)
            && wp != u64::from(pid)
            && child <= i32::MAX as u64
            && wp <= i32::MAX as u64
            && v["worker_vmas"]
                .as_u64()
                .is_some_and(|n| (1..=500_000).contains(&n))
            && v["elapsed_millis"]
                .as_u64()
                .is_some_and(|n| n <= 21_600_000),
        "invalid guard process/VMA bound"
    );
    for key in [
        "grace_only",
        "draining",
        "guard_trip",
        "durable_root_copy_verified",
        "replay_launch_authorized",
        "full_cold_epoch_peak_qualified",
        "retirement_authorized",
        "runtime_promotion_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            v[key] == false,
            "guard proof grants authority or is not a positive fire: {key}"
        );
    }
    ensure!(
        v["host_available_bytes"]
            .as_u64()
            .is_some_and(|n| n >= 544u64 << 30)
            && v["tmpfs_available_bytes"]
                .as_u64()
                .is_some_and(|n| (231_874_716_783..=768u64 << 30).contains(&n)
                    && (768u64 << 30) - n <= 224u64 << 30)
            && v["memory_current_bytes"]
                .as_u64()
                .is_some_and(|n| n <= 320u64 << 30)
            && v["memory_limit_events"] == 0
            && v["archive_physical_bytes"]
                .as_u64()
                .is_some_and(|n| n <= 16u64 << 30),
        "guard sample violates envelope"
    );
    Ok(())
}
fn read_kernel(path: &Path, max: u64) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?
        .take(max + 1)
        .read_to_end(&mut b)?;
    ensure!(b.len() as u64 <= max, "kernel input exceeded bound");
    Ok(b)
}
fn process_stat(raw: &str) -> Result<(u32, u32, u64)> {
    let (_, tail) = raw.rsplit_once(')').context("bad process stat")?;
    let p: Vec<_> = tail.split_whitespace().collect();
    ensure!(
        p.len() >= 20 && !matches!(p[0], "Z" | "X" | "x"),
        "terminal process"
    );
    Ok((p[1].parse()?, p[2].parse()?, p[19].parse()?))
}
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    (
        a.dev(),
        a.ino(),
        a.len(),
        a.uid(),
        a.gid(),
        a.mode(),
        a.nlink(),
        a.mtime(),
        a.mtime_nsec(),
        a.ctime(),
        a.ctime_nsec(),
    ) == (
        b.dev(),
        b.ino(),
        b.len(),
        b.uid(),
        b.gid(),
        b.mode(),
        b.nlink(),
        b.mtime(),
        b.mtime_nsec(),
        b.ctime(),
        b.ctime_nsec(),
    )
}
fn live_process(pid: u32, path: &Path, unit: &str) -> Result<(u32, u32, u64)> {
    let root = Path::new("/proc").join(pid.to_string());
    let before = process_stat(std::str::from_utf8(&read_kernel(
        &root.join("stat"),
        65536,
    )?)?)?;
    ensure!(
        fs::read_link(root.join("exe"))? == path
            && same_file(
                &fs::metadata(root.join("exe"))?,
                &fs::symlink_metadata(path)?
            ),
        "live executable changed"
    );
    ensure!(
        std::str::from_utf8(&read_kernel(&root.join("cgroup"), 65536)?)?.trim()
            == format!("0::/system.slice/{unit}"),
        "process escaped owner cgroup"
    );
    ensure!(
        process_stat(std::str::from_utf8(&read_kernel(
            &root.join("stat"),
            65536
        )?)?)?
            == before,
        "process changed during proof"
    );
    Ok(before)
}
fn raw_proof(p: &Plan) -> Result<(Value, Vec<u8>)> {
    let root = fs::symlink_metadata(&p.run_root)?;
    ensure!(
        p.run_root.canonicalize()? == p.run_root
            && root.is_dir()
            && root.uid() == 1000
            && root.gid() == 1000
            && root.mode() & 0o7777 == 0o700,
        "unsafe RAM root"
    );
    let (sha, m) = hash_file(&p.first_worker.path, 65536)?;
    ensure!(
        sha == p.first_worker.sha256
            && m.uid() == 1000
            && m.gid() == 1000
            && m.mode() & 0o7777 == 0o400
            && m.dev() == root.dev()
            && p.first_worker.path.canonicalize()? == p.first_worker.path,
        "unsafe guard first-worker file"
    );
    let b = read_kernel(&p.first_worker.path, 65536)?;
    ensure!(
        format!("{:x}", Sha256::digest(&b)) == sha
            && hash_file(&p.first_worker.path, 65536)?.0 == sha,
        "guard proof changed"
    );
    let v: Value = serde_json::from_slice(&b)?;
    ensure!(
        v["root_device"] == root.dev() && v["root_inode"] == root.ino(),
        "RAM root replaced"
    );
    Ok((v, b))
}
fn persistent_storage(p: &Plan, e: &Value) -> Result<Value> {
    let sandbox = &e["sandbox"];
    ensure!(
        sandbox["unit"] == p.unit && sandbox["run_root"].as_str() == p.run_root.to_str(),
        "sandbox scope differs"
    );
    let unit = sandbox["mount_unit"]
        .as_str()
        .context("mount unit missing")?;
    ensure!(
        unit.ends_with(".mount")
            && unit.len() <= 255
            && unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.\\".contains(&b)),
        "invalid mount unit"
    );
    let mount = properties(
        unit,
        "Id,InvocationID,ActiveState,SubState,Type,Where,What,StopWhenUnneeded,BindsTo,PartOf",
    )?;
    for (key, want) in [
        ("Id", unit),
        (
            "InvocationID",
            sandbox["mount_invocation_id"]
                .as_str()
                .context("mount invocation missing")?,
        ),
        ("ActiveState", "active"),
        ("SubState", "mounted"),
        ("Type", "tmpfs"),
        ("What", "tmpfs"),
        ("Where", p.run_root.to_str().context("root UTF8")?),
        ("StopWhenUnneeded", "no"),
        ("BindsTo", ""),
        ("PartOf", ""),
    ] {
        ensure!(
            mount.get(key).map(String::as_str) == Some(want),
            "persistent mount differs: {key}"
        );
    }
    let m = fs::symlink_metadata(&p.run_root)?;
    ensure!(
        sandbox["mount_device"] == json!([libc::major(m.dev()), libc::minor(m.dev())]),
        "mount device differs"
    );
    let path = std::ffi::CString::new(p.run_root.as_os_str().as_encoded_bytes())?;
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    let mut v: libc::statvfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::statfs(path.as_ptr(), &mut s) } == 0
            && s.f_type == 0x01021994
            && unsafe { libc::statvfs(path.as_ptr(), &mut v) } == 0
            && v.f_blocks.checked_mul(v.f_frsize) == Some(768u64 << 30),
        "not the bounded persistent tmpfs"
    );
    Ok(serde_json::to_value(mount)?)
}

fn persist(path: &Path, result: &Value) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let parent = path.parent().context("output parent")?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    serde_json::to_writer_pretty(tmp.as_file_mut(), result)?;
    tmp.write_all(b"\n")?;
    tmp.as_file().sync_all()?;
    tmp.persist_noclobber(path)
        .map_err(|e| anyhow::anyhow!("refusing occupied output: {e}"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
pub fn run() -> Result<()> {
    let a: Vec<_> = env::args().collect();
    ensure!(
        a.len() == 6 && a[2] == "--plan-sha256" && a[4] == "--self-sha256",
        "usage: jetstreamer-epoch203-ram-launch-attest PLAN --plan-sha256 HEX --self-sha256 HEX"
    );
    ensure!(unsafe { libc::geteuid() } == 0, "collector requires root");
    immutable(&Bound {
        path: fs::read_link("/proc/self/exe")?,
        sha256: a[5].clone(),
    })?;
    let pb = Bound {
        path: a[1].clone().into(),
        sha256: a[3].clone(),
    };
    let p: Plan = serde_json::from_value(bound_json(&pb)?)?;
    let e = bound_json(&p.supervisor_plan)?;
    let worker = validate_scope(&p, &e)?;
    immutable(&p.supervisor_binary)?;
    immutable(&p.setpriv)?;
    let parent = p.output.parent().context("output parent")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o7777 == 0o700
            && !p.output.try_exists()?,
        "unsafe or occupied durable output"
    );
    let props = "Id,InvocationID,LoadState,Type,ActiveState,SubState,NRestarts,Restart,User,Group,KillMode,Delegate,MainPID,ControlGroup,ExecStart";
    let before = properties(&p.unit, props)?;
    let pid = validate_live(&p, &before)?;
    let mount = persistent_storage(&p, &e)?;
    let (v, raw) = raw_proof(&p)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    validate_proof(&p, &e, &v, pid, worker, now)?;
    let child: u32 = v["child_pid"].as_u64().context("child")?.try_into()?;
    let wp: u32 = v["worker_pid"].as_u64().context("worker")?.try_into()?;
    let node = PathBuf::from(e["runner"]["node"]["path"].as_str().context("node path")?);
    let worker_path = PathBuf::from(v["worker_executable"].as_str().context("worker path")?);
    ensure!(
        worker_path.starts_with(p.run_root.join("scratch"))
            && worker_path
                .file_name()
                .is_some_and(|s| s == "historical-worker"),
        "worker path differs"
    );
    let node_bound = Bound {
        path: node.clone(),
        sha256: PARENT.into(),
    };
    immutable(&node_bound)?;
    let source_worker = Bound {
        path: e["runner"]["worker"]
            .as_str()
            .context("worker input missing")?
            .into(),
        sha256: worker.into(),
    };
    immutable(&source_worker)?;
    let (actual, wm) = hash_file(&worker_path, 256 << 20)?;
    ensure!(
        actual == worker
            && wm.uid() == 1000
            && worker_path.canonicalize()? == worker_path
            && v["worker_file_identity"]
                == json!([
                    wm.dev(),
                    wm.ino(),
                    wm.len(),
                    wm.uid(),
                    wm.mode(),
                    wm.nlink(),
                    wm.mtime(),
                    wm.mtime_nsec(),
                    wm.ctime(),
                    wm.ctime_nsec()
                ]),
        "worker digest differs"
    );
    let supervisor = live_process(pid, &p.supervisor_binary.path, &p.unit)?;
    let node_process = live_process(child, &node, &p.unit)?;
    let worker_process = live_process(wp, &worker_path, &p.unit)?;
    for owned in [pid, child, wp] {
        crate::ram_replay_sandbox::validate_process_status(std::str::from_utf8(&read_kernel(
            &Path::new("/proc").join(owned.to_string()).join("status"),
            65536,
        )?)?)?;
    }
    ensure!(
        node_process.0 == pid && node_process.1 == child && worker_process.1 == child,
        "process ownership/group differs"
    );
    let expected_argv = [
        p.supervisor_binary.path.display().to_string(),
        p.supervisor_plan.path.display().to_string(),
        "--plan-sha256".into(),
        p.supervisor_plan.sha256.clone(),
        "--self-sha256".into(),
        p.supervisor_binary.sha256.clone(),
    ]
    .join("\0")
        + "\0";
    ensure!(
        read_kernel(
            &Path::new("/proc").join(pid.to_string()).join("cmdline"),
            65536
        )? == expected_argv.as_bytes(),
        "supervisor argv differs"
    );
    ensure!(
        properties(&p.unit, props)? == before
            && persistent_storage(&p, &e)? == mount
            && raw_proof(&p)?.1 == raw
            && live_process(pid, &p.supervisor_binary.path, &p.unit)? == supervisor
            && live_process(child, &node, &p.unit)? == node_process
            && live_process(wp, &worker_path, &p.unit)? == worker_process
            && same_file(&wm, &fs::symlink_metadata(&worker_path)?),
        "owner changed during collection"
    );
    let committed_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    validate_proof(&p, &e, &v, pid, worker, committed_at)?;
    let result = json!({"schema":"jetstreamer-private-epoch203-ram-resource-launch-v1","launched":true,"simulated":false,
        "epoch":203,"unit":p.unit,"invocation_id":p.invocation_id,"private_run_root":p.run_root,
        "supervisor_profile":PROFILE,"worker_sha256":worker,"parent_sha256":PARENT,"snapshot_sha256":SNAPSHOT,
        "target_slot":87720000,"terminal_root_slot":88127580,"solana_rayon_threads":16,
        "filesystem_backend":"persistent-tmpfs","root_archive_scratch_increment_bytes":0,
        "maximum_entry_replays":4,"maximum_auxiliary_diagnostics":1,
        "supervisor_binary":binding(&p.supervisor_binary),"supervisor_plan":binding(&p.supervisor_plan),"setpriv":binding(&p.setpriv),
        "supervisor_sha256":p.supervisor_binary.sha256,"plan_sha256":p.supervisor_plan.sha256,
        "auxiliary_contract_sha256":e["auxiliary_contract"]["sha256"],"expected_exec_start":before["ExecStart"],
        "first_worker_proof":binding(&p.first_worker),"retained_first_worker":v,
        "collector_sha256":a[5],"collector_plan":binding(&pb),"written_unix_seconds":committed_at,"persistent_mount":mount,
        "ordinary_replay_authorized":false,"full_cold_epoch_peak_qualified":false,"runtime_promotion_authorized":false,
        "canonical_sidecar_authorized":false,"publication_authorized":false,"retirement_authorized":false,
        "remote_mutations":false,"r2_mutations":false});
    persist(&p.output, &result)?;
    println!("{}", p.output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Policy fixtures only. No services are started; no fixture is operational
    // launch, guard, admission or capability evidence.
    fn fixture() -> (Plan, Value, Value) {
        let b = |name: &str| Bound {
            path: format!("/var/lib/jetstreamer/tools/{name}").into(),
            sha256: "a".repeat(64),
        };
        let root =
            PathBuf::from("/home/ubuntu/.jetstreamer-private/ram-resource-203-baseline-test");
        let mut p = Plan {
            schema: "jetstreamer-private-epoch203-ram-launch-attest-plan-v1".into(),
            unit: "horizon-203-ram-resource-baseline-test.service".into(),
            invocation_id: "b".repeat(32),
            run_root: root.clone(),
            worker_sha256: BASELINE.into(),
            supervisor_binary: b("jetstreamer-epoch203-ram-resource"),
            supervisor_plan: b("plan.json"),
            setpriv: b("setpriv"),
            first_worker: Bound {
                path: root.join("receipts/ram-guard-first-worker.json"),
                sha256: "c".repeat(64),
            },
            output: "/var/lib/jetstreamer/horizon-203-ram-launch-test/launch.json".into(),
        };
        p.setpriv.sha256 = SETPRIV.into();
        let e = json!({"schema":"jetstreamer-private-epoch203-ram-supervisor-plan-v1","runner":{
            "schema":PROFILE,"unit":p.unit,"run_root":root,"worker":"/var/lib/jetstreamer/tools/worker",
            "snapshot":"/var/lib/jetstreamer/tools/snapshot-87695515-CYEr1vEwJyh2d4SSmnmYPYYj6EPhrDWTAJJCuzF2VhLX.tar.zst",
            "node":{"path":"/var/lib/jetstreamer/tools/node","sha256":PARENT},
            "target_slot":87720000,"terminal_slot":88127580,"minimum_free_bytes":575472100463u64,"maximum_runtime_seconds":21600},
            "auxiliary_contract":{"sha256":"d".repeat(64)}});
        let v = json!({"schema":"jetstreamer-private-epoch203-ram-guard-first-worker-v1",
            "unit":p.unit,"invocation_id":p.invocation_id,"supervisor_pid":42,"run_root":root,
            "node":e["runner"]["node"]["path"],"worker_sha256":BASELINE,
            "owned_process_census_verified":true,"pre_target_worker_observed":true,
            "written_unix_seconds":1000,"child_pid":43,"worker_pid":44,"worker_vmas":10,"elapsed_millis":10000,
            "grace_only":false,"draining":false,"guard_trip":false,"durable_root_copy_verified":false,
            "replay_launch_authorized":false,"full_cold_epoch_peak_qualified":false,"retirement_authorized":false,
            "runtime_promotion_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false,
            "host_available_bytes":544u64<<30,"tmpfs_available_bytes":768u64<<30,
            "memory_current_bytes":320u64<<30,"memory_limit_events":0,"archive_physical_bytes":16u64<<30});
        (p, e, v)
    }
    #[test]
    fn scope_uses_real_runner_string_inputs_and_keeps_exact_family_epoch_and_output() {
        let (mut p, e, _) = fixture();
        assert_eq!(validate_scope(&p, &e).unwrap(), BASELINE);
        for (field, value) in [
            ("target_slot", json!(87720001)),
            ("terminal_slot", json!(88127581)),
            ("snapshot", json!("/wrong/snapshot.tar.zst")),
            ("worker", json!({"sha256":BASELINE})),
            ("minimum_free_bytes", json!(1)),
            ("maximum_runtime_seconds", json!(86400)),
        ] {
            let mut wrong = e.clone();
            wrong["runner"][field] = value;
            assert!(validate_scope(&p, &wrong).is_err(), "{field}");
        }
        p.worker_sha256 = SHRINK.into();
        assert!(validate_scope(&p, &e).is_err());
        p.worker_sha256 = BASELINE.into();
        p.output = "/home/ubuntu/horizon/epoch-203.jet.sha256".into();
        assert!(validate_scope(&p, &e).is_err());
    }
    #[test]
    fn live_owner_is_an_exact_entry_command_not_a_capability_or_queued_unit() {
        let (p, _, _) = fixture();
        let command = format!(
            "{{ path={} ; argv[]={} --reuid=1000 --regid=1000 --clear-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs {} {} --plan-sha256 {} --self-sha256 {} ; ignore_errors=no ; }}",
            p.setpriv.path.display(),
            p.setpriv.path.display(),
            p.supervisor_binary.path.display(),
            p.supervisor_plan.path.display(),
            p.supervisor_plan.sha256,
            p.supervisor_binary.sha256
        );
        let unit = std::collections::BTreeMap::from([
            ("Id".into(), p.unit.clone()),
            ("InvocationID".into(), p.invocation_id.clone()),
            ("LoadState".into(), "loaded".into()),
            ("Type".into(), "oneshot".into()),
            ("ActiveState".into(), "activating".into()),
            ("SubState".into(), "start".into()),
            ("NRestarts".into(), "0".into()),
            ("Restart".into(), "no".into()),
            ("User".into(), "root".into()),
            ("Group".into(), "root".into()),
            ("KillMode".into(), "control-group".into()),
            ("Delegate".into(), "no".into()),
            ("MainPID".into(), "42".into()),
            ("ControlGroup".into(), format!("/system.slice/{}", p.unit)),
            ("ExecStart".into(), command.clone()),
        ]);
        assert_eq!(validate_live(&p, &unit).unwrap(), 42);
        for (key, value) in [
            ("MainPID", "0"),
            ("Type", "simple"),
            ("SubState", "start-pre"),
            ("NRestarts", "1"),
            ("ActiveState", "inactive"),
            ("InvocationID", "replacement"),
        ] {
            let mut wrong = unit.clone();
            wrong.insert(key.into(), value.into());
            assert!(validate_live(&p, &wrong).is_err(), "{key}");
        }
        let mut wrong = unit;
        wrong.insert(
            "ExecStart".into(),
            command.replace(" ; ignore_errors", " --storage-capability ; ignore_errors"),
        );
        assert!(validate_live(&p, &wrong).is_err());
    }
    #[test]
    fn only_fresh_positive_nonmutating_bounded_worker_proof_is_accepted() {
        let (p, e, v) = fixture();
        validate_proof(&p, &e, &v, 42, BASELINE, 1120).unwrap();
        assert!(validate_proof(&p, &e, &v, 42, BASELINE, 1121).is_err());
        assert!(validate_proof(&p, &e, &v, 42, BASELINE, 999).is_err());
        for (key, value) in [
            ("worker_vmas", json!(0)),
            ("worker_pid", json!(43)),
            ("supervisor_pid", json!(45)),
            ("grace_only", json!(true)),
            ("draining", json!(true)),
            ("guard_trip", json!(true)),
            ("publication_authorized", json!(true)),
            ("host_available_bytes", json!((544u64 << 30) - 1)),
            ("memory_limit_events", json!(1)),
            ("tmpfs_available_bytes", json!(231874716782u64)),
            ("memory_current_bytes", json!((320u64 << 30) + 1)),
        ] {
            let mut wrong = v.clone();
            wrong[key] = value;
            assert!(
                validate_proof(&p, &e, &wrong, 42, BASELINE, 1100).is_err(),
                "{key}"
            );
        }
    }
    #[test]
    fn process_stat_binds_start_ticks_and_rejects_terminal_or_truncated_processes() {
        let mut fields = vec!["0"; 20];
        fields[0] = "S";
        fields[1] = "42";
        fields[2] = "43";
        fields[19] = "123456";
        let raw = format!("44 (worker(a)b) {}", fields.join(" "));
        assert_eq!(process_stat(&raw).unwrap(), (42, 43, 123456));
        assert!(process_stat(&raw.replace(") S ", ") Z ")).is_err());
        assert!(process_stat("44 (broken) S 42 43").is_err());
    }
    #[test]
    fn durable_publication_is_private_atomic_and_never_overwrites() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("launch.json");
        persist(&path, &json!({"fixture_only":true})).unwrap();
        let bytes = fs::read(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o400);
        assert!(persist(&path, &json!({"replacement":true})).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }
}
