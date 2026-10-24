//! Exact 203 preparation/read capability/live capture; never a replay launcher.
use super::continuation203 as c;
use super::*;
use std::os::unix::{
    fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    io::AsRawFd,
};

const STATE: &str = "/var/lib/jetstreamer/horizon-continuation203-launch-state-ed66145-v1";
const CAP_ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/continuation203-input-capability-ed66145-v1";
const LEASE: &str = "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-203.lock";
const PREFIX: &str = "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-203-f9fc5a0-v1/output/epoch-203-prefix.jet";
const MANIFEST: &str =
    "/var/lib/jetstreamer/horizon-prefix203-terminal-independent-evidence-v1/manifest.json";
const NATIVE: &str = "/var/lib/jetstreamer/horizon-continuation203-parent-ed66145-v1/native.json";
const SNAPSHOT: &str = "/var/lib/jetstreamer/horizon-focused-204-complete-span-store8-ca2e38b-v1/snapshot-88127580-4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf.tar.zst";
const GENESIS: &str =
    "/var/lib/jetstreamer/horizon-focused-204-complete-span-store8-ca2e38b-v1/genesis.tar.bz2";
const MANIFEST_SHA: &str = "983ecabfc9c36e261a66641b8a039e5e1834198b0c9a07552db38457e67e5722";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";

fn sealed_self(hash: &str, uid: libc::uid_t) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == uid,
        "203 operation has wrong UID"
    );
    let path = fs::read_link("/proc/self/exe")?;
    let m = fs::symlink_metadata(&path)?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == hash,
        "203 operation helper is unsealed"
    );
    Ok(())
}
fn owned_directory(path: &Path, uid: u32) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && m.is_dir()
            && m.uid() == uid
            && m.gid() == uid
            && m.mode() & 0o777 == 0o700,
        "203 directory owner/mode/identity differs:{}",
        path.display()
    );
    Ok(())
}
fn create_owned_directory(path: &Path, uid: u32) -> Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {
            let f = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(path)?;
            f.set_permissions(fs::Permissions::from_mode(0o700))?;
            ensure!(
                unsafe { libc::fchown(f.as_raw_fd(), uid, uid) } == 0,
                "203 directory chown failed"
            );
            f.sync_all()?;
            File::open(path.parent().context("203 directory parent")?)?.sync_all()?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    owned_directory(path, uid)
}
fn owner_idle(v: &Value) -> Result<()> {
    ensure!(
        v["Id"] == c::UNIT
            && v["MainPID"] == "0"
            && v["NRestarts"] == "0"
            && v["ActiveState"] == "inactive"
            && v["SubState"] == "dead"
            && v["ExecMainStatus"] == "0"
            && v["Result"] == "success",
        "203 prepared owner already live/failed; preserve its work"
    );
    Ok(())
}
pub(super) fn layout() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 4 && args[2] == "--self-sha256",
        "usage: prepare-continuation203-layout --self-sha256 SHA"
    );
    sealed_self(&args[3], 0)?;
    create_owned_directory(Path::new(STATE), 0)?;
    let output = Path::new(STATE).join("layout.json");
    validate_output_destination(&output)?;
    let before = unit(c::UNIT)?;
    owner_idle(&before)?;
    owned_directory(
        Path::new(c::ROOT).parent().context("203 private parent")?,
        1000,
    )?;
    for path in [c::ROOT, CAP_ROOT] {
        create_owned_directory(Path::new(path), 1000)?;
        ensure!(
            fs::read_dir(path)?.next().is_none(),
            "203 preparation found retained work; do not truncate:{path}"
        );
    }
    let lease = match fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(LEASE)
    {
        Ok(f) => {
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
            ensure!(
                unsafe { libc::fchown(f.as_raw_fd(), 1000, 1000) } == 0,
                "203 lease chown failed"
            );
            f.sync_all()?;
            File::open(Path::new(LEASE).parent().unwrap())?.sync_all()?;
            f
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(LEASE)?,
        Err(e) => return Err(e.into()),
    };
    let lm = lease.metadata()?;
    ensure!(
        Path::new(LEASE).canonicalize()? == Path::new(LEASE)
            && lm.is_file()
            && lm.nlink() == 1
            && lm.len() == 0
            && lm.uid() == 1000
            && lm.gid() == 1000
            && lm.mode() & 0o777 == 0o600
            && unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "203 lease occupied/unsafe"
    );
    ensure!(
        unit(c::UNIT)? == before,
        "203 owner changed during preparation"
    );
    let rm = fs::symlink_metadata(c::ROOT)?;
    private157::immutable_receipt(
        &output,
        &json!({"schema":"jetstreamer-private203-layout-v1","root":c::ROOT,
        "root_device":rm.dev(),"root_inode":rm.ino(),"lease":LEASE,"lease_device":lm.dev(),"lease_inode":lm.ino(),
        "capability_root":CAP_ROOT,"uid":1000,"gid":1000,"helper_sha256":args[3],"owner":before,
        "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    )?;
    println!(
        "203 empty private root, capability directory and lease prepared; no admission/launch"
    );
    Ok(())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    schema: String,
    node: BoundFile,
    prefix_archive: BoundFile,
    prefix_manifest: BoundFile,
    native_probe: BoundFile,
    restart_snapshot: BoundFile,
    worker: BoundFile,
    genesis_archive: BoundFile,
    output: PathBuf,
}
fn inputs(s: &Inputs) -> Result<()> {
    ensure!(
        s.schema == "jetstreamer-private203-input-capability-spec-v1"
            && s.output == Path::new(CAP_ROOT).join("capability.json"),
        "203 foreign input capability"
    );
    for (b, path, hash) in [
        (&s.node, c::NODE, c::NODE_SHA),
        (&s.prefix_archive, PREFIX, c::PREFIX_SHA),
        (&s.prefix_manifest, MANIFEST, MANIFEST_SHA),
        (&s.native_probe, NATIVE, c::NATIVE_SHA),
        (&s.restart_snapshot, SNAPSHOT, c::SNAPSHOT_SHA),
        (&s.worker, c::WORKER, c::WORKER_SHA),
        (&s.genesis_archive, GENESIS, GENESIS_SHA),
    ] {
        ensure!(
            b.path == Path::new(path) && b.sha256 == hash,
            "203 exact capability input differs:{path}"
        );
    }
    Ok(())
}
fn measure(b: &BoundFile, size: Option<u64>) -> Result<Value> {
    ensure!(
        b.path.is_absolute() && b.path.canonicalize()? == b.path,
        "203 capability input is not canonical"
    );
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&b.path)?;
    let m = file.metadata()?;
    let before = identity(&m);
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && [0, 1000].contains(&m.uid())
            && m.mode() & 0o022 == 0
            && size.is_none_or(|n| n == m.len())
            && (size.is_some() || m.len() <= 256 << 20),
        "203 capability file metadata differs"
    );
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut n = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
        n = n.checked_add(read as u64).context("203 read overflow")?;
    }
    ensure!(
        n == before.length
            && hex_lower(&hash.finalize()) == b.sha256
            && identity(&file.metadata()?) == before
            && regular_identity(&b.path)? == before,
        "203 capability source changed/hash mismatch"
    );
    Ok(
        json!({"path":b.path,"sha256":b.sha256,"device":before.device,"inode":before.inode,"bytes":before.length,
        "modified_seconds":before.modified_seconds,"modified_nanoseconds":before.modified_nanoseconds,"opened_and_fully_hashed_as_uid":1000}),
    )
}
fn user_receipt(path: &Path, v: &Value) -> Result<()> {
    ensure!(
        path == Path::new(CAP_ROOT).join("capability.json"),
        "203 wrong user receipt"
    );
    let parent = path.parent().unwrap();
    owned_directory(parent, 1000)?;
    ensure!(
        !path.try_exists()?,
        "203 capability output exists; preserve evidence"
    );
    let mut t = tempfile::NamedTempFile::new_in(parent)?;
    t.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    serde_json::to_writer_pretty(t.as_file_mut(), v)?;
    t.write_all(b"\n")?;
    t.as_file().sync_all()?;
    t.persist_noclobber(path)
        .map_err(|e| anyhow!("203 capability receipt exists:{e}"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn spec_binding(args: &[String]) -> Result<BoundFile> {
    ensure!(
        args.len() == 7 && args[3] == "--spec-sha256" && args[5] == "--self-sha256",
        "203 operation requires bound spec and self SHA"
    );
    let b = BoundFile {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && b.path.canonicalize()? == b.path,
        "203 operation specification is not sealed"
    );
    Ok(b)
}
pub(super) fn capability() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    let b = spec_binding(&args)?;
    sealed_self(&args[6], 1000)?;
    let s: Inputs = serde_json::from_value(bound_json(&b)?)?;
    inputs(&s)?;
    owned_directory(Path::new(CAP_ROOT), 1000)?;
    ensure!(
        !s.output.try_exists()?,
        "203 capability receipt already exists"
    );
    let mut files = serde_json::Map::new();
    for (key, input, size) in [
        ("node", &s.node, None),
        ("prefix_archive", &s.prefix_archive, Some(103_781_283_604)),
        ("prefix_manifest", &s.prefix_manifest, None),
        ("native_probe", &s.native_probe, None),
        ("restart_snapshot", &s.restart_snapshot, Some(8_215_471_895)),
        ("worker", &s.worker, None),
        ("genesis_archive", &s.genesis_archive, None),
    ] {
        files.insert(key.into(), measure(input, size)?);
    }
    user_receipt(
        &s.output,
        &json!({"schema":"jetstreamer-private203-input-capability-v1","epoch":203,"passed":true,
        "uid":1000,"helper_sha256":args[6],"input_spec":private157::binding(&b),"inputs":s,"files":files,
        "whole_files_independently_hashed":true,"independent_archive_decoder_verified":false,
        "parent_must_repeat_complete_prefix_and_native_checks":true,"worker_spawned":false,"snapshot_copied":false,
        "native_bank_restored":false,"replay_entries_sent":0,"private_source_permissions_changed":false,
        "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    )?;
    println!(
        "203 exact inputs fully hashed/readable as UID 1000; no worker/replay/launch authority"
    );
    Ok(())
}
fn capability_matches(p: &Value, v: &Value, helper: &str) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-private203-input-capability-v1"
            && v["epoch"] == 203
            && v["passed"] == true
            && v["uid"] == 1000
            && v["helper_sha256"] == helper
            && v["whole_files_independently_hashed"] == true
            && v["parent_must_repeat_complete_prefix_and_native_checks"] == true
            && v["independent_archive_decoder_verified"] == false
            && v["worker_spawned"] == false
            && v["native_bank_restored"] == false
            && v["replay_entries_sent"] == 0
            && v["replay_launch_authorized"] == false
            && v["publication_authorized"] == false
            && v["r2_mutations"] == false,
        "203 input capability grants authority or belongs to another helper"
    );
    for k in [
        "prefix_archive",
        "prefix_manifest",
        "native_probe",
        "restart_snapshot",
        "worker",
        "genesis_archive",
    ] {
        ensure!(
            v["inputs"][k] == p[k]
                && v["files"][k]["sha256"] == p[k]["sha256"]
                && v["files"][k]["path"] == p[k]["path"]
                && v["files"][k]["opened_and_fully_hashed_as_uid"] == 1000,
            "203 plan differs from capability:{k}"
        );
    }
    ensure!(
        v["inputs"]["node"]["path"] == c::NODE && v["inputs"]["node"]["sha256"] == c::NODE_SHA,
        "203 capability parent differs"
    );
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureSpec {
    schema: String,
    continuation_plan: BoundFile,
    admission: BoundFile,
    observer: BoundFile,
    previous_fleet: BoundFile,
    capability: BoundFile,
    layout: BoundFile,
}
pub(super) fn capture() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    let sb = spec_binding(&args)?;
    sealed_self(&args[6], 0)?;
    owned_directory(Path::new(STATE), 0)?;
    let s: CaptureSpec = serde_json::from_value(bound_json(&sb)?)?;
    ensure!(
        s.schema == "jetstreamer-private203-launch-capture-spec-v1"
            && s.continuation_plan.path == Path::new(c::PLAN)
            && s.capability.path == Path::new(CAP_ROOT).join("capability.json")
            && s.layout.path == Path::new(STATE).join("layout.json"),
        "203 wrong launch capture scope"
    );
    let p = bound_json(&s.continuation_plan)?;
    let a = bound_json(&s.admission)?;
    let cap = bound_json(&s.capability)?;
    capability_matches(&p, &cap, &args[6])?;
    let cm = fs::symlink_metadata(&s.capability.path)?;
    ensure!(
        cm.is_file()
            && cm.uid() == 1000
            && cm.gid() == 1000
            && cm.nlink() == 1
            && cm.mode() & 0o777 == 0o400,
        "203 capability custody changed"
    );
    let layout = bound_json(&s.layout)?;
    let rm = fs::symlink_metadata(c::ROOT)?;
    let lm = fs::symlink_metadata(LEASE)?;
    ensure!(
        layout["schema"] == "jetstreamer-private203-layout-v1"
            && layout["root"] == c::ROOT
            && layout["root_device"] == rm.dev()
            && layout["root_inode"] == rm.ino()
            && layout["helper_sha256"] == args[6]
            && layout["lease"] == LEASE
            && layout["lease_device"] == lm.dev()
            && layout["lease_inode"] == lm.ino()
            && lm.is_file()
            && lm.nlink() == 1
            && lm.len() == 0
            && lm.uid() == 1000
            && lm.gid() == 1000
            && lm.mode() & 0o777 == 0o600
            && rm.uid() == 1000
            && rm.mode() & 0o777 == 0o700,
        "203 root changed since prepared layout"
    );
    let o = bound_json(&s.observer)?;
    let f = bound_json(&s.previous_fleet)?;
    ensure!(
        a["observer"] == private157::binding(&s.observer)
            && a["fleet"] == private157::binding(&s.previous_fleet)
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && f["observer_sha256"] == s.observer.sha256
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300,
        "203 capture predecessor differs"
    );
    let before = unit(c::UNIT)?;
    let iid = before["InvocationID"]
        .as_str()
        .context("203 producer IID")?;
    ensure!(
        before["Type"] == "exec"
            && before["ActiveState"] == "active"
            && before["SubState"] == "running"
            && before["NRestarts"] == "0"
            && before["MainPID"]
                .as_str()
                .is_some_and(|s| s.parse::<u32>().is_ok_and(|p| p > 0)),
        "203 capture producer is not exactly live"
    );
    let output = Path::new(STATE).join("launch.json");
    validate_output_destination(&output)?;
    let claim = DiagnosticClaim {
        epoch: 203,
        unit: c::UNIT.into(),
        invocation_id: iid.into(),
        scratch_path: c::ROOT.into(),
        launch_receipt: BoundFile {
            path: output.clone(),
            sha256: "0".repeat(64),
        },
    };
    let mut r = json!({"schema":c::SCHEMA,"epoch":203,"unit":c::UNIT,"invocation_id":iid,"launched":true,
        "node_sha256":c::NODE_SHA,"worker_sha256":c::WORKER_SHA,"snapshot_sha256":c::SNAPSHOT_SHA,
        "prefix_sha256":c::PREFIX_SHA,"native_result_sha256":c::NATIVE_SHA,"private_run_root":c::ROOT,
        "bootstrap_slot":88127580,"suffix_start_slot":88127581,"terminal_slot":88127999,"remaining_slots":419,
        "maximum_runtime_seconds":10800,"maximum_memory_bytes":128u64<<30,"maximum_cpu_percent":800,"solana_rayon_threads":16,
        "experimental_envelope_bytes":c::PEAK,"protected_existing_floor_bytes":a["protected_existing_floor_bytes"],
        "required_initial_free_bytes":p["minimum_free_bytes"],"required_guard_minimum_free_bytes":a["required_guard_minimum_free_bytes"],
        "private_suffix_authorized":true,"private_assembly_authorized":true,"continuation_plan":private157::binding(&s.continuation_plan),
        "admission":private157::binding(&s.admission),"observer":private157::binding(&s.observer),
        "previous_fleet":private157::binding(&s.previous_fleet),"capability":private157::binding(&s.capability),
        "layout":private157::binding(&s.layout),"capture_spec":private157::binding(&sb),"capture_self_sha256":args[6],
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"expected_exec_start":before["ExecStart"]});
    for key in c::NO_AUTHORITY {
        r[*key] = json!(false);
    }
    c::launch(&r, &claim)?;
    c::live_limits()?;
    ensure!(unit(c::UNIT)? == before, "203 owner changed during capture");
    private157::immutable_receipt(&output, &r)?;
    let guard_source = Path::new(STATE).join("guard-plan.json");
    private157::immutable_receipt(
        &guard_source,
        &json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1",
        "unit":c::UNIT,"invocation_id":iid,"filesystem":"/","minimum_free_bytes":a["required_guard_minimum_free_bytes"],
        "worker_root":c::ROOT,"maximum_worker_vmas":3500000,
        "receipt_directory":"/var/lib/jetstreamer/horizon-continuation203-guard-receipts-ed66145-v1"}),
    )?;
    let gb = private157::file_binding(&guard_source)?;
    private157::immutable_receipt(
        &Path::new(STATE).join("guard-seal-plan.json"),
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1",
        "destination":"/var/lib/jetstreamer/horizon-continuation203-guard-ed66145-v1",
        "members":[{"source":guard_source,"name":"guard-plan.json","sha256":gb["sha256"],"mode":256}]}),
    )?;
    println!(
        "203 live owner captured; seal guard and prove real-worker first fire before leaving unattended"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Inputs {
        let b = |p: &str, h: &str| BoundFile {
            path: p.into(),
            sha256: h.into(),
        };
        Inputs {
            schema: "jetstreamer-private203-input-capability-spec-v1".into(),
            node: b(c::NODE, c::NODE_SHA),
            prefix_archive: b(PREFIX, c::PREFIX_SHA),
            prefix_manifest: b(MANIFEST, MANIFEST_SHA),
            native_probe: b(NATIVE, c::NATIVE_SHA),
            restart_snapshot: b(SNAPSHOT, c::SNAPSHOT_SHA),
            worker: b(c::WORKER, c::WORKER_SHA),
            genesis_archive: b(GENESIS, GENESIS_SHA),
            output: Path::new(CAP_ROOT).join("capability.json"),
        }
    }
    #[test]
    fn input_capability_cannot_target_another_epoch_or_output() {
        let s = fixture();
        inputs(&s).unwrap();
        let mut v = serde_json::to_value(&s).unwrap();
        v["publication_authorized"] = json!(true);
        assert!(serde_json::from_value::<Inputs>(v).is_err());
        let mut s = fixture();
        s.worker.sha256 = "f".repeat(64);
        assert!(inputs(&s).is_err());
        let mut s = fixture();
        s.output = Path::new(c::ROOT).join("epoch-203.jet");
        assert!(inputs(&s).is_err());
        let mut s = fixture();
        s.prefix_archive.path = "/other-prefix.jet".into();
        assert!(inputs(&s).is_err());
    }
    #[test]
    fn preparation_never_reuses_live_failed_or_restarted_owner() {
        let v = json!({"Id":c::UNIT,"MainPID":"0","NRestarts":"0","ActiveState":"inactive","SubState":"dead",
            "ExecMainStatus":"0","Result":"success"});
        owner_idle(&v).unwrap();
        for k in [
            "Id",
            "MainPID",
            "NRestarts",
            "ActiveState",
            "SubState",
            "ExecMainStatus",
            "Result",
        ] {
            let mut bad = v.clone();
            bad[k] = json!("foreign");
            assert!(owner_idle(&bad).is_err(), "{k}");
        }
    }
    #[test]
    fn independent_file_hash_rejects_changed_bytes_aliases_and_wrong_sizes() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("input");
        fs::write(&p, b"canonical").unwrap();
        // The integrity fixture must not depend on the caller's umask (e.g.002).
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        let b = BoundFile {
            path: p.clone(),
            sha256: hex_lower(&Sha256::digest(b"canonical")),
        };
        // Fixture UID is the actual test owner; production capability separately enforces 1000.
        if [0, 1000].contains(&unsafe { libc::geteuid() }) {
            measure(&b, Some(9)).unwrap();
        }
        assert!(measure(&b, Some(8)).is_err());
        fs::write(&p, b"changedxx").unwrap();
        assert!(measure(&b, Some(9)).is_err());
        let link = d.path().join("alias");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(
            measure(
                &BoundFile {
                    path: link,
                    sha256: b.sha256
                },
                Some(9)
            )
            .is_err()
        );
    }
    #[test]
    fn capability_cannot_become_replay_authority_or_bind_another_plan() {
        let s = fixture();
        let p = serde_json::to_value(&s).unwrap();
        let mut files = serde_json::Map::new();
        for k in [
            "prefix_archive",
            "prefix_manifest",
            "native_probe",
            "restart_snapshot",
            "worker",
            "genesis_archive",
        ] {
            files.insert(k.into(),json!({"path":p[k]["path"],"sha256":p[k]["sha256"],"opened_and_fully_hashed_as_uid":1000}));
        }
        let v = json!({"schema":"jetstreamer-private203-input-capability-v1","epoch":203,"passed":true,"uid":1000,
            "helper_sha256":"a".repeat(64),"whole_files_independently_hashed":true,"parent_must_repeat_complete_prefix_and_native_checks":true,
            "independent_archive_decoder_verified":false,"worker_spawned":false,"native_bank_restored":false,"replay_entries_sent":0,
            "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false,"inputs":p,"files":files});
        capability_matches(&p, &v, &"a".repeat(64)).unwrap();
        for (key, bad) in [
            ("uid", json!(0)),
            ("replay_entries_sent", json!(1)),
            ("worker_spawned", json!(true)),
            ("publication_authorized", json!(true)),
            ("helper_sha256", json!("f".repeat(64))),
        ] {
            let mut changed = v.clone();
            changed[key] = bad;
            assert!(
                capability_matches(&p, &changed, &"a".repeat(64)).is_err(),
                "{key}"
            );
        }
        let mut bad = p;
        bad["restart_snapshot"]["sha256"] = json!("f".repeat(64));
        assert!(capability_matches(&bad, &v, &"a".repeat(64)).is_err());
    }
}
