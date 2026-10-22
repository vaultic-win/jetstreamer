//! Exact private144 suffix/assembly owner. Never ordinary replay or publication.
use super::*;
use std::os::unix::{
    fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    io::AsRawFd,
};

pub(super) const SCHEMA: &str = "jetstreamer-private-epoch144-checkpoint-continuation-launch-v2";
pub(super) const UNIT: &str = "horizon-qualify-144-checkpoint-continuation-20261022-v1.service";
pub(super) const ROOT: &str =
    "/home/sol/.jetstreamer-private/checkpoint-continuation-144-20261022-v1";
pub(super) const SCRATCH: &str =
    "/home/sol/.jetstreamer-private/checkpoint-continuation-144-20261022-v1/scratch";
pub(super) const NODE: &str =
    "/usr/local/lib/jetstreamer/horizon-continuation144-tools-20261022-v1/jetstreamer-node";
pub(super) const NODE_SHA: &str =
    "ac47031ac2cc42c0d7c343aebbfe049433fc76b7ee8d6da3ca2ac7de9f428dbd";
pub(super) const PLAN: &str =
    "/usr/local/lib/jetstreamer/horizon-continuation144-launch-plan-20261022-v1/plan.json";
const PROTECTED: u64 = 3_916_063_202_758;
const PEAK: u64 = 192 << 30;

pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    c.epoch == 144 && c.unit == UNIT
}
fn command(sha: &str) -> String {
    format!(
        "{{ path={NODE} ; argv[]={NODE} 144 {ROOT}/ledger --verify --checkpoint-continuation-plan={PLAN} --checkpoint-continuation-plan-sha256={sha}"
    )
}
fn command_part(value: &Value) -> Option<&str> {
    value
        .as_str()?
        .split_once(" ; ignore_errors=")
        .map(|(s, _)| s)
}
fn shape(r: &Value, c: &DiagnosticClaim) -> Result<()> {
    ensure!(
        namespace(c)
            && c.scratch_path == Path::new(SCRATCH)
            && r["schema"] == SCHEMA
            && r["epoch"] == 144
            && r["unit"] == UNIT
            && r["invocation_id"] == c.invocation_id
            && c.invocation_id.len() == 32
            && c.invocation_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            && r["launched"] == true
            && r["node_sha256"] == NODE_SHA
            && r["bootstrap_slot"] == 62639490
            && r["suffix_start_slot"] == 62639491
            && r["terminal_slot"] == 62639999
            && r["remaining_slots"] == 509
            && r["maximum_runtime_seconds"] == 7200
            && r["maximum_memory_bytes"] == 64u64 << 30
            && r["maximum_cpu_percent"] == 400
            && r["experimental_envelope_bytes"] == PEAK
            && r["protected_existing_floor_bytes"] == PROTECTED
            && r["private_suffix_authorized"] == true
            && r["private_assembly_authorized"] == true
            && r["continuation_plan"]["path"] == PLAN
            && canonical_digest(&r["continuation_plan"]["sha256"])
            && command_part(&r["expected_exec_start"])
                == Some(command(r["continuation_plan"]["sha256"].as_str().unwrap_or("")).as_str()),
        "private144 continuation launch scope differs"
    );
    for flag in [
        "ordinary_replay_claim",
        "current_sidecar_eta_valid",
        "full_epoch_verified",
        "local_retirement_authorized",
        "canonical_sidecar_authorized",
        "runtime_promotion_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            r[flag] == false,
            "private144 continuation launch grants forbidden authority:{flag}"
        );
    }
    Ok(())
}
pub(super) fn launch(r: &Value, c: &DiagnosticClaim) -> Result<()> {
    shape(r, c)?;
    let pb: BoundFile = serde_json::from_value(r["continuation_plan"].clone())?;
    let ab: BoundFile = serde_json::from_value(r["admission"].clone())?;
    let p = bound_json(&pb)?;
    let a = bound_json(&ab)?;
    bindings(r, &p, &a, &ab)
}
fn bindings(r: &Value, p: &Value, a: &Value, ab: &BoundFile) -> Result<()> {
    ensure!(
        p["schema"] == "jetstreamer-private-epoch144-checkpoint-continuation-plan-v2"
            && p["epoch"] == 144
            && p["producer_unit"] == UNIT
            && p["node_sha256"] == NODE_SHA
            && p["run_root"] == ROOT
            && p["minimum_free_bytes"] == PROTECTED + PEAK
            && p["admission_receipt"] == private157::binding(ab)
            && a["schema"] == "jetstreamer-epoch144-continuation-admission-v2"
            && a["admitted"] == true
            && a["private_continuation_and_assembly_only"] == true
            && a["node_sha256"] == NODE_SHA
            && a["candidate_incremental_peak_bytes"] == PEAK
            && a["protected_existing_floor_bytes"] == PROTECTED
            && a["remaining_slots"] == 509
            && a["required_guard_minimum_free_bytes"]
                .as_u64()
                .is_some_and(|n| n >= PROTECTED)
            && r["required_guard_minimum_free_bytes"] == a["required_guard_minimum_free_bytes"]
            && a["experimental_peak_guard_includes_other_fleet_allocations"] == true,
        "private144 requires its exact full-path plan/admission"
    );
    for (name, digest) in [
        (
            "prefix_archive",
            "917f700274c0ff0386cd8be2f27eb2ace9f3bc7dff38e1010d0c04bb79b8c273",
        ),
        (
            "prefix_manifest",
            "691d5f3768b8c283678937b49790606b6091d4ab632372bfff38664c005b544a",
        ),
        (
            "native_probe",
            "400b6215f060f541bd2cfe0c3ff14c303b0e057887bc30b1d9e765416b647d30",
        ),
        (
            "restart_snapshot",
            "f170976b2bc3f2d55dd0fbb5a415bfeae8d0903a0ad69334d8aa993b5cab35ae",
        ),
        (
            "worker",
            "2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8",
        ),
        (
            "genesis_archive",
            "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
        ),
        (
            "protection_release",
            "2e0aec223a30d9af4ada3b4ef5feb82996c718ca1b951dbe04b62d0d5bfbf3e6",
        ),
    ] {
        ensure!(
            p[name]["sha256"] == digest,
            "private144 input differs:{name}"
        );
    }
    ensure!(
        a["protection_release"] == p["protection_release"]
            && a["resource_policy"]["sha256"]
                == "4656cb2058d49f222d3e4bd0522d6c8fc7f7710b4bf23d940d5bbb0dc3d46c0a",
        "private144 protection/resource evidence differs"
    );
    for flag in [
        "ordinary_replay_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            a[flag] == false,
            "private144 admission grants forbidden authority"
        );
    }
    let admitted = a["recorded_unix_seconds"]
        .as_u64()
        .context("admission time")?;
    let launched = r["recorded_unix_seconds"].as_u64().context("launch time")?;
    ensure!(
        admitted <= launched && launched - admitted <= 900,
        "private144 launched from stale/future admission"
    );
    Ok(())
}
pub(super) fn validate_live(c: &DiagnosticClaim, current: &Value) -> Result<()> {
    let r = checked_diagnostic_launch(c)?;
    ensure!(
        namespace(c)
            && current["InvocationID"] == c.invocation_id
            && current["NRestarts"] == "0"
            && current["Type"] == "exec"
            && current["ActiveState"] == "active"
            && current["SubState"] == "running"
            && command_part(&current["ExecStart"]) == command_part(&r["expected_exec_start"]),
        "private144 continuation live owner differs"
    );
    live_limits()?;
    terminal_ancestors()
}
fn terminal_ancestors() -> Result<()> {
    let native = unit(native144::UNIT)?;
    ensure!(
        native["InvocationID"] == "1219f5b93e0a40639db09f6996746243"
            && native["MainPID"] == "0"
            && native["ActiveState"] == "active"
            && native["SubState"] == "exited"
            && native["Result"] == "success"
            && native["ExecMainStatus"] == "0",
        "private144 native checkpoint probe not clean terminal history"
    );
    crate::inactive_status::private144_terminal_manager_proof(&unit(
        "horizon-qualify-epoch144-loader-focus-20261016-v1.service",
    )?)?;
    let audit = unit("horizon-qualify-144-private-verification-20261021-v1.service")?;
    ensure!(
        audit["InvocationID"] == "0def5bbebbbc4d6aa8b7f6fe33d08365"
            && audit["MainPID"] == "0"
            && audit["ActiveState"] == "active"
            && audit["SubState"] == "exited"
            && audit["Result"] == "success"
            && audit["ExecMainStatus"] == "0",
        "private144 prefix audit not clean terminal history"
    );
    Ok(())
}
fn live_limits() -> Result<()> {
    live_limits_for(UNIT)
}
fn live_limits_for(name: &str) -> Result<()> {
    ensure!(
        name == UNIT || name == "horizon-continuation144-limits-fixture-20261022-v1.service",
        "foreign private144 limits fixture"
    );
    let out=ProcessCommand::new("systemctl").args(["show",name,"--no-pager","--property=Type,Restart,KillMode,Delegate,TasksMax,MemoryHigh,MemoryMax,MemorySwapMax,RuntimeMaxUSec,CPUQuotaPerSecUSec,ProtectSystem,ProtectHome,PrivateNetwork,PrivateMounts,NoNewPrivileges,ReadWritePaths,User,Group,UMask,CapabilityBoundingSet,AmbientCapabilities,Environment"]).output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 16384,
        "private144 limits unreadable"
    );
    let mut limits = BTreeMap::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("limits line")?;
        ensure!(limits.insert(k, v).is_none(), "duplicate limit");
    }
    validate_limits(&limits)
}
fn validate_limits(l: &BTreeMap<&str, &str>) -> Result<()> {
    for (k, v) in [
        ("Type", "exec"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("TasksMax", "512"),
        ("MemoryHigh", "34359738368"),
        ("MemoryMax", "68719476736"),
        ("MemorySwapMax", "0"),
        ("RuntimeMaxUSec", "2h"),
        ("CPUQuotaPerSecUSec", "4s"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("PrivateNetwork", "no"),
        ("PrivateMounts", "yes"),
        ("NoNewPrivileges", "yes"),
        ("User", "sol"),
        ("Group", "horizon"),
        ("UMask", "0077"),
        ("CapabilityBoundingSet", ""),
        ("AmbientCapabilities", ""),
    ] {
        ensure!(l.get(k) == Some(&v), "private144 sandbox differs:{k}");
    }
    let rw: BTreeSet<_> = l
        .get("ReadWritePaths")
        .context("writable paths")?
        .split_whitespace()
        .collect();
    ensure!(
        rw == BTreeSet::from([
            ROOT,
            "/home/sol/.jetstreamer-private/checkpoint-continuation-144.lock"
        ]),
        "private144 writable scope differs"
    );
    let env: BTreeSet<_> = l
        .get("Environment")
        .context("producer environment")?
        .split_whitespace()
        .collect();
    ensure!(
        env == BTreeSet::from([
            "SOLANA_RAYON_THREADS=2",
            "JETSTREAMER_HISTORICAL_CONTROL_TIMEOUT_SECS=60",
            "JETSTREAMER_HISTORICAL_INITIALIZE_TIMEOUT_SECS=900",
            "JETSTREAMER_HISTORICAL_CHECKPOINT_TIMEOUT_SECS=600",
            "JETSTREAMER_HISTORICAL_REAP_TIMEOUT_SECS=120",
            "JETSTREAMER_ALLOW_CANDIDATE_RUNTIME=1",
            "JETSTREAMER_HISTORICAL_WORKER_V1_4_25=/usr/local/lib/jetstreamer/deploy-epochs144-147-upgradeable-loader-20261016-v1/jetstreamer-historical-worker-v1-4-25"
        ]),
        "private144 environment differs from measured native and exact worker"
    );
    Ok(())
}

const STATE: &str = "/var/lib/jetstreamer/horizon-continuation144-launch-20261022-v1";
fn sealed_self(expected: &str) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "continuation144 preparation requires root"
    );
    let path = fs::read_link("/proc/self/exe")?;
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == expected,
        "unsealed continuation144 preparer"
    );
    Ok(())
}
fn state_directory() -> Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(STATE) {
        Ok(()) => {
            File::open(Path::new(STATE).parent().unwrap())?.sync_all()?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let m = fs::symlink_metadata(STATE)?;
    ensure!(
        m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o077 == 0
            && Path::new(STATE).canonicalize()? == Path::new(STATE),
        "unsafe launch state directory"
    );
    Ok(())
}
pub(super) fn prepare_layout() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 4 && args[2] == "--self-sha256",
        "usage: prepare-continuation144-layout --self-sha256 SHA"
    );
    sealed_self(&args[3])?;
    state_directory()?;
    let owner = unit(UNIT)?;
    ensure!(
        owner["MainPID"] == "0" && owner["ActiveState"] == "inactive" && owner["NRestarts"] == "0",
        "private144 layout owner already live or failed"
    );
    validate_output_destination(&Path::new(STATE).join("layout.json"))?;
    let base = Path::new(ROOT).parent().unwrap();
    let m = fs::symlink_metadata(base)?;
    ensure!(
        base.canonicalize()? == base && m.is_dir() && m.uid() == 1001 && m.mode() & 0o077 == 0,
        "unsafe private144 parent"
    );
    let group = unsafe { libc::getgrnam(c"horizon".as_ptr()) };
    ensure!(!group.is_null(), "horizon group missing");
    let gid = unsafe { (*group).gr_gid };
    match fs::DirBuilder::new().mode(0o700).create(ROOT) {
        Ok(()) => {
            let dir = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(ROOT)?;
            ensure!(
                unsafe { libc::fchown(dir.as_raw_fd(), 1001, gid) } == 0,
                "private144 root chown failed"
            );
            dir.sync_all()?;
            File::open(base)?.sync_all()?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let m = fs::symlink_metadata(ROOT)?;
    ensure!(
        Path::new(ROOT).canonicalize()? == Path::new(ROOT)
            && m.is_dir()
            && m.uid() == 1001
            && m.gid() == gid
            && m.mode() & 0o077 == 0
            && fs::read_dir(ROOT)?.next().is_none(),
        "private144 root occupied or unsafe; preserve existing work"
    );
    let lease = base.join("checkpoint-continuation-144.lock");
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&lease)
    {
        Ok(file) => {
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            ensure!(
                unsafe { libc::fchown(file.as_raw_fd(), 1001, gid) } == 0,
                "private144 lease chown failed"
            );
            file.sync_all()?;
            File::open(base)?.sync_all()?;
            file
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&lease)?,
        Err(e) => return Err(e.into()),
    };
    let lm = file.metadata()?;
    ensure!(
        lease.canonicalize()? == lease
            && lm.is_file()
            && lm.nlink() == 1
            && lm.len() == 0
            && lm.uid() == 1001
            && lm.gid() == gid
            && lm.mode() & 0o777 == 0o600
            && unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "private144 lease occupied or unsafe"
    );
    ensure!(
        unit(UNIT)? == owner,
        "private144 owner changed during layout preparation"
    );
    private157::immutable_receipt(
        &Path::new(STATE).join("layout.json"),
        &json!({"schema":"jetstreamer-private144-layout-v2",
        "root":ROOT,"root_device":m.dev(),"root_inode":m.ino(),"lease":lease,"lease_device":lm.dev(),"lease_inode":lm.ino(),"uid":1001,"gid":gid,
        "self_sha256":args[3],"replay_launch_authorized":false,"publication_authorized":false,"local_retirement_authorized":false,"r2_mutations":false}),
    )?;
    println!("private144 empty root and exact shared lease prepared; no admission or launch");
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
}
pub(super) fn capture_launch() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 7 && args[3] == "--spec-sha256" && args[5] == "--self-sha256",
        "usage: capture-continuation144-launch SPEC --spec-sha256 SHA --self-sha256 SHA"
    );
    sealed_self(&args[6])?;
    state_directory()?;
    let sb = BoundFile {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let sm = fs::symlink_metadata(&sb.path)?;
    ensure!(
        sm.is_file() && sm.uid() == 0 && sm.nlink() == 1 && sm.mode() & 0o222 == 0,
        "unsealed private144 capture spec"
    );
    let s: CaptureSpec = serde_json::from_value(bound_json(&sb)?)?;
    ensure!(
        s.schema == "jetstreamer-private144-launch-capture-spec-v2"
            && s.continuation_plan.path == Path::new(PLAN),
        "foreign private144 capture"
    );
    let a = bound_json(&s.admission)?;
    let o = bound_json(&s.observer)?;
    let f = bound_json(&s.previous_fleet)?;
    ensure!(
        a["observer"] == private157::binding(&s.observer)
            && a["fleet"] == private157::binding(&s.previous_fleet)
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && f["observer_sha256"] == s.observer.sha256
            && f["first_epoch"] == 101
            && f["last_epoch"] == 200,
        "private144 capture predecessor differs"
    );
    let before = unit(UNIT)?;
    let iid = before["InvocationID"]
        .as_str()
        .context("producer invocation")?;
    let claim = DiagnosticClaim {
        epoch: 144,
        unit: UNIT.into(),
        invocation_id: iid.into(),
        scratch_path: SCRATCH.into(),
        launch_receipt: BoundFile {
            path: Path::new(STATE).join("launch.json"),
            sha256: "0".repeat(64),
        },
    };
    let mut r = json!({"schema":SCHEMA,"epoch":144,"unit":UNIT,"invocation_id":iid,"launched":true,"node_sha256":NODE_SHA,
        "bootstrap_slot":62639490,"suffix_start_slot":62639491,"terminal_slot":62639999,"remaining_slots":509,
        "maximum_runtime_seconds":7200,"maximum_memory_bytes":64u64<<30,"maximum_cpu_percent":400,"experimental_envelope_bytes":PEAK,
        "protected_existing_floor_bytes":PROTECTED,"private_suffix_authorized":true,"private_assembly_authorized":true,
        "required_guard_minimum_free_bytes":a["required_guard_minimum_free_bytes"],"continuation_plan":private157::binding(&s.continuation_plan),
        "admission":private157::binding(&s.admission),"observer":private157::binding(&s.observer),"previous_fleet":private157::binding(&s.previous_fleet),
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"expected_exec_start":before["ExecStart"],
        "capture_spec":private157::binding(&sb),"capture_self_sha256":args[6]});
    for flag in [
        "ordinary_replay_claim",
        "current_sidecar_eta_valid",
        "full_epoch_verified",
        "local_retirement_authorized",
        "canonical_sidecar_authorized",
        "runtime_promotion_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        r[flag] = json!(false);
    }
    launch(&r, &claim)?;
    live_limits()?;
    terminal_ancestors()?;
    ensure!(
        before["Type"] == "exec"
            && before["ActiveState"] == "active"
            && before["SubState"] == "running"
            && before["NRestarts"] == "0"
            && before["MainPID"]
                .as_str()
                .and_then(|p| p.parse::<u32>().ok())
                .is_some_and(|p| p > 0),
        "private144 producer not bound live"
    );
    ensure!(
        unit(UNIT)? == before,
        "private144 owner changed during capture"
    );
    private157::immutable_receipt(&Path::new(STATE).join("launch.json"), &r)?;
    let guard_source = Path::new(STATE).join("guard-plan.json");
    persist(
        &guard_source,
        &json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":UNIT,"invocation_id":iid,
        "filesystem":"/home/sol","minimum_free_bytes":a["required_guard_minimum_free_bytes"],"worker_root":SCRATCH,
        "maximum_worker_vmas":3500000,"receipt_directory":"/var/lib/jetstreamer/horizon-continuation144-guard-20261022-v1","bounded_measurement":null}),
    )?;
    let guard_binding = private157::file_binding(&guard_source)?;
    persist(
        &Path::new(STATE).join("guard-seal-plan.json"),
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1",
        "destination":"/usr/local/lib/jetstreamer/horizon-continuation144-guard-20261022-v1",
        "members":[{"source":guard_source,"name":"guard-plan.json","sha256":guard_binding["sha256"],"mode":256}]}),
    )?;
    println!(
        "captured exact live private144 owner; first real one-worker guard and fleet event still required"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "root read-only actual private144 sandbox on harmless non-owner fixture"]
    fn root_actual_continuation_limits_fixture_matches() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        live_limits_for("horizon-continuation144-limits-fixture-20261022-v1.service").unwrap();
    }
    fn fixture() -> (DiagnosticClaim, Value) {
        let c = DiagnosticClaim {
            epoch: 144,
            unit: UNIT.into(),
            invocation_id: "a".repeat(32),
            scratch_path: SCRATCH.into(),
            launch_receipt: BoundFile {
                path: "/launch".into(),
                sha256: "b".repeat(64),
            },
        };
        let mut r = json!({"schema":SCHEMA,"epoch":144,"unit":UNIT,"invocation_id":c.invocation_id,"launched":true,"node_sha256":NODE_SHA,
            "bootstrap_slot":62639490,"suffix_start_slot":62639491,"terminal_slot":62639999,"remaining_slots":509,
            "maximum_runtime_seconds":7200,"maximum_memory_bytes":64u64<<30,"maximum_cpu_percent":400,
            "experimental_envelope_bytes":PEAK,"protected_existing_floor_bytes":PROTECTED,"private_suffix_authorized":true,"private_assembly_authorized":true,
            "continuation_plan":{"path":PLAN,"sha256":"c".repeat(64)},"expected_exec_start":format!("{} ; ignore_errors=no }}",command(&"c".repeat(64)))});
        for flag in [
            "ordinary_replay_claim",
            "current_sidecar_eta_valid",
            "full_epoch_verified",
            "local_retirement_authorized",
            "canonical_sidecar_authorized",
            "runtime_promotion_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            r[flag] = json!(false);
        }
        (c, r)
    }
    #[test]
    fn private_suffix_cannot_borrow_native_only_scope_or_publication() {
        let (c, r) = fixture();
        shape(&r, &c).unwrap();
        for (key, v) in [
            ("remaining_slots", json!(508)),
            ("experimental_envelope_bytes", json!(40u64 << 30)),
            ("node_sha256", json!("d".repeat(64))),
            ("publication_authorized", json!(true)),
            ("private_suffix_authorized", json!(false)),
            ("schema", json!(native144::SCHEMA)),
        ] {
            let mut bad = r.clone();
            bad[key] = v;
            assert!(shape(&bad, &c).is_err(), "{key}");
        }
        let mut bad = c;
        bad.unit = native144::UNIT.into();
        assert!(shape(&r, &bad).is_err());
    }
    #[test]
    fn full_path_binding_retains_budget_inputs_and_original_admission_clock() {
        let (_, mut r) = fixture();
        r["recorded_unix_seconds"] = json!(1900);
        r["required_guard_minimum_free_bytes"] = json!(PROTECTED + 1);
        let ab = BoundFile {
            path: "/sealed/admission.json".into(),
            sha256: "d".repeat(64),
        };
        let release = json!({"path":"/sealed/release.json","sha256":"2e0aec223a30d9af4ada3b4ef5feb82996c718ca1b951dbe04b62d0d5bfbf3e6"});
        let mut p = json!({"schema":"jetstreamer-private-epoch144-checkpoint-continuation-plan-v2","epoch":144,"producer_unit":UNIT,
            "node_sha256":NODE_SHA,"run_root":ROOT,"minimum_free_bytes":PROTECTED+PEAK,"admission_receipt":private157::binding(&ab),"protection_release":release});
        for (name, digest) in [
            (
                "prefix_archive",
                "917f700274c0ff0386cd8be2f27eb2ace9f3bc7dff38e1010d0c04bb79b8c273",
            ),
            (
                "prefix_manifest",
                "691d5f3768b8c283678937b49790606b6091d4ab632372bfff38664c005b544a",
            ),
            (
                "native_probe",
                "400b6215f060f541bd2cfe0c3ff14c303b0e057887bc30b1d9e765416b647d30",
            ),
            (
                "restart_snapshot",
                "f170976b2bc3f2d55dd0fbb5a415bfeae8d0903a0ad69334d8aa993b5cab35ae",
            ),
            (
                "worker",
                "2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8",
            ),
            (
                "genesis_archive",
                "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
            ),
        ] {
            p[name] = json!({"path":format!("/sealed/{name}"),"sha256":digest});
        }
        let mut a = json!({"schema":"jetstreamer-epoch144-continuation-admission-v2","admitted":true,"private_continuation_and_assembly_only":true,
            "node_sha256":NODE_SHA,"candidate_incremental_peak_bytes":PEAK,"protected_existing_floor_bytes":PROTECTED,"remaining_slots":509,
            "required_guard_minimum_free_bytes":PROTECTED+1,"experimental_peak_guard_includes_other_fleet_allocations":true,
            "protection_release":release,"resource_policy":{"sha256":"4656cb2058d49f222d3e4bd0522d6c8fc7f7710b4bf23d940d5bbb0dc3d46c0a"},"recorded_unix_seconds":1000});
        for flag in [
            "ordinary_replay_authorized",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            a[flag] = json!(false);
        }
        bindings(&r, &p, &a, &ab).unwrap();
        let mut bad = r.clone();
        bad["recorded_unix_seconds"] = json!(1901);
        assert!(bindings(&bad, &p, &a, &ab).is_err());
        let mut bad = p.clone();
        bad["restart_snapshot"]["sha256"] = json!("e".repeat(64));
        assert!(bindings(&r, &bad, &a, &ab).is_err());
        let mut bad = a.clone();
        bad["candidate_incremental_peak_bytes"] = json!(40u64 << 30);
        assert!(bindings(&r, &p, &bad, &ab).is_err());
        let mut bad = a.clone();
        bad["publication_authorized"] = json!(true);
        assert!(bindings(&r, &p, &bad, &ab).is_err());
        let mut bad = r.clone();
        bad["required_guard_minimum_free_bytes"] = json!(PROTECTED);
        assert!(bindings(&bad, &p, &a, &ab).is_err());
    }
}
