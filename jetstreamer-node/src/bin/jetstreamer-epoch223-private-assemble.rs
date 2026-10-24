//! Prepared private223 V3 assembly. No replay, sidecar, publication or R2.
#![recursion_limit = "256"]
#[allow(dead_code)]
#[path = "../../../jetstreamer-utils/src/epoch141_ledger_common.rs"]
mod evidence;
#[allow(dead_code)]
#[path = "epoch223_assembly/handoff.rs"]
mod handoff;
use anyhow::{Context, Result, ensure};
use handoff::Bound;
use jetstreamer_horizon::archive::{ArchiveWriterConfig, merge_runtime_segments};
use jetstreamer_node::{archive_checksum::*, segment_manifest::sha256_hex_string};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, BufReader, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const PREFIX: &str = "/home/ubuntu/.jetstreamer-private/qualification-223-v1620-prefix-full-root-v1/output/epoch-223.jet";
const TAIL: &str = "/home/ubuntu/.jetstreamer-private/qualification-223-v1625-tail-1743245a-v3/output/epoch-223.jet";
const OUTPUT: &str = "/var/lib/jetstreamer/horizon-223-native20-native25-private-assembly-v1";
const UNIT: &str = "horizon-assemble-223-native20-native25-v1.service";
const OLD_UNIT: &str = "horizon-qualify-223-v1620-root-prefix-resource-full-v1.service";
const OLD_IID: &str = "e70aaf097e7c4583b216aba454145910";
const TAIL_UNIT: &str = "horizon-qualify-223-v1625-tail-1743245a-v3.service";
const TAIL_IID: &str = "20dc145d1e8c41fdbc682046b6fe4289";
const GATE_SHA: &str = "137b5a3a767604ea4c9f7405dd0af7af0eb860f30e5ece52ce49017825d35c22";
const MAX_OUTPUT: u64 = 160 << 30;
const MEMORY_MAX: u64 = 64 << 30;
const MEMORY_HIGH: u64 = 48 << 30;
const MAX_SECONDS: u64 = 86400;
const MIN_FLOOR: u64 = 2_000_000_000_000;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    handoff_request: Bound,
    handoff_receipt: Bound,
    admission: Bound,
    output_root: PathBuf,
}
fn read(b: &Bound) -> Result<Value> {
    Ok(serde_json::from_slice(&evidence::bound_file(
        &b.path,
        &b.sha256,
        4 << 20,
        true,
    )?)?)
}
fn absent(path: &Path) -> Result<()> {
    ensure!(
        matches!(fs::symlink_metadata(path),Err(e)if e.kind()==io::ErrorKind::NotFound),
        "path must be absent: {}",
        path.display()
    );
    Ok(())
}
fn no_sidecar(path: &Path) -> Result<()> {
    absent(&archive_checksum_path(path)?)
}
fn seconds() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn properties(unit: &str) -> Result<Value> {
    let result=Command::new("/usr/bin/systemctl").args(["show",unit,"--property=InvocationID,MainPID,NRestarts,Restart,Result,ActiveState,SubState,Type,RuntimeMaxUSec,MemoryMax,MemoryHigh,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,User,UMask,PrivateNetwork,ProtectHome,ProtectSystem,ReadWritePaths,NoNewPrivileges,Job"]).output()?;
    ensure!(result.status.success(), "systemd property query failed");
    Ok(Value::Object(
        std::str::from_utf8(&result.stdout)?
            .lines()
            .filter_map(|s| s.split_once('='))
            .map(|(k, v)| (k.into(), json!(v)))
            .collect(),
    ))
}
fn terminal(p: &Value, iid: &str) -> Result<()> {
    ensure!(
        p["MainPID"] == "0"
            && p["NRestarts"] == "0"
            && p["Restart"] == "no"
            && p["Result"] == "success"
            && p["ActiveState"] == "inactive"
            && p["SubState"] == "dead"
            && p["Job"] == ""
            && (p["InvocationID"] == "" || p["InvocationID"] == iid),
        "original prefix is not idle after exact success"
    );
    Ok(())
}
fn owner(p: &Value, iid: &str) -> Result<()> {
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "invalid own invocation"
    );
    for (k, v) in [
        ("InvocationID", iid),
        ("Restart", "no"),
        ("NRestarts", "0"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("Type", "exec"),
        ("RuntimeMaxUSec", "1d"),
        ("MemoryMax", "68719476736"),
        ("MemoryHigh", "51539607552"),
        ("MemorySwapMax", "0"),
        ("CPUQuotaPerSecUSec", "4s"),
        ("TasksMax", "512"),
        ("User", "root"),
        ("UMask", "0077"),
        ("PrivateNetwork", "yes"),
        ("ProtectHome", "read-only"),
        ("ProtectSystem", "strict"),
        ("ReadWritePaths", OUTPUT),
        ("NoNewPrivileges", "yes"),
    ] {
        ensure!(p[k] == v, "assembly owner property differs: {k}");
    }
    ensure!(
        p["MainPID"].as_str().and_then(|s| s.parse::<u32>().ok()) == Some(std::process::id()),
        "not current persistent assembly process"
    );
    Ok(())
}
fn gate(plan: &Plan) -> Result<handoff::Prepared> {
    let request: handoff::Plan = serde_json::from_slice(&evidence::bound_file(
        &plan.handoff_request.path,
        &plan.handoff_request.sha256,
        65536,
        true,
    )?)?;
    let prepared = handoff::prepare(&request)?;
    let receipt = read(&plan.handoff_receipt)?;
    gate_receipt(plan, &prepared, &receipt)?;
    Ok(prepared)
}
fn gate_receipt(plan: &Plan, prepared: &handoff::Prepared, receipt: &Value) -> Result<()> {
    ensure!(
        receipt["self_sha256"] == GATE_SHA
            && receipt["plan"]["path"].as_str() == plan.handoff_request.path.to_str()
            && receipt["plan"]["sha256"] == plan.handoff_request.sha256,
        "not actual qualified handoff-gate output"
    );
    for (key, value) in prepared
        .receipt
        .as_object()
        .context("prepared receipt object")?
    {
        ensure!(
            receipt.get(key) == Some(value),
            "actual handoff receipt differs from current bound evidence: {key}"
        );
    }
    Ok(())
}
fn admission(
    plan: &Plan,
    a: &Value,
    prepared: &handoff::Prepared,
    self_sha: &str,
    now: u64,
) -> Result<u64> {
    ensure!(
        a["schema"] == "jetstreamer-private223-v3-assembly-admission-v1"
            && a["admitted"] == true
            && a["assembly_only_no_replay"] == true
            && a["assembler_sha256"] == self_sha
            && a["handoff_request_sha256"] == plan.handoff_request.sha256
            && a["handoff_receipt_sha256"] == plan.handoff_receipt.sha256
            && a["prefix_archive_sha256"] == sha256_hex_string(&prepared.prefix.archive_sha256)
            && a["tail_archive_sha256"] == sha256_hex_string(&prepared.tail.archive_sha256)
            && a["output_root"] == OUTPUT
            && a["maximum_archive_bytes"] == MAX_OUTPUT
            && a["candidate_memory_max_bytes"] == MEMORY_MAX
            && a["candidate_memory_high_bytes"] == MEMORY_HIGH
            && a["maximum_runtime_seconds"] == MAX_SECONDS
            && a["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t <= now && now - t <= 900),
        "missing/stale exact assembly admission"
    );
    for k in [
        "complete_fleet_census_passed",
        "older_producer_guards_preserved",
        "current_century_floor_preserved",
        "fresh_invocation_bound_resource_sample",
    ] {
        ensure!(a[k] == true, "assembly admission lacks {k}");
    }
    for k in [
        "replay_launch_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "runtime_promotion_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(a[k] == false, "unexpected admission authority: {k}");
    }
    for k in ["fleet_ledger", "observer_receipt"] {
        let bound: Bound = serde_json::from_value(a[k].clone())
            .context("missing bound fleet/observer evidence")?;
        ensure!(
            bound.path.is_absolute() && evidence::is_sha(&bound.sha256),
            "unbound fleet/observer evidence"
        );
    }
    let floor = a["required_guard_minimum_free_bytes"]
        .as_u64()
        .context("missing guard floor")?;
    let protected = a["protected_existing_floor_bytes"]
        .as_u64()
        .context("missing protected floor")?;
    let available = a["available_bytes"]
        .as_u64()
        .context("missing admission free bytes")?;
    let reserve = a["protected_existing_memory_reserve_bytes"]
        .as_u64()
        .context("missing existing memory reserve")?;
    let minimum = a["minimum_available_memory_bytes"]
        .as_u64()
        .context("missing memory minimum")?;
    ensure!(
        protected >= MIN_FLOOR
            && floor >= protected
            && available
                >= floor
                    .checked_add(MAX_OUTPUT)
                    .context("disk admission overflow")?
            && reserve > 0
            && minimum
                >= reserve
                    .checked_add(MEMORY_MAX)
                    .context("memory admission overflow")?,
        "assembly admission loses protected claims/output envelope"
    );
    Ok(floor)
}
fn free(directory: &Path) -> io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(directory.as_os_str().as_bytes())?;
    let mut stat = unsafe { std::mem::zeroed::<libc::statvfs>() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    stat.f_bavail
        .checked_mul(stat.f_frsize)
        .ok_or_else(|| io::Error::other("free byte overflow"))
}
fn memory() -> Result<u64> {
    fs::read_to_string("/proc/meminfo")?
        .lines()
        .find_map(|s| {
            s.strip_prefix("MemAvailable:")
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse::<u64>().ok())
                .and_then(|n| n.checked_mul(1024))
        })
        .context("available memory missing")
}
struct BoundedOutput {
    file: File,
    bytes: u64,
    started: Instant,
    floor: u64,
}
impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        ensure_write(
            self.bytes,
            bytes.len() as u64,
            self.started.elapsed().as_secs(),
            free(Path::new(OUTPUT))?,
            self.floor,
        )?;
        let written = self.file.write(bytes)?;
        self.bytes += written as u64;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
fn ensure_write(
    current: u64,
    next: u64,
    elapsed: u64,
    available: u64,
    floor: u64,
) -> io::Result<()> {
    if current.checked_add(next).is_none_or(|n| n > MAX_OUTPUT)
        || elapsed >= MAX_SECONDS
        || available.checked_sub(next).is_none_or(|n| n < floor)
    {
        return Err(io::Error::other(
            "assembly output/runtime/protected-floor bound crossed; preserve partial",
        ));
    }
    Ok(())
}
fn run() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let args: Vec<_> = env::args().skip(1).collect();
    let check = args.len() == 4 && args[3] == "--check-only";
    ensure!(
        args.len() == 3 || check,
        "usage: PLAN PLAN_SHA256 SELF_SHA256 [--check-only]"
    );
    evidence::bound_file(&fs::read_link("/proc/self/exe")?, &args[2], 128 << 20, true)?;
    let plan: Plan = serde_json::from_slice(&evidence::bound_file(
        Path::new(&args[0]),
        &args[1],
        65536,
        true,
    )?)?;
    ensure!(
        plan.schema == "jetstreamer-private223-v3-assembly-plan-v1"
            && plan.output_root == Path::new(OUTPUT),
        "wrong private assembly scope"
    );
    let prepared = gate(&plan)?;
    let provenance = handoff::provenance(&prepared.prefix, &prepared.tail)?;
    if check {
        println!(
            "metadata-only223 assembly preflight passed; no archive scan/admission/host observation/assembly/write; fresh separate admission and persistent bounded owner remain required"
        );
        return Ok(());
    }
    let admitted = read(&plan.admission)?;
    let floor = admission(&plan, &admitted, &prepared, &args[2], seconds()?)?;
    for key in ["fleet_ledger", "observer_receipt"] {
        let binding: Bound = serde_json::from_value(admitted[key].clone())?;
        read(&binding)?;
    }
    let old = properties(OLD_UNIT)?;
    terminal(&old, OLD_IID)?;
    let old_tail = properties(TAIL_UNIT)?;
    terminal(&old_tail, TAIL_IID)?;
    let iid = env::var("INVOCATION_ID").context("persistent bounded assembly owner required")?;
    let own = properties(UNIT)?;
    owner(&own, &iid)?;
    ensure!(
        plan.output_root.canonicalize()? == plan.output_root,
        "redirected output root"
    );
    let dir = fs::symlink_metadata(OUTPUT)?;
    ensure!(
        dir.is_dir()
            && dir.uid() == 0
            && dir.mode() & 0o077 == 0
            && dir.dev() == fs::metadata(PREFIX)?.dev()
            && admitted["output_filesystem_device"].as_u64() == Some(dir.dev())
            && fs::read_dir(OUTPUT)?.next().is_none(),
        "output must be fresh private root on admitted source filesystem"
    );
    let required_memory = admitted["minimum_available_memory_bytes"]
        .as_u64()
        .context("memory admission")?;
    ensure!(
        free(Path::new(OUTPUT))?
            >= floor
                .checked_add(MAX_OUTPUT)
                .context("free threshold overflow")?
            && memory()? >= required_memory,
        "current admission resources unavailable"
    );
    let mut sources = Vec::new();
    let mut identities = Vec::new();
    for (path, manifest) in [(PREFIX, &prepared.prefix), (TAIL, &prepared.tail)] {
        ensure!(
            Path::new(path).canonicalize()? == Path::new(path),
            "redirected private source"
        );
        no_sidecar(Path::new(path))?;
        let file = open_regular_nofollow(Path::new(path))?;
        let m = file.metadata()?;
        ensure!(
            m.is_file()
                && m.uid() == 1000
                && m.nlink() == 1
                && m.mode() & 0o077 == 0
                && m.len() > 0,
            "unsafe private source"
        );
        let identity = archive_file_identity(&file)?;
        identities.push((PathBuf::from(path), file.try_clone()?, identity));
        sources.push(jetstreamer_horizon::archive::RuntimeSegmentSource::new(
            BufReader::new(file),
            manifest.archive_sha256,
            manifest.terminal.last_blockhash_value()?,
        ));
    }
    admission(&plan, &admitted, &prepared, &args[2], seconds()?)?;
    ensure!(
        properties(OLD_UNIT)? == old
            && properties(TAIL_UNIT)? == old_tail
            && properties(UNIT)? == own,
        "owner changed before assembly"
    );
    evidence::write_receipt(
        &Path::new(OUTPUT).join("intent.json"),
        &json!({"schema":"jetstreamer-private223-v3-assembly-intent-v1",
        "unit":UNIT,"invocation_id":iid,"plan":{"path":args[0],"sha256":args[1]},"self_sha256":args[2],
        "handoff_request":plan.handoff_request,"handoff_receipt":plan.handoff_receipt,"admission":plan.admission,
        "publication_authorized":false,"r2_mutations":false}),
    )?;
    let target = Path::new(OUTPUT).join("epoch-223-private-v3.jet");
    no_sidecar(&target)?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&target)?;
    let started = Instant::now();
    let output = BoundedOutput {
        file,
        bytes: 0,
        started,
        floor,
    };
    let (mut output, stats) =
        merge_runtime_segments(sources, output, ArchiveWriterConfig::default(), &provenance)?;
    output.flush()?;
    output.file.sync_all()?;
    File::open(OUTPUT)?.sync_all()?;
    for (path, pin, identity) in &identities {
        ensure!(
            path.canonicalize()? == *path
                && archive_file_identity(pin)? == *identity
                && path_matches_archive_identity(path, *identity)?,
            "source changed during merge"
        );
        no_sidecar(path)?;
    }
    let target_pin = open_regular_nofollow(&target)?;
    let measured = measure_open_archive(&target_pin)?;
    ensure!(
        measured.identity == archive_file_identity(&output.file)?
            && path_matches_archive_identity(&target, measured.identity)?
            && target_pin.metadata()?.len() == output.bytes,
        "completed output identity/length changed"
    );
    for (path, pin, identity) in &identities {
        ensure!(
            path.canonicalize()? == *path
                && archive_file_identity(pin)? == *identity
                && path_matches_archive_identity(path, *identity)?,
            "source changed during final output hash"
        );
        no_sidecar(path)?;
    }
    ensure!(
        properties(OLD_UNIT)? == old
            && properties(TAIL_UNIT)? == old_tail
            && properties(UNIT)? == own,
        "owner changed before completion"
    );
    no_sidecar(&target)?;
    let expected_updates = provenance
        .runtime_segments
        .last()
        .context("missing final mapping")?
        .write_versions
        .archive_end_exclusive()
        .context("normalized extent overflow")?;
    ensure!(
        stats.source_archives == 2
            && stats.slots_merged == 432000
            && stats.account_updates_rebased == expected_updates,
        "incomplete assembly statistics"
    );
    evidence::write_receipt(
        &Path::new(OUTPUT).join("assembly.json"),
        &json!({"schema":"jetstreamer-private223-v3-assembly-v1","epoch":223,
        "unit":UNIT,"invocation_id":iid,"plan":{"path":args[0],"sha256":args[1]},"self_sha256":args[2],
        "handoff_request":plan.handoff_request,"handoff_receipt":plan.handoff_receipt,"admission":plan.admission,
        "private_output":target,"archive_sha256":sha256_hex_string(&measured.sha256),"archive_bytes":output.bytes,
        "source_archives":stats.source_archives,"slots_merged":stats.slots_merged,"account_updates_rebased":stats.account_updates_rebased,
        "provenance_version":3,"planned_mappings":prepared.receipt["planned_mappings"],"elapsed_millis":u64::try_from(started.elapsed().as_millis())?,
        "checked_private_merge_completed":true,"bank_rerun_performed":false,"independent_final_archive_verification_passed":false,
        "current_plugin_verification_passed":false,"canonical_sidecar_authorized":false,"publication_authorized":false,
        "runtime_promotion_authorized":false,"retirement_authorized":false,"repair_closed":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    println!(
        "private223 V3 assembly completed; final full/plugin/publication/repair gates remain separate"
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("private223 V3 assembly refused: {error:#}");
        std::process::exit(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding() -> Bound {
        Bound {
            path: "/not-an-operational-input".into(),
            sha256: "a".repeat(64),
        }
    }
    fn plan() -> Plan {
        Plan {
            schema: "jetstreamer-private223-v3-assembly-plan-v1".into(),
            handoff_request: binding(),
            handoff_receipt: binding(),
            admission: binding(),
            output_root: OUTPUT.into(),
        }
    }
    fn admission_fixture(p: &Plan, prepared: &handoff::Prepared) -> Value {
        json!({"schema":"jetstreamer-private223-v3-assembly-admission-v1","admitted":true,"assembly_only_no_replay":true,
            "assembler_sha256":"self-test-only","handoff_request_sha256":p.handoff_request.sha256,
            "handoff_receipt_sha256":p.handoff_receipt.sha256,"prefix_archive_sha256":sha256_hex_string(&prepared.prefix.archive_sha256),
            "tail_archive_sha256":sha256_hex_string(&prepared.tail.archive_sha256),"output_root":OUTPUT,
            "maximum_archive_bytes":MAX_OUTPUT,"candidate_memory_max_bytes":MEMORY_MAX,"candidate_memory_high_bytes":MEMORY_HIGH,
            "maximum_runtime_seconds":MAX_SECONDS,"recorded_unix_seconds":1000,
            "complete_fleet_census_passed":true,"older_producer_guards_preserved":true,"current_century_floor_preserved":true,
            "fresh_invocation_bound_resource_sample":true,"replay_launch_authorized":false,"canonical_sidecar_authorized":false,
            "publication_authorized":false,"runtime_promotion_authorized":false,"remote_mutations":false,"r2_mutations":false,
            "fleet_ledger":binding(),"observer_receipt":binding(),"required_guard_minimum_free_bytes":MIN_FLOOR,
            "protected_existing_floor_bytes":MIN_FLOOR,"available_bytes":MIN_FLOOR+MAX_OUTPUT,
            "protected_existing_memory_reserve_bytes":480u64<<30,"minimum_available_memory_bytes":544u64<<30})
    }
    #[test]
    fn write_guard_rejects_limit_floor_runtime_and_overflow_before_write() {
        ensure_write(0, 1, 0, MIN_FLOOR + 1, MIN_FLOOR).unwrap();
        ensure_write(MAX_OUTPUT - 1, 1, 0, MIN_FLOOR + 1, MIN_FLOOR).unwrap();
        for (current, next, elapsed, available) in [
            (MAX_OUTPUT, 1, 0, MIN_FLOOR + 1),
            (u64::MAX, 1, 0, u64::MAX),
            (0, 1, MAX_SECONDS, MIN_FLOOR + 1),
            (0, 1, 0, MIN_FLOOR),
            (0, u64::MAX, 0, 0),
        ] {
            assert!(ensure_write(current, next, elapsed, available, MIN_FLOOR).is_err());
        }
    }
    #[test]
    fn live_restarted_foreign_failed_or_queued_producer_forbids_assembly() {
        let good = json!({"MainPID":"0","NRestarts":"0","Restart":"no","Result":"success","ActiveState":"inactive","SubState":"dead","Job":"","InvocationID":OLD_IID});
        terminal(&good, OLD_IID).unwrap();
        for (key, value) in [
            ("MainPID", "10"),
            ("NRestarts", "1"),
            ("Restart", "on-failure"),
            ("Result", "exit-code"),
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("Job", "19"),
            ("InvocationID", TAIL_IID),
        ] {
            let mut bad = good.clone();
            bad[key] = json!(value);
            assert!(terminal(&bad, OLD_IID).is_err(), "{key}");
        }
    }
    #[test]
    fn admission_requires_actual_pair_fresh_fleet_and_protected_capacity() {
        let p = plan();
        let prepared = handoff::test_prepared();
        let good = admission_fixture(&p, &prepared);
        assert_eq!(
            admission(&p, &good, &prepared, "self-test-only", 1000).unwrap(),
            MIN_FLOOR
        );
        for (key, value) in [
            ("admitted", json!(false)),
            ("recorded_unix_seconds", json!(99)),
            ("recorded_unix_seconds", json!(1001)),
            ("complete_fleet_census_passed", json!(false)),
            ("older_producer_guards_preserved", json!(false)),
            ("handoff_receipt_sha256", json!("b".repeat(64))),
            ("prefix_archive_sha256", json!("b".repeat(64))),
            ("candidate_memory_max_bytes", json!(MEMORY_MAX - 1)),
            ("available_bytes", json!(MIN_FLOOR + MAX_OUTPUT - 1)),
            ("minimum_available_memory_bytes", json!(MEMORY_MAX)),
            ("protected_existing_floor_bytes", json!(1)),
            ("publication_authorized", json!(true)),
            ("fleet_ledger", json!({})),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(
                admission(&p, &bad, &prepared, "self-test-only", 1000).is_err(),
                "{key}"
            );
        }
    }
    #[test]
    fn actual_qualified_gate_receipt_must_match_recomputed_metadata() {
        let p = plan();
        let prepared = handoff::test_prepared();
        let mut good = prepared.receipt.clone();
        good["self_sha256"] = json!(GATE_SHA);
        good["plan"] = json!({"path":p.handoff_request.path,"sha256":p.handoff_request.sha256});
        gate_receipt(&p, &prepared, &good).unwrap();
        for (key, value) in [
            ("self_sha256", json!("b".repeat(64))),
            ("metadata_only", json!(false)),
            ("assembly_authorized", json!(true)),
            ("plan", json!({})),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(gate_receipt(&p, &prepared, &bad).is_err(), "{key}");
        }
    }
    #[test]
    fn persistent_owner_requires_exact_bounded_sandbox() {
        let iid = "a".repeat(32);
        let good = json!({"InvocationID":iid,"MainPID":std::process::id().to_string(),
            "Restart":"no","NRestarts":"0","ActiveState":"active","SubState":"running","Type":"exec","RuntimeMaxUSec":"1d",
            "MemoryMax":"68719476736","MemoryHigh":"51539607552","MemorySwapMax":"0","CPUQuotaPerSecUSec":"4s","TasksMax":"512",
            "User":"root","UMask":"0077","PrivateNetwork":"yes","ProtectHome":"read-only","ProtectSystem":"strict",
            "ReadWritePaths":OUTPUT,"NoNewPrivileges":"yes"});
        owner(&good, &iid).unwrap();
        for key in [
            "Type",
            "RuntimeMaxUSec",
            "MemoryMax",
            "MemorySwapMax",
            "MainPID",
            "UMask",
            "ReadWritePaths",
            "PrivateNetwork",
        ] {
            let mut bad = good.clone();
            bad[key] = json!("wrong");
            assert!(owner(&bad, &iid).is_err(), "{key}");
        }
    }
}
