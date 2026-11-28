//! Source proposal: select the already-recorded exact failed136 memory debt.
//! Uses both qualified libraries on one unchanged raw report. No new retirement
//! recording, DATA credit, namespace reuse, guard mutation or lane admission.
use anyhow::{Context, Result, ensure};
use horizon_original199_parent_memory as parent;
use jetstreamer_typed_memory as typed;
use parent::model::{Bound, Request};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const IMAGE: &str = "/usr/local/lib/jetstreamer/horizon-failed4-combined-current-reader-tools-20261109-v1/failed4-combine";
const UNIT: &str = "horizon-failed4-current-combined-memory-selection-20261109-v1.service";
const OUTPUT: &str = "/var/lib/jetstreamer/horizon-failed4-current-combined-memory-selection-v1";
const REDUCTION: u64 = 68 << 30;
const ROLE: &str = "terminal199-parent-memory-combined-current-reader";

struct SelectedCurrent {
    request: Request,
    combined: Value,
    accounting: Bound,
    captured141: Bound,
    totals: (u64, u64),
}

fn clock() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn binding(value: &Value) -> Result<Bound> {
    Ok(serde_json::from_value(value.clone())?)
}
fn immutable(bound: &Bound) -> Result<Value> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&bound.path)?;
    let before = file.metadata()?;
    ensure!(
        bound.path.canonicalize()? == bound.path
            && before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o222 == 0
            && before.len() <= 32 << 20,
        "immutable Root metadata required"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((32 << 20) + 1)
        .read_to_end(&mut bytes)?;
    let after = fs::symlink_metadata(&bound.path)?;
    ensure!(
        (
            before.dev(),
            before.ino(),
            before.len(),
            before.ctime(),
            before.ctime_nsec()
        ) == (
            after.dev(),
            after.ino(),
            after.len(),
            after.ctime(),
            after.ctime_nsec()
        ) && file.metadata()?.ino() == before.ino()
            && bytes.len() as u64 == before.len()
            && sha(&bytes) == bound.sha256,
        "bound metadata changed"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn native(iid: &str) -> Result<Value> {
    let out = Command::new("/usr/bin/systemctl").arg("--system")
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS").env_remove("SYSTEMD_BUS_ADDRESS")
        .env_remove("DBUS_SESSION_BUS_ADDRESS").env_remove("SYSTEMD_HOST")
        .args(["show", UNIT, "--no-pager", "--property=Id,InvocationID,MainPID,ControlPID,NRestarts,Restart,ActiveState,SubState,MemoryAccounting,MemoryMax,MemorySwapMax,RuntimeMaxUSec,Job"])
        .output()?;
    ensure!(
        out.status.success() && out.stderr.is_empty() && out.stdout.len() <= 65_536,
        "combined reader native identity unavailable"
    );
    let mut fields = serde_json::Map::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (key, value) = line.split_once('=').context("native property delimiter")?;
        ensure!(
            fields.insert(key.into(), json!(value)).is_none(),
            "duplicate native property"
        );
    }
    let value = Value::Object(fields);
    let expected_pid = std::process::id().to_string();
    ensure!(
        value["Id"] == UNIT
            && value["InvocationID"] == iid
            && value["MainPID"].as_str() == Some(expected_pid.as_str())
            && value["ControlPID"] == "0"
            && value["NRestarts"] == "0"
            && value["Restart"] == "no"
            && value["Job"] == ""
            && value["ActiveState"] == "active"
            && value["SubState"] == "running"
            && value["MemoryAccounting"] == "yes"
            && value["MemoryMax"] == "2147483648"
            && value["MemorySwapMax"] == "0"
            && value["RuntimeMaxUSec"] == "10min",
        "combined reader must be its original finite2GiB native actor"
    );
    Ok(value)
}
fn compose(
    parent_total: u64,
    parent_peers: u64,
    captured_total: u64,
    failed_total: u64,
    same_raw: bool,
) -> Result<(u64, u64)> {
    ensure!(
        same_raw && captured_total.checked_sub(failed_total) == Some(REDUCTION),
        "failed4 must reduce the same raw captured141 baseline exactly once"
    );
    Ok((
        parent_total
            .checked_sub(REDUCTION)
            .context("parent total omits failed4")?,
        parent_peers
            .checked_sub(REDUCTION)
            .context("parent peers omit failed4")?,
    ))
}
fn output(directory: &Path, name: &str, value: &Value) -> Result<Bound> {
    let bytes = serde_json::to_vec_pretty(value)?;
    ensure!(bytes.len() <= 32 << 20, "combined proof size bound");
    let path = directory.join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    file.write_all(&bytes)?;
    file.set_permissions(fs::Permissions::from_mode(0o400))?;
    file.sync_all()?;
    File::open(directory)?.sync_all()?;
    Ok(Bound {
        path,
        sha256: sha(&bytes),
    })
}
fn selection(spec: &Value, at: u64) -> Result<SelectedCurrent> {
    ensure!(
        spec["schema"] == "failed4-current-combined-memory-selection-spec-v1",
        "explicit combined-current spec required"
    );
    let parent_request = immutable(&binding(&spec["parent_request"])?)?;
    ensure!(
        parent_request["baseline"]["kind"] == "captured141-only",
        "caller baseline already includes failed4 or is unknown"
    );
    let request: Request = serde_json::from_value(parent_request)?;
    // This authenticates the genuine successful original complete reader and
    // census, captured141 and the independent original199/cached145 projections.
    let selected = parent::admission_bridge::from_current_reader(&request, at)?;
    let reader = immutable(&request.current_reader)?;
    let raw_bound = binding(&reader["accounting"])?;
    let raw = immutable(&raw_bound)?;
    let captured_bound = binding(&reader["captured141_selection"])?;
    let captured = immutable(&captured_bound)?;
    let before = typed::revalidate_captured_selection(&captured, &raw, at)?;
    let failed: typed::failed4::model::Request = serde_json::from_value(spec["failed4"].clone())?;
    ensure!(
        json!(failed.current) == json!(request.current),
        "failed4/parent current tuples crossed"
    );
    let inputs = json!({"observer":request.current.observer,"fleet":request.current.fleet,"fleet_plan":request.current.fleet_plan});
    // The existing exact selector authenticates the Nov4 receipt, normal enabled
    // registration, original writer completion and current six-role native
    // closure. It never records a second historical retirement.
    let combined = typed::failed4::select(
        before.raw_total_bytes(),
        &inputs,
        &raw,
        Some(&failed),
        &captured,
        at,
    )?;
    let total = compose(
        selected.effective_total_bytes(),
        selected.effective_peer_bytes(),
        before.effective_total_bytes(),
        combined.total,
        selected.raw_total_bytes() == before.raw_total_bytes()
            && selected.raw_peer_bytes() == before.raw_peer_bytes(),
    )?;
    Ok(SelectedCurrent {
        request,
        combined: combined.evidence,
        accounting: raw_bound,
        captured141: captured_bound,
        totals: total,
    })
}
fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 7
            && args[1] == "combine"
            && args[3] == "--spec-sha256"
            && args[5] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "combine SPEC --spec-sha256 SHA --self-sha256 SHA under exact Root unit"
    );
    ensure!(
        !env::vars_os()
            .any(|(key, _)| key.to_string_lossy().starts_with("LD_") || key == "GLIBC_TUNABLES"),
        "loader overrides forbidden"
    );
    ensure!(
        fs::read_link("/proc/self/exe")? == Path::new(IMAGE)
            && sha(&fs::read("/proc/self/exe")?) == args[6],
        "exact normal executable required"
    );
    let spec_bound = Bound {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let spec = immutable(&spec_bound)?;
    let iid = env::var("INVOCATION_ID")?;
    let native_before = native(&iid)?;
    let at = clock()?;
    let selected_current = selection(&spec, at)?;
    let request = &selected_current.request;
    let directory = Path::new(
        spec["output_directory"]
            .as_str()
            .context("output directory")?,
    );
    ensure!(
        directory.parent().and_then(Path::parent) == Some(Path::new(OUTPUT))
            && directory
                .parent()
                .and_then(Path::file_name)
                .is_some_and(|name| name == request.current.observer.sha256.as_str()),
        "output must be an exact observer/attempt namespace"
    );
    let metadata = fs::symlink_metadata(directory)?;
    ensure!(
        directory.canonicalize()? == directory
            && metadata.is_dir()
            && metadata.uid() == 0
            && metadata.mode() & 0o777 == 0o700,
        "fresh Root0700 output directory required"
    );
    let native_after = native(&iid)?;
    ensure!(
        native_before == native_after && clock()?.checked_sub(at).is_some_and(|n| n <= 120),
        "combined reader native actor changed or exceeded120s"
    );
    let selected = output(
        directory,
        "combined-selection.json",
        &selected_current.combined,
    )?;
    let proof = json!({"schema":"failed4-current-combined-memory-selection-proof-v1",
        "current":request.current,"current_reader":request.current_reader,
        "image":{"path":IMAGE,"sha256":args[6]},
        "program":{"path":IMAGE,"sha256":args[6]},"spec":spec_bound,
        "accounting":selected_current.accounting,"combined_selection":selected,
        "captured141_selection":selected_current.captured141,"failed4_reduction_bytes":REDUCTION,
        "unit":UNIT,"invocation_id":iid,"recorded_unix_seconds":clock()?,
        "scope":ROLE,"native_before":native_before,"native_after":native_after,
        "actual_native_capability_passed":true,"memory_credit_bytes":0,
        "after_original199_and_completed_cached145_total_bytes":selected_current.totals.0,
        "after_original199_and_completed_cached145_peer_bytes":selected_current.totals.1,
        "raw_history_preserved":true,"DATA_credit_bytes":0,"physical_credit_bytes":0,
        "memory_credit_applied_bytes":0,"admission_authorized":false,
        "replay_launch_authorized":false,"guard_changes":false,"remote_mutations":false});
    let proof_bound = output(directory, "proof.json", &proof)?;
    println!(
        "{}",
        json!({"proof":proof_bound,"combined_selection":selected,
        "view_only":true,"resource_credit_bytes":0,"replay_launch_authorized":false})
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("failed4 combined current reader: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_the_exact_failed4_delta_is_added_to_existing_parent_selection() {
        let got = compose(
            482_764_140_544,
            212_600_881_152,
            895_081_000_960,
            822_066_556_928,
            true,
        )
        .unwrap();
        assert_eq!(got, (409_749_696_512, 139_586_437_120));
    }
    #[test]
    fn crossed_raw_double_credit_parent_or_pool_refunds_are_rejected() {
        for failed in [895_081_000_960, 822_066_556_927, 614_834_384_896] {
            assert!(
                compose(
                    482_764_140_544,
                    212_600_881_152,
                    895_081_000_960,
                    failed,
                    true
                )
                .is_err()
            );
        }
        assert!(
            compose(
                482_764_140_544,
                212_600_881_152,
                895_081_000_960,
                822_066_556_928,
                false
            )
            .is_err()
        );
        assert!(compose(1, 212_600_881_152, 895_081_000_960, 822_066_556_928, true).is_err());
    }
}
