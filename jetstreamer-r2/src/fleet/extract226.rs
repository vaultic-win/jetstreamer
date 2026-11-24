//! Registration and resource census for the private workerless epoch 226
//! extraction and its read-only Original225 broker.
use super::*;
use std::{io::Read, os::unix::fs::MetadataExt};

pub(super) const SCHEMA: &str = "foundation-epoch226-held-extraction-launch-v1";
pub(super) const UNIT: &str = "horizon-qualify-226-checkpoint-continuation-extract-v1.service";
pub(super) const BROKER: &str = "foundation-226-original225-broker-v1.service";
const PREFIX: &str = "horizon-qualify-226-checkpoint-continuation-extract-";
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-226-extract-v1";
const STATE: &str = "/var/lib/jetstreamer/horizon226-extract-v1";
const PLAN: &str = "/var/lib/jetstreamer/horizon226-extract-v1/plan.json";
const PIN: &str = "/var/lib/jetstreamer/horizon226-extract-v1/held-broker.json";
const GUARD_PLAN: &str = "/var/lib/jetstreamer/horizon226-extract-v1/guard-plan.json";
const SOCKET: &str = "/run/jetstreamer-horizon-epoch226-holding-v1/source.sock";
const NODE: &str = "/run/foundation-epoch226-release.y35rokj7/jetstreamer-node";
const NODE_SHA: &str = "7e17105ad9429fccbeb53dcd38650adb3f469bc1d3fe797360afff2cc7379ded";
const BROKER_IMAGE: &str = "/run/foundation-original225-rust-broker.mdawjaqq/original225-broker";
const BROKER_SHA: &str = "753c9c00c19f2f7040a3c4377d8559f770a8c2f3aa15781c5432215157f03838";
const GUARD_SHA: &str = "938889f9dcca0b4bf271cf8c2cbad985edc3d841f944d132f1e96c8fad81386d";
const ROOT_CAP: u64 = 160 << 30;
const SHARED_FLOOR: u64 = 3_770_104_987_645;
const ORIGINAL_SIZE: u64 = 265_610_094_371;

pub(super) fn namespace(claim: &DiagnosticClaim) -> bool {
    claim.unit.starts_with(PREFIX)
}

fn iid(v: &Value) -> bool {
    v.as_str().is_some_and(|s| {
        s.len() == 32
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn sealed_json(v: &Value, expected: &Path) -> Result<Value> {
    root_bound_json(v, expected, 0o222)
}

fn root_bound_json(v: &Value, expected: &Path, forbidden_writes: u32) -> Result<Value> {
    let bound: BoundFile = serde_json::from_value(v.clone())?;
    ensure!(
        bound.path == expected && canonical_digest(&v["sha256"]),
        "226 evidence scope"
    );
    let m = fs::symlink_metadata(expected)?;
    ensure!(
        expected.canonicalize()? == expected
            && m.is_file()
            && m.uid() == 0
            && (m.mode() & forbidden_writes) == 0
            && m.nlink() == 1,
        "226 evidence is not sealed"
    );
    bound_json(&bound)
}

fn shape(claim: &DiagnosticClaim, receipt: &Value) -> Result<()> {
    let node_mem = receipt["node_memory_max"]
        .as_u64()
        .context("226 node memory cap")?;
    let broker_mem = receipt["broker_memory_max"]
        .as_u64()
        .context("226 broker memory cap")?;
    ensure!(
        claim.epoch == 226
            && claim.unit == UNIT
            && claim.scratch_path == Path::new(ROOT)
            && claim.launch_receipt.path == Path::new(STATE).join("fleet-launch.json")
            && receipt["schema"] == SCHEMA
            && receipt["epoch"] == 226
            && receipt["unit"] == UNIT
            && receipt["operation"] == "extract"
            && receipt["invocation_id"] == claim.invocation_id
            && iid(&receipt["invocation_id"])
            && iid(&receipt["broker_invocation_id"])
            && receipt["invocation_id"] != receipt["broker_invocation_id"]
            && receipt["node_sha256"] == NODE_SHA
            && receipt["broker_image_sha256"] == BROKER_SHA
            && receipt["broker_unit"] == BROKER
            && receipt["run_root"] == ROOT
            && receipt["root_cap_bytes"] == ROOT_CAP
            && receipt["guard_floor_bytes"] == SHARED_FLOOR
            && node_mem > 0
            && broker_mem > 0
            && node_mem
                .checked_add(broker_mem)
                .is_some_and(|n| n <= 7 << 30)
            && receipt["broker_range_budget_bytes"]
                .as_u64()
                .is_some_and(|n| n >= 3 * ORIGINAL_SIZE && n <= 8 * ORIGINAL_SIZE)
            && receipt["launched"] == true
            && receipt["local_retirement_authorized"] == false
            && receipt["publication_authorized"] == false
            && receipt["remote_mutations"] == false
            && receipt["r2_mutations"] == false,
        "invalid epoch 226 producer or broker launch scope"
    );
    Ok(())
}

pub(super) fn launch(claim: &DiagnosticClaim, receipt: &Value) -> Result<()> {
    shape(claim, receipt)?;
    let sealed = sealed_json(
        &json!({"path":claim.launch_receipt.path,"sha256":claim.launch_receipt.sha256}),
        Path::new(STATE).join("fleet-launch.json").as_path(),
    )?;
    ensure!(&sealed == receipt, "226 fleet launch changed");
    let plan = sealed_json(&receipt["node_plan"], Path::new(PLAN))?;
    let pin = sealed_json(&receipt["broker_pin"], Path::new(PIN))?;
    let guard = sealed_json(&receipt["guard_plan"], Path::new(GUARD_PLAN))?;
    let first_id = receipt["guard_first_invocation_id"]
        .as_str()
        .context("226 guard id")?;
    ensure!(
        iid(&receipt["guard_first_invocation_id"]),
        "invalid 226 guard invocation"
    );
    let first = root_bound_json(
        &receipt["first_guard"],
        &Path::new(STATE)
            .join("guard-receipts")
            .join(format!("sample-{first_id}.json")),
        0o022,
    )?;
    let admission = sealed_json(&plan["admission"], &Path::new(STATE).join("admission.json"))?;
    ensure!(
        plan["schema"] == "jetstreamer-private-epoch226-scoped-repair-plan-v1"
            && plan["epoch"] == 226
            && plan["producer_unit"] == UNIT
            && plan["run_root"] == ROOT
            && plan["node_sha256"] == NODE_SHA
            && plan["stage"]["operation"] == "extract"
            && plan["stage"]["held_broker"] == receipt["broker_pin"]
            && admission["schema"] == "jetstreamer-epoch226-scoped-repair-admission-v1"
            && admission["admitted"] == true
            && admission["epoch"] == 226
            && admission["operation"] == "extract"
            && admission["producer_unit"] == UNIT
            && admission["node_sha256"] == NODE_SHA
            && admission["run_root"] == ROOT
            && admission["authenticated_held_source_qualified"] == true
            && admission["actual_guard_and_owner_qualified"] == true
            && pin["schema"] == "foundation-epoch226-pinned-original225-broker-v1"
            && pin["socket"] == SOCKET
            && pin["length"] == ORIGINAL_SIZE
            && pin["etag"] == "\"4cd6d98c0ad728ddd15a128b17300724-3958\""
            && pin["sha256"] == "77c0f95a020ceb6c45e323f4ce1bb48066fd0b379615bd5c9dbcb67f9082d6f9"
            && pin["broker_pid"] == receipt["broker_pid"]
            && guard["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && guard["unit"] == UNIT
            && guard["invocation_id"] == claim.invocation_id
            && guard["worker_root"] == ROOT
            && guard["minimum_free_bytes"] == SHARED_FLOOR
            && guard["maximum_root_physical_bytes"] == ROOT_CAP
            && first["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && first["producer_invocation_id"] == claim.invocation_id
            && first["guard_invocation_id"] == first_id
            && first["guard_sha256"] == GUARD_SHA
            && first["plan_sha256"] == receipt["guard_plan"]["sha256"]
            && first["producer_stop_enabled"] == true
            && first["producer"]["sub"] == "start-pre"
            && first["producer"]["pid"] == 0
            && first["trip_reason"].is_null()
            && first["workers"].as_array().is_some_and(Vec::is_empty),
        "226 bound stage, read-only broker, first guard or admission differs"
    );
    Ok(())
}

fn exact_process(
    current: &Value,
    unit: &str,
    invocation: &Value,
    args: &[&str],
    image_sha: &str,
    limit: &Value,
) -> Result<Value> {
    let group = format!("/system.slice/{unit}");
    ensure!(
        current["Id"] == unit
            && current["InvocationID"] == *invocation
            && current["LoadState"] == "loaded"
            && current["Type"] == "exec"
            && current["ActiveState"] == "active"
            && current["SubState"] == "running"
            && current["ControlGroup"] == group
            && current["NRestarts"] == "0",
        "226 live owner changed"
    );
    let pid = u32::try_from(
        current["MainPID"]
            .as_str()
            .context("226 main pid")?
            .parse::<u64>()?,
    )?;
    ensure!(pid > 1, "missing epoch 226 owner");
    let root = Path::new("/proc").join(pid.to_string());
    let image = Path::new(args[0]);
    let actual = fs::read(root.join("cmdline"))?;
    let expected = args
        .iter()
        .flat_map(|arg| arg.bytes().chain([0]))
        .collect::<Vec<_>>();
    ensure!(
        actual == expected
            && fs::read_to_string(root.join("cgroup"))?.trim() == format!("0::{group}")
            && fs::read_link(root.join("exe"))? == image
            && image.canonicalize()? == image,
        "226 live program changed"
    );
    let mut mapped = File::open(root.join("exe"))?;
    let meta = mapped.metadata()?;
    let sealed = fs::symlink_metadata(image)?;
    ensure!(
        meta.dev() == sealed.dev()
            && meta.ino() == sealed.ino()
            && sealed.is_file()
            && sealed.uid() == 0
            && sealed.nlink() == 1
            && sealed.mode() & 0o222 == 0
            && sealed.len() < 96 << 20,
        "226 mapped image custody changed"
    );
    let mut hash = Sha256::new();
    let count = std::io::copy(
        &mut Read::by_ref(&mut mapped).take((96 << 20) + 1),
        &mut hash,
    )?;
    ensure!(
        count == sealed.len() && hex_lower(&hash.finalize()) == image_sha,
        "226 mapped image bytes differ"
    );
    let cg = Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/'));
    let memory_max = fs::read_to_string(cg.join("memory.max"))?
        .trim()
        .parse::<u64>()?;
    let memory_current = fs::read_to_string(cg.join("memory.current"))?
        .trim()
        .parse::<u64>()?;
    ensure!(
        limit.as_u64() == Some(memory_max)
            && fs::read_to_string(cg.join("memory.swap.max"))?.trim() == "0",
        "226 actual cgroup memory assignment differs"
    );
    let stat = fs::read_to_string(cg.join("memory.stat"))?;
    let anonymous = stat
        .lines()
        .find_map(|r| r.strip_prefix("anon "))
        .context("226 anonymous memory")?
        .parse::<u64>()?;
    Ok(
        json!({"unit":unit,"invocation_id":invocation,"pid":pid,"memory_max_bytes":memory_max,
        "memory_current_bytes":memory_current,"anonymous_bytes":anonymous,"image_sha256":image_sha,"cgroup":group}),
    )
}

pub(super) fn live(
    claim: &DiagnosticClaim,
    receipt: &Value,
    node: &Value,
    broker: &Value,
) -> Result<Value> {
    let plan_arg = format!("--checkpoint-continuation-plan={PLAN}");
    let sha_arg = format!(
        "--checkpoint-continuation-plan-sha256={}",
        receipt["node_plan"]["sha256"]
            .as_str()
            .context("226 live plan hash")?
    );
    let ledger = format!("{ROOT}/ledger");
    let budget = receipt["broker_range_budget_bytes"]
        .as_u64()
        .context("226 read budget")?
        .to_string();
    let prod = exact_process(
        node,
        UNIT,
        &receipt["invocation_id"],
        &[NODE, "226", &ledger, "--verify", &plan_arg, &sha_arg],
        NODE_SHA,
        &receipt["node_memory_max"],
    )?;
    let held = exact_process(
        broker,
        BROKER,
        &receipt["broker_invocation_id"],
        &[BROKER_IMAGE, UNIT, &budget],
        BROKER_SHA,
        &receipt["broker_memory_max"],
    )?;
    ensure!(
        prod["invocation_id"] == claim.invocation_id && held["pid"] == receipt["broker_pid"],
        "226 scoped broker and producer no longer match launch"
    );
    let dir = Path::new(ROOT);
    let here = dir.symlink_metadata()?;
    let there = Path::new("/proc")
        .join(format!(
            "{}/root",
            prod["pid"].as_u64().context("226 node pid")?
        ))
        .join(dir.strip_prefix("/")?)
        .metadata()?;
    ensure!(
        here.is_dir()
            && here.uid() == 1000
            && here.mode() & 0o077 == 0
            && here.dev() == there.dev()
            && here.ino() == there.ino(),
        "226 run root custody changed"
    );
    Ok(
        json!({"producer":prod,"broker":held,"run_root":ROOT,"root_cap_bytes":ROOT_CAP,
        "guard_plan":receipt["guard_plan"],"first_guard":receipt["first_guard"],
        "ordinary_replay_claim":false,"current_sidecar_eta_valid":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (DiagnosticClaim, Value) {
        let node_id = "a".repeat(32);
        let claim = DiagnosticClaim {
            epoch: 226,
            unit: UNIT.into(),
            invocation_id: node_id.clone(),
            scratch_path: ROOT.into(),
            launch_receipt: BoundFile {
                path: Path::new(STATE).join("fleet-launch.json"),
                sha256: "1".repeat(64),
            },
        };
        let value = json!({
            "schema": SCHEMA,
            "epoch": 226,
            "unit": UNIT,
            "operation": "extract",
            "invocation_id": node_id,
            "broker_invocation_id": "b".repeat(32),
            "node_sha256": NODE_SHA,
            "broker_image_sha256": BROKER_SHA,
            "broker_unit": BROKER,
            "run_root": ROOT,
            "root_cap_bytes": ROOT_CAP,
            "guard_floor_bytes": SHARED_FLOOR,
            "node_memory_max": 6u64 << 30,
            "broker_memory_max": 256u64 << 20,
            "broker_range_budget_bytes": 4 * ORIGINAL_SIZE,
            "launched": true,
            "local_retirement_authorized": false,
            "publication_authorized": false,
            "remote_mutations": false,
            "r2_mutations": false
        });
        (claim, value)
    }

    #[test]
    fn exact_extraction_claim_rejects_overlapping_or_changed_resource_owners() {
        let (mut claim, value) = fixture();
        shape(&claim, &value).unwrap();
        for (field, invalid) in [
            ("broker_unit", json!(UNIT)),
            ("broker_invocation_id", value["invocation_id"].clone()),
            ("operation", json!("replay")),
            ("root_cap_bytes", json!(ROOT_CAP + 1)),
            ("node_memory_max", json!(7u64 << 30)),
            ("broker_range_budget_bytes", json!(0)),
            ("publication_authorized", json!(true)),
        ] {
            let mut changed = value.clone();
            changed[field] = invalid;
            assert!(shape(&claim, &changed).is_err(), "accepted changed {field}");
        }
        claim.unit = format!("{PREFIX}unregistered.service");
        assert!(namespace(&claim));
        assert!(shape(&claim, &value).is_err());
    }
}
