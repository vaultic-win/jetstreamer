//! Exact 204 assembly recovery. Historical suffix success, failed original
//! assembler, and successful recovery remain separate authenticated facts.
//! The normal capped continuation natural-success validator is unchanged.
use super::*;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
mod artifact;
mod capacity;
mod context;
mod custody;
mod full209_terminal_peer;
use context::AcceptedContext;
// Full210 shares the authenticated complete context reader. Its maintenance
// admission retains the coordinated sample's own freshness and resource gates.
pub(super) fn accepted_context(fleet: &BoundFile, observer: &BoundFile) -> Result<Value> {
    AcceptedContext {
        fleet: fleet.clone(),
        observer: observer.clone(),
    }
    .historical()
}
mod delivery;
mod downstream;
mod startup;
pub(super) fn delivery_command_matches(actual: &str, expected: &str) -> bool {
    ownership::command_matches(actual, expected)
}
pub(super) fn qualified_delivery_tool(
    role: &str,
    tool: &BoundFile,
    proof: &BoundFile,
) -> Result<BoundFile> {
    downstream::qualified_tool(role, tool, proof)
}
pub(super) fn deployed_delivery_member(
    seal: &BoundFile,
    member: &BoundFile,
    maximum: u64,
) -> Result<()> {
    artifact::validate_member_binding(seal, member, maximum)
}

mod lineage;
mod ownership;
mod status_cleanup;
mod transition;
pub(super) use status_cleanup::{
    cleanup_current as cleared_success_cleanup_current,
    cleanup_time as cleared_success_cleanup_time,
};
pub(super) use transition::{EVENT_SCHEMA, event_predecessor, terminal_row};
#[cfg(test)]
mod tests;
pub(super) use ownership::{Claim, names, row, status_matches};
pub(super) use ownership::{
    peer_current, peer_guards, peer_limits, peer_memory_owners, peer_names, peer_observation,
    peer_resources, peer_view, qualification_successor,
};

const OLD_UNIT: &str = "horizon-qualify-204-capped-continuation-bounded8-v4-df57.service";
const OLD_GUARD: &str = "horizon-guard-204-capped-continuation-bounded8-v4-df57.service";
const OLD_IID: &str = "1989c5fd08084f08ab07dabdf8690e67";
const OLD_PLAN: &str = "bcabf3d06065d09501f139c192ab94c0e0263701eafe1b19e7d9d759085d5ef1";
const SUFFIX_PROOF: &str = "f93addfcb7c05fcb01996040f84c0c9f28cd945d09132e8cfb7c42db877c0470";
const PREFIX_SHA: &str = "08351adefb3ef0d693f12bb9c978f48caa1c56d32456d335a2ae52a1969b27c2";
const SUFFIX_SHA: &str = "260da3745f21c452a204c03b6eaeedb17945e97e7075758251aab3d31c56a988";
const WORKER: &str = "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc";
const SNAPSHOT: &str = "24b722b37fa87462876dc05916bafa98da13f095c95aaed7159e9008efa7352e";
const PREFIX_PATH: &str = "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-204-fcbf3992-v1/output/epoch-204-prefix.jet";
const OLD_ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-204-bounded8-v4-df57";
const SUFFIX_PATH: &str = "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-204-bounded8-v4-df57/output/epoch-204-suffix.jet";
const FAILED_V1_UNIT: &str = "horizon-qualify-204-assembly-only-recovery-v1.service";
const FAILED_V1_GUARD: &str = "horizon-guard-204-assembly-only-recovery-v1.service";
const FAILED_V1_IID: &str = "2acdd92edcf5410293e8bfda15f92a63";
const FAILED_V1_GUARD_IID: &str = "55d49be3ebd74fc991524a163e3874ea";
const RETRY_HELPER_SOURCE: &str = "aac7c8ca42bfc1153a33c1515062911d7c2cb292";
const UNIT: &str = "horizon-qualify-204-assembly-only-recovery-v2.service";
const GUARD: &str = "horizon-guard-204-assembly-only-recovery-v2.service";
const ROOT: &str = "/var/lib/jetstreamer/horizon-204-assembly-only-recovery-v2";
const OUTPUT: &str = "/var/lib/jetstreamer/horizon-204-assembly-only-recovery-v2/epoch-204-assembly-only-recovery-v4.jet";
const ORIGIN: u64 = 1792749926759;
const MEMORY: u64 = 64 << 30;
const GUARD_MEMORY: u64 = 128 << 20;
const OUTPUT_MAX: u64 = 160 << 30;
const DURATION: u64 = 28_800_000;
const GENERATION: &str =
    "jetstreamer-epoch204-assembly-only-recovery-v2/epoch204-capped-checkpoint-continuation-v1";
const STATUS_DIRECTORY: &str = "/home/ubuntu/.jetstreamer-private/r2-status-receipts";
const CANONICAL: &str = "/home/ubuntu/horizon";

fn n(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .with_context(|| format!("204 recovery integer missing: {k}"))
}
fn s<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .with_context(|| format!("204 recovery string missing: {k}"))
}
fn id(value: &str) -> bool {
    is_lower_hex(value, 32) && value.bytes().any(|v| v != b'0')
}
fn binding(path: &Path) -> Result<BoundFile> {
    let b = read_stable_bounded(path, 16 << 20, "204 recovery metadata")?;
    Ok(BoundFile {
        path: path.into(),
        sha256: hex_lower(&Sha256::digest(b)),
    })
}
fn sealed(b: &BoundFile, maximum: u64) -> Result<Vec<u8>> {
    let before = fs::symlink_metadata(&b.path)?;
    ensure!(
        b.path.is_absolute()
            && b.path.canonicalize()? == b.path
            && before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o222 == 0
            && before.len() <= maximum
            && is_lower_hex(&b.sha256, 64),
        "204 recovery input is not sealed"
    );
    let bytes = read_stable_bounded(&b.path, maximum, "204 recovery input")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == b.sha256
            && identity(&before) == identity(&fs::symlink_metadata(&b.path)?),
        "204 recovery input changed/digest mismatch"
    );
    Ok(bytes)
}
fn read(b: &BoundFile) -> Result<Value> {
    Ok(serde_json::from_slice(&sealed(b, 16 << 20)?)?)
}
fn deny(v: &Value) -> Result<()> {
    for k in [
        "canonical_sidecar_authorized",
        "publication_authorized",
        "retirement_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            v[k] == false,
            "204 recovery borrowed or missing authority: {k}"
        );
    }
    Ok(())
}
fn denied() -> Value {
    json!({"canonical_sidecar_authorized":false,"publication_authorized":false,
    "retirement_authorized":false,"remote_mutations":false,"r2_mutations":false})
}
fn private(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o777 == 0o700
            && path.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && path
                .file_name()
                .and_then(|x| x.to_str())
                .is_some_and(|x| x.starts_with("horizon-204-assembly-")),
        "204 recovery metadata parent escaped exact private namespace"
    );
    Ok(())
}
fn write(path: &Path, v: &Value) -> Result<BoundFile> {
    private(path.parent().context("204 recovery parent")?)?;
    persist(path, v)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o400))?;
    file.sync_all()?;
    File::open(path.parent().context("receipt parent")?)?.sync_all()?;
    binding(path)
}
fn issuer(spec: &BoundFile, self_sha: &str) -> Value {
    json!({"executable_sha256":self_sha,"spec":private157::binding(spec),"invocation_id":env::var("INVOCATION_ID").ok(),
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH).map(|v|v.as_secs()).unwrap_or(0),
        "reviewed_rust_issuer":true})
}
fn is_live(v: &Value) -> bool {
    v["LoadState"] == "loaded"
        && v["ActiveState"] == "active"
        && v["SubState"] == "running"
        && v["NRestarts"] == "0"
        && v["MainPID"]
            .as_str()
            .and_then(|x| x.parse::<u64>().ok())
            .is_some_and(|x| x > 1)
}
fn is_idle(v: &Value) -> bool {
    v["MainPID"] == "0"
        && v["NRestarts"] == "0"
        && matches!(v["ActiveState"].as_str(), Some("inactive" | "failed"))
        && matches!(v["SubState"].as_str(), Some("dead" | "failed"))
}
fn no_file(path: &Path) -> Result<()> {
    ensure!(
        matches!(fs::symlink_metadata(path),Err(e)if e.kind()==std::io::ErrorKind::NotFound),
        "204 recovery refuses existing file: {}",
        path.display()
    );
    Ok(())
}
fn no_sidecar(path: &Path) -> Result<()> {
    no_file(&PathBuf::from(format!("{}.sha256", path.display())))
}
fn same_owner(expected: &Value, actual: &Value) -> Result<()> {
    for k in [
        "Id",
        "InvocationID",
        "MainPID",
        "NRestarts",
        "ActiveState",
        "SubState",
        "ControlGroup",
    ] {
        ensure!(
            expected.get(k).is_some() && expected[k] == actual[k],
            "204 recovery owner changed: {k}"
        );
    }
    ensure!(
        pipeline_status::same_exec_start(s(expected, "ExecStart")?, s(actual, "ExecStart")?),
        "204 recovery command changed"
    );
    Ok(())
}
pub(super) fn scope(name: &str, first: u64, last: u64) -> bool {
    first <= 204
        && last >= 204
        && (name == UNIT
            || name == GUARD
            || downstream::Stage::all().iter().any(|x| x.unit() == name))
}
pub(super) fn binding_scope(epoch: u64, unit: &str, origin: &str, phase: &str) -> Result<()> {
    ensure!(
        epoch == 204
            && origin == UNIT
            && scope(unit, 204, 204)
            && unit != GUARD
            && matches!(phase, "verification" | "upload" | "readback")
            && (unit == downstream::Stage::Upload.unit() || phase == "verification"),
        "204 recovery status scope differs"
    );
    Ok(())
}
pub(super) fn command_name(name: &str) -> bool {
    matches!(
        name,
        "capture-assembly204-recovery-terminal"
            | "prepare-assembly204-delivery"
            | "capture-assembly204-plugin-capacity"
            | "release-assembly204-delivery-stage"
            | "capture-assembly204-recovery-sources"
            | "issue-assembly204-recovery-plan"
            | "admit-assembly204-recovery"
            | "capture-assembly204-recovery-launch"
            | "capture-assembly204-recovery-completion"
            | "derive-assembly204-recovery-expectation"
            | "run-assembly204-recovery-stage"
            | "admit-assembly204-recovery-stage"
            | "capture-assembly204-recovery-stage"
            | "capture-assembly204-recovery-work"
            | "prepare-assembly204-recovery-terminal-fleet"
            | "prepare-assembly204-recovery-fleet"
            | "publish-assembly204-recovery-status"
    )
}
pub(super) async fn run(command: &str) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "204 recovery issuer requires root"
    );
    let (spec, self_sha) = publication203::parsed_args(command)?;
    let value = read(&spec)?;
    match command {
        "prepare-assembly204-delivery" => delivery::prepare(&value, &spec, &self_sha),
        "capture-assembly204-plugin-capacity" => {
            delivery::capture_plugin_capacity(&value, &spec, &self_sha)
        }
        "release-assembly204-delivery-stage" => startup::release(&value, &spec, &self_sha),
        "capture-assembly204-recovery-terminal" => {
            custody::capture_terminal(&value, &spec, &self_sha)
        }
        "capture-assembly204-recovery-sources" => {
            custody::capture_sources(&value, &spec, &self_sha)
        }
        "issue-assembly204-recovery-plan" => custody::issue_plan(&value, &spec, &self_sha),
        "admit-assembly204-recovery" => capacity::admit(&value, &spec, &self_sha),
        "capture-assembly204-recovery-launch" => {
            ownership::capture_launch(&value, &spec, &self_sha)
        }
        "capture-assembly204-recovery-completion" => {
            lineage::capture_completion(&value, &spec, &self_sha)
        }
        "derive-assembly204-recovery-expectation" => lineage::expectation(&value, &spec, &self_sha),
        "run-assembly204-recovery-stage" => downstream::run_stage(&value, &spec, &self_sha).await,
        "admit-assembly204-recovery-stage" => downstream::admit_stage(&value, &spec, &self_sha),
        "capture-assembly204-recovery-stage" => downstream::capture_stage(&value, &spec, &self_sha),
        "capture-assembly204-recovery-work" => ownership::capture_work(&value, &spec, &self_sha),
        "prepare-assembly204-recovery-terminal-fleet" => {
            transition::prepare_terminal(&value, &spec, &self_sha)
        }
        "prepare-assembly204-recovery-fleet" => transition::prepare(&value, &spec, &self_sha),
        "publish-assembly204-recovery-status" => ownership::publish(&value, &spec, &self_sha).await,
        _ => bail!("unknown exact 204 recovery verb"),
    }
}
