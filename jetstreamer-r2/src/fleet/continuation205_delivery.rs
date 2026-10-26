//! Distinct epoch205 continuation delivery. Metadata never supplies a made-up
//! final archive digest: the first guarded copy-and-measure must establish it.
use super::*;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
mod capacity;
mod custody;
mod delivery;
mod downstream;
mod lineage;
mod peer;
mod startup;
mod terminal;
pub(in crate::fleet) use peer::{
    Claim, names, peer_current, peer_guards, peer_limits, peer_memory_owners, peer_names,
    peer_observation, peer_resources, peer_view, qualification_successor, row, status_matches,
};
const UNIT: &str = "horizon-qualify-205-capped-continuation-bounded8-refresh421-v1.service";
const IID: &str = "f8b69eb89f0847588afc0f405751344a";
const GUARD_IID: &str = "d5c72b4c1c504153a63855d6abf2edd5";
const OLD_PLAN: &str = "70acad78bb6f654a869fe006881266dc225d7a000dd3c2da5a416c5c3d04f5cc";
const OLD_IID: &str = IID;
const PREFIX_SHA: &str = "3188ea5552b65b0ef7ef0de7876b04b98b7bd31c1c1bb2f73667e61050fac138";
const SUFFIX_SHA: &str = "d7aff587adf414d9f6400bb0199b372390fa32981212ec3aca070f56e6cf1ff1";
const WORKER: &str = "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc";
const SNAPSHOT: &str = "1b2a41f022847dc2ba9609e5a13aadc0e79b213b5245166b06954bf8c6d9042f";
const GENERATION: &str = "jetstreamer-node/0.9.0/old-faithful-to-horizon-v2@6a327d89ef7ef7677f66d75bac99e9b0f7baf733/epoch205-capped-checkpoint-continuation-v1";
const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-205-bounded8-refresh421-v1/output";
const OUTPUT: &str = "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-205-bounded8-refresh421-v1/output/epoch-205-checkpoint-restart-v4.jet";
const BYTES: u64 = 104772252720;
const OUTPUT_MAX: u64 = 160 << 30;
const CANONICAL: &str = "/home/ubuntu/horizon";
pub(super) fn scope(name: &str) -> bool {
    name == UNIT || downstream::Stage::all().iter().any(|s| s.unit() == name)
}
pub(super) fn guard_scope(name: &str) -> bool {
    downstream::Stage::all()
        .iter()
        .any(|s| startup::guard_for_stage(*s).is_ok_and(|g| g == name))
}
pub(super) fn discovery_scope(name: &str) -> bool {
    [
        "horizon-full-verify-205-",
        "horizon-plugin-verify-205-",
        "horizon-boundary-verify-205-",
        "horizon-import-205-",
        "horizon-upload-205-",
        "horizon-205-delivery-",
    ]
    .iter()
    .any(|p| name.starts_with(p))
        && name.ends_with(".service")
}
fn n(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .with_context(|| format!("205 delivery integer missing: {k}"))
}
fn s<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .with_context(|| format!("205 delivery string missing: {k}"))
}
fn read(b: &BoundFile) -> Result<Value> {
    assembly204_recovery::sealed_delivery_metadata(b)
}
fn sealed(b: &BoundFile, maximum: u64) -> Result<Vec<u8>> {
    assembly204_recovery::sealed_delivery_bytes(b, maximum)
}
fn deny(v: &Value) -> Result<()> {
    for key in [
        "canonical_sidecar_authorized",
        "publication_authorized",
        "retirement_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(v[key] == false, "205 delivery borrowed authority: {key}");
    }
    Ok(())
}
fn denied() -> Value {
    json!({"canonical_sidecar_authorized":false,"publication_authorized":false,"retirement_authorized":false,"remote_mutations":false,"r2_mutations":false})
}
fn private(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && path.canonicalize()? == path
            && path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-205-delivery-"))
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o777 == 0o700,
        "205 delivery control namespace escaped root-private custody"
    );
    Ok(())
}
fn write(path: &Path, v: &Value) -> Result<()> {
    private(path.parent().context("205 metadata parent missing")?)?;
    persist(path, v)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o400))?;
    file.sync_all()?;
    File::open(path.parent().context("205 metadata parent missing")?)?.sync_all()?;
    Ok(())
}
pub(super) fn command_name(command: &str) -> bool {
    matches!(
        command,
        "derive-continuation205-delivery"
            | "capture-continuation205-completion"
            | "prepare-continuation205-delivery"
            | "capture-continuation205-plugin-capacity"
            | "admit-continuation205-delivery-stage"
            | "run-continuation205-delivery-stage"
            | "release-continuation205-delivery-stage"
            | "capture-continuation205-stage-launch"
            | "capture-continuation205-stage-work"
            | "capture-continuation205-stage-terminal"
            | "publish-continuation205-delivery-status"
    )
}
pub(super) async fn run(command: &str) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "205 delivery issuer requires root"
    );
    let (spec, self_sha) = publication203::parsed_args(command)?;
    match command {
        "derive-continuation205-delivery" => lineage::prepare(&read(&spec)?, &spec, &self_sha),
        "capture-continuation205-completion" => {
            lineage::capture_completion(&read(&spec)?, &spec, &self_sha)
        }
        "prepare-continuation205-delivery" => delivery::prepare(&read(&spec)?, &spec, &self_sha),
        "capture-continuation205-plugin-capacity" => {
            delivery::capture_plugin(&read(&spec)?, &spec, &self_sha)
        }
        "admit-continuation205-delivery-stage" => {
            downstream::admit(&read(&spec)?, &spec, &self_sha)
        }
        "run-continuation205-delivery-stage" => {
            downstream::run_stage(&read(&spec)?, &spec, &self_sha).await
        }
        "release-continuation205-delivery-stage" => {
            startup::release(&read(&spec)?, &spec, &self_sha)
        }
        "capture-continuation205-stage-launch" => {
            peer::capture_launch(&read(&spec)?, &spec, &self_sha)
        }
        "capture-continuation205-stage-work" => peer::capture_work(&read(&spec)?, &spec, &self_sha),
        "capture-continuation205-stage-terminal" => {
            terminal::capture(&read(&spec)?, &spec, &self_sha)
        }
        "publish-continuation205-delivery-status" => {
            peer::publish(&read(&spec)?, &spec, &self_sha).await
        }
        _ => bail!("unknown205 delivery command"),
    }
}
pub(super) fn binding_scope(epoch: u64, unit: &str, phase: &str) -> bool {
    epoch == 205
        && downstream::Stage::all().iter().any(|s| {
            s.unit() == unit
                && if *s == downstream::Stage::Upload {
                    matches!(phase, "upload" | "readback")
                } else {
                    phase == "verification"
                }
        })
}
#[cfg(test)]
mod scope_tests {
    use super::*;
    #[test]
    fn continuation205_status_and_discovery_are_epoch_and_phase_exact() {
        assert!(binding_scope(
            205,
            downstream::Stage::Full.unit(),
            "verification"
        ));
        assert!(!binding_scope(
            204,
            downstream::Stage::Full.unit(),
            "verification"
        ));
        assert!(!binding_scope(
            205,
            downstream::Stage::Full.unit(),
            "upload"
        ));
        assert!(!binding_scope(205, UNIT, "verification"));
        assert!(discovery_scope(
            "horizon-boundary-verify-205-unregistered.service"
        ));
        assert!(discovery_scope("horizon-import-205-unregistered.service"));
        assert!(discovery_scope("horizon-205-delivery-unregistered.service"));
        assert!(!discovery_scope("horizon-import-204-unregistered.service"));
    }
}
