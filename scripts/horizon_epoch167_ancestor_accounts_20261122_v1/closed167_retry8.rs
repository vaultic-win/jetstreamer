//! Retry8 always restores its sealed bootstrap. Its stopped AppendVecs are disjoint
//! from the retained archive, original Bank, and the successor checkpoint route.
use super::retirement_evidence::{bound_bytes, digest, open_input, path, staged_references};
pub(super) use super::retirement_evidence::{leases, verify_campaign_lock, verify_image};
use super::*;

pub(super) const BASE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch167-retry8-accounts-retirement-20261127-v1";
pub(super) const PROFILE: &[u8] = include_bytes!("profiles167_retry8.json");
pub(super) const CHECK_SCHEMA: &str = "horizon167-retry8-stopped-accounts-check-v1";
pub(super) const COMPLETE_SCHEMA: &str = "horizon167-retry8-stopped-accounts-complete-v1";
const IID: &str = "93e60160c9164d3781a5b544fc2a48b4";
const BOOT_SHA: &str = "948ca3ec94f7c9c7bc970fa21fef5e388ba2c3357e7d39589de402257ab5b81f";

fn lineage(
    p: &Value,
    successor: &Value,
    original: &Value,
    args: &Value,
    scope: &Value,
) -> Result<()> {
    ensure!(
        p["iid"] == IID
            && original["producer_pid"] == 2472615
            && successor["predecessor_stop"] == p["stop"]
            && successor["epoch"] == 167
            && successor["producer_invocation_id"] == "0876e9944c784b41afeff1b666539ead",
        "stopped retry8 and successor do not match"
    );
    let argv = args.as_array().context("original cold-start argv")?;
    for arg in [
        "--setenv=JETSTREAMER_CLEAR_ACCOUNTS_ON_START=true",
        "--setenv=JETSTREAMER_LOAD_FROM_DIR=0",
        "--setenv=JETSTREAMER_VERIFY_SNAPSHOTS=1",
        "--setenv=JETSTREAMER_SKIP_SNAPSHOT_VERIFY=0",
        "--root-checkpoint-cohort",
        &format!(
            "--snapshot-archive={}",
            string(&scope["bootstrap"], "path")?
        ),
        &format!(
            "--cohort-manifest={}",
            string(&scope["cohort_manifest"], "path")?
        ),
    ] {
        ensure!(
            argv.iter().any(|v| v == arg),
            "missing original cold-start argument {arg}"
        );
    }
    Ok(())
}

pub(super) fn gates(p: &Value, manifest: &Value) -> Result<Value> {
    let anchors = ancestor_gates(p, manifest, &["local3retry8"])?;
    let target = Path::new(string(p, "target")?);
    let scope = &manifest["scope"];
    let boot = &scope["bootstrap"];
    lineage(
        p,
        &bound(&manifest["successor_bound_original_stop"])?,
        &bound(&p["admission"])?,
        &bound(&manifest["source_argv"])?,
        scope,
    )?;
    let seal = bound(&scope["bootstrap_seal"])?;
    let length = open_input(boot)?.metadata()?.len();
    let boot_path = path(boot)?;
    ensure!(
        !boot_path.starts_with(target)
            && seal["destination"].as_str() == boot_path.parent().and_then(Path::to_str)
            && seal["members"]
                .as_array()
                .is_some_and(|members| members.iter().any(|v| v["name"].as_str()
                    == boot_path.file_name().and_then(|n| n.to_str())
                    && v["sha256"] == BOOT_SHA
                    && v["bytes"] == length
                    && v["mode"] == "0444")),
        "bootstrap seal changed"
    );
    bound_bytes(&scope["cohort_manifest"], 1 << 20)?;
    let attempt = target
        .ancestors()
        .find(|p| {
            p.file_name()
                .is_some_and(|s| s == "replacement-local3retry8-20261110-v1")
        })
        .context("attempt root")?;
    let mut visited = std::collections::BTreeSet::new();
    for dir in [
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        "/run/systemd/transient",
        "/run/systemd/system",
        "/run/systemd/generator",
        "/run/systemd/generator.early",
        "/run/systemd/generator.late",
        "/etc/cron.d",
    ] {
        if Path::new(dir).try_exists()? {
            staged_references(Path::new(dir), &[attempt, target], &[], &mut visited)?;
        }
    }
    Ok(
        json!({"original":anchors,"bootstrap":boot,"cold_start":manifest["source_argv"],"successor":manifest["successor_bound_original_stop"]}),
    )
}

pub(super) fn check_inventory(
    p: &Value,
    manifest: &Value,
    ledger: &stopped_tree::Ledger,
    allocated: u64,
) -> Result<()> {
    check_appendvecs(p, ledger, allocated, 54853148672)?;
    ensure!(
        p["expected_entries"] == (ledger.len() - 1) as u64 && p["expected_bytes"] == allocated,
        "retry8 inventory changed"
    );
    ensure!(
        digest(&manifest["scope"]["bootstrap"])? == BOOT_SHA,
        "bootstrap payload changed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binds_both_the_original_stop_and_cold_start() {
        let m: Value = serde_json::from_slice(PROFILE).unwrap();
        let p = &m["profiles"]["local3retry8"];
        let s = &m["scope"];
        let original = json!({"producer_pid":2472615});
        let mut successor = json!({"producer_invocation_id":"0876e9944c784b41afeff1b666539ead","predecessor_stop":p["stop"],"epoch":167});
        let mut args = json!([
            "--setenv=JETSTREAMER_CLEAR_ACCOUNTS_ON_START=true",
            "--setenv=JETSTREAMER_LOAD_FROM_DIR=0",
            "--setenv=JETSTREAMER_VERIFY_SNAPSHOTS=1",
            "--setenv=JETSTREAMER_SKIP_SNAPSHOT_VERIFY=0",
            "--root-checkpoint-cohort",
            format!(
                "--snapshot-archive={}",
                s["bootstrap"]["path"].as_str().unwrap()
            ),
            format!(
                "--cohort-manifest={}",
                s["cohort_manifest"]["path"].as_str().unwrap()
            )
        ]);
        lineage(p, &successor, &original, &args, s).unwrap();
        successor["predecessor_stop"]["sha256"] = json!("changed");
        assert!(lineage(p, &successor, &original, &args, s).is_err());
        successor["predecessor_stop"] = p["stop"].clone();
        args[1] = json!("--setenv=JETSTREAMER_LOAD_FROM_DIR=1");
        assert!(lineage(p, &successor, &original, &args, s).is_err());
    }
}
