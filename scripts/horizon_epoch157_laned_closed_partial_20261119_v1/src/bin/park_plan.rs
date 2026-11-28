//! Emit exact append-only park inputs; Root separately seals and admits execution.
use anyhow::{Context, Result, ensure};
use horizon_epoch157_laned_closed_partial::*;
use serde_json::{Value, json};
use std::{fs, path::Path};

fn main() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    ensure!(
        unsafe { libc::geteuid() } == 0
            && a.len() == 5
            && a[1] == "--inspection-sha256"
            && digest(&a[2])
            && a[3] == "--self-sha256"
            && digest(&a[4]),
        "root; --inspection-sha256 HEX --self-sha256 HEX"
    );
    ensure!(
        sha(&fs::read("/proc/self/exe")?) == a[4],
        "running plan image changed"
    );
    let bytes = bound(INSPECTION, &a[2])?;
    let i: Value = serde_json::from_slice(&bytes)?;
    let archive_sha = validate_inspection(&i, now()?)?;
    ensure!(
        exact_source()? == i["source_identity"] && preserved_snapshot()? == i["snapshot_identity"],
        "source changed after actual inspection"
    );
    empty_root(Path::new(PLAN_ROOT))?;
    let mapping_path = "/usr/local/lib/jetstreamer/horizon-node02-holding-20261023-v1/mapping.json";
    let mapping_sha = "61f7601f78a7aa1f71394a020cbbb28aa9dbd85de858f139def1c989f2b2a89e";
    bound(mapping_path, mapping_sha)?;
    let eligibility = save(
        &Path::new(PLAN_ROOT).join("eligibility.json"),
        &json!({"schema":"jetstreamer-horizon-holding-eligibility-v2","host":"dev-samjohnson","source":SOURCE,"length":LENGTH,"sha256":archive_sha,"closed":true,"content_class":"public-chain-artifact","credentials_config_and_logs_excluded":true,"canonical_archive":false,"local_retirement_authorized":false,"owner":"/root","inspection":{"path":INSPECTION,"sha256":a[2]},"purpose":"Append-only custody of old lane-d epoch157 partial for separately qualified capacity recovery; preserve sibling snapshot and original evidence","historical_stop_proven":false,"original_invocation_id":null,"closure_basis":"exact-seven-controller-leases-and-current-no-owner","complete_transitive_consumer_graph_qualified":false,"replay_launch_authorized":false,"valid_prefix_established":false,"runtime_checkpoint_qualified":false,"resource_credit_bytes":0,"restore_overlap_bytes":LENGTH,"restore_trigger":"Only if a separately admitted retained-prefix consumer requires these exact bytes","existing_replay_reservations_retained":true,"resource_admission_required":true}),
    )?;
    let plan = save(
        &Path::new(PLAN_ROOT).join("plan.json"),
        &json!({"schema":"jetstreamer-horizon-holding-park-plan-v2","mapping":{"path":mapping_path,"sha256":mapping_sha},"eligibility":{"path":format!("{PLAN_DEST}/eligibility.json"),"sha256":eligibility["sha256"]},"source":SOURCE,"length":LENGTH,"sha256":archive_sha}),
    )?;
    let members = [("eligibility.json", eligibility), ("plan.json", plan)]
        .into_iter()
        .map(|(name, b)| json!({"source":b["path"],"name":name,"sha256":b["sha256"],"mode":292}))
        .collect::<Vec<_>>();
    let seal = save(
        &Path::new(PLAN_ROOT).join("holding-seal-plan.json"),
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":PLAN_DEST,"members":members}),
    )?;
    ensure!(
        seal["path"]
            .as_str()
            .context("seal output")?
            .ends_with("holding-seal-plan.json"),
        "seal output changed"
    );
    println!(
        "{}",
        json!({"seal_plan":seal,"sealer_not_executed":true,"transfer_not_started":true,"local_retirement_authorized":false})
    );
    Ok(())
}
