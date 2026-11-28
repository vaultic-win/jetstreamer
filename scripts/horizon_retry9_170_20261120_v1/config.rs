//! Print a stage configuration from the current authenticated fleet and sealed artifacts.
use super::*;

fn contract_binding(generation: &str) -> Result<Value> {
    let dir = format!("{BASE}/data-contract-{generation}");
    let bind = |name: &str| -> Result<Value> {
        let path = format!("{dir}/{name}");
        let binding = peer::pair(&path, &format!("{:x}", Sha256::digest(fs::read(&path)?)));
        peer::bound(&binding)?;
        Ok(binding)
    };
    Ok(
        json!({"contract":bind("contract.json")?, "deployment_seal":bind("deployment-seal-receipt.json")?}),
    )
}

pub(super) fn config(args: &[String]) -> Result<Value> {
    ensure!(
        matches!(args.len(), 4 | 6),
        "stage-config FLEET SHA OPERATION GENERATION [MEASUREMENT SHA]"
    );
    let (operation, generation) = (args[2].as_str(), args[3].as_str());
    ensure!(
        !generation.is_empty()
            && generation.len() <= 32
            && generation
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
        "invalid witness generation"
    );
    ensure!(
        matches!(operation, "witness" | "measure" | "prepare" | "launch-plan")
            && (args.len() == 6) == (operation == "prepare"),
        "invalid operation or measurement"
    );
    let fleet_binding = peer::pair(&args[0], &args[1]);
    let fleet = peer::bound(&fleet_binding)?;
    terminal8::authenticate(&fleet["latest_terminal_retry8_170"])?;
    let evidence = peer::evidence()?;
    peer::live(&evidence)?;
    let live = fleet["actual_executing_replays"]
        .as_array()
        .context("fleet replays")?
        .iter()
        .chain(
            fleet["actual_active_bootstraps"]
                .as_array()
                .context("fleet bootstraps")?,
        )
        .collect::<Vec<_>>();
    let owners = peer::owners(&evidence);
    ensure!(
        owners.len() == 2
            && owners.len() == live.len()
            && owners
                .iter()
                .all(|o| live.iter().any(|v| v["epoch"] == o["epoch"]
                    && v["unit"]["Id"] == o["unit"]
                    && v["unit"]["InvocationID"] == o["invocation_id"]
                    && v["admission"] == o["admission"]
                    && v["guard_protection"] == o["guard_protection"])),
        "selected fleet differs from current admitted producers"
    );
    ensure!(
        fleet["latest_terminal170_observation"]["sha256"]
            == "e6aa44d51e8375e10428372ad2e15d391a8ac866d7bdb39e6b979f75761b2760"
            && fleet["owner"] == "/root"
            && fleet["primary_thread"] == "01a1af2a-9ce8-76a2-8939-b2112bd38f53",
        "wrong fleet owner"
    );
    let roots = peer::bound(&peer::pair(ROOTS, ROOTS_SHA))?;
    let path = Path::new(LANE).join(ATTEMPT);
    let stat = fs::symlink_metadata(&path)?;
    let row = roots["roots"]
        .as_array()
        .context("roots")?
        .iter()
        .find(|r| r["epoch"] == 170)
        .context("170 root")?;
    ensure!(
        path.canonicalize()? == path
            && row["path"] == json!(path)
            && stat.is_dir()
            && row["dev"] == stat.dev()
            && row["ino"] == stat.ino(),
        "170 root identity changed"
    );
    let mut cfg = json!({"schema":"horizon-170-retry9-joined-stage-config-v1","owner":"/root","primary_thread":fleet["primary_thread"],"operation":operation,"fleet":fleet_binding,"observer":fleet["observer"],"status":fleet["authenticated_status_audit"],"inventory":fleet["authenticated_inventory"],"next_observer":fleet["sole_next_observer"],"fresh_subtree_identity":{"path":path,"device":stat.dev(),"inode":stat.ino()},"witness_generation":{"generation":generation,"output_root":format!("{BASE}/stage-state/guard-witness-{generation}"),"unit":format!("horizon-170-retry9-witness-{generation}-20261120.service"),"contract_destination":format!("{BASE}/data-contract-{generation}")}});
    match operation {
        "measure" => cfg["measurement_contract"] = contract_binding(generation)?,
        "prepare" => {
            cfg["fresh_contract"] = contract_binding(generation)?;
            cfg["measurement"] = peer::pair(&args[4], &args[5]);
            let m = peer::bound(&cfg["measurement"])?;
            let predecessor = peer::bound(&m["fleet"])?;
            ensure!(
                predecessor["previous_Root_operational_review"] == cfg["fleet"]
                    && predecessor["observer"] == cfg["observer"],
                "measurement belongs to another fleet or observer"
            );
        }
        _ => {}
    }
    Ok(cfg)
}
