//! Exact private scan adoption; never an ordinary replay or ETA claim.
use super::*;
const ROOT: &str = "/var/lib/jetstreamer/horizon-assembly144-scan-launches-20261022-v1";
const RUNNER: &str = "/usr/local/lib/jetstreamer/horizon-epoch144-assembly-scan-tools-20261022-v1/jetstreamer-epoch144-private-verify";
const RUNNER_SHA: &str = "7dfe0fdabbee8e5f79b131c2b7cece49dbebe489168fe195a9086ab25f0b8810";
const READER: &str =
    "/usr/local/lib/jetstreamer/horizon-assembly144-scans-fleet-reader-20261022-v1/jetstreamer-r2";
const READER_SHA: &str = "b67f113c2e54ec42751583bd3a4fdd0ab56e393de7b25e845973737c93926115";
pub(super) fn reader(p: &Plan) -> bool {
    p.assembly144_scans.is_some()
        && p.tools.r2.path == Path::new(READER)
        && p.tools.r2.sha256 == READER_SHA
        && is_sha(READER_SHA)
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    full: Bound,
    plugin: Bound,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    full: Bound,
    plugin: Bound,
    replay_launch_authorized: bool,
    publication_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}
fn checked(stage: &str, b: &Bound, r: &Value) -> Result<Value> {
    let digest = match stage {
        "full" => "5f7aac2e313dc61f54f0fe8fc88b126a3a11583e2493af63d33d75ad459cca8b",
        "plugin" => "c0206e2bd72d9bcc21aa8a2783537333ba6580cbeaeba8954245078b2dccabfa",
        _ => anyhow::bail!("foreign scan stage"),
    };
    let unit = format!("horizon-assembly144-{stage}-verification-20261022-v1.service");
    let plan = format!(
        "/usr/local/lib/jetstreamer/horizon-epoch144-assembly-scan-plan-20261022-v1/{stage}.json"
    );
    let command = format!(
        "{{ path={RUNNER} ; argv[]={RUNNER} {plan} --plan-sha256 {digest} --self-sha256 {RUNNER_SHA}"
    );
    ensure!(
        b.path == Path::new(ROOT).join(stage).join("launch.json")
            && is_sha(&b.sha256)
            && r["schema"] == "jetstreamer-private144-assembly-only-scan-launch-v1"
            && r["epoch"] == 144
            && r["unit"] == unit
            && r["runner_sha256"] == RUNNER_SHA
            && r["private_verification_only"] == true
            && r["invocation_id"].as_str().is_some_and(|s| s.len() == 32
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            && r["scan_plan"]["path"] == plan
            && r["scan_plan"]["sha256"] == digest
            && r["producer_outcome"]["path"]
                == "/usr/local/lib/jetstreamer/horizon-assembly144-outcome-evidence-20261022-v1/assembly.json"
            && r["producer_outcome"]["sha256"]
                == "11cd3172f6cd5e26b98a3446205cb7ef1732bdfc56138cc30caed0f2c0e496ea"
            && r["expected_exec_start"]
                .as_str()
                .and_then(|s| s.split_once(" ; ignore_errors="))
                .map(|(s, _)| s)
                == Some(command.as_str()),
        "foreign assembly144 scan capture"
    );
    for flag in [
        "ordinary_replay_claim",
        "current_sidecar_eta_valid",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
        "replay_launch_authorized",
        "local_retirement_authorized",
    ] {
        ensure!(r[flag] == false, "scan capture grants authority:{flag}");
    }
    Ok(
        json!({"epoch":144,"phase":format!("private-{stage}-verification"),"unit":unit,
        "invocation_id":r["invocation_id"],"expected_exec_start":r["expected_exec_start"],"evidence":[b]}),
    )
}
pub(super) fn validate(p: &Plan) -> Result<()> {
    if let Some(s) = &p.assembly144_scans {
        ensure!(
            is_101(p)?
                && native141::reader(p)
                && native141::rejection_enabled(p)
                && p.assembly144_recovery.is_some()
                && !p.expected_epochs.contains(&144),
            "scan handoff cannot borrow another profile or ordinary claims"
        );
        for (stage, b) in [("full", &s.full), ("plugin", &s.plugin)] {
            checked(stage, b, &bound_json(b, true)?)?;
        }
    }
    Ok(())
}
pub(super) fn enable(p: &mut Plan, b: &Bound) -> Result<()> {
    ensure!(
        p.assembly144_scans.is_none(),
        "scan profile already adopted"
    );
    let s: Spec = serde_json::from_value(bound_json(b, true)?)?;
    ensure!(
        s.schema == "jetstreamer-assembly144-scans-monitor-handoff-v1"
            && !s.replay_launch_authorized
            && !s.publication_authorized
            && !s.remote_mutations
            && !s.r2_mutations,
        "foreign or authorizing scan handoff"
    );
    p.assembly144_scans = Some(Profile {
        full: s.full,
        plugin: s.plugin,
    });
    p.tools.r2 = Bound {
        path: READER.into(),
        sha256: READER_SHA.into(),
    };
    validate(p)
}
fn fold(f: &mut Value, c: Value) -> Result<()> {
    let rows = f["pipeline_claims"]
        .as_array_mut()
        .context("scan pipeline history")?;
    let found: Vec<_> = rows.iter().filter(|r| r["unit"] == c["unit"]).collect();
    ensure!(
        found.is_empty() || (found.len() == 1 && found[0] == &c),
        "scan history changed or duplicated"
    );
    if found.is_empty() {
        rows.push(c.clone());
    }
    let units = f["tracked_units"]
        .as_array_mut()
        .context("scan tracked units")?;
    if !units.contains(&c["unit"]) {
        units.push(c["unit"].clone());
    }
    let gate = &mut f["gates"]["144"];
    ensure!(
        gate["state"] == "blocked-qualification",
        "private scans cannot close144 qualification"
    );
    gate["next_action"] = json!(
        "Preserve successful private144 assembly and captured independent full/plugin scanners. Inspect actual terminal receipts/logs; a plan, capture or assembly is not scan success. V4-specific canonical import, full/plugin digest agreement and normal R2 ready-pair gates remain separate; no ordinary ETA or canonical sidecar from private scans."
    );
    let evidence = gate["evidence"]
        .as_array_mut()
        .context("scan repair evidence")?;
    for b in c["evidence"].as_array().context("scan evidence")? {
        if !evidence.contains(b) {
            evidence.push(b.clone());
        }
    }
    Ok(())
}
pub(super) fn derive_fleet(p: &Plan, f: &mut Value) -> Result<()> {
    let Some(s) = &p.assembly144_scans else {
        return Ok(());
    };
    validate(p)?;
    for (stage, b) in [("full", &s.full), ("plugin", &s.plugin)] {
        fold(f, checked(stage, b, &bound_json(b, true)?)?)?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(stage: &str) -> (Bound, Value) {
        let digest = if stage == "full" {
            "5f7aac2e313dc61f54f0fe8fc88b126a3a11583e2493af63d33d75ad459cca8b"
        } else {
            "c0206e2bd72d9bcc21aa8a2783537333ba6580cbeaeba8954245078b2dccabfa"
        };
        let plan = format!(
            "/usr/local/lib/jetstreamer/horizon-epoch144-assembly-scan-plan-20261022-v1/{stage}.json"
        );
        let b = Bound {
            path: Path::new(ROOT).join(stage).join("launch.json"),
            sha256: "a".repeat(64),
        };
        let mut r = json!({"schema":"jetstreamer-private144-assembly-only-scan-launch-v1","epoch":144,
            "unit":format!("horizon-assembly144-{stage}-verification-20261022-v1.service"),"runner_sha256":RUNNER_SHA,
            "private_verification_only":true,"invocation_id":"b".repeat(32),"scan_plan":{"path":plan,"sha256":digest},
            "producer_outcome":{"path":"/usr/local/lib/jetstreamer/horizon-assembly144-outcome-evidence-20261022-v1/assembly.json","sha256":"11cd3172f6cd5e26b98a3446205cb7ef1732bdfc56138cc30caed0f2c0e496ea"},
            "expected_exec_start":format!("{{ path={RUNNER} ; argv[]={RUNNER} {plan} --plan-sha256 {digest} --self-sha256 {RUNNER_SHA} ; ignore_errors=no }}")});
        for k in [
            "ordinary_replay_claim",
            "current_sidecar_eta_valid",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
            "replay_launch_authorized",
            "local_retirement_authorized",
        ] {
            r[k] = json!(false);
        }
        (b, r)
    }
    #[test]
    fn exact_capture_stage_owner_source_command_and_false_authority() {
        for stage in ["full", "plugin"] {
            let (b, r) = fixture(stage);
            checked(stage, &b, &r).unwrap();
            for k in r.as_object().unwrap().keys() {
                let mut bad = r.clone();
                bad[k] = Value::Null;
                assert!(
                    checked(stage, &b, &bad).is_err(),
                    "accepted missing{stage}/{k}"
                );
            }
            assert!(checked(if stage == "full" { "plugin" } else { "full" }, &b, &r).is_err());
        }
    }
    #[test]
    fn private_fold_is_idempotent_and_preserves_consensus_history() {
        let (b, r) = fixture("full");
        let c = checked("full", &b, &r).unwrap();
        let mut f = json!({"pipeline_claims":[],"tracked_units":[],"gates":{"144":{"state":"blocked-qualification","evidence":[]}},
            "diagnostics":[{"preserved":u64::MAX}],"epochs":[152,153,155,156,160,191,192,193,194]});
        fold(&mut f, c.clone()).unwrap();
        let once = f.clone();
        fold(&mut f, c.clone()).unwrap();
        assert_eq!(once, f);
        assert_eq!(f["pipeline_claims"].as_array().unwrap().len(), 1);
        assert_eq!(f["diagnostics"][0]["preserved"], u64::MAX);
        assert_eq!(
            f["epochs"],
            json!([152, 153, 155, 156, 160, 191, 192, 193, 194])
        );
        let mut changed = c;
        changed["invocation_id"] = "f".repeat(32).into();
        assert!(fold(&mut f, changed).is_err());
    }
}
