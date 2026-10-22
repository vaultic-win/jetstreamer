//! Metadata-only adoption of one genuinely captured exact144 local publisher.
use super::*;
const UNIT: &str = "horizon-publish-144-v4-20261022-v1.service";
const LAUNCH: &str = "/var/lib/jetstreamer/horizon-publication144-owner-20261022-v1/launch.json";
const TOOL: &str = "/usr/local/lib/jetstreamer/horizon-epoch144-publisher-candidate-20261022-v4/jetstreamer-epoch144-publish";
const TOOL_SHA: &str = "1b5e71ad4d7fb3ed7b5ac3143fabaad110dfeca7d978e186d6b86264bcbc17eb";
const TRACKER_SHA: &str = "0c2dc05018a46c7054790130565b13f83c8e235934e172730370d660c681ca0d";
const READER: &str =
    "/usr/local/lib/jetstreamer/horizon-publication144-fleet-reader-20261022-v1/jetstreamer-r2";
const READER_SHA: &str = "785aa2eb66b5da9817eabf17021a810bff0fd726dd500f21e332dbf5b34789b1";
const ACTIVE: &str = "Track exact144 local publisher; preserve original assembly and independently scanned/copy-hashed artifact. Capture terminal outcome promptly, then dispatch only exact full/plugin-gated authenticated R2 upload/readback and sidecar. Local publication is not remote readiness or retirement authority.";
const SUCCESS: &str = "Exact144 publisher is terminal-success; capture terminal receipt and revalidate actual committed publication, canonical archive/checksum and private full/plugin gates before authenticated R2 delivery. Service success alone is not archive or ready-pair proof.";
const FAILED: &str = "Exact144 publisher terminated unsuccessfully; capture terminal evidence immediately, preserve original and partial/copy/transaction receipts, remove any owned stale countdown through qualified lifecycle, and diagnose/recover the exact no-clobber transaction. Never blindly restart or discard valid artifacts.";
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    launch: Bound,
}
pub(super) fn reader(p: &Plan) -> bool {
    p.publication144.is_some()
        && native141::acquisition_enabled(p)
        && p.assembly144_scans.is_some()
        && p.tools.r2.path == Path::new(READER)
        && p.tools.r2.sha256 == READER_SHA
}
fn checked(b: &Bound, r: &Value) -> Result<Value> {
    ensure!(
        b.path == Path::new(LAUNCH)
            && is_sha(&b.sha256)
            && r["schema"] == "jetstreamer-exact144-publication-launch-v1"
            && r["epoch"] == 144
            && r["launched"] == true
            && r["publisher_sha256"] == TOOL_SHA
            && r["tracker_sha256"] == TRACKER_SHA
            && r["claim"]["epoch"] == 144
            && r["claim"]["phase"] == "local-publication"
            && r["claim"]["unit"] == UNIT
            && r["claim"]["invocation_id"]
                .as_str()
                .is_some_and(|s| s.len() == 32
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
        "foreign exact144 captured publisher"
    );
    for flag in [
        "ordinary_replay_claim",
        "current_sidecar_eta_valid",
        "publication_authorized",
        "retirement_authorized",
        "r2_mutations",
        "remote_mutations",
    ] {
        ensure!(
            r[flag] == false,
            "publisher capture grants authority:{flag}"
        );
    }
    let pb: Bound = serde_json::from_value(r["publisher_plan"].clone())?;
    let v = bound_json(&pb, true)?;
    ensure!(
        v["schema"] == "jetstreamer-exact144-v4-publication-plan-v2"
            && v["artifact_publication_authorized"] == true
            && v["remote_mutations"] == false
            && v["r2_mutations"] == false,
        "publisher capture requires sealed exact v2 plan"
    );
    let command = format!(
        "{{ path={TOOL} ; argv[]={TOOL} {} --plan-sha256 {} --self-sha256 {TOOL_SHA}",
        pb.path.display(),
        pb.sha256
    );
    ensure!(
        r["claim"]["expected_exec_start"]
            .as_str()
            .and_then(|s| s.split_once(" ; ignore_errors="))
            .is_some_and(|(a, b)| a == command && b.starts_with("no ;")),
        "publisher command changed"
    );
    let ib: Bound = serde_json::from_value(r["intent"].clone())?;
    let i = bound_json(&ib, false)?;
    ensure!(
        i["schema"] == "jetstreamer-exact144-v4-publication-context-v1"
            && i["plan"] == r["publisher_plan"]
            && i["publisher_sha256"] == TOOL_SHA
            && i["admission"]["refreshed_capacity"]["protected_bytes"] == 3984782679494u64,
        "captured publisher lacks exact fresh admission intent"
    );
    let mut claim = r["claim"].clone();
    claim["evidence"] = json!([b]);
    Ok(claim)
}
pub(super) fn validate(p: &Plan) -> Result<()> {
    if let Some(s) = &p.publication144 {
        ensure!(
            is_101(p)? && reader(p) && !p.expected_epochs.contains(&144),
            "publisher cannot borrow replay or another reader"
        );
        checked(&s.launch, &bound_json(&s.launch, true)?)?;
    }
    Ok(())
}
pub(super) fn retained_gate(p: &Plan, f: &Value) -> Result<Option<(Value, Value)>> {
    let Some(s) = &p.publication144 else {
        return Ok(None);
    };
    let claim = checked(&s.launch, &bound_json(&s.launch, true)?)?;
    retained_gate_from(f, &claim, &s.launch)
}
fn retained_gate_from(f: &Value, claim: &Value, launch: &Bound) -> Result<Option<(Value, Value)>> {
    let rows = f["pipeline_claims"]
        .as_array()
        .context("publication history")?;
    if !rows.iter().any(|r| r["unit"] == UNIT) {
        return Ok(None);
    }
    let gate = &f["gates"]["144"];
    ensure!(
        rows.iter().filter(|r| r["unit"] == UNIT).count() == 1
            && rows.contains(claim)
            && gate["evidence"]
                .as_array()
                .is_some_and(|a| a.contains(&serde_json::to_value(launch).unwrap()))
            && matches!(
                (gate["state"].as_str(), gate["next_action"].as_str()),
                (Some("post-replay-pipeline"), Some(ACTIVE | SUCCESS))
                    | (Some("failed-needs-repair"), Some(FAILED))
            ),
        "publisher history/gate changed"
    );
    Ok(Some((gate["state"].clone(), gate["next_action"].clone())))
}
pub(super) fn enable(p: &mut Plan, spec: &Bound) -> Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Spec {
        schema: String,
        launch: Bound,
    }
    ensure!(
        p.publication144.is_none() && native141::acquisition_enabled(p),
        "publisher adoption already present or missing prior history"
    );
    let s: Spec = serde_json::from_value(bound_json(spec, true)?)?;
    ensure!(
        s.schema == "jetstreamer-exact144-publication-monitor-handoff-v1",
        "foreign publisher handoff"
    );
    checked(&s.launch, &bound_json(&s.launch, true)?)?;
    p.publication144 = Some(Profile { launch: s.launch });
    p.tools.r2 = Bound {
        path: READER.into(),
        sha256: READER_SHA.into(),
    };
    validate(p)
}
pub(super) fn derive_fleet(p: &Plan, f: &mut Value) -> Result<()> {
    let Some(s) = &p.publication144 else {
        return Ok(());
    };
    validate(p)?;
    let r = bound_json(&s.launch, true)?;
    let claim = checked(&s.launch, &r)?;
    let rows = f["pipeline_claims"]
        .as_array_mut()
        .context("publisher claims")?;
    let found: Vec<_> = rows.iter().filter(|c| c["unit"] == UNIT).collect();
    ensure!(
        found.is_empty() || (found.len() == 1 && found[0] == &claim),
        "publisher history cannot be replaced"
    );
    if found.is_empty() {
        rows.push(claim);
    }
    let units = f["tracked_units"]
        .as_array_mut()
        .context("tracked publisher")?;
    if !units.contains(&json!(UNIT)) {
        units.push(json!(UNIT));
    }
    let o = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            UNIT,
            "--property=InvocationID,NRestarts,ActiveState,SubState,MainPID,Result,ExecMainStatus",
        ])
        .output()?;
    ensure!(o.status.success(), "publisher current state unreadable");
    let m: BTreeMap<_, _> = std::str::from_utf8(&o.stdout)?
        .lines()
        .filter_map(|l| l.split_once('='))
        .collect();
    let current = serde_json::to_value(m)?;
    ensure!(
        current["InvocationID"] == r["claim"]["invocation_id"] && current["NRestarts"] == "0",
        "publisher identity changed"
    );
    let live = (current["ActiveState"] == "active" && current["SubState"] == "running")
        || current["ActiveState"] == "activating";
    let success = current["ActiveState"] == "active"
        && current["SubState"] == "exited"
        && current["MainPID"] == "0"
        && current["Result"] == "success"
        && current["ExecMainStatus"] == "0";
    ensure!(
        live || success
            || current["ActiveState"] == "failed"
            || current["ActiveState"] == "inactive",
        "unknown publisher state"
    );
    let g = &mut f["gates"]["144"];
    g["state"] = json!(if live || success {
        "post-replay-pipeline"
    } else {
        "failed-needs-repair"
    });
    g["next_action"] = json!(if live {
        ACTIVE
    } else if success {
        SUCCESS
    } else {
        FAILED
    });
    let e = g["evidence"]
        .as_array_mut()
        .context("publisher gate evidence")?;
    let b = serde_json::to_value(&s.launch)?;
    if !e.contains(&b) {
        e.push(b);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_delivery_gate_requires_identical_capture_and_known_action() {
        let b = Bound {
            path: LAUNCH.into(),
            sha256: "a".repeat(64),
        };
        let c = json!({"unit":UNIT,"invocation_id":"b".repeat(32)});
        let f = json!({"pipeline_claims":[c],"gates":{"144":{"state":"post-replay-pipeline","next_action":ACTIVE,"evidence":[b]}}});
        assert!(retained_gate_from(&f, &c, &b).unwrap().is_some());
        for (pointer, value) in [
            ("/gates/144/next_action", json!("unknown newer action")),
            ("/gates/144/state", json!("remote-ready")),
            ("/gates/144/evidence", json!([])),
            ("/pipeline_claims/0/invocation_id", json!("c".repeat(32))),
        ] {
            let mut v = f.clone();
            *v.pointer_mut(pointer).unwrap() = value;
            assert!(retained_gate_from(&v, &c, &b).is_err(), "{pointer}");
        }
        let mut v = f;
        v["pipeline_claims"] = json!([]);
        assert!(retained_gate_from(&v, &c, &b).unwrap().is_none());
    }
    #[test]
    fn publication_reader_needs_acquisition_and_private_scan_histories() {
        let (p, ..) = crate::tests::fixture101();
        let mut v = serde_json::to_value(p).unwrap();
        let b = json!({"path":"/proof","sha256":"a".repeat(64)});
        v["native141_audit"] = json!({"first_guard":b,"rejection":b,"acquisition":b});
        v["assembly144_scans"] = json!({"full":b,"plugin":b});
        v["publication144"] = json!({"launch":b});
        v["tools"]["r2"] = json!({"path":READER,"sha256":READER_SHA});
        let p: Plan = serde_json::from_value(v.clone()).unwrap();
        assert!(reader(&p));
        assert!(native141::acquisition_reader(&p));
        for pointer in [
            "/native141_audit/acquisition",
            "/assembly144_scans",
            "/publication144",
        ] {
            let mut wrong = v.clone();
            *wrong.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(!reader(&serde_json::from_value(wrong).unwrap()));
        }
        v["tools"]["r2"]["sha256"] = json!("f".repeat(64));
        assert!(!reader(&serde_json::from_value(v).unwrap()));
    }
}
