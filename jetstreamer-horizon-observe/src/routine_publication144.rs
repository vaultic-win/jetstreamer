//! Metadata-only adoption of one genuinely captured exact144 local publisher.
use super::*;
#[path = "routine_publication144_status.rs"]
mod status;
#[path = "routine_publication144_upload.rs"]
mod upload;
pub(super) use status::publish_using;
pub(super) fn publish(p: &Plan, pipeline: &Value, observer: &Bound) -> Result<Value> {
    if uploading(p) {
        validate(p)?;
        let provisional: Bound = serde_json::from_value(pipeline["provisional_fleet"].clone())?;
        if let Some(completed) = public198::ready_delivery(p, &provisional, observer, 144)? {
            return Ok(completed);
        }
    }
    status::publish(p, pipeline, observer)
}
pub(super) fn validate_completed(p: &Plan, c: &Value) -> Result<()> {
    let d = &c["epoch144_delivery"];
    if d["delivery_completed"] == true {
        ensure!(
            uploading(p),
            "144 completed delivery lacks historical upload profile"
        );
        validate(p)?;
        let provisional: Bound = serde_json::from_value(d["provisional_fleet"].clone())?;
        ensure!(
            provisional.path == p.cycle_directory.join("public198-provisional-fleet.json"),
            "144 ready fleet path differs"
        );
        let observer: Bound = serde_json::from_value(c["observer"].clone())?;
        ensure!(
            public198::ready_delivery(p, &provisional, &observer, 144)?.as_ref() == Some(d),
            "144 completed delivery metadata differs from authenticated history"
        );
        return Ok(());
    }
    status::validate_completed(p, c)
}
pub(super) const HISTORY_READER: &str =
    "/usr/local/lib/jetstreamer/horizon-publication144-fleet-reader-20261023-v4/jetstreamer-r2";
pub(super) const HISTORY_READER_SHA: &str =
    "0ac98fef0a7397ba2f5cb879ff829dfc1a4a33a2b3d7c0cf1789764e04cd2e70";
pub(super) fn upgrade_reader(p: &mut Plan) {
    if p.publication144.is_some()
        && p.tools.r2.path == Path::new(COMPOSITE_READER)
        && p.tools.r2.sha256 == COMPOSITE_READER_SHA
    {
        p.tools.r2 = Bound {
            path: HISTORY_READER.into(),
            sha256: HISTORY_READER_SHA.into(),
        };
    }
}
const UNIT: &str = "horizon-publish-144-v4-20261022-v1.service";
const LAUNCH: &str = "/var/lib/jetstreamer/horizon-publication144-owner-20261022-v1/launch.json";
const TOOL: &str = "/usr/local/lib/jetstreamer/horizon-epoch144-publisher-candidate-20261022-v6/jetstreamer-epoch144-publish";
const TOOL_SHA: &str = "4274f83c6d84a2bc2014b30122a38406b6498045f543ba170598baa8369a7efa";
const TRACKER_SHA: &str = "b85dc978377f20036ecd40cb4495729f27c2e8dc906c3cb2576463d9adf1dc75";
pub(super) const READER: &str =
    "/usr/local/lib/jetstreamer/horizon-publication144-fleet-reader-20261022-v3/jetstreamer-r2";
pub(super) const READER_SHA: &str =
    "26fa2fddce3ddaa42753525bda6ef140380555ea055d42ab633aed8879d632f4";
pub(super) const COMPOSITE_READER: &str =
    "/usr/local/lib/jetstreamer/horizon-publication144-progress-client-20261022-v1/jetstreamer-r2";
pub(super) const COMPOSITE_READER_SHA: &str =
    "c91b5ab379e876c6426be82adb381644927e7b5a199e3709dc9ce59dc2a6d96a";
pub(super) fn composite_reader(p: &Plan) -> bool {
    p.publication144.is_some()
        && p.census141_poh.is_some()
        && native141::all_retry_enabled(p)
        && native141::acquisition_enabled(p)
        && p.assembly144_scans.is_some()
        && ((p.tools.r2.path == Path::new(COMPOSITE_READER)
            && p.tools.r2.sha256 == COMPOSITE_READER_SHA)
            || (p.tools.r2.path == Path::new(HISTORY_READER)
                && p.tools.r2.sha256 == HISTORY_READER_SHA)
            || original141::reader(p))
}
const ACTIVE: &str = "Track exact144 local publisher; preserve original assembly and independently scanned/copy-hashed artifact. Capture terminal outcome promptly, then dispatch only exact full/plugin-gated authenticated R2 upload/readback and sidecar. Local publication is not remote readiness or retirement authority.";
const SUCCESS: &str = "Exact144 publisher is terminal-success; capture terminal receipt and revalidate actual committed publication, canonical archive/checksum and private full/plugin gates before authenticated R2 delivery. Service success alone is not archive or ready-pair proof.";
const FAILED: &str = "Exact144 publisher terminated unsuccessfully; capture terminal evidence immediately, preserve original and partial/copy/transaction receipts, remove any owned stale countdown through qualified lifecycle, and diagnose/recover the exact no-clobber transaction. Never blindly restart or discard valid artifacts.";
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    launch: Bound,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    upload: Option<Bound>,
}
pub(super) fn uploading(p: &Plan) -> bool {
    p.publication144
        .as_ref()
        .is_some_and(|s| s.upload.is_some())
}
pub(super) fn reader(p: &Plan) -> bool {
    p.publication144.is_some()
        && native141::acquisition_enabled(p)
        && p.assembly144_scans.is_some()
        && ((p.census141_poh.is_none()
            && p.tools.r2.path == Path::new(READER)
            && p.tools.r2.sha256 == READER_SHA)
            || composite_reader(p))
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
        if s.upload.is_some() {
            ensure!(
                composite_reader(p),
                "144 upload must retain complete composite history"
            );
            upload::checked(s)?;
        }
    }
    Ok(())
}
pub(super) fn retained_gate(p: &Plan, f: &Value) -> Result<Option<(Value, Value)>> {
    let Some(s) = &p.publication144 else {
        return Ok(None);
    };
    let claim = checked(&s.launch, &bound_json(&s.launch, true)?)?;
    if s.upload.is_some() {
        return upload::retained(s, f, &claim);
    }
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
        #[serde(default)]
        upload: Option<Bound>,
    }
    ensure!(
        native141::acquisition_enabled(p),
        "publisher adoption missing prior history"
    );
    let s: Spec = serde_json::from_value(bound_json(spec, true)?)?;
    ensure!(
        s.schema == "jetstreamer-exact144-publication-monitor-handoff-v1",
        "foreign publisher handoff"
    );
    checked(&s.launch, &bound_json(&s.launch, true)?)?;
    if let Some(prior) = &p.publication144 {
        ensure!(
            prior.launch.path == s.launch.path
                && prior.launch.sha256 == s.launch.sha256
                && prior.upload.is_none()
                && s.upload.is_some(),
            "144 handoff cannot replace origin or existing upload history"
        );
    }
    p.publication144 = Some(Profile {
        launch: s.launch,
        upload: s.upload,
    });
    p.tools.r2 = if p.census141_poh.is_some() {
        Bound {
            path: HISTORY_READER.into(),
            sha256: HISTORY_READER_SHA.into(),
        }
    } else {
        Bound {
            path: READER.into(),
            sha256: READER_SHA.into(),
        }
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
        s.upload.is_none() || success,
        "144 upload requires unchanged terminal-success publisher"
    );
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
    if s.upload.is_some() {
        upload::derive(s, f)?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn composite_reader_preserves_both_profiles_and_all_native_history() {
        let (p, ..) = crate::tests::fixture101();
        let mut v = serde_json::to_value(p).unwrap();
        let b = json!({"path":"/proof","sha256":"a".repeat(64)});
        v["native141_audit"] = json!({"first_guard":b,"rejection":b,"acquisition":b,
            "all_acquisition":{"path":"/home/sol/.jetstreamer-private/epoch141-native-acquisition-all-20261022-v1/results/initial-guard.json","sha256":"259ef91d98fac5e50704a349b08761365033b0a62df67140484ff682369f716c"},"all_retry":b});
        v["assembly144_scans"] = json!({"full":b,"plugin":b});
        v["publication144"] = json!({"launch":b});
        v["census141_poh"] = json!({"launch":b});
        v["tools"]["r2"] = json!({"path":COMPOSITE_READER,"sha256":COMPOSITE_READER_SHA});
        let p: Plan = serde_json::from_value(v.clone()).unwrap();
        assert!(composite_reader(&p));
        assert!(reader(&p));
        assert!(census141_poh::reader(&p));
        assert!(native141::all_acquisition_reader(&p));
        assert!(native141::acquisition_reader(&p));
        assert!(crate::generation_101(&p).starts_with("publication144-census141-poh-"));
        for pointer in [
            "/publication144",
            "/census141_poh",
            "/native141_audit/all_retry",
            "/native141_audit/acquisition",
            "/assembly144_scans",
        ] {
            let mut bad = v.clone();
            *bad.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(
                !composite_reader(&serde_json::from_value(bad).unwrap()),
                "{pointer}"
            );
        }
        v["tools"]["r2"] = json!({"path":READER,"sha256":READER_SHA});
        let p: Plan = serde_json::from_value(v).unwrap();
        assert!(!reader(&p));
        assert!(!census141_poh::reader(&p));
    }
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
