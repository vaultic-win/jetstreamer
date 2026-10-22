//! Metadata-only adoption of the exact actual guarded native141 acquisition.
//! The observer/model/status census is unchanged; this is not a new replay lane.
use super::*;
#[path = "routine_native141_acquisition.rs"]
mod acquisition;
#[path = "routine_native141_all_acquisition.rs"]
mod all_acquisition;
#[path = "routine_native141_all_retry.rs"]
mod all_retry;
const UNIT: &str = "horizon-epoch141-native-full-census-20261022-v1.service";
const IID: &str = "1ca7610a4db34ceaaf2322736fa22092";
const ROOT: &str = "/home/sol/.jetstreamer-private/epoch141-native-full-census-20261022-v1";
const GUARD: &str = "/home/sol/.jetstreamer-private/epoch141-native-full-census-20261022-v1/results/initial-guard.json";
const GUARD_SHA: &str = "76450b5767660b47b4da9c1e7f2afc8a843d3346bccc0b1c6d065b277e0e224a";
const READER: &str =
    "/usr/local/lib/jetstreamer/horizon-native141-fleet-reader-20261022-v1/jetstreamer-r2";
const READER_SHA: &str = "32e4cc91e2da5075aca1cf3a25a04200c908a1ddedca30223bef0b434137f088";
const REJECTION_UNIT: &str = "horizon-epoch141-native-full-census-rejection-20261022-v1.service";
const REJECTION_ROOT: &str = "/home/sol/.jetstreamer-private/epoch141-native-rejection-20261022-v1";
const REJECTION_READER: &str = "/usr/local/lib/jetstreamer/horizon-native141-rejection-fleet-reader-20261022-v1/jetstreamer-r2";
const REJECTION_READER_SHA: &str =
    "5da179fd1857631e76453c92a573aabf9eab897ea14d569c72f12821035710e7";
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    first_guard: Bound,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rejection: Option<Bound>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    acquisition: Option<Bound>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    all_acquisition: Option<Bound>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    all_retry: Option<Bound>,
}
pub(super) fn all_retry_enabled(p: &Plan) -> bool {
    all_retry::enabled(p)
}
pub(super) fn enable_all_retry(p: &mut Plan, spec: &Bound) -> Result<()> {
    all_retry::enable(p, spec)
}
pub(super) fn all_acquisition_enabled(p: &Plan) -> bool {
    p.native141_audit
        .as_ref()
        .is_some_and(|s| s.all_acquisition.is_some())
}
pub(super) fn all_acquisition_reader(p: &Plan) -> bool {
    all_acquisition::reader(p)
}
pub(super) fn enable_all_acquisition(p: &mut Plan, spec: &Bound) -> Result<()> {
    all_acquisition::enable(p, spec)
}
pub(super) fn acquisition_enabled(p: &Plan) -> bool {
    p.native141_audit
        .as_ref()
        .is_some_and(|s| s.acquisition.is_some())
}
pub(super) fn acquisition_reader(p: &Plan) -> bool {
    acquisition::reader(p)
}
pub(super) fn enable_acquisition(p: &mut Plan, spec: &Bound) -> Result<()> {
    acquisition::enable(p, spec)
}
pub(super) fn reader(p: &Plan) -> bool {
    p.native141_audit.as_ref().is_some_and(|s| {
        if s.rejection.is_some() {
            (p.tools.r2.path == Path::new(REJECTION_READER)
                && p.tools.r2.sha256 == REJECTION_READER_SHA
                && is_sha(REJECTION_READER_SHA))
                || assembly144_scans::reader(p)
        } else {
            p.tools.r2.path == Path::new(READER) && p.tools.r2.sha256 == READER_SHA
        }
    })
}
pub(super) fn rejection_enabled(p: &Plan) -> bool {
    p.native141_audit
        .as_ref()
        .is_some_and(|s| s.rejection.is_some())
}
fn rejection_evidence(b: &Bound) -> Result<Value> {
    ensure!(
        b.path == Path::new(REJECTION_ROOT).join("results/initial-guard.json") && is_sha(&b.sha256),
        "foreign rejection first guard"
    );
    let g = bound_json(b, false)?;
    ensure!(
        g["schema"] == "jetstreamer-epoch141-native-initial-guard-v1"
            && g["epoch"] == 141
            && g["invocation_id"].as_str().is_some_and(|s| s.len() == 32
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            && g["self_sha256"]
                == "573ce13e04f25972962c671b88c5afea8e5dd445e0e425c93816ca73b72fba42"
            && g["minimum_free_bytes"] == 4740696923590u64
            && g["available_bytes"]
                .as_u64()
                .is_some_and(|v| v >= 4775056661958)
            && g["trip"] == false
            && g["publication_authorized"] == false
            && g["remote_mutations"] == false
            && g["r2_mutations"] == false,
        "rejection guard scope or authority differs"
    );
    let plan = bound_json(
        &Bound {
            path:
                "/usr/local/lib/jetstreamer/horizon-native141-rejection-plan-20261022-v1/plan.json"
                    .into(),
            sha256: g["plan_sha256"]
                .as_str()
                .context("rejection plan digest")?
                .into(),
        },
        true,
    )?;
    let admission=bound_json(&Bound { path:"/var/lib/jetstreamer/horizon-native141-admission-rejection-20261022-v1/admission.json".into(),
        sha256:g["admission_sha256"].as_str().context("rejection admission digest")?.into() },false)?;
    ensure!(
        plan["schema"] == "jetstreamer-epoch141-ledger-native-full-census-plan-v2"
            && plan["unit"] == REJECTION_UNIT
            && plan["minimum_free_bytes"] == 4740696923590u64
            && plan["initial_guard_receipt"].as_str() == b.path.to_str()
            && admission["native_profile"] == "epoch141-read-only-full-census-rejection-v3"
            && admission["native_unit"] == REJECTION_UNIT
            && admission["admitted"] == true,
        "rejection plan or admission owner differs"
    );
    for flag in [
        "services_started",
        "services_installed",
        "native_database_opened",
        "replay_launch_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            admission[flag] == false,
            "rejection admission grants authority:{flag}"
        );
    }
    Ok(g)
}
fn evidence(s: &Profile) -> Result<()> {
    ensure!(
        s.first_guard.path == Path::new(GUARD) && s.first_guard.sha256 == GUARD_SHA,
        "foreign native141 first guard"
    );
    let g = bound_json(&s.first_guard, false)?;
    ensure!(
        g["schema"] == "jetstreamer-epoch141-native-initial-guard-v1"
            && g["epoch"] == 141
            && g["invocation_id"] == IID
            && g["self_sha256"]
                == "f1592d185a51f5d7503a8b3763e0f18899bc0aa0b62b61cd00dc5659bf985e02"
            && g["plan_sha256"]
                == "46bebd571a2f5132418cd2fa29a6b64694cecf1ba6b3d53db13ddd954f6b5db4"
            && g["admission_sha256"]
                == "eff115cd9a6d0580ed0d4f286afee4bf7fdf503463b410c6b34a1c9556e33f5c"
            && g["minimum_free_bytes"] == 4740696923590u64
            && g["available_bytes"]
                .as_u64()
                .is_some_and(|v| v >= 4775056661958)
            && g["trip"] == false
            && g["publication_authorized"] == false
            && g["remote_mutations"] == false
            && g["r2_mutations"] == false,
        "native141 guard scope or authority differs"
    );
    Ok(())
}
pub(super) fn validate(p: &Plan) -> Result<()> {
    if let Some(s) = &p.native141_audit {
        ensure!(
            is_101(p)?
                && reader(p)
                && p.assembly144_recovery.is_some()
                && p.sample_target_utc.as_str() >= "2026-10-22T08:58:00Z"
                && !p.expected_epochs.contains(&141),
            "native141 cannot alter ordinary claims or use an unqualified reader"
        );
        evidence(s)?;
        if let Some(b) = &s.rejection {
            rejection_evidence(b)?;
        }
        if let Some(b) = &s.acquisition {
            ensure!(
                acquisition::reader(p),
                "acquisition requires its qualified reader"
            );
            acquisition::evidence(b)?;
        }
        if let Some(b) = &s.all_acquisition {
            ensure!(
                all_acquisition::reader(p),
                "all-target acquisition requires its exact reader and earlier history"
            );
            all_acquisition::evidence(b)?;
        }
        if let Some(b) = &s.all_retry {
            ensure!(
                all_retry::reader(p),
                "all-target retry requires failed-attempt history and its qualified reader"
            );
            all_acquisition::evidence_at(b, &all_acquisition::RETRY)?;
        }
    }
    Ok(())
}
pub(super) fn enable(p: &mut Plan) -> Result<()> {
    ensure!(
        is_101(p)? && p.native141_audit.is_none() && assembly144::reader_v2(p),
        "native141 needs accepted original assembly-reader profile"
    );
    let s = Profile {
        first_guard: Bound {
            path: GUARD.into(),
            sha256: GUARD_SHA.into(),
        },
        rejection: None,
        acquisition: None,
        all_acquisition: None,
        all_retry: None,
    };
    evidence(&s)?;
    p.native141_audit = Some(s);
    p.tools.r2 = Bound {
        path: READER.into(),
        sha256: READER_SHA.into(),
    };
    validate(p)
}
pub(super) fn enable_rejection(p: &mut Plan, spec: &Bound) -> Result<()> {
    ensure!(
        reader(p) && !rejection_enabled(p),
        "replacement requires original native141 history and reader"
    );
    let v = bound_json(spec, true)?;
    ensure!(
        v["schema"] == "jetstreamer-native141-rejection-monitor-handoff-v1"
            && v["replay_launch_authorized"] == false
            && v["publication_authorized"] == false
            && v["remote_mutations"] == false
            && v["r2_mutations"] == false,
        "foreign or authorizing rejection monitor handoff"
    );
    let b: Bound = serde_json::from_value(v["first_guard"].clone())?;
    rejection_evidence(&b)?;
    p.native141_audit
        .as_mut()
        .context("native141 profile")?
        .rejection = Some(b);
    p.tools.r2 = Bound {
        path: REJECTION_READER.into(),
        sha256: REJECTION_READER_SHA.into(),
    };
    validate(p)
}
pub(super) fn derive_fleet(p: &Plan, f: &mut Value) -> Result<()> {
    let Some(s) = &p.native141_audit else {
        return Ok(());
    };
    validate(p)?;
    let c = json!({"epoch":141,"unit":UNIT,"invocation_id":IID,"scratch_path":ROOT,"launch_receipt":s.first_guard});
    let ds = f["diagnostics"]
        .as_array_mut()
        .context("native141 diagnostic history")?;
    let found: Vec<_> = ds.iter().filter(|d| d["unit"] == UNIT).collect();
    ensure!(
        found.is_empty() || (found.len() == 1 && found[0] == &c),
        "native141 history changed or duplicated"
    );
    if found.is_empty() {
        ds.push(c);
    }
    let units = f["tracked_units"]
        .as_array_mut()
        .context("native141 tracked units")?;
    if !units.iter().any(|u| u == UNIT) {
        units.push(json!(UNIT));
    }
    let gate = &mut f["gates"]["141"];
    ensure!(
        gate["state"] == "failed-needs-repair",
        "native141 audit must not close or relabel failed repair"
    );
    gate["next_action"] = json!(
        "Track the exact admitted private read-only full-census native141 acquisition and retained candidate records. Preserve failure/terminal evidence and all original inputs; native success alone is not hidden-PoH/root qualification or recovery. Continue qualified PoH/checkpoint/full/plugin/ready-pair gates; no ordinary replay or public ETA from this audit."
    );
    let entries = gate["evidence"]
        .as_array_mut()
        .context("native141 repair evidence")?;
    let b = serde_json::to_value(&s.first_guard)?;
    if !entries.contains(&b) {
        entries.push(b);
    }
    if let Some(b) = &s.rejection {
        let g = rejection_evidence(b)?;
        let c = json!({"epoch":141,"unit":REJECTION_UNIT,"invocation_id":g["invocation_id"],
            "scratch_path":REJECTION_ROOT,"launch_receipt":b});
        let ds = f["diagnostics"]
            .as_array_mut()
            .context("rejection diagnostic history")?;
        let found: Vec<_> = ds.iter().filter(|d| d["unit"] == REJECTION_UNIT).collect();
        ensure!(
            found.is_empty() || (found.len() == 1 && found[0] == &c),
            "rejection history changed or duplicated"
        );
        if found.is_empty() {
            ds.push(c);
        }
        let units = f["tracked_units"]
            .as_array_mut()
            .context("rejection tracked units")?;
        if !units.iter().any(|u| u == REJECTION_UNIT) {
            units.push(json!(REJECTION_UNIT));
        }
        let gate = &mut f["gates"]["141"];
        gate["next_action"] = json!(
            "Track the separately admitted private rejection-evidence attempt and preserve the original failed native141 audit. Inspect metadata-rejection.json only after its post-close source revalidation; full-target census, hidden PoH, canonical roots, full/plugin checks and ready-pair remain unproven. No ordinary ETA, blind retry or relaxed connectivity rule."
        );
        let entries = gate["evidence"]
            .as_array_mut()
            .context("rejection repair evidence")?;
        let b = serde_json::to_value(b)?;
        if !entries.contains(&b) {
            entries.push(b);
        }
    }
    acquisition::derive_fleet(p, f)?;
    all_acquisition::derive_fleet(p, f)?;
    all_retry::derive_fleet(p, f)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absent_profile_cannot_make_new_reader_an_alias() {
        let (p, ..) = super::super::tests::fixture101();
        assert!(!reader(&p));
    }
    #[test]
    fn replacement_reader_cannot_borrow_original_profile_or_drop_history() {
        let (mut p, ..) = super::super::tests::fixture101();
        p.native141_audit = Some(Profile {
            first_guard: Bound {
                path: GUARD.into(),
                sha256: GUARD_SHA.into(),
            },
            rejection: None,
            acquisition: None,
            all_acquisition: None,
            all_retry: None,
        });
        p.tools.r2 = Bound {
            path: READER.into(),
            sha256: READER_SHA.into(),
        };
        assert!(reader(&p));
        assert!(!rejection_enabled(&p));
        p.tools.r2 = Bound {
            path: REJECTION_READER.into(),
            sha256: REJECTION_READER_SHA.into(),
        };
        assert!(!reader(&p));
        p.native141_audit.as_mut().unwrap().rejection = Some(Bound {
            path: Path::new(REJECTION_ROOT).join("results/initial-guard.json"),
            sha256: "a".repeat(64),
        });
        assert!(reader(&p));
        assert!(rejection_enabled(&p));
        assert_eq!(
            p.native141_audit.as_ref().unwrap().first_guard.sha256,
            GUARD_SHA
        );
        p.tools.r2.sha256 = READER_SHA.into();
        assert!(!reader(&p));
        p.native141_audit = None;
        assert!(!reader(&p));
    }
}
