//! Metadata-only adoption of the exact actual guarded native141 acquisition.
//! The observer/model/status census is unchanged; this is not a new replay lane.
use super::*;
const UNIT: &str = "horizon-epoch141-native-full-census-20261022-v1.service";
const IID: &str = "1ca7610a4db34ceaaf2322736fa22092";
const ROOT: &str = "/home/sol/.jetstreamer-private/epoch141-native-full-census-20261022-v1";
const GUARD: &str = "/home/sol/.jetstreamer-private/epoch141-native-full-census-20261022-v1/results/initial-guard.json";
const GUARD_SHA: &str = "76450b5767660b47b4da9c1e7f2afc8a843d3346bccc0b1c6d065b277e0e224a";
const READER: &str =
    "/usr/local/lib/jetstreamer/horizon-native141-fleet-reader-20261022-v1/jetstreamer-r2";
const READER_SHA: &str = "32e4cc91e2da5075aca1cf3a25a04200c908a1ddedca30223bef0b434137f088";
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    first_guard: Bound,
}
pub(super) fn reader(p: &Plan) -> bool {
    p.native141_audit.is_some()
        && p.tools.r2.path == Path::new(READER)
        && p.tools.r2.sha256 == READER_SHA
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
    };
    evidence(&s)?;
    p.native141_audit = Some(s);
    p.tools.r2 = Bound {
        path: READER.into(),
        sha256: READER_SHA.into(),
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
}
