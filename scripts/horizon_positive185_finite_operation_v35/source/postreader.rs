//! A separately qualified post-enrollment reader. Prelaunch memory/DATA readers
//! remain exact13; an unresolved successor pin never falls back to that image.
use crate::*;
pub(super) const PATH: &str = crate::successor_roles::HELPER33_PATH;
// Root replaces ONLY this None after actual helper29 qualification+normal seal.
// Source proposal presence grants no authority and invents no future digest.
const QUALIFIED_SHA: Option<&str> = crate::successor_roles::HELPER33_SHA;

fn selected(path: &str, sha: Option<&str>) -> Result<Bound> {
    let sha = sha.context("actual qualified postreader30 image SHA is unresolved")?;
    ensure!(
        path == PATH && storage::hex(sha, 64) && sha != HELPER_SHA && sha != FLEET_HELPER_SHA,
        "postreader30 cannot alias prelaunch13/fleet27 or an unknown image path/pin"
    );
    Ok(fixed(path, sha))
}
pub(super) fn image() -> Result<Bound> {
    selected(PATH, QUALIFIED_SHA)
}
fn image_is_exact(actual: &Value, expected: &Bound) -> Result<()> {
    ensure!(
        *actual == json!(expected) && *actual != json!(fixed(HELPER, HELPER_SHA)),
        "post-enrollment reader crossed exact successor image or borrowed prelaunch13"
    );
    Ok(())
}
pub(super) fn require_reader_image(actual: &Value) -> Result<()> {
    image_is_exact(actual, &image()?)
}
pub(super) fn role() -> Result<Value> {
    let image = image()?;
    let role = crate::role(
        image.path.to_str().context("postreader image UTF8")?,
        &image.sha256,
    )?;
    let proof = storage::json(&binding(&role["artifact"])?)?;
    ensure!(
        proof["production_artifact"]["sha256"] == image.sha256
            && proof["all_required_tests_passed"] == true
            && proof["genuine_current_complete_outer_adapter_passed"] == true
            && proof["replay_launch_authorized"] == false,
        "postreader30 needs actual exact-image strict/native/complete-outer qualification"
    );
    storage::bytes(&image, 128 << 20, true)?;
    Ok(role)
}
fn reader_argv_for(image: &Bound, spec: &Bound) -> Vec<String> {
    vec![
        image.path.display().to_string(),
        "read-failed4-current-accounting".into(),
        spec.path.display().to_string(),
        "--spec-sha256".into(),
        spec.sha256.clone(),
        "--self-sha256".into(),
        image.sha256.clone(),
    ]
}
pub(super) fn reader_argv(spec: &Bound) -> Result<Vec<String>> {
    Ok(reader_argv_for(&image()?, spec))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unresolved_successor_never_falls_back_to_prelaunch_or_fleet_reader() {
        assert!(selected(PATH, None).is_err());
        for sha in ["", "unresolved", HELPER_SHA, FLEET_HELPER_SHA] {
            assert!(selected(PATH, Some(sha)).is_err());
        }
        assert!(selected(PATH, Some(&"A".repeat(64))).is_err());
    }
    #[test]
    fn role_constructor_rejects_foreign_path_even_with_canonical_test_pin() {
        let pin = "a".repeat(64); // Pure fixture, never a qualified actual image.
        assert!(selected(PATH, Some(&pin)).is_ok());
        for path in [
            HELPER,
            FLEET_HELPER,
            "/tmp/jetstreamer-r2",
            "../jetstreamer-r2",
        ] {
            assert!(selected(path, Some(&pin)).is_err());
        }
    }
    #[test]
    fn postreader_proof_rejects_prelaunch13_crossed_digest_and_fleet27() {
        let selected = selected(PATH, Some(&"a".repeat(64))).unwrap();
        image_is_exact(&json!(selected), &selected).unwrap();
        assert!(image_is_exact(&json!(fixed(HELPER, HELPER_SHA)), &selected).is_err());
        assert!(image_is_exact(&json!(fixed(FLEET_HELPER, FLEET_HELPER_SHA)), &selected).is_err());
        assert!(image_is_exact(&json!(fixed(PATH, &"b".repeat(64))), &selected).is_err());
    }
    #[test]
    fn production_reader_argv_binds_successor_without_changing_spec_or_cli() {
        let selected = selected(PATH, Some(&"a".repeat(64))).unwrap();
        let spec = fixed(
            "/usr/local/lib/jetstreamer/fixture/spec.json",
            &"b".repeat(64),
        );
        let argv = reader_argv_for(&selected, &spec);
        assert_eq!(
            argv,
            vec![
                PATH.to_owned(),
                "read-failed4-current-accounting".into(),
                spec.path.display().to_string(),
                "--spec-sha256".into(),
                spec.sha256,
                "--self-sha256".into(),
                selected.sha256
            ]
        );
        assert!(
            !argv.iter().any(|a| a == HELPER
                || a == HELPER_SHA
                || a == FLEET_HELPER
                || a == FLEET_HELPER_SHA)
        );
    }
}
