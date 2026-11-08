//! Exact separately qualified successor images; no wildcard or image substitution.
//! Root must replace None only after Driver11 strict/native qualification and normal seal.
use super::*;
pub(super) const DRIVER11: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch185-guarded-adapter-v11/epoch185-guarded-cold";
pub(super) const DRIVER11_SHA: Option<&str> = Some("bdadc547439d2dbba11797f715c1741772dad693cd54073ac273132a7ba096f2");

fn select(path: &str, sha: &str, driver11_sha: Option<&str>) -> Result<BoundFile> {
    ensure!(
        is_lower_hex(sha, 64),
        "cold185 driver digest is not exact SHA256"
    );
    let original = path == DRIVER && sha == DRIVER_SHA;
    let successor =
        path == DRIVER11 && driver11_sha.is_some_and(|pin| is_lower_hex(pin, 64) && pin == sha);
    ensure!(
        original || successor,
        "cold185 driver image is not an exact registered original or qualified successor"
    );
    Ok(BoundFile {
        path: PathBuf::from(path),
        sha256: sha.to_owned(),
    })
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .with_context(|| format!("cold185 driver missing {key}"))
}
pub(super) fn from_envelope(v: &Value) -> Result<BoundFile> {
    select(
        text(v, "self_program")?,
        text(v, "self_sha256")?,
        DRIVER11_SHA,
    )
}
pub(super) fn from_proof(v: &Value) -> Result<BoundFile> {
    let selected = from_envelope(&v["envelope_value"])?;
    ensure!(
        v["source_bindings"]["driver"] == json!(selected)
            && v["ready"]["driver_sha256"] == selected.sha256,
        "cold185 original source/ready driver crossed its envelope"
    );
    if !v["mapped_driver"].is_null() {
        ensure!(
            v["mapped_driver"]["path"] == selected.path.to_string_lossy().as_ref()
                && v["mapped_driver"]["sha256"] == selected.sha256,
            "cold185 mapped image crossed original driver binding"
        );
    }
    Ok(selected)
}
pub(super) fn released_matches(v: &Value, proof: &Value) -> Result<()> {
    let selected = from_proof(proof)?;
    ensure!(
        v["path"] == selected.path.to_string_lossy().as_ref() && v["sha256"] == selected.sha256,
        "cold185 retained release substituted the original driver image"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn driver10_remains_exact_and_unresolved_driver11_fails_closed() {
        assert!(select(DRIVER, DRIVER_SHA, None).is_ok());
        assert!(select(DRIVER11, DRIVER_SHA, None).is_err());
        assert!(select(DRIVER11, &"b".repeat(64), None).is_err());
        assert!(select("/tmp/driver", DRIVER_SHA, None).is_err());
    }
    #[test]
    fn only_exact_successor_pair_passes_even_when_a_successor_pin_exists() {
        // Synthetic policy fixture, never a production hash or qualification claim.
        let pin = "b".repeat(64);
        assert!(select(DRIVER11, &pin, Some(&pin)).is_ok());
        assert!(select(DRIVER, DRIVER_SHA, Some(&pin)).is_ok());
        for (path, sha) in [
            (DRIVER11, DRIVER_SHA),
            (DRIVER, pin.as_str()),
            (
                "/usr/local/lib/jetstreamer/horizon-epoch185-guarded-adapter-v12/epoch185-guarded-cold",
                pin.as_str(),
            ),
        ] {
            assert!(select(path, sha, Some(&pin)).is_err());
        }
        assert!(select(DRIVER11, &pin, Some("unqualified")).is_err());
    }
    fn original() -> Value {
        json!({"envelope_value":{"self_program":DRIVER,"self_sha256":DRIVER_SHA},
            "source_bindings":{"driver":{"path":DRIVER,"sha256":DRIVER_SHA}},
            "ready":{"driver_sha256":DRIVER_SHA},
            "mapped_driver":{"path":DRIVER,"sha256":DRIVER_SHA}})
    }
    #[test]
    fn historical_current_and_released_images_must_all_share_one_registered_pair() {
        let proof = original();
        from_proof(&proof).unwrap();
        released_matches(&proof["mapped_driver"], &proof).unwrap();
        for pointer in [
            "/envelope_value/self_program",
            "/source_bindings/driver/path",
            "/mapped_driver/path",
        ] {
            let mut bad = proof.clone();
            *bad.pointer_mut(pointer).unwrap() = json!(DRIVER11);
            assert!(from_proof(&bad).is_err());
        }
        let mut terminal = proof.clone();
        terminal["mapped_driver"] = Value::Null;
        from_proof(&terminal).unwrap();
        let mut crossed = proof["mapped_driver"].clone();
        crossed["path"] = json!(DRIVER11);
        assert!(released_matches(&crossed, &terminal).is_err());
        let mut bad = proof.clone();
        bad["ready"]["driver_sha256"] = json!("b".repeat(64));
        assert!(from_proof(&bad).is_err());
    }
}
