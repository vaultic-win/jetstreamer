//! Root fills these only from actual qualification and normal seal evidence.
//! None always fails closed; legacy images are never an automatic fallback.
use crate::*;
pub const HELPER32_PATH: &str = "/usr/local/lib/jetstreamer/horizon-epoch185-driver11-postreader-tools-20261108-v32/jetstreamer-r2";
pub const HELPER32_SHA: Option<&str> = Some("7d93abb0ff24e187f648d3ba06a1be544d39528b28f46776f818dc409df21925");
const FINAL3_PATH: &str = "/usr/local/lib/jetstreamer/horizon-positive185-final-transaction-tools-20261108-v3/horizon-positive185-final";
const FINAL3_SHA: Option<&str> = Some("47fb5d1fd85e6a19ff31cc493bd4eb660441f4f8f08d6b238b62316d87f50f84");
const PLANNER3_PATH: &str = "/usr/local/lib/jetstreamer/horizon-positive185-current-witness-planner-tools-20261108-v3/planner";
const PLANNER3_SHA: Option<&str> = Some("3053400739e2370a7601abfb1b109db336b419ebfaa06283f369d314d023d5d2");
fn required(path: &str, sha: Option<&str>, name: &str) -> Result<Bound> {
    let sha = sha.with_context(|| format!("actual normally sealed {name} image is unresolved"))?;
    ensure!(storage::hex(sha, 64), "actual successor image digest");
    Ok(fixed(path, sha))
}
pub fn final_image() -> Result<Bound> {
    required(FINAL3_PATH, FINAL3_SHA, "Final3")
}
pub fn planner_image() -> Result<Bound> {
    required(PLANNER3_PATH, PLANNER3_SHA, "planner3")
}
pub fn native_capture() -> Result<Bound> {
    crate::postreader::image()
}
pub fn driver11_role() -> Result<Value> {
    ensure!(
        driver_policy::supported(&fixed(DRIVER, DRIVER_SHA))
            && !driver_policy::historical(&fixed(DRIVER, DRIVER_SHA)),
        "Operation31 exact qualified Driver11 selection"
    );
    let driver = role(DRIVER, DRIVER_SHA)?;
    let artifact = binding(&driver["artifact"])?;
    ensure!(
        artifact.sha256 == "4366c991c590c50223a73ca46323aee55b0a8987dbd855e5c066c7927a774b60",
        "actual qualified Driver11 artifact proof binding"
    );
    let proof = storage::json(&artifact)?;
    ensure!(
        proof["schema"] == "horizon-native-trigger-timespan-driver-artifact-v11"
            && proof["artifact"]["sha256"] == DRIVER_SHA
            && proof["exact_native_timer_timespan_parser_qualified"] == true
            && proof["original_five_and_ninety_second_native_freshness_bounds_retained"] == true
            && proof["actual_fresh_original_guard_first_fire_still_required"] == true,
        "Driver11 parser QA cannot stand in for a fresh native guard first fire"
    );
    storage::bytes(&fixed(DRIVER, DRIVER_SHA), 64 << 20, true)?;
    Ok(driver)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unresolved_roles_never_alias_historical_final_or_planner() {
        assert!(required(FINAL3_PATH, None, "Final3").is_err());
        assert!(required(PLANNER3_PATH, None, "planner3").is_err());
        assert!(required(HELPER32_PATH, Some("unresolved"), "Helper32").is_err());
    }
}

// Only the current Driver11 enrollment writer uses this qualified image.
// Historical fleet27 identity remains distinct in all retained-role checks.
pub fn enrolled_fleet() -> Result<Bound> { native_capture() }
#[cfg(test)] mod actual_enrolled_fleet_role_control {
use super::*;
#[test]
#[ignore = "Root exact qualified helper32 fleet role metadata only; no service or R2 mutation"]
fn actual_current_enrolled_fleet_uses_driver11_helper_and_preserves_historical_role() {
 let current=enrolled_fleet().unwrap();
 assert_ne!(current.path,Path::new(FLEET_HELPER));
 assert_ne!(current.sha256,FLEET_HELPER_SHA);
 assert_eq!(current,crate::postreader::image().unwrap());
 crate::require_qualified_fleet_helper().unwrap();
}
}

/// Native enrollment and capture validate the same exact Driver11 envelope.
pub fn enrollment() -> Result<Bound> { native_capture() }
