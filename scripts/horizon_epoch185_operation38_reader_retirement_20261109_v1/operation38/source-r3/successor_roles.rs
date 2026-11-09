//! Root fills these only from actual qualification and normal seal evidence.
//! None always fails closed; legacy images are never an automatic fallback.
use crate::*;
pub const HELPER34_PATH: &str = "/usr/local/lib/jetstreamer/horizon-epoch185-inherited-census-postreader-tools-20261108-v34/jetstreamer-r2";
pub const HELPER34_SHA: Option<&str> = Some("dda7f44b24b7d9475c654efea20e2230f8374df9640b3e0bf724e7edac44c389");
pub const HELPER35_PATH: &str = "/usr/local/lib/jetstreamer/horizon-epoch185-driver12-postreader-tools-20261109-v35/jetstreamer-r2";
pub const HELPER35_SHA: Option<&str> = Some("5059c749d74f59711ce5ed9642dd2383a4a3b4bb21e3338ff5c1dce77a5a47fa");
const FINAL3_PATH: &str = "/usr/local/lib/jetstreamer/horizon-positive185-final-transaction-tools-20261108-v3/horizon-positive185-final";
const FINAL3_SHA: Option<&str> = Some("47fb5d1fd85e6a19ff31cc493bd4eb660441f4f8f08d6b238b62316d87f50f84");
const FINAL4_PATH: &str = "/usr/local/lib/jetstreamer/horizon-positive185-final-transaction-tools-20261109-v4/horizon-positive185-final";
const FINAL4_SHA: Option<&str> = Some("5d72377dabc3d0646d490be70a9415ad07cba2527c6c63e5d2a0f36b5940687b");
const FINAL6_PATH: &str = "/usr/local/lib/jetstreamer/horizon-positive185-final-transaction-tools-20261109-v6/horizon-positive185-final";
const FINAL6_SHA: Option<&str> = Some("2ceb9bd082b7596a927f84b139d862c475166dc44f2042199170c583bea4a1b1");
const PLANNER5_PATH: &str = "/usr/local/lib/jetstreamer/horizon-positive185-current-witness-planner-tools-20261108-v5/planner";
const PLANNER5_SHA: Option<&str> = Some("e771306216e1436e3904ab2c11622597298c61c4083a4a7a1b485278bdb139e1");
const PLANNER6_PATH: &str = "/usr/local/lib/jetstreamer/horizon-positive185-current-witness-planner-tools-20261109-v6/planner";
const PLANNER6_SHA: Option<&str> = Some("fb29de082bf2fe070601eb1b5f7a5b34f80697dfcf6612ec37528f232fea97f9");
fn required(path: &str, sha: Option<&str>, name: &str) -> Result<Bound> {
    let sha = sha.with_context(|| format!("actual normally sealed {name} image is unresolved"))?;
    ensure!(storage::hex(sha, 64), "actual successor image digest");
    Ok(fixed(path, sha))
}
pub fn final_image() -> Result<Bound> {
    let selected=required(FINAL6_PATH, FINAL6_SHA, "Final6")?;
    ensure!(selected.path!=Path::new(FINAL3_PATH) && Some(selected.sha256.as_str())!=FINAL3_SHA && selected.path!=Path::new(FINAL4_PATH) && Some(selected.sha256.as_str())!=FINAL4_SHA,"current Final6 must not alias historical Final3/4");
    Ok(selected)
}
pub fn planner_image() -> Result<Bound> {
    let selected=required(PLANNER6_PATH, PLANNER6_SHA, "Planner6")?;
    ensure!(selected.path!=Path::new(PLANNER5_PATH) && Some(selected.sha256.as_str())!=PLANNER5_SHA,"current Planner6 must not alias historical Planner5");
    Ok(selected)
}
pub fn native_capture() -> Result<Bound> {
    crate::postreader::image()
}
pub fn driver12_role() -> Result<Value> {
    ensure!(driver_policy::supported(&fixed(DRIVER,DRIVER_SHA)) && !driver_policy::historical(&fixed(DRIVER,DRIVER_SHA)) && DRIVER==driver_policy::DRIVER12 && DRIVER_SHA==driver_policy::SHA12,"Operation38 exact qualified Driver12 selection");
    let driver=role(DRIVER,DRIVER_SHA)?;
    let artifact=binding(&driver["artifact"])?;
    ensure!(artifact.sha256=="5b08baacff6943fbc544dd05085b391bccda34e6963e0194ae4d05f41e6c937a","actual qualified Driver12 artifact proof binding");
    let proof=storage::json(&artifact)?;
    ensure!(proof["schema"]=="horizon-native-concurrent-census-driver-artifact-v12" && proof["artifact"]["sha256"]==DRIVER_SHA && proof["all_required_tests_passed"]==true && proof["all_old_Root_and_Sol_native_controls_preserved"]==true && proof["actual_Sol_six_census_negative_and_positive_tests_passed"]==true && proof["allocation_original30s_and_four_million_aggregate_entries_preserved"]==true && proof["finite_retry_attempts"]==8 && proof["original_memory_runtime_setup_final_token_and_guard_cadence_unchanged"]==true && proof["namespace_and_body_protection_unchanged"]==true && proof["fresh_native_first_guard_and_downstream_registration_required"]==true,"Driver12 census qualification preserves bounds and cannot replace a fresh actual first guard");
    storage::bytes(&fixed(DRIVER,DRIVER_SHA),64<<20,true)?;
    Ok(driver)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unresolved_roles_never_alias_historical_final_or_planner() {
        assert!(required(FINAL3_PATH, None, "Final3").is_err());
        assert!(required(PLANNER5_PATH, None, "Planner5").is_err());
        assert!(required(HELPER34_PATH, Some("unresolved"), "Helper34").is_err());
    }
}

// Only the current Driver12 enrollment writer uses this qualified image.
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

/// Native enrollment and capture validate the same exact Driver12 envelope.
pub fn enrollment() -> Result<Bound> { native_capture() }
