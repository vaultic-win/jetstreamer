//! Root-only metadata qualification of the actual selected sealed successor roles.
use crate::*;
#[test]
#[ignore = "Root actual sealed Operation38 test image and actual qualified Planner6 required; metadata only"]
fn actual_current38_requires_driver12_helper35_planner6_final6_and_retained_history() {
    let driver = successor_roles::driver12_role().unwrap();
    assert_eq!(
        driver["image"],
        json!(fixed(driver_policy::DRIVER12, driver_policy::SHA12))
    );
    require_qualified_fleet_helper().unwrap();
    let helper = postreader::role().unwrap();
    assert_eq!(
        helper["image"],
        json!(successor_roles::native_capture().unwrap())
    );
    assert_ne!(
        helper["image"],
        json!(fixed(
            successor_roles::HELPER34_PATH,
            successor_roles::HELPER34_SHA.unwrap()
        ))
    );
    let final_image = successor_roles::final_image().unwrap();
    let final_role = role(final_image.path.to_str().unwrap(), &final_image.sha256).unwrap();
    let final_proof = storage::json(&binding(&final_role["artifact"]).unwrap()).unwrap();
    assert_eq!(final_proof["all_required_tests_passed"], true);
    let planner = successor_roles::planner_image().unwrap();
    let planner_role = role(planner.path.to_str().unwrap(), &planner.sha256).unwrap();
    let planner_proof = storage::json(&binding(&planner_role["artifact"]).unwrap()).unwrap();
    assert_eq!(planner_proof["all_required_tests_passed"], true);
    for old in [
        fixed(driver_policy::DRIVER10, driver_policy::SHA10),
        fixed(driver_policy::DRIVER11, driver_policy::SHA11),
    ] {
        assert!(driver_policy::supported(&old));
    }
    assert_ne!(postreader::image().unwrap(), fixed(HELPER, HELPER_SHA));
    assert_ne!(
        postreader::image().unwrap(),
        fixed(FLEET_HELPER, FLEET_HELPER_SHA)
    );
}
