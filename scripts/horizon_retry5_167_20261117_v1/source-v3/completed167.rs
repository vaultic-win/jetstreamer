//! Completed scratch167 output is retained and bounded, never erased or credited.
use super::*;
pub(super) const COMPLETE_DATA: u64 =
    terminal169::COMPLETE_DATA + completed_output_report::RETAINED_CAP;
pub(super) const RAW_FLOOR: u64 = data_fulfillment::COMPLETED167_FLOOR;
pub(super) const WORKING_SET_SCHEMA: &str = "horizon-retry3-completed167-output-working-set-v1";
pub(super) const ZERO166_WORKING_SET_SCHEMA: &str =
    "horizon-retry3-zero166-completed167-working-set-v1";
pub(super) fn working_set_schema(p: &Plan) -> &'static str {
    if retry167::selected(p) { return retry167::WORKING_SET_SCHEMA; }
    if terminal166::selected(p) {
        ZERO166_WORKING_SET_SCHEMA
    } else {
        WORKING_SET_SCHEMA
    }
}
pub(super) fn review_binding() -> Value {
    json!({"path":completed_output_report::REVIEW_PATH,"sha256":completed_output_report::REVIEW_SHA})
}
pub(super) fn route_shape(p: &Plan) -> Result<()> {
    let successor = p
        .data_fulfillment
        .as_ref()
        .is_some_and(|r| [Path::new(completed167_native_guard::RUNTIME), Path::new(retry167_native_guard::RUNTIME)].contains(&r.runtime.path.as_path()));
    ensure!(
        successor == terminal167::selected(p),
        "completed167 output route and successor guard must be selected together"
    );
    Ok(())
}
pub(super) fn declaration(v: &Value, p: &Plan) -> Result<()> {
    if terminal167::selected(p) {
        ensure!(
            v["schema"] == working_set_schema(p)
                && v["immutable_raw_guard_floor_bytes"] == terminal169::floor(p)
                && v["complete_DATA_bytes"] == terminal169::data(p)
                && v["completed167_output_review"] == review_binding()
                && v["completed167_retained_output_cap_bytes"]
                    == completed_output_report::RETAINED_CAP,
            "exact completed167 retained output declaration required"
        );
    } else {
        ensure!(
            v["schema"] != WORKING_SET_SCHEMA
                && v["schema"] != ZERO166_WORKING_SET_SCHEMA
                && v["completed167_output_review"].is_null()
                && v["completed167_retained_output_cap_bytes"].is_null(),
            "legacy route cannot claim completed167 output scope"
        );
    }
    Ok(())
}
pub(super) fn observe(p: &Plan) -> Result<Option<Value>> {
    if !terminal167::selected(p) {
        return Ok(None);
    }
    let report = completed_output_scope::validate(true)?;
    completed_output_report::validate_report(&report, true)?;
    Ok(Some(report))
}
pub(super) fn equal_reports(p: &Plan, before: &Option<Value>, after: &Option<Value>) -> Result<()> {
    if terminal167::selected(p) {
        completed_output_report::validate_report(
            before.as_ref().context("completed167 before report")?,
            true,
        )?;
        completed_output_report::validate_report(
            after.as_ref().context("completed167 after report")?,
            true,
        )?;
        ensure!(
            before == after,
            "completed167 output changed across shared allocation window"
        );
    } else {
        ensure!(
            before.is_none() && after.is_none(),
            "completed167 reports on legacy route"
        );
    }
    Ok(())
}
#[cfg(test)]
#[path = "/var/lib/jetstreamer/peer170-completed167-native-operation-zero166-20261116-v1/parser-repair-v2/prepare-build-v2/source-sealed/completed167_tests.rs"]
mod tests;
