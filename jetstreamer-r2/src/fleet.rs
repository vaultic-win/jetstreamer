//! Read-only campaign reconciliation. The plan describes gates, never completion.
use super::*;
use serde_json::json;
use std::{collections::BTreeMap, process::Command as ProcessCommand};

const SCHEMA: &str = "jetstreamer-horizon-campaign-fleet-v1";
const PRIVATE_225_READER: &str = "/var/lib/jetstreamer/horizon-qualification225-reader-b261913-v1/jetstreamer-qualification-verify";
mod assembly144;
mod assembly144_admission;
mod assembly144_prepare;
mod assembly204_recovery;
mod assembly223;
mod assembly223_capacity;
mod assembly223_live_peer;
mod assembly223_prepare;
mod bounded205;
mod canary227;
mod canary227_admission;
mod canary227_allocation;
mod canary227_capability;
mod canary227_capture;
mod canary227_event;
mod canary227_peer;
mod canary227_status;
mod canary227_terminal;
mod capped204205_admission;
mod capped204205_work;
mod capped204_v4_admission;
mod census141_poh;
mod cold223_scan;
mod continuation144;
mod continuation144_admission;
mod continuation144_prepare;
mod continuation144_protection;
mod continuation203;
mod continuation203_admission;
mod continuation203_ops;
mod continuation203_runtime;
mod epoch136;
mod first_root233;
mod foundation_holding203;
mod foundation_holding_capacity;
pub(super) fn foundation_holding203_check(value: &Value, restoring: bool) -> Result<Value> {
    foundation_holding203::check(value, restoring)
}
mod demotion223_capacity;
mod demotion223_status;
mod full209_status;
mod full210_peer;
mod full210_status;
mod full210_terminal;
mod full227_failure;
mod full227_status;
mod maintenance_capacity;

pub(super) fn capture_demotion223_task() -> Result<()> {
    demotion223_status::capture()
}
pub(super) fn capture_demotion223_terminal() -> Result<()> {
    demotion223_status::capture_terminal()
}
pub(super) async fn publish_demotion223_status() -> Result<()> {
    demotion223_status::publish().await
}
pub(super) fn demotion223_binding_scope(
    b: &pipeline_status::Binding,
    epoch: u64,
    phase: &str,
) -> Result<()> {
    demotion223_status::binding_scope(b, epoch, phase)
}
pub(super) fn demotion223_inactive_owner(
    r: &StatusPublicationReceipt,
) -> Result<Option<(String, String)>> {
    demotion223_status::inactive_owner(r)
}
pub(super) fn demotion223_cleanup_time(epoch: u64, value: &Value) -> Result<Option<u64>> {
    demotion223_status::cleanup_time(epoch, value)
}
pub(super) fn demotion223_cleanup_current(
    epoch: u64,
    value: &Value,
    current: &BTreeMap<String, Value>,
    owners: &[(String, String)],
) -> Result<bool> {
    demotion223_status::cleanup_current(epoch, value, current, owners)
}
pub(super) fn compute_demotion223_capacity() -> Result<()> {
    demotion223_capacity::run()
}
mod demotion223_live_peer;
mod native141;
mod native144;
mod native203;
mod native207;
mod native207_admission;
mod native207_capture;
mod native207_event;
mod native207_terminal;
mod native209;
mod native209_admission;
mod native209_capture;
mod native209_event;
mod native209_full227;
mod native209_terminal;
mod native210;
mod native210_admission;
mod native210_capture;
mod native210_event;
mod native210_peer_history;
mod native210_terminal;
mod native227_terminal_observation;
mod native227_v1625;
mod native227_v1625_admission;
mod native227_v1625_capture;
mod native227_v1625_event;
mod native227_v1625_terminal;
mod native228;
mod native228_admission;
mod native228_capture;
mod native228_collected;
mod native228_event;
mod native228_full209;
mod native228_peer209;
mod native228_terminal;
mod original141;
mod original141_capped;
mod original141_freeze;
mod original141_trace;
mod original141_vote_prefix;
mod original_capped204205;
mod output_credit204205;
mod ownroot203_rebase;
mod prefix144;
mod prefix204;
mod prefix204_admission;
mod prefix204_capture;
mod prefix205;
mod prefix205_admission;
mod prefix205_capture;
mod prefix223;
mod prefix223_live_peer;
mod prefix223_live_sources;
mod prefix223_native20;
mod prefix223_native20_admission;
mod prefix223_native20_capture;
mod prefix223_native20_peer228;
mod prefix223_native20_status;
mod private144;
mod private144_scan;
mod private157;
mod private_prefix;
mod publication144_history;
mod publication203;
mod ram_auxiliary;
mod readback203_estimate;
mod retained220;
mod runtime157;
mod shrink_budget225;
mod shrink_root203;
mod singleton207;
mod singleton209;
mod singleton209_admission;
mod singleton209_capability;
mod singleton209_capture;
mod singleton209_delivery;
mod singleton209_peer223;
mod singleton209_prepare;
mod singleton210;
mod singleton210_admission;
mod singleton210_capability;
mod singleton210_capture;
mod singleton227;
mod singleton227_admission;
mod singleton227_capture;
mod singleton227_event;
mod singleton227_terminal;
mod snapshot144;
mod tail223;
mod tail223_scan;
mod verification223;
mod verification223_capacity;
mod verification223_live_peer;
mod verification223_prepare;
mod warmup223;
mod warmup223_input_capture;
mod warmup223_retire;
pub(crate) mod watch160;
pub(crate) mod watch198;

pub(super) async fn admit_original141() -> Result<()> {
    original141::admit().await
}
pub(super) async fn admit_epoch136_capped() -> Result<()> {
    epoch136::admit().await
}
pub(super) fn capture_epoch136_capped() -> Result<()> {
    epoch136::capture()
}
pub(super) fn prepare_epoch136_capped() -> Result<()> {
    epoch136::prepare()
}
pub(super) fn estimate_readback203() -> Result<()> {
    readback203_estimate::run()
}
pub(super) fn capture_warmup223_input() -> Result<()> {
    warmup223_input_capture::run()
}
pub(super) fn capture_warmup223_terminal() -> Result<()> {
    warmup223::capture_terminal()
}
pub(super) fn admit_prefix223_native20() -> Result<()> {
    prefix223_native20_admission::run()
}
pub(super) fn plan_prefix223_native20() -> Result<()> {
    prefix223_native20_admission::plan()
}
pub(super) fn capture_prefix223_native20() -> Result<()> {
    prefix223_native20_capture::run()
}
pub(super) async fn publish_prefix223_native20_status() -> Result<()> {
    prefix223_native20_status::run().await
}
pub(super) fn prefix223_native20_status_inactive_owner(
    receipt: &StatusPublicationReceipt,
) -> Result<Option<(String, String)>> {
    prefix223_native20_status::inactive_owner(receipt)
}
pub(super) fn admit_first_root233() -> Result<()> {
    first_root233::admit()
}
pub(super) fn capture_first_root233() -> Result<()> {
    first_root233::capture_launch()
}
pub(super) async fn publish_first_root233_status() -> Result<()> {
    first_root233::publish_status().await
}
pub(super) fn first_root233_status_inactive_owner(
    receipt: &StatusPublicationReceipt,
) -> Result<Option<(String, String)>> {
    first_root233::inactive_owner(receipt)
}
pub(super) fn capped_assembly_memory_owners(
    f: &Value,
    o: &Value,
) -> Result<BTreeMap<String, Value>> {
    let mut owners = capped204205_work::peer_assembly_memory_owners(f, o)?;
    for (name, proof) in assembly204_recovery::peer_memory_owners(f, o)? {
        ensure!(
            owners.insert(name, proof).is_none(),
            "duplicate typed assembly memory owner"
        );
    }
    Ok(owners)
}
pub(super) fn demotion223_memory_views(
    f: &Value,
    o: &Value,
) -> Result<(Value, Value, BTreeMap<String, Value>)> {
    demotion223_live_peer::memory_views(f, o)
}

pub(super) fn admit_singleton207() -> Result<()> {
    singleton207::admit()
}
pub(super) fn capture_singleton207() -> Result<()> {
    singleton207::capture_launch()
}
pub(super) async fn publish_singleton207_status() -> Result<()> {
    singleton207::publish_status().await
}
pub(super) fn singleton207_status_inactive_owner(
    receipt: &StatusPublicationReceipt,
) -> Result<Option<(String, String)>> {
    singleton207::inactive_owner(receipt)
}
pub(super) fn capture_singleton207_terminal() -> Result<()> {
    singleton207::capture_terminal()
}
pub(super) fn prepare_singleton207_inputs() -> Result<()> {
    singleton207::prepare_inputs()
}

pub(super) fn retire_warmup223_scratch() -> Result<()> {
    warmup223_retire::run()
}
pub(super) fn warmup223_terminal_status_identity(proof: &Value) -> Result<(String, String)> {
    warmup223::terminal_identity(proof)
}
pub(super) fn warmup223_terminal_not_replaced(proof: &Value) -> Result<()> {
    warmup223::terminal_not_replaced(proof)
}
pub(super) async fn publish_canary227_status() -> Result<()> {
    canary227_status::run().await
}
pub(super) fn canary227_status_inactive_owner(
    receipt: &StatusPublicationReceipt,
) -> Result<Option<(String, String)>> {
    canary227_status::inactive_owner(receipt)
}
pub(super) async fn publish_full227_status() -> Result<()> {
    full227_status::run().await
}
pub(super) fn capture_full227_failure() -> Result<()> {
    full227_failure::capture()
}
pub(super) async fn publish_full209_status() -> Result<()> {
    full209_status::run().await
}
pub(super) async fn publish_full210_status() -> Result<()> {
    full210_status::run().await
}
pub(super) fn full210_status_inactive_owner(
    receipt: &StatusPublicationReceipt,
) -> Result<Option<(String, String)>> {
    full210_status::inactive_owner(receipt)
}
pub(super) fn prepare_singleton210_inputs() -> Result<()> {
    singleton210_capability::run()
}
pub(super) fn admit_singleton210() -> Result<()> {
    singleton210_admission::run()
}
pub(super) fn capture_singleton210() -> Result<()> {
    singleton210_capture::run()
}
pub(super) fn capture_full210_terminal() -> Result<()> {
    full210_terminal::capture()
}
pub(super) fn full210_terminal_status_identity(proof: &Value) -> Result<(String, String)> {
    Ok((
        singleton210::UNIT.into(),
        full210_terminal::validate(proof)?.0,
    ))
}
pub(super) fn full210_terminal_current(proof: &Value, u: &Value) -> Result<()> {
    full210_terminal::current(proof, u)
}
pub(super) fn full209_status_inactive_owner(
    receipt: &StatusPublicationReceipt,
) -> Result<Option<(String, String)>> {
    full209_status::inactive_owner(receipt)
}
pub(super) fn prepare_singleton209_inputs() -> Result<()> {
    singleton209_capability::run()
}
pub(super) fn prepare_singleton209_admission_spec() -> Result<()> {
    singleton209_prepare::run()
}
pub(super) fn deliver_singleton209_output() -> Result<()> {
    singleton209_delivery::run()
}
pub(super) fn admit_singleton209_delivery() -> Result<()> {
    singleton209_delivery::admission::run()
}
pub(super) fn assembly204_recovery_command_name(command: &str) -> bool {
    assembly204_recovery::command_name(command)
}
pub(super) async fn assembly204_recovery_command(command: &str) -> Result<()> {
    assembly204_recovery::run(command).await
}
pub(super) fn admit_capped204_v4_delivery() -> Result<()> {
    capped204_v4_admission::run()
}
pub(super) fn admit_singleton209() -> Result<()> {
    singleton209_admission::run()
}
pub(super) fn capture_singleton209() -> Result<()> {
    singleton209_capture::run()
}
pub(super) fn full227_status_inactive_owner(
    receipt: &StatusPublicationReceipt,
) -> Result<Option<(String, String)>> {
    full227_status::inactive_owner(receipt)
}
pub(super) fn admit_warmup223(capture: bool) -> Result<()> {
    warmup223::run(capture)
}
pub(super) fn capture_original141() -> Result<()> {
    original141::capture()
}
pub(super) fn prepare_original141() -> Result<()> {
    original141::prepare()
}
pub(super) async fn admit_original141_trace() -> Result<()> {
    original141_trace::admit().await
}
pub(super) fn capture_original141_trace() -> Result<()> {
    original141_trace::capture()
}
pub(super) fn prepare_original141_trace() -> Result<()> {
    original141_trace::prepare()
}
pub(super) async fn admit_original141_freeze() -> Result<()> {
    original141_freeze::admit().await
}
pub(super) fn capture_original141_freeze() -> Result<()> {
    original141_freeze::capture()
}
pub(super) fn prepare_original141_freeze() -> Result<()> {
    original141_freeze::prepare()
}
pub(super) async fn admit_original141_vote_prefix() -> Result<()> {
    original141_vote_prefix::admit().await
}
pub(super) fn capture_original141_vote_prefix() -> Result<()> {
    original141_vote_prefix::capture()
}
pub(super) fn prepare_original141_vote_prefix() -> Result<()> {
    original141_vote_prefix::prepare()
}
pub(super) async fn admit_original141_capped() -> Result<()> {
    original141_capped::admit().await
}
pub(super) fn capture_original141_capped() -> Result<()> {
    original141_capped::capture()
}
pub(super) fn prepare_original141_capped() -> Result<()> {
    original141_capped::prepare()
}

pub(super) fn prepare_private_prefix157() -> Result<()> {
    private157::prepare()
}
pub(super) fn prepare_private_prefix144() -> Result<()> {
    prefix144::prepare()
}
pub(super) fn prepare_native144() -> Result<()> {
    native144::prepare()
}
pub(super) fn admit_snapshot144() -> Result<()> {
    snapshot144::run()
}
pub(super) async fn prepare_continuation144_protection() -> Result<()> {
    continuation144_protection::run().await
}
pub(super) async fn admit_continuation144() -> Result<()> {
    continuation144_admission::run().await
}
pub(super) fn admit_continuation203() -> Result<()> {
    continuation203_admission::run()
}
pub(super) fn admit_prefix205() -> Result<()> {
    prefix205_admission::run()
}
pub(super) fn admit_prefix204() -> Result<()> {
    prefix204_admission::run()
}
pub(super) fn capture_prefix204() -> Result<()> {
    prefix204_capture::run()
}
pub(super) fn admit_singleton227() -> Result<()> {
    singleton227_admission::run()
}
pub(super) fn capture_singleton227() -> Result<()> {
    singleton227_capture::run()
}
pub(super) fn capture_native227_terminal() -> Result<()> {
    singleton227_terminal::capture()
}
pub(super) fn native227_terminal_status_identity(proof: &Value) -> Result<(String, String)> {
    singleton227_terminal::terminal_status_identity(proof)
}
pub(super) fn admit_native207_input() -> Result<()> {
    native207_admission::run()
}
pub(super) fn capture_native207_input() -> Result<()> {
    native207_capture::run()
}
pub(super) fn capture_native207_terminal() -> Result<()> {
    native207_terminal::capture()
}
pub(super) fn native207_terminal_status_identity(proof: &Value) -> Result<(String, String)> {
    Ok((native207::UNIT.into(), native207_terminal::validate(proof)?))
}
pub(super) fn admit_native209_input() -> Result<()> {
    native209_admission::run()
}
pub(super) fn capture_native209_input() -> Result<()> {
    native209_capture::run()
}
pub(super) fn capture_native209_terminal() -> Result<()> {
    native209_terminal::capture()
}
pub(super) fn native209_terminal_status_identity(proof: &Value) -> Result<(String, String)> {
    Ok((native209::UNIT.into(), native209_terminal::validate(proof)?))
}
pub(super) fn admit_native210_input() -> Result<()> {
    native210_admission::run()
}
pub(super) fn admit_verification223_capacity() -> Result<()> {
    verification223_capacity::run()
}
pub(super) fn capture_verification223_launch() -> Result<()> {
    verification223::capture()
}
pub(super) fn prepare_verification223_fleet() -> Result<()> {
    verification223_prepare::run()
}
pub(super) fn capture_assembly223_launch() -> Result<()> {
    assembly223::capture()
}
pub(super) fn prepare_assembly223_fleet() -> Result<()> {
    assembly223_prepare::run()
}
pub(super) fn admit_assembly223_capacity() -> Result<()> {
    assembly223_capacity::run()
}
pub(super) fn foundation_holding_capacity(spec: &Value, additional_bytes: u64) -> Result<Value> {
    foundation_holding_capacity::check(spec, additional_bytes)
}
pub(super) fn foundation_holding_capacity_with_restore(
    spec: &Value,
    additional_bytes: u64,
    context: &crate::holding::Foundation213RestoreContext<'_>,
) -> Result<Value> {
    foundation_holding_capacity::check_with_restore(spec, additional_bytes, context)
}
pub(super) fn capture_native210_input() -> Result<()> {
    native210_capture::run()
}
pub(super) fn capture_native210_terminal() -> Result<()> {
    native210_terminal::capture()
}
pub(super) fn native210_terminal_status_identity(proof: &Value) -> Result<(String, String)> {
    Ok((native210::UNIT.into(), native210_terminal::validate(proof)?))
}
/// A derived accounting view only; raw observer/fleet bindings stay immutable.
pub(super) fn native227_terminal_observer_view(f: &Value, o: &Value) -> Result<Value> {
    native227_terminal_observation::view(f, o)
}
pub(super) fn capture_canary227_v1625_terminal() -> Result<()> {
    canary227_terminal::capture()
}
pub(super) fn canary227_terminal_status_identity(proof: &Value) -> Result<(String, String, u64)> {
    Ok((
        canary227::UNIT.into(),
        canary227_terminal::validate(proof)?,
        proof["main_pid"]
            .as_u64()
            .context("227 canary terminal PID")?,
    ))
}
pub(super) fn canary227_terminal_current(proof: &Value, current: &Value) -> Result<()> {
    canary227_terminal::validate_current(proof, current)
}
pub(super) fn admit_canary227_v1625() -> Result<()> {
    canary227_admission::run()
}
pub(super) fn admit_capped204205_continuation() -> Result<()> {
    capped204205_admission::run()
}
pub(super) fn capture_capped204205_work() -> Result<()> {
    capped204205_work::capture()
}
pub(super) fn prepare_capped204205_work() -> Result<()> {
    capped204205_work::prepare()
}
pub(super) async fn publish_capped204205_status() -> Result<()> {
    capped204205_work::publish().await
}
pub(super) fn assembly204_recovery_binding_scope(
    epoch: u64,
    unit: &str,
    origin: &str,
    phase: &str,
) -> Result<()> {
    assembly204_recovery::binding_scope(epoch, unit, origin, phase)
}
pub(super) fn capped204205_binding_scope(epoch: u64, unit: &str, phase: &str) -> Result<()> {
    capped204205_work::binding_scope(epoch, unit, phase)
}
pub(super) fn capped204205_origin_scope(epoch: u64, unit: &str) -> Result<()> {
    capped204205_work::origin_scope(epoch, unit)
}
pub(super) fn capped204205_cleanup_allowed(f: &Value, epoch: u64) -> bool {
    capped204205_work::cleanup_allowed(f, epoch)
        && (epoch != 204
            || f.get("assembly204_recovery").is_none_or(|v| {
                v.as_array().is_some_and(|rows| {
                    rows.iter()
                        .all(|r| r["live"] == false && r["positive_inactivity_confirmed"] == true)
                })
            }))
}
pub(super) fn original_capped204205_terminal_time(epoch: u64, e: &Value) -> Result<Option<u64>> {
    original_capped204205::terminal_time(epoch, e)
}
pub(super) fn original_capped204205_terminal_current(
    epoch: u64,
    e: &Value,
    current: &BTreeMap<String, Value>,
    owners: &[(String, String)],
) -> Result<bool> {
    original_capped204205::terminal_current(epoch, e, current, owners)
}
pub(super) fn original_capped204205_repair_scope(name: &str, first: u64, last: u64) -> bool {
    original_capped204205::repair_unit(name, first, last)
}
pub(super) fn capped204205_cleanup_current(
    f: &Value,
    epoch: u64,
    current: &BTreeMap<String, Value>,
    owners: &[(String, String)],
) -> Result<bool> {
    capped204205_work::cleanup_current(f, epoch, current, owners)
}
pub(super) fn admit_canary227_v1625_output_metadata() -> Result<()> {
    canary227_admission::run_output_metadata()
}
pub(super) fn capture_canary227_v1625() -> Result<()> {
    canary227_capture::run()
}
pub(super) fn admit_native227_v1625_input() -> Result<()> {
    native227_v1625_admission::run()
}
pub(super) fn capture_native227_v1625_input() -> Result<()> {
    native227_v1625_capture::run()
}
pub(super) fn capture_native227_v1625_terminal() -> Result<()> {
    native227_v1625_terminal::capture()
}
pub(super) fn native227_v1625_terminal_status_identity(proof: &Value) -> Result<(String, String)> {
    Ok((
        native227_v1625::UNIT.into(),
        native227_v1625_terminal::validate(proof)?,
    ))
}
pub(super) fn admit_native228_input() -> Result<()> {
    native228_admission::run()
}
pub(super) fn capture_native228_input() -> Result<()> {
    native228_capture::run()
}
pub(super) fn capture_native228_terminal() -> Result<()> {
    native228_terminal::capture()
}
pub(super) fn native228_terminal_status_identity(proof: &Value) -> Result<(String, String)> {
    Ok((native228::UNIT.into(), native228_terminal::validate(proof)?))
}
pub(super) fn validate_warmup223_status_claim(value: &Value) -> Result<()> {
    warmup223::status_claim(value)
}
pub(super) fn warmup223_status_jet_path(unit: &str) -> Result<PathBuf> {
    warmup223::status_jet_path(unit)
}
/// The native status publisher shares the exact fleet registration gates;
/// a metadata countdown cannot register or qualify a new native attempt.
pub(super) fn validate_native_input_status_claim(value: &Value) -> Result<()> {
    let claim: PipelineClaim = serde_json::from_value(value.clone())?;
    if claim.epoch == 207 && native207::scope(&claim.phase, &claim.unit) {
        native207::claim(&claim)
    } else if claim.epoch == 228 && native228::scope(&claim.phase, &claim.unit) {
        native228::claim(&claim)
    } else if claim.epoch == 209 && native209::scope(&claim.phase, &claim.unit) {
        native209::claim(&claim)
    } else if claim.epoch == 210 && native210::scope(&claim.phase, &claim.unit) {
        native210::claim(&claim)
    } else if claim.epoch == 227 && native227_v1625::scope(&claim.phase, &claim.unit) {
        native227_v1625::claim(&claim)
    } else if claim.epoch == 223 && cold223_scan::scope(&claim.phase, &claim.unit) {
        cold223_scan::validate(&claim)
    } else if claim.epoch == 227 && singleton227::native_scope(&claim.phase, &claim.unit) {
        singleton227::native_claim(&claim)
    } else {
        bail!("native input status claim is not a registered closed profile")
    }
}
pub(super) fn capture_native223_input() -> Result<()> {
    cold223_scan::capture_native20_input()
}
pub(super) fn native223_terminal_status_identity(proof: &Value) -> Result<(String, String)> {
    cold223_scan::terminal_status_identity(proof)
}
pub(super) fn admit_publication203() -> Result<()> {
    publication203::admit()
}
pub(super) fn capture_handoff203() -> Result<()> {
    publication203::capture()
}
pub(super) fn capture_prefix205() -> Result<()> {
    prefix205_capture::run()
}
pub(super) fn prepare_continuation203_layout() -> Result<()> {
    continuation203_ops::layout()
}
pub(super) fn probe_continuation203_inputs() -> Result<()> {
    continuation203_ops::capability()
}
pub(super) fn capture_continuation203_launch() -> Result<()> {
    continuation203_ops::capture()
}
pub(super) fn extend_continuation203_runtime() -> Result<()> {
    continuation203_runtime::run()
}
pub(super) fn prepare_ownroot203_rebase() -> Result<()> {
    ownroot203_rebase::prepare()
}
pub(super) fn capture_ownroot203_rebase() -> Result<()> {
    ownroot203_rebase::capture()
}
pub(super) fn recover_ownroot203_handoff() -> Result<()> {
    ownroot203_rebase::recover()
}
pub(super) fn prepare_continuation144_layout() -> Result<()> {
    continuation144::prepare_layout()
}
pub(super) fn capture_continuation144_launch() -> Result<()> {
    continuation144::capture_launch()
}
pub(super) fn prepare_continuation144_fleet() -> Result<()> {
    continuation144_prepare::run()
}
pub(super) async fn admit_assembly144() -> Result<()> {
    assembly144_admission::run().await
}
pub(super) fn capture_assembly144_launch() -> Result<()> {
    assembly144::capture_launch()
}
pub(super) fn capture_assembly144_scan_launch() -> Result<()> {
    private144_scan::capture_launch()
}
pub(super) fn prepare_assembly144_fleet() -> Result<()> {
    assembly144_prepare::run()
}

#[derive(Debug, Clone, Deserialize, serde::Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct BoundFile {
    path: PathBuf,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Gate {
    state: String,
    next_action: String,
    evidence: Vec<BoundFile>,
    #[serde(default)]
    reserve_stop: Option<reserve_stop::Evidence>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiagnosticClaim {
    epoch: u64,
    unit: String,
    invocation_id: String,
    scratch_path: PathBuf,
    launch_receipt: BoundFile,
}

fn native_restore_140(claim: &DiagnosticClaim) -> bool {
    claim.epoch == 140
        && claim
            .unit
            .starts_with("horizon-qualify-140-native-restore-")
        && claim.unit.ends_with(".service")
}

fn native_restore_140_launch_matches(claim: &DiagnosticClaim, receipt: &Value) -> bool {
    native_restore_140(claim)
        && claim.scratch_path.parent() == Some(Path::new("/home/sol/.jetstreamer-private"))
        && claim
            .scratch_path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.starts_with("epoch140-native-restore-"))
        && receipt["epoch"] == 140
        && receipt["private_run_root"].as_str() == claim.scratch_path.to_str()
        && receipt["snapshot_slot"] == 60_911_751u64
        && receipt["snapshot_sha256"]
            == "47d5911465901975e397c570e06ccf72296db7ecd3b3b1beda710cacd3e683a1"
        && receipt["worker_sha256"]
            == "abe395d482174e490833928c7343a33d135d8572096faf873ce3103c35fe520d"
        && receipt["original_journal_sha256"]
            == "8dfb8d6805d6b4d50ab340899447b90449c66117cc33b1af0ca6537b934a3b13"
        && receipt["serialized_clock_sha256"]
            == "f74aacd82655179686a43c6bb137e0c0e7c7bd2955809008a745ef80f16f8be2"
        && receipt["runtime"] == "solana-v1.4.25"
        && receipt["solana_rayon_threads"] == 2
        && canonical_digest(&receipt["probe_sha256"])
        && canonical_digest(&receipt["plan_sha256"])
        && receipt["maximum_runtime_seconds"] == 1800
        && receipt["experimental_envelope_bytes"] == 128u64 << 30
        && receipt["replay_entries_authorized"] == false
        && receipt["archive_prefix_verified"] == false
        && receipt["suffix_execution_authorized"] == false
        && receipt["runtime_promotion_authorized"] == false
        && receipt["canonical_sidecar_authorized"] == false
        && receipt["publication_authorized"] == false
        && receipt["expected_exec_start"].as_str().is_some_and(|s| {
            s.starts_with("{ path=/usr/local/lib/jetstreamer/horizon-epoch140-native-restore-tool-")
                && s.contains("/jetstreamer-epoch140-native-restore-probe ; argv[]=")
                && s.contains(" --plan-sha256 ")
                && s.contains(" --self-sha256 ")
        })
}

fn shrink_budget_203_namespace(claim: &DiagnosticClaim) -> bool {
    claim.epoch == 203
        && claim
            .unit
            .starts_with("horizon-qualify-203-bounded-resource-shrink-budget-")
}

fn diagnostic_scope(claim: &DiagnosticClaim) -> std::ops::RangeInclusive<u64> {
    if claim.epoch == 225
        && (claim
            .unit
            .starts_with("horizon-qualify-225-natural-root-resource-")
            || private_225_verification(claim))
    {
        // The tail is private diagnostic work, never a second ordinary claim.
        225..=226
    } else {
        claim.epoch..=claim.epoch
    }
}

fn private_225_verification(claim: &DiagnosticClaim) -> bool {
    claim.epoch == 225
        && claim
            .unit
            .starts_with("horizon-qualify-225-private-verification-")
        && claim.unit.ends_with(".service")
}

fn canonical_digest(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn validate_private_225_terminal(value: &Value) -> Result<()> {
    ensure!(
        value["schema"] == "jetstreamer-private-epoch225-natural-root-outcome-v1"
            && value["epoch"] == 225
            && value["producer_invocation_id"] == "ac9aee3d47eb41e483a5e008ed43d030"
            && value["natural_parent_exit_code"] == 0
            && value["deliberate_stop"] == false
            && value["output_slot_start"] == 97_200_000u64
            && value["terminal_slot"] == 98_063_464u64
            && value["output_slot_count"] == 863_465u64
            && canonical_digest(&value["segment_manifest_sha256"])
            && canonical_digest(&value["producer_journal_sha256"])
            && canonical_digest(&value["manager_journal_sha256"])
            && value["full_span_independently_qualified"] == false
            && value["runtime_promotion_authorized"] == false
            && value["canonical_sidecar_authorized"] == false
            && value["publication_authorized"] == false
            && value["remote_mutations"] == false
            && value["r2_mutations"] == false,
        "epoch225 verifier needs exact natural-completion terminal evidence, not a stopped benchmark"
    );
    Ok(())
}

fn checked_diagnostic_launch(claim: &DiagnosticClaim) -> Result<Value> {
    let launch = bound_json(&claim.launch_receipt)?;
    validate_diagnostic_launch(&launch, claim)?;
    if singleton207::namespace(claim) {
        singleton207::bindings(claim, &launch)?;
    }
    if first_root233::namespace(claim) {
        first_root233::bindings(claim, &launch)?;
    }
    if private_225_verification(claim) {
        let evidence: BoundFile = serde_json::from_value(launch["terminal_evidence"].clone())?;
        validate_private_225_terminal(&bound_json(&evidence)?)?;
    }
    if tail223::namespace(claim) {
        let evidence: BoundFile = serde_json::from_value(launch["capability"].clone())?;
        tail223::capability(&bound_json(&evidence)?)?;
    }
    if prefix223::namespace(claim) {
        let evidence: BoundFile = serde_json::from_value(launch["capability"].clone())?;
        prefix223::capability(&bound_json(&evidence)?)?;
        prefix223::terminal203_release(&launch)?;
    }
    if prefix223_native20::namespace(claim) {
        prefix223_native20::bindings(claim, &launch)?;
    }
    if prefix205::namespace(claim) {
        prefix205::bindings(claim, &launch)?;
    }
    if prefix204::namespace(claim) {
        prefix204::bindings(claim, &launch)?;
    }
    if singleton227::namespace(claim) {
        singleton227::bindings(claim, &launch)?;
    }
    if singleton209::namespace(claim) {
        singleton209::bindings(claim, &launch)?;
    }
    if singleton210::namespace(claim) {
        singleton210::bindings(claim, &launch)?;
    }
    Ok(launch)
}

fn register_live_diagnostic_scope(
    epochs: &mut BTreeSet<u64>,
    claim: &DiagnosticClaim,
) -> Result<()> {
    ensure!(
        diagnostic_scope(claim).all(|epoch| !epochs.contains(&epoch)),
        "overlapping live private diagnostic claims"
    );
    epochs.extend(diagnostic_scope(claim));
    Ok(())
}

// Observational only: these claims never authorize launch, publication or upload.
// Keep delivery distinct from private diagnostics, which forbid remote mutation.
#[derive(Deserialize, serde::Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct PipelineClaim {
    epoch: u64,
    phase: String,
    unit: String,
    invocation_id: String,
    expected_exec_start: String,
    evidence: Vec<BoundFile>,
}

// Unit names describe scope, not authority. Every live claim still needs the
// exact invocation/command, immutable evidence and an independent delivery gate.
pub(super) fn private223_status_scope(phase: &str, unit: &str) -> bool {
    matches!(
        (phase, unit),
        ("private-assembly-only", assembly223::UNIT)
            | ("private-verification-only", verification223::UNIT)
    )
}
pub(super) fn private223_status_origin(
    phase: &str,
    unit: &str,
    iid: &str,
    origin: &Value,
    binding: &Value,
    f: &Value,
) -> Result<PathBuf> {
    ensure!(
        private223_status_scope(phase, unit),
        "private 223 status phase/unit differs"
    );
    let p: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: f["plan"]
            .as_str()
            .context("private 223 status fleet plan")?
            .into(),
        sha256: f["plan_sha256"]
            .as_str()
            .context("private 223 status fleet digest")?
            .into(),
    })?)?;
    let claims = p
        .diagnostics
        .iter()
        .filter(|d| d.epoch == 223 && d.unit == unit && d.invocation_id == iid)
        .collect::<Vec<_>>();
    ensure!(
        claims.len() == 1,
        "private 223 status needs one exact accepted diagnostic claim"
    );
    let c = claims[0];
    ensure!(
        private157::binding(&c.launch_receipt) == *binding
            && checked_diagnostic_launch(c)? == *origin,
        "private 223 status launch differs from accepted diagnostic"
    );
    if assembly223::namespace(c) {
        Ok(Path::new(assembly223::ROOT).join("epoch-223-private-v3.jet"))
    } else {
        ensure!(
            verification223::namespace(c),
            "unknown private 223 status owner"
        );
        Ok(PathBuf::from(
            "/var/lib/jetstreamer/horizon-223-native20-native25-private-assembly-v1/epoch-223-private-v3.jet",
        ))
    }
}
pub(super) fn pipeline_unit_range_for_epoch(
    phase: &str,
    unit: &str,
    epoch: u64,
) -> Result<std::ops::RangeInclusive<u64>> {
    if epoch == 223 && demotion223_status::scope(phase, unit) {
        return Ok(223..=223);
    }
    if epoch == 223 && private223_status_scope(phase, unit) {
        return Ok(223..=223);
    }
    if epoch == 160 && watch160::namespace(phase, unit) {
        return Ok(160..=160);
    }
    pipeline_unit_range(phase, unit)
}
pub(super) fn pipeline_unit_range(
    phase: &str,
    unit: &str,
) -> Result<std::ops::RangeInclusive<u64>> {
    if private144_scan::scope(phase, unit) {
        return Ok(144..=144);
    }
    if native207::scope(phase, unit) {
        return Ok(207..=207);
    }
    if native209::scope(phase, unit) {
        return Ok(209..=209);
    }
    if native210::scope(phase, unit) {
        return Ok(210..=210);
    }
    if native227_v1625::scope(phase, unit) {
        return Ok(227..=227);
    }
    if native228::scope(phase, unit) {
        return Ok(228..=228);
    }
    if singleton227::native_scope(phase, unit) {
        return Ok(227..=227);
    }
    if tail223_scan::scope(phase, unit)
        || cold223_scan::scope(phase, unit)
        || warmup223::scope(phase, unit)
    {
        return Ok(223..=223);
    }
    if watch198::namespace(phase, unit) {
        return Ok(198..=198);
    }
    if super::repair141::scope(phase, unit) {
        return Ok(141..=141);
    }
    if super::cohort191_delivery::queue_scope(phase, unit) {
        return Ok(191..=194);
    }
    if let Some(epoch) = super::cohort191_delivery::queue_sync_epoch(phase, unit) {
        return Ok(epoch..=epoch);
    }
    if phase == "producer-finalization" {
        return super::cohort_finalization::scope(unit);
    }
    if phase == "controller-import-handoff" {
        return super::cohort_finalization::handoff_scope(unit);
    }
    ensure!(
        unit.len() <= 255
            && unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "invalid pipeline unit name"
    );
    // Adaptive controllers use this namespace for the same local-publication
    // stage. Parsing its scope is observational only; the exact live command,
    // invocation, evidence and assigned publication boundary remain mandatory.
    if phase == "local-publication"
        && let Some(scope) = unit.strip_prefix("jetstreamer-root-import-")
    {
        let scope = scope
            .strip_suffix(".service")
            .context("root importer lacks service suffix")?;
        let (controller, scope) = scope
            .rsplit_once("-e")
            .context("root importer lacks epoch scope")?;
        ensure!(!controller.is_empty(), "root importer lacks controller ID");
        let fields: Vec<_> = scope.split('-').collect();
        ensure!(fields.len() == 3, "invalid root importer scope");
        let number = |value: &str| -> Result<u64> {
            let parsed: u64 = value.parse()?;
            ensure!(value == parsed.to_string(), "noncanonical importer number");
            Ok(parsed)
        };
        let start = number(fields[0])?;
        let end = number(fields[1])?;
        let sequence = number(fields[2])?;
        ensure!(
            sequence > 0 && start <= end && end - start <= 1000,
            "invalid root importer range or sequence"
        );
        return Ok(start..=end);
    }
    let prefix = match phase {
        "full-verification" => "horizon-full-verify-",
        "plugin-verification" => "horizon-plugin-verify-",
        "local-publication" => "horizon-publish-",
        "upload-readback" => "horizon-upload-",
        _ => anyhow::bail!("invalid pipeline phase"),
    };
    let scope = unit
        .strip_prefix(prefix)
        .and_then(|s| s.strip_suffix(".service"))
        .context("pipeline unit does not match phase")?;
    let mut fields = scope.splitn(3, '-');
    let first = fields.next().context("pipeline epoch missing")?;
    let second = fields.next().context("pipeline unit suffix missing")?;
    let start: u64 = first.parse()?;
    ensure!(
        first == start.to_string() && !second.is_empty(),
        "noncanonical pipeline scope"
    );
    let end = if second.bytes().all(|b| b.is_ascii_digit()) {
        let end: u64 = second.parse()?;
        ensure!(
            second == end.to_string() && fields.next().is_some_and(|s| !s.is_empty()),
            "noncanonical pipeline range"
        );
        end
    } else {
        start
    };
    ensure!(
        start <= end && end - start <= 1000,
        "invalid pipeline range"
    );
    Ok(start..=end)
}

fn validate_pipeline_claim(claim: &PipelineClaim, first: u64, last: u64) -> Result<()> {
    let scope = pipeline_unit_range_for_epoch(&claim.phase, &claim.unit, claim.epoch)?;
    ensure!(
        (first..=last).contains(&claim.epoch)
            && scope.contains(&claim.epoch)
            && *scope.start() >= first
            && *scope.end() <= last
            && claim.invocation_id.len() == 32
            && claim
                .invocation_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && !claim.expected_exec_start.trim().is_empty()
            && !claim.evidence.is_empty(),
        "invalid observational pipeline claim"
    );
    if demotion223_status::scope(&claim.phase, &claim.unit) {
        demotion223_status::validate_claim(claim, None)?;
    }
    Ok(())
}

// The existing serial uploader owns independently evidenced epochs, not one
// shared replay cohort. Keep the generic cohort evidence-equality rule; admit
// only the two reviewed delivery bindings for this exact unchanged invocation.
fn independent160_198_upload_evidence(a: &PipelineClaim, b: &PipelineClaim) -> bool {
    let evidence = |c: &PipelineClaim| {
        serde_json::to_value(&c.evidence).ok().is_some_and(|v| match c.epoch {
            160 => v == json!([
                {"path":"/var/lib/jetstreamer/horizon-epoch160-public-observation-20261022-v1/proof.json","sha256":"c54ede068b3cfd743259f52b93a98847910abe4fac6ff50ab88c4bbcae5e9008"},
                {"path":"/home/sol/.jetstreamer-private/r2-status-receipts/epoch-160.status-20261022145800.json","sha256":"77cf948e486907911de4371c1109afcf318700e92d1d4eef90fb77f4f2b96246"}
            ]),
            198 => v == json!([
                {"path":"/usr/local/lib/jetstreamer/horizon-epoch198-uploader-transition-20261021-v1/transition.json","sha256":"024b23f765a26f17c252df2bf0281cd3439aae046ee7a545227bd0ded98f4794"}
            ]),
            _ => false,
        })
    };
    a.unit == watch198::UPLOAD
        && b.unit == a.unit
        && a.phase == "upload-readback"
        && b.phase == a.phase
        && a.invocation_id == "e4e455fbd455483282107652ca37b83d"
        && b.invocation_id == a.invocation_id
        && a.expected_exec_start == b.expected_exec_start
        && matches!((a.epoch, b.epoch), (160, 198) | (198, 160))
        && evidence(a)
        && evidence(b)
}

fn register_pipeline_claim<'a>(
    units: &mut BTreeMap<&'a str, &'a PipelineClaim>,
    claim: &'a PipelineClaim,
) -> Result<()> {
    if let Some(prior) = units.get(claim.unit.as_str()) {
        ensure!(
            prior.epoch != claim.epoch
                && prior.phase == claim.phase
                && prior.invocation_id == claim.invocation_id
                && prior.expected_exec_start == claim.expected_exec_start
                && (prior.evidence == claim.evidence
                    || independent160_198_upload_evidence(prior, claim)),
            "duplicate or inconsistent cohort pipeline claim"
        );
    } else {
        units.insert(claim.unit.as_str(), claim);
    }
    Ok(())
}

fn register_live_pipeline_stage(
    stages: &mut BTreeSet<(u64, String)>,
    claim: &PipelineClaim,
) -> Result<()> {
    ensure!(
        stages.insert((claim.epoch, claim.phase.clone())),
        "overlapping live claims for the same pipeline stage"
    );
    Ok(())
}

fn preserve_pipeline_claims(previous: &Plan, current: &Plan) -> Result<()> {
    ensure!(
        previous.schema == current.schema
            && previous.first_epoch == current.first_epoch
            && previous.last_epoch == current.last_epoch
            && previous.pipeline_claims == current.pipeline_claims,
        "same-sample diagnostic admission cannot change pipeline claims"
    );
    Ok(())
}

fn pipeline_live(claim: &PipelineClaim, current: &Value) -> Result<bool> {
    let live = (current["ActiveState"] == "active" && current["SubState"] == "running")
        || (current["ActiveState"] == "activating" && current["SubState"] == "start");
    if live {
        ensure!(
            current["InvocationID"] == claim.invocation_id
                && current["NRestarts"] == "0"
                && current["ExecStart"].as_str().is_some_and(|command| {
                    pipeline_status::same_exec_start(&claim.expected_exec_start, command)
                })
                && current["LoadState"] == "loaded"
                && current["MainPID"]
                    .as_str()
                    .and_then(|v| v.parse::<u64>().ok())
                    .is_some_and(|pid| pid > 0),
            "pipeline live identity or exact command changed"
        );
        if demotion223_status::scope(&claim.phase, &claim.unit) {
            demotion223_status::validate_claim(claim, Some(current))?;
        }
        if super::repair141::scope(&claim.phase, &claim.unit) {
            let evidence = claim
                .evidence
                .iter()
                .map(bound_json)
                .collect::<Result<Vec<_>>>()?;
            super::repair141::validate_fleet_claim(
                claim.epoch,
                &claim.phase,
                &claim.unit,
                &claim.invocation_id,
                &claim.expected_exec_start,
                &evidence,
            )?;
        }
        if private144_scan::scope(&claim.phase, &claim.unit) {
            private144_scan::validate_live(claim, current)?;
        }
        if tail223_scan::scope(&claim.phase, &claim.unit) {
            tail223_scan::validate_live(claim, current)?;
        }
        if cold223_scan::scope(&claim.phase, &claim.unit) {
            cold223_scan::validate_live(claim, current)?;
        }
        if singleton227::native_scope(&claim.phase, &claim.unit) {
            singleton227::native_live(claim, current)?;
        }
        if native207::scope(&claim.phase, &claim.unit) {
            native207::live(claim, current)?;
        } else if native228::scope(&claim.phase, &claim.unit) {
            native228::live(claim, current)?;
        } else if native209::scope(&claim.phase, &claim.unit) {
            native209::live(claim, current)?;
        } else if native210::scope(&claim.phase, &claim.unit) {
            native210::live(claim, current)?;
        } else if native227_v1625::scope(&claim.phase, &claim.unit) {
            native227_v1625::live(claim, current)?;
        }
        if warmup223::scope(&claim.phase, &claim.unit) {
            warmup223::validate_live(claim, current)?;
        }
        if claim.epoch == 160 && watch160::namespace(&claim.phase, &claim.unit) {
            return Ok(watch160::child_start(&claim.phase, current)?.is_some());
        }
        if watch198::namespace(&claim.phase, &claim.unit) {
            ensure!(claim.epoch == 198, "legacy watcher profile is198 only");
            return Ok(watch198::child_start(&claim.phase, current)?.is_some());
        }
    }
    Ok(live)
}

// RemainAfterExit retains a completed diagnostic as active/exited evidence.
// It is not a live owner and must not block its independently qualified delivery.
// A queued/activating diagnostic still owns the epoch and remains a conflict.
fn diagnostic_stage_running(current: &Value) -> bool {
    (current["ActiveState"] == "active" && current["SubState"] == "running")
        || current["ActiveState"] == "activating"
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    first_epoch: u64,
    last_epoch: u64,
    observer: BoundFile,
    previous_fleet: Option<BoundFile>,
    output: PathBuf,
    status_receipt_directory: PathBuf,
    gates: BTreeMap<u64, Gate>,
    // Include terminal and quarantined controllers, not just observer entries.
    tracked_units: Vec<String>,
    // Bounded private comparisons capture their own in-run resource counters.
    // They are active qualification work, not ordinary replay/sidecar claims.
    #[serde(default)]
    diagnostics: Vec<DiagnosticClaim>,
    #[serde(default)]
    epoch203_ram_auxiliary: Option<ram_auxiliary::Claim>,
    #[serde(default)]
    pipeline_claims: Vec<PipelineClaim>,
    #[serde(default)]
    runtime_handoff157: Option<BoundFile>,
    // One event-driven bounded admission may update the active list using the
    // same observer. This is not authority for another resource observation.
    #[serde(default)]
    admission_transition_guard: Option<BoundFile>,
    #[serde(default)]
    metadata_event: Option<BoundFile>,
    #[serde(default)]
    continuation203_runtime_extension: Option<BoundFile>,
    #[serde(default)]
    capped204205_work: Vec<capped204205_work::Claim>,
    #[serde(default)]
    capped204205_history: Vec<Value>,
    #[serde(default)]
    assembly204_recovery: Option<assembly204_recovery::Claim>,
    #[serde(default)]
    assembly204_recovery_history: Vec<Value>,
    #[serde(default)]
    assembly204_recovery_terminal: Option<BoundFile>,
}

fn validate_same_sample_admission(
    previous: &Value,
    plan: &Plan,
    sample: &str,
    guard: &Value,
    guard_plan: &Value,
    now: u64,
) -> Result<()> {
    ensure!(
        plan.epoch203_ram_auxiliary.is_none()
            && previous
                .get("auxiliary_diagnostics")
                .is_none_or(|r| r.as_array().is_some_and(Vec::is_empty)),
        "ordinary admission transition cannot drop or add a RAM auxiliary owner"
    );
    ensure!(
        previous["schema"] == SCHEMA
            && previous["first_epoch"] == plan.first_epoch
            && previous["last_epoch"] == plan.last_epoch
            && previous["sampled_at_utc"] == sample
            && previous["observer_receipt"].as_str() == plan.observer.path.to_str()
            && previous["observer_sha256"] == plan.observer.sha256
            && previous["admission_transition_guard"].is_null(),
        "same-sample admission requires the exact untransitioned modern predecessor"
    );
    let old = previous["diagnostics"]
        .as_array()
        .context("previous diagnostic census missing")?;
    ensure!(
        plan.diagnostics.len() == old.len() + 1,
        "admission must add exactly one diagnostic"
    );
    for prior in old {
        let matches: Vec<_> = plan
            .diagnostics
            .iter()
            .filter(|claim| {
                prior["unit"]["Id"] == claim.unit
                    && prior["epoch"] == claim.epoch
                    && prior["launch_invocation_id"] == claim.invocation_id
                    && prior["launch_receipt"].as_str() == claim.launch_receipt.path.to_str()
                    && prior["launch_receipt_sha256"] == claim.launch_receipt.sha256
            })
            .collect();
        ensure!(
            matches.len() == 1,
            "admission removed or changed diagnostic history"
        );
    }
    let added: Vec<_> = plan
        .diagnostics
        .iter()
        .filter(|claim| !old.iter().any(|prior| prior["unit"]["Id"] == claim.unit))
        .collect();
    ensure!(added.len() == 1, "admission has no unique added unit");
    let claim = added[0];
    if private157::namespace(claim) {
        return private157::admission(previous, plan, claim, guard, guard_plan, now);
    }
    if prefix144::namespace(claim) {
        return prefix144::admission(previous, plan, claim, guard, guard_plan, now);
    }
    // Only these separately pinned private measurement contracts may report
    // one same-sample admission; this never grants launch authority.
    let expected_guard = match claim.epoch {
        136 if epoch136::namespace(claim) => epoch136::GUARD_SHA,
        141 if original141_capped::namespace(claim) => original141_capped::GUARD_SHA,
        141 if original141_vote_prefix::namespace(claim) => original141_vote_prefix::GUARD_SHA,
        141 if original141_freeze::namespace(claim) => original141_freeze::GUARD_SHA,
        141 if original141_trace::namespace(claim) => original141_trace::GUARD_SHA,
        141 if original141::namespace(claim) => original141::GUARD_SHA,
        140 if native_restore_140(claim) => {
            // This host's unchanged, sealed generic bootstrap/drainage guard.
            // Admission still requires its real one-worker sandboxed first fire.
            "eca429932ffe9afe71aecba815ab301db46bdddbaf24b4c44af8c88bb74a6194"
        }
        144 if native144::namespace(claim) => {
            "eca429932ffe9afe71aecba815ab301db46bdddbaf24b4c44af8c88bb74a6194"
        }
        144 if continuation144::namespace(claim) => {
            "eca429932ffe9afe71aecba815ab301db46bdddbaf24b4c44af8c88bb74a6194"
        }
        144 if assembly144::namespace(claim) => {
            "eca429932ffe9afe71aecba815ab301db46bdddbaf24b4c44af8c88bb74a6194"
        }
        223 if assembly223::namespace(claim) => assembly223::GUARD_SHA,
        223 if verification223::namespace(claim) => verification223::GUARD_SHA,
        223 if tail223::namespace(claim) => tail223::GUARD_SHA,
        223 if prefix223::namespace(claim) => prefix223::GUARD_SHA,
        223 if prefix223_native20::namespace(claim) => prefix223_native20::GUARD_SHA,
        207 if singleton207::namespace(claim) => singleton207::GUARD_SHA,
        233 if first_root233::namespace(claim) => first_root233::GUARD_SHA,
        224 if claim
            .unit
            .starts_with("horizon-qualify-224-bounded-resource-") =>
        {
            "f4f5c0758c1c02b7d9a3b2b1595af7bbc033997f671cd43f2d4a92d38c346c69"
        }
        205 if bounded205::namespace(claim) => bounded205::GUARD_SHA256,
        227 if canary227::namespace(claim) => canary227::GUARD_SHA,
        205 if prefix205::namespace(claim) => prefix205::GUARD_SHA,
        204 if prefix204::namespace(claim) => prefix204::GUARD_SHA,
        227 if singleton227::namespace(claim) => singleton227::SINGLETON_GUARD_SHA,
        209 if singleton209::namespace(claim) => singleton209::GUARD_SHA,
        210 if singleton210::namespace(claim) => singleton210::GUARD_SHA,
        203 if native203::namespace(claim) => native203::GUARD_SHA,
        203 if continuation203::namespace(claim) => continuation203::GUARD_SHA,
        225 if claim
            .unit
            .starts_with("horizon-qualify-225-bounded-resource-") =>
        {
            "61e189bb50d58fa446b84f016d3b19433c30f490c6d470907130f113a01b644a"
        }
        225 if claim
            .unit
            .starts_with("horizon-qualify-225-natural-root-resource-") =>
        {
            // The unchanged standalone guard's natural-completion profile,
            // never a target-stop or zero-worker benchmark exemption.
            "cc3536dfcc268c913feccf1603a25e3cdbdf2807289c9061e04884027d1b1560"
        }
        203 if shrink_budget_203_namespace(claim) => {
            // Separately sealed guard with the exact epoch203 target-stop
            // profile; this does not replace a guard on an existing replay.
            "d039ddf0b161bc554614a862bd12987bd6a3474549a22d066ebefa5584e5dd98"
        }
        203 if claim
            .unit
            .starts_with("horizon-qualify-203-bounded-resource-")
            || claim
                .unit
                .starts_with("horizon-qualify-203-root-prefix-resource-") =>
        {
            "cc3536dfcc268c913feccf1603a25e3cdbdf2807289c9061e04884027d1b1560"
        }
        _ => anyhow::bail!("unsupported admission transition profile"),
    };
    let timestamp = guard["recorded_unix_seconds"]
        .as_u64()
        .context("guard omits time")?;
    let sample_seconds = utc_seconds(sample)?;
    ensure!(
        timestamp >= sample_seconds
            && timestamp <= now
            && now - timestamp <= 1800
            && now - sample_seconds <= 1800
            && previous["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t <= timestamp),
        "admission guard is stale, future or predates predecessor"
    );
    ensure!(
        guard["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && guard["guard_sha256"] == expected_guard
            && guard["producer_invocation_id"] == claim.invocation_id
            && guard["producer"]["invocation_id"] == claim.invocation_id
            && guard["producer"]["cgroup"] == format!("/system.slice/{}", claim.unit)
            && guard["producer"]["active"] == "active"
            && guard["producer"]["sub"] == "running"
            && guard["producer"]["load_state"] == "loaded"
            && guard["producer"]["result"] == "success"
            && guard["producer"]["restart_policy"] == "no"
            && guard["producer"]["kill_mode"] == "control-group"
            && guard["producer"]["delegated"] == false
            && guard["producer"]["restarts"] == 0
            && guard["producer"]["pid"].as_u64().is_some_and(|pid| pid > 0)
            && guard.get("trip_reason").is_some_and(Value::is_null)
            && guard
                .get("worker_observation_error")
                .is_some_and(Value::is_null)
            && if epoch136::namespace(claim)
                || original141_trace::namespace(claim)
                || original141_freeze::namespace(claim)
                || original141_vote_prefix::namespace(claim)
                || original141_capped::namespace(claim)
            {
                guard.get("canary_target_error").is_some_and(Value::is_null)
                    && guard["bounded_measurement"] == false
                    && guard.get("bounded_canary").is_some_and(Value::is_null)
                    && guard.get("target_handoff").is_some_and(Value::is_null)
                    && guard
                        .get("target_handoff_error")
                        .is_some_and(Value::is_null)
            } else if native_restore_140(claim)
                || original141::namespace(claim)
                || native144::namespace(claim)
                || continuation144::namespace(claim)
                || assembly144::namespace(claim)
            {
                // The pinned eca guard predates bounded-canary fields.
                guard.get("canary_target_error").is_none()
                    && guard["bounded_measurement"] == false
                    && guard.get("target_handoff").is_some_and(Value::is_null)
                    && guard
                        .get("target_handoff_error")
                        .is_some_and(Value::is_null)
            } else {
                guard.get("canary_target_error").is_some_and(Value::is_null)
            }
            && guard["r2_mutations"] == false
            && guard["remote_mutations"] == false,
        "admission lacks exact clean sandboxed guard evidence"
    );
    let workers = guard["workers"]
        .as_array()
        .context("guard workers missing")?;
    ensure!(
        diagnostic_guard_workers_match(claim, workers),
        "admission must prove its exact worker census (assembly-only requires zero)"
    );
    ensure!(
        guard_plan["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && guard_plan["unit"] == claim.unit
            && guard_plan["invocation_id"] == claim.invocation_id
            && guard_plan["worker_root"].as_str() == diagnostic_guard_worker_root(claim).to_str()
            && diagnostic_guard_profile_matches(claim, guard_plan)
            && guard_plan["maximum_worker_vmas"] == 3_500_000
            && guard["maximum_worker_vmas"] == guard_plan["maximum_worker_vmas"]
            && guard["minimum_free_bytes"] == guard_plan["minimum_free_bytes"]
            && guard_plan["minimum_free_bytes"]
                .as_u64()
                .is_some_and(|floor| floor > 0)
            && guard["available_bytes"]
                .as_u64()
                .zip(guard["minimum_free_bytes"].as_u64())
                .is_some_and(|(free, floor)| free >= floor),
        "admission guard plan or safety envelope differs"
    );
    Ok(())
}

fn diagnostic_guard_worker_root(claim: &DiagnosticClaim) -> PathBuf {
    if epoch136::namespace(claim)
        || original141_trace::namespace(claim)
        || original141_freeze::namespace(claim)
        || original141_vote_prefix::namespace(claim)
        || original141_capped::namespace(claim)
    {
        // The profile validator independently binds the exact canonical root.
        claim
            .scratch_path
            .parent()
            .unwrap_or(Path::new("/"))
            .to_path_buf()
    } else if tail223::namespace(claim)
        || prefix223::namespace(claim)
        || prefix205::namespace(claim)
        || prefix204::namespace(claim)
    {
        claim.scratch_path.join("scratch")
    } else {
        claim.scratch_path.clone()
    }
}

fn private_qualification_inventory_state(gate_state: &str) -> &str {
    if gate_state == "failed-needs-repair" {
        // A live diagnostic is repair progress, not closure of the incident.
        // Only the later authenticated ready-pair classification closes it.
        gate_state
    } else {
        "blocked-qualification"
    }
}

fn diagnostic_guard_workers_match(claim: &DiagnosticClaim, workers: &[Value]) -> bool {
    if assembly144::namespace(claim)
        || assembly223::namespace(claim)
        || verification223::namespace(claim)
    {
        workers.is_empty()
    } else {
        workers.len() == 1
            && workers[0][0].as_u64().is_some_and(|pid| pid > 0)
            && workers[0][1]
                .as_u64()
                .is_some_and(|vmas| vmas > 0 && vmas <= 3_500_000)
    }
}
fn diagnostic_owns_observation(claims: &[DiagnosticClaim], entry: &Value) -> bool {
    claims.iter().any(|c| {
        entry["epoch"] == c.epoch
            && entry["producer"]["Id"] == c.unit
            && entry["producer"]["InvocationID"] == c.invocation_id
            && entry["scratch_path"].as_str() == c.scratch_path.to_str()
    })
}

fn diagnostic_guard_profile_matches(claim: &DiagnosticClaim, plan: &Value) -> bool {
    if singleton207::namespace(claim) {
        return bound_json(&claim.launch_receipt)
            .is_ok_and(|r| singleton207::guard_matches(claim, &r, plan));
    }
    if first_root233::namespace(claim) {
        return bound_json(&claim.launch_receipt)
            .is_ok_and(|r| first_root233::guard_matches(claim, &r, plan));
    }
    if verification223::namespace(claim) {
        return bound_json(&claim.launch_receipt)
            .is_ok_and(|r| verification223::guard_matches(claim, &r, plan));
    }
    if assembly223::namespace(claim) {
        return bound_json(&claim.launch_receipt)
            .is_ok_and(|r| assembly223::guard_matches(claim, &r, plan));
    }
    if epoch136::namespace(claim) {
        return bound_json(&claim.launch_receipt)
            .is_ok_and(|r| epoch136::guard_matches(claim, &r, plan));
    }
    if original141_capped::namespace(claim) {
        return bound_json(&claim.launch_receipt)
            .is_ok_and(|r| original141_capped::guard_matches(claim, &r, plan));
    }
    if original141_vote_prefix::namespace(claim) {
        return bound_json(&claim.launch_receipt)
            .is_ok_and(|r| original141_vote_prefix::guard_matches(claim, &r, plan));
    }
    if original141_freeze::namespace(claim) {
        bound_json(&claim.launch_receipt)
            .is_ok_and(|r| original141_freeze::guard_matches(claim, &r, plan))
    } else if original141_trace::namespace(claim) {
        bound_json(&claim.launch_receipt)
            .is_ok_and(|r| original141_trace::guard_matches(claim, &r, plan))
    } else if original141::namespace(claim) {
        bound_json(&claim.launch_receipt).is_ok_and(|r| original141::guard_matches(claim, &r, plan))
    } else if continuation203::namespace(claim) {
        bound_json(&claim.launch_receipt)
            .is_ok_and(|r| continuation203::guard_matches(claim, &r, plan))
    } else if native203::namespace(claim) {
        bound_json(&claim.launch_receipt).is_ok_and(|r| native203::guard_matches(claim, &r, plan))
    } else if continuation144::namespace(claim) || assembly144::namespace(claim) {
        let Ok(launch) = checked_diagnostic_launch(claim) else {
            return false;
        };
        plan.get("bounded_canary").is_none_or(Value::is_null)
            && plan.get("bounded_measurement").is_none_or(Value::is_null)
            && plan["filesystem"] == "/home/sol"
            && plan["minimum_free_bytes"] == launch["required_guard_minimum_free_bytes"]
    } else if tail223::namespace(claim) {
        bound_json(&claim.launch_receipt)
            .is_ok_and(|receipt| tail223::guard_matches(claim, &receipt, plan))
    } else if prefix205::namespace(claim) {
        bound_json(&claim.launch_receipt).is_ok_and(|r| prefix205::guard_matches(claim, &r, plan))
    } else if prefix204::namespace(claim) {
        bound_json(&claim.launch_receipt).is_ok_and(|r| prefix204::guard_matches(claim, &r, plan))
    } else if singleton227::namespace(claim) {
        bound_json(&claim.launch_receipt)
            .is_ok_and(|r| singleton227::guard_matches(claim, &r, plan))
    } else if singleton209::namespace(claim) {
        bound_json(&claim.launch_receipt)
            .is_ok_and(|r| singleton209::guard_matches(claim, &r, plan))
    } else if singleton210::namespace(claim) {
        bound_json(&claim.launch_receipt)
            .is_ok_and(|r| singleton210::guard_matches(claim, &r, plan))
    } else if prefix223_native20::namespace(claim) {
        bound_json(&claim.launch_receipt)
            .is_ok_and(|r| prefix223_native20::guard_matches(claim, &r, plan))
    } else if prefix223::namespace(claim) {
        bound_json(&claim.launch_receipt)
            .is_ok_and(|receipt| prefix223::guard_matches(claim, &receipt, plan))
    } else if canary227::namespace(claim) {
        bound_json(&claim.launch_receipt)
            .is_ok_and(|receipt| canary227::guard_matches(claim, &receipt, plan))
    } else if bounded205::namespace(claim) {
        bound_json(&claim.launch_receipt)
            .is_ok_and(|receipt| bounded205::guard_matches(claim, &receipt, plan))
    } else if native144::namespace(claim) {
        plan.get("bounded_canary").is_none()
            && plan.get("bounded_measurement").is_none_or(Value::is_null)
            && plan["filesystem"] == "/home/sol"
            && plan["minimum_free_bytes"]
                .as_u64()
                .is_some_and(|n| n >= 4_740_696_923_590)
    } else if native_restore_140(claim) {
        plan.get("bounded_canary").is_none()
            && plan.get("bounded_measurement").is_none_or(Value::is_null)
            && plan["filesystem"] == "/home/sol"
            && plan["minimum_free_bytes"]
                .as_u64()
                .is_some_and(|v| v >= 5_153_080_892_870)
    } else if shrink_budget_203_namespace(claim) {
        !claim
            .unit
            .starts_with("horizon-qualify-203-bounded-resource-shrink-budget-r1-")
            && plan.get("bounded_measurement").is_none_or(Value::is_null)
            && plan["bounded_canary"]["expected_uid"] == 1000
            && plan["bounded_canary"]["maximum_drainage_seconds"] == 180
            && plan["bounded_canary"]["target_stop_intent"].as_str()
                == claim
                    .scratch_path
                    .join("receipts/target-stop.json")
                    .to_str()
    } else if claim.epoch == 225
        && claim
            .unit
            .starts_with("horizon-qualify-225-natural-root-resource-")
    {
        plan.get("bounded_canary").is_none_or(Value::is_null)
            && plan.get("bounded_measurement").is_none_or(Value::is_null)
            // Lower bound only: fresh admission must additionally protect the
            // remaining 203 debt. This does not adopt the proposed 512GiB
            // replacement for the still-live 576GiB 216-219 growth claim.
            && plan["minimum_free_bytes"]
                .as_u64()
                .is_some_and(|v| v >= 231_874_716_783 + ((576 + 640 + 64) << 30))
    } else if claim.epoch == 224
        && claim
            .unit
            .starts_with("horizon-qualify-224-bounded-resource-")
    {
        plan.get("bounded_measurement").is_none_or(Value::is_null)
            && plan["bounded_canary"]["expected_uid"] == 1000
            && plan["bounded_canary"]["maximum_drainage_seconds"] == 180
            && plan["bounded_canary"]["target_stop_intent"].as_str()
                == claim
                    .scratch_path
                    .join("receipts/target-stop.json")
                    .to_str()
    } else if claim.epoch == 203
        && claim
            .unit
            .starts_with("horizon-qualify-203-root-prefix-resource-")
    {
        // A natural-completion qualification is not a target-stopped benchmark.
        // Its first fire must still prove one worker above the old-growth floor.
        plan.get("bounded_canary").is_none_or(Value::is_null)
            && plan.get("bounded_measurement").is_none_or(Value::is_null)
            && plan["minimum_free_bytes"]
                .as_u64()
                .is_some_and(|v| v >= 2_158_885_108_875)
    } else {
        plan["bounded_canary"]["expected_uid"] == 1000
    }
}

fn validate_diagnostic_launch(receipt: &Value, claim: &DiagnosticClaim) -> Result<()> {
    if singleton207::namespace(claim) || receipt["schema"] == singleton207::SCHEMA {
        ensure!(
            singleton207::launch_matches(claim, receipt),
            "singleton 207 namespace, schema, or private prefix scope differs"
        );
        return Ok(());
    }
    if first_root233::namespace(claim) || receipt["schema"] == first_root233::SCHEMA {
        ensure!(
            first_root233::launch_matches(claim, receipt),
            "first root 233 namespace, schema, or private prefix scope differs"
        );
        return Ok(());
    }
    if epoch136::namespace(claim) || receipt["schema"] == epoch136::SCHEMA {
        return epoch136::launch(receipt, claim);
    }
    if original141_capped::namespace(claim) || receipt["schema"] == original141_capped::SCHEMA {
        return original141_capped::launch(receipt, claim);
    }
    if original141_vote_prefix::namespace(claim)
        || receipt["schema"] == original141_vote_prefix::SCHEMA
    {
        return original141_vote_prefix::launch(receipt, claim);
    }
    if original141_freeze::namespace(claim) || receipt["schema"] == original141_freeze::SCHEMA {
        return original141_freeze::launch(receipt, claim);
    }
    if original141_trace::namespace(claim) || receipt["schema"] == original141_trace::SCHEMA {
        return original141_trace::launch(receipt, claim);
    }
    if original141::namespace(claim) || receipt["schema"] == original141::SCHEMA {
        return original141::launch(receipt, claim);
    }
    if continuation203::namespace(claim) || receipt["schema"] == continuation203::SCHEMA {
        return continuation203::launch(receipt, claim);
    }
    if native203::namespace(claim) || receipt["schema"] == native203::SCHEMA {
        return native203::launch(receipt, claim);
    }
    if census141_poh::namespace(claim) || receipt["schema"] == census141_poh::SCHEMA {
        return census141_poh::launch(receipt, claim);
    }
    if native141::namespace(claim) || receipt["schema"] == native141::SCHEMA {
        return native141::launch(receipt, claim);
    }
    if verification223::namespace(claim) || receipt["schema"] == verification223::SCHEMA {
        return verification223::launch(receipt, claim);
    }
    if assembly223::namespace(claim) || receipt["schema"] == assembly223::SCHEMA {
        return assembly223::launch(receipt, claim);
    }
    if assembly144::namespace(claim) || receipt["schema"] == assembly144::SCHEMA {
        return assembly144::launch(receipt, claim);
    }
    if continuation144::namespace(claim) || receipt["schema"] == continuation144::SCHEMA {
        return continuation144::launch(receipt, claim);
    }
    if native144::namespace(claim) || receipt["schema"] == native144::SCHEMA {
        return native144::launch(receipt, claim);
    }
    if retained220::namespace(claim) || receipt["schema"] == retained220::SCHEMA {
        return retained220::launch(receipt, claim);
    }
    if prefix144::namespace(claim) || receipt["schema"] == prefix144::SCHEMA {
        return prefix144::launch(receipt, claim);
    }
    if private157::namespace(claim) || receipt["schema"] == private157::SCHEMA {
        return private157::launch(receipt, claim);
    }
    let native_restore =
        receipt["schema"] == "jetstreamer-private-epoch140-native-restore-launch-v1";
    let continuation =
        receipt["schema"] == "jetstreamer-private-epoch213-checkpoint-continuation-launch-v1";
    let bootstrap_resource =
        receipt["schema"] == "jetstreamer-private-epoch225-bootstrap-resource-launch-v1";
    let bounded_resource =
        receipt["schema"] == "jetstreamer-private-epoch225-bounded-resource-launch-v1";
    let bounded_v1625 = receipt["schema"] == "jetstreamer-private-epoch225-v1625-bounded-launch-v1";
    let shrink_budget_225 =
        receipt["schema"] == "jetstreamer-private-epoch225-shrink-budget-resource-launch-v1";
    ensure!(
        !shrink_budget225::namespace(claim) || shrink_budget_225,
        "shrink-budget225 namespace cannot borrow another diagnostic schema"
    );
    let bounded_203 =
        receipt["schema"] == "jetstreamer-private-epoch203-bounded-resource-launch-v1";
    let bounded_205 = receipt["schema"] == bounded205::SCHEMA;
    let canary_227 = receipt["schema"] == canary227::SCHEMA;
    ensure!(
        !canary227::namespace(claim) || canary_227,
        "227 canary namespace requires its exact launch schema"
    );
    let tail_223 = receipt["schema"] == tail223::SCHEMA;
    let prefix_223 = receipt["schema"] == prefix223::SCHEMA;
    let prefix_223_native20 = receipt["schema"] == prefix223_native20::SCHEMA;
    let prefix_205 = receipt["schema"] == prefix205::SCHEMA;
    let prefix_204 = receipt["schema"] == prefix204::SCHEMA;
    let singleton_227 = receipt["schema"] == singleton227::SCHEMA;
    let singleton_209 = receipt["schema"] == singleton209::SCHEMA;
    let singleton_210 = receipt["schema"] == singleton210::SCHEMA;
    ensure!(
        !singleton210::namespace(claim) || singleton_210,
        "capped210 namespace requires its own full singleton schema"
    );
    ensure!(
        !singleton209::namespace(claim) || singleton_209,
        "capped209 namespace requires its own full singleton schema"
    );
    ensure!(
        !singleton227::namespace(claim) || singleton_227,
        "capped227 namespace requires its own full singleton schema"
    );
    ensure!(
        !prefix204::namespace(claim) || prefix_204,
        "capped204 namespace requires its own schema"
    );
    ensure!(
        !prefix205::namespace(claim) || prefix_205,
        "capped205 namespace requires its own schema"
    );
    ensure!(
        !prefix223::namespace(claim) || prefix_223,
        "prefix223 namespace requires its own private schema"
    );
    ensure!(
        !prefix223_native20::namespace(claim) || prefix_223_native20,
        "native20 prefix223 namespace requires its own private schema"
    );
    ensure!(
        !tail223::namespace(claim) || tail_223,
        "tail223 namespace requires its own private schema"
    );
    ensure!(
        !bounded205::namespace(claim) || bounded_205,
        "bounded205 namespace requires its own launch schema"
    );
    let shrink_budget_203 =
        receipt["schema"] == "jetstreamer-private-epoch203-shrink-budget-resource-launch-v1";
    let bounded_224 =
        receipt["schema"] == "jetstreamer-private-epoch224-bounded-resource-launch-v1";
    let root_prefix_203 =
        receipt["schema"] == "jetstreamer-private-epoch203-root-prefix-resource-launch-v1";
    let shrink_root_203 =
        receipt["schema"] == "jetstreamer-private-epoch203-shrink-root-prefix-resource-launch-v1";
    let shrink_natural_root_225 =
        receipt["schema"] == "jetstreamer-private-epoch225-shrink-natural-root-resource-launch-v1";
    ensure!(
        !claim
            .unit
            .starts_with("horizon-qualify-225-natural-root-resource-shrink-budget-")
            || shrink_natural_root_225,
        "shrink natural-root225 namespace requires its own launch schema"
    );
    let natural_root_225 = shrink_natural_root_225
        || receipt["schema"] == "jetstreamer-private-epoch225-natural-root-resource-launch-v1";
    let private_verify_213 =
        receipt["schema"] == "jetstreamer-private-epoch213-verification-launch-v1";
    let private_verify_225 =
        receipt["schema"] == "jetstreamer-private-epoch225-verification-launch-v1";
    ensure!(
        (native_restore
            || continuation
            || bootstrap_resource
            || bounded_resource
            || bounded_v1625
            || shrink_budget_225
            || bounded_203
            || bounded_205
            || canary_227
            || tail_223
            || prefix_223
            || prefix_223_native20
            || prefix_205
            || prefix_204
            || singleton_227
            || singleton_209
            || singleton_210
            || shrink_budget_203
            || bounded_224
            || root_prefix_203
            || shrink_root_203
            || natural_root_225
            || private_verify_213
            || private_verify_225
            || receipt["schema"] == "jetstreamer-historical-performance-launch-receipt-v1")
            && receipt["launched"] == true
            && receipt["remote_mutations"] == false
            && receipt["r2_mutations"] == false,
        "invalid diagnostic launch receipt"
    );
    let scope_valid = if singleton_209 {
        singleton209::launch_matches(claim, receipt)
    } else if singleton_210 {
        singleton210::launch_matches(claim, receipt)
    } else if singleton_227 {
        singleton227::launch_matches(claim, receipt)
    } else if prefix_204 {
        prefix204::launch_matches(claim, receipt)
    } else if prefix_205 {
        prefix205::launch_matches(claim, receipt)
    } else if prefix_223_native20 {
        prefix223_native20::launch_matches(claim, receipt)
    } else if prefix_223 {
        prefix223::launch_matches(claim, receipt)
    } else if tail_223 {
        tail223::launch_matches(claim, receipt)
    } else if canary_227 {
        canary227::launch_matches(claim, receipt)
    } else if bounded_205 {
        bounded205::launch_matches(claim, receipt)
    } else if native_restore {
        native_restore_140_launch_matches(claim, receipt)
    } else if continuation {
        claim.epoch == 213
            && claim
                .unit
                .starts_with("horizon-qualify-213-checkpoint-continuation-")
            && claim.unit.ends_with(".service")
            && receipt["epoch"] == 213
            && receipt["private_run_root"].as_str() == claim.scratch_path.to_str()
            && receipt["replay_slot_start"] == 92_447_543u64
            && receipt["replay_slot_end_inclusive"] == 92_447_999u64
            && receipt["canonical_sidecar_authorized"] == false
            && receipt["publication_authorized"] == false
    } else if private_verify_225 {
        private_225_verification(claim)
            && receipt["epoch"] == 225
            && receipt["private_run_root"].as_str() == claim.scratch_path.to_str()
            && claim.scratch_path.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && claim
                .scratch_path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-225-private-scan-"))
            && receipt["verifier_sha256"]
                == "4cfa32a6956c3482891b9efe3b9e7c58135c8caddd40736bcf39a0bc7b6d9e2b"
            && receipt["producer_invocation_id"] == "ac9aee3d47eb41e483a5e008ed43d030"
            && receipt["archive_path"]
                == "/home/ubuntu/.jetstreamer-private/qualification-225-v1625-natural-root-63a2717-v1/output/epoch-225.jet"
            && receipt["output_slot_start"] == 97_200_000u64
            && receipt["terminal_slot"] == 98_063_464u64
            && receipt["output_slot_count"] == 863_465u64
            && receipt["private_verification_tail_epoch"] == 226
            && receipt["private_verification_tail_slots"] == 431_465u64
            && receipt["producer_natural_completion_confirmed"] == true
            && canonical_digest(&receipt["plan_sha256"])
            && canonical_digest(&receipt["terminal_evidence"]["sha256"])
            && receipt["terminal_evidence"]["path"]
                .as_str()
                .is_some_and(|s| Path::new(s).is_absolute())
            && receipt["expected_exec_start"].as_str().is_some_and(|s| {
                s.starts_with(&format!(
                    "{{ path={PRIVATE_225_READER} ; argv[]={PRIVATE_225_READER} "
                ))
            })
            && receipt["replay_entries_authorized"] == false
            && receipt["runtime_promotion_authorized"] == false
            && receipt["canonical_sidecar_authorized"] == false
            && receipt["publication_authorized"] == false
    } else if private_verify_213 {
        claim.epoch == 213
            && claim
                .unit
                .starts_with("horizon-qualify-213-private-verification-")
            && claim.unit.ends_with(".service")
            && receipt["epoch"] == 213
            && receipt["private_run_root"].as_str() == claim.scratch_path.to_str()
            && claim.scratch_path.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && claim
                .scratch_path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-213-private-scan-"))
            && receipt["verifier_sha256"]
                == "8d9bd29c60c8ea5870e2169255acaae8d2f7436c4ec130dc8154d28cc4628130"
            && receipt["producer_invocation_id"] == "1dfd29e7ced140b3ba407359cbdc0ee1"
            && receipt["provenance_expectation_sha256"]
                == "f7bb330186a8fbcc438b0fa49e903af5be5a1c30092f7cd434a86f6b2916bea5"
            && receipt["plan_sha256"].as_str().is_some_and(|s| {
                s.len() == 64
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            && receipt["replay_entries_authorized"] == false
            && receipt["canonical_sidecar_authorized"] == false
            && receipt["publication_authorized"] == false
    } else if bootstrap_resource {
        claim.epoch == 225
            && claim
                .unit
                .starts_with("horizon-qualify-225-bootstrap-resource-")
            && claim.unit.ends_with(".service")
            && receipt["epoch"] == 225
            && receipt["private_run_root"].as_str() == claim.scratch_path.to_str()
            && receipt["snapshot_slot"] == 97_199_617u64
            && receipt["snapshot_sha256"]
                == "094d3b28c39403580fbac083cdad67cc008b255dd375d611217103750d0f412d"
            && receipt["worker_sha256"]
                == "f39140b9a9659e7c6e8207076a2d0c560a6b69df42cc92e19a421cf46c2b761c"
            && receipt["replay_entries_authorized"] == false
            && receipt["full_cold_epoch_peak_qualified"] == false
            && receipt["canonical_sidecar_authorized"] == false
            && receipt["publication_authorized"] == false
    } else if natural_root_225 {
        claim.epoch == 225
            && (!shrink_natural_root_225
                || (claim
                    .unit
                    .starts_with("horizon-qualify-225-natural-root-resource-shrink-budget-")
                    && claim
                        .scratch_path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .is_some_and(|s| {
                            s.starts_with("qualification-225-v1625-natural-root-shrink-budget-")
                        })))
            && claim
                .unit
                .starts_with("horizon-qualify-225-natural-root-resource-")
            && claim.unit.ends_with(".service")
            && claim.scratch_path.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
            && claim
                .scratch_path
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("qualification-225-v1625-natural-root-"))
            && receipt["epoch"] == 225
            && receipt["private_run_root"].as_str() == claim.scratch_path.to_str()
            && receipt["snapshot_slot"] == 97_199_617u64
            && receipt["snapshot_sha256"]
                == "094d3b28c39403580fbac083cdad67cc008b255dd375d611217103750d0f412d"
            && receipt["worker_sha256"]
                == if shrink_natural_root_225 {
                    "2dcc9b84a6ce27edba3d3b053c6e6170f66a2337f12a5aae54900c3ad9e2eedd"
                } else {
                    "7cd48efc8719109a69fafcb3209a821ea9f07113e3fb0bfab49db23a6e77a146"
                }
            && receipt["node_sha256"]
                == "945f36fe11824263258ad561dba106e377148b702f2c615522b171c4ba97ed3b"
            && receipt["runtime"] == "solana-v1.6.25"
            && receipt["runtime_semantics_changed"] == true
            && receipt["solana_rayon_threads"] == 16
            && receipt["output_slot_start"] == 97_200_000u64
            && receipt["output_slot_count"] == 863_465u64
            && receipt["canonical_epoch_end"] == 97_631_999u64
            && receipt["terminal_root_slot"] == 98_063_464u64
            && receipt["required_checkpoints"] == json!([97_199_617, 97_631_459, 98_063_464])
            && receipt["private_verification_tail_epoch"] == 226
            && receipt["private_verification_tail_slots"] == 431_465u64
            && receipt["natural_parent_completion_required"] == true
            && receipt["maximum_runtime_seconds"] == 604_800u64
            && receipt["natural_root_resource_attempt_authorized"] == true
            && receipt["full_span_independently_qualified"] == false
            && receipt["full_cold_epoch_peak_qualified"] == false
            && receipt["ordinary_replay_authorized"] == false
            && receipt["runtime_promotion_authorized"] == false
            && receipt["canonical_sidecar_authorized"] == false
            && receipt["publication_authorized"] == false
    } else if shrink_root_203 {
        shrink_root203::launch_matches(claim, receipt)
    } else if root_prefix_203 {
        claim.epoch == 203
            && claim
                .unit
                .starts_with("horizon-qualify-203-root-prefix-resource-")
            && claim.unit.ends_with(".service")
            && claim.scratch_path.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
            && claim
                .scratch_path
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("root-prefix-resource-203-"))
            && receipt["epoch"] == 203
            && receipt["private_run_root"].as_str() == claim.scratch_path.to_str()
            && receipt["snapshot_slot"] == 87_695_515u64
            && receipt["snapshot_sha256"]
                == "e45584858d0c825f095a43ff5e5909e62a68d197d39c042a76727454525228c4"
            && receipt["worker_sha256"]
                == "3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a"
            && receipt["node_sha256"]
                == "025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d"
            && receipt["runner_sha256"]
                == "dee8959e8436ebd856b5b8d7e18f06464377b26fadb3a7a9f09ab158f9fd4a4e"
            && receipt["runtime"] == "solana-v1.6.16"
            && receipt["runtime_semantics_changed"] == false
            && receipt["solana_rayon_threads"] == 16
            && receipt["output_slot_start"] == 87_696_000u64
            && receipt["output_slot_count"] == 431_581u64
            && receipt["terminal_root_slot"] == 88_127_580u64
            && receipt["natural_parent_completion_required"] == true
            && receipt["maximum_terminal_scratch_bytes"] == 768u64 << 30
            && receipt["maximum_runtime_seconds"] == 259200u64
            && receipt["root_prefix_resource_attempt_authorized"] == true
            && receipt["canonical_prefix_independently_qualified"] == false
            && receipt["full_cold_epoch_peak_qualified"] == false
            && receipt["ordinary_replay_authorized"] == false
            && receipt["runtime_promotion_authorized"] == false
            && receipt["canonical_sidecar_authorized"] == false
            && receipt["publication_authorized"] == false
    } else if bounded_224 {
        claim.epoch == 224
            && claim
                .unit
                .starts_with("horizon-qualify-224-bounded-resource-")
            && claim.unit.ends_with(".service")
            && claim.scratch_path.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
            && claim
                .scratch_path
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("bounded-resource-224-"))
            && receipt["epoch"] == 224
            && receipt["private_run_root"].as_str() == claim.scratch_path.to_str()
            && receipt["snapshot_slot"] == 96_767_522u64
            && receipt["snapshot_sha256"]
                == "dc7f2ac03813bc609629885af82222ac5af070cc6187b7bce08e10944fd214e1"
            && receipt["worker_sha256"]
                == "f26fb8598aef4091356be31a0ee322c2e428609f201390cce26ec60df9c62c45"
            && receipt["node_sha256"]
                == "bcb76f90515465ee3b19486a18da907d15d4a3fbe310d66e0c3912a5daa4e257"
            && receipt["runner_sha256"]
                == "eb2399944540f0a0cd7aadffe350047ab75dd946bc963370fa5c486689a6e381"
            && receipt["runtime"] == "solana-v1.6.25"
            && receipt["runtime_semantics_changed"] == true
            && receipt["solana_rayon_threads"] == 16
            && receipt["target_slot"] == 96_800_000u64
            && receipt["terminal_root_slot"] == 97_631_459u64
            && receipt["maximum_terminal_scratch_bytes"] == 448u64 << 30
            && receipt["maximum_runtime_seconds"] == 259200u64
            && receipt["bounded_replay_authorized"] == true
            && receipt["ordinary_replay_authorized"] == false
            && receipt["full_cold_epoch_peak_qualified"] == false
            && receipt["canonical_prefix_qualified"] == false
            && receipt["runtime_promotion_authorized"] == false
            && receipt["canonical_sidecar_authorized"] == false
            && receipt["publication_authorized"] == false
    } else if shrink_budget_203 {
        shrink_budget_203_launch_matches(claim, receipt)
    } else if bounded_203 {
        claim.epoch == 203
            && claim
                .unit
                .starts_with("horizon-qualify-203-bounded-resource-")
            && claim.unit.ends_with(".service")
            && receipt["epoch"] == 203
            && receipt["private_run_root"].as_str() == claim.scratch_path.to_str()
            && receipt["snapshot_slot"] == 87_695_515u64
            && receipt["snapshot_sha256"]
                == "e45584858d0c825f095a43ff5e5909e62a68d197d39c042a76727454525228c4"
            && receipt["worker_sha256"]
                == "3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a"
            && epoch203_resource_runner_matches(claim, receipt)
            && receipt["runtime"] == "solana-v1.6.16"
            && receipt["runtime_semantics_changed"] == false
            && receipt["target_slot"] == 87_720_000u64
            && receipt["terminal_root_slot"] == 88_127_580u64
            && receipt["bounded_replay_authorized"] == true
            && receipt["ordinary_replay_authorized"] == false
            && receipt["full_cold_epoch_peak_qualified"] == false
            && receipt["canonical_prefix_qualified"] == false
            && receipt["runtime_promotion_authorized"] == false
            && receipt["canonical_sidecar_authorized"] == false
            && receipt["publication_authorized"] == false
    } else if shrink_budget_225 {
        shrink_budget225::launch_matches(claim, receipt)
    } else if bounded_resource || bounded_v1625 {
        claim.epoch == 225
            && claim
                .unit
                .starts_with("horizon-qualify-225-bounded-resource-")
            && claim.unit.ends_with(".service")
            && receipt["epoch"] == 225
            && receipt["private_run_root"].as_str() == claim.scratch_path.to_str()
            && receipt["snapshot_slot"] == 97_199_617u64
            && receipt["snapshot_sha256"]
                == "094d3b28c39403580fbac083cdad67cc008b255dd375d611217103750d0f412d"
            && if bounded_v1625 {
                claim
                    .unit
                    .starts_with("horizon-qualify-225-bounded-resource-v1625-")
                    && receipt["worker_sha256"]
                        == "74f805991023434932080b6db20385d36ec26d8a1dd9bbd7a33848099145859a"
                    && receipt["comparison_runtime"] == "solana-v1.6.25"
                    && receipt["runtime_semantics_changed"] == true
                    && receipt["worker_entry_end_exclusive"] == 97_202_600u64
                    && receipt["runtime_promotion_authorized"] == false
            } else {
                receipt["worker_sha256"]
                    == "f39140b9a9659e7c6e8207076a2d0c560a6b69df42cc92e19a421cf46c2b761c"
            }
            && receipt["target_slot"] == 97_202_500u64
            && receipt["terminal_root_slot"] == 97_631_459u64
            && receipt["bounded_replay_authorized"] == true
            && receipt["ordinary_replay_authorized"] == false
            && receipt["full_cold_epoch_peak_qualified"] == false
            && receipt["canonical_sidecar_authorized"] == false
            && receipt["publication_authorized"] == false
    } else {
        claim
            .unit
            .starts_with(&format!("horizon-perf-epoch{}-", claim.epoch))
            && claim.unit.contains('@')
    };
    ensure!(
        scope_valid && claim.scratch_path.is_absolute(),
        "diagnostic scope or scratch binding is invalid"
    );
    let matching: Vec<_> = receipt["evidence"]["units"]
        .as_array()
        .context("launch omits units")?
        .iter()
        .filter(|unit| unit["unit"] == claim.unit)
        .collect();
    ensure!(
        matching.len() == 1
            && matching[0]["invocation_id"] == claim.invocation_id
            && claim.invocation_id.len() == 32
            && claim
                .invocation_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && matching[0]["restarts"] == 0
            && matching[0]["load_state"] == "loaded"
            && matching[0]["result"] == "success"
            && matching[0]["main_pid"].as_u64().is_some_and(|pid| pid > 0)
            && matching[0]["active_state"] == "active"
            && matching[0]["sub_state"] == "running",
        "diagnostic launch identity mismatch"
    );
    Ok(())
}

fn epoch203_resource_runner_matches(claim: &DiagnosticClaim, receipt: &Value) -> bool {
    // A candidate cannot borrow the baseline schema or runner receipt even
    // when its namespace shares the historical bounded-resource prefix.
    if shrink_budget_203_namespace(claim) {
        return false;
    }
    match receipt["runner_sha256"].as_str() {
        Some("bc9a75b420210a93b6ab65d28bd82d1fe2748c95541394bfae2e0f0f5153bf12") => {
            !claim
                .unit
                .starts_with("horizon-qualify-203-bounded-resource-r1-")
                && receipt.get("solana_rayon_threads").is_none_or(|v| v == 16)
        }
        Some("c041979fa0be26f6a35cb7063e962a666e71ddde74b1f680c53c210a0f7b1722") => {
            claim
                .unit
                .starts_with("horizon-qualify-203-bounded-resource-r1-")
                && receipt["solana_rayon_threads"] == 1
        }
        _ => false,
    }
}

fn shrink_budget_203_launch_matches(claim: &DiagnosticClaim, receipt: &Value) -> bool {
    shrink_budget_203_namespace(claim)
        && !claim
            .unit
            .starts_with("horizon-qualify-203-bounded-resource-shrink-budget-r1-")
        && claim.unit.ends_with(".service")
        && claim.scratch_path.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
        && claim
            .scratch_path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| {
                s.starts_with("bounded-resource-203-shrink-budget-")
                    && !s.starts_with("bounded-resource-203-shrink-budget-r1-")
            })
        && receipt["epoch"] == 203
        && receipt["private_run_root"].as_str() == claim.scratch_path.to_str()
        && receipt["snapshot_slot"] == 87_695_515u64
        && receipt["snapshot_sha256"]
            == "e45584858d0c825f095a43ff5e5909e62a68d197d39c042a76727454525228c4"
        && receipt["worker_sha256"]
            == "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc"
        && receipt["node_sha256"]
            == "025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d"
        && receipt["runner_sha256"]
            == "d7b3f0c72f091426ce5679ebb237d7015cd054c2fa6953f811779a25736a2760"
        && receipt["runtime"] == "solana-v1.6.16"
        && receipt["runtime_semantics_changed"] == false
        && receipt["storage_maintenance_changed"] == true
        && receipt["upstream_shrink_budget_cap"] == true
        && receipt["solana_rayon_threads"] == 16
        && receipt["target_slot"] == 87_720_000u64
        && receipt["terminal_root_slot"] == 88_127_580u64
        && receipt["maximum_scratch_bytes"] == 256u64 << 30
        && receipt["maximum_runtime_seconds"] == 21_600u64
        && receipt["experimental_envelope_bytes"] == 416u64 << 30
        && receipt["bounded_replay_authorized"] == true
        && receipt["ordinary_replay_authorized"] == false
        && receipt["canonical_prefix_qualified"] == false
        && receipt["full_cold_epoch_peak_qualified"] == false
        && receipt["runtime_promotion_authorized"] == false
        && receipt["canonical_sidecar_authorized"] == false
        && receipt["publication_authorized"] == false
}

fn transitions(
    previous: &Value,
    current_units: &BTreeMap<String, Value>,
    epochs: &[Value],
) -> Vec<Value> {
    let mut changes = Vec::new();
    let prior_units = previous["unit_census"].as_object();
    let mut names: BTreeSet<_> = current_units.keys().cloned().collect();
    if let Some(units) = prior_units {
        names.extend(units.keys().cloned());
    }
    for name in names {
        let before = prior_units
            .and_then(|units| units.get(&name))
            .unwrap_or(&Value::Null);
        let after = current_units.get(&name).unwrap_or(&Value::Null);
        if before != after {
            changes
                .push(json!({"kind":"unit-transition","unit":name,"before":before,"after":after}));
        }
    }
    if let Some(prior_epochs) = previous["epochs"].as_array() {
        for epoch in epochs {
            if let Some(before) = prior_epochs
                .iter()
                .find(|prior| prior["epoch"] == epoch["epoch"])
                && before["state"] != epoch["state"]
            {
                changes.push(json!({"kind":"epoch-state-transition","epoch":epoch["epoch"],"before":before["state"],"after":epoch["state"]}));
            }
        }
    }
    changes
}

fn bound_json(bound: &BoundFile) -> Result<Value> {
    ensure!(bound.path.is_absolute(), "evidence path must be absolute");
    let bytes = read_stable_bounded(&bound.path, 16 * 1024 * 1024, "fleet evidence")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == bound.sha256,
        "fleet evidence digest mismatch: {}",
        bound.path.display()
    );
    Ok(serde_json::from_slice(&bytes)?)
}

pub(super) fn utc_seconds(value: &str) -> Result<u64> {
    ensure!(
        is_canonical_utc(value),
        "invalid fleet sample UTC timestamp"
    );
    let number = |start, end| value[start..end].parse::<i32>();
    let mut time: libc::tm = unsafe { std::mem::zeroed() };
    time.tm_year = number(0, 4)? - 1900;
    time.tm_mon = number(5, 7)? - 1;
    time.tm_mday = number(8, 10)?;
    time.tm_hour = number(11, 13)?;
    time.tm_min = number(14, 16)?;
    time.tm_sec = number(17, 19)?;
    let fields = (
        time.tm_year,
        time.tm_mon,
        time.tm_mday,
        time.tm_hour,
        time.tm_min,
        time.tm_sec,
    );
    let seconds = unsafe { libc::timegm(&mut time) };
    ensure!(
        fields
            == (
                time.tm_year,
                time.tm_mon,
                time.tm_mday,
                time.tm_hour,
                time.tm_min,
                time.tm_sec
            ),
        "nonexistent sample date"
    );
    Ok(u64::try_from(seconds)?)
}

pub(super) fn unit(name: &str) -> Result<Value> {
    ensure!(
        name.ends_with(".service")
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b)),
        "invalid fleet unit name"
    );
    let result = ProcessCommand::new("systemctl").args([
        "show", name, "--no-pager", "--property=Id,LoadState,Type,ActiveState,SubState,InvocationID,NRestarts,Result,ExecMainStatus,ExecStart,ControlGroup,MainPID",
    ]).output()?;
    let mut values = serde_json::Map::new();
    for line in std::str::from_utf8(&result.stdout)?.lines() {
        let (key, value) = line
            .split_once('=')
            .context("malformed systemctl property")?;
        ensure!(
            values
                .insert(key.into(), Value::String(value.into()))
                .is_none(),
            "duplicate unit property"
        );
    }
    ensure!(
        values.get("Id").and_then(Value::as_str) == Some(name),
        "unit identity mismatch"
    );
    ensure!(
        result.status.success()
            || (values.get("LoadState").and_then(Value::as_str) == Some("not-found")
                && values.get("ActiveState").and_then(Value::as_str) == Some("inactive")
                && values.get("SubState").and_then(Value::as_str) == Some("dead")),
        "fleet unit observation failed for {name}"
    );
    Ok(Value::Object(values))
}

fn ram_entry_owner(name: &str) -> bool {
    name.starts_with("horizon-203-ram-resource-")
}

// Singleton producers use a separate namespace from horizon-qualify. Discover
// every assigned singleton, including profiles this helper cannot yet interpret,
// so an old reader must reject an omitted new owner rather than hide its growth.
fn assigned_singleton_owner(name: &str, first_epoch: u64, last_epoch: u64) -> bool {
    name.strip_prefix("horizon-singleton-")
        .and_then(|tail| tail.split_once('-'))
        .and_then(|(epoch, _)| epoch.parse::<u64>().ok())
        .is_some_and(|epoch| (first_epoch..=last_epoch).contains(&epoch))
}

pub(super) fn census(
    names: &BTreeSet<String>,
    first_epoch: u64,
    last_epoch: u64,
) -> Result<BTreeMap<String, Value>> {
    let mut result = BTreeMap::new();
    for name in names {
        result.insert(name.clone(), unit(name)?);
    }
    // A newly launched producer outside the observer census invalidates the cycle.
    let units = ProcessCommand::new("systemctl")
        .args([
            "list-units",
            "--type=service",
            "--state=running,activating,deactivating",
            "--output=json",
            "--no-pager",
        ])
        .output()?;
    ensure!(units.status.success(), "fleet discovery failed");
    let discovered: Vec<Value> = serde_json::from_slice(&units.stdout)?;
    for value in discovered {
        let name = value["unit"]
            .as_str()
            .context("discovered unit omits name")?;
        if name == EPOCH154_SAFETY_GUARD {
            // This periodic oneshot can be active between census passes. It
            // never launches replay and must not be mistaken for a new lane.
            // Do not generalize this to a name-suffix exemption: authenticate
            // its complete static deployment and exact non-launching command.
            validate_epoch154_safety_guard(&result)?;
            continue;
        }
        let assigned_diagnostic = name.contains('@')
            && name
                .strip_prefix("horizon-perf-epoch")
                .and_then(|tail| tail.split('-').next())
                .and_then(|epoch| epoch.parse::<u64>().ok())
                .is_some_and(|epoch| (first_epoch..=last_epoch).contains(&epoch));
        let assigned_pipeline = [
            "horizon-publish-",
            "horizon-upload-",
            "horizon-full-verify-",
            "horizon-plugin-verify-",
            "horizon-independent-full-read-",
        ]
        .iter()
        .any(|prefix| {
            name.strip_prefix(prefix)
                .and_then(|tail| tail.split('-').next())
                .and_then(|epoch| epoch.parse::<u64>().ok())
                .is_some_and(|epoch| (first_epoch..=last_epoch).contains(&epoch))
        });
        if name.starts_with("jetstreamer-root-sweep-")
            || name.starts_with("horizon-controller-")
            || name.starts_with("horizon-qualify-")
            || assigned_singleton_owner(name, first_epoch, last_epoch)
            || original_capped204205::repair_unit(name, first_epoch, last_epoch)
            // Private RAM supervisors are entry owners too. Until the explicit
            // auxiliary claim contract is integrated, fail closed rather than
            // silently omit one from the complete campaign census.
            || ram_entry_owner(name)
            || [204, 205].into_iter().any(|epoch| (first_epoch..=last_epoch).contains(&epoch)
                && name.starts_with(&format!("horizon-guard-{epoch}-capped-continuation-")))
            || assigned_diagnostic
            || assigned_pipeline
            || ((first_epoch..=last_epoch).contains(&141) && (native141::unit_name(name) || original141::unit_name(name) || original141_trace::unit_name(name) || original141_freeze::unit_name(name) || original141_vote_prefix::unit_name(name) || original141_capped::unit_name(name)))
            || ((first_epoch..=last_epoch).contains(&141) && census141_poh::unit_name(name))
            || ((first_epoch..=last_epoch).contains(&144) && private144_scan::unit_name(name))
            || ((first_epoch..=last_epoch).contains(&223) && demotion223_status::discovered(name))
            || ((first_epoch..=last_epoch).contains(&223) && name == tail223_scan::UNIT)
            || ((first_epoch..=last_epoch).contains(&210) && native210::unit_name(name))
            || ((first_epoch..=last_epoch).contains(&227) && native227_v1625::unit_name(name))
        {
            ensure!(
                names.contains(name),
                "unbound live producer {name}; rebuild fleet plan and observer census"
            );
        }
    }
    Ok(result)
}

const EPOCH154_SAFETY_GUARD: &str =
    "horizon-qualify-epoch154-rayon10-growth-20261019-v1-guard.service";
const EPOCH154_GUARDED_PRODUCER: &str =
    "horizon-qualify-epoch154-rayon10-growth-20261019-v1.service";
const EPOCH154_GUARD_BINARY: &str = "/usr/local/lib/jetstreamer/horizon-standalone-guard-target-handoff-20261019-v2/jetstreamer-horizon-standalone-guard";
const EPOCH154_GUARD_BINARY_SHA: &str =
    "eca429932ffe9afe71aecba815ab301db46bdddbaf24b4c44af8c88bb74a6194";
const EPOCH154_GUARD_PLAN: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch154-growth-bound-guard-20261020-v1/guard-plan.json";
const EPOCH154_GUARD_PLAN_SHA: &str =
    "579dccb32a16c2884218cbaa5c2914f0b7b4340d8435bf8416ce083bb36e4bc5";
const EPOCH154_GUARD_FRAGMENT: &str =
    "/etc/systemd/system/horizon-qualify-epoch154-rayon10-growth-20261019-v1-guard.service";

fn validate_epoch154_guard_properties(properties: &Value) -> Result<()> {
    for (key, expected) in [
        ("Id", EPOCH154_SAFETY_GUARD),
        ("LoadState", "loaded"),
        ("Type", "oneshot"),
        ("User", "root"),
        ("Group", "root"),
        ("FragmentPath", EPOCH154_GUARD_FRAGMENT),
        ("DropInPaths", ""),
        ("Environment", ""),
        ("EnvironmentFiles", ""),
        ("PassEnvironment", ""),
        ("RootDirectory", ""),
        ("RootImage", ""),
        ("ExecStartPre", ""),
        ("ExecStartPost", ""),
        ("ExecCondition", ""),
        ("ExecStop", ""),
        ("ExecStopPost", ""),
        ("ExecReload", ""),
    ] {
        ensure!(
            properties[key] == expected,
            "safety guard property {key} differs"
        );
    }
    let command = properties["ExecStart"]
        .as_str()
        .context("guard command missing")?;
    let prefix = format!(
        "{{ path={EPOCH154_GUARD_BINARY} ; argv[]={EPOCH154_GUARD_BINARY} {EPOCH154_GUARD_PLAN} --plan-sha256 {EPOCH154_GUARD_PLAN_SHA} --self-sha256 {EPOCH154_GUARD_BINARY_SHA} ; ignore_errors=no ;"
    );
    ensure!(
        command.starts_with(&prefix)
            && command.ends_with(" }")
            && command.matches("{ path=").count() == 1
            && !command.contains('\n'),
        "safety guard has an unexpected or additional command"
    );
    Ok(())
}

fn pinned_guard_member(path: &str, digest: &str) -> Result<()> {
    let path = Path::new(path);
    ensure!(
        path.canonicalize()? == path,
        "guard member path is not exact"
    );
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o022 == 0,
        "guard member identity or mode differs"
    );
    let bytes = read_stable_bounded(path, 32 * 1024 * 1024, "pinned safety guard member")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == digest,
        "guard member SHA-256 mismatch"
    );
    Ok(())
}

fn validate_empty_guard_array(bytes: &[u8], signature: &str) -> Result<()> {
    let value: Value = serde_json::from_slice(bytes)?;
    ensure!(
        value["type"] == signature && value["data"].as_array().is_some_and(Vec::is_empty),
        "safety guard has a nonempty or unreadable DBus command/environment array"
    );
    Ok(())
}

fn validate_epoch154_safety_guard(current: &BTreeMap<String, Value>) -> Result<()> {
    let producer = current
        .get(EPOCH154_GUARDED_PRODUCER)
        .context("guard's producer is not in bound fleet")?;
    ensure!(
        producer["InvocationID"] == "85214d064b014c2e981bbfa8709f34db"
            && producer["NRestarts"] == "0"
            && producer["ActiveState"] == "active"
            && producer["SubState"] == "running",
        "guard parent is not the exact bound live producer"
    );
    let output = ProcessCommand::new("/usr/bin/systemctl").args(["show", EPOCH154_SAFETY_GUARD, "--all", "--no-pager", "--property=Id,LoadState,Type,User,Group,FragmentPath,DropInPaths,ExecStart,ExecStartPre,ExecStartPost,ExecCondition,ExecStop,ExecStopPost,ExecReload,Environment,EnvironmentFiles,PassEnvironment,RootDirectory,RootImage"]).output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 65536,
        "cannot inspect pinned safety guard"
    );
    let mut properties = serde_json::Map::new();
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let (key, value) = line.split_once('=').context("invalid guard property")?;
        ensure!(
            properties.insert(key.to_string(), json!(value)).is_none(),
            "duplicate guard property"
        );
    }
    // systemctl's custom printers omit empty command and EnvironmentFiles
    // arrays even with --all. Missing text is not proof of absence: require
    // exact empty typed DBus arrays before normalizing those fields.
    for (property, signature) in [
        ("EnvironmentFiles", "a(sb)"),
        ("ExecStartPre", "a(sasbttttuii)"),
        ("ExecStartPost", "a(sasbttttuii)"),
        ("ExecCondition", "a(sasbttttuii)"),
        ("ExecStop", "a(sasbttttuii)"),
        ("ExecStopPost", "a(sasbttttuii)"),
        ("ExecReload", "a(sasbttttuii)"),
    ] {
        let output = ProcessCommand::new("/usr/bin/busctl").args(["--system", "--json=short", "--timeout=10s", "get-property", "org.freedesktop.systemd1", "/org/freedesktop/systemd1/unit/horizon_2dqualify_2depoch154_2drayon10_2dgrowth_2d20261019_2dv1_2dguard_2eservice", "org.freedesktop.systemd1.Service", property]).output()?;
        ensure!(
            output.status.success() && output.stdout.len() <= 65536,
            "cannot inspect safety guard DBus array"
        );
        validate_empty_guard_array(&output.stdout, signature)?;
        ensure!(
            properties.get(property).is_none_or(|v| v == ""),
            "guard property contradicts DBus absence"
        );
        properties.insert(property.to_string(), json!(""));
    }
    validate_epoch154_guard_properties(&Value::Object(properties))?;
    for (path, sha) in [
        (
            EPOCH154_GUARD_FRAGMENT,
            "e60da7187a75af6aa11917836f0444a4c011ea43260b96eac56dee7acdf7ee4c",
        ),
        (EPOCH154_GUARD_BINARY, EPOCH154_GUARD_BINARY_SHA),
        (EPOCH154_GUARD_PLAN, EPOCH154_GUARD_PLAN_SHA),
    ] {
        pinned_guard_member(path, sha)?;
    }
    Ok(())
}

fn live_binding(observed: &Value, current: &Value) -> bool {
    current["ActiveState"] == "active"
        && current["SubState"] == "running"
        && current["NRestarts"] == "0"
        && observed["invocation_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty() && current["InvocationID"] == id)
        && observed["restarts"] == 0
}

fn status_matches(
    status: &EpochStatus,
    etag: &str,
    publication: &StatusPublicationReceipt,
    controller: &Value,
    producer: &Value,
) -> bool {
    publication.status == *status
        && publication.object_etag == etag
        && publication.authenticated_readback
        && controller["InvocationID"] == publication.controller_invocation_id
        && producer["InvocationID"] == publication.producer_invocation_id
        && controller["ActiveState"] == "active"
        && producer["ActiveState"] == "active"
        && controller["NRestarts"] == "0"
        && producer["NRestarts"] == "0"
}

fn production_status_binding_matches(owner_matches: bool, state: &str) -> bool {
    // A live private qualification can own an old status receipt without
    // claiming an archive that is eligible for production publication.
    // This distinction is display evidence only, never deletion authority.
    owner_matches && matches!(state, "live-replay" | "post-replay-pipeline")
}

fn validate_output_destination(path: &Path) -> Result<&Path> {
    ensure!(path.is_absolute(), "fleet output must be absolute");
    let parent = path.parent().context("fleet output has no parent")?;
    let meta = fs::symlink_metadata(parent)?;
    ensure!(
        meta.is_dir()
            && parent.canonicalize()? == parent
            && meta.uid() == 0
            && meta.mode() & 0o077 == 0,
        "fleet output directory must be root-owned and owner-only"
    );
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => anyhow::bail!("fleet output already exists"),
        Err(error) => return Err(error.into()),
    }
    Ok(parent)
}

pub(super) fn persist(path: &Path, value: &Value) -> Result<()> {
    // Repeat the preflight at publication; no-clobber rename remains the final
    // race-safe boundary if another writer appears after this check.
    let parent = validate_output_destination(path)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(temporary.as_file_mut(), value)?;
    temporary.as_file_mut().write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| anyhow!("fleet output publication failed: {error}"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn validate_previous_fleet(previous: &Value, first: u64, last: u64, sample: &str) -> Result<()> {
    ensure!(
        previous["schema"] == SCHEMA,
        "invalid previous fleet schema"
    );
    // The original sealed ledgers used an explicit assignment object. Preserve
    // their exact digest as the predecessor; never rewrite them into a new shape.
    let (old_first, old_last, old_sample) = if previous.get("assigned_range").is_some() {
        ensure!(
            previous.get("first_epoch").is_none()
                && previous.get("last_epoch").is_none()
                && previous.get("sampled_at_utc").is_none(),
            "ambiguous previous fleet shape"
        );
        (
            previous["assigned_range"]["first_epoch"].as_u64(),
            previous["assigned_range"]["last_epoch"].as_u64(),
            previous["production_observation_sampled_at_utc"].as_str(),
        )
    } else {
        (
            previous["first_epoch"].as_u64(),
            previous["last_epoch"].as_u64(),
            previous["sampled_at_utc"].as_str(),
        )
    };
    ensure!(
        old_first == Some(first) && old_last == Some(last),
        "previous fleet has different assignment"
    );
    let old_sample = old_sample.context("previous fleet omits sample timestamp")?;
    ensure!(
        utc_seconds(old_sample)? < utc_seconds(sample)?,
        "fleet sample must advance"
    );
    Ok(())
}

pub(super) async fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 5 && args[3] == "--plan-sha256",
        "usage: jetstreamer-r2 fleet-reconcile PLAN --plan-sha256 HEX"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "fleet reconciliation requires root"
    );
    let plan_bound = BoundFile {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let plan_metadata = fs::symlink_metadata(&plan_bound.path)?;
    ensure!(
        plan_metadata.is_file() && plan_metadata.uid() == 0 && plan_metadata.mode() & 0o022 == 0,
        "fleet plan must be a root-owned non-writable regular file"
    );
    let plan: Plan = serde_json::from_value(bound_json(&plan_bound)?)?;
    // Fail before any service census or remote inventory when the final receipt
    // cannot be published. In particular, a missing parent must not spend a
    // complete campaign inventory before discovering this local setup error.
    validate_output_destination(&plan.output)?;
    ensure!(
        plan.schema == "jetstreamer-horizon-campaign-fleet-plan-v1",
        "unsupported fleet plan"
    );
    ensure!(
        plan.first_epoch <= plan.last_epoch && plan.last_epoch - plan.first_epoch <= 1000,
        "invalid campaign range"
    );
    ensure!(
        plan.gates
            .keys()
            .copied()
            .eq(plan.first_epoch..=plan.last_epoch),
        "fleet gates must cover every assigned epoch exactly"
    );
    for gate in plan.gates.values() {
        ensure!(
            matches!(
                gate.state.as_str(),
                "post-replay-pipeline"
                    | "staged-admissible"
                    | "blocked-qualification"
                    | "failed-needs-repair"
                    | "not-yet-staged"
            ),
            "gate cannot declare remote or replay completion"
        );
        ensure!(
            !gate.next_action.trim().is_empty(),
            "gate requires next action"
        );
        ensure!(
            gate.state == "not-yet-staged" || !gate.evidence.is_empty(),
            "gate requires bound evidence"
        );
        for bound in &gate.evidence {
            bound_json(bound)?;
        }
    }
    let observer = bound_json(&plan.observer)?;
    let observer_bytes = read_stable_bounded(
        &plan.observer.path,
        MAX_OBSERVER_RECEIPT_BYTES,
        "fleet observer",
    )?;
    ensure!(
        hex_lower(&Sha256::digest(&observer_bytes)) == plan.observer.sha256,
        "observer changed after validation"
    );
    ensure!(
        observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2",
        "fleet requires v2 observer"
    );
    let sample = observer["recorded_at_utc"]
        .as_str()
        .context("missing sample timestamp")?;
    ensure!(
        is_canonical_utc(sample),
        "invalid observer sample timestamp"
    );
    let sample_seconds = utc_seconds(sample)?;
    let started_seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        sample_seconds <= started_seconds && started_seconds - sample_seconds <= 1800,
        "fleet requires an observer sample no older than 30 minutes"
    );
    let previous_fleet = if let Some(previous) = &plan.previous_fleet {
        let previous = bound_json(previous)?;
        if let Some(binding) = &plan.metadata_event {
            ensure!(
                plan.admission_transition_guard.is_none(),
                "metadata event cannot borrow replay admission"
            );
            let event = bound_json(binding)?;
            if event["schema"] == assembly204_recovery::EVENT_SCHEMA {
                assembly204_recovery::event_predecessor(
                    &previous,
                    &plan,
                    &plan_bound,
                    &event,
                    sample,
                    started_seconds,
                )?;
            } else if demotion223_status::event_schema(&event) {
                demotion223_status::event_predecessor(
                    &previous,
                    &plan,
                    &plan_bound,
                    &event,
                    sample,
                    started_seconds,
                )?;
            } else if event["schema"] == capped204205_work::EVENT_SCHEMA {
                capped204205_work::event_predecessor(
                    &previous,
                    &plan,
                    &plan_bound,
                    &event,
                    sample,
                    started_seconds,
                )?;
            } else if event["schema"] == warmup223::TERMINAL_SCHEMA
                || event["schema"] == warmup223::TERMINAL_SCHEMA_V2
            {
                warmup223::terminal_predecessor(&previous, &plan, &event, sample, started_seconds)?;
            } else if event["schema"] == "jetstreamer-private-warmup223-launch-v1" {
                warmup223::event_predecessor(&previous, &plan, &event, sample, started_seconds)?;
            } else if event["schema"]
                == "jetstreamer-private-epoch223-native-v1620-ram-snapshot-intent-v1"
            {
                cold223_scan::native20_event_predecessor(
                    &previous,
                    &plan,
                    &event,
                    sample,
                    started_seconds,
                )?;
            } else if event["schema"]
                == "jetstreamer-private-epoch223-native-v1620-terminal-event-v1"
            {
                cold223_scan::native20_terminal_predecessor(
                    &previous,
                    &plan,
                    &event,
                    sample,
                    started_seconds,
                )?;
            } else if event["schema"]
                == "jetstreamer-private-epoch227-native-input-terminal-event-v1"
            {
                singleton227_terminal::terminal_predecessor(
                    &previous,
                    &plan,
                    &event,
                    sample,
                    started_seconds,
                )?;
            } else if event["schema"] == full227_failure::SCHEMA {
                full227_failure::predecessor(&previous, &plan, &event, sample, started_seconds)?;
            } else if event["schema"] == full210_terminal::SCHEMA {
                full210_terminal::predecessor(&previous, &plan, &event, sample, started_seconds)?;
            } else if event["schema"] == native207_terminal::SCHEMA {
                native207_terminal::predecessor(&previous, &plan, &event, sample, started_seconds)?;
            } else if event["schema"] == native209_terminal::SCHEMA {
                native209_terminal::predecessor(&previous, &plan, &event, sample, started_seconds)?;
            } else if event["schema"] == native210_terminal::SCHEMA {
                native210_terminal::predecessor(&previous, &plan, &event, sample, started_seconds)?;
            } else if event["schema"] == native227_v1625_terminal::SCHEMA {
                native227_v1625_terminal::predecessor(
                    &previous,
                    &plan,
                    &event,
                    sample,
                    started_seconds,
                )?;
            } else if event["schema"] == canary227_terminal::SCHEMA {
                canary227_terminal::predecessor(&previous, &plan, &event, sample, started_seconds)?;
            } else if event["schema"] == canary227::SCHEMA {
                canary227_event::event_predecessor(
                    &previous,
                    &plan,
                    &event,
                    sample,
                    started_seconds,
                )?;
            } else if event["schema"] == native227_v1625::SCHEMA {
                native227_v1625_event::event_predecessor(
                    &previous,
                    &plan,
                    &event,
                    sample,
                    started_seconds,
                )?;
            } else if event["schema"] == native210::SCHEMA {
                native210_event::event_predecessor(
                    &previous,
                    &plan,
                    &event,
                    sample,
                    started_seconds,
                )?;
            } else if event["schema"] == native209::SCHEMA {
                native209_event::event_predecessor(
                    &previous,
                    &plan,
                    &event,
                    sample,
                    started_seconds,
                )?;
            } else if event["schema"] == native228_terminal::SCHEMA {
                native228_terminal::predecessor(&previous, &plan, &event, sample, started_seconds)?;
            } else if event["schema"] == native228::SCHEMA {
                native228_event::event_predecessor(
                    &previous,
                    &plan,
                    &event,
                    sample,
                    started_seconds,
                )?;
            } else if event["schema"] == native207::SCHEMA {
                native207_event::event_predecessor(
                    &previous,
                    &plan,
                    &event,
                    sample,
                    started_seconds,
                )?;
            } else if event["schema"] == "jetstreamer-private-epoch227-native-input-running-v1" {
                singleton227_event::event_predecessor(
                    &previous,
                    &plan,
                    &event,
                    sample,
                    started_seconds,
                )?;
            } else if event["schema"] == "jetstreamer-exact203-phase-handoff-v1" {
                publication203::event_predecessor(
                    &previous,
                    &plan,
                    &event,
                    sample,
                    started_seconds,
                )?;
            } else {
                publication144_history::event_predecessor(
                    &previous,
                    &plan,
                    &event,
                    sample,
                    started_seconds,
                )?;
            }
        } else if let Some(binding) = &plan.admission_transition_guard {
            let guard = bound_json(binding)?;
            let guard_plan = bound_json(&BoundFile {
                path: guard["plan"].as_str().context("guard plan missing")?.into(),
                sha256: guard["plan_sha256"]
                    .as_str()
                    .context("guard plan digest missing")?
                    .into(),
            })?;
            validate_same_sample_admission(
                &previous,
                &plan,
                sample,
                &guard,
                &guard_plan,
                started_seconds,
            )?;
        } else {
            validate_previous_fleet(&previous, plan.first_epoch, plan.last_epoch, sample)?;
        }
        previous
    } else {
        ensure!(
            plan.admission_transition_guard.is_none() && plan.metadata_event.is_none(),
            "admission transition requires predecessor"
        );
        Value::Null
    };
    let replays = observer["replays"]
        .as_array()
        .context("observer replays missing")?;
    let mut names: BTreeSet<_> = plan.tracked_units.iter().cloned().collect();
    for gate in plan.gates.values() {
        if let Some(stop) = &gate.reserve_stop {
            names.extend(stop.owners().into_iter().map(|(name, _)| name));
        }
    }
    for replay in replays {
        for kind in ["controller_after", "producer_after"] {
            names.insert(observer_string(replay, &[kind, "unit"])?.into());
        }
    }
    let mut diagnostic_units = BTreeSet::new();
    if let Some(claim) = &plan.assembly204_recovery {
        names.extend(assembly204_recovery::names(claim)?);
    }
    for claim in &plan.capped204205_work {
        names.extend(capped204205_work::names(claim)?);
    }
    for claim in &plan.diagnostics {
        if epoch136::namespace(claim) {
            ensure!(
                plan.gates
                    .get(&136)
                    .is_some_and(|g| g.state == "failed-needs-repair"),
                "private136 experiment cannot close or relabel original repair"
            );
        }
        if native141::namespace(claim)
            || census141_poh::namespace(claim)
            || original141::namespace(claim)
            || original141_trace::namespace(claim)
            || original141_freeze::namespace(claim)
            || original141_vote_prefix::namespace(claim)
            || original141_capped::namespace(claim)
        {
            ensure!(
                plan.gates[&141].state == "failed-needs-repair",
                "private native141 acquisition cannot close or relabel the failed repair"
            );
        }
        ensure!(
            (plan.first_epoch..=plan.last_epoch).contains(&claim.epoch)
                && diagnostic_units.insert(claim.unit.clone()),
            "duplicate or out-of-range diagnostic claim"
        );
        checked_diagnostic_launch(claim)?;
        for replay in replays {
            let replay_scope = parse_observer_claim_range(observer_string(replay, &["range"])?)?;
            ensure!(
                !diagnostic_scope(claim).any(|epoch| replay_scope.contains(&epoch)),
                "diagnostic overlaps an ordinary replay claim"
            );
        }
        names.insert(claim.unit.clone());
    }
    let auxiliary_launch = if let Some(claim) = &plan.epoch203_ram_auxiliary {
        ram_auxiliary::validate_scope(&plan, &observer, claim)?;
        let launch = ram_auxiliary::checked_launch(claim)?;
        names.insert(claim.unit.clone());
        Some(launch)
    } else {
        ensure!(
            observer
                .get("epoch203_ram_auxiliary")
                .is_none_or(|rows| rows.as_array().is_some_and(Vec::is_empty)),
            "observer auxiliary owner omitted from fleet plan"
        );
        None
    };
    let mut pipeline_units = BTreeMap::new();
    let mut pipeline_epoch_units = BTreeSet::new();
    if plan.admission_transition_guard.is_some() {
        // Preserve the exact claims from the hash-bound predecessor plan,
        // including completed delivery history. Requiring an empty vector
        // would silently force history to be dropped just to add a diagnostic.
        let previous_plan: Plan = serde_json::from_value(bound_json(&BoundFile {
            path: previous_fleet["plan"]
                .as_str()
                .context("predecessor plan missing")?
                .into(),
            sha256: previous_fleet["plan_sha256"]
                .as_str()
                .context("predecessor plan digest missing")?
                .into(),
        })?)?;
        preserve_pipeline_claims(&previous_plan, &plan)?;
    }
    for claim in &plan.pipeline_claims {
        validate_pipeline_claim(claim, plan.first_epoch, plan.last_epoch)?;
        if private144_scan::scope(&claim.phase, &claim.unit) {
            private144_scan::validate(claim)?;
        }
        if tail223_scan::scope(&claim.phase, &claim.unit) {
            tail223_scan::validate(claim)?;
        }
        if cold223_scan::scope(&claim.phase, &claim.unit) {
            cold223_scan::validate(claim)?;
        }
        if singleton227::native_scope(&claim.phase, &claim.unit) {
            singleton227::native_claim(claim)?;
        }
        if native207::scope(&claim.phase, &claim.unit) {
            native207::claim(claim)?;
        } else if native228::scope(&claim.phase, &claim.unit) {
            native228::claim(claim)?;
        } else if native209::scope(&claim.phase, &claim.unit) {
            native209::claim(claim)?;
        } else if native210::scope(&claim.phase, &claim.unit) {
            native210::claim(claim)?;
        } else if native227_v1625::scope(&claim.phase, &claim.unit) {
            native227_v1625::claim(claim)?;
        }
        if warmup223::scope(&claim.phase, &claim.unit) {
            warmup223::validate(claim)?;
        }
        ensure!(
            pipeline_epoch_units.insert((claim.epoch, claim.unit.clone()))
                && !diagnostic_units.contains(&claim.unit),
            "duplicate pipeline unit or diagnostic relabeling"
        );
        register_pipeline_claim(&mut pipeline_units, claim)?;
        if demotion223_status::scope(&claim.phase, &claim.unit) {
            names.extend(demotion223_status::claim_names(claim)?);
        }
        for evidence in &claim.evidence {
            bound_json(evidence)?;
        }
        names.insert(claim.unit.clone());
    }
    if plan.admission_transition_guard.is_some() {
        ensure!(
            previous_fleet["unit_census"]
                .as_object()
                .context("previous unit census missing")?
                .keys()
                .all(|name| names.contains(name)),
            "admission transition dropped a previously tracked unit"
        );
    }
    let before = census(&names, plan.first_epoch, plan.last_epoch)?;
    demotion223_status::event_census(&plan, &before)?;
    publication203::event_census(&plan, &before)?;
    warmup223::event_census(&plan, &before)?;
    warmup223::terminal_census(&plan, &before)?;
    cold223_scan::native20_event_census(&plan, &before)?;
    cold223_scan::native20_terminal_census(&plan, &before)?;
    singleton227_terminal::terminal_census(&plan, &before)?;
    full227_failure::census_check(&plan, &before)?;
    full210_terminal::census_check(&plan, &before)?;
    native207_terminal::census_check(&plan, &before)?;
    native209_terminal::census_check(&plan, &before)?;
    native210_terminal::census_check(&plan, &before)?;
    native227_v1625_terminal::census_check(&plan, &before)?;
    canary227_terminal::census_check(&plan, &before)?;
    native228_terminal::census_check(&plan, &before)?;
    if let Some(binding) = &plan.metadata_event
        && bound_json(binding)?["schema"] == canary227::SCHEMA
    {
        let previous = bound_json(
            plan.previous_fleet
                .as_ref()
                .context("227 canary prior fleet missing")?,
        )?;
        let claims = plan
            .diagnostics
            .iter()
            .filter(|c| canary227::namespace(c) && &c.launch_receipt == binding)
            .collect::<Vec<_>>();
        ensure!(
            claims.len() == 1,
            "227 canary event requires one exact new diagnostic"
        );
        canary227_event::event_census(&previous, &before, claims[0])?;
    }
    if let Some(binding) = &plan.metadata_event
        && bound_json(binding)?["schema"] == native209::SCHEMA
    {
        let previous = bound_json(
            plan.previous_fleet
                .as_ref()
                .context("native209 prior fleet missing")?,
        )?;
        let claims = plan
            .pipeline_claims
            .iter()
            .filter(|c| native209::scope(&c.phase, &c.unit) && c.evidence.first() == Some(binding))
            .collect::<Vec<_>>();
        ensure!(
            claims.len() == 1,
            "native209 event requires one bound new owner"
        );
        native209_event::event_census(&previous, &before, claims[0])?;
    }
    if let Some(binding) = &plan.metadata_event
        && bound_json(binding)?["schema"] == native210::SCHEMA
    {
        let previous = bound_json(
            plan.previous_fleet
                .as_ref()
                .context("native210 prior fleet missing")?,
        )?;
        let claims = plan
            .pipeline_claims
            .iter()
            .filter(|c| native210::scope(&c.phase, &c.unit) && c.evidence.first() == Some(binding))
            .collect::<Vec<_>>();
        ensure!(
            claims.len() == 1,
            "native210 event requires one bound new owner"
        );
        native210_event::event_census(&previous, &before, claims[0])?;
    }
    if let Some(binding) = &plan.metadata_event
        && bound_json(binding)?["schema"] == native227_v1625::SCHEMA
    {
        let previous = bound_json(
            plan.previous_fleet
                .as_ref()
                .context("native227-v1625 prior fleet missing")?,
        )?;
        let claims = plan
            .pipeline_claims
            .iter()
            .filter(|c| {
                native227_v1625::scope(&c.phase, &c.unit) && c.evidence.first() == Some(binding)
            })
            .collect::<Vec<_>>();
        ensure!(
            claims.len() == 1,
            "native227-v1625 event requires one bound new owner"
        );
        native227_v1625_event::event_census(&previous, &before, claims[0])?;
    }
    if let Some(binding) = &plan.metadata_event
        && bound_json(binding)?["schema"] == native228::SCHEMA
    {
        let previous = bound_json(
            plan.previous_fleet
                .as_ref()
                .context("native228 prior fleet missing")?,
        )?;
        let claims = plan
            .pipeline_claims
            .iter()
            .filter(|c| native228::scope(&c.phase, &c.unit) && c.evidence.first() == Some(binding))
            .collect::<Vec<_>>();
        ensure!(
            claims.len() == 1,
            "native228 event requires one bound new owner"
        );
        native228_event::event_census(&previous, &before, claims[0])?;
    }
    if let Some(binding) = &plan.metadata_event
        && bound_json(binding)?["schema"] == native207::SCHEMA
    {
        let previous = bound_json(
            plan.previous_fleet
                .as_ref()
                .context("native207 prior fleet missing")?,
        )?;
        let claims = plan
            .pipeline_claims
            .iter()
            .filter(|c| native207::scope(&c.phase, &c.unit) && c.evidence.first() == Some(binding))
            .collect::<Vec<_>>();
        ensure!(
            claims.len() == 1,
            "native207 event requires one bound new owner"
        );
        native207_event::event_census(&previous, &before, claims[0])?;
    }
    if let Some(binding) = &plan.metadata_event
        && bound_json(binding)?["schema"] == "jetstreamer-private-epoch227-native-input-running-v1"
    {
        let previous = bound_json(
            plan.previous_fleet
                .as_ref()
                .context("native227 prior fleet missing")?,
        )?;
        let claims = plan
            .pipeline_claims
            .iter()
            .filter(|c| {
                singleton227::native_scope(&c.phase, &c.unit) && c.evidence.first() == Some(binding)
            })
            .collect::<Vec<_>>();
        ensure!(
            claims.len() == 1,
            "native227 event requires exactly one bound new owner"
        );
        singleton227_event::event_census(&previous, &before, claims[0])?;
    }
    ram_auxiliary::validate_census(plan.epoch203_ram_auxiliary.as_ref(), &before)?;
    let mut terminal_replays = Vec::new();
    for (epoch, gate) in &plan.gates {
        if let Some(stop) = &gate.reserve_stop {
            ensure!(
                stop.epoch == *epoch
                    && matches!(
                        gate.state.as_str(),
                        "failed-needs-repair" | "blocked-qualification"
                    ),
                "reserve stop requires an exact blocked epoch gate"
            );
            let mut minimum_time = 0;
            for replay in replays {
                let range = parse_observer_claim_range(observer_string(replay, &["range"])?)?;
                if range.contains(epoch) {
                    ensure!(
                        range.len() == 1
                            && observer_string(replay, &["controller_after", "unit"])?
                                == stop.controller_unit
                            && observer_string(replay, &["controller_after", "invocation_id"])?
                                == stop.controller_invocation_id
                            && observer_string(replay, &["producer_after", "unit"])?
                                == stop.producer_unit
                            && observer_string(replay, &["producer_after", "invocation_id"])?
                                == stop.producer_invocation_id,
                        "reserve stop cannot discard another observer claim"
                    );
                    minimum_time = sample_seconds;
                }
            }
            stop.validate(&before, minimum_time, started_seconds)?;
            terminal_replays.push(serde_json::to_value(stop)?);
        }
    }
    let r2 = r2_config_from_env()?;
    let s3 = s3_client(&r2);
    let mut entries = Vec::new();
    let mut active = Vec::new();
    let mut diagnostics = Vec::new();
    let runtime157 = runtime157::observe(&plan, &observer, &before, sample)?;
    if let Some(entry) = &runtime157
        && entry["live"] == true
    {
        active.push(entry.clone());
    }
    let private144 = private144::observe(&plan, &observer, &before, sample)?;
    if let Some(entry) = &private144
        && entry["live"] == true
        && !diagnostic_owns_observation(&plan.diagnostics, entry)
    {
        // A captured diagnostic below owns the same physical invocation. Keep
        // its resource observation in observer_diagnostics, not a second job.
        active.push(entry.clone());
    }
    let mut live_diagnostic_epochs = BTreeSet::new();
    let mut pipelines = Vec::new();
    let mut live_pipeline_stages = BTreeSet::new();
    for claim in &plan.pipeline_claims {
        let current = &before[&claim.unit];
        let (is_active, finalization) = if (191..=194).contains(&claim.epoch) {
            // A same-cutoff native custody check can race a genuine importer
            // or verifier handoff. Preserve the failure in this durable fleet
            // without suppressing seven ordinary lanes/private141/successors.
            let result = (|| -> Result<(bool, Value)> {
                let live = pipeline_live(claim, current)?;
                if !live {
                    return Ok((false, Value::Null));
                }
                let mut proofs = Vec::new();
                for b in &claim.evidence {
                    let value = bound_json(b)?;
                    if let Some(proof) = super::cohort191_delivery::fleet_proof(
                        claim.epoch,
                        &claim.phase,
                        &claim.unit,
                        &claim.invocation_id,
                        &value,
                        &before,
                        sample_seconds,
                    )? {
                        proofs.push(proof);
                    }
                }
                ensure!(
                    proofs.len() == 1,
                    "191 delivery claim needs exactly one native custody event"
                );
                Ok((true, proofs.remove(0)))
            })();
            match result {
                Ok(v) => v,
                Err(e) => (
                    false,
                    json!({"schema":"jetstreamer-cohort191-status-incident-v2",
                    "epoch":claim.epoch,"sampled_at_utc":sample,"error":format!("{e:#}"),
                    "actual_owner_may_still_be_active":true,"inactivity_not_proven":true,
                    "status_deletion_authorized":false,"ordinary_lanes_continue":true,
                    "publication_authorized":false,"r2_mutations":false}),
                ),
            }
        } else {
            let live = pipeline_live(claim, current)?;
            let proof = if live && claim.phase == "producer-finalization" {
                super::cohort_finalization::observe(current, sample_seconds)?
            } else if live && claim.phase == "controller-import-handoff" {
                super::cohort_finalization::observe_handoff(current, sample_seconds)?
            } else {
                Value::Null
            };
            (live, proof)
        };
        let private_scan = demotion223_status::scope(&claim.phase, &claim.unit)
            || super::repair141::scope(&claim.phase, &claim.unit)
            || private144_scan::scope(&claim.phase, &claim.unit)
            || native209::scope(&claim.phase, &claim.unit)
            || native210::scope(&claim.phase, &claim.unit)
            || native227_v1625::scope(&claim.phase, &claim.unit)
            || native228::scope(&claim.phase, &claim.unit)
            || native207::scope(&claim.phase, &claim.unit)
            || tail223_scan::scope(&claim.phase, &claim.unit)
            || cold223_scan::scope(&claim.phase, &claim.unit)
            || singleton227::native_scope(&claim.phase, &claim.unit)
            || warmup223::scope(&claim.phase, &claim.unit);
        let mut entry = json!({"epoch":claim.epoch,"phase":claim.phase,"unit":current,
            "finalization_evidence":finalization,
            "live":is_active,"expected_invocation_id":claim.invocation_id,
            "evidence":claim.evidence.iter().map(|e|json!({"path":e.path,"sha256":e.sha256})).collect::<Vec<_>>(),
            "sampled_at_utc":sample,"ordinary_replay_claim":false,
            "current_sidecar_eta_valid":false,"grants_launch_or_publication_authority":false});
        if is_active && demotion223_status::scope(&claim.phase, &claim.unit) {
            entry["resource_contract"] = demotion223_status::resource_contract(claim)?;
        }
        if private_scan {
            entry["private_qualification_only"] = json!(true);
        }
        if is_active {
            register_live_pipeline_stage(&mut live_pipeline_stages, claim)?;
            ensure!(
                if private_scan {
                    plan.gates[&claim.epoch].state == "blocked-qualification"
                        || ((demotion223_status::scope(&claim.phase, &claim.unit)
                            || super::repair141::scope(&claim.phase, &claim.unit)
                            || tail223_scan::scope(&claim.phase, &claim.unit)
                            || native209::scope(&claim.phase, &claim.unit)
                            || native210::scope(&claim.phase, &claim.unit)
                            || native227_v1625::scope(&claim.phase, &claim.unit)
                            || native228::scope(&claim.phase, &claim.unit)
                            || native207::scope(&claim.phase, &claim.unit)
                            || cold223_scan::scope(&claim.phase, &claim.unit)
                            || singleton227::native_scope(&claim.phase, &claim.unit)
                            || warmup223::scope(&claim.phase, &claim.unit))
                            && plan.gates[&claim.epoch].state == "failed-needs-repair")
                } else {
                    plan.gates[&claim.epoch].state == "post-replay-pipeline"
                },
                "live pipeline requires an independently evidenced post-replay gate"
            );
            ensure!(
                !plan
                    .diagnostics
                    .iter()
                    .any(|d| diagnostic_scope(d).contains(&claim.epoch)
                        && diagnostic_stage_running(&before[&d.unit])),
                "live delivery overlaps private diagnostic work"
            );
            for replay in replays {
                ensure!(
                    !parse_observer_claim_range(observer_string(replay, &["range"])?)?
                        .contains(&claim.epoch),
                    "live pipeline overlaps an ordinary replay claim"
                );
            }
            if claim.epoch == 198 && !finalization["importer"].is_null() {
                let importer = &finalization["importer"];
                ensure!(
                    before.get(super::cohort198_handoff::IMPORTER) == Some(importer),
                    "198 importer not bound to complete fleet census"
                );
                active.push(json!({"epoch":198,"phase":"local-publication","unit":importer,
                    "owning_controller":current,"sampled_at_utc":sample,"evidence":entry["evidence"],
                    "ordinary_replay_claim":false,"current_sidecar_eta_valid":false}));
            }
            active.push(entry.clone());
        }
        pipelines.push(entry);
    }
    for claim in &plan.diagnostics {
        let current = &before[&claim.unit];
        let is_active = (current["ActiveState"] == "active" && current["SubState"] == "running")
            || (retained220::namespace(claim) && retained220::live(current));
        if is_active {
            register_live_diagnostic_scope(&mut live_diagnostic_epochs, claim)?;
            if singleton207::namespace(claim) {
                singleton207::validate_live(claim, current)?;
            }
            if first_root233::namespace(claim) {
                first_root233::validate_live(claim, current)?;
            }
            if private157::namespace(claim) {
                private157::live_limits()?;
            }
            if prefix144::namespace(claim) {
                prefix144::live_limits()?;
            }
            if native144::namespace(claim) {
                native144::validate_live(claim, current)?;
            }
            if native203::namespace(claim) {
                native203::validate_live(claim, current)?;
            }
            if continuation203::namespace(claim) {
                continuation203::validate_live(
                    claim,
                    current,
                    plan.continuation203_runtime_extension.as_ref(),
                )?;
            }
            if native141::namespace(claim) {
                native141::validate_live(claim, current)?;
            }
            if original141::namespace(claim) {
                original141::validate_live(claim, current)?;
            }
            if original141_trace::namespace(claim) {
                original141_trace::validate_live(claim, current)?;
            }
            if original141_freeze::namespace(claim) {
                original141_freeze::validate_live(claim, current)?;
            }
            if original141_vote_prefix::namespace(claim) {
                original141_vote_prefix::validate_live(claim, current)?;
            }
            if original141_capped::namespace(claim) {
                original141_capped::validate_live(claim, current)?;
            }
            if epoch136::namespace(claim) {
                epoch136::validate_live(claim, current)?;
            }
            if census141_poh::namespace(claim) {
                census141_poh::validate_live(claim, current)?;
            }
            if continuation144::namespace(claim) {
                continuation144::validate_live(claim, current)?;
            }
            if verification223::namespace(claim) {
                verification223::validate_live(claim, current)?;
            }
            if assembly223::namespace(claim) {
                assembly223::validate_live(claim, current)?;
            }
            if assembly144::namespace(claim) {
                assembly144::validate_live(claim, current)?;
            }
            if retained220::namespace(claim) {
                retained220::validate_live(claim, current)?;
            }
            ensure!(
                current["InvocationID"] == claim.invocation_id && current["NRestarts"] == "0",
                "diagnostic live invocation changed"
            );
            if private_225_verification(claim)
                || native_restore_140(claim)
                || private157::namespace(claim)
                || prefix144::namespace(claim)
            {
                let launch = bound_json(&claim.launch_receipt)?;
                ensure!(
                    current["ExecStart"] == launch["expected_exec_start"],
                    "private diagnostic live command changed"
                );
            }
            if shrink_root203::namespace(claim) {
                let launch = bound_json(&claim.launch_receipt)?;
                ensure!(
                    shrink_root203::same_command(
                        &current["ExecStart"],
                        &launch["expected_exec_start"]
                    ),
                    "shrink-root diagnostic live command changed"
                );
            }
            if tail223::namespace(claim) {
                let launch = bound_json(&claim.launch_receipt)?;
                ensure!(
                    tail223::same_command(
                        claim,
                        &current["ExecStart"],
                        &launch["expected_exec_start"]
                    ),
                    "tail223 diagnostic live command changed"
                );
            }
            if prefix223::namespace(claim) {
                let launch = bound_json(&claim.launch_receipt)?;
                ensure!(
                    prefix223::same_command(&current["ExecStart"], &launch["expected_exec_start"]),
                    "prefix223 diagnostic live command changed"
                );
            }
            if prefix223_native20::namespace(claim) {
                ensure!(
                    prefix223_native20::same_command(&current["ExecStart"]),
                    "native20 full-prefix live command changed"
                );
                let props = singleton227_capture::properties(
                    &claim.unit,
                    "Type,User,Group,Restart,KillMode,Delegate,MemoryHigh,MemoryMax,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec,ProtectHome,ProtectSystem,ProtectControlGroups,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,ReadWritePaths,Environment,OOMPolicy,OOMScoreAdjust,Result,ActiveState,SubState,NRestarts,ExecStart",
                )?;
                prefix223_native20_capture::sandbox(&props)?;
            }
            if canary227::namespace(claim) {
                let launch = bound_json(&claim.launch_receipt)?;
                ensure!(
                    canary227::same_command(&current["ExecStart"], &launch["expected_exec_start"]),
                    "227 canary live command changed"
                );
            }
            if bounded205::namespace(claim) {
                let launch = bound_json(&claim.launch_receipt)?;
                ensure!(
                    bounded205::same_command(&current["ExecStart"], &launch["expected_exec_start"]),
                    "bounded205 diagnostic live command changed"
                );
            }
            if prefix205::namespace(claim) {
                let launch = bound_json(&claim.launch_receipt)?;
                ensure!(
                    prefix205::same_command(&current["ExecStart"], &launch),
                    "capped205 live command changed"
                );
            }
            if prefix204::namespace(claim) {
                let launch = bound_json(&claim.launch_receipt)?;
                ensure!(
                    prefix204::same_command(&current["ExecStart"], &launch),
                    "capped204 live command changed"
                );
            }
            if singleton227::namespace(claim) {
                let launch = bound_json(&claim.launch_receipt)?;
                ensure!(
                    singleton227::same_command(&current["ExecStart"], &launch),
                    "capped227 live command changed"
                );
            }
            if singleton209::namespace(claim) {
                let launch = bound_json(&claim.launch_receipt)?;
                ensure!(
                    singleton209::same_command(&current["ExecStart"]),
                    "capped209 live command changed"
                );
                singleton209::bindings(claim, &launch)?;
            }
            if singleton210::namespace(claim) {
                let launch = bound_json(&claim.launch_receipt)?;
                ensure!(
                    singleton210::same_command(&current["ExecStart"]),
                    "capped210 live command changed"
                );
                singleton210::bindings(claim, &launch)?;
            }
            if shrink_budget225::namespace(claim) {
                let launch = bound_json(&claim.launch_receipt)?;
                ensure!(
                    shrink_budget225::same_command(
                        &current["ExecStart"],
                        &launch["expected_exec_start"]
                    ),
                    "shrink-budget225 diagnostic live command changed"
                );
            }
            ensure!(
                claim.scratch_path.canonicalize()? == claim.scratch_path
                    && claim.scratch_path.is_dir(),
                "diagnostic scratch must be an exact canonical directory"
            );
            let phase = if singleton207::namespace(claim) {
                "private-full-epoch-qualification"
            } else if epoch136::namespace(claim) {
                "private-corrected-worker-root-repair"
            } else if original141_capped::namespace(claim) {
                "private-original-entry-capped-root-qualification"
            } else if original141_vote_prefix::namespace(claim) {
                "private-original-entry-vote-prefix"
            } else if original141_freeze::namespace(claim) {
                "private-original-entry-freeze-components"
            } else if original141_trace::namespace(claim) {
                "private-original-entry-trace-repair"
            } else if original141::namespace(claim) {
                "private-original-entry-root-qualification"
            } else if prefix223::namespace(claim)
                || prefix223_native20::namespace(claim)
                || first_root233::namespace(claim)
                || prefix205::namespace(claim)
                || prefix204::namespace(claim)
            {
                "private-known-root-prefix"
            } else if tail223::namespace(claim) {
                "private-tail-comparison"
            } else if census141_poh::namespace(claim) {
                "private-poh-diagnostic"
            } else if native141::namespace(claim) {
                "native-ledger-read-only"
            } else if verification223::namespace(claim) {
                "private-verification-only"
            } else if assembly144::namespace(claim) || assembly223::namespace(claim) {
                "private-assembly-only"
            } else if continuation144::namespace(claim) || continuation203::namespace(claim) {
                "private-checkpoint-continuation"
            } else if native_restore_140(claim)
                || native144::namespace(claim)
                || native203::namespace(claim)
            {
                "native-restore-only"
            } else if claim
                .unit
                .starts_with("horizon-qualify-213-private-verification-")
                || private_225_verification(claim)
                || private157::namespace(claim)
                || prefix144::namespace(claim)
                || retained220::namespace(claim)
            {
                "private-verification"
            } else {
                "diagnostic-qualification"
            };
            active.push(json!({"epoch":claim.epoch,"phase":phase,"producer":current,
                "scratch_path":claim.scratch_path,"launch_receipt":claim.launch_receipt.path,
                "launch_receipt_sha256":claim.launch_receipt.sha256,"sampled_at_utc":sample,
                "scope_first_epoch":diagnostic_scope(claim).start(),
                "scope_last_epoch":diagnostic_scope(claim).end(),
                "resource_basis":"hash-bound private diagnostic launch and invocation identity; consult bound admission, guard and terminal evidence",
                "ordinary_replay_claim":false,"current_sidecar_eta_valid":false}));
        }
        diagnostics.push(json!({"epoch":claim.epoch,"unit":current,"live":is_active,
            "scope_first_epoch":diagnostic_scope(claim).start(),
            "scope_last_epoch":diagnostic_scope(claim).end(),
            "launch_invocation_id":claim.invocation_id,"launch_receipt":claim.launch_receipt.path,
            "launch_receipt_sha256":claim.launch_receipt.sha256,
            "terminal_outcome_requires_canary_receipt":!is_active}));
    }
    let capped_work =
        capped204205_work::rows(&plan.capped204205_work, &observer, &before, started_seconds)?;
    for row in &capped_work {
        if row["live"] == true {
            let epoch = row["epoch"].as_u64().context("capped row epoch missing")?;
            ensure!(
                row["ownership_unresolved"] == true
                    || (!live_diagnostic_epochs.contains(&epoch)
                        && !pipelines
                            .iter()
                            .any(|v| v["epoch"] == epoch && v["live"] == true)
                        && !replays.iter().any(|r| r["range"]
                            .as_str()
                            .and_then(|s| parse_observer_claim_range(s).ok())
                            .is_some_and(|r| r.contains(&epoch)))),
                "capped work overlaps another live epoch owner"
            );
            active.push(row.clone());
        }
    }
    let mut recovery_work = plan
        .assembly204_recovery
        .as_ref()
        .map(|c| assembly204_recovery::row(c, &observer, &before, started_seconds))
        .transpose()?
        .into_iter()
        .collect::<Vec<_>>();
    ensure!(
        plan.assembly204_recovery.is_none() || plan.assembly204_recovery_terminal.is_none(),
        "204 recovery cannot be live and terminal together"
    );
    if let Some(terminal) = &plan.assembly204_recovery_terminal {
        recovery_work.push(assembly204_recovery::terminal_row(terminal, &before)?);
    }
    for row in &recovery_work {
        ensure!(
            !active
                .iter()
                .any(|r| r["epoch"] == 204 && r["live"] == true),
            "204 recovery overlaps another accepted live owner"
        );
        if row["live"] == true {
            active.push(row.clone());
        }
    }
    let mut remote_entries = Vec::new();
    let requested_epochs = (plan.first_epoch..=plan.last_epoch).collect::<Vec<_>>();
    let remote_inventory =
        inventory_batch::collect(&requested_epochs, |epoch| inventory_epoch(&s3, &r2, epoch))
            .await?;
    for remote in remote_inventory {
        let epoch = remote.epoch;
        ensure!(
            !matches!(
                remote.state,
                InventoryState::SidecarOnly
                    | InventoryState::InvalidSidecar
                    | InventoryState::MetadataMismatch
            ),
            "epoch {epoch}: R2 pair anomaly"
        );
        let gate = &plan.gates[&epoch];
        let mut state = gate.state.as_str();
        let mut next = gate.next_action.as_str();
        if epoch == 157
            && let Some(entry) = &runtime157
            && entry["ordinary_replay_restored"] != true
        {
            state = if entry["live"] == true {
                "live-replay"
            } else {
                "blocked-qualification"
            };
            next = "Preserve original157 producer, queued successor replay and independent runtime-segment verification; ETA unavailable until a qualified rate-bearing replay observation is restored. Review actual terminal/ownership changes, never restart from a missing worker.";
        }
        if diagnostics.iter().any(|claim| {
            claim["live"] == true
                && claim["scope_first_epoch"]
                    .as_u64()
                    .is_some_and(|first| first <= epoch)
                && claim["scope_last_epoch"]
                    .as_u64()
                    .is_some_and(|last| epoch <= last)
        }) {
            let retains_open_repair = (epoch == 136
                && plan.diagnostics.iter().any(epoch136::namespace))
                || (epoch == 141
                    && plan.diagnostics.iter().any(|c| {
                        native141::namespace(c)
                            || census141_poh::namespace(c)
                            || original141::namespace(c)
                            || original141_trace::namespace(c)
                            || original141_freeze::namespace(c)
                            || original141_vote_prefix::namespace(c)
                            || original141_capped::namespace(c)
                    }));
            if !retains_open_repair {
                state = private_qualification_inventory_state(gate.state.as_str());
            }
            if epoch == 226
                && diagnostics.iter().any(|claim| {
                    claim["epoch"] == 225
                        && claim["scope_last_epoch"] == 226
                        && claim["live"] == true
                })
            {
                next = "Preserve private epoch-226 tail of live epoch-225 natural-root qualification; no ordinary replay, plugin publication or sidecar until a separately qualified handoff";
            }
        }
        if pipelines.iter().any(|claim| {
            claim["epoch"] == epoch
                && claim["live"] == true
                && claim["private_qualification_only"] != true
        }) {
            state = "post-replay-pipeline";
        }
        if epoch == 204 && recovery_work.iter().any(|r| r["live"] == true) {
            state = "post-replay-pipeline";
            next = "Continue the exact assembly recovery and its separately admitted verification, boundary, import and upload stages";
        }
        let mut live = None;
        for replay in replays {
            let range = parse_observer_claim_range(observer_string(replay, &["range"])?)?;
            if !range.contains(&epoch) {
                continue;
            }
            if gate.reserve_stop.is_some() {
                continue;
            }
            ensure!(
                live.is_none(),
                "overlapping observer claims for epoch {epoch}"
            );
            let controller = &before[observer_string(replay, &["controller_after", "unit"])?];
            let producer = &before[observer_string(replay, &["producer_after", "unit"])?];
            ensure!(
                live_binding(&replay["controller_after"], controller)
                    && live_binding(&replay["producer_after"], producer),
                "epoch {epoch}: observer invocation is no longer live"
            );
            validate_observer_binding(
                &observer_bytes,
                &plan.observer.sha256,
                epoch,
                observer_string(replay, &["controller_after", "invocation_id"])?,
                observer_string(replay, &["producer_after", "invocation_id"])?,
            )?;
            live = Some((controller, producer));
            if gate.state != "blocked-qualification" {
                state = "live-replay";
                next = "Complete replay and canonical checkpoint, then import and dispatch receipt-gated verification";
            }
            active.push(json!({"epoch":epoch,"phase":if gate.state == "blocked-qualification" {"qualification"} else {"replay"},"controller":controller,"producer":producer,"scratch_path":replay["scratch_path"],"useful_work":replay["useful_work"],"sampled_at_utc":sample}));
        }
        if remote.state == InventoryState::ReadyPair {
            state = "remote-ready";
            next = "Preserve ready pair; perform only receipt- and boundary-gated local retirement or status cleanup";
        }
        let key = format!("epoch-{epoch}.epoch-status.json");
        let status = if let Some(object) = get_mutable_object(&s3, &r2.bucket, &key).await? {
            let status: EpochStatus = serde_json::from_slice(&object.bytes)?;
            validate_epoch_status(&status, epoch)?;
            let publication = latest_status_publication_receipt(
                &plan.status_receipt_directory,
                &r2.bucket,
                epoch,
            );
            // Status phase describes actual work (replay, input verification),
            // while this separately authenticated owner binding preserves the
            // private compatibility gates and grants no production claim.
            let private_qualification_binding =
                publication.as_ref().is_ok_and(|(receipt, _, _)| {
                    qualification_status::matches(receipt, epoch, &observer, &before)
                        || super::repair141::matches(receipt, epoch, &before)
                        || canary227_status::matches(receipt, epoch, &observer, &before)
                        || full227_status::matches(receipt, epoch, &observer, &before)
                        || full209_status::matches(receipt, epoch, &observer, &before)
                        || full210_status::matches(receipt, epoch, &observer, &before)
                        || demotion223_status::matches(receipt, epoch, &before)
                        || prefix223_native20_status::matches(receipt, epoch, &observer, &before)
                        || first_root233::status_matches(receipt, epoch, &observer, &before)
                        || singleton207::status_matches(receipt, epoch, &observer, &before)
                        || native223_status::matches(receipt, epoch, &observer, &before)
                        || pipeline_status::native_input_matches_status(receipt, epoch, &before)
                        || capped204205_work::status_matches(receipt, epoch, &capped_work)
                        || assembly204_recovery::status_matches(receipt, epoch, &recovery_work)
                });
            // Missing local publication history is explicitly unbound, never current.
            let matches = publication.as_ref().is_ok_and(|(receipt, _, _)| {
                if private_qualification_binding {
                    return receipt.status == status
                        && receipt.object_etag == object.etag
                        && receipt.authenticated_readback;
                }
                if let Some(binding) = &receipt.pipeline_binding {
                    receipt.status == status
                        && receipt.object_etag == object.etag
                        && receipt.authenticated_readback
                        && pipelines.iter().any(|entry| {
                            entry["epoch"] == epoch
                                && entry["live"] == true
                                && binding.live_matches(&entry["unit"])
                        })
                } else {
                    live.is_some_and(|(controller, producer)| {
                        status_matches(&status, &object.etag, receipt, controller, producer)
                    })
                }
            });
            let production_matches = production_status_binding_matches(matches, state)
                || (matches && private_qualification_binding);
            let capped_current = publication.as_ref().is_ok_and(|(r, _, _)| {
                capped204205_work::status_matches(r, epoch, &capped_work)
                    || assembly204_recovery::status_matches(r, epoch, &recovery_work)
            });
            json!({"key":key,"etag":object.etag,"payload":status,"sha256":hex_lower(&Sha256::digest(&object.bytes)),"classification":if production_matches {"bound-live-status"} else {"stale-or-orphaned"},"owner_binding_matches":matches,"production_claim_eligible":matches!(state,"live-replay"|"post-replay-pipeline"),"sample_matches_observer":status.sampled_at_utc == sample,"current_eta_valid":production_matches && (status.sampled_at_utc == sample || capped_current)})
        } else {
            Value::Null
        };
        entries.push(json!({"epoch":epoch,"state":state,"next_action":next,"status":status,"gate_evidence":gate.evidence.iter().map(|e|json!({"path":e.path,"sha256":e.sha256})).collect::<Vec<_>>()}));
        remote_entries.push(remote);
    }
    let mut auxiliary_diagnostics = Vec::new();
    if let (Some(claim), Some(launch)) = (&plan.epoch203_ram_auxiliary, &auxiliary_launch) {
        let entry =
            ram_auxiliary::observe(claim, launch, &observer, &before[&claim.unit], &active)?;
        if entry["live"] == true {
            active.push(entry.clone());
        }
        auxiliary_diagnostics.push(entry);
    }
    let after = census(&names, plan.first_epoch, plan.last_epoch)?;
    ensure!(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() - sample_seconds <= 1800,
        "observer became stale during fleet reconciliation"
    );
    ensure!(
        before == after,
        "fleet unit identities or commands changed during reconciliation"
    );
    let inventory = inventory_report(remote_entries);
    let changes = transitions(&previous_fleet, &after, &entries);
    let receipt = json!({"schema":SCHEMA,"first_epoch":plan.first_epoch,"last_epoch":plan.last_epoch,"sampled_at_utc":sample,"observer_receipt":plan.observer.path,"observer_sha256":plan.observer.sha256,"previous_fleet":plan.previous_fleet.as_ref().map(|p|json!({"path":p.path,"sha256":p.sha256})),"plan":plan_bound.path,"plan_sha256":plan_bound.sha256,"admission_transition_guard":plan.admission_transition_guard.as_ref().map(|p|json!({"path":p.path,"sha256":p.sha256})),"inventory":inventory,"unit_census":after,"active":active,"diagnostics":diagnostics,"transitions":changes,"epochs":entries,"recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"remote_mutations":false,"producer_mutations":false,"publication_authorized":false});
    let mut receipt = receipt;
    receipt["assembly204_recovery"] = json!(recovery_work);
    receipt["assembly204_recovery_history"] = json!(plan.assembly204_recovery_history);
    receipt["capped204205_work"] = json!(capped_work);
    receipt["capped204205_history"] = json!(plan.capped204205_history);
    if let Some(event) = &plan.metadata_event {
        let proof = bound_json(event)?;
        receipt["metadata_event"] = json!({"path":event.path,"sha256":event.sha256});
        receipt["metadata_event_sampled_at_utc"] = proof["sampled_at_utc"].clone();
        receipt["new_resource_samples"] = json!(0);
    }
    if let Some(extension) = &plan.continuation203_runtime_extension {
        receipt["continuation203_runtime_extension"] = private157::binding(extension);
    }
    receipt["pipelines"] = json!(pipelines);
    receipt["terminal_replays"] = json!(terminal_replays);
    receipt["auxiliary_diagnostics"] = json!(auxiliary_diagnostics);
    if plan.first_epoch == 201 && plan.last_epoch == 300 {
        receipt["memory_target"] = fleet_memory::report(&observer, &receipt);
    }
    if let Some(entry) = runtime157 {
        receipt["runtime_handoff157"] = entry;
    }
    if let Some(entry) = private144 {
        receipt["observer_diagnostics"] = json!([entry]);
    }
    persist(&plan.output, &receipt)?;
    println!("{}", plan.output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn retained_terminal_diagnostic_does_not_own_a_delivery_lane() {
        use serde_json::json;
        for (active, sub, conflict) in [
            ("active", "exited", false),
            ("inactive", "dead", false),
            ("failed", "failed", false),
            ("active", "running", true),
            ("activating", "start", true),
            ("activating", "auto-restart", true),
        ] {
            assert_eq!(
                super::diagnostic_stage_running(&json!({"ActiveState":active,"SubState":sub})),
                conflict
            );
        }
    }
    #[test]
    fn exact_private_observation_is_not_a_second_captured_job() {
        let c = DiagnosticClaim {
            epoch: 144,
            unit: assembly144::UNIT.into(),
            invocation_id: "a".repeat(32),
            scratch_path: assembly144::ROOT.into(),
            launch_receipt: BoundFile {
                path: "/launch".into(),
                sha256: "b".repeat(64),
            },
        };
        let row = json!({"epoch":144,"producer":{"Id":c.unit,"InvocationID":c.invocation_id},"scratch_path":c.scratch_path});
        let claims = [c];
        assert!(diagnostic_owns_observation(&claims, &row));
        for (ptr, value) in [
            ("/epoch", json!(145)),
            ("/producer/Id", json!("another.service")),
            ("/producer/InvocationID", json!("c".repeat(32))),
            ("/scratch_path", json!("/another")),
        ] {
            let mut bad = row.clone();
            *bad.pointer_mut(ptr).unwrap() = value;
            assert!(!diagnostic_owns_observation(&claims, &bad));
        }
        assert!(!diagnostic_owns_observation(&[], &row));
    }
    #[test]
    fn private_qualification_owner_cannot_make_a_production_countdown_valid() {
        assert!(production_status_binding_matches(true, "live-replay"));
        assert!(production_status_binding_matches(
            true,
            "post-replay-pipeline"
        ));
        assert!(!production_status_binding_matches(false, "live-replay"));
        for state in [
            "blocked-qualification",
            "failed-needs-repair",
            "staged-admissible",
            "not-yet-staged",
            "remote-ready",
        ] {
            assert!(
                !production_status_binding_matches(true, state),
                "accepted status for {state}"
            );
        }
    }
    #[test]
    fn live_private_qualification_does_not_remove_an_open_failed_epoch_from_backlog() {
        assert_eq!(
            private_qualification_inventory_state("failed-needs-repair"),
            "failed-needs-repair"
        );
        for state in [
            "blocked-qualification",
            "staged-admissible",
            "not-yet-staged",
        ] {
            assert_eq!(
                private_qualification_inventory_state(state),
                "blocked-qualification"
            );
        }
        assert!(!production_status_binding_matches(
            true,
            private_qualification_inventory_state("failed-needs-repair")
        ));
    }

    fn epoch154_guard_properties() -> Value {
        json!({
            "Id":EPOCH154_SAFETY_GUARD,"LoadState":"loaded","Type":"oneshot",
            "User":"root","Group":"root","FragmentPath":EPOCH154_GUARD_FRAGMENT,
            "DropInPaths":"","Environment":"","EnvironmentFiles":"","PassEnvironment":"",
            "RootDirectory":"","RootImage":"","ExecStartPre":"","ExecStartPost":"","ExecCondition":"","ExecStop":"","ExecStopPost":"","ExecReload":"",
            "ExecStart":format!("{{ path={EPOCH154_GUARD_BINARY} ; argv[]={EPOCH154_GUARD_BINARY} {EPOCH154_GUARD_PLAN} --plan-sha256 {EPOCH154_GUARD_PLAN_SHA} --self-sha256 {EPOCH154_GUARD_BINARY_SHA} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=42 ; code=(null) ; status=0/0 }}")
        })
    }

    #[test]
    fn safety_guard_exemption_requires_the_complete_exact_nonlaunching_command() {
        let good = epoch154_guard_properties();
        validate_epoch154_guard_properties(&good).unwrap();
        for (key, value) in [
            ("Id", "horizon-qualify-other-guard.service"),
            ("Type", "simple"),
            ("User", "sol"),
            ("ExecStartPre", "/sealed/jetstreamer-node 154 /output"),
            ("ExecStartPost", "/sealed/replay"),
            ("ExecCondition", "/sealed/launch"),
            ("ExecStop", "/sealed/replay"),
            ("ExecStopPost", "/sealed/replay"),
            ("ExecReload", "/sealed/replay"),
            ("Environment", "LD_PRELOAD=/untrusted.so"),
            ("EnvironmentFiles", "/untrusted"),
            ("PassEnvironment", "LD_PRELOAD"),
            ("DropInPaths", "/untrusted"),
            ("RootImage", "/untrusted"),
        ] {
            let mut bad = good.clone();
            bad[key] = json!(value);
            assert!(
                validate_epoch154_guard_properties(&bad).is_err(),
                "accepted changed {key}"
            );
        }
        for command in [
            good["ExecStart"]
                .as_str()
                .unwrap()
                .replace(EPOCH154_GUARD_PLAN_SHA, &"a".repeat(64)),
            format!(
                "{} {{ path=/sealed/jetstreamer-node ; argv[]=/sealed/jetstreamer-node 154 /output ; }}",
                good["ExecStart"].as_str().unwrap()
            ),
            good["ExecStart"].as_str().unwrap().replace(
                " ; ignore_errors=no ;",
                " --extra-launch-argument ; ignore_errors=no ;",
            ),
        ] {
            let mut bad = good.clone();
            bad["ExecStart"] = json!(command);
            assert!(validate_epoch154_guard_properties(&bad).is_err());
        }
    }

    #[test]
    fn safety_guard_cannot_hide_an_unbound_or_replaced_parent() {
        assert!(validate_epoch154_safety_guard(&BTreeMap::new()).is_err());
        let mut parents = BTreeMap::new();
        parents.insert(EPOCH154_GUARDED_PRODUCER.to_string(), json!({"InvocationID":"replacement","NRestarts":"0","ActiveState":"active","SubState":"running"}));
        assert!(validate_epoch154_safety_guard(&parents).is_err());
    }

    #[test]
    fn safety_guard_absence_requires_exact_empty_typed_dbus_arrays() {
        validate_empty_guard_array(br#"{"type":"a(sb)","data":[]}"#, "a(sb)").unwrap();
        for bad in [
            br#"{"type":"a(sb)","data":null}"#.as_slice(),
            br#"{"type":"a(sb)"}"#,
            br#"{"type":"s","data":[]}"#,
            br#"{"type":"a(sb)","data":[["/untrusted",true]]}"#,
        ] {
            assert!(validate_empty_guard_array(bad, "a(sb)").is_err());
        }
    }

    #[test]
    #[ignore = "read-only capability check for the exact dev-samjohnson guard deployment"]
    fn host_epoch154_safety_guard_exact_deployment_is_observational() {
        let current = BTreeMap::from([(
            EPOCH154_GUARDED_PRODUCER.to_string(),
            unit(EPOCH154_GUARDED_PRODUCER).unwrap(),
        )]);
        validate_epoch154_safety_guard(&current).unwrap();
    }

    fn pipeline_fixture() -> (PipelineClaim, Value) {
        let claim = PipelineClaim {
            epoch: 213,
            phase: "local-publication".into(),
            unit: "horizon-publish-213-test.service".into(),
            invocation_id: "a".repeat(32),
            expected_exec_start:
                "{ path=/sealed/publisher ; argv[]=/sealed/publisher /sealed/plan ; }".into(),
            evidence: vec![BoundFile {
                path: "/sealed/plan".into(),
                sha256: "b".repeat(64),
            }],
        };
        let current = json!({"LoadState":"loaded","ActiveState":"activating","SubState":"start",
            "InvocationID":claim.invocation_id,"NRestarts":"0","ExecStart":claim.expected_exec_start,"MainPID":"123"});
        (claim, current)
    }

    #[test]
    fn pipeline_observation_binds_exact_live_command_and_invocation() {
        let (claim, current) = pipeline_fixture();
        validate_pipeline_claim(&claim, 201, 300).unwrap();
        assert!(pipeline_live(&claim, &current).unwrap());
        for (field, value) in [
            ("InvocationID", json!("c".repeat(32))),
            ("NRestarts", json!("1")),
            ("ExecStart", json!("/different")),
            ("MainPID", json!("0")),
            ("LoadState", json!("not-found")),
        ] {
            let mut bad = current.clone();
            bad[field] = value;
            assert!(pipeline_live(&claim, &bad).is_err(), "{field}");
        }
        let mut terminal = current;
        terminal["ActiveState"] = json!("inactive");
        terminal["SubState"] = json!("dead");
        assert!(!pipeline_live(&claim, &terminal).unwrap());
    }

    #[test]
    fn pipeline_observation_accepts_only_display_metadata_reset() {
        let (mut claim, mut current) = pipeline_fixture();
        claim.expected_exec_start = "{ path=/sealed/publisher ; argv[]=/sealed/publisher /sealed/plan ; ignore_errors=no ; start_time=[Thu 2026-10-22 01:08:06 UTC] ; stop_time=[n/a] ; pid=123 ; code=(null) ; status=0/0 }".into();
        let reset = "{ path=/sealed/publisher ; argv[]=/sealed/publisher /sealed/plan ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }";
        current["ExecStart"] = json!(reset);
        assert!(pipeline_live(&claim, &current).unwrap());
        for changed in [
            reset.replace("path=/sealed/publisher", "path=/different"),
            reset.replace("/sealed/plan", "/different/plan"),
            reset.replace("/sealed/plan ;", "/sealed/plan --extra ;"),
            reset.replace("ignore_errors=no", "ignore_errors=yes"),
            reset.replace("pid=0", "pid=invalid"),
            reset.replace(" ; status=0/0", " ; status=0/0 ; extra=1"),
        ] {
            let mut bad = current.clone();
            bad["ExecStart"] = json!(changed);
            assert!(pipeline_live(&claim, &bad).is_err());
        }
        for (field, value) in [
            ("InvocationID", json!("c".repeat(32))),
            ("NRestarts", json!("1")),
            ("MainPID", json!("0")),
            ("LoadState", json!("not-found")),
        ] {
            let mut bad = current.clone();
            bad[field] = value;
            assert!(pipeline_live(&claim, &bad).is_err(), "{field}");
        }
    }

    #[test]
    fn pipeline_claim_is_not_a_diagnostic_or_tail_publication() {
        let (mut claim, _) = pipeline_fixture();
        claim.epoch = 301;
        assert!(validate_pipeline_claim(&claim, 201, 300).is_err());
        claim.epoch = 213;
        claim.phase = "diagnostic-qualification".into();
        assert!(validate_pipeline_claim(&claim, 201, 300).is_err());
        claim.phase = "upload-readback".into();
        claim.unit = "horizon-upload-213-test.service".into();
        validate_pipeline_claim(&claim, 201, 300).unwrap();
        claim.evidence.clear();
        assert!(validate_pipeline_claim(&claim, 201, 300).is_err());
    }

    #[test]
    fn verifier_and_cohort_claims_retain_exact_epoch_scope() {
        let (mut claim, _) = pipeline_fixture();
        claim.epoch = 218;
        for (phase, unit) in [
            (
                "full-verification",
                "horizon-full-verify-216-219-cached-v1.service",
            ),
            (
                "plugin-verification",
                "horizon-plugin-verify-216-219-cached-v1.service",
            ),
            (
                "upload-readback",
                "horizon-upload-216-219-cached-v1.service",
            ),
        ] {
            claim.phase = phase.into();
            claim.unit = unit.into();
            validate_pipeline_claim(&claim, 201, 300).unwrap();
            claim.epoch = 220;
            assert!(validate_pipeline_claim(&claim, 201, 300).is_err());
            claim.epoch = 218;
        }
        for unit in [
            "horizon-upload-219-216-test.service",
            "horizon-upload-0216-219-test.service",
            "horizon-upload-216-0219-test.service",
            "horizon-upload-216-219.service",
            "horizon-upload-216--test.service",
            "horizon-upload-216-219-test/service",
        ] {
            claim.unit = unit.into();
            assert!(validate_pipeline_claim(&claim, 201, 300).is_err(), "{unit}");
        }
        claim.epoch = 300;
        claim.unit = "horizon-upload-298-301-private-tail.service".into();
        assert!(validate_pipeline_claim(&claim, 201, 300).is_err());
        claim.phase = "full-verification".into();
        claim.epoch = 206;
        claim.unit = "horizon-full-verify-206-production-v1.service".into();
        validate_pipeline_claim(&claim, 201, 300).unwrap();
        claim.phase = "plugin-verification".into();
        assert!(validate_pipeline_claim(&claim, 201, 300).is_err());
    }

    #[test]
    fn root_importer_is_an_exact_scoped_local_publication_claim() {
        let (mut claim, current) = pipeline_fixture();
        claim.epoch = 206;
        claim.phase = "local-publication".into();
        claim.unit = "jetstreamer-root-import-horizon-206-cf9b7e9-v1-e206-206-3.service".into();
        validate_pipeline_claim(&claim, 201, 300).unwrap();
        let mut current = current;
        current["Id"] = json!(claim.unit);
        assert!(pipeline_live(&claim, &current).unwrap());
        claim.phase = "upload-readback".into();
        assert!(validate_pipeline_claim(&claim, 201, 300).is_err());
        claim.phase = "local-publication".into();
        claim.epoch = 207;
        assert!(validate_pipeline_claim(&claim, 201, 300).is_err());
        claim.epoch = 300;
        claim.unit = "jetstreamer-root-import-tail-e298-301-1.service".into();
        assert!(validate_pipeline_claim(&claim, 201, 300).is_err());
    }

    #[test]
    fn root_importer_rejects_ambiguous_or_noncanonical_names() {
        for unit in [
            "jetstreamer-root-import--e206-206-1.service",
            "jetstreamer-root-import-test-e206-206-0.service",
            "jetstreamer-root-import-test-e0206-206-1.service",
            "jetstreamer-root-import-test-e206-0206-1.service",
            "jetstreamer-root-import-test-e206-206-01.service",
            "jetstreamer-root-import-test-e207-206-1.service",
            "jetstreamer-root-import-test-e206-206-retry.service",
            "jetstreamer-root-import-test-e206-206-1-extra.service",
            "jetstreamer-root-import-test-e206-206-1.timer",
            "jetstreamer-root-import-test-e206-206-1/service",
            "jetstreamer-root-import-test-e206-206-1.service\n",
            "jetstreamer-root-import-test-e0-1001-1.service",
        ] {
            assert!(
                pipeline_unit_range("local-publication", unit).is_err(),
                "{unit}"
            );
        }
    }

    #[test]
    fn independent160_198_upload_requires_exact_distinct_epoch_evidence() {
        let claim = |epoch, evidence| -> PipelineClaim {
            serde_json::from_value(json!({"epoch":epoch,"phase":"upload-readback",
                "unit":watch198::UPLOAD,"invocation_id":"e4e455fbd455483282107652ca37b83d",
                "expected_exec_start":"exact unchanged uploader command","evidence":evidence}))
            .unwrap()
        };
        let a = claim(
            160,
            json!([
                {"path":"/var/lib/jetstreamer/horizon-epoch160-public-observation-20261022-v1/proof.json","sha256":"c54ede068b3cfd743259f52b93a98847910abe4fac6ff50ab88c4bbcae5e9008"},
                {"path":"/home/sol/.jetstreamer-private/r2-status-receipts/epoch-160.status-20261022145800.json","sha256":"77cf948e486907911de4371c1109afcf318700e92d1d4eef90fb77f4f2b96246"}
            ]),
        );
        let b = claim(
            198,
            json!([
                {"path":"/usr/local/lib/jetstreamer/horizon-epoch198-uploader-transition-20261021-v1/transition.json","sha256":"024b23f765a26f17c252df2bf0281cd3439aae046ee7a545227bd0ded98f4794"}
            ]),
        );
        for (first, second) in [(&a, &b), (&b, &a)] {
            let mut units = BTreeMap::new();
            register_pipeline_claim(&mut units, first).unwrap();
            register_pipeline_claim(&mut units, second).unwrap();
            assert!(register_pipeline_claim(&mut units, first).is_err());
        }
        for field in [
            "epoch",
            "unit",
            "phase",
            "invocation_id",
            "expected_exec_start",
            "evidence",
        ] {
            let mut v = serde_json::to_value(&b).unwrap();
            v[field] = match field {
                "epoch" => json!(197),
                "evidence" => json!([]),
                _ => json!("foreign"),
            };
            let bad: PipelineClaim = serde_json::from_value(v).unwrap();
            assert!(!independent160_198_upload_evidence(&a, &bad), "{field}");
            assert!(!independent160_198_upload_evidence(&bad, &a), "{field}");
        }
        let mut bad = serde_json::to_value(&a).unwrap();
        bad["evidence"][0]["sha256"] = json!("f".repeat(64));
        assert!(!independent160_198_upload_evidence(
            &serde_json::from_value(bad).unwrap(),
            &b
        ));
    }

    #[test]
    fn shared_cohort_unit_requires_identical_invocation_command_and_evidence() {
        let (mut first, _) = pipeline_fixture();
        first.epoch = 216;
        first.unit = "horizon-upload-216-219-test.service".into();
        first.phase = "upload-readback".into();
        let copy = || PipelineClaim {
            epoch: 217,
            phase: first.phase.clone(),
            unit: first.unit.clone(),
            invocation_id: first.invocation_id.clone(),
            expected_exec_start: first.expected_exec_start.clone(),
            evidence: vec![BoundFile {
                path: first.evidence[0].path.clone(),
                sha256: first.evidence[0].sha256.clone(),
            }],
        };
        let next = copy();
        let mut units = BTreeMap::new();
        register_pipeline_claim(&mut units, &first).unwrap();
        register_pipeline_claim(&mut units, &next).unwrap();
        assert!(register_pipeline_claim(&mut units, &first).is_err());
        for field in ["invocation", "command", "evidence", "phase"] {
            let mut changed = copy();
            match field {
                "invocation" => changed.invocation_id = "f".repeat(32),
                "command" => changed.expected_exec_start.push_str(" changed"),
                "evidence" => changed.evidence.clear(),
                "phase" => changed.phase = "local-publication".into(),
                _ => unreachable!(),
            }
            let mut units = BTreeMap::new();
            register_pipeline_claim(&mut units, &first).unwrap();
            assert!(
                register_pipeline_claim(&mut units, &changed).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn concurrent_verifiers_and_upload_are_distinct_but_duplicate_stages_fail() {
        let (mut claim, _) = pipeline_fixture();
        let mut stages = BTreeSet::new();
        for phase in [
            "full-verification",
            "plugin-verification",
            "upload-readback",
        ] {
            claim.phase = phase.into();
            register_live_pipeline_stage(&mut stages, &claim).unwrap();
        }
        assert_eq!(stages.len(), 3);
        claim.unit = "horizon-upload-213-replacement.service".into();
        assert!(register_live_pipeline_stage(&mut stages, &claim).is_err());
        claim.epoch = 214;
        register_live_pipeline_stage(&mut stages, &claim).unwrap();
    }
    use super::*;
    #[test]
    fn ram_supervisors_cannot_disappear_from_the_complete_service_census() {
        for name in [
            "horizon-203-ram-resource-baseline-test.service",
            "horizon-203-ram-resource-shrink-test.service",
            "horizon-203-ram-resource-baseline-capability-v1.service",
        ] {
            assert!(ram_entry_owner(name));
        }
        assert!(!ram_entry_owner(
            "unrelated-horizon-203-ram-resource-test.service"
        ));
        assert!(!ram_entry_owner("horizon-203-ram-storage-probe-v3.service"));
    }

    #[test]
    fn natural_root_225_launch_keeps_the_complete_span_and_tail_private() {
        let mut claim = DiagnosticClaim {
            epoch: 225,
            unit: "horizon-qualify-225-natural-root-resource-test.service".into(),
            invocation_id: "a".repeat(32),
            scratch_path:
                "/home/ubuntu/.jetstreamer-private/qualification-225-v1625-natural-root-test".into(),
            launch_receipt: BoundFile {
                path: "/sealed/launch.json".into(),
                sha256: "b".repeat(64),
            },
        };
        assert_eq!(diagnostic_scope(&claim), 225..=226);
        assert!(!diagnostic_scope(&claim).contains(&224));
        assert!(!diagnostic_scope(&claim).contains(&227));
        let mut live_epochs = BTreeSet::new();
        register_live_diagnostic_scope(&mut live_epochs, &claim).unwrap();
        let mut overlapping = DiagnosticClaim {
            epoch: 226,
            unit: "horizon-qualify-226-test.service".into(),
            invocation_id: "c".repeat(32),
            scratch_path: "/private/226".into(),
            launch_receipt: BoundFile {
                path: "/sealed/226.json".into(),
                sha256: "d".repeat(64),
            },
        };
        assert!(register_live_diagnostic_scope(&mut live_epochs, &overlapping).is_err());
        assert_eq!(live_epochs, BTreeSet::from([225, 226]));
        overlapping.epoch = 227;
        register_live_diagnostic_scope(&mut live_epochs, &overlapping).unwrap();
        let receipt = json!({
            "schema":"jetstreamer-private-epoch225-natural-root-resource-launch-v1",
            "launched":true,"epoch":225,"private_run_root":claim.scratch_path,
            "snapshot_slot":97199617,
            "snapshot_sha256":"094d3b28c39403580fbac083cdad67cc008b255dd375d611217103750d0f412d",
            "worker_sha256":"7cd48efc8719109a69fafcb3209a821ea9f07113e3fb0bfab49db23a6e77a146",
            "node_sha256":"945f36fe11824263258ad561dba106e377148b702f2c615522b171c4ba97ed3b",
            "runtime":"solana-v1.6.25","runtime_semantics_changed":true,"solana_rayon_threads":16,
            "output_slot_start":97200000,"output_slot_count":863465,"canonical_epoch_end":97631999,
            "terminal_root_slot":98063464,"required_checkpoints":[97199617,97631459,98063464],
            "private_verification_tail_epoch":226,"private_verification_tail_slots":431465,
            "natural_parent_completion_required":true,"maximum_runtime_seconds":604800,
            "natural_root_resource_attempt_authorized":true,"full_span_independently_qualified":false,
            "full_cold_epoch_peak_qualified":false,"ordinary_replay_authorized":false,
            "runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,
            "publication_authorized":false,"remote_mutations":false,"r2_mutations":false,
            "evidence":{"units":[{"unit":claim.unit,"invocation_id":claim.invocation_id,
                "restarts":0,"load_state":"loaded","active_state":"active","sub_state":"running",
                "main_pid":123,"result":"success"}]}
        });
        validate_diagnostic_launch(&receipt, &claim).unwrap();
        let mut shrink_claim = DiagnosticClaim {
            epoch: 225,
            unit: "horizon-qualify-225-natural-root-resource-shrink-budget-test.service".into(),
            invocation_id: claim.invocation_id.clone(),
            scratch_path: "/home/ubuntu/.jetstreamer-private/qualification-225-v1625-natural-root-shrink-budget-test".into(),
            launch_receipt: BoundFile { path: "/sealed/shrink-launch.json".into(), sha256: "b".repeat(64) },
        };
        let mut shrink = receipt.clone();
        shrink["schema"] =
            json!("jetstreamer-private-epoch225-shrink-natural-root-resource-launch-v1");
        shrink["worker_sha256"] =
            json!("2dcc9b84a6ce27edba3d3b053c6e6170f66a2337f12a5aae54900c3ad9e2eedd");
        shrink["private_run_root"] = json!(shrink_claim.scratch_path);
        shrink["evidence"]["units"][0]["unit"] = json!(shrink_claim.unit);
        validate_diagnostic_launch(&shrink, &shrink_claim).unwrap();
        assert_eq!(diagnostic_scope(&shrink_claim), 225..=226);
        for (key, value) in [
            ("schema", receipt["schema"].clone()),
            ("worker_sha256", receipt["worker_sha256"].clone()),
            ("node_sha256", json!("c".repeat(64))),
            ("terminal_root_slot", json!(97631459)),
            ("output_slot_count", json!(432000)),
            ("required_checkpoints", json!([97199617, 98063464])),
            ("private_verification_tail_slots", json!(0)),
            ("natural_parent_completion_required", json!(false)),
            ("runtime_promotion_authorized", json!(true)),
            ("publication_authorized", json!(true)),
        ] {
            let mut bad = shrink.clone();
            bad[key] = value;
            assert!(
                validate_diagnostic_launch(&bad, &shrink_claim).is_err(),
                "shrink {key}"
            );
        }
        shrink_claim.unit = claim.unit.clone();
        shrink["evidence"]["units"][0]["unit"] = json!(shrink_claim.unit);
        assert!(validate_diagnostic_launch(&shrink, &shrink_claim).is_err());
        for (key, value) in [
            (
                "schema",
                json!("jetstreamer-private-epoch225-v1625-bounded-launch-v1"),
            ),
            ("epoch", json!(226)),
            ("snapshot_slot", json!(97199618)),
            ("snapshot_sha256", json!("c".repeat(64))),
            ("worker_sha256", json!("c".repeat(64))),
            ("node_sha256", json!("c".repeat(64))),
            ("runtime", json!("solana-v1.6.20")),
            ("runtime_semantics_changed", json!(false)),
            ("solana_rayon_threads", json!(1)),
            ("output_slot_start", json!(97199618)),
            ("output_slot_count", json!(432000)),
            ("canonical_epoch_end", json!(97631459)),
            ("terminal_root_slot", json!(97631459)),
            ("required_checkpoints", json!([97199617, 98063464])),
            ("private_verification_tail_epoch", json!(225)),
            ("private_verification_tail_slots", json!(0)),
            ("natural_parent_completion_required", json!(false)),
            ("maximum_runtime_seconds", json!(604801)),
            ("natural_root_resource_attempt_authorized", json!(false)),
            ("full_span_independently_qualified", json!(true)),
            ("full_cold_epoch_peak_qualified", json!(true)),
            ("ordinary_replay_authorized", json!(true)),
            ("runtime_promotion_authorized", json!(true)),
            ("canonical_sidecar_authorized", json!(true)),
            ("publication_authorized", json!(true)),
            ("remote_mutations", json!(true)),
            ("r2_mutations", json!(true)),
        ] {
            let mut bad = receipt.clone();
            bad[key] = value;
            assert!(validate_diagnostic_launch(&bad, &claim).is_err(), "{key}");
            bad = receipt.clone();
            bad.as_object_mut().unwrap().remove(key);
            assert!(
                validate_diagnostic_launch(&bad, &claim).is_err(),
                "missing {key}"
            );
        }
        let mut bad = receipt.clone();
        bad["evidence"]["units"][0]["invocation_id"] = json!("c".repeat(32));
        assert!(validate_diagnostic_launch(&bad, &claim).is_err());
        claim.unit = "horizon-qualify-225-bounded-resource-test.service".into();
        assert_eq!(diagnostic_scope(&claim), 225..=225);
        assert!(validate_diagnostic_launch(&receipt, &claim).is_err());
        claim.unit = "horizon-qualify-225-natural-root-resource-test.service".into();
        claim.scratch_path = "/home/ubuntu/horizon".into();
        bad = receipt.clone();
        bad["private_run_root"] = json!(claim.scratch_path);
        assert!(validate_diagnostic_launch(&bad, &claim).is_err());
    }

    #[test]
    fn natural_root_225_admission_is_not_a_target_stop_exemption() {
        let (previous, mut plan, mut guard, mut gp) = admission_fixture();
        let name = "horizon-qualify-225-natural-root-resource-test.service";
        plan.diagnostics[1].unit = name.into();
        gp["unit"] = json!(name);
        gp.as_object_mut().unwrap().remove("bounded_canary");
        guard["producer"]["cgroup"] = json!(format!("/system.slice/{name}"));
        guard["guard_sha256"] =
            json!("cc3536dfcc268c913feccf1603a25e3cdbdf2807289c9061e04884027d1b1560");
        let sample = "2026-10-20T00:04:42Z";
        validate_same_sample_admission(&previous, &plan, sample, &guard, &gp, 1792455200).unwrap();
        for (key, value) in [
            ("bounded_canary", json!({"expected_uid":1000})),
            ("bounded_measurement", json!({})),
            ("minimum_free_bytes", json!(1_606_264_251_502u64)),
        ] {
            let mut bad = gp.clone();
            bad[key] = value;
            let mut matching_guard = guard.clone();
            matching_guard["minimum_free_bytes"] = bad["minimum_free_bytes"].clone();
            assert!(
                validate_same_sample_admission(
                    &previous,
                    &plan,
                    sample,
                    &matching_guard,
                    &bad,
                    1792455200
                )
                .is_err(),
                "{key}"
            );
        }
        for (key, value) in [
            ("workers", json!([])),
            ("workers", json!([[123, 100], [124, 100]])),
            ("workers", json!([[123, 3500001]])),
            (
                "guard_sha256",
                json!("61e189bb50d58fa446b84f016d3b19433c30f490c6d470907130f113a01b644a"),
            ),
        ] {
            let mut bad = guard.clone();
            bad[key] = value;
            assert!(
                validate_same_sample_admission(&previous, &plan, sample, &bad, &gp, 1792455200)
                    .is_err(),
                "{key}"
            );
        }
    }

    fn admission_fixture() -> (Value, Plan, Value, Value) {
        let prior = json!({"epoch":213,"unit":{"Id":"old.service"},"launch_invocation_id":"a".repeat(32),"launch_receipt":"/old/launch.json","launch_receipt_sha256":"b".repeat(64)});
        let old_claim = json!({"epoch":213,"unit":"old.service","invocation_id":"a".repeat(32),"scratch_path":"/old/scratch","launch_receipt":{"path":"/old/launch.json","sha256":"b".repeat(64)}});
        let new_claim = json!({"epoch":225,"unit":"horizon-qualify-225-bounded-resource-test.service","invocation_id":"c".repeat(32),"scratch_path":"/new/scratch","launch_receipt":{"path":"/new/launch.json","sha256":"d".repeat(64)}});
        let previous = json!({"schema":SCHEMA,"first_epoch":201,"last_epoch":300,"sampled_at_utc":"2026-10-20T00:04:42Z","observer_receipt":"/observer.json","observer_sha256":"e".repeat(64),"recorded_unix_seconds":1792454800u64,"diagnostics":[prior]});
        let plan:Plan=serde_json::from_value(json!({"schema":"jetstreamer-horizon-campaign-fleet-plan-v1","first_epoch":201,"last_epoch":300,"observer":{"path":"/observer.json","sha256":"e".repeat(64)},"previous_fleet":{"path":"/previous.json","sha256":"f".repeat(64)},"output":"/output.json","status_receipt_directory":"/receipts","gates":{},"tracked_units":["old.service"],"diagnostics":[old_claim,new_claim],"admission_transition_guard":{"path":"/guard.json","sha256":"a".repeat(64)}})).unwrap();
        let guard = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","guard_sha256":"61e189bb50d58fa446b84f016d3b19433c30f490c6d470907130f113a01b644a","recorded_unix_seconds":1792455124u64,"producer_invocation_id":"c".repeat(32),"producer":{"invocation_id":"c".repeat(32),"cgroup":"/system.slice/horizon-qualify-225-bounded-resource-test.service","active":"active","sub":"running","load_state":"loaded","result":"success","restart_policy":"no","kill_mode":"control-group","delegated":false,"restarts":0,"pid":123},"trip_reason":null,"worker_observation_error":null,"canary_target_error":null,"workers":[[124,416937]],"maximum_worker_vmas":3500000,"minimum_free_bytes":2910800286422u64,"available_bytes":3605067464704u64,"r2_mutations":false,"remote_mutations":false});
        let guard_plan = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":"horizon-qualify-225-bounded-resource-test.service","invocation_id":"c".repeat(32),"worker_root":"/new/scratch","bounded_canary":{"expected_uid":1000},"maximum_worker_vmas":3500000,"minimum_free_bytes":2910800286422u64});
        (previous, plan, guard, guard_plan)
    }
    #[test]
    fn tail223_same_sample_admission_binds_nested_worker_root_at_real_call_site() {
        let (previous, mut plan, mut guard, mut gp) = admission_fixture();
        let (mut claim, launch) = tail223::tests::fixture();
        claim.invocation_id = "c".repeat(32);
        let root = tempfile::tempdir().unwrap();
        let bytes = serde_json::to_vec(&launch).unwrap();
        let path = root.path().join("tail-launch.json");
        fs::write(&path, &bytes).unwrap();
        claim.launch_receipt = BoundFile {
            path,
            sha256: hex_lower(&Sha256::digest(&bytes)),
        };
        gp["unit"] = json!(claim.unit);
        gp["worker_root"] = json!(claim.scratch_path.join("scratch"));
        gp["filesystem"] = json!("/");
        gp["minimum_free_bytes"] = json!(3024728567181u64);
        gp.as_object_mut().unwrap().remove("bounded_canary");
        guard["producer"]["cgroup"] = json!(format!("/system.slice/{}", claim.unit));
        guard["guard_sha256"] = json!(tail223::GUARD_SHA);
        guard["minimum_free_bytes"] = gp["minimum_free_bytes"].clone();
        plan.diagnostics[1] = claim;
        let check = |g: &Value, p: &Value| {
            validate_same_sample_admission(
                &previous,
                &plan,
                "2026-10-20T00:04:42Z",
                g,
                p,
                1792455200,
            )
        };
        check(&guard, &gp).unwrap();
        for path in [
            plan.diagnostics[1].scratch_path.clone(),
            root.path().to_owned(),
            plan.diagnostics[1].scratch_path.join("scratch-other"),
        ] {
            let mut bad = gp.clone();
            bad["worker_root"] = json!(path);
            assert!(check(&guard, &bad).is_err());
        }
        for workers in [
            json!([]),
            json!([[124, 10], [125, 10]]),
            json!([[124, 3500001]]),
        ] {
            let mut bad = guard.clone();
            bad["workers"] = workers;
            assert!(check(&bad, &gp).is_err());
        }
        let mut bad = gp.clone();
        bad["bounded_canary"] = json!({"expected_uid":1000});
        assert!(check(&guard, &bad).is_err());
    }

    #[test]
    fn prefix223_same_sample_admission_keeps_natural_root_and_exact_guard_envelope() {
        let (previous, mut plan, mut guard, mut gp) = admission_fixture();
        let (mut claim, launch) = prefix223::tests::fixture();
        claim.invocation_id = "c".repeat(32);
        let root = tempfile::tempdir().unwrap();
        let bytes = serde_json::to_vec(&launch).unwrap();
        let path = root.path().join("prefix-launch.json");
        fs::write(&path, &bytes).unwrap();
        claim.launch_receipt = BoundFile {
            path,
            sha256: hex_lower(&Sha256::digest(&bytes)),
        };
        gp["unit"] = json!(claim.unit);
        gp["worker_root"] = json!(claim.scratch_path.join("scratch"));
        gp["filesystem"] = json!("/");
        gp["minimum_free_bytes"] = json!(1004203426707u64);
        gp.as_object_mut().unwrap().remove("bounded_canary");
        guard["producer"]["cgroup"] = json!(format!("/system.slice/{}", claim.unit));
        guard["guard_sha256"] = json!(prefix223::GUARD_SHA);
        guard["minimum_free_bytes"] = gp["minimum_free_bytes"].clone();
        plan.diagnostics[1] = claim;
        let check = |g: &Value, p: &Value| {
            validate_same_sample_admission(
                &previous,
                &plan,
                "2026-10-20T00:04:42Z",
                g,
                p,
                1792455200,
            )
        };
        check(&guard, &gp).unwrap();
        let mut bad = gp.clone();
        bad["minimum_free_bytes"] = json!(1004203426706u64);
        assert!(check(&guard, &bad).is_err());
        let mut bad = gp.clone();
        bad["worker_root"] = json!(plan.diagnostics[1].scratch_path);
        assert!(check(&guard, &bad).is_err());
        let mut bad = guard.clone();
        bad["workers"] = json!([]);
        assert!(check(&bad, &gp).is_err());
    }
    #[test]
    fn natural_root_prefix_admission_still_requires_one_real_worker_and_protection() {
        let (previous, mut plan, mut guard, mut gp) = admission_fixture();
        let name = "horizon-qualify-203-root-prefix-resource-test.service";
        plan.diagnostics[1].epoch = 203;
        plan.diagnostics[1].unit = name.into();
        gp["unit"] = json!(name);
        gp.as_object_mut().unwrap().remove("bounded_canary");
        guard["producer"]["cgroup"] = json!(format!("/system.slice/{name}"));
        guard["guard_sha256"] =
            json!("cc3536dfcc268c913feccf1603a25e3cdbdf2807289c9061e04884027d1b1560");
        validate_same_sample_admission(
            &previous,
            &plan,
            "2026-10-20T00:04:42Z",
            &guard,
            &gp,
            1792455200,
        )
        .unwrap();
        let mut bad = guard.clone();
        bad["workers"] = json!([]);
        assert!(
            validate_same_sample_admission(
                &previous,
                &plan,
                "2026-10-20T00:04:42Z",
                &bad,
                &gp,
                1792455200
            )
            .is_err()
        );
        gp["minimum_free_bytes"] = json!(2_158_885_108_874u64);
        guard["minimum_free_bytes"] = gp["minimum_free_bytes"].clone();
        assert!(
            validate_same_sample_admission(
                &previous,
                &plan,
                "2026-10-20T00:04:42Z",
                &guard,
                &gp,
                1792455200
            )
            .is_err()
        );
    }
    #[test]
    fn root_prefix_launch_is_exact_and_not_full_epoch_or_peak_qualification() {
        let claim = DiagnosticClaim {
            epoch: 203,
            unit: "horizon-qualify-203-root-prefix-resource-test.service".into(),
            invocation_id: "a".repeat(32),
            scratch_path: "/home/ubuntu/.jetstreamer-private/root-prefix-resource-203-test".into(),
            launch_receipt: BoundFile {
                path: "/sealed/launch.json".into(),
                sha256: "b".repeat(64),
            },
        };
        let r = json!({"schema":"jetstreamer-private-epoch203-root-prefix-resource-launch-v1","launched":true,
            "epoch":203,"private_run_root":claim.scratch_path,"snapshot_slot":87695515,
            "snapshot_sha256":"e45584858d0c825f095a43ff5e5909e62a68d197d39c042a76727454525228c4",
            "worker_sha256":"3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a",
            "node_sha256":"025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d",
            "runner_sha256":"dee8959e8436ebd856b5b8d7e18f06464377b26fadb3a7a9f09ab158f9fd4a4e",
            "runtime":"solana-v1.6.16","runtime_semantics_changed":false,"solana_rayon_threads":16,
            "output_slot_start":87696000,"output_slot_count":431581,"terminal_root_slot":88127580,
            "natural_parent_completion_required":true,"maximum_terminal_scratch_bytes":768u64<<30,
            "maximum_runtime_seconds":259200,"root_prefix_resource_attempt_authorized":true,
            "canonical_prefix_independently_qualified":false,"full_cold_epoch_peak_qualified":false,
            "ordinary_replay_authorized":false,"runtime_promotion_authorized":false,
            "canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false,
            "evidence":{"units":[{"unit":claim.unit,"invocation_id":claim.invocation_id,
                "restarts":0,"load_state":"loaded","active_state":"active","sub_state":"running","main_pid":123,"result":"success"}]}});
        validate_diagnostic_launch(&r, &claim).unwrap();
        for (key, value) in [
            ("output_slot_count", json!(432000)),
            ("terminal_root_slot", json!(88127999)),
            ("worker_sha256", json!("c".repeat(64))),
            ("natural_parent_completion_required", json!(false)),
            ("canonical_prefix_independently_qualified", json!(true)),
            ("full_cold_epoch_peak_qualified", json!(true)),
            ("ordinary_replay_authorized", json!(true)),
            ("publication_authorized", json!(true)),
        ] {
            let mut bad = r.clone();
            bad[key] = value;
            assert!(
                validate_diagnostic_launch(&bad, &claim).is_err(),
                "accepted {key}"
            );
        }
    }
    #[test]
    fn same_sample_admission_is_one_guarded_event_not_another_poll() {
        let (previous, plan, guard, gp) = admission_fixture();
        validate_same_sample_admission(
            &previous,
            &plan,
            "2026-10-20T00:04:42Z",
            &guard,
            &gp,
            1792455200,
        )
        .unwrap();
        assert!(
            validate_previous_fleet(&previous, 201, 300, "2026-10-20T00:04:42Z").is_err(),
            "ordinary reconciliation must still advance"
        );
        let mut changed = previous.clone();
        changed["admission_transition_guard"] = json!({"path":"/prior-guard.json"});
        assert!(
            validate_same_sample_admission(
                &changed,
                &plan,
                "2026-10-20T00:04:42Z",
                &guard,
                &gp,
                1792455200
            )
            .is_err()
        );
        let mut changed = previous;
        changed["observer_sha256"] = json!("0".repeat(64));
        assert!(
            validate_same_sample_admission(
                &changed,
                &plan,
                "2026-10-20T00:04:42Z",
                &guard,
                &gp,
                1792455200
            )
            .is_err()
        );
    }
    #[test]
    fn same_sample_admission_preserves_every_historical_claim() {
        let (previous, mut plan, guard, gp) = admission_fixture();
        plan.diagnostics[0].invocation_id = "0".repeat(32);
        assert!(
            validate_same_sample_admission(
                &previous,
                &plan,
                "2026-10-20T00:04:42Z",
                &guard,
                &gp,
                1792455200
            )
            .is_err()
        );
        let (previous, mut plan, guard, gp) = admission_fixture();
        plan.diagnostics.pop();
        assert!(
            validate_same_sample_admission(
                &previous,
                &plan,
                "2026-10-20T00:04:42Z",
                &guard,
                &gp,
                1792455200
            )
            .is_err()
        );
        let (previous, mut plan, guard, gp) = admission_fixture();
        plan.diagnostics[1].epoch = 226;
        assert!(
            validate_same_sample_admission(
                &previous,
                &plan,
                "2026-10-20T00:04:42Z",
                &guard,
                &gp,
                1792455200
            )
            .is_err()
        );
    }
    #[test]
    fn same_sample_admission_fails_on_stale_unsafe_or_unreadable_guard() {
        let (previous, plan, guard, gp) = admission_fixture();
        for (pointer, value) in [
            ("/guard_sha256", json!("0".repeat(64))),
            ("/recorded_unix_seconds", json!(1792454000u64)),
            ("/recorded_unix_seconds", json!(1792455300u64)),
            ("/producer/restarts", json!(1)),
            ("/producer/invocation_id", json!("other")),
            ("/producer/delegated", json!(true)),
            ("/trip_reason", json!("reserve")),
            ("/worker_observation_error", json!("unreadable")),
            ("/canary_target_error", json!("bad intent")),
            ("/workers", json!([])),
            ("/workers", json!([[1, 2], [3, 4]])),
            ("/workers", json!([[124, 3500001]])),
            ("/available_bytes", json!(1)),
        ] {
            let mut changed = guard.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate_same_sample_admission(
                    &previous,
                    &plan,
                    "2026-10-20T00:04:42Z",
                    &changed,
                    &gp,
                    1792455200
                )
                .is_err(),
                "{pointer}"
            );
        }
        assert!(
            validate_same_sample_admission(
                &previous,
                &plan,
                "2026-10-20T00:04:42Z",
                &guard,
                &gp,
                1792459000
            )
            .is_err()
        );
        let mut changed = guard;
        changed.as_object_mut().unwrap().remove("trip_reason");
        assert!(
            validate_same_sample_admission(
                &previous,
                &plan,
                "2026-10-20T00:04:42Z",
                &changed,
                &gp,
                1792455200
            )
            .is_err()
        );
    }
    #[test]
    fn same_sample_admission_guard_plan_must_match() {
        let (previous, plan, guard, gp) = admission_fixture();
        for (pointer, value) in [
            ("/unit", json!("foreign.service")),
            ("/invocation_id", json!("other")),
            ("/worker_root", json!("/different")),
            ("/maximum_worker_vmas", json!(4000000)),
            ("/minimum_free_bytes", json!(1)),
        ] {
            let mut changed = gp.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate_same_sample_admission(
                    &previous,
                    &plan,
                    "2026-10-20T00:04:42Z",
                    &guard,
                    &changed,
                    1792455200
                )
                .is_err()
            );
        }
    }
    #[test]
    fn private_213_verification_is_identity_bound_and_not_publication() {
        let claim = DiagnosticClaim {
            epoch: 213,
            unit: "horizon-qualify-213-private-verification-ccbe0f1-v1.service".into(),
            invocation_id: "a".repeat(32),
            scratch_path: "/var/lib/jetstreamer/horizon-213-private-scan-test".into(),
            launch_receipt: BoundFile {
                path: "/sealed/launch.json".into(),
                sha256: "b".repeat(64),
            },
        };
        let receipt = json!({"schema":"jetstreamer-private-epoch213-verification-launch-v1","launched":true,"epoch":213,"private_run_root":claim.scratch_path,"verifier_sha256":"8d9bd29c60c8ea5870e2169255acaae8d2f7436c4ec130dc8154d28cc4628130","producer_invocation_id":"1dfd29e7ced140b3ba407359cbdc0ee1","provenance_expectation_sha256":"f7bb330186a8fbcc438b0fa49e903af5be5a1c30092f7cd434a86f6b2916bea5","plan_sha256":"c".repeat(64),"replay_entries_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false,"evidence":{"units":[{"unit":claim.unit,"invocation_id":claim.invocation_id,"restarts":0,"load_state":"loaded","active_state":"active","sub_state":"running","main_pid":123,"result":"success"}]}});
        validate_diagnostic_launch(&receipt, &claim).unwrap();
        for (key, value) in [
            ("verifier_sha256", json!("0".repeat(64))),
            ("producer_invocation_id", json!("0".repeat(32))),
            ("plan_sha256", json!("c".repeat(63))),
            ("provenance_expectation_sha256", json!("0".repeat(64))),
            ("replay_entries_authorized", json!(true)),
            ("publication_authorized", json!(true)),
            ("canonical_sidecar_authorized", json!(true)),
        ] {
            let mut bad = receipt.clone();
            bad[key] = value;
            assert!(validate_diagnostic_launch(&bad, &claim).is_err(), "{key}");
        }
        let mut wrong = claim;
        wrong.scratch_path = "/home/ubuntu/horizon".into();
        let mut substituted = receipt;
        substituted["private_run_root"] = json!(wrong.scratch_path);
        assert!(validate_diagnostic_launch(&substituted, &wrong).is_err());
    }

    #[test]
    fn private_225_verification_is_exact_nonpromoting_and_covers_its_private_tail() {
        let mut claim = DiagnosticClaim {
            epoch: 225,
            unit: "horizon-qualify-225-private-verification-test-v1.service".into(),
            invocation_id: "a".repeat(32),
            scratch_path: "/var/lib/jetstreamer/horizon-225-private-scan-test".into(),
            launch_receipt: BoundFile {
                path: "/sealed/launch.json".into(),
                sha256: "b".repeat(64),
            },
        };
        let receipt = json!({
            "schema":"jetstreamer-private-epoch225-verification-launch-v1",
            "launched":true,"epoch":225,"private_run_root":claim.scratch_path,
            "verifier_sha256":"4cfa32a6956c3482891b9efe3b9e7c58135c8caddd40736bcf39a0bc7b6d9e2b",
            "producer_invocation_id":"ac9aee3d47eb41e483a5e008ed43d030",
            "archive_path":"/home/ubuntu/.jetstreamer-private/qualification-225-v1625-natural-root-63a2717-v1/output/epoch-225.jet",
            "output_slot_start":97200000,"terminal_slot":98063464,"output_slot_count":863465,
            "private_verification_tail_epoch":226,"private_verification_tail_slots":431465,
            "producer_natural_completion_confirmed":true,"plan_sha256":"c".repeat(64),
            "terminal_evidence":{"path":"/sealed/terminal.json","sha256":"d".repeat(64)},
            "expected_exec_start":format!("{{ path={PRIVATE_225_READER} ; argv[]={PRIVATE_225_READER} /private/archive ; ignore_errors=no }}"),
            "replay_entries_authorized":false,"runtime_promotion_authorized":false,
            "canonical_sidecar_authorized":false,"publication_authorized":false,
            "remote_mutations":false,"r2_mutations":false,
            "evidence":{"units":[{"unit":claim.unit,"invocation_id":claim.invocation_id,
                "restarts":0,"load_state":"loaded","active_state":"active","sub_state":"running",
                "main_pid":123,"result":"success"}]}
        });
        validate_diagnostic_launch(&receipt, &claim).unwrap();
        assert_eq!(diagnostic_scope(&claim), 225..=226);
        // Exercise the production pre-census loader: structurally valid launch
        // JSON must not hide missing, substituted or stopped-producer evidence.
        let root = tempfile::tempdir().unwrap();
        let terminal_path = root.path().join("terminal.json");
        let launch_path = root.path().join("launch.json");
        let terminal = private_225_terminal_fixture();
        let terminal_bytes = serde_json::to_vec(&terminal).unwrap();
        let mut checked_launch = receipt.clone();
        checked_launch["terminal_evidence"] = json!({"path":terminal_path,
            "sha256":hex_lower(&Sha256::digest(&terminal_bytes))});
        let launch_bytes = serde_json::to_vec(&checked_launch).unwrap();
        fs::write(&launch_path, &launch_bytes).unwrap();
        claim.launch_receipt = BoundFile {
            path: launch_path,
            sha256: hex_lower(&Sha256::digest(&launch_bytes)),
        };
        assert!(checked_diagnostic_launch(&claim).is_err());
        fs::write(&terminal_path, &terminal_bytes).unwrap();
        checked_diagnostic_launch(&claim).unwrap();
        fs::write(&terminal_path, b"{}\n").unwrap();
        assert!(checked_diagnostic_launch(&claim).is_err());
        let mut stopped = terminal;
        stopped["deliberate_stop"] = json!(true);
        let bytes = serde_json::to_vec(&stopped).unwrap();
        fs::write(&terminal_path, &bytes).unwrap();
        checked_launch["terminal_evidence"]["sha256"] = json!(hex_lower(&Sha256::digest(&bytes)));
        let bytes = serde_json::to_vec(&checked_launch).unwrap();
        fs::write(&claim.launch_receipt.path, &bytes).unwrap();
        claim.launch_receipt.sha256 = hex_lower(&Sha256::digest(&bytes));
        assert!(checked_diagnostic_launch(&claim).is_err());
        let mut live = BTreeSet::new();
        register_live_diagnostic_scope(&mut live, &claim).unwrap();
        assert!(register_live_diagnostic_scope(&mut live, &claim).is_err());
        assert_eq!(live, BTreeSet::from([225, 226]));
        for (key, value) in [
            (
                "schema",
                json!("jetstreamer-private-epoch213-verification-launch-v1"),
            ),
            ("epoch", json!(226)),
            ("private_run_root", json!("/home/ubuntu/horizon")),
            ("verifier_sha256", json!("0".repeat(64))),
            ("producer_invocation_id", json!("0".repeat(32))),
            ("archive_path", json!("/home/ubuntu/horizon/epoch-225.jet")),
            ("output_slot_start", json!(97200001)),
            ("terminal_slot", json!(97631999)),
            ("output_slot_count", json!(432000)),
            ("private_verification_tail_epoch", json!(225)),
            ("private_verification_tail_slots", json!(0)),
            ("producer_natural_completion_confirmed", json!(false)),
            ("plan_sha256", json!("c".repeat(63))),
            (
                "terminal_evidence",
                json!({"path":"relative","sha256":"d".repeat(64)}),
            ),
            ("expected_exec_start", json!("/bin/true")),
            ("replay_entries_authorized", json!(true)),
            ("runtime_promotion_authorized", json!(true)),
            ("canonical_sidecar_authorized", json!(true)),
            ("publication_authorized", json!(true)),
            ("remote_mutations", json!(true)),
            ("r2_mutations", json!(true)),
        ] {
            let mut bad = receipt.clone();
            bad[key] = value;
            assert!(validate_diagnostic_launch(&bad, &claim).is_err(), "{key}");
            let mut missing = receipt.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(
                validate_diagnostic_launch(&missing, &claim).is_err(),
                "missing{key}"
            );
        }
        claim.scratch_path = "/home/ubuntu/horizon".into();
        let mut bad = receipt.clone();
        bad["private_run_root"] = json!(claim.scratch_path);
        assert!(validate_diagnostic_launch(&bad, &claim).is_err());
        claim.epoch = 213;
        assert!(!private_225_verification(&claim));
    }

    fn private_225_terminal_fixture() -> Value {
        json!({"schema":"jetstreamer-private-epoch225-natural-root-outcome-v1",
            "epoch":225,"producer_invocation_id":"ac9aee3d47eb41e483a5e008ed43d030",
            "natural_parent_exit_code":0,"deliberate_stop":false,"output_slot_start":97200000,
            "terminal_slot":98063464,"output_slot_count":863465,"segment_manifest_sha256":"a".repeat(64),
            "producer_journal_sha256":"b".repeat(64),"manager_journal_sha256":"c".repeat(64),
            "full_span_independently_qualified":false,"runtime_promotion_authorized":false,
            "canonical_sidecar_authorized":false,"publication_authorized":false,
            "remote_mutations":false,"r2_mutations":false})
    }

    #[test]
    fn private_225_verification_rejects_stopped_incomplete_or_unbound_terminal_evidence() {
        let receipt = private_225_terminal_fixture();
        validate_private_225_terminal(&receipt).unwrap();
        for (key, value) in [
            (
                "schema",
                json!("jetstreamer-private-epoch225-v1625-bounded-outcome-v1"),
            ),
            ("epoch", json!(224)),
            ("producer_invocation_id", json!("a".repeat(32))),
            ("natural_parent_exit_code", json!(1)),
            ("deliberate_stop", json!(true)),
            ("output_slot_start", json!(97200001)),
            ("terminal_slot", json!(97631459)),
            ("output_slot_count", json!(432000)),
            ("segment_manifest_sha256", json!("A".repeat(64))),
            ("producer_journal_sha256", json!("")),
            ("manager_journal_sha256", json!(null)),
            ("full_span_independently_qualified", json!(true)),
            ("runtime_promotion_authorized", json!(true)),
            ("canonical_sidecar_authorized", json!(true)),
            ("publication_authorized", json!(true)),
            ("remote_mutations", json!(true)),
            ("r2_mutations", json!(true)),
        ] {
            let mut bad = receipt.clone();
            bad[key] = value;
            assert!(validate_private_225_terminal(&bad).is_err(), "{key}");
            let mut missing = receipt.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(
                validate_private_225_terminal(&missing).is_err(),
                "missing{key}"
            );
        }
    }
    #[test]
    fn bounded_203_has_an_exact_nonpromoting_launch_schema() {
        let claim = DiagnosticClaim {
            epoch: 203,
            unit: "horizon-qualify-203-bounded-resource-store8-test.service".into(),
            invocation_id: "a".repeat(32),
            scratch_path: "/private/203".into(),
            launch_receipt: BoundFile {
                path: "/private/launch.json".into(),
                sha256: "b".repeat(64),
            },
        };
        let receipt = json!({"schema":"jetstreamer-private-epoch203-bounded-resource-launch-v1","launched":true,"epoch":203,"private_run_root":claim.scratch_path,"snapshot_slot":87695515,"snapshot_sha256":"e45584858d0c825f095a43ff5e5909e62a68d197d39c042a76727454525228c4","worker_sha256":"3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a","runner_sha256":"bc9a75b420210a93b6ab65d28bd82d1fe2748c95541394bfae2e0f0f5153bf12","runtime":"solana-v1.6.16","runtime_semantics_changed":false,"target_slot":87720000,"terminal_root_slot":88127580,"bounded_replay_authorized":true,"ordinary_replay_authorized":false,"canonical_prefix_qualified":false,"full_cold_epoch_peak_qualified":false,"runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false,"evidence":{"units":[{"unit":claim.unit,"invocation_id":claim.invocation_id,"restarts":0,"load_state":"loaded","active_state":"active","sub_state":"running","main_pid":123,"result":"success"}]}});
        validate_diagnostic_launch(&receipt, &claim).unwrap();
        for (key, value) in [
            (
                "schema",
                json!("jetstreamer-private-epoch225-bounded-resource-launch-v1"),
            ),
            ("snapshot_slot", json!(87695516)),
            ("worker_sha256", json!("0".repeat(64))),
            ("runner_sha256", json!("0".repeat(64))),
            ("runtime_semantics_changed", json!(true)),
            ("target_slot", json!(88127580)),
            ("terminal_root_slot", json!(88559361)),
            ("canonical_prefix_qualified", json!(true)),
            ("runtime_promotion_authorized", json!(true)),
            ("publication_authorized", json!(true)),
            ("full_cold_epoch_peak_qualified", json!(true)),
        ] {
            let mut bad = receipt.clone();
            bad[key] = value;
            assert!(validate_diagnostic_launch(&bad, &claim).is_err(), "{key}");
        }
    }
    #[test]
    fn bounded_203_r1_runner_requires_its_exact_thread_count_and_namespace() {
        let mut claim = DiagnosticClaim {
            epoch: 203,
            unit: "horizon-qualify-203-bounded-resource-r1-test.service".into(),
            invocation_id: "a".repeat(32),
            scratch_path: "/private/203-r1".into(),
            launch_receipt: BoundFile {
                path: "/private/launch.json".into(),
                sha256: "b".repeat(64),
            },
        };
        let mut receipt = json!({"runner_sha256":"c041979fa0be26f6a35cb7063e962a666e71ddde74b1f680c53c210a0f7b1722","solana_rayon_threads":1});
        assert!(epoch203_resource_runner_matches(&claim, &receipt));
        receipt["solana_rayon_threads"] = json!(16);
        assert!(!epoch203_resource_runner_matches(&claim, &receipt));
        receipt["solana_rayon_threads"] = json!(1);
        claim.unit = "horizon-qualify-203-bounded-resource-store8-test.service".into();
        assert!(!epoch203_resource_runner_matches(&claim, &receipt));
        receipt["runner_sha256"] =
            json!("bc9a75b420210a93b6ab65d28bd82d1fe2748c95541394bfae2e0f0f5153bf12");
        assert!(!epoch203_resource_runner_matches(&claim, &receipt));
        receipt["solana_rayon_threads"] = json!(16);
        assert!(epoch203_resource_runner_matches(&claim, &receipt));
    }

    fn shrink_budget_203_fixture() -> (DiagnosticClaim, Value) {
        let claim = DiagnosticClaim {
            epoch: 203,
            unit: "horizon-qualify-203-bounded-resource-shrink-budget-test.service".into(),
            invocation_id: "a".repeat(32),
            scratch_path:
                "/home/ubuntu/.jetstreamer-private/bounded-resource-203-shrink-budget-test".into(),
            launch_receipt: BoundFile {
                path: "/private/launch.json".into(),
                sha256: "b".repeat(64),
            },
        };
        let receipt = json!({
            "schema":"jetstreamer-private-epoch203-shrink-budget-resource-launch-v1",
            "launched":true,"epoch":203,"private_run_root":claim.scratch_path,
            "snapshot_slot":87695515,
            "snapshot_sha256":"e45584858d0c825f095a43ff5e5909e62a68d197d39c042a76727454525228c4",
            "worker_sha256":"4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc",
            "node_sha256":"025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d",
            "runner_sha256":"d7b3f0c72f091426ce5679ebb237d7015cd054c2fa6953f811779a25736a2760",
            "runtime":"solana-v1.6.16","runtime_semantics_changed":false,
            "storage_maintenance_changed":true,"upstream_shrink_budget_cap":true,
            "solana_rayon_threads":16,"target_slot":87720000,"terminal_root_slot":88127580,
            "maximum_scratch_bytes":256u64<<30,"maximum_runtime_seconds":21600,
            "experimental_envelope_bytes":416u64<<30,
            "bounded_replay_authorized":true,"ordinary_replay_authorized":false,
            "canonical_prefix_qualified":false,"full_cold_epoch_peak_qualified":false,
            "runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,
            "publication_authorized":false,"remote_mutations":false,"r2_mutations":false,
            "evidence":{"units":[{"unit":claim.unit,"invocation_id":claim.invocation_id,
                "restarts":0,"load_state":"loaded","active_state":"active",
                "sub_state":"running","main_pid":123,"result":"success"}]}
        });
        (claim, receipt)
    }

    #[test]
    fn bounded_203_shrink_budget_requires_exact_candidate_and_nonpromotion_fields() {
        let (claim, receipt) = shrink_budget_203_fixture();
        validate_diagnostic_launch(&receipt, &claim).unwrap();
        for key in receipt.as_object().unwrap().keys() {
            let mut bad = receipt.clone();
            bad.as_object_mut().unwrap().remove(key);
            assert!(
                validate_diagnostic_launch(&bad, &claim).is_err(),
                "missing {key}"
            );
        }
        for (key, value) in [
            (
                "schema",
                json!("jetstreamer-private-epoch203-bounded-resource-launch-v1"),
            ),
            (
                "worker_sha256",
                json!("3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a"),
            ),
            ("node_sha256", json!("0".repeat(64))),
            (
                "runner_sha256",
                json!("bc9a75b420210a93b6ab65d28bd82d1fe2748c95541394bfae2e0f0f5153bf12"),
            ),
            ("snapshot_slot", json!(87695516)),
            ("snapshot_sha256", json!("0".repeat(64))),
            ("solana_rayon_threads", json!(1)),
            ("target_slot", json!(88127580)),
            ("terminal_root_slot", json!(88127999)),
            ("maximum_scratch_bytes", json!(768u64 << 30)),
            ("maximum_runtime_seconds", json!(21601)),
            ("experimental_envelope_bytes", json!(415u64 << 30)),
            ("runtime_semantics_changed", json!(true)),
            ("storage_maintenance_changed", json!(false)),
            ("upstream_shrink_budget_cap", json!(false)),
            ("canonical_prefix_qualified", json!(true)),
            ("full_cold_epoch_peak_qualified", json!(true)),
            ("runtime_promotion_authorized", json!(true)),
            ("canonical_sidecar_authorized", json!(true)),
            ("ordinary_replay_authorized", json!(true)),
            ("publication_authorized", json!(true)),
            ("remote_mutations", json!(true)),
            ("r2_mutations", json!(true)),
        ] {
            let mut bad = receipt.clone();
            bad[key] = value;
            assert!(validate_diagnostic_launch(&bad, &claim).is_err(), "{key}");
        }
    }

    #[test]
    fn bounded_203_shrink_budget_cannot_borrow_baseline_or_r1_namespaces() {
        let (mut claim, mut receipt) = shrink_budget_203_fixture();
        for unit in [
            "horizon-qualify-203-bounded-resource-store8-test.service",
            "horizon-qualify-203-bounded-resource-shrink-budget-r1-test.service",
            "horizon-qualify-203-root-prefix-resource-test.service",
            "horizon-qualify-203-bounded-resource-shrink-budget-test.timer",
        ] {
            claim.unit = unit.into();
            receipt["evidence"]["units"][0]["unit"] = json!(unit);
            assert!(
                validate_diagnostic_launch(&receipt, &claim).is_err(),
                "{unit}"
            );
        }
        let (mut claim, mut receipt) = shrink_budget_203_fixture();
        for root in [
            "/private/203",
            "/home/ubuntu/.jetstreamer-private/bounded-resource-203-test",
            "/home/ubuntu/.jetstreamer-private/bounded-resource-203-shrink-budget-r1-test",
        ] {
            claim.scratch_path = root.into();
            receipt["private_run_root"] = json!(root);
            assert!(
                validate_diagnostic_launch(&receipt, &claim).is_err(),
                "{root}"
            );
        }
        let (claim, mut receipt) = shrink_budget_203_fixture();
        receipt["runner_sha256"] =
            json!("bc9a75b420210a93b6ab65d28bd82d1fe2748c95541394bfae2e0f0f5153bf12");
        assert!(!epoch203_resource_runner_matches(&claim, &receipt));
    }

    #[test]
    fn bounded_203_shrink_budget_requires_own_guard_and_exact_target_handoff() {
        let (previous, mut plan, mut guard, mut gp) = admission_fixture();
        let (claim, _) = shrink_budget_203_fixture();
        plan.diagnostics[1].epoch = claim.epoch;
        plan.diagnostics[1].unit = claim.unit.clone();
        plan.diagnostics[1].scratch_path = claim.scratch_path.clone();
        gp["unit"] = json!(claim.unit);
        gp["worker_root"] = json!(claim.scratch_path);
        gp["bounded_canary"]["maximum_drainage_seconds"] = json!(180);
        gp["bounded_canary"]["target_stop_intent"] =
            json!(claim.scratch_path.join("receipts/target-stop.json"));
        guard["producer"]["cgroup"] = json!(format!("/system.slice/{}", claim.unit));
        let check = |g: &Value, p: &Value| {
            validate_same_sample_admission(
                &previous,
                &plan,
                "2026-10-20T00:04:42Z",
                g,
                p,
                1792455130,
            )
        };
        assert!(check(&guard, &gp).is_err());
        guard["guard_sha256"] =
            json!("d039ddf0b161bc554614a862bd12987bd6a3474549a22d066ebefa5584e5dd98");
        check(&guard, &gp).unwrap();
        for (pointer, value) in [
            ("/bounded_canary/expected_uid", json!(0)),
            ("/bounded_canary/maximum_drainage_seconds", json!(181)),
            (
                "/bounded_canary/target_stop_intent",
                json!("/other/target-stop.json"),
            ),
        ] {
            let mut bad = gp.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(check(&guard, &bad).is_err(), "{pointer}");
        }
        let mut bad = gp.clone();
        bad.as_object_mut().unwrap().remove("bounded_canary");
        assert!(check(&guard, &bad).is_err());
        let mut bad = gp.clone();
        bad["bounded_measurement"] = json!({});
        assert!(check(&guard, &bad).is_err());
        let (mut single_thread, _) = shrink_budget_203_fixture();
        single_thread.unit =
            "horizon-qualify-203-bounded-resource-shrink-budget-r1-test.service".into();
        assert!(!diagnostic_guard_profile_matches(&single_thread, &gp));
    }

    #[test]
    fn same_sample_diagnostic_preserves_exact_existing_pipeline_history() {
        let (_, mut previous, _, _) = admission_fixture();
        let pipeline = json!({"epoch":213,"phase":"upload-readback","unit":"horizon-upload-213-test.service",
            "invocation_id":"a".repeat(32),"expected_exec_start":"exact original command",
            "evidence":[{"path":"/proof.json","sha256":"b".repeat(64)}]});
        previous.pipeline_claims = vec![serde_json::from_value(pipeline.clone()).unwrap()];
        let (_, mut current, _, _) = admission_fixture();
        current.pipeline_claims = vec![serde_json::from_value(pipeline).unwrap()];
        preserve_pipeline_claims(&previous, &current).unwrap();
        current.pipeline_claims[0].invocation_id = "c".repeat(32);
        assert!(preserve_pipeline_claims(&previous, &current).is_err());
        current.pipeline_claims[0].invocation_id = "a".repeat(32);
        current.pipeline_claims[0].expected_exec_start = "substituted command".into();
        assert!(preserve_pipeline_claims(&previous, &current).is_err());
        current.pipeline_claims.clear();
        assert!(preserve_pipeline_claims(&previous, &current).is_err());
    }
    #[test]
    fn bounded_224_same_sample_admission_requires_its_exact_guard_and_target_path() {
        let (previous, mut plan, mut guard, mut gp) = admission_fixture();
        plan.diagnostics[1].epoch = 224;
        plan.diagnostics[1].unit = "horizon-qualify-224-bounded-resource-test.service".into();
        plan.diagnostics[1].scratch_path =
            "/home/ubuntu/.jetstreamer-private/bounded-resource-224-test".into();
        let claim = &plan.diagnostics[1];
        guard["producer"]["cgroup"] = json!(format!("/system.slice/{}", claim.unit));
        gp["unit"] = json!(claim.unit);
        gp["worker_root"] = json!(claim.scratch_path);
        gp["bounded_canary"]["maximum_drainage_seconds"] = json!(180);
        gp["bounded_canary"]["target_stop_intent"] =
            json!(claim.scratch_path.join("receipts/target-stop.json"));
        let sample = "2026-10-20T00:04:42Z";
        assert!(
            validate_same_sample_admission(&previous, &plan, sample, &guard, &gp, 1792455130)
                .is_err()
        );
        guard["guard_sha256"] =
            json!("f4f5c0758c1c02b7d9a3b2b1595af7bbc033997f671cd43f2d4a92d38c346c69");
        validate_same_sample_admission(&previous, &plan, sample, &guard, &gp, 1792455130).unwrap();
        gp["bounded_canary"]["target_stop_intent"] = json!("/other/receipts/target-stop.json");
        assert!(
            validate_same_sample_admission(&previous, &plan, sample, &guard, &gp, 1792455130)
                .is_err()
        );
    }

    #[test]
    fn bounded_203_same_sample_event_requires_its_own_guard_and_preserves_cadence() {
        let (previous, mut plan, mut guard, mut gp) = admission_fixture();
        plan.diagnostics[1].epoch = 203;
        plan.diagnostics[1].unit =
            "horizon-qualify-203-bounded-resource-store8-test.service".into();
        guard["producer"]["cgroup"] = json!(format!("/system.slice/{}", plan.diagnostics[1].unit));
        gp["unit"] = json!(plan.diagnostics[1].unit);
        assert!(
            validate_same_sample_admission(
                &previous,
                &plan,
                "2026-10-20T00:04:42Z",
                &guard,
                &gp,
                1792455200
            )
            .is_err()
        );
        guard["guard_sha256"] =
            json!("cc3536dfcc268c913feccf1603a25e3cdbdf2807289c9061e04884027d1b1560");
        validate_same_sample_admission(
            &previous,
            &plan,
            "2026-10-20T00:04:42Z",
            &guard,
            &gp,
            1792455200,
        )
        .unwrap();
        let mut transitioned = previous.clone();
        transitioned["admission_transition_guard"] = json!({"path":"/already-used.json"});
        assert!(
            validate_same_sample_admission(
                &transitioned,
                &plan,
                "2026-10-20T00:04:42Z",
                &guard,
                &gp,
                1792455200
            )
            .is_err()
        );
        assert!(
            validate_same_sample_admission(
                &previous,
                &plan,
                "2026-10-20T00:04:42Z",
                &guard,
                &gp,
                1792457000
            )
            .is_err()
        );
        assert!(validate_previous_fleet(&previous, 201, 300, "2026-10-20T00:04:42Z").is_err());
    }
    #[test]
    fn bounded_224_repair_is_exact_private_and_does_not_promote_its_target() {
        let claim = DiagnosticClaim {
            epoch: 224,
            unit: "horizon-qualify-224-bounded-resource-test.service".into(),
            invocation_id: "a".repeat(32),
            scratch_path: "/home/ubuntu/.jetstreamer-private/bounded-resource-224-test".into(),
            launch_receipt: BoundFile {
                path: "/private/launch.json".into(),
                sha256: "b".repeat(64),
            },
        };
        let receipt = json!({
            "schema":"jetstreamer-private-epoch224-bounded-resource-launch-v1",
            "launched":true,"epoch":224,"private_run_root":claim.scratch_path,
            "snapshot_slot":96767522,
            "snapshot_sha256":"dc7f2ac03813bc609629885af82222ac5af070cc6187b7bce08e10944fd214e1",
            "worker_sha256":"f26fb8598aef4091356be31a0ee322c2e428609f201390cce26ec60df9c62c45",
            "node_sha256":"bcb76f90515465ee3b19486a18da907d15d4a3fbe310d66e0c3912a5daa4e257",
            "runner_sha256":"eb2399944540f0a0cd7aadffe350047ab75dd946bc963370fa5c486689a6e381",
            "runtime":"solana-v1.6.25","runtime_semantics_changed":true,
            "solana_rayon_threads":16,"target_slot":96800000,"terminal_root_slot":97631459,
            "maximum_terminal_scratch_bytes":448u64<<30,"maximum_runtime_seconds":259200,
            "bounded_replay_authorized":true,"ordinary_replay_authorized":false,
            "full_cold_epoch_peak_qualified":false,"canonical_prefix_qualified":false,
            "runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,
            "publication_authorized":false,"remote_mutations":false,"r2_mutations":false,
            "evidence":{"units":[{"unit":claim.unit,"invocation_id":claim.invocation_id,
                "restarts":0,"load_state":"loaded","active_state":"active","sub_state":"running",
                "main_pid":123,"result":"success"}]}
        });
        validate_diagnostic_launch(&receipt, &claim).unwrap();
        for (key, value) in [
            ("epoch", json!(225)),
            ("target_slot", json!(97199999)),
            ("terminal_root_slot", json!(97199617)),
            ("snapshot_slot", json!(96767523)),
            ("worker_sha256", json!("0".repeat(64))),
            ("node_sha256", json!("0".repeat(64))),
            ("runner_sha256", json!("0".repeat(64))),
            ("solana_rayon_threads", json!(1)),
            ("maximum_terminal_scratch_bytes", json!(449u64 << 30)),
            ("maximum_runtime_seconds", json!(259201)),
            ("runtime_semantics_changed", json!(false)),
            ("ordinary_replay_authorized", json!(true)),
            ("publication_authorized", json!(true)),
            ("full_cold_epoch_peak_qualified", json!(true)),
            ("canonical_prefix_qualified", json!(true)),
            ("runtime_promotion_authorized", json!(true)),
            ("canonical_sidecar_authorized", json!(true)),
        ] {
            let mut bad = receipt.clone();
            bad[key] = value;
            assert!(validate_diagnostic_launch(&bad, &claim).is_err(), "{key}");
        }
        let wrong = DiagnosticClaim {
            epoch: claim.epoch,
            unit: claim.unit.clone(),
            invocation_id: claim.invocation_id.clone(),
            scratch_path: "/home/ubuntu/horizon".into(),
            launch_receipt: BoundFile {
                path: claim.launch_receipt.path.clone(),
                sha256: claim.launch_receipt.sha256.clone(),
            },
        };
        let mut bad = receipt.clone();
        bad["private_run_root"] = json!(wrong.scratch_path);
        assert!(validate_diagnostic_launch(&bad, &wrong).is_err());
        let guard = json!({"bounded_canary":{"expected_uid":1000,"maximum_drainage_seconds":180,
            "target_stop_intent":claim.scratch_path.join("receipts/target-stop.json")}});
        assert!(diagnostic_guard_profile_matches(&claim, &guard));
        let mut bad = guard.clone();
        bad["bounded_canary"]["maximum_drainage_seconds"] = json!(181);
        assert!(!diagnostic_guard_profile_matches(&claim, &bad));
        let mut bad = guard;
        bad["bounded_canary"]["target_stop_intent"] = json!("/other/receipts/target-stop.json");
        assert!(!diagnostic_guard_profile_matches(&claim, &bad));
    }

    #[test]
    fn bounded_225_replay_is_diagnostic_only_and_cannot_expand_its_target() {
        let claim = DiagnosticClaim {
            epoch: 225,
            unit: "horizon-qualify-225-bounded-resource-test.service".into(),
            invocation_id: "a".repeat(32),
            scratch_path: "/private/bounded-225".into(),
            launch_receipt: BoundFile {
                path: "/private/launch.json".into(),
                sha256: "b".repeat(64),
            },
        };
        let receipt = json!({"schema":"jetstreamer-private-epoch225-bounded-resource-launch-v1","launched":true,"epoch":225,"private_run_root":claim.scratch_path,"snapshot_slot":97199617,"snapshot_sha256":"094d3b28c39403580fbac083cdad67cc008b255dd375d611217103750d0f412d","worker_sha256":"f39140b9a9659e7c6e8207076a2d0c560a6b69df42cc92e19a421cf46c2b761c","target_slot":97202500,"terminal_root_slot":97631459,"bounded_replay_authorized":true,"ordinary_replay_authorized":false,"full_cold_epoch_peak_qualified":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false,"evidence":{"units":[{"unit":claim.unit,"invocation_id":claim.invocation_id,"restarts":0,"load_state":"loaded","active_state":"active","sub_state":"running","main_pid":123,"result":"success"}]}});
        validate_diagnostic_launch(&receipt, &claim).unwrap();
        for (key, value) in [
            ("target_slot", json!(97202501)),
            ("terminal_root_slot", json!(97631458)),
            ("ordinary_replay_authorized", json!(true)),
            ("full_cold_epoch_peak_qualified", json!(true)),
            ("bounded_replay_authorized", json!(false)),
            ("publication_authorized", json!(true)),
        ] {
            let mut bad = receipt.clone();
            bad[key] = value;
            assert!(validate_diagnostic_launch(&bad, &claim).is_err(), "{key}");
        }
    }
    #[test]
    fn bounded_v1625_is_separately_labeled_and_cannot_promote_or_expand() {
        let claim = DiagnosticClaim {
            epoch: 225,
            unit: "horizon-qualify-225-bounded-resource-v1625-test.service".into(),
            invocation_id: "a".repeat(32),
            scratch_path: "/private/225-v1625".into(),
            launch_receipt: BoundFile {
                path: "/private/launch.json".into(),
                sha256: "b".repeat(64),
            },
        };
        let receipt = json!({"schema":"jetstreamer-private-epoch225-v1625-bounded-launch-v1","launched":true,"epoch":225,"private_run_root":claim.scratch_path,"snapshot_slot":97199617,"snapshot_sha256":"094d3b28c39403580fbac083cdad67cc008b255dd375d611217103750d0f412d","worker_sha256":"74f805991023434932080b6db20385d36ec26d8a1dd9bbd7a33848099145859a","comparison_runtime":"solana-v1.6.25","runtime_semantics_changed":true,"worker_entry_end_exclusive":97202600,"runtime_promotion_authorized":false,"target_slot":97202500,"terminal_root_slot":97631459,"bounded_replay_authorized":true,"ordinary_replay_authorized":false,"full_cold_epoch_peak_qualified":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false,"evidence":{"units":[{"unit":claim.unit,"invocation_id":claim.invocation_id,"restarts":0,"load_state":"loaded","active_state":"active","sub_state":"running","main_pid":123,"result":"success"}]}});
        validate_diagnostic_launch(&receipt, &claim).unwrap();
        for (key, value) in [
            (
                "worker_sha256",
                json!("f39140b9a9659e7c6e8207076a2d0c560a6b69df42cc92e19a421cf46c2b761c"),
            ),
            ("runtime_semantics_changed", json!(false)),
            ("worker_entry_end_exclusive", json!(97202601)),
            ("runtime_promotion_authorized", json!(true)),
            (
                "schema",
                json!("jetstreamer-private-epoch225-bounded-resource-launch-v1"),
            ),
            ("target_slot", json!(97202501)),
        ] {
            let mut bad = receipt.clone();
            bad[key] = value;
            assert!(validate_diagnostic_launch(&bad, &claim).is_err(), "{key}");
        }
    }
    #[test]
    fn bootstrap_resource_claim_is_exact_and_cannot_authorize_replay_or_publication() {
        let claim = DiagnosticClaim {
            epoch: 225,
            unit: "horizon-qualify-225-bootstrap-resource-test.service".into(),
            invocation_id: "a".repeat(32),
            scratch_path: "/private/resource-225".into(),
            launch_receipt: BoundFile {
                path: "/private/launch.json".into(),
                sha256: "b".repeat(64),
            },
        };
        let receipt = json!({"schema":"jetstreamer-private-epoch225-bootstrap-resource-launch-v1",
            "launched":true,"epoch":225,"private_run_root":claim.scratch_path,
            "snapshot_slot":97199617u64,
            "snapshot_sha256":"094d3b28c39403580fbac083cdad67cc008b255dd375d611217103750d0f412d",
            "worker_sha256":"f39140b9a9659e7c6e8207076a2d0c560a6b69df42cc92e19a421cf46c2b761c",
            "replay_entries_authorized":false,"full_cold_epoch_peak_qualified":false,
            "canonical_sidecar_authorized":false,"publication_authorized":false,
            "remote_mutations":false,"r2_mutations":false,
            "evidence":{"units":[{"unit":claim.unit,"invocation_id":claim.invocation_id,
                "restarts":0,"load_state":"loaded","result":"success","main_pid":1,
                "active_state":"active","sub_state":"running"}]}});
        validate_diagnostic_launch(&receipt, &claim).unwrap();
        for (field, value) in [
            ("epoch", json!(226)),
            ("snapshot_slot", json!(97199618u64)),
            ("worker_sha256", json!("c".repeat(64))),
            ("snapshot_sha256", json!("d".repeat(64))),
            ("private_run_root", json!("/elsewhere")),
            ("replay_entries_authorized", json!(true)),
            ("full_cold_epoch_peak_qualified", json!(true)),
            ("publication_authorized", json!(true)),
        ] {
            let mut bad = receipt.clone();
            bad[field] = value;
            assert!(validate_diagnostic_launch(&bad, &claim).is_err(), "{field}");
        }
    }
    #[test]
    fn private_continuation_is_exact_scoped_and_never_publication_authority() {
        let mut claim = DiagnosticClaim {
            epoch: 213,
            unit: "horizon-qualify-213-checkpoint-continuation-test-v1.service".into(),
            invocation_id: "a".repeat(32),
            scratch_path: "/private/continuation-213".into(),
            launch_receipt: BoundFile {
                path: "/private/launch.json".into(),
                sha256: "b".repeat(64),
            },
        };
        let receipt = json!({"schema":"jetstreamer-private-epoch213-checkpoint-continuation-launch-v1",
            "launched":true,"epoch":213,"remote_mutations":false,"r2_mutations":false,
            "private_run_root":claim.scratch_path,"replay_slot_start":92447543u64,
            "replay_slot_end_inclusive":92447999u64,"canonical_sidecar_authorized":false,
            "publication_authorized":false,
            "evidence":{"units":[{"unit":claim.unit,"invocation_id":claim.invocation_id,
                "restarts":0,"load_state":"loaded","result":"success","main_pid":1,
                "active_state":"active","sub_state":"running"}]}});
        validate_diagnostic_launch(&receipt, &claim).unwrap();
        for (field, value) in [
            ("epoch", json!(214)),
            ("private_run_root", json!("/another/root")),
            ("replay_slot_start", json!(92447542u64)),
            ("replay_slot_end_inclusive", json!(92448000u64)),
            ("canonical_sidecar_authorized", json!(true)),
            ("publication_authorized", json!(true)),
            ("remote_mutations", json!(true)),
            ("r2_mutations", json!(true)),
        ] {
            let mut bad = receipt.clone();
            bad[field] = value;
            assert!(validate_diagnostic_launch(&bad, &claim).is_err(), "{field}");
        }
        let mut bad = receipt.clone();
        bad["evidence"]["units"][0]["restarts"] = json!(1);
        assert!(validate_diagnostic_launch(&bad, &claim).is_err());
        claim.epoch = 214;
        assert!(validate_diagnostic_launch(&receipt, &claim).is_err());
    }

    #[test]
    fn native_restore_140_admission_requires_pinned_guard_and_one_readable_worker() {
        let (previous, mut plan, mut guard, mut gp) = admission_fixture();
        let claim = &mut plan.diagnostics[1];
        claim.epoch = 140;
        claim.unit = "horizon-qualify-140-native-restore-test-v1.service".into();
        claim.scratch_path =
            "/home/sol/.jetstreamer-private/epoch140-native-restore-test-v1".into();
        guard["guard_sha256"] =
            json!("eca429932ffe9afe71aecba815ab301db46bdddbaf24b4c44af8c88bb74a6194");
        guard["producer"]["cgroup"] = json!(format!("/system.slice/{}", claim.unit));
        guard["minimum_free_bytes"] = json!(5153080892870u64);
        guard["available_bytes"] = json!(5153080892871u64);
        guard.as_object_mut().unwrap().remove("canary_target_error");
        guard["bounded_measurement"] = json!(false);
        guard["target_handoff"] = Value::Null;
        guard["target_handoff_error"] = Value::Null;
        gp["unit"] = json!(claim.unit);
        gp["worker_root"] = json!(claim.scratch_path);
        gp["filesystem"] = json!("/home/sol");
        gp["minimum_free_bytes"] = guard["minimum_free_bytes"].clone();
        gp.as_object_mut().unwrap().remove("bounded_canary");
        gp["bounded_measurement"] = Value::Null;
        // Preserve the actual old binary's emitted schema as a regression,
        // replacing only fixture identities/time and its bound plan digest.
        let mut emitted: Value = serde_json::from_str(include_str!(
            "../../jetstreamer-utils/tests/fixtures/epoch140-eca-guard-sample.json"
        ))
        .unwrap();
        emitted["producer_invocation_id"] = guard["producer_invocation_id"].clone();
        emitted["producer"] = guard["producer"].clone();
        emitted["recorded_unix_seconds"] = guard["recorded_unix_seconds"].clone();
        emitted["plan_sha256"] = guard["plan_sha256"].clone();
        validate_same_sample_admission(
            &previous,
            &plan,
            "2026-10-20T00:04:42Z",
            &emitted,
            &gp,
            1792455200,
        )
        .unwrap();
        validate_same_sample_admission(
            &previous,
            &plan,
            "2026-10-20T00:04:42Z",
            &guard,
            &gp,
            1792455200,
        )
        .unwrap();
        for (pointer, value) in [
            (
                "/guard_sha256",
                json!("cc3536dfcc268c913feccf1603a25e3cdbdf2807289c9061e04884027d1b1560"),
            ),
            ("/workers", json!([])),
            ("/workers", json!([[1, 2], [3, 4]])),
            ("/workers", json!([[1, 3500001]])),
            ("/worker_observation_error", json!("unreadable maps")),
            ("/producer/restarts", json!(1)),
            ("/available_bytes", json!(5153080892869u64)),
        ] {
            let mut bad = guard.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate_same_sample_admission(
                    &previous,
                    &plan,
                    "2026-10-20T00:04:42Z",
                    &bad,
                    &gp,
                    1792455200
                )
                .is_err(),
                "{pointer}"
            );
        }
        let mut bad = gp.clone();
        bad["bounded_canary"] = json!({"expected_uid":1001});
        assert!(
            validate_same_sample_admission(
                &previous,
                &plan,
                "2026-10-20T00:04:42Z",
                &guard,
                &bad,
                1792455200
            )
            .is_err()
        );
    }

    #[test]
    fn native_restore_140_is_exact_zero_entry_diagnostic_not_continuation() {
        let mut claim = DiagnosticClaim {
            epoch: 140,
            unit: "horizon-qualify-140-native-restore-test-v1.service".into(),
            invocation_id: "a".repeat(32),
            scratch_path: "/home/sol/.jetstreamer-private/epoch140-native-restore-test-v1".into(),
            launch_receipt: BoundFile {
                path: "/private/launch.json".into(),
                sha256: "b".repeat(64),
            },
        };
        let receipt = json!({
            "schema":"jetstreamer-private-epoch140-native-restore-launch-v1",
            "launched":true,"epoch":140,"remote_mutations":false,"r2_mutations":false,
            "private_run_root":claim.scratch_path,"snapshot_slot":60911751u64,
            "snapshot_sha256":"47d5911465901975e397c570e06ccf72296db7ecd3b3b1beda710cacd3e683a1",
            "worker_sha256":"abe395d482174e490833928c7343a33d135d8572096faf873ce3103c35fe520d",
            "original_journal_sha256":"8dfb8d6805d6b4d50ab340899447b90449c66117cc33b1af0ca6537b934a3b13",
            "serialized_clock_sha256":"f74aacd82655179686a43c6bb137e0c0e7c7bd2955809008a745ef80f16f8be2",
            "probe_sha256":"c".repeat(64),"plan_sha256":"d".repeat(64),
            "runtime":"solana-v1.4.25","solana_rayon_threads":2,
            "maximum_runtime_seconds":1800,"experimental_envelope_bytes":128u64<<30,
            "replay_entries_authorized":false,"archive_prefix_verified":false,
            "suffix_execution_authorized":false,"runtime_promotion_authorized":false,
            "canonical_sidecar_authorized":false,"publication_authorized":false,
            "expected_exec_start":"{ path=/usr/local/lib/jetstreamer/horizon-epoch140-native-restore-tool-test/jetstreamer-epoch140-native-restore-probe ; argv[]=/usr/local/lib/jetstreamer/horizon-epoch140-native-restore-tool-test/jetstreamer-epoch140-native-restore-probe /private/plan.json --plan-sha256 HEX --self-sha256 HEX ; ignore_errors=no }",
            "evidence":{"units":[{"unit":claim.unit,"invocation_id":claim.invocation_id,
                "restarts":0,"load_state":"loaded","result":"success","main_pid":1,
                "active_state":"active","sub_state":"running"}]}
        });
        validate_diagnostic_launch(&receipt, &claim).unwrap();
        for (field, value) in [
            ("epoch", json!(141)),
            ("snapshot_slot", json!(60911999)),
            ("private_run_root", json!("/another/root")),
            ("snapshot_sha256", json!("0".repeat(64))),
            ("worker_sha256", json!("0".repeat(64))),
            ("original_journal_sha256", json!("0".repeat(64))),
            ("serialized_clock_sha256", json!("0".repeat(64))),
            ("probe_sha256", json!("not-a-digest")),
            ("plan_sha256", json!(null)),
            ("runtime", json!("solana-v1.6.16")),
            ("solana_rayon_threads", json!(8)),
            ("maximum_runtime_seconds", json!(1801)),
            ("experimental_envelope_bytes", json!(1)),
            ("replay_entries_authorized", json!(true)),
            ("archive_prefix_verified", json!(true)),
            ("suffix_execution_authorized", json!(true)),
            ("runtime_promotion_authorized", json!(true)),
            ("canonical_sidecar_authorized", json!(true)),
            ("publication_authorized", json!(true)),
            ("remote_mutations", json!(true)),
            ("r2_mutations", json!(true)),
            (
                "expected_exec_start",
                json!("{ path=/bin/true ; argv[]=/bin/true }"),
            ),
        ] {
            let mut bad = receipt.clone();
            bad[field] = value;
            assert!(validate_diagnostic_launch(&bad, &claim).is_err(), "{field}");
        }
        let guard = json!({"filesystem":"/home/sol","minimum_free_bytes":5153080892870u64});
        assert!(diagnostic_guard_profile_matches(&claim, &guard));
        for (field, value) in [
            ("minimum_free_bytes", json!(5153080892869u64)),
            ("filesystem", json!("/")),
            ("bounded_canary", json!({"expected_uid":1001})),
            ("bounded_measurement", json!({"producer_uid":1001})),
        ] {
            let mut bad = guard.clone();
            bad[field] = value;
            assert!(!diagnostic_guard_profile_matches(&claim, &bad), "{field}");
        }
        claim.epoch = 213;
        assert!(validate_diagnostic_launch(&receipt, &claim).is_err());
        claim.epoch = 140;
        claim.unit = "horizon-qualify-213-checkpoint-continuation-test.service".into();
        assert!(validate_diagnostic_launch(&receipt, &claim).is_err());
        claim.unit = "horizon-qualify-140-native-restore-test-v1.service".into();
        claim.scratch_path = "/home/sol/.jetstreamer-private/unrelated".into();
        assert!(validate_diagnostic_launch(&receipt, &claim).is_err());
    }

    #[test]
    fn diagnostic_launch_binds_epoch_unit_and_exact_zero_restart_invocation() {
        let mut claim = DiagnosticClaim {
            epoch: 154,
            unit: "horizon-perf-epoch154-test@control.service".into(),
            invocation_id: "a".repeat(32),
            scratch_path: "/private/epoch154/control/scratch".into(),
            launch_receipt: BoundFile {
                path: "/private/launch.json".into(),
                sha256: "b".repeat(64),
            },
        };
        let mut receipt = json!({"schema":"jetstreamer-historical-performance-launch-receipt-v1",
            "launched":true,"remote_mutations":false,"r2_mutations":false,
            "evidence":{"units":[{"unit":claim.unit,"invocation_id":claim.invocation_id,
                "restarts":0,"load_state":"loaded","result":"success","main_pid":1,
                "active_state":"active","sub_state":"running"}]}});
        validate_diagnostic_launch(&receipt, &claim).unwrap();
        claim.epoch = 155;
        assert!(validate_diagnostic_launch(&receipt, &claim).is_err());
        claim.epoch = 154;
        receipt["evidence"]["units"][0]["invocation_id"] = json!("c".repeat(32));
        assert!(validate_diagnostic_launch(&receipt, &claim).is_err());
        receipt["evidence"]["units"][0]["invocation_id"] = json!(claim.invocation_id);
        receipt["evidence"]["units"][0]["restarts"] = json!(1);
        assert!(validate_diagnostic_launch(&receipt, &claim).is_err());
    }

    #[test]
    fn fleet_records_disappeared_invocations_new_units_and_epoch_transitions() {
        let previous = json!({"unit_census":{"old.service":{"InvocationID":"a"},
            "gone.service":{"InvocationID":"c"}},"epochs":[{"epoch":154,"state":"blocked-qualification"}]});
        let current = BTreeMap::from([
            ("old.service".into(), json!({"InvocationID":"b"})),
            ("new.service".into(), json!({"InvocationID":"d"})),
        ]);
        let epochs = vec![json!({"epoch":154,"state":"remote-ready"})];
        let changes = transitions(&previous, &current, &epochs);
        assert_eq!(changes.len(), 4);
        assert!(
            changes
                .iter()
                .any(|c| c["unit"] == "gone.service" && c["after"].is_null())
        );
        assert!(
            changes
                .iter()
                .any(|c| c["unit"] == "new.service" && c["before"].is_null())
        );
        assert!(
            changes
                .iter()
                .any(|c| c["kind"] == "epoch-state-transition" && c["epoch"] == 154)
        );
    }

    #[test]
    fn predecessor_migration_preserves_assignment_and_monotonic_sample() {
        let sample = "2026-10-19T14:34:42Z";
        let mut previous = json!({"schema":SCHEMA,"assigned_range":{"first_epoch":201,"last_epoch":300},"production_observation_sampled_at_utc":"2026-10-19T14:04:42Z"});
        validate_previous_fleet(&previous, 201, 300, sample).unwrap();
        assert!(validate_previous_fleet(&previous, 200, 300, sample).is_err());
        assert!(validate_previous_fleet(&previous, 201, 300, "2026-10-19T14:04:42Z").is_err());
        previous["first_epoch"] = json!(201);
        assert!(validate_previous_fleet(&previous, 201, 300, sample).is_err());
        previous = json!({"schema":SCHEMA,"first_epoch":201,"last_epoch":300,"sampled_at_utc":"2026-10-19T14:04:42Z"});
        validate_previous_fleet(&previous, 201, 300, sample).unwrap();
        previous["sampled_at_utc"] = json!("2026-02-30T00:00:00Z");
        assert!(validate_previous_fleet(&previous, 201, 300, sample).is_err());
    }
    #[test]
    fn stale_or_replaced_status_never_matches_a_live_claim() {
        let status = EpochStatus {
            epoch: 198,
            jet_size_bytes: 0,
            elapsed_execution_millis: 1,
            estimated_remaining_millis: 2,
            sampled_at_utc: "2026-10-19T14:07:00Z".into(),
            phase: "replay".into(),
        };
        let mut publication = StatusPublicationReceipt {
            schema: STATUS_RECEIPT_SCHEMA.into(),
            bucket: "test".into(),
            epoch: 198,
            key: "epoch-198.epoch-status.json".into(),
            status: status.clone(),
            object_etag: "etag".into(),
            previous_object_etag: None,
            observer_receipt: "/private/observer.json".into(),
            observer_receipt_sha256: "0".repeat(64),
            controller_invocation_id: "controller".into(),
            producer_invocation_id: "producer".into(),
            authenticated_readback: true,
            verified_unix_seconds: 0,
            pipeline_binding: None,
        };
        let controller =
            json!({"InvocationID":"controller","ActiveState":"active","NRestarts":"0"});
        let mut producer =
            json!({"InvocationID":"producer","ActiveState":"active","NRestarts":"0"});
        assert!(status_matches(
            &status,
            "etag",
            &publication,
            &controller,
            &producer
        ));
        assert!(!status_matches(
            &status,
            "new-etag",
            &publication,
            &controller,
            &producer
        ));
        producer["ActiveState"] = json!("inactive");
        assert!(!status_matches(
            &status,
            "etag",
            &publication,
            &controller,
            &producer
        ));
        producer["ActiveState"] = json!("active");
        producer["InvocationID"] = json!("replacement");
        assert!(!status_matches(
            &status,
            "etag",
            &publication,
            &controller,
            &producer
        ));
        producer["InvocationID"] = json!("producer");
        publication.status.estimated_remaining_millis += 1;
        assert!(!status_matches(
            &status,
            "etag",
            &publication,
            &controller,
            &producer
        ));
    }
    #[test]
    fn rejects_stale_date_shapes_and_handles_utc_epoch() {
        assert_eq!(utc_seconds("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(utc_seconds("1970-01-01T00:30:00Z").unwrap(), 1800);
        assert!(utc_seconds("2026-02-30T00:00:00Z").is_err());
        assert!(utc_seconds("2026-01-01T24:00:00Z").is_err());
        assert!(utc_seconds("2026-01-01T00:00:00").is_err());
    }
    #[test]
    fn stopped_or_restarted_invocations_are_not_live() {
        let observed = json!({"invocation_id":"abc","restarts":0});
        let mut current = json!({"InvocationID":"abc","NRestarts":"0","ActiveState":"active","SubState":"running"});
        assert!(live_binding(&observed, &current));
        for (field, value) in [
            ("InvocationID", "other"),
            ("NRestarts", "1"),
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
        ] {
            let saved = current[field].clone();
            current[field] = json!(value);
            assert!(!live_binding(&observed, &current));
            current[field] = saved;
        }
    }
    #[test]
    fn fleet_receipt_is_private_and_no_clobber() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("fleet.json");
        persist(&path, &json!({"test":1})).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o077, 0);
        assert!(persist(&path, &json!({"test":2})).is_err());
    }

    #[test]
    fn output_preflight_rejects_missing_unsafe_and_occupied_destinations() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("fleet.json");
        assert!(validate_output_destination(&path).is_ok());
        assert!(validate_output_destination(&root.path().join("missing/fleet.json")).is_err());
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o750)).unwrap();
        assert!(validate_output_destination(&path).is_err());
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&path, b"retained receipt").unwrap();
        assert!(validate_output_destination(&path).is_err());
        let link = root.path().join("dangling.json");
        symlink(root.path().join("absent"), &link).unwrap();
        assert!(validate_output_destination(&link).is_err());
        let parent_link = root.path().join("alias");
        symlink(root.path(), &parent_link).unwrap();
        assert!(validate_output_destination(&parent_link.join("new.json")).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"retained receipt");
    }
}

#[cfg(test)]
mod singleton_discovery_tests {
    use super::assigned_singleton_owner;
    #[test]
    fn assigned_singletons_cannot_hide_from_an_older_fleet_reader() {
        for unit in [
            "horizon-singleton-209-capped-4aeca563-v1.service",
            "horizon-singleton-210-capped-4aeca563-v1.service",
            "horizon-singleton-227-capped-710f6523-v1.service",
            "horizon-singleton-210-unknown-future-profile.service",
        ] {
            assert!(assigned_singleton_owner(unit, 201, 300), "{unit}");
            assert!(!assigned_singleton_owner(unit, 101, 200), "{unit}");
        }
        for unit in [
            "horizon-singleton210-protective-v1.service",
            "horizon-qualify-227-v1625-bounded-resource-d01adb19-selection-v2.service",
            "unrelated.service",
        ] {
            assert!(!assigned_singleton_owner(unit, 201, 300), "{unit}");
        }
    }
}

// Shared producer contract; entrypoint-only methods are unused in the R2 consumer.
#[allow(dead_code)]
#[path = "../../jetstreamer-node/src/capped_thread_profile.rs"]
mod capped204205_thread_profile;

// Status-only authentication of a typed recovery successor; no fleet projection,
// owner release, resource credit or original terminal-proof substitution.
pub(super) fn qualification_recovery204_successor(
    f: &Value,
    current: &BTreeMap<String, Value>,
    unit: &str,
    iid: &str,
    actor_launch: &Value,
) -> Result<()> {
    assembly204_recovery::qualification_successor(
        f,
        current,
        unit,
        iid,
        &serde_json::from_value(actor_launch.clone())?,
    )
}
