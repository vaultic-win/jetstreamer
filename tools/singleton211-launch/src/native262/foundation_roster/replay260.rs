//! Price epoch 260's exact singleton inputs in the existing Foundation roster.
use super::*;

pub(super) const EPOCH: u64 = 260;
pub(super) const UNIT: &str = "horizon-qualify-260-singleton-v1.service";
pub(super) const GUARD: &str = "horizon-260-singleton-protective-v1";
pub(super) const ROSTER_SCHEMA: &str = "foundation-epoch260-full-replay-roster-binding-v1";
pub(super) const REGISTRATION: ReplayRegistration = ReplayRegistration {
    epoch: EPOCH,
    unit: UNIT,
    receipt: (
        "/var/lib/jetstreamer/horizon260-full-replay-runtime-v1/cadence-registration.json",
        "", // Authenticated below against the actual admission and sealed input.
    ),
    schema: "foundation-epoch260-replay-cadence-registration-v1",
    node_key: "replay_node",
    receipt_disk: DISK_RECEIPTS,
};
const INPUTS: (&str, &str) = (
    "/var/lib/jetstreamer/horizon260-full-replay-inputs-v1/replay-inputs.json",
    "0fe2904b1b572929f72d9a306ff2927fcf1b7323f9cf8685c07da85bb74be685",
);
const BOOTSTRAP_SLOT: u64 = 112_316_757;
const TERMINAL_SLOT: u64 = 112_751_309;
const CAP: u64 = 514_359_320_727;
const MEMORY: u64 = 160 << 30;

fn inputs() -> Bound {
    Bound::new(INPUTS.0, INPUTS.1)
}

pub(super) fn quote() -> Result<FullReplayQuote> {
    let inputs = inputs();
    let plan = inputs.sealed()?;
    let reference = binding(&plan["native_bootstrap_terminal"])?;
    let terminal = reference.sealed()?;
    let checkpoint = &plan["terminal_checkpoint_metadata"];
    let sizing = &plan["capacity_model"];
    ensure!(
        plan["schema"] == "foundation-epoch260-full-replay-input-envelope-v1"
            && plan["epoch"] == EPOCH
            && plan["full_replay_admitted"] == false
            && plan["publication_authorized"] == false
            && terminal["schema"] == "foundation-epoch260-native-restore-terminal-v1"
            && terminal["epoch"] == EPOCH
            && terminal["checkpoint_slot"] == BOOTSTRAP_SLOT
            && terminal["native_restore_qualified"] == true
            && terminal["guard_drained"] == true
            && checkpoint["slot"] == TERMINAL_SLOT
            && checkpoint["generation"] == 1640541164758326u64
            && num(sizing, "whole_tree_cap_bytes")? == CAP
            && num(sizing, "producer_memory_max_bytes")? == MEMORY
            && num(sizing, "receipt_disk_reservation_bytes")? == DISK_RECEIPTS
            && num(sizing, "guard_memory_max_bytes")? == 1 << 30,
        "epoch 260 replay inputs or sizing changed"
    );
    binding(&plan["replay_node"])?.artifact()?;
    binding(&plan["worker"])?.artifact()?;
    binding(&plan["manifest"])?.sealed()?;
    binding(&plan["slot_ranges_override"])?.sealed()?;
    Ok(FullReplayQuote {
        epoch: EPOCH,
        reference,
        inputs,
        working_disk: CAP,
        producer_memory: MEMORY,
    })
}

pub(super) fn check_live_binding(
    registration: &Value,
    admission: &Value,
    fit: &Value,
    input_ref: &Bound,
) -> Result<()> {
    let expected = inputs();
    ensure!(
        input_ref.path == expected.path
            && input_ref.sha256 == expected.sha256
            && fit["schema"] == ROSTER_SCHEMA
            && fit["epoch"] == EPOCH
            && fit["full_replay_quote"]["inputs"] == json!(expected)
            && fit["full_replay_quote"]["whole_tree_bytes"] == CAP
            && admission["profile"] == registration["profile"],
        "epoch 260 registered replay differs from its full-roster admission"
    );
    Ok(())
}
