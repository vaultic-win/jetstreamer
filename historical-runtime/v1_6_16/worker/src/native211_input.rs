//! Exact epoch 211 bootstrap, independent of all other epochs' native proofs.
use super::native_cold_common::{self, Profile};
#[path = "native211_gate.rs"]
mod startup_gate;

const INPUT: Profile = Profile {
    epoch: 211,
    package: "/var/lib/jetstreamer/horizon-focused-211-complete-span-store8-ca2e38b-v1",
    snapshot: "snapshot-91151575-xiEDMtStmnD9Pc8Ph9rJ4dFhfvvqZDSPeX89wjPELXx.tar.zst",
    bytes: 8_731_506_223,
    snapshot_sha256: "958a8e5aad2423350f04470dffbd90fd8d7e458f7f8e774e15dd86d43291b5fb",
    slot: 91_151_575,
    accounts_hash: "xiEDMtStmnD9Pc8Ph9rJ4dFhfvvqZDSPeX89wjPELXx",
    scratch_environment: "JETSTREAMER_EPOCH211_V1616_TEST_SCRATCH",
    scratch_prefix: "native-input211-v1616-capped-",
};

#[test]
fn closed_native211_inputs_reject_changed_writable_or_symlinked_files() {
    native_cold_common::integrity_regression(&INPUT);
}

#[test]
#[ignore]
fn native_epoch211_cold_input_matches_canonical_accounts_commitment() {
    startup_gate::before_snapshot(startup_gate::admit, || {
        native_cold_common::native_cold(&INPUT)
    })
    .expect("epoch211 first guard must precede all snapshot work");
}
