//! Exact epoch210 bootstrap, independent of all other epochs' native proofs.
use super::native_cold_common::{self,Profile};
const INPUT:Profile=Profile {
    epoch:210,
    package:"/var/lib/jetstreamer/horizon-focused-210-complete-span-store8-ca2e38b-v1",
    snapshot:"snapshot-90719638-3C18JGi6UtMvAi6M4AUPC96redPqo7h6QnAsrUi8d3SJ.tar.zst",
    bytes:8_579_041_139,
    snapshot_sha256:"3f67f416d254d7fb795bc902d5c47a6ae374fa36c173c00411d4b541fc610ccd",
    slot:90_719_638,
    accounts_hash:"3C18JGi6UtMvAi6M4AUPC96redPqo7h6QnAsrUi8d3SJ",
    scratch_environment:"JETSTREAMER_EPOCH210_V1616_TEST_SCRATCH",
    scratch_prefix:"native-input210-v1616-capped-",
};
#[test]
fn closed_native210_inputs_reject_changed_writable_or_symlinked_files() {
    native_cold_common::integrity_regression(&INPUT);
}
#[test]
#[ignore]
fn native_epoch210_cold_input_matches_canonical_accounts_commitment() {
    native_cold_common::native_cold(&INPUT);
}
