//! Private fixed epoch203 restore-only comparator; no replay or publication.
mod profile {
    pub(super) const EPOCH: u64 = 203;
    pub(super) const SLOT: u64 = 88_127_580;
    pub(super) const START: u64 = 87_696_000;
    pub(super) const WORKER: &str =
        "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc";
    pub(super) const SNAPSHOT: &str =
        "d3114597ce25c3efaa4a96899ab3e9437c51cb9086d4166639f0ad2ae0613ee6";
    pub(super) const SNAPSHOT_SIZE: u64 = 8_215_471_895;
    pub(super) const SNAPSHOT_NAME: &str =
        "snapshot-88127580-4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf.tar.zst";
    pub(super) const ROOT_HASH: &str = "4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf";
    pub(super) const GENESIS: &str =
        "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
    pub(super) const PREFIX: &str = "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-203-f9fc5a0-v1/output/epoch-203-prefix.jet";
    pub(super) const BOOTSTRAP: u64 = 87_695_515;
    pub(super) const BOOTSTRAP_HASH: &str = "CYEr1vEwJyh2d4SSmnmYPYYj6EPhrDWTAJJCuzF2VhLX";
    pub(super) const INPUT_SCHEMA: &str = "jetstreamer-epoch203-native-input-policy-v1";
    pub(super) const ADMISSION_SCHEMA: &str = "jetstreamer-epoch203-native-admission-receipt-v1";
    pub(super) const PLAN_SCHEMA: &str =
        "jetstreamer-private-epoch203-native-restore-probe-plan-v1";
    pub(super) const RECEIPT_SCHEMA: &str = "jetstreamer-private-epoch203-native-restore-probe-v1";
    pub(super) const UNIT_PREFIX: &str = "horizon-native-203-";
    pub(super) const RUN_PREFIX: &str = "epoch203-native-";
    pub(super) const LEASE_PATH: &str = "/home/ubuntu/.jetstreamer-private/epoch203-native.lock";
}
#[path = "../native_restore_fixed.rs"]
mod fixed;
fn main() {
    fixed::main();
}

#[cfg(test)]
mod profile_tests {
    use super::profile::*;
    #[test]
    fn existing203_bindings_remain_unchanged() {
        let scope = (EPOCH, START, SLOT, BOOTSTRAP, SNAPSHOT_SIZE);
        assert_eq!(
            scope,
            (203, 87_696_000, 88_127_580, 87_695_515, 8_215_471_895)
        );
        let digests = (WORKER, SNAPSHOT);
        assert_eq!(
            digests,
            (
                "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc",
                "d3114597ce25c3efaa4a96899ab3e9437c51cb9086d4166639f0ad2ae0613ee6"
            )
        );
        let namespaces = (UNIT_PREFIX, RUN_PREFIX, RECEIPT_SCHEMA);
        assert_eq!(
            namespaces,
            (
                "horizon-native-203-",
                "epoch203-native-",
                "jetstreamer-private-epoch203-native-restore-probe-v1"
            )
        );
    }
}
