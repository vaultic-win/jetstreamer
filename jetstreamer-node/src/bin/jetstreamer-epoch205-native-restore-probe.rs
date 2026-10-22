//! Private fixed epoch205 restore-only comparator; no replay or publication.
mod profile {
    pub(super) const EPOCH: u64 = 205;
    pub(super) const SLOT: u64 = 88_991_050;
    pub(super) const START: u64 = 88_560_000;
    pub(super) const WORKER: &str =
        "3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a";
    pub(super) const SNAPSHOT: &str =
        "1b2a41f022847dc2ba9609e5a13aadc0e79b213b5245166b06954bf8c6d9042f";
    pub(super) const SNAPSHOT_SIZE: u64 = 8_407_269_066;
    pub(super) const SNAPSHOT_NAME: &str =
        "snapshot-88991050-BAsq3Vn4KyLYuLqrevCL2dnE1fjLyA6NSX9qQjG7VCDp.tar.zst";
    pub(super) const ROOT_HASH: &str = "BAsq3Vn4KyLYuLqrevCL2dnE1fjLyA6NSX9qQjG7VCDp";
    pub(super) const GENESIS: &str =
        "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
    pub(super) const PREFIX: &str = "/home/ubuntu/.jetstreamer-private/qualification-205-prefix-store8-v1/output/epoch-205-through-88991050.jet";
    pub(super) const BOOTSTRAP: u64 = 88_559_361;
    pub(super) const BOOTSTRAP_HASH: &str = "83H83cZe1j8pnukHcZiXxKRyvCNUAZjcR43Wv9aQtnYA";
    pub(super) const INPUT_SCHEMA: &str = "jetstreamer-epoch205-native-input-policy-v1";
    pub(super) const ADMISSION_SCHEMA: &str = "jetstreamer-epoch205-native-admission-receipt-v1";
    pub(super) const PLAN_SCHEMA: &str =
        "jetstreamer-private-epoch205-native-restore-probe-plan-v1";
    pub(super) const RECEIPT_SCHEMA: &str = "jetstreamer-private-epoch205-native-restore-probe-v1";
    pub(super) const UNIT_PREFIX: &str = "horizon-native-205-";
    pub(super) const RUN_PREFIX: &str = "epoch205-native-";
    pub(super) const LEASE_PATH: &str = "/home/ubuntu/.jetstreamer-private/epoch205-native.lock";
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
    fn exact205_profile_keeps_the_949_slot_suffix_unqualified() {
        let scope = (EPOCH, START, SLOT, BOOTSTRAP, SNAPSHOT_SIZE);
        assert_eq!(
            scope,
            (205, 88_560_000, 88_991_050, 88_559_361, 8_407_269_066)
        );
        let uncovered = 88_991_999 - SLOT;
        assert_eq!(uncovered, 949);
        let digests = (WORKER, SNAPSHOT);
        assert_eq!(
            digests,
            (
                "3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a",
                "1b2a41f022847dc2ba9609e5a13aadc0e79b213b5245166b06954bf8c6d9042f"
            )
        );
        let namespaces = (UNIT_PREFIX, RUN_PREFIX, RECEIPT_SCHEMA);
        assert_eq!(
            namespaces,
            (
                "horizon-native-205-",
                "epoch205-native-",
                "jetstreamer-private-epoch205-native-restore-probe-v1"
            )
        );
    }
}
