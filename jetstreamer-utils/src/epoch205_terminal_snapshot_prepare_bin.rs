//! Compressed epoch205 terminal input only; no restore, suffix or publication.
mod profile {
    pub(super) const EPOCH: u64 = 205;
    pub(super) const PROTECTED_FLEET: bool = true;
    pub(super) const PLAN_SCHEMA: &str = "horizon-epoch205-terminal-snapshot-prepare-plan-v1";
    pub(super) const RECEIPT_SCHEMA: &str = "horizon-epoch205-terminal-snapshot-prepared-v1";
    // Unchanged older203/223/225 full growth claims plus the thirteen-jet floor.
    pub(super) const MINIMUM_PROTECTED_FREE: u64 = 3_615_543_542_675;
    pub(super) const FILENAME: &str =
        "snapshot-88991050-BAsq3Vn4KyLYuLqrevCL2dnE1fjLyA6NSX9qQjG7VCDp.tar.zst";
    pub(super) const OBJECT: super::epoch141_ledger_common::ObjectSpec =
        super::epoch141_ledger_common::ObjectSpec {
            bucket: "mainnet-beta-ledger-us-ny5",
            name: "88991050/snapshot-88991050-BAsq3Vn4KyLYuLqrevCL2dnE1fjLyA6NSX9qQjG7VCDp.tar.zst",
            generation: "1634790073611030",
            size: 8_407_269_066,
            crc: "9/mUyw==",
            md5: "fBpHLn3nugSP8+TvNmpB1Q==",
            uri: "gs://mainnet-beta-ledger-us-ny5/88991050/snapshot-88991050-BAsq3Vn4KyLYuLqrevCL2dnE1fjLyA6NSX9qQjG7VCDp.tar.zst#1634790073611030",
        };
}
include!("bootstrap_prepare.rs");

#[cfg(test)]
mod profile_tests {
    use super::profile::*;

    #[test]
    fn terminal_input_does_not_claim_the_missing_suffix() {
        assert_eq!(EPOCH, 205);
        const { assert!(PROTECTED_FLEET) };
        assert_eq!(88_991_999 - 88_991_050, 949);
        assert_eq!(OBJECT.size, 8_407_269_066);
        assert_eq!(OBJECT.generation, "1634790073611030");
        assert_eq!(OBJECT.crc, "9/mUyw==");
        assert_eq!(OBJECT.md5, "fBpHLn3nugSP8+TvNmpB1Q==");
        assert_eq!(MINIMUM_PROTECTED_FREE, 3_615_543_542_675);
        assert!(FILENAME.starts_with("snapshot-88991050-"));
        assert!(PLAN_SCHEMA.contains("terminal-snapshot"));
        assert!(RECEIPT_SCHEMA.contains("terminal-snapshot"));
    }
}
