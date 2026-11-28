//! Immutable identity of the target-stopped workspace and its preserved evidence.
pub(super) const CHILD: &str = "jetstreamer-historical-parent-RiHhWU";
pub(super) const RUNTIME: &str = "jetstreamer-historical-v1.8.11-AKggFf";
pub(super) const RUN: &str = "/home/ubuntu/.jetstreamer-private/qualification-266-capped-bounded-v210/state/destination-3b3d36405c6940de810510759e829af5e5ec72ffc8e54a1d5eb7ba63860cfc4f/work/root-cohort-266-266/run-3483521-1795402817505873578";
pub(super) const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/qualification-266-capped-bounded-v210";
pub(super) const Q: &str = ".horizon266-1dd482d1-derived-quarantine";
pub(super) const IMAGE: &str =
    "/var/lib/jetstreamer/horizon266-capped-bounded-v210-control/pilot/private.ext4";
pub(super) const LOOP: &str = "/dev/loop18";
pub(super) const STATE: &str = "/var/lib/jetstreamer/horizon266-stopped-bounded-v215-state";
pub(super) const GRANTS: &str = "/run/horizon266-stopped-bounded-v215-grants";
pub(super) const UNIT: &str = "horizon-qualify-266-capped-bounded-v210.service";
pub(super) const GUARD: &str = "horizon-266-capped-bounded-v210-protective.service";
pub(super) const TIMER: &str = "horizon-266-capped-bounded-v210-protective.timer";
pub(super) const FAILSAFE: &str = "horizon-266-capped-bounded-v210-protective-failsafe.service";
pub(super) const CHECK: &str = "cf0b9ea9a89f287b8259d86222415e6c613222db4f224e9350acf50e0eba8d38";
pub(super) const STOP: &str = "94958f52d3f1265519325c5b5bbccacf68b119cf441a8939ea678eb8946f5667";
pub(super) const DEVICE: u64 = 1810;
pub(super) const MOUNT: u64 = 804;
pub(super) const PARENT_INODE: u64 = 19005455;
pub(super) const CHILD_INODE: u64 = 19005456;
pub(super) const IMAGE_INODE: u64 = 13850126;
pub(super) const IMAGE_SIZE: u64 = 344997011456;
pub(super) const MAX_ENTRIES: u64 = 500000;
pub(super) const STATE_INODE: u64 = 19005451;
pub(super) const STATE_MTIME: i64 = 1795402817505157514;
pub(super) const ARCHIVE_INODE: u64 = 19005466;
pub(super) const ARCHIVE_SIZE: u64 = 5085745842;
pub(super) const ARCHIVE_MTIME: i64 = 1795409649356579349;
pub(super) const ARCHIVE_SHA: &str =
    "a58ca8569cf3d10b2a063f9b731ac94ce61945a48adf216cc1c65608d2e3111a";
pub(super) const CONTROL_DIR: &str =
    "/var/lib/jetstreamer/horizon266-capped-bounded-v210-control/pilot";
pub(super) const PRODUCER_IID: &str = "1dd482d1481448debb4e9de11f2dc1f6";
pub(super) const SERVICE_GENERATION: &str = "v215";
pub(super) const EXPECTED: super::Counts = super::Counts {
    files: 398514,
    directories: 13,
    logical: 96769757397,
    allocated_files: 96705163264,
};
pub(super) const EVENTS: &[(&str, &str)] = &[
    (
        "39f53479d3a045ac8e11786248231fbf",
        "s=d048fb8ccd4e4326a91b8c5edb351816;i=a1e747;b=3b17d0055c3a4a0e8841da097e0957b5;m=7f90966566;t=660e8caed688f;x=265d7bff4c561dba",
    ),
    (
        "de5b426a63be47a7b6ac3eaac82e2f6f",
        "s=d048fb8ccd4e4326a91b8c5edb351816;i=a23cef;b=3b17d0055c3a4a0e8841da097e0957b5;m=81297305c4;t=660ea63ca08ed;x=1d8fc6659731e647",
    ),
    (
        "7ad2d189f7e94e70a38c781354912448",
        "s=d048fb8ccd4e4326a91b8c5edb351816;i=a23cf0;b=3b17d0055c3a4a0e8841da097e0957b5;m=81297aff53;t=660ea63d2027c;x=95ef8627c835c971",
    ),
    (
        "9d1aaa27d60140bd96365438aad20286",
        "s=d048fb8ccd4e4326a91b8c5edb351816;i=a23cf1;b=3b17d0055c3a4a0e8841da097e0957b5;m=81297b0036;t=660ea63d2035f;x=9f044c6adcf4390c",
    ),
];
pub(super) const ORIGINALS: &str = include_str!("v210-originals.tsv");
pub(super) const RETAINED: &str = include_str!("v210-retained.tsv");
