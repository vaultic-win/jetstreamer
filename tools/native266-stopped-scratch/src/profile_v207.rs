//! Immutable identity of the guard-stopped workspace and its preserved evidence.
pub(super) const CHILD: &str = "jetstreamer-historical-parent-S9Z5zo";
pub(super) const RUNTIME: &str = "jetstreamer-historical-v1.8.11-lbzuDW";
pub(super) const RUN: &str = "/home/ubuntu/.jetstreamer-private/qualification-266-capped-bounded-v207/state/destination-03d8921677161460edeac2cc957580ab734be886878fc55704cb83c21c20bdfc/work/root-cohort-266-266/run-3451480-1795400044028916144";
pub(super) const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/qualification-266-capped-bounded-v207";
pub(super) const Q: &str = ".horizon266-39999fd2-derived-quarantine";
pub(super) const IMAGE: &str =
    "/var/lib/jetstreamer/horizon266-capped-bounded-v207-control/pilot/private.ext4";
pub(super) const LOOP: &str = "/dev/loop15";
pub(super) const STATE: &str = "/var/lib/jetstreamer/horizon266-stopped-bounded-v210-state";
pub(super) const GRANTS: &str = "/run/horizon266-stopped-bounded-v210-grants";
pub(super) const UNIT: &str = "horizon-qualify-266-capped-bounded-v207.service";
pub(super) const GUARD: &str = "horizon-266-capped-bounded-v207-protective.service";
pub(super) const TIMER: &str = "horizon-266-capped-bounded-v207-protective.timer";
pub(super) const FAILSAFE: &str = "horizon-266-capped-bounded-v207-protective-failsafe.service";
pub(super) const CHECK: &str = "302dc6c3bdc31c36d40e38f60a541dad58d849d54985a629219d15b39fb058eb";
pub(super) const STOP: &str = "6d080f38689a4061d09094cfd9bb6b8dff14c3fc836c4b31cf1f1772792f5053";
pub(super) const DEVICE: u64 = 1807;
pub(super) const MOUNT: u64 = 611;
pub(super) const PARENT_INODE: u64 = 14942223;
pub(super) const CHILD_INODE: u64 = 14942224;
pub(super) const IMAGE_INODE: u64 = 6025749;
pub(super) const IMAGE_SIZE: u64 = 344997011456;
pub(super) const MAX_ENTRIES: u64 = 500000;
pub(super) const STATE_INODE: u64 = 14942219;
pub(super) const STATE_MTIME: i64 = 1795400044028384545;
pub(super) const ARCHIVE_INODE: u64 = 14942235;
pub(super) const ARCHIVE_SIZE: u64 = 0;
pub(super) const ARCHIVE_MTIME: i64 = 1795400620626260816;
pub(super) const ARCHIVE_SHA: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
pub(super) const CONTROL_DIR: &str =
    "/var/lib/jetstreamer/horizon266-capped-bounded-v207-control/pilot";
pub(super) const PRODUCER_IID: &str = "39999fd278dd40c18310a3d6c10c4e21";
pub(super) const SERVICE_GENERATION: &str = "v210";
pub(super) const EXPECTED: super::Counts = super::Counts {
    files: 398480,
    directories: 13,
    logical: 89742926037,
    allocated_files: 89694781440,
};
pub(super) const EVENTS: &[(&str, &str)] = &[
    (
        "39f53479d3a045ac8e11786248231fbf",
        "s=d048fb8ccd4e4326a91b8c5edb351816;i=a1c34e;b=3b17d0055c3a4a0e8841da097e0957b5;m=7eeb3c0a83;t=660e825930dac;x=5a7613cfaa189fb",
    ),
    (
        "de5b426a63be47a7b6ac3eaac82e2f6f",
        "s=d048fb8ccd4e4326a91b8c5edb351816;i=a1d380;b=3b17d0055c3a4a0e8841da097e0957b5;m=7f300ec5a0;t=660e86a65c8c9;x=7468a4b42c479dbc",
    ),
    (
        "7ad2d189f7e94e70a38c781354912448",
        "s=d048fb8ccd4e4326a91b8c5edb351816;i=a1d381;b=3b17d0055c3a4a0e8841da097e0957b5;m=7f3014e1e8;t=660e86a6be511;x=5b0b1732a47f85ae",
    ),
    (
        "9d1aaa27d60140bd96365438aad20286",
        "s=d048fb8ccd4e4326a91b8c5edb351816;i=a1d382;b=3b17d0055c3a4a0e8841da097e0957b5;m=7f3014e287;t=660e86a6be5b0;x=b13effa1f07fe984",
    ),
];
pub(super) const ORIGINALS: &str = include_str!("v207-originals.tsv");
pub(super) const RETAINED: &str = include_str!("v207-retained.tsv");
