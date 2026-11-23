//! Immutable identity of the guard-stopped workspace and its preserved evidence.
pub(super) const CHILD: &str = "jetstreamer-historical-parent-RXHuqy";
pub(super) const RUNTIME: &str = "jetstreamer-historical-v1.8.11-DUyhUa";
pub(super) const RUN: &str = "/home/ubuntu/.jetstreamer-private/qualification-266-instructions-2789f821-v194/state/destination-74cdfe7e1c89e4a0cb05e5bab400c86f7c3bf8eb5465bf28fcda37ebfd52105c/work/root-cohort-266-266/run-3215067-1795375088043578768";
pub(super) const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/qualification-266-instructions-2789f821-v194";
pub(super) const Q: &str = ".horizon266-41cf6e5a-derived-quarantine";
pub(super) const IMAGE: &str =
    "/var/lib/jetstreamer/horizon266-instructions-2789f821-v194-control/pilot/private.ext4";
pub(super) const LOOP: &str = "/dev/loop12";
pub(super) const STATE: &str = "/var/lib/jetstreamer/horizon266-stopped-scratch-v207-state";
pub(super) const GRANTS: &str = "/run/horizon266-stopped-scratch-v207-grants";
pub(super) const UNIT: &str = "horizon-qualify-266-instructions-2789f821-v194.service";
pub(super) const GUARD: &str = "horizon-266-instructions-2789f821-v194-protective.service";
pub(super) const TIMER: &str = "horizon-266-instructions-2789f821-v194-protective.timer";
pub(super) const FAILSAFE: &str =
    "horizon-266-instructions-2789f821-v194-protective-failsafe.service";
pub(super) const CHECK: &str = "5dfd32d2d7f7523d39f3f20981437558610ac01a45fa22a426ee56468ddf4ce0";
pub(super) const STOP: &str = "7fdef3126f8a86624ff78cf512dfb955c594dbbe67e67305900858be58ed6ad2";
pub(super) const DEVICE: u64 = 1804;
pub(super) const MOUNT: u64 = 416;
pub(super) const PARENT_INODE: u64 = 16252943;
pub(super) const CHILD_INODE: u64 = 16252944;
pub(super) const IMAGE_INODE: u64 = 18340079;
pub(super) const IMAGE_SIZE: u64 = 320 << 30;
pub(super) const MAX_ENTRIES: u64 = 500000;
pub(super) const STATE_INODE: u64 = 16252939;
pub(super) const STATE_MTIME: i64 = 1795375088043023729;
pub(super) const ARCHIVE_INODE: u64 = 16252954;
pub(super) const ARCHIVE_SIZE: u64 = 5085926416;
pub(super) const ARCHIVE_MTIME: i64 = 1795381275914069247;
pub(super) const ARCHIVE_SHA: &str =
    "5a80ceca275c203b0d8bde0e095036cfab3268b4296d94eed5c607215dd395c5";
pub(super) const CONTROL_DIR: &str =
    "/var/lib/jetstreamer/horizon266-instructions-2789f821-v194-control/pilot";
pub(super) const PRODUCER_IID: &str = "41cf6e5a5cd54d57adc5eba3f0c0ecef";
pub(super) const SERVICE_GENERATION: &str = "v207";
pub(super) const EXPECTED: super::Counts = super::Counts {
    files: 470_432,
    directories: 13,
    logical: 353_293_836_501,
    allocated_files: 331_357_659_136,
};
pub(super) const EVENTS: &[(&str, &str)] = &[
    (
        "39f53479d3a045ac8e11786248231fbf",
        "s=d048fb8ccd4e4326a91b8c5edb351816;i=a0cad1;b=3b17d0055c3a4a0e8841da097e0957b5;m=791bbf3c71;t=660e256163f9a;x=656b5d6fc0c7e223",
    ),
    (
        "de5b426a63be47a7b6ac3eaac82e2f6f",
        "s=d048fb8ccd4e4326a91b8c5edb351816;i=a11167;b=3b17d0055c3a4a0e8841da097e0957b5;m=7a8df96b3f;t=660e3c8506e68;x=49ce7dc93e56a0cd",
    ),
    (
        "7ad2d189f7e94e70a38c781354912448",
        "s=d048fb8ccd4e4326a91b8c5edb351816;i=a11168;b=3b17d0055c3a4a0e8841da097e0957b5;m=7a8e000509;t=660e3c8570832;x=dae477121aa1527a",
    ),
    (
        "9d1aaa27d60140bd96365438aad20286",
        "s=d048fb8ccd4e4326a91b8c5edb351816;i=a11169;b=3b17d0055c3a4a0e8841da097e0957b5;m=7a8e0005de;t=660e3c8570907;x=ef9eac7e4ba55af9",
    ),
];
pub(super) const ORIGINALS: &str = include_str!("v194-originals.tsv");
pub(super) const RETAINED: &str = include_str!("v194-retained.tsv");
