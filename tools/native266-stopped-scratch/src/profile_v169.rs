//! Immutable identity of the guard-stopped workspace and its preserved evidence.
pub(super) const CHILD: &str = "jetstreamer-historical-parent-XJEdNU";
pub(super) const RUNTIME: &str = "jetstreamer-historical-v1.8.11-lQAA8n";
pub(super) const RUN: &str = "/home/ubuntu/.jetstreamer-private/qualification-266-instructions-2789f821-v169/state/destination-7842454ffe9bde170be8ce42da5b2a5b9ffe7770939d4697f306fceecf45b7c3/work/root-cohort-266-266/run-2863142-1795309320359102473";
pub(super) const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/qualification-266-instructions-2789f821-v169";
pub(super) const Q: &str = ".horizon266-cad28704-derived-quarantine";
pub(super) const IMAGE: &str =
    "/var/lib/jetstreamer/horizon266-instructions-2789f821-v169-control/pilot/private.ext4";
pub(super) const LOOP: &str = "/dev/loop9";
pub(super) const STATE: &str = "/var/lib/jetstreamer/horizon266-stopped-scratch-v173-state";
pub(super) const GRANTS: &str = "/run/horizon266-stopped-scratch-v173-grants";
pub(super) const UNIT: &str = "horizon-qualify-266-instructions-2789f821-v169.service";
pub(super) const GUARD: &str = "horizon-266-instructions-2789f821-v169-protective.service";
pub(super) const TIMER: &str = "horizon-266-instructions-2789f821-v169-protective.timer";
pub(super) const FAILSAFE: &str =
    "horizon-266-instructions-2789f821-v169-protective-failsafe.service";
pub(super) const CHECK: &str = "f068ddb1f4b01b77fd5befb7da0c6ca8dfbebeb99909daec5804d97dc99cbe30";
pub(super) const STOP: &str = "95c4635f0cce38ec8f936ff508289340f4151099fe4fdce12a2560394b9a1ed9";
pub(super) const DEVICE: u64 = 1801;
pub(super) const MOUNT: u64 = 1555;
pub(super) const PARENT_INODE: u64 = 5767183;
pub(super) const CHILD_INODE: u64 = 5767184;
pub(super) const IMAGE_INODE: u64 = 18335082;
pub(super) const IMAGE_SIZE: u64 = 128 << 30;
pub(super) const MAX_ENTRIES: u64 = 450000;
pub(super) const STATE_INODE: u64 = 5767179;
pub(super) const STATE_MTIME: i64 = 1795309320358444375;
pub(super) const ARCHIVE_INODE: u64 = 5767194;
pub(super) const ARCHIVE_SIZE: u64 = 488934107;
pub(super) const ARCHIVE_MTIME: i64 = 1795310933092021856;
pub(super) const ARCHIVE_SHA: &str =
    "0cbc940306fb1fce868729390ff4c38b0967fd18ff73eaf4b19a0ddbc71cff2d";
pub(super) const CONTROL_DIR: &str =
    "/var/lib/jetstreamer/horizon266-instructions-2789f821-v169-control/pilot";
pub(super) const PRODUCER_IID: &str = "cad28704afe54672a6993db729227149";
pub(super) const SERVICE_GENERATION: &str = "v173";
pub(super) const EXPECTED: super::Counts = super::Counts {
    files: 413_571,
    directories: 13,
    logical: 134_663_299_285,
    allocated_files: 129_322_577_920,
};
pub(super) const EVENTS: &[(&str, &str)] = &[
    (
        "39f53479d3a045ac8e11786248231fbf",
        "s=d048fb8ccd4e4326a91b8c5edb351816;i=9e2566;b=3b17d0055c3a4a0e8841da097e0957b5;m=69cb912eae;t=660d305e831d7;x=ec9c05d97960a311",
    ),
    (
        "de5b426a63be47a7b6ac3eaac82e2f6f",
        "s=d048fb8ccd4e4326a91b8c5edb351816;i=9e4013;b=3b17d0055c3a4a0e8841da097e0957b5;m=6a2cf68010;t=660d3674d8339;x=1f6f0dad5fdb637",
    ),
    (
        "7ad2d189f7e94e70a38c781354912448",
        "s=d048fb8ccd4e4326a91b8c5edb351816;i=9e4015;b=3b17d0055c3a4a0e8841da097e0957b5;m=6a2cff61bf;t=660d3675664e7;x=cdeb485a4247e9f5",
    ),
    (
        "9d1aaa27d60140bd96365438aad20286",
        "s=d048fb8ccd4e4326a91b8c5edb351816;i=9e4016;b=3b17d0055c3a4a0e8841da097e0957b5;m=6a2cff62ca;t=660d3675665f3;x=89b15a6f07bf9640",
    ),
];
pub(super) const ORIGINALS: &str = include_str!("originals.tsv");
pub(super) const RETAINED: &str = include_str!("retained.tsv");
