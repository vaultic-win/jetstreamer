//! Pinned mainnet compact-index dimensions. The prefixes bind both tables to the CAR root.
macro_rules! register {
    ($epoch:literal, $car:literal, $slot_bytes:literal, $entries:literal, $slot_buckets:literal, $cid_bytes:literal, $cid_buckets:literal) => {
        pub const EPOCH: u64 = $epoch;
        pub const CAR: u64 = $car;
        pub const SLOT_BYTES: usize = $slot_bytes;
        pub const SLOT_ENTRIES: usize = $entries;
        pub const SLOT_BUCKETS: usize = $slot_buckets;
        pub const CID_BYTES: u64 = $cid_bytes;
        pub const CID_BUCKETS: usize = $cid_buckets;
        pub const SLOT_PREFIX: &[u8; 4096] =
            include_bytes!(concat!(stringify!($epoch), "-slot-to-cid.bin"));
        pub const CID_PREFIX: &[u8; 4096] =
            include_bytes!(concat!(stringify!($epoch), "-cid-prefix.bin"));
    };
}

#[cfg(epoch271)]
register!(
    271,
    346_337_409_273,
    14_976_550,
    383_993,
    44,
    8_241_976_270,
    300_000
);
#[cfg(epoch272)]
register!(
    272,
    504_331_014_291,
    16_055_407,
    411_656,
    44,
    12_351_946_162,
    300_000
);
#[cfg(epoch273)]
register!(
    273,
    505_109_600_074,
    16_016_407,
    410_656,
    44,
    12_266_939_638,
    300_000
);
#[cfg(epoch274)]
register!(
    274,
    500_678_680_702,
    16_112_074,
    413_109,
    44,
    12_180_921_202,
    300_000
);
