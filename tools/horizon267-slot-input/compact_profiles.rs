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
#[cfg(epoch275)]
register!(
    275,
    490_317_638_534,
    15_951_043,
    408_980,
    44,
    11_882_647_846,
    300_000
);
#[cfg(epoch276)]
register!(
    276,
    508_471_695_938,
    16_064_377,
    411_886,
    44,
    12_366_825_202,
    300_000
);
#[cfg(epoch277)]
register!(
    277,
    508_122_442_412,
    15_887_200,
    407_343,
    44,
    12_311_386_762,
    300_000
);
#[cfg(epoch278)]
register!(
    278,
    497_956_610_737,
    15_877_567,
    407_096,
    44,
    12_022_297_810,
    300_000
);
#[cfg(epoch279)]
register!(
    279,
    499_133_102_307,
    15_952_486,
    409_017,
    44,
    12_014_595_334,
    300_000
);
#[cfg(epoch280)]
register!(
    280,
    497_546_531_409,
    15_898_501,
    407_634,
    41,
    12_007_079_718,
    100_046
);
#[cfg(epoch281)]
register!(
    281,
    466_037_864_351,
    15_839_494,
    406_121,
    41,
    11_021_980_254,
    91_838
);
#[cfg(epoch282)]
register!(
    282,
    482_279_853_071,
    15_635_446,
    400_889,
    41,
    11_246_594_502,
    93_710
);
