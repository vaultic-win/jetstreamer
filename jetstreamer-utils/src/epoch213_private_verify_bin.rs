//! Exact retained213 profile; existing sealed deployments are unchanged.
mod profile {
    pub const UNIT: &str = "horizon-qualify-213-checkpoint-continuation-ae43646-v1.service";
    pub const INVOCATION: &str = "1dfd29e7ced140b3ba407359cbdc0ee1";
    pub const SOURCE: &str = "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-213-ae43646-v1/output/epoch-213-checkpoint-restart-v4.jet";
    pub const PROVENANCE: &str = "a85a2df80f7d6ca8720e597f372661df65fd0d891e41d420a3db6f866ab4121b";
    pub const EXPECTATION: &str =
        "f7bb330186a8fbcc438b0fa49e903af5be5a1c30092f7cd434a86f6b2916bea5";
    pub const FULL: &str = "067ca3124a47cdbff4545918c65ff070df80f96ee0caf648873036ed1f11fcb9";
    pub const PLUGIN: &str = "167954ad8087a4214dbdd65c8f72690bd66d7aa6637179ddf85db85b9a03a547";
    pub const PREFIX: &str = "e9b0fa7bbad1fdbf86d9d564baa0c377003ec20e40709dae249fac8ba0cb91d9";
    pub const SUFFIX: &str = "3360ba3da029865522511a821c30851447a7a6eca5e9fe28cd536181edf07d03";
    pub const SNAPSHOT: &str = "bae33ebaeaa7bfb3c4c9230ef9f7aabb2e68628ac2fc0a8d435b7e2e976bbe08";
    pub const NODE: &str = "83398ece0317a6ab3b321f9e1eb8d0c7f76f21f1cb5997cd07899ba19f2992f3";
    pub const PRODUCER_PLAN: &str =
        "83eeb441502e39510ad7610ae6dac9165d9f5a6f32afaeab1f19205e9ab6f144";
    // Older measured growth + four-epoch century floor, plus the entire 225 budget.
    // Fresh admission may require more, never less than this reviewed baseline.
    pub const MIN_PROTECTED: u64 = 2_498_483_426_006 + 256 * 1024 * 1024 * 1024;

    pub const EPOCH: u64 = 213;
    pub const PLAN_SCHEMA: &str = "jetstreamer-private-epoch213-verification-plan-v1";
    pub const OUTCOME_SCHEMA: &str = "jetstreamer-private-epoch213-checkpoint-continuation-v1";
    pub const EXPECTATION_SCHEMA: &str = "jetstreamer-private-epoch213-provenance-expectation-v1";
    pub const INTENT_SCHEMA: &str = "jetstreamer-private-epoch213-verification-intent-v1";
    pub const FULL_SCHEMA: &str = "jetstreamer-private-epoch213-full-scan-v1";
    pub const VERIFICATION_SCHEMA: &str = "jetstreamer-private-epoch213-verification-v1";
    pub const PRIVATE_PREFIX: &str = "horizon-213-private-scan-";
    pub const ARCHIVE_NAME: &str = "epoch-213.jet";
    pub const ROOT_SLOT: u64 = 92447542;
    pub const ANCHOR_SLOT: u64 = 92015999;
    pub const ANCHOR_HASH: &str = "9xdazt5sEpSUzwYi9nTRMmXJDuP4kLdcY9ZXAM5oQVi7";
    pub const TERMINAL_SLOT: u64 = 92447999;
    pub const TERMINAL_HASH: &str = "2SMgef3T3X5aeHZy1USrSR5qEJqwQbsz2yVr3tRs25Ki";
    pub const COMPLETION_MARKER: &str = "private epoch213 checkpoint continuation assembled; independent final/plugin verification and publication gates remain closed";
    pub const PRODUCER_EXE: &str =
        "/var/lib/jetstreamer/horizon-213-checkpoint-continuation-ae43646-v1/jetstreamer-node";
    pub const PRODUCER_PID: &str = "847475";
    pub const BOUNDARY_METADATA: Option<&str> = None;
    pub const BOUNDARY_SCHEMA: &str = "";
    pub const PRIOR_NATIVE: Option<&str> = None;
    pub const REMAINING_SUFFIX: Option<u64> = None;
}
use profile::*;
include!("private_v4_verify_runner.rs");
include!("epoch213_private_verify_tests.rs");
