//! Guarded cold replay of epoch 167, admitted November 22.
//! The sealed receiver keeps the epoch lock and committed-source leases through upload.
#[cfg(any(
    feature = "retry170",
    feature = "full172",
    feature = "retry10",
    feature = "metered168"
))]
compile_error!("cold167 cannot be combined with another producer generation");

pub(super) const EPOCH: u64 = 167;
pub(super) const DELIVERY: &str = "epoch167-cold-delivery-20261122-v3";
pub(super) const UNIT: &str = "horizon-publish-167-cold-source-index-committed.service";
pub(super) const ORIGIN: &str = "horizon-qualify-167-source-index-v3-20261122.service";
pub(super) const GENERATION: &str = "6e4b569b61d7420fb30a24a4ad0609dd";
pub(super) const LIVE: &str = "525b8104545f5d8a5716291e8540386932f49b1cfc096898fb380c602713c16e";
pub(super) const LIVE_SCHEMA: &str = "horizon-singleton-live-to-terminal-witness-v1";
pub(super) const LOCK: (u64, u64) = (64512, 114491424);

pub(super) mod controller {
    pub(in super::super) const FIELD: &str = "cold167_local_commit";
    pub(in super::super) const FIT: &str =
        "epoch167-cold-delivery-20261122-v3/capacity-tools-bounded/publication-fit";
    pub(in super::super) const RECEIVER: &str =
        "epoch167-cold-delivery-20261122-v3/receiver-tools/receiver.py";
    pub(in super::super) const FLAG: &str = "--cold167";
    pub(in super::super) const TERMINAL: &str = "terminal167";
    pub(in super::super) const TERMINAL_SHA: &str =
        "72c2d093719693931e5e2282334256ac711ab72b8f766872aee14f10674e96de";
}
