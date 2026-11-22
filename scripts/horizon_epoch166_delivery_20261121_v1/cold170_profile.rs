//! Guarded cold replay of epoch 170, admitted November 22.
//! The sealed receiver keeps the epoch lock and committed-source leases through upload.
#[cfg(any(
    feature = "source167",
    feature = "full172",
    feature = "retry10",
    feature = "metered168"
))]
compile_error!("cold170 cannot be combined with another producer generation");

pub(super) const EPOCH: u64 = 170;
pub(super) const DELIVERY: &str = "epoch170-cold-delivery-20261122-v13";
pub(super) const UNIT: &str = "horizon-publish-170-cold-retry13-committed.service";
pub(super) const ORIGIN: &str = "horizon-qualify-170-replacement-local3retry13-20261122.service";
pub(super) const GENERATION: &str = "c44b5215f8d949159e7ce9cf911e9be1";
pub(super) const LIVE: &str = "c73815d49529c42cc70f0e7ba11ab171f9b1ecdfb92c418afbe1b7631e57d898";
pub(super) const LIVE_SCHEMA: &str = "horizon-singleton-live-to-terminal-witness-v1";
pub(super) const LOCK: (u64, u64) = (64512, 113981960);

pub(super) mod controller {
    pub(in super::super) const FIELD: &str = "cold170_local_commit";
    pub(in super::super) const FIT: &str =
        "epoch170-cold-delivery-20261122-v13/capacity-tools-bounded/publication-fit";
    pub(in super::super) const RECEIVER: &str =
        "epoch170-cold-delivery-20261122-v13/receiver-tools/receiver.py";
    pub(in super::super) const FLAG: &str = "--cold170";
    pub(in super::super) const TERMINAL: &str = "terminal170";
    pub(in super::super) const TERMINAL_SHA: &str =
        "42b38c626ae197806d115882585772bbbd915d000285192f24a3a26a379e76c0";
}
