//! Committed archive from the guarded fourth cold epoch 168 replay.
#[cfg(any(
    feature = "retry10",
    feature = "metered168",
    feature = "source167",
    feature = "retry170",
    feature = "full172"
))]
compile_error!("cold168 cannot be combined with another producer generation");

pub(super) const EPOCH: u64 = 168;
pub(super) const DELIVERY: &str = "epoch168-cold-delivery-20261123-v4";
pub(super) const UNIT: &str = "horizon-publish-168-cold-retry4-committed.service";
pub(super) const ORIGIN: &str = "horizon-qualify-168-full-metered-cold-v4-20261123.service";
pub(super) const GENERATION: &str = "913443d7f9f44d7e9d3e0eec420acfab";
pub(super) const LIVE: &str = "0ab0e88e1182f1672c5abfb612256722b101ce6beb7a78abf361f445516598d8";
pub(super) const LIVE_SCHEMA: &str = "horizon-singleton-live-to-terminal-witness-v1";
pub(super) const LOCK: (u64, u64) = (64512, 103481818);

pub(super) mod controller {
    pub(in super::super) const FIELD: &str = "cold168_local_commit";
    pub(in super::super) const FIT: &str =
        "epoch168-cold-delivery-20261123-v4/capacity-tools-bounded/publication-fit";
    pub(in super::super) const RECEIVER: &str =
        "epoch168-cold-delivery-20261123-v4/receiver-tools/receiver.py";
    pub(in super::super) const FLAG: &str = "--cold168";
    pub(in super::super) const TERMINAL: &str = "terminal168";
    pub(in super::super) const TERMINAL_SHA: &str =
        "9b81b519d62027b770229eb2595d7907044bbf1bffb6e13f9b1f589d5b59aab7";
}
