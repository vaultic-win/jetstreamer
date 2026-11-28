//! Fixed bindings for the source-index and retry10 native singleton writers.
#[cfg(feature = "source167")]
macro_rules! select {
    ($source:literal, $retry:literal, $half:literal) => {
        $source
    };
}
#[cfg(feature = "retry170")]
macro_rules! select {
    ($source:literal, $retry:literal, $half:literal) => {
        $retry
    };
}

#[cfg(feature = "full172")]
macro_rules! select {
    ($source:literal, $retry:literal, $half:literal) => {
        $half
    };
}

pub(super) const EPOCH: u64 = select!(167, 170, 172);
pub(super) const DELIVERY: &str = select!(
    "epoch167-current-delivery-20261121-v1",
    "epoch170-current-delivery-20261121-v1",
    "epoch172-current-delivery-20261121-v1"
);
pub(super) const UNIT: &str = select!(
    "horizon-publish-167-source-index-committed.service",
    "horizon-publish-170-retry10-committed.service",
    "horizon-publish-172-full-committed.service"
);
pub(super) const ORIGIN: &str = select!(
    "horizon-qualify-167-source-index-v1-20261121.service",
    "horizon-qualify-170-replacement-local3retry10-20261121-v1.service",
    "horizon-qualify-172-full-half-core-20261120-v1.service"
);
pub(super) const GENERATION: &str = select!(
    "0876e9944c784b41afeff1b666539ead",
    "a456b826ce1c4634a2df66d66c5cc07f",
    "0e17b745938546608b0bdc52815151d0"
);
pub(super) const LIVE: &str = select!(
    "f9b3e1fbdddfd983f1589ead46439a5bde07762cfc6151a8cfbb6f5580e818be",
    "8221f8f31df8bd360b7ef95a82b6cbf04c27fff2a0dc53508f6c79d1731dff7b",
    "4d4e760ba2d4cb53368cfc7c616044f789f82f66934499ad91e5797f41cf6dc2"
);
pub(super) const LIVE_SCHEMA: &str = "horizon-singleton-live-to-terminal-witness-v1";

pub(super) mod controller {
    pub(in super::super) const FIELD: &str = select!(
        "indexed167_local_commit",
        "recovered170_local_commit",
        "full172_local_commit"
    );
    pub(in super::super) const FIT: &str = select!(
        "epoch167-current-delivery-20261121-v1/capacity-tools/publication-fit",
        "epoch170-current-delivery-20261121-v1/capacity-tools/publication-fit",
        "epoch172-current-delivery-20261121-v1/capacity-tools/publication-fit"
    );
    pub(in super::super) const RECEIVER: &str = select!(
        "epoch167-current-delivery-20261121-v1/publisher-tools/receiver.py",
        "epoch170-current-delivery-20261121-v1/publisher-tools/receiver.py",
        "epoch172-current-delivery-20261121-v1/publisher-tools/receiver.py"
    );
    pub(in super::super) const FLAG: &str = select!("--source167", "--retry170", "--full172");
    pub(in super::super) const TERMINAL: &str =
        select!("terminal167", "terminal170", "terminal172");
    pub(in super::super) const TERMINAL_SHA: &str = select!(
        "e19166571e5e23338d6db68a14ed354d38c2b9f34317ac8cd1836da23812606a",
        "fca4c122b08d414dfdb4765680bfef7ecf5a7e5b15fb993578e8f1cdd91b62ed",
        "fa1330215d2d6238f432fc32e3352a9332e729d75aa49c34b39852131973bb0b"
    );
}

pub(super) const LOCK: (u64, u64) = (64512, select!(113979804, 113907416, 115671412));
