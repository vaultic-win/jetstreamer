pub(crate) const BYTES: u64 = 128 << 30;
pub(crate) const INODES: u64 = 1_048_576;
#[cfg(feature = "capped-worker")]
const SOURCE: &str = "horizon266-capped-native-cold";
#[cfg(not(feature = "capped-worker"))]
const SOURCE: &str = "horizon266-native-cold";
include!("../../horizon261-native-input/src/mount.rs");
