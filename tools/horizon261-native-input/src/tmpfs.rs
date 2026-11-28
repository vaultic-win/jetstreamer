pub(crate) const BYTES: u64 = 128 << 30;
pub(crate) const INODES: u64 = 1_048_576;
const SOURCE: &str = "horizon261-native-cold";

include!("mount.rs");
