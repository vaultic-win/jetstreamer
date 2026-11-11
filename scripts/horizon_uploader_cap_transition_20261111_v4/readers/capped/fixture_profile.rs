//! Compile-time isolated cap-transition fixture; never a production alias.
pub(crate) const UNIT: &str = "horizon-uploader-cap-transition-fixture-20261111-v2.service";
pub(crate) const CGROUP: &str = "/horizon_uploader_cap_transition_20261111_v2.slice/horizon_uploader_cap_transition_20261111_v2-fixture.slice/horizon-uploader-cap-transition-fixture-20261111-v2.service";
pub(crate) const ORIGINAL: &str = "/etc/systemd/system/horizon-uploader-cap-transition-fixture-20261111-v2.service";
pub(crate) const PRESERVED: &str = "/etc/systemd/system/.horizon-uploader-cap-transition-original-preserved-20261111-v1";
pub(crate) const OUTPUT: &str = "/var/lib/jetstreamer/horizon-uploader-cap-transition-20261111-v2";
