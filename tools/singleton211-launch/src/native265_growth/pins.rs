//! Exact sealed helper and source qualification for the closed native input experiment.
pub(super) const TEST_COUNT: u64 = 14;
pub(super) const HELPER_SHA: &str =
    "733771a1524281be7f0a05d3bdbb7fe319a15d08afc35bb09fd51ecfcaab711d";
pub(super) const SOURCE_COMMIT: &str = "7971542753ad6441416a467f98c1f67023d649ae";
pub(super) const QUALIFICATION_PATH: &str =
    "/var/lib/jetstreamer/horizon-native265-scratch-retirer-20261120-v2/qualification.json";
pub(super) const QUALIFICATION_SHA: &str =
    "94e83e8e6061c74c1adedcb8e1fffc2969e4807788f979a5bd772f3973e8fd01";
pub(super) const SEAL_PATH: &str = "/var/lib/jetstreamer/horizon-native265-scratch-retirer-20261120-v2/deployment-seal-receipt.json";
pub(super) const SEAL_SHA: &str =
    "7d36390c8d6cddcd79aeaeed9a1581ffebc04c21b0c09c80727a63471ca339e0";
pub(super) const MEMBERS: &[(&str, &str, u64, &str)] = &[
    (
        "native265-scratch-retire",
        "733771a1524281be7f0a05d3bdbb7fe319a15d08afc35bb09fd51ecfcaab711d",
        1041608,
        "0555",
    ),
    (
        "source.sha256",
        "e36a658c177d25842273fedc370a45295958b27ab4464e9661dc37eefe778536",
        630,
        "0444",
    ),
    (
        "qualification.json",
        "94e83e8e6061c74c1adedcb8e1fffc2969e4807788f979a5bd772f3973e8fd01",
        661,
        "0444",
    ),
    (
        "booking.json",
        "a3ae5dee49f1cffb656d449786f22bfd6a9b428cd77070bc65d7ac50904679ff",
        2058,
        "0444",
    ),
    (
        "build",
        "18a4ea2c8e097e93a3bdb2de7f6ce15d069ece3ddb1c85dcd542622d1a1a24cc",
        1178,
        "0444",
    ),
    (
        "build.log",
        "bd3d3980784845924f8ea35a9151e45624f3bbf6a2f6c1e43dbe9f84deff9b4c",
        4275,
        "0444",
    ),
];
