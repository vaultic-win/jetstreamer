//! Bind the shared read-only selector to the stopped epoch 167 source and its decoded seam.
use super::selected_prefix::{self, PrefixScope};
use std::{error::Error, fs::File, io, os::unix::fs::MetadataExt};

pub(super) const SOURCE: &str = concat!(
    "/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1/",
    "replacement-source-index-v1-20261121/cold-source-index-v3-20261122/private/",
    "destination-e677f81687d92afb1ef9d81f2d57842d0c8bd0d94c6353aa87a7ddc53eb10d0f/",
    "work/root-cohort-167-167/run-660590-1795377153608080439/archives/epoch-167.jet"
);
const BYTES: u64 = 101_301_229_551;

pub(super) fn original_identity(file: &File) -> io::Result<()> {
    let m = file.metadata()?;
    if !m.is_file()
        || m.nlink() != 1
        || (m.dev(), m.ino(), m.len()) != (64512, 114491454, BYTES)
        || (m.mtime(), m.mtime_nsec()) != (1795745919, 857606760)
        || (m.ctime(), m.ctime_nsec()) != (1795745919, 857606760)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stopped epoch 167 archive changed",
        ));
    }
    Ok(())
}

pub(super) fn run() -> Result<(), Box<dyn Error>> {
    selected_prefix::verify(&PrefixScope {
        schema: "horizon-epoch167-private-selected-prefix-evidence-v1",
        path: SOURCE,
        epoch: 167,
        first: 72_144_000,
        physical_end: 72_512_768,
        bytes: BYTES,
        source_sha: "430561d1a97572e727e62e7c8d8991cac5adcfcd33f00e203525e1a7735ebea9",
        seam: 72_509_256,
        seam_hash: "1BK4wPkM1ZGbKrVAFdCzyXYWaB8bhPK7vBcfZqN8U1G",
        next_raw: Some(52_685_674_983),
        check_identity: original_identity,
    })
}
