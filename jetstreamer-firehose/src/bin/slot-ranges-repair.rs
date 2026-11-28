//! Exact, no-clobber candidate repair for the six decoded epoch 253–255 index anomalies.
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    env,
    error::Error,
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const SOURCE: &str = "/home/ubuntu/.jetstreamer-private/qualification-252-256-source-20261118-v1";

struct Patch {
    slot: u64,
    before: (u64, u32),
    after: (u64, u32),
}

struct Epoch {
    number: u64,
    source_sha256: &'static str,
    car_bytes: u64,
    expected_present: u64,
    patches: &'static [Patch],
}

const EPOCHS: &[Epoch] = &[
    Epoch {
        number: 253,
        source_sha256: "3759b10bd20360f802d92345fa7739a80a2c54464bbbbc678105ce6ce5d48ee7",
        car_bytes: 423_894_870_459,
        expected_present: 396_322,
        patches: &[
            Patch {
                slot: 109_428_259,
                before: (130_873_622_537, 2_414_326_479),
                after: (0, 0),
            },
            Patch {
                slot: 109_428_260,
                before: (0, 0),
                after: (130_873_622_537, 131_474),
            },
        ],
    },
    Epoch {
        number: 254,
        source_sha256: "1c4963c2691ca21fee6d903af8ff33c8f128f2f876c610cc51be1553ca411965",
        car_bytes: 405_916_264_315,
        expected_present: 389_645,
        patches: &[
            Patch {
                slot: 109_741_316,
                before: (7_732_870_003, 3_788_604_592),
                after: (11_520_834_698, 639_897),
            },
            Patch {
                slot: 110_101_496,
                before: (349_567_601_706, 3_123_479_882),
                after: (0, 0),
            },
            Patch {
                slot: 110_101_500,
                before: (0, 0),
                after: (349_567_601_706, 1_296_668),
            },
        ],
    },
    Epoch {
        number: 255,
        source_sha256: "f46b4633a7a9a4dd78121bc87e091cd88747b4c013c6957eb48ec1255101e90a",
        car_bytes: 421_724_513_371,
        expected_present: 399_771,
        patches: &[
            Patch {
                slot: 110_170_054,
                before: (9_771_314_983, 3_109_582_664),
                after: (0, 0),
            },
            Patch {
                slot: 110_170_056,
                before: (0, 0),
                after: (9_771_314_983, 1_179_831),
            },
            Patch {
                slot: 110_193_392,
                before: (29_600_843_771, 1_977_255_083),
                after: (31_577_078_110, 1_020_744),
            },
            Patch {
                slot: 110_349_343,
                before: (185_447_524_890, 781_914_249),
                after: (0, 0),
            },
            Patch {
                slot: 110_349_344,
                before: (0, 0),
                after: (185_447_524_890, 1_494_659),
            },
        ],
    },
];

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn record(bytes: &[u8], index: usize) -> (u64, u32) {
    let at = index * 12;
    (
        u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap()),
        u32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap()),
    )
}

fn scan(bytes: &[u8], epoch: &Epoch) -> Result<(u64, u64, u64)> {
    let mut present = 0;
    let mut gaps = 0;
    let mut maximum_length = 0;
    let mut previous_end = 59_u64;
    for index in 0..432_000 {
        let (offset, length) = record(bytes, index);
        if length == 0 {
            if offset != 0 {
                return Err(
                    format!("epoch {} nonzero skipped offset at {index}", epoch.number).into(),
                );
            }
            continue;
        }
        let end = offset
            .checked_add(length as u64)
            .ok_or("CAR range end overflow")?;
        if offset < previous_end || end > epoch.car_bytes {
            return Err(format!(
                "epoch {} overlap or out-of-bounds at slot {}",
                epoch.number,
                epoch.number * 432_000 + index as u64
            )
            .into());
        }
        gaps += u64::from(offset > previous_end);
        present += 1;
        maximum_length = maximum_length.max(length as u64);
        previous_end = end;
    }
    if present != epoch.expected_present {
        return Err(format!("epoch {} present slot count changed", epoch.number).into());
    }
    Ok((present, gaps, maximum_length))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::File::open(path.parent().ok_or("missing output parent")?)?.sync_all()?;
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = env::args_os().collect();
    if args.len() != 2 || unsafe { libc::geteuid() } != 0 {
        return Err("usage: root slot-ranges-repair PRIVATE_OUTPUT_DIRECTORY".into());
    }
    let output = PathBuf::from(&args[1]);
    let meta = fs::symlink_metadata(&output)?;
    if !output.is_absolute()
        || output.canonicalize()? != output
        || !meta.is_dir()
        || meta.uid() != 0
        || meta.mode() & 0o077 != 0
    {
        return Err("output must be a canonical root-private directory".into());
    }
    let mut rows = Vec::new();
    for epoch in EPOCHS {
        let input = PathBuf::from(format!(
            "{SOURCE}/{0}/epoch-{0}-slot-ranges.raw",
            epoch.number
        ));
        let input_meta = fs::symlink_metadata(&input)?;
        if !input_meta.is_file() || input_meta.uid() != 0 || input_meta.mode() & 0o022 != 0 {
            return Err("source index is not root-owned immutable input".into());
        }
        let mut bytes = fs::read(&input)?;
        if bytes.len() != 432_000 * 12 || sha(&bytes) != epoch.source_sha256 {
            return Err(format!("epoch {} source index changed", epoch.number).into());
        }
        for patch in epoch.patches {
            let index = usize::try_from(patch.slot - epoch.number * 432_000)?;
            if record(&bytes, index) != patch.before {
                return Err(format!(
                    "epoch {} slot {} did not match exact repair input",
                    epoch.number, patch.slot
                )
                .into());
            }
            let at = index * 12;
            bytes[at..at + 8].copy_from_slice(&patch.after.0.to_le_bytes());
            bytes[at + 8..at + 12].copy_from_slice(&patch.after.1.to_le_bytes());
        }
        let (present, gaps, maximum_length) = scan(&bytes, epoch)?;
        let target = output.join(format!("epoch-{}-slot-ranges.repaired.raw", epoch.number));
        write_new(&target, &bytes)?;
        rows.push(json!({
            "epoch":epoch.number,"source":input,"source_sha256":epoch.source_sha256,
            "repaired":target,"repaired_sha256":sha(&bytes),"car_bytes":epoch.car_bytes,
            "present_slots":present,"gaps":gaps,"maximum_range_bytes":maximum_length,
            "patches":epoch.patches.iter().map(|p|json!({"slot":p.slot,"before":[p.before.0,p.before.1],"after":[p.after.0,p.after.1]})).collect::<Vec<_>>()
        }));
    }
    let mut receipt = serde_json::to_vec_pretty(&json!({
        "schema":"horizon253255-exact-slot-ranges-repair-candidate-v1",
        "rows":rows,"full_index_nonoverlap_and_bounds_checked":true,
        "native_car_boundary_proofs_required_for_admission":true,
        "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false
    }))?;
    receipt.push(b'\n');
    write_new(&output.join("repair-candidate.json"), &receipt)?;
    println!("{}", output.join("repair-candidate.json").display());
    Ok(())
}
