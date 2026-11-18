//! Native Block checks at every gap edge of an exact repaired slot index.
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    env,
    error::Error,
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};

const SOURCE: &str = "/home/ubuntu/.jetstreamer-private/qualification-252-256-source-20261118-v1";
const PROBE_SHA256: &str = "1edef7d09de77b97fc8f43c961f41dd73d07330b454209bfdc1f047ee2e7781b";

struct Spec {
    epoch: u64,
    index_sha256: &'static str,
    header_sha256: &'static str,
    car_bytes: u64,
    present: u64,
    gaps: u64,
}

const SPECS: &[Spec] = &[
    Spec {
        epoch: 253,
        index_sha256: "688a88bce858f48c4f1ec123dcc567d22f4fd959d9a55e01d86b9450be538b2c",
        header_sha256: "1292c86d76a06a4449ed28dc3c3f216fc8fc90dc93564d5061964160761e7f06",
        car_bytes: 423_894_870_459,
        present: 396_322,
        gaps: 21,
    },
    Spec {
        epoch: 254,
        index_sha256: "c9cbfb189d616b42de31a3b59f691d7c3ebcc225a9b51e1dd4ba76f076733edc",
        header_sha256: "e7071dc8e93a1f0e8b01e60c8fdce4c932bffc07ff003df420dac0f3cca20e61",
        car_bytes: 405_916_264_315,
        present: 389_645,
        gaps: 17,
    },
    Spec {
        epoch: 255,
        index_sha256: "16ee2a7b9461f20afcfb814b48a281f0e5c423b4cbe0ebd0a3079576198928b4",
        header_sha256: "77eed02ddca5b0094b76096738299608e9c8e7a551b9d50070e822f7f00a2bee",
        car_bytes: 421_724_513_371,
        present: 399_771,
        gaps: 19,
    },
];

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn record(bytes: &[u8], index: usize) -> (u64, u64) {
    let at = index * 12;
    (
        u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap()),
        u32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap()) as u64,
    )
}

fn regular_root(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.nlink() != 1
        || meta.mode() & 0o022 != 0
        || path.canonicalize()? != path
    {
        return Err("evidence must be canonical root-owned immutable input".into());
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = env::args_os().collect();
    if args.len() != 4 || unsafe { libc::geteuid() } != 0 {
        return Err(
            "usage: root slot-ranges-edge-audit EPOCH PRIVATE_CANDIDATE_DIR CAR_PROBE".into(),
        );
    }
    let epoch: u64 = args[1].to_string_lossy().parse()?;
    let spec = SPECS
        .iter()
        .find(|spec| spec.epoch == epoch)
        .ok_or("unsupported epoch")?;
    let directory = PathBuf::from(&args[2]);
    let meta = fs::symlink_metadata(&directory)?;
    if !directory.is_absolute()
        || directory.canonicalize()? != directory
        || !meta.is_dir()
        || meta.uid() != 0
        || meta.mode() & 0o077 != 0
    {
        return Err("candidate directory must be canonical root-private state".into());
    }
    let index = directory.join(format!("epoch-{epoch}-slot-ranges.repaired.raw"));
    regular_root(&index)?;
    let bytes = fs::read(&index)?;
    if bytes.len() != 432_000 * 12 || sha(&bytes) != spec.index_sha256 {
        return Err("repaired index binding changed".into());
    }
    let probe = PathBuf::from(&args[3]);
    regular_root(&probe)?;
    if sha(&fs::read(&probe)?) != PROBE_SHA256 {
        return Err("native CAR probe binary changed".into());
    }
    let header = PathBuf::from(format!("{SOURCE}/{epoch}/car-header-0-4095.bin"));
    regular_root(&header)?;
    if sha(&fs::read(&header)?) != spec.header_sha256 {
        return Err("CAR header binding changed".into());
    }
    let mut edges = BTreeSet::new();
    let mut previous: Option<(u64, u64)> = None;
    let mut present = 0;
    let mut gaps = 0;
    for i in 0..432_000 {
        let (offset, length) = record(&bytes, i);
        if length == 0 {
            continue;
        }
        let slot = epoch * 432_000 + i as u64;
        let end = offset.checked_add(length).ok_or("range overflow")?;
        if end > spec.car_bytes {
            return Err("range extends past CAR".into());
        }
        if let Some((prior_slot, prior_end)) = previous {
            if offset < prior_end {
                return Err("repaired index overlap".into());
            }
            if offset > prior_end {
                gaps += 1;
                edges.insert(prior_slot);
                edges.insert(slot);
            }
        } else {
            edges.insert(slot);
        }
        previous = Some((slot, end));
        present += 1;
    }
    edges.insert(previous.ok_or("empty index")?.0);
    if present != spec.present || gaps != spec.gaps {
        return Err("repaired index census changed".into());
    }
    let mut checks = Vec::new();
    for slot in edges {
        let (offset, length) = record(&bytes, (slot - epoch * 432_000) as usize);
        let output = Command::new("/usr/bin/timeout")
            .arg("30s")
            .arg(&probe)
            .arg(epoch.to_string())
            .arg(slot.to_string())
            .arg(offset.to_string())
            .arg(length.to_string())
            .arg(spec.car_bytes.to_string())
            .arg(&header)
            .arg(spec.header_sha256)
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "slot {slot} native boundary failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        let proof = String::from_utf8(output.stdout)?;
        if !proof.starts_with(&format!(
            "epoch={epoch} slot={slot} offset={offset} length={length} "
        )) {
            return Err(
                format!("slot {slot} native proof did not bind the requested range").into(),
            );
        }
        checks.push(json!({"slot":slot,"offset":offset,"length":length,"proof":proof.trim()}));
    }
    let receipt_path = directory.join(format!("epoch-{epoch}-gap-edge-audit.json"));
    let mut receipt = serde_json::to_vec_pretty(&json!({
        "schema":"horizon-repaired-slot-ranges-native-gap-edge-audit-v1",
        "epoch":epoch,"repaired_index":index,"repaired_index_sha256":spec.index_sha256,
        "car_header":header,"car_header_sha256":spec.header_sha256,"car_bytes":spec.car_bytes,
        "probe_binary":probe,"probe_binary_sha256":PROBE_SHA256,
        "present_slots":present,"gaps":gaps,"checked_edges":checks,
        "all_gap_edges_native_decoded":true,"replay_launch_authorized":false,
        "publication_authorized":false,"r2_mutations":false
    }))?;
    receipt.push(b'\n');
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(&receipt_path)?;
    file.write_all(&receipt)?;
    file.sync_all()?;
    fs::File::open(&directory)?.sync_all()?;
    println!("{}", receipt_path.display());
    Ok(())
}
