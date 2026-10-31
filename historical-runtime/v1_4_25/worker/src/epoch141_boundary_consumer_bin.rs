//! Fixed-input, read-only pinned-SDK census consumption. No Bank/replay hook.
use serde::Deserialize;
use sha2_fast::{Digest, Sha256};
use solana_sdk::hash::Hash;
use std::{
    collections::HashSet,
    env,
    fs::{self, File, Metadata, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    str::FromStr,
};

const INPUT: &str = "/usr/local/lib/jetstreamer/horizon-epoch141-boundary-input-candidate-20261022-v1/boundaries.json";
const INPUT_SHA: &str = "e371b3546d62e5fdac79a497607b61ea2647c3c5d410157b3ff456709f78be4a";
const CAP: u64 = 32 << 20;
const GROUPS: usize = 18_283;
const BOUNDARIES: usize = 84_597;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Census {
    schema: String,
    slots: Vec<Group>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Group {
    slot: u64,
    parent_slot: u64,
    boundaries: Vec<Boundary>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Boundary {
    tick_ordinal: u64,
    hash: String,
}

fn validate(bytes: &[u8]) -> Result<usize, String> {
    if bytes.len() as u64 > CAP {
        return Err("census exceeds byte cap".into());
    }
    let census: Census = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if census.schema != "jetstreamer-epoch141-decoded-gap-boundaries-v1"
        || census.slots.len() != GROUPS
    {
        return Err("wrong schema or incomplete target census".into());
    }
    let mut seen = HashSet::new();
    let mut previous = None;
    for group in census.slots {
        if group.parent_slot < 60_911_751
            || group.slot >= 61_344_000
            || group.slot <= group.parent_slot
            || previous.map_or(false, |p| group.slot <= p)
        {
            return Err("foreign, non-increasing or invalid slot/parent".into());
        }
        let count = group.slot - group.parent_slot;
        if count < 2 || count as usize != group.boundaries.len() {
            return Err("gap boundary count differs from parent jump".into());
        }
        for (index, boundary) in group.boundaries.iter().enumerate() {
            if boundary.tick_ordinal != 64 * (index as u64 + 1) {
                return Err("noncanonical pinned 64tick boundary ordinal".into());
            }
            let hash = Hash::from_str(&boundary.hash).map_err(|e| e.to_string())?;
            if hash == Hash::default() || hash.to_string() != boundary.hash || !seen.insert(hash) {
                return Err("zero, noncanonical or repeated boundary hash".into());
            }
        }
        previous = Some(group.slot);
    }
    if seen.len() != BOUNDARIES {
        return Err("incomplete boundary census".into());
    }
    Ok(seen.len())
}

fn identity(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mode() == b.mode()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
        && a.nlink() == b.nlink()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}
fn digest_reader(mut file: File) -> Result<String, String> {
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    Ok(format!("{:x}", digest.finalize()))
}
fn run() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 3
        || args[1] != "--self-sha256"
        || args[2].len() != 64
        || !args[2]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("usage: jetstreamer-epoch141-boundary-consumer --self-sha256 HEX".into());
    }
    if digest_reader(File::open("/proc/self/exe").map_err(|e| e.to_string())?)? != args[2] {
        return Err("running executable digest differs".into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(INPUT)
        .map_err(|e| e.to_string())?;
    let before = file.metadata().map_err(|e| e.to_string())?;
    if !before.is_file()
        || before.nlink() != 1
        || before.uid() != 0
        || before.mode() & 0o222 != 0
        || before.len() == 0
        || before.len() > CAP
    {
        return Err("input is not bounded immutable root-owned single-link regular file".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(CAP + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if format!("{:x}", Sha256::digest(&bytes)) != INPUT_SHA {
        return Err("input digest differs from exact collected census".into());
    }
    let count = validate(&bytes)?;
    let after = file.metadata().map_err(|e| e.to_string())?;
    let path = fs::symlink_metadata(Path::new(INPUT)).map_err(|e| e.to_string())?;
    if !identity(&before, &after) || !identity(&before, &path) || path.file_type().is_symlink() {
        return Err("input identity changed".into());
    }
    println!(
        "{}",
        serde_json::json!({"schema":"jetstreamer-epoch141-pinned-boundary-consumer-diagnostic-v1",
        "backend":"solana-v1.4.25","input":INPUT,"input_sha256":INPUT_SHA,"self_sha256":args[2],
        "target_count":GROUPS,"boundary_count":count,"hidden_boundaries":count-GROUPS,"ticks_per_slot":64,
        "complete_census_consumed":true,"bank_loaded":false,"canonical_root_qualified":false,
        "runtime_boundary_input_authorized":false,"replay_launch_authorized":false,
        "runtime_promotion_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false})
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> serde_json::Value {
        let mut slots = Vec::new();
        for index in 0..GROUPS {
            let count = if index < BOUNDARIES - 4 * GROUPS {
                5
            } else {
                4
            };
            let mut boundaries = Vec::new();
            for ordinal in 1..=count {
                let mut bytes = [31u8; 32];
                bytes[..8].copy_from_slice(&(index as u64).to_le_bytes());
                bytes[8..16].copy_from_slice(&(ordinal as u64).to_le_bytes());
                boundaries.push(serde_json::json!({"tick_ordinal":64*ordinal,"hash":Hash::new(&bytes).to_string()}));
            }
            let slot = 60_911_776 + index as u64 * 10;
            slots.push(serde_json::json!({"slot":slot,"parent_slot":slot-count as u64,"boundaries":boundaries}));
        }
        serde_json::json!({"schema":"jetstreamer-epoch141-decoded-gap-boundaries-v1","slots":slots})
    }
    #[test]
    fn complete_synthetic_census_and_rejections() {
        let good = fixture();
        assert_eq!(
            validate(&serde_json::to_vec(&good).unwrap()).unwrap(),
            BOUNDARIES
        );
        for kind in 0..9 {
            let mut bad = good.clone();
            match kind {
                0 => {
                    bad["slots"].as_array_mut().unwrap().pop();
                }
                1 => bad["slots"][1]["slot"] = bad["slots"][0]["slot"].clone(),
                2 => bad["slots"][0]["parent_slot"] = bad["slots"][0]["slot"].clone(),
                3 => bad["slots"][0]["boundaries"][0]["tick_ordinal"] = serde_json::json!(63),
                4 => {
                    bad["slots"][1]["boundaries"][0]["hash"] =
                        bad["slots"][0]["boundaries"][0]["hash"].clone()
                }
                5 => bad["slots"][0]["boundaries"][0]["hash"] = serde_json::json!("bad!"),
                6 => {
                    bad["slots"][0]["boundaries"][0]["hash"] =
                        serde_json::json!(Hash::default().to_string())
                }
                7 => bad["slots"][0]["parent_slot"] = serde_json::json!(1),
                _ => bad["slots"][0]["unknown"] = serde_json::json!(true),
            }
            assert!(
                validate(&serde_json::to_vec(&bad).unwrap()).is_err(),
                "case{}",
                kind
            );
        }
    }
}
