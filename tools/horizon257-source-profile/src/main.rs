mod bootstrap;
mod edges;
mod manifest;
mod ranges;
mod repair;
mod repair261;
mod repair262;
mod tables;
mod transport;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

const PACKET: &str = "/var/lib/jetstreamer/horizon257-index-source-20261120-v1";
const MANIFEST: &str = "/var/lib/jetstreamer/horizon257-singleton-manifest-20261120-v1";
const SEAL: &str = "2ccc8beeb75fa215b115b78f0860d2a53b4eb2b429322b24b027eb067cb194af";
const MANIFEST_SEAL: &str = "04b5813b281b1f2fcf79c97213291c27030a0a3a0f76df3c28779b8644e7c013";
const MANIFEST_FILE: &str = "preflight-257-singleton.json";
const RAW: &str = "epoch-257-slot-ranges.raw";
const RAW_SHA: &str = "b7b842362218277c70d7e9d2b7e5211ae4215943702cfb61683e0c0b732d3b18";
const SEALER: &str = "faf7aa8270b3472969bf394d4486cdf94445e30e4f15bc6acd38bed56880877a";

fn hash(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}
fn identity(m: &fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

fn read_checked(dir: &Path, name: &str, limit: u64, expected: &str) -> Result<Vec<u8>> {
    let path = dir.join(name);
    ensure!(path.canonicalize()? == path, "source path is not canonical");
    let before = fs::symlink_metadata(&path)?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.gid() == 0
            && before.nlink() == 1
            && before.mode() & 0o777 == 0o444
            && before.len() <= limit,
        "unsafe sealed member {name}"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    ensure!(
        identity(&file.metadata()?) == identity(&before),
        "changed before read"
    );
    let mut bytes = Vec::new();
    (&file).take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.len()
            && hash(&bytes) == expected
            && identity(&file.metadata()?) == identity(&fs::symlink_metadata(path)?)
            && identity(&before) == identity(&file.metadata()?),
        "sealed member changed: {name}"
    );
    Ok(bytes)
}

fn packet(
    dir: &str,
    seal_sha: &str,
    names: &BTreeSet<String>,
) -> Result<BTreeMap<String, Vec<u8>>> {
    packet_bounded(dir, seal_sha, names, |name| {
        if name == RAW { 5_184_000 } else { 16_384 }
    })
}
fn packet_bounded(
    dir: &str,
    seal_sha: &str,
    names: &BTreeSet<String>,
    limit: impl Fn(&str) -> u64,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let dir = Path::new(dir);
    let md = fs::symlink_metadata(dir)?;
    ensure!(
        dir.canonicalize()? == dir && md.is_dir() && md.uid() == 0 && md.mode() & 0o222 == 0,
        "sealed package directory"
    );
    let seal: Value = serde_json::from_slice(&read_checked(
        dir,
        "deployment-seal-receipt.json",
        16384,
        seal_sha,
    )?)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == dir.to_str().context("path")?
            && seal["sealer_sha256"] == SEALER
            && seal["remote_mutations"] == false
            && seal["replay_launch_authorized"] == false,
        "seal identity"
    );
    let mut out = BTreeMap::new();
    for v in seal["members"].as_array().context("seal members")? {
        let name = v["name"].as_str().context("member name")?;
        ensure!(
            names.contains(name) && !out.contains_key(name) && v["mode"] == "0444",
            "wrong or duplicate seal member"
        );
        let limit = limit(name);
        let b = read_checked(
            dir,
            name,
            limit,
            v["sha256"].as_str().context("member digest")?,
        )?;
        ensure!(v["bytes"] == b.len(), "receipt byte count");
        out.insert(name.to_owned(), b);
    }
    ensure!(out.len() == names.len(), "missing sealed member");
    Ok(out)
}

fn inputs() -> BTreeSet<String> {
    let mut files: BTreeSet<_> = [
        RAW,
        "257.index.headers",
        "transport-review.json",
        "index-booking.json",
        "source-booking.json",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    for epoch in [256, 257] {
        for kind in ["car", "slot-to-cid", "cid-to-offset-and-size"] {
            for suffix in ["headers", "prefix"] {
                files.insert(format!("{epoch}.{kind}.{suffix}"));
            }
        }
    }
    files
}

fn inspect() -> Result<Value> {
    let manifests = packet(
        MANIFEST,
        MANIFEST_SEAL,
        &BTreeSet::from([MANIFEST_FILE.to_owned()]),
    )?;
    let manifest = manifest::validate(&serde_json::from_slice(&manifests[MANIFEST_FILE])?)?;
    let data = packet(PACKET, SEAL, &inputs())?;
    let raw = &data[RAW];
    ensure!(hash(raw) == RAW_SHA, "raw index digest");
    transport::headers(
        &data["257.index.headers"],
        raw.len() as u64,
        true,
        "binary/octet-stream",
    )?;
    let ranges = ranges::validate(raw)?;
    let historical: Value = serde_json::from_slice(&data["transport-review.json"])?;
    ensure!(
        historical["present"] == ranges["present"]
            && historical["absent"] == ranges["absent_zero_records"]
            && historical["records"] == ranges["rows"]
            && historical["qualification_granted"] == false,
        "retained source witness disagrees"
    );
    let original_edges = historical["discontinuities"]
        .as_array()
        .context("transport edges")?;
    ensure!(
        original_edges.len() == edges::EDGES.len()
            && original_edges.iter().zip(edges::EDGES).all(
                |(v, &(_, slot, end, offset))| v["slot"] == slot
                    && v["previous_end"] == end
                    && v["offset"] == offset
            ),
        "transport edge witness disagrees"
    );
    let mut epochs = Vec::new();
    for e in &transport::EPOCHS {
        let prefix = |kind: &str| &data[&format!("{}.{kind}.prefix", e.number)];
        let headers = |kind: &str| &data[&format!("{}.{kind}.headers", e.number)];
        transport::headers(headers("car"), e.car, false, "application/vnd.curl.car")?;
        transport::car(prefix("car"), e.cid)?;
        let mut compact = Vec::new();
        for (kind, total) in [
            ("slot-to-cid", e.slot_bytes),
            ("cid-to-offset-and-size", e.offset_bytes),
        ] {
            transport::headers(headers(kind), total, false, "application/octet-stream")?;
            compact.push(transport::compact(prefix(kind), e, kind)?);
        }
        epochs.push(json!({"epoch":e.number,"car_root":e.cid,"car_bytes":e.car,"prefix_bytes_observed":4096,"compact_indexes":compact}));
    }
    Ok(
        json!({"schema":"horizon257-sealed-source-profile-v1","source_packet":{"path":PACKET,"seal_sha256":SEAL},"manifest_packet":{"path":MANIFEST,"seal_sha256":MANIFEST_SEAL},"raw_index_sha256":RAW_SHA,"manifest":manifest,"source_epochs":epochs,"raw_ranges":ranges,"full_index_bodies_checked":false,"decoded_car_ranges":false,"repair_qualified":false,"native_runtime_qualified":false,"admission_authorized":false,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false}),
    )
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.as_slice() == [std::ffi::OsString::from("measure-bootstrap-inputs")] {
        println!("{}", serde_json::to_string_pretty(&bootstrap::measure()?)?);
        return Ok(());
    }
    if args.as_slice() == [std::ffi::OsString::from("compact-tables")] {
        println!("{}", serde_json::to_string_pretty(&tables::run()?)?);
        return Ok(());
    }
    if args.len() == 2 && args[0] == "repair-261" {
        return repair261::run(Path::new(&args[1]));
    }
    if args.len() == 2 && args[0] == "repair-262" {
        return repair262::run(Path::new(&args[1]));
    }
    if args.len() == 2 && args[0] == "repair" {
        return repair::run(Path::new(&args[1]));
    }
    ensure!(
        args.is_empty(),
        "usage: horizon257-source-profile [measure-bootstrap-inputs|compact-tables|repair NEW_OUTPUT|repair-261 NEW_OUTPUT|repair-262 NEW_OUTPUT]"
    );
    println!("{}", serde_json::to_string_pretty(&inspect()?)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // The shipped test suite is portable. This acceptance test consumes the actual Foundation package.
    #[test]
    #[ignore = "requires the two exact sealed Foundation packages"]
    fn sealed_source_packet_and_adversarial_mutations() -> Result<()> {
        let receipt = inspect()?;
        assert_eq!(
            receipt["raw_ranges"]["discontinuities"]
                .as_array()
                .unwrap()
                .len(),
            29
        );
        assert_eq!(
            receipt["raw_ranges"]["raw_index_qualified_for_replay"],
            false
        );
        let sealed = packet(PACKET, SEAL, &inputs())?;
        let raw = &sealed[RAW];
        for &(prev, _, _, _) in edges::EDGES {
            let mut change = raw.clone();
            let at = (prev - ranges::START) as usize * 12 + 8;
            change[at] ^= 1;
            assert!(
                ranges::validate(&change).is_err(),
                "unrecognized edge change at {prev}"
            );
        }
        for (i, e) in transport::EPOCHS.iter().enumerate() {
            let other = &transport::EPOCHS[1 - i];
            assert!(
                transport::car(&sealed[&format!("{}.car.prefix", e.number)], other.cid).is_err()
            );
            for kind in ["slot-to-cid", "cid-to-offset-and-size"] {
                let b = &sealed[&format!("{}.{kind}.prefix", e.number)];
                assert!(transport::compact(b, other, kind).is_err());
                let mut changed = b.clone();
                let at = changed.windows(7).position(|w| w == b"mainnet").unwrap();
                changed[at] = b't';
                assert!(transport::compact(&changed, e, kind).is_err());
            }
        }
        let manifests = packet(
            MANIFEST,
            MANIFEST_SEAL,
            &BTreeSet::from([MANIFEST_FILE.to_owned()]),
        )?;
        let baseline: Value = serde_json::from_slice(&manifests[MANIFEST_FILE])?;
        for (epoch_path, cohort_path) in [
            (
                "/manifest/epochs/0/bootstrap/generation",
                "/manifest/verification_cohorts/0/bootstrap/generation",
            ),
            (
                "/manifest/epochs/0/post_bootstrap_root_checkpoints/0/generation",
                "/manifest/verification_cohorts/0/root_checkpoints/0/generation",
            ),
        ] {
            let mut changed = baseline.clone();
            for pointer in [epoch_path, cohort_path] {
                *changed.pointer_mut(pointer).unwrap() = json!(1);
            }
            assert!(manifest::validate(&changed).is_err());
        }
        Ok(())
    }
}
