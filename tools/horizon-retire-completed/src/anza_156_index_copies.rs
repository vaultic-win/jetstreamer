//! Remove two historical copies of the published epoch's large compact index.
use super::anza_167_index_copies::{retire_duplicates, unchanged};
use super::anza_stopped_167::{definitions, lock, scan_run_references};
use super::*;
use std::collections::BTreeMap;

pub(super) const REVIEW: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch156-compact-index-pairs-20261127-v1/REVIEW.json";
const REVIEW_SHA: &str = "edef5ee1bbf2ef963cc3641831ea0b0738c9cb27796e22ae1d67fff07fa0c151";
const INDEX_SHA: &str = "73f76775e3366fe642e52e32381ecb3d4dfbfa0bded24f559f9f7640a1d9140b";
const ARCHIVE_SHA: &str = "436ce3b98d819a685b8228f7ff34851ee28fb7bedbbde9dc47ed9b350b30ec38";
const NAME: &str = "epoch-156-bafyreie4aarhdjltl4uvunvdxnpeyqrcbtx7m5kfosro26aceo77wjhxa4-mainnet-cid-to-offset-and-size.index";
const LANES: [&str; 3] = [
    "epochs122-147-20260922-v1/lane-m",
    "epochs150-173-20260923-v2/lane-d",
    "epochs150-173-20260923-v2/lane-f",
];

#[derive(Deserialize)]
struct Lease {
    path: PathBuf,
    dev: u64,
    inode: u64,
    uid: u32,
    gid: u32,
}
#[derive(Deserialize)]
struct Review {
    retained: Target,
    targets: [Target; 2],
    siblings: [Target; 3],
    evidence: Vec<Bound>,
    definitions: Vec<Bound>,
    tokens: Vec<String>,
    leases: [Lease; 5],
    units: BTreeMap<String, BTreeMap<String, String>>,
    digest_receipt: Bound,
    canonical: Bound,
    inventory_binary: Bound,
}

fn stopped_owners(review: &Review) -> Result<()> {
    for (unit, expected) in &review.units {
        let fields = expected
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(",");
        let out = Command::new("/usr/bin/systemctl")
            .args(["show", unit, "--all", "-p", &fields])
            .output()?;
        ensure!(
            out.stderr.is_empty()
                && (out.status.success()
                    || (out.status.code() == Some(4) && expected["LoadState"] == "not-found")),
            "cannot inspect historic unit {unit}"
        );
        let actual = std::str::from_utf8(&out.stdout)?
            .lines()
            .map(|line| line.split_once('=').context("invalid manager property"))
            .collect::<Result<BTreeMap<_, _>>>()?;
        ensure!(
            actual.len() == expected.len()
                && expected
                    .iter()
                    .all(|(k, v)| actual.get(k.as_str()) == Some(&v.as_str()))
                && actual["ActiveState"] == "inactive"
                && actual["MainPID"] == "0"
                && actual["ControlPID"] == "0"
                && actual["Job"].is_empty()
                && actual["TriggeredBy"].is_empty()
                && actual["ControlGroup"].is_empty(),
            "historic unit changed: {unit}"
        );
    }
    Ok(())
}

pub(super) fn run(bytes: &[u8], sha: &str, image: &str, check_only: bool) -> Result<()> {
    ensure!(sha == REVIEW_SHA, "unregistered epoch 156 review");
    let r: Review = serde_json::from_slice(bytes)?;
    let dir = Path::new(REVIEW).parent().context("review parent")?;
    let deployment = dir.join("tools/retire");
    ensure!(
        dir.canonicalize()? == dir
            && dir.metadata()?.uid() == 0
            && dir.metadata()?.mode() & 0o7777 == 0o700
            && fs::read_link("/proc/self/exe")? == deployment
            && stamp(&exact(&deployment)?) == stamp(&fs::metadata("/proc/self/exe")?),
        "unexpected deployment"
    );
    let _operation = lock(
        Path::new("/run/horizon-epoch171-to136-g1.operation.lock"),
        26,
        3453440,
        0,
        0,
    )?;
    let base = Path::new(HOME_ROOT).join(".jetstreamer-private");
    let receipts = base.join("r2-receipts");
    let _mutation = lock(
        &receipts.join("local-mutation.lock"),
        64512,
        101135013,
        1001,
        1003,
    )?;
    let _owners = r
        .leases
        .iter()
        .map(|l| lock(&l.path, l.dev, l.inode, l.uid, l.gid))
        .collect::<Result<Vec<_>>>()?;
    for b in &r.evidence {
        bound(b, LIMIT)?;
    }
    let hashes: Value = serde_json::from_slice(&bound(&r.digest_receipt, LIMIT)?)?;
    for (i, t) in std::iter::once(&r.retained).chain(&r.targets).enumerate() {
        let expected = base
            .join(LANES[i])
            .join("output/compact-indexes/156")
            .join(NAME);
        ensure!(
            t.epoch == 156
                && t.path == expected
                && t.identity.ino == [102368000, 99291241, 95879188][i]
                && hashes["sha256_by_path"][expected.to_str().context("index path")?] == INDEX_SHA,
            "unbound index"
        );
        ensure!(
            r.siblings[i].path
                == expected.with_file_name(NAME.replace("cid-to-offset-and-size", "slot-to-cid")),
            "unexpected sibling"
        );
    }
    let delivery: Value = serde_json::from_slice(&bound(&r.canonical, LIMIT)?)?;
    ensure!(
        delivery["archive_sha256"] == ARCHIVE_SHA,
        "unexpected canonical archive"
    );
    ready(
        156,
        &delivery,
        &authenticated_inventory(
            &r.inventory_binary,
            &Path::new(HOME_ROOT).join("horizon"),
            &receipts,
            (156, 156),
        )?,
    )?;
    // The common receipt protocol rechecks the keeper, siblings and current consumers before each unlink.
    retire_duplicates(
        dir,
        &r.retained,
        &r.targets,
        INDEX_SHA,
        (sha, image),
        check_only,
        || {
            unchanged(&r.retained)?;
            for s in &r.siblings {
                unchanged(s)?;
            }
            stopped_owners(&r)?;
            definitions(&r.definitions, &r.tokens)?;
            scan_run_references(&r.tokens[..4])?;
            scan_consumers(&r.targets)
        },
    )
}
