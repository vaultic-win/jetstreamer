//! Reconstruct the epoch 258 gaps and overlapping range from sealed CAR windows.
use super::{hash, packet_with_sealer, read_checked, repair, transport};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs::File, path::Path};

const DIR: &str = "/var/lib/jetstreamer/horizon258-rooted-index-source-v1";
const SEAL: &str = "ef7519016b3d345c9476828a505bde79ecc6689c17025bee439e95d84e4f7e4e";
const SEALER: &str = "2c939dde066672a13d6119d86dfb2bf460c428fd95e0854da726c6c6419f6853";
const RAW: &str = "epoch-258-slot-ranges.raw";
const RAW_SHA: &str = "13231cbf4231ebc1837e3f60f99f1f85395f84c66471b92c51f88e7a090ae8aa";
const PREFIX: &str = "epoch-258.car.prefix";
const CANDIDATE: &str = "epoch-258-slot-ranges.candidate.raw";
const CAR_ROOT: &str = "bafyreicszutajk2nhrbkpfscbidbqpno6toqvwin65e77naxkzhfmltb74";
const SLOT_INDEX: &str = "epoch-258-bafyreicszutajk2nhrbkpfscbidbqpno6toqvwin65e77naxkzhfmltb74-mainnet-slot-to-cid.index";
const SLOT_SHA: &str = "749892ec382d1b19317e6e5c6cbb171e32d269ba9e9c108525e4e010a17bc878";
const SLOT_BYTES: u64 = 15_780_253;
const CENSUS_SHA: &str = "9509c044aa68766362d2d6f7ce2e6e20bdacc756d9596c3d7619db2b9803d82e";
const DOWNLOAD_SHA: &str = "18372af3372cc3ae411fcec309616ab9b48fbffa6de82d8be9a86c3314f63605";
const ROWS: u64 = 432_000;
const FIRST: u64 = 258 * ROWS;
const PRESENT: u64 = 404_591;
const PROFILE: repair::Source<'static> = repair::Source {
    epoch: 258,
    car_size: 445_674_159_994,
    window_bytes: 52_692_410,
    max_window: 6_501_521,
    plan_sha: "5de6591cd5e94cc3facb42f0fc9800c71c499c4a58d2aed5fdc2616017d96554",
    prefix_sha: "2404a6a6be593eda927d0ef133d92352d507204050a71bd93d15de82e291253f",
};

fn original_edges(raw: &[u8]) -> Result<Vec<(u64, u64, u64, u64)>> {
    ensure!(raw.len() as u64 == ROWS * 12, "epoch 258 raw table length");
    let mut edges = Vec::new();
    let mut previous = (FIRST - 1, 59);
    let mut present = 0;
    for slot in FIRST..FIRST + ROWS {
        let (offset, length) = repair::record(raw, slot, FIRST);
        if length == 0 {
            ensure!(offset == 0, "partial empty range at {slot}");
            continue;
        }
        let end = offset.checked_add(u64::from(length)).context("range end")?;
        ensure!(
            offset >= 59 && end <= PROFILE.car_size,
            "invalid range at {slot}"
        );
        if previous.1 != offset {
            if previous.1 > offset {
                ensure!(
                    (previous.0, slot, previous.1, offset)
                        == (111_533_811, 111_533_817, 80_723_942_467, 77_271_252_595),
                    "unexpected overlapping range at {slot}"
                );
            }
            edges.push((previous.0, slot, previous.1, offset));
        }
        present += 1;
        previous = (slot, end);
    }
    ensure!(
        present == PRESENT && edges.len() == 12,
        "epoch 258 range census"
    );
    Ok(edges)
}

pub(super) fn run(output: &Path) -> Result<()> {
    let dir = Path::new(DIR);
    let raw = read_checked(dir, RAW, ROWS * 12, RAW_SHA)?;
    let edges = original_edges(&raw)?;
    let mut members: BTreeSet<_> = [
        RAW,
        PREFIX,
        SLOT_INDEX,
        "epoch258-census.json",
        "car.headers",
        "ranges.headers",
        "compact.headers",
        "edge-windows.json",
        "download.json",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    for label in ["prefix-before".to_owned(), "prefix-after".to_owned()]
        .into_iter()
        .chain(edges.iter().map(|(_, edge, _, _)| edge.to_string()))
    {
        members.insert(format!("{label}.car"));
        members.insert(format!("{label}.headers"));
    }
    let mut source = packet_with_sealer(DIR, SEAL, SEALER, &members, |name| match name {
        RAW => ROWS * 12,
        SLOT_INDEX => SLOT_BYTES,
        name if name.ends_with(".car") => PROFILE.max_window,
        _ => 16_384,
    })?;
    let mut candidate = source.remove(RAW).context("raw table missing")?;
    ensure!(candidate == raw, "raw table changed on reopen");
    let prefix = &source[PREFIX];
    transport::car(prefix, CAR_ROOT)?;
    transport::headers(
        &source["car.headers"],
        PROFILE.car_size,
        false,
        "application/vnd.curl.car",
    )?;
    transport::headers(
        &source["ranges.headers"],
        ROWS * 12,
        true,
        "binary/octet-stream",
    )?;
    transport::headers(
        &source["compact.headers"],
        SLOT_BYTES,
        true,
        "application/octet-stream",
    )?;
    ensure!(
        hash(prefix) == PROFILE.prefix_sha
            && hash(&source[SLOT_INDEX]) == SLOT_SHA
            && hash(&source["epoch258-census.json"]) == CENSUS_SHA
            && hash(&source["download.json"]) == DOWNLOAD_SHA,
        "epoch 258 source identity changed"
    );
    let windows = repair::windows(&candidate, &source["edge-windows.json"], &edges, &PROFILE)?;
    let download: Value = serde_json::from_slice(&source["download.json"])?;
    let reviews = repair::repair_windows(
        &PROFILE,
        &mut candidate,
        &windows,
        &download,
        |name, _, _| {
            source
                .remove(&format!("{name}.car"))
                .context("captured CAR body missing")
        },
    )?;
    let (present, gaps) = repair::scan_candidate(&PROFILE, &candidate)?;
    ensure!(
        gaps == 0 && present >= PRESENT,
        "repaired table has gaps or lost coverage"
    );
    let result = json!({
        "schema":"horizon258-direct-car-repair-candidate-v1","epoch":258,
        "source_sha256":RAW_SHA,"source_seal_sha256":SEAL,"car_root":CAR_ROOT,
        "download_plan_sha256":PROFILE.plan_sha,"download_sha256":DOWNLOAD_SHA,
        "original_present":PRESENT,"original_discontinuities":edges.len(),"rows_scanned":ROWS,
        "candidate_present":present,"candidate_gaps":gaps,"candidate_sha256":hash(&candidate),
        "edges":reviews,"all_windows_verified":true,"independent_native_comparison_pending":true,
        "replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false
    });
    repair::new_output(output)?;
    repair::write_new(output, CANDIDATE, &candidate)?;
    repair::write_new(
        output,
        "repair-candidate.json",
        &serde_json::to_vec_pretty(&result)?,
    )?;
    File::open(output)?.sync_all()?;
    File::open(output.parent().context("output parent missing")?)?.sync_all()?;
    Ok(())
}
