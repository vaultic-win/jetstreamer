//! Operational countdowns for live private replays. Never archive qualification.
use super::*;
use serde_json::json;
use std::{collections::BTreeMap, process::Command as ProcessCommand};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    observer: Bound,
    fleet: Bound,
    receipt_directory: PathBuf,
    estimate_receipt: PathBuf,
    downstream_allowance_millis: BTreeMap<u64, u64>,
    estimate_basis: String,
}
struct Profile {
    first: u64,
    last: u64,
    unit: &'static str,
    iid: &'static str,
    root: &'static str,
    terminal: u64,
}
const PROFILES: [Profile; 3] = [
    Profile {
        first: 204,
        last: 204,
        unit: "horizon-qualify-204-shrink-root-prefix-resource-fcbf3992-v1.service",
        iid: "448da7f2a3a34217afe7e115120b3cea",
        root: "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-204-fcbf3992-v1",
        terminal: 88_559_361,
    },
    Profile {
        first: 205,
        last: 205,
        unit: "horizon-qualify-205-shrink-root-prefix-resource-5c01bf93-v1.service",
        iid: "373359a11aef4993a1a949e19ff617c3",
        root: "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-205-5c01bf93-v1",
        terminal: 88_991_050,
    },
    Profile {
        first: 225,
        last: 226,
        unit: "horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service",
        iid: "4cd76ae1353a4411885b997f04306402",
        root: "/home/ubuntu/.jetstreamer-private/qualification-225-v1625-natural-root-shrink-budget-2f856bd-v1",
        terminal: 98_063_464,
    },
];
fn bound(b: &Bound) -> Result<Value> {
    ensure!(
        b.path.is_absolute() && is_lower_hex(&b.sha256, 64),
        "invalid qualification evidence binding"
    );
    let bytes = read_stable_bounded(
        &b.path,
        MAX_OBSERVER_RECEIPT_BYTES,
        "qualification evidence",
    )?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == b.sha256,
        "qualification evidence digest differs"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn profile(epoch: u64) -> Result<&'static Profile> {
    PROFILES
        .iter()
        .find(|p| (p.first..=p.last).contains(&epoch))
        .context("unsupported qualification epoch")
}
fn observed<'a>(o: &'a Value, p: &Profile) -> Result<&'a Value> {
    let rows = o["diagnostic_replays"]
        .as_array()
        .context("qualification observer census")?;
    let matches = rows
        .iter()
        .filter(|r| r["producer_unit"] == p.unit)
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "qualification owner missing or duplicated"
    );
    let r = matches[0];
    let row = &r["observation"];
    ensure!(
        r["status"] == "observed"
            && r["range"] == format!("{}-{}", p.first, p.last)
            && r["expected_producer_invocation_id"] == p.iid
            && row["invocation_binding_stable"] == true
            && row["useful_work"]["journal_invocation_id"] == p.iid,
        "qualification observation differs"
    );
    for point in [
        "controller_before",
        "controller_after",
        "producer_before",
        "producer_after",
    ] {
        ensure!(
            row[point]["invocation_id"] == p.iid
                && row[point]["restarts"] == 0
                && row[point]["active_state"] == "active"
                && row[point]["sub_state"] == "running",
            "qualification observation is not a stable live replay"
        );
    }
    Ok(row)
}
fn live(p: &Profile, f: &Value) -> Result<Value> {
    let u = fleet::unit(p.unit)?;
    let old = &f["unit_census"][p.unit];
    ensure!(
        u["Id"] == p.unit
            && u["InvocationID"] == p.iid
            && u["NRestarts"] == "0"
            && u["LoadState"] == "loaded"
            && u["ActiveState"] == "active"
            && u["SubState"] == "running"
            && u["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|n| n > 0)
            && old["InvocationID"] == p.iid
            && old["MainPID"] == u["MainPID"]
            && pipeline_status::same_exec_start(
                old["ExecStart"]
                    .as_str()
                    .context("prior qualification command")?,
                u["ExecStart"]
                    .as_str()
                    .context("live qualification command")?
            ),
        "qualification live owner changed"
    );
    Ok(u)
}
fn elapsed(p: &Profile, sampled: u64) -> Result<u64> {
    let out = ProcessCommand::new("systemctl")
        .args([
            "show",
            p.unit,
            "--property=ExecMainStartTimestampMonotonic",
            "--value",
        ])
        .output()?;
    ensure!(
        out.status.success(),
        "qualification start clock unavailable"
    );
    let start = std::str::from_utf8(&out.stdout)?.trim().parse::<u64>()? / 1000;
    let mut clock = std::mem::MaybeUninit::<libc::timespec>::uninit();
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, clock.as_mut_ptr()) } == 0,
        "monotonic clock failed"
    );
    let clock = unsafe { clock.assume_init() };
    let now = u64::try_from(clock.tv_sec)?
        .checked_mul(1000)
        .and_then(|s| s.checked_add(u64::try_from(clock.tv_nsec).ok()? / 1_000_000))
        .context("clock overflow")?;
    let age = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .checked_sub(u128::from(sampled) * 1000)
        .context("future sample")?;
    now.checked_sub(start)
        .and_then(|n| n.checked_sub(u64::try_from(age).ok()?))
        .context("qualification invocation clock is newer than sample")
}
fn remaining(row: &Value, p: &Profile, allowance: u64) -> Result<u64> {
    ensure!(
        allowance > 0 && row["useful_work"]["sufficient_for_rates"] == true,
        "qualification estimate needs a rate and downstream allowance"
    );
    let slot = row["useful_work"]["last"]["slot"]
        .as_u64()
        .context("qualification slot missing")?;
    ensure!(
        slot <= p.terminal,
        "qualification stage changed beyond replay terminal"
    );
    let rate = row["useful_work"]["slots_per_second"]
        .as_f64()
        .context("qualification rate missing")?;
    ensure!(rate.is_finite() && rate > 0.0, "qualification rate invalid");
    let millis = ((p.terminal - slot) as f64 * 1000.0 / rate).ceil();
    ensure!(
        millis.is_finite() && millis >= 0.0 && millis < u64::MAX as f64,
        "qualification ETA overflow"
    );
    (millis as u64)
        .checked_add(allowance)
        .context("qualification ETA overflow")
}
fn jet(p: &Profile, epoch: u64) -> Result<u64> {
    let name = if p.first < 225 {
        format!("epoch-{epoch}-prefix.jet")
    } else {
        format!("epoch-{epoch}.jet")
    };
    let path = Path::new(p.root).join("output").join(name);
    match fs::symlink_metadata(path) {
        Ok(m) => {
            ensure!(m.is_file() && m.nlink() == 1, "qualification jet identity");
            Ok(m.len())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e.into()),
    }
}
pub(super) fn matches(
    receipt: &StatusPublicationReceipt,
    epoch: u64,
    o: &Value,
    census: &BTreeMap<String, Value>,
) -> bool {
    let Ok(p) = profile(epoch) else { return false };
    let Some(u) = census.get(p.unit) else {
        return false;
    };
    receipt.status.phase == "qualification"
        && receipt.epoch == epoch
        && receipt.producer_invocation_id == p.iid
        && receipt.controller_invocation_id == p.iid
        && u["InvocationID"] == p.iid
        && u["NRestarts"] == "0"
        && u["ActiveState"] == "active"
        && u["SubState"] == "running"
        && observed(o, p).is_ok()
}
pub(super) async fn run() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    ensure!(
        (args.len() == 7 || (args.len() == 8 && args[7] == "--check-only"))
            && args[3] == "--plan-sha256"
            && args[5] == "--self-sha256",
        "qualification status PLAN --plan-sha256 HEX --self-sha256 HEX [--check-only]"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0
            && is_lower_hex(&args[6], 64)
            && hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == args[6],
        "qualification status tool must be root and self-bound"
    );
    let plan_bound = Bound {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let p: Plan = serde_json::from_value(bound(&plan_bound)?)?;
    ensure!(
        p.schema == "jetstreamer-qualification-status-plan-v1"
            && p.downstream_allowance_millis
                .keys()
                .copied()
                .eq([204, 205, 225, 226])
            && !p.estimate_basis.trim().is_empty()
            && p.estimate_receipt.is_absolute(),
        "qualification status plan differs"
    );
    let o = bound(&p.observer)?;
    let f = bound(&p.fleet)?;
    let sampled = o["recorded_at_utc"]
        .as_str()
        .context("qualification sample time")?;
    let seconds = fleet::utc_seconds(sampled)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && now >= seconds
            && now - seconds <= 1800
            && f["observer_receipt"].as_str() == p.observer.path.to_str()
            && f["observer_sha256"] == p.observer.sha256
            && f["sampled_at_utc"] == sampled
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["inventory"]["anomalies"] == 0,
        "qualification status needs fresh accepted fleet"
    );
    let mut states = Vec::new();
    let mut owners = BTreeMap::new();
    for profile in &PROFILES {
        let row = observed(&o, profile)?;
        owners.insert(profile.unit, live(profile, &f)?);
        let elapsed = elapsed(profile, seconds)?;
        for epoch in profile.first..=profile.last {
            states.push(EpochStatus {
                epoch,
                jet_size_bytes: jet(profile, epoch)?,
                elapsed_execution_millis: elapsed,
                estimated_remaining_millis: remaining(
                    row,
                    profile,
                    p.downstream_allowance_millis[&epoch],
                )?,
                sampled_at_utc: sampled.into(),
                phase: "qualification".into(),
            });
        }
    }
    // Reuse the first durable estimate on a partial publication retry. Never
    // replace a same-sample payload with a newer size or recomputed countdown.
    if p.estimate_receipt.exists() {
        let saved: Value = serde_json::from_slice(&read_stable_bounded(
            &p.estimate_receipt,
            MAX_OBSERVER_RECEIPT_BYTES,
            "qualification estimate",
        )?)?;
        ensure!(
            saved["plan_sha256"] == plan_bound.sha256
                && saved["observer_sha256"] == p.observer.sha256,
            "qualification estimate receipt is foreign"
        );
        states = serde_json::from_value(saved["statuses"].clone())?;
        ensure!(
            states.iter().map(|s| s.epoch).eq([204, 205, 225, 226])
                && states
                    .iter()
                    .all(|s| s.sampled_at_utc == sampled && s.phase == "qualification"),
            "qualification estimate receipt differs"
        );
    } else if args.len() == 7 {
        fleet::persist(
            &p.estimate_receipt,
            &json!({"schema":"jetstreamer-qualification-status-estimate-v1","plan_sha256":plan_bound.sha256,
            "observer_sha256":p.observer.sha256,"fleet_sha256":p.fleet.sha256,"estimate_basis":p.estimate_basis,
            "downstream_allowance_millis":p.downstream_allowance_millis,"statuses":states,"archive_or_sidecar_mutation_authorized":false}),
        )?;
    }
    if args.len() == 8 {
        println!(
            "{}",
            serde_json::to_string(&json!({"statuses":states,"r2_mutations":false}))?
        );
        return Ok(());
    }
    preflight_status_receipt_write(&p.receipt_directory)?;
    let r2 = r2_config_from_env()?;
    let s3 = s3_client(&r2);
    for status in states {
        let profile = profile(status.epoch)?;
        ensure!(
            live(profile, &f)? == owners[profile.unit],
            "qualification owner changed before status publication"
        );
        let (etag, previous) = publish_epoch_status(&s3, &r2, &status).await?;
        let path = status_receipt_path(&p.receipt_directory, &status);
        if path.exists() {
            let old: StatusPublicationReceipt = serde_json::from_slice(&read_stable_bounded(
                &path,
                MAX_STATUS_BYTES,
                "qualification publication",
            )?)?;
            ensure!(
                old.status == status
                    && old.object_etag == etag
                    && old.authenticated_readback
                    && old.observer_receipt_sha256 == p.observer.sha256
                    && old.controller_invocation_id == profile.iid
                    && old.producer_invocation_id == profile.iid,
                "existing qualification publication differs"
            );
        } else {
            let receipt = StatusPublicationReceipt {
                schema: STATUS_RECEIPT_SCHEMA.into(),
                bucket: r2.bucket.clone(),
                epoch: status.epoch,
                key: format!("epoch-{}.epoch-status.json", status.epoch),
                status,
                object_etag: etag,
                previous_object_etag: previous,
                observer_receipt: p.observer.path.clone(),
                observer_receipt_sha256: p.observer.sha256.clone(),
                controller_invocation_id: profile.iid.into(),
                producer_invocation_id: profile.iid.into(),
                authenticated_readback: true,
                verified_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                pipeline_binding: None,
            };
            write_status_receipt(&p.receipt_directory, &receipt)?;
        }
        ensure!(
            live(profile, &f)? == owners[profile.unit],
            "qualification owner changed during publication"
        );
        println!("{}", path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn eta_includes_every_queued_slot_and_downstream_work() {
        let p = &PROFILES[2];
        let row = json!({"useful_work":{"sufficient_for_rates":true,"last":{"slot":p.terminal-120},"slots_per_second":2.0}});
        assert_eq!(remaining(&row, p, 90_000).unwrap(), 150_000);
        assert!(remaining(&row, p, 0).is_err());
        let mut bad = row.clone();
        bad["useful_work"]["slots_per_second"] = json!(0);
        assert!(remaining(&bad, p, 90_000).is_err());
        bad = row;
        bad["useful_work"]["last"]["slot"] = json!(p.terminal + 1);
        assert!(remaining(&bad, p, 90_000).is_err());
    }
    #[test]
    fn closed_scope_has_four_epochs_across_three_owners() {
        assert!(profile(223).is_err());
        assert!(profile(203).is_err());
        assert_eq!(profile(225).unwrap().unit, profile(226).unwrap().unit);
        assert_eq!(
            PROFILES
                .iter()
                .flat_map(|p| p.first..=p.last)
                .collect::<Vec<_>>(),
            vec![204, 205, 225, 226]
        );
    }
}
