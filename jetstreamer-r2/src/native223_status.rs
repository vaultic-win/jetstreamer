//! Provisional sidecar countdown for one admitted zero-entry native repair.
//! This operational status never qualifies a runtime, replay or archive.
use super::*;
use serde_json::json;
use std::{collections::BTreeMap, process::Command};

const UNIT: &str = "archive-223-v1620-native-input-actual-v1.service";
const IID: &str = "41684426155f4124a64b10c55ffeed96";
const INTENT: &str = "/var/lib/jetstreamer/horizon-ram-snapshot-tests/ram-snapshot-test-223-v1620-actual-v1/intent.json";
const INTENT_SHA: &str = "2d6f4a1b081d700e4b0a68488a1eb69e2f68301dcbd6dc27a1883c2b5a8d88c8";
const STAGES: [&str; 5] = [
    "assembly_verification_upload",
    "bounded_warmup",
    "native_input",
    "prefix_replay",
    "suffix_restart",
];

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
    intent: Bound,
    sampled_at_utc: String,
    receipt_directory: PathBuf,
    estimate_receipt: PathBuf,
    stage_allowance_millis: BTreeMap<String, u64>,
    estimate_basis: String,
    estimate_evidence: Vec<Bound>,
}
fn bound(b: &Bound) -> Result<Value> {
    ensure!(
        b.path.is_absolute() && is_lower_hex(&b.sha256, 64),
        "native223 evidence binding"
    );
    let bytes = read_stable_bounded(&b.path, MAX_OBSERVER_RECEIPT_BYTES, "native223 evidence")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == b.sha256,
        "native223 evidence digest differs"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn intent(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-private-epoch223-native-v1620-ram-snapshot-intent-v1"
            && v["invocation_id"] == IID
            && v["plan_sha256"]
                == "395262f95e2dc504300b3174542936aaf5996684060e2f9c804f66d4ed13f87d"
            && v["self_sha256"]
                == "8768a500512a36a3f1d887f4383c6b7c42feb4924cd4f32e8b237ad02d65ae85"
            && v["test_sha256"]
                == "01e69e4a5a1ec30d5ad9055c60aa5f1dc98e7fddc93001cd2db389937e78079a"
            && v["snapshot_sha256"]
                == "301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665"
            && v["maximum_memory_bytes"] == 128u64 * (1 << 30)
            && v["resource_samples_taken"] == 0,
        "native223 intent scope differs"
    );
    for key in [
        "entry_replay",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(v[key] == false, "native223 intent grants authority");
    }
    Ok(())
}
fn owner(v: &Value) -> bool {
    v["Id"] == UNIT
        && v["InvocationID"] == IID
        && v["NRestarts"] == "0"
        && v["LoadState"] == "loaded"
        && ((v["ActiveState"] == "activating" && v["SubState"] == "start")
            || (v["ActiveState"] == "active" && v["SubState"] == "running"))
        && v["MainPID"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .is_some_and(|n| n > 0)
}
fn live(f: &Value) -> Result<Value> {
    ensure!(
        !Path::new(INTENT).with_file_name("result.json").exists(),
        "native223 input already reached its terminal handoff"
    );
    let current = fleet::unit(UNIT)?;
    let old = &f["unit_census"][UNIT];
    ensure!(
        owner(&current)
            && owner(old)
            && current["MainPID"] == old["MainPID"]
            && pipeline_status::same_exec_start(
                old["ExecStart"]
                    .as_str()
                    .context("native223 accepted command")?,
                current["ExecStart"]
                    .as_str()
                    .context("native223 current command")?
            ),
        "native223 owner changed"
    );
    Ok(current)
}
fn elapsed(sample: u64) -> Result<u64> {
    let output = Command::new("systemctl")
        .args([
            "show",
            UNIT,
            "--property=ExecMainStartTimestampMonotonic",
            "--value",
        ])
        .output()?;
    ensure!(
        output.status.success(),
        "native223 invocation clock unavailable"
    );
    let start = std::str::from_utf8(&output.stdout)?.trim().parse::<u64>()? / 1000;
    let mut clock = std::mem::MaybeUninit::<libc::timespec>::uninit();
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, clock.as_mut_ptr()) } == 0,
        "native223 monotonic clock"
    );
    let clock = unsafe { clock.assume_init() };
    let now = u64::try_from(clock.tv_sec)?
        .checked_mul(1000)
        .and_then(|n| n.checked_add(u64::try_from(clock.tv_nsec).ok()? / 1_000_000))
        .context("native223 clock overflow")?;
    let age = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .checked_sub(u128::from(sample) * 1000)
        .context("native223 future status")?;
    now.checked_sub(start)
        .and_then(|n| n.checked_sub(u64::try_from(age).ok()?))
        .context("native223 sample predates invocation")
}
fn remaining(stages: &BTreeMap<String, u64>, elapsed: u64) -> Result<u64> {
    ensure!(
        stages.keys().map(String::as_str).eq(STAGES)
            && stages.values().all(|n| *n > 0 && *n <= 30 * 86_400_000)
            && stages["native_input"] <= 1_800_000
            && stages["bounded_warmup"] <= 3_600_000,
        "native223 complete staged ETA required"
    );
    stages.iter().try_fold(0u64, |total, (stage, value)| {
        total
            .checked_add(if stage == "native_input" {
                value.saturating_sub(elapsed).max(1)
            } else {
                *value
            })
            .context("native223 ETA overflow")
    })
}
pub(super) fn matches(
    receipt: &StatusPublicationReceipt,
    epoch: u64,
    o: &Value,
    census: &BTreeMap<String, Value>,
) -> bool {
    epoch == 223
        && receipt.epoch == 223
        && receipt.status.phase == "qualification"
        && receipt.status.jet_size_bytes == 0
        && receipt.controller_invocation_id == IID
        && receipt.producer_invocation_id == IID
        && receipt.pipeline_binding.is_none()
        && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
        && census.get(UNIT).is_some_and(owner)
}
/// Select only the authenticated native status owner; ordinary inactive-cleanup
/// terminal, replacement/handoff, conditional-delete and race gates remain.
pub(super) fn inactive_owner(
    publication: &StatusPublicationReceipt,
) -> Result<Option<(String, String)>> {
    if publication.epoch != 223 || publication.status.phase != "qualification" {
        return Ok(None);
    }
    ensure!(
        publication.controller_invocation_id == IID
            && publication.producer_invocation_id == IID
            && publication.pipeline_binding.is_none()
            && publication.status.jet_size_bytes == 0,
        "native223 inactive status owner differs"
    );
    let i = bound(&Bound {
        path: INTENT.into(),
        sha256: INTENT_SHA.into(),
    })?;
    intent(&i)?;
    let o = bound(&Bound {
        path: publication.observer_receipt.clone(),
        sha256: publication.observer_receipt_sha256.clone(),
    })?;
    ensure!(
        o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && fleet::utc_seconds(&publication.status.sampled_at_utc)?
                == fleet::utc_seconds(
                    o["recorded_at_utc"]
                        .as_str()
                        .context("native223 inactive observer clock")?
                )?
                .max(
                    i["recorded_unix_seconds"]
                        .as_u64()
                        .context("native223 inactive event clock")?
                ),
        "native223 inactive status sample differs"
    );
    Ok(Some((UNIT.into(), IID.into())))
}
pub(super) async fn run() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    ensure!(
        (args.len() == 7 || (args.len() == 8 && args[7] == "--check-only"))
            && args[3] == "--plan-sha256"
            && args[5] == "--self-sha256",
        "native223 status arguments"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0
            && is_lower_hex(&args[6], 64)
            && hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == args[6],
        "native223 root/self binding"
    );
    let plan_bound = Bound {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let p: Plan = serde_json::from_value(bound(&plan_bound)?)?;
    ensure!(
        p.schema == "jetstreamer-native223-status-plan-v1"
            && p.intent.path == Path::new(INTENT)
            && p.intent.sha256 == INTENT_SHA
            && !p.estimate_basis.trim().is_empty()
            && !p.estimate_evidence.is_empty()
            && p.estimate_evidence.len() <= 16
            && p.estimate_receipt.is_absolute(),
        "native223 status plan scope"
    );
    let i = bound(&p.intent)?;
    intent(&i)?;
    let o = bound(&p.observer)?;
    let f = bound(&p.fleet)?;
    for evidence in &p.estimate_evidence {
        bound(evidence)?;
    }
    let observer_clock = fleet::utc_seconds(
        o["recorded_at_utc"]
            .as_str()
            .context("native223 observer clock")?,
    )?;
    let event_clock = i["recorded_unix_seconds"]
        .as_u64()
        .context("native223 intent clock")?;
    let sample = fleet::utc_seconds(&p.sampled_at_utc)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        sample == observer_clock.max(event_clock)
            && now >= sample
            && now - sample <= 1800
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && f["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && f["observer_receipt"].as_str() == p.observer.path.to_str()
            && f["observer_sha256"] == p.observer.sha256
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["inventory"]["anomalies"] == 0
            && f["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n >= event_clock),
        "native223 needs accepted event/fresh observation"
    );
    let fleet_plan = bound(&Bound {
        path: f["plan"]
            .as_str()
            .context("native223 accepted plan")?
            .into(),
        sha256: f["plan_sha256"]
            .as_str()
            .context("native223 accepted plan digest")?
            .into(),
    })?;
    ensure!(
        fleet_plan["pipeline_claims"]
            .as_array()
            .is_some_and(|claims| claims.iter().any(|claim| claim["epoch"] == 223
                && claim["phase"] == "private-cold-snapshot-verification"
                && claim["unit"] == UNIT
                && claim["invocation_id"] == IID
                && claim["evidence"].as_array().is_some_and(|rows| rows
                    .iter()
                    .any(|row| row["path"] == INTENT && row["sha256"] == INTENT_SHA)))),
        "native223 accepted fleet lacks the exact native intent claim"
    );
    let before = live(&f)?;
    let elapsed = elapsed(sample)?;
    ensure!(
        elapsed <= 1_800_000,
        "native223 input runtime allowance exhausted"
    );
    let mut status = EpochStatus {
        epoch: 223,
        jet_size_bytes: 0,
        elapsed_execution_millis: elapsed,
        estimated_remaining_millis: remaining(&p.stage_allowance_millis, elapsed)?,
        sampled_at_utc: p.sampled_at_utc.clone(),
        phase: "qualification".into(),
    };
    if p.estimate_receipt.exists() {
        let saved: Value = serde_json::from_slice(&read_stable_bounded(
            &p.estimate_receipt,
            MAX_OBSERVER_RECEIPT_BYTES,
            "native223 estimate",
        )?)?;
        ensure!(
            saved["schema"] == "jetstreamer-native223-status-estimate-v1"
                && saved["plan_sha256"] == plan_bound.sha256
                && saved["intent_sha256"] == INTENT_SHA,
            "foreign native223 estimate"
        );
        status = serde_json::from_value(saved["status"].clone())?;
        ensure!(
            status.epoch == 223
                && status.sampled_at_utc == p.sampled_at_utc
                && status.phase == "qualification"
                && status.jet_size_bytes == 0,
            "native223 saved estimate scope"
        );
    } else if args.len() == 7 {
        fleet::persist(
            &p.estimate_receipt,
            &json!({"schema":"jetstreamer-native223-status-estimate-v1","plan_sha256":plan_bound.sha256,"observer_sha256":p.observer.sha256,"fleet_sha256":p.fleet.sha256,"intent_sha256":INTENT_SHA,"stage_allowance_millis":p.stage_allowance_millis,"estimate_basis":p.estimate_basis,"status":status,"provisional_best_guess":true,"entry_replay":false,"archive_or_sidecar_mutation_authorized":false,"resource_observation_performed":false}),
        )?;
    }
    ensure!(
        live(&f)? == before,
        "native223 owner changed during estimate"
    );
    if args.len() == 8 {
        println!(
            "{}",
            serde_json::to_string(&json!({"status":status,"r2_mutations":false}))?
        );
        return Ok(());
    }
    preflight_status_receipt_write(&p.receipt_directory)?;
    let config = r2_config_from_env()?;
    let s3 = s3_client(&config);
    ensure!(
        live(&f)? == before,
        "native223 owner changed before publication"
    );
    let (etag, previous) = publish_epoch_status(&s3, &config, &status).await?;
    let path = status_receipt_path(&p.receipt_directory, &status);
    if path.exists() {
        let bytes = read_stable_bounded(&path, MAX_STATUS_BYTES, "native223 publication")?;
        let old = validate_status_publication_receipt_bytes(
            &p.receipt_directory,
            &path,
            &bytes,
            &config.bucket,
            223,
        )?;
        ensure!(
            old.status == status
                && old.object_etag == etag
                && old.authenticated_readback
                && old.observer_receipt_sha256 == p.observer.sha256
                && old.controller_invocation_id == IID
                && old.producer_invocation_id == IID,
            "native223 prior publication differs"
        );
    } else {
        write_status_receipt(
            &p.receipt_directory,
            &StatusPublicationReceipt {
                schema: STATUS_RECEIPT_SCHEMA.into(),
                bucket: config.bucket,
                epoch: 223,
                key: "epoch-223.epoch-status.json".into(),
                status,
                object_etag: etag,
                previous_object_etag: previous,
                observer_receipt: p.observer.path,
                observer_receipt_sha256: p.observer.sha256,
                controller_invocation_id: IID.into(),
                producer_invocation_id: IID.into(),
                authenticated_readback: true,
                verified_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                pipeline_binding: None,
            },
        )?;
    }
    ensure!(
        live(&f)? == before,
        "native223 owner changed during publication"
    );
    println!("{}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_intent_cannot_grant_replay_or_borrow_a_different_test() {
        let good = json!({"schema":"jetstreamer-private-epoch223-native-v1620-ram-snapshot-intent-v1",
            "invocation_id":IID,"plan_sha256":"395262f95e2dc504300b3174542936aaf5996684060e2f9c804f66d4ed13f87d",
            "self_sha256":"8768a500512a36a3f1d887f4383c6b7c42feb4924cd4f32e8b237ad02d65ae85",
            "test_sha256":"01e69e4a5a1ec30d5ad9055c60aa5f1dc98e7fddc93001cd2db389937e78079a",
            "snapshot_sha256":"301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665",
            "maximum_memory_bytes":137438953472u64,"resource_samples_taken":0,"entry_replay":false,
            "publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
        intent(&good).unwrap();
        for (key, value) in [
            ("entry_replay", json!(true)),
            ("resource_samples_taken", json!(1)),
            ("test_sha256", json!("0".repeat(64))),
            ("invocation_id", json!("0".repeat(32))),
            ("maximum_memory_bytes", json!(137438953473u64)),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(intent(&bad).is_err());
        }
    }
    #[test]
    fn every_unfinished_stage_is_included_without_floating_point() {
        let mut stages = STAGES
            .into_iter()
            .map(|s| (s.into(), 1000u64))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(remaining(&stages, 250).unwrap(), 4750);
        assert_eq!(remaining(&stages, 2000).unwrap(), 4001);
        stages.remove("suffix_restart");
        assert!(remaining(&stages, 0).is_err());
        stages.insert("suffix_restart".into(), 0);
        assert!(remaining(&stages, 0).is_err());
    }
    #[test]
    fn only_the_admitted_live_zero_restart_native_invocation_matches() {
        let good = json!({"Id":UNIT,"InvocationID":IID,"NRestarts":"0","LoadState":"loaded","ActiveState":"activating","SubState":"start","MainPID":"100"});
        assert!(owner(&good));
        for (key, value) in [
            ("InvocationID", json!("0".repeat(32))),
            ("NRestarts", json!("1")),
            ("ActiveState", json!("inactive")),
            ("MainPID", json!("0")),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(!owner(&bad));
        }
    }
}
