//! Release only completed198's future growth, not its retained archive or evidence.
//! This receipt is a protection-accounting proposal, never admission or launch.
use super::*;

const ORIGINAL: u64 = 4_740_696_923_590;
const RELEASE: u64 = 768 << 30;
const POLICY_SHA: &str = "b5efbe4c14d573ecc41bdddc6669188802774bda431a2677587e903487b71a30";
const FLOOR_SHA: &str = "39673f485b44ffb5c2053e2a553819da0bd0be30dcfc3cb8990553dd4de0f682";
const READY_SHA: &str = "81470e448a855612c57c2727e11f08dbb9b52a19bbe6168cea440fe1b17ae1f3";
const ARCHIVE_SHA: &str = "4a1252a650f7b50f45326a07c0a58090b8c0174cf547099a16eeca45869f7ffb";
const PRODUCER: &str =
    "jetstreamer-root-sweep-e198-readerfix-20261019-v1-r2-e198-198-lane-a-1.service";
const CONTROLLER: &str = "jetstreamer-epoch198-readerfix-singleton-20261019-v1-r2.service";
const ROOT: &str = "/var/lib/jetstreamer/horizon-continuation144-protection-v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    observer: BoundFile,
    fleet: BoundFile,
    fleet_plan: BoundFile,
    original_policy: BoundFile,
    floor: BoundFile,
    epoch198_ready: BoundFile,
    output: PathBuf,
}

fn release_policy(policy: &Value, floor: u64, ready: &Value) -> Result<Value> {
    let claims = policy["claims"].as_object().context("original claims")?;
    ensure!(
        policy["schema"] == "jetstreamer-epoch141-retention-protection-transition-v1"
            && policy["protected_free_bytes"] == ORIGINAL
            && claims.len() == 7
            && claims["198"]["remaining_growth_bytes"] == RELEASE
            && claims["198"]["producer_unit"] == PRODUCER
            && claims["198"]["producer_invocation_id"] == "e5612ef00a5b4fcab04df2c13a6b35b0"
            && claims["198"]["controller_unit"] == CONTROLLER,
        "original198 reservation differs"
    );
    let sum = claims.values().try_fold(0u64, |sum, v| {
        sum.checked_add(
            v["remaining_growth_bytes"]
                .as_u64()
                .context("claim bytes")?,
        )
        .context("claim sum overflow")
    })?;
    let margin = policy["priority_margin_bytes"].as_u64().context("margin")?;
    let obligated = sum
        .checked_add(floor)
        .and_then(|n| n.checked_add(margin))
        .context("protection overflow")?;
    ensure!(obligated <= ORIGINAL, "original protection underfunded");
    ensure!(
        ready["schema"] == "jetstreamer-horizon-r2-receipt-v1"
            && ready["epoch"] == 198
            && ready["archive_key"] == "epoch-198.jet"
            && ready["checksum_key"] == "epoch-198.jet.sha256"
            && ready["bucket"] == "solana-archive-with-accounts-data"
            && ready["archive_length"] == 99_381_250_591u64
            && ready["archive_sha256"] == ARCHIVE_SHA
            && ready["remote_sha256_readback"] == true,
        "198 lacks original whole-object completion proof"
    );
    let mut retained = claims.clone();
    retained.remove("198");
    Ok(
        json!({"original_protected_free_bytes":ORIGINAL,"released_epoch":198,
        "released_future_growth_bytes":RELEASE,"protected_free_bytes":ORIGINAL-RELEASE,
        "retained_claims":retained,"century_floor_bytes":floor,"priority_margin_bytes":margin,
        "additional_original_slack_bytes":ORIGINAL-obligated,
        "retained144_and157_claims_are_conservative_reservations_not_live_work":true}),
    )
}

fn accepted(s: &Spec, observer: &Value, fleet: &Value, plan: &Value, now: u64) -> Result<()> {
    let sample = utc_seconds(
        observer["recorded_at_utc"]
            .as_str()
            .context("sample time")?,
    )?;
    ensure!(
        s.schema == "jetstreamer-continuation144-protection-spec-v1"
            && s.original_policy.sha256 == POLICY_SHA
            && s.floor.sha256 == FLOOR_SHA
            && s.epoch198_ready.sha256 == READY_SHA
            && observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && fleet["schema"] == SCHEMA
            && fleet["first_epoch"] == 101
            && fleet["last_epoch"] == 200
            && fleet["observer_sha256"] == s.observer.sha256
            && fleet["sampled_at_utc"] == observer["recorded_at_utc"]
            && fleet["plan"].as_str() == s.fleet_plan.path.to_str()
            && fleet["plan_sha256"] == s.fleet_plan.sha256
            && plan["observer"] == private157::binding(&s.observer)
            && fleet["inventory"]["anomalies"] == 0
            && sample <= now
            && now - sample <= 1800,
        "foreign or stale accepted protection basis"
    );
    let epoch198: Vec<_> = fleet["epochs"]
        .as_array()
        .context("epoch census")?
        .iter()
        .filter(|v| v["epoch"] == 198)
        .collect();
    ensure!(
        epoch198.len() == 1
            && epoch198[0]["state"] == "remote-ready"
            && !fleet["active"]
                .as_array()
                .context("active census")?
                .iter()
                .any(|v| v["epoch"] == 198),
        "198 has not completed or still has an active claim"
    );
    let name = s
        .output
        .file_name()
        .and_then(|n| n.to_str())
        .context("output name")?;
    ensure!(
        s.output.parent() == Some(Path::new(ROOT))
            && name.starts_with("protection-")
            && name.ends_with(".json")
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "protection output outside private namespace"
    );
    Ok(())
}

pub(super) fn owners(fleet: &Value, current: &BTreeMap<String, Value>) -> Result<()> {
    snapshot144::check_owners(fleet, current)?;
    // A dormant tracked lane becoming live is just as material as a newly
    // discovered unit. Do not rely only on the prior active-list subset.
    for (name, owner) in current {
        if owner["MainPID"]
            .as_str()
            .and_then(|s| s.parse::<u32>().ok())
            .is_some_and(|pid| pid > 0)
        {
            let old = fleet["unit_census"]
                .get(name)
                .context("new live tracked owner")?;
            ensure!(
                old["MainPID"]
                    .as_str()
                    .and_then(|s| s.parse::<u32>().ok())
                    .is_some_and(|pid| pid > 0)
                    && old["InvocationID"] == owner["InvocationID"]
                    && old["NRestarts"] == owner["NRestarts"],
                "tracked owner changed since protection basis"
            );
        }
    }
    for name in [PRODUCER, CONTROLLER] {
        let owner = current
            .get(name)
            .context("198 owner absent from complete census")?;
        ensure!(
            owner["MainPID"] == "0"
                && matches!(owner["ActiveState"].as_str(), Some("inactive" | "failed"))
                && owner["NRestarts"] == "0",
            "198 owner not terminal/dormant"
        );
    }
    Ok(())
}

fn remote_matches(remote: &InventoryEntry, ready: &Value) -> Result<()> {
    ensure!(
        remote.epoch == 198
            && remote.state == InventoryState::ReadyPair
            && remote.archive_length == Some(99_381_250_591)
            && remote.archive_etag.as_deref() == ready["archive_etag"].as_str()
            && remote.sidecar_sha256.as_deref() == Some(ARCHIVE_SHA)
            && remote.archive_metadata_sha256.as_deref() == Some(ARCHIVE_SHA),
        "198 authenticated remote ready pair differs"
    );
    Ok(())
}

pub(super) async fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    let check = args.len() == 8 && args[7] == "--check-only";
    ensure!(
        (args.len() == 7 || check)
            && args[3] == "--spec-sha256"
            && args[5] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: prepare-continuation144-protection SPEC --spec-sha256 SHA --self-sha256 SHA [--check-only] (root)"
    );
    let executable = fs::read_link("/proc/self/exe")?;
    let metadata = fs::symlink_metadata(&executable)?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o222 == 0
            && hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == args[6],
        "unsealed protection writer"
    );
    let bound = BoundFile {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let m = fs::symlink_metadata(&bound.path)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && bound.path.canonicalize()? == bound.path,
        "unsealed protection spec"
    );
    let s: Spec = serde_json::from_value(bound_json(&bound)?)?;
    let observer = bound_json(&s.observer)?;
    let fleet = bound_json(&s.fleet)?;
    let plan = bound_json(&s.fleet_plan)?;
    let policy = bound_json(&s.original_policy)?;
    let floor = snapshot144::floor(&bound_json(&s.floor)?)?;
    let ready = bound_json(&s.epoch198_ready)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    accepted(&s, &observer, &fleet, &plan, now)?;
    let proposal = release_policy(&policy, floor, &ready)?;
    validate_output_destination(&s.output)?;
    if check {
        println!(
            "protection preflight passed; no service, resource or remote observation, writes or launch"
        );
        return Ok(());
    }
    let invocation = env::var("INVOCATION_ID").context("persistent invocation required")?;
    ensure!(
        invocation.len() == 32
            && invocation
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "invalid invocation"
    );
    let mut names: BTreeSet<String> = fleet["unit_census"]
        .as_object()
        .context("unit census")?
        .keys()
        .cloned()
        .collect();
    names.extend([PRODUCER.to_owned(), CONTROLLER.to_owned()]);
    let names = names.into_iter().collect();
    let before = census(&names, 101, 200)?;
    owners(&fleet, &before)?;
    let r2 = r2_config_from_env()?;
    ensure!(
        r2.bucket == "solana-archive-with-accounts-data",
        "wrong bucket"
    );
    let s3 = s3_client(&r2);
    let remote = inventory_epoch(&s3, &r2, 198).await?;
    remote_matches(&remote, &ready)?;
    let after = census(&names, 101, 200)?;
    owners(&fleet, &after)?;
    let final_remote = inventory_epoch(&s3, &r2, 198).await?;
    remote_matches(&final_remote, &ready)?;
    private157::immutable_receipt(
        &s.output,
        &json!({
            "schema":"jetstreamer-continuation144-protection-release-v1","epoch":144,
            "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            "invocation_id":invocation,"self_sha256":args[6],"spec":private157::binding(&bound),
            "observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),
            "original_policy":private157::binding(&s.original_policy),"floor":private157::binding(&s.floor),
            "epoch198_ready":private157::binding(&s.epoch198_ready),"protection":proposal,
            "unit_census_before":before,"unit_census_after":after,"authenticated198_ready_pair_revalidated":true,
            "new_resource_samples":0,"service_state_changed":false,"admission_authorized":false,
            "replay_launch_authorized":false,"publication_authorized":false,"local_retirement_authorized":false,
            "remote_mutations":false,"r2_mutations":false
        }),
    )?;
    println!(
        "released only completed198future-growth accounting; no admission or launch authority"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "root exact retained policy/floor/ready receipts; no service/resource/remote observations or writes"]
    fn root_exact_retained_accounting_inputs_pass() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let input = |path: &str, sha: &str| {
            bound_json(&BoundFile {
                path: path.into(),
                sha256: sha.into(),
            })
            .unwrap()
        };
        let p = input(
            "/usr/local/lib/jetstreamer/horizon-epoch141-retention-protection-20261020-v2/policy.json",
            POLICY_SHA,
        );
        let f = input(
            "/home/sol/.jetstreamer-private/century-floor-epoch201-audit-20261019-v1/verification-v3/century-floor.json",
            FLOOR_SHA,
        );
        let r = input(
            "/home/sol/.jetstreamer-private/r2-receipts/epoch-198.r2.json",
            READY_SHA,
        );
        let result = release_policy(&p, snapshot144::floor(&f).unwrap(), &r).unwrap();
        assert_eq!(result["protected_free_bytes"], 3_916_063_202_758u64);
        assert_eq!(
            result["retained_claims"]["157"]["remaining_growth_bytes"],
            512u64 << 30
        );
        assert_eq!(
            result["retained_claims"]["160"]["remaining_growth_bytes"],
            768u64 << 30
        );
    }
    fn policy() -> Value {
        let mut claims = serde_json::Map::new();
        for name in ["144", "157", "160", "198", "152-153", "155-156", "191-194"] {
            claims.insert(name.into(),json!({"remaining_growth_bytes":if name=="198" || name=="160" {RELEASE} else {512u64<<30}}));
        }
        claims.get_mut("198").unwrap()["producer_unit"] = json!(PRODUCER);
        claims.get_mut("198").unwrap()["producer_invocation_id"] =
            json!("e5612ef00a5b4fcab04df2c13a6b35b0");
        claims.get_mut("198").unwrap()["controller_unit"] = json!(CONTROLLER);
        json!({"schema":"jetstreamer-epoch141-retention-protection-transition-v1","protected_free_bytes":ORIGINAL,
            "priority_margin_bytes":64u64<<30,"claims":claims})
    }
    fn ready() -> Value {
        json!({"schema":"jetstreamer-horizon-r2-receipt-v1","epoch":198,"archive_key":"epoch-198.jet",
            "checksum_key":"epoch-198.jet.sha256","bucket":"solana-archive-with-accounts-data",
            "archive_length":99381250591u64,"archive_sha256":ARCHIVE_SHA,"remote_sha256_readback":true})
    }
    #[test]
    fn release_preserves_every_other_reservation_floor_margin_and_slack() {
        let p = policy();
        let r = release_policy(&p, 205211459014, &ready()).unwrap();
        assert_eq!(r["protected_free_bytes"], ORIGINAL - RELEASE);
        assert_eq!(r["retained_claims"].as_object().unwrap().len(), 6);
        for (name, v) in p["claims"].as_object().unwrap() {
            if name != "198" {
                assert_eq!(&r["retained_claims"][name], v);
            }
        }
        assert_eq!(r["century_floor_bytes"], 205211459014u64);
        assert_eq!(r["priority_margin_bytes"], 64u64 << 30);
    }
    #[test]
    fn no_release_from_wrong_pair_unverified_receipt_or_underfunded_policy() {
        for (field, value) in [
            ("epoch", json!(197)),
            ("archive_length", json!(1)),
            ("remote_sha256_readback", json!(false)),
            ("checksum_key", json!("epoch-197.jet.sha256")),
        ] {
            let mut r = ready();
            r[field] = value;
            assert!(release_policy(&policy(), 205211459014, &r).is_err());
        }
        let mut p = policy();
        p["claims"]["198"]["remaining_growth_bytes"] = json!(RELEASE + 1);
        assert!(release_policy(&p, 205211459014, &ready()).is_err());
        assert!(release_policy(&policy(), ORIGINAL, &ready()).is_err());
    }
    #[test]
    fn dormant_tracked_lane_cannot_consume_headroom_unobserved() {
        let terminal =
            json!({"MainPID":"0","ActiveState":"inactive","NRestarts":"0","InvocationID":""});
        let mut current = BTreeMap::from([
            (PRODUCER.into(), terminal.clone()),
            (CONTROLLER.into(), terminal.clone()),
            ("horizon-qualify-144-other.service".into(), terminal),
        ]);
        let fleet = json!({"active":[],"unit_census":current});
        owners(&fleet, &current).unwrap();
        current
            .get_mut("horizon-qualify-144-other.service")
            .unwrap()["MainPID"] = json!("123");
        assert!(owners(&fleet, &current).is_err());
        current.get_mut(PRODUCER).unwrap()["MainPID"] = json!("456");
        assert!(owners(&fleet, &current).is_err());
    }
}
