//! Fresh, read-only-storage admission for exact144 assembly-only recovery.
//! Never launches a service or mutates any R2 object.
use super::*;
const ASSEMBLER: &str = "/usr/local/lib/jetstreamer/horizon-epoch144-assembly-only-tools-20261022-v1/jetstreamer-epoch144-assembly-only";
const ASSEMBLER_SHA: &str = "9cde9f28e1f281eed76faae4a99a6f251984d7bcb8c62ee90a3e8b271a5f3e71";
const ORIGINAL_IID: &str = "8fddd3ef045c4fe5b12c7d25f43a4b73";
const PREFIX: &str = "917f700274c0ff0386cd8be2f27eb2ace9f3bc7dff38e1010d0c04bb79b8c273";
const SUFFIX: &str = "3df30cabba516ff6de39bfc236fca030e3bb75b45603d88ef7baf7a6d669a414";
const PREFIX_MANIFEST: &str = "691d5f3768b8c283678937b49790606b6091d4ab632372bfff38664c005b544a";
const SUFFIX_MANIFEST: &str = "065445bef8d301a45a24ba8e14f34b2c0c06906a9cfe7a06cbfd04eeba3f15ce";
const FLOOR_SHA: &str = "39673f485b44ffb5c2053e2a553819da0bd0be30dcfc3cb8990553dd4de0f682";
const RELEASE_SHA: &str = "2e0aec223a30d9af4ada3b4ef5feb82996c718ca1b951dbe04b62d0d5bfbf3e6";
const BASELINE: u64 = 3_916_063_202_758;
const PEAK: u64 = 160 << 30;
const ROOT: &str = "/var/lib/jetstreamer/horizon-epoch144-assembly-only-admissions-20261022-v1";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    observer: BoundFile,
    fleet: BoundFile,
    fleet_plan: BoundFile,
    floor: BoundFile,
    protection_release: BoundFile,
    assembler: BoundFile,
    prefix_manifest: BoundFile,
    suffix_manifest: BoundFile,
    output: PathBuf,
}
fn accepted(s: &Spec, o: &Value, f: &Value, p: &Value, now: u64) -> Result<()> {
    let t = utc_seconds(o["recorded_at_utc"].as_str().context("observer time")?)?;
    ensure!(
        s.schema == "jetstreamer-private144-assembly-only-admission-spec-v1"
            && s.assembler.path == Path::new(ASSEMBLER)
            && s.assembler.sha256 == ASSEMBLER_SHA
            && s.floor.sha256 == FLOOR_SHA
            && s.protection_release.sha256 == RELEASE_SHA
            && s.prefix_manifest.sha256 == PREFIX_MANIFEST
            && s.suffix_manifest.sha256 == SUFFIX_MANIFEST
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && f["schema"] == SCHEMA
            && f["first_epoch"] == 101
            && f["last_epoch"] == 200
            && f["observer_sha256"] == s.observer.sha256
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && f["plan"].as_str() == s.fleet_plan.path.to_str()
            && f["plan_sha256"] == s.fleet_plan.sha256
            && p["observer"] == private157::binding(&s.observer)
            && f["inventory"]["anomalies"] == 0
            && t <= now
            && now - t <= 1800,
        "stale/foreign assembly-only admission basis"
    );
    ensure!(
        o["filesystem"]["conservative_available_bytes"]
            .as_u64()
            .is_some_and(|n| n >= BASELINE + PEAK)
            && o["host_memory"]["conservative_available_kib"]
                .as_u64()
                .is_some_and(|n| n >= 128 * 1024 * 1024),
        "assembly-only sampled resource gate"
    );
    continuation144_admission::clean_replays(o)?;
    ensure!(
        f["active"]
            .as_array()
            .context("active census")?
            .iter()
            .all(|r| r["epoch"] != 144
                || (r["producer"]["Id"] == continuation144::UNIT
                    && r["ordinary_replay_claim"] == false)),
        "another144claim overlaps assembly-only recovery"
    );
    ensure!(
        s.output.parent() == Some(Path::new(ROOT))
            && s.output
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("admission-")
                    && s.ends_with(".json")
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))),
        "foreign assembly admission output"
    );
    Ok(())
}
fn source_manifests(p: &Value, s: &Value) -> Result<()> {
    ensure!(
        p["schema_version"] == 1
            && s["schema_version"] == 1
            && p["epoch"] == 144
            && s["epoch"] == 144
            && p["archive_sha256"] == PREFIX
            && s["archive_sha256"] == SUFFIX
            && p["output_slot_start"] == 62208000
            && p["output_slot_count"] == 431491
            && p["terminal"]["slot"] == 62639490
            && s["output_slot_start"] == 62639491
            && s["output_slot_count"] == 509
            && s["bootstrap"]["slot"] == 62639490
            && s["terminal"]["slot"] == 62639999
            && s["bootstrap"]["write_count"] == 0
            && s["runtime"]["runtime_profile"] == "solana-v1.4.25"
            && p["runtime"]["runtime_profile"] == s["runtime"]["runtime_profile"],
        "wrong complete144 sources"
    );
    for key in [
        "slot",
        "bank_hash",
        "accounts_hash",
        "last_blockhash",
        "capitalization",
        "transaction_count",
        "tick_height",
        "slot_complete",
    ] {
        ensure!(
            p["terminal"].get(key).is_some() && p["terminal"][key] == s["bootstrap"][key],
            "native restart mismatch:{key}"
        );
    }
    Ok(())
}
fn timeout_properties() -> Result<Value> {
    let out=ProcessCommand::new("systemctl").args(["show",continuation144::UNIT,"--property=Id,InvocationID,MainPID,NRestarts,Restart,Result,ActiveState,SubState,RuntimeMaxUSec,ExecMainStatus,ExecStart"]).output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 16384,
        "original144 timeout observation failed"
    );
    let fields: serde_json::Map<_, _> = std::str::from_utf8(&out.stdout)?
        .lines()
        .filter_map(|s| s.split_once('='))
        .map(|(k, v)| (k.into(), json!(v)))
        .collect();
    let v = Value::Object(fields);
    check_timeout(&v)?;
    Ok(v)
}
fn check_timeout(v: &Value) -> Result<()> {
    ensure!(
        v["Id"] == continuation144::UNIT
            && v["InvocationID"] == ORIGINAL_IID
            && v["MainPID"] == "0"
            && v["NRestarts"] == "0"
            && v["Restart"] == "no"
            && v["Result"] == "timeout"
            && v["ActiveState"] == "failed"
            && v["SubState"] == "failed"
            && v["RuntimeMaxUSec"] == "2h"
            && matches!(v["ExecMainStatus"].as_str(), Some("9" | "15" | "1")),
        "original144 not exact terminal timeout; no assembly-only admission"
    );
    Ok(())
}
fn protected_owners(f: &Value, current: &BTreeMap<String, Value>) -> Result<()> {
    let mut filtered = f.clone();
    let old = filtered["unit_census"][continuation144::UNIT].clone();
    ensure!(
        old["InvocationID"] == ORIGINAL_IID,
        "original144 predecessor identity absent/changed"
    );
    filtered["active"]
        .as_array_mut()
        .context("active census")?
        .retain(|v| v["producer"]["Id"] != continuation144::UNIT);
    // Only the separately authenticated original timeout is allowed to leave
    // the old active list. Every other owner and dormant-to-live edge remains
    // under the existing conservative protection checker.
    continuation144_protection::owners(&filtered, current)
}
async fn remote_floor(s3: &Client, r2: &R2Config, floor: &Value) -> Result<()> {
    for proof in floor["samples"].as_array().context("floor samples")? {
        let epoch = proof["epoch"].as_u64().context("floor epoch")?;
        let remote = inventory_epoch(s3, r2, epoch).await?;
        let evidence = |path: &str, sha: &str| -> Result<Value> {
            bound_json(&BoundFile {
                path: proof[path].as_str().context("floor evidence path")?.into(),
                sha256: proof[sha].as_str().context("floor evidence digest")?.into(),
            })
        };
        let ready = evidence("r2_receipt", "r2_receipt_sha256")?;
        let verified = evidence(
            "private_resource_verification",
            "private_resource_verification_sha256",
        )?;
        ensure!(
            remote.state == InventoryState::ReadyPair
                && remote.archive_length == proof["jet_size_bytes"].as_u64()
                && remote.archive_etag.as_deref() == ready["archive_etag"].as_str()
                && remote.sidecar_sha256.as_deref() == proof["archive_sha256"].as_str()
                && remote.archive_metadata_sha256.as_deref() == proof["archive_sha256"].as_str()
                && ready["authenticated_ready_pair_revalidated"] == true
                && ready["remote_sha256_readback"] == true
                && verified["status"] == "passed"
                && verified["full_verifier"]["exit_code"] == 0
                && verified["current_plugin"]["exit_code"] == 0
                && verified["archive_sha256_before_after_verified"] == true,
            "century floor proof/remote identity failed"
        );
        for v in [ready, verified] {
            ensure!(
                v["epoch"] == epoch
                    && v["archive_length"] == proof["jet_size_bytes"]
                    && v["archive_sha256"] == proof["archive_sha256"],
                "floor source tuple differs"
            );
        }
    }
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
        "usage: admit-assembly-only144 SPEC --spec-sha256 SHA --self-sha256 SHA [--check-only]"
    );
    let own = fs::read_link("/proc/self/exe")?;
    let m = fs::symlink_metadata(&own)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == args[6],
        "unsealed assembly admission tool"
    );
    let sb = BoundFile {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let m = fs::symlink_metadata(&sb.path)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && sb.path.canonicalize()? == sb.path,
        "unsealed assembly admission spec"
    );
    let s: Spec = serde_json::from_value(bound_json(&sb)?)?;
    let o = bound_json(&s.observer)?;
    let f = bound_json(&s.fleet)?;
    let plan = bound_json(&s.fleet_plan)?;
    let floor = bound_json(&s.floor)?;
    let floor_bytes = snapshot144::floor(&floor)?;
    let release = bound_json(&s.protection_release)?;
    ensure!(
        release["schema"] == "jetstreamer-continuation144-protection-release-v1"
            && release["authenticated198_ready_pair_revalidated"] == true
            && release["protection"]["protected_free_bytes"] == BASELINE
            && release["protection"]["century_floor_bytes"] == floor_bytes,
        "assembly protection/floor changed"
    );
    source_manifests(
        &bound_json(&s.prefix_manifest)?,
        &bound_json(&s.suffix_manifest)?,
    )?;
    let m = fs::symlink_metadata(&s.assembler.path)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && s.assembler.path.canonicalize()? == s.assembler.path
            && hex_lower(&Sha256::digest(fs::read(&s.assembler.path)?)) == ASSEMBLER_SHA,
        "unsealed/wrong assembly binary"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    accepted(&s, &o, &f, &plan, now)?;
    validate_output_destination(&s.output)?;
    if check {
        println!(
            "assembly-only admission preflight passed; no service/resource/remote observation,writes or launch; actual original timeout remains required"
        );
        return Ok(());
    }
    let timeout = timeout_properties()?;
    let invocation =
        env::var("INVOCATION_ID").context("persistent admission invocation required")?;
    ensure!(
        invocation.len() == 32
            && invocation
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "invalid admission invocation"
    );
    let names = f["unit_census"]
        .as_object()
        .context("fleet census")?
        .keys()
        .cloned()
        .collect();
    let before = census(&names, 101, 200)?;
    protected_owners(&f, &before)?;
    let r2 = r2_config_from_env()?;
    ensure!(
        r2.bucket == "solana-archive-with-accounts-data",
        "wrong bucket"
    );
    let s3 = s3_client(&r2);
    remote_floor(&s3, &r2, &floor).await?;
    let ready198: BoundFile = serde_json::from_value(release["epoch198_ready"].clone())?;
    continuation144_protection::remote_matches(
        &inventory_epoch(&s3, &r2, 198).await?,
        &bound_json(&ready198)?,
    )?;
    let available = snapshot144::free_bytes()?;
    let mem = fs::read_to_string("/proc/meminfo")?
        .lines()
        .find_map(|l| {
            l.strip_prefix("MemAvailable:")
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse::<u64>().ok())
        })
        .context("memory available")?;
    ensure!(
        available >= BASELINE + PEAK && mem >= 128 * 1024 * 1024,
        "actual assembly-only resource gate failed"
    );
    let after = census(&names, 101, 200)?;
    protected_owners(&f, &after)?;
    ensure!(
        timeout_properties()? == timeout,
        "original timeout identity changed"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    accepted(&s, &o, &f, &plan, now)?;
    private157::immutable_receipt(
        &s.output,
        &json!({"schema":"jetstreamer-private144-assembly-only-admission-v1","epoch":144,"admitted":true,"assembly_only_no_replay":true,
        "assembler_sha256":ASSEMBLER_SHA,"prefix_sha256":PREFIX,"suffix_sha256":SUFFIX,"prefix_manifest_sha256":PREFIX_MANIFEST,"suffix_manifest_sha256":SUFFIX_MANIFEST,
        "candidate_incremental_peak_bytes":PEAK,"protected_existing_floor_bytes":BASELINE,"maximum_archive_bytes":112u64<<30,"maximum_runtime_seconds":86400,
        "available_bytes":available,"memory_available_kib":mem,"required_guard_minimum_free_bytes":available.saturating_sub(PEAK).max(BASELINE),"century_floor_bytes":floor_bytes,
        "observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),"spec":private157::binding(&sb),"original_timeout":timeout,
        "unit_census_before":before,"unit_census_after":after,"recorded_unix_seconds":now,"invocation_id":invocation,"self_sha256":args[6],
        "new_resource_samples":0,"guard_first_fire_required":true,"fleet_transition_required":true,"exact_node_capability_required":true,
        "replay_launch_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"r2_mutations":false,"remote_mutations":false}),
    )?;
    println!("assembly-only admission written; no launch, guard or publication authority");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepted_sample_is_fresh_and_preserves_only_the_original_timeout_exception() {
        let b = || BoundFile {
            path: "/sealed/input".into(),
            sha256: "a".repeat(64),
        };
        let mut s = Spec {
            schema: "jetstreamer-private144-assembly-only-admission-spec-v1".into(),
            observer: b(),
            fleet: b(),
            fleet_plan: b(),
            floor: b(),
            protection_release: b(),
            assembler: b(),
            prefix_manifest: b(),
            suffix_manifest: b(),
            output: Path::new(ROOT).join("admission-test.json"),
        };
        s.floor.sha256 = FLOOR_SHA.into();
        s.protection_release.sha256 = RELEASE_SHA.into();
        s.assembler.path = ASSEMBLER.into();
        s.assembler.sha256 = ASSEMBLER_SHA.into();
        s.prefix_manifest.sha256 = PREFIX_MANIFEST.into();
        s.suffix_manifest.sha256 = SUFFIX_MANIFEST.into();
        let rows=["152-153","155-156","160","191-194"].map(|range|json!({"range":range,"invocation_binding_stable":true,"producer_after":{"restarts":0},"controller_after":{"restarts":0},"worker_after":{"matching_workers":1,"vmas":400000},"useful_work":{"sufficient_for_rates":true,"slots_per_second":1.0},"producer_cgroup_counter_delta":{"memory_events.oom":0,"memory_events.oom_kill":0,"memory_events.oom_group_kill":0,"memory_events.max":0}}));
        let o = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"2026-10-22T01:58:00Z","filesystem":{"conservative_available_bytes":BASELINE+PEAK},"host_memory":{"conservative_available_kib":128u64*1024*1024},"replays":rows});
        let mut f = json!({"schema":SCHEMA,"first_epoch":101,"last_epoch":200,"observer_sha256":s.observer.sha256,"sampled_at_utc":o["recorded_at_utc"],"plan":s.fleet_plan.path,"plan_sha256":s.fleet_plan.sha256,"inventory":{"anomalies":0},"active":[{"epoch":144,"producer":{"Id":continuation144::UNIT},"ordinary_replay_claim":false}]});
        let p = json!({"observer":private157::binding(&s.observer)});
        let now = utc_seconds("2026-10-22T01:58:00Z").unwrap();
        accepted(&s, &o, &f, &p, now + 1800).unwrap();
        assert!(accepted(&s, &o, &f, &p, now + 1801).is_err());
        assert!(accepted(&s, &o, &f, &p, now - 1).is_err());
        f["active"][0]["ordinary_replay_claim"] = json!(true);
        assert!(accepted(&s, &o, &f, &p, now).is_err());
        f["active"][0]["ordinary_replay_claim"] = json!(false);
        f["active"][0]["producer"]["Id"] = json!("different");
        assert!(accepted(&s, &o, &f, &p, now).is_err());
    }
    #[test]
    fn timeout_cannot_be_borrowed_from_a_live_successful_or_foreign_owner() {
        let good = json!({"Id":continuation144::UNIT,"InvocationID":ORIGINAL_IID,"MainPID":"0","NRestarts":"0","Restart":"no","Result":"timeout","ActiveState":"failed","SubState":"failed","RuntimeMaxUSec":"2h","ExecMainStatus":"9"});
        check_timeout(&good).unwrap();
        for (k, v) in [
            ("Result", "success"),
            ("MainPID", "42"),
            ("InvocationID", "foreign"),
            ("NRestarts", "1"),
        ] {
            let mut bad = good.clone();
            bad[k] = json!(v);
            assert!(check_timeout(&bad).is_err());
        }
    }
}
