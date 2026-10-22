//! Exact private144 full-path experimental admission. No service is launched.
use super::*;

const PROTECTION_SHA: &str = "2e0aec223a30d9af4ada3b4ef5feb82996c718ca1b951dbe04b62d0d5bfbf3e6";
const NATIVE_SHA: &str = "400b6215f060f541bd2cfe0c3ff14c303b0e057887bc30b1d9e765416b647d30";
const PREFIX_SHA: &str = "917f700274c0ff0386cd8be2f27eb2ace9f3bc7dff38e1010d0c04bb79b8c273";
const SNAPSHOT_SHA: &str = "f170976b2bc3f2d55dd0fbb5a415bfeae8d0903a0ad69334d8aa993b5cab35ae";
const WORKER_SHA: &str = "2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8";
const FLOOR_SHA: &str = "39673f485b44ffb5c2053e2a553819da0bd0be30dcfc3cb8990553dd4de0f682";
const PROTECTED: u64 = 3_916_063_202_758;
const PEAK: u64 = 192 << 30;
const ROOT: &str = "/var/lib/jetstreamer/horizon-continuation144-admission-v2";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    observer: BoundFile,
    fleet: BoundFile,
    fleet_plan: BoundFile,
    protection_release: BoundFile,
    native_result: BoundFile,
    floor: BoundFile,
    node: BoundFile,
    resource_policy: BoundFile,
    output: PathBuf,
}

fn policy(p: &Value, native: &Value, release: &Value) -> Result<()> {
    ensure!(
        p["schema"] == "jetstreamer-epoch144-continuation-resource-policy-v2"
            && p["epoch"] == 144
            && p["remaining_slots"] == 509
            && p["prefix_archive_bytes"] == 109_159_726_722u64
            && p["native_result_sha256"] == NATIVE_SHA
            && p["protected_existing_floor_bytes"] == PROTECTED
            && p["candidate_incremental_peak_bytes"] == PEAK
            && p["native_copy_restore_indexes_bytes"] == 40u64 << 30
            && p["suffix_archive_and_growth_bytes"] == 8u64 << 30
            && p["assembled_archive_bytes"] == 112u64 << 30
            && p["independent_verification_scratch_bytes"] == 16u64 << 30
            && p["incremental_margin_bytes"] == 16u64 << 30
            && p["replay_launch_authorized"] == false
            && p["publication_authorized"] == false
            && p["r2_mutations"] == false
            && p["full_cold_peak_qualified"] == false
            && p["experimental_guarded_envelope"] == true,
        "144 full-path policy differs; native-only evidence is insufficient"
    );
    ensure!(
        native["schema"] == "jetstreamer-private-epoch144-native-restore-probe-v1"
            && native["passed"] == true
            && native["replay_entries_sent"] == 0
            && native["native_result"]["comparison_passed"] == true
            && native["native_result"]["shutdown_passed"] == true,
        "144 prior native barrier failed"
    );
    ensure!(
        release["schema"] == "jetstreamer-continuation144-protection-release-v1"
            && release["authenticated198_ready_pair_revalidated"] == true
            && release["protection"]["original_protected_free_bytes"] == 4_740_696_923_590u64
            && release["protection"]["released_epoch"] == 198
            && release["protection"]["released_future_growth_bytes"] == 768u64 << 30
            && release["protection"]["protected_free_bytes"] == PROTECTED
            && release["admission_authorized"] == false
            && release["replay_launch_authorized"] == false,
        "144 missing exact completed198 accounting release"
    );
    Ok(())
}

fn sample(s: &Spec, o: &Value, f: &Value, p: &Value, now: u64) -> Result<()> {
    let time = utc_seconds(o["recorded_at_utc"].as_str().context("observer time")?)?;
    ensure!(
        s.schema == "jetstreamer-epoch144-continuation-admission-spec-v2"
            && s.protection_release.sha256 == PROTECTION_SHA
            && s.native_result.sha256 == NATIVE_SHA
            && s.floor.sha256 == FLOOR_SHA
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
            && time <= now
            && now - time <= 1800,
        "stale or unaccepted144 full-path admission sample"
    );
    ensure!(
        o["filesystem"]["conservative_available_bytes"]
            .as_u64()
            .is_some_and(|n| n >= PROTECTED + PEAK)
            && o["host_memory"]["conservative_available_kib"]
                .as_u64()
                .is_some_and(|n| n >= 192 * 1024 * 1024)
            && o["vm_max_map_count"]
                .as_u64()
                .is_some_and(|n| n >= 4_194_304),
        "sampled144 disk/memory/VMA envelope unavailable"
    );
    ensure!(
        !f["active"]
            .as_array()
            .context("active census")?
            .iter()
            .any(|v| v["epoch"] == 144),
        "144 already active"
    );
    clean_replays(o)?;
    let name = s
        .output
        .file_name()
        .and_then(|n| n.to_str())
        .context("output name")?;
    ensure!(
        s.output.parent() == Some(Path::new(ROOT))
            && name.starts_with("admission-")
            && name.ends_with(".json")
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "wrong admission output"
    );
    Ok(())
}

fn clean_replays(o: &Value) -> Result<()> {
    let rows = o["replays"].as_array().context("ordinary replay census")?;
    let ranges: BTreeSet<_> = rows.iter().filter_map(|v| v["range"].as_str()).collect();
    ensure!(
        rows.len() == 4 && ranges == BTreeSet::from(["152-153", "155-156", "160", "191-194"]),
        "144 admission requires exact four established lanes"
    );
    for row in rows {
        ensure!(
            row["invocation_binding_stable"] == true
                && row["producer_after"]["restarts"] == 0
                && row["controller_after"]["restarts"] == 0
                && row["worker_after"]["matching_workers"] == 1
                && row["worker_after"]["vmas"]
                    .as_u64()
                    .is_some_and(|n| n > 0 && n < 800_000)
                && row["useful_work"]["sufficient_for_rates"] == true
                && row["useful_work"]["slots_per_second"]
                    .as_f64()
                    .is_some_and(|n| n.is_finite() && n > 0.0),
            "144 existing replay not stable/advancing/below VMA bound"
        );
        for key in [
            "memory_events.oom",
            "memory_events.oom_kill",
            "memory_events.oom_group_kill",
            "memory_events.max",
        ] {
            ensure!(
                row["producer_cgroup_counter_delta"][key] == 0,
                "144 admission blocked by existing memory event"
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
        "usage: admit-continuation144 SPEC --spec-sha256 SHA --self-sha256 SHA [--check-only] (root)"
    );
    let own = fs::read_link("/proc/self/exe")?;
    let m = fs::symlink_metadata(&own)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == args[6],
        "unsealed admission writer"
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
        "unsealed admission spec"
    );
    let s: Spec = serde_json::from_value(bound_json(&sb)?)?;
    let o = bound_json(&s.observer)?;
    let f = bound_json(&s.fleet)?;
    let p = bound_json(&s.fleet_plan)?;
    let release = bound_json(&s.protection_release)?;
    let original_ready: BoundFile = serde_json::from_value(release["epoch198_ready"].clone())?;
    let ready198 = bound_json(&original_ready)?;
    let native = bound_json(&s.native_result)?;
    policy(&bound_json(&s.resource_policy)?, &native, &release)?;
    let floor = bound_json(&s.floor)?;
    let floor_bytes = snapshot144::floor(&floor)?;
    ensure!(
        release["protection"]["century_floor_bytes"] == floor_bytes,
        "century floor changed; refresh complete protection"
    );
    let m = fs::symlink_metadata(&s.node.path)?;
    ensure!(
        s.node.path.is_absolute()
            && s.node.path.canonicalize()? == s.node.path
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && m.len() <= 256 << 20
            && s.node.path.file_name().and_then(|n| n.to_str()) == Some("jetstreamer-node")
            && hex_lower(&Sha256::digest(fs::read(&s.node.path)?)) == s.node.sha256,
        "unsealed144 node"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    sample(&s, &o, &f, &p, now)?;
    validate_output_destination(&s.output)?;
    if check {
        println!(
            "144full-path preflight passed; no service/resource/remote observations or writes"
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
    let names = f["unit_census"]
        .as_object()
        .context("unit census")?
        .keys()
        .cloned()
        .collect();
    let before = census(&names, 101, 200)?;
    continuation144_protection::owners(&f, &before)?;
    let r2 = r2_config_from_env()?;
    ensure!(
        r2.bucket == "solana-archive-with-accounts-data",
        "wrong bucket"
    );
    let s3 = s3_client(&r2);
    for epoch in [198, 201] {
        let remote = inventory_epoch(&s3, &r2, epoch).await?;
        ensure!(
            remote.state == InventoryState::ReadyPair,
            "required ready-pair absent"
        );
        if epoch == 201 {
            let proof = floor["samples"]
                .as_array()
                .context("floor samples")?
                .iter()
                .find(|v| v["epoch"] == 201)
                .context("audited201 sample")?;
            let evidence = |path: &str, digest: &str| -> Result<Value> {
                bound_json(&BoundFile {
                    path: proof[path].as_str().context("floor proof path")?.into(),
                    sha256: proof[digest].as_str().context("floor proof digest")?.into(),
                })
            };
            let remote_proof = evidence("r2_receipt", "r2_receipt_sha256")?;
            let verification = evidence(
                "private_resource_verification",
                "private_resource_verification_sha256",
            )?;
            ensure!(
                remote.archive_length == proof["jet_size_bytes"].as_u64()
                    && remote.sidecar_sha256.as_deref() == proof["archive_sha256"].as_str()
                    && remote.archive_metadata_sha256.as_deref()
                        == proof["archive_sha256"].as_str()
                    && remote.archive_etag.as_deref() == remote_proof["archive_etag"].as_str()
                    && remote_proof["authenticated_ready_pair_revalidated"] == true
                    && remote_proof["remote_sha256_readback"] == true
                    && verification["status"] == "passed"
                    && verification["full_verifier"]["exit_code"] == 0
                    && verification["current_plugin"]["exit_code"] == 0
                    && verification["archive_sha256_before_after_verified"] == true,
                "floor sample remote identity changed"
            );
            for receipt in [&remote_proof, &verification] {
                ensure!(
                    receipt["epoch"] == 201
                        && receipt["archive_length"] == proof["jet_size_bytes"]
                        && receipt["archive_sha256"] == proof["archive_sha256"],
                    "floor proof identity differs"
                );
            }
        } else {
            continuation144_protection::remote_matches(&remote, &ready198)?;
        }
    }
    let available = snapshot144::free_bytes()?;
    let mem = fs::read_to_string("/proc/meminfo")?
        .lines()
        .find_map(|l| {
            l.strip_prefix("MemAvailable:")
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse::<u64>().ok())
        })
        .context("memory available")?;
    let vmas = fs::read_to_string("/proc/sys/vm/max_map_count")?
        .trim()
        .parse::<u64>()?;
    ensure!(
        available >= PROTECTED + PEAK && mem >= 192 * 1024 * 1024 && vmas >= 4_194_304,
        "actual144 full-path resource gate failed"
    );
    let after = census(&names, 101, 200)?;
    continuation144_protection::owners(&f, &after)?;
    sample(
        &s,
        &o,
        &f,
        &p,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    private157::immutable_receipt(
        &s.output,
        &json!({
            "schema":"jetstreamer-epoch144-continuation-admission-v2","epoch":144,"admitted":true,"private_continuation_and_assembly_only":true,
            "node_sha256":s.node.sha256,"prefix_sha256":PREFIX_SHA,"snapshot_sha256":SNAPSHOT_SHA,"native_result_sha256":NATIVE_SHA,
            "worker_sha256":WORKER_SHA,"remaining_slots":509,"candidate_incremental_peak_bytes":PEAK,"protected_existing_floor_bytes":PROTECTED,
            "protection_release":private157::binding(&s.protection_release),"resource_policy":private157::binding(&s.resource_policy),
            "observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),"spec":private157::binding(&sb),
            "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"invocation_id":invocation,"self_sha256":args[6],
            "century_floor_bytes":floor_bytes,"available_bytes":available,"memory_available_kib":mem,"vm_max_map_count":vmas,
            "required_guard_minimum_free_bytes":available.saturating_sub(PEAK).max(PROTECTED),
            "experimental_peak_guard_includes_other_fleet_allocations":true,
            "unit_census_before":before,"unit_census_after":after,"exact_node_capability_required":true,"guard_first_fire_required":true,
            "new_resource_samples":0,"full_cold_peak_qualified":false,"ordinary_replay_authorized":false,"canonical_sidecar_authorized":false,
            "publication_authorized":false,"r2_mutations":false,"remote_mutations":false
        }),
    )?;
    println!(
        "144full-path admitted experimentally; exact-node capability and bound guard still required"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn inputs() -> (Value, Value, Value) {
        (
            json!({"schema":"jetstreamer-epoch144-continuation-resource-policy-v2","epoch":144,"remaining_slots":509,
            "prefix_archive_bytes":109159726722u64,"native_result_sha256":NATIVE_SHA,"protected_existing_floor_bytes":PROTECTED,
            "candidate_incremental_peak_bytes":PEAK,"native_copy_restore_indexes_bytes":40u64<<30,"suffix_archive_and_growth_bytes":8u64<<30,
            "assembled_archive_bytes":112u64<<30,"independent_verification_scratch_bytes":16u64<<30,"incremental_margin_bytes":16u64<<30,
            "full_cold_peak_qualified":false,"experimental_guarded_envelope":true,
            "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
            json!({"schema":"jetstreamer-private-epoch144-native-restore-probe-v1","passed":true,"replay_entries_sent":0,
            "native_result":{"comparison_passed":true,"shutdown_passed":true}}),
            json!({"schema":"jetstreamer-continuation144-protection-release-v1","authenticated198_ready_pair_revalidated":true,
            "protection":{"original_protected_free_bytes":4740696923590u64,"released_epoch":198,"released_future_growth_bytes":768u64<<30,
            "protected_free_bytes":PROTECTED},"admission_authorized":false,"replay_launch_authorized":false}),
        )
    }
    #[test]
    fn full_path_cannot_borrow_native_only_or_omit_assembly_and_verification() {
        let (p, n, r) = inputs();
        policy(&p, &n, &r).unwrap();
        for key in [
            "candidate_incremental_peak_bytes",
            "assembled_archive_bytes",
            "independent_verification_scratch_bytes",
            "native_copy_restore_indexes_bytes",
        ] {
            let mut bad = p.clone();
            bad[key] = json!(0);
            assert!(policy(&bad, &n, &r).is_err());
        }
        let mut bad = p.clone();
        bad["candidate_incremental_peak_bytes"] = json!(40u64 << 30);
        assert!(policy(&bad, &n, &r).is_err());
        let mut bad = r.clone();
        bad["protection"]["released_epoch"] = json!(197);
        assert!(policy(&p, &n, &bad).is_err());
        let mut bad = n.clone();
        bad["passed"] = json!(false);
        assert!(policy(&p, &bad, &r).is_err());
        assert_eq!((40u64 + 8 + 112 + 16 + 16) << 30, PEAK);
    }
    fn healthy() -> Value {
        let rows:Vec<_>=["152-153","155-156","160","191-194"].into_iter().map(|range|json!({"range":range,
            "invocation_binding_stable":true,"producer_after":{"restarts":0},"controller_after":{"restarts":0},
            "worker_after":{"matching_workers":1,"vmas":400000},"useful_work":{"sufficient_for_rates":true,"slots_per_second":1.0},
            "producer_cgroup_counter_delta":{"memory_events.oom":0,"memory_events.oom_kill":0,"memory_events.oom_group_kill":0,"memory_events.max":0}})).collect();
        json!({"replays":rows})
    }
    #[test]
    fn existing_lanes_must_be_complete_stable_advancing_and_oom_free() {
        let good = healthy();
        clean_replays(&good).unwrap();
        let mut bad = good.clone();
        bad["replays"][0]["producer_cgroup_counter_delta"]["memory_events.oom_kill"] = json!(1);
        assert!(clean_replays(&bad).is_err());
        let mut bad = good.clone();
        bad["replays"][0]["worker_after"]["vmas"] = json!(800000);
        assert!(clean_replays(&bad).is_err());
        let mut bad = good.clone();
        bad["replays"].as_array_mut().unwrap().pop();
        assert!(clean_replays(&bad).is_err());
    }
    #[test]
    fn fresh_binding_and_complete_capacity_are_mandatory_even_in_preflight() {
        let b = |name: &str, sha: &str| BoundFile {
            path: Path::new("/sealed").join(name),
            sha256: sha.into(),
        };
        let s = Spec {
            schema: "jetstreamer-epoch144-continuation-admission-spec-v2".into(),
            observer: b("observer.json", &"a".repeat(64)),
            fleet: b("fleet.json", &"b".repeat(64)),
            fleet_plan: b("fleet-plan.json", &"c".repeat(64)),
            protection_release: b("release.json", PROTECTION_SHA),
            native_result: b("native.json", NATIVE_SHA),
            floor: b("floor.json", FLOOR_SHA),
            node: b("jetstreamer-node", &"d".repeat(64)),
            resource_policy: b("policy.json", &"e".repeat(64)),
            output: Path::new(ROOT).join("admission-test.json"),
        };
        let mut o = healthy();
        o["schema"] = json!("jetstreamer-horizon-live-resource-sample-v2");
        o["recorded_at_utc"] = json!("2026-10-21T23:58:00Z");
        o["filesystem"] = json!({"conservative_available_bytes":PROTECTED+PEAK});
        o["host_memory"] = json!({"conservative_available_kib":192u64*1024*1024});
        o["vm_max_map_count"] = json!(4_194_304);
        let f = json!({"schema":SCHEMA,"first_epoch":101,"last_epoch":200,"observer_sha256":s.observer.sha256,
            "sampled_at_utc":o["recorded_at_utc"],"plan":s.fleet_plan.path,"plan_sha256":s.fleet_plan.sha256,
            "inventory":{"anomalies":0},"active":[]});
        let p = json!({"observer":private157::binding(&s.observer)});
        let time = utc_seconds("2026-10-21T23:58:00Z").unwrap();
        sample(&s, &o, &f, &p, time + 1800).unwrap();
        assert!(sample(&s, &o, &f, &p, time + 1801).is_err());
        assert!(sample(&s, &o, &f, &p, time - 1).is_err());
        let mut bad = o.clone();
        bad["filesystem"]["conservative_available_bytes"] = json!(PROTECTED + PEAK - 1);
        assert!(sample(&s, &bad, &f, &p, time).is_err());
        let mut bad = f.clone();
        bad["observer_sha256"] = json!("f".repeat(64));
        assert!(sample(&s, &o, &bad, &p, time).is_err());
        let mut bad = f.clone();
        bad["active"] = json!([{"epoch":144}]);
        assert!(sample(&s, &o, &bad, &p, time).is_err());
    }
}
