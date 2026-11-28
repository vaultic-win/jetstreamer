use anyhow::{Context, Result, ensure};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
#[allow(dead_code)]
#[path = "../../../horizon_retry6_170_guarded_launch_20261119_v1/src/audit_budget.rs"]
mod audit_budget;

const THREAD: &str = "01a1af2a-9ce8-76a2-8939-b2112bd38f53";
const PROPERTIES: &str = "Id,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,NRestarts,Job,Triggers,TriggeredBy,ExecStart,CPUQuotaPerSecUSec,MemoryMax";

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn read_bound(path: &Path, expected: &str) -> Result<Value> {
    let bytes = fs::read(path)?;
    ensure!(
        sha(&bytes) == expected,
        "binding mismatch: {}",
        path.display()
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn binding(path: &Path) -> Result<Value> {
    Ok(json!({"path":path,"sha256":sha(&fs::read(path)?)}))
}
fn bound(value: &Value) -> Result<Value> {
    let path = Path::new(value["path"].as_str().context("bound path")?);
    read_bound(path, value["sha256"].as_str().context("bound SHA")?)
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn utc_now() -> Result<String> {
    let seconds = libc::time_t::try_from(now()?)?;
    let mut tm = unsafe { std::mem::zeroed::<libc::tm>() };
    ensure!(
        !unsafe { libc::gmtime_r(&seconds, &mut tm) }.is_null(),
        "UTC conversion"
    );
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    ))
}
fn write(root: &Path, name: &str, value: &Value) -> Result<PathBuf> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let path = root.join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(&path)?;
    file.write_all(&bytes)?;
    if name.ends_with("PLAN.json") {
        file.set_permissions(fs::Permissions::from_mode(0o400))?;
    }
    file.sync_all()?;
    File::open(root)?.sync_all()?;
    Ok(path)
}
fn output(command: &mut Command) -> Result<String> {
    let result = command.output()?;
    ensure!(
        result.status.success(),
        "command failed: {:?}: {}",
        command,
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(String::from_utf8(result.stdout)?)
}
fn unit_names(previous: &Value, template: &Value) -> Result<BTreeSet<String>> {
    let list = output(Command::new("/usr/bin/systemctl").args([
        "list-units",
        "--all",
        "--type=service",
        "--type=timer",
        "--no-legend",
        "--plain",
        "--no-pager",
    ]))?;
    let mut names: BTreeSet<String> = list
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| name.ends_with(".service") || name.ends_with(".timer"))
        .map(str::to_owned)
        .collect();
    for key in previous["complete_metadata_unit_census"]
        .as_object()
        .context("old full census")?
        .keys()
    {
        names.insert(key.clone());
    }
    for value in template["closed_units"]
        .as_array()
        .context("closed units")?
    {
        names.insert(value.as_str().context("closed unit name")?.to_owned());
    }
    names.insert(
        template["producer_unit"]
            .as_str()
            .context("producer unit")?
            .to_owned(),
    );
    for suffix in ["service", "timer"] {
        names.insert(format!(
            "horizon-guard-replacement-166-local3retry6-20261110-v1.{suffix}"
        ));
    }
    for epoch in [166, 167, 169, 170] {
        names.insert(format!(
            "horizon-qualify-{epoch}-replacement-local3retry3-20261110-v1.service"
        ));
    }
    for epoch in [166, 167, 170] {
        names.insert(format!(
            "horizon-qualify-{epoch}-replacement-local3retry4-20261110-v1.service"
        ));
    }
    names.insert("horizon-qualify-166-replacement-local3retry5-20261110-v1.service".to_owned());
    Ok(names)
}
fn native(names: &BTreeSet<String>) -> Result<BTreeMap<String, Value>> {
    let names: Vec<_> = names.iter().collect();
    let mut rows = BTreeMap::new();
    for chunk in names.chunks(100) {
        let mut command = Command::new("/usr/bin/systemctl");
        command
            .arg("show")
            .arg(format!("-p{PROPERTIES}"))
            .arg("--")
            .args(chunk);
        let text = output(&mut command)?;
        for (id, row) in parse_blocks(&text)? {
            ensure!(
                rows.insert(id.clone(), row).is_none(),
                "duplicate native unit: {id}"
            );
        }
    }
    ensure!(
        names.iter().all(|name| rows.contains_key(name.as_str())),
        "incomplete native unit census"
    );
    Ok(rows)
}
fn parse_blocks(text: &str) -> Result<BTreeMap<String, Value>> {
    let mut rows = BTreeMap::new();
    for block in text.trim().split("\n\n") {
        let mut row = Map::new();
        for line in block.lines() {
            if let Some((key, value)) = line.split_once('=') {
                row.insert(key.to_owned(), Value::String(value.to_owned()));
            }
        }
        let Some(id) = row.get("Id").and_then(Value::as_str).map(str::to_owned) else {
            continue;
        };
        if id.ends_with(".timer") {
            let mut absent = Vec::new();
            for key in ["MainPID", "ControlPID"] {
                if !row.contains_key(key) {
                    row.insert(key.to_owned(), Value::String("0".to_owned()));
                    absent.push(key);
                }
            }
            row.insert(
                "native_timer_absent_PID_properties_interpreted_as_zero".to_owned(),
                json!(absent),
            );
        }
        ensure!(
            rows.insert(id.clone(), Value::Object(row)).is_none(),
            "duplicate native unit: {id}"
        );
    }
    Ok(rows)
}
fn closed(row: &Value) -> bool {
    matches!(row["ActiveState"].as_str(), Some("inactive" | "failed"))
        && row["Job"] == ""
        && row["MainPID"] == "0"
        && row["ControlPID"] == "0"
}
fn process_claims() -> Result<Vec<Value>> {
    let images = [
        "/usr/local/lib/jetstreamer/horizon-independent170-singleton-package-20261109-v1/jetstreamer-node",
        "/usr/local/lib/jetstreamer/horizon-independent170-singleton-package-20261109-v1/jetstreamer-historical-worker-v1-5-6",
    ];
    let mut claims = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let path = entry.path();
        let Ok(exe) = fs::read_link(path.join("exe")) else {
            continue;
        };
        let Ok(args) = fs::read(path.join("cmdline")) else {
            continue;
        };
        let exe = exe.to_string_lossy().to_string();
        let argv: Vec<String> = args
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).to_string())
            .collect();
        if images.contains(&exe.as_str()) || argv.iter().any(|arg| images.contains(&arg.as_str())) {
            claims.push(json!({"pid":pid,"executable":exe,"argv":argv}));
        }
    }
    Ok(claims)
}

const COMPLETE_DATA: u64 = 6_794_761_027_378;
const RAW_FLOOR: u64 = 6_829_053_656_882;
const CAP: u64 = 309_237_645_312;
const PREPARER: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-home-audit-v8-20261119-v1/prepare-v5/prepare";
const PREPARER_SHA: &str = env!("HORIZON_170_PREPARER_V5_SHA256");
const GUARD: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch170-retry6-live166retry7-data-guard-20261118-v1/guard";
const GUARD_SHA: &str = "2572c20c10b1473a9438e8d08d4aaf6ccb06fa9aa47e3508fe90e6bcaddddc6b";
const TEMPLATE: &str =
    "/var/lib/jetstreamer/epoch170-retry5-recovery-20261117-v1/measure0743-v3/PLAN-FINAL.json";
const TEMPLATE_SHA: &str = "e7133f6349619370806f475b1c1511cd505e456da330c3f9be38e6e12642de86";
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
const ROOT: &str = "/var/lib/jetstreamer/epoch170-retry8-peer-stage-20261119-v1";
const FRESH: &str = "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1/replacement-local3retry6-20261110-v1";
fn b(p: &str) -> Result<Value> {
    binding(Path::new(p))
}
fn read(p: &str) -> Result<Value> {
    bound(&b(p)?)
}
fn private_new(p: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(p)?;
    File::open(p.parent().context("parent")?)?.sync_all()?;
    Ok(())
}
fn peer(epoch: u64) -> (&'static str, &'static str, u64, u64, &'static str) {
    match epoch {
        166 => (
            "horizon-qualify-166-replacement-local3retry8-20261110-v1.service",
            "4f09db5f45074244a45b06aeef932d1d",
            1746683,
            339966412,
            "/var/lib/jetstreamer/retry8-single166-guarded-launch-20261119-v1/epoch166",
        ),
        167 => {
            let p = PEER167.get().expect("peer validated before staging");
            (
                "horizon-qualify-167-replacement-local3retry7-20261110-v1.service",
                p.0.as_str(),
                p.1,
                p.2,
                "/var/lib/jetstreamer/retry7-single167-guarded-launch-20261119-v1/epoch167",
            )
        }
        _ => unreachable!(),
    }
}
fn peer_shape(epoch: u64, v: &Value) -> Result<()> {
    let (unit, iid, pid, _, _) = peer(epoch);
    let pid_text = pid.to_string();
    ensure!(
        v["Id"] == unit
            && v["InvocationID"] == iid
            && v["MainPID"].as_str() == Some(pid_text.as_str())
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["NRestarts"] == "0"
            && v["ControlPID"] == "0"
            && v["Job"] == "",
        "peer {epoch} changed"
    );
    Ok(())
}
fn generation(v: &Value) -> Result<(PathBuf, String, String)> {
    let tag = v["generation"]
        .as_str()
        .context("explicit witness generation")?;
    ensure!(
        (1..=32).contains(&tag.len())
            && tag
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
        "unsafe witness generation"
    );
    let root = Path::new(ROOT).join(format!("guard-witness-{tag}"));
    let unit = format!("horizon-170-retry8-witness-{tag}-20261119.service");
    let dest = format!(
        "/var/lib/jetstreamer/horizon_runtime_data/epoch170-home-audit-v8-20261119-v1/data-contract-{tag}"
    );
    ensure!(
        v["output_root"] == root.to_str().unwrap()
            && v["unit"] == unit
            && v["contract_destination"] == dest,
        "generation output/unit/contract mismatch"
    );
    Ok((root, unit, dest))
}
fn selected_contract(fresh: bool) -> Result<Value> {
    let cfg = CONFIG.get().context("config")?;
    let value = &cfg[if fresh {
        "fresh_contract"
    } else {
        "measurement_contract"
    }];
    let c = bound(&value["contract"])?;
    let seal = bound(&value["deployment_seal"])?;
    let path = Path::new(
        value["contract"]["path"]
            .as_str()
            .context("contract path")?,
    );
    ensure!(
        path.file_name().is_some_and(|n| n == "contract.json")
            && seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == path.parent().unwrap().to_str().unwrap()
            && seal["sealer_sha256"] == SEALER_SHA
            && seal["remote_mutations"] == false
            && seal["replay_launch_authorized"] == false
            && value["deployment_seal"]["path"]
                == path
                    .parent()
                    .unwrap()
                    .join("deployment-seal-receipt.json")
                    .to_str()
                    .unwrap()
            && seal["members"].as_array().is_some_and(|m| m
                .iter()
                .any(|r| r["name"] == "contract.json"
                    && r["sha256"] == value["contract"]["sha256"]
                    && r["mode"] == "0444")),
        "contract hash/normal seal differs"
    );
    let w = bound(&c["qualified_native_witness"])?;
    ensure!(
        w["native_identity"]["executable"] == GUARD
            && w["native_identity"]["executable_sha256"] == GUARD_SHA,
        "own-image witness required"
    );
    if fresh {
        let (root, _, dest) = generation(&cfg["witness_generation"])?;
        ensure!(
            path == Path::new(&dest).join("contract.json")
                && c["qualified_native_witness"]["path"]
                    == root.join("NATIVE_WITNESS.json").to_str().unwrap(),
            "fresh generation mismatch"
        );
        let t = w["recorded_unix_seconds"]
            .as_u64()
            .context("witness time")?;
        let at = now()?;
        ensure!(t <= at && at - t <= 120, "fresh witness exceeds120seconds");
    }
    Ok(value.clone())
}
fn own_witness() -> Result<()> {
    let (root, unit, contract_destination) =
        generation(&CONFIG.get().context("config")?["witness_generation"])?;
    ensure!(
        !root.try_exists()? && !Path::new(&contract_destination).try_exists()?,
        "generation already consumed"
    );
    let load = output(Command::new("/usr/bin/systemctl").args([
        "show",
        &unit,
        "--property=LoadState",
        "--value",
    ]))?;
    ensure!(
        load.trim() == "not-found",
        "witness unit generation already consumed"
    );
    let parent = Path::new(&contract_destination)
        .parent()
        .context("contract parent")?;
    let meta = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent
            && meta.is_dir()
            && meta.uid() == 0
            && meta.mode() & 0o022 == 0
            && meta.dev() == fs::metadata("/home/sol")?.dev(),
        "fresh contract parent must be protected and HOME-backed"
    );
    private_new(&root)?;
    ensure!(
        sha(&fs::read(GUARD)?) == GUARD_SHA && sha(&fs::read(SEALER)?) == SEALER_SHA,
        "sealed image changed"
    );
    let witness = root.join("NATIVE_WITNESS.json");
    output(Command::new("/usr/bin/systemd-run").args(["--unit",&unit,
        "--property=Type=oneshot","--property=RemainAfterExit=yes","--property=CPUQuota=200%","--property=MemoryMax=2G","--property=MemorySwapMax=0","--property=TasksMax=128","--property=LimitNOFILE=1048576",
        GUARD,"--qualify-data-witness","/usr/local/lib/jetstreamer/horizon-original-slot-data-witness-set-20261118-v6/witness-set.json",
        "--seed-sha256","8eb041519cba5c3f6368cb1432be9e289489ce1acdc28aa8b49f3d6ec7f382ee","--seal",
        "/usr/local/lib/jetstreamer/horizon-original-slot-data-witness-set-20261118-v6/deployment-seal-receipt.json","--seal-sha256","611c29b18c52e02fce0be67314cdaae4ff780bea72b0e8e6c22a7dd248dfc24f",
        "--output",witness.to_str().unwrap(),"--self-sha256",GUARD_SHA]))?;
    let w = read(witness.to_str().unwrap())?;
    ensure!(
        w["native_identity"]["executable"] == GUARD
            && w["native_identity"]["executable_sha256"] == GUARD_SHA,
        "own-image witness required"
    );
    let mut contract =
        read("/var/lib/jetstreamer/epoch170-retry6-recovery-20261118-v1/contract-v1.json")?;
    contract["qualified_native_witness"] = binding(&witness)?;
    let c = write(&root, "contract.json", &contract)?;
    let plan = write(
        &root,
        "CONTRACT-SEAL-PLAN.json",
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":contract_destination,
        "members":[{"source":c,"name":"contract.json","sha256":sha(&fs::read(&c)?),"mode":292}]}),
    )?;
    output(Command::new(SEALER).arg(&plan).args([
        "--plan-sha256",
        &sha(&fs::read(&plan)?),
        "--self-sha256",
        SEALER_SHA,
    ]))?;
    println!("{}", b(&format!("{contract_destination}/contract.json"))?);
    Ok(())
}
fn measured(v: &Value, at: u64) -> Result<u64> {
    let t = v["recorded_unix_seconds"]
        .as_u64()
        .context("measurement time")?;
    let bytes = v["physical"]["physical_bytes"]
        .as_u64()
        .context("physical bytes")?;
    ensure!(
        v["schema"] == "horizon-standard-replacement-local-physical-ledger-v1"
            && v["owner"] == "/root"
            && v["epoch"] == 170
            && v["read_only"] == true
            && v["resource_credit_bytes"] == 0
            && v["replay_launch_authorized"] == false
            && v["lane_root"]
                == "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1"
            && t <= at
            && at - t <= 1800
            && bytes > 0
            && bytes < CAP,
        "fresh full170 ledger required"
    );
    Ok(bytes)
}
fn prepare_review(root: &Path, plan: &mut Value, census: &Path, measurement: &Path) -> Result<()> {
    let mb = binding(measurement)?;
    let m = bound(&mb)?;
    let retained = measured(&m, now()?)?;
    let mut review = bound(&plan["review"])?;
    let mut working = bound(&plan["retry3"]["concurrent_working_set"])?;
    let mut input = bound(&plan["input_proof"])?;
    ensure!(
        input["epoch"] == 170
            && input["local_inputs"] == plan["local_inputs"]
            && input["authentication_qualified"] == false
            && input["network_GCS_probe_performed"] == false,
        "local input template differs"
    );
    input["recorded_unix_seconds"] = json!(now()?);
    plan["input_proof"] = binding(&write(root, "LOCAL_INPUT_REQUEST.json", &input)?)?;
    working["schema"] = json!("horizon-epoch170-retry6-current-fleet-working-set-v1");
    working["recorded_unix_seconds"] = json!(now()?);
    working["fleet"] = plan["fleet"].clone();
    working["native_preparer_image"] = json!(PREPARER);
    working["native_preparer_qualification"] = b(&format!(
        "{}/artifact-proof.json",
        Path::new(PREPARER).parent().unwrap().display()
    ))?;
    working["immutable_raw_guard_floor_bytes"] = json!(RAW_FLOOR);
    working["complete_DATA_bytes"] = json!(COMPLETE_DATA);
    working["retained_epoch167_cap_booking"] =
        plan["retry170"]["retained_epoch167_booking"].clone();
    working["retained167_booking"] = plan["retry170"]["retained_epoch167_booking"].clone();
    working["candidate_root_cap_bytes"] = json!(CAP);
    working["protected167_root_cap_bytes"] = json!(512u64 << 30);
    working["retained_retry6_166_DATA_bytes"] = json!(CAP);
    let rows = working["lanes"].as_array_mut().context("lanes")?;
    ensure!(
        rows.len() == 4
            && rows
                .iter()
                .filter_map(|r| r["epoch"].as_u64())
                .collect::<BTreeSet<_>>()
                == BTreeSet::from([166, 167, 169, 170]),
        "complete working set required"
    );
    for row in rows {
        let epoch = row["epoch"].as_u64().context("epoch")?;
        if epoch == 166 || epoch == 167 {
            let (unit, iid, _, _, prefix) = peer(epoch);
            let a = read(&format!("{prefix}/ACTUAL_REPLACEMENT_ADMISSION.json"))?;
            let prep = bound(&a["fresh_native_Rust_preparation"])?;
            let baseline = prep["actual_full_lane_ledger"]["physical_bytes"]
                .as_u64()
                .context("peer ledger")?;
            ensure!(baseline > 0 && baseline < CAP, "peer historical ledger");
            let cap = if epoch == 167 { 512u64 << 30 } else { CAP };
            *row = json!({"epoch":epoch,"state":"active","producer_unit":unit,"invocation_id":iid,"retained_lane_physical_bytes":baseline,"remaining_growth_bytes":cap-baseline});
        } else if epoch == 170 {
            *row = json!({"epoch":170,"state":"candidate","producer_unit":plan["producer_unit"],"retained_lane_physical_bytes":retained,"remaining_growth_bytes":CAP-retained});
        }
    }
    plan["retry3"]["concurrent_working_set"] =
        binding(&write(root, "WORKING_SET.json", &working)?)?;
    let slot = json!({"schema":"horizon-standard-replacement-exclusive-slot-mapping-v1","owner":"/root","epoch":170,
        "recorded_unix_seconds":now()?,"physical_ledger":mb,"retained_lane_physical_bytes":retained,"combined_original_lane_cap_bytes":CAP,
        "old_remaining_future_promise_bytes":CAP-retained,"proposed_fresh_working_maximum_bytes":CAP-retained,"additional_DATA_bytes":0,
        "all_original_promises_retained":true,"guard_root_remains_whole_original_lane":true,"original_stop":m["original_stop"],"replay_launch_authorized":false});
    review["exact_slot_mapping_and_physical_ledger"] =
        binding(&write(root, "EXCLUSIVE_SLOT_MAPPING.json", &slot)?)?;
    review["attempt"] = plan["attempt"].clone();
    review["recorded_unix_seconds"] = json!(now()?);
    for (r, p) in [
        ("source_fleet", "fleet"),
        ("source_inventory", "inventory"),
        ("input_proof", "input_proof"),
        ("cleanup_completion", "cleanup_completion"),
        ("data_fulfillment", "data_fulfillment"),
    ] {
        review[r] = plan[p].clone();
    }
    review["full_current_proc_and_unit_census"] = binding(census)?;
    review["minimum_initial_available_data_bytes"] = json!(RAW_FLOOR + (64u64 << 20));
    review["retained_lane_physical_bytes"] = json!(retained);
    for key in [
        "existing_original_slot_future_growth_bytes",
        "proposed_fresh_working_maximum_bytes",
        "candidate_remaining_growth_bytes",
    ] {
        review[key] = json!(CAP - retained);
    }
    review["additional_growth_not_covered_by_existing_promise_bytes"] = json!(0);
    plan["review"] = binding(&write(root, "PRELAUNCH_REVIEW.json", &review)?)?;
    Ok(())
}
fn stage(tag: &str, measurement: Option<&Path>) -> Result<()> {
    ensure!(
        tag.len() == 4 && tag.bytes().all(|b| b.is_ascii_digit()),
        "four-digit attempt tag"
    );
    let root = Path::new(ROOT).join(tag);
    private_new(&root)?;
    let observer = read(cfg_path("observer")?)?;
    let status = read(cfg_path("status")?)?;
    let mut fleet = read(cfg_path("fleet")?)?;
    let current = utc_now()?;
    ensure!(
        observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && observer["recorded_at_utc"].as_str().context("sample")? <= current.as_str()
            && current.as_str()
                < observer["cadence"]["next_routine_observation_not_before_utc"]
                    .as_str()
                    .context("next")?
            && status["observer"] == b(cfg_path("observer")?)?
            && status["authenticated_readback"] == true
            && status["authenticated_status_count"] == 19
            && fleet["complete_DATA_bytes"] == COMPLETE_DATA
            && fleet["complete_projected_memory_bytes"] == 761_131_708_416u64,
        "fresh two-peer cycle required"
    );
    let mut plan = read_bound(Path::new(TEMPLATE), TEMPLATE_SHA)?;
    ensure!(
        plan["epoch"] == 170 && plan["attempt"] == "local3retry5",
        "exact prior170 template"
    );
    plan["attempt"] = json!("local3retry6");
    plan["producer_unit"] =
        json!("horizon-qualify-170-replacement-local3retry6-20261110-v1.service");
    plan["guard_base"] = json!("horizon-guard-replacement-170-local3retry6-20261110-v1");
    plan["fresh_subtree"] = json!(FRESH);
    plan["current_allocation"]["schema"] = json!("horizon-epoch170-retry6-native-allocation-v1");
    for unit in [
        "horizon-qualify-170-replacement-local3retry6-20261110-v1.service",
        "horizon-guard-replacement-170-local3retry6-20261110-v1.service",
        "horizon-guard-replacement-170-local3retry6-20261110-v1.timer",
    ] {
        let units = plan["closed_units"]
            .as_array_mut()
            .context("closed units")?;
        ensure!(!units.contains(&json!(unit)), "duplicate new unit");
        units.push(json!(unit));
    }
    let previous = bound(&fleet["full_current_proc_and_unit_census"])?;
    let mut names = unit_names(&previous, &plan)?;
    for e in [166, 167] {
        names.insert(peer(e).0.into());
    }
    let before = native(&names)?;
    for e in [166, 167] {
        peer_shape(e, &before[peer(e).0])?;
    }
    for unit in plan["closed_units"].as_array().unwrap() {
        let u = unit.as_str().context("unit")?;
        ensure!(closed(&before[u]), "target/old owner not closed: {u}");
    }
    ensure!(process_claims()?.is_empty(), "170 process still exists");
    let mut owners = Vec::new();
    let mut executing = Vec::new();
    let mut bootstrap = Vec::new();
    for e in [166, 167] {
        let (unit, iid, pid, ticks, prefix) = peer(e);
        let ab = b(&format!("{prefix}/ACTUAL_REPLACEMENT_ADMISSION.json"))?;
        let pb = b(&format!("{prefix}/ACTUAL_GUARD_PROTECTION.json"))?;
        let a = bound(&ab)?;
        let p = bound(&pb)?;
        ensure!(
            a["fresh_admission_passed"] == true
                && a["producer_invocation_id"] == iid
                && a["producer_pid"] == pid
                && p["admission"] == ab,
            "genuine peer required"
        );
        owners.push(json!({"epoch":e,"unit":unit,"invocation_id":iid,"main_pid":pid,"main_start_ticks":ticks,"admission":ab,"guard_protection":pb}));
        let range = e.to_string();
        let obs = observer["replays"]
            .as_array()
            .context("observer rows")?
            .iter()
            .find(|r| r["range"].as_str() == Some(range.as_str()))
            .context("peer sample")?;
        ensure!(
            obs["invocation_binding_stable"] == true
                && obs["producer_after"]["invocation_id"] == iid
                && obs["producer_after"]["active_state"] == "active"
                && obs["producer_after"]["restarts"] == 0,
            "peer sample differs"
        );
        let replay = obs["useful_work"]["sufficient_for_rates"] == true
            && obs["useful_work"]["transaction_delta"]
                .as_u64()
                .is_some_and(|n| n > 0);
        let row = json!({"epoch":e,"unit":before[unit],"admission":ab,"guard_protection":pb,"observer":b(cfg_path("observer")?)?,"in_current_observer":true,"scratch_path":obs["scratch_path"],"progress":obs["useful_work"],"phase":if replay{"replay"}else{"bootstrap"}});
        if replay {
            executing.push(row);
        } else {
            bootstrap.push(row);
        }
    }
    plan["resident_memory"]["owners"] = json!(owners);
    plan["resident_memory"]["observer"] = b(cfg_path("observer")?)?;
    plan["resident_memory"]["terminal166"] = Value::Null;
    plan["resident_memory"]["terminal167"] = Value::Null;
    plan["retry170"]["stopped_retry5_170"] = b(
        "/var/lib/jetstreamer/retry3-preparation-20261113-v1/epoch170/local3retry5/guard-state/receipts/stop-completion.json",
    )?;
    plan["retry170"]["protected167_admission"] = owners[1]["admission"].clone();
    plan["retry170"]["protected167_guard"] = owners[1]["guard_protection"].clone();
    let a167 = bound(&owners[1]["admission"])?;
    let prep167 = bound(&a167["fresh_native_Rust_preparation"])?;
    let p167 = bound(&prep167["plan"])?;
    plan["retry170"]["retained_epoch167_booking"] =
        p167["retry167"]["additive_data_booking"].clone();
    let guard_parent = Path::new(GUARD).parent().unwrap().display();
    plan["data_fulfillment"] = json!({"runtime":b(GUARD)?,"runtime_seal":b(&format!("{guard_parent}/deployment-seal-receipt.json"))?,
        "qualification":b(&format!("{guard_parent}/artifact-proof.json"))?,
        "contract":selected_contract(measurement.is_some())?});
    let after = native(&names)?;
    for e in [166, 167] {
        ensure!(
            before[peer(e).0] == after[peer(e).0],
            "peer changed across census"
        );
    }
    for u in plan["closed_units"].as_array().unwrap() {
        let u = u.as_str().unwrap();
        ensure!(
            before[u] == after[u] && closed(&after[u]),
            "closed owner changed"
        );
    }
    ensure!(process_claims()?.is_empty(), "170 process appeared");
    let raw = write(&root, "CURRENT_NATIVE_RAW.json", &json!(before))?;
    let census = write(
        &root,
        "CURRENT_CENSUS.json",
        &json!({"schema":"horizon-standard-replacement-Root-current-unit-and-proc-census-v1","owner":"/root","sole_primary_thread":THREAD,
        "recorded_unix_seconds":now()?,"complete_metadata_unit_census":before,"full_raw_native_metadata_census":binding(&raw)?,"exact_selected_node_and_worker_process_claims":[],
        "no_new_target_owner_or_queued_launch":true}),
    )?;
    fleet["previous_Root_operational_review"] = b(cfg_path("fleet")?)?;
    fleet["full_current_proc_and_unit_census"] = binding(&census)?;
    fleet["metadata_unit_census"] = json!(before);
    fleet["recorded_unix_seconds"] = json!(now()?);
    fleet["actual_executing_replays"] = json!(executing);
    fleet["actual_active_bootstraps"] = json!(bootstrap);
    fleet["active_producer_count"] = json!(2);
    fleet["live_replay_count"] = json!(executing.len());
    fleet["useful_replay_count"] = json!(executing.len());
    fleet["observer"] = b(cfg_path("observer")?)?;
    fleet["authenticated_status_audit"] = b(cfg_path("status")?)?;
    fleet["sole_next_observer"] = b(cfg_path("next_observer")?)?;
    let fp = write(&root, "ROOT_COMPLETE_OPERATIONAL_FLEET.json", &fleet)?;
    plan["fleet"] = binding(&fp)?;
    plan["inventory"] = b(cfg_path("inventory")?)?;
    if let Some(measurement) = measurement {
        prepare_review(&root, &mut plan, &census, measurement)?;
    }
    let path = write(
        &root,
        if measurement.is_some() {
            "PREPARE_PLAN.json"
        } else {
            "MEASURE_PLAN.json"
        },
        &plan,
    )?;
    ensure!(
        sha(&fs::read(PREPARER)?) == PREPARER_SHA,
        "preparer changed"
    );
    println!(
        "{}",
        json!({"plan":binding(&path)?,"fleet":binding(&fp)?,"resource_promise_ending_bytes":0,"replay_launch_authorized":false})
    );
    let op = if measurement.is_some() {
        "prepare"
    } else {
        "measure"
    };
    println!(
        "{}",
        json!({"operation":op,"native_preparer_argv":[PREPARER,path.to_str().unwrap(),"--plan-sha256",sha(&fs::read(&path)?),"--self-sha256",PREPARER_SHA,if measurement.is_some(){"--prepare"}else{"--measure-only"}],"replay_launch_authorized":false})
    );
    Ok(())
}
static CONFIG: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
static PEER167: std::sync::OnceLock<(String, u64, u64)> = std::sync::OnceLock::new();
fn root_entries_for_operation(operation: &str, names: &BTreeSet<String>) -> Result<()> {
    match operation {
        "witness" | "measure" | "prepare" => ensure!(names.is_empty(), "fresh root occupied"),
        "launch-plan" => ensure!(
            names == &BTreeSet::from(["output".to_owned()]),
            "prepared root must contain only its staged output"
        ),
        _ => anyhow::bail!("unknown staging operation"),
    }
    Ok(())
}
fn cfg_path(k: &str) -> Result<&'static str> {
    CONFIG.get().context("config")?[k]["path"]
        .as_str()
        .context("config path")
}
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    ensure!(
        unsafe { libc::geteuid() } == 0
            && (a.len() == 7 || a.len() == 8)
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256",
        "CONFIG --plan-sha256 SHA --self-sha256 SHA (witness|launch-plan|measure TAG|prepare TAG MEASUREMENT)"
    );
    ensure!(
        sha(&fs::read("/proc/self/exe")?) == a[5],
        "wrapper self hash"
    );
    launch_plan::published_sources()?;
    let cfg = read_bound(Path::new(&a[1]), &a[3])?;
    for k in [
        "fleet",
        "observer",
        "status",
        "inventory",
        "next_observer",
        "peer167_admission",
        "peer167_protection",
    ] {
        bound(&cfg[k])?;
    }
    ensure!(
        cfg["owner"] == "/root" && cfg["primary_thread"] == THREAD,
        "config owner"
    );
    let fleet = bound(&cfg["fleet"])?;
    ensure!(
        fleet["observer"] == cfg["observer"]
            && fleet["authenticated_status_audit"] == cfg["status"]
            && fleet["authenticated_inventory"] == cfg["inventory"]
            && fleet["sole_next_observer"] == cfg["next_observer"],
        "mixed cycle evidence"
    );
    audit_budget::validate_fleet_obligation(&fleet["continuing_audit_obligation"])?;
    audit_budget::observe()?;
    let admission = bound(&cfg["peer167_admission"])?;
    let protection = bound(&cfg["peer167_protection"])?;
    let prefix = "/var/lib/jetstreamer/retry7-single167-guarded-launch-20261119-v1/epoch167";
    ensure!(
        cfg["peer167_admission"]["path"] == format!("{prefix}/ACTUAL_REPLACEMENT_ADMISSION.json")
            && cfg["peer167_protection"]["path"]
                == format!("{prefix}/ACTUAL_GUARD_PROTECTION.json")
            && admission["producer_unit"]
                == "horizon-qualify-167-replacement-local3retry7-20261110-v1.service"
            && admission["fresh_admission_passed"] == true
            && admission["all_prior_promises_retained"] == true
            && admission["guard_minimum_free_bytes"] == RAW_FLOOR
            && protection["admission"] == cfg["peer167_admission"],
        "genuine167retry7 required"
    );
    let iid = admission["producer_invocation_id"]
        .as_str()
        .context("167 IID")?
        .to_owned();
    let pid = admission["producer_pid"].as_u64().context("167 PID")?;
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let ticks = stat
        .rsplit_once(')')
        .context("proc stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("start ticks")?
        .parse::<u64>()?;
    ensure!(
        iid.len() == 32 && iid.bytes().all(|b| b.is_ascii_hexdigit()) && pid > 1 && ticks > 0,
        "167 native identity"
    );
    PEER167
        .set((iid, pid, ticks))
        .map_err(|_| anyhow::anyhow!("peer initialized"))?;
    CONFIG
        .set(cfg)
        .map_err(|_| anyhow::anyhow!("config initialized"))?;
    let repo = "/home/sol/workspace/jetstreamer";
    let own = "scripts/horizon_retry6_167_live166_stage_20261118_v1/src/bin/stage170retry8.rs";
    let commit = output(Command::new("git").args([
        "-c",
        &format!("safe.directory={repo}"),
        "-C",
        repo,
        "rev-parse",
        "HEAD",
    ]))?;
    output(Command::new("git").args([
        "-c",
        &format!("safe.directory={repo}"),
        "-C",
        repo,
        "merge-base",
        "--is-ancestor",
        commit.trim(),
        "origin/account-updates",
    ]))?;
    ensure!(
        output(Command::new("git").args([
            "-c",
            &format!("safe.directory={repo}"),
            "-C",
            repo,
            "show",
            &format!("HEAD:{own}")
        ]))?
        .as_bytes()
            == fs::read(format!("{repo}/{own}"))?,
        "unpublished wrapper bytes"
    );
    ensure!(
        sha(&fs::read(PREPARER)?) == PREPARER_SHA
            && sha(&fs::read(format!(
                "{}/artifact-proof.json",
                Path::new(PREPARER).parent().unwrap().display()
            ))?) == env!("HORIZON_170_PREPARER_V5_PROOF_SHA256"),
        "qualified preparer/proof changed"
    );
    let m = fs::symlink_metadata(FRESH)?;
    ensure!(
        m.is_dir()
            && m.uid() == 1001
            && m.mode() & 0o7777 == 0o700
            && m.dev() == 64512
            && m.ino() == 107746436
            && Path::new(FRESH).canonicalize()? == Path::new(FRESH),
        "precreated170 root changed"
    );
    let entries = fs::read_dir(FRESH)?
        .map(|entry| {
            entry?
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("non-UTF8 entry in fresh root"))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    root_entries_for_operation(&a[6], &entries)?;
    let rm = fs::symlink_metadata(ROOT)?;
    ensure!(
        rm.is_dir() && rm.uid() == 0 && rm.mode() & 0o7777 == 0o700,
        "parent must precreate private metadata root"
    );
    match a[6].as_str() {
        "witness" if a.len() == 7 => own_witness(),
        "launch-plan" if a.len() == 7 => launch_plan::run(),
        "measure" if a.len() == 8 => stage(&a[7], None),
        "prepare" if a.len() == 8 => {
            bound(&CONFIG.get().unwrap()["measurement"])?;
            stage(&a[7], Some(Path::new(cfg_path("measurement")?)))
        }
        _ => anyhow::bail!("use witness or measure; prepare uses measurement from config"),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preparation_and_launch_require_distinct_root_states() {
        let empty = BTreeSet::new();
        let staged = BTreeSet::from(["output".to_owned()]);
        for operation in ["witness", "measure", "prepare"] {
            root_entries_for_operation(operation, &empty).unwrap();
            assert!(root_entries_for_operation(operation, &staged).is_err());
        }
        root_entries_for_operation("launch-plan", &staged).unwrap();
        assert!(root_entries_for_operation("launch-plan", &empty).is_err());
        assert!(
            root_entries_for_operation(
                "launch-plan",
                &BTreeSet::from(["output".to_owned(), "scratch".to_owned()])
            )
            .is_err()
        );
        assert!(root_entries_for_operation("unknown", &empty).is_err());
    }
    #[test]
    fn generation_requires_disjoint_exact_names() {
        let good = json!({"generation":"v2","output_root":format!("{ROOT}/guard-witness-v2"),"unit":"horizon-170-retry8-witness-v2-20261119.service","contract_destination":"/var/lib/jetstreamer/horizon_runtime_data/epoch170-home-audit-v8-20261119-v1/data-contract-v2"});
        generation(&good).unwrap();
        let mut root_backed = good.clone();
        root_backed["contract_destination"] = json!(
            "/usr/local/lib/jetstreamer/horizon-epoch170-retry6-live166retry8-data-contract-v2"
        );
        assert!(generation(&root_backed).is_err());
        for k in ["generation", "output_root", "unit", "contract_destination"] {
            let mut bad = good.clone();
            bad[k] = json!("../v1");
            assert!(generation(&bad).is_err());
        }
    }
    #[test]
    fn measurement_rejects_wrong_epoch_expiry_and_nonphysical_credit() {
        let mut v = json!({"schema":"horizon-standard-replacement-local-physical-ledger-v1","owner":"/root","epoch":170,"read_only":true,
            "resource_credit_bytes":0,"replay_launch_authorized":false,"lane_root":"/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1",
            "recorded_unix_seconds":100,"physical":{"physical_bytes":1}});
        assert_eq!(measured(&v, 1900).unwrap(), 1);
        assert!(measured(&v, 1901).is_err());
        assert!(measured(&v, 99).is_err());
        v["epoch"] = json!(167);
        assert!(measured(&v, 100).is_err());
        v["epoch"] = json!(170);
        v["resource_credit_bytes"] = json!(1);
        assert!(measured(&v, 100).is_err());
    }
    #[test]
    fn live_peer_rejects_foreign_identity_and_restart() {
        {
            let e = 166;
            let (u, i, p, _, _) = peer(e);
            let v = json!({"Id":u,"InvocationID":i,"MainPID":p.to_string(),"ActiveState":"active","SubState":"running","NRestarts":"0","ControlPID":"0","Job":""});
            peer_shape(e, &v).unwrap();
            let mut bad = v.clone();
            bad["NRestarts"] = json!("1");
            assert!(peer_shape(e, &bad).is_err());
            let mut bad = v;
            bad["Id"] = json!("foreign.service");
            assert!(peer_shape(e, &bad).is_err());
        }
    }
}

mod launch_plan {
    //! Bind the completed epoch170 preparation for the separately sealed launcher.
    //! This metadata command neither admits nor starts a producer.
    use anyhow::{Context, Result, ensure};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        path::Path,
        process::Command,
    };

    const REPO: &str = "/home/sol/workspace/jetstreamer";
    const PREPARED: &str = "/var/lib/jetstreamer/retry6-170-preparation-20261118-v1/epoch170/local3retry6/prepared.json";
    const ROOT: &str = "/var/lib/jetstreamer/retry6-single170-guarded-launch-20261119-v1";
    const THREAD: &str = "01a1af2a-9ce8-76a2-8939-b2112bd38f53";

    fn sha(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }
    fn identity(m: &fs::Metadata) -> Value {
        json!([
            m.dev(),
            m.ino(),
            m.uid(),
            m.gid(),
            m.mode(),
            m.nlink(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec()
        ])
    }
    fn validate_staged_genesis(prepared: &Value) -> Result<()> {
        staged_genesis_at(Path::new(super::FRESH), prepared)
    }
    fn staged_genesis_at(root: &Path, prepared: &Value) -> Result<()> {
        let root_meta = fs::symlink_metadata(root)?;
        let recorded = &prepared["fresh_subtree"];
        ensure!(
            recorded["path"] == root.to_str().context("root UTF8")?
                && recorded["identity"][0] == root_meta.dev()
                && recorded["identity"][1] == root_meta.ino(),
            "preparation root identity differs"
        );
        let output = root.join("output");
        let output_meta = fs::symlink_metadata(&output)?;
        ensure!(
            output_meta.is_dir()
                && output_meta.uid() == 1001
                && output_meta.mode() & 0o7777 == 0o700
                && output.canonicalize()? == output,
            "unsafe prepared output"
        );
        let names = fs::read_dir(&output)?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<std::io::Result<Vec<_>>>()?;
        ensure!(
            names == ["genesis.tar.bz2"],
            "unexpected prepared output content"
        );
        let path = output.join("genesis.tar.bz2");
        let stage = &prepared["genesis_stage"];
        ensure!(
            stage["path"] == path.to_str().context("genesis UTF8")?
                && stage["source"] == prepared["local_inputs"]["genesis"]
                && stage["no_clobber"] == true,
            "unbound staged genesis"
        );
        let m = fs::symlink_metadata(&path)?;
        ensure!(
            m.is_file()
                && m.uid() == 1001
                && m.nlink() == 1
                && m.mode() & 0o7777 == 0o600
                && m.len() <= 1 << 20
                && identity(&m) == stage["identity"],
            "staged genesis identity differs"
        );
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take((1 << 20) + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            !bytes.is_empty()
                && bytes.len() as u64 == m.len()
                && stage["bytes"] == m.len()
                && stage["sha256"] == sha(&bytes)
                && stage["source"]["sha256"] == sha(&bytes)
                && identity(&file.metadata()?) == stage["identity"]
                && identity(&fs::symlink_metadata(&path)?) == stage["identity"],
            "staged genesis changed"
        );
        Ok(())
    }
    fn git(args: &[&str]) -> Result<String> {
        let result = Command::new("git")
            .args(["-c", &format!("safe.directory={REPO}")])
            .arg("-C")
            .arg(REPO)
            .args(args)
            .output()?;
        ensure!(
            result.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        Ok(String::from_utf8(result.stdout)?)
    }
    pub(super) fn published_sources() -> Result<String> {
        let commit = git(&["rev-parse", "HEAD"])?;
        git(&[
            "merge-base",
            "--is-ancestor",
            commit.trim(),
            "origin/account-updates",
        ])?;
        for (path, compiled_sha) in [
            (
                "scripts/horizon_retry6_167_live166_stage_20261118_v1/src/bin/stage170retry8.rs",
                sha(include_bytes!("stage170retry8.rs")),
            ),
            (
                "scripts/horizon_retry6_167_live166_stage_20261118_v1/Cargo.toml",
                sha(include_bytes!("../../Cargo.toml")),
            ),
            (
                "scripts/horizon_retry6_167_live166_stage_20261118_v1/Cargo.lock",
                sha(include_bytes!("../../Cargo.lock")),
            ),
            (
                "scripts/horizon_retry6_170_guarded_launch_20261119_v1/src/audit_budget.rs",
                crate::audit_budget::compiled_source_sha256(),
            ),
        ] {
            ensure!(
                git(&["status", "--porcelain", "--untracked-files=all", "--", path])?.is_empty()
                    && sha(git(&["show", &format!("HEAD:{path}")])?.as_bytes()) == compiled_sha,
                "staging compiled source is not the published source: {path}"
            );
        }
        Ok(commit.trim().to_owned())
    }
    fn private(path: &Path) -> Result<()> {
        match fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => File::open(path.parent().context("directory parent")?)?.sync_all()?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        let m = fs::symlink_metadata(path)?;
        ensure!(
            m.is_dir()
                && m.uid() == 0
                && m.mode() & 0o7777 == 0o700
                && path.canonicalize()? == path,
            "unsafe metadata directory"
        );
        Ok(())
    }
    pub(super) fn run() -> Result<()> {
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "Root required; plan_launch170 takes no arguments"
        );
        let launcher = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-home-audit-v8-20261119-v1/launch-v8/launch";
        ensure!(
            sha(&fs::read(launcher)?) == env!("HORIZON_170_RETRY8_LAUNCH_V8_SHA256"),
            "sealed launcher differs"
        );
        let commit = published_sources()?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(PREPARED)?;
        let before = file.metadata()?;
        ensure!(
            before.is_file()
                && before.uid() == 0
                && before.nlink() == 1
                && before.mode() & 0o022 == 0
                && before.len() <= 32 << 20,
            "unsafe preparation"
        );
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take((32 << 20) + 1)
            .read_to_end(&mut bytes)?;
        let after = file.metadata()?;
        let current = fs::symlink_metadata(PREPARED)?;
        ensure!(
            bytes.len() as u64 == before.len()
                && before.dev() == after.dev()
                && before.ino() == after.ino()
                && before.len() == after.len()
                && before.mtime() == after.mtime()
                && before.mtime_nsec() == after.mtime_nsec()
                && before.ctime() == after.ctime()
                && before.ctime_nsec() == after.ctime_nsec()
                && after.dev() == current.dev()
                && after.ino() == current.ino(),
            "preparation changed"
        );
        let prepared: Value = serde_json::from_slice(&bytes)?;
        ensure!(
            prepared["schema"] == "horizon-standard-replacement-recipe-preparation-v1"
                && prepared["epoch"] == 170
                && prepared["attempt"] == "local3retry6"
                && prepared["owner"] == "/root"
                && prepared["primary_thread"] == THREAD
                && prepared["replay_launched"] == false
                && prepared["remote_mutations"] == false,
            "foreign or already consumed preparation"
        );
        validate_staged_genesis(&prepared)?;
        let contract = &prepared["data_fulfillment"]["contract"];
        ensure!(
            contract["contract"]["path"].is_string()
                && contract["contract"]["sha256"].is_string()
                && contract["deployment_seal"]["path"].is_string()
                && contract["deployment_seal"]["sha256"].is_string(),
            "missing bound DATA contract"
        );
        let output_root = format!("{ROOT}/epoch170");
        private(Path::new(ROOT))?;
        private(Path::new(&output_root))?;
        ensure!(
            fs::read_dir(&output_root)?.next().is_none(),
            "launch state already used"
        );
        let plan = json!({"schema":"horizon-retry6-single170-launch-plan-v1",
        "owner":"/root","primary_thread":THREAD,"launch_authorized":true,
        "output_root":output_root,"prepared":{"path":PREPARED,"sha256":sha(&bytes)},
        "data_fulfillment":contract,"source_commit":commit.trim()});
        let path = format!("{ROOT}/launch-plan.json");
        let encoded = serde_json::to_vec_pretty(&plan)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        output.write_all(&encoded)?;
        output.sync_all()?;
        File::open(ROOT)?.sync_all()?;
        println!(
            "{}",
            json!({"path":path,"sha256":sha(&encoded),"replay_launched":false})
        );
        Ok(())
    }
    #[cfg(test)]
    mod staged_tests {
        use super::*;
        use std::os::unix::fs::PermissionsExt;
        #[test]
        fn genuine_staging_accepts_only_unchanged_bound_genesis() {
            let root = std::env::temp_dir()
                .join(format!("horizon170-staged-genesis-{}", std::process::id()));
            fs::create_dir(&root).unwrap();
            let output = root.join("output");
            fs::create_dir(&output).unwrap();
            fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).unwrap();
            let path = output.join("genesis.tar.bz2");
            fs::write(&path, b"genesis fixture").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let source =
                json!({"path":"/immutable/genesis.tar.bz2","sha256":sha(b"genesis fixture")});
            let prepared = json!({"fresh_subtree":{"path":root,"identity":identity(&fs::metadata(&root).unwrap())},
                "local_inputs":{"genesis":source},"genesis_stage":{"path":path,"source":source,
                "no_clobber":true,"identity":identity(&fs::metadata(&path).unwrap()),
                "bytes":15,"sha256":sha(b"genesis fixture")}});
            // Fixture length is taken from the file, independently of the recorded digest.
            let mut prepared = prepared;
            prepared["genesis_stage"]["bytes"] = json!(fs::metadata(&path).unwrap().len());
            staged_genesis_at(&root, &prepared).unwrap();
            let mut bad = prepared.clone();
            bad["fresh_subtree"]["identity"][1] = json!(0);
            assert!(staged_genesis_at(&root, &bad).is_err());
            bad = prepared.clone();
            bad["local_inputs"]["genesis"]["sha256"] = json!("0".repeat(64));
            assert!(staged_genesis_at(&root, &bad).is_err());
            fs::write(output.join("unexpected"), b"x").unwrap();
            assert!(staged_genesis_at(&root, &prepared).is_err());
            fs::remove_file(output.join("unexpected")).unwrap();
            fs::write(&path, b"changed fixture").unwrap();
            assert!(staged_genesis_at(&root, &prepared).is_err());
            fs::remove_dir_all(root).unwrap();
        }
    }
}
