use anyhow::{ensure, Context, Result};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

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
        "/usr/local/lib/jetstreamer/horizon-independent167-singleton-package-20261109-v1/jetstreamer-node",
        "/usr/local/lib/jetstreamer/horizon-independent167-singleton-package-20261109-v1/jetstreamer-historical-worker-v1-5-6",
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

const PEER: &str = "horizon-qualify-166-replacement-local3retry7-20261110-v1.service";
const IID: &str = "03fa3ce80d8c4769a1e9dec548cdbeca";
const COMPLETE_DATA: u64 = 6_794_761_027_378;
const RAW_FLOOR: u64 = 6_829_053_656_882;
const CAP: u64 = 309_237_645_312;

fn live_peer(v: &Value) -> Result<()> {
    ensure!(v["Id"] == PEER && v["InvocationID"] == IID
        && v["MainPID"] == "1450368" && v["ControlPID"] == "0"
        && v["ActiveState"] == "active" && v["SubState"] == "running"
        && v["NRestarts"] == "0" && v["Job"] == "", "live166 changed");
    Ok(())
}
fn observe(v: &Value) -> Result<()> {
    let rows = v["replays"].as_array().context("observer replays")?;
    ensure!(rows.len() == 1 && rows[0]["range"] == "166"
        && rows[0]["invocation_binding_stable"] == true
        && rows[0]["producer_after"]["invocation_id"] == IID
        && rows[0]["producer_after"]["main_pid"] == 1450368
        && rows[0]["producer_after"]["restarts"] == 0
        && rows[0]["producer_after"]["active_state"] == "active"
        && rows[0]["useful_work"]["sufficient_for_rates"] == true,
        "exact useful live166 observation required");
    let current = utc_now()?;
    ensure!(v["recorded_at_utc"].as_str().context("sample clock")? <= current.as_str()
        && current.as_str() < v["cadence"]["next_routine_observation_not_before_utc"].as_str().context("cadence")?,
        "stale observation");
    Ok(())
}

fn retained_measurement(v: &Value, at: u64) -> Result<u64> {
    let measured_at = v["recorded_unix_seconds"].as_u64().context("measurement clock")?;
    let retained = v["physical"]["physical_bytes"].as_u64().context("physical bytes")?;
    ensure!(v["schema"] == "horizon-standard-replacement-local-physical-ledger-v1"
        && v["owner"] == "/root" && v["epoch"] == 167 && v["read_only"] == true
        && v["resource_credit_bytes"] == 0 && v["replay_launch_authorized"] == false
        && v["lane_root"] == "/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1"
        && measured_at <= at && at - measured_at <= 1800 && retained > 0 && retained < CAP,
        "fresh complete candidate167 physical measurement required");
    Ok(retained)
}

fn prepare_review(cfg: &Value, root: &Path, plan: &mut Value, census: &Path) -> Result<PathBuf> {
    let measurement = bound(&cfg["measurement"])?;
    let retained = retained_measurement(&measurement, now()?)?;
    let candidate_cap = 512u64 << 30;
    let qualification = bound(&cfg["preparer_qualification"])?;
    let image = cfg["preparer_image"].as_str().context("preparer image")?;
    ensure!(image == "/usr/local/lib/jetstreamer/horizon-epoch167-retry6-live166retry7-prepare-20261118-v3/prepare"
        && qualification["epoch"] == 167 && qualification["attempt"] == "local3retry6"
        && qualification["source_commit_verified_on_origin_account_updates"] == true
        && qualification["tests_failed"] == 0
        && qualification["production"]["sha256"] == sha(&fs::read(image)?),
        "current published qualified preparer required");
    let mut review = bound(&plan["review"])?;
    let mut working = bound(&plan["retry3"]["concurrent_working_set"])?;
    let mut input = bound(&plan["input_proof"])?;
    ensure!(input["epoch"] == 167 && input["local_inputs"] == plan["local_inputs"]
        && input["authentication_qualified"] == false && input["network_GCS_probe_performed"] == false,
        "exact local input route template");
    input["recorded_unix_seconds"] = json!(now()?);
    plan["input_proof"] = binding(&write(root, "LOCAL_INPUT_REQUEST.json", &input)?)?;
    working["schema"] = json!("horizon-epoch167-retry6-cap512-working-set-v1");
    working["recorded_unix_seconds"] = json!(now()?);
    working["fleet"] = plan["fleet"].clone();
    working["native_preparer_image"] = json!(image);
    working["native_preparer_qualification"] = cfg["preparer_qualification"].clone();
    working["immutable_raw_guard_floor_bytes"] = json!(RAW_FLOOR);
    working["complete_DATA_bytes"] = json!(COMPLETE_DATA);
    working["candidate_root_cap_booking"] = plan["retry167"]["additive_data_booking"].clone();
    working["retained_epoch167_additive_data_booking"] = plan["retry167"]["additive_data_booking"].clone();
    working["candidate_root_cap_bytes"] = json!(candidate_cap);
    working["additive_root_cap_reservation_bytes"] = json!(candidate_cap - CAP);
    working["protected166_root_cap_bytes"] = json!(CAP);
    working["stopped170_root_cap_bytes"] = json!(CAP);
    working["retained_retry6_166_DATA_bytes"] = json!(CAP);
    working.as_object_mut().context("working set object")?.remove("terminal166_retained");
    let admission = bound(&cfg["peer_admission"])?;
    let peer_preparation = bound(&admission["fresh_native_Rust_preparation"])?;
    let peer_retained = peer_preparation["actual_full_lane_ledger"]["physical_bytes"].as_u64().context("peer ledger")?;
    ensure!(peer_retained > 0 && peer_retained < CAP, "peer baseline cap");
    let rows = working["lanes"].as_array_mut().context("four working set rows")?;
    ensure!(rows.len() == 4 && rows.iter().filter_map(|r|r["epoch"].as_u64()).collect::<BTreeSet<_>>() == BTreeSet::from([166,167,169,170]), "complete working set");
    for row in rows {
        match row["epoch"].as_u64().context("row epoch")? {
            166 => *row = json!({"epoch":166,"state":"active","producer_unit":PEER,
                "invocation_id":IID,"retained_lane_physical_bytes":peer_retained,"remaining_growth_bytes":CAP-peer_retained}),
            167 => *row = json!({"epoch":167,"state":"candidate","producer_unit":plan["producer_unit"],
                "retained_lane_physical_bytes":retained,"remaining_growth_bytes":candidate_cap-retained}),
            170 => {
                row["producer_unit"] = json!("horizon-qualify-170-replacement-local3retry4-20261110-v1.service");
                row["invocation_id"] = json!("aabba5ff4c8e4c22ad18c80472713aa9");
                row["terminal_event"] = plan["resident_memory"]["terminal170"]["stop_completion"].clone();
            }
            169 => (),
            _ => unreachable!(),
        }
    }
    plan["retry3"]["concurrent_working_set"] = binding(&write(root,"CONCURRENT_WORKING_SET.json",&working)?)?;
    let slot = json!({"schema":"horizon-standard-replacement-exclusive-slot-mapping-v1","owner":"/root",
        "epoch":167,"recorded_unix_seconds":now()?,"physical_ledger":cfg["measurement"],
        "retained_lane_physical_bytes":retained,"combined_original_lane_cap_bytes":candidate_cap,
        "old_remaining_future_promise_bytes":CAP-retained,"proposed_fresh_working_maximum_bytes":candidate_cap-retained,
        "additional_DATA_bytes":candidate_cap-CAP,"all_original_promises_retained":true,
        "guard_root_remains_whole_original_lane":true,"original_stop":measurement["original_stop"],
        "replay_launch_authorized":false});
    review["exact_slot_mapping_and_physical_ledger"] = binding(&write(root,"EXCLUSIVE_SLOT_MAPPING.json",&slot)?)?;
    review["attempt"] = plan["attempt"].clone();
    review["recorded_unix_seconds"] = json!(now()?);
    review["source_fleet"] = plan["fleet"].clone();
    review["source_inventory"] = plan["inventory"].clone();
    review["input_proof"] = plan["input_proof"].clone();
    review["cleanup_completion"] = plan["cleanup_completion"].clone();
    review["full_current_proc_and_unit_census"] = binding(census)?;
    review["data_fulfillment"] = plan["data_fulfillment"].clone();
    review["minimum_initial_available_data_bytes"] = json!(RAW_FLOOR + (64u64 << 20));
    review["retained_lane_physical_bytes"] = json!(retained);
    review["existing_original_slot_future_growth_bytes"] = json!(CAP-retained);
    review["proposed_fresh_working_maximum_bytes"] = json!(candidate_cap-retained);
    review["candidate_remaining_growth_bytes"] = json!(candidate_cap-retained);
    review["additional_growth_not_covered_by_existing_promise_bytes"] = json!(candidate_cap-CAP);
    plan["review"] = binding(&write(root,"PRELAUNCH_REVIEW.json",&review)?)?;
    write(root,"PREPARE_PLAN.json",plan)
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(args.len() == 6 && args[2] == "--plan-sha256" && args[4] == "--self-sha256"
        && unsafe { libc::geteuid() } == 0, "stage PLAN --plan-sha256 SHA --self-sha256 SHA");
    ensure!(sha(&fs::read("/proc/self/exe")?) == args[5], "self digest");
    let cfg = read_bound(Path::new(&args[1]), &args[3])?;
    ensure!(cfg["owner"] == "/root" && cfg["primary_thread"] == THREAD, "owner");
    let root = PathBuf::from(cfg["output_root"].as_str().context("output")?);
    let m = fs::symlink_metadata(&root)?;
    ensure!(root.canonicalize()? == root && m.uid() == 0 && m.is_dir()
        && m.mode() & 0o7777 == 0o700 && fs::read_dir(&root)?.next().is_none(), "empty private output");
    let observer = bound(&cfg["observer"])?;
    observe(&observer)?;
    let status = bound(&cfg["status_audit"])?;
    ensure!(status["observer"] == cfg["observer"] && status["authenticated_readback"] == true
        && status["authenticated_status_count"] == 19 && status["authenticated_ready_pairs"] == 70,
        "same-sample status readback");
    let inventory = bound(&cfg["inventory"])?;
    ensure!(inventory["ready_pairs"] == 70 && inventory["anomalies"] == 0
        && inventory["entries"].as_array().context("inventory")?.iter().any(|r|r["epoch"] == 167 && r["state"] == "missing"),
        "missing167 inventory");
    let mut fleet = bound(&cfg["previous_fleet"])?;
    ensure!(fleet["owner"] == "/root" && fleet["primary_thread"] == THREAD
        && fleet["complete_DATA_bytes"] == 6_485_523_382_066u64
        && fleet["complete_projected_memory_bytes"] == 761_131_708_416u64,
        "complete retained fleet baseline");
    let mut plan = bound(&cfg["template"])?;
    ensure!(plan["epoch"] == 167 && plan["attempt"] == "local3retry5", "exact prior template");
    plan["attempt"] = json!("local3retry6");
    plan["producer_unit"] = json!("horizon-qualify-167-replacement-local3retry6-20261110-v1.service");
    plan["guard_base"] = json!("horizon-guard-replacement-167-local3retry6-20261110-v1");
    plan["fresh_subtree"] = json!("/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1/replacement-local3retry6-20261110-v1");
    plan["current_allocation"]["schema"] = json!("horizon-epoch167-retry6-native-allocation-v1");
    for (epoch, attempt) in [(166,"local3retry6"),(167,"local3retry5"),(167,"local3retry6"),(170,"local3retry5")] {
        for unit in [format!("horizon-qualify-{epoch}-replacement-{attempt}-20261110-v1.service"),
            format!("horizon-guard-replacement-{epoch}-{attempt}-20261110-v1.service"),
            format!("horizon-guard-replacement-{epoch}-{attempt}-20261110-v1.timer")] {
            let units = plan["closed_units"].as_array_mut().context("closed units")?;
            if !units.contains(&json!(unit)) { units.push(json!(unit)); }
        }
    }
    let prior_census = bound(&fleet["full_current_proc_and_unit_census"])?;
    let mut names = unit_names(&prior_census, &plan)?;
    names.insert(PEER.to_owned());
    let before = native(&names)?;
    live_peer(&before[PEER])?;
    for unit in plan["closed_units"].as_array().unwrap() {
        let name = unit.as_str().context("unit")?;
        ensure!(closed(&before[name]), "target/old owner not closed: {name}");
    }
    ensure!(process_claims()?.is_empty(), "candidate167 has a live process");
    let admission = bound(&cfg["peer_admission"])?;
    let protection = bound(&cfg["peer_protection"])?;
    ensure!(admission["producer_invocation_id"] == IID && admission["producer_unit"] == PEER
        && admission["fresh_admission_passed"] == true && admission["all_prior_promises_retained"] == true
        && admission["guard_minimum_free_bytes"] == 6_584_106_303_282u64
        && protection["admission"] == cfg["peer_admission"], "genuine protected166 admission");
    let guard_plan = bound(&protection["plan"])?;
    ensure!(guard_plan["minimum_free_bytes"] == 6_584_106_303_282u64
        && guard_plan["unit"] == PEER && guard_plan["invocation_id"] == IID, "peer guard floor");
    let owner = json!({"epoch":166,"unit":PEER,"invocation_id":IID,"main_pid":1450368,
        "main_start_ticks":337513170u64,"admission":cfg["peer_admission"],"guard_protection":cfg["peer_protection"]});
    plan["resident_memory"]["owners"] = json!([owner]);
    plan["resident_memory"]["observer"] = cfg["observer"].clone();
    plan["data_fulfillment"] = cfg["data_fulfillment"].clone();
    for key in ["runtime_seal", "qualification"] { bound(&plan["data_fulfillment"][key])?; }
    // The preparer authenticates the binary, contract, source proof and exact route itself.
    let after = native(&plan["closed_units"].as_array().unwrap().iter().map(|v|v.as_str().unwrap().to_owned())
        .chain(std::iter::once(PEER.to_owned())).collect())?;
    for (name,row) in &after { ensure!(before[name] == *row, "identity changed during census: {name}"); }
    ensure!(process_claims()?.is_empty(), "candidate appeared during census");
    let native_path = write(&root,"CURRENT_NATIVE_RAW.json",&json!(before))?;
    let census_path = write(&root,"CURRENT_CENSUS.json",&json!({"schema":"horizon-standard-replacement-Root-current-unit-and-proc-census-v1",
        "owner":"/root","sole_primary_thread":THREAD,"recorded_unix_seconds":now()?,
        "complete_metadata_unit_census":before,"full_raw_native_metadata_census":binding(&native_path)?,
        "exact_selected_node_and_worker_process_claims":[],"no_new_target_owner_or_queued_launch":true}))?;
    let peer_row = json!({"epoch":166,"unit":before[PEER],"in_current_observer":true,
        "observer":cfg["observer"],"phase":"replay","progress":observer["replays"][0]["useful_work"],
        "scratch_path":observer["replays"][0]["scratch_path"],"admission":cfg["peer_admission"],
        "guard_protection":cfg["peer_protection"]});
    fleet["actual_executing_replays"] = json!([peer_row]);
    fleet["actual_active_bootstraps"] = json!([]);
    for key in ["active_producer_count","live_replay_count","useful_replay_count"] { fleet[key] = json!(1); }
    fleet["complete_DATA_bytes"] = json!(COMPLETE_DATA);
    fleet["previous_Root_operational_review"] = cfg["previous_fleet"].clone();
    fleet["observer"] = cfg["observer"].clone();
    fleet["authenticated_status_audit"] = cfg["status_audit"].clone();
    fleet["authenticated_inventory"] = cfg["inventory"].clone();
    fleet["full_current_proc_and_unit_census"] = binding(&census_path)?;
    fleet["metadata_unit_census"] = json!(before);
    fleet["recorded_unix_seconds"] = json!(now()?);
    fleet["sampled_at_utc"] = observer["recorded_at_utc"].clone();
    fleet["same_sample_conservative_free_DATA_bytes"] = observer["filesystem"]["conservative_available_bytes"].clone();
    fleet["sole_next_observer"] = cfg["next_observer"].clone();
    fleet["retained_retry6_166_DATA_bytes"] = json!(CAP);
    fleet["complete_DATA_authority"] = json!({"previous":cfg["previous_fleet"],"retained166_admission":cfg["peer_admission"],
        "complete_DATA_bytes":COMPLETE_DATA,"additional_retained_root_bytes":CAP,"promise_ending_bytes":0});
    let current_peer = fleet["actual_executing_replays"][0].clone();
    let rows = fleet["epochs"].as_array_mut().context("epochs")?;
    ensure!(rows.len()==100 && rows.iter().enumerate().all(|(i,r)|r["epoch"] == 101+i),"full epoch range");
    for row in rows.iter_mut() {
        let epoch = row["epoch"].as_u64().context("epoch")?;
        if let Some(b) = status["receipts"].get(epoch.to_string()) {
            let receipt = bound(b)?;
            ensure!(receipt["authenticated_readback"] == true && receipt["epoch"] == epoch,
                "status row binding");
            row["current_authenticated_status_receipt"] = b.clone();
            row["status_publication"] = b.clone();
            row["current_status"] = receipt["after_status"].clone();
            row["status"] = receipt["after_status"].clone();
        }
        row["current_coordinated_observer"] = cfg["observer"].clone();
    }
    rows[65]["current_replay"] = current_peer;
    rows[65]["no_live_producer_claimed"] = json!(false);
    rows[65]["state"] = json!("replay");
    rows[65]["current_repair_owner"] = Value::Null;
    let fleet_path = write(&root,"ROOT_COMPLETE_OPERATIONAL_FLEET.json",&fleet)?;
    let mut booking = bound(&cfg["previous_booking"])?;
    ensure!(booking["complete_DATA_bytes"] == COMPLETE_DATA-CAP && booking["raw_floor_bytes"] == RAW_FLOOR-CAP,
        "prior booking arithmetic");
    booking["source_fleet"] = binding(&fleet_path)?;
    booking["complete_DATA_bytes"] = json!(COMPLETE_DATA);
    booking["raw_floor_bytes"] = json!(RAW_FLOOR);
    booking["retained_retry6_166_DATA_bytes"] = json!(CAP);
    booking["protected166_admission"] = cfg["peer_admission"].clone();
    booking["protected166_guard"] = cfg["peer_protection"].clone();
    booking["previous_retry6_reservation"] = cfg["previous_booking"].clone();
    let booking_path = PathBuf::from(cfg["booking_path"].as_str().context("booking path")?);
    ensure!(booking_path.parent() == Some(Path::new("/var/lib/jetstreamer/epoch167-retry6-zeropeer-20261118-v1")), "booking directory");
    let booking_path = write(booking_path.parent().unwrap(),booking_path.file_name().unwrap().to_str().unwrap(),&booking)?;
    plan["retry167"]["additive_data_booking"] = binding(&booking_path)?;
    plan["fleet"] = binding(&fleet_path)?;
    plan["inventory"] = cfg["inventory"].clone();
    let plan_path = write(&root,"MEASURE_PLAN.json",&plan)?;
    let selected_plan = if cfg["measurement"].is_object() {
        prepare_review(&cfg,&root,&mut plan,&census_path)?
    } else { plan_path };
    println!("{}",json!({"plan":binding(&selected_plan)?,"fleet":binding(&fleet_path)?,"booking":binding(&booking_path)?,"replay_launch_authorized":false}));
    Ok(())
}
fn main() { if let Err(e)=run() { eprintln!("{e:#}"); std::process::exit(1); } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn measurement_must_be_recent_complete_and_for_the_exact_lane() {
        let v = json!({"schema":"horizon-standard-replacement-local-physical-ledger-v1",
            "owner":"/root","epoch":167,"recorded_unix_seconds":1000,"read_only":true,
            "resource_credit_bytes":0,"replay_launch_authorized":false,
            "lane_root":"/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1",
            "physical":{"physical_bytes":100}});
        assert_eq!(retained_measurement(&v,2800).unwrap(),100);
        assert!(retained_measurement(&v,2801).is_err());
        assert!(retained_measurement(&v,999).is_err());
        for (key,value) in [("epoch",json!(166)),("read_only",json!(false)),
            ("resource_credit_bytes",json!(1)),("replay_launch_authorized",json!(true)),
            ("lane_root",json!("/tmp/foreign"))] {
            let mut bad=v.clone(); bad[key]=value;
            assert!(retained_measurement(&bad,1000).is_err());
        }
        for bytes in [0,CAP,CAP+1] {
            let mut bad=v.clone();bad["physical"]["physical_bytes"]=json!(bytes);
            assert!(retained_measurement(&bad,1000).is_err());
        }
    }
    #[test]
    fn peer_identity_and_closure_are_disjoint() {
        let row=json!({"Id":PEER,"InvocationID":IID,"MainPID":"1450368","ControlPID":"0",
            "ActiveState":"active","SubState":"running","NRestarts":"0","Job":""});
        live_peer(&row).unwrap(); assert!(!closed(&row));
        for key in ["Id","InvocationID","MainPID","ControlPID","ActiveState","SubState","NRestarts","Job"] {
            let mut bad=row.clone();bad[key]=json!("changed");assert!(live_peer(&bad).is_err());
        }
    }
    #[test]
    fn native_census_accepts_leading_dash_mount_name() {
        let rows = native(&BTreeSet::from(["-.mount".to_owned()])).unwrap();
        assert_eq!(rows["-.mount"]["Id"], "-.mount");
        assert_eq!(rows["-.mount"]["LoadState"], "loaded");
    }
    #[test]
    fn additive_budget_keeps_existing_reservations() {
        assert_eq!(COMPLETE_DATA-CAP,6_485_523_382_066);
        assert_eq!(RAW_FLOOR-CAP,6_519_816_011_570);
    }
}
