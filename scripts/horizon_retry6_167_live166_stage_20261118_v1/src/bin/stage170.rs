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
const PREPARER: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch170-retry6-live166retry7-prepare-20261118-v1/prepare";
const PREPARER_SHA: &str = "095d99efd0b0c6d657fb806943ecad86b0a19ea3528d273ca5d48d577e9bfaff";
const GUARD: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch170-retry6-live166retry7-data-guard-20261118-v1/guard";
const GUARD_SHA: &str = "2572c20c10b1473a9438e8d08d4aaf6ccb06fa9aa47e3508fe90e6bcaddddc6b";
const CONTRACT: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch170-retry6-live166retry7-data-contract-20261118-v1";
const TEMPLATE: &str =
    "/var/lib/jetstreamer/epoch170-retry5-recovery-20261117-v1/measure0743-v3/PLAN-FINAL.json";
const TEMPLATE_SHA: &str = "e7133f6349619370806f475b1c1511cd505e456da330c3f9be38e6e12642de86";
const FLEET: &str = "/var/lib/jetstreamer/root0049-live166167-observation-20261119-v2/ROOT_COMPLETE_OPERATIONAL_FLEET.json";
const OBSERVER: &str = "/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-root0049-live166167-20261119-v1.json";
const STATUS: &str = "/home/sol/.jetstreamer-private/r2-status-receipts/cycle0049-live166167-19-20261119-v1/COMPLETED.json";
const INVENTORY: &str =
    "/home/sol/horizon-disk-audit-20261116T2052Z/r2-inventory-101-200-20261118T1750Z.json";
const NEXT: &str = "/usr/local/lib/jetstreamer/horizon-live166167-observer-config-0049-20261119-v2/next-observer.json";
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
const ROOT: &str = "/var/lib/jetstreamer/epoch170-two-peer-stage-20261119-v1";
const FRESH: &str = "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1/replacement-local3retry6-20261110-v1";
const STAGE_IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch170-two-peer-stage-20261119-v1/stage170";
const PACKAGE: &str = "scripts/horizon_retry6_167_live166_stage_20261118_v1";
fn seal_stage(commit: &str) -> Result<()> {
    let root = Path::new(ROOT).join("deployment");
    private_new(&root)?;
    let repo = Path::new("/home/sol/workspace/jetstreamer");
    let mut members = Vec::new();
    for (leaf, name, mode) in [
        ("src/bin/stage170.rs", "stage170.rs", 0o444),
        ("Cargo.toml", "Cargo.toml", 0o444),
        ("Cargo.lock", "Cargo.lock", 0o444),
        ("target/release/stage170", "stage170", 0o555),
    ] {
        let source = repo.join(PACKAGE).join(leaf);
        if !leaf.starts_with("target/") {
            let published = output(
                Command::new("git")
                    .arg("-C")
                    .arg(repo)
                    .args(["show", &format!("{commit}:{PACKAGE}/{leaf}")]),
            )?;
            ensure!(
                published.as_bytes() == fs::read(&source)?,
                "unpublished stage source"
            );
        }
        members.push(
            json!({"source":source,"name":name,"mode":mode,"sha256":sha(&fs::read(&source)?)}),
        );
    }
    let mut executions = Map::new();
    for phase in ["tests", "clippy", "build"] {
        let unit = format!("horizon-two-peer170-stage-{phase}-20261119-v3.service");
        let raw = output(Command::new("systemctl").args([
            "show",
            &unit,
            "-pResult,ExecMainStatus,ActiveState,SubState,InvocationID,ExecStart",
        ]))?;
        for expected in [
            "Result=success",
            "ExecMainStatus=0",
            "ActiveState=active",
            "SubState=exited",
        ] {
            ensure!(
                raw.lines().any(|l| l == expected),
                "qualification {unit}: missing {expected}"
            );
        }
        let iid = raw
            .lines()
            .find_map(|l| l.strip_prefix("InvocationID="))
            .context("qualification invocation")?;
        let log = output(Command::new("journalctl").args([
            "--all",
            "--no-pager",
            "-o",
            "cat",
            &format!("_SYSTEMD_INVOCATION_ID={iid}"),
        ]))?;
        if phase == "tests" {
            ensure!(
                log.contains("test result: ok. 2 passed; 0 failed;"),
                "stage tests incomplete"
            );
        }
        let evidence = write(
            &root,
            &format!("{phase}.json"),
            &json!({"unit":unit,"native":raw,"journal":log}),
        )?;
        executions.insert(phase.into(), binding(&evidence)?);
        members.push(json!({"source":evidence,"name":format!("{phase}.json"),"mode":0o444,"sha256":sha(&fs::read(&evidence)?)}));
    }
    let proof = write(
        &root,
        "artifact-proof.json",
        &json!({"source_commit":commit,"executions":executions,"tests_passed":2,"remote_mutations":false,"replay_launch_authorized":false}),
    )?;
    members.push(json!({"source":proof,"name":"artifact-proof.json","mode":0o444,"sha256":sha(&fs::read(&proof)?)}));
    let plan = write(
        &root,
        "STAGE-SEAL-PLAN.json",
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":Path::new(STAGE_IMAGE).parent(),"members":members}),
    )?;
    ensure!(sha(&fs::read(SEALER)?) == SEALER_SHA, "sealer changed");
    output(Command::new(SEALER).arg(&plan).args([
        "--plan-sha256",
        &sha(&fs::read(&plan)?),
        "--self-sha256",
        SEALER_SHA,
    ]))?;
    println!("{}", b(STAGE_IMAGE)?);
    Ok(())
}
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
            "horizon-qualify-166-replacement-local3retry7-20261110-v1.service",
            "03fa3ce80d8c4769a1e9dec548cdbeca",
            1450368,
            337513170,
            "/var/lib/jetstreamer/retry7-single166-guarded-launch-20261118-v2/epoch166",
        ),
        167 => (
            "horizon-qualify-167-replacement-local3retry6-20261110-v1.service",
            "fdfadeb7b76d4760a37983b402fd2771",
            1718241,
            339577396,
            "/var/lib/jetstreamer/retry6-single167-guarded-launch-20261118-v1/epoch167",
        ),
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
fn own_witness() -> Result<()> {
    let root = Path::new(ROOT).join("guard-witness");
    private_new(&root)?;
    ensure!(
        sha(&fs::read(GUARD)?) == GUARD_SHA && sha(&fs::read(SEALER)?) == SEALER_SHA,
        "sealed image changed"
    );
    let witness = root.join("NATIVE_WITNESS.json");
    output(Command::new("/usr/bin/systemd-run").args(["--unit","horizon-170-two-peer-own-witness-20261119-v1",
        "--property=Type=oneshot","--property=RemainAfterExit=yes","--property=CPUQuota=200%","--property=MemoryMax=4G","--property=TasksMax=128","--property=LimitNOFILE=1048576",
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
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":CONTRACT,
        "members":[{"source":c,"name":"contract.json","sha256":sha(&fs::read(&c)?),"mode":292}]}),
    )?;
    output(Command::new(SEALER).arg(&plan).args([
        "--plan-sha256",
        &sha(&fs::read(&plan)?),
        "--self-sha256",
        SEALER_SHA,
    ]))?;
    println!("{}", b(&format!("{CONTRACT}/contract.json"))?);
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
    let observer = read(OBSERVER)?;
    let status = read(STATUS)?;
    let mut fleet = read(FLEET)?;
    let current = utc_now()?;
    ensure!(
        observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && observer["recorded_at_utc"].as_str().context("sample")? <= current.as_str()
            && current.as_str()
                < observer["cadence"]["next_routine_observation_not_before_utc"]
                    .as_str()
                    .context("next")?
            && status["observer"] == b(OBSERVER)?
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
        let row = json!({"epoch":e,"unit":before[unit],"admission":ab,"guard_protection":pb,"observer":b(OBSERVER)?,"in_current_observer":true,"scratch_path":obs["scratch_path"],"progress":obs["useful_work"],"phase":if replay{"replay"}else{"bootstrap"}});
        if replay {
            executing.push(row);
        } else {
            bootstrap.push(row);
        }
    }
    plan["resident_memory"]["owners"] = json!(owners);
    plan["resident_memory"]["observer"] = b(OBSERVER)?;
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
        "contract":{"contract":b(&format!("{CONTRACT}/contract.json"))?,"deployment_seal":b(&format!("{CONTRACT}/deployment-seal-receipt.json"))?}});
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
    fleet["previous_Root_operational_review"] = b(FLEET)?;
    fleet["full_current_proc_and_unit_census"] = binding(&census)?;
    fleet["metadata_unit_census"] = json!(before);
    fleet["recorded_unix_seconds"] = json!(now()?);
    fleet["actual_executing_replays"] = json!(executing);
    fleet["actual_active_bootstraps"] = json!(bootstrap);
    fleet["active_producer_count"] = json!(2);
    fleet["live_replay_count"] = json!(executing.len());
    fleet["useful_replay_count"] = json!(executing.len());
    fleet["observer"] = b(OBSERVER)?;
    fleet["authenticated_status_audit"] = b(STATUS)?;
    fleet["sole_next_observer"] = b(NEXT)?;
    let fp = write(&root, "ROOT_COMPLETE_OPERATIONAL_FLEET.json", &fleet)?;
    plan["fleet"] = binding(&fp)?;
    plan["inventory"] = b(INVENTORY)?;
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
    output(Command::new("/usr/bin/systemd-run").args([
        "--unit",
        &format!("horizon-170-two-peer-{op}-{tag}-20261119-v1"),
        "--property=Type=oneshot",
        "--property=RemainAfterExit=yes",
        "--property=CPUQuota=200%",
        "--property=MemoryMax=4G",
        "--property=TasksMax=128",
        "--property=LimitNOFILE=1048576",
        PREPARER,
        path.to_str().unwrap(),
        "--plan-sha256",
        &sha(&fs::read(&path)?),
        "--self-sha256",
        PREPARER_SHA,
        if measurement.is_some() {
            "--prepare"
        } else {
            "--measure-only"
        },
    ]))?;
    Ok(())
}
fn main() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "Root required");
    let a: Vec<_> = std::env::args().collect();
    ensure!(
        (a.len() == 2 && matches!(a[1].as_str(), "witness" | "seal"))
            || (a.len() == 3 && a[1] == "measure")
            || (a.len() == 4 && a[1] == "prepare"),
        "stage170 seal | witness | measure TAG | prepare TAG MEASUREMENT"
    );
    let repo = "/home/sol/workspace/jetstreamer";
    let commit = output(Command::new("git").args(["-C", repo, "rev-parse", "HEAD"]))?;
    output(Command::new("git").args([
        "-C",
        repo,
        "merge-base",
        "--is-ancestor",
        commit.trim(),
        "origin/account-updates",
    ]))?;
    ensure!(
        output(Command::new("git").args([
            "-C",
            repo,
            "status",
            "--porcelain",
            "--untracked-files=no",
            "--",
            PACKAGE
        ]))?
        .is_empty(),
        "tracked source changed"
    );
    if !Path::new(ROOT).try_exists()? {
        private_new(Path::new(ROOT))?;
    }
    let root_md = fs::symlink_metadata(ROOT)?;
    ensure!(
        root_md.is_dir() && root_md.uid() == 0 && root_md.mode() & 0o7777 == 0o700,
        "unsafe staging root"
    );
    if a[1] == "seal" {
        return seal_stage(commit.trim());
    }
    ensure!(
        fs::read_link("/proc/self/exe")? == Path::new(STAGE_IMAGE),
        "sealed stage image required"
    );
    let seal = read(&format!(
        "{}/deployment-seal-receipt.json",
        Path::new(STAGE_IMAGE).parent().unwrap().display()
    ))?;
    let members = seal["members"].as_array().context("stage seal members")?;
    let self_sha = sha(&fs::read("/proc/self/exe")?);
    ensure!(
        members
            .iter()
            .any(|m| m["name"] == "stage170" && m["sha256"] == self_sha),
        "stage image seal mismatch"
    );
    if a[1] == "witness" {
        own_witness()
    } else {
        stage(&a[2], a.get(3).map(Path::new))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
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
        for e in [166, 167] {
            let (u, i, p, _, _) = peer(e);
            let v = json!({"Id":u,"InvocationID":i,"MainPID":p.to_string(),"ActiveState":"active","SubState":"running","NRestarts":"0","ControlPID":"0","Job":""});
            peer_shape(e, &v).unwrap();
            let mut bad = v.clone();
            bad["NRestarts"] = json!("1");
            assert!(peer_shape(e, &bad).is_err());
            assert!(peer_shape(if e == 166 { 167 } else { 166 }, &v).is_err());
        }
    }
}
