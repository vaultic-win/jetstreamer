//! Stage only the sealed independent epoch 166 preparer. The controller executes the emitted argv.
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
    let md = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && md.is_file()
            && md.uid() == 0
            && md.mode() & 0o022 == 0
            && md.nlink() == 1
            && md.len() <= 32 << 20,
        "unsafe metadata {}",
        path.display()
    );
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
    if name.ends_with("PLAN.json") || name == "launch-plan.json" {
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

fn private(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => File::open(path.parent().context("parent")?)?.sync_all()?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    let md = fs::symlink_metadata(path)?;
    ensure!(
        md.is_dir() && md.uid() == 0 && md.mode() & 0o7777 == 0o700 && path.canonicalize()? == path,
        "unsafe private root"
    );
    Ok(())
}
#[allow(dead_code)]
#[path = "../peer/main.rs"]
mod independent166;
#[path = "../prepare_proof.rs"]
mod prepare_proof;
const BASE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch167-retry8-recovery-20261120-v1";
const HIST: &str = "/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1";
const UNIT: &str = "horizon-qualify-167-replacement-local3retry8-20261110-v1.service";
const GUARD_BASE: &str = "horizon-guard-replacement-167-local3retry8-20261110-v1";
const PEER: &str = "horizon-qualify-independent-cold166-20261120-v1.service";
const IID: &str = "fa16ee2f14fe44ecbc37c59e197553ac";
const CAP: u64 = 309_237_645_312;
const RAW_FLOOR: u64 = 6_829_053_656_882;
const COMPLETE_DATA: u64 = 6_794_761_027_378;
const OLD_PLAN: &str =
    "/var/lib/jetstreamer/root0647-prepare167retry7-20261119-v1/PREPARE_PLAN.json";
const OLD_SHA: &str = "4dc4aa68356ee66104ea8ddc228c3c229671c8790286af6f1c3128fc72058db7";
const BOOT: &str = "/var/lib/jetstreamer/horizon_runtime_data/root0345-zero-recovery-20261120-v1/live166-start/ROOT_OPERATIONAL_BOOTSTRAP_EVENT.json";
const BOOT_SHA: &str = "1a611ae704e42fd50a881f2ba45a0aff4002cd85c52bd530b3d8f0a9a328a3ca";
const OLD_ROOTS: &str = "/var/lib/jetstreamer/horizon_runtime_data/root-zero-166167-stop-20261120-v1/SUCCESSOR_ROOTS_BEFORE_WITNESS.json";
const OLD_ROOTS_SHA: &str = "d9e8ae44c9726811b2104cac494b4ccc4a5ef3cb7bf56e5cadec6bf6f9b4be89";
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
fn base() -> &'static Path {
    Path::new(BASE)
}
fn pair(path: &str, digest: &str) -> Value {
    json!({"path":path,"sha256":digest})
}
fn n(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64().with_context(|| format!("missing {k}"))
}
fn fresh(v: &Value, key: &str, at: u64, max: u64) -> Result<()> {
    ensure!(
        at.checked_sub(n(v, key)?).is_some_and(|age| age <= max),
        "stale/future {key}"
    );
    Ok(())
}
fn plan_shape(original: &Value, fleet: &Value) -> Result<Value> {
    plan_shape_for_owner(original, fleet, &independent166::actual_owner()?)
}
fn plan_shape_for_owner(original: &Value, fleet: &Value, owner: &Value) -> Result<Value> {
    let mut p = original.clone();
    ensure!(
        p["epoch"] == 167 && p["attempt"] == "local3retry7",
        "wrong predecessor plan"
    );
    p["attempt"] = json!("local3retry8");
    p["producer_unit"] = json!(UNIT);
    p["guard_base"] = json!(GUARD_BASE);
    p["fresh_subtree"] = json!(Path::new(HIST).join("replacement-local3retry8-20261110-v1"));
    p["resident_memory"]["owners"] = json!([owner]);
    p["resident_memory"]["observer"] = fleet["observer"].clone();
    p["inventory"] = fleet["authenticated_inventory"].clone();
    let mut closed: BTreeSet<String> = serde_json::from_value(p["closed_units"].clone())?;
    for (epoch, retry) in [(166, 8), (166, 9), (167, 7), (167, 8), (170, 6)] {
        closed.insert(format!(
            "horizon-qualify-{epoch}-replacement-local3retry{retry}-20261110-v1.service"
        ));
        for suffix in ["service", "timer"] {
            closed.insert(format!(
                "horizon-guard-replacement-{epoch}-local3retry{retry}-20261110-v1.{suffix}"
            ));
        }
    }
    ensure!(
        closed.len() <= 64 && !closed.contains(PEER),
        "invalid candidate closed-unit set"
    );
    p["closed_units"] = json!(closed);
    Ok(p)
}

fn check_observer(fleet: &Value) -> Result<()> {
    let boot = read_bound(Path::new(BOOT), BOOT_SHA)?;
    let owner = independent166::actual_owner()?;
    let preceding = bound(&boot["previous_complete_fleet"])?;
    let observer = bound(&fleet["observer"])?;
    let rows = observer["replays"]
        .as_array()
        .context("coordinated replay rows")?;
    let active = fleet["actual_executing_replays"]
        .as_array()
        .context("fleet replays")?;
    let bootstrap = fleet["actual_active_bootstraps"]
        .as_array()
        .context("fleet bootstraps")?;
    ensure!(
        boot["admission"] == owner["admission"]
            && boot["protection"] == owner["guard_protection"]
            && boot["additional_independent_DATA_bytes"] == CAP
            && boot["all_prior_promises_retained"] == true
            && boot["resource_credit_bytes"] == 0
            && fleet["owner"] == "/root"
            && fleet["primary_thread"] == THREAD
            && fleet["complete_DATA_bytes"] == COMPLETE_DATA
            && fleet["complete_projected_memory_bytes"] == 761_131_708_416u64
            && fleet["retained_retry6_166_DATA_bytes"] == CAP
            && fleet["active_producer_count"] == 1
            && fleet["all_existing_memory_DATA_OS_native_transport_promises_retained"] == true
            && active.len() + bootstrap.len() == 1
            && active.iter().chain(bootstrap).any(|r| r["epoch"] == 166
                && r["unit"]["Id"] == PEER
                && r["unit"]["InvocationID"] == IID
                && r["admission"] == owner["admission"]
                && r["guard_protection"] == owner["guard_protection"])
            && observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && rows.len() == 1
            && rows[0]["range"] == "166"
            && rows[0]["invocation_binding_stable"] == true
            && rows[0]["producer_after"]["invocation_id"] == IID
            && rows[0]["producer_after"]["main_pid"] == owner["main_pid"]
            && utc_now()?.as_str()
                < observer["cadence"]["next_routine_observation_not_before_utc"]
                    .as_str()
                    .context("deadline")?,
        "fresh single-owner fleet, coordinated observation, or bootstrap admission differs"
    );
    for key in [
        "additional_retained_build_allocation",
        "retry9_auxiliary_commitments",
    ] {
        ensure!(
            !preceding[key].is_null() && fleet[key] == preceding[key],
            "historical fleet obligation changed: {key}"
        );
    }
    let audit = &fleet["continuing_audit_obligation"];
    ensure!(
        audit["additional_memory_bytes"] == 25_769_803_776u64
            && audit["additional_cpu_quota_micros"] == 4_000_000
            && audit["per_epoch_capacity_reserves_exact_archive_bytes"] == true
            && audit["DATA_storage_filesystem"] == "/home/sol",
        "home audit reservation missing"
    );
    let status = bound(&fleet["authenticated_status_audit"])?;
    ensure!(
        status["observer"] == fleet["observer"] && status["authenticated_readback"] == true,
        "inventory/status generation differs"
    );
    let inventory = bound(&fleet["authenticated_inventory"])?;
    ensure!(
        inventory["anomalies"] == 0 && inventory["ready_pairs"].as_u64().is_some_and(|n| n >= 70),
        "invalid range inventory"
    );
    Ok(())
}
fn capture_fleet(root: &Path, p: &Value, source: &Value, mut fleet: Value) -> Result<Value> {
    check_observer(&fleet)?;
    let prior = bound(&fleet["full_current_proc_and_unit_census"])?;
    let names = unit_names(&prior, p)?;
    let first = native(&names)?;
    let target: BTreeSet<String> = serde_json::from_value(p["closed_units"].clone())?;
    for unit in &target {
        ensure!(
            first.get(unit).is_some_and(closed),
            "owner active/queued: {unit}"
        );
    }
    ensure!(process_claims()?.is_empty(), "167 source process found");
    let second = native(&target)?;
    for unit in &target {
        ensure!(
            first[unit] == second[unit] && closed(&second[unit]),
            "owner changed: {unit}"
        );
    }
    ensure!(process_claims()?.is_empty(), "167 source process appeared");
    let raw = write(root, "CURRENT_NATIVE_RAW.json", &json!(&first))?;
    let census = write(
        root,
        "CURRENT_CENSUS.json",
        &json!({"schema":"horizon-standard-replacement-Root-current-unit-and-proc-census-v1","owner":"/root","sole_primary_thread":THREAD,"recorded_unix_seconds":now()?,"complete_metadata_unit_census":&first,"full_raw_native_metadata_census":binding(&raw)?,"exact_selected_node_and_worker_process_claims":[],"no_new_target_owner_or_queued_launch":true}),
    )?;
    fleet["previous_Root_operational_review"] = source.clone();
    fleet["full_current_proc_and_unit_census"] = binding(&census)?;
    fleet["metadata_unit_census"] = json!(first);
    fleet["recorded_unix_seconds"] = json!(now()?);
    fleet["retained_native_census_is_historical"] = json!(false);
    fleet["fresh_campaign_unit_census_claimed"] = json!(true);
    let path = write(root, "ROOT_COMPLETE_OPERATIONAL_FLEET.json", &fleet)?;
    ensure!(
        fs::metadata(&path)?.len() <= 16 << 20,
        "launcher fleet size exceeded"
    );
    binding(&path)
}
fn witness_contract(
    template: &Value,
    w: &Value,
    b: &Value,
    guard: &Value,
    at: u64,
    age: u64,
) -> Result<Value> {
    let mut c = template.clone();
    let old = read_bound(Path::new(OLD_ROOTS), OLD_ROOTS_SHA)?;
    ensure!(
        w["schema"] == "horizon-original-slot-DATA-native-witness-qualification-v1"
            && w["owner"] == "/root"
            && w["primary_thread"] == THREAD
            && w["native_identity"]["executable"] == guard["path"]
            && w["native_identity"]["executable_sha256"] == guard["sha256"]
            && w["witness_set"] == c["witness_set"]
            && w["witness_set_deployment_seal"] == c["witness_set_deployment_seal"]
            && n(w, "started_unix_seconds")? >= n(&old, "captured")?
            && n(w, "started_unix_seconds")? <= n(w, "recorded_unix_seconds")?
            && w["replay_admission_authorized"] == false
            && w["resource_credit_bytes"] == 0
            && w["DATA_ending_bytes"] == 0
            && w["remote_mutations"] == false,
        "independent witness lineage/image changed"
    );
    fresh(w, "recorded_unix_seconds", at, age)?;
    c["qualified_native_witness"] = b.clone();
    Ok(c)
}
fn fulfillment(
    root: &Path,
    witness: &Value,
    orig: &Value,
    images: &Value,
    age: u64,
) -> Result<Value> {
    let guard = &images["guard"];
    let dest = root.join("sealed-contract");
    let template = bound(&orig["data_fulfillment"]["contract"]["contract"])?;
    let w = bound(witness)?;
    let c = witness_contract(&template, &w, witness, guard, now()?, age)?;
    let cp = write(root, "contract.json", &c)?;
    let seal = write(
        root,
        "CONTRACT_SEAL_PLAN.json",
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":dest,"members":[{"source":cp,"name":"contract.json","sha256":sha(&fs::read(&cp)?),"mode":0o444}]}),
    )?;
    ensure!(sha(&fs::read(SEALER)?) == SEALER_SHA, "sealer changed");
    output(Command::new(SEALER).arg(&seal).args([
        "--plan-sha256",
        &sha(&fs::read(&seal)?),
        "--self-sha256",
        SEALER_SHA,
    ]))?;
    Ok(
        json!({"runtime":guard,"runtime_seal":binding(&base().join("guard-v1/deployment-seal-receipt.json"))?,"qualification":binding(&base().join("guard-v1/artifact-proof.json"))?,"contract":{"contract":binding(&dest.join("contract.json"))?,"deployment_seal":binding(&dest.join("deployment-seal-receipt.json"))?}}),
    )
}
fn retained_measurement(v: &Value, at: u64) -> Result<u64> {
    let measured_at = v["recorded_unix_seconds"]
        .as_u64()
        .context("measurement clock")?;
    let retained = v["physical"]["physical_bytes"]
        .as_u64()
        .context("physical bytes")?;
    ensure!(
        v["schema"] == "horizon-standard-replacement-local-physical-ledger-v1"
            && v["owner"] == "/root"
            && v["epoch"] == 167
            && v["read_only"] == true
            && v["resource_credit_bytes"] == 0
            && v["replay_launch_authorized"] == false
            && v["lane_root"]
                == "/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1"
            && measured_at <= at
            && at - measured_at <= 1800
            && retained > 0
            && retained < CAP,
        "fresh complete candidate167 physical measurement required"
    );
    Ok(retained)
}

fn declared_peer_lane(admission: &Value, prepared: &Value) -> Result<Value> {
    let root = "/home/sol/.jetstreamer-private/epoch166-independent-cold-20261120-v1";
    ensure!(
        admission["epoch"] == 166
            && admission["producer_unit"] == PEER
            && admission["producer_invocation_id"] == IID
            && admission["independent_worker_root"] == root
            && admission["independent_physical_cap_bytes"] == CAP
            && prepared["epoch"] == 166
            && prepared["attempt"] == "local3retry9"
            && prepared["retry2_retirement"]["new_attempt"] == "local3retry9"
            && prepared["independent_physical_cap_bytes"] == CAP
            && prepared["independent_worker_root"] == root,
        "166 admission and prepared independent root differ"
    );
    Ok(
        json!({"epoch":166,"state":"active","producer_unit":PEER,"invocation_id":IID,
        "retained_lane_physical_bytes":0,"remaining_growth_bytes":CAP}),
    )
}

fn prepare_review(cfg: &Value, root: &Path, plan: &mut Value, census: &Path) -> Result<PathBuf> {
    let measurement = bound(&cfg["measurement"])?;
    let retained = retained_measurement(&measurement, now()?)?;
    let candidate_cap = 512u64 << 30;
    let qualification = bound(&cfg["preparer_qualification"])?;
    let image = cfg["preparer_image"].as_str().context("preparer image")?;
    ensure!(
        image
            == "/var/lib/jetstreamer/horizon_runtime_data/epoch167-retry8-recovery-20261120-v1/prepare-v2/prepare"
            && qualification["schema"] == "horizon-retry8-independent166-preparer-build-proof-v2"
            && qualification["source_commit_verified_on_origin_account_updates"] == true
            && qualification["tests_failed"] == 0
            && qualification["production"]["sha256"] == sha(&fs::read(image)?),
        "current published qualified preparer required"
    );
    let mut review = bound(&plan["review"])?;
    let mut working = bound(&plan["retry3"]["concurrent_working_set"])?;
    let mut input = bound(&plan["input_proof"])?;
    ensure!(
        input["epoch"] == 167
            && input["local_inputs"] == plan["local_inputs"]
            && input["authentication_qualified"] == false
            && input["network_GCS_probe_performed"] == false,
        "exact local input route template"
    );
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
    working["retained_epoch167_additive_data_booking"] =
        plan["retry167"]["additive_data_booking"].clone();
    working["candidate_root_cap_bytes"] = json!(candidate_cap);
    working["additive_root_cap_reservation_bytes"] = json!(candidate_cap - CAP);
    working["protected166_root_cap_bytes"] = json!(CAP);
    working["stopped170_root_cap_bytes"] = json!(CAP);
    working["retained_retry6_166_DATA_bytes"] = json!(CAP);
    working
        .as_object_mut()
        .context("working set object")?
        .remove("terminal166_retained");
    let admission = bound(&cfg["peer_admission"])?;
    let peer_preparation = bound(&admission["fresh_native_Rust_preparation"])?;
    let peer_lane = declared_peer_lane(&admission, &peer_preparation)?;
    let rows = working["lanes"]
        .as_array_mut()
        .context("four working set rows")?;
    ensure!(
        rows.len() == 4
            && rows
                .iter()
                .filter_map(|r| r["epoch"].as_u64())
                .collect::<BTreeSet<_>>()
                == BTreeSet::from([166, 167, 169, 170]),
        "complete working set"
    );
    for row in rows {
        match row["epoch"].as_u64().context("row epoch")? {
            166 => {
                *row = peer_lane.clone();
            }
            167 => {
                *row = json!({"epoch":167,"state":"candidate","producer_unit":plan["producer_unit"],
                "retained_lane_physical_bytes":retained,"remaining_growth_bytes":candidate_cap-retained})
            }
            170 => {
                row["producer_unit"] =
                    json!("horizon-qualify-170-replacement-local3retry4-20261110-v1.service");
                row["invocation_id"] = json!("aabba5ff4c8e4c22ad18c80472713aa9");
                row["terminal_event"] =
                    plan["resident_memory"]["terminal170"]["stop_completion"].clone();
            }
            169 => (),
            _ => unreachable!(),
        }
    }
    plan["retry3"]["concurrent_working_set"] =
        binding(&write(root, "CONCURRENT_WORKING_SET.json", &working)?)?;
    let slot = json!({"schema":"horizon-standard-replacement-exclusive-slot-mapping-v1","owner":"/root",
        "epoch":167,"recorded_unix_seconds":now()?,"physical_ledger":cfg["measurement"],
        "retained_lane_physical_bytes":retained,"combined_original_lane_cap_bytes":candidate_cap,
        "old_remaining_future_promise_bytes":CAP-retained,"proposed_fresh_working_maximum_bytes":candidate_cap-retained,
        "additional_DATA_bytes":candidate_cap-CAP,"all_original_promises_retained":true,
        "guard_root_remains_whole_original_lane":true,"original_stop":measurement["original_stop"],
        "replay_launch_authorized":false});
    review["exact_slot_mapping_and_physical_ledger"] =
        binding(&write(root, "EXCLUSIVE_SLOT_MAPPING.json", &slot)?)?;
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
    review["existing_original_slot_future_growth_bytes"] = json!(CAP - retained);
    review["proposed_fresh_working_maximum_bytes"] = json!(candidate_cap - retained);
    review["candidate_remaining_growth_bytes"] = json!(candidate_cap - retained);
    review["additional_growth_not_covered_by_existing_promise_bytes"] = json!(candidate_cap - CAP);
    plan["review"] = binding(&write(root, "PRELAUNCH_REVIEW.json", &review)?)?;
    write(root, "PREPARE_PLAN.json", plan)
}
fn previous_plan() -> Result<Value> {
    read_bound(Path::new(OLD_PLAN), OLD_SHA)
}

fn book(root: &Path, plan: &Value, fleet: &Value, tag: &str) -> Result<Value> {
    ensure!(
        tag.len() == 14
            && tag.as_bytes()[..8].iter().all(u8::is_ascii_digit)
            && tag.as_bytes()[8] == b'T'
            && tag.as_bytes()[9..13].iter().all(u8::is_ascii_digit)
            && tag.as_bytes()[13] == b'Z',
        "booking timestamp must be YYYYMMDDTHHMMZ"
    );
    let previous = &plan["retry167"]["additive_data_booking"];
    let mut b = bound(previous)?;
    let owner = independent166::actual_owner()?;
    ensure!(
        b["owner"] == "/root"
            && b["primary_thread"] == THREAD
            && b["epoch"] == 167
            && b["candidate_root_cap_bytes"] == 512u64 << 30
            && b["raw_floor_bytes"] == RAW_FLOOR
            && b["complete_DATA_bytes"] == COMPLETE_DATA
            && b["reservation_booked"] == true
            && b["all_prior_promises_retained"] == true,
        "historical 167 reservation changed"
    );
    b["attempt"] = json!("local3retry8");
    b["previous_retry7_reservation"] = previous.clone();
    b["source_fleet"] = fleet.clone();
    b["protected166_admission"] = owner["admission"].clone();
    b["protected166_guard"] = owner["guard_protection"].clone();
    b["independent166_full_additional_bytes"] = json!(CAP);
    b["independent166_bootstrap_event"] = pair(BOOT, BOOT_SHA);
    b["recorded_unix_seconds"] = json!(now()?);
    let directory = base().join("booking");
    private(&directory)?;
    let name = format!("ROOT_DATA_BOOKING-{tag}.json");
    let record = binding(&write(&directory, &name, &b)?)?;
    write(root, "BOOKING_BINDING.json", &record)?;
    Ok(record)
}
fn staging() -> PathBuf {
    base().join("staging")
}
fn stage_root(tag: &str) -> Result<PathBuf> {
    ensure!(
        !tag.is_empty()
            && tag.len() <= 48
            && tag.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "invalid unique stage tag"
    );
    ensure!(
        fs::metadata(base())?.dev() == fs::metadata("/home/sol")?.dev(),
        "runtime is not on HOME"
    );
    let parent = staging();
    private(&parent)?;
    let root = parent.join(tag);
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .context("unique stage tag already used or inaccessible")?;
    File::open(parent)?.sync_all()?;
    private(&root)?;
    Ok(root)
}
fn generated(path: &str, component: &str, file_name: &str) -> Result<()> {
    let path = Path::new(path);
    let relative = path.strip_prefix(base().join(component))?;
    ensure!(
        path.canonicalize()? == path
            && relative.components().count() == 2
            && path.file_name().is_some_and(|n| n == file_name),
        "unexpected stage receipt path"
    );
    Ok(())
}
fn emit(root: &Path, images: &Value, plan: &Value, mode: &str) -> Result<()> {
    let prepare = &images["prepare"];
    let out = base().join("preparation");
    private(&out)?;
    private(&out.join("epoch167"))?;
    private(&out.join("epoch167/local3retry8"))?;
    let path = write(
        root,
        if mode == "--prepare" {
            "PREPARE_PLAN.json"
        } else {
            "MEASURE_PLAN.json"
        },
        plan,
    )?;
    let b = binding(&path)?;
    println!(
        "{}",
        json!({"plan":b,"preparer_argv":[prepare["path"],b["path"],"--plan-sha256",b["sha256"],"--self-sha256",prepare["sha256"],mode]})
    );
    Ok(())
}
fn images() -> Result<Value> {
    let root = base().join("prepare-v2");
    let guard_dir = base().join("guard-v1");
    let guard = binding(&guard_dir.join("guard"))?;
    ensure!(
        guard["sha256"] == "7f3b53a6a316a91ea868fdb9fb17cb4e8585cfd32c91afc7122a91ce86db94fe",
        "qualified guard image changed"
    );
    let prepare = binding(&root.join("prepare"))?;
    let proof = binding(&root.join("artifact-proof.json"))?;
    let seal: Value =
        serde_json::from_slice(&fs::read(root.join("deployment-seal-receipt.json"))?)?;
    let attestation = bound(&proof)?;
    prepare_proof::tested_independent_baseline(&attestation)?;
    ensure!(
        root.canonicalize()? == root
            && fs::metadata(&root)?.dev() == fs::metadata("/home/sol")?.dev()
            && seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == root.to_str().context("prepare path")?
            && seal["sealer_sha256"] == SEALER_SHA
            && seal["remote_mutations"] == false
            && seal["members"].as_array().is_some_and(|rows| rows
                .iter()
                .any(|r| r["name"] == "prepare"
                    && r["mode"] == "0555"
                    && r["sha256"] == prepare["sha256"])
                && rows.iter().any(|r| r["name"] == "artifact-proof.json"
                    && r["mode"] == "0444"
                    && r["sha256"] == proof["sha256"]))
            && attestation["schema"] == "horizon-retry8-independent166-preparer-build-proof-v2"
            && attestation["source_commit_verified_on_origin_account_updates"] == true
            && attestation["production"]["sha256"] == prepare["sha256"]
            && attestation["tests_failed"] == 0
            && n(&attestation, "tests_passed")? >= 321,
        "prepared native image, source, qualification or deployed member differs"
    );
    Ok(json!({"guard": guard, "prepare":prepare, "qualification":proof}))
}

fn run(a: &[String]) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0 && a.len() >= 4 && a[a.len() - 2] == "--self-sha256",
        "root stage must be invoked with its digest"
    );
    let exe = fs::read_link("/proc/self/exe")?;
    ensure!(
        exe == base().join("stage-v1/stage167") && sha(&fs::read(&exe)?) == a[a.len() - 1],
        "stage deployment changed"
    );
    let original = previous_plan()?;
    match &a[1..a.len() - 2] {
        [mode] if mode == "bind-launch" => {
            let path = base().join("preparation/epoch167/local3retry8/prepared.json");
            let prepared = binding(&path)?;
            let record = bound(&prepared)?;
            ensure!(
                record["schema"] == "horizon-standard-replacement-recipe-preparation-v1"
                    && record["owner"] == "/root"
                    && record["primary_thread"] == THREAD
                    && record["epoch"] == 167
                    && record["attempt"] == "local3retry8"
                    && record["replay_launched"] == false
                    && record["remote_mutations"] == false,
                "wrong preparation for launch"
            );
            let contract = &record["data_fulfillment"]["contract"];
            bound(&contract["contract"])?;
            bound(&contract["deployment_seal"])?;
            let root = base().join("launch-state");
            let dest = root.join("epoch167");
            private(&root)?;
            private(&dest)?;
            private(&base().join("guard-plans"))?;
            ensure!(
                fs::read_dir(&dest)?.next().is_none(),
                "launch output already used"
            );
            let plan = json!({"schema":"horizon-retry8-single167-launch-plan-v1",
                "owner":"/root","primary_thread":THREAD,"launch_authorized":true,
                "output_root":dest,"prepared":prepared,"data_fulfillment":contract});
            println!("{}", binding(&write(&root, "launch-plan.json", &plan)?)?);
        }
        [mode, fp, fsum] if mode == "check-fleet" => {
            let f = read_bound(Path::new(fp), fsum)?;
            check_observer(&f)?;
            let plan = plan_shape(&original, &f)?;
            println!(
                "{}",
                json!({"closed_units":plan["closed_units"].as_array().unwrap().len(),"owner":independent166::actual_owner()?,
                "source_fleet":pair(fp,fsum),"replay_launch_authorized":false})
            );
        }
        [mode, tag, stamp, fp, fsum, wp, ws] if mode == "measure" => {
            let fb = pair(fp, fsum);
            let f = bound(&fb)?;
            check_observer(&f)?;
            let images = images()?;
            let mut p = plan_shape(&original, &f)?;
            let root = stage_root(tag)?;
            let fleet = capture_fleet(&root, &p, &fb, f)?;
            p["retry167"]["additive_data_booking"] = book(&root, &p, &fleet, stamp)?;
            p["fleet"] = fleet;
            p["data_fulfillment"] =
                fulfillment(&root, &pair(wp, ws), &original, &images, u64::MAX)?;
            emit(&root, &images, &p, "--measure-only")?;
        }
        [mode, tag, mp, ms, lp, ls, wp, ws] if mode == "prepare" => {
            generated(mp, "staging", "MEASURE_PLAN.json")?;
            let mut p = read_bound(Path::new(mp), ms)?;
            let fleet = bound(&p["fleet"])?;
            check_observer(&fleet)?;
            fresh(&fleet, "recorded_unix_seconds", now()?, 180)?;
            let origin = bound(&fleet["previous_Root_operational_review"])?;
            check_observer(&origin)?;
            let expected = plan_shape(&original, &origin)?;
            for (key, value) in expected.as_object().context("template")? {
                if !["fleet", "data_fulfillment", "retry167"].contains(&key.as_str()) {
                    ensure!(&p[key] == value, "measure template differs at {key}");
                }
            }
            let mut req = expected["retry167"].clone();
            let stage = Path::new(mp).parent().context("measure tag")?;
            ensure!(
                p["fleet"]["path"]
                    == stage
                        .join("ROOT_COMPLETE_OPERATIONAL_FLEET.json")
                        .to_str()
                        .context("fleet path")?,
                "measure plan and fleet belong to different stages"
            );
            let booking: Value =
                serde_json::from_slice(&fs::read(stage.join("BOOKING_BINDING.json"))?)?;
            let booked = bound(&booking)?;
            ensure!(
                booked["source_fleet"] == p["fleet"]
                    && booked["independent166_bootstrap_event"] == pair(BOOT, BOOT_SHA)
                    && booked["previous_retry7_reservation"]
                        == expected["retry167"]["additive_data_booking"],
                "booking differs from measure plan"
            );
            req["additive_data_booking"] = booking;
            ensure!(
                p["retry167"] == req,
                "candidate retirement or booking changed after measurement"
            );
            let ledger = Path::new(lp);
            ensure!(
                ledger.parent() == Some(base().join("preparation/epoch167/local3retry8").as_path())
                    && ledger
                        .file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|s| s.starts_with("physical-") && s.ends_with(".json")),
                "wrong physical ledger path"
            );
            let measurement = pair(lp, ls);
            let m = bound(&measurement)?;
            ensure!(
                m["fleet"] == p["fleet"] && m["epoch"] == 167,
                "physical ledger and staged fleet differ"
            );
            let images = images()?;
            let root = stage_root(tag)?;
            p["data_fulfillment"] = fulfillment(&root, &pair(wp, ws), &original, &images, 120)?;
            let owner = independent166::actual_owner()?;
            let cfg = json!({"measurement":measurement, "preparer_qualification":images["qualification"],
                "preparer_image":images["prepare"]["path"],"peer_admission":owner["admission"]});
            let census = Path::new(
                fleet["full_current_proc_and_unit_census"]["path"]
                    .as_str()
                    .context("census")?,
            );
            let final_plan = prepare_review(&cfg, &root, &mut p, census)?;
            let b = binding(&final_plan)?;
            println!(
                "{}",
                json!({"plan":b,"preparer_argv":[images["prepare"]["path"],b["path"],"--plan-sha256",b["sha256"],"--self-sha256",images["prepare"]["sha256"],"--prepare"]})
            );
        }
        _ => anyhow::bail!(
            "check-fleet FLEET SHA | measure TAG YYYYMMDDTHHMMZ FLEET SHA WITNESS SHA | prepare TAG MEASURE_PLAN SHA LEDGER SHA FRESH_WITNESS SHA; append --self-sha256 SHA"
        ),
    }
    Ok(())
}
fn main() -> Result<()> {
    run(&std::env::args().collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cold_peer_row_never_credits_the_standard_ledger() {
        let owner: Value = serde_json::from_str(include_str!("../peer/actual-owner.json")).unwrap();
        let admission = bound(&owner["admission"]).unwrap();
        let prepared = bound(&admission["fresh_native_Rust_preparation"]).unwrap();
        assert_eq!(
            prepared["actual_full_lane_ledger"]["physical_bytes"],
            269_184_225_280u64
        );
        let row = declared_peer_lane(&admission, &prepared).unwrap();
        assert_eq!(row["retained_lane_physical_bytes"], 0);
        assert_eq!(row["remaining_growth_bytes"], CAP);
    }
    #[test]
    fn current_plan_uses_the_historical_167_root_and_preserves_other_owners() {
        let original = previous_plan().unwrap();
        let owner: Value = serde_json::from_str(include_str!("../peer/actual-owner.json")).unwrap();
        let fleet = json!({"observer":{"path":"/sample","sha256":"1".repeat(64)},
            "authenticated_inventory":original["inventory"]});
        let p = plan_shape_for_owner(&original, &fleet, &owner).unwrap();
        let closed: BTreeSet<String> = serde_json::from_value(p["closed_units"].clone()).unwrap();
        assert_eq!(closed.len(), 64);
        assert!(closed.contains(UNIT));
        assert!(!closed.contains(PEER));
        assert!(
            closed.contains("horizon-qualify-166-replacement-local3retry8-20261110-v1.service")
        );
        assert_eq!(p["local_inputs"], original["local_inputs"]);
        assert_eq!(p["resident_memory"]["owners"], json!([owner]));
        assert_eq!(
            p["fresh_subtree"],
            format!("{HIST}/replacement-local3retry8-20261110-v1")
        );
    }
    #[test]
    fn checked_ledger_rejects_age_and_wrong_root() {
        let mut m = json!({"schema":"horizon-standard-replacement-local-physical-ledger-v1",
          "owner":"/root","epoch":167,"read_only":true,"replay_launch_authorized":false,"resource_credit_bytes":0,
          "physical":{"physical_bytes":248085250048u64},"recorded_unix_seconds":100,"lane_root":HIST});
        assert_eq!(retained_measurement(&m, 101).unwrap(), 248085250048);
        assert!(retained_measurement(&m, 1901).is_err());
        m["lane_root"] = json!("/home/sol");
        assert!(retained_measurement(&m, 101).is_err());
    }
}
