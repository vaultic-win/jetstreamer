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
        "/usr/local/lib/jetstreamer/horizon-independent166-singleton-package-20261109-v1/jetstreamer-node",
        "/usr/local/lib/jetstreamer/horizon-independent166-singleton-package-20261109-v1/jetstreamer-historical-worker-v1-5-6",
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
const BASE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch166-independent-cold-20261120-v1";
const HIST: &str = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1";
const COLD: &str = "/home/sol/.jetstreamer-private/epoch166-independent-cold-20261120-v1";
const UNIT: &str = "horizon-qualify-independent-cold166-20261120-v1.service";
const GUARD_BASE: &str = "horizon-guard-independent-cold166-20261120-v1";
const CAP: u64 = 309_237_645_312;
const FLOOR: u64 = 6_829_053_656_882;
const OLD_PLAN: &str = "/var/lib/jetstreamer/retry8-166-stage-20261119-v1/0147/PREPARE_PLAN.json";
const OLD_SHA: &str = "223d16e6fb41c1f79c6dfa52bf6d52318c8e2e34ff05f3ad875e0af74749a5cb";
const FLEET: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch166-retry9-recovery-20261120-v1/fleet0315-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json";
const FLEET_SHA: &str = "422426a655ede66eb5ea4f1fb7cbe8a1830a459de6aac2f0066f098d1847ac05";
const OLD_ROOTS: &str = "/var/lib/jetstreamer/horizon_runtime_data/root-zero-166167-stop-20261120-v1/SUCCESSOR_ROOTS_BEFORE_WITNESS.json";
const OLD_ROOTS_SHA: &str = "d9e8ae44c9726811b2104cac494b4ccc4a5ef3cb7bf56e5cadec6bf6f9b4be89";
const NEW_ROOTS: &str = "/var/lib/jetstreamer/horizon_runtime_data/root0245-zero-recovery-20261120-v1/INDEPENDENT_COLD_ROOTS_BEFORE_WITNESS.json";
const NEW_ROOTS_SHA: &str = "40bd46800a52705e1dcb485edb09f36d8122adb541e430a4b549caa92f13c7fa";
const QUAL: &str = "/var/lib/jetstreamer/horizon_runtime_data/root0315-zero-recovery-20261120-v1/INDEPENDENT_166_QUALIFIED.json";
const QUAL_SHA: &str = "f1e7c581706ca034775328632d1ed70512466b3d69c7d2078d45f1eb7db62e0d";
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
    let mut p = original.clone();
    let obj = p.as_object_mut().context("template")?;
    ensure!(
        obj.remove("retry8_precreated_roots").is_some(),
        "wrong template"
    );
    p["attempt"] = json!("local3retry9");
    p["producer_unit"] = json!(UNIT);
    p["guard_base"] = json!(GUARD_BASE);
    p["fresh_subtree"] = json!(Path::new(COLD).join("replacement-local3retry9-20261110-v1"));
    p["retry9_precreated_roots"] = pair(OLD_ROOTS, OLD_ROOTS_SHA);
    p["resident_memory"]["observer"] = fleet["observer"].clone();
    p["resident_memory"]["owners"] = json!([]);
    p["inventory"] = fleet["authenticated_inventory"].clone();
    let mut units: BTreeSet<String> = serde_json::from_value(p["closed_units"].clone())?;
    for (e, g) in [(166, 7), (166, 8), (166, 9), (167, 6), (167, 7), (170, 6)] {
        units.insert(format!(
            "horizon-qualify-{e}-replacement-local3retry{g}-20261110-v1.service"
        ));
        for suffix in ["timer", "service"] {
            units.insert(format!(
                "horizon-guard-replacement-{e}-local3retry{g}-20261110-v1.{suffix}"
            ));
        }
    }
    units.extend([
        UNIT.to_string(),
        format!("{GUARD_BASE}.timer"),
        format!("{GUARD_BASE}.service"),
    ]);
    ensure!(units.len() <= 64, "preparer census bound");
    p["closed_units"] = json!(units);
    Ok(p)
}
fn fleet_contract(v: &Value, reference: &Value) -> Result<()> {
    for key in [
        "owner",
        "primary_thread",
        "complete_DATA_bytes",
        "complete_projected_memory_bytes",
        "retained_retry6_166_DATA_bytes",
        "additional_retained_build_allocation",
        "retry9_auxiliary_commitments",
        "continuing_audit_obligation",
        "retry9_recovery_chain",
    ] {
        ensure!(
            !reference[key].is_null() && v[key] == reference[key],
            "missing or altered accepted fleet field {key}"
        );
    }
    let cycles = v["subsequent_zero_cycles"]
        .as_array()
        .context("fleet cycles")?;
    ensure!(
        cycles.starts_with(
            reference["subsequent_zero_cycles"]
                .as_array()
                .context("reference cycles")?
        ) && cycles
            .last()
            .is_some_and(|r| r["observer"] == v["observer"])
            && v["active_producer_count"] == 0
            && v["actual_executing_replays"] == json!([])
            && v["actual_active_bootstraps"] == json!([])
            && v["all_existing_memory_DATA_OS_native_transport_promises_retained"] == true,
        "expected reconciled zero-owner fleet with 03:15 ancestry"
    );
    Ok(())
}
fn check_observer(fleet: &Value) -> Result<()> {
    let observer = bound(&fleet["observer"])?;
    ensure!(
        observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && observer["replays"] == json!([])
            && utc_now()?.as_str()
                < observer["cadence"]["next_routine_observation_not_before_utc"]
                    .as_str()
                    .context("observation deadline")?,
        "coordinated observation expired or advancing replay exists"
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
    ensure!(process_claims()?.is_empty(), "166 source process found");
    let second = native(&target)?;
    for unit in &target {
        ensure!(
            first[unit] == second[unit] && closed(&second[unit]),
            "owner changed: {unit}"
        );
    }
    ensure!(process_claims()?.is_empty(), "166 source process appeared");
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
    let roots = read_bound(Path::new(NEW_ROOTS), NEW_ROOTS_SHA)?;
    let old = read_bound(Path::new(OLD_ROOTS), OLD_ROOTS_SHA)?;
    ensure!(
        w["schema"] == "horizon-original-slot-DATA-native-witness-qualification-v1"
            && w["owner"] == "/root"
            && w["primary_thread"] == THREAD
            && w["native_identity"]["executable"] == guard["path"]
            && w["native_identity"]["executable_sha256"] == guard["sha256"]
            && w["independent_roots_receipt"] == pair(NEW_ROOTS, NEW_ROOTS_SHA)
            && w["witness_set"] == c["witness_set"]
            && w["witness_set_deployment_seal"] == c["witness_set_deployment_seal"]
            && n(w, "started_unix_seconds")? >= n(&roots, "at")?.max(n(&old, "captured")?)
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
fn measured(m: &Value, fleet: &Value, at: u64) -> Result<u64> {
    let retained = n(&m["physical"], "physical_bytes")?;
    ensure!(
        m["schema"] == "horizon-standard-replacement-local-physical-ledger-v1"
            && m["owner"] == "/root"
            && m["epoch"] == 166
            && m["lane_root"] == HIST
            && m["fleet"] == *fleet
            && m["read_only"] == true
            && m["resource_credit_bytes"] == 0
            && m["replay_launch_authorized"] == false
            && (1..=CAP).contains(&retained),
        "measurement not for historical epoch 166 and this exact staged fleet"
    );
    fresh(m, "recorded_unix_seconds", at, 1800)?;
    Ok(retained)
}
fn mapping(fleet: &Value, m: &Value, retained: u64) -> Value {
    json!({"schema":"horizon-independent-cold166-DATA-mapping-v1","owner":"/root","epoch":166,"fleet":fleet,"historical_lane":HIST,"independent_lane":COLD,"retained_original_cap_bytes":CAP,"new_independent_cap_bytes":CAP,"physical_ledger":m,"retained_lane_physical_bytes":retained,"resource_credit_bytes":0,"resource_promise_ending_bytes":0})
}
fn working(fleet: &Value, at: u64) -> Value {
    json!({"schema":"horizon-retry3-concurrent-working-set-v1","owner":"/root","recorded_unix_seconds":at,"fleet":fleet,"forecast_offloads_credited_bytes":0,"retained_promises_released_bytes":0,"immutable_raw_guard_floor_bytes":FLOOR,"unrelated_growth_margin_bytes":10u64<<30,"lanes":[{"epoch":166,"state":"candidate","producer_unit":UNIT,"retained_lane_physical_bytes":0,"remaining_growth_bytes":CAP}]})
}
fn original_plan() -> Result<Value> {
    read_bound(Path::new(OLD_PLAN), OLD_SHA)
}
fn finish_plan(root: &Path, p: &mut Value, measurement: &Value) -> Result<()> {
    let m = bound(measurement)?;
    let fleet = bound(&p["fleet"])?;
    check_observer(&fleet)?;
    let time = now()?;
    fresh(&fleet, "recorded_unix_seconds", time, 180)?;
    let retained = measured(&m, &p["fleet"], time)?;
    let mut input = bound(&p["input_proof"])?;
    ensure!(
        input["local_inputs"] == p["local_inputs"]
            && input["authentication_qualified"] == false
            && input["network_GCS_probe_performed"] == false,
        "unexpected authenticated or nonlocal input request"
    );
    input["recorded_unix_seconds"] = json!(time);
    p["input_proof"] = binding(&write(root, "LOCAL_INPUT_REQUEST.json", &input)?)?;
    let mut r = bound(&p["review"])?;
    for (to, from) in [
        ("source_fleet", "fleet"),
        ("source_inventory", "inventory"),
        ("input_proof", "input_proof"),
        ("cleanup_completion", "cleanup_completion"),
        ("data_fulfillment", "data_fulfillment"),
        ("attempt", "attempt"),
    ] {
        r[to] = p[from].clone();
    }
    r["recorded_unix_seconds"] = json!(time);
    r["full_current_proc_and_unit_census"] = fleet["full_current_proc_and_unit_census"].clone();
    r["exclusive_original_slot_replacement"] = json!(false);
    r["retained_lane_physical_bytes"] = json!(retained);
    r["existing_original_slot_future_growth_bytes"] = json!(CAP - retained);
    for key in [
        "proposed_fresh_working_maximum_bytes",
        "candidate_remaining_growth_bytes",
        "additional_growth_not_covered_by_existing_promise_bytes",
    ] {
        r[key] = json!(CAP);
    }
    r["minimum_initial_available_data_bytes"] =
        json!(FLOOR + CAP + (10u64 << 30) + n(&r, "fresh_subtree_overlap_booked_bytes")?);
    r["exact_slot_mapping_and_physical_ledger"] = binding(&write(
        root,
        "INDEPENDENT_SLOT_MAPPING.json",
        &mapping(&p["fleet"], measurement, retained),
    )?)?;
    p["retry3"]["concurrent_working_set"] = binding(&write(
        root,
        "WORKING_SET.json",
        &working(&p["fleet"], time),
    )?)?;
    p["review"] = binding(&write(root, "PRELAUNCH_REVIEW.json", &r)?)?;
    Ok(())
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
    private(&out.join("epoch166"))?;
    private(&out.join("epoch166/local3retry9"))?;
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
fn run(a: &[String]) -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "Root required");
    ensure!(
        a.len() >= 4 && a[a.len() - 2] == "--self-sha256",
        "explicit stage digest required"
    );
    let exe = fs::read_link("/proc/self/exe")?;
    ensure!(
        exe == base().join("stage-v2/stage166") && sha(&fs::read(&exe)?) == a[a.len() - 1],
        "sealed stage image mismatch"
    );
    let args = &a[1..a.len() - 2];
    let mut q = read_bound(Path::new(QUAL), QUAL_SHA)?;
    // Same qualified guard and launcher; the larger historical ledger requires the v2 preparer.
    q["images"]["prepare"] = json!({"path":base().join("prepare-v2/prepare"),"sha256":"46ad9a36b93867aea4df446e7f4404f1b955f19fe7156f90e577f24c7da26cf9"});
    let images = &q["images"];
    for (key, name) in [
        ("guard", "guard-v1/guard"),
        ("prepare", "prepare-v2/prepare"),
        ("launch", "launch-v1/launch"),
    ] {
        ensure!(
            binding(&base().join(name))? == images[key],
            "deployed {key} changed"
        );
    }
    let original = original_plan()?;
    match args {
        [mode, tag, path, digest, wp, ws] if mode == "measure" => {
            let reference = read_bound(Path::new(FLEET), FLEET_SHA)?;
            let fb = pair(path, digest);
            let fleet = bound(&fb)?;
            fleet_contract(&fleet, &reference)?;
            check_observer(&fleet)?;
            let mut p = plan_shape(&original, &fleet)?;
            let root = stage_root(tag)?;
            p["fleet"] = capture_fleet(&root, &p, &fb, fleet)?;
            p["data_fulfillment"] = fulfillment(&root, &pair(wp, ws), &original, images, u64::MAX)?;
            emit(&root, images, &p, "--measure-only")
        }
        [mode, tag, mp, ms, lp, ls, wp, ws] if mode == "prepare" => {
            generated(mp, "staging", "MEASURE_PLAN.json")?;
            let measure_binding = pair(mp, ms);
            let mut p = bound(&measure_binding)?;
            let source = bound(&p["fleet"])?;
            let origin = bound(&source["previous_Root_operational_review"])?;
            fleet_contract(&origin, &read_bound(Path::new(FLEET), FLEET_SHA)?)?;
            let expected = plan_shape(&original, &origin)?;
            for (k, v) in expected.as_object().context("template")? {
                if k != "fleet" && k != "data_fulfillment" {
                    ensure!(p[k] == *v, "altered measurement template field {k}");
                }
            }
            ensure!(
                Path::new(mp)
                    .parent()
                    .context("measure tag")?
                    .join("ROOT_COMPLETE_OPERATIONAL_FLEET.json")
                    == Path::new(p["fleet"]["path"].as_str().context("staged fleet")?),
                "measurement fleet not in same stage"
            );
            let ledger = Path::new(lp);
            ensure!(
                ledger.parent() == Some(base().join("preparation/epoch166/local3retry9").as_path())
                    && ledger
                        .file_name()
                        .and_then(|x| x.to_str())
                        .is_some_and(|s| s.starts_with("physical-") && s.ends_with(".json")),
                "use the actual preparer ledger receipt"
            );
            let root = stage_root(tag)?;
            p["data_fulfillment"] = fulfillment(&root, &pair(wp, ws), &original, images, 120)?;
            finish_plan(&root, &mut p, &pair(lp, ls))?;
            emit(&root, images, &p, "--prepare")
        }
        _ => anyhow::bail!(
            "measure TAG FLEET SHA WITNESS SHA | prepare TAG MEASURE_PLAN SHA LEDGER SHA WITNESS SHA; append --self-sha256 SHA"
        ),
    }
}
fn main() -> Result<()> {
    run(&std::env::args().collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_0315_fleet_and_original_producer_preserve_inputs_and_obligations() {
        let f = read_bound(Path::new(FLEET), FLEET_SHA).unwrap();
        fleet_contract(&f, &f).unwrap();
        let prior = original_plan().unwrap();
        let p = plan_shape(&prior, &f).unwrap();
        assert_eq!(p["local_inputs"], prior["local_inputs"]);
        assert_eq!(p["resident_memory"]["observer"], f["observer"]);
        assert!(p.get("retry8_precreated_roots").is_none());
        assert!(p["closed_units"].as_array().unwrap().contains(&json!(
            "horizon-qualify-170-replacement-local3retry6-20261110-v1.service"
        )));
        let mut altered = f.clone();
        altered["continuing_audit_obligation"] = Value::Null;
        assert!(fleet_contract(&altered, &f).is_err());
    }
    #[test]
    fn witness_fixture_matches_both_accepted_root_receipts_but_expires_for_prepare() {
        let wb = pair(
            &format!("{BASE}/native-witness-v1/NATIVE_WITNESS.json"),
            "e41a39159dcd2942c4f3b4b60ba5db54fe767147b86fe9a90167ff767da697bb",
        );
        let w = bound(&wb).unwrap();
        let q = read_bound(Path::new(QUAL), QUAL_SHA).unwrap();
        let template =
            bound(&original_plan().unwrap()["data_fulfillment"]["contract"]["contract"]).unwrap();
        let clock = n(&w, "recorded_unix_seconds").unwrap();
        assert_eq!(
            witness_contract(&template, &w, &wb, &q["images"]["guard"], clock, 120).unwrap()["qualified_native_witness"],
            wb
        );
        assert!(
            witness_contract(&template, &w, &wb, &q["images"]["guard"], clock + 121, 120).is_err()
        );
    }
    #[test]
    fn historic_ledger_cannot_change_fleet_or_reduce_the_new_cap() {
        let f = pair(FLEET, FLEET_SHA);
        let mut m = json!({"schema":"horizon-standard-replacement-local-physical-ledger-v1","owner":"/root","epoch":166,"read_only":true,"resource_credit_bytes":0,"replay_launch_authorized":false,"lane_root":HIST,"fleet":f,"physical":{"physical_bytes":CAP-1},"recorded_unix_seconds":100});
        let retained = measured(&m, &f, 101).unwrap();
        assert_eq!(
            mapping(&f, &Value::Null, retained)["new_independent_cap_bytes"],
            CAP
        );
        assert_eq!(working(&f, 101)["lanes"][0]["remaining_growth_bytes"], CAP);
        m["fleet"] = Value::Null;
        assert!(measured(&m, &f, 101).is_err());
    }
}
