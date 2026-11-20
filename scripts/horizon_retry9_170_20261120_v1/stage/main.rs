#[path = "../terminal8.rs"]
mod terminal8;
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
#[path = "../../horizon_audit79_budget_v10_20261120_v1/audit_budget.rs"]
mod audit_budget;
#[path = "../../horizon_170_join_independent166_20261120_v1/peer.rs"]
mod join_peer;

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
const STAGE_IMAGE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry9-recovery-20261120-v1/stage-v2/stage";
const PREPARER: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry9-recovery-20261120-v1/prepare-v2/prepare";
const PREPARER_SHA: &str = env!("HORIZON170_RETRY9_PREPARE_SHA");
const PREPARER_PROOF_SHA: &str = env!("HORIZON170_RETRY9_PREPARE_PROOF_SHA");
const LAUNCHER_SHA: &str = env!("HORIZON170_RETRY9_LAUNCH_SHA");
const GUARD: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry9-recovery-20261120-v1/guard-v1/guard";
const GUARD_SHA: &str = "b2271db6f25696612c388297db3a10852f7911560887f67dcb404392d91f7016";
const TEMPLATE: &str =
    "/var/lib/jetstreamer/epoch170-retry5-recovery-20261117-v1/measure0743-v3/PLAN-FINAL.json";
const TEMPLATE_SHA: &str = "e7133f6349619370806f475b1c1511cd505e456da330c3f9be38e6e12642de86";
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
const ROOT: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry9-recovery-20261120-v1/stage-state";
const FRESH: &str = "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/replacement-local3retry9-20261110-v1";
const STOP5: &str = "/var/lib/jetstreamer/retry3-preparation-20261113-v1/epoch170/local3retry5/guard-state/receipts/stop-completion.json";
const STOP5_SHA: &str = "1751d0ad7c16e58b7dec251908120275f8ea0bb1fc6fe85073e3d812a1618168";
const STOP6: &str = "/var/lib/jetstreamer/retry6-170-preparation-20261118-v1/epoch170/local3retry6/guard-state/receipts/stop-completion.json";
const STOP6_SHA: &str = "3601e2dabb55f7c3ca9ed8f91c253588f301b51a87c42ba9ece18f73fab48264";

const STOP7: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry7-recovery-20261120-v1/preparation/epoch170/local3retry7/guard-state/receipts/stop-completion.json";
const STOP7_SHA: &str = "a7b35a191ec0e07863aa0357b2e48e37ca18e3b3a1d49e2ea51fa8a53f0d5a28";
const INTENT7: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry7-recovery-20261120-v1/preparation/epoch170/local3retry7/guard-state/receipts/stop-intent.json";
const INTENT7_SHA: &str = "bdec2f5f6aefb0eb863ce6b9486ecf2e110fb16e9c4d00262126b4632a9425bf";

fn validate_retry7_event(fleet: &Value) -> Result<()> {
    let terminal = &fleet["latest_terminal170_observation"];
    ensure!(
        terminal["path"]
            == "/var/lib/jetstreamer/horizon_runtime_data/root0615-terminal170-recovery-20261120-v1/event.json"
            && terminal["sha256"]
                == "e6aa44d51e8375e10428372ad2e15d391a8ac866d7bdb39e6b979f75761b2760",
        "current fleet lost the retry7 terminal event"
    );
    let event = bound(terminal)?;
    ensure!(
        event["terminal_stop"] == fixed_binding(STOP7, STOP7_SHA)?
            && event["intent"] == fixed_binding(INTENT7, INTENT7_SHA)?,
        "retry7 terminal evidence differs"
    );
    Ok(())
}

fn fixed_binding(path: &str, expected: &str) -> Result<Value> {
    read_bound(Path::new(path), expected)?;
    Ok(json!({"path":path,"sha256":expected}))
}

fn retry9_route(plan: &mut Value) -> Result<()> {
    ensure!(
        plan["epoch"] == 170 && plan["attempt"] == "local3retry5",
        "exact historical retry5 template required"
    );
    plan["attempt"] = json!("local3retry9");
    plan["producer_unit"] =
        json!("horizon-qualify-170-replacement-local3retry9-20261110-v1.service");
    plan["guard_base"] = json!("horizon-guard-replacement-170-local3retry9-20261110-v1");
    plan["fresh_subtree"] = json!(FRESH);
    plan["current_allocation"]["schema"] = json!("horizon-epoch170-retry9-native-allocation-v1");
    let units = plan["closed_units"]
        .as_array_mut()
        .context("closed units")?;
    let mut unique = BTreeSet::new();
    for unit in units.iter() {
        ensure!(
            unique.insert(unit.as_str().context("closed unit name")?.to_owned()),
            "duplicate historical closed unit"
        );
    }
    // The retry5 template remains historical evidence. Keep every existing
    // entry and explicitly close stopped retries 4 through 8 and the proposed retry9.
    for attempt in 4..=9 {
        for unit in [
            format!("horizon-qualify-170-replacement-local3retry{attempt}-20261110-v1.service"),
            format!("horizon-guard-replacement-170-local3retry{attempt}-20261110-v1.service"),
            format!("horizon-guard-replacement-170-local3retry{attempt}-20261110-v1.timer"),
        ] {
            if unique.insert(unit.clone()) {
                units.push(json!(unit));
            }
        }
    }
    Ok(())
}

fn fresh_root_binding(cfg: &Value, dev: u64, ino: u64) -> Result<()> {
    let recorded = &cfg["fresh_subtree_identity"];
    ensure!(
        recorded["path"] == FRESH
            && recorded["device"]
                .as_u64()
                .is_some_and(|v| v > 0 && v == dev)
            && recorded["inode"]
                .as_u64()
                .is_some_and(|v| v > 0 && v == ino),
        "explicit retry9 fresh-root device/inode binding required"
    );
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
    if epoch == 166 {
        return (
            join_peer::UNIT,
            join_peer::IID,
            join_peer::PID,
            join_peer::START,
            "/var/lib/jetstreamer/horizon_runtime_data/epoch166-independent-cold-20261120-v1/launch-state/epoch166",
        );
    }
    let x = PEER167.get().expect("validated active167");
    (
        join_peer::NEXT167,
        &x.0,
        x.1,
        x.2,
        "/var/lib/jetstreamer/horizon_runtime_data/epoch167-retry8-recovery-20261120-v1/launch-state/epoch167",
    )
}
fn epochs() -> Vec<u64> {
    if PEER167.get().is_some() {
        vec![166, 167]
    } else {
        vec![166]
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
    let unit = format!("horizon-170-retry9-witness-{tag}-20261120.service");
    let dest = format!(
        "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry9-recovery-20261120-v1/data-contract-{tag}"
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
    working["schema"] = json!("horizon-epoch170-retry9-current-fleet-working-set-v1");
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
        if epochs().contains(&epoch) {
            let (unit, iid, _, _, prefix) = peer(epoch);
            let a = read(&format!("{prefix}/ACTUAL_REPLACEMENT_ADMISSION.json"))?;
            let prep = bound(&a["fresh_native_Rust_preparation"])?;
            let baseline = prep["actual_full_lane_ledger"]["physical_bytes"]
                .as_u64()
                .context("peer ledger")?;
            let cap = if epoch == 167 { 512u64 << 30 } else { CAP };
            ensure!(baseline > 0 && baseline < cap, "peer historical ledger");
            *row = json!({"epoch":epoch,"state":"active","producer_unit":unit,"invocation_id":iid,"retained_lane_physical_bytes":baseline,"remaining_growth_bytes":cap-baseline});
        } else if epoch == 167 {
            let old = read(
                "/var/lib/jetstreamer/retry7-single167-guarded-launch-20261119-v1/epoch167/ACTUAL_REPLACEMENT_ADMISSION.json",
            )?;
            let previous = bound(&old["fresh_native_Rust_preparation"])?;
            let baseline = previous["actual_full_lane_ledger"]["physical_bytes"]
                .as_u64()
                .context("closed 167 historical ledger")?;
            ensure!(
                baseline > 0 && baseline < (512u64 << 30),
                "closed167 baseline"
            );
            *row = json!({"epoch":167,"state":"terminal","stop_completion":join_peer::pair(join_peer::STOP167,join_peer::STOP167_SHA),"booking":plan["retry170"]["retained_epoch167_booking"],"retained_lane_physical_bytes":baseline,"remaining_growth_bytes":(512u64<<30)-baseline,"resource_credit_bytes":0});
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
        "current coordinated fleet and authenticated status required"
    );
    let mut plan = read_bound(Path::new(TEMPLATE), TEMPLATE_SHA)?;
    retry9_route(&mut plan)?;
    ensure!(
        observer["replays"]
            .as_array()
            .context("sample members")?
            .len()
            == epochs().len(),
        "observer owner count changed"
    );
    let previous = bound(&fleet["full_current_proc_and_unit_census"])?;
    let mut names = unit_names(&previous, &plan)?;
    for e in epochs() {
        names.insert(peer(e).0.into());
    }
    let before = native(&names)?;
    for e in epochs() {
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
    for e in epochs() {
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
                && obs["producer_after"]["main_pid"] == pid
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
    plan["retry170"]["stopped_retry5_170"] = fixed_binding(STOP5, STOP5_SHA)?;
    plan["retry170"]["stopped_retry6_170"] = fixed_binding(STOP6, STOP6_SHA)?;
    for (key, binding) in terminal8::authenticate(&fleet["latest_terminal_retry8_170"])?
        .as_object()
        .context("retry8 bindings")?
    {
        plan["retry170"][key] = binding.clone();
    }
    plan["retry170"]["stopped_retry7_170"] = fixed_binding(STOP7, STOP7_SHA)?;
    plan["retry170"]["stop_intent_retry7_170"] = fixed_binding(INTENT7, INTENT7_SHA)?;
    plan["retry170"]["stopped167_retry7"] =
        join_peer::pair(join_peer::STOP167, join_peer::STOP167_SHA);
    plan["retry170"]["retained_epoch167_booking"] = fixed_binding(
        "/var/lib/jetstreamer/epoch167-retry6-zeropeer-20261118-v1/ROOT_DATA_BOOKING-20261119T0647Z.json",
        "4b51da0a5b2c60f4039edca0f66a99c6acf46182c8cf9f89dee467d6f5d7d38c",
    )?;
    let guard_parent = Path::new(GUARD).parent().unwrap().display();
    plan["data_fulfillment"] = json!({"runtime":b(GUARD)?,"runtime_seal":b(&format!("{guard_parent}/deployment-seal-receipt.json"))?,
        "qualification":b(&format!("{guard_parent}/artifact-proof.json"))?,
        "contract":selected_contract(measurement.is_some())?});
    let after = native(&names)?;
    for e in epochs() {
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
    fleet["active_producer_count"] = json!(owners.len());
    fleet["live_replay_count"] = json!(executing.len());
    fleet["useful_replay_count"] = json!(executing.len());
    fleet["observer"] = b(cfg_path("observer")?)?;
    fleet["authenticated_status_audit"] = b(cfg_path("status")?)?;
    fleet["sole_next_observer"] = b(cfg_path("next_observer")?)?;
    fleet["admitted_independent166_capacity"] =
        join_peer::evidence()?["post_guard_capacity"].clone();
    if let Some(m) = measurement {
        let ledger = bound(&binding(m)?)?;
        let predecessor = bound(&ledger["fleet"])?;
        ensure!(
            predecessor["previous_Root_operational_review"]
                == fleet["previous_Root_operational_review"]
                && predecessor["admitted_independent166_capacity"]
                    == fleet["admitted_independent166_capacity"]
                && predecessor["observer"] == fleet["observer"]
                && predecessor["actual_executing_replays"] == fleet["actual_executing_replays"]
                && predecessor["actual_active_bootstraps"] == fleet["actual_active_bootstraps"],
            "measurement source/owners changed"
        );
        let then = predecessor["recorded_unix_seconds"]
            .as_u64()
            .context("measured fleet time")?;
        ensure!(
            now()?.checked_sub(then).is_some_and(|age| age <= 180),
            "measured fleet too old for launch gates"
        );
        plan["fleet"] = ledger["fleet"].clone();
    } else {
        plan["fleet"] = binding(&write(
            &root,
            "ROOT_COMPLETE_OPERATIONAL_FLEET.json",
            &fleet,
        )?)?;
    }
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
        json!({"plan":binding(&path)?,"fleet":plan["fleet"],"resource_promise_ending_bytes":0,"replay_launch_authorized":false})
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
        fs::read_link("/proc/self/exe")? == Path::new(STAGE_IMAGE)
            && sha(&fs::read("/proc/self/exe")?) == a[5],
        "sealed stage-v2 image path and self hash required"
    );
    launch_plan::published_sources()?;
    let cfg = read_bound(Path::new(&a[1]), &a[3])?;
    for k in ["fleet", "observer", "status", "inventory", "next_observer"] {
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
    validate_retry7_event(&fleet)?;
    terminal8::authenticate(&fleet["latest_terminal_retry8_170"])?;
    let authority = join_peer::evidence()?;
    join_peer::live(&authority)?;
    let owner_rows = join_peer::owners(&authority);
    ensure!(
        owner_rows.len() == 2,
        "retry8 requires both independent166 and retry8-167"
    );
    let expected = owner_rows
        .iter()
        .map(|row| row["epoch"].as_u64().unwrap())
        .collect::<BTreeSet<_>>();
    let active = fleet["actual_executing_replays"]
        .as_array()
        .context("replays")?
        .iter()
        .chain(
            fleet["actual_active_bootstraps"]
                .as_array()
                .context("bootstraps")?,
        )
        .collect::<Vec<_>>();
    ensure!(
        active.len() == expected.len()
            && active
                .iter()
                .filter_map(|v| v["epoch"].as_u64())
                .collect::<BTreeSet<_>>()
                == expected,
        "fleet does not represent every actual peer"
    );
    for o in &owner_rows {
        let row = active
            .iter()
            .find(|r| r["epoch"] == o["epoch"])
            .context("peer absent")?;
        ensure!(
            row["admission"] == o["admission"]
                && row["guard_protection"] == o["guard_protection"]
                && row["unit"]["Id"] == o["unit"]
                && row["unit"]["InvocationID"] == o["invocation_id"],
            "peer custody differs"
        );
    }
    if let Some(o) = owner_rows.get(1) {
        PEER167
            .set((
                o["invocation_id"].as_str().context("IID")?.into(),
                o["main_pid"].as_u64().context("PID")?,
                o["main_start_ticks"].as_u64().context("ticks")?,
            ))
            .map_err(|_| anyhow::anyhow!("duplicate167"))?;
    }
    CONFIG
        .set(cfg)
        .map_err(|_| anyhow::anyhow!("config initialized"))?;
    let repo = "/home/sol/workspace/jetstreamer";
    let own = "scripts/horizon_retry9_170_20261120_v1/stage/main.rs";
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
            ))?) == PREPARER_PROOF_SHA,
        "qualified preparer/proof changed"
    );
    let m = fs::symlink_metadata(FRESH)?;
    fresh_root_binding(CONFIG.get().context("config")?, m.dev(), m.ino())?;
    ensure!(
        m.is_dir()
            && m.uid() == 1001
            && m.mode() & 0o7777 == 0o700
            && m.dev() == fs::metadata("/home/sol")?.dev()
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
        rm.is_dir()
            && rm.uid() == 0
            && rm.mode() & 0o7777 == 0o700
            && rm.dev() == fs::metadata("/home/sol")?.dev()
            && Path::new(ROOT).canonicalize()? == Path::new(ROOT),
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
    fn retry9_requires_the_actual_two_peer_terminal_event() {
        let mut fleet = json!({"latest_terminal170_observation":{
            "path":"/var/lib/jetstreamer/horizon_runtime_data/root0615-terminal170-recovery-20261120-v1/event.json",
            "sha256":"e6aa44d51e8375e10428372ad2e15d391a8ac866d7bdb39e6b979f75761b2760"}});
        validate_retry7_event(&fleet).unwrap();
        fleet["latest_terminal170_observation"]["sha256"] = json!(STOP6_SHA);
        assert!(validate_retry7_event(&fleet).is_err());
    }

    #[test]
    fn retry9_keeps_all_prior_closed_generations_and_terminal_lineage() {
        let lineage = json!({"stopped_retry4_170":{"historical":"retained"}});
        let original = "unrelated-historical.service";
        let mut plan = json!({"epoch":170,"attempt":"local3retry5",
            "current_allocation":{"schema":"historical"},"retry170":lineage,
            "closed_units":[original,
                "horizon-qualify-170-replacement-local3retry5-20261110-v1.service"]});
        retry9_route(&mut plan).unwrap();
        assert_eq!(plan["attempt"], "local3retry9");
        assert_eq!(plan["fresh_subtree"], FRESH);
        assert_eq!(plan["retry170"], lineage);
        let units = plan["closed_units"].as_array().unwrap();
        assert_eq!(units.len(), 19);
        assert!(units.contains(&json!(original)));
        for attempt in 4..=9 {
            for unit in [
                format!("horizon-qualify-170-replacement-local3retry{attempt}-20261110-v1.service"),
                format!("horizon-guard-replacement-170-local3retry{attempt}-20261110-v1.service"),
                format!("horizon-guard-replacement-170-local3retry{attempt}-20261110-v1.timer"),
            ] {
                assert_eq!(units.iter().filter(|v| **v == json!(unit)).count(), 1);
            }
        }
        assert!(retry9_route(&mut plan).is_err());
    }
    #[test]
    fn retry9_rejects_foreign_templates_and_duplicate_closed_owners() {
        let template = json!({"epoch":170,"attempt":"local3retry5",
            "current_allocation":{},"closed_units":[]});
        for (key, value) in [("epoch", json!(167)), ("attempt", json!("local3retry6"))] {
            let mut bad = template.clone();
            bad[key] = value;
            assert!(retry9_route(&mut bad).is_err());
        }
        let mut bad = template;
        bad["closed_units"] = json!(["duplicate.service", "duplicate.service"]);
        assert!(retry9_route(&mut bad).is_err());
    }
    #[test]
    fn fresh_root_needs_exact_explicit_retry9_identity() {
        let good = json!({"fresh_subtree_identity":{"path":FRESH,"device":1,"inode":2}});
        fresh_root_binding(&good, 1, 2).unwrap();
        assert!(fresh_root_binding(&Value::Null, 1, 2).is_err());
        assert!(fresh_root_binding(&good, 2, 2).is_err());
        assert!(fresh_root_binding(&good, 1, 3).is_err());
        for (key, value) in [
            ("path", json!(FRESH.replace("retry7", "retry6"))),
            ("device", json!(0)),
            ("inode", json!(0)),
        ] {
            let mut bad = good.clone();
            bad["fresh_subtree_identity"][key] = value;
            assert!(fresh_root_binding(&bad, 1, 2).is_err());
        }
    }
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
        let good = json!({"generation":"v2","output_root":format!("{ROOT}/guard-witness-v2"),"unit":"horizon-170-retry9-witness-v2-20261120.service","contract_destination":"/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry9-recovery-20261120-v1/data-contract-v2"});
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
    const PREPARED: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry9-recovery-20261120-v1/preparation/epoch170/local3retry9/prepared.json";
    const ROOT: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry9-recovery-20261120-v1/launch-state";
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
            .arg("--no-optional-locks")
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
                "scripts/horizon_retry9_170_20261120_v1/terminal8.rs",
                sha(include_bytes!("../terminal8.rs")),
            ),
            (
                "scripts/horizon_170_join_independent166_20261120_v1/peer.rs",
                sha(include_bytes!(
                    "../../horizon_170_join_independent166_20261120_v1/peer.rs"
                )),
            ),
            (
                "scripts/horizon_retry9_170_20261120_v1/stage/main.rs",
                sha(include_bytes!("main.rs")),
            ),
            (
                "scripts/horizon_retry9_170_20261120_v1/stage/Cargo.toml",
                sha(include_bytes!("Cargo.toml")),
            ),
            (
                "scripts/horizon_retry9_170_20261120_v1/stage/Cargo.lock",
                sha(include_bytes!("Cargo.lock")),
            ),
            (
                "scripts/horizon_audit79_budget_v10_20261120_v1/audit_budget.rs",
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
        let launcher = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry9-recovery-20261120-v1/launch-v2/launch";
        ensure!(
            sha(&fs::read(launcher)?) == super::LAUNCHER_SHA,
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
                && prepared["attempt"] == "local3retry9"
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
        let plan = json!({"schema":"horizon-retry9-single170-launch-plan-v1",
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
            // Native qualification also reads root-owned predecessor receipts. Give the
            // fixture the same owner as a genesis file staged for the replay service.
            if unsafe { libc::geteuid() } == 0 {
                for member in [&output, &path] {
                    std::os::unix::fs::chown(member, Some(1001), None).unwrap();
                }
            }
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
