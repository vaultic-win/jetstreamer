//! The independently guarded, zero-entry epoch 228 cold worker.
use super::*;
use super::native265::text;
pub(super) const UNIT: &str = "horizon-native-input-228-demotion-16d4b158-v1.service";
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch228-demotion-native-input-running-v1";
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/native-input228-v1620-demotion-v1";
const IMAGE: &str =
    "/var/lib/jetstreamer/horizon228-demotion-bank-9d2fd8d4-v158-v2-qualified/worker";
const SHA: &str = "16d4b15881979bb7d65a0f49408580d4508b451a5953f35cbb60505d2e3cee00";
const GUARD: &str = "/var/lib/jetstreamer/horizon228-demotion-controls-v160-a1-qualified/guard";
const GUARD_SHA: &str = "98ae85499fd21fa294104a1ff05c21dc155c9aa14ea10a70a0b29302d853dbfb";
const RECEIPTS: &str = "/var/lib/jetstreamer/horizon228-demotion-cold-guard-receipts-v1";
fn sealed(v: &Value) -> Result<Value> {
    native228::immutable_json(&serde_json::from_value(v.clone())?)
}
fn original_dir(path: &Path, leaf: &str) -> Result<()> {
    ensure!(
        path.file_name() == Some(std::ffi::OsStr::new(leaf))
            && path.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && path
                .parent()
                .and_then(Path::file_name)
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon228-demotion-live-")),
        "foreign 228 evidence path"
    );
    Ok(())
}
fn original_controller(origin: &Value, review: &Value, emission: &str) -> Result<()> {
    let owner = &origin["controller"];
    let unit = owner["Id"].as_str().context("228 controller")?;
    let iid = owner["InvocationID"]
        .as_str()
        .context("228 controller iid")?;
    let pid = owner["MainPID"].as_str().context("228 controller pid")?;
    let image: BoundFile = serde_json::from_value(review["controller_image"].clone())?;
    ensure!(
        unit.starts_with("horizon228-demotion-cold-control-")
            && unit.ends_with(".service")
            && review["epoch228_controller_unit"] == unit
            && owner["Type"] == "exec"
            && owner["MemoryMax"] == "536870912"
            && owner["MemorySwapMax"] == "0"
            && native265::hex(iid, 32)
            && pid.parse::<u32>()? > 1
            && image.path.file_name().is_some_and(|n| n == "native-fit")
            && image.path.parent().and_then(Path::parent)
                == Some(Path::new("/var/lib/jetstreamer"))
            && native265::hex(&image.sha256, 64),
        "228 controller tuple"
    );
    // The sealed deployment must contain the very executable which emitted
    // the origin digest in the original controller invocation.
    let seal = sealed(&review["epoch228_controller_seal"])?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == json!(image.path.parent())
            && seal["members"].as_array().is_some_and(|rows| rows
                .iter()
                .filter(|r| r["name"] == "native-fit"
                    && r["mode"] == "0555"
                    && r["sha256"] == image.sha256)
                .count()
                == 1),
        "228 deployed controller"
    );
    let message = emission;
    let result = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            "-b",
            "--no-pager",
            "-o",
            "json",
            "-n",
            "2",
            "_UID=0",
            &format!("_SYSTEMD_UNIT={unit}"),
            &format!("_SYSTEMD_INVOCATION_ID={iid}"),
            &format!("_PID={pid}"),
            &format!("_EXE={}", image.path.display()),
            &format!("MESSAGE={message}"),
        ])
        .output()?;
    ensure!(
        result.status.success() && result.stdout.len() < 65536,
        "228 controller journal"
    );
    let rows = serde_json::Deserializer::from_slice(&result.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        rows.len() == 1 && rows[0]["MESSAGE"] == message,
        "228 original controller emission"
    );
    Ok(())
}
fn format_ok(c: &PipelineClaim, v: &Value) -> Result<()> {
    let command = format!("{{ path={IMAGE} ; argv[]={IMAGE}");
    ensure!(
        c.unit == UNIT
            && c.epoch == 228
            && c.phase == "private-cold-snapshot-verification"
            && c.evidence.len() == 1
            && native265::hex(&c.invocation_id, 32)
            && v["schema"] == SCHEMA
            && v["epoch"] == 228
            && v["unit"] == UNIT
            && v["invocation_id"] == c.invocation_id
            && v["expected_exec_start"] == c.expected_exec_start
            && c.expected_exec_start
                .split_once(" ; ignore_errors=no ; start_time=")
                .is_some_and(|(cmd, _)| cmd == command)
            && v["private_run_root"] == ROOT
            && v["test_sha256"] == SHA
            && v["snapshot_sha256"] == native228::SNAPSHOT_SHA
            && v["genesis_sha256"] == native228::GENESIS_SHA
            && v["accounts_hash"] == native228::ACCOUNTS_HASH
            && v["maximum_memory_bytes"] == native228::MEMORY
            && v["maximum_scratch_bytes"] == native228::SCRATCH
            && v["bootstrap_slot"] == 98_495_291
            && v["replay_entries"] == 0
            && v["resource_samples_taken"] == 0
            && v["native_input_qualified"] == false
            && v["ordinary_replay_claim"] == false
            && v["public_sidecar_countdown_authorized"] == true,
        "foreign 228 demotion claim"
    );
    native228::no_authority(v)
}
pub(super) fn claim(c: &PipelineClaim) -> Result<()> {
    let b = c.evidence.first().context("228 demotion origin")?;
    original_dir(&b.path, "origin.json")?;
    let v = native228::immutable_json(b)?;
    format_ok(c, &v)?;
    let release = sealed(&v["release"])?;
    let admission = sealed(&v["admission"])?;
    let plan = sealed(&v["guard_plan"])?;
    let initial = sealed(&admission["initial_fit"])?;
    let held = sealed(&admission["source_fit"])?;
    let review = sealed(&admission["review"])?;
    let ledger = sealed(&admission["reservation_ledger"])?;
    let launch = sealed(&v["launch"])?;
    let pid = v["main_pid"].as_u64().context("228 main pid")?;
    let guard_file: BoundFile = serde_json::from_value(v["guard"].clone())?;
    let g = bound_json(&guard_file)?;
    let iid = &c.invocation_id;
    let gid = g["guard_invocation_id"]
        .as_str()
        .context("228 original guard")?;
    let wall = v["recorded_unix_seconds"].as_u64().context("228 wall")?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    ensure!(
        pid > 1
            && utc_seconds(v["sampled_at_utc"].as_str().context("228 UTC")?)? == wall
            && release["schema"] == "epoch228-demotion-cold-release-v1"
            && release["unit"] == UNIT
            && release["producer_iid"] == *iid
            && release["worker_pid"] == pid
            && release["worker_sha256"] == SHA
            && release["host_boot_id"] == boot.trim()
            && release["issued_unix_seconds"] == wall
            && release["expires_unix_seconds"]
                .as_u64()
                .is_some_and(|end| end > wall && end - wall <= 300)
            && release["admission"] == v["admission"]
            && release["plan"] == v["guard_plan"]
            && release["first_guard"] == v["guard"]
            && release["guard"] == json!({"path":GUARD,"sha256":GUARD_SHA})
            && release["guard_source"] == "f68492a79b280fa58b7526da1a013028c5fdf784",
        "228 original release"
    );
    ensure!(
        admission["schema"] == "epoch228-demotion-cold-admission-v1"
            && admission["unit"] == UNIT
            && admission["worker_sha256"] == SHA
            && admission["scratch_root"] == ROOT
            && admission["guard"] == release["guard"]
            && admission["producer_memory_bytes"] == native228::MEMORY
            && admission["producer_only_no_entries"] == true
            && admission["fleet"] == v["fleet"]
            && admission["reservation_ledger"] == review["reservation_ledger"]
            && review["observer"] == v["observer"]
            && review["fleet"] == v["fleet"]
            && ledger["observer"] == v["observer"]
            && ledger["fleet"] == v["fleet"]
            && ledger["Main_accepted"] == true
            && review["Main_accepted"] == true
            && review["single_campaign_controller_confirmed"] == true
            && admission["issued_unix_seconds"] == wall
            && release["protected_floor_bytes"] == admission["protected_floor_bytes"]
            && release["required_free_bytes"] == admission["required_free_bytes"],
        "228 native admission"
    );
    for (f, expected) in [(&initial, false), (&held, true)] {
        let capacity = &f["scenarios"]["cold"]["capacity"];
        ensure!(
            f["schema"] == "horizon-native228-demotion-current-fit-v1"
                && f["held"] == expected
                && f["unit"] == UNIT
                && f["worker"] == json!({"path":IMAGE,"sha256":SHA})
                && f["controller"]["InvocationID"] == v["controller"]["InvocationID"]
                && f["controller"]["MainPID"] == v["controller"]["MainPID"]
                && f["scenarios"]["cold"]["fits"] == true
                && f["review"] == admission["review"]
                && f["observer"] == v["observer"]
                && f["fleet"] == v["fleet"]
                && f["reservation_ledger"] == admission["reservation_ledger"]
                && f["boot_id"] == boot.trim()
                && f["additional_paired_retry_credit_bytes"] == 0
                && f["holding_reclamation_credit_bytes"] == 0
                && capacity["protected_existing_floor_bytes"]
                    .as_u64()
                    .zip(release["protected_floor_bytes"].as_u64())
                    .is_some_and(|(x, y)| x > 0 && x <= y)
                && f["recorded_unix_seconds"]
                    .as_u64()
                    .is_some_and(|stamp| stamp <= wall && wall - stamp <= 300),
            "228 independent fit"
        );
    }
    let pid_text = pid.to_string();
    ensure!(
        held["producer"]["InvocationID"] == *iid
            && held["producer"]["MainPID"].as_str() == Some(pid_text.as_str())
            && launch["producer"]["InvocationID"] == *iid
            && launch["producer"]["ExecStart"] == v["expected_exec_start"]
            && launch["producer"]["MainPID"].as_str() == Some(pid_text.as_str())
            && launch["controller"] == v["controller"]
            && launch["initial_fit"] == admission["initial_fit"],
        "228 held/lifetime tuple"
    );
    ensure!(
        native265::hex(gid, 32)
            && guard_file.path == Path::new(RECEIPTS).join(format!("sample-{gid}.json"))
            && plan["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && plan["native_main"] == json!({"executable":IMAGE,"sha256":SHA,"main_pid":pid})
            && plan["unit"] == UNIT
            && plan["invocation_id"] == *iid
            && plan["worker_root"] == ROOT
            && plan["receipt_directory"] == RECEIPTS
            && plan["filesystem"] == "/"
            && plan["minimum_free_bytes"] == release["protected_floor_bytes"]
            && plan["maximum_worker_vmas"] == 3_500_000
            && plan["maximum_root_physical_bytes"] == native228::SCRATCH
            && g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["producer_invocation_id"] == *iid
            && g["producer"]["pid"] == pid
            && g["producer_stop_enabled"] == true
            && g["guard_sha256"] == GUARD_SHA
            && g["plan_sha256"] == v["guard_plan"]["sha256"]
            && g["native_main"] == plan["native_main"]
            && g["trip_reason"].is_null()
            && g["root_physical_observation_error"].is_null()
            && g["worker_observation_error"].is_null()
            && g["root_physical_observation"]["exceeds_budget"] == false
            && g["available_bytes"]
                .as_u64()
                .zip(release["required_free_bytes"].as_u64())
                .is_some_and(|(free, needed)| free >= needed),
        "228 independent guard"
    );
    original_controller(
        &v,
        &review,
        &format!("HORIZON228_ORIGIN_SHA256={}", b.sha256),
    )
}
pub(super) fn live(c: &PipelineClaim, current: &Value) -> Result<()> {
    claim(c)?;
    let v = native228::immutable_json(&c.evidence[0])?;
    let pid_text = v["main_pid"].as_u64().context("pid")?.to_string();
    ensure!(
        current["Id"] == UNIT
            && current["InvocationID"] == c.invocation_id
            && current["ActiveState"] == "active"
            && current["SubState"] == "running"
            && current["MainPID"].as_str() == Some(pid_text.as_str())
            && current["NRestarts"] == "0"
            && pipeline_status::same_exec_start(
                &c.expected_exec_start,
                current["ExecStart"].as_str().context("228 command")?
            ),
        "228 live owner"
    );
    let p = native228_capture::properties(UNIT)?;
    singleton227_capture::require(
        &p,
        &[
            ("Type", "exec"),
            ("User", "ubuntu"),
            ("Group", "ubuntu"),
            ("MemoryMax", "137438953472"),
            ("MemoryHigh", "120259084288"),
            ("MemorySwapMax", "0"),
            ("TasksMax", "512"),
            ("ProtectHome", "read-only"),
            ("ProtectSystem", "strict"),
            ("PrivateNetwork", "yes"),
            ("NoNewPrivileges", "yes"),
            ("ReadWritePaths", ROOT),
            ("Restart", "no"),
            ("KillMode", "control-group"),
        ],
    )?;
    let pid = current["MainPID"].as_str().context("228 live pid")?;
    ensure!(
        fs::read_link(format!("/proc/{pid}/exe"))? == Path::new(IMAGE)
            && fs::read_to_string(format!("/proc/{pid}/cgroup"))?.trim()
                == format!("0::/system.slice/{UNIT}"),
        "228 original image/cgroup"
    );
    Ok(())
}

pub(super) const TERMINAL_SCHEMA: &str = "horizon-epoch228-demotion-cold-fleet-terminal-v1";
pub(super) fn terminal(proof: &Value) -> Result<String> {
    ensure!(
        proof["schema"] == TERMINAL_SCHEMA
            && proof["epoch"] == 228
            && proof["unit"] == UNIT
            && proof["native_cold_qualified"] == true
            && proof["replay_entries"] == 0,
        "228 demotion terminal event"
    );
    native228::no_authority(proof)?;
    let b: BoundFile = serde_json::from_value(proof["running_origin"].clone())?;
    original_dir(&b.path, "origin.json")?;
    let v = native228::immutable_json(&b)?;
    let iid = v["invocation_id"].as_str().context("228 original iid")?;
    let c = PipelineClaim {
        epoch: 228,
        phase: "private-cold-snapshot-verification".into(),
        unit: UNIT.into(),
        invocation_id: iid.into(),
        expected_exec_start: v["expected_exec_start"]
            .as_str()
            .context("228 original argv")?
            .into(),
        evidence: vec![b.clone()],
    };
    claim(&c)?;
    let done: BoundFile = serde_json::from_value(proof["completion"].clone())?;
    original_dir(&done.path, "completion.json")?;
    ensure!(
        done.path.parent() == b.path.parent(),
        "foreign 228 terminal directory"
    );
    let t = native228::immutable_json(&done)?;
    let a = sealed(&v["admission"])?;
    let review = sealed(&a["review"])?;
    original_controller(
        &v,
        &review,
        &format!("HORIZON228_COMPLETION_SHA256={}", done.sha256),
    )?;
    let d = sealed(&t["protocol_proof"])?;
    let released = sealed(&v["release"])?;
    ensure!(
        proof["invocation_id"] == iid
            && proof["main_pid"] == v["main_pid"]
            && t["schema"] == "horizon-epoch228-demotion-cold-controller-completed-v1"
            && t["epoch"] == 228
            && t["unit"] == UNIT
            && t["producer_iid"] == iid
            && t["worker_pid"] == v["main_pid"]
            && t["origin"] == proof["running_origin"]
            && t["controller"] == v["controller"]
            && t["release"] == v["release"]
            && t["timer_invocation_id"] == v["timer_invocation_id"]
            && t["worker"] == json!({"path":IMAGE,"sha256":SHA})
            && t["native_cold_qualified"] == true
            && t["protocol_exit_code"] == 0
            && t["worker_exit_code"] == 0
            && t["worker_drained"] == true
            && t["timer_stopped"] == true
            && t["r2_mutations"] == false
            && t["replay_launch_authorized"] == false
            && d["release"] == released
            && d["shutdown_acknowledged"] == true
            && d["worker_pid"] == v["main_pid"]
            && d["worker_sha256"] == SHA
            && d["snapshot_loaded"] == true
            && d["replay_entries"] == 0,
        "foreign 228 cold proof"
    );
    let checkpoint = &d["checkpoint"];
    ensure!(
        d["initialized"]["slot"] == 98_495_291u64
            && checkpoint["slot"] == 98_495_291u64
            && checkpoint["slot_complete"] == true
            && checkpoint["capitalization"] == 504_915_797_589_943_503u64
            && checkpoint["transaction_count"] == 29_954_968_857u64
            && checkpoint["tick_height"] == 6_303_698_688u64
            && checkpoint["next_write_version"] == 113_087_684_591u64
            && checkpoint["writes"] == json!([]),
        "228 cold bank tuple"
    );
    let rows = t["journal"].as_array().context("228 manager evidence")?;
    let check = |id: &str| {
        rows.iter()
            .filter(|r| {
                r["MESSAGE_ID"] == id
                    && r["_UID"] == "0"
                    && r["_PID"] == "1"
                    && r["UNIT"] == UNIT
                    && r["INVOCATION_ID"] == iid
            })
            .count()
            == 1
    };
    ensure!(
        check("39f53479d3a045ac8e11786248231fbf")
            && check("7ad2d189f7e94e70a38c781354912448")
            && rows
                .iter()
                .all(|r| r.get("UNIT_RESULT").is_none_or(|s| s == "success")),
        "228 original manager terminal"
    );
    Ok(iid.into())
}
pub(super) fn terminal_owner(u: &Value, iid: &str) -> Result<()> {
    ensure!(
        native265::hex(iid, 32)
            && u["Id"] == UNIT
            && (u["LoadState"] == "not-found" || u["LoadState"] == "loaded")
            && u["ActiveState"] == "inactive"
            && u["SubState"] == "dead"
            && u["MainPID"] == "0"
            && u["NRestarts"] == "0"
            && (u["InvocationID"] == "" || u["InvocationID"] == iid)
            && u["Result"] == "success"
            && !Path::new("/sys/fs/cgroup/system.slice")
                .join(UNIT)
                .try_exists()?,
        "228 new or undrained terminal owner"
    );
    Ok(())
}
/// Keep the entire prior census, including dual-role replay managers. A
/// separately registered periodic guard may have completed another firing.
pub(super) fn peers(f: &Value, current: &BTreeMap<String, Value>, c: &PipelineClaim) -> Result<()> {
    let origin = native228::immutable_json(c.evidence.first().context("228 origin")?)?;
    let admission = sealed(&origin["admission"])?;
    let review = sealed(&admission["review"])?;
    let ledger = sealed(&admission["reservation_ledger"])?;
    let mut periodic = BTreeMap::new();
    for row in ledger["periodic_controls"]["controls"]
        .as_array()
        .context("228 existing guards")?
    {
        periodic.insert(text(row, "unit")?.to_owned(), row["guard_plan"].clone());
    }
    if review["control_units"]
        .as_array()
        .context("228 controls")?
        .iter()
        .any(|r| r["unit"] == "horizon-native266-protective-v1.service")
    {
        let accounting = native228::immutable_json(&BoundFile {
            path: "/var/lib/jetstreamer/horizon266-native-accounting-v161-v1/accounting.json"
                .into(),
            sha256: "fa5d43cb4be48bde528811fbb154ebc9d98dfb436582c7f83cf2f25db808be81".into(),
        })?;
        periodic.insert(
            "horizon-native266-protective-v1.service".into(),
            accounting["original"]["guard_plan"].clone(),
        );
    }
    let mut adjusted = f.clone();
    let old = f["unit_census"]
        .as_object()
        .context("228 complete old census")?;
    for (name, plan) in periodic {
        let Some(prior) = old.get(&name) else {
            continue;
        };
        let next = current.get(&name).context("228 prior guard omitted")?;
        if prior["InvocationID"] == next["InvocationID"] {
            continue;
        }
        let plan_data = sealed(&plan)?;
        let guarded = plan_data
            .get("unit")
            .or_else(|| plan_data.get("producer_unit"))
            .and_then(Value::as_str)
            .context("228 peer guarded unit")?;
        let producer_iid = plan_data
            .get("invocation_id")
            .or_else(|| plan_data.get("producer_invocation_id"))
            .and_then(Value::as_str)
            .context("228 peer guarded IID")?;
        let directory = Path::new(text(&plan_data, "receipt_directory")?);
        ensure!(
            directory.is_absolute()
                && directory.canonicalize()? == directory
                && native265::hex(producer_iid, 32)
                && !guarded.is_empty(),
            "peer guard receipt path"
        );
        for endpoint in [prior, next] {
            let iid = text(endpoint, "InvocationID")?;
            ensure!(
                native265::hex(iid, 32)
                    && endpoint["Id"] == name
                    && endpoint["Type"] == "oneshot"
                    && endpoint["LoadState"] == "loaded"
                    && endpoint["ActiveState"] == "inactive"
                    && endpoint["SubState"] == "dead"
                    && endpoint["NRestarts"] == "0"
                    && endpoint["MainPID"] == "0"
                    && endpoint["ExecMainStatus"] == "0"
                    && endpoint["Result"] == "success"
                    && endpoint["ControlGroup"] == "",
                "228 peer guard not between original firings"
            );
            let samples = ["sample", "terminal"]
                .iter()
                .map(|k| directory.join(format!("{k}-{iid}.json")))
                .filter(|p| p.exists())
                .collect::<Vec<_>>();
            ensure!(
                samples.len() == 1,
                "228 peer guard original sample or terminal absent"
            );
            let m = fs::symlink_metadata(&samples[0])?;
            ensure!(
                m.is_file() && m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o022 == 0,
                "228 peer receipt custody"
            );
            let sample: Value = serde_json::from_slice(&read_stable_bounded(
                &samples[0],
                4 << 20,
                "228 original peer guard",
            )?)?;
            ensure!(
                sample["guard_invocation_id"] == iid
                    && sample["producer_invocation_id"] == producer_iid
                    && sample["plan_sha256"] == plan["sha256"]
                    && sample["trip_reason"].is_null(),
                "228 foreign peer guard firing"
            );
            let output = ProcessCommand::new("/usr/bin/journalctl")
                .args([
                    "-b",
                    "-o",
                    "json",
                    "--no-pager",
                    "-n",
                    "3",
                    "_UID=0",
                    "_PID=1",
                    &format!("UNIT={name}"),
                    &format!("INVOCATION_ID={iid}"),
                    "MESSAGE_ID=7ad2d189f7e94e70a38c781354912448",
                ])
                .output()?;
            ensure!(
                output.status.success() && output.stdout.len() < 65536,
                "228 guard journal"
            );
            let events = serde_json::Deserializer::from_slice(&output.stdout)
                .into_iter::<Value>()
                .collect::<std::result::Result<Vec<_>, _>>()?;
            ensure!(
                events.len() == 1
                    && events[0]["UNIT"] == name
                    && events[0]["INVOCATION_ID"] == iid
                    && events[0].get("UNIT_RESULT").is_none_or(|s| s == "success"),
                "228 guard original PID1 terminal"
            );
        }
        adjusted["unit_census"][&name]["InvocationID"] = next["InvocationID"].clone();
    }
    native265_capture::peers(&adjusted, current, UNIT)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selected_worker_cannot_borrow_previous_harness() {
        assert!(
            native228::scope("private-cold-snapshot-verification", UNIT)
                && native228::scope("private-cold-snapshot-verification", native228::UNIT)
        );
        assert!(
            !native228::scope("producer-finalization", UNIT)
                && !native228::scope(
                    "private-cold-snapshot-verification",
                    "horizon-228-anything.service"
                )
        );
        let c = PipelineClaim {
            epoch: 228,
            phase: "private-cold-snapshot-verification".into(),
            unit: UNIT.into(),
            invocation_id: "a".repeat(32),
            expected_exec_start: native228::command(),
            evidence: vec![],
        };
        assert!(format_ok(&c, &json!({"schema":native228::SCHEMA})).is_err());
        assert!(original_dir(Path::new("/tmp/origin.json"), "origin.json").is_err());
        assert!(terminal(&json!({"schema":native228_terminal::SCHEMA})).is_err());
    }
}
