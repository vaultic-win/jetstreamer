//! A positive link from the genuine 136 actor to its single-use admission,
//! current protector and paid root. Charge its remaining growth only once.
use super::*;
use std::collections::BTreeSet;

pub const UNIT: &str = "horizon-qualify-136-actual-20261120-g1.service";
pub(super) const BASE136: &str = "/home/sol/.jetstreamer-private/epoch136-actual-20261120-g1";
const WRITER: &str = "horizon-admit-136-actual-20261120-g1.service";
const TIMER: &str = "horizon-guard-136-actual-20261120-g1.timer";
const GUARD: &str = "horizon-guard-136-actual-20261120-g1.service";
const GUARD_SHA: &str = "b2271db6f25696612c388297db3a10852f7911560887f67dcb404392d91f7016";
const GUARD_IMAGE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry9-recovery-20261120-v1/guard-v1/guard";
const HELPER: &str = "93162c6910f01149cb50eccdfa742e5a732658dd8ac17865a5f2eaef526c0594";
const NODE: &str = "bf702870fa328cf3fc43dd12a3943cab059fb7b0aa4ea1d3753c6a09b940cd71";
pub(super) const WORKER: &str = "3ea95997d956de6a8c7fa431e679d496a5d3c31e15f8a104a8ddb0086646ea3d";
pub const LIMIT: u64 = 72 << 30;
pub(super) const ROOT_CAP: u64 = 64 << 30;
const ROOT136: &str = "/home/sol/.jetstreamer-private/epoch136-actual-20261120-g1/reproduction";

pub struct Candidate {
    pub occupied: bool,
    pub armed: bool,
    pub realized: u64,
    pub floor: u64,
    pub identity: Value,
}

impl Candidate {
    pub fn remaining(&self) -> u64 {
        LIMIT - self.realized
    }
    pub fn json(&self, protected: u64) -> Result<Value> {
        ensure!(
            self.realized <= ROOT_CAP && (self.occupied || self.realized == 0),
            "positive candidate realization without the admitted actor/root"
        );
        Ok(
            json!({"limit_bytes":LIMIT,"realized_bytes":self.realized,"remaining_bytes":self.remaining(),
            "required_total_bytes":protected.max(self.floor).checked_add(self.remaining()).context("joint disk overflow")?,
            "identity":self.identity,"armed":self.armed}),
        )
    }
}
fn idle(armed: bool, floor: u64) -> Candidate {
    Candidate {
        occupied: false,
        armed,
        realized: 0,
        floor,
        identity: Value::Null,
    }
}
fn num(v: &Value, k: &str) -> Result<u64> {
    capacity::n(v, k)
}
fn prop<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("missing {k}"))
}
pub fn show(unit: &str, keys: &str) -> Result<Value> {
    let mut v = json!({});
    for row in capacity::run(
        "/usr/bin/systemctl",
        &["show", unit, &format!("--property={keys}")],
        "8",
    )?
    .lines()
    {
        let (k, val) = row.split_once('=').context("native unit property")?;
        ensure!(v[k].is_null(), "duplicate native property");
        v[k] = val.into();
    }
    Ok(v)
}
pub fn immutable(p: &Path) -> Result<(Bound, Value)> {
    let id = custody::frozen_identity(p)?;
    ensure!(id.bytes <= 2 << 20, "oversized immutable receipt");
    let b = Bound {
        path: p.into(),
        sha256: custody::sha(&fs::read(p)?),
    };
    let value = custody::json(&b, true)?;
    Ok((b, value))
}
fn jsonref(v: &Value) -> Result<Value> {
    custody::json(&serde_json::from_value(v.clone())?, true)
}
fn string_args(pid: u32) -> Result<Vec<String>> {
    let raw = fs::read(format!("/proc/{pid}/cmdline"))?;
    ensure!(
        raw.len() < 1 << 20 && raw.last() == Some(&0),
        "proc command"
    );
    Ok(raw[..raw.len() - 1]
        .split(|b| *b == 0)
        .map(|b| String::from_utf8(b.to_vec()))
        .collect::<std::result::Result<_, _>>()?)
}
fn same_image(pid: u32, file: &Path) -> Result<bool> {
    let a = custody::frozen_identity(file)?;
    let b = match fs::metadata(format!("/proc/{pid}/exe")) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(capacity::GuardInFlight.into());
        }
        Err(e) => return Err(e.into()),
    };
    Ok(a.device == b.dev() && a.inode == b.ino())
}
fn link(base: &Path, name: &str, hash: &str) -> Value {
    json!({"path":base.join("tools").join(name),"sha256":hash})
}
fn writer(plan: &Value, a: &Value, base: &Path) -> Result<(Value, bool)> {
    let iid = prop(a, "writer_invocation_id")?;
    let b: Bound = serde_json::from_value(a["writer"].clone())?;
    ensure!(
        custody::hex(iid, 32)
            && plan["controller"] == json!(b)
            && b.path == base.join("controller/admit136"),
        "foreign 136 writer"
    );
    let seal = jsonref(&plan["controller_deployment"])?;
    let package = Path::new(prop(&seal, "destination")?);
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && plan["controller_deployment"]["path"]
                == package
                    .join("deployment-seal-receipt.json")
                    .to_str()
                    .unwrap()
            && seal["members"].as_array().is_some_and(|r| r
                .iter()
                .any(|m| m["name"] == "admit136"
                    && m["mode"] == "0555"
                    && m["sha256"] == b.sha256)),
        "unsealed 136 writer"
    );
    let installed = Bound {
        path: package.join("admit136"),
        sha256: b.sha256.clone(),
    };
    custody::bytes(&installed, 16 << 20, true)?;
    let w = show(
        WRITER,
        "Id,InvocationID,MainPID,ActiveState,Job,NRestarts,ControlGroup,MemorySwapMax,CPUQuotaPerSecUSec,MemoryMax",
    )?;
    if w["ActiveState"] == "active" || w["ActiveState"] == "activating" {
        let pid: u32 = prop(&w, "MainPID")?.parse()?;
        ensure!(
            w["InvocationID"] == iid
                && (w["Job"] == "" || w["ActiveState"] == "activating")
                && w["NRestarts"] == "0"
                && w["ControlGroup"] == format!("/system.slice/{WRITER}")
                && w["MemorySwapMax"] == "0"
                && w["MemoryMax"] == "536870912"
                && w["CPUQuotaPerSecUSec"] == "250ms"
                && fs::read_to_string(format!("/proc/{pid}/cgroup"))?.trim()
                    == format!("0::/system.slice/{WRITER}")
                && same_image(pid, &package.join("admit136"))?,
            "136 writer generation or limits changed"
        );
        Ok((
            json!({"unit":WRITER,"invocation_id":iid,"image":b,"seal":plan["controller_deployment"]}),
            true,
        ))
    } else {
        ensure!(
            w["ActiveState"] == "inactive" && w["MainPID"] == "0" && w["Job"] == "",
            "136 writer not cleanly drained"
        );
        let success = capacity::run(
            "/usr/bin/journalctl",
            &[
                "--no-pager",
                "-ojson",
                "--output-fields=UNIT,INVOCATION_ID,MESSAGE_ID",
                "_PID=1",
                &format!("UNIT={WRITER}"),
                &format!("INVOCATION_ID={iid}"),
                "MESSAGE_ID=7ad2d189f7e94e70a38c781354912448",
            ],
            "10",
        )?;
        ensure!(
            success
                .lines()
                .filter_map(|l| serde_json::from_str::<Value>(l).ok())
                .any(|v| v["UNIT"] == WRITER && v["INVOCATION_ID"] == iid),
            "136 writer lacks genuine success"
        );
        Ok((
            json!({"unit":WRITER,"invocation_id":iid,"image":b,"seal":plan["controller_deployment"],"successful_drain":true}),
            false,
        ))
    }
}
fn candidate_contract(a: &Value, base: &Path) -> Result<Value> {
    let cap = jsonref(&a["resource_accounting"])?;
    let payload = jsonref(&a["plan"])?;
    let plan = jsonref(&cap["writer_plan"])?;
    let fields = [
        "schema",
        "node",
        "helper",
        "worker",
        "tools_seal",
        "qualification",
        "source_proof",
        "source_commit",
        "history",
        "controller",
        "barrier_version",
    ];
    ensure!(
        cap["payload_plan"] == a["plan"]
            && a["plan"]["path"] == base.join("payload-plan.json").to_str().unwrap()
            && payload.as_object().is_some_and(|m| m.len() == fields.len())
            && fields
                .iter()
                .all(|k| payload.get(k).is_some() && payload[k] == plan[k]),
        "136 writer did not project the admitted payload"
    );
    jsonref(&a["tools_seal"])?;
    candidate_values(a, &plan, base, &cap)?;
    Ok(plan)
}
fn candidate_values(a: &Value, plan: &Value, base: &Path, cap: &Value) -> Result<()> {
    ensure!(
        a["schema"] == "horizon-epoch136-actual-admission-v1"
            && a["bounded_reproduction_authorized"] == true
            && a["publication_authorized"] == false
            && a["remote_mutations"] == false
            && a["r2_mutations"] == false
            && a["data_reservation_bytes"] == LIMIT
            && a["memory_max_bytes"] == 68u64 << 30
            && a["cpu_quota_micros"] == 3_000_000
            && a["tools_seal"]
                == link(
                    base,
                    "deployment-seal-receipt.json",
                    "5a4176a52fa18d69e247d0f42a0900163fecce5c7b1c516310fb6c69376ecf17"
                )
            && a["helper"] == link(base, "epoch136-actual-payload", HELPER)
            && a["node"] == link(base, "jetstreamer-node", NODE)
            && a["worker"] == link(base, "jetstreamer-historical-worker-v1-4-25", WORKER)
            && ["helper", "worker", "node", "tools_seal"]
                .iter()
                .all(|k| plan[k] == a[k])
            && plan["standard169_cpu_loan"]
                == json!({"standard_route":{"path":"/var/lib/jetstreamer/retry3-peer169-native-operation-20261113-v2/epoch169/epoch169-PREPARE_PLAN.json",
             "sha256":"6251beb7e726ce4cc395b4c7034a72d0a2e6311a2ce206de0f6a2c148b8acbd8"},"cpu_quota_micros":4250000})
            && num(a, "protected_existing_free_bytes")?.checked_add(LIMIT)
                == Some(num(a, "required_initial_free_bytes")?),
        "foreign 136 CPU, memory, disk, images or joint admission"
    );
    ensure!(
        cap["candidate_reserved_once"] == true
            && cap["candidate_data_bytes"] == LIMIT
            && cap["candidate_unit"] == UNIT
            && cap["writer_invocation_id"] == a["writer_invocation_id"]
            && cap["writer"] == a["writer"]
            && cap["exclusive_handoff_accepted"] == true
            && cap["candidate_run_root"] == ROOT136
            && cap["total_memory_promises_including_floor_and_candidate_bytes"]
                == 810_658_050_048u64
            && cap["protected_existing_home_free_bytes"] == a["protected_existing_free_bytes"],
        "unbound 136 donor capacity"
    );
    Ok(())
}

fn timer_trigger() -> Result<u64> {
    let trigger = capacity::run(
        "/usr/bin/busctl",
        &[
            "--system",
            "--timeout=5s",
            "get-property",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1/unit/horizon_2dguard_2d136_2dactual_2d20261120_2dg1_2etimer",
            "org.freedesktop.systemd1.Timer",
            "LastTriggerUSecMonotonic",
        ],
        "8",
    )?;
    Ok(trigger
        .strip_prefix("t ")
        .and_then(|v| v.strip_suffix('\n'))
        .context("timer trigger")?
        .parse::<u64>()?)
}

const TIMER_FIELDS: &str = "Id,InvocationID,ActiveState,Triggers,Job";
const GUARD_FIELDS: &str = "Id,InvocationID,Type,Result,ExecMainStatus,ExecStart,NRestarts,ExecMainStartTimestampMonotonic,MainPID,ControlPID";

pub(super) struct GuardFire {
    timer: Value,
    service: Value,
    trigger: u64,
    receipt: Bound,
    pub sample: Value,
}

impl GuardFire {
    pub fn is_current(&self) -> Result<bool> {
        Ok(show(TIMER, TIMER_FIELDS)? == self.timer
            && show(GUARD, GUARD_FIELDS)? == self.service
            && timer_trigger()? == self.trigger)
    }
}

/// Bind the completed PID1 timer invocation to its own sample file.
pub(super) fn guard_fire(
    gp: &Bound,
    iid: &str,
    pid: u32,
    floor: u64,
    staging: bool,
) -> Result<GuardFire> {
    let timer = show(TIMER, TIMER_FIELDS)?;
    let guard = show(GUARD, GUARD_FIELDS)?;
    if (timer["ActiveState"] != "active" || guard["InvocationID"] == "") && staging {
        return Err(capacity::GuardInFlight.into());
    }
    let trigger = timer_trigger()?;
    if trigger == 0
        || guard["MainPID"] != "0"
        || guard["ControlPID"] != "0"
        || prop(&guard, "ExecMainStartTimestampMonotonic")?.parse::<u64>()? < trigger
    {
        return Err(capacity::GuardInFlight.into());
    }
    let gid = prop(&guard, "InvocationID")?;
    let line = format!(
        "{{ path={GUARD_IMAGE} ; argv[]={GUARD_IMAGE} {} --plan-sha256 {} --self-sha256 {GUARD_SHA} ;",
        gp.path.display(),
        gp.sha256
    );
    ensure!(
        timer["ActiveState"] == "active"
            && timer["Triggers"] == GUARD
            && timer["Job"] == ""
            && custody::hex(prop(&timer, "InvocationID")?, 32)
            && custody::hex(gid, 32)
            && guard["Type"] == "oneshot"
            && guard["NRestarts"] == "0"
            && prop(&guard, "ExecStart")?.starts_with(&line)
            && prop(&guard, "ExecStart")?.matches(" ; argv[]=").count() == 1,
        "foreign 136 guard/timer"
    );
    let sp = Path::new(ROOT136)
        .join("receipts/guard")
        .join(format!("sample-{gid}.json"));
    if !sp.try_exists()? {
        return Err(capacity::GuardInFlight.into());
    }
    let (sb, sample) = joint::receipt(&sp)?;
    let o = &sample["root_physical_observation"];
    ensure!(
        guard["Result"] == "success"
            && guard["ExecMainStatus"] == "0"
            && sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && sample["guard_invocation_id"] == gid
            && sample["producer_invocation_id"] == iid
            && sample["plan_sha256"] == gp.sha256
            && sample["producer"]["pid"] == pid
            && sample["producer"]["invocation_id"] == iid
            && sample["producer"]["cgroup"] == format!("/system.slice/{UNIT}")
            && sample["producer"]["active"] == "active"
            && sample["producer"]["sub"] == "running"
            && sample["producer"]["restarts"] == 0
            && sample["guard_sha256"] == GUARD_SHA
            && sample["minimum_free_bytes"] == floor
            && sample["maximum_root_physical_bytes"] == ROOT_CAP
            && sample["maximum_worker_vmas"] == 3_500_000
            && sample["bounded_measurement"] == false
            && sample["bounded_canary"].is_null()
            && sample["native_main"].is_null()
            && sample["producer_stop_enabled"] == true
            && sample["trip_reason"].is_null()
            && sample["worker_observation_error"].is_null()
            && sample["root_physical_observation_error"].is_null()
            && o["exceeds_budget"] == false
            && num(o, "conservative_physical_bytes")? <= ROOT_CAP
            && num(&sample, "available_bytes")? >= floor
            && custody::now()?
                .checked_sub(num(&sample, "recorded_unix_seconds")?)
                .is_some_and(|d| d <= 120),
        "136 guard health or generation"
    );
    Ok(GuardFire {
        timer,
        service: guard,
        trigger,
        receipt: sb,
        sample,
    })
}

pub fn observe() -> Result<Candidate> {
    let base = Path::new(BASE136);
    let ap = base.join("admission.json");
    let group = Path::new("/sys/fs/cgroup/system.slice").join(UNIT);
    let members = match fs::read_to_string(group.join("cgroup.procs")) {
        Ok(s) => s
            .lines()
            .map(str::parse::<u32>)
            .collect::<std::result::Result<BTreeSet<_>, _>>()?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeSet::new(),
        Err(e) => return Err(e.into()),
    };
    if members.is_empty() {
        // PID1 queues jobs before the service has any cgroup members.
        let jobs = capacity::run(
            "/usr/bin/systemctl",
            &["list-jobs", "--no-legend", "--no-pager", "--full"],
            "8",
        )?;
        if jobs
            .lines()
            .any(|line| line.split_whitespace().nth(1) == Some(UNIT))
        {
            return Err(capacity::GuardInFlight.into());
        }
    }
    if !ap.try_exists()? {
        ensure!(
            members.is_empty(),
            "unknown 136 appeared without its admission"
        );
        return Ok(idle(false, 0));
    }
    let (ab, a) = immutable(&ap)?;
    let now = custody::now()?;
    if members.is_empty() && now >= num(&a, "launch_expires_unix_seconds")? {
        return Ok(idle(false, 0));
    }
    let plan = candidate_contract(&a, base)?;
    let (w, live_writer) = writer(&plan, &a, base)?;
    let floor = num(&a, "protected_existing_free_bytes")?;
    if members.is_empty() {
        ensure!(live_writer, "armed 136 admission without its writer");
        return Ok(idle(true, floor));
    }
    let beginning = show(UNIT, "InvocationID,ActiveState,Job")?;
    if live_writer
        && beginning["ActiveState"] == "activating"
        && custody::now()? <= num(&a, "launch_expires_unix_seconds")?
    {
        return Err(capacity::GuardInFlight.into());
    }
    let s = capacity::native_values(UNIT)?;
    let iid = prop(&s, "InvocationID")?;
    let pid: u32 = prop(&s, "MainPID")?.parse()?;
    let ticks = native::ticks(pid)?;
    ensure!(
        custody::hex(iid, 32)
            && members.contains(&pid)
            && s["ControlGroup"] == format!("/system.slice/{UNIT}")
            && s["CPUQuotaPerSecUSec"] == "3s"
            && s["MemoryMax"] == (68u64 << 30).to_string()
            && same_image(pid, &base.join("tools/epoch136-actual-payload"))?,
        "136 runtime owner or limits"
    );
    let args = string_args(pid)?;
    ensure!(
        args == [
            prop(&a["helper"], "path")?,
            prop(&a["plan"], "path")?,
            "--plan-sha256",
            prop(&a["plan"], "sha256")?,
            "--self-sha256",
            HELPER,
            "--admission",
            ap.to_str().unwrap(),
            "--admission-sha256",
            &ab.sha256
        ],
        "136 payload args differ"
    );
    let receipts = Path::new(ROOT136).join("receipts");
    let plan_path = receipts.join("guard-plan.json");
    let ready = receipts.join("parent-release.json");
    if !plan_path.try_exists()? && live_writer && now <= num(&a, "launch_expires_unix_seconds")? {
        return Err(capacity::GuardInFlight.into());
    }
    let launch = joint::receipt(&receipts.join("launch.json"))?.1;
    ensure!(
        launch["unit"] == UNIT
            && launch["invocation_id"] == iid
            && launch["pid"] == pid
            && launch["start_ticks"] == ticks
            && launch["plan"] == a["plan"]
            && launch["admission"] == json!(ab),
        "136 launch/actor mismatch"
    );
    let (gp, g) = joint::receipt(&plan_path)?;
    ensure!(
        g["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && g["unit"] == UNIT
            && g["invocation_id"] == iid
            && g["worker_root"] == ROOT136
            && g["minimum_free_bytes"] == floor
            && g["filesystem"] == "/home/sol"
            && g["maximum_worker_vmas"] == 3_500_000
            && g["maximum_root_physical_bytes"] == ROOT_CAP
            && g["receipt_directory"] == receipts.join("guard").to_str().unwrap(),
        "136 guard plan changed"
    );
    let fire = guard_fire(
        &gp,
        iid,
        pid,
        floor,
        live_writer && now <= num(&a, "launch_expires_unix_seconds")?,
    )?;
    let sample = &fire.sample;
    let o = &sample["root_physical_observation"];
    let root = Path::new(ROOT136);
    let procgroup = format!("0::/system.slice/{UNIT}");
    let census = |members: &BTreeSet<u32>| {
        joint_worker::census(
            members,
            pid,
            &procgroup,
            root,
            &base.join("tools/jetstreamer-node"),
            &base.join("tools/jetstreamer-historical-worker-v1-4-25"),
            WORKER,
        )
    };
    let tree = census(&members)?;
    let node = tree.node.as_ref().map(|p| p.pid);
    let worker = tree.worker.as_ref().map(|p| p.pid);
    if node.is_some() || !live_writer {
        let rel = joint::receipt(&ready)?.1;
        ensure!(
            rel["schema"] == "horizon-epoch136-actual-parent-release-v1"
                && rel["unit"] == UNIT
                && rel["invocation_id"] == iid
                && rel["node_spawn_authorized"] == true
                && rel["writer"] == a["writer"]
                && rel["writer_invocation_id"] == a["writer_invocation_id"]
                && rel["helper"] == a["helper"]
                && rel["node"] == a["node"]
                && rel["worker"] == a["worker"],
            "missing actual 136 writer release"
        );
    }
    if let Some(w) = &tree.worker {
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        ensure!(hz > 0, "kernel process clock");
        let guard_start = prop(&fire.service, "ExecMainStartTimestampMonotonic")?.parse::<u64>()?;
        if (u128::from(w.start_ticks) + 1) * 1_000_000 > u128::from(guard_start) * hz as u128 {
            return Err(capacity::GuardInFlight.into());
        }
    }
    let actual = sample["workers"].as_array().context("136 worker census")?;
    if (worker.is_some()
        && !(actual.len() == 1
            && actual[0][0] == worker.unwrap()
            && actual[0][1]
                .as_u64()
                .is_some_and(|n| n > 0 && n <= 3_500_000)))
        || (worker.is_none() && !actual.is_empty())
    {
        return Err(capacity::GuardInFlight.into());
    }
    let rm = fs::symlink_metadata(root)?;
    ensure!(
        rm.is_dir()
            && rm.uid() == 0
            && rm.gid() == 0
            && rm.mode() & 0o7777 == 0o711
            && rm.dev() == 64512
            && root.canonicalize()? == root,
        "136 charged root"
    );
    let (physical, proof) = stable::measure(root)?;
    let realized = physical
        .min(num(&o["first"], "physical_bytes")?)
        .min(num(&o["second"], "physical_bytes")?);
    ensure!(
        realized <= ROOT_CAP && native::ticks(pid)? == ticks && capacity::native_values(UNIT)? == s,
        "136 producer generation changed during fit"
    );
    let current_members = fs::read_to_string(group.join("cgroup.procs"))?
        .lines()
        .map(str::parse::<u32>)
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    if current_members != members
        || census(&current_members)? != tree
        || !same_image(pid, &base.join("tools/epoch136-actual-payload"))?
        || fs::read_to_string(format!("/proc/{pid}/cgroup"))?.trim() != procgroup
        || !{
            let after = fs::symlink_metadata(root)?;
            after.dev() == rm.dev() && after.ino() == rm.ino()
        }
        || !fire.is_current()?
    {
        return Err(capacity::GuardInFlight.into());
    }
    Ok(Candidate {
        occupied: true,
        armed: true,
        floor,
        realized,
        identity: json!({"unit":UNIT,"invocation_id":iid,
      "pid":pid,"start_ticks":ticks,"admission":ab,"writer_invocation_id":a["writer_invocation_id"],"writer":w,
      "guard_plan":gp,"guard_sample":fire.receipt,"node_pid":node,"worker_pid":worker,"process_tree":tree,"positive_physical_subset":proof}),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binds_candidate_only_to_sealed_actor_exact_donor_and_full_floor() {
        let base = Path::new(BASE136);
        let h = link(base, "epoch136-actual-payload", HELPER);
        let n = link(base, "jetstreamer-node", NODE);
        let w = link(base, "jetstreamer-historical-worker-v1-4-25", WORKER);
        let seal = link(
            base,
            "deployment-seal-receipt.json",
            "5a4176a52fa18d69e247d0f42a0900163fecce5c7b1c516310fb6c69376ecf17",
        );
        let plan = json!({"helper":h,"node":n,"worker":w,"tools_seal":seal,"standard169_cpu_loan":{"standard_route":{
            "path":"/var/lib/jetstreamer/retry3-peer169-native-operation-20261113-v2/epoch169/epoch169-PREPARE_PLAN.json",
            "sha256":"6251beb7e726ce4cc395b4c7034a72d0a2e6311a2ce206de0f6a2c148b8acbd8"},"cpu_quota_micros":4250000}});
        let a = json!({"schema":"horizon-epoch136-actual-admission-v1","bounded_reproduction_authorized":true,
            "publication_authorized":false,"remote_mutations":false,"r2_mutations":false,"data_reservation_bytes":LIMIT,
            "memory_max_bytes":68u64<<30,"cpu_quota_micros":3000000,"helper":h,"node":n,"worker":w,"tools_seal":seal,
            "protected_existing_free_bytes":451,"required_initial_free_bytes":451+LIMIT,"writer":{"path":"writer"},"writer_invocation_id":"generation"});
        let cap = json!({"candidate_reserved_once":true,"candidate_data_bytes":LIMIT,"candidate_unit":UNIT,
            "writer_invocation_id":a["writer_invocation_id"],"writer":a["writer"],"exclusive_handoff_accepted":true,
            "candidate_run_root":ROOT136,"total_memory_promises_including_floor_and_candidate_bytes":810658050048u64,
            "protected_existing_home_free_bytes":451});
        candidate_values(&a, &plan, base, &cap).unwrap();
        for (key, v) in [
            ("worker", json!({"path":"foreign"})),
            ("data_reservation_bytes", json!(LIMIT - 1)),
            ("required_initial_free_bytes", json!(LIMIT)),
            ("publication_authorized", json!(true)),
        ] {
            let mut bad = a.clone();
            bad[key] = v;
            assert!(candidate_values(&bad, &plan, base, &cap).is_err());
        }
        let mut bad = cap.clone();
        bad["writer_invocation_id"] = "other".into();
        assert!(candidate_values(&a, &plan, base, &bad).is_err());
        let mut bad = plan.clone();
        bad["standard169_cpu_loan"]["cpu_quota_micros"] = 1.into();
        assert!(candidate_values(&a, &bad, base, &cap).is_err());
    }
    #[test]
    fn actual_credit_is_once_only_and_never_crosses_the_measured_root() {
        assert_eq!(
            idle(false, 0).json(5).unwrap()["required_total_bytes"],
            5 + LIMIT
        );
        let c = Candidate {
            occupied: true,
            armed: true,
            floor: 101,
            realized: 20,
            identity: json!({"unit":UNIT}),
        };
        assert_eq!(
            c.json(100).unwrap()["required_total_bytes"],
            101 + LIMIT - 20
        );
        assert!(
            Candidate {
                occupied: false,
                ..c
            }
            .json(0)
            .is_err()
        );
    }
}
