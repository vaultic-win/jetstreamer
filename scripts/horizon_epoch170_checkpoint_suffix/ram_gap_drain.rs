//! Hand back the identified RAM-gap guard after durable partial-output custody.
use super::{evidence, gap_floor_stop};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{
    fs,
    os::fd::AsRawFd,
    path::Path,
    thread,
    time::{Duration, Instant},
};

const ROOT: &str = gap_floor_stop::RAM_ROOT;
const UNIT: &str = gap_floor_stop::RAM_UNIT;
const TIMER: &str = "horizon-guard-170-from-73760367-ram-20261128-v1.timer";
const GUARD: &str = "horizon-guard-170-from-73760367-ram-20261128-v1.service";
const TIMER_ID: &str = "da36ff9db8f44e668164ff29465ce6d0";

fn persist(name: &str, value: &Value) -> Result<Value> {
    let path = Path::new(ROOT).join(name);
    if path.try_exists()? {
        let saved = evidence::reference(&path)?;
        ensure!(evidence::bound(&saved)? == *value, "different {name}");
        return Ok(saved);
    }
    evidence::receipt(&path, value)
}

fn timer(grant: &Value) -> Result<bool> {
    evidence::idle(UNIT)?;
    let state = evidence::props(
        TIMER,
        "Id,LoadState,ActiveState,SubState,Job,InvocationID,Triggers",
    )?;
    ensure!(
        state["Id"] == TIMER && state["Job"].is_empty(),
        "different or transitioning guard timer"
    );
    if state["ActiveState"] == "inactive" {
        return Ok(false);
    }
    let unit = evidence::props(
        GUARD,
        "Id,LoadState,TriggeredBy,ExecStart,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,Restart",
    )?;
    let plan = evidence::bound(&grant["guard_plan"])?;
    let executable = format!("{ROOT}/package/guard");
    let expected = format!(
        "argv[]={executable} {ROOT}/ACTUAL_GUARD_PLAN.json --plan-sha256 {} --self-sha256 91e272ec9910f153dedf754c1190862149deb90330f13ec625b946658e90288b ;",
        evidence::word(&grant["guard_plan"], "sha256")?
    );
    ensure!(
        state["ActiveState"] == "active"
            && matches!(state["SubState"].as_str(), "waiting" | "running")
            && state["InvocationID"] == TIMER_ID
            && grant["guard_timer_invocation_id"] == TIMER_ID
            && state["Triggers"] == GUARD
            && unit["Id"] == GUARD
            && unit["TriggeredBy"] == TIMER
            && unit["Restart"] == "no"
            && unit["MemoryMax"] == "1073741824"
            && unit["MemorySwapMax"] == "0"
            && unit["CPUQuotaPerSecUSec"] == "1s"
            && unit["ExecStart"].contains(&expected)
            && plan["unit"] == UNIT
            && plan["invocation_id"] == gap_floor_stop::RAM_IID,
        "different guard timer, executable, invocation, plan or resources"
    );
    Ok(true)
}

fn drained() -> Result<()> {
    evidence::idle(TIMER)?;
    evidence::idle(GUARD)?;
    evidence::idle(UNIT)?;
    for name in [GUARD, UNIT] {
        let state = evidence::props(name, "Id,LoadState,ControlGroup")?;
        ensure!(
            state["Id"] == name
                && state["ControlGroup"].is_empty()
                && !Path::new("/sys/fs/cgroup/system.slice")
                    .join(name)
                    .join("cgroup.procs")
                    .try_exists()?,
            "{name} still has a cgroup"
        );
    }
    Ok(())
}

pub(super) fn run(action: &str) -> Result<Value> {
    ensure!(unsafe { libc::geteuid() } == 0, "root custody is required");
    let lock = fs::File::open("/run/horizon-epoch171-to136-g1.operation.lock")?;
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } == 0,
        "cannot lock fleet"
    );
    let custody = gap_floor_stop::report(true)?;
    if action == "ram-floor-stop" {
        return persist("PRIVATE_RAM_V1_FLOOR_STOP.json", &custody);
    }
    let grant = evidence::bound(&custody["release"])?;
    let active = timer(&grant)?;
    let binding = json!({"producer":UNIT,"invocation_id":gap_floor_stop::RAM_IID,"guard":GUARD,"timer":TIMER,
                          "timer_invocation_id":TIMER_ID,"release":custody["release"],"stop_completion":custody["stop_completion"]});
    if action == "ram-drain-check" {
        if !active {
            drained()?;
        }
        return Ok(
            json!({"binding":binding,"active_timer":active,"partial":custody["partial"],"mutated":false}),
        );
    }
    let terminal = persist("PRIVATE_RAM_V1_FLOOR_STOP.json", &custody)?;
    let intent = persist(
        "PRIVATE_RAM_V1_GUARD_DRAIN_INTENT.json",
        &json!({"binding":binding,"terminal":terminal}),
    )?;
    if active {
        ensure!(timer(&grant)?, "timer changed before handback");
        evidence::command("/usr/bin/systemctl", &["stop", "--", TIMER])?;
    }
    let deadline = Instant::now() + Duration::from_secs(45);
    while let Err(error) = drained() {
        if Instant::now() >= deadline {
            return Err(error);
        }
        thread::sleep(Duration::from_millis(150));
    }
    persist(
        "PRIVATE_RAM_V1_GUARD_DRAIN.json",
        &json!({"intent":intent,"terminal":terminal,"binding":binding,
            "producer_and_guard_drained":true,"resource_credit_bytes":0,"closed_segment":false,"publication_authorized":false}),
    )
}
