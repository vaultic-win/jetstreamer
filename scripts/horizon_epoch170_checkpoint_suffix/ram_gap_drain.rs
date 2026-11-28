//! Hand back the identified RAM-gap guard after durable partial-output custody.
use super::{evidence, gap_floor_stop, ram_bootstrap_stop};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{
    fs,
    os::fd::AsRawFd,
    path::Path,
    thread,
    time::{Duration, Instant},
};

struct Attempt {
    root: &'static str,
    unit: &'static str,
    guard: &'static str,
    timer: &'static str,
    timer_id: &'static str,
    iid: &'static str,
    guard_sha: &'static str,
    receipt_prefix: &'static str,
}

const FIRST: Attempt = Attempt {
    root: gap_floor_stop::RAM_ROOT,
    unit: gap_floor_stop::RAM_UNIT,
    iid: gap_floor_stop::RAM_IID,
    guard: "horizon-guard-170-from-73760367-ram-20261128-v1.service",
    timer: "horizon-guard-170-from-73760367-ram-20261128-v1.timer",
    timer_id: "da36ff9db8f44e668164ff29465ce6d0",
    guard_sha: "91e272ec9910f153dedf754c1190862149deb90330f13ec625b946658e90288b",
    receipt_prefix: "PRIVATE_RAM_V1",
};
const SECOND: Attempt = Attempt {
    root: ram_bootstrap_stop::ROOT,
    unit: ram_bootstrap_stop::UNIT,
    iid: ram_bootstrap_stop::IID,
    guard: "horizon-guard-170-from-73760367-ram-20261128-v2.service",
    timer: "horizon-guard-170-from-73760367-ram-20261128-v2.timer",
    timer_id: "12958af424c94be8b63ba2ffde7a7d22",
    guard_sha: "d317d61f8c678b34dde4f2f0a107fcb8a54e5a47d4673648dae4cc2447524fc8",
    receipt_prefix: "PRIVATE_RAM_V2",
};

fn persist(attempt: &Attempt, name: &str, value: &Value) -> Result<Value> {
    let path = Path::new(attempt.root).join(format!("{}_{name}", attempt.receipt_prefix));
    if path.try_exists()? {
        let saved = evidence::reference(&path)?;
        ensure!(evidence::bound(&saved)? == *value, "different {name}");
        return Ok(saved);
    }
    evidence::receipt(&path, value)
}

fn timer(attempt: &Attempt, grant: &Value) -> Result<bool> {
    evidence::idle(attempt.unit)?;
    let state = evidence::props(
        attempt.timer,
        "Id,LoadState,ActiveState,SubState,Job,InvocationID,Triggers",
    )?;
    ensure!(
        state["Id"] == attempt.timer && state["Job"].is_empty(),
        "different or transitioning guard timer"
    );
    if state["ActiveState"] == "inactive" {
        return Ok(false);
    }
    let unit = evidence::props(
        attempt.guard,
        "Id,LoadState,TriggeredBy,ExecStart,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,Restart",
    )?;
    let plan = evidence::bound(&grant["guard_plan"])?;
    let root = attempt.root;
    let executable = format!("{root}/package/guard");
    let expected = format!(
        "argv[]={executable} {root}/ACTUAL_GUARD_PLAN.json --plan-sha256 {} --self-sha256 {} ;",
        evidence::word(&grant["guard_plan"], "sha256")?,
        attempt.guard_sha
    );
    ensure!(
        state["ActiveState"] == "active"
            && matches!(state["SubState"].as_str(), "waiting" | "running")
            && state["InvocationID"] == attempt.timer_id
            && grant["guard_timer_invocation_id"] == attempt.timer_id
            && state["Triggers"] == attempt.guard
            && unit["Id"] == attempt.guard
            && unit["TriggeredBy"] == attempt.timer
            && unit["Restart"] == "no"
            && unit["MemoryMax"] == "1073741824"
            && unit["MemorySwapMax"] == "0"
            && unit["CPUQuotaPerSecUSec"] == "1s"
            && unit["ExecStart"].contains(&expected)
            && plan["unit"] == attempt.unit
            && plan["invocation_id"] == attempt.iid,
        "different guard timer, executable, invocation, plan or resources"
    );
    Ok(true)
}

fn drained(attempt: &Attempt) -> Result<()> {
    evidence::idle(attempt.timer)?;
    evidence::idle(attempt.guard)?;
    evidence::idle(attempt.unit)?;
    for name in [attempt.guard, attempt.unit] {
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
    let (attempt, custody) = if action.starts_with("ram-second-") {
        (&SECOND, ram_bootstrap_stop::report()?)
    } else {
        (&FIRST, gap_floor_stop::report(true)?)
    };
    if action.ends_with("-floor-stop") {
        return persist(attempt, "FLOOR_STOP.json", &custody);
    }
    let grant = evidence::bound(&custody["release"])?;
    let active = timer(attempt, &grant)?;
    let binding = json!({"producer":attempt.unit,"invocation_id":attempt.iid,"guard":attempt.guard,"timer":attempt.timer,
                          "timer_invocation_id":attempt.timer_id,"release":custody["release"],"stop_completion":custody["stop_completion"]});
    if action.ends_with("-drain-check") {
        if !active {
            drained(attempt)?;
        }
        return Ok(
            json!({"binding":binding,"active_timer":active,"partial":custody["partial"],"mutated":false}),
        );
    }
    let terminal = persist(attempt, "FLOOR_STOP.json", &custody)?;
    let intent = persist(
        attempt,
        "GUARD_DRAIN_INTENT.json",
        &json!({"binding":binding,"terminal":terminal}),
    )?;
    if active {
        ensure!(timer(attempt, &grant)?, "timer changed before handback");
        evidence::command("/usr/bin/systemctl", &["stop", "--", attempt.timer])?;
    }
    let deadline = Instant::now() + Duration::from_secs(45);
    while let Err(error) = drained(attempt) {
        if Instant::now() >= deadline {
            return Err(error);
        }
        thread::sleep(Duration::from_millis(150));
    }
    persist(
        attempt,
        "GUARD_DRAIN.json",
        &json!({"intent":intent,"terminal":terminal,"binding":binding,
            "producer_and_guard_drained":true,"resource_credit_bytes":0,"closed_segment":false,"publication_authorized":false}),
    )
}
