//! One original held service's scheduler request, without changing its process.
//! Cancel before task capture; reattach only after the reader and first guard.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    fs,
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub trait Transport {
    fn metadata(&mut self, label: &str, command: Command, limit: Duration) -> Result<Value>;
}
const FIELDS: &str = "Id,InvocationID,MainPID,ControlPID,ControlGroup,NRestarts,Job,ActiveState,SubState,Result,ExecMainStartTimestampMonotonic,StateChangeTimestampMonotonic,InactiveExitTimestampMonotonic,ActiveEnterTimestampMonotonic,TimeoutStartUSec,RuntimeMaxUSec,MemoryMax,MemoryHigh,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,User,Group,NoNewPrivileges,ExecStart,ExecStartPre,FragmentPath,DropInPaths";
fn number(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .with_context(|| format!("start request integer {key}"))
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .with_context(|| format!("start request string {key}"))
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn hex(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn unit(s: &str) -> bool {
    s.len() < 180
        && s.ends_with(".service")
        && (s.starts_with("horizon-qualify-185-")
            || s.starts_with("horizon-positive185-held-request-control-"))
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
fn job_id(s: &str) -> Result<u32> {
    let id = s.parse::<u32>()?;
    ensure!(
        id > 0 && id.to_string() == s,
        "canonical positive start job id"
    );
    Ok(id)
}
pub fn process_start_ticks(pid: u32) -> Result<u64> {
    ensure!(pid > 1, "original held PID");
    let raw = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    raw.rsplit_once(')')
        .context("held stat command")?
        .1
        .split_whitespace()
        .nth(19)
        .context("held stat start clock")?
        .parse()
        .map_err(Into::into)
}
pub struct Owner {
    actor: String,
    iid: String,
    pid: u32,
    ticks: u64,
    deadline: u64,
}
impl Owner {
    pub fn from_ready(actor: &str, iid: &str, ready: &Value, deadline: u64) -> Result<Self> {
        let pid = u32::try_from(number(ready, "pid")?)?;
        ensure!(
            unit(actor) && hex(iid) && pid > 1 && pid <= i32::MAX as u32,
            "exact original held start request owner"
        );
        ensure!(
            ready["actor_unit"] == actor
                && ready["actor_invocation_id"] == iid
                && number(ready, "started_at")?.checked_add(600) == Some(deadline)
                && number(ready, "start_ticks")? > 0,
            "original ready identity/600s clock"
        );
        Ok(Self {
            actor: actor.into(),
            iid: iid.into(),
            pid,
            ticks: number(ready, "start_ticks")?,
            deadline,
        })
    }
    fn value(&self) -> Value {
        json!({"actor":self.actor,"invocation_id":self.iid,"pid":self.pid,
            "start_ticks":self.ticks,"original_setup_deadline":self.deadline})
    }
    fn held(&self, native: &Value) -> Result<()> {
        let pid_text = self.pid.to_string();
        ensure!(
            now()? < self.deadline,
            "original held setup expired; no request handoff"
        );
        ensure!(
            native["Id"] == self.actor
                && native["InvocationID"] == self.iid
                && native["MainPID"] == "0"
                && native["ControlPID"] == pid_text.as_str()
                && native["ActiveState"] == "activating"
                && native["SubState"] == "start-pre"
                && native["NRestarts"] == "0"
                && native["Result"] == "success"
                && native["ExecMainStartTimestampMonotonic"] == "0"
                && native["ControlGroup"] == format!("/system.slice/{}", self.actor),
            "original held owner changed during request handoff"
        );
        ensure!(
            process_start_ticks(self.pid)? == self.ticks,
            "original held PID start clock changed"
        );
        ensure!(
            fs::read_to_string(format!("/proc/{}/cgroup", self.pid))?
                == format!("0::/system.slice/{}\n", self.actor),
            "original held process cgroup changed"
        );
        Ok(())
    }
}
struct Pidfd(i32);
impl Pidfd {
    fn open(pid: u32) -> Result<Self> {
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 };
        ensure!(fd >= 0, "original held pidfd");
        Ok(Self(fd))
    }
    fn alive(&self) -> Result<()> {
        let mut p = libc::pollfd {
            fd: self.0,
            events: libc::POLLIN,
            revents: 0,
        };
        ensure!(
            unsafe { libc::poll(&mut p, 1, 0) } == 0,
            "original held process exited during handoff"
        );
        Ok(())
    }
}
impl Drop for Pidfd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}
fn stdout(v: &Value) -> Result<Vec<u8>> {
    ensure!(
        v["exit_code"] == 0
            && v["exit_signal"].is_null()
            && v["wait_error"].is_null()
            && v["stdout_overflow"] == false
            && v["stderr_overflow"] == false
            && v["stdout_read_error"].is_null()
            && v["stderr_read_error"].is_null(),
        "original request command failed or output was incomplete"
    );
    Ok(serde_json::from_value(v["stdout_bytes"].clone())?)
}
fn query(t: &mut impl Transport, owner: &Owner) -> Result<Value> {
    let mut command = Command::new("/usr/bin/systemctl");
    command.args([
        "show",
        &owner.actor,
        "--no-pager",
        &format!("--property={FIELDS}"),
    ]);
    let out = t.metadata("start-request-owner", command, Duration::from_secs(5))?;
    let mut map = serde_json::Map::new();
    for line in std::str::from_utf8(&stdout(&out)?)?.lines() {
        let (k, v) = line.split_once('=').context("start request native line")?;
        ensure!(
            map.insert(k.into(), json!(v)).is_none(),
            "duplicate request native field"
        );
    }
    ensure!(
        map.len() == FIELDS.split(',').count(),
        "complete original held native properties"
    );
    let value = Value::Object(map);
    owner.held(&value)?;
    Ok(value)
}
fn same_except_job(before: &Value, after: &Value) -> Result<()> {
    let a = before.as_object().context("original native object")?;
    let b = after.as_object().context("following native object")?;
    ensure!(
        a.len() == b.len() && a.iter().all(|(k, v)| k == "Job" || b.get(k) == Some(v)),
        "request handoff changed original native process/source/limit/state/clock"
    );
    Ok(())
}
fn unit_object(actor: &str) -> String {
    let mut out = String::from("/org/freedesktop/systemd1/unit/");
    for b in actor.bytes() {
        if b.is_ascii_alphanumeric() {
            out.push(char::from(b));
        } else {
            use std::fmt::Write as _;
            write!(out, "_{b:02x}").expect("String formatting");
        }
    }
    out
}
fn job_output(raw: &[u8], actor: &str, id: &str) -> Result<()> {
    job_id(id)?;
    let expected = format!(
        "u {id}\n(so) {actor:?} {:?}\ns \"start\"\ns \"running\"\n",
        unit_object(actor)
    );
    ensure!(
        raw == expected.as_bytes(),
        "exact native held start request Unit/Id/type/state"
    );
    Ok(())
}
fn authenticate_job(t: &mut impl Transport, owner: &Owner, native: &Value) -> Result<Value> {
    let id = text(native, "Job")?;
    job_id(id)?;
    let mut command = Command::new("/usr/bin/busctl");
    command.args([
        "--system",
        "get-property",
        "org.freedesktop.systemd1",
        &format!("/org/freedesktop/systemd1/job/{id}"),
        "org.freedesktop.systemd1.Job",
        "Id",
        "Unit",
        "JobType",
        "State",
    ]);
    let actual = t.metadata("start-request-typed-job", command, Duration::from_secs(5))?;
    job_output(&stdout(&actual)?, &owner.actor, id)?;
    Ok(actual)
}
pub fn detach(t: &mut impl Transport, owner: &Owner) -> Result<Value> {
    let fd = Pidfd::open(owner.pid)?;
    fd.alive()?;
    let before = query(t, owner)?;
    let job = text(&before, "Job")?.to_owned();
    let typed = authenticate_job(t, owner, &before)?;
    let mut command = Command::new("/usr/bin/systemctl");
    command.args(["cancel", &job]);
    let cancel = t.metadata(
        "cancel-only-original-start-request",
        command,
        Duration::from_secs(5),
    )?;
    stdout(&cancel)?;
    let after = query(t, owner)?;
    fd.alive()?;
    same_except_job(&before, &after)?;
    ensure!(after["Job"] == "", "original start request remains queued");
    Ok(
        json!({"schema":"horizon-original-held-start-request-detached-v1","owner":owner.value(),
        "before_native":before,"detached_native":after,"original_typed_job":typed,
        "original_cancel_command":cancel,"recorded_at":now()?,"original_pidfd_alive_after":true,
        "no_actor_signal_restart_or_clock_renewal":true,"resource_credit_bytes":0,"replay_launch_authorized":false}),
    )
}
pub fn validate_detached(proof: &Value, owner: &Owner) -> Result<()> {
    ensure!(
        proof["schema"] == "horizon-original-held-start-request-detached-v1"
            && proof["owner"] == owner.value()
            && proof["original_pidfd_alive_after"] == true
            && proof["no_actor_signal_restart_or_clock_renewal"] == true
            && proof["resource_credit_bytes"] == 0
            && proof["replay_launch_authorized"] == false
            && number(proof, "recorded_at")? < owner.deadline
            && number(proof, "recorded_at")? <= now()?,
        "original detached request proof scope/identity/clock changed"
    );
    let before = &proof["before_native"];
    let after = &proof["detached_native"];
    same_except_job(before, after)?;
    owner.held(after)?;
    let job = text(before, "Job")?;
    job_id(job)?;
    ensure!(
        after["Job"] == "",
        "detached request native job is not empty"
    );
    let cancel = &proof["original_cancel_command"];
    ensure!(
        cancel["program"] == "/usr/bin/systemctl" && cancel["argv"] == json!(["cancel", job]),
        "detachment did not cancel only the original start request"
    );
    stdout(cancel)?;
    job_output(&stdout(&proof["original_typed_job"])?, &owner.actor, job)?;
    Ok(())
}
pub fn restore(t: &mut impl Transport, owner: &Owner, detached: &Value) -> Result<Value> {
    validate_detached(detached, owner)?;
    let fd = Pidfd::open(owner.pid)?;
    fd.alive()?;
    let before = query(t, owner)?;
    same_except_job(&detached["detached_native"], &before)?;
    ensure!(
        before["Job"] == "",
        "another request attached before original restore"
    );
    let mut command = Command::new("/usr/bin/systemctl");
    command.args(["--no-block", "start", &owner.actor]);
    let start = t.metadata(
        "restore-same-original-start-request",
        command,
        Duration::from_secs(5),
    )?;
    stdout(&start)?;
    let after = query(t, owner)?;
    fd.alive()?;
    same_except_job(&before, &after)?;
    let job = text(&after, "Job")?;
    job_id(job)?;
    ensure!(
        after["Job"] != detached["before_native"]["Job"],
        "original canceled job was reused"
    );
    let typed = authenticate_job(t, owner, &after)?;
    Ok(
        json!({"schema":"horizon-original-held-start-request-restored-v1","owner":owner.value(),
        "before_native":before,"restored_native":after,"original_start_command":start,
        "replacement_typed_job":typed,"recorded_at":now()?,"original_pidfd_alive_after":true,
        "no_actor_signal_restart_or_clock_renewal":true,"resource_credit_bytes":0,"replay_launch_authorized":false}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_job_ids_reject_empty_zero_signed_and_overflow() {
        assert_eq!(job_id("123").unwrap(), 123);
        for s in ["", "0", "01", "+1", "-1", "4294967296", "12/start"] {
            assert!(job_id(s).is_err(), "{s}");
        }
    }
    #[test]
    fn handoff_preserves_every_non_job_native_field() {
        let a = json!({"Job":"123","InvocationID":"a","ControlPID":"24","StateChangeTimestampMonotonic":"100","MemoryMax":"999"});
        let mut b = a.clone();
        b["Job"] = json!("");
        assert!(same_except_job(&a, &b).is_ok());
        for k in [
            "InvocationID",
            "ControlPID",
            "StateChangeTimestampMonotonic",
            "MemoryMax",
        ] {
            let mut bad = b.clone();
            bad[k] = json!("changed");
            assert!(same_except_job(&a, &bad).is_err());
        }
        b.as_object_mut().unwrap().remove("ControlPID");
        assert!(same_except_job(&a, &b).is_err());
    }
    #[test]
    fn typed_start_request_rejects_foreign_owner_type_state_and_id() {
        let actor = "horizon-qualify-185-test.service";
        let raw = format!(
            "u 12\n(so) {actor:?} {:?}\ns \"start\"\ns \"running\"\n",
            unit_object(actor)
        );
        assert!(job_output(raw.as_bytes(), actor, "12").is_ok());
        for bad in [
            raw.replace("u 12", "u 13"),
            raw.replace("\"start\"", "\"stop\""),
            raw.replace("\"running\"", "\"waiting\""),
            raw.replace("test.service", "foreign.service"),
        ] {
            assert!(job_output(bad.as_bytes(), actor, "12").is_err());
        }
    }
    #[test]
    fn original_ready_requires_exact_owner_pid_start_and_600s_clock() {
        let a = "horizon-qualify-185-test.service";
        let iid = "a".repeat(32);
        let r = json!({"actor_unit":a,"actor_invocation_id":iid,"pid":123,"start_ticks":10,"started_at":1000});
        assert!(Owner::from_ready(a, &iid, &r, 1600).is_ok());
        assert!(Owner::from_ready(a, &iid, &r, 1601).is_err());
        assert!(Owner::from_ready(a, &"b".repeat(32), &r, 1600).is_err());
        for (k, v) in [("pid", 0), ("start_ticks", 0)] {
            let mut bad = r.clone();
            bad[k] = json!(v);
            assert!(Owner::from_ready(a, &iid, &bad, 1600).is_err());
        }
    }
}
