//! Retain the exact transient unit until its main-process exit status is durable.
use super::{CAPTURE_DIR as DIR, IID, UNIT, evidence::*};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    ffi::{CString, c_char, c_int, c_void},
    fs, io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::Path,
    ptr, thread,
    time::Duration,
};

const FIELDS: &str = "Id,ActiveState,InvocationID,MainPID,ControlPID,ExecMainPID,ExecMainCode,ExecMainStatus,ExecMainExitTimestampMonotonic,Result";
#[link(name = "libsystemd.so.0", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    fn sd_bus_open_system(bus: *mut *mut c_void) -> c_int;
    fn sd_bus_call_method(
        bus: *mut c_void,
        dest: *const c_char,
        path: *const c_char,
        interface: *const c_char,
        method: *const c_char,
        error: *mut c_void,
        reply: *mut *mut c_void,
        types: *const c_char,
        ...
    ) -> c_int;
    fn sd_bus_flush_close_unref(bus: *mut c_void) -> *mut c_void;
}

struct Bus(*mut c_void);
impl Drop for Bus {
    fn drop(&mut self) {
        // Closing the private connection releases its RefUnit reference.
        unsafe {
            sd_bus_flush_close_unref(self.0);
        }
    }
}
fn check_bus(result: c_int) -> Result<()> {
    if result < 0 {
        return Err(io::Error::from_raw_os_error(-result).into());
    }
    Ok(())
}
impl Bus {
    fn pin() -> Result<Self> {
        let mut ptr = ptr::null_mut();
        check_bus(unsafe { sd_bus_open_system(&mut ptr) })?;
        let bus = Self(ptr);
        let unit = CString::new(UNIT)?;
        check_bus(unsafe {
            sd_bus_call_method(
                bus.0,
                c"org.freedesktop.systemd1".as_ptr(),
                c"/org/freedesktop/systemd1".as_ptr(),
                c"org.freedesktop.systemd1.Manager".as_ptr(),
                c"RefUnit".as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                c"s".as_ptr(),
                unit.as_ptr(),
            )
        })?;
        Ok(bus)
    }
}
pub fn native_exit(actor: &Value) -> Result<Value> {
    let record = bound(&reference(&Path::new(DIR).join("PID1_EXIT.json"))?)?;
    let state = &record["properties"];
    ensure!(
        record["actor"] == *actor
            && state["InvocationID"] == IID
            && state["Id"] == UNIT
            && word(state, "ExecMainPID")?.parse::<u64>()? == num(actor, "producer_pid")?
            && word(state, "ExecMainExitTimestampMonotonic")?.parse::<u64>()? > 0
            && state["MainPID"] == "0"
            && state["ControlPID"] == "0",
        "foreign terminal capture"
    );
    Ok(state.clone())
}
pub fn capture(actor: &Value, release: &Value) -> Result<()> {
    let dir = Path::new(DIR);
    ensure!(
        actor["producer_invocation_id"] == IID
            && actor["unit"] == UNIT
            && fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim()
                == word(actor, "boot_id")?,
        "foreign actor"
    );
    if dir.join("PID1_EXIT.json").try_exists()? {
        native_exit(actor)?;
        return Ok(());
    }
    let _bus = Bus::pin()?;
    let pid: u32 = num(actor, "producer_pid")?.try_into()?;
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    let s = props(UNIT, FIELDS)?;
    ensure!(
        s["Id"] == UNIT
            && s["ActiveState"] == "active"
            && s["InvocationID"] == IID
            && s["MainPID"] == pid.to_string()
            && ticks(pid)? == num(actor, "start_ticks")?,
        "actor changed before pidfd bound"
    );
    let armed_path = dir.join("ARMED.json");
    let armed = if armed_path.try_exists()? {
        let r = reference(&armed_path)?;
        let prior = bound(&r)?;
        ensure!(
            prior["actor"] == *actor
                && prior["release"] == *release
                && prior["pidfd_bound"] == true
                && prior["unit_reference_held"] == true,
            "a different capture was armed"
        );
        r
    } else {
        receipt(
            &armed_path,
            &json!({"actor":actor,"release":release,"pidfd_bound":true,"unit_reference_held":true,"timestamp":now()?}),
        )?
    };
    let mut wait = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let result = unsafe { libc::poll(&mut wait, 1, -1) };
        if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        ensure!(
            result == 1 && wait.revents & libc::POLLIN != 0,
            "pidfd wait failed"
        );
        break;
    }
    for _ in 0..100 {
        let end = props(UNIT, FIELDS)?;
        ensure!(
            end["Id"] == UNIT
                && end["InvocationID"] == IID
                && end["ExecMainPID"] == pid.to_string(),
            "replaced PID1 identity"
        );
        if matches!(end["ActiveState"].as_str(), "failed" | "inactive")
            && end["MainPID"] == "0"
            && end["ControlPID"] == "0"
        {
            ensure!(
                end["ExecMainExitTimestampMonotonic"]
                    .parse::<u64>()
                    .context("invalid exit time")?
                    > 0,
                "no native exit time"
            );
            receipt(
                &dir.join("PID1_EXIT.json"),
                &json!({"actor":actor,"release":release,"armed":armed,"properties":end,"timestamp":now()?}),
            )?;
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    anyhow::bail!("PID1 did not settle after producer exit")
}
