//! Preserve PID1's process exit status before systemd collects the transient unit.
//! Follows the epoch 170 continuation observer's RefUnit and pidfd sequence.

use super::*;
use std::{
    ffi::{c_char, c_int, c_void},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    ptr, thread,
    time::Duration,
};

const SCHEMA: &str = "foundation-epoch266-private-overlap-pid1-exit-v1";

#[link(name = "libsystemd.so.0", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    fn sd_bus_open_system(bus: *mut *mut c_void) -> c_int;
    fn sd_bus_call_method(
        bus: *mut c_void,
        destination: *const c_char,
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

struct UnitReference(*mut c_void);

impl UnitReference {
    fn hold(unit: &str) -> Result<Self> {
        let mut raw = ptr::null_mut();
        // SAFETY: raw is a writable bus pointer out-parameter.
        systemd_result(unsafe { sd_bus_open_system(&mut raw) })?;
        let bus = Self(raw);
        let unit = CString::new(unit)?;
        // SAFETY: the bus is open, the variadic argument is a single C string
        // as specified by "s", and no reply or error ownership is requested.
        systemd_result(unsafe {
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

impl Drop for UnitReference {
    fn drop(&mut self) {
        // SAFETY: this object exclusively owns the bus. Disconnect releases
        // the manager reference without starting, stopping, or editing a unit.
        unsafe { sd_bus_flush_close_unref(self.0) };
    }
}

fn systemd_result(value: c_int) -> Result<()> {
    if value < 0 {
        return Err(io::Error::from_raw_os_error(-value).into());
    }
    Ok(())
}

fn pidfd(pid: u32) -> Result<OwnedFd> {
    // SAFETY: pidfd_open takes a PID and flags and returns a new descriptor.
    let result = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if result < 0 {
        return Err(io::Error::last_os_error()).context("opening the admitted producer pidfd");
    }
    // SAFETY: successful pidfd_open created a descriptor owned by this process.
    Ok(unsafe { OwnedFd::from_raw_fd(result as i32) })
}

fn exited(fd: &OwnedFd, timeout_ms: i32) -> Result<bool> {
    loop {
        let mut descriptor = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: the descriptor is live and the single pollfd entry is writable.
        match unsafe { libc::poll(&mut descriptor, 1, timeout_ms) } {
            0 => return Ok(false),
            1 if descriptor.revents & libc::POLLIN != 0 => return Ok(true),
            -1 if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => continue,
            -1 => return Err(io::Error::last_os_error()).context("waiting on producer pidfd"),
            _ => bail!("unexpected producer pidfd event"),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Capture {
    schema: String,
    launch: Reference,
    boot_id: String,
    producer_invocation: String,
    producer_pid: u32,
    properties: UnitState,
}

fn ensure_unit(state: &UnitState, launch: &Launch) -> Result<()> {
    for (field, expected) in [
        ("Id", launch.unit.as_str()),
        ("InvocationID", launch.invocation_id.as_str()),
        ("ExecMainPID", &launch.main_pid.to_string()),
        ("LoadState", "loaded"),
        ("NRestarts", "0"),
        ("Restart", "no"),
    ] {
        ensure!(
            state.get(field).is_some_and(|value| value == expected),
            "PID1 producer {field} changed during exit capture"
        );
    }
    Ok(())
}

pub(super) fn capture(launch_sha: &str, destination: &Path) -> Result<Value> {
    require_root()?;
    let parent = destination_parent(destination)?;
    let admitted = Admitted::load(launch_sha)?;
    let launch = &admitted.launch;
    let _held = UnitReference::hold(&launch.unit)
        .context("retaining the producer unit until PID1 exit capture")?;
    let fd = pidfd(launch.main_pid)?;
    let running = unit_state(&launch.unit)?;
    ensure_unit(&running, launch)?;
    let start = state_timestamp(&running, "ExecMainStartTimestampMonotonic")?;
    ensure!(
        running
            .get("ActiveState")
            .is_some_and(|state| state == "active")
            && running
                .get("SubState")
                .is_some_and(|state| state == "running")
            && running
                .get("MainPID")
                .is_some_and(|pid| pid == &launch.main_pid.to_string())
            && running
                .get("ControlGroup")
                .is_some_and(|group| group == &launch.cgroup())
            && PathBuf::from(format!("/proc/{}/exe", launch.main_pid)).read_link()?
                == launch.node_path
            && !exited(&fd, 0)?,
        "producer is no longer running under the admitted identity"
    );
    eprintln!(
        "Watching PID1 exit for {} invocation {} PID {}",
        launch.unit, launch.invocation_id, launch.main_pid
    );
    ensure!(
        exited(&fd, 7_300_000)?,
        "producer exceeded the exit capture window"
    );
    for _ in 0..100 {
        let properties = unit_state(&launch.unit)?;
        ensure_unit(&properties, launch)?;
        ensure!(
            state_timestamp(&properties, "ExecMainStartTimestampMonotonic")? == start,
            "PID1 records a new producer start"
        );
        if matches!(
            properties.get("ActiveState").map(String::as_str),
            Some("inactive" | "failed")
        ) && properties.get("MainPID").is_some_and(|value| value == "0")
            && properties
                .get("ControlPID")
                .is_some_and(|value| value == "0")
        {
            ensure!(
                state_timestamp(&properties, "ExecMainExitTimestampMonotonic")? > start,
                "PID1 lacks a terminal process exit time"
            );
            admitted.unchanged()?;
            let receipt = Capture {
                schema: SCHEMA.to_owned(),
                launch: Reference::new(LAUNCH, launch_sha),
                boot_id: admitted.boot.clone(),
                producer_invocation: launch.invocation_id.clone(),
                producer_pid: launch.main_pid,
                properties,
            };
            let staging = stage_package(parent)?;
            let reference = write_sealed(&staging.path().join("pid1-exit.json"), &receipt)?;
            persist_package(staging, destination, parent)?;
            return Ok(
                json!({"pid1_exit": Reference::new(destination.join("pid1-exit.json"), &reference.sha256)}),
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
    bail!("PID1 did not settle after the admitted producer exited")
}

pub(super) fn read(reference: &Reference, admitted: &Admitted) -> Result<UnitState> {
    let capture: Capture = serde_json::from_value(reference.read()?)?;
    ensure!(
        capture.schema == SCHEMA
            && capture.launch == admitted.reference
            && capture.boot_id == admitted.boot
            && capture.producer_pid == admitted.launch.main_pid
            && capture.producer_invocation == admitted.launch.invocation_id,
        "PID1 exit receipt belongs to a different launch or boot"
    );
    ensure_unit(&capture.properties, &admitted.launch)?;
    Ok(capture.properties)
}
