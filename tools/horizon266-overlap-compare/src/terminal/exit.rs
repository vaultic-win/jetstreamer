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
pub(super) struct Capture {
    schema: String,
    launch: Reference,
    boot_id: String,
    producer_invocation: String,
    producer_pid: u32,
    properties: UnitState,
}

struct Producer<'a> {
    unit: &'a str,
    invocation: &'a str,
    pid: u32,
    node: &'a Path,
}

impl<'a> From<&'a Launch> for Producer<'a> {
    fn from(launch: &'a Launch) -> Self {
        Self {
            unit: &launch.unit,
            invocation: &launch.invocation_id,
            pid: launch.main_pid,
            node: &launch.node_path,
        }
    }
}

fn ensure_unit(state: &UnitState, producer: &Producer<'_>) -> Result<()> {
    for (field, expected) in [
        ("Id", producer.unit),
        ("InvocationID", producer.invocation),
        ("ExecMainPID", &producer.pid.to_string()),
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

fn capture_properties(
    producer: &Producer<'_>,
    timeout_ms: i32,
) -> Result<(UnitReference, UnitState)> {
    let held = UnitReference::hold(producer.unit)
        .context("retaining the producer unit until PID1 exit capture")?;
    let fd = pidfd(producer.pid)?;
    let running = unit_state(producer.unit)?;
    ensure_unit(&running, producer)?;
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
                .is_some_and(|pid| pid == &producer.pid.to_string())
            && running
                .get("ControlGroup")
                .is_some_and(|group| group == &format!("/system.slice/{}", producer.unit))
            && PathBuf::from(format!("/proc/{}/exe", producer.pid)).read_link()? == producer.node
            && !exited(&fd, 0)?,
        "producer is no longer running under the admitted identity"
    );
    eprintln!(
        "Watching PID1 exit for {} invocation {} PID {}",
        producer.unit, producer.invocation, producer.pid
    );
    ensure!(
        exited(&fd, timeout_ms)?,
        "producer exceeded the exit capture window"
    );
    for _ in 0..100 {
        let properties = unit_state(producer.unit)?;
        ensure_unit(&properties, producer)?;
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
            return Ok((held, properties));
        }
        thread::sleep(Duration::from_millis(100));
    }
    bail!("PID1 did not settle after the admitted producer exited")
}

fn persist_capture(parent: &Path, destination: &Path, receipt: &Capture) -> Result<Value> {
    let staging = stage_package(parent)?;
    let reference = write_sealed(&staging.path().join("pid1-exit.json"), receipt)?;
    persist_package(staging, destination, parent)?;
    Ok(json!({"pid1_exit": Reference::new(destination.join("pid1-exit.json"), &reference.sha256)}))
}

pub(super) fn capture(launch_sha: &str, destination: &Path) -> Result<Value> {
    require_root()?;
    let parent = destination_parent(destination)?;
    let admitted = Admitted::load(launch_sha)?;
    let producer = Producer::from(&admitted.launch);
    let (_held, properties) = capture_properties(&producer, 7_300_000)?;
    admitted.unchanged()?;
    persist_capture(
        parent,
        destination,
        &Capture {
            schema: SCHEMA.to_owned(),
            launch: Reference::new(LAUNCH, launch_sha),
            boot_id: admitted.boot.clone(),
            producer_invocation: producer.invocation.to_owned(),
            producer_pid: producer.pid,
            properties,
        },
    )
}

pub(super) fn capture_v1627(launch_sha: &str, destination: &Path) -> Result<Value> {
    capture_window230(&window230::V1627, launch_sha, destination)
}

pub(super) fn capture_adjacent230(launch_sha: &str, destination: &Path) -> Result<Value> {
    capture_window230(&window230::ADJACENT, launch_sha, destination)
}

pub(super) fn capture_next_v1627(
    launch_sha: &str,
    invocation: &str,
    destination: &Path,
) -> Result<Value> {
    capture_window230(&window230::next_v1627(launch_sha, invocation)?, launch_sha, destination)
}

pub(super) const WINDOW266_STATE: &str =
    "/var/lib/jetstreamer/horizon266-window-114929698-114936474-runtime-v1";
pub(super) const WINDOW266_UNIT: &str =
    "horizon-qualify-checkpoint-continuation-266-window-114936474-v1.service";
pub(super) const WINDOW266_NODE: &str =
    "/var/lib/jetstreamer/horizon266-window-node-10fe8f2f-v1/jetstreamer-node";
const WINDOW266_EXIT_SCHEMA: &str = "foundation-epoch266-private-window-pid1-exit-v1";

pub(super) fn window266_launch(launch_sha: &str) -> Result<(Reference, Value, u32)> {
    const PROFILE_SHA: &str = "f7562054a31277bc38747652f9a79e6967b393d8713499e6998841390cb4c5d6";
    let state = Path::new(WINDOW266_STATE);
    let reference = Reference::new(state.join("cadence-registration.json"), launch_sha);
    let launch = reference.read()?;
    let invocation = string(&launch, "invocation_id")?;
    let pid: u32 = serde_json::from_value(launch["main_pid"].clone())?;
    let guard_plan: Reference = serde_json::from_value(launch["guard_plan"].clone())?;
    let active_guard: Reference = serde_json::from_value(launch["active_guard"].clone())?;
    let release: Reference = serde_json::from_value(launch["guard_release_fit"].clone())?;
    let sample = active_guard.read_guard_sample(&state.join("guard-receipts"))?;
    let fit = release.read()?;
    ensure!(
        launch["schema"] == "jetstreamer-historical-performance-launch-receipt-v1"
            && launch["kind"] == "epoch266-private-hourly-window"
            && launch["epoch"] == 266
            && launch["unit"] == WINDOW266_UNIT
            && launch["node_path"] == WINDOW266_NODE
            && launch["profile"] == json!(Reference::new(state.join("profile.json"), PROFILE_SHA))
            && launch["launched"] == true
            && launch["diagnostic_only"] == true
            && launch["canonical_epoch_publication_authorized"] == false
            && hex(invocation, 32)
            && pid > 1
            && guard_plan.path == state.join("guard-plan.json")
            && guard_plan.read()?["invocation_id"] == invocation
            && release.path == state.join("guard-release-fit.json")
            && fit["schema"] == "foundation-epoch266-private-window-guard-release-fit-v1"
            && fit["invocation_id"] == invocation
            && fit["guard_plan"] == launch["guard_plan"]
            && fit["node_plan"] == launch["node_plan"]
            && sample["producer_invocation_id"] == invocation
            && sample["producer"]["active"] == "active"
            && sample["producer"]["pid"] == pid
            && sample["plan_sha256"] == guard_plan.sha256
            && sample["producer_stop_enabled"] == true
            && sample["trip_reason"].is_null(),
        "foreign epoch 266 window launch or live guard"
    );
    Ok((reference, launch, pid))
}

pub(super) fn capture_window266(launch_sha: &str, destination: &Path) -> Result<Value> {
    require_root()?;
    let parent = destination_parent(destination)?;
    let (reference, launch, pid) = window266_launch(launch_sha)?;
    let invocation = string(&launch, "invocation_id")?;
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    ensure!(hex(&boot_id, 32), "invalid running boot ID");
    let producer = Producer {
        unit: WINDOW266_UNIT,
        invocation,
        pid,
        node: Path::new(WINDOW266_NODE),
    };
    let (_held, properties) = capture_properties(&producer, 7_300_000)?;
    ensure!(
        reference.read()? == launch,
        "epoch 266 window launch changed during capture"
    );
    persist_capture(
        parent,
        destination,
        &Capture {
            schema: WINDOW266_EXIT_SCHEMA.to_owned(),
            launch: reference,
            boot_id,
            producer_invocation: invocation.to_owned(),
            producer_pid: pid,
            properties,
        },
    )
}

pub(super) fn read_window266(
    reference: &Reference,
    launch: &Reference,
    invocation: &str,
    pid: u32,
    boot: &str,
) -> Result<UnitState> {
    let capture: Capture = serde_json::from_value(reference.read()?)?;
    ensure!(
        capture.schema == WINDOW266_EXIT_SCHEMA
            && &capture.launch == launch
            && capture.boot_id == boot
            && capture.producer_invocation == invocation
            && capture.producer_pid == pid,
        "foreign epoch 266 window PID1 exit capture"
    );
    ensure_unit(
        &capture.properties,
        &Producer {
            unit: WINDOW266_UNIT,
            invocation,
            pid,
            node: Path::new(WINDOW266_NODE),
        },
    )?;
    Ok(capture.properties)
}

fn capture_window230(
    window: &window230::Window<'_>,
    launch_sha: &str,
    destination: &Path,
) -> Result<Value> {
    require_root()?;
    let parent = destination_parent(destination)?;
    ensure!(
        launch_sha == window.launch_sha,
        "foreign epoch 230 launch receipt"
    );
    let (reference, launch, pid) = window230::load_launch(window)?;
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    ensure!(hex(&boot_id, 32), "invalid running boot ID");
    let producer = Producer {
        unit: window.unit,
        invocation: window.invocation,
        pid,
        node: Path::new(window.node),
    };
    let (_held, properties) = capture_properties(&producer, window.capture_timeout_ms)?;
    ensure!(
        reference.read()? == launch,
        "epoch 230 launch changed during capture"
    );
    persist_capture(
        parent,
        destination,
        &Capture {
            schema: window.exit_schema.to_owned(),
            launch: reference,
            boot_id,
            producer_invocation: window.invocation.to_owned(),
            producer_pid: pid,
            properties,
        },
    )
}

pub(super) const PREDECESSOR_UNIT: &str = "horizon-qualify-266-original-predecessor-v1.service";
const PREDECESSOR_EXIT_SCHEMA: &str = "foundation-epoch266-private-predecessor-pid1-exit-v1";

pub(super) fn predecessor_launch(launch_sha: &str) -> Result<(Reference, Value, u32)> {
    const STATE: &str = "/var/lib/jetstreamer/horizon266-original-predecessor-runtime-v1";
    const NODE: &str = "/var/lib/jetstreamer/horizon253255-node-index-20261118-v2/jetstreamer-node";
    let state = Path::new(STATE);
    let reference = Reference::new(state.join("cadence-registration.json"), launch_sha);
    let launch = reference.read()?;
    let invocation = string(&launch, "invocation_id")?;
    let pid = serde_json::from_value(launch["main_pid"].clone())?;
    let plan: Reference = serde_json::from_value(launch["guard_plan"].clone())?;
    let guard: Reference = serde_json::from_value(launch["active_guard"].clone())?;
    let sample = guard.read_guard_sample(&state.join("guard-receipts"))?;
    ensure!(
        launch["schema"] == "jetstreamer-historical-performance-launch-receipt-v1"
            && launch["epoch"] == 266
            && launch["kind"] == "epoch266-private-original-predecessor"
            && launch["unit"] == PREDECESSOR_UNIT
            && launch["node_path"] == NODE
            && launch["profile"]["sha256"]
                == "7ed80c05ae0e1c706a271452d9b0dcb516c651fd0f97a2ec3f1c61a477a30f21"
            && launch["bootstrap_custody"]["sha256"]
                == "afd03e2258229848a2878f1c2ff75b424ebf810b79fec65788c75ac5111a5959"
            && launch["launched"] == true
            && launch["diagnostic_only"] == true
            && launch["canonical_epoch_publication_authorized"] == false
            && hex(invocation, 32)
            && pid > 1
            && plan.path == state.join("guard-plan.json")
            && plan.read()?["invocation_id"] == invocation
            && sample["producer_invocation_id"] == invocation
            && sample["producer"]["pid"] == pid
            && sample["plan_sha256"] == plan.sha256
            && sample["producer_stop_enabled"] == true
            && sample["trip_reason"].is_null(),
        "foreign epoch 266 predecessor launch or live guard"
    );
    Ok((reference, launch, pid))
}

pub(super) fn capture_predecessor(launch_sha: &str, destination: &Path) -> Result<Value> {
    require_root()?;
    let parent = destination_parent(destination)?;
    let (reference, launch, pid) = predecessor_launch(launch_sha)?;
    let invocation = string(&launch, "invocation_id")?;
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    ensure!(hex(&boot_id, 32), "invalid running boot ID");
    let producer = Producer {
        unit: PREDECESSOR_UNIT,
        invocation,
        pid,
        node: Path::new(string(&launch, "node_path")?),
    };
    let (_held, properties) = capture_properties(&producer, 7_300_000)?;
    ensure!(
        reference.read()? == launch,
        "predecessor launch changed during capture"
    );
    persist_capture(
        parent,
        destination,
        &Capture {
            schema: PREDECESSOR_EXIT_SCHEMA.to_owned(),
            launch: reference,
            boot_id,
            producer_invocation: invocation.to_owned(),
            producer_pid: pid,
            properties,
        },
    )
}

pub(super) fn read_predecessor(
    reference: &Reference,
    launch: &Reference,
    invocation: &str,
    pid: u32,
    boot: &str,
) -> Result<UnitState> {
    let captured: Capture = serde_json::from_value(reference.read()?)?;
    ensure!(
        captured.schema == PREDECESSOR_EXIT_SCHEMA
            && captured.launch == *launch
            && captured.producer_invocation == invocation
            && captured.producer_pid == pid
            && captured.boot_id == boot,
        "PID1 predecessor exit belongs to a different launch or boot"
    );
    Ok(captured.properties)
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
    ensure_unit(&capture.properties, &Producer::from(&admitted.launch))?;
    Ok(capture.properties)
}

pub(super) fn read_window230(
    window: &window230::Window<'_>,
    reference: &Reference,
    launch: &Reference,
    pid: u32,
    boot: &str,
) -> Result<UnitState> {
    let saved: Capture = serde_json::from_value(reference.read()?)?;
    ensure!(
        saved.schema == window.exit_schema
            && &saved.launch == launch
            && saved.boot_id == boot
            && saved.producer_pid == pid
            && saved.producer_invocation == window.invocation,
        "foreign epoch 230 PID1 exit capture"
    );
    let producer = Producer {
        unit: window.unit,
        invocation: window.invocation,
        pid,
        node: Path::new(window.node),
    };
    ensure_unit(&saved.properties, &producer)?;
    Ok(saved.properties)
}
