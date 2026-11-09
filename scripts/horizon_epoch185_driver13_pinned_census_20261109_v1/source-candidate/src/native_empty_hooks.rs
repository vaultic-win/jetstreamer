//! Read-only attestation for execution arrays omitted by systemctl's text renderer.
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;
fn unit_path(unit: &str) -> Result<String> {
    ensure!(
        unit.len() <= 180
            && unit.ends_with(".service")
            && unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "invalid service identity"
    );
    let mut path = String::from("/org/freedesktop/systemd1/unit/");
    for b in unit.bytes() {
        if b.is_ascii_alphanumeric() {
            path.push(char::from(b));
        } else {
            path.push_str(&format!("_{b:02x}"));
        }
    }
    Ok(path)
}
// Keep one system-bus connection and a temporary metadata reference. Separate
// busctl processes lose dormant units between queries when PID1 collects them.
use std::ffi::{CStr, CString, c_char, c_int, c_void};
#[link(name = "libsystemd.so.0", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    fn sd_bus_new(bus: *mut *mut c_void) -> c_int;
    fn sd_bus_set_address(bus: *mut c_void, address: *const c_char) -> c_int;
    fn sd_bus_set_bus_client(bus: *mut c_void, enabled: c_int) -> c_int;
    fn sd_bus_set_method_call_timeout(bus: *mut c_void, usec: u64) -> c_int;
    fn sd_bus_start(bus: *mut c_void) -> c_int;
    fn sd_bus_unref(bus: *mut c_void) -> *mut c_void;
    fn sd_bus_call_method(
        bus: *mut c_void,
        destination: *const c_char,
        path: *const c_char,
        interface: *const c_char,
        member: *const c_char,
        error: *mut c_void,
        reply: *mut *mut c_void,
        types: *const c_char,
        ...
    ) -> c_int;
    fn sd_bus_get_property(
        bus: *mut c_void,
        destination: *const c_char,
        path: *const c_char,
        interface: *const c_char,
        member: *const c_char,
        error: *mut c_void,
        reply: *mut *mut c_void,
        types: *const c_char,
    ) -> c_int;
    fn sd_bus_message_unref(message: *mut c_void) -> *mut c_void;
    fn sd_bus_message_read_basic(message: *mut c_void, kind: c_char, value: *mut c_void) -> c_int;
    fn sd_bus_message_peek_type(
        message: *mut c_void,
        kind: *mut c_char,
        contents: *mut *const c_char,
    ) -> c_int;
    fn sd_bus_message_enter_container(
        message: *mut c_void,
        kind: c_char,
        contents: *const c_char,
    ) -> c_int;
    fn sd_bus_message_at_end(message: *mut c_void, complete: c_int) -> c_int;
}
struct Bus(*mut c_void);
struct Message(*mut c_void);
impl Drop for Bus {
    fn drop(&mut self) {
        unsafe {
            sd_bus_unref(self.0);
        }
    }
}
impl Drop for Message {
    fn drop(&mut self) {
        unsafe {
            sd_bus_message_unref(self.0);
        }
    }
}
fn checked(code: c_int) -> Result<()> {
    ensure!(
        code >= 0,
        "native system-bus operation failed with errno {}",
        -code
    );
    Ok(())
}
impl Bus {
    fn open() -> Result<Self> {
        let mut raw = std::ptr::null_mut();
        checked(unsafe { sd_bus_new(&mut raw) })?;
        let bus = Self(raw);
        checked(unsafe {
            sd_bus_set_address(bus.0, c"unix:path=/run/dbus/system_bus_socket".as_ptr())
        })?;
        checked(unsafe { sd_bus_set_bus_client(bus.0, 1) })?;
        checked(unsafe { sd_bus_set_method_call_timeout(bus.0, 5_000_000) })?;
        checked(unsafe { sd_bus_start(bus.0) })?;
        Ok(bus)
    }
    fn manager(&self, method: &str, unit: &str) -> Result<Message> {
        let method = CString::new(method)?;
        let unit = CString::new(unit)?;
        let mut raw = std::ptr::null_mut();
        let code = unsafe {
            sd_bus_call_method(
                self.0,
                c"org.freedesktop.systemd1".as_ptr(),
                c"/org/freedesktop/systemd1".as_ptr(),
                c"org.freedesktop.systemd1.Manager".as_ptr(),
                method.as_ptr(),
                std::ptr::null_mut(),
                &mut raw,
                c"s".as_ptr(),
                unit.as_ptr(),
            )
        };
        let message = Message(raw);
        checked(code)?;
        Ok(message)
    }
    fn object(&self, unit: &str) -> Result<Value> {
        let message = self.manager("GetUnit", unit)?;
        let mut raw: *const c_char = std::ptr::null();
        let count = unsafe {
            sd_bus_message_read_basic(
                message.0,
                b'o' as c_char,
                (&mut raw as *mut *const c_char).cast(),
            )
        };
        ensure!(
            count > 0 && !raw.is_null(),
            "native service object reply has no exact path"
        );
        let path = unsafe { CStr::from_ptr(raw) }.to_str()?;
        Ok(serde_json::json!({"type":"o","data":[path]}))
    }
    fn empty(&self, path: &str, hook: &str) -> Result<Value> {
        let path = CString::new(path)?;
        let hook = CString::new(hook)?;
        let mut raw = std::ptr::null_mut();
        let code = unsafe {
            sd_bus_get_property(
                self.0,
                c"org.freedesktop.systemd1".as_ptr(),
                path.as_ptr(),
                c"org.freedesktop.systemd1.Service".as_ptr(),
                hook.as_ptr(),
                std::ptr::null_mut(),
                &mut raw,
                c"a(sasbttttuii)".as_ptr(),
            )
        };
        let message = Message(raw);
        checked(code)?;
        let mut kind = 0;
        let mut contents = std::ptr::null();
        let count = unsafe { sd_bus_message_peek_type(message.0, &mut kind, &mut contents) };
        ensure!(
            count > 0 && kind == b'a' as c_char && !contents.is_null(),
            "native hook reply is not an array"
        );
        let signature = unsafe { CStr::from_ptr(contents) }.to_str()?;
        ensure!(
            signature == "(sasbttttuii)",
            "native execution array signature changed"
        );
        checked(unsafe { sd_bus_message_enter_container(message.0, kind, contents) })?;
        ensure!(
            unsafe { sd_bus_message_at_end(message.0, 0) } == 1,
            "omitted native hook contains execution commands"
        );
        Ok(serde_json::json!({"type":format!("a{signature}"),"data":[]}))
    }
}
fn object_reply(value: &Value, expected: &str) -> Result<()> {
    ensure!(
        value == &serde_json::json!({"type":"o","data":[expected]}),
        "native service object identity changed"
    );
    Ok(())
}
fn empty_reply(value: &Value) -> Result<()> {
    ensure!(
        value == &serde_json::json!({"type":"a(sasbttttuii)","data":[]}),
        "omitted native hook is not the exact typed empty execution array"
    );
    Ok(())
}
pub(super) fn complete_missing(
    unit: &str,
    hooks: &[&str],
    native: &mut BTreeMap<String, String>,
) -> Result<()> {
    ensure!(
        native.get("Id").is_some_and(|v| v == unit)
            && native.get("LoadState").is_some_and(|v| v == "loaded"),
        "native empty-hook source is not the exact loaded unit"
    );
    let mut missing = Vec::new();
    let mut selected = BTreeSet::new();
    for hook in hooks {
        ensure!(
            ["ExecStartPost", "ExecStop", "ExecStopPost"].contains(hook) && selected.insert(*hook),
            "foreign or duplicate execution hook selector"
        );
        if !native.contains_key(*hook) {
            missing.push(*hook);
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    let path = unit_path(unit)?;
    let bus = Bus::open()?;
    // Root metadata readers may pin dormant units. Unprivileged actors read
    // their already resident exact live unit without requesting manage-unit
    // authority. A missing or collected unit still fails closed.
    let pinned = unsafe { libc::geteuid() } == 0;
    if pinned {
        bus.manager("RefUnit", unit)?;
    }
    object_reply(&bus.object(unit)?, &path)?;
    for hook in &missing {
        empty_reply(&bus.empty(&path, hook)?)?;
    }
    object_reply(&bus.object(unit)?, &path)?;
    let out = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            unit,
            "--no-pager",
            "--property=Id,LoadState,InvocationID",
        ])
        .env("LC_ALL", "C")
        .env_remove("SYSTEMD_HOST")
        .env_remove("SYSTEMD_BUS_ADDRESS")
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 65536,
        "native empty-hook owner recheck failed"
    );
    let mut after = BTreeMap::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (key, value) = line.split_once('=').context("native identity framing")?;
        ensure!(
            after.insert(key, value).is_none(),
            "duplicate native identity property"
        );
    }
    for key in ["Id", "LoadState", "InvocationID"] {
        ensure!(
            after.get(key).copied() == native.get(key).map(String::as_str),
            "native empty-hook owner changed"
        );
    }
    if pinned {
        bus.manager("UnrefUnit", unit)?;
    }
    // This string represents the genuinely observed empty D-Bus execution array.
    // Missing data, query failures and nonempty arrays never enter this branch.
    for hook in missing {
        native.insert(hook.to_owned(), String::new());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn exact_empty_array_is_required() {
        empty_reply(&json!({"type":"a(sasbttttuii)","data":[]})).unwrap();
        for bad in [
            json!(null),
            json!({}),
            json!({"type":"s","data":[]}),
            json!({"type":"a(sasbttttuii)","data":[[]]}),
            json!({"type":"a(sasbttttuii)","data":["command"]}),
            json!({"type":"a(sasbttttuii)","data":[],"extra":true}),
        ] {
            assert!(empty_reply(&bad).is_err());
        }
    }
    #[test]
    fn object_reply_cannot_cross_unit_or_type() {
        object_reply(&json!({"type":"o","data":["/exact"]}), "/exact").unwrap();
        for bad in [
            json!({"type":"s","data":["/exact"]}),
            json!({"type":"o","data":["/foreign"]}),
            json!({"type":"o","data":[]}),
            json!({"type":"o","data":["/exact","/extra"]}),
        ] {
            assert!(object_reply(&bad, "/exact").is_err());
        }
    }
    #[test]
    fn canonical_unit_path_escapes_all_separators() {
        assert_eq!(
            unit_path("horizon-test_a.service").unwrap(),
            "/org/freedesktop/systemd1/unit/horizon_2dtest_5fa_2eservice"
        );
        for bad in [
            "foreign.timer",
            "../bad.service",
            "a/b.service",
            "a;bad.service",
            "",
        ] {
            assert!(unit_path(bad).is_err());
        }
    }
}
