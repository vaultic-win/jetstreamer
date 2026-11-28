//! Read-only receipt writer. Does not stop, restart, admit or mutate an archive.
#![deny(warnings)]
#[allow(dead_code)]
mod fsutil;
use anyhow::{Context, Result, ensure};
use fsutil as f;
use horizon_original199_parent_memory as parent;
use model::{Bound, CaptureSpec};
pub use parent::model;
use serde_json::{Value, json};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
const IMAGE: &str = "/usr/local/lib/jetstreamer/horizon-first-lane-witness-original199-parent-census-tools-20261107-v1/parent-memory-census";
const UNIT: &str = "horizon-original199-parent-memory-census-20261104-v1.service";
fn native(iid: &str) -> Result<Value> {
    let out=Command::new("/usr/bin/systemctl").arg("--system").env_remove("DBUS_SYSTEM_BUS_ADDRESS").env_remove("DBUS_SESSION_BUS_ADDRESS").env_remove("SYSTEMD_BUS_ADDRESS").env_remove("SYSTEMD_HOST").args(["show",UNIT,"--no-pager","--property=Id,InvocationID,MainPID,ControlPID,NRestarts,Restart,ActiveState,SubState,MemoryAccounting,MemoryMax,MemorySwapMax,Job"]).output()?;
    ensure!(
        out.status.success() && out.stderr.is_empty() && out.stdout.len() <= 65536,
        "actual selector native query unavailable"
    );
    let mut m = serde_json::Map::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("native framing")?;
        ensure!(
            m.insert(k.into(), json!(v)).is_none(),
            "duplicate native field"
        );
    }
    let n = Value::Object(m);
    let expected_main_pid = std::process::id().to_string();
    ensure!(
        n["Id"] == UNIT
            && n["InvocationID"] == iid
            && n["MainPID"] == expected_main_pid
            && n["ControlPID"] == "0"
            && n["NRestarts"] == "0"
            && n["Restart"] == "no"
            && n["ActiveState"] == "active"
            && n["SubState"] == "running"
            && n["MemoryAccounting"] == "yes"
            && n["MemoryMax"] == "2147483648"
            && n["MemorySwapMax"] == "0"
            && n["Job"] == "",
        "selector actual identity or2GiB hard booking differs"
    );
    Ok(n)
}
fn validate_mode(mode: &str) -> Result<()> {
    ensure!(mode == "capture", "current witness census is capture-only; legacy controller-probe must not open original protected inputs");
    Ok(())
}
fn run() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root selector required");
    ensure!(
        !env::vars_os()
            .any(|(k, _)| k.to_string_lossy().starts_with("LD_") || k == "GLIBC_TUNABLES"),
        "loader overrides forbidden"
    );
    let a = env::args().skip(1).collect::<Vec<_>>();
    ensure!(
        a.len() == 8
            && validate_mode(&a[0]).is_ok()
            && a[2] == "--spec-sha256"
            && a[4] == "--self-sha256"
            && a[6] == "--output",
        "usage: capture SPEC --spec-sha256 SHA --self-sha256 SHA --output NEW_RECEIPT"
    );
    let image = Bound {
        path: fs::read_link("/proc/self/exe")?,
        sha256: a[5].clone(),
    };
    ensure!(
        image.path == Path::new(IMAGE),
        "normal selector namespace differs"
    );
    let raw = f::bytes(&image, 128 << 20, true)?;
    ensure!(raw.starts_with(b"\x7fELF"), "normal selector is not ELF");
    let mut running = File::open("/proc/self/exe")?;
    let m = running.metadata()?;
    let canonical = f::open(&image.path)?.metadata()?;
    ensure!(
        (m.dev(), m.ino()) == (canonical.dev(), canonical.ino()),
        "running/canonical selector inode differs"
    );
    let mut actual = Vec::new();
    Read::by_ref(&mut running)
        .take((128 << 20) + 1)
        .read_to_end(&mut actual)?;
    ensure!(actual == raw, "running selector bytes differ");
    let sb = Bound {
        path: a[1].clone().into(),
        sha256: a[3].clone(),
    };
    let spec = f::immutable(&sb)?;
    let iid = env::var("INVOCATION_ID")?;
    ensure!(f::hex(&iid, 32), "actual selector invocation absent");
    let before = native(&iid)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let request: CaptureSpec = serde_json::from_value(spec)?;
    let census = json!(parent::census_capture::capture(&request, &image, now)?);
    let output_directory = request.output_directory;
    let after = native(&iid)?;
    ensure!(before == after, "selector actual invocation changed");
    let output = Path::new(&a[7]);
    let dir = output.parent().context("receipt parent")?;
    let d = f::open(dir)?;
    let dm = d.metadata()?;
    ensure!(
        dm.is_dir() && dm.uid() == 0 && dm.mode() & 0o777 == 0o700,
        "output parent must be root0700"
    );
    ensure!(
        output
            == output_directory.join("capture-execution.json"),
        "capture execution output namespace differs"
    );
    let v = json!({"schema":"terminal199-parent-memory-census-original-execution-v1","scope":"terminal199-parent-only-memory-census","program":image,"spec":sb,
        "unit":UNIT,"invocation_id":iid,"native_before":before,"native_after":after,"recorded_unix_seconds":now,
        "census":census,"controller_bindings":Value::Null,"probe_only":false,"selection_written":false,
        "actual_native_capability_passed":true,"memory_credit_bytes":0,"DATA_credit_bytes":0,
        "replay_launch_authorized":false,"admission_authorized":false,"publication_authorized":false,
        "archive_mutations":false,"sidecar_mutations":false,"r2_mutations":false});
    let mut bytes = serde_json::to_vec_pretty(&v)?;
    bytes.push(b'\n');
    ensure!(bytes.len() <= 32 << 20, "receipt size bound");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(output)?;
    file.write_all(&bytes)?;
    file.set_permissions(fs::Permissions::from_mode(0o400))?;
    file.sync_all()?;
    d.sync_all()?;
    println!(
        "{}",
        json!({"receipt_written":true,"selection_written":false,"replay_launch_authorized":false})
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("parent-only memory selector rejected evidence: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_current_capture_mode_is_available() {
        assert!(validate_mode("capture").is_ok());
    }
    #[test]
    fn legacy_probe_and_other_modes_cannot_open_protected_inputs() {
        for mode in ["controller-probe", "native-capability", "", "Capture", "capture "] {
            assert!(validate_mode(mode).is_err(), "{mode}");
        }
    }
}
