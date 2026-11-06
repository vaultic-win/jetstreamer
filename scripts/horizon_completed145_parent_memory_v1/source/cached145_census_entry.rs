//! Exact read-only census/qualification writer. No scheduler or replay authority.
#![deny(warnings)]
#[allow(dead_code)]
mod fsutil;
use anyhow::{Context, Result, ensure};
use horizon_original199_parent_memory as parent;
use model::{Bound, Current};
use parent::cached145;
pub use parent::model;
use serde::Deserialize;
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
const IMAGE: &str = "/usr/local/lib/jetstreamer/horizon-completed145-parent-memory-census-tools-20261106-v1/cached145-census";
const UNIT: &str = "horizon-completed145-parent-memory-census-20261106-v1.service";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    current: Current,
    request: cached145::Request,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeSpec {
    schema: String,
    program: Bound,
}
fn native_spec(value: Value, image: &Bound) -> Result<()> {
    let spec: NativeSpec = serde_json::from_value(value)?;
    ensure!(
        spec.schema == "cached145-completed-parent-census-native-capability-spec-v1"
            && spec.program == *image,
        "exact native capability spec/program"
    );
    Ok(())
}
fn native(image: &Bound, iid: &str) -> Result<Value> {
    let out=Command::new("/usr/bin/systemctl").arg("--system")
        .args(["show",UNIT,"--no-pager","--property=Id,InvocationID,MainPID,ControlPID,NRestarts,Restart,ActiveState,SubState,MemoryAccounting,MemoryMax,MemorySwapMax,Job"])
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS").env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env_remove("SYSTEMD_BUS_ADDRESS").env_remove("SYSTEMD_HOST").output()?;
    ensure!(
        out.status.success() && out.stderr.is_empty() && out.stdout.len() <= 65536,
        "completed145 census native failed"
    );
    let mut m = serde_json::Map::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("native framing")?;
        ensure!(
            m.insert(k.into(), json!(v)).is_none(),
            "duplicate native field"
        );
    }
    let mut n = Value::Object(m);
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
        "completed145 census not exact2GiB root zero-restart actor"
    );
    n["program"] = json!(image);
    Ok(n)
}
fn save(path: &Path, v: &Value) -> Result<()> {
    let dir = path.parent().context("receipt parent")?;
    let d = fsutil::open(dir)?;
    let m = d.metadata()?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o777 == 0o700,
        "root0700 output required"
    );
    let mut raw = serde_json::to_vec_pretty(v)?;
    raw.push(b'\n');
    ensure!(raw.len() <= 32 << 20, "receipt bound");
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    f.write_all(&raw)?;
    f.set_permissions(fs::Permissions::from_mode(0o400))?;
    f.sync_all()?;
    d.sync_all()?;
    Ok(())
}
fn run() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    ensure!(
        !env::vars_os()
            .any(|(k, _)| k.to_string_lossy().starts_with("LD_") || k == "GLIBC_TUNABLES"),
        "loader override"
    );
    let a = env::args().skip(1).collect::<Vec<_>>();
    ensure!(
        a.len() == 8
            && matches!(a[0].as_str(), "capture" | "native-capability")
            && a[2] == "--spec-sha256"
            && a[4] == "--self-sha256"
            && a[6] == "--output",
        "usage: capture|native-capability SPEC --spec-sha256 SHA --self-sha256 SHA --output NEW_RECEIPT"
    );
    let image = Bound {
        path: fs::read_link("/proc/self/exe")?,
        sha256: a[5].clone(),
    };
    ensure!(
        image.path == Path::new(IMAGE),
        "normal census image namespace"
    );
    let expected = fsutil::bytes(&image, 128 << 20, true)?;
    let mut running = File::open("/proc/self/exe")?;
    let m = running.metadata()?;
    let n = fsutil::open(&image.path)?.metadata()?;
    ensure!(
        (m.dev(), m.ino()) == (n.dev(), n.ino()) && expected.starts_with(b"\x7fELF"),
        "running image inode/ELF"
    );
    let mut raw = vec![];
    Read::by_ref(&mut running)
        .take((128 << 20) + 1)
        .read_to_end(&mut raw)?;
    ensure!(raw == expected, "running image SHA differs");
    let sb = Bound {
        path: a[1].clone().into(),
        sha256: a[3].clone(),
    };
    let spec_value = fsutil::immutable(&sb)?;
    let iid = env::var("INVOCATION_ID")?;
    ensure!(fsutil::hex(&iid, 32), "invocation absent");
    let before = native(&image, &iid)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let output = Path::new(&a[7]);
    let value = if a[0] == "native-capability" {
        native_spec(spec_value, &image)?;
        ensure!(
            output
                == Path::new(
                    "/var/lib/jetstreamer/horizon-completed145-parent-memory-bootstrap-20261106-v1/native-capability.json"
                ),
            "native capability output namespace"
        );
        let after = native(&image, &iid)?;
        ensure!(before == after, "native capability actor changed");
        json!({"program":image,"scope":"completed145-parent-only-memory-census","actual_native_capability_passed":true,
            "native_before":before,"native_after":after,"spec":sb,"memory_credit_bytes":0,"DATA_credit_bytes":0,
            "replay_launch_authorized":false,"r2_mutations":false})
    } else {
        let spec: Spec = serde_json::from_value(spec_value)?;
        ensure!(
            spec.schema == "cached145-completed-parent-census-spec-v1",
            "exact census spec schema"
        );
        let mut c = cached145::capture(
            &spec.request,
            &spec.current,
            &image,
            &iid,
            &before,
            &before,
            now,
        )?;
        let after = native(&image, &iid)?;
        ensure!(before == after, "actual census actor changed");
        c.actor_native_after = after;
        let dir = Path::new("/var/lib/jetstreamer/horizon-completed145-parent-memory-census-v1")
            .join(&spec.current.observer.sha256);
        ensure!(
            output == dir.join("census.json"),
            "census current observer output namespace"
        );
        serde_json::to_value(c)?
    };
    save(output, &value)?;
    println!(
        "{}",
        json!({"receipt_written":true,"memory_credit_bytes":0,"replay_launch_authorized":false})
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("completed145 parent census rejected: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn image() -> Bound {
        Bound {
            path: IMAGE.into(),
            sha256: "a".repeat(64),
        }
    }
    fn plan() -> Value {
        json!({"schema":"cached145-completed-parent-census-native-capability-spec-v1","program":image()})
    }
    #[test]
    fn native_capability_needs_only_its_actual_program() {
        assert!(native_spec(plan(), &image()).is_ok());
    }
    #[test]
    fn changed_program_path_or_hash_cannot_qualify() {
        for key in ["path", "sha256"] {
            let mut v = plan();
            v["program"][key] = json!("foreign");
            assert!(native_spec(v, &image()).is_err());
        }
    }
    #[test]
    fn capture_schema_or_extra_authority_is_not_native_capability() {
        let mut v = plan();
        v["schema"] = json!("cached145-completed-parent-census-spec-v1");
        assert!(native_spec(v, &image()).is_err());
        let mut v = plan();
        v["memory_credit_bytes"] = json!(192u64 << 30);
        assert!(native_spec(v, &image()).is_err());
    }
    #[test]
    fn native_capability_plan_cannot_supply_a_capture_request() {
        assert!(serde_json::from_value::<Spec>(plan()).is_err());
        let mut v = plan();
        v["request"] = json!({});
        assert!(native_spec(v, &image()).is_err());
    }
}
