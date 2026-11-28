use super::*;
pub(super) fn native(iid: &str) -> Result<Value> {
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
    ensure!(
        n["Id"] == UNIT
            && n["InvocationID"] == iid
            && n["MainPID"].as_str().and_then(|s| s.parse::<u32>().ok())
                == Some(std::process::id())
            && n["MainPID"].as_str().is_some_and(|s| !s.starts_with('0'))
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
