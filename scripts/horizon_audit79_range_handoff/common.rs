use anyhow::{Context, Result, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    process::Command,
};
pub(crate) const UNIT: &str = "horizon-r2-chronological-plugin-audit-20261118-v1.service";
pub(crate) const STATE: &str = "/var/lib/jetstreamer/r2-chronological-plugin-audit-20261118-v1";
pub(crate) const ROOT: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/r2-audit-storage-20261119-v1";
pub(crate) const CFG_DIR: &str =
    "/etc/systemd/system/horizon-r2-chronological-plugin-audit-20261118-v1.service.d";
pub(crate) fn sha(path: &Path) -> Result<String> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    std::io::copy(&mut f, &mut h)?;
    Ok(format!("{:x}", h.finalize()))
}
pub(crate) fn read(path: &Path) -> Result<Value> {
    Ok(serde_json::from_reader(File::open(path)?)?)
}
pub(crate) fn run(cmd: &str, args: &[&str]) -> Result<String> {
    let o = Command::new(cmd).args(args).output()?;
    ensure!(
        o.status.success(),
        "{cmd} {args:?} failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    Ok(String::from_utf8(o.stdout)?)
}
pub(crate) fn native() -> Result<BTreeMap<String, String>> {
    let raw = run(
        "systemctl",
        &[
            "show",
            UNIT,
            "-p",
            "InvocationID,SubState,MainPID,ControlGroup,FreezerState,Job,NRestarts,MemoryMax,CPUQuotaPerSecUSec,MemorySwapMax,TasksMax",
        ],
    )?;
    Ok(raw
        .lines()
        .filter_map(|s| s.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect())
}
pub(crate) fn durable(path: &Path, data: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    File::open(path.parent().context("no parent")?)?.sync_all()?;
    Ok(())
}
pub(crate) struct Frozen;
impl Drop for Frozen {
    fn drop(&mut self) {
        let _ = run("systemctl", &["thaw", UNIT]);
    }
}
