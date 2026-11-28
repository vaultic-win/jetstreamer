//! The producer's MainPID remains in this bounded bootstrap barrier until its timer-driven
//! guard has succeeded and the parent has committed both capacity fits. Exec preserves PID.
use anyhow::{Result, ensure};
use std::{
    fs, io,
    os::unix::{fs::MetadataExt, process::CommandExt},
    path::Path,
    process::Command,
    thread,
    time::{Duration, Instant},
};
fn main() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 1001 && unsafe { libc::getegid() } == 1003,
        "sol:horizon required"
    );
    let id = std::env::var("INVOCATION_ID")?;
    ensure!(
        guard172::iid(&id)
            && fs::read_to_string("/proc/self/cgroup")?.trim()
                == format!("0::/system.slice/{}", guard172::UNIT),
        "wrong producer cgroup"
    );
    let token = Path::new(guard172::BARRIER_ALIAS).join("allow");
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(90) {
        match fs::symlink_metadata(&token) {
            Ok(m) => {
                ensure!(
                    m.is_file()
                        && m.uid() == 0
                        && m.mode() & 0o7777 == 0o444
                        && m.nlink() == 1
                        && m.len() == 32
                        && fs::read_to_string(&token)? == id,
                    "wrong replay gate token"
                );
                let error = Command::new(guard172::PAYLOAD_ALIAS).arg("run").exec();
                return Err(error.into());
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                thread::sleep(Duration::from_millis(100))
            }
            Err(e) => return Err(e.into()),
        }
    }
    anyhow::bail!("first protective guard and admission deadline expired")
}
