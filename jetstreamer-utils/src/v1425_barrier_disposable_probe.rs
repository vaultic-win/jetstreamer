//! Disposable barrier exec identity probe. Never replays a transaction.
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    time::Duration,
};
fn main() {
    assert_eq!(
        std::env::args().collect::<Vec<_>>(),
        vec![
            "/usr/local/lib/jetstreamer/horizon-v1425-barrier-disposable-probe-20261023-v1/probe",
            "--disposable-exec-proof"
        ]
    );
    let pid = std::process::id();
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
    let ticks = stat
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap();
    let root = "/var/lib/jetstreamer-v1425-barrier-disposable-20261023-v1/tree";
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(format!("{root}/exec-proof.txt"))
        .unwrap();
    writeln!(
        f,
        "pid={pid}\nstartticks={ticks}\niid={}",
        std::env::var("INVOCATION_ID").unwrap()
    )
    .unwrap();
    f.sync_all().unwrap();
    File::open(root).unwrap().sync_all().unwrap();
    std::thread::sleep(Duration::from_secs(12));
}
