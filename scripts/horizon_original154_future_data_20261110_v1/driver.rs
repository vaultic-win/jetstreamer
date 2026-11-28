//! SOURCE ONLY. Amalgamate with checker, ending and independently reviewed actual ancestry.
#![recursion_limit = "512"]
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
const IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-original154-future-data-tools-20261110-v2/check";
fn save(path: &Path, value: &Value) -> checker::R<()> {
    let parent = path.parent().ok_or("check output parent")?;
    checker::need(
        parent.is_absolute() && parent.canonicalize()? == parent,
        "canonical result parent",
    )?;
    let m = fs::symlink_metadata(parent)?;
    checker::need(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "private Root result parent",
    )?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(0x20000 | 0x80000)
        .open(path)?;
    serde_json::to_writer_pretty(&mut f, value)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn helper(operation: &str) -> checker::R<Value> {
    let name = format!("horizon-original154-future-data-{operation}-20261110-v2.service");
    let n = checker::native(&name)?;
    checker::need(
        n["ActiveState"] == "active"
            && n["SubState"] == "running"
            && checker::string(&n, "MainPID")?.parse::<u32>()? == std::process::id()
            && n["ControlPID"] == "0"
            && n["NRestarts"] == "0"
            && n["Restart"] == "no"
            && n["Type"] == "exec"
            && n["User"] == "root"
            && n["Group"] == "root"
            && n["MemoryMax"] == "536870912"
            && n["MemorySwapMax"] == "0"
            && n["RuntimeMaxUSec"] == "3min"
            && n["CPUQuotaPerSecUSec"] == "2s"
            && n["Job"] == ""
            && n["ControlGroup"] == format!("/system.slice/{name}")
            && n["InvocationID"] == std::env::var("INVOCATION_ID")?,
        "exact finite512MiB own helper required",
    )?;
    checker::need(
        fs::read_to_string("/proc/self/cgroup")? == format!("0::/system.slice/{name}\n"),
        "own cgroup differs",
    )?;
    Ok(n)
}
fn run() -> checker::R<()> {
    let a = std::env::args().collect::<Vec<_>>();
    checker::need(
        a.len() == 8
            && matches!(a[1].as_str(), "check" | "end")
            && a[3] == "--plan-sha256"
            && a[5] == "--self-sha256"
            && a[7] == "--no-additional-authority",
        "exact argv required",
    )?;
    checker::need(
        fs::read_link("/proc/self/exe")? == Path::new(IMAGE)
            && checker::sha(&checker::bytes(Path::new(IMAGE), 32 << 20)?) == a[6],
        "normally sealed exact helper image required",
    )?;
    let plan = checker::bound(&json!({"path":a[2],"sha256":a[4]}))?;
    let before = helper(&a[1])?;
    let booking = checker::bound(&plan["native16_suballocation"])?;
    checker::need(
        booking["native_pool_bytes"] == 16u64 << 30
            && booking["all_committed_existing_native_bytes"] == 13_757_317_120u64
            && booking["one_serial_compiler_or_native_bytes"] == 512u64 << 20
            && booking["total_native_with_callback_bytes"] == 14_294_188_032u64
            && booking["new_hard_memory_or_DATA_promise_bytes"] == 0,
        "retained native16 serial512MiB booking required",
    )?;
    let value = if a[1] == "check" {
        checker::check(&plan, ancestry::verify)?
    } else {
        ending::end(&plan, ancestry::verify)?
    };
    checker::need(helper(&a[1])? == before, "own finite helper changed")?;
    save(Path::new(checker::string(&plan, "output")?), &value)?;
    println!(
        "{}",
        json!({"output":plan["output"],"original_invocation_id":checker::IID,"operation":a[1],"replay_admission_authorized":false,"Root_selection_pending_actual_actor_drain":true})
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("original154 future DATA rejected: {e}");
        std::process::exit(1);
    }
}
