//! Exporter-coexistence protection is independent of the typed legacy closure.
use super::*;
const FLOOR: u64 = 642177138688;
const MARGIN: u64 = 8 << 30;
const ROOT: &str = "/home/sol/.jetstreamer-private/epoch163-first-output128-20261106-v1/work";
pub(super) fn node_argv() -> Vec<String> {
    vec!["/usr/local/lib/jetstreamer/horizon-first-lane-witness-first163128-node-tools-20261107-v2/jetstreamer-node".into(),"163".into(),format!("{ROOT}/ledger"),"--verify".into(),"--qualification-end-slot=70416000".into(),"--snapshot-archive=/home/sol/.jetstreamer-private/epoch163-first-output128-20261106-v1/inputs/snapshot-70415741-2aSbRXHXZJgT4bdrY34gWizngFB527wavw6Ar9KadzUY.tar.zst".into(),"--epoch-hashes=/home/sol/.jetstreamer-private/epoch163-first-output128-20261106-v1/inputs/checkpoint-names.txt".into(),format!("--horizon-output={ROOT}/output/first-output.jet"),format!("--replay-scratch={ROOT}/scratch")]
}
fn parent_charged() -> Result<u64> {
    // Credit only resident anonymous pages under this zero-swap hard cgroup.
    // memory.current includes reclaimable file cache already in MemAvailable.
    let path = Path::new("/sys/fs/cgroup/system.slice")
        .join(UNIT)
        .join("memory.stat");
    let raw = fs::read_to_string(path)?;
    ensure!(raw.len() <= 1 << 20, "memory.stat bound");
    let values = raw
        .lines()
        .filter_map(|l| l.strip_prefix("anon "))
        .collect::<Vec<_>>();
    ensure!(
        values.len() == 1,
        "exact recursive anonymous memory counter required"
    );
    let anon = values[0].parse::<u64>()?;
    ensure!(anon <= 128u64 << 30, "anonymous hard cap exceeded");
    Ok(anon)
}
fn available() -> Result<u64> {
    let raw = fs::read_to_string("/proc/meminfo")?;
    raw.lines()
        .find_map(|l| l.strip_prefix("MemAvailable:"))
        .context("MemAvailable missing")?
        .split_whitespace()
        .next()
        .context("MemAvailable bytes")?
        .parse::<u64>()?
        .checked_mul(1024)
        .context("MemAvailable overflow")
}
fn memory_gate(available: u64, charged: u64) -> Result<()> {
    ensure!(charged <= 128u64 << 30, "anonymous hard cap exceeded");
    let remaining = (128u64 << 30) - charged;
    let required = FLOOR
        .checked_add(remaining)
        .and_then(|n| n.checked_add(2u64 << 30))
        .and_then(|n| n.checked_add(512u64 << 20))
        .and_then(|n| n.checked_add(MARGIN))
        .context("memory reserve overflow")?;
    ensure!(
        available >= required,
        "bounded163 would threaten immutable exporter floor with remaining hard growth"
    );
    Ok(())
}
pub(super) fn continuity(p: &Plan, now: u64) -> Result<()> {
    let a = f::immutable(&p.admission)?;
    let policy = f::immutable(&p.input_policy)?;
    ensure!(
        a["schema"] == "epoch163-first-output128-full-admission-v1"
            && a["input_policy"] == json!(p.input_policy)
            && a["admitted"] == true
            && a["parent_unit"] == UNIT
            && a["parent_program"] == json!(p.parent_program)
            && a["parent_hard_bytes"] == 128u64 << 30
            && a["exporter_floor_bytes"] == FLOOR
            && a["memory_receipt"] == json!(p.selected_memory_receipt)
            && a["data_receipt"] == json!(p.selected_data_receipt)
            && a["minimum_free_bytes"] == p.minimum_free_bytes
            && a["publication_authorized"] == false
            && policy["maximum_runtime_seconds"] == 3600
            && policy["maximum_replayed_slots"] == 259,
        "bounded original admission/input policy crossed"
    );
    let boot = f::n(&a, "recorded_unix_seconds")?;
    ensure!(
        boot > 0 && now.checked_sub(boot).is_some_and(|v| v <= 3780),
        "bounded original runtime expired"
    );
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    ensure!(hz > 0, "native clock tick frequency");
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) } == 0 && ts.tv_sec >= 0,
        "native boottime"
    );
    let millis = (ts.tv_sec as u64)
        .checked_mul(1000)
        .and_then(|v| v.checked_add(ts.tv_nsec as u64 / 1_000_000))
        .context("boottime overflow")?;
    let start = p
        .parent_start_ticks
        .checked_mul(1000)
        .context("start clock overflow")?
        / (hz as u64);
    ensure!(
        millis.checked_sub(start).is_some_and(|v| v <= 3_600_000),
        "exact original one-hour runtime exceeded"
    );
    memory_gate(available()?, parent_charged()?)?;
    let out = Path::new(ROOT).join("output/first-output.jet");
    match fs::symlink_metadata(out) {
        Ok(m) => ensure!(
            m.is_file() && !m.file_type().is_symlink() && m.len() <= 1 << 30,
            "first output work budget"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_remaining_growth_and_margin_are_charged_before_launch() {
        let need = FLOOR + (128u64 << 30) + (2u64 << 30) + (512u64 << 20) + MARGIN;
        memory_gate(need, 0).unwrap();
        assert!(memory_gate(need - 1, 0).is_err());
        memory_gate(need - (100u64 << 30), 100u64 << 30).unwrap();
    }
    #[test]
    fn current_parent_consumption_never_lowers_immutable_exporter_floor() {
        assert!(memory_gate(FLOOR - 1, 128u64 << 30).is_err());
        assert!(memory_gate(FLOOR, 128u64 << 30).is_err());
    }
    #[test]
    fn exact_command_is_finite_private_and_excludes_cohort_recovery() {
        let a = node_argv();
        assert_eq!(a.len(), 9);
        assert!(a.contains(&"--qualification-end-slot=70416000".into()));
        assert!(
            !a.iter()
                .any(|a| a.contains("root-checkpoint-cohort") || a.contains("recover"))
        );
    }
}
