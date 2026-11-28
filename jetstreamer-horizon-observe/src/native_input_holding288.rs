//! Resource-only sampling of the Foundation epoch 288 encrypted holding scope.
use super::*;

const UNIT: &str = "foundation-288-closed-partial-custody-v1.service";
const ROOT: &str = "/var/lib/jetstreamer/horizon288-full-partial-custody-hash-v1";
const RELEASE: &str = "/var/lib/jetstreamer/horizon288-closed-partial-custody-tools-v1";
const RELEASE_SHA: &str = "a2f615b0808834bf88f60450a0397dd4eb0965e9cf0a07db88f02981f159bf5f";

pub(super) fn validate(n: &NativeConfig) -> Result<()> {
    let root = Path::new(RELEASE);
    let receipt = root.join("acceptance.json");
    let meta = receipt.symlink_metadata()?;
    ensure!(
        n.epoch == 288
            && n.unit == UNIT
            && n.scratch_path == Path::new(ROOT)
            && n.executable == root.join("jetstreamer-r2")
            && n.main_pid > 1
            && n.main_pid <= i32::MAX as u32
            && is_invocation_id(&n.expected_invocation_id)
            && receipt.canonicalize()? == receipt
            && meta.is_file()
            && meta.uid() == 0
            && meta.mode() & 0o222 == 0
            && meta.len() <= 65_536,
        "epoch 288 custody resource scope differs"
    );
    let raw = fs::read(&receipt)?;
    ensure!(
        sha256(&raw) == RELEASE_SHA,
        "epoch 288 custody release differs"
    );
    let release: Value = serde_json::from_slice(&raw)?;
    ensure!(
        release["tools"]["jetstreamer-r2"]
            == serde_json::json!({
                "path":n.executable,"sha256":n.executable_sha256
            }),
        "epoch 288 custody resource image differs"
    );
    Ok(())
}

pub(super) fn processes(rss: &Value, n: &NativeConfig) -> Result<()> {
    let processes = rss["processes"]
        .as_array()
        .context("epoch 288 custody RSS census")?;
    ensure!(
        rss["census_stable"] == true
            && rss["error"].is_null()
            && (1..=3).contains(&processes.len())
            && processes.iter().filter(|p| p["pid"] == n.main_pid).count() == 1,
        "epoch 288 custody RSS owner differs"
    );
    let group = format!("0::/system.slice/{UNIT}");
    for child in processes.iter().filter(|p| p["pid"] != n.main_pid) {
        let pid = child["pid"]
            .as_u64()
            .context("epoch 288 custody child PID")?;
        let proc = PathBuf::from(format!("/proc/{pid}"));
        let image = fs::read_link(proc.join("exe"))?;
        ensure!(
            matches!(image.to_str(), Some("/usr/bin/gpg" | "/usr/bin/gpg-agent"))
                && fs::read_to_string(proc.join("cgroup"))?.trim() == group,
            "foreign epoch 288 custody child or cgroup"
        );
    }
    Ok(())
}
