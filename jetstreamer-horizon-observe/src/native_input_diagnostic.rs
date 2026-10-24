//! Closed native input telemetry. No entry progress or qualification evidence.
use super::*;
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeConfig {
    epoch: u64,
    unit: String,
    expected_invocation_id: String,
    main_pid: u32,
    scratch_path: PathBuf,
    executable: PathBuf,
    executable_sha256: String,
}
impl NativeConfig {
    fn validate(&self) -> Result<()> {
        let tuple = match self.epoch {
            207 => (
                "archive-207-v1616-native-input-actual-v1.service",
                "/home/ubuntu/.jetstreamer-private/native-input207-v1616-capped-v1/scratch",
                "/var/lib/jetstreamer/horizon-207-native-input-optimized-3a2a-v1/native-input-test",
                "3a2a21e2987ee7c66785bfc64f1caaf4dfc000871ef692278ed83b3f63c65948",
            ),
            209 => (
                "archive-209-v1616-native-input-actual-v1.service",
                "/home/ubuntu/.jetstreamer-private/native-input209-v1616-capped-v1/scratch",
                "/var/lib/jetstreamer/horizon-209-native-input-optimized-v1/native-input-test",
                "5276276827aab0ccc809d123ebc8bf78cc7bfc36e6def550566059e70a8d4842",
            ),
            210 => (
                "archive-210-v1616-native-input-actual-v1.service",
                "/home/ubuntu/.jetstreamer-private/native-input210-v1616-capped-v1/scratch",
                "/var/lib/jetstreamer/horizon-210-native-input-optimized-v1/native-input-test",
                "2f33396ed027cefbb2529bee194a83e0d0c8dcd079b76cc9410a53852ad1cec6",
            ),
            227 => (
                "horizon-native-input-227-capped-710f6523-v1.service",
                "/home/ubuntu/.jetstreamer-private/native-input227-v1620-capped-v1/scratch",
                "/var/lib/jetstreamer/horizon-227-native-test-optimized-v1/native-input-test",
                "1446cd728b4408208f125d073ecc52b1ae4205df095747dad7e91f3581ce4bf3",
            ),
            228 => (
                "horizon-native-input-228-capped-1bfa8d51-v1.service",
                "/home/ubuntu/.jetstreamer-private/native-input228-v1620-capped-v1/scratch",
                "/var/lib/jetstreamer/horizon-228-native-test-optimized-d3fe9c72-v1/native-input-test",
                "d3fe9c72d542237c97504e0b680fe51e2eb4365b8a9343a631f9bc7512529827",
            ),
            _ => return Err(anyhow!("unknown native input telemetry profile")),
        };
        ensure!(
            self.unit == tuple.0
                && self.scratch_path == Path::new(tuple.1)
                && self.executable == Path::new(tuple.2)
                && self.executable_sha256 == tuple.3
                && self.main_pid > 1
                && self.main_pid <= i32::MAX as u32
                && is_invocation_id(&self.expected_invocation_id),
            "native input telemetry tuple differs"
        );
        Ok(())
    }
}
pub(super) fn validate(config: &Config) -> Result<()> {
    let mut epochs = std::collections::BTreeSet::new();
    for n in &config.native_input_diagnostics {
        n.validate()?;
        ensure!(
            epochs.insert(n.epoch),
            "duplicate native input telemetry owner"
        );
        for r in config.replays.iter().chain(&config.diagnostic_replays) {
            let (first, last) = r.range.split_once('-').unwrap_or((&r.range, &r.range));
            let (first, last) = (first.parse::<u64>()?, last.parse::<u64>()?);
            ensure!(
                !(first..=last).contains(&n.epoch)
                    && r.producer_unit != n.unit
                    && r.controller_unit != n.unit
                    && !n.scratch_path.starts_with(&r.scratch_path)
                    && !r.scratch_path.starts_with(&n.scratch_path),
                "native input telemetry overlaps replay owner"
            );
        }
    }
    Ok(())
}
fn identity(u: &UnitObservation, n: &NativeConfig) -> Result<()> {
    ensure!(
        u.main_pid == u64::from(n.main_pid)
            && u.unit == n.unit
            && u.invocation_id == n.expected_invocation_id
            && u.control_group == Path::new(&format!("/system.slice/{}", n.unit)),
        "native input MainPID/cgroup changed"
    );
    let rss = serde_json::to_value(&u.rss)?;
    ensure!(
        rss["census_stable"] == true
            && rss["error"].is_null()
            && rss["processes"].as_array().is_some_and(|v| v.len() == 1)
            && rss["processes"][0]["pid"] == n.main_pid,
        "native input RSS owner census changed"
    );
    Ok(())
}
fn mapped_at(n: &NativeConfig, proc_root: &Path, trusted_uid: u32) -> Result<Value> {
    let expected = fs::symlink_metadata(&n.executable)?;
    ensure!(
        n.executable.canonicalize()? == n.executable
            && expected.is_file()
            && expected.uid() == trusted_uid
            && expected.nlink() == 1
            && expected.mode() & 0o222 == 0
            && expected.len() <= 256 << 20,
        "unsafe native input executable"
    );
    let proc = proc_root.join(n.main_pid.to_string());
    ensure!(
        fs::read_link(proc.join("exe"))? == n.executable,
        "native input mapped path changed"
    );
    let mut exe = File::open(proc.join("exe"))?;
    let opened = exe.metadata()?;
    ensure!(
        expected.dev() == opened.dev() && expected.ino() == opened.ino(),
        "native input mapped inode differs"
    );
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    let mut bytes = 0u64;
    loop {
        let count = exe.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes += count as u64;
        ensure!(bytes <= 256 << 20, "native input executable grew");
        hash.update(&buffer[..count]);
    }
    let after = fs::symlink_metadata(&n.executable)?;
    ensure!(
        bytes == expected.len()
            && sha256_equal(&format!("{:x}", hash.finalize()), &n.executable_sha256)
            && same_file(&expected, &after)
            && same_file(&expected, &exe.metadata()?)
            && fs::read_link(proc.join("exe"))? == n.executable,
        "native input executable changed"
    );
    let maps = fs::read_to_string(proc.join("maps"))?;
    let vmas = maps.lines().count();
    ensure!(vmas > 0 && vmas <= 3_500_000, "native input VMA bound");
    Ok(
        serde_json::json!({"pid":n.main_pid,"executable":n.executable,"sha256":n.executable_sha256,"vmas":vmas,"mapped_inode":expected.ino(),"mapped_device":expected.dev(),"historical_worker_claim":false}),
    )
}
fn sha256_equal(actual: &str, expected: &str) -> bool {
    actual == expected
}
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
}
fn observe(n: &NativeConfig) -> Result<Value> {
    n.validate()?;
    let before = observe_unit(&n.unit, &n.expected_invocation_id)?;
    identity(&before, n)?;
    let mapped_before = mapped_at(n, Path::new("/proc"), 0)?;
    ensure!(
        n.scratch_path.canonicalize()? == n.scratch_path,
        "native input scratch noncanonical"
    );
    let root = fs::symlink_metadata(&n.scratch_path)?;
    ensure!(
        root.is_dir() && root.uid() == 1000 && root.mode() & 0o077 == 0,
        "native input scratch owner/mode differs"
    );
    let first = scan_scratch(&n.scratch_path)?;
    let second = scan_scratch(&n.scratch_path)?;
    let after = observe_unit(&n.unit, &n.expected_invocation_id)?;
    identity(&after, n)?;
    let mapped_after = mapped_at(n, Path::new("/proc"), 0)?;
    let end = fs::symlink_metadata(&n.scratch_path)?;
    ensure!(
        root.dev() == end.dev()
            && root.ino() == end.ino()
            && n.scratch_path.canonicalize()? == n.scratch_path
            && stable_unit(&before, &after)
            && before.main_pid == after.main_pid,
        "native input owner/root changed during sample"
    );
    let b = serde_json::to_value(&before.rss)?;
    let a = serde_json::to_value(&after.rss)?;
    ensure!(
        b["processes"][0]["start_ticks"] == a["processes"][0]["start_ticks"],
        "native input PID reused"
    );
    Ok(
        serde_json::json!({"range":format!("{}-{}",n.epoch,n.epoch),"resource_only":true,"native_input_diagnostic":true,
        "controller_before":before,"producer_before":before,"controller_after":after,"producer_after":after,
        "native_main_before":mapped_before,"native_main_after":mapped_after,"scratch_path":n.scratch_path,
        "scratch_measurement_method":"two race-tolerant non-symlink-following physical-block scans",
        "scratch_pass_1":first,"scratch_pass_2":second,"conservative_observed_physical_bytes":first.physical_bytes.max(second.physical_bytes),
        "invocation_binding_stable":true,"useful_work":{"sufficient_for_rates":false,"entry_progress_observed":false},
        "entry_replay":false,"native_input_qualified":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )
}
fn row(n: &NativeConfig, result: Result<Value>) -> Value {
    let (status, observation, error) = match result {
        Ok(v) => ("observed", Some(v), None),
        Err(e) => ("unavailable", None, Some(format!("{e:#}"))),
    };
    serde_json::json!({"range":format!("{}-{}",n.epoch,n.epoch),"producer_unit":n.unit,"expected_producer_invocation_id":n.expected_invocation_id,
        "scratch_path":n.scratch_path,"native_resource_only":true,"status":status,"observation":observation,"error":error,
        "ordinary_replay_claim":false,"entry_replay":false,"publication_authorized":false,"r2_mutations":false})
}
pub(super) fn sample(configs: &[NativeConfig]) -> Vec<Value> {
    configs.iter().map(|n| row(n, observe(n))).collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    fn config() -> NativeConfig {
        serde_json::from_value(serde_json::json!({"epoch":227,"unit":"horizon-native-input-227-capped-710f6523-v1.service","expected_invocation_id":"a".repeat(32),"main_pid":42,"scratch_path":"/home/ubuntu/.jetstreamer-private/native-input227-v1620-capped-v1/scratch","executable":"/var/lib/jetstreamer/horizon-227-native-test-optimized-v1/native-input-test","executable_sha256":"1446cd728b4408208f125d073ecc52b1ae4205df095747dad7e91f3581ce4bf3"})).unwrap()
    }
    #[test]
    fn config_pins_complete_native_tuple_and_keeps_unavailable_rows_non_authorizing() {
        let n = config();
        n.validate().unwrap();
        for (key, value) in [
            ("epoch", serde_json::json!(207)),
            ("main_pid", serde_json::json!(1)),
            ("executable_sha256", serde_json::json!("a".repeat(64))),
            ("unit", serde_json::json!("other.service")),
        ] {
            let mut bad = serde_json::to_value(&n).unwrap();
            bad[key] = value;
            assert!(
                serde_json::from_value::<NativeConfig>(bad)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{key}"
            );
        }
        let r = row(&n, Err(anyhow!("native owner terminated")));
        assert_eq!(r["status"], "unavailable");
        assert_eq!(r["observation"], Value::Null);
        assert_eq!(r["entry_replay"], false);
    }
    #[test]
    fn native209_requires_its_own_complete_sealed_tuple() {
        let mut value = serde_json::to_value(config()).unwrap();
        value["epoch"] = serde_json::json!(209);
        value["unit"] = serde_json::json!("archive-209-v1616-native-input-actual-v1.service");
        value["scratch_path"] = serde_json::json!(
            "/home/ubuntu/.jetstreamer-private/native-input209-v1616-capped-v1/scratch"
        );
        value["executable"] = serde_json::json!(
            "/var/lib/jetstreamer/horizon-209-native-input-optimized-v1/native-input-test"
        );
        value["executable_sha256"] =
            serde_json::json!("5276276827aab0ccc809d123ebc8bf78cc7bfc36e6def550566059e70a8d4842");
        serde_json::from_value::<NativeConfig>(value.clone())
            .unwrap()
            .validate()
            .unwrap();
        let original = serde_json::to_value(config()).unwrap();
        for field in [
            "epoch",
            "unit",
            "scratch_path",
            "executable",
            "executable_sha256",
        ] {
            let mut wrong = value.clone();
            wrong[field] = original[field].clone();
            assert!(
                serde_json::from_value::<NativeConfig>(wrong)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{field}"
            );
        }
    }
    #[test]
    fn native210_resource_registration_is_closed_to_its_own_harness_and_scratch() {
        let good = serde_json::json!({"epoch":210,"unit":"archive-210-v1616-native-input-actual-v1.service",
            "expected_invocation_id":"a".repeat(32),"main_pid":42,
            "scratch_path":"/home/ubuntu/.jetstreamer-private/native-input210-v1616-capped-v1/scratch",
            "executable":"/var/lib/jetstreamer/horizon-210-native-input-optimized-v1/native-input-test",
            "executable_sha256":"2f33396ed027cefbb2529bee194a83e0d0c8dcd079b76cc9410a53852ad1cec6"});
        let native: NativeConfig = serde_json::from_value(good.clone()).unwrap();
        native.validate().unwrap();
        for (key, value) in [
            ("epoch", serde_json::json!(209)),
            (
                "unit",
                serde_json::json!("archive-209-v1616-native-input-actual-v1.service"),
            ),
            (
                "scratch_path",
                serde_json::json!(
                    "/home/ubuntu/.jetstreamer-private/native-input209-v1616-capped-v1/scratch"
                ),
            ),
            (
                "executable",
                serde_json::json!(
                    "/var/lib/jetstreamer/horizon-209-native-input-optimized-v1/native-input-test"
                ),
            ),
            (
                "executable_sha256",
                serde_json::json!(
                    "5276276827aab0ccc809d123ebc8bf78cc7bfc36e6def550566059e70a8d4842"
                ),
            ),
            ("main_pid", serde_json::json!(1)),
            ("expected_invocation_id", serde_json::json!("invalid")),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(
                serde_json::from_value::<NativeConfig>(bad)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{key}"
            );
        }
        let unavailable = row(&native, Err(anyhow!("exact owner terminated")));
        assert_eq!(unavailable["status"], "unavailable");
        assert_eq!(unavailable["observation"], Value::Null);
        for field in [
            "ordinary_replay_claim",
            "entry_replay",
            "publication_authorized",
            "r2_mutations",
        ] {
            assert_eq!(unavailable[field], false);
        }
    }
    #[test]
    fn native228_cannot_use_the_neighboring_native_harness() {
        let mut n: NativeConfig = serde_json::from_value(serde_json::json!({
            "epoch":228,"unit":"horizon-native-input-228-capped-1bfa8d51-v1.service",
            "expected_invocation_id":"a".repeat(32),"main_pid":42,
            "scratch_path":"/home/ubuntu/.jetstreamer-private/native-input228-v1620-capped-v1/scratch",
            "executable":"/var/lib/jetstreamer/horizon-228-native-test-optimized-d3fe9c72-v1/native-input-test",
            "executable_sha256":"d3fe9c72d542237c97504e0b680fe51e2eb4365b8a9343a631f9bc7512529827"
        })).unwrap();
        n.validate().unwrap();
        let neighbor = config();
        n.executable = neighbor.executable;
        n.executable_sha256 = neighbor.executable_sha256;
        assert!(n.validate().is_err());
    }
    #[test]
    fn mapped_process_requires_exact_inode_hash_and_owner_without_worker_impersonation() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("native-input-test");
        fs::write(&exe, b"native").unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o555)).unwrap();
        let proc = dir.path().join("proc/42");
        fs::create_dir_all(&proc).unwrap();
        symlink(&exe, proc.join("exe")).unwrap();
        fs::write(proc.join("maps"), "mapping\n").unwrap();
        let mut n = config();
        n.executable = exe;
        n.executable_sha256 = sha256(b"native");
        let uid = fs::metadata(&n.executable).unwrap().uid();
        assert_eq!(
            mapped_at(&n, &dir.path().join("proc"), uid).unwrap()["historical_worker_claim"],
            false
        );
        assert!(mapped_at(&n, &dir.path().join("proc"), uid + 1).is_err());
        n.executable_sha256 = "0".repeat(64);
        assert!(mapped_at(&n, &dir.path().join("proc"), uid).is_err());
    }
}
