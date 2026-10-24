//! Explicit sealed native MainPID route; no historical-worker impersonation.
use super::*;
use std::io::{BufRead, BufReader};
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    pub executable: PathBuf,
    pub sha256: String,
    pub main_pid: u32,
}
pub(super) fn validate(p: &Plan, n: &Binding) -> Result<()> {
    let small210 = cfg!(feature = "epoch210-native-small")
        && p.unit == "archive-210-v1616-native-input-small-v2.service"
        && p.worker_root
            == Path::new("/home/ubuntu/.jetstreamer-private/native-input210-v1616-capped-small-v2")
        && n.executable
            == Path::new(
                "/var/lib/jetstreamer/horizon-210-native-input-optimized-v1/native-input-test",
            )
        && n.sha256 == "2f33396ed027cefbb2529bee194a83e0d0c8dcd079b76cc9410a53852ad1cec6";
    let small227 = cfg!(feature = "epoch227-v1625-native-small")
        && p.unit == "horizon-native-input-227-v1625-small-v2.service"
        && p.worker_root
            == Path::new("/home/ubuntu/.jetstreamer-private/native-input227-v1625-full-small-v2")
        && n.executable
            == Path::new(
                "/var/lib/jetstreamer/horizon-227-v1625-qualification-tests-df338451-v1/test-runner",
            )
        && n.sha256 == "df3384519a64629e99aafadee46833ad2889a9c60c3255ac939bd444965578ef";
    let profile227_v1625 = cfg!(feature = "epoch227-v1625-native-main-guard")
        && p.unit == "horizon-native-input-227-v1625-7a831420-v1.service"
        && p.worker_root
            == Path::new("/home/ubuntu/.jetstreamer-private/native-input227-v1625-full-v1")
        && n.executable
            == Path::new(
                "/var/lib/jetstreamer/horizon-227-v1625-qualification-tests-df338451-v1/test-runner",
            )
        && n.sha256 == "df3384519a64629e99aafadee46833ad2889a9c60c3255ac939bd444965578ef";
    let profile227 = cfg!(feature = "epoch227-native-main-guard")
        && p.unit == "horizon-native-input-227-capped-710f6523-v1.service"
        && p.worker_root
            == Path::new("/home/ubuntu/.jetstreamer-private/native-input227-v1620-capped-v1")
        && n.executable
            == Path::new(
                "/var/lib/jetstreamer/horizon-227-native-test-optimized-v1/native-input-test",
            )
        && n.sha256 == "1446cd728b4408208f125d073ecc52b1ae4205df095747dad7e91f3581ce4bf3";
    let profile207 = cfg!(feature = "epoch207-native-main-guard")
        && p.unit == "archive-207-v1616-native-input-actual-v1.service"
        && p.worker_root
            == Path::new("/home/ubuntu/.jetstreamer-private/native-input207-v1616-capped-v1")
        && n.executable
            == Path::new(
                "/var/lib/jetstreamer/horizon-207-native-input-optimized-3a2a-v1/native-input-test",
            )
        && n.sha256 == "3a2a21e2987ee7c66785bfc64f1caaf4dfc000871ef692278ed83b3f63c65948";
    let profile209 = cfg!(feature = "epoch209-native-main-guard")
        && p.unit == "archive-209-v1616-native-input-actual-v1.service"
        && p.worker_root
            == Path::new("/home/ubuntu/.jetstreamer-private/native-input209-v1616-capped-v1")
        && n.executable
            == Path::new(
                "/var/lib/jetstreamer/horizon-209-native-input-optimized-v1/native-input-test",
            )
        && n.sha256 == "5276276827aab0ccc809d123ebc8bf78cc7bfc36e6def550566059e70a8d4842";
    let profile210 = cfg!(feature = "epoch210-native-main-guard")
        && p.unit == "archive-210-v1616-native-input-actual-v1.service"
        && p.worker_root
            == Path::new("/home/ubuntu/.jetstreamer-private/native-input210-v1616-capped-v1")
        && n.executable
            == Path::new(
                "/var/lib/jetstreamer/horizon-210-native-input-optimized-v1/native-input-test",
            )
        && n.sha256 == "2f33396ed027cefbb2529bee194a83e0d0c8dcd079b76cc9410a53852ad1cec6";
    let profile228 = cfg!(feature = "epoch228-native-main-guard")
        && p.unit == "horizon-native-input-228-capped-1bfa8d51-v1.service"
        && p.worker_root
            == Path::new("/home/ubuntu/.jetstreamer-private/native-input228-v1620-capped-v1")
        && n.executable
            == Path::new(
                "/var/lib/jetstreamer/horizon-228-native-test-optimized-d3fe9c72-v1/native-input-test",
            )
        && n.sha256 == "d3fe9c72d542237c97504e0b680fe51e2eb4365b8a9343a631f9bc7512529827";
    ensure!(
        (small210
            || small227
            || profile227_v1625
            || profile227
            || profile207
            || profile209
            || profile210
            || profile228)
            && n.main_pid > 1
            && p.maximum_root_physical_bytes
                == Some(if small210 || small227 {
                    96_000_000_000
                } else {
                    300_000_000_000
                })
            && p.maximum_worker_vmas == 3500000
            && p.bounded_canary.is_none()
            && p.bounded_measurement.is_none(),
        "native input guard profile differs"
    );
    Ok(())
}
pub(super) fn observe(unit: &Unit, n: &Binding) -> Result<Vec<(u32, u64)>> {
    observe_at(unit, n, Path::new("/sys/fs/cgroup"), Path::new("/proc"), 0)
}
fn same(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
}
fn observe_at(
    unit: &Unit,
    n: &Binding,
    cgroups: &Path,
    processes: &Path,
    owner: u32,
) -> Result<Vec<(u32, u64)>> {
    ensure!(
        unit.pid == u64::from(n.main_pid)
            && n.main_pid > 1
            && unit.cgroup.starts_with('/')
            && !unit.cgroup.starts_with("//")
            && unit.cgroup != "/"
            && !unit.cgroup.split('/').any(|s| s == ".." || s == "."),
        "native227 MainPID/cgroup differs"
    );
    let pids = cgroup_pids(&cgroups.join(&unit.cgroup[1..]))?;
    ensure!(
        pids == vec![n.main_pid],
        "native227 missing, escaped or additional process"
    );
    ensure!(
        n.executable.is_absolute() && n.executable.canonicalize()? == n.executable,
        "native227 noncanonical executable"
    );
    let expected = fs::symlink_metadata(&n.executable)?;
    ensure!(
        expected.is_file()
            && expected.uid() == owner
            && expected.nlink() == 1
            && expected.mode() & 0o222 == 0
            && expected.len() <= 256 << 20,
        "native227 unsafe sealed executable"
    );
    let proc = processes.join(n.main_pid.to_string());
    ensure!(
        fs::read_link(proc.join("exe"))? == n.executable,
        "native227 executable escaped/replaced"
    );
    // Read the actual mapped inode through proc, not just the same pathname.
    let mut exe = File::open(proc.join("exe"))?;
    ensure!(
        same(&expected, &exe.metadata()?),
        "native227 mapped inode differs"
    );
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    let mut total = 0u64;
    loop {
        let count = exe.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        ensure!(total <= 256 << 20, "native227 executable grew");
        hash.update(&buffer[..count]);
    }
    ensure!(
        total == expected.len()
            && format!("{:x}", hash.finalize()) == n.sha256
            && same(&expected, &fs::symlink_metadata(&n.executable)?)
            && same(&expected, &exe.metadata()?),
        "native227 executable digest/identity changed"
    );
    let mut vmas = 0u64;
    for line in BufReader::new(File::open(proc.join("maps"))?).lines() {
        line?;
        vmas += 1;
        if vmas > 3500000 {
            break;
        }
    }
    ensure!(
        vmas > 0
            && fs::read_link(proc.join("exe"))? == n.executable
            && cgroup_pids(&cgroups.join(&unit.cgroup[1..]))? == vec![n.main_pid],
        "native227 process/maps changed during observation"
    );
    Ok(vec![(n.main_pid, vmas)])
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    #[test]
    fn epoch207_requires_its_complete_registered_tuple_and_preserves227() {
        let mut p: Plan = serde_json::from_value(json!({
            "schema":"jetstreamer-horizon-standalone-guard-plan-v1",
            "unit":"archive-207-v1616-native-input-actual-v1.service",
            "invocation_id":"a".repeat(32),"filesystem":"/","minimum_free_bytes":1,
            "worker_root":"/home/ubuntu/.jetstreamer-private/native-input207-v1616-capped-v1",
            "maximum_worker_vmas":3500000,"maximum_root_physical_bytes":300_000_000_000u64,
            "receipt_directory":"/receipts"
        }))
        .unwrap();
        let mut n = Binding {
            executable:
                "/var/lib/jetstreamer/horizon-207-native-input-optimized-3a2a-v1/native-input-test"
                    .into(),
            sha256: "3a2a21e2987ee7c66785bfc64f1caaf4dfc000871ef692278ed83b3f63c65948".into(),
            main_pid: 123,
        };
        assert_eq!(
            validate(&p, &n).is_ok(),
            cfg!(feature = "epoch207-native-main-guard")
        );
        p.unit = "horizon-native-input-227-capped-710f6523-v1.service".into();
        assert!(
            validate(&p, &n).is_err(),
            "a registered unit cannot borrow the 207 root/executable"
        );
        p.worker_root = "/home/ubuntu/.jetstreamer-private/native-input227-v1620-capped-v1".into();
        assert!(
            validate(&p, &n).is_err(),
            "a registered root cannot borrow the 207 executable"
        );
        n.executable =
            "/var/lib/jetstreamer/horizon-227-native-test-optimized-v1/native-input-test".into();
        assert!(
            validate(&p, &n).is_err(),
            "a registered executable cannot borrow the 207 digest"
        );
        n.sha256 = "1446cd728b4408208f125d073ecc52b1ae4205df095747dad7e91f3581ce4bf3".into();
        assert_eq!(
            validate(&p, &n).is_ok(),
            cfg!(feature = "epoch227-native-main-guard")
        );
        n.main_pid = 1;
        assert!(validate(&p, &n).is_err());
        n.main_pid = 123;
        p.unit = "unknown-native.service".into();
        assert!(validate(&p, &n).is_err());
    }
    #[test]
    fn native_plan_cannot_borrow_an_ordinary_worker_or_another_unit() {
        let mut p:Plan=serde_json::from_value(json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":"horizon-native-input-227-capped-710f6523-v1.service","invocation_id":"a".repeat(32),"filesystem":"/","minimum_free_bytes":1,
            "worker_root":"/home/ubuntu/.jetstreamer-private/native-input227-v1620-capped-v1","maximum_worker_vmas":3500000,"maximum_root_physical_bytes":300_000_000_000u64,"receipt_directory":"/receipts"})).unwrap();
        let n = Binding {
            executable:
                "/var/lib/jetstreamer/horizon-227-native-test-optimized-v1/native-input-test".into(),
            sha256: "1446cd728b4408208f125d073ecc52b1ae4205df095747dad7e91f3581ce4bf3".into(),
            main_pid: 123,
        };
        assert_eq!(
            validate(&p, &n).is_ok(),
            cfg!(feature = "epoch227-native-main-guard")
        );
        p.unit = "horizon-singleton-227-capped-710f6523-v1.service".into();
        assert!(validate(&p, &n).is_err());
    }
    fn fixture() -> (tempfile::TempDir, Unit, Binding) {
        let t = tempfile::tempdir().unwrap();
        fs::create_dir_all(t.path().join("groups/test")).unwrap();
        fs::create_dir_all(t.path().join("proc/123")).unwrap();
        let exe = t.path().join("native-input-test");
        fs::write(&exe, b"native exact bytes").unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o555)).unwrap();
        fs::write(t.path().join("groups/test/cgroup.procs"), b"123\n").unwrap();
        fs::write(t.path().join("proc/123/maps"), b"one\ntwo\n").unwrap();
        symlink(&exe, t.path().join("proc/123/exe")).unwrap();
        let u = Unit {
            load_state: "loaded".into(),
            invocation_id: "a".repeat(32),
            active: "active".into(),
            sub: "running".into(),
            result: "success".into(),
            restarts: 0,
            restart_policy: "no".into(),
            kill_mode: "control-group".into(),
            delegated: false,
            cgroup: "/test".into(),
            pid: 123,
        };
        let n = Binding {
            executable: exe,
            sha256: format!("{:x}", Sha256::digest(b"native exact bytes")),
            main_pid: 123,
        };
        (t, u, n)
    }
    #[test]
    fn native_route_requires_exact_mainpid_mapped_executable_and_unique_cgroup_owner() {
        let (t, mut u, mut n) = fixture();
        let uid = unsafe { libc::geteuid() };
        let observe = |u: &Unit, n: &Binding| {
            observe_at(u, n, &t.path().join("groups"), &t.path().join("proc"), uid)
        };
        assert_eq!(observe(&u, &n).unwrap(), vec![(123, 2)]);
        u.pid = 124;
        assert!(observe(&u, &n).is_err());
        u.pid = 123;
        fs::write(t.path().join("groups/test/cgroup.procs"), b"123\n124\n").unwrap();
        assert!(observe(&u, &n).is_err());
        fs::write(t.path().join("groups/test/cgroup.procs"), b"123\n").unwrap();
        n.sha256 = "a".repeat(64);
        assert!(observe(&u, &n).is_err());
        n.sha256 = format!("{:x}", Sha256::digest(b"native exact bytes"));
        fs::remove_file(&n.executable).unwrap();
        fs::write(&n.executable, b"replacement executable bytes").unwrap();
        fs::set_permissions(&n.executable, fs::Permissions::from_mode(0o555)).unwrap();
        assert!(observe(&u, &n).is_err());
        fs::remove_file(t.path().join("proc/123/exe")).unwrap();
        symlink("/escaped/native-input-test", t.path().join("proc/123/exe")).unwrap();
        assert!(observe(&u, &n).is_err());
    }
}
