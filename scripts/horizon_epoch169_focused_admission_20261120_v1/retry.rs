//! Reuse only the exact empty stage left by the failed second fit. New records are
//! exclusive, and the original preflight, package, log inodes and lock stay in place.
use super::*;
use std::collections::BTreeSet;
pub(super) const OLD_SOURCE: &str = "9ed762e402c9342d484dfd7b22a74cc63839c528";
const PRE: &str = "3d730a513a6d124d77a486d3fe1de45632d75feaba8152b499d7236eca7676d4";
const SEAL: &str = "fcf906c9a087220848d90d639f01822f149490c0993a75c1983e6fa56c842c22";
const PROOF: &str = "8c2e902dd0550dc16e2963e6a7727130575441d525b4cd10016672ae83bd0183";
const FLEET: &str = "/var/lib/jetstreamer/horizon_runtime_data/root124959-live166167170-20261120-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json";
const FLEET_SHA: &str = "4b32b72a638e4aacd7da8ffacd98204d47bbb7220360765d2ec383143be439da";
fn names(dir: &Path) -> Result<BTreeSet<String>> {
    fs::read_dir(dir)?
        .map(|row| {
            row?.file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("invalid filename"))
        })
        .collect()
}
fn file(path: &Path, ino: u64, uid: u32, gid: u32, mode: u32, len: u64) -> Result<File> {
    file_on_device(
        path,
        fs::metadata("/home/sol")?.dev(),
        ino,
        uid,
        gid,
        mode,
        len,
    )
}
fn file_on_device(
    path: &Path,
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    len: u64,
) -> Result<File> {
    ensure!(
        path.canonicalize()? == path,
        "noncanonical {}",
        path.display()
    );
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.dev() == dev
            && m.ino() == ino
            && m.uid() == uid
            && m.gid() == gid
            && m.mode() & 0o7777 == mode
            && m.len() == len
            && m.nlink() == 1,
        "wrong retry file identity or contents: {}",
        path.display()
    );
    Ok(f)
}
pub(super) fn open_lock() -> Result<File> {
    file(
        &Path::new(BASE).join("admission.lock"),
        101132300,
        0,
        0,
        0o600,
        0,
    )
}
fn exact_entries(path: &Path, expected: &[&str]) -> Result<()> {
    ensure!(
        names(path)? == expected.iter().map(|s| s.to_string()).collect(),
        "unexpected entries in {}",
        path.display()
    );
    Ok(())
}
fn no_jobs() -> Result<()> {
    for unit in [UNIT, GUARD_SERVICE, TIMER] {
        unused(unit)?;
        // An empty root can still have children. cgroup v2 populated covers descendants.
        let path = Path::new("/sys/fs/cgroup/system.slice").join(unit);
        if path.try_exists()? {
            ensure!(
                fs::read_to_string(path.join("cgroup.events"))?
                    .lines()
                    .any(|l| l == "populated 0"),
                "occupied cgroup {unit}"
            );
        }
    }
    let jobs = run(
        "/usr/bin/systemctl",
        &["list-jobs".into(), "--no-legend".into(), "--plain".into()],
        bounded(),
    )?;
    ensure!(
        !jobs
            .lines()
            .filter_map(|l| l.split_whitespace().nth(1))
            .any(|s| s.starts_with("horizon-")
                && s.contains("169")
                && (s.starts_with("horizon-qualify-")
                    || s.starts_with("horizon-guard-")
                    || s.starts_with("horizon-admit-"))),
        "pending 169 job"
    );
    Ok(())
}
pub(super) fn cold() -> Result<Value> {
    let root = Path::new(BASE);
    custody(root, 0, 0, Some(101131907), 0o700)?;
    // The only optional entries are the separately sealed recovery package and its
    // explicitly named preparation files. Every guard, admission or token is excluded.
    const OLD: &[&str] = &[
        "PREFLIGHT.json",
        "admission-v1",
        "admission.lock",
        "artifact-proof.json",
        "barrier",
        "controller-plan.json",
        "guard-receipts",
        "guard.stderr",
        "guard.stdout",
        "native-controls.log",
        "seal-controller-g2.py",
        "seal-controller.py",
    ];
    const NEW: &[&str] = &[
        "admission-retry1-v1",
        "retry1-artifact-proof.json",
        "retry1-controller-plan.json",
        "seal-controller-retry1.py",
        "retry1-native-controls.log",
    ];
    let entries = names(root)?;
    ensure!(
        OLD.iter().all(|n| entries.contains(*n))
            && entries
                .iter()
                .all(|n| OLD.contains(&n.as_str()) || NEW.contains(&n.as_str())),
        "unexpected runtime evidence or missing G2 custody"
    );
    let pre_path = root.join("PREFLIGHT.json");
    file(&pre_path, 101132301, 0, 0, 0o400, 28535)?;
    let pre = json_pin(&pre_path, PRE)?;
    let old = root.join("admission-v1");
    let seal = old.join("deployment-seal-receipt.json");
    let proof = old.join("artifact-proof.json");
    pinned(&seal, SEAL)?;
    pinned(&proof, PROOF)?;
    pinned(Path::new(FLEET), FLEET_SHA)?;
    ensure!(
        pre["fleet"] == binding(Path::new(FLEET), FLEET_SHA)
            && pre["provenance"]["controller_commit"] == OLD_SOURCE
            && pre["provenance"]["controller_seal"] == SEAL
            && pre["provenance"]["members"]["artifact-proof.json"] == PROOF,
        "old G2 provenance differs"
    );
    open_lock()?;
    let mut empty = json!({});
    for (name, ino, mode) in [
        ("barrier", 101132303, 0o755),
        ("guard-receipts", 101132302, 0o700),
    ] {
        let path = root.join(name);
        custody(&path, 0, 0, Some(ino), mode)?;
        exact_entries(&path, &[])?;
        empty[name] = json!({"inode":ino,"mode":mode,"entries":[]});
    }
    for (name, ino) in [("guard.stdout", 101132304), ("guard.stderr", 101132305)] {
        file(&root.join(name), ino, 0, 0, 0o600, 0)?;
        empty[name] = json!({"inode":ino,"mode":0o600,"bytes":0});
    }
    custody(Path::new(LANE), 1001, 1003, Some(111744585), 0o700)?;
    let attempt = Path::new(ATTEMPT);
    custody(attempt, 1001, 1003, Some(113313296), 0o700)?;
    exact_entries(attempt, &["producer.log"])?;
    file(
        &attempt.join("producer.log"),
        113313521,
        1001,
        1003,
        0o600,
        0,
    )?;
    no_jobs()?;
    Ok(
        json!({"schema":"epoch169-g2-pre-spawn-custody-v1","original_preflight":binding(&pre_path,PRE),
        "original_controller_seal":binding(&seal,SEAL),"original_controller_proof":binding(&proof,PROOF),
        "original_fleet":pre["fleet"],"original_source":OLD_SOURCE,"runtime_inode":101131907,"runtime_entries":entries,
        "admission_lock_inode":101132300,"empty_guard_stage":empty,"attempt":attempt,"attempt_inode":113313296,
        "producer_log_inode":113313521,"producer_log_bytes":0,"native_units_unused":[UNIT,GUARD_SERVICE,TIMER],
        "cgroups_unpopulated":true,"queued_169_jobs":0,"recorded_at":now()?}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stage_rejects_extra_or_missing_entries() {
        let dir = tempfile::tempdir().unwrap();
        assert!(exact_entries(dir.path(), &["producer.log"]).is_err());
        fs::write(dir.path().join("producer.log"), []).unwrap();
        exact_entries(dir.path(), &["producer.log"]).unwrap();
        fs::write(dir.path().join("allow"), []).unwrap();
        assert!(exact_entries(dir.path(), &["producer.log"]).is_err());
    }
    #[test]
    fn file_identity_rejects_nonempty_replacement_or_excess_links() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        fs::write(&path, []).unwrap();
        let m = fs::metadata(&path).unwrap();
        let verify =
            |ino| file_on_device(&path, m.dev(), ino, m.uid(), m.gid(), m.mode() & 0o7777, 0);
        verify(m.ino()).unwrap();
        assert!(verify(m.ino() + 1).is_err());
        fs::hard_link(&path, dir.path().join("alias")).unwrap();
        assert!(verify(m.ino()).is_err());
        fs::remove_file(dir.path().join("alias")).unwrap();
        fs::write(&path, b"x").unwrap();
        assert!(verify(m.ino()).is_err());
    }
    #[test]
    #[ignore = "read-only, requires installed original root evidence and empty stage"]
    fn genuine_g2_cold_stage() {
        cold().unwrap();
    }
}
