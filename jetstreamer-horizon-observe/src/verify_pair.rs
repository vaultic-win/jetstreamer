//! Native per-epoch full/plugin receipt producer. Never publishes archives or R2.
#[allow(dead_code)]
#[path = "../../jetstreamer-utils/src/epoch141_ledger_common.rs"]
mod evidence;
use {
    anyhow::{Context, Result, ensure},
    serde::Deserialize,
    sha2::{Digest, Sha256},
    std::{
        env,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        path::{Path, PathBuf},
        process::{Child, Command},
        time::{SystemTime, UNIX_EPOCH},
    },
};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Stage {
    Full,
    Plugin,
}

fn milestone(p: &Plan, event: &str) -> Result<()> {
    eprintln!(
        "{}",
        serde_json::json!({"schema":"horizon-pair-verification-milestone-v1","epoch":p.epoch,"stage":p.stage.suffix(),"event":event,"unix_millis":SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis()})
    );
    Ok(())
}
impl Stage {
    fn suffix(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Plugin => "plugin",
        }
    }
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    epoch: u64,
    stage: Stage,
    archive_directory: PathBuf,
    expected_archive_sha256: String,
    verifier: Bound,
    threads_per_command: usize,
    state_directory: PathBuf,
}

fn validate_plan(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "horizon-verify-canonical-pair-plan-v1",
        "wrong schema"
    );
    ensure!(
        (201..=300).contains(&p.epoch),
        "epoch outside assigned campaign"
    );
    ensure!(
        (1..=32).contains(&p.threads_per_command),
        "unbounded threads"
    );
    ensure!(
        evidence::is_sha(&p.expected_archive_sha256),
        "invalid archive digest"
    );
    ensure!(
        p.archive_directory == Path::new("/home/ubuntu/horizon"),
        "foreign archive directory"
    );
    ensure!(
        p.state_directory.is_absolute()
            && !p.state_directory.starts_with(&p.archive_directory)
            && p.verifier.path.is_absolute(),
        "unsafe verification paths"
    );
    ensure!(
        p.verifier.path.file_name().and_then(|s| s.to_str())
            == Some(match p.stage {
                Stage::Full => "verify_archive",
                Stage::Plugin => "horizon_pipeline",
            }),
        "wrong verifier executable for stage"
    );
    Ok(())
}

fn batch_absent(directory: &Path) -> Result<()> {
    for name in [
        ".jetstreamer-archive-batch",
        ".jetstreamer-archive-batch-outcome",
    ] {
        match fs::symlink_metadata(directory.join(name)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
            Ok(_) => anyhow::bail!("archive batch publication is not acknowledged"),
        }
    }
    Ok(())
}

fn open_stable(path: &Path) -> Result<File> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical input"
    );
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.mode() & 0o222 == 0,
        "input must be an immutable singly linked regular file"
    );
    ensure!(
        evidence::identity(&m) == evidence::identity(&fs::symlink_metadata(path)?),
        "input raced open"
    );
    Ok(f)
}

fn recheck(path: &Path, f: &File, before: &fs::Metadata) -> Result<()> {
    ensure!(
        evidence::identity(before) == evidence::identity(&f.metadata()?)
            && evidence::identity(before) == evidence::identity(&fs::symlink_metadata(path)?),
        "input path or descriptor changed"
    );
    Ok(())
}

fn hash_archive(path: &Path) -> Result<(String, fs::Metadata)> {
    let mut f = open_stable(path)?;
    let m = f.metadata()?;
    ensure!(m.len() > 0, "empty archive");
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 8 * 1024 * 1024];
    loop {
        let n = f.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    recheck(path, &f, &m)?;
    Ok((format!("{:x}", digest.finalize()), m))
}

fn sidecar(path: &Path, epoch: u64, digest: &str) -> Result<Vec<u8>> {
    let mut f = open_stable(path)?;
    let m = f.metadata()?;
    ensure!(m.len() <= 512, "oversized sidecar");
    let mut bytes = Vec::new();
    (&mut f).take(513).read_to_end(&mut bytes)?;
    ensure!(
        bytes == format!("{digest}  epoch-{epoch}.jet\n").as_bytes(),
        "noncanonical or mismatching sidecar"
    );
    recheck(path, &f, &m)?;
    Ok(bytes)
}

fn commands(p: &Plan) -> Vec<Vec<String>> {
    let archive = p.archive_directory.join(format!("epoch-{}.jet", p.epoch));
    let threads = p.threads_per_command.to_string();
    match p.stage {
        Stage::Full => vec![
            vec![
                archive.display().to_string(),
                "--threads".into(),
                threads.clone(),
            ],
            vec![
                archive.display().to_string(),
                "--full".into(),
                "--internal-full".into(),
                "--threads".into(),
                threads,
            ],
        ],
        Stage::Plugin => vec![vec![
            format!("{}:{}", p.epoch, p.epoch),
            p.archive_directory.display().to_string(),
            "--threads".into(),
            threads,
            "--verify-only".into(),
        ]],
    }
}

struct Children(Vec<Child>);
impl Drop for Children {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
fn run_commands(executable: &Path, args: &[Vec<String>]) -> Result<()> {
    let mut children = Children(Vec::new());
    for command in args {
        children
            .0
            .push(Command::new(executable).args(command).spawn()?);
    }
    for child in &mut children.0 {
        ensure!(
            child.wait()?.success(),
            "independent verifier command failed"
        );
    }
    Ok(())
}

fn private_directory(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o077 == 0,
        "verification state must be root-owned and owner-only: {} uid={} mode={:o}",
        path.display(),
        m.uid(),
        m.mode() & 0o7777
    );
    Ok(())
}
fn commit_receipt(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("receipt parent missing")?;
    private_directory(parent)?;
    if let Ok(m) = fs::symlink_metadata(path) {
        ensure!(
            m.is_file() && m.nlink() == 1 && m.uid() == 0 && m.mode() & 0o077 == 0,
            "unsafe existing receipt"
        );
        let mut old = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        let mut found = Vec::new();
        (&mut old).take(4097).read_to_end(&mut found)?;
        ensure!(
            found == bytes
                && evidence::identity(&m) == evidence::identity(&old.metadata()?)
                && evidence::identity(&m) == evidence::identity(&fs::symlink_metadata(path)?),
            "existing receipt differs"
        );
        old.sync_all()?;
        File::open(parent)?.sync_all()?;
        return Ok(());
    }
    let mut temp = tempfile::Builder::new()
        .prefix(".verify-pair-")
        .tempfile_in(parent)?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    temp.persist_noclobber(path).map_err(|e| e.error)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn run() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let args: Vec<_> = env::args().skip(1).collect();
    ensure!(args.len() == 3, "usage: PLAN PLAN_SHA256 SELF_SHA256");
    let self_path = fs::read_link("/proc/self/exe")?;
    evidence::bound_file(&self_path, &args[2], 64 * 1024 * 1024, true)?;
    let raw = evidence::bound_file(Path::new(&args[0]), &args[1], 65536, true)?;
    let p: Plan = serde_json::from_slice(&raw)?;
    validate_plan(&p)?;
    private_directory(&p.state_directory)?;
    let receipts = p.state_directory.join("receipts");
    private_directory(&receipts)?;
    batch_absent(&p.archive_directory)?;
    evidence::bound_file(
        &p.verifier.path,
        &p.verifier.sha256,
        128 * 1024 * 1024,
        true,
    )?;
    let archive = p.archive_directory.join(format!("epoch-{}.jet", p.epoch));
    let checksum = p
        .archive_directory
        .join(format!("epoch-{}.jet.sha256", p.epoch));
    let before_sidecar = sidecar(&checksum, p.epoch, &p.expected_archive_sha256)?;
    milestone(&p, "pre_verification_hash_started")?;
    let (before_hash, before_meta) = hash_archive(&archive)?;
    ensure!(
        before_hash == p.expected_archive_sha256,
        "archive digest differs before verification"
    );
    milestone(&p, "pre_verification_hash_passed")?;
    eprintln!(
        "epoch {} {} verification started",
        p.epoch,
        p.stage.suffix()
    );
    run_commands(&p.verifier.path, &commands(&p))?;
    milestone(&p, "independent_verifier_commands_passed")?;
    milestone(&p, "post_verification_hash_started")?;
    let (after_hash, after_meta) = hash_archive(&archive)?;
    ensure!(
        before_hash == after_hash
            && evidence::identity(&before_meta) == evidence::identity(&after_meta),
        "archive changed across independent verification"
    );
    milestone(&p, "post_verification_hash_passed")?;
    ensure!(
        sidecar(&checksum, p.epoch, &p.expected_archive_sha256)? == before_sidecar,
        "sidecar changed"
    );
    evidence::bound_file(
        &p.verifier.path,
        &p.verifier.sha256,
        128 * 1024 * 1024,
        true,
    )?;
    evidence::bound_file(Path::new(&args[0]), &args[1], 65536, true)?;
    evidence::bound_file(&self_path, &args[2], 64 * 1024 * 1024, true)?;
    batch_absent(&p.archive_directory)?;
    let output = receipts.join(format!("epoch-{}.{}.ok", p.epoch, p.stage.suffix()));
    milestone(&p, "receipt_fsync_started")?;
    commit_receipt(
        &output,
        format!("{} {} {}\n", after_hash, p.verifier.sha256, args[2]).as_bytes(),
    )?;
    milestone(&p, "receipt_durable")?;
    println!("{}", output.display());
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn plan(stage: Stage) -> Plan {
        Plan {
            schema: "horizon-verify-canonical-pair-plan-v1".into(),
            epoch: 220,
            stage,
            archive_directory: "/home/ubuntu/horizon".into(),
            expected_archive_sha256: "a".repeat(64),
            verifier: Bound {
                path: match stage {
                    Stage::Full => "/immutable/verify_archive",
                    Stage::Plugin => "/immutable/horizon_pipeline",
                }
                .into(),
                sha256: "b".repeat(64),
            },
            threads_per_command: 8,
            state_directory: "/private/state".into(),
        }
    }
    #[test]
    fn full_requires_both_ordered_and_internal_full_scans() {
        let p = plan(Stage::Full);
        let c = commands(&p);
        assert_eq!(c.len(), 2);
        assert_eq!(
            c[0],
            vec!["/home/ubuntu/horizon/epoch-220.jet", "--threads", "8"]
        );
        assert_eq!(
            c[1],
            vec![
                "/home/ubuntu/horizon/epoch-220.jet",
                "--full",
                "--internal-full",
                "--threads",
                "8"
            ]
        );
    }
    #[test]
    fn plugin_is_one_epoch_current_verify_only() {
        assert_eq!(
            commands(&plan(Stage::Plugin)),
            vec![vec![
                "220:220",
                "/home/ubuntu/horizon",
                "--threads",
                "8",
                "--verify-only"
            ]]
        );
    }
    #[test]
    fn campaign_bounds_and_threads_never_expand() {
        let mut p = plan(Stage::Full);
        validate_plan(&p).unwrap();
        for n in [0, 200, 301, 1000] {
            p.epoch = n;
            assert!(validate_plan(&p).is_err());
        }
        p.epoch = 220;
        for n in [0, 33, usize::MAX] {
            p.threads_per_command = n;
            assert!(validate_plan(&p).is_err());
        }
    }
    #[test]
    fn strict_plan_rejects_skip_overwrite_and_retirement() {
        let p = json!({"schema":"horizon-verify-canonical-pair-plan-v1","epoch":220,"stage":"full","archive_directory":"/home/ubuntu/horizon","expected_archive_sha256":"a".repeat(64),"verifier":{"path":"/bin/verifier","sha256":"b".repeat(64)},"threads_per_command":8,"state_directory":"/private/state"});
        assert!(serde_json::from_value::<Plan>(p.clone()).is_ok());
        for key in ["skip_full", "delete_local", "overwrite", "allow_partial"] {
            let mut bad = p.clone();
            bad[key] = json!(true);
            assert!(serde_json::from_value::<Plan>(bad).is_err());
        }
    }
    fn immutable_file(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o440)).unwrap();
    }
    #[test]
    fn sidecar_is_exact_and_hardlinks_writable_files_reject() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a");
        let digest = "a".repeat(64);
        immutable_file(&p, format!("{digest}  epoch-220.jet\n").as_bytes());
        sidecar(&p, 220, &digest).unwrap();
        assert!(sidecar(&p, 221, &digest).is_err());
        assert!(sidecar(&p, 220, &"b".repeat(64)).is_err());
        let link = d.path().join("b");
        fs::hard_link(&p, &link).unwrap();
        assert!(sidecar(&p, 220, &digest).is_err());
        fs::remove_file(link).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(sidecar(&p, 220, &digest).is_err());
    }
    #[test]
    fn path_replacement_is_not_stable_evidence() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a");
        immutable_file(&p, b"first");
        let f = open_stable(&p).unwrap();
        let m = f.metadata().unwrap();
        fs::rename(&p, d.path().join("old")).unwrap();
        immutable_file(&p, b"first");
        assert!(recheck(&p, &f, &m).is_err());
    }
    #[test]
    fn command_failure_does_not_succeed() {
        assert!(run_commands(Path::new("/bin/false"), &[vec![], vec![]]).is_err());
    }
    #[test]
    fn dangling_batch_marker_is_not_absence() {
        let d = tempfile::tempdir().unwrap();
        batch_absent(d.path()).unwrap();
        std::os::unix::fs::symlink("missing", d.path().join(".jetstreamer-archive-batch")).unwrap();
        assert!(batch_absent(d.path()).is_err());
    }
    #[test]
    fn receipt_is_no_clobber_private_and_idempotently_durable() {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let p = d.path().join("epoch-220.full.ok");
        let bytes = b"digest verifier runner\n";
        if unsafe { libc::geteuid() } != 0 {
            assert!(commit_receipt(&p, bytes).is_err());
            return;
        }
        commit_receipt(&p, bytes).unwrap();
        commit_receipt(&p, bytes).unwrap();
        assert_eq!(fs::read(&p).unwrap(), bytes);
        assert_eq!(fs::symlink_metadata(&p).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::symlink_metadata(&p).unwrap().nlink(), 1);
        assert!(commit_receipt(&p, b"changed").is_err());
        assert_eq!(fs::read(&p).unwrap(), bytes);
    }
    #[test]
    fn stages_cannot_use_a_different_executable_name() {
        let mut p = plan(Stage::Full);
        p.verifier.path = "/bin/true".into();
        assert!(validate_plan(&p).is_err());
        p.verifier.path = "/immutable/horizon_pipeline".into();
        assert!(validate_plan(&p).is_err());
        p.stage = Stage::Plugin;
        validate_plan(&p).unwrap();
    }
}
