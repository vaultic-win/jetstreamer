//! Recoverable clean-exit -> sealed resume-evidence controller phase.
//! No producer signals, resource release, replay launch or remote operations.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
};

const EXIT: &str =
    "/var/lib/jetstreamer/horizon-pressure-exit-recovery-20261119-v1/pressure-checkpoint-exit";
const EXIT_SHA: &str = "ea70093e85a113c5879e8625a2bf90730da94ac6a335ff248f9e38689e1047e6";
const SEALER: &str =
    "/var/lib/jetstreamer/horizon251-published-sealer-20261118-v1/horizon251-sealer";
const SEALER_SHA: &str = "faf7aa8270b3472969bf394d4486cdf94445e30e4f15bc6acd38bed56880877a";

#[derive(Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Evidence {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    exit_plan: Evidence,
    state_directory: PathBuf,
    destination: PathBuf,
}
fn digest(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn id(m: &fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64, u32, u64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
        m.mode(),
        m.nlink(),
    )
}
fn bytes(path: &Path, mode: u32, bound: u64) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical input"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o7777 == mode
            && m.len() <= bound,
        "invalid input custody/size: {}",
        path.display()
    );
    let mut b = Vec::new();
    (&mut f).take(bound + 1).read_to_end(&mut b)?;
    ensure!(
        b.len() as u64 <= bound
            && id(&m) == id(&f.metadata()?)
            && id(&m) == id(&fs::symlink_metadata(path)?),
        "input changed"
    );
    Ok(b)
}
fn bound(e: &Evidence, mode: u32) -> Result<Vec<u8>> {
    ensure!(
        e.sha256.len() == 64
            && e.sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid digest"
    );
    let b = bytes(&e.path, mode, 4 << 20)?;
    ensure!(digest(&b) == e.sha256, "bound digest mismatch");
    Ok(b)
}
fn scoped(path: &Path, prefix: &str) -> Result<()> {
    ensure!(
        path.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && path
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with(prefix)
                    && s.len() < 193
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))),
        "path outside handoff scope"
    );
    Ok(())
}
fn directory(path: &Path, mode: u32) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o7777 == mode && path.canonicalize()? == path,
        "invalid directory custody"
    );
    Ok(())
}
fn persist(path: &Path, b: &[u8], mode: u32) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => ensure!(
            bytes(path, mode, 4 << 20)? == b,
            "existing controller record differs"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut f = tempfile::NamedTempFile::new_in(path.parent().context("missing parent")?)?;
            f.write_all(b)?;
            f.as_file()
                .set_permissions(fs::Permissions::from_mode(mode))?;
            f.as_file().sync_all()?;
            f.persist_noclobber(path)?;
        }
        Err(e) => return Err(e.into()),
    }
    File::open(path)?.sync_all()?;
    File::open(path.parent().context("missing parent")?)?.sync_all()?;
    Ok(())
}
fn invoke(image: &str, sha: &str, args: &[&str]) -> Result<()> {
    ensure!(
        digest(&bytes(Path::new(image), 0o555, 64 << 20)?) == sha,
        "controller dependency image changed"
    );
    let r = Command::new(image)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .output()?;
    ensure!(
        r.status.success(),
        "qualified helper rejected: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    Ok(())
}
fn prove_exit(e: &Evidence) -> Result<()> {
    invoke(
        EXIT,
        EXIT_SHA,
        &[
            e.path.to_str().context("plan path UTF8")?,
            "--plan-sha256",
            &e.sha256,
            "--self-sha256",
            EXIT_SHA,
        ],
    )
}
fn validate_package(destination: &Path, seal: &Value, seal_sha: &str) -> Result<Evidence> {
    directory(destination, 0o555)?;
    let rp = destination.join("deployment-seal-receipt.json");
    let raw = bytes(&rp, 0o444, 4 << 20)?;
    let receipt: Value = serde_json::from_slice(&raw)?;
    ensure!(
        receipt["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && receipt["plan_sha256"] == seal_sha
            && receipt["sealer_sha256"] == SEALER_SHA
            && receipt["destination"] == seal["destination"],
        "deployment receipt binding differs"
    );
    for k in [
        "publication_authorized",
        "replay_launch_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(receipt[k] == false, "deployment claims authority");
    }
    let members = seal["members"].as_array().context("seal members")?;
    let recorded = receipt["members"].as_array().context("receipt members")?;
    ensure!(
        members.len() == 3 && recorded.len() == members.len(),
        "deployment member count differs"
    );
    let mut names = BTreeSet::from([
        "SHA256SUMS".to_string(),
        "deployment-seal-receipt.json".to_string(),
    ]);
    let mut sums = BTreeMap::from([("deployment-seal-receipt.json".to_string(), digest(&raw))]);
    for (member, r) in members.iter().zip(recorded) {
        let name = member["name"].as_str().context("member name")?;
        let b = bytes(&destination.join(name), 0o444, 4 << 20)?;
        ensure!(
            r["source"] == member["source"]
                && r["name"] == name
                && r["sha256"] == member["sha256"]
                && r["mode"] == "0444"
                && r["bytes"] == b.len()
                && digest(&b) == member["sha256"],
            "sealed member differs"
        );
        ensure!(names.insert(name.into()), "duplicate member");
        sums.insert(name.into(), digest(&b));
    }
    let sums = sums
        .iter()
        .map(|(name, sha)| format!("{sha}  {name}\n"))
        .collect::<String>();
    ensure!(
        bytes(&destination.join("SHA256SUMS"), 0o444, 4 << 20)? == sums.as_bytes(),
        "sealed digest list differs"
    );
    let actual = fs::read_dir(destination)?
        .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<std::io::Result<BTreeSet<_>>>()?;
    ensure!(actual == names, "unexpected deployment member");
    Ok(Evidence {
        path: rp,
        sha256: digest(&raw),
    })
}
fn run(args: &[String]) -> Result<()> {
    ensure!(
        args.len() == 5 && args[1] == "--plan-sha256" && args[3] == "--self-sha256",
        "usage: pressure-checkpoint-handoff PLAN --plan-sha256 HEX --self-sha256 HEX"
    );
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let image = fs::read("/proc/self/exe")?;
    ensure!(digest(&image) == args[4], "running image differs");
    let binding = Evidence {
        path: args[0].clone().into(),
        sha256: args[2].clone(),
    };
    let plan_bytes = bound(&binding, 0o444)?;
    let p: Plan = serde_json::from_slice(&plan_bytes)?;
    ensure!(
        p.schema == "horizon-pressure-checkpoint-handoff-plan-v1",
        "unknown handoff plan"
    );
    scoped(&p.state_directory, "horizon-pressure-handoff-state-")?;
    scoped(&p.destination, "horizon-pressure-resume-evidence-")?;
    directory(&p.state_directory, 0o700)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p.state_directory.join("controller.lock"))?;
    let lm = lock.metadata()?;
    ensure!(
        lm.uid() == 0 && lm.nlink() == 1 && lm.is_file() && lm.mode() & 0o7777 == 0o600,
        "invalid controller lock"
    );
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "another controller holds this transition"
    );
    let exit_bytes = bound(&p.exit_plan, 0o444)?;
    let exit: Value = serde_json::from_slice(&exit_bytes)?;
    ensure!(
        exit["schema"] == "horizon-pressure-exit-plan-v1",
        "unknown exit plan"
    );
    prove_exit(&p.exit_plan)?;
    let report: Evidence = serde_json::from_value(exit["report"].clone())?;
    let report_bytes = bound(&report, 0o600)?;
    let proof_path = PathBuf::from(exit["output"].as_str().context("exit output")?);
    let proof_bytes = bytes(&proof_path, 0o600, 4 << 20)?;
    let proof: Value = serde_json::from_slice(&proof_bytes)?;
    ensure!(
        proof["schema"] == "horizon-pressure-exit-proof-v1"
            && proof["tool_sha256"] == EXIT_SHA
            && proof["plan"] == serde_json::to_value(&p.exit_plan)?
            && proof["report"] == exit["report"]
            && proof["epoch"] == exit["epoch"],
        "fresh exit proof binding differs"
    );
    let members = json!([
        {"source":report.path,"name":"paused.json","sha256":digest(&report_bytes),"mode":292},
        {"source":proof_path,"name":"exit-proof.json","sha256":digest(&proof_bytes),"mode":292},
        {"source":p.exit_plan.path,"name":"exit-plan.json","sha256":digest(&exit_bytes),"mode":292}
    ]);
    let seal = json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":p.destination,"members":members});
    let seal_bytes = serde_json::to_vec_pretty(&seal)?;
    let seal_sha = digest(&seal_bytes);
    let seal_path = p.state_directory.join("seal-plan.json");
    persist(&seal_path, &seal_bytes, 0o444)?;
    match fs::symlink_metadata(&p.destination) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => invoke(
            SEALER,
            SEALER_SHA,
            &[
                seal_path.to_str().context("seal path UTF8")?,
                "--plan-sha256",
                &seal_sha,
                "--self-sha256",
                SEALER_SHA,
            ],
        )?,
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    let receipt = validate_package(&p.destination, &seal, &seal_sha)?;
    #[cfg(test)]
    if std::env::var("JETSTREAMER_HANDOFF_TEST_CRASH").as_deref() == Ok("after-seal") {
        unsafe { libc::_exit(86) }
    }
    // Collection/restart between proof and sealing cannot become a completed
    // transition. Keep the parent invocation retained until this step finishes.
    prove_exit(&p.exit_plan)?;
    ensure!(
        bound(&binding, 0o444)? == plan_bytes
            && bound(&report, 0o600)? == report_bytes
            && bytes(&proof_path, 0o600, 4 << 20)? == proof_bytes,
        "transition inputs changed"
    );
    directory(&p.state_directory, 0o700)?;
    let completion = json!({"schema":"horizon-pressure-checkpoint-handoff-v1","plan":binding,"controller_sha256":args[4],"epoch":exit["epoch"],"deployment":receipt,"destination":p.destination,"phase":"resume-evidence-sealed","fresh_admission_required":true,"worker_launch_authorized":false,"resource_release_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
    persist(
        &p.state_directory.join("completion.json"),
        &serde_json::to_vec_pretty(&completion)?,
        0o600,
    )?;
    println!(
        "{}",
        json!({"completion":p.state_directory.join("completion.json"),"phase":"resume-evidence-sealed","fresh_admission_required":true,"worker_launch_authorized":false})
    );
    Ok(())
}
fn main() {
    if let Err(e) = run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("pressure checkpoint handoff rejected: {e:#}");
        std::process::exit(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "root integration with the pinned Rust deployment sealer"]
    fn real_seal_recovery_rejects_changed_members_and_unexpected_files() {
        ensure_root();
        let d = tempfile::tempdir_in("/var/lib/jetstreamer").unwrap();
        let destination = d.path().join("sealed");
        let mut members = Vec::new();
        for name in ["paused.json", "exit-proof.json", "exit-plan.json"] {
            let source = d.path().join(name);
            persist(&source, name.as_bytes(), 0o600).unwrap();
            members.push(
                json!({"source":source,"name":name,"sha256":digest(name.as_bytes()),"mode":292}),
            );
        }
        let seal = json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":destination,"members":members});
        let raw = serde_json::to_vec_pretty(&seal).unwrap();
        let sha = digest(&raw);
        let plan = d.path().join("plan.json");
        persist(&plan, &raw, 0o444).unwrap();
        invoke(
            SEALER,
            SEALER_SHA,
            &[
                plan.to_str().unwrap(),
                "--plan-sha256",
                &sha,
                "--self-sha256",
                SEALER_SHA,
            ],
        )
        .unwrap();
        let before = bytes(&destination.join("SHA256SUMS"), 0o444, 4 << 20).unwrap();
        let receipt = validate_package(&destination, &seal, &sha).unwrap();
        assert!(receipt == validate_package(&destination, &seal, &sha).unwrap());
        assert_eq!(
            before,
            bytes(&destination.join("SHA256SUMS"), 0o444, 4 << 20).unwrap()
        );
        assert!(validate_package(&destination, &seal, &"0".repeat(64)).is_err());
        let member = destination.join("paused.json");
        fs::write(&member, b"changed").unwrap();
        assert!(validate_package(&destination, &seal, &sha).is_err());
        fs::write(&member, b"paused.json").unwrap();
        validate_package(&destination, &seal, &sha).unwrap();
        fs::write(destination.join("unexpected"), b"extra").unwrap();
        assert!(validate_package(&destination, &seal, &sha).is_err());
    }
    #[test]
    fn output_scope_is_closed() {
        assert!(
            scoped(
                Path::new("/var/lib/jetstreamer/horizon-pressure-resume-evidence-test"),
                "horizon-pressure-resume-evidence-"
            )
            .is_ok()
        );
        for path in [
            "/tmp/horizon-pressure-resume-evidence-test",
            "/var/lib/jetstreamer/other",
            "/var/lib/jetstreamer/horizon-pressure-resume-evidence-a/b",
            "/var/lib/jetstreamer/horizon-pressure-resume-evidence-..",
        ] {
            assert!(scoped(Path::new(path), "horizon-pressure-resume-evidence-").is_err());
        }
    }
    #[test]
    #[ignore = "root-private record recovery and conflict controls"]
    fn root_records_reuse_exact_bytes_and_reject_conflicts_and_links() {
        ensure_root();
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("record.json");
        persist(&p, b"original", 0o600).unwrap();
        let before = id(&fs::symlink_metadata(&p).unwrap());
        persist(&p, b"original", 0o600).unwrap();
        assert_eq!(before, id(&fs::symlink_metadata(&p).unwrap()));
        assert!(persist(&p, b"different", 0o600).is_err());
        let alias = d.path().join("alias");
        std::os::unix::fs::symlink(&p, &alias).unwrap();
        assert!(persist(&alias, b"original", 0o600).is_err());
        fs::remove_file(alias).unwrap();
        fs::hard_link(&p, d.path().join("hard")).unwrap();
        assert!(persist(&p, b"original", 0o600).is_err());
    }
    fn ensure_root() {
        assert_eq!(unsafe { libc::geteuid() }, 0)
    }
    #[test]
    #[ignore = "native controller crash after actual Rust deployment seal"]
    fn native_controller_crash_after_seal() {
        ensure_root();
        let args: Vec<String> =
            serde_json::from_str(&std::env::var("JETSTREAMER_HANDOFF_NATIVE_ARGS").unwrap())
                .unwrap();
        run(&args).unwrap();
    }
}
