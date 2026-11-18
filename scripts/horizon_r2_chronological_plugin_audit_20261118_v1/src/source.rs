use crate::{Config, local::*};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};
pub const READER_ROOT: &str = "/usr/local/lib/jetstreamer/horizon-r2-audit-readers-20261118-v1";
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reader {
    pub branch_commit: String,
    pub source_fingerprint: String,
    pub source_files: BTreeMap<String, String>,
    pub cargo_lock_sha256: String,
    pub rustc_version: String,
    pub cargo_version: String,
    pub cargo_sha256: String,
    pub rustc_sha256: String,
    pub features: Vec<String>,
    pub artifact: PathBuf,
    pub artifact_sha256: String,
    pub seal_receipt_sha256: String,
    pub built_from_commit: String,
    pub equivalence_reused: bool,
    pub fetched_at: u64,
}
fn check_sealed_reader(reader: &Reader) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let parent = reader
        .artifact
        .parent()
        .context("reader has no deployment")?;
    ensure!(
        parent.parent() == Some(Path::new(READER_ROOT))
            && reader
                .artifact
                .file_name()
                .is_some_and(|n| n == "horizon_pipeline"),
        "reader escaped sealed deployment root"
    );
    let m = fs::symlink_metadata(&reader.artifact)?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.mode() & 0o7777 == 0o555 && m.nlink() == 1,
        "reader is not root-sealed"
    );
    ensure!(
        hash_file(&reader.artifact)? == reader.artifact_sha256,
        "sealed reader image changed"
    );
    let path = parent.join("deployment-seal-receipt.json");
    ensure!(
        hash_file(&path)? == reader.seal_receipt_sha256,
        "reader seal receipt changed"
    );
    let receipt: Value = read_json(&path)?;
    ensure!(
        receipt["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && receipt["sealer_sha256"] == SEALER_SHA
            && receipt["destination"].as_str() == parent.to_str(),
        "reader seal identity mismatch"
    );
    ensure!(
        receipt["members"]
            .as_array()
            .context("seal members missing")?
            .iter()
            .any(|m| m["name"] == "horizon_pipeline" && m["sha256"] == reader.artifact_sha256),
        "reader absent from seal"
    );
    for flag in [
        "publication_authorized",
        "replay_launch_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            receipt[flag] == false,
            "reader seal unexpectedly authorizes mutations"
        );
    }
    Ok(())
}
fn capture(mut command: Command) -> Result<String> {
    let output = command.output()?;
    ensure!(
        output.status.success(),
        "source command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    ensure!(
        output.stdout.len() < 32 * 1024 * 1024,
        "source command output exceeds bound"
    );
    Ok(String::from_utf8(output.stdout)?)
}
fn git(source: &Path) -> Command {
    let mut c = clean_command(Path::new("/usr/bin/git"));
    c.arg("-C").arg(source);
    c
}
fn git_text(source: &Path, args: &[&str]) -> Result<String> {
    let mut c = git(source);
    c.args(args);
    capture(c)
}
fn ssh_socket(cfg: &Config) -> Result<PathBuf> {
    let mut key = clean_command(Path::new("/usr/bin/ssh-keygen"));
    key.args(["-l", "-f"])
        .arg(cfg.git_home.join(".ssh/matt_vaultic.pub"));
    let key_identity = capture(key)?;
    let fingerprint = key_identity
        .split_ascii_whitespace()
        .nth(1)
        .context("cannot identify the configured Vaultic SSH key")?;
    let mut candidates = Vec::new();
    if let Some(p) = env::var_os("SSH_AUTH_SOCK") {
        candidates.push(PathBuf::from(p));
    }
    if let Ok(entries) = fs::read_dir(cfg.git_home.join(".keychain")) {
        for entry in entries.flatten() {
            if !entry.file_name().to_string_lossy().ends_with("-sh") {
                continue;
            }
            let file = open_read(&entry.path())?;
            ensure!(
                file.metadata()?.len() <= 16384,
                "keychain metadata exceeds bound"
            );
            use std::io::Read;
            let mut text = String::new();
            file.take(16384).read_to_string(&mut text)?;
            for line in text.lines() {
                if let Some(value) = line
                    .strip_prefix("SSH_AUTH_SOCK=")
                    .and_then(|s| s.split(';').next())
                    && value.starts_with('/')
                    && !value.contains(['\n', '\r', '\0'])
                {
                    candidates.push(PathBuf::from(value));
                }
            }
        }
    }
    for entry in fs::read_dir("/tmp")? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with("ssh-") && entry.file_type()?.is_dir() {
            for file in fs::read_dir(entry.path())? {
                let file = file?;
                if file.file_name().to_string_lossy().starts_with("agent.") {
                    candidates.push(file.path());
                }
            }
        }
    }
    for path in candidates {
        let mut c = clean_command(Path::new("/usr/bin/ssh-add"));
        c.arg("-l").env("SSH_AUTH_SOCK", &path);
        let out = c.output()?;
        if out.status.success()
            && String::from_utf8_lossy(&out.stdout)
                .split_ascii_whitespace()
                .any(|word| word == fingerprint)
        {
            return Ok(path);
        }
    }
    anyhow::bail!("no currently loaded SSH agent for account-updates fetch")
}
fn network_git(cfg: &Config) -> Result<Command> {
    let mut c = clean_command(Path::new("/usr/bin/git"));
    fn quote(path: &Path) -> Result<String> {
        let text = path.to_str().context("SSH path must be UTF-8")?;
        Ok(format!("'{}'", text.replace('\'', "'\\''")))
    }
    let ssh = cfg.git_home.join(".ssh");
    let ssh_command = format!(
        "ssh -F {} -i {} -oUserKnownHostsFile={} -oIdentityAgent=SSH_AUTH_SOCK -oBatchMode=yes -oConnectTimeout=30 -oStrictHostKeyChecking=yes",
        quote(&ssh.join("config"))?,
        quote(&ssh.join("matt_vaultic"))?,
        quote(&ssh.join("known_hosts"))?
    );
    c.env("SSH_AUTH_SOCK", ssh_socket(cfg)?)
        .env("HOME", &cfg.git_home)
        .env("GIT_SSH_COMMAND", ssh_command);
    Ok(c)
}
fn cargo(cfg: &Config, source: &Path) -> Result<Command> {
    // ProtectSystem=strict makes the service's global /tmp read-only. Native
    // dependency build scripts must use scratch included in our allocation walk.
    let temporary = cfg.state_directory.join("build-tmp");
    private_dir(&temporary)?;
    let mut c = clean_command(&cfg.cargo);
    c.current_dir(source)
        .env("CARGO_HOME", &cfg.cargo_home)
        .env("RUSTC", &cfg.rustc)
        .env("HOME", &cfg.git_home)
        .env("TMPDIR", temporary)
        .env("CARGO_TARGET_DIR", cfg.state_directory.join("build"))
        .env("CARGO_BUILD_JOBS", cfg.build_jobs.to_string());
    Ok(c)
}
pub fn fetch(cfg: &Config, attempt: &Path, seq: u64) -> Result<String> {
    let source = cfg.state_directory.join("source");
    let mut command = network_git(cfg)?;
    private_dir(&source)?;
    if !source.join(".git").try_exists()? {
        git_text(&source, &["init", "--initial-branch=account-updates"])?;
    }
    let remotes = git_text(&source, &["remote"])?;
    if remotes.trim().is_empty() {
        git_text(&source, &["remote", "add", "origin", &cfg.repository])?;
    }
    ensure!(
        git_text(&source, &["remote", "get-url", "origin"])?.trim() == cfg.repository,
        "audit source origin changed"
    );
    ensure!(
        git_text(
            &source,
            &["status", "--porcelain", "--untracked-files=normal"]
        )?
        .trim()
        .is_empty(),
        "audit source checkout was modified"
    );
    command.arg("-C").arg(&source).args([
        "fetch",
        "--depth=1",
        "--no-tags",
        "origin",
        "+refs/heads/account-updates:refs/remotes/origin/account-updates",
    ]);
    ensure!(
        run_logged(
            command,
            &attempt.join(format!("fetch-{seq}.log")),
            600,
            cfg.max_log_bytes,
            &cfg.state_directory,
            cfg.reserve_bytes,
            cfg.build_reserve_bytes
        )?,
        "account-updates fetch failed"
    );
    let commit = git_text(
        &source,
        &["rev-parse", "refs/remotes/origin/account-updates"],
    )?
    .trim()
    .to_owned();
    ensure!(
        commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid source commit"
    );
    git_text(&source, &["checkout", "--detach", &commit])?;
    ensure!(
        git_text(
            &source,
            &["status", "--porcelain", "--untracked-files=normal"]
        )?
        .trim()
        .is_empty(),
        "unclean reader source"
    );
    Ok(commit)
}

pub fn fingerprint_files(
    source: &Path,
    tracked: &str,
    dirs: &BTreeSet<PathBuf>,
) -> Result<BTreeMap<String, String>> {
    let mut files = BTreeMap::new();
    for name in tracked.split('\0').filter(|s| !s.is_empty()) {
        let relative = Path::new(name);
        let root_required = matches!(
            name,
            "Cargo.toml" | "Cargo.lock" | "rust-toolchain.toml" | "rust-toolchain" | "build.rs"
        ) || relative.starts_with("src")
            || relative.starts_with(".cargo");
        if root_required || dirs.iter().any(|d| relative.starts_with(d)) {
            let path = source.join(relative);
            ensure!(
                fs::symlink_metadata(&path)?.is_file(),
                "reader input is not a regular tracked file: {name}"
            );
            files.insert(name.to_owned(), hash_file(&path)?);
        }
    }
    for required in [
        "Cargo.toml",
        "Cargo.lock",
        "src/bin/horizon_pipeline.rs",
        "jetstreamer-plugin/src/plugins/verification.rs",
    ] {
        ensure!(
            files.contains_key(required),
            "reader closure missing {required}"
        );
    }
    Ok(files)
}
fn source_closure(cfg: &Config, attempt: &Path) -> Result<BTreeMap<String, String>> {
    let source = cfg.state_directory.join("source");
    let mut command = cargo(cfg, &source)?;
    command.args([
        "metadata",
        "--quiet",
        "--offline",
        "--locked",
        "--format-version",
        "1",
        "--no-default-features",
    ]);
    let metadata_path = attempt.join(format!("cargo-metadata-{}.json", nonce()));
    ensure!(
        run_logged(
            command,
            &metadata_path,
            600,
            32 * 1024 * 1024,
            &cfg.state_directory,
            cfg.reserve_bytes,
            cfg.build_reserve_bytes
        )?,
        "Cargo metadata failed; inspect bounded metadata log"
    );
    let file = open_read(&metadata_path)?;
    ensure!(
        file.metadata()?.len() <= 32 * 1024 * 1024,
        "Cargo metadata exceeds bound"
    );
    let metadata: Value = serde_json::from_reader(file)?;
    let packages = metadata["packages"]
        .as_array()
        .context("metadata packages missing")?;
    let resolve = &metadata["resolve"];
    let root = resolve["root"].as_str().context("metadata root missing")?;
    let nodes: BTreeMap<&str, &Value> = resolve["nodes"]
        .as_array()
        .context("resolve nodes missing")?
        .iter()
        .map(|n| Ok((n["id"].as_str().context("node ID missing")?, n)))
        .collect::<Result<_>>()?;
    let mut queue = VecDeque::from([root]);
    let mut closure = BTreeSet::new();
    while let Some(id) = queue.pop_front() {
        if !closure.insert(id) {
            continue;
        }
        let node = nodes.get(id).context("unresolved dependency")?;
        for dependency in node["dependencies"]
            .as_array()
            .context("dependencies missing")?
        {
            queue.push_back(dependency.as_str().context("dependency ID missing")?);
        }
    }
    let mut dirs = BTreeSet::new();
    for package in packages {
        if package["source"].is_null()
            && closure.contains(package["id"].as_str().context("package ID missing")?)
        {
            let manifest = Path::new(
                package["manifest_path"]
                    .as_str()
                    .context("manifest missing")?,
            );
            let dir = manifest
                .parent()
                .context("manifest parent missing")?
                .strip_prefix(&source)
                .context("reader dependency escapes its checked-out repository")?;
            if !dir.as_os_str().is_empty() {
                dirs.insert(dir.to_owned());
            }
        }
    }
    let tracked = git_text(&source, &["ls-files", "-z"])?;
    let files = fingerprint_files(&source, &tracked, &dirs)?;
    // The durable Reader receipt stores the exact closure hashes. Successful
    // dependency-graph JSON is reproducible and can be tens of MB per fetch;
    // do not retain hundreds of redundant copies. Failed diagnostics remain.
    fs::remove_file(&metadata_path)?;
    sync_dir(attempt)?;
    Ok(files)
}

pub fn qualify(cfg: &Config, attempt: &Path, seq: u64) -> Result<Reader> {
    let commit = fetch(cfg, attempt, seq)?;
    let source = cfg.state_directory.join("source");
    // External Cargo configuration could replace sources or alter the build.
    // Require it absent, and use a fixed toolchain and cleared child environment.
    for name in ["config", "config.toml"] {
        ensure!(
            !cfg.cargo_home.join(name).try_exists()?,
            "external Cargo configuration is not admitted"
        );
    }
    let files = source_closure(cfg, attempt)?;
    let mut rustc = clean_command(&cfg.rustc);
    rustc.arg("-vV");
    let rustc_version = capture(rustc)?;
    let mut cargo_version_cmd = clean_command(&cfg.cargo);
    cargo_version_cmd.arg("--version");
    let cargo_version = capture(cargo_version_cmd)?;
    let cargo_sha256 = hash_file(&cfg.cargo)?;
    let rustc_sha256 = hash_file(&cfg.rustc)?;
    let features = vec!["--no-default-features".to_owned()];
    let build_environment = serde_json::json!({"temporary_directory":"owned-state/build-tmp","build_jobs":cfg.build_jobs});
    let fingerprint = digest(&serde_json::to_vec(&(
        &files,
        &rustc_version,
        &cargo_version,
        &features,
        &cargo_sha256,
        &rustc_sha256,
        &build_environment,
    ))?);
    let old = cfg.state_directory.join("reader.json");
    if old.try_exists()? {
        let mut reader: Reader = read_json(&old)?;
        if reader.source_fingerprint == fingerprint {
            check_sealed_reader(&reader)?;
            reader.branch_commit = commit;
            reader.equivalence_reused = true;
            reader.fetched_at = now();
            write_json(&old, &reader, true)?;
            return Ok(reader);
        }
    }
    require_space(
        &cfg.state_directory,
        cfg.reserve_bytes,
        remaining_working_budget(&cfg.state_directory, cfg.build_reserve_bytes)?,
    )?;
    let mut command = cargo(cfg, &source)?;
    command.args([
        "build",
        "--release",
        "--locked",
        "--package",
        "jetstreamer",
        "--bin",
        "horizon_pipeline",
        "--no-default-features",
    ]);
    ensure!(
        run_logged(
            command,
            &attempt.join(format!("build-{seq}.log")),
            cfg.build_timeout_seconds,
            cfg.max_log_bytes,
            &cfg.state_directory,
            cfg.reserve_bytes,
            cfg.build_reserve_bytes
        )?,
        "current account-updates reader build failed"
    );
    ensure!(
        source_closure(cfg, attempt)? == files,
        "reader inputs changed during compilation"
    );
    ensure!(
        git_text(
            &source,
            &["status", "--porcelain", "--untracked-files=normal"]
        )?
        .trim()
        .is_empty(),
        "build modified reader source"
    );
    let built = cfg.state_directory.join("build/release/horizon_pipeline");
    let artifact_sha256 = hash_file(&built)?;
    use std::os::unix::fs::MetadataExt;
    let root = Path::new(READER_ROOT);
    validate_absolute(root)?;
    let meta = fs::symlink_metadata(root)
        .context("parent must provision the root-owned reader deployment directory")?;
    ensure!(
        meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o022 == 0,
        "unsafe reader deployment root"
    );
    ensure!(
        meta.dev() == fs::metadata(&cfg.state_directory)?.dev(),
        "reader deployments require the admitted state filesystem"
    );
    ensure!(
        hash_file(Path::new(SEALER))? == SEALER_SHA,
        "approved runtime sealer changed"
    );
    let generation = nonce();
    let destination = root.join(format!("reader-{}-{generation}", &fingerprint[..16]));
    let proof_path = attempt.join(format!("reader-build-proof-{generation}.json"));
    write_json(
        &proof_path,
        &serde_json::json!({"schema":"horizon-r2-audit-reader-build-v1","branch":"account-updates",
        "branch_commit":commit,"source_fingerprint":fingerprint,"source_files":files,"artifact_sha256":artifact_sha256,
        "cargo_lock_sha256":files["Cargo.lock"],"cargo_sha256":cargo_sha256,"rustc_sha256":rustc_sha256,
        "cargo_version":cargo_version,"rustc_version":rustc_version,"features":features,"build_environment":build_environment,"remote_mutations":false}),
        false,
    )?;
    let plan = serde_json::json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":destination,"members":[
        {"source":built,"name":"horizon_pipeline","sha256":artifact_sha256,"mode":0o555},
        {"source":proof_path,"name":"build-proof.json","sha256":hash_file(&proof_path)?,"mode":0o444}]});
    let plan_path = attempt.join(format!("reader-seal-plan-{generation}.json"));
    write_json(&plan_path, &plan, false)?;
    let mut seal = clean_command(Path::new("/usr/bin/sudo"));
    seal.args(["-n", SEALER])
        .arg(&plan_path)
        .arg("--plan-sha256")
        .arg(hash_file(&plan_path)?)
        .args(["--self-sha256", SEALER_SHA]);
    ensure!(
        run_logged(
            seal,
            &attempt.join(format!("reader-seal-{generation}.log")),
            300,
            cfg.max_log_bytes,
            &cfg.state_directory,
            cfg.reserve_bytes,
            cfg.build_reserve_bytes
        )?,
        "root reader deployment sealing failed"
    );
    let artifact = destination.join("horizon_pipeline");
    ensure!(
        hash_file(&artifact)? == artifact_sha256,
        "sealed reader image differs from build"
    );
    let seal_receipt_sha256 = hash_file(&destination.join("deployment-seal-receipt.json"))?;
    let mut probe = clean_command(&artifact);
    probe.arg("--archive-capacity-probe");
    let capacity_path = attempt.join(format!("capacity-{seq}.json"));
    ensure!(
        run_logged(
            probe,
            &capacity_path,
            120,
            1024 * 1024,
            &cfg.state_directory,
            cfg.reserve_bytes,
            cfg.build_reserve_bytes
        )?,
        "sealed reader capability probe failed"
    );
    let capacity: Value = read_json(&capacity_path)?;
    ensure!(
        capacity["schema"] == "jetstreamer-horizon-plugin-capacity-probe-v1",
        "reader capability probe unsupported"
    );
    ensure!(
        capacity["decoded_records"] == 71524 && capacity["account_data_bytes"] == 1144384,
        "reader failed the observed record/data capacity fixture"
    );
    for name in [
        "publication_authorized",
        "production_completion_authorized",
        "local_retirement_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            capacity[name] == false,
            "reader probe unexpectedly authorizes mutations"
        );
    }
    let reader = Reader {
        branch_commit: commit.clone(),
        source_fingerprint: fingerprint,
        cargo_lock_sha256: files["Cargo.lock"].clone(),
        source_files: files,
        rustc_version,
        cargo_version,
        cargo_sha256,
        rustc_sha256,
        features,
        artifact,
        artifact_sha256,
        seal_receipt_sha256,
        built_from_commit: commit,
        equivalence_reused: false,
        fetched_at: now(),
    };
    check_sealed_reader(&reader)?;
    write_json(&old, &reader, true)?;
    Ok(reader)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_build_temporary_files_stay_in_accounted_state() {
        let state = tempfile::tempdir().unwrap();
        let mut cfg: Config = serde_json::from_str(include_str!("../config.example.json")).unwrap();
        cfg.state_directory = state.path().to_owned();
        cfg.cargo = "/usr/bin/mktemp".into();
        let output = cargo(&cfg, state.path()).unwrap().arg("-d").output().unwrap();
        assert!(output.status.success());
        let created = PathBuf::from(String::from_utf8(output.stdout).unwrap().trim());
        assert_eq!(created.parent().unwrap(), state.path().join("build-tmp"));
        fs::write(created.join("native-build-output"), vec![1; 65536]).unwrap();
        assert!(working_bytes(state.path()).unwrap() >= 65536);
    }
    #[test]
    fn native_build_temporary_directory_cannot_escape_through_symlink() {
        let state = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), state.path().join("build-tmp")).unwrap();
        let mut cfg: Config = serde_json::from_str(include_str!("../config.example.json")).unwrap();
        cfg.state_directory = state.path().to_owned();
        assert!(cargo(&cfg, state.path()).is_err());
    }
    #[test]
    fn relevant_changes_invalidate_but_operator_notes_do_not() {
        let root = tempfile::tempdir().unwrap();
        let paths = [
            "Cargo.toml",
            "Cargo.lock",
            "src/bin/horizon_pipeline.rs",
            "jetstreamer-plugin/src/plugins/verification.rs",
            "scripts/note.md",
        ];
        for p in paths {
            let path = root.path().join(p);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, "old").unwrap();
        }
        let tracked = paths.join("\0");
        let dirs = BTreeSet::from([PathBuf::from("jetstreamer-plugin")]);
        let first = fingerprint_files(root.path(), &tracked, &dirs).unwrap();
        fs::write(root.path().join("scripts/note.md"), "changed").unwrap();
        assert_eq!(
            first,
            fingerprint_files(root.path(), &tracked, &dirs).unwrap()
        );
        fs::write(
            root.path()
                .join("jetstreamer-plugin/src/plugins/verification.rs"),
            "changed",
        )
        .unwrap();
        assert_ne!(
            first,
            fingerprint_files(root.path(), &tracked, &dirs).unwrap()
        );
        fs::write(root.path().join("Cargo.lock"), "new dependency").unwrap();
        assert_ne!(
            first,
            fingerprint_files(root.path(), &tracked, &dirs).unwrap()
        );
    }
}
