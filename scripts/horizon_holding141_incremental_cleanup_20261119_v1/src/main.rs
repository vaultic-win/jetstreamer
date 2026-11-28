//! Partially retire single-link holding141 compiler-cache files after a separate check.
mod evidence;
mod incremental;
mod process_references;
mod staged;
use anyhow::{Context, Result, ensure};
use evidence::{bound_json, hash_file};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
    process::Command,
};
const REPO: &str = "/home/sol/workspace/jetstreamer";
const ROOT: &str = "/tmp/holding141-target";
const DEBUG: &str = "/tmp/holding141-target/debug";
const TARGET: &str = "/tmp/holding141-target/debug/incremental";
const LOCK: &str = "/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock";
const PROFILE: &str = "horizon-holding141-incremental-partial-cleanup-plan-v6";
const SCHEMA: &str = "horizon-holding141-incremental-partial-cleanup-check-v6";
// A full selection binds every selected/shared path and directory, not just a digest.
// Keep ordinary plans at 1 MiB; only these immutable check receipts get a larger bound.
const PARTIAL_CHECK_MAX_BYTES: u64 = 64 << 20;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    source_commit: String,
    cargo_lock_sha256: String,
    output: PathBuf,
    prior_check: Option<Bound>,
}
fn validate_plan(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == PROFILE && p.source_commit.len() == 40 && p.cargo_lock_sha256.len() == 64,
        "wrong fixed profile or reproduction binding"
    );
    let check =
        Path::new("/var/lib/jetstreamer/holding141-incremental-check-v6-20261119/check.json");
    let retire =
        Path::new("/var/lib/jetstreamer/holding141-incremental-retire-v6-20261119/check.json");
    ensure!(
        match &p.prior_check {
            None => p.output == check,
            Some(prior) => p.output == retire && prior.path == check,
        },
        "output/prior check is outside fixed v6 partial-cleanup evidence scope"
    );
    Ok(())
}
fn git(args: &[&str]) -> Result<Vec<u8>> {
    let o = Command::new("/usr/bin/git")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(["-c", &format!("safe.directory={REPO}"), "-C", REPO])
        .args(args)
        .output()?;
    ensure!(
        o.status.success() && o.stdout.len() <= 1 << 20,
        "git reproduction proof failed"
    );
    Ok(o.stdout)
}
fn private_group_output(group: &[u8], passwd: &[u8]) -> Result<()> {
    ensure!(
        group == b"sol:x:1001:\n",
        "cache group gained supplemental members"
    );
    let owners: Vec<_> = std::str::from_utf8(passwd)?
        .lines()
        .filter(|row| row.split(':').nth(3) == Some("1001"))
        .collect();
    ensure!(
        owners.len() == 1 && owners[0].starts_with("sol:x:1001:1001:"),
        "cache group gained primary members"
    );
    Ok(())
}
fn private_group() -> Result<Value> {
    let g = Command::new("/usr/bin/getent")
        .args(["group", "sol"])
        .output()?;
    let p = Command::new("/usr/bin/getent").arg("passwd").output()?;
    ensure!(
        g.status.success() && p.status.success() && p.stdout.len() <= 1 << 20,
        "group census failed"
    );
    private_group_output(&g.stdout, &p.stdout)?;
    Ok(
        json!({"uid":1001,"gid":1001,"sole_group_principal":"sol","group_sha256":format!("{:x}",Sha256::digest(&g.stdout)),"passwd_sha256":format!("{:x}",Sha256::digest(&p.stdout))}),
    )
}
fn relative_cache_reference(bytes: &[u8], _: &Path) -> bool {
    let exact = |path: &str| process_references::encoded_reference(bytes, path.as_bytes(), true);
    exact(DEBUG)
        || (exact(ROOT)
            && [
                b"CARGO_TARGET_DIR".as_slice(),
                b"cargo",
                b"rustc",
                b"sccache",
            ]
            .iter()
            .any(|needle| bytes.windows(needle.len()).any(|w| w == *needle)))
}
fn no_builders() -> Result<()> {
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        if !entry.file_name().as_bytes().iter().all(u8::is_ascii_digit) {
            continue;
        }
        let exe = match fs::read_link(entry.path().join("exe")) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        ensure!(
            !matches!(
                exe.file_name()
                    .and_then(|v| v.to_str())
                    .map(|v| v.trim_end_matches(" (deleted)")),
                Some("cargo" | "rustc" | "sccache")
            ),
            "builder remains: {}",
            entry.path().display()
        );
    }
    Ok(())
}
fn acquire(path: &Path, dev: u64, ino: u64, uid: u32, gid: u32, mode: u32) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.dev() == dev
            && m.ino() == ino
            && m.uid() == uid
            && m.gid() == gid
            && m.mode() & 0o7777 == mode
            && m.nlink() == 1,
        "lock custody changed"
    );
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "lock busy"
    );
    Ok(file)
}
fn persist(path: &Path, v: &Value) -> Result<()> {
    let parent = path.parent().context("output parent")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o7777 == 0o700,
        "unsafe private output"
    );
    let mut t = tempfile::NamedTempFile::new_in(parent)?;
    t.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    let mut bytes = serde_json::to_vec_pretty(v)?;
    bytes.push(b'\n');
    ensure!(
        bytes.len() as u64 <= PARTIAL_CHECK_MAX_BYTES,
        "partial cleanup receipt exceeded bound"
    );
    t.write_all(&bytes)?;
    t.as_file().sync_all()?;
    t.persist_noclobber(path)
        .map_err(|e| anyhow::anyhow!("output already occupied: {e}"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn consumers() -> Result<Value> {
    let roots = [
        "/etc/systemd/system",
        "/run/systemd/transient",
        "/run/systemd/system",
        "/run/systemd/generator",
        "/run/systemd/generator.early",
        "/run/systemd/generator.late",
        "/home/sol/.config/systemd/user",
        "/etc/cron.d",
    ];
    let mut missing = Vec::new();
    let units = staged::staged_references(
        &roots.iter().map(Path::new).collect::<Vec<_>>(),
        Path::new(TARGET),
        &mut missing,
    )?;
    let processes = process_references::scan(Path::new("/proc"), Path::new(DEBUG))?;
    Ok(json!({"staged":units,"processes":processes,"missing_aliases":missing}))
}
fn unused(c: &Value) -> bool {
    c["staged"] == json!([]) && c["processes"]["references"] == json!([])
}
fn lock_unchanged(file: &File, path: &Path) -> Result<()> {
    ensure!(
        evidence::identity(&file.metadata()?) == evidence::identity(&fs::symlink_metadata(path)?),
        "held mutation/Cargo lock path changed"
    );
    Ok(())
}
fn retained() -> Result<Value> {
    let path = Path::new(DEBUG).join("jetstreamer-r2");
    let before = fs::symlink_metadata(&path)?;
    ensure!(
        before.is_file() && before.uid() == 1001 && before.gid() == 1001 && before.nlink() == 2,
        "retained debug image changed"
    );
    let original = Path::new(
        "/usr/local/lib/jetstreamer/horizon-holding141-retirement-20261118-v1/jetstreamer-r2",
    );
    let deployed = hash_file(original, 256 << 20)?;
    ensure!(
        deployed.0 == "885e12ccea8a66892693d6542e1f2781b707b14b63ff50488128d7b420bccf8c"
            && deployed.1.uid() == 0
            && deployed.1.mode() & 0o222 == 0,
        "original sealed retirement image changed"
    );
    let deps = fs::symlink_metadata(Path::new(DEBUG).join("deps"))?;
    ensure!(
        deps.is_dir() && deps.uid() == 1001 && deps.gid() == 1001,
        "retained dependency root changed"
    );
    Ok(
        json!({"debug_image":[before.dev(),before.ino(),before.len(),before.mtime(),before.mtime_nsec(),before.ctime(),before.ctime_nsec(),before.nlink()],"deps":[deps.dev(),deps.ino(),deps.mtime(),deps.mtime_nsec()],"sealed_original_sha256":deployed.0,"retained_paths":[path,Path::new(DEBUG).join("deps")]}),
    )
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 6 && args[2] == "--plan-sha256" && args[4] == "--self-sha256",
        "usage: cleanup PLAN --plan-sha256 SHA --self-sha256 SHA"
    );
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let exe = fs::read_link("/proc/self/exe")?;
    ensure!(
        exe == Path::new(
            "/usr/local/lib/jetstreamer/horizon-holding141-incremental-cleanup-20261119-v6/cleanup"
        ),
        "sealed image path required"
    );
    let own = hash_file(&exe, 32 << 20)?;
    ensure!(
        own.0 == args[5] && own.1.uid() == 0 && own.1.mode() & 0o222 == 0,
        "sealed image differs"
    );
    let pb = Bound {
        path: args[1].clone().into(),
        sha256: args[3].clone(),
    };
    let plan: Plan = serde_json::from_value(bound_json(&pb)?)?;
    validate_plan(&plan)?;
    ensure!(
        git(&["rev-parse", "HEAD"])? == format!("{}\n", plan.source_commit).as_bytes(),
        "source revision differs"
    );
    ensure!(
        git(&[
            "status",
            "--porcelain",
            "--untracked-files=no",
            "--",
            "scripts/horizon_holding141_incremental_cleanup_20261119_v1",
            "jetstreamer-r2",
            "Cargo.toml",
            "Cargo.lock"
        ])?
        .is_empty(),
        "relevant source changed"
    );
    git(&[
        "merge-base",
        "--is-ancestor",
        &plan.source_commit,
        "origin/account-updates",
    ])?;
    ensure!(
        hash_file(&Path::new(REPO).join("Cargo.lock"), 16 << 20)?.0 == plan.cargo_lock_sha256,
        "reproduction lock differs"
    );
    let group = private_group()?;
    no_builders()?;
    let shared = acquire(Path::new(LOCK), 64512, 101135013, 1001, 1003, 0o600)?;
    let cargo = acquire(
        &Path::new(DEBUG).join(".cargo-lock"),
        2304,
        6695981,
        1001,
        1001,
        0o664,
    )?;
    let target = Path::new(TARGET);
    let m = fs::symlink_metadata(target)?;
    ensure!(
        target.canonicalize()? == target && m.dev() == 2304 && m.ino() == 6695985,
        "selected cache identity changed"
    );
    let mounts = incremental::incremental_mounts(target)?;
    let selection = incremental::select_single_link_files(target, 1001)?;
    let tree = serde_json::to_value(&selection)?;
    let preserved = retained()?;
    let refs = consumers()?;
    let result = json!({"schema":SCHEMA,"profile":PROFILE,"source_commit":plan.source_commit,"cargo_lock_sha256":plan.cargo_lock_sha256,"self_sha256":args[5],"plan":{"path":pb.path,"sha256":pb.sha256},"cache":tree,"group":group,"consumers":refs,"retained":preserved,"mount_census_sha256":mounts,"cache_unused_proven":unused(&refs),"archive_deletion_authorized":false,"DATA_credit_bytes":0,"r2_mutations":false});
    if !unused(&refs) {
        persist(&plan.output, &result)?;
        anyhow::bail!("live or staged consumer remains; negative check saved");
    }
    no_builders()?;
    lock_unchanged(&shared, Path::new(LOCK))?;
    lock_unchanged(&cargo, &Path::new(DEBUG).join(".cargo-lock"))?;
    ensure!(
        incremental::select_single_link_files(target, 1001)? == selection
            && incremental::incremental_mounts(target)? == mounts
            && retained()? == preserved
            && private_group()? == group
            && unused(&consumers()?),
        "cache or consumers changed during check"
    );
    if let Some(prior) = &plan.prior_check {
        let previous = evidence::bound_partial_check(prior)?;
        ensure!(
            previous["schema"] == SCHEMA
                && previous["profile"] == PROFILE
                && previous["cache_unused_proven"] == true
                && previous["cache"] == tree
                && previous["retained"] == preserved
                && previous["group"] == group
                && previous["mount_census_sha256"] == mounts
                && previous["self_sha256"] == args[5]
                && previous["source_commit"] == plan.source_commit
                && previous["cargo_lock_sha256"] == plan.cargo_lock_sha256,
            "prior positive proof differs"
        );
    }
    persist(&plan.output, &result)?;
    if let Some(prior) = plan.prior_check {
        let parent = plan.output.parent().unwrap();
        persist(
            &parent.join("intent.json"),
            &json!({"schema":"horizon-holding141-incremental-partial-cleanup-intent-v6","partial_cleanup":true,"cache":tree,"prior_check":{"path":prior.path,"sha256":prior.sha256},"current_check":{"path":plan.output,"sha256":hash_file(&plan.output,PARTIAL_CHECK_MAX_BYTES)?.0},"retained":preserved}),
        )?;
        no_builders()?;
        lock_unchanged(&shared, Path::new(LOCK))?;
        lock_unchanged(&cargo, &Path::new(DEBUG).join(".cargo-lock"))?;
        ensure!(
            unused(&consumers()?)
                && incremental::select_single_link_files(target, 1001)? == selection
                && incremental::incremental_mounts(target)? == mounts
                && private_group()? == group
                && retained()? == preserved,
            "pre-removal custody changed"
        );
        let after = incremental::retire_single_link_files(target, 1001, &selection)?;
        ensure!(
            retained()? == preserved
                && incremental::incremental_mounts(target)? == mounts
                && private_group()? == group,
            "retained artifacts or custody changed"
        );
        lock_unchanged(&shared, Path::new(LOCK))?;
        lock_unchanged(&cargo, &Path::new(DEBUG).join(".cargo-lock"))?;
        persist(
            &parent.join("completion.json"),
            &json!({"schema":"horizon-holding141-incremental-partial-cleanup-completion-v6","partial_cleanup":true,"cache":tree,"selected_files_absent":true,"removed_files":selection.selected_files.len(),"preserved_shared_files":after.preserved_shared_files,"all_directories_preserved":true,"selected_allocated_bytes":selection.selected_allocated_bytes,"post_operation_allocated_bytes":after.cache["physical_bytes"],"post_operation_cache":after.cache,"retained":preserved,"DATA_credit_bytes":0,"actual_free_delta_claimed":false,"r2_mutations":false}),
        )?;
    }
    println!("{}", plan.output.display());
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests;
