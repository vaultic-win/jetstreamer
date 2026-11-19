//! Exact holding141 dependency-cache retirement. Preserves external hardlinks,
//! dependency manifests, all directories, top-level executable and R2 objects.
mod cache;
mod evidence;
mod mounts;
mod process_references;
mod source;
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
const PACKAGE: &str = "scripts/horizon_holding141_build_cleanup_20261119_v1";
const IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-holding141-build-cleanup-20261119-v1/cleanup";
const PROFILE: &str = "horizon-holding141-build-partial-cleanup-plan-v1";
const SCHEMA: &str = "horizon-holding141-build-partial-cleanup-check-v1";
const REVIEW_SCHEMA: &str = "horizon-holding141-build-consumer-closure-v1";
const PARTIAL_CHECK_MAX_BYTES: u64 = 64 << 20;
const TARGET: &str = "/tmp/holding141-target/debug/build";
const CHECK: &str = "/var/lib/jetstreamer/holding141-build-check-20261119-v1/check.json";
const EXECUTE: &str = "/var/lib/jetstreamer/holding141-build-retire-20261119-v1/check.json";
const LOCK: &str = "/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock";
const TARGETS: [(&str, u64, u32, bool); 1] = [(TARGET, 6695986, 0o775, true)];
const LOCKS: [(&str, u64, u64, u32, u32); 2] = [
    (LOCK, 64512, 101135013, 1003, 0o600),
    (
        "/tmp/holding141-target/debug/.cargo-lock",
        2304,
        6695981,
        1001,
        0o664,
    ),
];
#[derive(Clone, Deserialize, serde::Serialize)]
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
    indirect_review: Bound,
    output: PathBuf,
    prior_check: Option<Bound>,
}
fn hex(value: &str, n: usize) -> bool {
    value.len() == n
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn validate_plan(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == PROFILE && hex(&p.source_commit, 40) && hex(&p.cargo_lock_sha256, 64),
        "wrong closed profile/source binding"
    );
    ensure!(
        match &p.prior_check {
            None => p.output == Path::new(CHECK),
            Some(b) =>
                p.output == Path::new(EXECUTE) && b.path == Path::new(CHECK) && hex(&b.sha256, 64),
        },
        "wrong fixed check/execute evidence path"
    );
    ensure!(
        p.indirect_review.path.is_absolute() && hex(&p.indirect_review.sha256, 64),
        "invalid indirect review binding"
    );
    Ok(())
}
fn relative_cache_reference(bytes: &[u8], target: &Path) -> bool {
    let exact =
        |p: &Path| process_references::encoded_reference(bytes, p.as_os_str().as_bytes(), true);
    exact(target)
        || (target.parent().is_some_and(exact)
            && [
                b"CARGO_TARGET_DIR".as_slice(),
                b"cargo",
                b"rustc",
                b"sccache",
            ]
            .iter()
            .any(|n| bytes.windows(n.len()).any(|w| w == *n)))
}
fn private_group() -> Result<Value> {
    let group = Command::new("/usr/bin/getent")
        .args(["group", "sol"])
        .output()?;
    let passwd = Command::new("/usr/bin/getent").arg("passwd").output()?;
    ensure!(
        group.status.success()
            && passwd.status.success()
            && group.stdout == b"sol:x:1001:\n"
            && passwd.stdout.len() < 1 << 20,
        "private cache group differs"
    );
    let owners: Vec<_> = std::str::from_utf8(&passwd.stdout)?
        .lines()
        .filter(|s| s.split(':').nth(3) == Some("1001"))
        .collect();
    ensure!(
        owners.len() == 1 && owners[0].starts_with("sol:x:1001:1001:"),
        "cache group has foreign principal"
    );
    Ok(json!({"group":sha(&group.stdout),"passwd":sha(&passwd.stdout)}))
}
fn no_builders() -> Result<()> {
    for e in fs::read_dir("/proc")? {
        let e = e?;
        if !e.file_name().as_bytes().iter().all(u8::is_ascii_digit) {
            continue;
        }
        let exe = match fs::read_link(e.path().join("exe")) {
            Ok(x) => x,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        ensure!(
            !matches!(
                exe.file_name()
                    .and_then(|s| s.to_str())
                    .map(|s| s.trim_end_matches(" (deleted)")),
                Some("cargo" | "rustc" | "sccache")
            ),
            "builder remains: {}",
            e.path().display()
        );
    }
    Ok(())
}
fn acquire_locks() -> Result<Vec<File>> {
    let mut out = vec![];
    for (path, dev, ino, gid, mode) in LOCKS {
        let p = Path::new(path);
        ensure!(p.canonicalize()? == p, "lock ancestor alias");
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(p)?;
        let m = f.metadata()?;
        ensure!(
            m.is_file()
                && m.dev() == dev
                && m.ino() == ino
                && m.uid() == 1001
                && m.gid() == gid
                && m.mode() & 0o7777 == mode
                && m.nlink() == 1,
            "existing lock custody differs"
        );
        ensure!(
            unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "existing lock busy"
        );
        out.push(f);
    }
    Ok(out)
}
fn locks_unchanged(locks: &[File]) -> Result<()> {
    ensure!(locks.len() == LOCKS.len(), "incomplete lock ownership");
    for (f, (path, _, _, _, _)) in locks.iter().zip(LOCKS) {
        ensure!(
            evidence::identity(&f.metadata()?) == evidence::identity(&fs::symlink_metadata(path)?),
            "held lock path changed"
        );
    }
    Ok(())
}
fn selection() -> Result<Vec<cache::Selection>> {
    TARGETS
        .iter()
        .map(|(path, ino, mode, build)| {
            let md = fs::symlink_metadata(path)?;
            ensure!(
                md.is_dir()
                    && md.dev() == 2304
                    && md.ino() == *ino
                    && md.uid() == 1001
                    && md.gid() == 1001
                    && md.mode() & 0o7777 == *mode,
                "fixed target identity differs"
            );
            cache::select(Path::new(path), 1001, *build)
        })
        .collect()
}
fn persist(path: &Path, value: &Value) -> Result<()> {
    let parent = path.parent().context("receipt parent")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o7777 == 0o700,
        "unsafe receipt directory"
    );
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    ensure!(
        bytes.len() as u64 <= PARTIAL_CHECK_MAX_BYTES,
        "receipt exceeds readback bound"
    );
    let mut t = tempfile::NamedTempFile::new_in(parent)?;
    t.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    t.write_all(&bytes)?;
    t.as_file().sync_all()?;
    t.persist_noclobber(path)
        .map_err(|e| anyhow::anyhow!("receipt occupied: {e}"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
const CLASSES: [&str; 7] = [
    "producer-controller",
    "libraries-and-relative-inputs",
    "sealed-launch-plans",
    "timer-path-cron",
    "future-builds",
    "recovery",
    "live-accounting-and-witness-roots",
];
fn validate_review(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == REVIEW_SCHEMA
            && v["owner"] == "/root"
            && v["targets"] == json!(TARGETS.iter().map(|x| x.0).collect::<Vec<_>>())
            && v["no_current_or_staged_consumer"] == true
            && v["no_reopen_until_completion_reconciled"] == true
            && v["indirect_dependencies"].is_array()
            && v["retired_units"].is_array()
            && v["terminal_owners_inspected"] == true,
        "exact controller closure required"
    );
    let rows = v["classes"].as_array().context("indirect classes")?;
    let got: BTreeSet<_> = rows
        .iter()
        .map(|r| r["class"].as_str().context("reader class"))
        .collect::<Result<_>>()?;
    ensure!(
        rows.len() == CLASSES.len() && got == CLASSES.into_iter().collect(),
        "incomplete indirect closure classes"
    );
    for row in rows {
        ensure!(
            row["no_local_outputs_required"] == true
                && row["reason"].as_str().is_some_and(|s| !s.is_empty())
                && row["inspected_inputs"]
                    .as_array()
                    .is_some_and(|a| !a.is_empty()),
            "indirect closure lacks input evidence"
        );
    }
    let mut units = BTreeSet::new();
    for unit in v["retired_units"].as_array().unwrap() {
        let unit = unit.as_str().context("retired unit name")?;
        ensure!(
            !unit.starts_with('-')
                && unit.len() <= 255
                && [".service", ".timer", ".path"]
                    .iter()
                    .any(|s| unit.ends_with(s))
                && unit
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.@\\".contains(&b))
                && units.insert(unit),
            "invalid or duplicate retired owner"
        );
    }
    ensure!(units.len() <= 1024, "retired owner bound");
    Ok(())
}
fn consumer_inputs(p: &Plan) -> Result<(Value, Vec<PathBuf>, Vec<PathBuf>)> {
    let review = bound_json(&p.indirect_review)?;
    validate_review(&review)?;
    let mut inputs = BTreeSet::new();
    let mut count = 0;
    for row in review["classes"].as_array().unwrap() {
        for item in row["inspected_inputs"].as_array().unwrap() {
            count += 1;
            ensure!(count <= 4096, "indirect input bound");
            let b: Bound = serde_json::from_value(item.clone())?;
            ensure!(
                b.path.is_absolute()
                    && b.path.canonicalize()? == b.path
                    && hex(&b.sha256, 64)
                    && !TARGETS.iter().any(|(r, _, _, _)| b.path.starts_with(r)),
                "unsafe indirect input"
            );
            let (digest, md) = hash_file(&b.path, 16 << 20)?;
            ensure!(
                digest == b.sha256 && md.uid() == 0 && md.mode() & 0o222 == 0,
                "indirect immutable input changed"
            );
            inputs.insert(b.path);
        }
    }
    // Inspected plans are retained review evidence. Only actual cache-dependent
    // inputs propagate a live/staged reference to the selected compiler cache.
    // Require an explicit (possibly empty) dependency census, never infer it
    // from the set of files the operator read to establish independence.
    let mut dependencies = BTreeSet::new();
    for item in review["indirect_dependencies"].as_array().unwrap() {
        count += 1;
        ensure!(count <= 4096, "indirect input bound");
        let b: Bound = serde_json::from_value(item.clone())?;
        ensure!(
            b.path.is_absolute() && b.path.canonicalize()? == b.path && hex(&b.sha256, 64),
            "unsafe indirect dependency"
        );
        let (digest, md) = hash_file(&b.path, 16 << 20)?;
        ensure!(
            digest == b.sha256 && md.uid() == 0 && md.mode() & 0o222 == 0,
            "indirect dependency changed"
        );
        dependencies.insert(b.path);
    }
    Ok((
        review,
        inputs.into_iter().collect(),
        dependencies.into_iter().collect(),
    ))
}
fn consumers(p: &Plan) -> Result<Value> {
    let (review, inputs, dependencies) = consumer_inputs(p)?;
    let roots = [
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        "/run/systemd/system",
        "/run/systemd/transient",
        "/run/systemd/generator",
        "/run/systemd/generator.early",
        "/run/systemd/generator.late",
        "/etc/systemd/user",
        "/usr/lib/systemd/user",
        "/home/sol/.config/systemd/user",
        "/root/.config/systemd/user",
        "/etc/crontab",
        "/etc/anacrontab",
        "/etc/cron.d",
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron",
    ];
    let roots: Vec<_> = roots.iter().map(Path::new).collect();
    let mut refs = vec![];
    let mut missing = vec![];
    let mut processes = vec![];
    for (target, _, _, _) in TARGETS {
        let target = Path::new(target);
        let process = process_references::scan(
            Path::new("/proc"),
            target,
            target.parent().context("cache profile parent")?,
            &dependencies,
        )?;
        refs.extend(process.references.iter().cloned());
        processes.push(process);
        refs.extend(staged::staged_references(&roots, target, &mut missing)?);
    }
    for input in &dependencies {
        refs.extend(staged::staged_references(&roots, input, &mut missing)?);
    }
    // PID1 can retain a failed transient command after its fragment disappears.
    // Do not suppress that actor: require it to be fully unloaded and unarmed.
    let mut terminal_owners = BTreeMap::new();
    for unit in review["retired_units"].as_array().unwrap() {
        let unit = unit.as_str().context("retired owner")?;
        let native = evidence::properties(
            unit,
            "Id,LoadState,ActiveState,SubState,MainPID,ControlPID,Job,Triggers,TriggeredBy,ExecStart,ExecStartPre,ExecStartPost,ExecCondition,ExecReload,ExecStop,ExecStopPost",
        )?;
        ensure!(
            native.get("Id").map(String::as_str) == Some(unit)
                && native.get("LoadState").map(String::as_str) == Some("not-found")
                && native.get("ActiveState").map(String::as_str) == Some("inactive")
                && native.get("SubState").map(String::as_str) == Some("dead"),
            "historical cache owner remains staged: {unit}"
        );
        for key in [
            "MainPID",
            "ControlPID",
            "Job",
            "Triggers",
            "TriggeredBy",
            "ExecStart",
            "ExecStartPre",
            "ExecStartPost",
            "ExecCondition",
            "ExecReload",
            "ExecStop",
            "ExecStopPost",
        ] {
            ensure!(
                native.get(key).is_none_or(
                    |v| v.is_empty() || ((key == "MainPID" || key == "ControlPID") && v == "0")
                ),
                "old owner retains command/pid/job: {unit} {key}"
            );
        }
        terminal_owners.insert(unit, native);
    }
    ensure!(
        bound_json(&p.indirect_review)? == review,
        "review changed during consumer census"
    );
    Ok(
        json!({"references":refs,"processes":processes,"missing_aliases":missing,"indirect_review":p.indirect_review,"inspected_inputs":inputs,"indirect_dependencies":dependencies,"terminal_owners":terminal_owners}),
    )
}
fn unused(v: &Value) -> bool {
    v["references"] == json!([])
}
fn prior_matches(previous: &Value, current: &Value) -> Result<()> {
    for key in [
        "schema",
        "profile",
        "source_commit",
        "cargo_lock_sha256",
        "self_sha256",
        "selection",
        "source_proof",
        "group",
        "mount_census_sha256",
        "indirect_review",
    ] {
        ensure!(
            previous[key] == current[key],
            "prior positive proof differs: {key}"
        );
    }
    ensure!(
        previous["cache_unused_proven"] == true && current["cache_unused_proven"] == true,
        "positive unused proofs required"
    );
    Ok(())
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 6 && args[2] == "--plan-sha256" && args[4] == "--self-sha256",
        "usage: cleanup PLAN --plan-sha256 SHA --self-sha256 SHA"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0 && fs::read_link("/proc/self/exe")? == Path::new(IMAGE),
        "root sealed image required"
    );
    let own = hash_file(Path::new(IMAGE), 32 << 20)?;
    ensure!(
        own.0 == args[5] && own.1.uid() == 0 && own.1.mode() & 0o222 == 0,
        "sealed image differs"
    );
    let b = Bound {
        path: args[1].clone().into(),
        sha256: args[3].clone(),
    };
    let p: Plan = serde_json::from_value(bound_json(&b)?)?;
    validate_plan(&p)?;
    let source = source::proof(&p)?;
    let group = private_group()?;
    no_builders()?;
    let locks = acquire_locks()?;
    let mount = mounts::census()?;
    let before = selection()?;
    let refs = consumers(&p)?;
    let check = json!({"schema":SCHEMA,"profile":PROFILE,"source_commit":p.source_commit,"cargo_lock_sha256":p.cargo_lock_sha256,"source_proof":source,"self_sha256":args[5],"selection":before,"group":group,"mount_census_sha256":mount,"consumers":refs,"cache_unused_proven":unused(&refs),"indirect_review":p.indirect_review,"partial_cleanup":true,"r2_mutations":false,"resource_credit_bytes":0});
    if !unused(&refs) {
        persist(&p.output, &check)?;
        anyhow::bail!("live/staged/indirect consumer remains; negative check saved");
    }
    no_builders()?;
    locks_unchanged(&locks)?;
    ensure!(
        selection()? == before
            && mounts::census()? == mount
            && source::proof(&p)? == source
            && private_group()? == group
            && unused(&consumers(&p)?),
        "check drift"
    );
    if let Some(prior) = &p.prior_check {
        prior_matches(&evidence::bound_partial_check(prior)?, &check)?;
    }
    persist(&p.output, &check)?;
    if let Some(prior) = &p.prior_check {
        let out = p.output.parent().context("execute output")?;
        persist(
            &out.join("intent.json"),
            &json!({"schema":"horizon-holding141-build-partial-cleanup-intent-v1","check":{"path":p.output,"sha256":hash_file(&p.output,PARTIAL_CHECK_MAX_BYTES)?.0},"prior_check":prior,"selection":before,"resource_credit_bytes":0}),
        )?;
        no_builders()?;
        locks_unchanged(&locks)?;
        ensure!(
            selection()? == before
                && mounts::census()? == mount
                && source::proof(&p)? == source
                && private_group()? == group
                && unused(&consumers(&p)?),
            "full pre-unlink check drift"
        );
        let mut after = vec![];
        for (tree, (_, _, _, build)) in before.iter().zip(TARGETS) {
            after.push(cache::retire(tree, 1001, build)?);
        }
        locks_unchanged(&locks)?;
        ensure!(
            source::proof(&p)? == source && private_group()? == group && mounts::census()? == mount,
            "post-unlink source/lock/custody drift"
        );
        for (tree, (_, _, _, build)) in before.iter().zip(TARGETS) {
            cache::verify_after(tree, 1001, build)?;
        }
        persist(
            &out.join("completion.json"),
            &json!({"schema":"horizon-holding141-build-partial-cleanup-completion-v1","partial_cleanup":true,"all_directories_preserved":true,"all_locks_preserved":true,"selected_paths_absent":true,"before":before,"after":after,"actual_free_delta_claimed":false,"resource_credit_bytes":0,"r2_mutations":false}),
        )?;
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e:#}");
        std::process::exit(1)
    }
}
#[cfg(test)]
mod tests;
