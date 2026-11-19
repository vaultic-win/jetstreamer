//! Seal the fixed incremental retirer and close only its completed build units.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
    process::Command,
};
const REPO: &str = "/home/sol/workspace/jetstreamer";
const ROOT: &str = "/var/lib/jetstreamer/holding141-incremental-deployment-20261119-v1";
const DEST: &str = "/usr/local/lib/jetstreamer/horizon-holding141-incremental-cleanup-20261119-v1";
const IMAGE: &str = "/home/sol/.jetstreamer-private/holding141-incremental-qualification-target-20261119-v1/debug/horizon-holding141-incremental-cleanup";
const IMAGE_SHA: &str = "1bbc43473711860e27015870f6eecbbd47af14a34407ea8fbd8b3afd9256aeb9";
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn run(c: &mut Command) -> Result<Vec<u8>> {
    let o = c.output()?;
    ensure!(
        o.status.success(),
        "{c:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    Ok(o.stdout)
}
fn git(a: &[&str]) -> Result<Vec<u8>> {
    run(Command::new("git")
        .args(["-c", &format!("safe.directory={REPO}"), "-C", REPO])
        .args(a))
}
fn bind(p: &Path) -> Result<Value> {
    Ok(json!({"path":p,"sha256":sha(&fs::read(p)?)}))
}
fn save(root: &Path, name: &str, b: &[u8]) -> Result<Value> {
    let p = root.join(name);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p)?;
    f.write_all(b)?;
    f.sync_all()?;
    File::open(root)?.sync_all()?;
    bind(&p)
}
fn private(p: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(p)?;
    File::open(p.parent().context("parent")?)?.sync_all()?;
    Ok(())
}
fn seal(root: &Path, name: &str, dest: &Path, members: Value) -> Result<()> {
    ensure!(sha(&fs::read(SEALER)?) == SEALER_SHA, "sealer changed");
    let p = save(
        root,
        name,
        &serde_json::to_vec_pretty(
            &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":dest,"members":members}),
        )?,
    )?;
    run(Command::new(SEALER).args([
        p["path"].as_str().unwrap(),
        "--plan-sha256",
        p["sha256"].as_str().unwrap(),
        "--self-sha256",
        SEALER_SHA,
    ]))?;
    Ok(())
}
fn native(unit: &str) -> Result<Vec<u8>> {
    run(Command::new("systemctl").args(["show",unit,"-pId,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,Job,Result,ExecMainStatus,ExecStart,ExecStop,ExecStopPost,FragmentPath,Triggers,TriggeredBy,UnitFileState"]))
}
fn field<'a>(s: &'a str, key: &str) -> Result<&'a str> {
    s.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")))
        .with_context(|| format!("missing {key}"))
}
fn idle_build(s: &str) -> Result<()> {
    for k in ["MainPID", "ControlPID"] {
        ensure!(field(s, k)? == "0", "live build process");
    }
    for k in ["Job", "Triggers", "TriggeredBy"] {
        ensure!(field(s, k)?.is_empty(), "queued or triggered build");
    }
    for k in ["ExecStop", "ExecStopPost"] {
        ensure!(
            s.lines()
                .find_map(|l| l.strip_prefix(&format!("{k}=")))
                .is_none_or(str::is_empty),
            "stop command must be absent"
        );
    }
    ensure!(
        matches!(
            (field(s, "ActiveState")?, field(s, "SubState")?),
            ("active", "exited") | ("failed", "failed") | ("inactive", "dead")
        ),
        "nonterminal build state"
    );
    ensure!(
        field(s, "ExecStart")?.contains("cargo")
            && field(s, "ExecStart")?.contains("jetstreamer-r2"),
        "not an old141 build"
    );
    Ok(())
}
fn deploy() -> Result<()> {
    let commit = String::from_utf8(git(&["rev-parse", "HEAD"])?)?;
    git(&[
        "merge-base",
        "--is-ancestor",
        commit.trim(),
        "origin/account-updates",
    ])?;
    let paths = String::from_utf8(git(&[
        "ls-files",
        "--",
        "scripts/horizon_holding141_incremental_cleanup_20261119_v1",
        "scripts/horizon_retry6_167_live166_stage_20261118_v1/src/bin/cache141.rs",
    ])?)?;
    let mut sources = serde_json::Map::new();
    for p in paths.lines() {
        let b = fs::read(Path::new(REPO).join(p))?;
        ensure!(
            git(&["show", &format!("HEAD:{p}")])? == b,
            "source not committed"
        );
        sources.insert(p.into(), json!(sha(&b)));
    }
    ensure!(
        sources.len() > 4 && sha(&fs::read(IMAGE)?) == IMAGE_SHA,
        "source closure or image differs"
    );
    private(Path::new(ROOT))?;
    let mut evidence = Vec::new();
    for (phase, summary) in [
        ("tests", "test result: ok. 12 passed; 0 failed; 0 ignored;"),
        ("clippy", ""),
        ("build", ""),
    ] {
        let u = format!("horizon-holding141-incremental-{phase}-20261119-v1.service");
        let n = native(&u)?;
        let s = std::str::from_utf8(&n)?;
        for (k, v) in [
            ("Result", "success"),
            ("ExecMainStatus", "0"),
            ("MainPID", "0"),
            ("ControlPID", "0"),
            ("SubState", "exited"),
        ] {
            ensure!(field(s, k)? == v, "qualification differs");
        }
        let log = run(Command::new("journalctl").args([
            "--no-pager",
            "-o",
            "cat",
            &format!("_SYSTEMD_INVOCATION_ID={}", field(s, "InvocationID")?),
        ]))?;
        ensure!(
            summary.is_empty() || std::str::from_utf8(&log)?.contains(summary),
            "tests incomplete"
        );
        evidence.push(json!({"unit":u,"native":save(Path::new(ROOT),&format!("{phase}.native"),&n)?,"journal":save(Path::new(ROOT),&format!("{phase}.log"),&log)?}));
    }
    let proof = save(
        Path::new(ROOT),
        "artifact-proof.json",
        &serde_json::to_vec_pretty(
            &json!({"source_commit":commit.trim(),"sources":sources,"executions":evidence,"production_sha256":IMAGE_SHA,"tests_passed":12,"clippy_all_targets_passed":true,"remote_mutations":false,"retirement_authorized":false}),
        )?,
    )?;
    let own = fs::read_link("/proc/self/exe")?;
    seal(
        Path::new(ROOT),
        "seal-plan.json",
        Path::new(DEST),
        json!([
 {"source":IMAGE,"name":"cleanup","sha256":IMAGE_SHA,"mode":365},
 {"source":own,"name":"operate","sha256":sha(&fs::read(&own)?),"mode":365},
 {"source":proof["path"],"name":"artifact-proof.json","sha256":proof["sha256"],"mode":292}]),
    )
}
fn close() -> Result<()> {
    let completion = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/retirements/epoch141-completion.json";
    ensure!(
        sha(&fs::read(completion)?)
            == "47856e43c56bc4a42edf1daaf896a4efe7cffa69b2ca650ebbc85f6d16372c89",
        "holding141 retirement differs"
    );
    let root = Path::new(ROOT).join("closed-build-units");
    private(&root)?;
    let units = [
        "retirement-parallel-opt3-build-20261118-v1",
        "retirement-parallel-opt3-tests-20261118-v1",
        "retirement-parallel-tests-20261118-v1",
        "retirement-parallel-benchmark-20261118-v1",
        "retirement-optimized-build-20261118-v1",
        "retirement-optimized-tests-20261118-v1",
        "retirement-optimized-stream-tests-20261118-v1",
        "retirement-parallel-opt3-benchmark-20261118-v1",
        "retirement-optimized-build-20261118-v2",
        "retirement-optimized-hash-tests-20261118-v1",
        "manifest-mode-build-20261118-v1",
        "manifest-mode-tests-20261118-v1",
        "retirement-build-20261118-v1",
        "retirement-tests-20261118-v1",
        "retirement-build-20261118-v2",
    ];
    for name in units {
        let u = format!("horizon-holding141-{name}.service");
        let before = native(&u)?;
        let s = std::str::from_utf8(&before)?;
        idle_build(s)?;
        let fragment = field(s, "FragmentPath")?;
        ensure!(
            fragment == format!("/run/systemd/transient/{u}"),
            "not exact transient fragment"
        );
        let bytes = fs::read(fragment)?;
        ensure!(
            std::str::from_utf8(&bytes)?.contains("/tmp/holding141-target"),
            "foreign cache target"
        );
        save(&root, &format!("{name}-native.txt"), &before)?;
        save(&root, &format!("{name}.service"), &bytes)?;
        save(
            &root,
            &format!("{name}.log"),
            &run(Command::new("journalctl").args(["--no-pager", "--all", "-o", "cat", "-u", &u]))?,
        )?;
        ensure!(
            native(&u)? == before && fs::read(fragment)? == bytes,
            "build changed before closure"
        );
        run(Command::new("systemctl").args(["stop", &u]))?;
        let after = native(&u)?;
        let s = std::str::from_utf8(&after)?;
        if field(s, "LoadState")? == "loaded" && field(s, "ActiveState")? == "failed" {
            run(Command::new("systemctl").args(["reset-failed", &u]))?;
        }
        let after = native(&u)?;
        save(&root, &format!("{name}-after.txt"), &after)?;
        ensure!(
            !Path::new(fragment).exists(),
            "transient fragment retained; preserve cache"
        );
    }
    save(
        &root,
        "completion.json",
        &serde_json::to_vec_pretty(
            &json!({"closed_units":15,"holding141_retirement":bind(Path::new(completion))?,"cache_removed":false,"r2_mutations":false}),
        )?,
    )?;
    Ok(())
}
fn check(retire: bool) -> Result<()> {
    let label = if retire { "retire-v1" } else { "check-v1" };
    let root = std::path::PathBuf::from(format!(
        "/var/lib/jetstreamer/holding141-incremental-{label}-20261119"
    ));
    private(&root)?;
    let commit = String::from_utf8(git(&["rev-parse", "HEAD"])?)?;
    let prior = if retire {
        bind(Path::new(
            "/var/lib/jetstreamer/holding141-incremental-check-v1-20261119/check.json",
        ))?
    } else {
        Value::Null
    };
    let plan = save(
        &root,
        "plan.json",
        &serde_json::to_vec_pretty(
            &json!({"schema":"horizon-holding141-incremental-cleanup-plan-v1","source_commit":commit.trim(),"cargo_lock_sha256":sha(&fs::read(Path::new(REPO).join("Cargo.lock"))?),"output":root.join("check.json"),"prior_check":prior}),
        )?,
    )?;
    let dest = std::path::PathBuf::from(format!("{DEST}-{label}-plan"));
    seal(
        &root,
        "plan-seal.json",
        &dest,
        json!([{"source":plan["path"],"name":"plan.json","sha256":plan["sha256"],"mode":292}]),
    )?;
    run(Command::new(format!("{DEST}/cleanup"))
        .arg(dest.join("plan.json"))
        .args([
            "--plan-sha256",
            plan["sha256"].as_str().unwrap(),
            "--self-sha256",
            IMAGE_SHA,
        ]))?;
    Ok(())
}
fn main() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "Root required");
    let a: Vec<_> = std::env::args().collect();
    ensure!(a.len() == 2, "deploy | close | check | retire");
    if a[1] == "deploy" {
        return deploy();
    }
    ensure!(
        fs::read_link("/proc/self/exe")? == Path::new(&format!("{DEST}/operate")),
        "sealed operator required"
    );
    match a[1].as_str() {
        "close" => close(),
        "check" => check(false),
        "retire" => check(true),
        _ => anyhow::bail!("unknown mode"),
    }
}
