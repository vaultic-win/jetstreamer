//! Seal the fixed incremental retirer and preserve its earlier build-unit closure.
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
const ROOT: &str = "/var/lib/jetstreamer/holding141-incremental-deployment-20261119-v6";
const DEST: &str = "/usr/local/lib/jetstreamer/horizon-holding141-incremental-cleanup-20261119-v6";
const IMAGE: &str = "/home/sol/.jetstreamer-private/holding141-incremental-qualification-target-20261119-v1/debug/horizon-holding141-incremental-cleanup";
const CLOSED: &str = "/var/lib/jetstreamer/holding141-incremental-deployment-20261119-v1/closed-build-units/completion.json";
const CLOSED_SHA: &str = "e60d30c769ca38322a28fcb565c045c910f59d9be8a54310bc202e36bb552ac4";
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
fn closed() -> Result<Value> {
    let bytes = fs::read(CLOSED)?;
    ensure!(
        sha(&bytes) == CLOSED_SHA,
        "prior build-unit closure changed"
    );
    let proof: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        proof["closed_units"] == 15
            && proof["cache_removed"] == false
            && proof["r2_mutations"] == false,
        "prior closure scope differs"
    );
    bind(Path::new(CLOSED))
}
fn valid_sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn installed_image_sha() -> Result<String> {
    let proof_bytes = fs::read(format!("{DEST}/artifact-proof.json"))?;
    let proof: Value = serde_json::from_slice(&proof_bytes)?;
    let seal: Value =
        serde_json::from_slice(&fs::read(format!("{DEST}/deployment-seal-receipt.json"))?)?;
    let hash = proof["production_sha256"]
        .as_str()
        .context("production hash")?;
    ensure!(
        valid_sha(hash)
            && seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == DEST
            && seal["members"].as_array().is_some_and(|rows| rows
                .iter()
                .any(|r| r["name"] == "cleanup" && r["sha256"] == hash && r["mode"] == "0555")
                && rows.iter().any(|r| r["name"] == "artifact-proof.json"
                    && r["sha256"] == sha(&proof_bytes)
                    && r["mode"] == "0444")),
        "installed image seal differs"
    );
    ensure!(
        sha(&fs::read(format!("{DEST}/cleanup"))?) == hash,
        "installed image differs"
    );
    Ok(hash.to_owned())
}
fn deploy(image_sha: &str) -> Result<()> {
    ensure!(
        valid_sha(image_sha),
        "explicit production image SHA required"
    );
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
        sources.len() > 4 && sha(&fs::read(IMAGE)?) == image_sha,
        "source closure or image differs"
    );
    private(Path::new(ROOT))?;
    let mut evidence = Vec::new();
    for (phase, summary) in [
        ("tests", "test result: ok. 24 passed; 0 failed; 0 ignored;"),
        ("clippy", ""),
        ("build", ""),
    ] {
        let version = "v6";
        let u = format!("horizon-holding141-incremental-{phase}-20261119-{version}.service");
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
            &json!({"source_commit":commit.trim(),"sources":sources,"executions":evidence,"production_sha256":image_sha,"tests_passed":24,"clippy_all_targets_passed":true,"prior_closed_build_units":closed()?,"remote_mutations":false,"retirement_authorized":false}),
        )?,
    )?;
    let own = fs::read_link("/proc/self/exe")?;
    seal(
        Path::new(ROOT),
        "seal-plan.json",
        Path::new(DEST),
        json!([
 {"source":IMAGE,"name":"cleanup","sha256":image_sha,"mode":365},
 {"source":own,"name":"operate","sha256":sha(&fs::read(&own)?),"mode":365},
 {"source":proof["path"],"name":"artifact-proof.json","sha256":proof["sha256"],"mode":292}]),
    )
}
fn check(retire: bool) -> Result<()> {
    let _ = closed()?;
    let image_sha = installed_image_sha()?;
    let label = if retire { "retire-v6" } else { "check-v6" };
    let root = std::path::PathBuf::from(format!(
        "/var/lib/jetstreamer/holding141-incremental-{label}-20261119"
    ));
    private(&root)?;
    let commit = String::from_utf8(git(&["rev-parse", "HEAD"])?)?;
    let prior = if retire {
        bind(Path::new(
            "/var/lib/jetstreamer/holding141-incremental-check-v6-20261119/check.json",
        ))?
    } else {
        Value::Null
    };
    let plan = save(
        &root,
        "plan.json",
        &serde_json::to_vec_pretty(
            &json!({"schema":"horizon-holding141-incremental-partial-cleanup-plan-v6","source_commit":commit.trim(),"cargo_lock_sha256":sha(&fs::read(Path::new(REPO).join("Cargo.lock"))?),"output":root.join("check.json"),"prior_check":prior}),
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
            &image_sha,
        ]))?;
    Ok(())
}
fn main() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "Root required");
    let a: Vec<_> = std::env::args().collect();
    ensure!(a.len() >= 2, "deploy IMAGE_SHA | check | retire");
    if a[1] == "deploy" {
        ensure!(a.len() == 3, "deploy requires exact production SHA");
        return deploy(&a[2]);
    }
    ensure!(a.len() == 2, "check/retire take no extra arguments");
    ensure!(
        fs::read_link("/proc/self/exe")? == Path::new(&format!("{DEST}/operate")),
        "sealed operator required"
    );
    match a[1].as_str() {
        "check" => check(false),
        "retire" => check(true),
        _ => anyhow::bail!("unknown mode"),
    }
}
