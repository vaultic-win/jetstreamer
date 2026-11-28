//! Seal exact published epoch167 retry7 preparer source and qualified artifacts.
//! No witness, resource admission, service mutation, replay launch or R2 operation.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
    process::Command,
};
const REPO: &str = "/home/sol/workspace/jetstreamer";
const PACKAGE: &str = "scripts/horizon_retry7_167_20261119_v1/prepare";
const OWN: &str =
    "scripts/horizon_retry6_167_live166_stage_20261118_v1/src/bin/deploy_prepare167retry7.rs";
const ROOT: &str =
    "/var/lib/jetstreamer/epoch167-retry7-live166retry8-prepare-deployment-20261119-v1";
const SOURCE: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch167-retry7-live166retry8-prepare-source-20261119-v1";
const DEST: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch167-retry7-live166retry8-prepare-20261119-v1";
const TARGET: &str = "scripts/horizon_retry8_166_20261119_v1/guard/target";
const TEST: &str = "prepare-bd5a1c2bb7e5518f";
const GUARD: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch167-retry7-live166retry8-guard-20261119-v1";
const GUARD_COMMIT: &str = "50f0a21c385ca38462b77bac770d6ed8cce594a2";
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
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("missing {k}"))
}
fn regular(p: &str) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(p)?;
    ensure!(
        m.is_file() && !m.file_type().is_symlink(),
        "regular file required: {p}"
    );
    Ok(fs::read(p)?)
}
fn bind(p: &str) -> Result<Value> {
    Ok(json!({"path":p,"sha256":sha(&regular(p)?)}))
}
fn save(n: &str, b: &[u8]) -> Result<Value> {
    ensure!(!n.contains('/'), "leaf required");
    let p = format!("{ROOT}/{n}");
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p)?;
    f.write_all(b)?;
    f.sync_all()?;
    File::open(ROOT)?.sync_all()?;
    bind(&p)
}
fn field<'a>(s: &'a str, k: &str) -> Result<&'a str> {
    s.lines()
        .find_map(|l| l.strip_prefix(&format!("{k}=")))
        .with_context(|| format!("native field {k}"))
}
fn member(p: &str, n: &str, mode: u32) -> Result<Value> {
    Ok(json!({"source":p,"name":n,"sha256":sha(&regular(p)?),"mode":mode}))
}
fn seal(name: &str, dest: &str, members: Value) -> Result<Value> {
    let plan = save(
        name,
        &serde_json::to_vec_pretty(
            &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":dest,"members":members}),
        )?,
    )?;
    run(Command::new(SEALER).args([
        text(&plan, "path")?,
        "--plan-sha256",
        text(&plan, "sha256")?,
        "--self-sha256",
        SEALER_SHA,
    ]))?;
    let receipt = bind(&format!("{dest}/deployment-seal-receipt.json"))?;
    let value: Value = serde_json::from_slice(&regular(text(&receipt, "path")?)?)?;
    ensure!(
        value["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && value["destination"] == dest
            && value["sealer_sha256"] == SEALER_SHA
            && value["replay_launch_authorized"] == false
            && value["remote_mutations"] == false,
        "normal seal differs"
    );
    Ok(receipt)
}
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    ensure!(
        unsafe { libc::geteuid() } == 0 && a.len() == 4 && a[2] == "--plan-sha256",
        "usage: deploy_prepare167retry7 PLAN --plan-sha256 SHA (root)"
    );
    let m = fs::symlink_metadata(&a[1])?;
    ensure!(m.uid() == 0 && m.mode() & 0o022 == 0, "root plan custody");
    let raw = regular(&a[1])?;
    ensure!(sha(&raw) == a[3], "plan digest");
    let plan: Value = serde_json::from_slice(&raw)?;
    ensure!(
        plan["schema"] == "horizon-retry7-167-preparer-deployment-input-v1",
        "input schema"
    );
    let commit = text(&plan, "source_commit")?;
    ensure!(
        commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit()),
        "source commit"
    );
    git(&[
        "merge-base",
        "--is-ancestor",
        commit,
        "origin/account-updates",
    ])?;
    git(&[
        "merge-base",
        "--is-ancestor",
        GUARD_COMMIT,
        "origin/account-updates",
    ])?;
    ensure!(
        git(&[
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            PACKAGE,
            OWN
        ])?
        .is_empty(),
        "unpublished source"
    );
    let files = String::from_utf8(git(&["ls-files", "--", PACKAGE, OWN])?)?;
    let mut source_rows = serde_json::Map::new();
    let mut members = Vec::new();
    for p in files.lines() {
        let path = format!("{REPO}/{p}");
        let bytes = regular(&path)?;
        ensure!(
            git(&["show", &format!("{commit}:{p}")])? == bytes,
            "source differs from published commit: {p}"
        );
        source_rows.insert(p.into(), json!(sha(&bytes)));
        if p != OWN {
            let n = p
                .strip_prefix(&format!("{PACKAGE}/"))
                .context("package prefix")?;
            ensure!(!n.contains('/'), "unexpected nested source");
            members.push(member(&path, n, 0o444)?);
        }
    }
    ensure!(
        members.len() >= 40 && source_rows.contains_key(OWN),
        "incomplete published source closure"
    );
    for n in [
        "main.rs",
        "retry167.rs",
        "dep_8319089e637c_local.rs",
        "Cargo.toml",
        "Cargo.lock",
    ] {
        ensure!(
            source_rows.contains_key(&format!("{PACKAGE}/{n}")),
            "missing source member {n}"
        );
    }
    let production = format!("{REPO}/{TARGET}/release/prepare");
    let test = format!("{REPO}/{TARGET}/release/deps/{TEST}");
    ensure!(
        sha(&regular(&production)?) == text(&plan, "production_sha256")?
            && sha(&regular(&test)?) == text(&plan, "test_sha256")?,
        "genuine image hash differs"
    );
    let guard_proof: Value =
        serde_json::from_slice(&regular(&format!("{GUARD}/artifact-proof.json"))?)?;
    ensure!(
        guard_proof["source_commit"] == GUARD_COMMIT
            && guard_proof["source_commit_verified_on_origin_account_updates"] == true
            && guard_proof["production"]["sha256"] == sha(&regular(&format!("{GUARD}/guard"))?),
        "qualified guard differs"
    );
    let expected_env = [
        (
            "HORIZON_RETRY7_167_GUARD_SHA256",
            sha(&regular(&format!("{GUARD}/guard"))?),
        ),
        (
            "HORIZON_RETRY7_167_GUARD_SEAL_SHA256",
            sha(&regular(&format!("{GUARD}/deployment-seal-receipt.json"))?),
        ),
        (
            "HORIZON_RETRY7_167_GUARD_PROOF_SHA256",
            sha(&regular(&format!("{GUARD}/artifact-proof.json"))?),
        ),
        ("HORIZON_RETRY7_167_SOURCE_COMMIT", GUARD_COMMIT.to_owned()),
    ];
    ensure!(sha(&regular(SEALER)?) == SEALER_SHA, "sealer differs");
    // Observe and validate all qualification before creating deployment state.
    let mut captured = Vec::new();
    for (phase, unit) in [
        (
            "build",
            "horizon-retry7-167-prepare-build-20261119-v1.service",
        ),
        (
            "test-build",
            "horizon-retry7-167-prepare-test-build-20261119-v2.service",
        ),
        (
            "test-root",
            "horizon-retry7-167-prepare-test-root-20261119-v2.service",
        ),
    ] {
        let native=run(Command::new("systemctl").args(["show",unit,"-pId,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,Result,ExecMainStatus,ExecStart,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,Environment"]))?;
        let s = std::str::from_utf8(&native)?;
        for (k, v) in [
            ("Id", unit),
            ("LoadState", "loaded"),
            ("ActiveState", "active"),
            ("SubState", "exited"),
            ("MainPID", "0"),
            ("ControlPID", "0"),
            ("Result", "success"),
            ("ExecMainStatus", "0"),
            ("MemoryMax", "2147483648"),
            ("MemorySwapMax", "0"),
            ("CPUQuotaPerSecUSec", "2s"),
        ] {
            ensure!(field(s, k)? == v, "native {phase} {k} differs");
        }
        let iid = field(s, "InvocationID")?;
        ensure!(
            iid.len() == 32 && iid == text(&plan["invocation_ids"], phase)?,
            "qualification invocation differs"
        );
        let exec = field(s, "ExecStart")?;
        if phase == "test-root" {
            ensure!(
                exec.contains(&test)
                    && !exec.contains("--ignored")
                    && !exec.contains("--skip")
                    && !exec.contains("--exact"),
                "wrong/filtered test image"
            );
        } else {
            ensure!(
                exec.contains(&format!("{PACKAGE}/Cargo.toml"))
                    && exec.contains("--features preparation")
                    && exec.contains("--release")
                    && exec.contains("--jobs 2")
                    && exec.contains(TARGET)
                    && !exec.contains("--all-features"),
                "foreign manifest/feature/profile/target"
            );
            ensure!(
                (phase == "test-build") == exec.contains("--no-run"),
                "wrong compile phase"
            );
            let environment = field(s, "Environment")?;
            for (k, v) in &expected_env {
                ensure!(
                    environment
                        .split_whitespace()
                        .filter(|x| x.trim_matches('"') == format!("{k}={v}"))
                        .count()
                        == 1,
                    "missing exact build environment {k}"
                );
            }
            ensure!(
                !environment.contains("RUSTFLAGS=")
                    && !environment.contains("CARGO_ENCODED_RUSTFLAGS="),
                "unexpected rust flags"
            );
        }
        let log = run(Command::new("journalctl").args([
            "--no-pager",
            "--all",
            "-o",
            "cat",
            &format!("_SYSTEMD_INVOCATION_ID={iid}"),
        ]))?;
        if phase == "test-root" {
            let l = std::str::from_utf8(&log)?;
            ensure!(
                l.contains(
                    "test result: ok. 298 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;"
                ),
                "full298 tests not proved"
            );
        }
        captured.push((phase, unit, native, log));
    }
    // Revalidate exact source/artifact bytes after qualification observation.
    for (p, h) in &source_rows {
        ensure!(
            sha(&regular(&format!("{REPO}/{p}"))?) == h.as_str().unwrap(),
            "source changed during capture"
        );
    }
    ensure!(
        sha(&regular(&production)?) == text(&plan, "production_sha256")?
            && sha(&regular(&test)?) == text(&plan, "test_sha256")?,
        "images changed during capture"
    );
    fs::DirBuilder::new().mode(0o700).create(ROOT)?;
    save("input.json", &raw)?;
    let mut executions = serde_json::Map::new();
    for (phase, unit, native, log) in captured {
        executions.insert(phase.into(),json!({"unit":unit,"native":save(&format!("{phase}.native"),&native)?,"journal":save(&format!("{phase}.log"),&log)?}));
    }
    let source_seal = seal("source-seal-plan.json", SOURCE, json!(members))?;
    let proof = save(
        "artifact-proof.json",
        &serde_json::to_vec_pretty(
            &json!({"schema":"horizon-live166retry8-preparer-build-proof-v1","owner":"/root","primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53","epoch":167,"attempt":"local3retry7","source_commit":commit,"source_commit_verified_on_origin_account_updates":true,"source_seal":source_seal,"source_files":source_rows,"production":{"path":format!("{DEST}/prepare"),"sha256":plan["production_sha256"]},"test_image":{"path":test,"sha256":plan["test_sha256"]},"tests_passed":298,"tests_failed":0,"tests_ignored":0,"features":["preparation"],"build_guard_source_commit":GUARD_COMMIT,"executions":executions,"resource_credit_bytes":0,"replay_launch_authorized":false,"remote_mutations":false,"native_witness_and_fresh_admission_still_required":true}),
        )?,
    )?;
    let runtime_seal = seal(
        "runtime-seal-plan.json",
        DEST,
        json!([
            member(&production, "prepare", 0o555)?,
            member(text(&proof, "path")?, "artifact-proof.json", 0o444)?
        ]),
    )?;
    ensure!(
        sha(&regular(&format!("{DEST}/prepare"))?) == text(&plan, "production_sha256")?,
        "deployed image mismatch"
    );
    println!(
        "{}",
        json!({"runtime":bind(&format!("{DEST}/prepare"))?,"proof":bind(&format!("{DEST}/artifact-proof.json"))?,"source_seal":source_seal,"runtime_seal":runtime_seal,"replay_launched":false})
    );
    Ok(())
}
