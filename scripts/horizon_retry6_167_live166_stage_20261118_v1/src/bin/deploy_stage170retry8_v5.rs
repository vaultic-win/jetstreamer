//! Capture genuine stage qualification, seal immutable runtime, and bind metadata inputs.
//! No replay launch, resource credit, or remote mutation.
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
const PACKAGE: &str = "scripts/horizon_retry6_167_live166_stage_20261118_v1";
const STATE: &str = "/var/lib/jetstreamer/stage170retry8-deployment-20261119-v5";
const DEST: &str = "/usr/local/lib/jetstreamer/horizon-stage170retry8-20261119-v5";
const IMAGE: &str = "/home/sol/workspace/jetstreamer/scripts/horizon_retry8_166_20261119_v1/guard/target/release/stage170retry8";
const SHA: &str = "aae416fe1febbe8a9c5cffd1493b1831e7124b48f442decc043b4968d9e49001";
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
const ROOT: &str = "/var/lib/jetstreamer/epoch170-retry8-peer-stage-20261119-v1";
const BINDINGS: [(&str, &str); 3] = [
    (
        "HORIZON_170_PREPARER_V2_SHA256",
        "4b9c35f6983be37cf73a1422841735fca71754a94427536cb747866fd9c0b0f6",
    ),
    (
        "HORIZON_170_PREPARER_V2_PROOF_SHA256",
        "59aa310a6ca1543b6e1a1d68b100ccd913158a7e6566a7098cc6bbab80036c40",
    ),
    (
        "HORIZON_170_RETRY8_LAUNCH_V4_SHA256",
        "4356643b93da4cdfcf8db293abc20e9cb749de9768f4b7732f5e24ea0d708405",
    ),
];
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn run(c: &mut Command) -> Result<String> {
    let o = c.output()?;
    ensure!(
        o.status.success(),
        "{c:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    Ok(String::from_utf8(o.stdout)?)
}
fn git(a: &[&str]) -> Result<String> {
    run(Command::new("git")
        .args(["-c", &format!("safe.directory={REPO}"), "-C", REPO])
        .args(a))
}
fn bind(p: &str) -> Result<Value> {
    Ok(json!({"path":p,"sha256":sha(&fs::read(p)?)}))
}
fn save(p: &str, b: &[u8]) -> Result<Value> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)?;
    f.write_all(b)?;
    f.sync_all()?;
    File::open(Path::new(p).parent().context("parent")?)?.sync_all()?;
    bind(p)
}
fn member(p: &str, n: &str, mode: u32) -> Result<Value> {
    Ok(json!({"source":p,"name":n,"sha256":sha(&fs::read(p)?),"mode":mode}))
}
fn main() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "Root required");
    let args: Vec<_> = std::env::args().collect();
    let commit = git(&["rev-parse", "HEAD"])?;
    git(&[
        "merge-base",
        "--is-ancestor",
        commit.trim(),
        "origin/account-updates",
    ])?;
    let own = format!("{PACKAGE}/src/bin/deploy_stage170retry8_v5.rs");
    ensure!(
        git(&["show", &format!("HEAD:{own}")])?.as_bytes() == fs::read(format!("{REPO}/{own}"))?,
        "unpublished helper"
    );
    if args.len() == 2 && args[1] == "seal" {
        ensure!(
            sha(&fs::read(IMAGE)?) == SHA && sha(&fs::read(SEALER)?) == SEALER_SHA,
            "artifact changed"
        );
        fs::DirBuilder::new().mode(0o700).create(STATE)?;
        let mut members = vec![member(IMAGE, "stage", 0o555)?];
        let mut sources = serde_json::Map::new();
        let mut executions = serde_json::Map::new();
        for (phase, iid) in [
            ("tests", "e2e5fb0b460b4ce487e543641dadf658"),
            ("clippy", "127c66a3e6624fd3a5e301a2d6f4422d"),
            ("production", "7d421daf5fc5484285cbd179850bfc4f"),
        ] {
            let unit = format!("horizon-170-stagev5-{phase}-20261119-v1.service");
            let native=run(Command::new("systemctl").args(["show",&unit,"-pId,InvocationID,LoadState,ActiveState,SubState,MainPID,ControlPID,Result,ExecMainStatus,ExecStart,Environment,CPUQuotaPerSecUSec,MemoryMax,MemorySwapMax"]))?;
            for property in [
                format!("InvocationID={iid}"),
                "LoadState=loaded".into(),
                "ActiveState=active".into(),
                "SubState=exited".into(),
                "MainPID=0".into(),
                "ControlPID=0".into(),
                "Result=success".into(),
                "ExecMainStatus=0".into(),
                "CPUQuotaPerSecUSec=2s".into(),
                "MemoryMax=2147483648".into(),
                "MemorySwapMax=0".into(),
            ] {
                ensure!(native.lines().any(|l| l == property), "missing {property}");
            }
            let command = native
                .lines()
                .find_map(|l| l.strip_prefix("ExecStart="))
                .context("command")?;
            ensure!(
                command.contains(PACKAGE)
                    && command.contains("--bin stage170retry8")
                    && command.contains("--release")
                    && command.contains("--locked")
                    && command.contains("--jobs 2"),
                "foreign build"
            );
            if phase == "clippy" {
                ensure!(command.contains("-D warnings"), "non-strict clippy");
            }
            let env = native
                .lines()
                .find_map(|l| l.strip_prefix("Environment="))
                .context("environment")?;
            for (key, val) in BINDINGS {
                ensure!(
                    env.contains(&format!("{key}={val}")),
                    "compile binding differs"
                );
            }
            ensure!(!env.contains("RUSTFLAGS="), "unqualified flags");
            let log = run(Command::new("journalctl").args([
                "--no-pager",
                "--all",
                "-o",
                "cat",
                &format!("_SYSTEMD_INVOCATION_ID={iid}"),
            ]))?;
            if phase == "tests" {
                ensure!(log.contains("test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;"),"incomplete tests");
            }
            for (name, bytes) in [
                (format!("{phase}-native.txt"), native.as_bytes()),
                (format!("{phase}.log"), log.as_bytes()),
            ] {
                let p = format!("{STATE}/{name}");
                save(&p, bytes)?;
                members.push(member(&p, &name, 0o444)?);
            }
            executions.insert(phase.into(), json!({"unit":unit,"invocation_id":iid}));
        }
        for name in ["src/bin/stage170retry8.rs", "Cargo.toml", "Cargo.lock"] {
            let rel = format!("{PACKAGE}/{name}");
            let p = format!("{REPO}/{rel}");
            let b = fs::read(&p)?;
            ensure!(
                git(&["show", &format!("HEAD:{rel}")])?.as_bytes() == b,
                "unpublished source"
            );
            sources.insert(p.clone(), json!(sha(&b)));
            members.push(member(&p, &name.replace('/', "-"), 0o444)?);
        }
        let proof = json!({"schema":"horizon-two-peer170-stage-build-proof-v1","source_commit":commit.trim(),"source_contained_in_origin_account_updates":true,"production_sha256":SHA,"tests_passed":5,"tests_failed":0,"production_clippy_passed":true,"features":[],"sources":sources,"executions":executions,"compile_bindings":BINDINGS.into_iter().collect::<std::collections::BTreeMap<_,_>>(),"fresh_two_peer_sample_and_admission_required":true,"replay_launch_authorized":false,"resource_credit_bytes":0});
        let p = format!("{STATE}/artifact-proof.json");
        save(&p, &serde_json::to_vec_pretty(&proof)?)?;
        members.push(member(&p, "artifact-proof.json", 0o444)?);
        let plan = save(
            &format!("{STATE}/seal-plan.json"),
            &serde_json::to_vec_pretty(
                &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":DEST,"members":members}),
            )?,
        )?;
        run(Command::new(SEALER).args([
            plan["path"].as_str().unwrap(),
            "--plan-sha256",
            plan["sha256"].as_str().unwrap(),
            "--self-sha256",
            SEALER_SHA,
        ]))?;
        println!(
            "{}",
            json!({"runtime":bind(&format!("{DEST}/stage"))?,"proof":bind(&p)?})
        );
    } else if (args.len() == 5 || args.len() == 6) && args[1] == "config" {
        let tag = &args[2];
        let generation = &args[3];
        for v in [tag, generation] {
            ensure!(
                (1..=32).contains(&v.len())
                    && v.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "unsafe tag"
            );
        }
        let fleet: Value = serde_json::from_slice(&fs::read(&args[4])?)?;
        let mut cfg = json!({"owner":"/root","primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53","fleet":bind(&args[4])?,"observer":fleet["observer"],"status":fleet["authenticated_status_audit"],"inventory":fleet["authenticated_inventory"],"next_observer":fleet["sole_next_observer"]});
        for (key, leaf) in [
            ("peer167_admission", "ACTUAL_REPLACEMENT_ADMISSION.json"),
            ("peer167_protection", "ACTUAL_GUARD_PROTECTION.json"),
        ] {
            cfg[key] = bind(&format!(
                "/var/lib/jetstreamer/retry7-single167-guarded-launch-20261119-v1/epoch167/{leaf}"
            ))?;
        }
        let old = "/usr/local/lib/jetstreamer/horizon-epoch170-retry6-live166retry8-data-contract-20261119-v1";
        cfg["measurement_contract"] = json!({"contract":bind(&format!("{old}/contract.json"))?,"deployment_seal":bind(&format!("{old}/deployment-seal-receipt.json"))?});
        let fresh = format!(
            "/usr/local/lib/jetstreamer/horizon-epoch170-retry6-live166retry8-data-contract-{generation}"
        );
        cfg["witness_generation"] = json!({"generation":generation,"output_root":format!("{ROOT}/guard-witness-{generation}"),"unit":format!("horizon-170-retry8-witness-{generation}-20261119.service"),"contract_destination":fresh});
        if args.len() == 6 {
            cfg["measurement"] = bind(&args[5])?;
            cfg["fresh_contract"] = json!({"contract":bind(&format!("{fresh}/contract.json"))?,"deployment_seal":bind(&format!("{fresh}/deployment-seal-receipt.json"))?});
        }
        println!(
            "{}",
            save(
                &format!("{ROOT}/config-{tag}.json"),
                &serde_json::to_vec_pretty(&cfg)?
            )?
        );
    } else {
        anyhow::bail!(
            "usage: deploy_stage170retry8_v5 seal | config TAG GENERATION FLEET [MEASUREMENT]"
        );
    }
    Ok(())
}
