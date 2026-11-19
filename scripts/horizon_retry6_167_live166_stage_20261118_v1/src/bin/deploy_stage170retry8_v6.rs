//! Capture genuine home-audit stage v6 qualification, seal runtime, and bind metadata inputs.
//! No replay launch, resource credit, or remote mutation.
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
const PACKAGE: &str = "scripts/horizon_retry6_167_live166_stage_20261118_v1";
const STATE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-home-audit-v8-20261119-v1/stage-v6-evidence";
const DEST: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-home-audit-v8-20261119-v1/stage-v6";
const IMAGE: &str = "/home/sol/workspace/jetstreamer/scripts/horizon_retry8_166_20261119_v1/guard/target/release/stage170retry8";
const SHA: &str = "d87d8a3c11612a792bb710981cd890428e5f76dea8952253a35b64d23bca68dd";
const BUILD_COMMIT: &str = "0ae58804bc54ad0c4830977ca83dac1d8547e0ca";
const AUDIT_SOURCE: &str =
    "scripts/horizon_retry6_170_guarded_launch_20261119_v1/src/audit_budget.rs";
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
const ROOT: &str = "/var/lib/jetstreamer/epoch170-retry8-peer-stage-20261119-v1";
const BINDINGS: [(&str, &str); 3] = [
    (
        "HORIZON_170_PREPARER_V3_SHA256",
        "0b4e325aa56377455ceb33f955a0155e3c5753870e4a0ac60e625256a5547574",
    ),
    (
        "HORIZON_170_PREPARER_V3_PROOF_SHA256",
        "819de1a3970b0768b73123b041e2457fd866fd99a147b0aa986c97f40f6c5022",
    ),
    (
        "HORIZON_170_RETRY8_LAUNCH_V5_SHA256",
        "74cafe74769946f686c0fef3b3fa8064839c8deb4bf7009ec2ba3de9c7ac4a34",
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
fn home_backed(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && fs::metadata(path)?.dev() == fs::metadata("/home/sol")?.dev(),
        "deployment/state path is not home-backed: {}",
        path.display()
    );
    Ok(())
}
fn compile_environment(environment: &str) -> Result<()> {
    ensure!(
        !environment.contains("RUSTFLAGS=") && !environment.contains("CARGO_ENCODED_RUSTFLAGS="),
        "unqualified compiler flags"
    );
    for (key, value) in BINDINGS {
        let prefix = format!("{key}=");
        let found: Vec<_> = environment
            .split_whitespace()
            .filter(|word| word.starts_with(&prefix))
            .collect();
        ensure!(
            found.len() == 1 && found[0] == format!("{key}={value}"),
            "compile binding differs: {key}"
        );
    }
    Ok(())
}
fn test_count(log: &str) -> Result<u64> {
    let summaries: Vec<_> = log
        .lines()
        .filter(|line| line.starts_with("test result:"))
        .collect();
    let expected = "test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;";
    ensure!(
        summaries.len() == 1
            && summaries[0]
                .strip_prefix(expected)
                .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with(" finished in ")),
        "exact complete twelve-test qualification required"
    );
    Ok(12)
}
fn source_closure() -> Vec<(String, String)> {
    let mut files = ["src/bin/stage170retry8.rs", "Cargo.toml", "Cargo.lock"]
        .into_iter()
        .map(|name| (format!("{PACKAGE}/{name}"), name.replace('/', "-")))
        .collect::<Vec<_>>();
    files.push((AUDIT_SOURCE.to_owned(), "shared-audit-budget.rs".to_owned()));
    files
}
fn qualified_command(command: &str, phase: &str) -> Result<()> {
    let verb = match phase {
        "tests" => "test",
        "clippy" => "clippy",
        "production" => "build",
        _ => anyhow::bail!("unknown qualification phase"),
    };
    ensure!(
        command.contains(&format!("argv[]=/home/sol/.cargo/bin/cargo {verb} "))
            && command.contains(&format!("--manifest-path {PACKAGE}/Cargo.toml "))
            && command.contains("--bin stage170retry8 ")
            && command.contains("--release ")
            && command.contains("--offline ")
            && command.contains("--locked ")
            && command.contains("--jobs 2 ")
            && command
                .contains("--target-dir scripts/horizon_retry8_166_20261119_v1/guard/target ")
            && !command.contains("--features")
            && !command.contains("--all-features")
            && !command.contains("--no-default-features")
            && !command.contains("--no-run")
            && !command.contains("--skip")
            && !command.contains("--exact"),
        "foreign or filtered stage qualification command"
    );
    ensure!(
        phase != "clippy" || command.contains("-- -D warnings "),
        "non-strict clippy"
    );
    Ok(())
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
    let own = format!("{PACKAGE}/src/bin/deploy_stage170retry8_v6.rs");
    ensure!(
        git(&["show", &format!("HEAD:{own}")])?.as_bytes() == fs::read(format!("{REPO}/{own}"))?
            && fs::read(format!("{REPO}/{own}"))?.as_slice()
                == include_bytes!("deploy_stage170retry8_v6.rs"),
        "unpublished helper"
    );
    git(&[
        "merge-base",
        "--is-ancestor",
        BUILD_COMMIT,
        "origin/account-updates",
    ])?;
    for (rel, _) in source_closure() {
        let bytes = fs::read(format!("{REPO}/{rel}"))?;
        ensure!(
            git(&["show", &format!("{BUILD_COMMIT}:{rel}")])?.as_bytes() == bytes
                && git(&["show", &format!("HEAD:{rel}")])?.as_bytes() == bytes,
            "qualified build source is not publication-equivalent: {rel}"
        );
    }
    home_backed(Path::new(ROOT))?;
    if args.len() == 2 && args[1] == "seal" {
        ensure!(
            sha(&fs::read(IMAGE)?) == SHA && sha(&fs::read(SEALER)?) == SEALER_SHA,
            "artifact changed"
        );
        for path in [
            Path::new(STATE).parent().context("state parent")?,
            Path::new(DEST).parent().context("destination parent")?,
            Path::new(IMAGE),
        ] {
            home_backed(path)?;
        }
        fs::DirBuilder::new().mode(0o700).create(STATE)?;
        home_backed(Path::new(STATE))?;
        let mut members = vec![member(IMAGE, "stage", 0o555)?];
        let mut sources = serde_json::Map::new();
        let mut executions = serde_json::Map::new();
        for (phase, iid) in [
            ("tests", "7f36fa2792d74353805598249293012d"),
            ("clippy", "9ae056e6509f4b879a86f29b96d27a83"),
            ("production", "ac478a6dc3234f96bdcab24f97bf286e"),
        ] {
            let unit = format!("horizon-170-stagev6-{phase}-20261119-v2.service");
            let native=run(Command::new("systemctl").args(["show",&unit,"-pId,InvocationID,LoadState,ActiveState,SubState,MainPID,ControlPID,Result,ExecMainStatus,ExecStart,Environment,WorkingDirectory,CPUQuotaPerSecUSec,MemoryMax,MemorySwapMax"]))?;
            for property in [
                format!("Id={unit}"),
                format!("WorkingDirectory={REPO}"),
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
            qualified_command(command, phase)?;
            let env = native
                .lines()
                .find_map(|l| l.strip_prefix("Environment="))
                .context("environment")?;
            compile_environment(env)?;
            let log = run(Command::new("journalctl").args([
                "--no-pager",
                "--all",
                "-o",
                "cat",
                &format!("_SYSTEMD_INVOCATION_ID={iid}"),
            ]))?;
            if phase == "tests" {
                test_count(&log)?;
            }
            // Preserve native properties without copying unrelated environment
            // values into a sealed package. The observed environment is hashed;
            // the exact allowed compiler bindings are recorded separately.
            let selected_native = native
                .lines()
                .filter(|line| !line.starts_with("Environment="))
                .map(|line| format!("{line}\n"))
                .collect::<String>();
            for (name, bytes) in [
                (format!("{phase}-native.txt"), selected_native.as_bytes()),
                (format!("{phase}.log"), log.as_bytes()),
            ] {
                let p = format!("{STATE}/{name}");
                save(&p, bytes)?;
                members.push(member(&p, &name, 0o444)?);
            }
            executions.insert(phase.into(), json!({"unit":unit,"invocation_id":iid,
                "native_properties_exclude_environment":true,"observed_environment_sha256":sha(env.as_bytes()),
                "native":bind(&format!("{STATE}/{phase}-native.txt"))?,"log":bind(&format!("{STATE}/{phase}.log"))?}));
        }
        for (rel, name) in source_closure() {
            let p = format!("{REPO}/{rel}");
            let b = fs::read(&p)?;
            ensure!(
                git(&["show", &format!("HEAD:{rel}")])?.as_bytes() == b
                    && git(&["show", &format!("{BUILD_COMMIT}:{rel}")])?.as_bytes() == b,
                "unpublished source"
            );
            sources.insert(p.clone(), json!(sha(&b)));
            members.push(member(&p, &name, 0o444)?);
        }
        ensure!(
            sources.len() == 4
                && sources.contains_key(&format!("{REPO}/{AUDIT_SOURCE}"))
                && sha(&fs::read(IMAGE)?) == SHA,
            "qualified stage source/image changed"
        );
        let proof = json!({"schema":"horizon-two-peer170-stage-build-proof-v1","source_commit":commit.trim(),
            "equivalent_build_source_commit":BUILD_COMMIT,"source_contained_in_origin_account_updates":true,
            "build_source_contained_in_origin_account_updates":true,"publication_equivalence_checked_for_entire_source_closure":true,
            "production_sha256":SHA,"tests_passed":12,"tests_failed":0,"production_clippy_passed":true,"features":[],
            "sources":sources,"shared_audit_budget_source":bind(&format!("{REPO}/{AUDIT_SOURCE}"))?,
            "executions":executions,"compile_bindings":BINDINGS.into_iter().collect::<std::collections::BTreeMap<_,_>>(),
            "home_storage_required":true,"historical_stage_root_preserved":ROOT,
            "fresh_two_peer_sample_and_admission_required":true,"replay_launch_authorized":false,"resource_credit_bytes":0,
            "remote_mutations":false});
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
        home_backed(Path::new(DEST))?;
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
            "usage: deploy_stage170retry8_v6 seal | config TAG GENERATION FLEET [MEASUREMENT]"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compiler_bindings_are_exact_and_flags_cannot_bypass_qualification() {
        let valid = BINDINGS
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ");
        compile_environment(&valid).unwrap();
        let (key, value) = BINDINGS[0];
        for bad in [
            valid.replace(&format!("{key}={value}"), ""),
            valid.replace(value, &format!("{value}0")),
            format!("{valid} {key}={value}"),
            format!("{valid} RUSTFLAGS=-Awarnings"),
            format!("{valid} CARGO_ENCODED_RUSTFLAGS=-Awarnings"),
        ] {
            assert!(compile_environment(&bad).is_err());
        }
    }
    #[test]
    fn qualification_requires_one_unfiltered_twelve_test_success() {
        let good = "test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s";
        assert_eq!(test_count(good).unwrap(), 12);
        for bad in [
            good.replace("12 passed", "5 passed"),
            good.replace("0 failed", "1 failed"),
            good.replace("0 ignored", "1 ignored"),
            good.replace("0 filtered out", "1 filtered out"),
            format!("{good}\n{good}"),
            String::new(),
        ] {
            assert!(test_count(&bad).is_err());
        }
    }
    #[test]
    fn source_closure_and_native_commands_require_the_home_audit_build() {
        let files = source_closure();
        assert_eq!(files.len(), 4);
        assert!(
            files
                .iter()
                .any(|(rel, leaf)| rel == AUDIT_SOURCE && leaf == "shared-audit-budget.rs")
        );
        for (phase, verb, suffix) in [
            ("tests", "test", ""),
            ("clippy", "clippy", "-- -D warnings "),
            ("production", "build", ""),
        ] {
            let command = format!(
                "{{ path=/home/sol/.cargo/bin/cargo ; argv[]=/home/sol/.cargo/bin/cargo {verb} --manifest-path {PACKAGE}/Cargo.toml --bin stage170retry8 --release --offline --locked --jobs 2 --target-dir scripts/horizon_retry8_166_20261119_v1/guard/target {suffix}; ignore_errors=no ; }}"
            );
            qualified_command(&command, phase).unwrap();
            for bad in [
                command.replace("--bin stage170retry8", "--bin stage170retry8_other"),
                command.replace("--jobs 2", "--jobs 20"),
                command.replace("--offline ", ""),
                format!("{command} --skip ignored"),
                format!("{command} --features unqualified"),
            ] {
                assert!(qualified_command(&bad, phase).is_err());
            }
        }
    }
}
