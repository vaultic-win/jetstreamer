//! Capture explicit genuine stage v7 qualification, seal runtime, and bind HOME metadata inputs.
//! No replay launch, resource credit, or remote mutation.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
    process::Command,
};
const REPO: &str = "/home/sol/workspace/jetstreamer";
const PACKAGE: &str = "scripts/horizon_retry6_167_live166_stage_20261118_v1";
const STATE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-home-audit-v8-20261119-v1/stage-v7-evidence";
const DEST: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-home-audit-v8-20261119-v1/stage-v7";
const HOME_BASE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-home-audit-v8-20261119-v1";
const AUDIT_SOURCE: &str =
    "scripts/horizon_retry6_170_guarded_launch_20261119_v1/src/audit_budget.rs";
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
const ROOT: &str = "/var/lib/jetstreamer/epoch170-retry8-peer-stage-20261119-v1";
const PREPARER_BINDINGS: [(&str, &str); 2] = [
    (
        "HORIZON_170_PREPARER_V3_SHA256",
        "0b4e325aa56377455ceb33f955a0155e3c5753870e4a0ac60e625256a5547574",
    ),
    (
        "HORIZON_170_PREPARER_V3_PROOF_SHA256",
        "819de1a3970b0768b73123b041e2457fd866fd99a147b0aa986c97f40f6c5022",
    ),
];
const LAUNCH_BINDING: &str = "HORIZON_170_RETRY8_LAUNCH_V6_SHA256";

fn exact_fields(v: &Value, keys: &[&str]) -> Result<()> {
    let object = v.as_object().context("qualification object required")?;
    ensure!(
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key)),
        "qualification fields differ from the explicit schema"
    );
    Ok(())
}
fn field<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .with_context(|| format!("missing qualification string {key}"))
}
fn digest_shape(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}
fn qualification_shape(q: &Value) -> Result<()> {
    exact_fields(
        q,
        &[
            "schema",
            "production",
            "build_source_commit",
            "executions",
            "launcher_v6_sha256",
        ],
    )?;
    ensure!(
        q["schema"] == "horizon-stage170-v7-deployment-input-v1",
        "qualification schema"
    );
    exact_fields(&q["production"], &["path", "sha256"])?;
    let path = Path::new(field(&q["production"], "path")?);
    ensure!(
        path.is_absolute()
            && path.file_name().is_some_and(|n| n == "stage170retry8")
            && path
                .parent()
                .and_then(Path::file_name)
                .is_some_and(|n| n == "release")
            && path.components().all(|c| matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            ))
            && path
                .to_str()
                .context("image path UTF8")?
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b)),
        "explicit canonical release/stage170retry8 image required"
    );
    ensure!(
        digest_shape(field(&q["production"], "sha256")?, 64)
            && digest_shape(field(q, "build_source_commit")?, 40)
            && digest_shape(field(q, "launcher_v6_sha256")?, 64),
        "full qualification digests required"
    );
    exact_fields(&q["executions"], &["tests", "production", "clippy"])?;
    let mut units = BTreeSet::new();
    let mut invocations = BTreeSet::new();
    for phase in ["tests", "production", "clippy"] {
        let execution = &q["executions"][phase];
        exact_fields(execution, &["unit", "invocation_id"])?;
        let unit = field(execution, "unit")?;
        let iid = field(execution, "invocation_id")?;
        ensure!(
            unit.starts_with("horizon-")
                && unit.ends_with(".service")
                && unit.len() <= 255
                && unit
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b))
                && digest_shape(iid, 32)
                && units.insert(unit)
                && invocations.insert(iid),
            "explicit distinct native qualification units and invocation IDs required"
        );
    }
    Ok(())
}
fn qualification_input(path: &str) -> Result<(Value, Value, Vec<u8>)> {
    home_backed(Path::new(path))?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o022 == 0
            && before.len() <= 1 << 20,
        "unsafe qualification input custody/size"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((1 << 20) + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    let identity = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    ensure!(
        bytes.len() as u64 == before.len()
            && identity(&before) == identity(&after)
            && identity(&before) == identity(&named),
        "qualification input changed during read"
    );
    let q: Value = serde_json::from_slice(&bytes)?;
    qualification_shape(&q)?;
    Ok((q, json!({"path":path,"sha256":sha(&bytes)}), bytes))
}
fn compile_bindings(q: &Value) -> Result<Vec<(&'static str, &str)>> {
    Ok(vec![
        PREPARER_BINDINGS[0],
        PREPARER_BINDINGS[1],
        (LAUNCH_BINDING, field(q, "launcher_v6_sha256")?),
    ])
}
fn fresh_contract_path(generation: &str) -> Result<String> {
    ensure!(
        (1..=32).contains(&generation.len())
            && generation
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
        "unsafe generation"
    );
    Ok(format!("{HOME_BASE}/data-contract-{generation}"))
}
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
fn compile_environment(environment: &str, q: &Value) -> Result<()> {
    ensure!(
        !environment.contains("RUSTFLAGS=") && !environment.contains("CARGO_ENCODED_RUSTFLAGS="),
        "unqualified compiler flags"
    );
    for (key, value) in compile_bindings(q)? {
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
fn qualified_command(command: &str, phase: &str, q: &Value) -> Result<()> {
    let verb = match phase {
        "tests" => "test",
        "clippy" => "clippy",
        "production" => "build",
        _ => anyhow::bail!("unknown qualification phase"),
    };
    ensure!(
        command.starts_with("{ path=/home/sol/.cargo/bin/cargo ; ")
            && command.trim_end().ends_with('}')
            && command.matches("argv[]=").count() == 1,
        "one native Cargo execution required"
    );
    let image = Path::new(field(&q["production"], "path")?);
    let target = image
        .parent()
        .and_then(Path::parent)
        .context("release image target")?;
    let argv = command
        .split_once("argv[]=")
        .context("native argv")?
        .1
        .split_once(" ;")
        .context("native argv delimiter")?
        .0;
    let actual: Vec<_> = argv.split_whitespace().collect();
    let manifest = format!("{PACKAGE}/Cargo.toml");
    let mut expected = vec![
        "/home/sol/.cargo/bin/cargo",
        verb,
        "--manifest-path",
        &manifest,
        "--bin",
        "stage170retry8",
        "--release",
        "--offline",
        "--locked",
        "--jobs",
        "2",
        "--target-dir",
    ];
    let target_text = target.to_str().context("target UTF8")?;
    expected.push(target_text);
    if phase == "clippy" {
        expected.extend(["--", "-D", "warnings"]);
    }
    let exact_absolute = actual == expected;
    let exact_relative = if let Ok(relative) = target.strip_prefix(REPO) {
        expected[12] = relative.to_str().context("relative target UTF8")?;
        actual == expected
    } else {
        false
    };
    ensure!(
        exact_absolute || exact_relative,
        "foreign, filtered or non-strict stage qualification command"
    );
    Ok(())
}
fn main() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "Root required");
    let args: Vec<_> = std::env::args().collect();
    let sealing = args.len() == 3 && args[1] == "seal";
    let configuring = (args.len() == 6 || args.len() == 7) && args[1] == "config";
    ensure!(
        sealing || configuring,
        "usage: deploy_stage170retry8_v7 seal INPUT | config TAG GENERATION FLEET [MEASUREMENT] INPUT"
    );
    let (qualification, input_binding, input_bytes) =
        qualification_input(args.last().context("qualification input")?)?;
    let image = field(&qualification["production"], "path")?;
    let image_sha = field(&qualification["production"], "sha256")?;
    let build_commit = field(&qualification, "build_source_commit")?;
    let commit = git(&["rev-parse", "HEAD"])?;
    git(&[
        "merge-base",
        "--is-ancestor",
        commit.trim(),
        "origin/account-updates",
    ])?;
    let own = format!("{PACKAGE}/src/bin/deploy_stage170retry8_v7.rs");
    ensure!(
        git(&["show", &format!("HEAD:{own}")])?.as_bytes() == fs::read(format!("{REPO}/{own}"))?
            && fs::read(format!("{REPO}/{own}"))?.as_slice()
                == include_bytes!("deploy_stage170retry8_v7.rs"),
        "unpublished helper"
    );
    git(&[
        "merge-base",
        "--is-ancestor",
        build_commit,
        "origin/account-updates",
    ])?;
    for (rel, _) in source_closure() {
        let bytes = fs::read(format!("{REPO}/{rel}"))?;
        ensure!(
            git(&["show", &format!("{build_commit}:{rel}")])?.as_bytes() == bytes
                && git(&["show", &format!("HEAD:{rel}")])?.as_bytes() == bytes,
            "qualified build source is not publication-equivalent: {rel}"
        );
    }
    home_backed(Path::new(ROOT))?;
    if sealing {
        ensure!(
            sha(&fs::read(image)?) == image_sha && sha(&fs::read(SEALER)?) == SEALER_SHA,
            "artifact changed"
        );
        for path in [
            Path::new(STATE).parent().context("state parent")?,
            Path::new(DEST).parent().context("destination parent")?,
            Path::new(image),
        ] {
            home_backed(path)?;
        }
        fs::DirBuilder::new().mode(0o700).create(STATE)?;
        home_backed(Path::new(STATE))?;
        let input_copy = format!("{STATE}/qualification-input.json");
        save(&input_copy, &input_bytes)?;
        let mut members = vec![
            member(image, "stage", 0o555)?,
            member(&input_copy, "qualification-input.json", 0o444)?,
        ];
        let mut sources = serde_json::Map::new();
        let mut executions = serde_json::Map::new();
        for phase in ["tests", "clippy", "production"] {
            let execution = &qualification["executions"][phase];
            let unit = field(execution, "unit")?;
            let iid = field(execution, "invocation_id")?;
            let native=run(Command::new("systemctl").args(["show",unit,"-pId,InvocationID,LoadState,ActiveState,SubState,MainPID,ControlPID,Result,ExecMainStatus,ExecStart,Environment,WorkingDirectory,CPUQuotaPerSecUSec,MemoryMax,MemorySwapMax"]))?;
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
            qualified_command(command, phase, &qualification)?;
            let env = native
                .lines()
                .find_map(|l| l.strip_prefix("Environment="))
                .context("environment")?;
            compile_environment(env, &qualification)?;
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
                    && git(&["show", &format!("{build_commit}:{rel}")])?.as_bytes() == b,
                "unpublished source"
            );
            sources.insert(p.clone(), json!(sha(&b)));
            members.push(member(&p, &name, 0o444)?);
        }
        ensure!(
            sources.len() == 4
                && sources.contains_key(&format!("{REPO}/{AUDIT_SOURCE}"))
                && sha(&fs::read(image)?) == image_sha,
            "qualified stage source/image changed"
        );
        let proof = json!({"schema":"horizon-two-peer170-stage-build-proof-v1","source_commit":commit.trim(),
            "equivalent_build_source_commit":build_commit,"source_contained_in_origin_account_updates":true,
            "build_source_contained_in_origin_account_updates":true,"publication_equivalence_checked_for_entire_source_closure":true,
            "production_sha256":image_sha,"production":qualification["production"],
            "qualification_input":input_binding,"tests_passed":12,"tests_failed":0,"production_clippy_passed":true,"features":[],
            "sources":sources,"shared_audit_budget_source":bind(&format!("{REPO}/{AUDIT_SOURCE}"))?,
            "executions":executions,"compile_bindings":compile_bindings(&qualification)?.into_iter().collect::<std::collections::BTreeMap<_,_>>(),
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
    } else {
        ensure!(
            sha(&fs::read(format!("{DEST}/qualification-input.json"))?)
                == input_binding["sha256"].as_str().context("input digest")?
                && sha(&fs::read(format!("{DEST}/stage"))?) == image_sha,
            "config input must bind the actually sealed stage v7 qualification"
        );
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
        home_backed(Path::new(HOME_BASE))?;
        let fresh = fresh_contract_path(generation)?;
        cfg["witness_generation"] = json!({"generation":generation,"output_root":format!("{ROOT}/guard-witness-{generation}"),"unit":format!("horizon-170-retry8-witness-{generation}-20261119.service"),"contract_destination":fresh});
        if args.len() == 7 {
            home_backed(Path::new(&fresh))?;
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
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn qualification() -> Value {
        json!({"schema":"horizon-stage170-v7-deployment-input-v1",
            "production":{"path":format!("{REPO}/scripts/horizon_retry8_166_20261119_v1/guard/target/release/stage170retry8"),"sha256":"a".repeat(64)},
            "build_source_commit":"b".repeat(40),"launcher_v6_sha256":"c".repeat(64),
            "executions":{
                "tests":{"unit":"horizon-170-stagev7-tests-fixture.service","invocation_id":"d".repeat(32)},
                "production":{"unit":"horizon-170-stagev7-production-fixture.service","invocation_id":"e".repeat(32)},
                "clippy":{"unit":"horizon-170-stagev7-clippy-fixture.service","invocation_id":"f".repeat(32)}}})
    }
    #[test]
    fn explicit_qualification_rejects_missing_unknown_and_reused_identity() {
        let good = qualification();
        qualification_shape(&good).unwrap();
        let mut bad = good.clone();
        bad.as_object_mut().unwrap().remove("executions");
        assert!(qualification_shape(&bad).is_err());
        let mut bad = good.clone();
        bad["tests_passed"] = json!(12);
        assert!(qualification_shape(&bad).is_err());
        for key in ["unit", "invocation_id"] {
            let mut bad = good.clone();
            bad["executions"]["production"][key] = bad["executions"]["tests"][key].clone();
            assert!(qualification_shape(&bad).is_err());
        }
        for (key, value) in [
            ("build_source_commit", "0ae58804"),
            ("launcher_v6_sha256", "unqualified"),
        ] {
            let mut bad = good.clone();
            bad[key] = json!(value);
            assert!(qualification_shape(&bad).is_err());
        }
        for path in [
            "relative/release/stage170retry8",
            "/home/sol/debug/stage170retry8",
            "/home/sol/release/another",
            "/home/sol/../release/stage170retry8",
        ] {
            let mut bad = good.clone();
            bad["production"]["path"] = json!(path);
            assert!(qualification_shape(&bad).is_err());
        }
    }
    #[test]
    fn fresh_contracts_stay_in_home_and_reject_path_escape() {
        assert_eq!(
            fresh_contract_path("v7-real").unwrap(),
            "/var/lib/jetstreamer/horizon_runtime_data/epoch170-home-audit-v8-20261119-v1/data-contract-v7-real"
        );
        for bad in ["", "../outside", "v7/name", "V7", "two words"] {
            assert!(fresh_contract_path(bad).is_err());
        }
        assert!(fresh_contract_path(&"v".repeat(33)).is_err());
    }
    #[test]
    fn compiler_bindings_are_exact_and_flags_cannot_bypass_qualification() {
        let q = qualification();
        let bindings = compile_bindings(&q).unwrap();
        let valid = bindings
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ");
        compile_environment(&valid, &q).unwrap();
        let (key, value) = bindings[0];
        for bad in [
            valid.replace(&format!("{key}={value}"), ""),
            valid.replace(value, &format!("{value}0")),
            format!("{valid} {key}={value}"),
            format!("{valid} RUSTFLAGS=-Awarnings"),
            format!("{valid} CARGO_ENCODED_RUSTFLAGS=-Awarnings"),
        ] {
            assert!(compile_environment(&bad, &q).is_err());
        }
        let stale_launcher = valid.replace(LAUNCH_BINDING, "HORIZON_170_RETRY8_LAUNCH_V5_SHA256");
        assert!(compile_environment(&stale_launcher, &q).is_err());
        let changed_launcher =
            valid.replace(field(&q, "launcher_v6_sha256").unwrap(), &"d".repeat(64));
        assert!(compile_environment(&changed_launcher, &q).is_err());
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
        let q = qualification();
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
            qualified_command(&command, phase, &q).unwrap();
            let absolute = command.replace(
                "--target-dir scripts/",
                &format!("--target-dir {REPO}/scripts/"),
            );
            qualified_command(&absolute, phase, &q).unwrap();
            for bad in [
                command.replace("--bin stage170retry8", "--bin stage170retry8_other"),
                command.replace("--jobs 2", "--jobs 20"),
                command.replace("--offline ", ""),
                format!("{command} --skip ignored"),
                format!("{command} --features unqualified"),
            ] {
                assert!(qualified_command(&bad, phase, &q).is_err());
            }
            let wrong_target = command.replace("guard/target", "guard/another-target");
            assert!(qualified_command(&wrong_target, phase, &q).is_err());
            let extra_arg =
                command.replace("; ignore_errors", "--config unqualified ; ignore_errors");
            assert!(qualified_command(&extra_arg, phase, &q).is_err());
        }
    }
}
