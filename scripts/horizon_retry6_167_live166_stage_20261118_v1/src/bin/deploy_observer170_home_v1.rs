//! Seal the two genuinely qualified observer170 tools and their exact source/evidence.
//! Usage: deploy_observer170_home_v1 INPUT --input-sha256 SHA
//! No admission, replay, timer, publication or resource-release authority.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::Path,
    process::Command,
};

const REPO: &str = "/home/sol/workspace/jetstreamer";
const PACKAGE: &str = "scripts/horizon_retry6_167_live166_stage_20261118_v1";
const TARGET: &str = "scripts/horizon_retry8_166_20261119_v1/guard/target";
const COMMIT: &str = "e3185dc533902b65f9bfe2127750cc5974d0b7b2";
const OWN: &str =
    "scripts/horizon_retry6_167_live166_stage_20261118_v1/src/bin/deploy_observer170_home_v1.rs";
const BASE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-home-audit-v8-20261119-v1";
const DEST: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-home-audit-v8-20261119-v1/observer170-v1";
const STATE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-home-audit-v8-20261119-v1/observer170-v1-evidence";
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
const BINS: [(&str, &str, &str, u64); 2] = [
    (
        "prepare_join",
        "prepare_observe170_homeaudit_join",
        "584ee70bbd3c0c3754b3d2e0a1e7cca61ef0fae96769607693083990c6efa39a",
        10,
    ),
    (
        "cycle",
        "observe_cycle_retry8_homeaudit170",
        "edbe03085a7021f4db60d59f7dd7e6ef0f6a6b265fd58e7602d03e83a7880f39",
        17,
    ),
];
const PHASES: [(&str, &str, &str); 3] = [
    (
        "tests",
        "1f7e7781b3064021b49fd41d9e6ab9a5",
        "f7e43a73f2940ccb3f69fe6c83bd7f93ba69a5c6a39e6d22caea89dfb71c2a92",
    ),
    (
        "clippy",
        "d1a37ede56994b83a8216ad3c5ab1842",
        "73c8f77cbdb228b40401fe24fc6711fef9b143ca147888198751ae18212b21a7",
    ),
    (
        "production",
        "723e150c09bd42828ffe14cbc0597d54",
        "f08bcc7965e2f4b2de7341e1cf5ad971a414fa7b1b81f1a469bc17b99ee25dab",
    ),
];
fn unit(phase: &str) -> String {
    format!("horizon-170-observerjoin-{phase}-20261119-v2.service")
}
fn log_path(phase: &str) -> String {
    format!("/home/sol/.jetstreamer-private/epoch170-observerjoin-{phase}-20261119-v2.log")
}
fn image(bin: &str) -> String {
    format!("{REPO}/{TARGET}/release/{bin}")
}
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .with_context(|| format!("missing string {key}"))
}
fn exact_keys(value: &Value, keys: &[&str]) -> Result<()> {
    let object = value.as_object().context("object required")?;
    ensure!(
        object.len() == keys.len() && keys.iter().all(|k| object.contains_key(*k)),
        "unexpected/missing fields"
    );
    Ok(())
}
fn input_shape(value: &Value) -> Result<()> {
    exact_keys(
        value,
        &["schema", "build_source_commit", "production", "executions"],
    )?;
    ensure!(
        value["schema"] == "horizon-observer170-home-deployment-input-v1"
            && value["build_source_commit"] == COMMIT,
        "unqualified source/input"
    );
    exact_keys(&value["production"], &["prepare_join", "cycle"])?;
    for (key, bin, hash, _) in BINS {
        exact_keys(&value["production"][key], &["path", "sha256"])?;
        ensure!(
            value["production"][key]["path"] == image(bin)
                && value["production"][key]["sha256"] == hash,
            "unqualified {key} artifact"
        );
    }
    exact_keys(&value["executions"], &["tests", "clippy", "production"])?;
    for (phase, iid, hash) in PHASES {
        let row = &value["executions"][phase];
        exact_keys(row, &["unit", "invocation_id", "log"])?;
        exact_keys(&row["log"], &["path", "sha256"])?;
        ensure!(
            row["unit"] == unit(phase)
                && row["invocation_id"] == iid
                && row["log"]["path"] == log_path(phase)
                && row["log"]["sha256"] == hash,
            "unqualified {phase} execution"
        );
    }
    Ok(())
}
fn identity(m: &fs::Metadata) -> [u64; 10] {
    [
        m.dev(),
        m.ino(),
        m.uid().into(),
        m.mode().into(),
        m.nlink(),
        m.len(),
        m.mtime() as u64,
        m.mtime_nsec() as u64,
        m.ctime() as u64,
        m.ctime_nsec() as u64,
    ]
}
fn bytes(path: &Path, limit: u64, root_owned: bool) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical input: {}",
        path.display()
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.len() <= limit
            && (!root_owned || (m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o022 == 0)),
        "unsafe or oversized input"
    );
    let mut b = Vec::new();
    Read::by_ref(&mut f).take(limit + 1).read_to_end(&mut b)?;
    ensure!(
        b.len() as u64 == m.len()
            && identity(&m) == identity(&f.metadata()?)
            && identity(&m) == identity(&fs::symlink_metadata(path)?),
        "input changed while reading"
    );
    Ok(b)
}
fn binding(path: &Path, raw: &[u8]) -> Value {
    json!({"path":path,"sha256":sha(raw)})
}
fn run(command: &mut Command) -> Result<String> {
    let result = command.output()?;
    ensure!(
        result.status.success() && result.stdout.len() <= 16 << 20,
        "command failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(String::from_utf8(result.stdout)?)
}
fn git(args: &[&str]) -> Result<String> {
    run(Command::new("git")
        .args(["-c", &format!("safe.directory={REPO}"), "-C", REPO])
        .args(args))
}
fn properties(raw: &str) -> Result<Value> {
    ensure!(raw.len() <= 64 << 10, "oversized native metadata");
    let mut map = serde_json::Map::new();
    for line in raw.lines() {
        let (k, v) = line.split_once('=').context("native property")?;
        ensure!(
            map.insert(k.into(), json!(v)).is_none(),
            "duplicate native property"
        );
    }
    Ok(Value::Object(map))
}
fn native(phase: &str) -> Result<String> {
    run(Command::new("/usr/bin/systemctl").args(["show",&unit(phase),"-pId,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,Result,ExecMainStatus,ExecStart,User,Group,WorkingDirectory,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,Environment,StandardOutput,StandardError,RemainAfterExit,FragmentPath,DropInPaths,Transient"]))
}
fn expected_argv(phase: &str) -> Result<Vec<String>> {
    let verb = match phase {
        "tests" => "test",
        "clippy" => "clippy",
        "production" => "build",
        _ => anyhow::bail!("unknown phase"),
    };
    let mut args = [
        "/home/sol/.cargo/bin/cargo",
        verb,
        "--manifest-path",
        &format!("{PACKAGE}/Cargo.toml"),
        "--bin",
        BINS[0].1,
        "--bin",
        BINS[1].1,
        "--release",
        "--offline",
        "--locked",
        "--jobs",
        "2",
        "--target-dir",
        TARGET,
    ]
    .map(str::to_owned)
    .to_vec();
    if phase == "clippy" {
        args.extend(["--", "-D", "warnings"].map(str::to_owned));
    }
    Ok(args)
}
fn qualified_command(command: &str, phase: &str) -> Result<()> {
    ensure!(
        command.starts_with("{ path=/home/sol/.cargo/bin/cargo ; ")
            && command.matches("argv[]=").count() == 1
            && command.trim_end().ends_with('}'),
        "one direct Cargo command required"
    );
    let argv = command
        .split_once("argv[]=")
        .context("argv")?
        .1
        .split_once(" ;")
        .context("argv end")?
        .0;
    let actual: Vec<_> = argv.split_whitespace().collect();
    ensure!(
        actual == expected_argv(phase)?,
        "qualification command is changed/filtered"
    );
    Ok(())
}
fn native_shape(v: &Value, phase: &str, iid: &str) -> Result<()> {
    for (key, expected) in [
        ("Id", unit(phase)),
        ("InvocationID", iid.into()),
        ("LoadState", "loaded".into()),
        ("ActiveState", "active".into()),
        ("SubState", "exited".into()),
        ("MainPID", "0".into()),
        ("ControlPID", "0".into()),
        ("Result", "success".into()),
        ("ExecMainStatus", "0".into()),
        ("RemainAfterExit", "yes".into()),
        ("User", "sol".into()),
        ("Group", "".into()),
        ("WorkingDirectory", REPO.into()),
        ("MemoryMax", "2147483648".into()),
        ("MemorySwapMax", "0".into()),
        ("CPUQuotaPerSecUSec", "2s".into()),
        ("TasksMax", "256".into()),
        ("StandardOutput", "append".into()),
        ("StandardError", "append".into()),
        ("Transient", "yes".into()),
        ("DropInPaths", "".into()),
        (
            "FragmentPath",
            format!("/run/systemd/transient/{}", unit(phase)),
        ),
    ] {
        ensure!(v[key] == expected, "native {phase} {key} differs");
    }
    qualified_command(text(v, "ExecStart")?, phase)?;
    let mut env = text(v, "Environment")?
        .split_whitespace()
        .collect::<Vec<_>>();
    env.sort_unstable();
    let mut expected = vec![
        "TMPDIR=/home/sol/.jetstreamer-private/epoch170-home-v8-build-tmp",
        "RUSTUP_HOME=/home/sol/.rustup",
        "RUSTUP_TOOLCHAIN=1.98.0",
    ];
    expected.sort_unstable();
    ensure!(
        env == expected,
        "unqualified build environment or Rust flags"
    );
    Ok(())
}
fn fragment_shape(fragment: &str, phase: &str) -> Result<()> {
    ensure!(
        fragment.len() <= 64 << 10 && !fragment.contains("\\\n"),
        "unbounded/continued unit definition"
    );
    let mut section = "";
    let mut outputs = Vec::new();
    let mut errors = Vec::new();
    for line in fragment.lines().map(str::trim) {
        if line.starts_with('[') {
            section = line;
        }
        if section == "[Service]" {
            if let Some(v) = line.strip_prefix("StandardOutput=") {
                outputs.push(v);
            }
            if let Some(v) = line.strip_prefix("StandardError=") {
                errors.push(v);
            }
        }
    }
    let expected = format!("append:{}", log_path(phase));
    ensure!(
        outputs == [expected.as_str()] && errors == [expected.as_str()],
        "native append log paths differ"
    );
    Ok(())
}
fn test_counts(log: &str) -> Result<Value> {
    ensure!(log.len() <= 1 << 20, "oversized test log");
    let mut pending = None;
    let mut seen = BTreeMap::new();
    for line in log.lines().map(str::trim) {
        if line.starts_with("Running unittests ") {
            ensure!(pending.is_none(), "missing prior test summary");
            let mut found = None;
            for (key, bin, _, count) in BINS {
                let prefix =
                    format!("Running unittests src/bin/{bin}.rs ({TARGET}/release/deps/{bin}-");
                if let Some(suffix) = line.strip_prefix(&prefix).and_then(|v| v.strip_suffix(')')) {
                    ensure!(
                        suffix.len() == 16 && suffix.bytes().all(|b| b.is_ascii_hexdigit()),
                        "unexpected test artifact"
                    );
                    found = Some((key, count));
                }
            }
            pending = Some(found.context("foreign test binary")?);
        }
        if line.starts_with("test result:") {
            let (key, count) = pending.take().context("unbound/duplicate test summary")?;
            let expected = format!(
                "test result: ok. {count} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;"
            );
            ensure!(
                line.strip_prefix(&expected)
                    .is_some_and(|v| v.is_empty() || v.starts_with(" finished in "))
                    && seen.insert(key, count).is_none(),
                "incomplete/duplicate test suite"
            );
        }
    }
    ensure!(
        pending.is_none()
            && seen.len() == 2
            && seen.get("prepare_join") == Some(&10)
            && seen.get("cycle") == Some(&17),
        "both complete suites required"
    );
    Ok(json!(seen))
}
fn home(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && fs::metadata(path)?.dev() == fs::metadata("/home/sol")?.dev(),
        "path not on HOME"
    );
    Ok(())
}
fn source_closure() -> Vec<(String, String)> {
    let mut result = [
        (
            "src/bin/prepare_observe170_homeaudit_join.rs",
            "source-prepare-join.rs",
        ),
        (
            "src/bin/observe_cycle_retry8_homeaudit170.rs",
            "source-cycle.rs",
        ),
        ("src/observer170_join.rs", "source-observer170_join.rs"),
        ("Cargo.toml", "source-Cargo.toml"),
        ("Cargo.lock", "source-Cargo.lock"),
    ]
    .into_iter()
    .map(|(path, name)| (format!("{PACKAGE}/{path}"), name.into()))
    .collect::<Vec<_>>();
    result.push((
        "scripts/horizon_retry6_170_guarded_launch_20261119_v1/src/audit_budget.rs".into(),
        "source-audit_budget.rs".into(),
    ));
    result
}
fn save(name: &str, raw: &[u8]) -> Result<Value> {
    ensure!(
        !name.is_empty() && !name.contains('/') && name != "." && name != "..",
        "leaf required"
    );
    let path = Path::new(STATE).join(name);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    f.write_all(raw)?;
    f.sync_all()?;
    File::open(STATE)?.sync_all()?;
    Ok(binding(&path, raw))
}
fn member(v: &Value, name: &str, mode: u32) -> Value {
    json!({"source":v["path"],"name":name,"sha256":v["sha256"],"mode":mode})
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        unsafe { libc::geteuid() } == 0 && args.len() == 4 && args[2] == "--input-sha256",
        "Root required: deploy_observer170_home_v1 INPUT --input-sha256 SHA"
    );
    let input_bytes = bytes(Path::new(&args[1]), 64 << 10, true)?;
    ensure!(sha(&input_bytes) == args[3], "input digest differs");
    let input: Value = serde_json::from_slice(&input_bytes)?;
    input_shape(&input)?;
    let commit = git(&["rev-parse", "HEAD"])?;
    for source in [COMMIT, commit.trim()] {
        git(&[
            "merge-base",
            "--is-ancestor",
            source,
            "origin/account-updates",
        ])?;
    }
    let own = bytes(&Path::new(REPO).join(OWN), 1 << 20, false)?;
    ensure!(
        own.as_slice() == include_bytes!("deploy_observer170_home_v1.rs")
            && git(&["show", &format!("HEAD:{OWN}")])?.as_bytes() == own,
        "helper is not the published compiled source"
    );
    let mut sources = Vec::new();
    let mut staged: Vec<(String, Vec<u8>)> = Vec::new();
    for (relative, name) in source_closure() {
        let path = Path::new(REPO).join(&relative);
        let raw = bytes(&path, 2 << 20, false)?;
        ensure!(
            git(&["show", &format!("HEAD:{relative}")])?.as_bytes() == raw
                && git(&["show", &format!("{COMMIT}:{relative}")])?.as_bytes() == raw,
            "source differs from exact qualified/published closure"
        );
        sources.push(json!({"original":binding(&path,&raw),"sealed_member":name}));
        staged.push((name, raw));
    }
    let mut productions = serde_json::Map::new();
    for (key, bin, hash, _) in BINS {
        let path = image(bin);
        home(Path::new(&path))?;
        let raw = bytes(Path::new(&path), 64 << 20, false)?;
        ensure!(sha(&raw) == hash, "qualified production changed");
        productions.insert(key.into(), binding(Path::new(&path), &raw));
    }
    let mut executions = serde_json::Map::new();
    let mut counts = Value::Null;
    for (phase, iid, hash) in PHASES {
        let raw = native(phase)?;
        let parsed = properties(&raw)?;
        native_shape(&parsed, phase, iid)?;
        let fragment_path = Path::new(text(&parsed, "FragmentPath")?);
        let fragment = bytes(fragment_path, 64 << 10, true)?;
        fragment_shape(std::str::from_utf8(&fragment)?, phase)?;
        let log = log_path(phase);
        home(Path::new(&log))?;
        let log_bytes = bytes(Path::new(&log), 1 << 20, true)?;
        ensure!(sha(&log_bytes) == hash, "qualified append log changed");
        if phase == "tests" {
            counts = test_counts(std::str::from_utf8(&log_bytes)?)?;
        }
        ensure!(
            native(phase)? == raw
                && bytes(fragment_path, 64 << 10, true)? == fragment
                && bytes(Path::new(&log), 1 << 20, true)? == log_bytes,
            "native qualification changed during capture"
        );
        executions.insert(phase.into(),json!({"unit":unit(phase),"invocation_id":iid,"native_member":format!("{phase}-native.txt"),
            "native_sha256":sha(raw.as_bytes()),"fragment_original":binding(fragment_path,&fragment),"fragment_member":format!("{phase}-unit.service"),
            "log_original":binding(Path::new(&log),&log_bytes),"log_member":format!("{phase}.log"),"native_append_paths_verified":true,"success":true}));
        staged.extend([
            (format!("{phase}-native.txt"), raw.into_bytes()),
            (format!("{phase}-unit.service"), fragment),
            (format!("{phase}.log"), log_bytes),
        ]);
    }
    home(Path::new(BASE))?;
    let parent = fs::symlink_metadata(BASE)?;
    ensure!(
        parent.is_dir() && parent.uid() == 0 && parent.mode() & 0o022 == 0,
        "unsafe deployment parent"
    );
    ensure!(
        !Path::new(DEST).try_exists()? && !Path::new(STATE).try_exists()?,
        "deployment/evidence already exists"
    );
    ensure!(
        sha(&bytes(Path::new(SEALER), 64 << 20, true)?) == SEALER_SHA,
        "normal sealer differs"
    );
    fs::DirBuilder::new().mode(0o700).create(STATE)?;
    home(Path::new(STATE))?;
    staged.push(("qualification-input.json".into(), input_bytes));
    staged.push(("source-deploy-helper.rs".into(), own));
    let mut members = Vec::new();
    let mut evidence = Vec::new();
    for (name, raw) in staged {
        let saved = save(&name, &raw)?;
        members.push(member(&saved, &name, 0o444));
        evidence.push(json!({"member":name,"sha256":saved["sha256"]}));
    }
    for (key, bin, hash, _) in BINS {
        ensure!(
            sha(&bytes(Path::new(&image(bin)), 64 << 20, false)?) == hash,
            "production changed before seal"
        );
        members.push(member(
            &productions[key],
            if key == "prepare_join" {
                "prepare-join"
            } else {
                "cycle"
            },
            0o555,
        ));
    }
    let proof = json!({"schema":"horizon-observer170-home-build-proof-v1","owner":"/root","source_commit":commit.trim(),"equivalent_build_source_commit":COMMIT,
        "source_contained_in_origin_account_updates":true,"entire_source_closure_equivalent":true,"source_members":sources,"sealed_evidence":evidence,
        "production":productions,"runtime":{"prepare_join":format!("{DEST}/prepare-join"),"cycle":format!("{DEST}/cycle")},
        "tests_by_binary":counts,"tests_passed":27,"tests_failed":0,"tests_ignored":0,"tests_filtered_out":0,"production_clippy_passed":true,
        "executions":executions,"features":[],"home_storage_required":true,"replay_launch_authorized":false,"admission_authority":false,
        "timer_mutations":false,"remote_mutations":false,"resource_credit_bytes":0,"promise_ending_bytes":0});
    let proof_binding = save("artifact-proof.json", &serde_json::to_vec_pretty(&proof)?)?;
    members.push(member(&proof_binding, "artifact-proof.json", 0o444));
    let plan = save(
        "seal-plan.json",
        &serde_json::to_vec_pretty(
            &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":DEST,"members":members}),
        )?,
    )?;
    let mut sealer = Command::new(SEALER);
    sealer.args([
        text(&plan, "path")?,
        "--plan-sha256",
        text(&plan, "sha256")?,
        "--self-sha256",
        SEALER_SHA,
    ]);
    // Scope the deployed sealer's required umask to its child, preserving private evidence modes.
    unsafe {
        sealer.pre_exec(|| {
            libc::umask(0o022);
            Ok(())
        });
    }
    run(&mut sealer)?;
    home(Path::new(DEST))?;
    for (key, _, hash, _) in BINS {
        let path = Path::new(DEST).join(if key == "prepare_join" {
            "prepare-join"
        } else {
            "cycle"
        });
        ensure!(
            sha(&bytes(&path, 64 << 20, true)?) == hash,
            "sealed runtime differs"
        );
    }
    println!(
        "{}",
        json!({"runtime_directory":DEST,"proof":binding(&Path::new(DEST).join("artifact-proof.json"),&bytes(&Path::new(DEST).join("artifact-proof.json"),2<<20,true)?),
        "replay_launch_authorized":false,"admission_authority":false,"timer_mutations":false,"remote_mutations":false})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Value {
        let mut production = serde_json::Map::new();
        for (key, bin, hash, _) in BINS {
            production.insert(key.into(), json!({"path":image(bin),"sha256":hash}));
        }
        let mut executions = serde_json::Map::new();
        for (phase, iid, hash) in PHASES {
            executions.insert(phase.into(),json!({"unit":unit(phase),"invocation_id":iid,"log":{"path":log_path(phase),"sha256":hash}}));
        }
        json!({"schema":"horizon-observer170-home-deployment-input-v1","build_source_commit":COMMIT,"production":production,"executions":executions})
    }
    #[test]
    fn input_rejects_missing_extra_substituted_or_reused_identity() {
        let good = fixture();
        input_shape(&good).unwrap();
        for pointer in [
            "/build_source_commit",
            "/production/cycle/sha256",
            "/executions/tests/invocation_id",
            "/executions/clippy/log/path",
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = json!("wrong");
            assert!(input_shape(&bad).is_err());
        }
        let mut bad = good.clone();
        bad["extra"] = json!(true);
        assert!(input_shape(&bad).is_err());
        let mut bad = good.clone();
        bad.as_object_mut().unwrap().remove("executions");
        assert!(input_shape(&bad).is_err());
        let mut bad = good.clone();
        bad["executions"]["production"] = good["executions"]["tests"].clone();
        assert!(input_shape(&bad).is_err());
    }
    #[test]
    fn command_requires_both_bins_exact_flags_and_strict_clippy() {
        for phase in ["tests", "clippy", "production"] {
            let command = format!(
                "{{ path=/home/sol/.cargo/bin/cargo ; argv[]={} ; ignore_errors=no ; code=exited ; status=0 }}",
                expected_argv(phase).unwrap().join(" ")
            );
            qualified_command(&command, phase).unwrap();
            for bad in [
                command.replace("--offline ", ""),
                command.replace("--jobs 2", "--jobs 3"),
                command.replace("--release", "--release --features altered"),
                command.replace(" --locked", " --locked -- --skip skipped"),
                command.replace("--bin prepare_observe170_homeaudit_join ", ""),
            ] {
                assert!(qualified_command(&bad, phase).is_err());
            }
            if phase == "clippy" {
                assert!(qualified_command(&command.replace(" -- -D warnings", ""), phase).is_err());
            }
        }
    }
    fn full_log() -> String {
        BINS.into_iter().map(|(_,bin,_,count)|format!("Running unittests src/bin/{bin}.rs ({TARGET}/release/deps/{bin}-1234567890abcdef)\ntest result: ok. {count} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n")).collect()
    }
    #[test]
    fn counts_are_bound_to_both_complete_binary_sections() {
        let good = full_log();
        let counts = test_counts(&good).unwrap();
        assert_eq!(counts["prepare_join"], 10);
        assert_eq!(counts["cycle"], 17);
        for bad in [
            good.replace("17 passed", "16 passed"),
            good.replace("0 ignored", "1 ignored"),
            good.replace("0 filtered out", "1 filtered out"),
            format!("{good}{good}"),
            good.replace(
                "src/bin/observe_cycle_retry8_homeaudit170.rs",
                "src/bin/unrelated.rs",
            ),
            "test result: ok. 27 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;".into(),
        ] {
            assert!(test_counts(&bad).is_err());
        }
    }
    #[test]
    fn append_paths_require_one_exact_service_assignment_each() {
        let good = format!(
            "[Service]\nStandardOutput=append:{}\nStandardError=append:{}\n",
            log_path("tests"),
            log_path("tests")
        );
        fragment_shape(&good, "tests").unwrap();
        for bad in [
            good.replace("StandardError=append:", "StandardError=file:"),
            good.replace("observerjoin-tests", "observerjoin-clippy"),
            format!("{good}StandardOutput=journal\n"),
            good.replace("[Service]", "[Unit]"),
        ] {
            assert!(fragment_shape(&bad, "tests").is_err());
        }
    }
}
