//! Cargo rustc-wrapper for a source-bound, compiler-free command capture.
//!
//! This program NEVER launches rustc, Cargo, a build script, a linker, or another
//! process. It returns only two exact, previously recorded metadata responses.
//! Every other argv is durably captured and fails with exit 86 before compilation.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

type R<T> = Result<T, Box<dyn std::error::Error>>;
const IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-uploader-cargo-intercept-tools-20261110-v1/wrapper";
const RUSTC: &str = "/home/sol/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/rustc";
const CARGO: &str = "/home/sol/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/cargo";
const ROOT: &str = "/home/sol/workspace/jetstreamer";
const SOURCE: &str = "/home/sol/workspace/jetstreamer/jetstreamer-r2/src/main.rs";
const SOURCE_SHA: &str = "4f008782bb85eaebbf93f1a66f5ccf7eb207918065e388642c39ad51fa9d275d";
const NOFOLLOW: i32 = 0x20000;
const CLOEXEC: i32 = 0x80000;
const MAX_RECORDS: usize = 64;
const MAX_LOG_BYTES: u64 = 4 << 20;

fn need(ok: bool, why: &str) -> R<()> {
    if ok { Ok(()) } else { Err(why.into()) }
}
fn s<'a>(v: &'a Value, key: &str) -> R<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| format!("missing string {key}").into())
}
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn identity(m: &fs::Metadata) -> Value {
    json!([
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec()
    ])
}
fn read_stable(path: &Path, cap: u64, root_owned: bool) -> R<Vec<u8>> {
    need(
        path.is_absolute() && path.canonicalize()? == path,
        "canonical absolute file required",
    )?;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(NOFOLLOW | CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    need(
        m.is_file() && m.nlink() == 1 && m.mode() & 0o022 == 0 && m.len() <= cap,
        "unsafe or oversized input",
    )?;
    if root_owned {
        need(m.uid() == 0, "Root-owned sealed file required")?;
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut f).take(cap + 1).read_to_end(&mut bytes)?;
    need(
        bytes.len() as u64 == m.len()
            && identity(&m) == identity(&f.metadata()?)
            && identity(&m) == identity(&fs::symlink_metadata(path)?),
        "input changed during read",
    )?;
    Ok(bytes)
}
fn strings(v: &Value) -> R<Vec<String>> {
    v.as_array()
        .ok_or("argument array required")?
        .iter()
        .map(|x| {
            let x = x.as_str().ok_or("UTF-8 string argument required")?;
            need(x.len() <= 60_000 && !x.contains('\0'), "invalid argument")?;
            Ok(x.to_owned())
        })
        .collect()
}
fn print_argv() -> Vec<String> {
    [
        "-",
        "--crate-name",
        "___",
        "--print=file-names",
        "--crate-type",
        "bin",
        "--crate-type",
        "rlib",
        "--crate-type",
        "dylib",
        "--crate-type",
        "cdylib",
        "--crate-type",
        "staticlib",
        "--crate-type",
        "proc-macro",
        "--print=sysroot",
        "--print=split-debuginfo",
        "--print=crate-name",
        "--print=cfg",
        "-Wwarnings",
    ]
    .iter()
    .map(|x| (*x).to_owned())
    .collect()
}
fn probe_name(argv: &[String]) -> Option<&'static str> {
    if argv == ["-vV"] {
        Some("version-verbose")
    } else if argv == print_argv() {
        Some("cargo-native-target-metadata")
    } else {
        None
    }
}
fn validate_plan(v: &Value) -> R<()> {
    need(
        v["schema"] == "horizon-uploader-cargo-intercept-plan-v1"
            && v["owner"] == "/root"
            && v["primary_thread"] == "01a1af2a-9ce8-76a2-8939-b2112bd38f53"
            && v["compiler_execution_authorized"] == false
            && v["build_script_execution_authorized"] == false
            && v["replay_admission_authorized"] == false
            && v["working_directory"] == ROOT
            && v["source"]["path"] == SOURCE
            && v["source"]["sha256"] == SOURCE_SHA
            && v["rustc"]["path"] == RUSTC
            && v["cargo"]["path"] == CARGO,
        "exact source-bound no-compiler plan required",
    )?;
    let rows = v["probe_responses"]
        .as_array()
        .ok_or("two exact probe responses required")?;
    need(rows.len() == 2, "exactly two probe responses required")?;
    let mut seen = std::collections::BTreeSet::new();
    for row in rows {
        let args = strings(&row["argv"])?;
        let name = probe_name(&args).ok_or("plan attempts to permit a non-probe argv")?;
        need(
            row["name"] == name && seen.insert(name),
            "duplicate or misnamed probe",
        )?;
        let out = s(row, "stdout")?;
        need(
            out.len() <= 16_384
                && sha(out.as_bytes()) == s(row, "stdout_sha256")?
                && s(row, "stdin_sha256")?.len() == 64,
            "probe output digest/bound mismatch",
        )?;
        if name == "version-verbose" {
            need(
                out.starts_with("rustc 1.98.0 (88d9e12ae 2026-08-18)\n")
                    && out.contains("commit-hash: 88d9e12ae178fab0fb5cc050a94da85685d449ea\n")
                    && out.contains("host: x86_64-unknown-linux-gnu\n")
                    && out.ends_with("LLVM version: 22.1.8\n")
                    && row["stdin_sha256"] == sha(b""),
                "wrong compiler version response",
            )?;
        }
    }
    Ok(())
}
fn selected_environment(get: impl Fn(&str) -> Option<String>) -> BTreeMap<String, String> {
    [
        "CARGO",
        "RUSTC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_HOME",
        "CARGO_TARGET_DIR",
        "CARGO_BUILD_TARGET",
        "CARGO_MANIFEST_DIR",
        "CARGO_MANIFEST_PATH",
        "CARGO_PKG_NAME",
        "CARGO_PKG_VERSION",
        "CARGO_CRATE_NAME",
        "CARGO_PRIMARY_PACKAGE",
        "PROFILE",
        "OPT_LEVEL",
        "DEBUG",
        "HOST",
        "TARGET",
        "RUST_MIN_STACK",
        "LANG",
        "LC_ALL",
        "PATH",
        "LD_LIBRARY_PATH",
    ]
    .iter()
    .filter_map(|k| get(k).map(|v| ((*k).to_owned(), v)))
    .collect()
}
fn check_environment(v: &BTreeMap<String, String>) -> R<()> {
    for k in [
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_TARGET",
    ] {
        need(
            v.get(k).is_none_or(String::is_empty),
            "inherited wrapper/rustflags/target forbidden",
        )?;
    }
    for (key, value) in [
        ("RUSTC_WRAPPER", IMAGE),
        ("RUSTC", RUSTC),
        ("CARGO_HOME", "/home/sol/.cargo"),
        ("CARGO_TARGET_DIR", "/home/sol/workspace/jetstreamer/target"),
    ] {
        need(
            v.get(key).is_some_and(|s| s == value),
            "exact Cargo environment binding required",
        )?;
    }
    if let Some(value) = v.get("CARGO") {
        need(value == CARGO, "wrong Cargo executable")?;
    }
    if let Some(value) = v.get("CARGO_MANIFEST_DIR") {
        need(
            value == "/home/sol/workspace/jetstreamer/jetstreamer-r2",
            "only original uploader package may be captured",
        )?;
    }
    Ok(())
}
fn choose_response<'a>(plan: &'a Value, args: &[String], stdin: &[u8]) -> R<Option<&'a str>> {
    let Some(name) = probe_name(args) else {
        return Ok(None);
    };
    let row = plan["probe_responses"]
        .as_array()
        .ok_or("probe responses")?
        .iter()
        .find(|r| r["name"] == name)
        .ok_or("probe response absent")?;
    need(
        strings(&row["argv"])? == args && row["stdin_sha256"] == sha(stdin),
        "probe stdin or exact argv changed",
    )?;
    Ok(Some(s(row, "stdout")?))
}
fn durable(parent: &Path, value: &Value) -> R<()> {
    need(
        parent.is_absolute() && parent.canonicalize()? == parent,
        "canonical receipt directory required",
    )?;
    let m = fs::symlink_metadata(parent)?;
    need(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "Root-private receipt directory required",
    )?;
    let mut count = 0usize;
    let mut bytes = 0u64;
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let md = fs::symlink_metadata(entry.path())?;
        need(
            md.is_file() && md.uid() == 0 && md.nlink() == 1 && md.mode() & 0o077 == 0,
            "unexpected capture-directory member",
        )?;
        count += 1;
        bytes = bytes.checked_add(md.len()).ok_or("log sum overflow")?;
    }
    let raw = serde_json::to_vec_pretty(value)?;
    need(
        raw.len() <= 65_535
            && count < MAX_RECORDS
            && bytes
                .checked_add(raw.len() as u64 + 1)
                .is_some_and(|n| n <= MAX_LOG_BYTES),
        "finite capture log allowance exceeded",
    )?;
    let path = parent.join(format!("rustc-wrapper-{}.json", std::process::id()));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(NOFOLLOW | CLOEXEC)
        .open(path)?;
    f.write_all(&raw)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn run() -> R<i32> {
    let image = fs::read_link("/proc/self/exe")?;
    need(
        image == Path::new(IMAGE),
        "exact normally sealed wrapper required",
    )?;
    let self_sha = std::env::var("HORIZON_INTERCEPT_SELF_SHA256")?;
    need(
        sha(&read_stable(&image, 32 << 20, true)?) == self_sha,
        "wrapper digest mismatch",
    )?;
    let plan_path = PathBuf::from(std::env::var("HORIZON_INTERCEPT_PLAN")?);
    let plan_bytes = read_stable(&plan_path, 64 << 10, true)?;
    let plan_sha = std::env::var("HORIZON_INTERCEPT_PLAN_SHA256")?;
    need(sha(&plan_bytes) == plan_sha, "plan digest mismatch")?;
    let plan: Value = serde_json::from_slice(&plan_bytes)?;
    validate_plan(&plan)?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    need(
        (2..=256).contains(&args.len())
            && args[0] == RUSTC
            && args.iter().map(|s| s.len() + 1).sum::<usize>() <= 60_000,
        "bounded exact rustc-wrapper ABI required",
    )?;
    for (key, cap) in [
        ("rustc", 64 << 20),
        ("cargo", 64 << 20),
        ("source", 1 << 20),
    ] {
        let bytes = read_stable(Path::new(s(&plan[key], "path")?), cap, key == "source")?;
        need(
            sha(&bytes) == s(&plan[key], "sha256")?,
            "source/toolchain digest changed",
        )?;
    }
    need(
        std::env::current_dir()? == Path::new(ROOT),
        "original absolute working directory required",
    )?;
    let environment = selected_environment(|k| std::env::var(k).ok());
    check_environment(&environment)?;
    let call = &args[1..];
    let mut input = Vec::new();
    if probe_name(call) == Some("cargo-native-target-metadata") {
        std::io::stdin().take(4097).read_to_end(&mut input)?;
        need(input.len() <= 4096, "metadata stdin exceeds bound")?;
    }
    let response = choose_response(&plan, call, &input)?;
    let report = json!({"schema":"horizon-uploader-cargo-intercept-invocation-v1", "owner":"/root",
        "pid":std::process::id(), "invocation_id":std::env::var("INVOCATION_ID").ok(),
        "plan":{"path":plan_path,"sha256":plan_sha}, "self_sha256":self_sha,
        "source":plan["source"], "rustc":plan["rustc"], "cargo":plan["cargo"],
        "working_directory":ROOT, "argv":args, "selected_environment":environment,
        "stdin_sha256":sha(&input), "pre_recorded_probe_response":response.is_some(),
        "compiler_invoked":false, "build_script_invoked":false, "linker_invoked":false,
        "compile_denied_before_execution":response.is_none(), "exit_code":if response.is_some(){0}else{86},
        "new_memory_promise_bytes":0,"artifact_provenance_qualified":false,"replay_admission_authorized":false});
    durable(Path::new(s(&plan, "receipt_directory")?), &report)?;
    if let Some(out) = response {
        std::io::stdout().write_all(out.as_bytes())?;
        Ok(0)
    } else {
        eprintln!(
            "HORIZON_COMPILER_INTERCEPTED: argv captured; no compiler, build script or linker was executed"
        );
        Ok(86)
    }
}
fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("intercept rejected: {error}");
            std::process::exit(87);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> Value {
        let version = "rustc 1.98.0 (88d9e12ae 2026-08-18)\nbinary: rustc\ncommit-hash: 88d9e12ae178fab0fb5cc050a94da85685d449ea\nhost: x86_64-unknown-linux-gnu\nLLVM version: 22.1.8\n";
        json!({"schema":"horizon-uploader-cargo-intercept-plan-v1","owner":"/root",
            "primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53","working_directory":ROOT,
            "source":{"path":SOURCE,"sha256":SOURCE_SHA},"rustc":{"path":RUSTC},"cargo":{"path":CARGO},
            "compiler_execution_authorized":false,"build_script_execution_authorized":false,"replay_admission_authorized":false,
            "probe_responses":[{"name":"version-verbose","argv":["-vV"],"stdin_sha256":sha(b""),"stdout":version,"stdout_sha256":sha(version.as_bytes())},
                {"name":"cargo-native-target-metadata","argv":print_argv(),"stdin_sha256":sha(b""),"stdout":"fixture\n","stdout_sha256":sha(b"fixture\n")}]})
    }
    #[test]
    fn only_two_exact_metadata_queries_can_succeed() {
        assert_eq!(probe_name(&["-vV".into()]), Some("version-verbose"));
        assert_eq!(
            probe_name(&print_argv()),
            Some("cargo-native-target-metadata")
        );
        assert_eq!(probe_name(&["--version".into()]), None);
        assert_eq!(probe_name(&["-vV".into(), "--emit=link".into()]), None);
    }
    #[test]
    fn normal_uploader_compile_is_denied() {
        let a = [
            "--crate-name",
            "jetstreamer_r2",
            "--edition=2024",
            "jetstreamer-r2/src/main.rs",
            "--crate-type",
            "bin",
            "--emit=dep-info,link",
        ];
        assert!(
            choose_response(&plan(), &a.map(str::to_owned), b"")
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn dependency_build_script_and_metadata_compiles_are_denied() {
        for a in [
            [
                "--crate-name",
                "build_script_build",
                "build.rs",
                "--emit=link",
            ],
            ["--crate-name", "serde", "src/lib.rs", "--emit=metadata"],
        ] {
            assert!(
                choose_response(&plan(), &a.map(str::to_owned), b"")
                    .unwrap()
                    .is_none()
            );
        }
    }
    #[test]
    fn injected_codegen_or_response_file_cannot_extend_a_probe() {
        for extra in [
            "--emit=link",
            "-o",
            "@/tmp/args",
            "--extern=evil=/tmp/evil.so",
            "-Cllvm-args=x",
        ] {
            let mut a = print_argv();
            a.push(extra.into());
            assert_eq!(probe_name(&a), None);
        }
    }
    #[test]
    fn changed_print_order_or_target_is_not_accepted() {
        let mut a = print_argv();
        a.swap(3, 16);
        assert_eq!(probe_name(&a), None);
        a = print_argv();
        a.extend(["--target".into(), "wasm32-unknown-unknown".into()]);
        assert_eq!(probe_name(&a), None);
    }
    #[test]
    fn compiler_authority_cannot_be_added_by_plan() {
        let mut p = plan();
        assert!(validate_plan(&p).is_ok());
        p["compiler_execution_authorized"] = json!(true);
        assert!(validate_plan(&p).is_err());
    }
    #[test]
    fn forged_metadata_response_digest_is_rejected() {
        let mut p = plan();
        p["probe_responses"][0]["stdout"] = json!("forged");
        assert!(validate_plan(&p).is_err());
    }
    #[test]
    fn duplicate_probe_cannot_hide_compile_permissions() {
        let mut p = plan();
        p["probe_responses"][1] = p["probe_responses"][0].clone();
        assert!(validate_plan(&p).is_err());
        p = plan();
        p["probe_responses"][1]["argv"] = json!(["--emit=link"]);
        assert!(validate_plan(&p).is_err());
    }
    #[test]
    fn stdin_is_bound_even_for_print_only_queries() {
        assert!(choose_response(&plan(), &print_argv(), b"#![allow(warnings)]").is_err());
        assert_eq!(
            choose_response(&plan(), &print_argv(), b"").unwrap(),
            Some("fixture\n")
        );
    }
    fn clean_env() -> BTreeMap<String, String> {
        [
            ("RUSTC_WRAPPER", IMAGE),
            ("RUSTC", RUSTC),
            ("CARGO_HOME", "/home/sol/.cargo"),
            ("CARGO_TARGET_DIR", "/home/sol/workspace/jetstreamer/target"),
        ]
        .map(|(k, v)| (k.into(), v.into()))
        .into()
    }
    #[test]
    fn inherited_workspace_wrapper_and_encoded_flags_are_rejected() {
        for k in [
            "RUSTC_WORKSPACE_WRAPPER",
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_BUILD_TARGET",
        ] {
            let mut e = clean_env();
            assert!(check_environment(&e).is_ok());
            e.insert(k.into(), "injected".into());
            assert!(check_environment(&e).is_err());
        }
    }
    #[test]
    fn wrong_rustc_or_package_cannot_be_captured_as_uploader() {
        let mut e = clean_env();
        e.insert("RUSTC".into(), "/usr/bin/rustc".into());
        assert!(check_environment(&e).is_err());
        e = clean_env();
        e.insert("CARGO_MANIFEST_DIR".into(), "/tmp/other".into());
        assert!(check_environment(&e).is_err());
    }
    #[test]
    fn arbitrary_credentials_are_never_recorded() {
        let e = selected_environment(|k| Some(format!("value-for-{k}")));
        assert!(!e.contains_key("HORIZON_SECRET_ACCESS_KEY"));
        assert!(!e.contains_key("AWS_SECRET_ACCESS_KEY"));
        assert!(!e.contains_key("GOOGLE_APPLICATION_CREDENTIALS"));
        assert!(!e.contains_key("SSH_AUTH_SOCK"));
    }
}
