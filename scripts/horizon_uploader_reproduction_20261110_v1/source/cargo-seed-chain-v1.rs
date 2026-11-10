//! Same-process namespace seeding for a compiler-free Cargo capture.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
type R<T> = Result<T, Box<dyn std::error::Error>>;
const IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-uploader-cargo-seed-chain-tools-20261110-v1/chain";
const ROOT: &str = "/home/sol/workspace/jetstreamer";
const TARGET: &str = "/home/sol/workspace/jetstreamer/target";
const DEST: &str = "/home/sol/workspace/jetstreamer/target/release/.fingerprint";
const SOURCE: &str =
    "/var/lib/jetstreamer-builds/readback-progress-20261022-v1/release/.fingerprint";
const CARGO: &str = "/home/sol/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/cargo";
const WRAPPER: &str =
    "/usr/local/lib/jetstreamer/horizon-uploader-cargo-intercept-tools-20261110-v1/wrapper";
fn need(ok: bool, why: &str) -> R<()> {
    if ok { Ok(()) } else { Err(why.into()) }
}
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn s<'a>(v: &'a Value, k: &str) -> R<&'a str> {
    v[k].as_str().ok_or_else(|| format!("missing {k}").into())
}
fn identity(m: &fs::Metadata) -> Vec<u64> {
    vec![
        m.dev(),
        m.ino(),
        m.mode() as u64,
        m.uid() as u64,
        m.gid() as u64,
        m.nlink(),
        m.len(),
        m.mtime() as u64,
        m.mtime_nsec() as u64,
        m.ctime() as u64,
        m.ctime_nsec() as u64,
    ]
}
fn read(path: &Path, max: u64, root: bool) -> R<Vec<u8>> {
    need(
        path.is_absolute() && path.canonicalize()? == path,
        "canonical input",
    )?;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(0x20000 | 0x80000)
        .open(path)?;
    let m = f.metadata()?;
    need(
        m.is_file()
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.len() <= max
            && (!root || m.uid() == 0),
        "unsafe input",
    )?;
    let mut b = Vec::new();
    Read::by_ref(&mut f).take(max + 1).read_to_end(&mut b)?;
    need(
        b.len() as u64 == m.len()
            && identity(&m) == identity(&f.metadata()?)
            && identity(&m) == identity(&fs::symlink_metadata(path)?),
        "input changed",
    )?;
    Ok(b)
}
fn bound(v: &Value, max: u64, root: bool) -> R<Vec<u8>> {
    let b = read(Path::new(s(v, "path")?), max, root)?;
    need(sha(&b) == s(v, "sha256")?, "digest mismatch")?;
    Ok(b)
}
fn validate(v: &Value) -> R<()> {
    need(
        v["schema"] == "horizon-uploader-Cargo-same-namespace-seed-plan-v1"
            && v["owner"] == "/root"
            && v["primary_thread"] == "01a1af2a-9ce8-76a2-8939-b2112bd38f53"
            && v["source_fingerprints"] == SOURCE
            && v["destination_fingerprints"] == DEST
            && v["working_directory"] == ROOT
            && v["compiler_execution_authorized"] == false
            && v["build_script_execution_authorized"] == false
            && v["replay_admission_authorized"] == false
            && v["native_cap_bytes"] == 512u64 << 20
            && v["target_tmpfs_max_bytes"] == 96u64 << 20
            && v["cargo"]["path"] == CARGO
            && v["cp"]["path"] == "/usr/bin/cp"
            && v["wrapper"]["path"] == WRAPPER,
        "exact bounded capture plan",
    )?;
    let rows = v["sentinels"].as_array().ok_or("sentinels")?;
    need((2..=8).contains(&rows.len()), "bounded sentinels")?;
    let mut names = std::collections::BTreeSet::new();
    for row in rows {
        let r = s(row, "relative")?;
        need(
            !r.starts_with('/')
                && !r.split('/').any(|x| x.is_empty() || x == "." || x == "..")
                && names.insert(r),
            "unsafe or duplicate sentinel",
        )?;
        need(s(row, "sha256")?.len() == 64, "sentinel digest")?;
    }
    Ok(())
}
fn environment(get: impl Fn(&str) -> Option<String>) -> R<()> {
    for (k, v) in [
        ("RUSTC_WRAPPER", WRAPPER),
        ("CARGO_HOME", "/home/sol/.cargo"),
        ("CARGO_TARGET_DIR", TARGET),
    ] {
        need(get(k).as_deref() == Some(v), "capture environment differs")?;
    }
    for k in [
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_TARGET",
    ] {
        need(
            get(k).is_none_or(|v| v.is_empty()),
            "inherited compiler override",
        )?;
    }
    Ok(())
}
fn tmpfs(text: &str) -> bool {
    text.lines().any(|line| {
        let Some((a, b)) = line.split_once(" - ") else {
            return false;
        };
        let cols: Vec<_> = a.split_whitespace().collect();
        cols.len() >= 6
            && cols[4] == TARGET
            && cols[5].split(',').any(|x| x == "rw")
            && b.split_whitespace().next() == Some("tmpfs")
    })
}
fn run() -> R<()> {
    let a: Vec<_> = std::env::args().collect();
    need(
        a.len() == 6 && a[2] == "--plan-sha256" && a[4] == "--self-sha256",
        "exact argv",
    )?;
    need(
        fs::read_link("/proc/self/exe")? == Path::new(IMAGE)
            && sha(&read(Path::new(IMAGE), 32 << 20, true)?) == a[5],
        "normally sealed chain image",
    )?;
    let v: Value =
        serde_json::from_slice(&bound(&json!({"path":a[1],"sha256":a[3]}), 64 << 10, true)?)?;
    validate(&v)?;
    need(
        std::env::current_dir()? == Path::new(ROOT),
        "original cwd required",
    )?;
    environment(|k| std::env::var(k).ok())?;
    let iid = std::env::var("INVOCATION_ID")?;
    need(
        iid.len() == 32 && iid.bytes().all(|c| c.is_ascii_hexdigit()),
        "genuine invocation required",
    )?;
    need(
        tmpfs(&fs::read_to_string("/proc/self/mountinfo")?),
        "actual writable target tmpfs missing",
    )?;
    need(
        !Path::new(DEST).try_exists()? && fs::symlink_metadata(TARGET)?.uid() == 0,
        "new Root tmpfs destination required",
    )?;
    bound(&v["cargo"], 64 << 20, false)?;
    bound(&v["cp"], 4 << 20, true)?;
    bound(&v["wrapper"], 32 << 20, true)?;
    for row in v["sentinels"].as_array().unwrap() {
        let b = read(&Path::new(SOURCE).join(s(row, "relative")?), 1 << 20, false)?;
        need(sha(&b) == s(row, "sha256")?, "source sentinel changed")?;
    }
    eprintln!(
        "same-namespace fingerprint seed start iid={iid}; no compiler/buildscript execution authorized"
    );
    need(
        Command::new("/usr/bin/cp")
            .args(["-a", "--no-preserve=ownership", SOURCE, DEST])
            .status()?
            .success(),
        "bounded namespace copy failed",
    )?;
    for row in v["sentinels"].as_array().unwrap() {
        let rel = s(row, "relative")?;
        let b = read(&Path::new(DEST).join(rel), 1 << 20, true)?;
        need(
            sha(&b) == s(row, "sha256")?
                && b == read(&Path::new(SOURCE).join(rel), 1 << 20, false)?,
            "copy not present or changed in actual Cargo namespace",
        )?;
    }
    eprintln!("same-namespace fingerprint seed verified iid={iid}; exec compiler-free Cargo");
    let err = Command::new(CARGO)
        .args([
            "build",
            "--release",
            "-p",
            "jetstreamer-r2",
            "--bin",
            "jetstreamer-r2",
            "--offline",
            "--locked",
            "--jobs",
            "1",
            "--verbose",
        ])
        .exec();
    Err(err.into())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("same-namespace capture rejected: {e}");
        std::process::exit(88);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> Value {
        json!({"schema":"horizon-uploader-Cargo-same-namespace-seed-plan-v1","owner":"/root","primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53","source_fingerprints":SOURCE,"destination_fingerprints":DEST,"working_directory":ROOT,"compiler_execution_authorized":false,"build_script_execution_authorized":false,"replay_admission_authorized":false,"native_cap_bytes":512u64<<20,"target_tmpfs_max_bytes":96u64<<20,"cargo":{"path":CARGO},"cp":{"path":"/usr/bin/cp"},"wrapper":{"path":WRAPPER},"sentinels":[{"relative":"libc-1/lib-libc","sha256":"a".repeat(64)},{"relative":"anyhow-1/lib-anyhow","sha256":"b".repeat(64)}]})
    }
    #[test]
    fn only_exact_capture_purpose_is_allowed() {
        let mut v = plan();
        assert!(validate(&v).is_ok());
        v["compiler_execution_authorized"] = json!(true);
        assert!(validate(&v).is_err());
    }
    #[test]
    fn source_and_destination_cannot_escape() {
        for key in ["source_fingerprints", "destination_fingerprints"] {
            let mut v = plan();
            v[key] = json!("/tmp/unbound");
            assert!(validate(&v).is_err());
        }
    }
    #[test]
    fn sentinels_cannot_escape_or_duplicate() {
        for rel in ["../x", "/etc/passwd", "a//b", "a/./b"] {
            let mut v = plan();
            v["sentinels"][0]["relative"] = json!(rel);
            assert!(validate(&v).is_err());
        }
        let mut v = plan();
        v["sentinels"][1] = v["sentinels"][0].clone();
        assert!(validate(&v).is_err());
    }
    #[test]
    fn compiler_or_shell_cannot_replace_cargo() {
        let mut v = plan();
        v["cargo"]["path"] = json!("/bin/sh");
        assert!(validate(&v).is_err());
    }
    #[test]
    fn enlarged_or_zero_caps_are_rejected() {
        for n in [0, 8u64 << 30] {
            let mut v = plan();
            v["native_cap_bytes"] = json!(n);
            assert!(validate(&v).is_err());
        }
    }
    #[test]
    fn target_must_be_actual_writable_tmpfs() {
        let good = format!("1 2 0:1 / {TARGET} rw,nosuid - tmpfs tmpfs rw,size=98304k");
        assert!(tmpfs(&good));
        assert!(!tmpfs(&good.replace("rw,nosuid", "ro,nosuid")));
        assert!(!tmpfs(&good.replace("- tmpfs", "- ext4")));
        assert!(!tmpfs(&good.replace(TARGET, "/tmp/other")));
    }
    fn clean(k: &str) -> Option<String> {
        match k {
            "RUSTC_WRAPPER" => Some(WRAPPER.into()),
            "CARGO_HOME" => Some("/home/sol/.cargo".into()),
            "CARGO_TARGET_DIR" => Some(TARGET.into()),
            _ => None,
        }
    }
    #[test]
    fn inherited_compiler_overrides_are_rejected() {
        assert!(environment(clean).is_ok());
        for key in [
            "RUSTC_WORKSPACE_WRAPPER",
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_BUILD_TARGET",
        ] {
            assert!(
                environment(|k| if k == key {
                    Some("injected".into())
                } else {
                    clean(k)
                })
                .is_err()
            );
        }
    }
    #[test]
    fn wrapper_and_cargo_home_cannot_be_replaced() {
        for key in ["RUSTC_WRAPPER", "CARGO_HOME", "CARGO_TARGET_DIR"] {
            assert!(
                environment(|k| if k == key {
                    Some("/tmp/other".into())
                } else {
                    clean(k)
                })
                .is_err()
            );
        }
    }
}
