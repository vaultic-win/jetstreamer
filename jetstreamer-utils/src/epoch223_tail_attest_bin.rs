//! Immutable-package and no-replay capability proof for one private 477-slot comparison.
//! Deliberately separate from complete-epoch attestation; never launch authority.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::Command,
};

const PACKAGE: &str = "/var/lib/jetstreamer/horizon-focused-223-v1625-tail-d2507ee8-v2";
const SEALER: &str = "2c939dde066672a13d6119d86dfb2bf460c428fd95e0854da726c6c6419f6853";
const SNAPSHOT: &str = "snapshot-96767522-3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7.tar.zst";
const CORE: &[(&str, &str)] = &[
    (
        "jetstreamer-node",
        "b859bce6efc54f8f31b8eb4963f7996f8cdda1b136b79b8566bb5e032d5c26df",
    ),
    (
        "jetstreamer-historical-worker-v1-6-25",
        "fde3ba53cc52012b894bac29bd7889b4cfd326fff75f4f67ec4cbdbf2ac7136c",
    ),
    (
        SNAPSHOT,
        "dc7f2ac03813bc609629885af82222ac5af070cc6187b7bce08e10944fd214e1",
    ),
    (
        "genesis.tar.bz2",
        "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
    ),
    (
        "epoch-hashes-223-qualification.txt",
        "9ce886d556f70e84386dbf1b2c4abc4b4fb7ea57064b903e50ff6b34479a0c15",
    ),
    (
        "snapshot-source-preflight.json",
        "f25f3cbe90e74ba977622bf572be0da8e2ae063514a741cbdb670276879aff5e",
    ),
    (
        "qualification-design.md",
        "59ae782fb168afefeceae751af14fc283b03a4cf240686a84d6dc8bbd48f1038",
    ),
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    package: PathBuf,
    seal_sha256: String,
    sums_sha256: String,
    probe_root: PathBuf,
    receipt_directory: PathBuf,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct Identity {
    sha256: String,
    bytes: u64,
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn hash(mut f: impl Read) -> Result<String> {
    let mut h = Sha256::new();
    let mut b = vec![0; 1 << 20];
    loop {
        let n = f.read(&mut b)?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}
fn file(path: &Path, limit: u64) -> Result<Identity> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "aliased input"
    );
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = f.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o222 == 0
            && before.len() <= limit,
        "unsafe immutable input"
    );
    let sha256 = hash(&f)?;
    let current = fs::symlink_metadata(path)?;
    let key = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.uid(),
            m.gid(),
            m.mode(),
            m.nlink(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    ensure!(
        key(&before) == key(&f.metadata()?) && key(&before) == key(&current),
        "input changed"
    );
    Ok(Identity {
        sha256,
        bytes: before.len(),
        dev: before.dev(),
        ino: before.ino(),
        mode: before.mode() & 0o7777,
        uid: before.uid(),
        gid: before.gid(),
        modified: (before.mtime(), before.mtime_nsec()),
        changed: (before.ctime(), before.ctime_nsec()),
    })
}
fn directory(path: &Path, uid: u32, private: bool) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && m.is_dir()
            && m.uid() == uid
            && m.mode() & if private { 0o077 } else { 0o022 } == 0,
        "unsafe directory"
    );
    Ok(())
}
fn persist(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    File::open(path.parent().context("output parent")?)?.sync_all()?;
    Ok(())
}
fn shape(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-private-epoch223-tail-package-plan-v1"
            && p.package == Path::new(PACKAGE)
            && digest(&p.seal_sha256)
            && digest(&p.sums_sha256),
        "wrong package plan"
    );
    ensure!(
        p.probe_root.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
            && p.probe_root
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s
                    .strip_prefix("qualification-223-v1625-tail-capability-")
                    .is_some_and(|s| !s.is_empty()
                        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))),
        "wrong probe root"
    );
    directory(&p.receipt_directory, 0, true)?;
    directory(p.probe_root.parent().context("probe parent")?, 1000, true)?;
    ensure!(
        fs::symlink_metadata(&p.probe_root)
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "probe root exists or is unreadable"
    );
    Ok(())
}
fn sums(text: &str) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let (sha, name) = line.split_once("  ").context("invalid sums")?;
        ensure!(
            digest(sha)
                && !name.is_empty()
                && !name.contains('/')
                && name != "."
                && name != ".."
                && out.insert(name.to_string(), sha.to_string()).is_none(),
            "unsafe sums entry"
        );
    }
    ensure!(
        out.len() == CORE.len() + 2
            && out.contains_key("parent-build-final.log")
            && out.contains_key("deployment-seal-receipt.json"),
        "wrong member census"
    );
    for &(name, sha) in CORE {
        ensure!(
            out.get(name).map(String::as_str) == Some(sha),
            "wrong fixed member {name}"
        );
    }
    Ok(out)
}
fn seal_shape(v: &Value, entries: &BTreeMap<String, Identity>) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && v["destination"] == PACKAGE
            && v["sealer_sha256"] == SEALER
            && v["plan_sha256"].as_str().is_some_and(digest),
        "wrong native seal"
    );
    for key in [
        "publication_authorized",
        "replay_launch_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(v[key] == false, "seal has mutation authority");
    }
    let members = v["members"].as_array().context("seal members")?;
    ensure!(members.len() == entries.len(), "seal census differs");
    let mut seen = std::collections::BTreeSet::new();
    for m in members {
        let name = m["name"].as_str().context("member name")?;
        let actual = entries.get(name).context("foreign member")?;
        ensure!(
            seen.insert(name)
                && m["sha256"] == actual.sha256
                && m["bytes"] == actual.bytes
                && m["mode"] == format!("{:04o}", actual.mode),
            "native seal member mismatch"
        );
    }
    Ok(())
}
fn source_snapshot(v: &Value) -> Result<()> {
    let epochs = v["manifest"]["epochs"]
        .as_array()
        .context("snapshot source epochs")?;
    let selected: Vec<_> = epochs.iter().filter(|e| e["epoch"] == 224).collect();
    ensure!(selected.len() == 1, "ambiguous original snapshot source");
    let b = &selected[0]["bootstrap"];
    ensure!(
        b["slot"] == 96_767_522u64
            && b["generation"] == 1_632_093_412_056_045u64
            && b["size"] == 9_705_551_147u64
            && b["crc32c"] == "woMSaA=="
            && b["md5_hash"] == "vVpo0VoKsPfVgsQaYG6n/g=="
            && b["versioned_uri"]
                == format!("gs://mainnet-beta-ledger-us-ny5/96767522/{SNAPSHOT}#1632093412056045"),
        "wrong immutable snapshot generation metadata"
    );
    Ok(())
}
fn package(p: &Plan) -> Result<BTreeMap<String, Identity>> {
    directory(&p.package, 0, false)?;
    ensure!(
        fs::symlink_metadata(&p.package)?.mode() & 0o222 == 0,
        "package directory is writable"
    );
    let seal = file(&p.package.join("deployment-seal-receipt.json"), 1 << 20)?;
    let checksum = file(&p.package.join("SHA256SUMS"), 1 << 20)?;
    ensure!(
        seal.sha256 == p.seal_sha256 && checksum.sha256 == p.sums_sha256,
        "package metadata binding"
    );
    let mut expected = sums(&fs::read_to_string(p.package.join("SHA256SUMS"))?)?;
    ensure!(
        expected.remove("deployment-seal-receipt.json").as_deref() == Some(p.seal_sha256.as_str()),
        "generated native seal digest differs"
    );
    let mut names = std::collections::BTreeSet::new();
    for e in fs::read_dir(&p.package)? {
        let e = e?;
        ensure!(
            e.file_type()?.is_file()
                && names.insert(e.file_name().to_str().context("member UTF8")?.to_string()),
            "unsafe package member"
        );
    }
    let mut allowed: std::collections::BTreeSet<_> = expected.keys().cloned().collect();
    allowed.extend([
        "SHA256SUMS".to_string(),
        "deployment-seal-receipt.json".to_string(),
    ]);
    ensure!(names == allowed, "package member set differs");
    let mut entries = BTreeMap::new();
    for (name, sha) in expected {
        let m = file(&p.package.join(&name), 12 << 30)?;
        ensure!(m.sha256 == sha, "member hash differs");
        if name == "jetstreamer-node" || name == "jetstreamer-historical-worker-v1-6-25" {
            ensure!(m.mode == 0o555, "binary not immutable executable");
        }
        if name == SNAPSHOT {
            ensure!(m.bytes == 9_705_551_147, "snapshot length differs");
        }
        entries.insert(name, m);
    }
    seal_shape(
        &serde_json::from_slice(&fs::read(p.package.join("deployment-seal-receipt.json"))?)?,
        &entries,
    )?;
    source_snapshot(&serde_json::from_slice(&fs::read(
        p.package.join("snapshot-source-preflight.json"),
    )?)?)?;
    Ok(entries)
}
fn artifact_free(path: &Path, remaining: &mut usize) -> Result<()> {
    for e in fs::read_dir(path)? {
        ensure!(*remaining > 0, "probe tree limit");
        *remaining -= 1;
        let e = e?;
        let m = e.file_type()?;
        let path = e.path();
        ensure!(!m.is_symlink(), "probe tree alias");
        if m.is_dir() {
            artifact_free(&path, remaining)?;
        } else {
            ensure!(m.is_file(), "probe member type");
            let name = e.file_name();
            let name = name.to_str().context("probe member UTF8")?;
            ensure!(
                !name.ends_with(".jet")
                    && !name.ends_with(".sha256")
                    && !name.contains("segment-manifest"),
                "probe created archive evidence"
            );
        }
    }
    Ok(())
}
fn output_gate(code: Option<i32>, text: &str, mode: usize, missing: &Path) -> Result<()> {
    if mode == 3 {
        ensure!(code == Some(0), "planning preflight did not succeed");
        ensure!(
            !text.to_ascii_lowercase().contains("replaying"),
            "preflight started replay"
        );
        return planning_preflight(text).map(|_| ());
    }
    let marker = match mode {
        0 => "epoch223 private build accepts only focused epoch223".to_string(),
        1 => "epoch223-v1-6-25-qualification requires private focused epoch223".to_string(),
        2 => format!("failed to read snapshot {}", missing.display()),
        _ => anyhow::bail!("unknown probe mode"),
    };
    ensure!(
        code == Some(if mode == 2 { 1 } else { 2 }) && text.contains(&marker),
        "wrong capability rejection"
    );
    ensure!(
        !text.to_ascii_lowercase().contains("replaying"),
        "probe started replay"
    );
    if mode == 2 {
        ensure!(text.contains("focused qualification requested: epoch 223, bootstrap 96767522, replay 96767523..=96767999")
        && text.contains("selected execution profile solana-v1.6.25"), "probe missed focused/runtime gate");
    }
    Ok(())
}
fn planning_preflight(text: &str) -> Result<Value> {
    let reports: Vec<Value> = text
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|v| v["schema"] == "jetstreamer-private-epoch223-tail-planning-preflight-v1")
        .collect();
    ensure!(
        reports.len() == 1,
        "missing or ambiguous post-bootstrap planning preflight"
    );
    let v = reports.into_iter().next().expect("one report");
    ensure!(
        v["epoch"] == 223
            && v["bootstrap_slot"] == 96_767_522u64
            && v["output_slot_start"] == 96_767_523u64
            && v["terminal_slot"] == 96_767_999u64
            && v["output_slot_count"] == 477
            && v["runtime_profile"] == "solana-v1.6.25"
            && v["runtime_revision"] == "7de8a55b54d3e11058b82f9483bb405d143b455c"
            && v["worker_identity"] == "jetstreamer-historical-worker-v1-6-25"
            && v["worker_environment_override"] == "JETSTREAMER_HISTORICAL_WORKER_V1_6_25"
            && v["canonical_bootstrap_bound"] == true
            && v["tail_comparison_only"] == true,
        "planning preflight scope/runtime/bootstrap differs"
    );
    for key in [
        "canonical_terminal_required",
        "terminal_canonical_root_independently_known",
        "complete_epoch_span_covered",
        "worker_spawned",
        "archive_created",
        "snapshot_schema_or_contents_tested",
        "fresh_resource_admission_passed",
        "canonical_prefix_qualified",
        "full_cold_epoch_peak_qualified",
        "replay_launch_authorized",
        "runtime_promotion_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            v[key] == false,
            "planning preflight grants foreign authority: {key}"
        );
    }
    Ok(v)
}
fn preseed_genesis(p: &Plan) -> Result<()> {
    for name in ["ledger", "output"] {
        let dir = p.probe_root.join(name);
        match fs::create_dir(&dir) {
            Ok(()) => {
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
                let path = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(
                    dir.as_os_str(),
                ))?;
                ensure!(
                    unsafe { libc::chown(path.as_ptr(), 1000, 1000) } == 0,
                    "genesis directory owner"
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        directory(&dir, 1000, true)?;
        let mut input = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(p.package.join("genesis.tar.bz2"))?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(dir.join("genesis.tar.bz2"))?;
        std::io::copy(&mut input, &mut output)?;
        output.sync_all()?;
        ensure!(
            hash(File::open(dir.join("genesis.tar.bz2"))?)? == CORE[3].1,
            "preseeded genesis digest differs"
        );
        use std::os::fd::AsRawFd;
        ensure!(
            unsafe { libc::fchown(output.as_raw_fd(), 1000, 1000) } == 0,
            "genesis owner"
        );
        output.sync_all()?;
        File::open(&dir)?.sync_all()?;
    }
    File::open(&p.probe_root)?.sync_all()?;
    Ok(())
}
fn probe(p: &Plan) -> Result<Vec<Value>> {
    fs::create_dir(&p.probe_root)?;
    fs::set_permissions(&p.probe_root, fs::Permissions::from_mode(0o700))?;
    let c = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(
        p.probe_root.as_os_str(),
    ))?;
    ensure!(
        unsafe { libc::chown(c.as_ptr(), 1000, 1000) } == 0,
        "probe owner"
    );
    File::open(p.probe_root.parent().context("probe parent")?)?.sync_all()?;
    let missing = p.probe_root.join("missing").join(SNAPSHOT);
    let wrong = p
        .probe_root
        .join("missing/snapshot-96767521-3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7.tar.zst");
    let mut evidence = Vec::new();
    for mode in 0..4 {
        if mode == 3 {
            preseed_genesis(p)?;
        }
        let mut cmd = Command::new(p.package.join("jetstreamer-node"));
        if mode == 0 {
            cmd.args([
                "--failed-prefix220-recover",
                "/absent/must-not-read.json",
                "invalid",
                "invalid",
            ]);
        } else {
            cmd.arg("223")
                .arg(p.probe_root.join("ledger"))
                .args(["--verify", "--qualification-end-slot=96767999"])
                .arg(format!(
                    "--snapshot-archive={}",
                    if mode == 1 {
                        wrong.clone()
                    } else if mode == 3 {
                        p.package.join(SNAPSHOT)
                    } else {
                        missing.clone()
                    }
                    .display()
                ))
                .arg(format!(
                    "--epoch-hashes={}",
                    p.package
                        .join("epoch-hashes-223-qualification.txt")
                        .display()
                ))
                .arg(format!(
                    "--horizon-output={}",
                    p.probe_root.join("output/epoch-223.jet").display()
                ))
                .arg(format!(
                    "--replay-scratch={}",
                    p.probe_root.join("scratch").display()
                ));
            if mode == 3 {
                cmd.args(["--epoch223-tail-comparison", "--epoch223-tail-preflight"]);
            }
        }
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("RUST_LOG", "info")
            .env("TOKIO_WORKER_THREADS", "2")
            .env("RAYON_NUM_THREADS", "2")
            .env("JETSTREAMER_ALLOW_CANDIDATE_RUNTIME", "1")
            .env(
                "JETSTREAMER_HISTORICAL_WORKER_V1_6_25",
                p.package.join("jetstreamer-historical-worker-v1-6-25"),
            )
            .current_dir(&p.probe_root)
            .uid(1000)
            .gid(1000);
        let out = cmd.output()?;
        let mut bytes = out.stdout;
        bytes.extend_from_slice(&out.stderr);
        ensure!(bytes.len() <= 16 << 20, "probe log bound");
        let log = p.receipt_directory.join(format!("probe-{mode}.log"));
        persist(&log, &bytes)?;
        output_gate(
            out.status.code(),
            &String::from_utf8_lossy(&bytes),
            mode,
            &missing,
        )?;
        artifact_free(&p.probe_root, &mut 4096)?;
        let mut result = json!({"mode":mode,"exit_code":out.status.code(),"log":log,"log_sha256":format!("{:x}",Sha256::digest(&bytes))});
        if mode == 3 {
            result["planning_preflight"] = planning_preflight(&String::from_utf8_lossy(&bytes))?;
        }
        evidence.push(result);
    }
    Ok(evidence)
}
fn run() -> Result<()> {
    let a: Vec<_> = env::args().collect();
    ensure!(
        a.len() == 6 && a[2] == "--plan-sha256" && a[4] == "--self-sha256",
        "usage: PLAN --plan-sha256 HEX --self-sha256 HEX"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0 && digest(&a[3]) && digest(&a[5]),
        "root and independent digests required"
    );
    let exe = File::open("/proc/self/exe")?;
    ensure!(
        exe.metadata()?.uid() == 0 && exe.metadata()?.mode() & 0o222 == 0 && hash(exe)? == a[5],
        "running executable differs"
    );
    let plan = file(Path::new(&a[1]), 1 << 20)?;
    ensure!(plan.sha256 == a[3], "plan digest differs");
    let p: Plan = serde_json::from_slice(&fs::read(&a[1])?)?;
    shape(&p)?;
    for name in [
        "capability.json",
        "probe-0.log",
        "probe-1.log",
        "probe-2.log",
        "probe-3.log",
    ] {
        ensure!(
            fs::symlink_metadata(p.receipt_directory.join(name))
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "receipt already exists or unreadable"
        );
    }
    let invocation = env::var("INVOCATION_ID").context("persistent service identity required")?;
    ensure!(
        invocation.len() == 32
            && invocation
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid service identity"
    );
    let before = package(&p)?;
    let probes = probe(&p)?;
    ensure!(before == package(&p)?, "package changed across probes");
    let value = json!({"schema":"jetstreamer-private-epoch223-tail-package-capability-v2","epoch":223,
        "plan_path":a[1],"plan_sha256":a[3],"self_sha256":a[5],"package":p.package,"members":before,"probes":probes,
        "invocation_id":invocation,"recorded_unix_seconds":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
        "snapshot_source_role":"generation-bound source only; original epoch224 plan is not launch authority",
        "output_slot_start":96767523u64,"terminal_slot":96767999u64,"slot_count":477,
        "tail_comparison_only":true,"complete_epoch_span_covered":false,"snapshot_schema_or_contents_tested":false,
        "canonical_prefix_qualified":false,"full_cold_epoch_peak_qualified":false,
        "runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,
        "fresh_resource_admission_passed":false,"replay_launch_authorized":false,"publication_authorized":false,
        "remote_mutations":false,"r2_mutations":false,"probe_cleanup_pending":true,"probe_retirement_authorized":false});
    let mut bytes = serde_json::to_vec_pretty(&value)?;
    bytes.push(b'\n');
    persist(&p.receipt_directory.join("capability.json"), &bytes)?;
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("epoch223 tail package failed closed: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn preflight_fixture() -> Value {
        let mut v = json!({"schema":"jetstreamer-private-epoch223-tail-planning-preflight-v1",
            "epoch":223,"bootstrap_slot":96767522,"output_slot_start":96767523,
            "terminal_slot":96767999,"output_slot_count":477,"runtime_profile":"solana-v1.6.25",
            "runtime_revision":"7de8a55b54d3e11058b82f9483bb405d143b455c",
            "worker_identity":"jetstreamer-historical-worker-v1-6-25",
            "worker_environment_override":"JETSTREAMER_HISTORICAL_WORKER_V1_6_25",
            "canonical_bootstrap_bound":true,"tail_comparison_only":true});
        for key in [
            "canonical_terminal_required",
            "terminal_canonical_root_independently_known",
            "complete_epoch_span_covered",
            "worker_spawned",
            "archive_created",
            "snapshot_schema_or_contents_tested",
            "fresh_resource_admission_passed",
            "canonical_prefix_qualified",
            "full_cold_epoch_peak_qualified",
            "replay_launch_authorized",
            "runtime_promotion_authorized",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            v[key] = json!(false);
        }
        v
    }
    #[test]
    fn full_planning_probe_requires_one_successful_exact_non_authorizing_report() {
        let v = preflight_fixture();
        let text = format!("selected execution profile solana-v1.6.25\n{v}\n");
        output_gate(Some(0), &text, 3, Path::new("/missing")).unwrap();
        assert!(output_gate(Some(1), &text, 3, Path::new("/missing")).is_err());
        assert!(planning_preflight("selected execution profile solana-v1.6.25").is_err());
        assert!(planning_preflight(&format!("{v}\n{v}\n")).is_err());
        assert!(
            output_gate(
                Some(0),
                &format!("{text}replaying"),
                3,
                Path::new("/missing")
            )
            .is_err()
        );
        for key in v.as_object().unwrap().keys() {
            let mut bad = v.clone();
            bad.as_object_mut().unwrap().remove(key);
            assert!(
                planning_preflight(&bad.to_string()).is_err(),
                "missing {key}"
            );
            let mut bad = v.clone();
            bad[key] = if v[key].is_boolean() {
                json!(!v[key].as_bool().unwrap())
            } else {
                json!("wrong")
            };
            assert!(
                planning_preflight(&bad.to_string()).is_err(),
                "changed {key}"
            );
        }
    }
    #[test]
    fn actual_native_sums_separate_generated_receipt_from_eight_payload_members() {
        let mut parsed = sums(include_str!(
            "../tests/fixtures/epoch223-tail-native-sha256sums.txt"
        ))
        .unwrap();
        assert_eq!(parsed.len(), 9);
        assert_eq!(
            parsed.remove("deployment-seal-receipt.json").unwrap(),
            "66c92353066ef0c4920f945b095ac6ae955f8bfc09ce60e30c7042f1e4bd5da7"
        );
        assert_eq!(parsed.len(), 8);
        assert!(
            parsed
                .keys()
                .all(|k| k != "SHA256SUMS" && k != "deployment-seal-receipt.json")
        );
    }
    #[test]
    fn native_seal_never_grants_authority_or_accepts_changed_members() {
        let member = Identity {
            sha256: CORE[0].1.into(),
            bytes: 1,
            dev: 1,
            ino: 1,
            mode: 0o555,
            uid: 0,
            gid: 0,
            modified: (1, 0),
            changed: (1, 0),
        };
        let entries = BTreeMap::from([("jetstreamer-node".to_string(), member)]);
        let v = json!({"schema":"jetstreamer-sealed-deployment-receipt-v1","destination":PACKAGE,"sealer_sha256":SEALER,"plan_sha256":"a".repeat(64),
            "publication_authorized":false,"replay_launch_authorized":false,"remote_mutations":false,"r2_mutations":false,
            "members":[{"name":"jetstreamer-node","sha256":CORE[0].1,"bytes":1,"mode":"0555"}]});
        seal_shape(&v, &entries).unwrap();
        for key in [
            "publication_authorized",
            "replay_launch_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            let mut changed = v.clone();
            changed[key] = json!(true);
            assert!(seal_shape(&changed, &entries).is_err());
        }
        let mut changed = v.clone();
        changed["members"][0]["bytes"] = json!(2);
        assert!(seal_shape(&changed, &entries).is_err());
        let mut changed = v.clone();
        changed["members"]
            .as_array_mut()
            .unwrap()
            .push(v["members"][0].clone());
        assert!(seal_shape(&changed, &entries).is_err());
    }
    #[test]
    fn source_metadata_is_one_exact_generation_not_an_epoch224_launch() {
        let b = json!({"slot":96767522u64,"generation":1632093412056045u64,"size":9705551147u64,
            "crc32c":"woMSaA==","md5_hash":"vVpo0VoKsPfVgsQaYG6n/g==",
            "versioned_uri":format!("gs://mainnet-beta-ledger-us-ny5/96767522/{SNAPSHOT}#1632093412056045")});
        let v = json!({"manifest":{"epochs":[{"epoch":224,"bootstrap":b}]}});
        source_snapshot(&v).unwrap();
        for key in [
            "slot",
            "generation",
            "size",
            "crc32c",
            "md5_hash",
            "versioned_uri",
        ] {
            let mut changed = v.clone();
            changed["manifest"]["epochs"][0]["bootstrap"][key] = Value::Null;
            assert!(source_snapshot(&changed).is_err());
        }
        let mut changed = v.clone();
        changed["manifest"]["epochs"]
            .as_array_mut()
            .unwrap()
            .push(v["manifest"]["epochs"][0].clone());
        assert!(source_snapshot(&changed).is_err());
    }
    #[test]
    fn probe_artifact_census_rejects_archives_and_aliases() {
        let t = tempfile::tempdir().unwrap();
        artifact_free(t.path(), &mut 10).unwrap();
        let file = t.path().join("epoch-223.jet");
        fs::write(&file, b"x").unwrap();
        assert!(artifact_free(t.path(), &mut 10).is_err());
        fs::remove_file(&file).unwrap();
        std::os::unix::fs::symlink("absent", t.path().join("alias")).unwrap();
        assert!(artifact_free(t.path(), &mut 10).is_err());
    }
    #[test]
    fn private_evidence_is_no_clobber() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("receipt");
        persist(&p, b"original").unwrap();
        assert!(persist(&p, b"replacement").is_err());
        assert_eq!(fs::read(&p).unwrap(), b"original");
    }
    #[test]
    fn canonical_hash_and_digest_shape() {
        assert_eq!(
            hash(&b"abc"[..]).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(digest(CORE[0].1));
        assert!(!digest(&"A".repeat(64)));
        assert!(!digest("123"));
    }
    #[test]
    fn fixed_member_census_cannot_borrow_other_runtime_or_checkpoint() {
        let valid = CORE
            .iter()
            .map(|(n, s)| format!("{s}  {n}\n"))
            .collect::<String>()
            + &format!(
                "{}  parent-build-final.log\n{}  deployment-seal-receipt.json\n",
                "a".repeat(64),
                "b".repeat(64)
            );
        assert!(sums(&valid).is_ok());
        assert!(sums(&(valid.clone() + &format!("{}  extra\n", "b".repeat(64)))).is_err());
        assert!(sums(&(valid.clone() + &format!("{}  jetstreamer-node\n", CORE[0].1))).is_err());
        assert!(sums(&valid.replace(CORE[0].1, &"0".repeat(64))).is_err());
        assert!(sums(&valid.replace("parent-build-final.log", "../escape")).is_err());
    }
    #[test]
    fn no_replay_probe_gate_is_exact() {
        let missing = Path::new("/absent/snapshot");
        assert!(
            output_gate(
                Some(2),
                "epoch223 private build accepts only focused epoch223",
                0,
                missing
            )
            .is_ok()
        );
        assert!(
            output_gate(
                Some(0),
                "epoch223 private build accepts only focused epoch223",
                0,
                missing
            )
            .is_err()
        );
        assert!(
            output_gate(
                Some(1),
                "failed to read snapshot /absent/snapshot",
                2,
                missing
            )
            .is_err()
        );
        let text = "focused qualification requested: epoch 223, bootstrap 96767522, replay 96767523..=96767999 selected execution profile solana-v1.6.25 failed to read snapshot /absent/snapshot";
        assert!(output_gate(Some(1), text, 2, missing).is_ok());
        assert!(output_gate(Some(1), &(text.to_string() + " REPLAYING"), 2, missing).is_err());
        assert!(output_gate(Some(1), text, 3, missing).is_err());
    }
}
