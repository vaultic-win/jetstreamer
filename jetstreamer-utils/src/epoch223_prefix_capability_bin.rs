//! Exact private cold223-prefix no-worker proof. Never replay/admission authority.
#[allow(dead_code)]
#[path = "epoch223_tail_attest_bin.rs"]
mod immutable;
use anyhow::{Context, Result, ensure};
use immutable::{Identity, artifact_free, digest, directory, file, hash, persist};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::Command,
};

const PACKAGE: &str = "/var/lib/jetstreamer/horizon-223-prefix-preflight-a928381d-v1";
const NODE_SHA: &str = "90474659be2a4a7d1cc9d4dfe3d5ab1587adb1b388b83163b2bf16c771624f66";
const SNAPSHOT: &str = "snapshot-96335538-Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE.tar.zst";
const WORKER: &str = "jetstreamer-historical-worker-v1-6-25";
const GENESIS: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const SEALER: &str = "2c939dde066672a13d6119d86dfb2bf460c428fd95e0854da726c6c6419f6853";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    package: PathBuf,
    node_sha256: String,
    seal_sha256: String,
    sums_sha256: String,
    probe_root: PathBuf,
    receipt_directory: PathBuf,
}
fn scope(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-private-epoch223-prefix-capability-plan-v1"
            && p.package == Path::new(PACKAGE)
            && p.node_sha256 == NODE_SHA
            && digest(&p.seal_sha256)
            && digest(&p.sums_sha256),
        "wrong prefix package binding"
    );
    ensure!(
        p.probe_root.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
            && p.probe_root
                .file_name()
                .and_then(|s| s.to_str())
                .and_then(|s| s.strip_prefix("qualification-223-v1625-prefix-capability-"))
                .is_some_and(
                    |s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                ),
        "wrong prefix probe namespace"
    );
    ensure!(
        p.receipt_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && p.receipt_directory
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-223-prefix-capability-receipts-")
                    && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
        "wrong receipts namespace"
    );
    Ok(())
}
fn package(p: &Plan) -> Result<BTreeMap<String, Identity>> {
    directory(&p.package, 0, false)?;
    ensure!(
        fs::symlink_metadata(&p.package)?.mode() & 0o222 == 0,
        "writable package"
    );
    ensure!(
        file(&p.package.join("deployment-seal-receipt.json"), 1 << 20)?.sha256 == p.seal_sha256
            && file(&p.package.join("SHA256SUMS"), 1 << 20)?.sha256 == p.sums_sha256,
        "package metadata mismatch"
    );
    let seal: Value =
        serde_json::from_slice(&fs::read(p.package.join("deployment-seal-receipt.json"))?)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == PACKAGE
            && seal["sealer_sha256"] == SEALER
            && seal["plan_sha256"].as_str().is_some_and(digest),
        "wrong native seal"
    );
    for key in [
        "replay_launch_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(seal[key] == false, "seal grants authority");
    }
    let mut members = BTreeMap::new();
    for line in fs::read_to_string(p.package.join("SHA256SUMS"))?.lines() {
        let (sha, name) = line.split_once("  ").context("invalid sums")?;
        ensure!(
            digest(sha)
                && !name.is_empty()
                && name != "."
                && name != ".."
                && !name.contains('/')
                && !members.contains_key(name),
            "unsafe sums member"
        );
        let identity = file(&p.package.join(name), 12 << 30)?;
        ensure!(identity.sha256 == sha, "member digest mismatch");
        members.insert(name.to_owned(), identity);
    }
    let fixed = [
        ("jetstreamer-node", p.node_sha256.as_str()),
        (
            WORKER,
            "fde3ba53cc52012b894bac29bd7889b4cfd326fff75f4f67ec4cbdbf2ac7136c",
        ),
        (
            SNAPSHOT,
            "301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665",
        ),
        ("genesis.tar.bz2", GENESIS),
        (
            "epoch-hashes-223-prefix.txt",
            "9ce886d556f70e84386dbf1b2c4abc4b4fb7ea57064b903e50ff6b34479a0c15",
        ),
    ];
    for (name, sha) in fixed {
        ensure!(
            members.get(name).is_some_and(|m| m.sha256 == sha),
            "wrong fixed member {name}"
        );
    }
    ensure!(
        members[SNAPSHOT].bytes == 9_815_262_303
            && members["jetstreamer-node"].mode == 0o555
            && members[WORKER].mode == 0o555,
        "member size/mode"
    );
    ensure!(
        members
            .get("deployment-seal-receipt.json")
            .is_some_and(|m| m.sha256 == p.seal_sha256),
        "seal not in sums"
    );
    let actual: BTreeSet<_> = fs::read_dir(&p.package)?
        .map(|e| {
            let e = e?;
            ensure!(e.file_type()?.is_file(), "nonregular package member");
            Ok(e.file_name().to_str().context("member utf8")?.to_owned())
        })
        .collect::<Result<_>>()?;
    let mut expected: BTreeSet<_> = members.keys().cloned().collect();
    expected.insert("SHA256SUMS".into());
    ensure!(actual == expected, "unexpected package member");
    let sealed = seal["members"].as_array().context("seal members")?;
    ensure!(sealed.len() + 1 == members.len(), "seal census mismatch");
    let mut seen = BTreeSet::new();
    for member in sealed {
        let name = member["name"].as_str().context("seal name")?;
        let identity = members.get(name).context("seal foreign member")?;
        ensure!(
            seen.insert(name)
                && member["sha256"] == identity.sha256
                && member["bytes"] == identity.bytes
                && member["mode"] == format!("{:04o}", identity.mode),
            "seal member mismatch"
        );
    }
    Ok(members)
}
fn report(text: &str) -> Result<Value> {
    let reports: Vec<Value> = text
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| v["schema"] == "jetstreamer-private-epoch223-prefix-planning-preflight-v1")
        .collect();
    ensure!(
        reports.len() == 1,
        "missing or ambiguous prefix pre-worker report"
    );
    let v = reports.into_iter().next().expect("one report");
    ensure!(
        v["epoch"] == 223
            && v["bootstrap_slot"] == 96_335_538u64
            && v["output_slot_start"] == 96_336_000u64
            && v["terminal_slot"] == 96_767_522u64
            && v["output_slot_count"] == 431_523
            && v["runtime_profile"] == "solana-v1.6.25"
            && v["runtime_revision"] == "7de8a55b54d3e11058b82f9483bb405d143b455c"
            && v["worker_identity"] == WORKER
            && v["worker_environment_override"] == "JETSTREAMER_HISTORICAL_WORKER_V1_6_25"
            && v["worker_executable"] == format!("{PACKAGE}/{WORKER}"),
        "wrong prefix/runtime/worker scope"
    );
    for key in [
        "canonical_bootstrap_bound",
        "canonical_terminal_required",
        "terminal_canonical_root_independently_known",
        "known_root_prefix_planning_only",
        "runtime_checkpoint_policy_validated",
        "pre_worker_barrier_reached",
        "worker_profile_validated",
    ] {
        ensure!(v[key] == true, "prefix missing required gate {key}");
    }
    for key in [
        "tail_comparison_only",
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
        ensure!(v[key] == false, "prefix grants authority {key}");
    }
    Ok(v)
}
fn preseed(p: &Plan) -> Result<()> {
    directory(&p.probe_root, 1000, true)?;
    ensure!(
        fs::read_dir(&p.probe_root)?.next().is_none(),
        "probe root not empty"
    );
    for path in [p.probe_root.join("ledger"), p.probe_root.join("output")] {
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
        ensure!(
            unsafe { libc::chown(c.as_ptr(), 1000, 1000) } == 0,
            "probe owner"
        );
        let mut input = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(p.package.join("genesis.tar.bz2"))?;
        let target = path.join("genesis.tar.bz2");
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&target)?;
        std::io::copy(&mut input, &mut output)?;
        output.sync_all()?;
        ensure!(
            hash(File::open(&target)?)? == GENESIS,
            "copied genesis differs"
        );
        use std::os::fd::AsRawFd;
        ensure!(
            unsafe { libc::fchown(output.as_raw_fd(), 1000, 1000) } == 0,
            "genesis owner"
        );
        output.sync_all()?;
        File::open(&path)?.sync_all()?;
    }
    File::open(&p.probe_root)?.sync_all()?;
    File::open(p.probe_root.parent().context("probe parent")?)?.sync_all()?;
    Ok(())
}
fn probe(p: &Plan) -> Result<Value> {
    preseed(p)?;
    let mut command = Command::new(p.package.join("jetstreamer-node"));
    command
        .arg("223")
        .arg(p.probe_root.join("ledger"))
        .args([
            "--verify",
            "--qualification-end-slot=96767522",
            "--epoch223-prefix-preflight",
        ])
        .arg(format!(
            "--snapshot-archive={}",
            p.package.join(SNAPSHOT).display()
        ))
        .arg(format!(
            "--epoch-hashes={}",
            p.package.join("epoch-hashes-223-prefix.txt").display()
        ))
        .arg(format!(
            "--horizon-output={}",
            p.probe_root.join("output/epoch-223.jet").display()
        ))
        .arg(format!(
            "--replay-scratch={}",
            p.probe_root.join("scratch").display()
        ))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("RUST_LOG", "info")
        .env("TOKIO_WORKER_THREADS", "2")
        .env("RAYON_NUM_THREADS", "2")
        .env("JETSTREAMER_ALLOW_CANDIDATE_RUNTIME", "1")
        .env(
            "JETSTREAMER_HISTORICAL_WORKER_V1_6_25",
            p.package.join(WORKER),
        )
        .current_dir(&p.probe_root);
    unsafe {
        command.pre_exec(|| {
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(1000) != 0
                || libc::setuid(1000) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = command.output()?;
    let mut bytes = out.stdout;
    bytes.extend_from_slice(&out.stderr);
    ensure!(bytes.len() <= 16 << 20, "probe log bound");
    persist(&p.receipt_directory.join("probe.log"), &bytes)?;
    ensure!(
        out.status.success(),
        "prefix preflight failed: {}",
        out.status
    );
    let value = report(&String::from_utf8_lossy(&bytes))?;
    artifact_free(&p.probe_root, &mut 4096)?;
    Ok(value)
}
fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 6
            && args[2] == "--plan-sha256"
            && args[4] == "--self-sha256"
            && digest(&args[3])
            && digest(&args[5])
            && unsafe { libc::geteuid() } == 0,
        "root and independent plan/self hashes required"
    );
    let executable = file(&fs::read_link("/proc/self/exe")?, 256 << 20)?;
    ensure!(executable.sha256 == args[5], "running binary mismatch");
    ensure!(
        file(Path::new(&args[1]), 1 << 20)?.sha256 == args[3],
        "plan mismatch"
    );
    let p: Plan = serde_json::from_slice(&fs::read(&args[1])?)?;
    scope(&p)?;
    directory(&p.receipt_directory, 0, true)?;
    directory(p.probe_root.parent().context("probe parent")?, 1000, true)?;
    directory(&p.probe_root, 1000, true)?;
    ensure!(
        fs::read_dir(&p.probe_root)?.next().is_none(),
        "probe root not empty"
    );
    for name in ["capability.json", "probe.log"] {
        ensure!(
            fs::symlink_metadata(p.receipt_directory.join(name))
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "receipt exists or unreadable"
        );
    }
    let invocation = env::var("INVOCATION_ID")?;
    ensure!(
        invocation.len() == 32
            && invocation
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid persistent invocation"
    );
    let before = package(&p)?;
    let planning = probe(&p)?;
    ensure!(before == package(&p)?, "package changed across probe");
    let value = json!({"schema":"jetstreamer-private-epoch223-prefix-package-capability-v1",
        "epoch":223,"plan_path":args[1],"plan_sha256":args[3],"self_sha256":args[5],"invocation_id":invocation,
        "package":p.package,"members":before,"planning_preflight":planning,
        "recorded_unix_seconds":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
        "snapshot_schema_or_contents_tested":false,"fresh_resource_admission_passed":false,
        "replay_launch_authorized":false,"canonical_prefix_qualified":false,"native_restart_qualified":false,
        "assembly_qualified":false,"publication_authorized":false,"canonical_sidecar_authorized":false,
        "remote_mutations":false,"r2_mutations":false,"probe_cleanup_pending":true});
    let mut bytes = serde_json::to_vec_pretty(&value)?;
    bytes.write_all(b"\n")?;
    persist(&p.receipt_directory.join("capability.json"), &bytes)
}
fn main() {
    if let Err(e) = run() {
        eprintln!("epoch223 prefix capability failed closed: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Value {
        let mut v = json!({"schema":"jetstreamer-private-epoch223-prefix-planning-preflight-v1",
            "epoch":223,"bootstrap_slot":96335538,"output_slot_start":96336000,"terminal_slot":96767522,
            "output_slot_count":431523,"runtime_profile":"solana-v1.6.25",
            "runtime_revision":"7de8a55b54d3e11058b82f9483bb405d143b455c","worker_identity":WORKER,
            "worker_environment_override":"JETSTREAMER_HISTORICAL_WORKER_V1_6_25",
            "worker_executable":format!("{PACKAGE}/{WORKER}")});
        for k in [
            "canonical_bootstrap_bound",
            "canonical_terminal_required",
            "terminal_canonical_root_independently_known",
            "known_root_prefix_planning_only",
            "runtime_checkpoint_policy_validated",
            "pre_worker_barrier_reached",
            "worker_profile_validated",
        ] {
            v[k] = json!(true);
        }
        for k in [
            "tail_comparison_only",
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
            v[k] = json!(false);
        }
        v
    }
    #[test]
    fn report_requires_exact_scope_every_gate_and_no_granted_authority() {
        let v = fixture();
        report(&v.to_string()).unwrap();
        assert!(report(&format!("{v}\n{v}")).is_err());
        for (key, value) in v.as_object().unwrap() {
            let mut changed = v.clone();
            changed[key] = if value.is_boolean() {
                json!(!value.as_bool().unwrap())
            } else {
                Value::Null
            };
            assert!(
                report(&changed.to_string()).is_err(),
                "accepted changed {key}"
            );
        }
        let mut tail = v.clone();
        tail["terminal_slot"] = json!(96767999);
        assert!(report(&tail.to_string()).is_err());
    }
    #[test]
    fn scope_rejects_foreign_package_tail_namespace_and_aliased_receipts() {
        let make = || Plan {
            schema: "jetstreamer-private-epoch223-prefix-capability-plan-v1".into(),
            package: PACKAGE.into(),
            node_sha256: NODE_SHA.into(),
            seal_sha256: "b".repeat(64),
            sums_sha256: "c".repeat(64),
            probe_root:
                "/home/ubuntu/.jetstreamer-private/qualification-223-v1625-prefix-capability-test"
                    .into(),
            receipt_directory: "/var/lib/jetstreamer/horizon-223-prefix-capability-receipts-test"
                .into(),
        };
        scope(&make()).unwrap();
        for variant in 0..4 {
            let mut p = make();
            match variant {
            0=>p.package="/var/lib/jetstreamer/foreign".into(),
            1=>p.probe_root="/home/ubuntu/.jetstreamer-private/qualification-223-v1625-tail-capability-test".into(),
            2=>p.receipt_directory="/tmp/receipts".into(),_=>p.node_sha256="invalid".into()};
            assert!(scope(&p).is_err());
        }
    }
}
