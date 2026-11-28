//! Source-only epoch 239 native import unit renderer. Never installs or starts it.
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    mem::MaybeUninit,
    os::unix::{ffi::OsStrExt, fs::{MetadataExt, OpenOptionsExt, PermissionsExt}},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const ROOT: &str = "/var/lib/jetstreamer/horizon239-current-import-source-20261117-v3";
const RUNTIME: &str = "/var/lib/jetstreamer/horizon239-current-import-runtime-20261117-v3";
const UNIT: &str = "horizon-import-239-current-20261117-v3.service";
const PROBE_UNIT: &str = "horizon-import-239-namespace-probe-20261117-v3.service";
const TOKENS: &str = "/var/lib/jetstreamer/horizon239-current-import-tokens-20261117-v3";
const LEASE_SCOPE: &str = "/home/ubuntu/.jetstreamer-private/destination-cc16e4ac982549c49990203164025f5c92247f275e6530e0654ed82c45a07519";
const PRIVATE: &str = "/home/ubuntu/.jetstreamer-private/qualification-239-general-shrink-debt-budget506-e3f15eb2-v1";
const ARCHIVE: &str = "/home/ubuntu/.jetstreamer-private/qualification-239-general-shrink-debt-budget506-e3f15eb2-v1/output/epoch-239.jet";
const SIDECAR: &str = "/home/ubuntu/.jetstreamer-private/qualification-239-general-shrink-debt-budget506-e3f15eb2-v1/output/epoch-239.jet.sha256";
const BATCH: &str = "/home/ubuntu/.jetstreamer-private/qualification-239-general-shrink-debt-budget506-e3f15eb2-v1/state/destination-b4e3137cb505f40edb9d8bc149c2495a50a77e65c8531f9b2271d27918914318/evidence/archive-batches/destination-0000000000010301-0000000001324079/batch-d2b5f6549317bb9da201f4bdc315ad4288d6f3e7ea67d3f3cd6fbb674b9937b0.json";
const BATCH_SHA: &str = "9229bb72b8c8a84b69bf2f477e760c87ad34ad9f1772dd7a28dd9a45dd533cb8";
const HASH_REPORT: &str = "/home/ubuntu/.codex/diagnostics/horizon-239-private-archive-hash-20261117.txt";
const MANIFEST: &str = "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/preflight-233-301-target1-offline-publish300.json";
const MANIFEST_SHA: &str = "207701a70fad8b6cdee7e848b0e7e5f7e88bbe4648f808fc89a5976b51b3bded";
const FINGERPRINT: &str = "sha256:3f0e03105ba1e6b166091d3519e1aea1f432d81e51044c3a35f49fb3e8991970";
const NODE: &str = "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node";
const NODE_SHA: &str = "362e928c778c171dff190c2efcf631a7fc9675b96be4f1b699e433993ac365a1";
const PRIOR_UNIT: &str = "/var/lib/jetstreamer/horizon245-import1027-runtime-v4/horizon-publish-245-postcommit1027-v4.service";
const PRIOR_UNIT_SHA: &str = "f2b12f6f3936ee1f0961237d9fc24cff5aad79219e21e6d5a521df6f52c4f099";
const DIGEST: &str = "d530332035fa1765f4f222c3df6ff9aa5825817c2be5ff0dc27f7f1d37c88189";
const LENGTH: u64 = 161_186_911_272;

fn hash(path: &Path, maximum: u64) -> Result<String> {
    let before = fs::symlink_metadata(path)?;
    ensure!(before.is_file() && before.nlink() == 1 && before.len() <= maximum, "unsafe pin {}", path.display());
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1 << 20];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 { break; }
        hasher.update(&buffer[..count]);
    }
    let after = fs::symlink_metadata(path)?;
    ensure!(before.dev() == after.dev() && before.ino() == after.ino() && before.len() == after.len()
        && before.mtime() == after.mtime() && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime() && before.ctime_nsec() == after.ctime_nsec(),
        "pin changed {}", path.display());
    Ok(format!("{:x}", hasher.finalize()))
}

fn check_source() -> Result<Value> {
    for (path, digest, limit) in [(BATCH, BATCH_SHA, 1 << 20), (MANIFEST, MANIFEST_SHA, 1 << 20),
        (NODE, NODE_SHA, 128 << 20), (PRIOR_UNIT, PRIOR_UNIT_SHA, 1 << 20)] {
        ensure!(hash(Path::new(path), limit)? == digest, "source pin changed: {path}");
    }
    let manifest: Value = serde_json::from_slice(&fs::read(MANIFEST)?)?;
    ensure!(manifest["manifest_fingerprint"] == FINGERPRINT
        && manifest["manifest"]["epochs"].as_array().is_some_and(|a| a.iter().any(|e| e["epoch"] == 239)),
        "manifest does not bind epoch 239");
    let batch: Value = serde_json::from_slice(&fs::read(BATCH)?)?;
    let member = &batch["outcome"]["members"][0];
    ensure!(batch["schema"] == "jetstreamer-root-cohort-publication-receipt-v2"
        && batch["manifest_fingerprint"] == FINGERPRINT
        && batch["epochs"].as_array().is_some_and(|a| a.len() == 1 && a[0] == 239)
        && batch["outcome"]["kind"] == "committed"
        && batch["outcome"]["members"].as_array().is_some_and(|a| a.len() == 1)
        && member["epoch"] == 239 && member["archive_sha256"] == DIGEST
        && member["committed_archive"]["length"] == LENGTH,
        "foreign or incomplete native source receipt");
    ensure!(STANDARD.decode(member["archive_path_base64"].as_str().context("archive path")?)? == ARCHIVE.as_bytes(),
        "native receipt points to another archive");
    ensure!(STANDARD.decode(member["checksum_path_base64"].as_str().context("sidecar path")?)? == SIDECAR.as_bytes(),
        "native receipt points to another sidecar");
    let m = fs::symlink_metadata(ARCHIVE)?;
    let native = &member["committed_archive"];
    ensure!(m.is_file() && m.nlink() == 1 && m.uid() == 1000 && m.gid() == 1000
        && m.mode() & 0o222 == 0 && m.len() == LENGTH
        && native["device"] == m.dev() && native["inode"] == m.ino()
        && native["mode"] == m.mode() && native["uid"] == m.uid()
        && native["gid"] == m.gid() && native["link_count"] == m.nlink()
        && native["modified_seconds"] == m.mtime() && native["modified_nanoseconds"] == m.mtime_nsec()
        && native["changed_seconds"] == m.ctime() && native["changed_nanoseconds"] == m.ctime_nsec(),
        "archive changed since native commit");
    ensure!(fs::read_to_string(SIDECAR)? == format!("{DIGEST}  epoch-239.jet\n"), "noncanonical sidecar");
    let report = fs::symlink_metadata(HASH_REPORT)?;
    ensure!(report.is_file() && report.nlink() == 1 && report.uid() == 0 && report.mode() & 0o022 == 0,
        "untrusted independent hash report");
    ensure!(fs::read_to_string(HASH_REPORT)? == format!("{DIGEST}  {ARCHIVE}\n"), "independent hash differs");
    ensure!(!Path::new("/home/ubuntu/horizon/epoch-239.jet").exists()
        && !Path::new("/home/ubuntu/horizon/epoch-239.jet.sha256").exists(),
        "canonical epoch 239 already exists");
    Ok(json!({"batch":{"path":BATCH,"sha256":BATCH_SHA},"archive":{"path":ARCHIVE,"sha256":DIGEST,"bytes":LENGTH,"device":m.dev(),"inode":m.ino()},
        "sidecar":SIDECAR,"manifest":{"path":MANIFEST,"sha256":MANIFEST_SHA,"fingerprint":FINGERPRINT},
        "node":{"path":NODE,"sha256":NODE_SHA},"independent_hash_report":HASH_REPORT}))
}

fn safe_component(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn children(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().context("non-UTF8 mask")?;
        ensure!(safe_component(name), "unsafe mask name: {name}");
        ensure!(!entry.file_type()?.is_symlink(), "symlink mask: {}", entry.path().display());
        out.push(entry.path());
    }
    out.sort();
    Ok(out)
}

fn masks() -> Result<Vec<PathBuf>> {
    let home = Path::new("/home/ubuntu");
    let private = home.join(".jetstreamer-private");
    let public = home.join("horizon");
    let source = Path::new(PRIVATE);
    let output = source.join("output");
    let mut masks = Vec::new();
    masks.extend(children(home)?.into_iter().filter(|p| p != &private && p != &public));
    masks.extend(children(&private)?.into_iter().filter(|p| p != source && p != Path::new(LEASE_SCOPE)));
    masks.extend(children(&public)?.into_iter().filter(|p| p.file_name().is_none_or(|n| n != "epoch-239.jet" && n != "epoch-239.jet.sha256")));
    masks.extend(children(source)?.into_iter().filter(|p| p != &output));
    masks.extend(children(&output)?.into_iter().filter(|p| p != Path::new(ARCHIVE) && p != Path::new(SIDECAR)));
    for live in ["qualification-247-reboot-20261117-v2", "qualification-248-reboot-20261117-v1", "qualification-249-reboot-20261117-v1"] {
        ensure!(masks.iter().any(|p| p == &private.join(live)), "live replay root unmasked: {live}");
    }
    ensure!(masks.iter().all(|p| p != Path::new(ARCHIVE) && p != Path::new(SIDECAR)
        && p != &public && p != &private && p != source && p != &output && p != Path::new(LEASE_SCOPE)), "writable namespace accidentally masked");
    Ok(masks)
}

fn render(prior: &str, masks: &[PathBuf]) -> Result<String> {
    let mut rendered = String::from(
        "# Source only: native namespace proof, first guard token, and fresh admission required.\n",
    );
    let token = format!("{TOKENS}/${{INVOCATION_ID}}/guard-admission.json");
    let mut changed = [false; 6];
    for line in prior.lines() {
        if line.starts_with('#') && rendered.lines().count() == 1 {
            continue;
        }
        if line.starts_with("Description=") {
            rendered.push_str("Description=Deeply validate and transactionally import committed Horizon epoch 239\n");
            changed[0] = true;
        } else if line.starts_with("ReadOnlyPaths=") {
            ensure!(!masks.is_empty(), "empty namespace masks");
            rendered.push_str("ReadOnlyPaths=");
            for (i, path) in masks.iter().enumerate() {
                ensure!(path.is_absolute(), "relative mask");
                if i != 0 { rendered.push(' '); }
                rendered.push('"');
                rendered.push_str(path.to_str().context("non-UTF8 mask")?);
                rendered.push('"');
            }
            rendered.push('\n');
            changed[1] = true;
        } else if line.starts_with("ExecStart=") {
            rendered.push_str("ExecStartPre=/usr/bin/sleep 60\n");
            rendered.push_str(&format!("ExecStartPre=/usr/bin/test -f {token}\n"));
            rendered.push_str(&format!("ExecStartPre=/usr/bin/test ! -L {token}\n"));
            rendered.push_str(&format!("ExecStart={NODE} 239 /home/ubuntu/horizon --verify --recover-staged-cohort-only --cohort-manifest={MANIFEST} --cohort-manifest-fingerprint={FINGERPRINT} --source-cohort-receipt={BATCH} --publish-through-epoch=239\n"));
            changed[2] = true;
        } else if line.starts_with("StandardOutput=") {
            rendered.push_str(&format!("StandardOutput=append:{PRIVATE}/output/import-239.log\n"));
            changed[3] = true;
        } else if line.starts_with("StandardError=") {
            rendered.push_str(&format!("StandardError=append:{PRIVATE}/output/import-239.log\n"));
            changed[4] = true;
        } else if line == "ReadWritePaths=/home/ubuntu" {
            rendered.push_str(line);
            rendered.push('\n');
            changed[5] = true;
        } else {
            ensure!(!line.starts_with("ExecStartPre=") && !line.starts_with("ExecCondition=")
                && !line.starts_with("EnvironmentFile="), "unexpected predecessor start gate");
            rendered.push_str(line);
            rendered.push('\n');
        }
    }
    ensure!(changed.into_iter().all(|v| v), "predecessor unit shape changed");
    ensure!(rendered.matches("ExecStart=").count() == 1
        && rendered.matches("ReadOnlyPaths=").count() == 1
        && rendered.matches("ExecStartPre=").count() == 3,
        "generated unit has duplicate start or namespace fields");
    Ok(rendered)
}

fn render_probe(import_unit: &str) -> Result<String> {
    let mut rendered = String::new();
    for line in import_unit.lines() {
        if line.starts_with("ExecStartPre=") { continue; }
        if line.starts_with("Description=") {
            rendered.push_str("Description=Native namespace and access probe for committed Horizon epoch 239\n");
        } else if line == "Type=exec" {
            rendered.push_str("Type=oneshot\n");
        } else if line == "RuntimeMaxSec=12h" {
            rendered.push_str("TimeoutStartSec=300\n");
        } else if line.starts_with("ExecStart=") {
            rendered.push_str(&format!("ExecStart={RUNTIME}/horizon-epoch239-import-source probe\n"));
        } else if line.starts_with("StandardOutput=") {
            rendered.push_str("StandardOutput=journal\n");
        } else if line.starts_with("StandardError=") {
            rendered.push_str("StandardError=journal\n");
        } else {
            rendered.push_str(line);
            rendered.push('\n');
        }
    }
    ensure!(rendered.contains(&format!("ExecStart={RUNTIME}/horizon-epoch239-import-source probe\n"))
        && rendered.matches("ReadOnlyPaths=").count() == 1
        && rendered.matches("ExecStartPre=").count() == 0,
        "invalid namespace probe source");
    Ok(rendered)
}

fn readonly(path: &Path) -> Result<bool> {
    let name = CString::new(path.as_os_str().as_bytes())?;
    let mut info = MaybeUninit::<libc::statvfs>::uninit();
    let code = unsafe { libc::statvfs(name.as_ptr(), info.as_mut_ptr()) };
    ensure!(code == 0, "statvfs {}: {}", path.display(), std::io::Error::last_os_error());
    let info = unsafe { info.assume_init() };
    Ok(info.f_flag & libc::ST_RDONLY != 0)
}

fn probe() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 1000, "namespace probe must run as ubuntu");
    let prepared: Value = serde_json::from_slice(&fs::read(format!("{RUNTIME}/preparation.json"))?)?;
    let expected = prepared["read_only_masks"].as_array().context("prepared masks missing")?;
    let actual = masks()?;
    ensure!(actual.len() == expected.len(), "mask catalog changed after rendering");
    for (path, row) in actual.iter().zip(expected) {
        ensure!(row.as_str() == path.to_str() && readonly(path)?, "unprotected mask: {}", path.display());
    }
    ensure!(!readonly(Path::new(PRIVATE))? && !readonly(Path::new(ARCHIVE))?
        && !readonly(Path::new(SIDECAR))? && !readonly(Path::new("/home/ubuntu/horizon"))?
        && !readonly(Path::new(LEASE_SCOPE))? && !readonly(&Path::new(LEASE_SCOPE).join("locks"))?,
        "source, destination, or lease mount is read-only");
    let lease = fs::symlink_metadata(Path::new(LEASE_SCOPE).join("locks"))?;
    ensure!(lease.is_dir() && lease.uid() == 1000 && lease.mode() & 0o077 == 0,
        "lease directory is not owner-only");
    let archive = File::open(ARCHIVE)?;
    let sidecar = File::open(SIDECAR)?;
    let destination = File::open("/home/ubuntu/horizon")?;
    ensure!(archive.metadata()?.dev() == destination.metadata()?.dev()
        && archive.metadata()?.dev() == sidecar.metadata()?.dev(),
        "source and destination are on different filesystems");
    ensure!(destination.metadata()?.mode() & 0o200 != 0, "destination is not writable by owner");
    println!("{}", json!({"schema":"horizon-epoch239-native-namespace-proof-v1",
        "mask_count":actual.len(),"source_and_destination_device":archive.metadata()?.dev(),
        "all_masks_read_only":true,"source_and_destination_mounts_writable":true,
        "source_and_destination_same_device":true,"archive_mutations":false,"remote_mutations":false}));
    Ok(())
}

fn write_new(path: &Path, body: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o400).open(path)?;
    file.write_all(body)?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o400))?;
    Ok(())
}

fn main() -> Result<()> {
    if std::env::args().nth(1).as_deref() == Some("probe") { return probe(); }
    ensure!(std::env::args().len() == 1, "unexpected renderer arguments");
    ensure!(unsafe { libc::geteuid() } == 0, "renderer must run as root");
    let source = check_source()?;
    let masks = masks()?;
    let prior = fs::read_to_string(PRIOR_UNIT)?;
    let unit = render(&prior, &masks)?;
    let probe_unit = render_probe(&unit)?;
    let mask_rows = masks.iter().map(|p| p.to_str().unwrap()).collect::<Vec<_>>();
    let preparation = json!({
        "schema":"horizon-epoch239-native-import-source-v1",
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "unit":UNIT,
        "unit_sha256":format!("{:x}", Sha256::digest(unit.as_bytes())),
        "probe_unit":PROBE_UNIT,
        "probe_unit_sha256":format!("{:x}", Sha256::digest(probe_unit.as_bytes())),
        "source":source,
        "prior_unit":{"path":PRIOR_UNIT,"sha256":PRIOR_UNIT_SHA},
        "read_only_masks":mask_rows,
        "first_guard_token_directory":TOKENS,
        "rendered_source_only":true,
        "unit_installed":false,
        "native_namespace_proof_completed":false,
        "fresh_admission_completed":false,
        "archive_mutations":false,
        "remote_mutations":false,
    });
    let root = Path::new(ROOT);
    fs::create_dir(root).with_context(|| format!("create new source directory {ROOT}"))?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    write_new(&root.join(UNIT), unit.as_bytes())?;
    write_new(&root.join(PROBE_UNIT), probe_unit.as_bytes())?;
    write_new(&root.join("preparation.json"), &serde_json::to_vec_pretty(&preparation)?)?;
    File::open(root)?.sync_all()?;
    File::open(root.parent().context("source directory parent")?)?.sync_all()?;
    println!("{ROOT}/{UNIT}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_names_reject_systemd_syntax() {
        for bad in ["a b", "a\"b", "a/b", "a\\b", "a\nb", ""] {
            assert!(!safe_component(bad));
        }
        assert!(safe_component("qualification-247-reboot-20261117-v2"));
    }

    #[test]
    fn rendered_unit_keeps_first_guard_and_exact_native_import() {
        let prior = "[Unit]\nDescription=old\n[Service]\nReadWritePaths=/home/ubuntu\nReadOnlyPaths=\"/old\"\nExecStart=/old 245\nStandardOutput=append:/old.log\nStandardError=append:/old.log\n";
        let masks = vec![PathBuf::from("/home/ubuntu/workspace"), PathBuf::from("/home/ubuntu/.jetstreamer-private/qualification-247-reboot-20261117-v2")];
        let unit = render(prior, &masks).unwrap();
        assert!(unit.contains("ExecStartPre=/usr/bin/sleep 60\n"));
        assert!(unit.contains(&format!("ExecStartPre=/usr/bin/test -f {TOKENS}/${{INVOCATION_ID}}/guard-admission.json\n")));
        assert!(unit.contains("--recover-staged-cohort-only") && unit.contains("--publish-through-epoch=239"));
        assert!(unit.contains(BATCH) && unit.contains(MANIFEST) && unit.contains(FINGERPRINT));
        assert!(!unit.contains("ExecStart=/old") && !unit.contains("/old.log"));
    }

    #[test]
    fn predecessor_gate_change_is_rejected() {
        let prior = "Description=x\nReadWritePaths=/home/ubuntu\nReadOnlyPaths=/old\nExecStartPre=/bin/true\nExecStart=/old\nStandardOutput=x\nStandardError=x\n";
        assert!(render(prior, &[PathBuf::from("/safe")]).is_err());
    }

    #[test]
    fn probe_uses_the_importers_namespace_without_its_mutating_command() {
        let prior = "[Unit]\nDescription=old\n[Service]\nType=exec\nRuntimeMaxSec=12h\nReadWritePaths=/home/ubuntu\nReadOnlyPaths=/old\nExecStart=/old\nStandardOutput=append:/old.log\nStandardError=append:/old.log\n";
        let import = render(prior, &[PathBuf::from("/home/ubuntu/workspace")]).unwrap();
        let probe = render_probe(&import).unwrap();
        let import_masks = import.lines().find(|s| s.starts_with("ReadOnlyPaths=")).unwrap();
        assert!(probe.lines().any(|s| s == import_masks));
        assert!(probe.contains("Type=oneshot\n") && probe.contains("TimeoutStartSec=300\n"));
        assert!(!probe.contains("--recover-staged-cohort-only") && !probe.contains("ExecStartPre="));
    }
}
