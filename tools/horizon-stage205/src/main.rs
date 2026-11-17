use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

const SOURCE: &str = "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-205-bounded8-refresh421-v1/output/epoch-205-checkpoint-restart-v4.jet";
const DEST: &str = "/home/ubuntu/horizon";
const RECEIPTS: &str = "/home/ubuntu/.jetstreamer-private/epoch205-canonical-stage-20261117-v2";
const LOCK: &str = "/home/ubuntu/.jetstreamer-private/r2-receipts/local-mutation.lock";
const SIZE: u64 = 104_772_252_720;
const SHA: &str = "8a8205ade01bc4a39b5c59b5597841869bf7bd2bbda9f982744e14ac1dd250d7";
const RECOVERY_TEMP: &str = "/home/ubuntu/horizon/.epoch-205.jet.stage-501033";
const FAILED_UNIT: &str = "horizon205-canonical-stage-20261117-v1.service";
const FAILED_ID: &str = "c84065c9c32d4ae8a1ee98b23071d0b6";
const FAILED_INTENT: &str =
    "/home/ubuntu/.jetstreamer-private/epoch205-canonical-stage-20261117-v1/intent.json";
const FAILED_INTENT_SHA: &str = "241405395fe1d22ec74ddeaae0e7801659c2747c5473566c89c07b3950c22cc9";
const FULL: (&str, &str, &str) = (
    "horizon205-internal-full-20261117-v1.service",
    "de93145c5ad74b85bef571859db6216f",
    "RESULT: OK (internal only)",
);
const PLUGIN: (&str, &str, &str) = (
    "horizon205-plugin-diagnostic-20261117-v1.service",
    "d7c75dddfa574f3ca55b93559d8d5611",
    "verified epoch 205 through 8 workers: slots=432000",
);

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hash(path: &Path) -> Result<String> {
    let mut f = if path == Path::new("/proc/self/exe") {
        File::open(path)?
    } else {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?
    };
    let mut h = Sha256::new();
    let mut buf = vec![0; 8 * 1024 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}
fn file(path: &Path, bytes: u64, uid: u32, mode: u32) -> Result<fs::Metadata> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.file_type().is_file() && m.nlink() == 1 && m.len() == bytes,
        "file type, size, or links changed: {}",
        path.display()
    );
    ensure!(
        m.uid() == uid && m.mode() & 0o777 == mode,
        "file custody changed: {}",
        path.display()
    );
    Ok(m)
}
fn dir(path: &Path) -> Result<File> {
    ensure!(
        fs::canonicalize(path)? == path,
        "directory redirects: {}",
        path.display()
    );
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)?;
    ensure!(f.metadata()?.is_dir(), "not directory");
    Ok(f)
}
fn absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => anyhow::bail!("path occupied: {}", path.display()),
        Err(e) => Err(e.into()),
    }
}
fn diagnostic((unit, id, marker): (&str, &str, &str)) -> Result<()> {
    let show = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            unit,
            "-p",
            "Result",
            "-p",
            "ExecMainStatus",
            "--no-pager",
        ])
        .output()?;
    ensure!(show.status.success(), "unit inspection failed");
    let text = String::from_utf8(show.stdout)?;
    ensure!(
        text.lines().any(|s| s == "Result=success")
            && text.lines().any(|s| s == "ExecMainStatus=0"),
        "diagnostic unit failed: {unit}"
    );
    let logs = Command::new("/usr/bin/journalctl")
        .args(["-u", unit, "-o", "json", "--no-pager"])
        .output()?;
    ensure!(logs.status.success(), "diagnostic journal failed");
    let seen = logs
        .stdout
        .split(|b| *b == b'\n')
        .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
        .any(|v| {
            v["_SYSTEMD_INVOCATION_ID"].as_str() == Some(id)
                && v["MESSAGE"].as_str().is_some_and(|m| m.contains(marker))
        });
    ensure!(seen, "exact diagnostic invocation marker missing: {unit}");
    Ok(())
}
fn recovery(source_device: u64) -> Result<()> {
    let show = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            FAILED_UNIT,
            "-p",
            "ActiveState",
            "-p",
            "Result",
            "-p",
            "ExecMainStatus",
            "-p",
            "InvocationID",
            "--no-pager",
        ])
        .output()?;
    ensure!(show.status.success(), "failed unit inspection unavailable");
    let text = String::from_utf8(show.stdout)?;
    for expected in [
        "ActiveState=failed",
        "Result=exit-code",
        "ExecMainStatus=1",
        "InvocationID=c84065c9c32d4ae8a1ee98b23071d0b6",
    ] {
        ensure!(
            text.lines().any(|s| s == expected),
            "failed unit identity changed: {expected}"
        );
    }
    ensure!(
        hash(Path::new(FAILED_INTENT))? == FAILED_INTENT_SHA,
        "failed intent changed"
    );
    let temp = file(Path::new(RECOVERY_TEMP), SIZE, 0, 0o600)?;
    ensure!(
        temp.dev() == source_device && temp.ino() == 518346,
        "failed stage inode changed"
    );
    Ok(())
}
fn rename_noreplace(from: &Path, to: &Path) -> Result<()> {
    let a = CString::new(from.as_os_str().as_encoded_bytes())?;
    let b = CString::new(to.as_os_str().as_encoded_bytes())?;
    ensure!(
        unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                a.as_ptr(),
                libc::AT_FDCWD,
                b.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
        "no clobber rename failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}
fn durable(path: &Path, value: &Value) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(&serde_json::to_vec_pretty(value)?)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    dir(path.parent().context("receipt parent")?)?.sync_all()?;
    Ok(())
}
fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    ensure!(
        args.len() == 4 || (args.len() == 5 && args[4] == "--check-only"),
        "usage: horizon-stage205 PLAN PLAN_SHA256 SELF_SHA256 [--check-only]"
    );
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let raw = fs::read(&args[1])?;
    ensure!(
        sha(&raw) == args[2] && hash(Path::new("/proc/self/exe"))? == args[3],
        "plan or binary hash mismatch"
    );
    let p: Value = serde_json::from_slice(&raw)?;
    ensure!(
        p.as_object().is_some_and(|m| m.len() == 6),
        "unexpected plan fields"
    );
    ensure!(
        p["schema"] == "horizon-stage205-plan-v2"
            && p["source"] == SOURCE
            && p["destination_directory"] == DEST
            && p["receipt_directory"] == RECEIPTS
            && p["expected_bytes"] == SIZE
            && p["expected_sha256"] == SHA,
        "plan identity mismatch"
    );
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(LOCK)?;
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } == 0,
        "mutation lock failed"
    );
    let src = file(Path::new(SOURCE), SIZE, 0, 0o400)?;
    ensure!(
        fs::canonicalize(SOURCE)? == Path::new(SOURCE),
        "source redirects"
    );
    let outdir = dir(Path::new(DEST))?;
    ensure!(outdir.metadata()?.dev() == src.dev(), "cross device stage");
    let receipts = dir(Path::new(RECEIPTS))?;
    ensure!(
        receipts.metadata()?.uid() == 0 && receipts.metadata()?.mode() & 0o777 == 0o700,
        "receipt custody changed"
    );
    let archive = Path::new(DEST).join("epoch-205.jet");
    let sidecar = Path::new(DEST).join("epoch-205.jet.sha256");
    let intent = Path::new(RECEIPTS).join("intent.json");
    let done = Path::new(RECEIPTS).join("completion.json");
    for path in [&archive, &sidecar, &intent, &done] {
        absent(path)?;
    }
    diagnostic(FULL)?;
    diagnostic(PLUGIN)?;
    recovery(src.dev())?;
    if args.len() == 5 {
        println!("stage preflight passed");
        return Ok(());
    }
    let cdir = CString::new(DEST)?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::statvfs(cdir.as_ptr(), &mut stat) } == 0,
        "statvfs failed"
    );
    ensure!(
        (stat.f_bavail as u128) * (stat.f_frsize as u128) > SIZE as u128 + 200_000_000_000,
        "insufficient reserve"
    );
    durable(
        &intent,
        &json!({"schema":"horizon-stage205-intent-v2","source":SOURCE,"source_device":src.dev(),"source_inode":src.ino(),"size":SIZE,"sha256":SHA,"destination":archive,"recovery_temp":RECOVERY_TEMP,"recovery_inode":518346,"failed_unit":FAILED_UNIT,"failed_invocation":FAILED_ID,"failed_intent_sha256":FAILED_INTENT_SHA,"full_unit":FULL.0,"full_invocation":FULL.1,"plugin_unit":PLUGIN.0,"plugin_invocation":PLUGIN.1,"r2_mutations":false}),
    )?;
    let tmp = Path::new(RECOVERY_TEMP).to_path_buf();
    let tmp_sidecar = Path::new(DEST).join(format!(
        ".epoch-205.jet.sha256.stage-{}",
        std::process::id()
    ));
    ensure!(
        hash(Path::new(SOURCE))? == SHA,
        "private source digest mismatch"
    );
    ensure!(hash(&tmp)? == SHA, "recovery copy digest mismatch");
    let after = file(Path::new(SOURCE), SIZE, 0, 0o400)?;
    ensure!(
        after.dev() == src.dev()
            && after.ino() == src.ino()
            && after.mtime() == src.mtime()
            && after.mtime_nsec() == src.mtime_nsec(),
        "source changed during copy"
    );
    recovery(src.dev())?;
    let output = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)?;
    ensure!(
        unsafe { libc::fchown(output.as_raw_fd(), 1000, 1000) } == 0,
        "archive chown failed"
    );
    output.set_permissions(fs::Permissions::from_mode(0o440))?;
    output.sync_all()?;
    ensure!(
        file(&tmp, SIZE, 1000, 0o440)?.ino() == 518346,
        "recovered copy identity changed"
    );
    let sidecar_bytes = format!("{SHA}  epoch-205.jet\n");
    let mut sf = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp_sidecar)?;
    sf.write_all(sidecar_bytes.as_bytes())?;
    ensure!(
        unsafe { libc::fchown(sf.as_raw_fd(), 1000, 1000) } == 0,
        "sidecar chown failed"
    );
    sf.set_permissions(fs::Permissions::from_mode(0o440))?;
    sf.sync_all()?;
    absent(&archive)?;
    absent(&sidecar)?;
    rename_noreplace(&tmp, &archive)?;
    outdir.sync_all()?;
    rename_noreplace(&tmp_sidecar, &sidecar)?;
    outdir.sync_all()?;
    let staged = file(&archive, SIZE, 1000, 0o440)?;
    ensure!(
        staged.dev() == src.dev()
            && staged.ino() != src.ino()
            && fs::read(&sidecar)? == sidecar_bytes.as_bytes(),
        "canonical pair identity mismatch"
    );
    durable(
        &done,
        &json!({"schema":"horizon-stage205-completion-v2","epoch":205,"source":SOURCE,"destination":archive,"source_inode":src.ino(),"destination_inode":staged.ino(),"bytes":SIZE,"sha256":SHA,"sidecar_sha256":sha(sidecar_bytes.as_bytes()),"intent_sha256":hash(&intent)?,"failed_intent_sha256":FAILED_INTENT_SHA,"reused_recovery_temp":true,"source_preserved":true,"canonical_pair_present":true,"full_unit":FULL.0,"full_invocation":FULL.1,"plugin_unit":PLUGIN.0,"plugin_invocation":PLUGIN.1,"r2_mutations":false,"verification_authorized":false,"upload_authorized":false,"retirement_authorized":false}),
    )?;
    println!("epoch 205 canonical pair staged");
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_clobber_preserves_both_files() {
        let root =
            std::env::temp_dir().join(format!("horizon-stage205-test-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let a = root.join("source");
        let b = root.join("destination");
        fs::write(&a, b"original").unwrap();
        fs::write(&b, b"existing").unwrap();
        assert!(rename_noreplace(&a, &b).is_err());
        assert_eq!(fs::read(&a).unwrap(), b"original");
        assert_eq!(fs::read(&b).unwrap(), b"existing");
        fs::remove_dir_all(root).unwrap();
    }
}
