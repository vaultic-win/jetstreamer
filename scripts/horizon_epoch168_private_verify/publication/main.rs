//! A native suballocation of the drained 167 tail for the two-thread 168 uploader.
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[allow(dead_code)]
#[path = "../custody.rs"]
mod custody;
use custody::{Bound, Opened, bound, num, reference, string};
mod lifecycle;
mod price;

const RT: &str = "/var/lib/jetstreamer/horizon_runtime_data";
const STATE: &str = "epoch168-exact-publication-v1";
const TOOLS: &str = "admission-tools-v3";
const BINARY: &str = "publication";
const LOCK: &str = "/run/horizon-epoch171-to136-g1.operation.lock";
const UNIT: &str = "horizon-retained-publish-168-20261128-v1.service";
const ARCHIVE: &str =
    "/home/sol/.jetstreamer-private/epoch168-private-assembly-20261127-v1/output/epoch-168.jet";
const ARCHIVE_SHA: &str = "311d78ee8e4ae91ed2e868e1b9de98f5edd6433b45796b2744374fbf47dfc994";
const LENGTH: u64 = 121_787_223_572;
const MEMORY: u64 = 8 << 30;
const META: u64 = 16 << 20;
const CPU: u64 = 2_000_000;
const WORKSPACE: &str = "008436fe1b74606331262bf0f55166bd34f923adb3bcb3cacd14f96211fdaca8";
const RECONCILED: &str = "b47871dcbdf07f32a729cf32b60375e7b1e8c2cb2d0028e7b0d672a95d5c9b7f";
const PAIR: &str = "d66e2c6b8396600f08e25f58963939ebd4560697febf2d83a5c5b150312249d8";
const RECON: &str = "epoch168-private-playback-reconciliation-20261128-v1/ORIGINAL_PRIVATE_PLAYBACK_RECONCILED.json";

fn root() -> PathBuf {
    Path::new(RT).join(STATE)
}
fn data() -> PathBuf {
    root().join("admission")
}
fn fixed(path: impl Into<PathBuf>, sha256: &str) -> Bound {
    Bound {
        path: path.into(),
        sha256: sha256.into(),
    }
}
fn nanos() -> Result<u128> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())
}
fn boot() -> Result<String> {
    Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', ""))
}
fn lock() -> Result<File> {
    let f = File::open(LOCK)?;
    ensure!(
        unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } == 0,
        "operation lock unavailable"
    );
    ensure!(
        fs::metadata(LOCK)?.ino() == f.metadata()?.ino(),
        "different operation lock"
    );
    Ok(f)
}
fn private_directory(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && m.is_dir()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o777 == 0o700
            && m.dev() == fs::metadata("/home/sol")?.dev(),
        "different private directory {}",
        path.display()
    );
    Ok(())
}
fn write_once(path: &Path, doc: &Value) -> Result<Bound> {
    let parent = path.parent().context("no receipt parent")?;
    let mut f = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(f.as_file_mut(), doc)?;
    f.write_all(b"\n")?;
    f.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    f.as_file().sync_all()?;
    f.persist_noclobber(path)?;
    File::open(parent)?.sync_all()?;
    bound(path)
}
fn own_seal() -> Result<Bound> {
    let dir = root().join(TOOLS);
    let receipt = bound(&dir.join("deployment-seal-receipt.json"))?;
    let seal = receipt.json()?;
    let expected = dir.join(BINARY);
    let m = fs::metadata(&expected)?;
    let me = fs::metadata("/proc/self/exe")?;
    ensure!(
        seal["destination"] == dir.to_str().unwrap() && (m.dev(), m.ino()) == (me.dev(), me.ino()),
        "use sealed 168 admission binary"
    );
    let sub = seal["members"]
        .as_array()
        .context("seal members")?
        .iter()
        .find(|v| v["name"] == BINARY)
        .context("no native member")?;
    ensure!(
        sub["bytes"] == m.len() && m.mode() & 0o777 == 0o555 && m.uid() == 0 && m.nlink() == 1,
        "admission executable changed"
    );
    fixed(expected, string(sub, "sha256")?).binary()?;
    Ok(receipt)
}
fn scope() -> Result<Value> {
    private_directory(&root())?;
    let ws = fixed(
        root().join("PUBLICATION_WORKSPACE_PREPARED.json"),
        WORKSPACE,
    )
    .json()?;
    let rec = fixed(Path::new(RT).join(RECON), RECONCILED).json()?;
    let pair = fixed(root().join("PRIVATE_VERIFIED_PAIR.json"), PAIR).json()?;
    let archive = Opened::open(Path::new(ARCHIVE))?;
    ensure!(
        ws["epoch"] == 168
            && ws["comparison_memory_request_bytes"] == MEMORY
            && ws["metadata_allowance_bytes"] == META
            && ws["two_thread_publication_uses_zero_archive_scratch"] == true
            && ws["archive_identity"] == serde_json::to_value(&archive.start)?
            && archive.start.len == LENGTH
            && rec["private_native_reports_validated"] == true
            && rec["archive"] == ARCHIVE
            && rec["archive_sha256"] == ARCHIVE_SHA
            && rec["archive_stamp"] == ws["archive_identity"]
            && rec["assembly"] == ws["archive_assembly"]
            && rec["counters"]["slots"] == 432000
            && rec["counters"]["worker_count"] == 2
            && pair["validated_private_playback"]["sha256"] == RECONCILED
            && pair["archive_sha256"] == ARCHIVE_SHA
            && pair["unchanged_archive_identity"] == ws["archive_identity"],
        "workspace, private playback or pinned archive changed"
    );
    for dir in ["publication-receipts", "publication-scratch"] {
        private_directory(&root().join(dir))?;
    }
    let sidecar = &pair["local_sidecar"];
    ensure!(
        sidecar["path"] == format!("{ARCHIVE}.sha256") && sidecar["bytes"] == 80,
        "different local sidecar"
    );
    fixed(string(sidecar, "path")?, string(sidecar, "sha256")?).binary()?;
    let inputs = reference(&ws, "static_inputs")?.json()?;
    ensure!(
        inputs["uploader"]["path"]
            == format!("{RT}/epoch168-current-anza-reader-20261127-v1/jetstreamer-r2")
            && inputs["uploader"]["sha256"]
                == "6a3d88c17fc431e6611c790befa46aa193c7fc27ac0b917ec3e053fbfa34fb62"
            && inputs["plan_before_root_prices_minimum_free_bytes"]["threads"] == 2
            && inputs["canonical_first_upload_argv"][2]
                == Path::new(ARCHIVE).parent().unwrap().to_str().unwrap(),
        "different ordinary uploader or two-thread plan"
    );
    archive.unchanged()?;
    Ok(inputs)
}
fn command(argv: &[&str]) -> Result<String> {
    let output = Command::new(argv[0]).args(&argv[1..]).output()?;
    ensure!(
        output.status.success(),
        "{} failed: {}",
        argv[0],
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}
fn actual() -> Result<(u64, u64)> {
    let mut st = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(c"/home/sol".as_ptr(), st.as_mut_ptr()) } == 0,
        "HOME capacity"
    );
    let st = unsafe { st.assume_init() };
    let text = fs::read_to_string("/proc/meminfo")?;
    let ram = text
        .lines()
        .find_map(|l| l.strip_prefix("MemAvailable:"))
        .context("MemAvailable")?
        .split_whitespace()
        .next()
        .context("missing kB")?
        .parse::<u64>()?
        * 1024;
    Ok((st.f_bavail * st.f_frsize, ram))
}
fn main() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "run native admission as root"
    );
    let args: Vec<String> = std::env::args().skip(1).collect();
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match a.as_slice() {
        ["account"] => {
            let mut input = String::new();
            std::io::stdin().take(4 << 20).read_to_string(&mut input)?;
            price::account(serde_json::from_str(&input)?, &own_seal()?)?
        }
        ["quote", p, h] => price::quote(&fixed(*p, h))?,
        ["admit", p, h, i, s, sock] => {
            lifecycle::admit(&fixed(*p, h), &fixed(*i, s), Path::new(sock))?
        }
        ["enter", p, h] => lifecycle::enter(&fixed(*p, h))?,
        ["finish"] => lifecycle::finish()?,
        ["check-scope"] => {
            let s = scope()?;
            json!({"scope":true,"archive":ARCHIVE,"native":s["uploader"],"threads":2})
        }
        _ => bail!(
            "usage: publication account|quote PROVIDER SHA|admit PROVIDER SHA INVENTORY SHA SSH_AGENT_SOCKET|enter ATTEMPT SHA|finish|check-scope"
        ),
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
