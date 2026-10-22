//! Dormant exact144 assembly-only recovery. No worker, replay, sidecar or R2.
//! The original producer must have timed out; a successful/live owner forbids
//! this fallback. Fresh distinct admission and a guard remain mandatory.
use provenance as evidence;
#[allow(dead_code)]
#[path = "jetstreamer-epoch144-provenance-expectation.rs"]
mod provenance;
use anyhow::{Context, Result, ensure};
use jetstreamer_horizon::archive::*;
use jetstreamer_node::{archive_checksum::*, segment_manifest::*};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufReader, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
const ORIGINAL: &str = "horizon-qualify-144-checkpoint-continuation-20261022-v1.service";
const ORIGINAL_IID: &str = "8fddd3ef045c4fe5b12c7d25f43a4b73";
const LEASE: &str = "/home/sol/.jetstreamer-private/checkpoint-continuation-144.lock";
const UNIT: &str = "horizon-qualify-144-assembly-only-recovery-20261022-v1.service";
const ROOT: &str = "/var/lib/jetstreamer/horizon-epoch144-assembly-only-20261022-v1";
const PREFIX: &str = "/home/sol/.jetstreamer-private/epoch144-upgradeable-loader-focus-20261016-v1/output/epoch-144-through-62639490.jet";
const SUFFIX: &str = "/home/sol/.jetstreamer-private/checkpoint-continuation-144-20261022-v1/output/epoch-144-suffix.jet";
const PREFIX_SHA: &str = "917f700274c0ff0386cd8be2f27eb2ace9f3bc7dff38e1010d0c04bb79b8c273";
const SUFFIX_SHA: &str = "3df30cabba516ff6de39bfc236fca030e3bb75b45603d88ef7baf7a6d669a414";
const PREFIX_MANIFEST: &str = "691d5f3768b8c283678937b49790606b6091d4ab632372bfff38664c005b544a";
const SUFFIX_MANIFEST: &str = "065445bef8d301a45a24ba8e14f34b2c0c06906a9cfe7a06cbfd04eeba3f15ce";
const BASELINE: u64 = 3_916_063_202_758;
const PEAK: u64 = 160 << 30;
const MAX_ARCHIVE: u64 = 112 << 30;
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    assembler_sha256: String,
    prefix_manifest: Bound,
    suffix_manifest: Bound,
    admission: Bound,
    output_root: PathBuf,
    maximum_runtime_seconds: u64,
    maximum_archive_bytes: u64,
}
fn read(b: &Bound) -> Result<Value> {
    Ok(serde_json::from_slice(&evidence::bound_file(
        &b.path,
        &b.sha256,
        4 << 20,
        true,
    )?)?)
}
fn scope(p: &Plan, self_sha: &str) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-private144-assembly-only-plan-v1"
            && p.assembler_sha256 == self_sha
            && evidence::is_sha(self_sha)
            && p.prefix_manifest.sha256 == PREFIX_MANIFEST
            && p.suffix_manifest.sha256 == SUFFIX_MANIFEST
            && p.output_root == Path::new(ROOT)
            && p.maximum_runtime_seconds == 86400
            && p.maximum_archive_bytes == MAX_ARCHIVE,
        "foreign assembly-only plan"
    );
    Ok(())
}
fn timeout_state(v: &Value) -> Result<()> {
    ensure!(
        v["InvocationID"] == ORIGINAL_IID
            && v["MainPID"] == "0"
            && v["NRestarts"] == "0"
            && v["Restart"] == "no"
            && v["Result"] == "timeout"
            && v["ActiveState"] == "failed"
            && v["SubState"] == "failed"
            && v["RuntimeMaxUSec"] == "2h"
            && matches!(v["ExecMainStatus"].as_str(), Some("9" | "15" | "1")),
        "assembly-only requires original exact terminal timeout, never a live or successful producer"
    );
    Ok(())
}
fn unit(name: &str) -> Result<Value> {
    let o=Command::new("/usr/bin/systemctl").args(["show",name,"--property=InvocationID,MainPID,NRestarts,Restart,Result,ActiveState,SubState,RuntimeMaxUSec,ExecMainStatus,Type,ExecStart"]).output()?;
    ensure!(o.status.success(), "unit observation failed");
    let fields: serde_json::Map<_, _> = std::str::from_utf8(&o.stdout)?
        .lines()
        .filter_map(|s| s.split_once('='))
        .map(|(k, v)| (k.into(), json!(v)))
        .collect();
    Ok(Value::Object(fields))
}
fn admission(p: &Plan, a: &Value, now: u64) -> Result<u64> {
    ensure!(
        a["schema"] == "jetstreamer-private144-assembly-only-admission-v1"
            && a["admitted"] == true
            && a["assembly_only_no_replay"] == true
            && a["assembler_sha256"] == p.assembler_sha256
            && a["prefix_sha256"] == PREFIX_SHA
            && a["suffix_sha256"] == SUFFIX_SHA
            && a["prefix_manifest_sha256"] == PREFIX_MANIFEST
            && a["suffix_manifest_sha256"] == SUFFIX_MANIFEST
            && a["candidate_incremental_peak_bytes"] == PEAK
            && a["protected_existing_floor_bytes"] == BASELINE
            && a["maximum_archive_bytes"] == MAX_ARCHIVE
            && a["maximum_runtime_seconds"] == 86400
            && a["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t <= now && now - t <= 900),
        "missing/stale exact assembly-only admission"
    );
    for k in [
        "replay_launch_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "r2_mutations",
        "remote_mutations",
    ] {
        ensure!(a[k] == false, "assembly admission grants authority:{k}");
    }
    let floor = a["required_guard_minimum_free_bytes"]
        .as_u64()
        .context("assembly guard floor")?;
    let available = a["available_bytes"]
        .as_u64()
        .context("admission available bytes")?;
    ensure!(
        available >= BASELINE + PEAK && floor >= BASELINE.max(available.saturating_sub(PEAK)),
        "assembly guard lost older claims or experimental envelope"
    );
    ensure!(
        a["memory_available_kib"]
            .as_u64()
            .is_some_and(|n| n >= 128 * 1024 * 1024),
        "assembly admission lacks memory reserve"
    );
    Ok(floor)
}
fn free(path: &Path) -> io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let p = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(p.as_ptr(), &mut s) } != 0 {
        return Err(io::Error::last_os_error());
    }
    s.f_bavail
        .checked_mul(s.f_frsize)
        .ok_or_else(|| io::Error::other("free space overflow"))
}
struct BoundedOutput {
    file: File,
    bytes: u64,
    maximum: u64,
    floor: u64,
    started: Instant,
    filesystem: PathBuf,
}
impl Write for BoundedOutput {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if self
            .bytes
            .checked_add(b.len() as u64)
            .is_none_or(|n| n > self.maximum)
            || self.started.elapsed().as_secs() >= 86400
        {
            return Err(io::Error::other(
                "assembly output/time bound exceeded; preserve partial",
            ));
        }
        if free(&self.filesystem)? < self.floor {
            return Err(io::Error::other("assembly guard floor crossed"));
        }
        let n = self.file.write(b)?;
        self.bytes += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
fn absent_sidecar(path: &Path) -> Result<()> {
    ensure!(
        matches!(fs::symlink_metadata(path.with_extension("jet.sha256")),Err(e)if e.kind()==io::ErrorKind::NotFound),
        "private source/output has checksum"
    );
    Ok(())
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn run() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    let check = a.len() == 7 && a[6] == "--check-only";
    ensure!(
        (a.len() == 6 || check)
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: jetstreamer-epoch144-assembly-only PLAN --plan-sha256 SHA --self-sha256 SHA [--check-only]"
    );
    evidence::bound_file(&fs::read_link("/proc/self/exe")?, &a[5], 128 << 20, true)?;
    let p: Plan = serde_json::from_slice(&evidence::bound_file(
        Path::new(&a[1]),
        &a[3],
        1 << 20,
        true,
    )?)?;
    scope(&p, &a[5])?;
    let prefix: HistoricalSegmentManifest = serde_json::from_value(read(&p.prefix_manifest)?)?;
    let suffix: HistoricalSegmentManifest = serde_json::from_value(read(&p.suffix_manifest)?)?;
    let expected = provenance::derive_pair(&prefix, &suffix, true)?;
    if check {
        println!(
            "assembly-only source/plan preflight passed; no source scan,admission,service observation,replay or writes; original terminal timeout and fresh admission still required"
        );
        return Ok(());
    }
    let original = unit(ORIGINAL)?;
    timeout_state(&original)?;
    // Existing no-overlap lease, never recreated or chmod'ed. Linux flock
    // permits this exclusive lease on a read-only descriptor, so the fallback
    // needs no writable home mount.
    let lease = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(LEASE)?;
    let lm = lease.metadata()?;
    use std::os::fd::AsRawFd;
    ensure!(
        lm.is_file()
            && lm.uid() == 1001
            && lm.nlink() == 1
            && lm.mode() & 0o077 == 0
            && unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "shared144lease occupied or unsafe"
    );
    let own = unit(UNIT)?;
    let iid = std::env::var("INVOCATION_ID").context("persistent assembly unit required")?;
    ensure!(
        own["InvocationID"] == iid
            && own["MainPID"].as_str().and_then(|s| s.parse::<u32>().ok())
                == Some(std::process::id())
            && own["Type"] == "exec"
            && own["Restart"] == "no"
            && own["NRestarts"] == "0"
            && own["ActiveState"] == "active"
            && own["SubState"] == "running"
            && own["RuntimeMaxUSec"] == "1d",
        "assembly owner/24h bound differs"
    );
    let admitted = read(&p.admission)?;
    let floor = admission(&p, &admitted, now()?)?;
    let dir = fs::symlink_metadata(ROOT)?;
    ensure!(
        dir.is_dir()
            && dir.uid() == 0
            && dir.mode() & 0o077 == 0
            && p.output_root.canonicalize()? == p.output_root
            && fs::read_dir(ROOT)?.next().is_none(),
        "assembly root must be fresh/root-private"
    );
    ensure!(
        free(Path::new(ROOT))? >= BASELINE + PEAK && free(Path::new(ROOT))? >= floor,
        "assembly resource floor unavailable"
    );
    let memory = fs::read_to_string("/proc/meminfo")?
        .lines()
        .find_map(|l| {
            l.strip_prefix("MemAvailable:")
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse::<u64>().ok())
        })
        .context("current available memory")?;
    ensure!(
        memory >= 128 * 1024 * 1024,
        "assembly memory reserve unavailable"
    );
    let mut sources = Vec::new();
    let mut identities = Vec::new();
    for (path, manifest, binding, size) in [
        (PREFIX, &prefix, &p.prefix_manifest, 109_159_726_722u64),
        (SUFFIX, &suffix, &p.suffix_manifest, 132_263_319),
    ] {
        absent_sidecar(Path::new(path))?;
        let validated = read_and_validate_segment_manifest_from(Path::new(path), &binding.path)?;
        ensure!(
            validated == *manifest,
            "source manifest changed during independent reread"
        );
        let f = open_regular_nofollow(Path::new(path))?;
        let m = f.metadata()?;
        ensure!(
            m.len() == size && m.nlink() == 1 && m.mode() & 0o022 == 0,
            "source size/ownership changed"
        );
        let identity = archive_file_identity(&f)?;
        let pin = f.try_clone()?;
        sources.push(RuntimeSegmentSource::new(
            BufReader::new(f),
            manifest.archive_sha256,
            manifest.terminal.last_blockhash.parse()?,
        ));
        identities.push((PathBuf::from(path), pin, identity));
    }
    admission(&p, &admitted, now()?)?;
    ensure!(
        unit(ORIGINAL)? == original,
        "original timeout identity changed"
    );
    let target = p.output_root.join("epoch-144-assembly-only-v4.jet");
    absent_sidecar(&target)?;
    evidence::write_receipt(
        &p.output_root.join("intent.json"),
        &json!({"schema":"jetstreamer-private144-assembly-only-intent-v1","unit":UNIT,"invocation_id":iid,"plan_sha256":a[3],"assembler_sha256":a[5],"original_terminal":original,"admission":p.admission,"no_replay":true,"publication_authorized":false,"r2_mutations":false}),
    )?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&target)?;
    let started = Instant::now();
    let output = BoundedOutput {
        file,
        bytes: 0,
        maximum: MAX_ARCHIVE,
        floor,
        started,
        filesystem: p.output_root.clone(),
    };
    let ArchiveProvenance::V4(v4) = &expected else {
        anyhow::bail!("V4 required")
    };
    let (mut output, stats) =
        merge_checkpoint_restart_segments(sources, output, ArchiveWriterConfig::default(), v4)?;
    output.flush()?;
    output.file.sync_all()?;
    File::open(ROOT)?.sync_all()?;
    for (path, f, identity) in identities {
        ensure!(
            archive_file_identity(&f)? == identity
                && path_matches_archive_identity(&path, identity)?,
            "assembly source changed"
        );
        absent_sidecar(&path)?;
    }
    absent_sidecar(&target)?;
    let mut source = open_regular_nofollow(&target)?;
    let mut sha = sha2::Sha256::new();
    std::io::copy(&mut source, &mut sha)?;
    use sha2::Digest;
    evidence::write_receipt(
        &p.output_root.join("assembly.json"),
        &json!({"schema":"jetstreamer-private144-assembly-only-v1","epoch":144,"unit":UNIT,"invocation_id":iid,
        "assembler_sha256":a[5],"plan":{"path":a[1],"sha256":a[3]},"original_terminal":original,"prefix_manifest":p.prefix_manifest,"suffix_manifest":p.suffix_manifest,
        "prefix_sha256":PREFIX_SHA,"suffix_sha256":SUFFIX_SHA,"private_output":target,"archive_sha256":format!("{:x}",sha.finalize()),"archive_bytes":output.bytes,
        "source_archives":stats.source_archives,"slots_merged":stats.slots_merged,"provenance_version":4,"assembly_profile":"jetstreamer-epoch144-assembly-only-v1",
        "elapsed_millis":u64::try_from(started.elapsed().as_millis())?,"no_replay":true,"independent_final_archive_verification_passed":false,"current_plugin_verification_passed":false,
        "canonical_sidecar_authorized":false,"publication_authorized":false,"retirement_authorized":false,"r2_mutations":false}),
    )?;
    Ok(())
}
fn main() -> Result<()> {
    run()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_exact_terminal_timeout_permits_fallback() {
        let good = json!({"InvocationID":ORIGINAL_IID,"MainPID":"0","NRestarts":"0","Restart":"no","Result":"timeout","ActiveState":"failed","SubState":"failed","RuntimeMaxUSec":"2h","ExecMainStatus":"9"});
        timeout_state(&good).unwrap();
        for (k, v) in [
            ("Result", "success"),
            ("MainPID", "42"),
            ("InvocationID", "foreign"),
            ("ActiveState", "active"),
            ("RuntimeMaxUSec", "1d"),
        ] {
            let mut bad = good.clone();
            bad[k] = json!(v);
            assert!(timeout_state(&bad).is_err());
        }
    }
    #[test]
    fn output_never_writes_past_its_declared_cap() {
        let dir = tempfile::tempdir().unwrap();
        let f = tempfile::tempfile_in(dir.path()).unwrap();
        let mut output = BoundedOutput {
            file: f,
            bytes: 0,
            maximum: 3,
            floor: 0,
            started: Instant::now(),
            filesystem: dir.path().into(),
        };
        output.write_all(b"one").unwrap();
        assert!(output.write(b"four").is_err());
        assert_eq!(output.file.metadata().unwrap().len(), 3);
        output.maximum = 10;
        output.floor = u64::MAX;
        assert!(output.write(b"x").is_err());
        assert_eq!(output.file.metadata().unwrap().len(), 3);
        output.floor = 0;
        output.started = Instant::now() - std::time::Duration::from_secs(86400);
        assert!(output.write(b"x").is_err());
        assert_eq!(output.file.metadata().unwrap().len(), 3);
    }
    #[test]
    fn admission_cannot_borrow_native_only_budget_staleness_or_authority() {
        let b = || Bound {
            path: "/sealed/evidence".into(),
            sha256: "a".repeat(64),
        };
        let p = Plan {
            schema: "jetstreamer-private144-assembly-only-plan-v1".into(),
            assembler_sha256: "e".repeat(64),
            prefix_manifest: b(),
            suffix_manifest: b(),
            admission: b(),
            output_root: ROOT.into(),
            maximum_runtime_seconds: 86400,
            maximum_archive_bytes: MAX_ARCHIVE,
        };
        let mut a = json!({"schema":"jetstreamer-private144-assembly-only-admission-v1","admitted":true,"assembly_only_no_replay":true,"assembler_sha256":p.assembler_sha256,
            "prefix_sha256":PREFIX_SHA,"suffix_sha256":SUFFIX_SHA,"prefix_manifest_sha256":PREFIX_MANIFEST,"suffix_manifest_sha256":SUFFIX_MANIFEST,
            "candidate_incremental_peak_bytes":PEAK,"protected_existing_floor_bytes":BASELINE,"maximum_archive_bytes":MAX_ARCHIVE,"maximum_runtime_seconds":86400,
            "recorded_unix_seconds":1000,"required_guard_minimum_free_bytes":BASELINE+100,"available_bytes":BASELINE+PEAK+100,"memory_available_kib":128u64*1024*1024});
        for k in [
            "replay_launch_authorized",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "r2_mutations",
            "remote_mutations",
        ] {
            a[k] = json!(false);
        }
        admission(&p, &a, 1900).unwrap();
        assert!(admission(&p, &a, 1901).is_err());
        assert!(admission(&p, &a, 999).is_err());
        for (k, v) in [
            ("candidate_incremental_peak_bytes", json!(40u64 << 30)),
            ("required_guard_minimum_free_bytes", json!(BASELINE)),
            ("publication_authorized", json!(true)),
            ("memory_available_kib", json!(1)),
        ] {
            let mut bad = a.clone();
            bad[k] = v;
            assert!(admission(&p, &bad, 1000).is_err());
        }
    }
}
