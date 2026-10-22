//! Exact144 independent private scans. A read-only bind supplies the canonical
//! plugin filename without copying109GB or creating a checksum/public archive.
#[allow(dead_code)]
#[path = "epoch141_ledger_common.rs"]
mod evidence;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
const UNIT: &str = "horizon-qualify-144-checkpoint-continuation-20261022-v1.service";
const IID: &str = "8fddd3ef045c4fe5b12c7d25f43a4b73";
const SOURCE: &str = "/home/sol/.jetstreamer-private/checkpoint-continuation-144-20261022-v1/output/epoch-144-checkpoint-restart-v4.jet";
const VIEW: &str = "/run/horizon-epoch144-private-verification-20261022-v1/epoch-144.jet";
const FULL: &str = "41c03e493daa309ab7cffd9760b4e6cfe2195b3af0bb13a17f19508eb929d6e7";
const PLUGIN: &str = "73e7535b9cedc7e565a92735ca6e07c7efb8e66755a6d5272ed16649b4d8cee9";
const FLOOR: u64 = 4_577_238_421_504;
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Stage {
    Full,
    Plugin,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    stage: Stage,
    producer_outcome: Bound,
    provenance_expectation: Bound,
    boundaries: Bound,
    observer: Bound,
    verifier: Bound,
    state_directory: PathBuf,
}
fn read(b: &Bound, immutable: bool) -> Result<Value> {
    Ok(serde_json::from_slice(&evidence::bound_file(
        &b.path,
        &b.sha256,
        4 << 20,
        immutable,
    )?)?)
}
fn validate(p: &Plan, v: &Value, e: &Value, b: &Value) -> Result<()> {
    let stage = if p.stage == Stage::Full {
        "full"
    } else {
        "plugin"
    };
    ensure!(
        p.schema == "jetstreamer-private144-verification-plan-v2"
            && p.state_directory
                == Path::new(
                    "/var/lib/jetstreamer/horizon-epoch144-private-verification-20261022-v1"
                )
                .join(stage),
        "foreign144scan plan"
    );
    ensure!(
        p.verifier.sha256 == if p.stage == Stage::Full { FULL } else { PLUGIN },
        "unqualified verifier"
    );
    ensure!(
        v["schema"] == "jetstreamer-private-epoch144-checkpoint-continuation-v2"
            && v["producer_unit"] == UNIT
            && v["producer_invocation_id"] == IID
            && v["private_output"] == SOURCE
            && v["assembly"]["slots_merged"] == 432000
            && v["assembly"]["provenance_version"] == 4
            && v["fresh_prefix_full_validation_passed"] == true
            && v["fresh_native_checkpoint_matches"] == true,
        "not complete private144 assembly"
    );
    ensure!(
        e["schema"] == "jetstreamer-private-epoch144-provenance-expectation-v2"
            && e["epoch"] == 144
            && e["producer_outcome"] == serde_json::to_value(&p.producer_outcome)?
            && e["source_manifest_scope_validated"] == true
            && e["assembled_target_opened"] == false
            && e["expected_provenance_sha256"]
                .as_str()
                .is_some_and(evidence::is_sha),
        "wrong independent provenance expectation"
    );
    ensure!(
        b["schema"] == "jetstreamer-private144-finalized-boundaries-v2"
            && b["epoch"] == 144
            && b["blocks"].as_array().is_some_and(|a| a.len() == 2)
            && b["blocks"][0]["slot"] == 62207999
            && b["blocks"][1]["slot"] == 62639999
            && b["blocks"][0]["blockhash"] == "6XkxRpAhiXkxqFfD4nqgydUUYAanNfoFLWwWYgq4zvMT"
            && b["blocks"][1]["blockhash"] == "Fnoa95TKZ1U419CubZrxYDtFnqadRmvM554FFi2xSizB",
        "wrong finalized boundaries"
    );
    for x in [v, e, b] {
        for flag in [
            "canonical_sidecar_authorized",
            "publication_authorized",
            "r2_mutations",
        ] {
            ensure!(x[flag] == false, "input grants authority:{flag}");
        }
    }
    Ok(())
}
fn terminal() -> Result<Value> {
    let o=Command::new("/usr/bin/systemctl").args(["show",UNIT,"--property=InvocationID,MainPID,NRestarts,Restart,Result,ExecMainStatus,ActiveState,SubState"]).output()?;
    ensure!(o.status.success(), "terminal observation failed");
    let t = std::str::from_utf8(&o.stdout)?;
    let f: std::collections::BTreeMap<_, _> = t.lines().filter_map(|l| l.split_once('=')).collect();
    for (k, v) in [
        ("InvocationID", IID),
        ("MainPID", "0"),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
        ("ActiveState", "active"),
        ("SubState", "exited"),
    ] {
        ensure!(f.get(k) == Some(&v), "producer not exact terminal:{k}");
    }
    Ok(json!(f))
}
fn open(path: &Path) -> Result<File> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical archive path"
    );
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.len() > 0
            && m.len() <= 112u64 << 30,
        "unsafe archive identity/size"
    );
    ensure!(
        evidence::identity(&m) == evidence::identity(&fs::symlink_metadata(path)?),
        "archive changed while opening"
    );
    Ok(f)
}
fn measured(path: &Path) -> Result<(String, Value)> {
    let mut f = open(path)?;
    let before = evidence::identity(&f.metadata()?);
    let mut sha = Sha256::new();
    let mut buf = [0; 128 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        sha.update(&buf[..n]);
    }
    ensure!(
        before == evidence::identity(&f.metadata()?)
            && before == evidence::identity(&fs::symlink_metadata(path)?),
        "archive changed during hashing"
    );
    Ok((format!("{:x}", sha.finalize()), json!(before)))
}
fn command(p: &Plan, expected: &Value) -> Vec<String> {
    if p.stage == Stage::Plugin {
        return vec![
            "144:144".into(),
            Path::new(VIEW).parent().unwrap().display().to_string(),
            "--threads".into(),
            "8".into(),
            "--verify-only".into(),
        ];
    }
    vec![
        VIEW.into(),
        "--full".into(),
        "--anchor".into(),
        "62207999".into(),
        "6XkxRpAhiXkxqFfD4nqgydUUYAanNfoFLWwWYgq4zvMT".into(),
        "--expected-terminal".into(),
        "62639999".into(),
        "Fnoa95TKZ1U419CubZrxYDtFnqadRmvM554FFi2xSizB".into(),
        "--threads".into(),
        "8".into(),
        "--expected-provenance-sha256".into(),
        expected["expected_provenance_sha256"]
            .as_str()
            .unwrap()
            .into(),
    ]
}
fn utc_seconds(s: &str) -> Result<u64> {
    let input = std::ffi::CString::new(s)?;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let end = unsafe { libc::strptime(input.as_ptr(), c"%Y-%m-%dT%H:%M:%SZ".as_ptr(), &mut tm) };
    ensure!(
        !end.is_null() && unsafe { *end } == 0,
        "invalid observer UTC"
    );
    let seconds = unsafe { libc::timegm(&mut tm) };
    ensure!(
        seconds >= 0
            && format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                tm.tm_year + 1900,
                tm.tm_mon + 1,
                tm.tm_mday,
                tm.tm_hour,
                tm.tm_min,
                tm.tm_sec
            ) == s,
        "noncanonical observer UTC"
    );
    Ok(seconds as u64)
}
fn observer_admission(o: &Value, now: u64) -> Result<()> {
    ensure!(
        o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && o["filesystem"]["conservative_available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= FLOOR)
            && o["host_memory"]["conservative_available_kib"]
                .as_u64()
                .is_some_and(|n| n >= 192 * 1024 * 1024),
        "observer resource envelope insufficient"
    );
    let sample = utc_seconds(o["recorded_at_utc"].as_str().context("observer clock")?)?;
    ensure!(sample <= now && now - sample <= 1800, "stale observer");
    ensure!(
        o["cadence"]["routine_minimum_interval_enforced"] == true
            && o["replays"].as_array().is_some_and(|rows| rows.len() == 4
                && rows.iter().all(|r| r["invocation_binding_stable"] == true
                    && r["controller_after"]["restarts"] == 0
                    && r["producer_after"]["restarts"] == 0)),
        "unstable or non-routine fleet observation"
    );
    Ok(())
}
fn admission(o: &Value) -> Result<()> {
    observer_admission(o, SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let mem = fs::read_to_string("/proc/meminfo")?
        .lines()
        .find_map(|l| {
            l.strip_prefix("MemAvailable:")
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse::<u64>().ok())
        })
        .context("memory available")?;
    let path = std::ffi::CString::new("/home/sol")?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), &mut stat) } == 0,
        "statvfs failed"
    );
    ensure!(
        mem >= 192 * 1024 * 1024
            && stat
                .f_bavail
                .checked_mul(stat.f_frsize)
                .is_some_and(|n| n >= FLOOR),
        "actual verifier admission insufficient"
    );
    Ok(())
}
fn run() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    let check = a.len() == 7 && a[6] == "--check-only";
    ensure!(
        (a.len() == 6 || check)
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: jetstreamer-epoch144-private-verify PLAN --plan-sha256 SHA --self-sha256 SHA [--check-only]"
    );
    evidence::bound_file(&fs::read_link("/proc/self/exe")?, &a[5], 128 << 20, true)?;
    let p: Plan = serde_json::from_slice(&evidence::bound_file(
        Path::new(&a[1]),
        &a[3],
        1 << 20,
        true,
    )?)?;
    let outcome = read(&p.producer_outcome, true)?;
    let expected = read(&p.provenance_expectation, true)?;
    let boundaries = read(&p.boundaries, true)?;
    validate(&p, &outcome, &expected, &boundaries)?;
    evidence::bound_file(&p.verifier.path, &p.verifier.sha256, 512 << 20, true)?;
    let owner = terminal()?;
    let source = open(Path::new(SOURCE))?;
    let view = open(Path::new(VIEW))?;
    ensure!(
        evidence::identity(&source.metadata()?) == evidence::identity(&view.metadata()?),
        "canonical view is not the same bound source inode"
    );
    for path in [
        Path::new(SOURCE).with_extension("jet.sha256"),
        Path::new(VIEW).with_extension("jet.sha256"),
    ] {
        ensure!(
            matches!(fs::symlink_metadata(path),Err(e)if e.kind()==std::io::ErrorKind::NotFound),
            "private scan must remain sidecar-free"
        );
    }
    admission(&read(&p.observer, false)?)?;
    if check {
        println!("private144 scan preflight passed; no archive hash,child scan or writes");
        return Ok(());
    }
    let before = measured(Path::new(SOURCE))?;
    evidence::write_receipt(
        &p.state_directory.join("intent.json"),
        &json!({"schema":"jetstreamer-private144-scan-intent-v2","plan_sha256":a[3],"stage":p.stage,"archive_sha256":before.0,"archive_identity":before.1,"source":SOURCE,"canonical_view":VIEW,"copy_performed":false,"producer":owner,"publication_authorized":false,"r2_mutations":false}),
    )?;
    let args = command(&p, &expected);
    let log_path = p.state_directory.join("scan.log");
    let mut log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&log_path)?;
    let start = Instant::now();
    let status = Command::new(&p.verifier.path)
        .args(&args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log.try_clone()?)
        .status()?;
    log.flush()?;
    log.sync_all()?;
    File::open(&p.state_directory)?.sync_all()?;
    ensure!(
        status.success(),
        "private scan failed; preserve exact scan log:{status}"
    );
    ensure!(
        measured(Path::new(SOURCE))? == before
            && evidence::identity(&source.metadata()?) == evidence::identity(&view.metadata()?),
        "archive/view changed during scan"
    );
    let after = terminal()?;
    evidence::bound_file(&p.verifier.path, &p.verifier.sha256, 512 << 20, true)?;
    read(&p.producer_outcome, true)?;
    read(&p.provenance_expectation, true)?;
    read(&p.boundaries, true)?;
    evidence::write_receipt(
        &p.state_directory.join("verification.json"),
        &json!({"schema":"jetstreamer-private144-independent-scan-v2","epoch":144,"stage":p.stage,
        "plan":{"path":a[1],"sha256":a[3]},"runner_sha256":a[5],"producer_outcome":p.producer_outcome,"producer_terminal":after,
        "provenance_expectation":p.provenance_expectation,"boundaries":p.boundaries,"verifier":p.verifier,"arguments":args,"elapsed_millis":u64::try_from(start.elapsed().as_millis())?,
        "exit_code":0,"archive_path":SOURCE,"archive_sha256":before.0,"archive_identity":before.1,"canonical_view":VIEW,"copy_performed":false,
        "runtime_admission_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"retirement_authorized":false,"r2_mutations":false}),
    )?;
    Ok(())
}
fn main() -> Result<()> {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn fixture() -> (Plan, Value, Value, Value) {
        let bound = || Bound {
            path: "/sealed/input".into(),
            sha256: "a".repeat(64),
        };
        let p = Plan {
            schema: "jetstreamer-private144-verification-plan-v2".into(),
            stage: Stage::Full,
            producer_outcome: bound(),
            provenance_expectation: bound(),
            boundaries: bound(),
            observer: bound(),
            verifier: Bound {
                path: "/sealed/verify_archive".into(),
                sha256: FULL.into(),
            },
            state_directory:
                "/var/lib/jetstreamer/horizon-epoch144-private-verification-20261022-v1/full".into(),
        };
        let v = json!({"schema":"jetstreamer-private-epoch144-checkpoint-continuation-v2","producer_unit":UNIT,"producer_invocation_id":IID,
            "private_output":SOURCE,"assembly":{"slots_merged":432000,"provenance_version":4},"fresh_prefix_full_validation_passed":true,
            "fresh_native_checkpoint_matches":true,"canonical_sidecar_authorized":false,"publication_authorized":false,"r2_mutations":false});
        let e = json!({"schema":"jetstreamer-private-epoch144-provenance-expectation-v2","epoch":144,"producer_outcome":p.producer_outcome,
            "source_manifest_scope_validated":true,"assembled_target_opened":false,"expected_provenance_sha256":"b".repeat(64),
            "canonical_sidecar_authorized":false,"publication_authorized":false,"r2_mutations":false});
        let b = json!({"schema":"jetstreamer-private144-finalized-boundaries-v2","epoch":144,"blocks":[
            {"slot":62207999,"blockhash":"6XkxRpAhiXkxqFfD4nqgydUUYAanNfoFLWwWYgq4zvMT"},
            {"slot":62639999,"blockhash":"Fnoa95TKZ1U419CubZrxYDtFnqadRmvM554FFi2xSizB"}],
            "canonical_sidecar_authorized":false,"publication_authorized":false,"r2_mutations":false});
        (p, v, e, b)
    }
    #[test]
    fn commands_bind_strict_full_and_independent_plugin_without_copy_or_sidecar() {
        let (mut p, v, e, b) = fixture();
        validate(&p, &v, &e, &b).unwrap();
        let args = command(&p, &e);
        assert_eq!(args.len(), 12);
        assert_eq!(args[0], VIEW);
        assert_eq!(args[1], "--full");
        assert_eq!(args[2], "--anchor");
        assert_eq!(args[5], "--expected-terminal");
        assert_eq!(args[10], "--expected-provenance-sha256");
        assert!(
            !args
                .iter()
                .any(|a| a == "--internal-full" || a == "--bench")
        );
        p.stage = Stage::Plugin;
        p.verifier.sha256 = PLUGIN.into();
        p.state_directory.set_file_name("plugin");
        validate(&p, &v, &e, &b).unwrap();
        assert_eq!(
            command(&p, &e),
            vec![
                "144:144",
                Path::new(VIEW).parent().unwrap().to_str().unwrap(),
                "--threads",
                "8",
                "--verify-only"
            ]
        );
    }
    #[test]
    fn wrong_owner_provenance_boundary_tool_or_authority_is_fatal() {
        let (mut p, v, e, b) = fixture();
        for (key, value) in [
            ("producer_invocation_id", json!("foreign")),
            ("publication_authorized", json!(true)),
        ] {
            let mut bad = v.clone();
            bad[key] = value;
            assert!(validate(&p, &bad, &e, &b).is_err());
        }
        let mut bad = e.clone();
        bad["producer_outcome"]["sha256"] = json!("c".repeat(64));
        assert!(validate(&p, &v, &bad, &b).is_err());
        let mut bad = b.clone();
        bad["blocks"][1]["slot"] = json!(62639998);
        assert!(validate(&p, &v, &e, &bad).is_err());
        p.verifier.sha256 = PLUGIN.into();
        assert!(validate(&p, &v, &e, &b).is_err());
    }
    #[test]
    fn observer_clock_and_resource_floor_are_real_v2_fields() {
        let time = "2026-10-22T01:28:00Z";
        let now = utc_seconds(time).unwrap();
        let o = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":time,
            "filesystem":{"conservative_available_bytes":FLOOR},"host_memory":{"conservative_available_kib":192u64*1024*1024},
            "cadence":{"routine_minimum_interval_enforced":true},"replays":(0..4).map(|_|json!({"invocation_binding_stable":true,"controller_after":{"restarts":0},"producer_after":{"restarts":0}})).collect::<Vec<_>>()});
        observer_admission(&o, now + 1800).unwrap();
        assert!(observer_admission(&o, now + 1801).is_err());
        assert!(observer_admission(&o, now - 1).is_err());
        let mut bad = o.clone();
        bad["filesystem"]["conservative_available_bytes"] = json!(FLOOR - 1);
        assert!(observer_admission(&bad, now).is_err());
        for time in [
            "2026-02-30T01:28:00Z",
            "2026-10-22T1:28:00Z",
            "2026-10-22T01:28:00Zextra",
        ] {
            assert!(utc_seconds(time).is_err());
        }
    }
    #[test]
    fn archive_gate_rejects_symlinks_and_measures_unchanged_file() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("archive");
        fs::write(&p, b"exact private bytes").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        let result = measured(&p).unwrap();
        assert_eq!(result.0, evidence::sha(b"exact private bytes"));
        let alias = d.path().join("alias");
        std::os::unix::fs::symlink(&p, &alias).unwrap();
        assert!(open(&alias).is_err());
    }
}
