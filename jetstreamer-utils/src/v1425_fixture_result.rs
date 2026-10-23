//! Closed collector for ONE synthetic guarded fixture result. No execution/remote authority.
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
const IID: &str = "e1f9211414d1485b9f290f34c7c8e774";
const WATCH_IID: &str = "f1d49ce2a6cd45c99eb3b7043708452d";
const ROOT: &str =
    "/var/lib/jetstreamer-checkpoint-fixtures/native-v1425-capped-20261023-v1/native-v12-6UWexW";
const RECEIPTS:&str="/var/lib/jetstreamer-v1425-fixture-barrier-20261023-v1/receipts/e1f9211414d1485b9f290f34c7c8e774";
const LOGS:&str="/var/lib/jetstreamer-v1425-native-fixture-run-20261023-v1/attempt-e1f9211414d1485b9f290f34c7c8e774";
const FIXTURE_SHA: &str = "7d0678d3d1edf4f75240bc7d7a800fd1093d61ef3ae7a77fe1348ed74425c539";
const BARRIER_SHA: &str = "0170e2c5b938174a689aa02499e999213e890d475441f29b866b6111a49b2584";
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn read(p: &str, uid: u32, max: u64, evidence: &mut Vec<Value>) -> Result<Vec<u8>> {
    let path = Path::new(p);
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && m.nlink() == 1
            && m.uid() == uid
            && m.mode() & 0o022 == 0
            && m.len() <= max,
        "unsafe result input"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    ensure!(f.metadata()?.ino() == m.ino(), "result input replaced");
    let mut b = Vec::new();
    Read::by_ref(&mut f).take(max + 1).read_to_end(&mut b)?;
    let after = fs::symlink_metadata(path)?;
    ensure!(
        b.len() as u64 <= max
            && m.ino() == after.ino()
            && m.len() == after.len()
            && m.mtime() == after.mtime()
            && m.mtime_nsec() == after.mtime_nsec(),
        "result input changed"
    );
    f.sync_all()?;
    File::open(path.parent().unwrap())?.sync_all()?;
    evidence.push(json!({"path":p,"sha256":sha(&b),"bytes":b.len(),"uid":uid}));
    Ok(b)
}
fn value(p: &str, e: &mut Vec<Value>) -> Result<Value> {
    Ok(serde_json::from_slice(&read(p, 0, 1 << 20, e)?)?)
}
fn take<'a>(b: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    ensure!(b.len() >= n, "truncated native bincode tuple");
    let (a, rest) = b.split_at(n);
    *b = rest;
    Ok(a)
}
fn u64le(b: &mut &[u8]) -> Result<u64> {
    Ok(u64::from_le_bytes(take(b, 8)?.try_into()?))
}
fn vector(b: &mut &[u8]) -> Result<Vec<u8>> {
    let n = u64le(b)?;
    ensure!(n <= 1 << 20, "native bincode length bound");
    Ok(take(b, n as usize)?.to_vec())
}
fn string(b: &mut &[u8]) -> Result<String> {
    Ok(String::from_utf8(vector(b)?)?)
}
fn run() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "result collector requires root"
    );
    let a: Vec<_> = std::env::args().collect();
    ensure!(
        a.len() == 3 && a[1] == "--self-sha256" && sha(&fs::read("/proc/self/exe")?) == a[2],
        "result collector self hash"
    );
    let mut e = Vec::new();
    let first = value(&format!("{RECEIPTS}/first-no-trip.json"), &mut e)?;
    let natural = value(&format!("{RECEIPTS}/natural-completion.json"), &mut e)?;
    let release = value(
        &format!("/var/lib/jetstreamer-v1425-fixture-barrier-20261023-v1/gate/{IID}.release.json"),
        &mut e,
    )?;
    ensure!(
        first["watcher_iid"] == WATCH_IID
            && first["self_sha256"] == BARRIER_SHA
            && first["sample"]["trip"] == false
            && first["watch_plan"]["fixture_iid"] == IID
            && first["watch_plan"]["fixture_pid"] == 1182622
            && first["watch_plan"]["fixture_startticks"] == "113549592"
            && first["watch_plan"]["fixture_start_monotonic"] == "1135495948086",
        "first sample identity"
    );
    ensure!(
        release["first_sample_sha256"] == e[0]["sha256"]
            && release["fixture_iid"] == IID
            && release["fixture_pid"] == 1182622
            && release["fixture_startticks"] == first["watch_plan"]["fixture_startticks"]
            && release["fixture_start_monotonic"] == first["watch_plan"]["fixture_start_monotonic"]
            && release["launch_sha256"] == first["launch_sha256"]
            && release["fixture_sha256"] == FIXTURE_SHA
            && release["watcher_iid"] == WATCH_IID
            && release["watcher_pid"] == first["watcher_pid"]
            && release["watcher_startticks"] == first["watcher_startticks"]
            && release["watcher_start_monotonic"] == first["watcher_start_monotonic"]
            && release["fresh_sample"]["trip"] == false,
        "release binding"
    );
    let t = &natural["terminal"];
    ensure!(
        natural["watch_plan"] == first["watch_plan"]
            && t["InvocationID"] == IID
            && t["MainPID"] == "0"
            && t["Result"] == "success"
            && t["ExecMainStatus"] == "0"
            && t["NRestarts"] == "0"
            && t["UMask"] == "0077",
        "natural terminal result"
    );
    for name in ["stop-intent.json", "stop-submitted.json"] {
        ensure!(
            fs::symlink_metadata(format!("{RECEIPTS}/{name}"))
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "fixture stop frontier exists/unreadable"
        );
    }
    let exec_observed =
        match fs::symlink_metadata(format!("{RECEIPTS}/authenticated-exec-observed.json")) {
            Err(x) if x.kind() == std::io::ErrorKind::NotFound => false,
            Err(x) => return Err(x.into()),
            Ok(_) => {
                value(
                    &format!("{RECEIPTS}/authenticated-exec-observed.json"),
                    &mut e,
                )?;
                true
            }
        };
    let check=value("/var/lib/jetstreamer-v1425-os-guard-fixture-20261023-v1/receipts/e1f9211414d1485b9f290f34c7c8e774/check-1792788894015516187.json",&mut e)?;
    ensure!(
        check["check_only"] == true
            && check["descriptor"]["invocation_id"] == IID
            && check["descriptor"]["start_monotonic"] == "1135495948086"
            && check["target"]["InvocationID"] == IID
            && check["target_after"]["InvocationID"] == IID
            && check["target_after"]["MainPID"] == "0"
            && check["sample"]["trip"] == false
            && check["sample"]["minimum_free_bytes"] == 209506426310u64,
        "post terminal guard check"
    );
    let free = check["sample"]["available_bytes"]
        .as_u64()
        .context("free bytes")?;
    let physical = check["sample"]["tree"]["conservative_physical_bytes"]
        .as_u64()
        .context("physical bytes")?;
    ensure!(
        free >= 209506426310 && physical <= 10 << 30,
        "post terminal OS bounds"
    );
    let bytes = read(&format!("{ROOT}/child-success.bin"), 1001, 1 << 20, &mut e)?;
    let mut b = bytes.as_slice();
    ensure!(
        string(&mut b)? == "native-v12-fresh-process-equivalence-test-only",
        "wrong child marker"
    );
    let creator = u32::from_le_bytes(take(&mut b, 4)?.try_into()?);
    let child = u32::from_le_bytes(take(&mut b, 4)?.try_into()?);
    ensure!(
        creator == 1182622 && child != creator && child > 1 && take(&mut b, 1)? == [1],
        "child process/profile proof"
    );
    let plan_digest = vector(&mut b)?;
    let exe_digest = vector(&mut b)?;
    let plan = read(&format!("{ROOT}/plan.bin"), 1001, 1 << 20, &mut e)?;
    ensure!(
        plan_digest == Sha256::digest(&plan).as_slice() && hex(&exe_digest) == FIXTURE_SHA,
        "child plan/executable binding"
    );
    let archive = string(&mut b)?;
    ensure!(
        !archive.contains('/')
            && archive.starts_with("snapshot-1-")
            && archive.ends_with(".tar.bz2"),
        "foreign child archive"
    );
    let length = u64le(&mut b)?;
    let archive_digest = vector(&mut b)?;
    let archive_bytes = read(&format!("{ROOT}/{archive}"), 1001, 1 << 20, &mut e)?;
    ensure!(
        archive_bytes.len() as u64 == length
            && archive_digest == Sha256::digest(&archive_bytes).as_slice()
            && take(&mut b, 1)? == [0]
            && b.is_empty(),
        "child archive/authority binding"
    );
    let stdout = String::from_utf8(read(&format!("{LOGS}/stdout.log"), 0, 1 << 20, &mut e)?)?;
    ensure!(
        stdout.contains("test result: ok. 1 passed; 0 failed;")
            && read(&format!("{LOGS}/stderr.log"), 0, 1 << 20, &mut e)?.is_empty(),
        "fixture test output"
    );
    let journal = String::from_utf8(read(
        &format!("{LOGS}/watcher-journal.jsonl"),
        0,
        1 << 20,
        &mut e,
    )?)?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    let mut last = None;
    for line in journal.lines() {
        let row: Value = serde_json::from_str(line)?;
        ensure!(
            row["_PID"] == "1"
                && row["_UID"] == "0"
                && row["UNIT"] == "horizon-v1425-fixture-barrier-watch-20261023-v1.service"
                && row["INVOCATION_ID"] == WATCH_IID
                && row["_BOOT_ID"] == boot,
            "foreign watcher journal history"
        );
        last = Some(row);
    }
    let last = last.context("missing watcher PID1 terminal history")?;
    ensure!(
        last["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
            && last["__MONOTONIC_TIMESTAMP"]
                .as_str()
                .context("journal time")?
                .parse::<u64>()?
                > 1135497360065,
        "watcher lacks successful terminal proof"
    );
    let report = json!({"schema":"jetstreamer-v1425-guarded-synthetic-fixture-result-v1","fixture_iid":IID,"watcher_iid":WATCH_IID,"fixture_exit":0,"watcher_success_proof":"trusted PID1 terminal history bound to first-sample watcher IID; manager cleared inactive fields","guard_ready_before_release":true,"fresh_floor_before_release":true,"natural_completion":true,"stop_intent_absent":true,"authenticated_exec_observed_receipt_present":exec_observed,"sampling_limitation":"fixture completed between five-second watcher samples; no separate actual-exec observation is claimed","creator_pid_matches_original_launcher":creator,"fresh_child_pid":child,"unchanged_test_assertions_passed":true,"post_terminal_available_bytes":free,"post_terminal_fixture_physical_bytes":physical,"evidence":e,"production_resume_qualified":false,"mainnet_qualified":false,"publication_authorized":false,"r2_mutations":false});
    let directory = Path::new(RECEIPTS);
    let m = fs::symlink_metadata(directory)?;
    ensure!(
        directory.canonicalize()? == directory && m.uid() == 0 && m.mode() & 0o777 == 0o700,
        "unsafe result directory"
    );
    let output = directory.join("guarded-synthetic-result.json");
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&output)?;
    f.write_all(&serde_json::to_vec_pretty(&report)?)?;
    f.sync_all()?;
    File::open(directory)?.sync_all()?;
    println!("{}", output.display());
    Ok(())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_native_tuple_parser_rejects_truncation_and_length_bombs() {
        assert!(u64le(&mut &[0u8; 7][..]).is_err());
        assert!(vector(&mut &u64::MAX.to_le_bytes()[..]).is_err());
        let mut valid = &[2, 0, 0, 0, 0, 0, 0, 0, b'o', b'k'][..];
        assert_eq!(string(&mut valid).unwrap(), "ok");
        assert!(valid.is_empty());
    }
}
