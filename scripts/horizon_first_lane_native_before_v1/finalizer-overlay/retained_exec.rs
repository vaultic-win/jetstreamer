//! Successful Type=exec/RemainAfterExit actors stay active/exited. Their original
//! PID1 start plus successful manager exit/drain authenticates completion; never
//! invent a deactivation event for a unit which has not deactivated.
use super::*;
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(test)]
const EXIT_FIELDS: &str = "Id,InvocationID,Type,RemainAfterExit,MainPID,ControlPID,NRestarts,Result,ExecMainStatus,ExecMainCode,ExecMainPID,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic,ExecMainExitTimestamp,ActiveState,SubState,ControlGroup,Job";
fn now() -> Result<u64> { Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()) }
fn exit_utc_seconds(raw: &str) -> Result<u64> {
    ensure!(raw.ends_with(" UTC"), "retained exec exit timezone");
    let input = std::ffi::CString::new(raw)?;
    let mut tm = unsafe { std::mem::zeroed::<libc::tm>() };
    let end = unsafe { libc::strptime(input.as_ptr(), c"%a %Y-%m-%d %H:%M:%S UTC".as_ptr(), &mut tm) };
    ensure!(!end.is_null() && unsafe { *end } == 0, "retained exec exit timestamp framing");
    let seconds = unsafe { libc::timegm(&mut tm) };
    ensure!(seconds >= 0, "retained exec exit before epoch");
    Ok(seconds as u64)
}
fn fields(raw: &[u8]) -> Result<BTreeMap<&str, &str>> {
    let mut out = BTreeMap::new();
    for line in std::str::from_utf8(raw)?.lines() {
        let (key, value) = line.split_once('=').context("retained exec field framing")?;
        ensure!(out.insert(key, value).is_none(), "duplicate retained exec field");
    }
    Ok(out)
}
fn original_start(unit: &str, iid: &str) -> Result<Value> {
    let iid_filter = format!("INVOCATION_ID={iid}");
    let unit_filter = format!("UNIT={unit}");
    let raw = command(&["/usr/bin/journalctl", "--all", "--no-pager", "-o", "json", "-n", "2", "_PID=1", "_UID=0", &unit_filter, &iid_filter, "JOB_TYPE=start", "JOB_RESULT=done"])?;
    let rows = std::str::from_utf8(&raw)?.lines().map(serde_json::from_str::<Value>).collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(rows.len() == 1, "exactly one original retained actor PID1 start required");
    rows.into_iter().next().context("original retained actor start")
}
fn retained_exit_scope(unit: &str, raw: &[u8], start: &Value, iid: &str, recorded: u64, boot: &str, clock: u64) -> Result<()> {
    ensure!(iid.len() == 32 && iid.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()), "retained original actor IID");
    ensure!(boot.len() == 32 && boot.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()), "retained current boot identity");
    let v = fields(raw)?;
    ensure!(v.get("Id") == Some(&unit) && v.get("InvocationID") == Some(&iid)
        && start["_PID"] == "1" && start["_UID"] == "0" && start["UNIT"] == unit
        && start["INVOCATION_ID"] == iid && start["JOB_TYPE"] == "start"
        && start["JOB_RESULT"] == "done" && start["_BOOT_ID"] == boot,
        "retained original actor PID1 identity/boot/start");
    for (key, want) in [("Type", "exec"), ("RemainAfterExit", "yes"), ("MainPID", "0"), ("ControlPID", "0"),
        ("NRestarts", "0"), ("Result", "success"), ("ExecMainCode", "1"), ("ExecMainStatus", "0"),
        ("ActiveState", "active"), ("SubState", "exited"), ("ControlGroup", ""), ("Job", "")] {
        ensure!(v.get(key) == Some(&want), "retained original actor terminal property: {key}");
    }
    let number = |key: &str| -> Result<u64> { Ok(v.get(key).with_context(|| format!("retained actor {key}"))?.parse()?) };
    let pid = number("ExecMainPID")?;
    let began = number("ExecMainStartTimestampMonotonic")?;
    let ended = number("ExecMainExitTimestampMonotonic")?;
    let pid1 = start["__MONOTONIC_TIMESTAMP"].as_str().context("original PID1 start clock")?.parse::<u64>()?;
    ensure!(pid > 1 && pid <= i32::MAX as u64 && began > 0 && began <= pid1 && pid1 < ended, "retained actor original PID/start/exit ordering");
    let exit = exit_utc_seconds(v.get("ExecMainExitTimestamp").context("retained actor exit time")?)?;
    ensure!(exit >= recorded && exit <= clock, "retained actor exit predates original admission or is future");
    Ok(())
}
fn process_and_cgroup_drained(unit: &str, raw: &[u8]) -> Result<()> {
    let v = fields(raw)?;
    let pid = v.get("ExecMainPID").context("retained actor original PID")?.parse::<u64>()?;
    ensure!(pid > 1 && pid <= i32::MAX as u64 && !Path::new(&format!("/proc/{pid}")).try_exists()?, "original retained actor PID remains live");
    let root = PathBuf::from(format!("/sys/fs/cgroup/system.slice/{unit}"));
    if root.try_exists()? {
        let mut queue = vec![root];
        let mut scanned = 0;
        while let Some(path) = queue.pop() {
            scanned += 1;
            ensure!(scanned <= 64, "retained actor cgroup subtree bound");
            ensure!(fs::read_to_string(path.join("cgroup.procs"))?.trim().is_empty(), "retained actor cgroup remains populated");
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() { queue.push(entry.path()); }
            }
        }
    }
    Ok(())
}
// Called only after the original outcome and its exact admission authenticate IID.
// before/after are the production finalizer's exact native() snapshots, retaining
// every original actor property and command-line check.
pub(super) fn retained_completion(before: &[u8], iid: &str, recorded: u64) -> Result<Value> {
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let start = original_start(UNIT, iid)?;
    let clock = now()?;
    retained_exit_scope(UNIT, before, &start, iid, recorded, &boot.trim().replace('-', ""), clock)?;
    process_and_cgroup_drained(UNIT, before)?;
    ensure!(native()? == before && fs::read_to_string("/proc/sys/kernel/random/boot_id")? == boot, "retained original actor manager/boot changed");
    process_and_cgroup_drained(UNIT, before)?;
    Ok(json!({"schema":"epoch163-original-retained-exec-manager-completion-v1", "source":"actual-original-manager-exit-and-drain", "unit":UNIT, "invocation_id":iid,
        "native_properties":std::str::from_utf8(before)?, "original_PID1_start":start, "original_admission_recorded_unix_seconds":recorded, "validated_unix_seconds":clock,
        "original_process_absent":true, "original_cgroup_empty":true, "not_a_PID1_success_journal_record":true}))
}
#[cfg(test)]
mod tests {
    use super::*;
    const IID: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const BOOT: &str = "763ea84ca81f4dddad364b1ea2ba36dd";
    fn shape() -> (String, Value) {
        (format!("Id={UNIT}\nInvocationID={IID}\nType=exec\nRemainAfterExit=yes\nMainPID=0\nControlPID=0\nNRestarts=0\nResult=success\nExecMainCode=1\nExecMainStatus=0\nActiveState=active\nSubState=exited\nControlGroup=\nJob=\nExecMainPID=2702622\nExecMainStartTimestampMonotonic=2415046355060\nExecMainExitTimestampMonotonic=2415112924788\nExecMainExitTimestamp=Sat 2026-11-07 16:20:51 UTC\n"),
         json!({"_PID":"1", "_UID":"0", "UNIT":UNIT, "INVOCATION_ID":IID, "JOB_TYPE":"start", "JOB_RESULT":"done", "_BOOT_ID":BOOT, "__MONOTONIC_TIMESTAMP":"2415046359844"}))
    }
    fn check(raw: &str, start: &Value, recorded: u64, boot: &str, clock: u64) -> Result<()> {
        retained_exit_scope(UNIT, raw.as_bytes(), start, IID, recorded, boot, clock)
    }
    #[test]
    fn retained_actor_completion_uses_real_manager_exit_not_invented_deactivation() {
        let (raw, start) = shape();
        assert!(start.get("UNIT_RESULT").is_none());
        assert!(start.get("MESSAGE_ID").is_none());
        check(&raw, &start, 1794068451, BOOT, 1794068452).unwrap();
    }
    #[test]
    fn retained_actor_completion_rejects_wrong_owner_restart_failure_or_nonterminal_manager() {
        let (raw, start) = shape();
        for (from, to) in [(IID,"ffffffffffffffffffffffffffffffff"), ("Type=exec","Type=oneshot"), ("RemainAfterExit=yes","RemainAfterExit=no"),
            ("MainPID=0","MainPID=2702622"), ("ControlPID=0","ControlPID=2"), ("NRestarts=0","NRestarts=1"),
            ("Result=success","Result=exit-code"), ("ExecMainCode=1","ExecMainCode=2"), ("ExecMainStatus=0","ExecMainStatus=1"),
            ("ActiveState=active","ActiveState=inactive"), ("SubState=exited","SubState=dead"), ("ControlGroup=\n","ControlGroup=/live\n"), ("Job=\n","Job=1\n"),
            ("ExecMainPID=2702622","ExecMainPID=1"), ("ExecMainStartTimestampMonotonic=2415046355060","ExecMainStartTimestampMonotonic=2415046359845"),
            ("ExecMainExitTimestampMonotonic=2415112924788","ExecMainExitTimestampMonotonic=2415046359844")] {
            assert!(check(&raw.replace(from,to), &start,1794068451,BOOT,1794068452).is_err(), "{from}");
        }
        assert!(check(&(raw.clone()+"MainPID=0\n"), &start,1794068451,BOOT,1794068452).is_err());
        assert!(check(&raw.replace("ExecMainPID=2702622\n",""), &start,1794068451,BOOT,1794068452).is_err());
    }
    #[test]
    fn retained_actor_completion_rejects_crossed_journal_boot_and_wall_clocks() {
        let (raw, start) = shape();
        for (key, value) in [("_PID","2"), ("_UID","1001"), ("UNIT","other.service"), ("INVOCATION_ID","ffffffffffffffffffffffffffffffff"),
            ("JOB_TYPE","stop"), ("JOB_RESULT","failed"), ("_BOOT_ID","00000000000000000000000000000000"), ("__MONOTONIC_TIMESTAMP","2415112924788")] {
            let mut bad=start.clone();bad[key]=json!(value);
            assert!(check(&raw,&bad,1794068451,BOOT,1794068452).is_err(),"{key}");
        }
        assert!(check(&raw,&start,1794068452,BOOT,1794068452).is_err());
        assert!(check(&raw,&start,1794068451,BOOT,1794068450).is_err());
        assert!(check(&raw,&start,1794068451,"other-boot",1794068452).is_err());
        assert_eq!(exit_utc_seconds("Sat 2026-11-07 16:20:51 UTC").unwrap(),1794068451);
        for bad in ["Sat 2026-11-07 16:20:51 PST", "Sat 2026-11-07 16:20:51 UTC extra", "bad UTC"] { assert!(exit_utc_seconds(bad).is_err()); }
    }
    #[test]
    #[ignore = "Root creates one metadata-only Type=exec/RemainAfterExit control; no real native inputs"]
    fn actual_retained_exec_kernel_completion_authenticates_start_exit_and_drain_without_deactivation() {
        const CONTROL: &str = "horizon-native163-retained-exec-finalizer-control-20261108-v2.service";
        ensure_root_control().unwrap();
        let raw = command(&["/usr/bin/systemctl","show",CONTROL,&format!("--property={EXIT_FIELDS}")]).unwrap();
        let v = fields(&raw).unwrap();let iid = v["InvocationID"];
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
        let start = original_start(CONTROL,iid).unwrap();
        let recorded = start["__REALTIME_TIMESTAMP"].as_str().unwrap().parse::<u64>().unwrap()/1_000_000;
        retained_exit_scope(CONTROL,&raw,&start,iid,recorded,&boot.trim().replace('-',""),now().unwrap()).unwrap();
        process_and_cgroup_drained(CONTROL,&raw).unwrap();
        let absent = command(&["/usr/bin/journalctl","--all","--no-pager","-ojson","-n","1","_PID=1","_UID=0",&format!("UNIT={CONTROL}"),&format!("INVOCATION_ID={iid}"),"MESSAGE_ID=7ad2d189f7e94e70a38c781354912448"]).unwrap();
        assert!(absent.is_empty(),"retained active/exited control must not require or invent deactivation");
        assert_eq!(command(&["/usr/bin/systemctl","show",CONTROL,&format!("--property={EXIT_FIELDS}")]).unwrap(),raw);
        assert_eq!(fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap(),boot);
    }
    fn ensure_root_control() -> Result<()> { ensure!(unsafe { libc::geteuid() } == 0,"actual retained-exec control is Root-only"); Ok(()) }
}
