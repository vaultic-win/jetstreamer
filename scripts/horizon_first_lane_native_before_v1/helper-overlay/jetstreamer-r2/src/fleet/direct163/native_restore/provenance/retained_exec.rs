use super::*;
// systemd retains a successful Type=exec/RemainAfterExit owner as active/exited.
// That lifecycle has no UNIT_RESULT=success journal entry. Authenticate the
// original PID1 start plus the unchanged manager exit metadata and real drain.
fn exit_utc_seconds(raw: &str) -> Result<u64> {
    ensure!(raw.ends_with(" UTC"), "retained exec exit timezone");
    let input=std::ffi::CString::new(raw)?;
    let format=c"%a %Y-%m-%d %H:%M:%S UTC";
    let mut tm=unsafe { std::mem::zeroed::<libc::tm>() };
    let end=unsafe { libc::strptime(input.as_ptr(),format.as_ptr(),&mut tm) };
    ensure!(!end.is_null() && unsafe { *end }==0,"retained exec exit timestamp framing");
    let seconds=unsafe { libc::timegm(&mut tm) };
    ensure!(seconds>=0,"retained exec exit timestamp before epoch");
    Ok(seconds as u64)
}
fn retained_exit_scope(v:&Value,start:&Value,recorded:u64,boot:&str,clock:u64)->Result<()> {
    ensure!(v["Id"]==CURRENT_DOWNLOAD_UNIT && v["InvocationID"]==CURRENT_DOWNLOAD_IID
        && start["_PID"]=="1" && start["_UID"]=="0" && start["UNIT"]==CURRENT_DOWNLOAD_UNIT
        && start["INVOCATION_ID"]==CURRENT_DOWNLOAD_IID && start["JOB_TYPE"]=="start"
        && start["JOB_RESULT"]=="done" && start["_BOOT_ID"]==boot,
        "retained exec original PID1 identity/boot/start");
    for (k,want) in [("Type","exec"),("RemainAfterExit","yes"),("MainPID","0"),("ControlPID","0"),
        ("NRestarts","0"),("Result","success"),("ExecMainCode","1"),("ExecMainStatus","0"),
        ("ActiveState","active"),("SubState","exited"),("ControlGroup",""),("Job","")] {
        ensure!(v[k]==want,"retained exec original terminal property: {k}");
    }
    let number=|key:&str|->Result<u64> {Ok(v[key].as_str().with_context(||format!("retained exec {key}"))?.parse()?)};
    let pid=number("ExecMainPID")?;
    let began=number("ExecMainStartTimestampMonotonic")?;
    let ended=number("ExecMainExitTimestampMonotonic")?;
    let pid1=start["__MONOTONIC_TIMESTAMP"].as_str().context("retained PID1 original start clock")?.parse::<u64>()?;
    ensure!(pid>1 && began>0 && began<=pid1 && pid1<ended,"retained exec original PID/start/exit ordering");
    let exit=exit_utc_seconds(v["ExecMainExitTimestamp"].as_str().context("retained exec exit time")?)?;
    ensure!(exit>=recorded && exit<=clock,"retained exec original exit predates receipt or is future");
    Ok(())
}
pub(super) fn retained_completion(unit:&str,iid:&str,recorded:u64,start:&Value)->Result<Value> {
    ensure!(unit==CURRENT_DOWNLOAD_UNIT && iid==CURRENT_DOWNLOAD_IID,"only the exact original retained downloader can use native exit completion");
    let query=||->Result<Value> {
        let out=ProcessCommand::new("/usr/bin/systemctl").args(["show",unit,"--no-pager","--property=Id,InvocationID,Type,RemainAfterExit,MainPID,ControlPID,NRestarts,Result,ExecMainStatus,ExecMainCode,ExecMainPID,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic,ExecMainExitTimestamp,ActiveState,SubState,ControlGroup,Job"])
            .env("LC_ALL","C").env("TZ","UTC").env_remove("SYSTEMD_HOST").env_remove("SYSTEMD_BUS_ADDRESS").env_remove("DBUS_SYSTEM_BUS_ADDRESS").output()?;
        ensure!(out.status.success() && out.stderr.is_empty() && out.stdout.len()<=65536,"retained exec manager query");
        let mut fields=serde_json::Map::new();
        for line in std::str::from_utf8(&out.stdout)?.lines() {
            let (key,value)=line.split_once('=').context("retained exec native framing")?;
            ensure!(fields.insert(key.into(),json!(value)).is_none(),"duplicate retained exec native field");
        }
        Ok(Value::Object(fields))
    };
    let before=query()?;
    let boot=fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    retained_exit_scope(&before,start,recorded,&boot.trim().replace('-',""),now()?)?;
    let pid=before["ExecMainPID"].as_str().context("retained original PID")?.parse::<u64>()?;
    ensure!(!Path::new(&format!("/proc/{pid}")).try_exists()?,"original retained downloader process still exists");
    let cgroup=PathBuf::from(format!("/sys/fs/cgroup/system.slice/{unit}"));
    if cgroup.try_exists()? {
        ensure!(fs::read_to_string(cgroup.join("cgroup.procs"))?.trim().is_empty(),"retained downloader cgroup remains populated");
    }
    let after=query()?;
    ensure!(before==after && fs::read_to_string("/proc/sys/kernel/random/boot_id")?==boot,"retained downloader original completion changed");
    Ok(json!({"schema":"native163-original-retained-exec-manager-completion-v1","source":"actual-original-manager-exit-and-drain","unit":unit,"invocation_id":iid,"native":before,"original_PID1_start":start,"original_process_absent":true,"original_cgroup_empty":true,"not_a_PID1_success_journal_record":true}))
}
#[cfg(test)]
mod retained_exec_tests {
    use super::*;
    fn actual_shape()->(Value,Value) {
        (json!({"Id":CURRENT_DOWNLOAD_UNIT,"InvocationID":CURRENT_DOWNLOAD_IID,"Type":"exec","RemainAfterExit":"yes","MainPID":"0","ControlPID":"0","NRestarts":"0","Result":"success","ExecMainCode":"1","ExecMainStatus":"0","ActiveState":"active","SubState":"exited","ControlGroup":"","Job":"","ExecMainPID":"2702622","ExecMainStartTimestampMonotonic":"2415046355060","ExecMainExitTimestampMonotonic":"2415112924788","ExecMainExitTimestamp":"Sat 2026-11-07 16:20:51 UTC"}),
         json!({"_PID":"1","_UID":"0","UNIT":CURRENT_DOWNLOAD_UNIT,"INVOCATION_ID":CURRENT_DOWNLOAD_IID,"JOB_TYPE":"start","JOB_RESULT":"done","_BOOT_ID":"boot","__MONOTONIC_TIMESTAMP":"2415046359844"}))
    }
    #[test]fn retained_original_exit_accepts_without_inventing_a_success_journal() {
        let (v,start)=actual_shape();assert!(start.get("UNIT_RESULT").is_none());
        retained_exit_scope(&v,&start,1794068451,"boot",1794068452).unwrap();
    }
    #[test]fn retained_original_exit_rejects_incomplete_foreign_restarted_or_time_crossed() {
        let (v,start)=actual_shape();
        for (key,value) in [("InvocationID","00000000000000000000000000000000"),("MainPID","2702622"),("Result","exit-code"),("ExecMainStatus","1"),("ExecMainCode","2"),("NRestarts","1"),("SubState","running"),("ControlGroup","/populated"),("Job","1"),("ExecMainStartTimestampMonotonic","2415046359845"),("ExecMainExitTimestampMonotonic","2415046359843")] {
            let mut bad=v.clone();bad[key]=json!(value);assert!(retained_exit_scope(&bad,&start,1794068451,"boot",1794068452).is_err(),"{key}");
        }
        assert!(retained_exit_scope(&v,&start,1794068452,"boot",1794068452).is_err());
        assert!(retained_exit_scope(&v,&start,1794068451,"other-boot",1794068452).is_err());
        assert!(retained_exit_scope(&v,&start,1794068451,"boot",1794068450).is_err());
    }
    #[test]fn retained_original_exit_utc_parser_rejects_ambiguous_or_extra_text() {
        assert_eq!(exit_utc_seconds("Sat 2026-11-07 16:20:51 UTC").unwrap(),1794068451);
        for bad in ["Sat 2026-11-07 17:40:51 PST","Sat 2026-11-07 16:20:51 UTC extra","bad UTC"] {assert!(exit_utc_seconds(bad).is_err());}
    }
}
