//! Pure actor/diagnostic gates plus narrow no-follow durable log I/O.
use super::*;
fn log_metadata(m: &fs::Metadata) -> LogMetadata {
    LogMetadata { regular:m.is_file(),device:m.dev(),inode:m.ino(),uid:m.uid(),gid:m.gid(),mode:m.mode() & 0o7777,links:m.nlink(),bytes:m.len() }
}
pub(super) fn validate_private_log(expected: &PrivateLog, actual: &LogMetadata) -> Result<()> {
    ensure!(actual.regular && actual.uid==0 && actual.gid==0 && actual.mode==0o600 && actual.links==1 && actual.bytes<=1<<20,"unsafe or oversized private reader log");
    ensure!(actual.device==expected.device && actual.inode==expected.inode,"reader log identity replaced");
    Ok(())
}
pub(super) fn new_private_log(path: &Path) -> Result<PrivateLog> {
    write_new(path,b"",0o600)?;
    let m=fs::symlink_metadata(path)?;
    let log=PrivateLog {path:path.into(),device:m.dev(),inode:m.ino()};
    validate_private_log(&log,&log_metadata(&m))?;
    Ok(log)
}
pub(super) fn sync_private_log(log: &PrivateLog) -> Result<Bound> {
    ensure!(log.path.parent()==Some(root().as_path()) && log.path.canonicalize()?==log.path,"foreign or noncanonical reader log");
    let mut f=OpenOptions::new().read(true).write(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK).open(&log.path)?;
    let before=f.metadata()?;
    validate_private_log(log,&log_metadata(&before))?;
    // Caller has proven termination and an empty reader cgroup. Flush the actual
    // appends through this exact regular fd before deriving the receipt digest.
    f.sync_all()?;
    let mut raw=Vec::new();
    (&mut f).take((1<<20)+1).read_to_end(&mut raw)?;
    ensure!(raw.len() as u64==before.len() && raw.len()<=1<<20,"reader log size changed after termination");
    let after=f.metadata()?;
    let path_after=fs::symlink_metadata(&log.path)?;
    validate_private_log(log,&log_metadata(&after))?;
    validate_private_log(log,&log_metadata(&path_after))?;
    ensure!(evidence::identity(&before)==evidence::identity(&after) && evidence::identity(&before)==evidence::identity(&path_after),"reader diagnostic changed while durably binding");
    File::open(root())?.sync_all()?;
    Ok(Bound{path:log.path.clone(),sha256:evidence::sha(&raw)})
}
pub(super) fn validate_reader_intent(phase: &str, intent: &ReaderStartIntent, expected_reader: &Bound) -> Result<()> {
    ensure!(["old-idle","old-frozen","capped-frozen","capped-idle"].contains(&phase),"foreign reader phase");
    let unit=format!("horizon-uploader-cap-transition-reader-{phase}-20261111-v2.service");
    ensure!(intent.schema=="horizon-isolated-reader-start-intent-v2" && intent.unit==unit && intent.reader==*expected_reader && intent.recorded_unix_seconds>0,"foreign typed reader start intent");
    ensure!(intent.plan.path==phase_destination(phase).join("plan.json") && evidence::is_sha(&intent.plan.sha256) && evidence::is_sha(&intent.reader.sha256),"foreign reader plan binding");
    let argv=vec![intent.reader.path.display().to_string(),intent.plan.path.display().to_string(),intent.plan.sha256.clone(),intent.reader.sha256.clone()];
    ensure!(intent.command_line==argv && intent.expected_control_group==format!("/{SLICE}/{unit}"),"reader argv/scope intent differs");
    ensure!(intent.stdout.path==root().join(format!("reader-{phase}.stdout")) && intent.stderr.path==root().join(format!("reader-{phase}.stderr")) && intent.stdout.path!=intent.stderr.path,"foreign reader log intent");
    Ok(())
}
fn iid(s: &str) -> bool {s.len()==32 && s.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b))}
pub(super) fn validate_reader_cleanup_owner(current: &Value, witness: Option<&ReaderWitness>, intent_bound: &Bound, intent: &ReaderStartIntent) -> Result<()> {
    let prior=witness.context("unknown reader invocation: no authenticated initial identity; stop forbidden")?;
    ensure!(prior.schema=="horizon-isolated-reader-identity-v2" && prior.unit==intent.unit && prior.start_intent==*intent_bound && iid(&prior.invocation_id) && prior.native["InvocationID"]==prior.invocation_id && prior.native["Id"]==intent.unit,"reader witness does not bind exact typed launch intent");
    ensure!(prior.native["MemoryMax"]=="134217728" && prior.native["MemorySwapMax"]=="0" && prior.native["NRestarts"]=="0","initial reader witness envelope differs");
    ensure!(current["Id"]==intent.unit,"foreign current reader unit");
    if current["InvocationID"]=="" {
        ensure!(current["MainPID"]=="0" && current["ControlPID"]=="0" && current["Job"]=="" && (current["ActiveState"]=="inactive" || current["LoadState"]=="not-found"),"reader IID disappeared while activity remains");
        return Ok(());
    }
    ensure!(current["InvocationID"]==prior.invocation_id && current["MemoryMax"]=="134217728" && current["MemorySwapMax"]=="0" && current["NRestarts"]=="0","reader cleanup crossed invocation or envelope");
    if current["MainPID"]!="0" || current["ControlPID"]!="0" {ensure!(current["ControlGroup"]==intent.expected_control_group,"reader active outside declared scope");}
    Ok(())
}
pub(super) fn ensure_reader_terminated(native: &Value) -> Result<()> {
    ensure!(native["MainPID"]=="0" && native["ControlPID"]=="0" && native["Job"]=="" && (native["SubState"]=="exited" || native["ActiveState"]=="failed" || native["ActiveState"]=="inactive"),"reader may still append diagnostics");
    Ok(())
}
pub(super) fn reader_cgroup_empty(intent: &ReaderStartIntent) -> Result<()> {
    let c=Path::new("/sys/fs/cgroup").join(intent.expected_control_group.trim_start_matches('/'));
    if c.try_exists()? {
        ensure!(c.canonicalize()?==c,"reader cgroup escape");
        ensure!(String::from_utf8(bounded(&c.join("cgroup.events"),65536)?)?.lines().any(|s|s=="populated 0"),"reader cgroup remains populated");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (ReaderStartIntent,Bound,ReaderWitness,Value) {
        let phase="old-idle";
        let unit=format!("horizon-uploader-cap-transition-reader-{phase}-20261111-v2.service");
        let reader=Bound{path:OLD_READER.into(),sha256:"a".repeat(64)};
        let plan=Bound{path:phase_destination(phase).join("plan.json"),sha256:"b".repeat(64)};
        let intent=ReaderStartIntent{schema:"horizon-isolated-reader-start-intent-v2".into(),unit:unit.clone(),reader:reader.clone(),plan:plan.clone(),command_line:vec![reader.path.display().to_string(),plan.path.display().to_string(),plan.sha256.clone(),reader.sha256.clone()],expected_control_group:format!("/{SLICE}/{unit}"),stdout:PrivateLog{path:root().join("reader-old-idle.stdout"),device:1,inode:2},stderr:PrivateLog{path:root().join("reader-old-idle.stderr"),device:1,inode:3},recorded_unix_seconds:1};
        let b=Bound{path:root().join("READER-old-idle-START-INTENT.json"),sha256:"c".repeat(64)};
        let native=json!({"Id":unit,"LoadState":"loaded","InvocationID":"d".repeat(32),"MemoryMax":"134217728","MemorySwapMax":"0","NRestarts":"0","MainPID":"42","ControlPID":"0","ControlGroup":intent.expected_control_group,"ActiveState":"active","SubState":"running","Job":""});
        let witness=ReaderWitness{schema:"horizon-isolated-reader-identity-v2".into(),unit:intent.unit.clone(),invocation_id:"d".repeat(32),start_intent:b.clone(),native:native.clone(),recorded_unix_seconds:2};
        (intent,b,witness,native)
    }
    #[test]
    fn missing_reader_witness_never_authorizes_stop() {
        let (intent,b,w,current)=fixture();
        validate_reader_intent("old-idle",&intent,&intent.reader).unwrap();
        validate_reader_cleanup_owner(&current,Some(&w),&b,&intent).unwrap();
        assert!(validate_reader_cleanup_owner(&current,None,&b,&intent).is_err());
        let mut gone=current;
        gone["InvocationID"]=json!("");gone["MainPID"]=json!("0");gone["ActiveState"]=json!("inactive");gone["LoadState"]=json!("not-found");
        assert!(validate_reader_cleanup_owner(&gone,None,&b,&intent).is_err());
        validate_reader_cleanup_owner(&gone,Some(&w),&b,&intent).unwrap();
    }
    #[test]
    fn changed_invocation_or_start_intent_rejects_cleanup() {
        let (intent,b,w,mut current)=fixture();
        current["InvocationID"]=json!("e".repeat(32));
        assert!(validate_reader_cleanup_owner(&current,Some(&w),&b,&intent).is_err());
        current["InvocationID"]=json!(w.invocation_id);
        let mut other=b.clone();other.sha256="f".repeat(64);
        assert!(validate_reader_cleanup_owner(&current,Some(&w),&other,&intent).is_err());
        let mut bad=intent.clone();bad.command_line.push("--skip-proof".into());
        assert!(validate_reader_intent("old-idle",&bad,&intent.reader).is_err());
        bad=intent.clone();bad.expected_control_group="/system.slice/other.service".into();
        assert!(validate_reader_intent("old-idle",&bad,&intent.reader).is_err());
    }
    #[test]
    fn reader_log_policy_rejects_replacement_exposure_and_oversize() {
        let log=PrivateLog{path:root().join("reader-old-idle.stderr"),device:2,inode:3};
        let good=LogMetadata{regular:true,device:2,inode:3,uid:0,gid:0,mode:0o600,links:1,bytes:1024};
        validate_private_log(&log,&good).unwrap();
        let mut cases=Vec::new();
        let mut bad=good.clone();bad.regular=false;cases.push(bad);
        let mut bad=good.clone();bad.inode+=1;cases.push(bad);
        let mut bad=good.clone();bad.device+=1;cases.push(bad);
        let mut bad=good.clone();bad.uid=1001;cases.push(bad);
        let mut bad=good.clone();bad.gid=1003;cases.push(bad);
        let mut bad=good.clone();bad.mode=0o640;cases.push(bad);
        let mut bad=good.clone();bad.links=2;cases.push(bad);
        let mut bad=good.clone();bad.bytes=(1<<20)+1;cases.push(bad);
        for m in cases {assert!(validate_private_log(&log,&m).is_err());}
    }
    #[test]
    fn final_logs_cannot_bind_while_reader_can_still_write() {
        let mut v=json!({"MainPID":"0","ControlPID":"0","Job":"","ActiveState":"active","SubState":"exited"});
        ensure_reader_terminated(&v).unwrap();
        v["MainPID"]=json!("42");assert!(ensure_reader_terminated(&v).is_err());
        v["MainPID"]=json!("0");v["ControlPID"]=json!("43");assert!(ensure_reader_terminated(&v).is_err());
        v["ControlPID"]=json!("0");v["Job"]=json!("7/start");assert!(ensure_reader_terminated(&v).is_err());
        v["Job"]=json!("");v["SubState"]=json!("running");assert!(ensure_reader_terminated(&v).is_err());
    }
}
