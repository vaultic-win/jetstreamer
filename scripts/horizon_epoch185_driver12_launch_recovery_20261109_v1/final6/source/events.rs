//! Finite inotify event waits for this original transaction, never resource polling.
use crate::{storage,process,now,n,text};
use anyhow::{Context,Result,ensure};
use serde_json::Value;
use std::{ffi::CString,fs::{self,OpenOptions},io::{Read,Write},os::unix::fs::{OpenOptionsExt,MetadataExt},
    path::Path,time::{Duration,Instant}};
#[derive(Debug,PartialEq,Eq)]
struct Event{name:String,mask:u32}
// Driver11 persists directly to the final guard filename, then closes its
// writer. No qualified guard publisher uses atomic rename; MOVED_TO alone is
// therefore only a wakeup, never publication authority for this consumer.
fn guard_published(event:&Event)->bool{
    event.mask&libc::IN_CLOSE_WRITE!=0&&event.mask&libc::IN_ISDIR==0
}
// poll() accepts integral milliseconds; never truncate a positive remainder.
// This is only a kernel-wait timeout, never a renewed authentication deadline.
fn event_poll_millis(left:Duration)->Result<i32>{
    ensure!(!left.is_zero(),"original event deadline expired");
    Ok(left.as_nanos().div_ceil(1_000_000).min(i32::MAX as u128)as i32)
}
pub struct Watch{fd:i32,guard_events:std::cell::Cell<usize>}
impl Drop for Watch{fn drop(&mut self){unsafe{libc::close(self.fd);}}}
impl Watch{
    pub fn new(path:&Path)->Result<Self>{
        Self::with_mask(path,libc::IN_MOVED_TO|libc::IN_CLOSE_WRITE|libc::IN_MODIFY)
    }
    pub fn guard_directory(path:&Path)->Result<Self>{
        // The append/log watcher still gets MODIFY. This watch subscribes only
        // to completed guard writers, avoiding an event-budget charge for each
        // partial serde_json write without changing the 256-publication bound.
        Self::with_mask(path,libc::IN_CLOSE_WRITE)
    }
    fn with_mask(path:&Path,mask:u32)->Result<Self>{
        ensure!(path.canonicalize()?==path&&fs::symlink_metadata(path)?.is_dir(),"event watch directory alias");
        let name=CString::new(path.as_os_str().as_encoded_bytes())?;
        let fd=unsafe{libc::inotify_init1(libc::IN_CLOEXEC|libc::IN_NONBLOCK)};
        ensure!(fd>=0,"cannot initialize original event watch");
        let wd=unsafe{libc::inotify_add_watch(fd,name.as_ptr(),mask|libc::IN_DELETE_SELF|libc::IN_MOVE_SELF)};
        if wd<0{unsafe{libc::close(fd);}anyhow::bail!("cannot arm original directory watch")}
        Ok(Self{fd,guard_events:std::cell::Cell::new(0)})
    }
    fn events(&self,until:Instant)->Result<Vec<Event>>{
        loop{
            let left=until.checked_duration_since(Instant::now()).context("original event deadline expired")?;
            let mut p=libc::pollfd{fd:self.fd,events:libc::POLLIN,revents:0};
            let r=unsafe{libc::poll(&mut p,1,event_poll_millis(left)?)};
            if r<0{
                let error=std::io::Error::last_os_error();
                if error.kind()==std::io::ErrorKind::Interrupted{continue}
                return Err(error).context("original event watch poll failed")
            }
            // A kernel timeout can precede until, including capped/rounded waits.
            // Recheck that same original Instant at the loop head; never renew it.
            if r==0{continue}
            ensure!(Instant::now()<until,"original event deadline expired");
            ensure!(p.revents&libc::POLLIN!=0,"original event watch descriptor closed/error");
            let mut bytes=[0u8;65536];let count=unsafe{libc::read(self.fd,bytes.as_mut_ptr().cast(),bytes.len())};
            ensure!(count>0,"event watch closed/read error");
            let events=parse_events(&bytes[..count as usize])?;
            ensure!(Instant::now()<until,"original event deadline expired");
            return Ok(events);
        }
    }
    pub fn guard(&self,root:&Path,actor:&str,iid:&str,admission:&str,until:Instant)->Result<(storage::Bound,Value)>{
        loop{
            for event in self.events(until)?{
                self.count_guard_event()?;
                if !guard_published(&event)||!guard_filename(&event.name){continue}
                let name=event.name;
                let path=root.join(&name);
                let b=process::bind_file(&path,4<<20)?;let v=storage::json(&b)?;
                if v["actor_unit"]!=actor||v["actor_invocation_id"]!=iid{continue}
                let sampled=n(&v,"sampled_at")?;let clock=now()?;
                ensure!(v["schema"]=="horizon-epoch185-native-guard-result-v4"
                    &&v["epoch"]==185&&v["admission_sha256"]==admission
                    &&v["success"]==true&&v["timer_driven"]==true&&v["capacity_credit_bytes"]==0
                    &&clock.checked_sub(sampled).is_some_and(|age|age<=30)
                    &&name==format!("guard-{}.json",text(&v,"guard_invocation_id")?),
                    "genuine matching first guard failed or changed admission/identity");
                ensure!(Instant::now()<until,"original event deadline expired");
                return Ok((b,v))
            }
        }
    }
    fn count_guard_event(&self)->Result<()> {
        let count=self.guard_events.get().checked_add(1).context("original guard event counter overflow")?;
        ensure!(count<=256,"bounded original guard event count exceeded");
        self.guard_events.set(count);Ok(())
    }
    pub fn post_main_guard(&self,root:&Path,scope:&crate::post_main::GuardScope<'_>,until:Instant)->Result<(storage::Bound,Value)>{
        // The very same CLOSE_WRITE watch was armed before the original timer.
        // It also retains the shared256-event cap across prestart and postMain.
        loop {
            for event in self.events(until)? {
                self.count_guard_event()?;
                if !guard_published(&event)||!guard_filename(&event.name){continue}
                let b=process::bind_file(&root.join(&event.name),4<<20)?;
                let value=storage::json(&b)?;
                if value["actor_unit"]!=scope.actor||value["actor_invocation_id"]!=scope.iid{continue}
                match crate::post_main::receipt_policy(&value,&event.name,scope,now()?)? {
                    crate::post_main::ReceiptDecision::WaitPrestart=>continue,
                    crate::post_main::ReceiptDecision::AcceptMain=>{
                        ensure!(Instant::now()<until,"original event deadline expired");
                        return Ok((b,value))
                    },
                }
            }
        }
    }
    pub fn main_event(&self,log:&Path,until:Instant)->Result<()>{
        // This event is only a wakeup. The qualified lifecycle helper must
        // subsequently authenticate actual MainPID and original PID1 release.
        loop{
            if input_validation_log(&read_sol_log(log)?){return Ok(())}
            let _=self.events(until)?;
        }
    }
}
fn guard_filename(s:&str)->bool{
    s.strip_prefix("guard-").and_then(|s|s.strip_suffix(".json"))
        .is_some_and(|s|storage::hex(s,32))
}
fn read_sol_log(path:&Path)->Result<Vec<u8>>{
    ensure!(path.canonicalize()?==path,"original log path alias");
    let mut f=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).open(path)?;
    let m=f.metadata()?;
    ensure!(m.is_file()&&m.uid()==1001&&m.nlink()==1&&m.mode()&0o7777==0o600&&m.len()<=64<<20,
        "original private driver log custody/bound");
    let mut raw=Vec::new();Read::by_ref(&mut f).take((64<<20)+1).read_to_end(&mut raw)?;
    ensure!(raw.len()<=64<<20,"original driver log grew outside bound");Ok(raw)
}
fn input_validation_log(raw:&[u8])->bool{
    for line in raw.split_inclusive(|b|*b==b'\n'){
        if line.last()!=Some(&b'\n'){continue}
        if let Ok(v)=serde_json::from_slice::<Value>(line)
            && v["epoch"]==185&&v["event"]=="phase start"&&v["phase"]=="input validation"{return true}
    }
    false
}
fn parse_events(mut raw:&[u8])->Result<Vec<Event>>{
    let mut result=Vec::new();
    while !raw.is_empty(){
        let size=std::mem::size_of::<libc::inotify_event>();
        ensure!(raw.len()>=size,"truncated original event header");
        let event=unsafe{std::ptr::read_unaligned(raw.as_ptr().cast::<libc::inotify_event>())};
        ensure!(event.mask&(libc::IN_Q_OVERFLOW|libc::IN_IGNORED|libc::IN_DELETE_SELF|libc::IN_MOVE_SELF)==0,
            "original watch overflowed or directory moved/disappeared");
        let end=size.checked_add(event.len as usize).context("event length overflow")?;
        ensure!(end<=raw.len(),"truncated original event name");
        let name=&raw[size..end];let used=name.iter().position(|b|*b==0).unwrap_or(name.len());
        if used>0{
            let value=std::str::from_utf8(&name[..used])?;
            ensure!(!value.contains('/')&&value!="."&&value!="..","event filename escape");
            result.push(Event{name:value.into(),mask:event.mask});
        }
        raw=&raw[end..];
    }Ok(result)
}

/// Wait for the original PID1 completion event, including historical rows that
/// raced the receipt commit. This is one bounded journal event stream, not
/// repeated native/resource queries. Current native state is checked afterward.
pub fn guard_completed(unit:&str,iid:&str,since:u64,until:Instant,raw_path:&Path)->Result<Vec<Value>>{
    use std::{os::fd::AsRawFd,process::{Command,Stdio}};
    ensure!(crate::unit_name(unit)&&unit.starts_with("horizon-guard-185-capped-cold-")
        &&storage::hex(iid,32),"exact original guard journal scope");
    let mut original_raw=OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).open(raw_path)?;
    original_raw.sync_all()?;
    fs::File::open(raw_path.parent().context("original journal parent")?)?.sync_all()?;
    let mut child=Command::new("/usr/bin/journalctl")
        .args(["--no-pager","--all","--output=json","--follow",&format!("--since=@{since}"),
            "_PID=1","_UID=0",&format!("UNIT={unit}"),&format!("INVOCATION_ID={iid}")])
        .env("LC_ALL","C").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn()?;
    let mut stdout=child.stdout.take().context("original guard journal stdout")?;
    let result=(||{
        let mut buffer=Vec::new();let mut rows=Vec::new();let mut count=0usize;
        loop{
            let left=until.checked_duration_since(Instant::now()).context("original guard completion deadline")?;
            let mut fd=libc::pollfd{fd:stdout.as_raw_fd(),events:libc::POLLIN,revents:0};
            let r=unsafe{libc::poll(&mut fd,1,left.as_millis().clamp(1,i32::MAX as u128)as i32)};
            if r<0&&std::io::Error::last_os_error().kind()==std::io::ErrorKind::Interrupted{continue}
            ensure!(r>0&&fd.revents&libc::POLLIN!=0,"original guard journal timed out/closed");
            let mut block=[0u8;16384];let size=stdout.read(&mut block)?;ensure!(size>0,"original guard journal ended");
            count+=size;ensure!(count<=1<<20,"original guard journal bound exceeded");
            original_raw.write_all(&block[..size])?;original_raw.sync_all()?;
            buffer.extend_from_slice(&block[..size]);
            while let Some(end)=buffer.iter().position(|b|*b==b'\n'){
                let line=buffer.drain(..=end).collect::<Vec<_>>();
                if line.len()==1{continue}
                let row:Value=serde_json::from_slice(&line)?;
                ensure!(row["_PID"]=="1"&&row["_UID"]=="0"&&row["UNIT"]==unit&&row["INVOCATION_ID"]==iid,
                    "original guard manager journal crossed owner");
                let finished=row["MESSAGE"].as_str().is_some_and(|s|s.contains("Deactivated successfully"));
                rows.push(row);
                if finished{return Ok(rows)}
            }
        }
    })();
    let _=child.kill();let _=child.wait();result
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn event_poll_timeout_rounds_positive_remainders_up_without_renewing_deadline(){
        assert!(event_poll_millis(Duration::ZERO).is_err());
        assert_eq!(event_poll_millis(Duration::from_nanos(1)).unwrap(),1);
        assert_eq!(event_poll_millis(Duration::from_millis(150)).unwrap(),150);
        // This models the actual150ms test after its prestart event was parsed:
        // floor149 would terminate early; the unchanged absolute deadline remains.
        assert_eq!(event_poll_millis(Duration::from_nanos(149_500_001)).unwrap(),150);
        assert_eq!(event_poll_millis(Duration::from_nanos(999_999)).unwrap(),1);
        assert_eq!(event_poll_millis(Duration::from_nanos(1_000_001)).unwrap(),2);
        assert_eq!(event_poll_millis(Duration::from_secs(u64::MAX)).unwrap(),i32::MAX);
    }
    #[test]fn only_exact_invocation_guard_names_are_candidates(){
        assert!(guard_filename(&format!("guard-{}.json","a".repeat(32))));
        for s in ["guard-../x.json","guard-a.json","token.json","guard-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.json"]{assert!(!guard_filename(s))}
    }
    #[test]fn incomplete_or_nonmatching_log_is_only_absent_wakeup(){
        assert!(!input_validation_log(br#"{"epoch":185,"event":"phase start","phase":"input validation"}"#));
        assert!(input_validation_log(b"{\"epoch\":185,\"event\":\"phase start\",\"phase\":\"input validation\"}\n"));
        assert!(!input_validation_log(b"{\"epoch\":186,\"event\":\"phase start\",\"phase\":\"input validation\"}\n"));
    }
    #[test]fn truncated_and_overflow_events_fail_closed(){
        assert!(parse_events(&[0;3]).is_err());
        let mut raw=vec![0u8;std::mem::size_of::<libc::inotify_event>()];
        raw[4..8].copy_from_slice(&libc::IN_Q_OVERFLOW.to_ne_bytes());
        assert!(parse_events(&raw).is_err());
    }
    fn native_event(name:&str,mask:u32)->Vec<u8>{
        let header=std::mem::size_of::<libc::inotify_event>();
        let length=(name.len()+1+3)&!3;
        let mut raw=vec![0u8;header+length];
        raw[0..4].copy_from_slice(&1i32.to_ne_bytes());
        raw[4..8].copy_from_slice(&mask.to_ne_bytes());
        raw[12..16].copy_from_slice(&(length as u32).to_ne_bytes());
        raw[header..header+name.len()].copy_from_slice(name.as_bytes());raw
    }
    #[test]fn guard_publication_preserves_masks_and_requires_completed_writer(){
        let name=format!("guard-{}.json","a".repeat(32));
        for (mask,accepted) in [(libc::IN_MODIFY,false),(libc::IN_MOVED_TO,false),
            (libc::IN_CLOSE_WRITE,true),(libc::IN_CLOSE_WRITE|libc::IN_MODIFY,true),
            (libc::IN_CLOSE_WRITE|libc::IN_ISDIR,false)]{
            let events=parse_events(&native_event(&name,mask)).unwrap();
            assert_eq!(events,vec![Event{name:name.clone(),mask}]);
            assert_eq!(guard_published(&events[0]),accepted);
        }
    }
    #[test]fn every_original_watch_invalidation_fails_closed(){
        for mask in [libc::IN_Q_OVERFLOW,libc::IN_IGNORED,libc::IN_DELETE_SELF,libc::IN_MOVE_SELF]{
            assert!(parse_events(&native_event("",mask)).is_err());
        }
    }
    #[test]fn malformed_event_names_and_lengths_still_fail_closed(){
        for name in ["../guard.json","guard/name",".",".."]{
            assert!(parse_events(&native_event(name,libc::IN_CLOSE_WRITE)).is_err());
        }
        let name=format!("guard-{}.json","a".repeat(32));
        let mut truncated=native_event(&name,libc::IN_CLOSE_WRITE);truncated.pop();
        assert!(parse_events(&truncated).is_err());
        let mut invalid=native_event("a",libc::IN_CLOSE_WRITE);
        invalid[std::mem::size_of::<libc::inotify_event>()]=0xff;
        assert!(parse_events(&invalid).is_err());
    }

}

#[cfg(test)]
#[path="events_publication_native_tests.rs"]
mod publication_native_tests;
