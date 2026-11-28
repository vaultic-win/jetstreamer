//! Finite inotify event waits for this original transaction, never resource polling.
use crate::{storage,process,now,n,text};
use anyhow::{Context,Result,ensure};
use serde_json::Value;
use std::{ffi::CString,fs::{self,OpenOptions},io::{Read,Write},os::unix::fs::{OpenOptionsExt,MetadataExt},
    path::Path,time::Instant};
pub struct Watch{fd:i32}
impl Drop for Watch{fn drop(&mut self){unsafe{libc::close(self.fd);}}}
impl Watch{
    pub fn new(path:&Path)->Result<Self>{
        ensure!(path.canonicalize()?==path&&fs::symlink_metadata(path)?.is_dir(),"event watch directory alias");
        let name=CString::new(path.as_os_str().as_encoded_bytes())?;
        let fd=unsafe{libc::inotify_init1(libc::IN_CLOEXEC|libc::IN_NONBLOCK)};
        ensure!(fd>=0,"cannot initialize original event watch");
        let wd=unsafe{libc::inotify_add_watch(fd,name.as_ptr(),libc::IN_MOVED_TO|libc::IN_CLOSE_WRITE|libc::IN_MODIFY|libc::IN_DELETE_SELF|libc::IN_MOVE_SELF)};
        if wd<0{unsafe{libc::close(fd);}anyhow::bail!("cannot arm original directory watch")}
        Ok(Self{fd})
    }
    fn names(&self,until:Instant)->Result<Vec<String>>{
        loop{
            let left=until.checked_duration_since(Instant::now()).context("original event deadline expired")?;
            let mut p=libc::pollfd{fd:self.fd,events:libc::POLLIN,revents:0};
            let r=unsafe{libc::poll(&mut p,1,left.as_millis().clamp(1,i32::MAX as u128)as i32)};
            if r<0&&std::io::Error::last_os_error().kind()==std::io::ErrorKind::Interrupted{continue}
            ensure!(r>0&&p.revents&libc::POLLIN!=0,"original event watch timeout/error");
            let mut bytes=[0u8;65536];let count=unsafe{libc::read(self.fd,bytes.as_mut_ptr().cast(),bytes.len())};
            ensure!(count>0,"event watch closed/read error");return parse_names(&bytes[..count as usize]);
        }
    }
    pub fn guard(&self,root:&Path,actor:&str,iid:&str,admission:&str,until:Instant)->Result<(storage::Bound,Value)>{
        let mut events=0;
        loop{
            for name in self.names(until)?{
                events+=1;ensure!(events<=256,"bounded original guard event count exceeded");
                if !guard_filename(&name){continue}
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
                return Ok((b,v))
            }
        }
    }
    pub fn main_event(&self,log:&Path,until:Instant)->Result<()>{
        // This event is only a wakeup. The qualified lifecycle helper must
        // subsequently authenticate actual MainPID and original PID1 release.
        loop{
            if input_validation_log(&read_sol_log(log)?){return Ok(())}
            let _=self.names(until)?;
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
fn parse_names(mut raw:&[u8])->Result<Vec<String>>{
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
            result.push(value.into());
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
        assert!(parse_names(&[0;3]).is_err());
        let mut raw=vec![0u8;std::mem::size_of::<libc::inotify_event>()];
        raw[4..8].copy_from_slice(&libc::IN_Q_OVERFLOW.to_ne_bytes());
        assert!(parse_names(&raw).is_err());
    }
}
