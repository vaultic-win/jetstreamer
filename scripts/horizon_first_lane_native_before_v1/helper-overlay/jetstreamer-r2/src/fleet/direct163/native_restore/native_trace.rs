//! Bounded failed-syscall diagnostics for one already authenticated held actor.
//! Shares the original2GiB issuer cgroup/CPU cap; never alters native limits.
use super::*;
use std::os::unix::process::CommandExt;
const PROGRAM:&str="/usr/local/lib/jetstreamer/horizon-native163-syscall-tracer-tools-20261108-v1/strace";
const PROGRAM_SHA:&str="28f957c227012de0b18d1bd7fff2d396cb693ea60ed8013be68de071e84b5001";
const MAX_BYTES:u64=1<<20;
pub(super) struct Trace {child:std::process::Child,actor_pid:u32,argv:Vec<String>,log:PathBuf,attached:Option<Value>}
fn arguments(pid:u32,log:&Path)->Result<Vec<String>> {
 ensure!(pid>1 && log.is_absolute() && log.file_name().is_some_and(|x|x=="unpack-syscalls.strace"),"exact native trace target/output scope");
 Ok(vec![PROGRAM.into(),"-f".into(),"--status=failed".into(),"-s".into(),"128".into(),"-y".into(),"-e".into(),"trace=%file,write,pwrite64,ftruncate,copy_file_range,mmap,mremap,mprotect".into(),"-e".into(),"raw=write,pwrite64".into(),"-o".into(),log.display().to_string(),"-p".into(),pid.to_string()])
}
pub(super) fn start(enabled:bool,p:&NativePlan,pb:&Bound,first:&Value)->Result<Option<Trace>> {
 if !enabled {return Ok(None)}
 ensure!(held::capture(p,pb)?==*first,"trace requires genuine unchanged original held capture");
 storage::bytes(&fixed(PROGRAM,PROGRAM_SHA),16<<20,true)?;
 let seal=immutable(&fixed("/usr/local/lib/jetstreamer/horizon-native163-syscall-tracer-tools-20261108-v1/deployment-seal-receipt.json","99bec452075e67a77f320706626ce1700313394a32c427f8fdda236a82737dc5"))?;
 ensure!(seal["destination"]==Path::new(PROGRAM).parent().unwrap().display().to_string()
  && seal["members"].as_array().is_some_and(|a|a.iter().filter(|r|r["name"]=="strace"&&r["sha256"]==PROGRAM_SHA&&r["mode"]=="0555").count()==1),"normal sealed diagnostic image");
 let pid=u32::try_from(n(first,"pid")?)?;let log=p.state.join("unpack-syscalls.strace");
 let file=OpenOptions::new().write(true).create_new(true).mode(0o600).open(&log)?;file.sync_all()?;drop(file);
 let error=OpenOptions::new().write(true).create_new(true).mode(0o600).open(p.state.join("unpack-tracer.stderr"))?;
 let argv=arguments(pid,&log)?;let mut command=ProcessCommand::new("/usr/bin/timeout");
 command.args(["--foreground","--signal=TERM","--kill-after=2s","90s"]).args(&argv)
  .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::from(error));
 unsafe {command.pre_exec(||{let limit=libc::rlimit{rlim_cur:MAX_BYTES,rlim_max:MAX_BYTES};if libc::setrlimit(libc::RLIMIT_FSIZE,&limit)!=0{return Err(std::io::Error::last_os_error())}Ok(())});}
 let child=command.spawn()?;
 // Original90/105/120s and worker7200s clocks remain authoritative. Timeout
 // signals only its own tracer. The tracee lives in a different native cgroup.
 Ok(Some(Trace{child,actor_pid:pid,argv,log,attached:None}))
}
impl Trace {
 pub(super) fn validate_attached(&mut self,first:&Value)->Result<()> {
  ensure!(self.child.try_wait()?.is_none() && n(first,"pid")?==u64::from(self.actor_pid),"original diagnostic exited before admission; no unchanged retry");
  let status=fs::read_to_string(format!("/proc/{}/status",self.actor_pid))?;
  let tracer=status.lines().find_map(|s|s.strip_prefix("TracerPid:")).context("actual tracer identity")?.trim().parse::<u32>()?;
  ensure!(tracer>1,"original native diagnostic is not actually attached");
  held::mapped(tracer,&fixed(PROGRAM,PROGRAM_SHA),&self.argv)?;
  ensure!(fs::read(format!("/proc/{tracer}/cgroup"))?==fs::read("/proc/self/cgroup")?,"actual tracer must share unchanged issuer2GiB pool cgroup");
  let stat=fs::read_to_string(format!("/proc/{tracer}/stat"))?;
  let fields=stat.rsplit_once(") ").context("actual tracer proc stat")?.1.split_whitespace().collect::<Vec<_>>();
  ensure!(fields.get(1).context("actual tracer parent")?.parse::<u32>()?==self.child.id(),"actual tracer must belong to original finite timeout child");
  self.attached=Some(json!({"tracer_pid":tracer,"tracer_start_ticks":fields.get(19).context("actual tracer ticks")?.parse::<u64>()?,"original_timeout_pid":self.child.id(),"program":fixed(PROGRAM,PROGRAM_SHA),"actual_shared_issuer_cgroup":true}));Ok(())
 }
 pub(super) fn evidence(&self)->Value {json!({"schema":"native163-original-bounded-unpack-syscall-diagnostic-v1","actor_pid":self.actor_pid,"actual_attachment":self.attached,"program":fixed(PROGRAM,PROGRAM_SHA),"argv":self.argv,"trace_log":self.log,"maximum_trace_file_bytes":MAX_BYTES,"maximum_seconds":90,"memory_and_CPU_within_original_issuer_cgroup":true,"completion_pending":true,"no_native_resource_or_clock_change":true,"no_replay_or_publication_authority":true})}
}
#[cfg(test)]mod tests {
 use super::*;
 #[test]fn diagnostic_argv_is_one_fixed_actor_and_failed_syscalls_only(){let a=arguments(123,Path::new("/private/state/unpack-syscalls.strace")).unwrap();assert_eq!(a[0],PROGRAM);assert!(a.iter().any(|s|s=="--status=failed"));assert!(a.iter().any(|s|s=="raw=write,pwrite64"));assert_eq!(&a[a.len()-2..],["-p","123"]);assert!(arguments(0,Path::new("/private/state/unpack-syscalls.strace")).is_err());assert!(arguments(1,Path::new("/private/state/unpack-syscalls.strace")).is_err());assert!(arguments(123,Path::new("/arbitrary/other.log")).is_err());}
}
