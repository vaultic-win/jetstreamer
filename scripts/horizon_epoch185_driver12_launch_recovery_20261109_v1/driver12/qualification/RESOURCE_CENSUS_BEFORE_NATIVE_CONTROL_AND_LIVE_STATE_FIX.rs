//! Bounded complete censuses; a disappearing descendant never becomes zero usage.
use anyhow::{Context, Result, ensure};
use std::{fs::{self, File, Metadata, OpenOptions}, io, os::unix::fs::{MetadataExt, OpenOptionsExt}, path::{Path, PathBuf}, time::{Duration, Instant}};
const RETRIES: usize = 8;
#[derive(Debug)]
struct UnstableEntry(PathBuf);
impl std::fmt::Display for UnstableEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f,"descendant disappeared during allocation census: {}",self.0.display()) }
}
impl std::error::Error for UnstableEntry {}
fn descendant_io<T>(value: io::Result<T>, path: &Path, root: &Path, operation: &str) -> Result<T> {
    match value {
        Ok(v) => Ok(v),
        Err(e) if e.kind()==io::ErrorKind::NotFound && path!=root && path.starts_with(root) => Err(UnstableEntry(path.to_owned()).into()),
        Err(e) => Err(e).with_context(||format!("allocation {operation}: {}",path.display())),
    }
}
fn identity(m: &Metadata) -> (u64,u64) { (m.dev(),m.ino()) }
fn root_unchanged(root: &Path, fd: &File, expected: (u64,u64)) -> Result<()> {
    let named=fs::symlink_metadata(root).with_context(||format!("allocation root identity: {}",root.display()))?;
    let held=fd.metadata().context("allocation pinned root metadata")?;
    ensure!(named.is_dir() && !named.file_type().is_symlink() && identity(&named)==expected && identity(&held)==expected,"allocation root replaced: {}",root.display());
    Ok(())
}
struct Budget { started: Instant, visited: u64, maximum_seen: u64 }
impl Budget {
    fn step(&mut self, depth: u32) -> Result<()> {
        ensure!(depth<=64 && self.visited<4_000_000 && self.started.elapsed()<Duration::from_secs(30),"guard allocation census bound");
        self.visited+=1; Ok(())
    }
}
pub(super) fn allocated(root: &Path, maximum: u64) -> Result<u64> {
    allocated_with(root,maximum,&mut |_,_|{})
}
fn allocated_with(root: &Path, maximum: u64, before: &mut impl FnMut(usize,&Path)) -> Result<u64> {
    let original=fs::symlink_metadata(root).with_context(||format!("allocation initial root: {}",root.display()))?;
    ensure!(original.is_dir() && !original.file_type().is_symlink(),"allocation root is not a real directory");
    let fd=OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC).open(root).with_context(||format!("pin allocation root: {}",root.display()))?;
    let expected=identity(&original);
    root_unchanged(root,&fd,expected)?;
    let mut budget=Budget{started:Instant::now(),visited:0,maximum_seen:0};
    for attempt in 0..RETRIES {
        root_unchanged(root,&fd,expected)?;
        let pass=(|| -> Result<()> {
            let mut pending=vec![(root.to_owned(),0u32)]; let mut bytes=0u64;
            while let Some((path,depth))=pending.pop() {
                super::heartbeat(); budget.step(depth)?; before(attempt,&path);
                let m=descendant_io(fs::symlink_metadata(&path),&path,root,"stat")?;
                ensure!(m.dev()==expected.0 && !m.file_type().is_symlink(),"guard allocation escaped at {}",path.display());
                bytes=bytes.checked_add(m.blocks().checked_mul(512).context("allocation block overflow")?).context("allocation sum overflow")?;
                budget.maximum_seen=budget.maximum_seen.max(bytes);
                ensure!(budget.maximum_seen<=maximum,"allocation ceiling exceeded at {}",path.display());
                if m.is_dir() {
                    let entries=descendant_io(fs::read_dir(&path),&path,root,"read directory")?;
                    for entry in entries {
                        pending.push((descendant_io(entry,&path,root,"read entry")?.path(),depth+1));
                    }
                } else { ensure!(m.is_file(),"foreign scratch object: {}",path.display()); }
            }
            Ok(())
        })();
        // Root identity is checked even when a child lookup failed.
        root_unchanged(root,&fd,expected)?;
        match pass {
            Ok(()) => return Ok(budget.maximum_seen),
            Err(e) if e.downcast_ref::<UnstableEntry>().is_some() => {
                if attempt+1==RETRIES { return Err(e).context("allocation census retry limit; no usage accepted"); }
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}
fn members(path: &Path) -> Result<Vec<u32>> {
    let raw=fs::read_to_string(path).with_context(||format!("read cgroup membership: {}",path.display()))?;
    let mut out:Vec<u32>=raw.lines().map(|s| {let pid=s.parse::<u32>().context("cgroup PID framing")?;ensure!(pid>0,"zero cgroup PID");Ok(pid)}).collect::<Result<_>>()?;
    out.sort_unstable();ensure!(!out.windows(2).any(|p|p[0]==p[1]),"duplicate cgroup PID");Ok(out)
}
fn pid_identity(proc_root: &Path, pid: u32) -> Result<Option<(u64,char)>> {
    match fs::read_to_string(proc_root.join(pid.to_string()).join("stat")) {
        Err(e) if matches!(e.raw_os_error(),Some(libc::ENOENT|libc::ESRCH)) => Ok(None),
        Err(e) => Err(e).with_context(||format!("recheck missing-maps PID {pid} identity")),
        Ok(raw) => {
            let (_,fields)=raw.rsplit_once(')').context("PID stat framing")?;
            let fields:Vec<_>=fields.split_whitespace().collect();ensure!(fields.len()>19,"short PID stat");
            let state=fields[0].chars().next().context("PID stat state")?;
            let ticks=fields[19].parse::<u64>().context("PID start ticks")?;ensure!(ticks>0,"zero PID start ticks");
            Ok(Some((ticks,state)))
        }
    }
}
fn exited(proc_root:&Path,pid:u32)->Result<bool>{Ok(pid_identity(proc_root,pid)?.is_none_or(|(_,s)|matches!(s,'Z'|'X')))}
pub(super) fn maximum_vmas(cgroup: &Path) -> Result<usize> {
    vmas_with(&cgroup.join("cgroup.procs"),Path::new("/proc"),&mut |_,_|{})
}
fn vmas_with(cgroup_procs: &Path, proc_root: &Path, before: &mut impl FnMut(usize,u32)) -> Result<usize> {
    let started=Instant::now(); let mut maximum=0;
    for attempt in 0..RETRIES {
        ensure!(started.elapsed()<Duration::from_secs(5),"VMA census retry deadline; no usage accepted");
        let pids=members(cgroup_procs)?;let mut retry=false;
        for &pid in &pids {
            before(attempt,pid);
            let identity=pid_identity(proc_root,pid)?;
            let path=proc_root.join(pid.to_string()).join("maps");
            match fs::read_to_string(&path) {
                Ok(maps) => {
                    maximum=maximum.max(maps.lines().count());
                    let after=pid_identity(proc_root,pid)?;
                    if identity!=after || identity.is_none() {
                        ensure!(exited(proc_root,pid)? && !members(cgroup_procs)?.contains(&pid),"PID identity changed across VMA census for {pid}");
                        retry=true;break;
                    }
                },
                Err(e) if matches!(e.raw_os_error(),Some(libc::ENOENT|libc::ESRCH)) => {
                    // A missing maps file for a live or still-member PID is never accepted.
                    ensure!(exited(proc_root,pid)? && !members(cgroup_procs)?.contains(&pid),"missing maps for live or retained cgroup PID {pid}");
                    retry=true;break;
                }
                Err(e) => return Err(e).with_context(||format!("read actor VMA census {}",path.display())),
            }
        }
        if !retry && members(cgroup_procs)?==pids { return Ok(maximum); }
    }
    anyhow::bail!("VMA census retry limit; no usage accepted")
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    #[test] fn disappearing_child_requires_a_new_complete_pass() {
        let t=tempfile::tempdir().unwrap();let doomed=t.path().join("gone");fs::write(&doomed,b"payload").unwrap();let mut removed=false;
        let measured=allocated_with(t.path(),1<<20,&mut |attempt,path|{if attempt==0 && path==doomed {fs::remove_file(path).unwrap();removed=true;}}).unwrap();
        assert!(removed);assert!(measured>=fs::metadata(t.path()).unwrap().blocks()*512);
    }
    #[test] fn lost_or_replaced_root_never_gets_retry_credit() {
        let t=tempfile::tempdir().unwrap();let root=t.path().join("root");fs::create_dir(&root).unwrap();let moved=t.path().join("old");let mut once=false;
        assert!(allocated_with(&root,1<<20,&mut |_,path|{if !once && path==root {once=true;fs::rename(&root,&moved).unwrap();fs::create_dir(&root).unwrap();}}).is_err());
        assert!(allocated(&t.path().join("absent"),1<<20).is_err());
    }
    #[test] fn symlink_and_ceiling_errors_are_never_transient() {
        let t=tempfile::tempdir().unwrap();let outside=tempfile::tempdir().unwrap();symlink(outside.path(),t.path().join("link")).unwrap();assert!(allocated(t.path(),1<<20).is_err());
        fs::remove_file(t.path().join("link")).unwrap();fs::write(t.path().join("large"),vec![1u8;8192]).unwrap();assert!(allocated(t.path(),0).is_err());
    }
    #[test] fn perpetual_file_churn_hits_same_finite_retry_bound() {
        let t=tempfile::tempdir().unwrap();let child=t.path().join("child");fs::write(&child,b"x").unwrap();let mut attempts=0;
        assert!(allocated_with(t.path(),1<<20,&mut |attempt,path| {if path==t.path(){fs::write(&child,b"x").unwrap();attempts=attempt+1;}else if path==child{fs::remove_file(&child).unwrap();}}).is_err());assert_eq!(attempts,RETRIES);
    }
    #[test] fn missing_maps_requires_proven_exit_and_absent_membership() {
        let t=tempfile::tempdir().unwrap();let c=t.path().join("cgroup.procs");let proc=t.path().join("proc");fs::create_dir(&proc).unwrap();fs::write(&c,"123\n").unwrap();
        assert!(vmas_with(&c,&proc,&mut |_,_|{}).is_err());
        let mut once=false;assert_eq!(vmas_with(&c,&proc,&mut |_,_|{if !once{once=true;fs::write(&c,"").unwrap();}}).unwrap(),0);
    }
    #[test] fn live_pid_without_maps_is_not_a_zero_usage_process() {
        let t=tempfile::tempdir().unwrap();let c=t.path().join("cgroup.procs");fs::write(&c,"").unwrap();let proc=t.path().join("proc");fs::create_dir_all(proc.join("123")).unwrap();fs::write(proc.join("123/stat"),"123 (live) S 1 2 3").unwrap();
        assert!(vmas_with(&c,&proc,&mut |_,_|{}).is_ok());fs::write(&c,"123\n").unwrap();assert!(vmas_with(&c,&proc,&mut |_,_|{fs::write(&c,"").unwrap();}).is_err());
    }
}
