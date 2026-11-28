//! Bounded complete censuses; a disappearing descendant never becomes zero usage.
use anyhow::{Context, Result, ensure};
use std::{fs::{self, File, Metadata, OpenOptions}, io, os::{fd::{AsRawFd, FromRawFd}, unix::{ffi::OsStrExt, fs::{MetadataExt, OpenOptionsExt}}}, path::{Path, PathBuf}, time::{Duration, Instant}};
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
    allocated_with_hooks(root, maximum, before, &mut |_,_,_|{})
}
fn allocated_with_hooks(root: &Path, maximum: u64,
    before: &mut impl FnMut(usize,&Path), after_pin: &mut impl FnMut(usize,&Path,&File)) -> Result<u64> {
    let original=fs::symlink_metadata(root).with_context(||format!("allocation initial root: {}",root.display()))?;
    ensure!(original.is_dir() && !original.file_type().is_symlink(),"allocation root is not a real directory");
    let fd=OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC).open(root).with_context(||format!("pin allocation root: {}",root.display()))?;
    let expected=identity(&original);
    root_unchanged(root,&fd,expected)?;
    let mut budget=Budget{started:Instant::now(),visited:0,maximum_seen:0};
    for attempt in 0..RETRIES {
        root_unchanged(root,&fd,expected)?;
        let pass=(|| -> Result<()> {
            super::heartbeat();budget.step(0)?;before(attempt,root);
            let mut traversal=PinnedPass{root,device:expected.0,maximum,budget:&mut budget,
                before:&mut *before,after_pin:&mut *after_pin,attempt,bytes:0};
            traversal.visit(&fd,root,0,None)
        })();
        // Preserve the original whole-pass root revalidation, including errors.
        root_unchanged(root,&fd,expected)?;
        ensure!(budget.started.elapsed()<Duration::from_secs(30),"guard allocation census bound");
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
// Hold inode references rather than queuing names until after a large directory
// has been enumerated. An unlinked held file is still measured and charged.
struct DirectoryEntries(*mut libc::DIR);
impl DirectoryEntries {
    fn new(held: &File, path: &Path, root: &Path) -> Result<Self> {
        // openat(".") creates a fresh directory-stream offset on every pass.
        // dup(held) would share the old EOF offset and could skip a retry's tree.
        let dot = c".";
        let raw = unsafe { libc::openat(held.as_raw_fd(), dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        let fd = descendant_io(if raw < 0 { Err(io::Error::last_os_error()) } else { Ok(raw) },
            path, root, "open pinned directory stream")?;
        let stream = unsafe { libc::fdopendir(fd) };
        if stream.is_null() {
            let error = io::Error::last_os_error();
            unsafe { libc::close(fd); }
            return Err(error).with_context(|| format!("allocation fdopendir: {}", path.display()));
        }
        Ok(Self(stream))
    }
    fn next_name(&mut self, path: &Path, root: &Path) -> Result<Option<std::ffi::CString>> {
        loop {
            unsafe { *libc::__errno_location() = 0; }
            let entry = unsafe { libc::readdir(self.0) };
            if entry.is_null() {
                let error = io::Error::last_os_error();
                return if error.raw_os_error() == Some(0) { Ok(None) }
                    else { descendant_io(Err(error), path, root, "read pinned directory entry") };
            }
            let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
            if name.to_bytes() == b"." || name.to_bytes() == b".." { continue; }
            ensure!(!name.to_bytes().contains(&b'/'), "allocation directory name escape");
            return Ok(Some(name.to_owned()));
        }
    }
}
impl Drop for DirectoryEntries {
    fn drop(&mut self) { unsafe { libc::closedir(self.0); } }
}

struct PinnedPass<'a, Before, After> {
    root: &'a Path,
    device: u64,
    maximum: u64,
    budget: &'a mut Budget,
    before: &'a mut Before,
    after_pin: &'a mut After,
    attempt: usize,
    bytes: u64,
}
impl<Before, After> PinnedPass<'_, Before, After>
where Before: FnMut(usize, &Path), After: FnMut(usize, &Path, &File) {
    fn directory_named(&self, path: &Path, held: &File) -> Result<Metadata> {
        let named = descendant_io(fs::symlink_metadata(path), path, self.root, "revalidate directory name")?;
        ensure!(named.dev() == self.device && named.is_dir() && !named.file_type().is_symlink(),
            "guard allocation escaped directory at {}", path.display());
        ensure!(identity(&named) == identity(&held.metadata()?),
            "allocation directory inode replaced at {}", path.display());
        Ok(named)
    }
    fn charge(&mut self, blocks: u64, path: &Path) -> Result<()> {
        self.bytes = self.bytes.checked_add(blocks.checked_mul(512).context("allocation block overflow")?)
            .context("allocation sum overflow")?;
        self.budget.maximum_seen = self.budget.maximum_seen.max(self.bytes);
        ensure!(self.budget.maximum_seen <= self.maximum,
            "allocation ceiling exceeded at {}", path.display());
        Ok(())
    }
    fn grow_charge(&mut self, counted: &mut u64, observed: u64, path: &Path) -> Result<()> {
        let high = (*counted).max(observed);
        self.charge(high.checked_sub(*counted).context("allocation block high-water underflow")?, path)?;
        *counted = high; Ok(())
    }
    fn visit(&mut self, held: &File, path: &Path, depth: u32, parent_held: Option<&File>) -> Result<()> {
        (self.after_pin)(self.attempt, path, held);
        let m = held.metadata().with_context(|| format!("allocation pinned metadata: {}", path.display()))?;
        ensure!(m.dev() == self.device && !m.file_type().is_symlink(),
            "guard allocation escaped at {}", path.display());
        ensure!(m.is_file() || m.is_dir(), "foreign scratch object: {}", path.display());
        self.charge(m.blocks(), path)?;
        let mut largest_blocks = m.blocks();
        if m.is_dir() {
            let named = self.directory_named(path, held)?;
            self.grow_charge(&mut largest_blocks, named.blocks(), path)?;
            let mut entries = DirectoryEntries::new(held, path, self.root)?;
            while let Some(name) = entries.next_name(path, self.root)? {
                super::heartbeat();
                self.budget.step(depth + 1)?;
                let child = path.join(std::ffi::OsStr::from_bytes(name.to_bytes()));
                (self.before)(self.attempt, &child);
                let raw = unsafe { libc::openat(held.as_raw_fd(), name.as_ptr(),
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
                let fd = descendant_io(if raw < 0 { Err(io::Error::last_os_error()) } else { Ok(raw) },
                    &child, self.root, "pin discovered inode")?;
                let pinned = unsafe { File::from_raw_fd(fd) };
                self.visit(&pinned, &child, depth + 1, Some(held))?;
            }
            // A detached/replaced directory must not masquerade as a complete
            // traversal of the still-admitted rooted namespace.
            let named = self.directory_named(path, held)?;
            self.grow_charge(&mut largest_blocks, named.blocks(), path)?;
        } else {
            let parent = path.parent().context("allocation pinned file parent")?;
            match fs::symlink_metadata(path) {
                Ok(named) => {
                    ensure!(named.dev() == self.device && named.is_file() && !named.file_type().is_symlink(),
                        "guard allocation escaped file at {}", path.display());
                    if identity(&named) != identity(&m) {
                        // Retain every observed inode's blocks before rejecting
                        // a replacement, including an already-over-ceiling one.
                        self.charge(named.blocks(), path)?;
                        return Err(anyhow::Error::new(UnstableEntry(path.to_owned())))
                            .context("allocation file name replaced after pin; complete new pass required");
                    }
                    self.grow_charge(&mut largest_blocks, named.blocks(), path)?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    // Charge the measured held inode even though its former name
                    // is gone. Check that this was a child unlink, not a vanished
                    // parent namespace. No unknown or missing-before-pin entry
                    // reaches this branch, and no usage is replaced with zero.
                    let named_parent = descendant_io(fs::symlink_metadata(parent), parent, self.root,
                        "revalidate unlinked file parent")?;
                    let expected_parent = parent_held.context("pinned child parent descriptor")?.metadata()?;
                    ensure!(named_parent.is_dir() && !named_parent.file_type().is_symlink()
                        && named_parent.dev() == self.device
                        && identity(&named_parent) == identity(&expected_parent),
                        "allocation parent namespace escaped for {}", path.display());
                }
                Err(error) => return Err(error).with_context(|| format!("allocation pinned file name: {}", path.display())),
            }
        }
        let after = held.metadata().with_context(|| format!("allocation pinned final metadata: {}", path.display()))?;
        ensure!(identity(&after) == identity(&m) && after.dev() == self.device,
            "allocation pinned inode identity changed at {}", path.display());
        self.grow_charge(&mut largest_blocks, after.blocks(), path)?;
        Ok(())
    }
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
                    if identity.map(|(ticks,_)|ticks)!=after.map(|(ticks,_)|ticks) || identity.is_none() {
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

#[cfg(test)] mod native_controls {
    use super::*;
    #[test]
    #[ignore = "Root-booked actual Root/Sol transient filesystem and exited owned child in its native cgroup; no replay"]
    fn actual_native_complete_censuses_survive_unlink_and_owned_pid_exit() {
        assert!(matches!(unsafe{libc::geteuid()},0|1001));
        let t=tempfile::tempdir().unwrap();let path=t.path().join("entry");fs::write(&path,b"genuine-filesystem-entry").unwrap();
        let mut unlinked=false;
        let bytes=allocated_with(t.path(),1<<20,&mut |attempt,p|{if attempt==0 && p==path{fs::remove_file(&path).unwrap();unlinked=true;}}).unwrap();
        assert!(unlinked);assert!(bytes>=fs::metadata(t.path()).unwrap().blocks()*512);
        let cgroup=fs::read_to_string("/proc/self/cgroup").unwrap();let relative=cgroup.strip_prefix("0::/").unwrap().trim();
        assert!(relative.starts_with("system.slice/"));let membership=Path::new("/sys/fs/cgroup").join(relative).join("cgroup.procs");
        let mut child=std::process::Command::new("/usr/bin/sleep").arg("10").spawn().unwrap();let pid=child.id();
        assert!(members(&membership).unwrap().contains(&pid));let mut reaped=false;let mut later_pass=false;
        let result=vmas_with(&membership,Path::new("/proc"),&mut |attempt,p| {later_pass|=attempt>0;if p==pid && !reaped{child.kill().unwrap();child.wait().unwrap();reaped=true;}});
        let _=child.kill();let _=child.wait();
        assert!(reaped && later_pass);assert!(result.unwrap()>0);assert!(!members(&membership).unwrap().contains(&pid));
    }
}

#[cfg(test)]
mod pinned_inode_tests {
    use super::*;
    #[test]
    fn inode_pinned_before_unlink_is_charged_without_restarting_the_whole_tree() {
        let t=tempfile::tempdir().unwrap();let child=t.path().join("account");
        fs::write(&child,vec![7u8;8192]).unwrap();
        let expected=fs::metadata(t.path()).unwrap().blocks()*512+fs::metadata(&child).unwrap().blocks()*512;
        let mut unlinked=false;let mut last_attempt=0;
        let measured=allocated_with_hooks(t.path(),1<<20,&mut |attempt,_|last_attempt=attempt,
            &mut |_,path,held|{if path==child{assert!(held.metadata().unwrap().blocks()>0);fs::remove_file(path).unwrap();unlinked=true;}}).unwrap();
        assert!(unlinked);assert_eq!(last_attempt,0);assert!(measured>=expected);
    }
    #[test]
    fn every_discovered_account_can_unlink_after_pin_without_zero_charge() {
        let t=tempfile::tempdir().unwrap();let accounts=t.path().join("accounts");fs::create_dir(&accounts).unwrap();
        let mut expected=0;
        for i in 0..32{let p=accounts.join(format!("account-{i}"));fs::write(&p,vec![3u8;8192]).unwrap();expected+=fs::metadata(p).unwrap().blocks()*512;}
        let mut charged=0;let mut last_attempt=0;
        let measured=allocated_with_hooks(t.path(),1<<20,&mut |attempt,_|last_attempt=attempt,
            &mut |_,path,held|{if path.parent()==Some(accounts.as_path())&&held.metadata().unwrap().is_file(){charged+=1;fs::remove_file(path).unwrap();}}).unwrap();
        assert_eq!(charged,32);assert_eq!(last_attempt,0);assert!(measured>=expected);
    }
    #[test]
    fn unlinked_pinned_inode_still_enforces_the_original_ceiling() {
        let t=tempfile::tempdir().unwrap();let p=t.path().join("large");fs::write(&p,vec![1u8;16384]).unwrap();
        let blocks=fs::metadata(&p).unwrap().blocks()*512;assert!(blocks>0);
        let error=allocated_with_hooks(t.path(),blocks-1,&mut |_,_|{},
            &mut |_,path,_|{if path==p{fs::remove_file(path).unwrap();}}).unwrap_err();
        assert!(format!("{error:#}").contains("allocation ceiling exceeded"));
    }
    #[test]
    fn a_replaced_file_name_requires_a_new_complete_pass_and_counts_its_replacement() {
        let t=tempfile::tempdir().unwrap();let p=t.path().join("account");fs::write(&p,b"small").unwrap();
        let mut replaced=false;let mut later=false;
        let measured=allocated_with_hooks(t.path(),1<<20,&mut |attempt,_|later|=attempt>0,
            &mut |_,path,_|{if path==p&&!replaced{fs::remove_file(path).unwrap();fs::write(path,vec![1u8;32768]).unwrap();replaced=true;}}).unwrap();
        assert!(replaced&&later);assert!(measured>=fs::metadata(&p).unwrap().blocks()*512);
    }
    #[test]
    fn observed_replacement_above_ceiling_is_not_forgotten_by_a_later_retry() {
        let t=tempfile::tempdir().unwrap();let p=t.path().join("account");fs::write(&p,b"small").unwrap();
        let mut replaced=false;let mut last_attempt=0;
        let error=allocated_with_hooks(t.path(),16<<10,&mut |attempt,_|last_attempt=attempt,
            &mut |_,path,_|{if path==p&&!replaced{fs::remove_file(path).unwrap();fs::write(path,vec![1u8;32768]).unwrap();replaced=true;}}).unwrap_err();
        assert!(replaced);assert_eq!(last_attempt,0);assert!(format!("{error:#}").contains("allocation ceiling exceeded"));
    }
    #[test]
    fn held_directory_does_not_hide_a_replaced_root_or_symlink() {
        let t=tempfile::tempdir().unwrap();let root=t.path().join("root");fs::create_dir(&root).unwrap();
        let child=root.join("child");fs::create_dir(&child).unwrap();let moved=t.path().join("original");let mut changed=false;
        assert!(allocated_with_hooks(&root,1<<20,&mut |_,_|{},&mut |_,path,_|{
            if path==child&&!changed{fs::rename(&root,&moved).unwrap();fs::create_dir(&root).unwrap();changed=true;}
        }).is_err());
        let t=tempfile::tempdir().unwrap();let child=t.path().join("child");fs::create_dir(&child).unwrap();let old=t.path().join("old");let mut changed=false;
        assert!(allocated_with_hooks(t.path(),1<<20,&mut |_,_|{},&mut |_,path,_|{
            if path==child&&!changed{fs::rename(&child,&old).unwrap();std::os::unix::fs::symlink(&old,&child).unwrap();changed=true;}
        }).is_err());
    }
    #[test]
    fn retries_read_a_fresh_directory_stream_instead_of_reusing_its_eof_offset() {
        let t=tempfile::tempdir().unwrap();let gone=t.path().join("gone");let large=t.path().join("large");
        fs::write(&gone,b"old").unwrap();let mut changed=false;let mut later=false;
        let error=allocated_with(t.path(),16<<10,&mut |attempt,path|{
            later|=attempt>0;
            if path==gone&&!changed{fs::remove_file(&gone).unwrap();fs::write(&large,vec![5u8;32768]).unwrap();changed=true;}
        }).unwrap_err();
        assert!(changed&&later);assert!(format!("{error:#}").contains("allocation ceiling exceeded"));
    }
    #[test]
    #[ignore="Root/Sol-booked real openat/fdopendir and another-thread unlink; isolated files only"]
    fn actual_native_pinned_inode_census_charges_concurrent_unlinks() {
        assert!(matches!(unsafe{libc::geteuid()},0|1001));
        let t=tempfile::tempdir().unwrap();let accounts=t.path().join("accounts");fs::create_dir(&accounts).unwrap();
        let mut expected=0;
        for i in 0..64{let p=accounts.join(format!("account-{i}"));fs::write(&p,vec![9u8;8192]).unwrap();expected+=fs::metadata(p).unwrap().blocks()*512;}
        let(tx,rx)=std::sync::mpsc::channel::<PathBuf>();let(ack,done)=std::sync::mpsc::channel();
        let writer=std::thread::spawn(move||{while let Ok(path)=rx.recv(){fs::remove_file(path).unwrap();ack.send(()).unwrap();}});
        let mut charged=0;let mut last_attempt=0;
        let result=allocated_with_hooks(t.path(),4<<20,&mut |attempt,_|last_attempt=attempt,&mut |_,path,held|{
            if path.parent()==Some(accounts.as_path())&&held.metadata().unwrap().is_file(){
                tx.send(path.to_owned()).unwrap();done.recv_timeout(Duration::from_secs(2)).unwrap();
                assert_eq!(held.metadata().unwrap().nlink(),0);assert!(held.metadata().unwrap().blocks()>0);charged+=1;
            }
        });
        drop(tx);writer.join().unwrap();assert_eq!(charged,64);assert_eq!(last_attempt,0);assert!(result.unwrap()>=expected);
    }
}
