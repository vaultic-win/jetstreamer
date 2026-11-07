//! Self-only page identity/charge mechanics. Never grants campaign memory credit.
use anyhow::{ensure, Context, Result};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Read,
    os::fd::{AsRawFd, FromRawFd},
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    path::PathBuf,
    process::Command,
};
const PAGE: u64 = 4096;
const PAGES: usize = 512;
const POSITIVE: &str = "horizon-anon-exclusivity-fixture948-v1.service";
const NEGATIVE: &str = "horizon-anon-exclusivity-fixture948-no-admin-v1.service";
const KERNEL: &str = "7.0.0-38-generic";
const CONFIG_SHA: &str = "6cb18717c6914d4947489eedf8cb69ac23db3faa8ef9b9f563ff02c346dcd32d";
const KERNEL_NOTES_SHA: &str = "fd51d169bb2483dd09cd9705e059104f743c78d21998152292e801ee54ef4827";
const ADMIN: u64 = 1 << 21;
const BASE_CAPS: u64 = (1 << 1) | (1 << 19);
const PRESENT: u64 = 1 << 63;
const SWAPPED: u64 = 1 << 62;
const FILE_OR_SHARED: u64 = 1 << 61;
const PFN_MASK: u64 = (1 << 55) - 1;
const ANON: u64 = 1 << 12;
const SWAPBACKED: u64 = 1 << 14;
const FORBIDDEN: u64 = (1 << 7)
    | (1 << 10)
    | (1 << 13)
    | (1 << 15)
    | (1 << 16)
    | (1 << 17)
    | (1 << 19)
    | (1 << 20)
    | (1 << 21)
    | (1 << 22)
    | (1 << 23)
    | (1 << 24)
    | (1 << 26);
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn canonical_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn bytes_for(pages: u64) -> Result<u64> {
    pages.checked_mul(PAGE).context("page-byte overflow")
}
fn decode_pfn(entry: u64) -> Result<Option<u64>> {
    ensure!(entry & SWAPPED == 0, "swapped fixture page");
    ensure!(
        entry & ((1 << 59) | (1 << 60)) == 0,
        "unknown pagemap state"
    );
    if entry & PRESENT == 0 || entry & FILE_OR_SHARED != 0 {
        return Ok(None);
    }
    let pfn = entry & PFN_MASK;
    ensure!(pfn != 0, "present page has undisclosed/zero PFN");
    Ok(Some(pfn))
}
fn eligible(flags: u64, charge: u64, expected: u64) -> bool {
    expected != 0
        && charge == expected
        && flags & (ANON | SWAPBACKED) == (ANON | SWAPBACKED)
        && flags & FORBIDDEN == 0
        && flags >> 27 == 0
}
fn open_read(path: &str) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?)
}
fn word(file: &File, index: u64) -> Result<u64> {
    let offset = index.checked_mul(8).context("page table offset overflow")?;
    let mut bytes = [0; 8];
    file.read_exact_at(&mut bytes, offset)?;
    Ok(u64::from_le_bytes(bytes))
}
fn ticks() -> Result<u64> {
    let s = fs::read_to_string("/proc/self/stat")?;
    Ok(s.rsplit_once(") ")
        .context("process stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("start ticks")?
        .parse()?)
}
fn native(unit: &str) -> Result<BTreeMap<String, String>> {
    let o = Command::new("/usr/bin/systemctl").env_clear().env("PATH", "/usr/bin:/bin")
        .args(["show", "--all", unit, "--property=Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Job,ControlGroup,Type,User,Group,MemoryMax,MemorySwapMax,TasksMax,TimeoutStartUSec,NoNewPrivileges"])
        .output()?;
    ensure!(
        o.status.success() && o.stdout.len() < 65536 && o.stderr.len() < 65536,
        "native transport failed"
    );
    let mut m = BTreeMap::new();
    for l in std::str::from_utf8(&o.stdout)?.lines() {
        let (k, v) = l.split_once('=').context("native scalar")?;
        ensure!(
            m.insert(k.into(), v.into()).is_none(),
            "duplicate native scalar"
        );
    }
    Ok(m)
}
struct ContextBinding {
    unit: &'static str,
    iid: String,
    start: u64,
    cg: File,
    inode: u64,
    native: BTreeMap<String, String>,
}
fn context() -> Result<ContextBinding> {
    ensure!(unsafe { libc::geteuid() } == 0, "Root fixture required");
    ensure!(
        cfg!(target_endian = "little")
            && usize::BITS == 64
            && unsafe { libc::sysconf(libc::_SC_PAGESIZE) } == PAGE as i64,
        "unsupported page/architecture profile"
    );
    let group = fs::read_to_string("/proc/self/cgroup")?;
    let unit = [POSITIVE, NEGATIVE]
        .into_iter()
        .find(|u| group == format!("0::/system.slice/{u}\n"))
        .context("only fixed self-only disposable memory units are accepted")?;
    let iid = std::env::var("INVOCATION_ID")?;
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid actual IID"
    );
    let m = native(unit)?;
    for (k, v) in [
        ("Id", unit.to_string()),
        ("LoadState", "loaded".into()),
        ("ActiveState", "activating".into()),
        ("SubState", "start".into()),
        ("InvocationID", iid.clone()),
        ("MainPID", std::process::id().to_string()),
        ("ControlPID", "0".into()),
        ("NRestarts", "0".into()),
        ("ControlGroup", format!("/system.slice/{unit}")),
        ("Type", "oneshot".into()),
        ("User", "root".into()),
        ("Group", "root".into()),
        ("MemoryMax", "67108864".into()),
        ("MemorySwapMax", "0".into()),
        ("TasksMax", "128".into()),
        ("TimeoutStartUSec", "20s".into()),
        ("NoNewPrivileges", "yes".into()),
    ] {
        ensure!(m.get(k) == Some(&v), "native fixture differs:{k}");
    }
    ensure!(
        m.get("Job")
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|v| v > 0),
        "missing own original start job"
    );
    let status = fs::read_to_string("/proc/self/status")?;
    ensure!(
        status.lines().any(|l| l == "NoNewPrivs:\t1"),
        "kernel NoNewPrivileges differs"
    );
    let cap = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:\t"))
        .context("effective caps")?;
    let caps = u64::from_str_radix(cap, 16)?;
    ensure!(
        caps == if unit == POSITIVE {
            BASE_CAPS | ADMIN
        } else {
            BASE_CAPS
        },
        "unexpected effective caps"
    );
    ensure!(caps & ADMIN != 0, "CAP_SYS_ADMIN required before PFN reads");
    let config = fs::read(format!("/boot/config-{KERNEL}"))?;
    ensure!(hash(&config) == CONFIG_SHA, "kernel config changed");
    ensure!(
        hash(&fs::read("/sys/kernel/notes")?) == KERNEL_NOTES_SHA,
        "running kernel notes changed"
    );
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    ensure!(unsafe { libc::uname(&mut uts) } == 0, "uname failed");
    let release = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) }.to_str()?;
    ensure!(release == KERNEL, "unsupported running kernel");
    let path = PathBuf::from(format!("/sys/fs/cgroup/system.slice/{unit}"));
    let cg = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    let mut statfs: libc::statfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::fstatfs(cg.as_raw_fd(), &mut statfs) } == 0 && statfs.f_type == 0x63677270,
        "not actual cgroup2 filesystem"
    );
    let inode = cg.metadata()?.ino();
    for (file, expected) in [
        ("memory.max", "67108864"),
        ("memory.swap.max", "0"),
        ("memory.swap.current", "0"),
        ("pids.max", "128"),
    ] {
        ensure!(
            fs::read_to_string(path.join(file))?.trim() == expected,
            "kernel fixture differs:{file}"
        );
    }
    Ok(ContextBinding {
        unit,
        iid,
        start: ticks()?,
        cg,
        inode,
        native: m,
    })
}
struct Mapping {
    ptr: *mut u8,
    len: usize,
}
impl Mapping {
    fn new() -> Result<Self> {
        let len = bytes_for(PAGES as u64)? as usize;
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        ensure!(ptr != libc::MAP_FAILED, "mmap failed");
        let mapping = Self {
            ptr: ptr.cast(),
            len,
        };
        ensure!(
            unsafe { libc::madvise(ptr, len, libc::MADV_NOHUGEPAGE) } == 0,
            "NOHUGEPAGE failed"
        );
        Ok(mapping)
    }
    fn touch(&self) {
        for n in 0..PAGES {
            unsafe { self.ptr.add(n * PAGE as usize).write_volatile(1) };
        }
    }
    fn lazy_free(&self) -> Result<()> {
        ensure!(
            unsafe { libc::madvise(self.ptr.cast(), self.len, libc::MADV_FREE) } == 0,
            "MADV_FREE failed"
        );
        Ok(())
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr.cast(), self.len);
        }
    }
}
// These patterns are fixture observations, not memory-credit eligibility.
// The original strict `eligible` function is preserved and reported separately.
const OWNER2: u64 = 1 << 34;
const PTE_EXCLUSIVE: u64 = 1 << 56;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pattern {
    Exclusive,
    SharedTwice,
    LazyExclusive,
    Other,
}
fn pattern(entry: u64, flags: u64, charge: u64, expected: u64, maps: u64) -> Pattern {
    if !matches!(decode_pfn(entry), Ok(Some(_)))
        || expected == 0
        || charge != expected
        || flags & ANON == 0
        || flags & FORBIDDEN != 0
        || flags & !(((1u64 << 27) - 1) | OWNER2) != 0
    {
        return Pattern::Other;
    }
    let both_exclusive = flags & OWNER2 != 0 && entry & PTE_EXCLUSIVE != 0;
    if maps == 1 && both_exclusive {
        if flags & SWAPBACKED != 0 {
            Pattern::Exclusive
        } else {
            Pattern::LazyExclusive
        }
    } else if maps == 2
        && flags & OWNER2 == 0
        && entry & PTE_EXCLUSIVE == 0
        && flags & SWAPBACKED != 0
    {
        Pattern::SharedTwice
    } else {
        Pattern::Other
    }
}
struct Observation {
    exclusive: BTreeSet<u64>,
    shared: BTreeSet<u64>,
    lazy: BTreeSet<u64>,
    original: BTreeSet<u64>,
    swapbacked_pages: usize,
}
struct Reader {
    pagemap: File,
    flags: File,
    charges: File,
    counts: File,
}
impl Reader {
    fn new() -> Result<Self> {
        Ok(Self {
            pagemap: open_read(&format!("/proc/{}/pagemap", std::process::id()))?,
            flags: open_read("/proc/kpageflags")?,
            charges: open_read("/proc/kpagecgroup")?,
            counts: open_read("/proc/kpagecount")?,
        })
    }
    fn sample(&self, mapping: &Mapping, owner: u64, stage: &str) -> Result<Observation> {
        let mut out = Observation {
            exclusive: BTreeSet::new(),
            shared: BTreeSet::new(),
            lazy: BTreeSet::new(),
            original: BTreeSet::new(),
            swapbacked_pages: 0,
        };
        let mut attrs = BTreeMap::<String, u64>::new();
        let mut flag_counts = BTreeMap::<String, u64>::new();
        let mut charge_counts = BTreeMap::<String, u64>::new();
        let mut map_counts = BTreeMap::<String, u64>::new();
        for n in 0..PAGES {
            let address = (mapping.ptr as u64)
                .checked_add(n as u64 * PAGE)
                .context("virtual address overflow")?;
            let before = word(&self.pagemap, address / PAGE)?;
            *attrs.entry(format!("{:03x}", before >> 55)).or_default() += 1;
            if let Some(pfn) = decode_pfn(before)? {
                let flags = word(&self.flags, pfn)?;
                let charge = word(&self.charges, pfn)?;
                let maps = word(&self.counts, pfn)?;
                ensure!(
                    word(&self.pagemap, address / PAGE)? == before
                        && word(&self.flags, pfn)? == flags
                        && word(&self.charges, pfn)? == charge
                        && word(&self.counts, pfn)? == maps,
                    "self page identity/flags/charge/mapcount changed during diagnostic sample"
                );
                *flag_counts.entry(format!("{flags:016x}")).or_default() += 1;
                *charge_counts.entry(charge.to_string()).or_default() += 1;
                *map_counts.entry(maps.to_string()).or_default() += 1;
                if flags & SWAPBACKED != 0 {
                    out.swapbacked_pages += 1;
                }
                if eligible(flags, charge, owner) {
                    out.original.insert(pfn);
                }
                match pattern(before, flags, charge, owner, maps) {
                    Pattern::Exclusive => {
                        out.exclusive.insert(pfn);
                    }
                    Pattern::SharedTwice => {
                        out.shared.insert(pfn);
                    }
                    Pattern::LazyExclusive => {
                        out.lazy.insert(pfn);
                    }
                    Pattern::Other => {}
                }
            }
        }
        println!(
            "{}",
            json!({"schema":"horizon-self-anon-pattern-diagnostic-v1","stage":stage,
            "expected_memcg_inode":owner,"pagemap_attributes_without_PFNs":attrs,"exported_kernel_flags":flag_counts,
            "page_charge_inode_counts":charge_counts,"physical_mapcount_histogram":map_counts,
            "diagnostic_exclusive_pattern_pages":out.exclusive.len(),"diagnostic_shared_twice_pattern_pages":out.shared.len(),
            "diagnostic_lazy_exclusive_pattern_pages":out.lazy.len(),"observed_swapbacked_pages":out.swapbacked_pages,
            "original_strict_eligible_unique_pages":out.original.len(),"diagnostic_only":true,
            "original_strict_eligibility_unchanged":true,"capacity_credit_bytes":0,"admission_authorized":false,"live_freeze_authorized":false})
        );
        Ok(out)
    }
}
struct OwnedChild {
    pid: libc::pid_t,
    pidfd: File,
    release: Option<File>,
    start_ticks: u64,
}
impl OwnedChild {
    fn begin(ctx: &ContextBinding) -> Result<Self> {
        let mut ready = [0; 2];
        let mut release = [0; 2];
        ensure!(
            unsafe { libc::pipe2(ready.as_mut_ptr(), libc::O_CLOEXEC) } == 0,
            "ready pipe failed"
        );
        let ready_read = unsafe { File::from_raw_fd(ready[0]) };
        let ready_write = unsafe { File::from_raw_fd(ready[1]) };
        ensure!(
            unsafe { libc::pipe2(release.as_mut_ptr(), libc::O_CLOEXEC) } == 0,
            "release pipe failed"
        );
        let release_read = unsafe { File::from_raw_fd(release[0]) };
        let release_write = unsafe { File::from_raw_fd(release[1]) };
        let mut disposition: libc::sigaction = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut disposition) } == 0
                && disposition.sa_sigaction == libc::SIG_DFL
                && disposition.sa_flags & libc::SA_NOCLDWAIT == 0,
            "self child must remain waitable until explicit reap"
        );
        let pid = unsafe { libc::fork() };
        ensure!(pid >= 0, "self-only fork failed");
        if pid == 0 {
            // This branch performs only bounded raw syscalls after fork, never allocates,
            // never opens page tables and cannot accept a target PID or command.
            #[repr(C)]
            struct Header {
                version: u32,
                pid: i32,
            }
            #[repr(C)]
            #[derive(Clone, Copy)]
            struct Data {
                effective: u32,
                permitted: u32,
                inheritable: u32,
            }
            let mut header = Header {
                version: 0x20080522,
                pid: 0,
            };
            let mut data = [Data {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            }; 2];
            unsafe {
                libc::close(ready[0]);
                libc::close(release[1]);
                if libc::syscall(libc::SYS_capset, &header as *const Header, data.as_ptr()) != 0 {
                    libc::_exit(90);
                }
                if libc::syscall(
                    libc::SYS_capget,
                    &mut header as *mut Header,
                    data.as_mut_ptr(),
                ) != 0
                    || data
                        .iter()
                        .any(|d| d.effective != 0 || d.permitted != 0 || d.inheritable != 0)
                {
                    libc::_exit(91);
                }
                let byte = b'R';
                if libc::write(ready[1], &byte as *const u8 as *const libc::c_void, 1) != 1 {
                    libc::_exit(92);
                }
                libc::close(ready[1]);
                let mut byte = 0u8;
                loop {
                    let rc = libc::read(release[0], &mut byte as *mut u8 as *mut libc::c_void, 1);
                    if rc >= 0 {
                        libc::_exit(if rc == 1 && byte == b'Q' { 0 } else { 93 });
                    }
                    if *libc::__errno_location() != libc::EINTR {
                        libc::_exit(94);
                    }
                }
            }
        }
        let pidfd_raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if pidfd_raw < 0 {
            // SIGCHLD is pinned to default and this single-threaded fixture has no
            // other reaper. Closing the pipe lets only the unreaped child exit.
            drop(release_write);
            drop(release_read);
            drop(ready_write);
            unsafe {
                libc::waitpid(pid, std::ptr::null_mut(), 0);
            }
            anyhow::bail!("self child pidfd could not be bound");
        }
        let pidfd = unsafe { File::from_raw_fd(pidfd_raw as i32) };
        drop(ready_write);
        drop(release_read);
        let mut child = Self {
            pid,
            pidfd,
            release: Some(release_write),
            start_ticks: 0,
        };
        let mut byte = [0];
        let mut ready_read = ready_read;
        ready_read.read_exact(&mut byte)?;
        ensure!(byte == [b'R'], "child readiness differs");
        let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
        child.start_ticks = stat
            .rsplit_once(") ")
            .context("child stat")?
            .1
            .split_whitespace()
            .nth(19)
            .context("child ticks")?
            .parse()?;
        child.check(ctx)?;
        Ok(child)
    }
    fn check(&self, ctx: &ContextBinding) -> Result<()> {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.pid as u32,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            } == 0
                && unsafe { info.si_pid() } == 0,
            "original child no longer waiting"
        );
        let stat = fs::read_to_string(format!("/proc/{}/stat", self.pid))?;
        let start: u64 = stat
            .rsplit_once(") ")
            .context("child stat")?
            .1
            .split_whitespace()
            .nth(19)
            .context("child ticks")?
            .parse()?;
        ensure!(
            start == self.start_ticks
                && fs::read_to_string(format!("/proc/{}/cgroup", self.pid))?
                    == format!("0::/system.slice/{}\n", ctx.unit),
            "self-created child changed identity/cgroup"
        );
        Ok(())
    }
    fn finish(mut self) -> Result<()> {
        use std::io::Write;
        self.release
            .as_mut()
            .context("child release pipe")?
            .write_all(b"Q")?;
        drop(self.release.take());
        let mut status = 0;
        let got = unsafe { libc::waitpid(self.pid, &mut status, 0) };
        if got == self.pid {
            self.pid = 0;
        }
        ensure!(
            got > 0 && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "child did not close successfully"
        );
        Ok(())
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        drop(self.release.take());
        if self.pid > 0 {
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
                libc::waitpid(self.pid, std::ptr::null_mut(), 0);
            }
        }
    }
}
fn run() -> Result<()> {
    let ctx = context()?;
    let reader = Reader::new()?;
    let map = Mapping::new()?;
    ensure!(
        reader
            .sample(&map, ctx.inode, "untouched")?
            .exclusive
            .is_empty(),
        "untouched exclusive pattern"
    );
    unsafe {
        std::hint::black_box(map.ptr.read_volatile());
    }
    ensure!(
        reader
            .sample(&map, ctx.inode, "read-zero")?
            .exclusive
            .is_empty(),
        "zero-page exclusive pattern"
    );
    map.touch();
    let before = reader.sample(&map, ctx.inode, "touched-private-before-fork")?;
    ensure!(
        before.exclusive.len() == PAGES && before.original.is_empty(),
        "initial strict-failed/exclusive diagnostic pattern not established"
    );
    let wrong = reader.sample(&map, ctx.inode.wrapping_add(1), "wrong-charge-control")?;
    ensure!(
        wrong.exclusive.is_empty() && wrong.shared.is_empty(),
        "foreign charge matched diagnostic pattern"
    );
    let child = OwnedChild::begin(&ctx)?;
    child.check(&ctx)?;
    let shared = reader.sample(&map, ctx.inode, "fork-shared-child-alive")?;
    ensure!(
        shared.shared.len() == PAGES && shared.exclusive.is_empty(),
        "actual sharing/mapcount/owner2 pattern differs"
    );
    child.check(&ctx)?;
    map.touch();
    let cow = reader.sample(&map, ctx.inode, "parent-COW-child-alive")?;
    ensure!(
        cow.exclusive.len() == PAGES && cow.shared.is_empty() && cow.original.is_empty(),
        "parent COW diagnostic pattern differs"
    );
    child.check(&ctx)?;
    let child_pid = child.pid;
    let child_start = child.start_ticks;
    child.finish()?;
    map.lazy_free()?;
    let lazy = reader.sample(&map, ctx.inode, "MADV_FREE-after-child-closed")?;
    ensure!(
        lazy.exclusive.is_empty() && lazy.swapbacked_pages == 0,
        "MADV_FREE retained swap-backed exclusive pattern"
    );
    ensure!(
        ctx.cg.metadata()?.ino() == ctx.inode && ticks()? == ctx.start,
        "self owner changed"
    );
    ensure!(
        native(ctx.unit)? == ctx.native
            && fs::read_to_string("/proc/self/cgroup")?
                == format!("0::/system.slice/{}\n", ctx.unit),
        "self invocation changed"
    );
    let named = fs::symlink_metadata(format!("/sys/fs/cgroup/system.slice/{}", ctx.unit))?;
    ensure!(
        named.ino() == ctx.inode && named.dev() == ctx.cg.metadata()?.dev(),
        "self cgroup path replaced"
    );
    let mut h = Sha256::new();
    for pfn in &cow.exclusive {
        h.update(pfn.to_le_bytes());
    }
    println!(
        "{}",
        json!({"schema":"horizon-self-anon-exclusivity-fixture-v1","unit":ctx.unit,"invocation_id":ctx.iid,
        "pid":std::process::id(),"start_ticks":ctx.start,"cgroup_inode":ctx.inode,"kernel":KERNEL,
        "kernel_notes_sha256":KERNEL_NOTES_SHA,"config_sha256":CONFIG_SHA,"self_only_controlled_pattern_checks_passed":true,
        "private_pattern_pages":before.exclusive.len(),"fork_shared_pattern_pages":shared.shared.len(),"parent_COW_pattern_pages":cow.exclusive.len(),
        "actual_self_created_child_pid":child_pid,"actual_child_start_ticks":child_start,"child_effective_permitted_inheritable_caps_zero":true,
        "child_closed_successfully":true,"child_signal_authority_bound_by_pidfd":true,"MADV_FREE_swapbacked_pages_after":lazy.swapbacked_pages,"parent_COW_PFN_set_sha256":format!("{:x}",h.finalize()),
        "original_strict_profile_qualified":false,"original_strict_eligibility_unchanged":true,"kernel_hacking_flag_not_promoted_to_stable_ABI":true,
        "global_availability_coherence_proven":false,"live_owner_or_complete_cross_process_closure_proven":false,
        "capacity_credit_bytes":0,"admission_authorized":false,"live_freeze_authorized":false})
    );
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 4
            && args[1] == "--self-sha256"
            && canonical_sha(&args[2])
            && args[3] == "--fixture-only",
        "usage: self fixture --self-sha256 SHA --fixture-only"
    );
    let mut exe = File::open("/proc/self/exe")?;
    let mut h = Sha256::new();
    let mut b = [0; 65536];
    loop {
        let n = exe.read(&mut b)?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    ensure!(
        format!("{:x}", h.finalize()) == args[2],
        "self hash differs"
    );
    run()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pagemap_present_private_and_disclosed_identity_are_required() {
        assert_eq!(decode_pfn(0).unwrap(), None);
        assert_eq!(decode_pfn(PRESENT | 123).unwrap(), Some(123));
        assert_eq!(decode_pfn(PRESENT | FILE_OR_SHARED | 123).unwrap(), None);
        for x in [
            PRESENT,
            SWAPPED | 123,
            PRESENT | SWAPPED | 123,
            PRESENT | (1 << 59) | 123,
            PRESENT | (1 << 60) | 123,
        ] {
            assert!(decode_pfn(x).is_err());
        }
    }
    #[test]
    fn unsupported_page_classes_and_unknown_flags_are_excluded() {
        let good = ANON | SWAPBACKED | (1 << 11) | (1 << 4);
        assert!(eligible(good, 7, 7));
        for bit in 0..64 {
            if FORBIDDEN & (1 << bit) != 0 || bit >= 27 {
                assert!(!eligible(good | (1 << bit), 7, 7));
            }
        }
    }
    #[test]
    fn actual_charge_ownership_is_required_even_for_anonymous_pages() {
        let flags = ANON | SWAPBACKED;
        assert!(!eligible(flags, 0, 0));
        assert!(!eligible(flags, 4, 5));
        assert!(eligible(flags, 4, 4));
    }
    #[test]
    fn lazyfree_without_swapbacking_never_counts_as_consumed_memory() {
        assert!(!eligible(ANON, 9, 9));
        assert!(!eligible(SWAPBACKED, 9, 9));
        assert!(!eligible(0, 9, 9));
    }
    #[test]
    fn duplicate_physical_identities_are_counted_once() {
        let pages: BTreeSet<_> = [2u64, 3, 2, 3, 4].into_iter().collect();
        assert_eq!(bytes_for(pages.len() as u64).unwrap(), 3 * PAGE);
    }
    #[test]
    fn byte_accounting_and_independent_self_digest_fail_closed() {
        assert!(bytes_for(u64::MAX / PAGE + 1).is_err());
        assert_eq!(bytes_for(0).unwrap(), 0);
        assert!(canonical_sha(&"a".repeat(64)));
        assert!(!canonical_sha(&"A".repeat(64)));
        assert!(!canonical_sha("zero"));
    }

    #[test]
    fn exclusive_diagnostic_pattern_requires_independent_identity_flags_charge_and_mapcount() {
        let pte = PRESENT | PTE_EXCLUSIVE | 123;
        let flags = ANON | SWAPBACKED | OWNER2;
        assert_eq!(pattern(pte, flags, 7, 7, 1), Pattern::Exclusive);
        assert!(!eligible(flags, 7, 7));
        for (p, f, c, n) in [
            (pte, flags, 8, 1),
            (pte, flags, 7, 2),
            (PRESENT | 123, flags, 7, 1),
            (pte, flags & !OWNER2, 7, 1),
            (pte | FILE_OR_SHARED, flags, 7, 1),
            (pte, flags | (1 << 35), 7, 1),
            (pte, flags | (1 << 22), 7, 1),
        ] {
            assert_eq!(pattern(p, f, c, 7, n), Pattern::Other);
        }
    }
    #[test]
    fn sharing_diagnostic_requires_two_maps_and_both_exclusivity_indicators_clear() {
        let pte = PRESENT | 123;
        let flags = ANON | SWAPBACKED;
        assert_eq!(pattern(pte, flags, 7, 7, 2), Pattern::SharedTwice);
        // The untouched original classifier is deliberately not a sharing proof.
        assert!(eligible(flags, 7, 7));
        for (p, f, n) in [
            (pte, flags, 1),
            (pte, flags, 3),
            (pte | PTE_EXCLUSIVE, flags, 2),
            (pte, flags | OWNER2, 2),
        ] {
            assert_eq!(pattern(p, f, 7, 7, n), Pattern::Other);
        }
    }
    #[test]
    fn lazy_free_diagnostic_never_matches_swapbacked_private_pattern() {
        let pte = PRESENT | PTE_EXCLUSIVE | 123;
        assert_eq!(pattern(pte, ANON | OWNER2, 7, 7, 1), Pattern::LazyExclusive);
        assert_eq!(
            pattern(pte, ANON | SWAPBACKED | OWNER2, 7, 7, 1),
            Pattern::Exclusive
        );
        assert_eq!(pattern(pte, ANON | OWNER2, 7, 8, 1), Pattern::Other);
        assert_eq!(pattern(0, ANON | OWNER2, 7, 7, 1), Pattern::Other);
    }
}
