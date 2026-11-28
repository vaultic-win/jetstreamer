//! Fixed self-only local lazyfree drain mechanism diagnostic. Never grants memory credit.
use anyhow::{Context, Result, ensure};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Read,
    os::fd::AsRawFd,
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    path::PathBuf,
    process::Command,
};
const PAGE: u64 = 4096;
const PAGES: usize = 512;
const POSITIVE: &str = "horizon-anon-lazyfree-drain-fixture950-v1.service";
const NEGATIVE: &str = "horizon-anon-lazyfree-drain-fixture950-no-admin-v1.service";
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
        .args(["show", "--all", unit, "--property=Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Job,ControlGroup,Type,User,Group,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,TimeoutStartUSec,NoNewPrivileges"])
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
        ("CPUQuotaPerSecUSec", "1s".into()),
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
    let cpu = fs::read_to_string(path.join("cpu.max"))?;
    let words: Vec<_> = cpu.split_whitespace().collect();
    ensure!(
        words.len() == 2
            && words[0].parse::<u64>()? > 0
            && words[0].parse::<u64>()? == words[1].parse::<u64>()?,
        "kernel CPU quota differs"
    );
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

const FIXED_CPU: usize = 56;
const ORIGINAL_FAILURE_SHA: &str =
    "feb592fcb7ab70c67e0885c0d0d70b76c837421216c7c97e947d03678a6e09bd";
const KERNEL_REVIEW_SHA: &str = "6b5107281770853d69dc029f3d299826fba3eb7b63b38eb9b37d10597b277cfd";
const ORIGINAL_FAILURE_PATH: &str = "/var/lib/jetstreamer/horizon-anon-exclusivity948-native-preparation-v1/horizon-anon-exclusivity-fixture948-v1.service.completion.json";

fn validate_cpu_mask(mask: &BTreeSet<usize>, pinned: bool) -> Result<()> {
    ensure!(
        FIXED_CPU < libc::CPU_SETSIZE as usize,
        "fixed CPU outside affinity representation"
    );
    ensure!(mask.contains(&FIXED_CPU), "fixed CPU56 not permitted");
    ensure!(
        !pinned || mask.len() == 1,
        "calling thread is not pinned to CPU56"
    );
    Ok(())
}
fn affinity() -> Result<BTreeSet<usize>> {
    let mut mask: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&mask), &mut mask) } == 0,
        "calling-thread affinity read failed"
    );
    Ok((0..libc::CPU_SETSIZE as usize)
        .filter(|cpu| unsafe { libc::CPU_ISSET(*cpu, &mask) })
        .collect())
}
fn check_pinned() -> Result<()> {
    validate_cpu_mask(&affinity()?, true)?;
    ensure!(
        unsafe { libc::sched_getcpu() } == FIXED_CPU as i32,
        "calling thread CPU differs"
    );
    Ok(())
}
fn pin_calling_thread() -> Result<()> {
    let before = affinity()?;
    validate_cpu_mask(&before, false)?;
    let mut mask: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::CPU_ZERO(&mut mask);
        libc::CPU_SET(FIXED_CPU, &mut mask);
    }
    // Linux pid0 addresses only this calling thread, not the whole cgroup.
    ensure!(
        unsafe { libc::sched_setaffinity(0, std::mem::size_of_val(&mask), &mask) } == 0,
        "calling-thread pin failed"
    );
    check_pinned()?;
    println!(
        "{}",
        json!({"schema":"horizon-self-lazyfree-drain-affinity-v1","allowed_before":before,"pinned_after":affinity()?,"cpu":FIXED_CPU,"calling_thread_only":true,"capacity_credit_bytes":0,"admission_authorized":false,"live_freeze_authorized":false})
    );
    Ok(())
}
#[derive(Clone, Debug)]
struct PageSample {
    entry: u64,
    pfn: Option<u64>,
    flags: u64,
    charge: u64,
    maps: u64,
}
#[derive(Clone, Debug, Default)]
struct Observation {
    pages: Vec<PageSample>,
}
impl Observation {
    fn emit(&self, owner: u64, stage: &str, error: Option<String>) {
        let mut attrs = BTreeMap::<String, u64>::new();
        let mut flags = BTreeMap::<String, u64>::new();
        let mut charges = BTreeMap::<String, u64>::new();
        let mut maps = BTreeMap::<String, u64>::new();
        let mut classes = [0usize; 4];
        let mut originals = 0;
        for p in &self.pages {
            *attrs.entry(format!("{:03x}", p.entry >> 55)).or_default() += 1;
            if p.pfn.is_some() {
                *flags.entry(format!("{:016x}", p.flags)).or_default() += 1;
                *charges.entry(p.charge.to_string()).or_default() += 1;
                *maps.entry(p.maps.to_string()).or_default() += 1;
                let n = match pattern(p.entry, p.flags, p.charge, owner, p.maps) {
                    Pattern::Exclusive => 0,
                    Pattern::LazyExclusive => 1,
                    Pattern::SharedTwice => 2,
                    Pattern::Other => 3,
                };
                classes[n] += 1;
                if eligible(p.flags, p.charge, owner) {
                    originals += 1;
                }
            }
        }
        println!(
            "{}",
            json!({"schema":"horizon-self-lazyfree-drain-sample-v1","stage":stage,"sampled_pages":self.pages.len(),"expected_pages":PAGES,"sample_complete":error.is_none()&&self.pages.len()==PAGES,"error":error,"cpu":FIXED_CPU,"pagemap_attributes_without_PFNs":attrs,"exported_kernel_flags":flags,"page_charge_inode_counts":charges,"physical_mapcount_histogram":maps,"diagnostic_exclusive_pattern_pages":classes[0],"diagnostic_lazy_exclusive_pattern_pages":classes[1],"diagnostic_shared_twice_pattern_pages":classes[2],"original_strict_eligible_pages":originals,"original_strict_eligibility_unchanged":true,"original948_failure_remains_failed":true,"original_failure_sha256":ORIGINAL_FAILURE_SHA,"kernel_review_sha256":KERNEL_REVIEW_SHA,"diagnostic_only":true,"capacity_credit_bytes":0,"admission_authorized":false,"live_freeze_authorized":false})
        );
    }
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
            pages: Vec::with_capacity(PAGES),
        };
        let result = (|| -> Result<()> {
            check_pinned()?;
            for n in 0..PAGES {
                let address = (mapping.ptr as u64)
                    .checked_add(bytes_for(n as u64)?)
                    .context("virtual address overflow")?;
                let entry = word(&self.pagemap, address / PAGE)?;
                let mut p = PageSample {
                    entry,
                    pfn: decode_pfn(entry)?,
                    flags: 0,
                    charge: 0,
                    maps: 0,
                };
                if let Some(pfn) = p.pfn {
                    p.flags = word(&self.flags, pfn)?;
                    p.charge = word(&self.charges, pfn)?;
                    p.maps = word(&self.counts, pfn)?;
                }
                out.pages.push(p);
                let p = out.pages.last().unwrap();
                ensure!(
                    word(&self.pagemap, address / PAGE)? == entry,
                    "self pagemap changed during sample"
                );
                if let Some(pfn) = p.pfn {
                    ensure!(
                        word(&self.flags, pfn)? == p.flags
                            && word(&self.charges, pfn)? == p.charge
                            && word(&self.counts, pfn)? == p.maps,
                        "self flags/charge/mapcount changed during sample"
                    );
                }
            }
            check_pinned()?;
            Ok(())
        })();
        // Emit the captured prefix even when a later read/identity gate fails.
        out.emit(
            owner,
            stage,
            result.as_ref().err().map(|e| format!("{e:#}")),
        );
        result?;
        Ok(out)
    }
}
fn present_private_pages(o: &Observation, owner: u64, allow_lazy: bool) -> Result<()> {
    ensure!(o.pages.len() == PAGES, "partial page sample");
    let mut identities = BTreeSet::new();
    for p in &o.pages {
        let pfn = p.pfn.context("victim/control page disappeared")?;
        ensure!(
            p.pfn == decode_pfn(p.entry)? && identities.insert(pfn),
            "aliased or inconsistent physical identity"
        );
        let class = pattern(p.entry, p.flags, p.charge, owner, p.maps);
        ensure!(
            class == Pattern::Exclusive || (allow_lazy && class == Pattern::LazyExclusive),
            "foreign/shared/unsupported private page pattern"
        );
    }
    Ok(())
}
fn stable_private(
    before: &Observation,
    after: &Observation,
    owner: u64,
    allow_lazy: bool,
) -> Result<()> {
    present_private_pages(before, owner, false)?;
    present_private_pages(after, owner, allow_lazy)?;
    ensure!(
        before
            .pages
            .iter()
            .zip(&after.pages)
            .all(|(a, b)| a.pfn == b.pfn),
        "victim/control PFN changed"
    );
    Ok(())
}
fn trigger_unfaulted(o: &Observation) -> Result<()> {
    ensure!(o.pages.len() == PAGES, "partial trigger sample");
    ensure!(
        o.pages
            .iter()
            .all(|p| p.entry & PRESENT == 0 && p.entry & SWAPPED == 0 && p.pfn.is_none()),
        "trigger mapping faulted"
    );
    Ok(())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Discriminating { cleared_pages: usize },
    NonDiscriminating,
}
struct Samples<'a> {
    victim_before: &'a Observation,
    first: &'a Observation,
    after: &'a Observation,
    trigger_before: &'a Observation,
    trigger_after: &'a Observation,
    control_before: &'a Observation,
    control_after: &'a Observation,
}
fn evaluate(s: &Samples<'_>, owner: u64) -> Result<Outcome> {
    stable_private(s.victim_before, s.first, owner, true)?;
    stable_private(s.victim_before, s.after, owner, true)?;
    trigger_unfaulted(s.trigger_before)?;
    trigger_unfaulted(s.trigger_after)?;
    stable_private(s.control_before, s.control_after, owner, false)?;
    let initial = s
        .first
        .pages
        .iter()
        .filter(|p| p.flags & SWAPBACKED != 0)
        .count();
    let remaining = s
        .after
        .pages
        .iter()
        .filter(|p| p.flags & SWAPBACKED != 0)
        .count();
    ensure!(
        remaining == 0,
        "victim retains swap-backed residue after explicit local-drain trigger"
    );
    if initial == 0 {
        Ok(Outcome::NonDiscriminating)
    } else {
        Ok(Outcome::Discriminating {
            cleared_pages: initial,
        })
    }
}
fn reauthenticate(ctx: &ContextBinding) -> Result<()> {
    check_pinned()?;
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
    Ok(())
}
fn run() -> Result<()> {
    // Capless control fails in context before Reader opens any PFN interface.
    let ctx = context()?;
    pin_calling_thread()?;
    let reader = Reader::new()?;
    let victim = Mapping::new()?;
    let trigger = Mapping::new()?;
    let control = Mapping::new()?;
    victim.touch();
    control.touch();
    let before = reader.sample(&victim, ctx.inode, "victim-private-baseline")?;
    let trigger_before = reader.sample(&trigger, ctx.inode, "trigger-untouched-before")?;
    let control_before = reader.sample(&control, ctx.inode, "control-private-before")?;
    present_private_pages(&before, ctx.inode, false)?;
    trigger_unfaulted(&trigger_before)?;
    present_private_pages(&control_before, ctx.inode, false)?;
    check_pinned()?;
    victim.lazy_free()?; // Exactly one FREE of the victim; never touch it again.
    let first = reader.sample(&victim, ctx.inode, "victim-first-after-FREE")?;
    stable_private(&before, &first, ctx.inode, true)?;
    check_pinned()?;
    // Entry lru_add_drain in the exact kernel FREE path is the mechanism under
    // test. An untouched trigger has no present folios to enqueue afterward.
    trigger.lazy_free()?; // Exactly one trigger; no retry, sleep, or page read.
    let trigger_after = reader.sample(&trigger, ctx.inode, "trigger-untouched-after-FREE")?;
    let after = reader.sample(&victim, ctx.inode, "victim-after-local-drain-trigger")?;
    let control_after = reader.sample(&control, ctx.inode, "control-private-after")?;
    let outcome = evaluate(
        &Samples {
            victim_before: &before,
            first: &first,
            after: &after,
            trigger_before: &trigger_before,
            trigger_after: &trigger_after,
            control_before: &control_before,
            control_after: &control_after,
        },
        ctx.inode,
    );
    // Publish the actual experiment outcome before an error or non-discriminating exit.
    let (status, cleared, error) = match &outcome {
        Ok(Outcome::Discriminating { cleared_pages }) => ("discriminating", *cleared_pages, None),
        Ok(Outcome::NonDiscriminating) => ("non-discriminating", 0, None),
        Err(e) => ("failed", 0, Some(format!("{e:#}"))),
    };
    println!(
        "{}",
        json!({"schema":"horizon-self-lazyfree-drain-outcome-v1","status":status,"cleared_residue_pages":cleared,"error":error,"cpu":FIXED_CPU,"victim_FREE_calls":1,"trigger_FREE_calls":1,"trigger_body_read":false,"retries":0,"mechanism_observed":matches!(outcome,Ok(Outcome::Discriminating {..})),"source_review_only_no_campaign_qualification":true,"original_failure":{"path":ORIGINAL_FAILURE_PATH,"sha256":ORIGINAL_FAILURE_SHA},"kernel_review_sha256":KERNEL_REVIEW_SHA,"kernel_notes_sha256":KERNEL_NOTES_SHA,"config_sha256":CONFIG_SHA,"original948_failure_remains_failed":true,"original_strict_eligibility_unchanged":true,"kernel_hacking_flag_not_promoted_to_stable_ABI":true,"global_availability_coherence_proven":false,"live_owner_or_complete_cross_process_closure_proven":false,"capacity_credit_bytes":0,"admission_authorized":false,"live_freeze_authorized":false})
    );
    let outcome = outcome?;
    reauthenticate(&ctx)?;
    ensure!(
        outcome != Outcome::NonDiscriminating,
        "initial zero residue is non-discriminating; mechanism not qualified"
    );
    println!(
        "{}",
        json!({"schema":"horizon-self-lazyfree-drain-native-result-v1","self_only_mechanism_diagnostic_passed":true,"unit":ctx.unit,"invocation_id":ctx.iid,"pid":std::process::id(),"start_ticks":ctx.start,"cgroup_inode":ctx.inode,"cpu":FIXED_CPU,"original948_failure_remains_failed":true,"original_strict_profile_qualified":false,"capacity_credit_bytes":0,"admission_authorized":false,"live_freeze_authorized":false})
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

    fn page(pfn: u64, lazy: bool) -> PageSample {
        PageSample {
            entry: PRESENT | PTE_EXCLUSIVE | pfn,
            pfn: Some(pfn),
            flags: ANON | OWNER2 | if lazy { 0 } else { SWAPBACKED },
            charge: 7,
            maps: 1,
        }
    }
    fn private() -> Observation {
        Observation {
            pages: (1..=PAGES as u64).map(|p| page(p, false)).collect(),
        }
    }
    fn first(residual: usize) -> Observation {
        Observation {
            pages: (1..=PAGES as u64)
                .enumerate()
                .map(|(n, p)| page(p, n >= residual))
                .collect(),
        }
    }
    fn trigger() -> Observation {
        Observation {
            pages: (0..PAGES)
                .map(|_| PageSample {
                    entry: 0,
                    pfn: None,
                    flags: 0,
                    charge: 0,
                    maps: 0,
                })
                .collect(),
        }
    }
    fn result(first: &Observation, after: &Observation) -> Result<Outcome> {
        let before = private();
        let trigger = trigger();
        let control = private();
        evaluate(
            &Samples {
                victim_before: &before,
                first,
                after,
                trigger_before: &trigger,
                trigger_after: &trigger,
                control_before: &control,
                control_after: &control,
            },
            7,
        )
    }
    #[test]
    fn sixteen_residue_pages_clearing_on_same_identity_is_discriminating() {
        assert_eq!(
            result(&first(16), &first(0)).unwrap(),
            Outcome::Discriminating { cleared_pages: 16 }
        );
    }
    #[test]
    fn arbitrary_nonzero_residue_is_not_hardcoded_to_sixteen() {
        for n in [1, 2, 30, 31, 32, 511, 512] {
            assert_eq!(
                result(&first(n), &first(0)).unwrap(),
                Outcome::Discriminating { cleared_pages: n }
            );
        }
    }
    #[test]
    fn zero_initial_residue_is_explicitly_non_discriminating() {
        assert_eq!(
            result(&first(0), &first(0)).unwrap(),
            Outcome::NonDiscriminating
        );
    }
    #[test]
    fn residue_persistence_never_qualifies_the_local_drain() {
        for n in [1, 16, 512] {
            assert!(result(&first(16), &first(n)).is_err());
        }
    }
    #[test]
    fn changed_or_lost_victim_pfn_fails_closed() {
        let mut changed = first(0);
        changed.pages[0] = page(1000, true);
        assert!(result(&first(16), &changed).is_err());
        changed.pages[0] = PageSample {
            entry: 0,
            pfn: None,
            flags: 0,
            charge: 0,
            maps: 0,
        };
        assert!(result(&first(16), &changed).is_err());
    }
    #[test]
    fn foreign_charge_and_shared_victim_patterns_cannot_qualify() {
        let mut bad = first(0);
        bad.pages[0].charge = 8;
        assert!(result(&first(16), &bad).is_err());
        bad.pages[0].charge = 7;
        bad.pages[0].maps = 2;
        bad.pages[0].entry &= !PTE_EXCLUSIVE;
        bad.pages[0].flags = ANON | SWAPBACKED;
        assert!(result(&first(16), &bad).is_err());
    }
    #[test]
    fn a_faulted_or_partly_sampled_trigger_cannot_claim_a_local_only_drain() {
        let before = private();
        let first = first(16);
        let after = first_zero();
        let empty = trigger();
        let mut faulted = trigger();
        faulted.pages[0] = page(1000, false);
        let control = private();
        assert!(
            evaluate(
                &Samples {
                    victim_before: &before,
                    first: &first,
                    after: &after,
                    trigger_before: &empty,
                    trigger_after: &faulted,
                    control_before: &control,
                    control_after: &control
                },
                7
            )
            .is_err()
        );
        faulted.pages.pop();
        assert!(trigger_unfaulted(&faulted).is_err());
    }
    fn first_zero() -> Observation {
        first(0)
    }
    #[test]
    fn a_private_control_losing_backing_rejects_the_mechanism() {
        let before = private();
        let first = first(16);
        let after = first_zero();
        let empty = trigger();
        let mut bad = private();
        bad.pages[0] = page(1, true);
        assert!(
            evaluate(
                &Samples {
                    victim_before: &before,
                    first: &first,
                    after: &after,
                    trigger_before: &empty,
                    trigger_after: &empty,
                    control_before: &before,
                    control_after: &bad
                },
                7
            )
            .is_err()
        );
    }
    #[test]
    fn wrong_cpu_wide_affinity_and_byte_overflow_fail_closed() {
        validate_cpu_mask(&[56].into_iter().collect(), true).unwrap();
        validate_cpu_mask(&[56, 57].into_iter().collect(), false).unwrap();
        for cpus in [vec![], vec![55], vec![56, 57]] {
            assert!(validate_cpu_mask(&cpus.into_iter().collect(), true).is_err());
        }
        assert!(bytes_for(u64::MAX / PAGE + 1).is_err());
    }
    #[test]
    fn duplicate_physical_pages_and_incomplete_victim_samples_reject() {
        let mut bad = first(0);
        bad.pages[1] = bad.pages[0].clone();
        assert!(result(&first(16), &bad).is_err());
        bad = first(0);
        bad.pages.pop();
        assert!(result(&first(16), &bad).is_err());
    }
}
