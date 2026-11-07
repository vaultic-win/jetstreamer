//! Self-only page identity/charge mechanics. Never grants campaign memory credit.
use anyhow::{ensure, Context, Result};
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
const POSITIVE: &str = "horizon-memory-page-fixture946-v1.service";
const NEGATIVE: &str = "horizon-memory-page-fixture946-no-admin-v1.service";
const KERNEL: &str = "7.0.0-38-generic";
const CONFIG_SHA: &str = "6cb18717c6914d4947489eedf8cb69ac23db3faa8ef9b9f563ff02c346dcd32d";
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
struct Reader {
    pagemap: File,
    flags: File,
    charges: File,
}
impl Reader {
    fn new() -> Result<Self> {
        Ok(Self {
            pagemap: open_read(&format!("/proc/{}/pagemap", std::process::id()))?,
            flags: open_read("/proc/kpageflags")?,
            charges: open_read("/proc/kpagecgroup")?,
        })
    }
    fn sample(&self, mapping: &Mapping, owner: u64) -> Result<BTreeSet<u64>> {
        let mut set = BTreeSet::new();
        for n in 0..PAGES {
            let address = (mapping.ptr as u64)
                .checked_add(n as u64 * PAGE)
                .context("virtual address overflow")?;
            let before = word(&self.pagemap, address / PAGE)?;
            if let Some(pfn) = decode_pfn(before)? {
                let flags = word(&self.flags, pfn)?;
                let charge = word(&self.charges, pfn)?;
                ensure!(
                    word(&self.pagemap, address / PAGE)? == before
                        && word(&self.flags, pfn)? == flags
                        && word(&self.charges, pfn)? == charge,
                    "self page changed during sample"
                );
                if eligible(flags, charge, owner) {
                    set.insert(pfn);
                }
            }
        }
        Ok(set)
    }
}
fn run() -> Result<()> {
    let ctx = context()?;
    let reader = Reader::new()?;
    let map = Mapping::new()?;
    ensure!(
        reader.sample(&map, ctx.inode)?.is_empty(),
        "untouched pages unexpectedly eligible"
    );
    unsafe {
        std::hint::black_box(map.ptr.read_volatile());
    }
    ensure!(
        reader.sample(&map, ctx.inode)?.is_empty(),
        "read-zero page unexpectedly eligible"
    );
    map.touch();
    let owned = reader.sample(&map, ctx.inode)?;
    ensure!(
        owned.len() == PAGES,
        "own anonymous PFN/flags/charge profile not established"
    );
    ensure!(
        reader.sample(&map, ctx.inode.wrapping_add(1))?.is_empty(),
        "foreign charge accepted"
    );
    map.lazy_free()?;
    let lazy = reader.sample(&map, ctx.inode)?;
    ensure!(
        lazy.is_empty(),
        "MADV_FREE pages remain eligible: contract unqualified"
    );
    ensure!(
        ctx.cg.metadata()?.ino() == ctx.inode && ticks()? == ctx.start,
        "self owner changed"
    );
    let after = native(ctx.unit)?;
    ensure!(
        after == ctx.native
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
    for pfn in &owned {
        h.update(pfn.to_le_bytes());
    }
    println!(
        "{}",
        json!({"schema":"horizon-self-memory-page-fixture-v1","unit":ctx.unit,"invocation_id":ctx.iid,"pid":std::process::id(),"start_ticks":ctx.start,"cgroup_inode":ctx.inode,"kernel":KERNEL,"config_sha256":CONFIG_SHA,"private_anon_unique_pages":owned.len(),"private_anon_bytes_observed":bytes_for(owned.len() as u64)?,"PFN_set_sha256":format!("{:x}",h.finalize()),"untouched_and_read_zero_excluded":true,"wrong_charge_excluded":true,"MADV_FREE_pages_eligible_after":lazy.len(),"fixture_only":true,"global_availability_coherence_proven":false,"cross_process_sharing_and_live_owner_proven":false,"capacity_credit_bytes":0,"admission_authorized":false,"live_freeze_authorized":false})
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
}
