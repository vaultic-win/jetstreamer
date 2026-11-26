//! Measure blocks already occupied by a guarded replay guest.
//! File descriptors pin the objects, while two FIEMAP samples establish which
//! logical bytes still map to the same exclusive physical blocks.
use super::*;
use std::os::{fd::AsRawFd, unix::fs::FileTypeExt};

struct Guest {
    epoch: u64,
    state: &'static str,
    guest: &'static str,
    unit: &'static str,
    iid: &'static str,
    pid: u64,
    loop_number: u32,
    inode: u64,
    mount_id: &'static str,
    cap: u64,
    handoff: &'static str,
    held: &'static str,
    mount: &'static str,
}

const E228: Guest = Guest {
    epoch: 228,
    state: "/var/lib/jetstreamer/horizon228-native-root-tail-v166-a1/pilot",
    guest: "/home/ubuntu/.jetstreamer-private/qualification-228-demotion-root-tail-v1",
    unit: "horizon-qualify-228-demotion-root-tail-16d4b158-v1.service",
    iid: "5566869f329b46309aa8a2ea8f46047a",
    pid: 2819393,
    loop_number: 6,
    inode: 18330573,
    mount_id: "1167",
    cap: 112 << 30,
    handoff: "da3fdea0fa6f6682daa741e4c72d5f3a81d6bd420743d5df70c46d40b6319752",
    held: "45e7ff78f1fae3b0075dc84a0e66add7fe6751a655260f7d1fcf93b7a8e50895",
    mount: "eb09b34163d040856017b3ccdd45295448922483836ac20d4498d1697aeb335b",
};
const E266: Guest = Guest {
    epoch: 266,
    state: "/var/lib/jetstreamer/horizon266-instructions-2789f821-v194-control/pilot",
    guest: "/home/ubuntu/.jetstreamer-private/qualification-266-instructions-2789f821-v194",
    unit: "horizon-qualify-266-instructions-2789f821-v194.service",
    iid: "41cf6e5a5cd54d57adc5eba3f0c0ecef",
    pid: 3215067,
    loop_number: 12,
    inode: 18340079,
    mount_id: "416",
    cap: 320 << 30,
    handoff: "fcab517e7281c8c1dde68c9e7f56cbabc294eff2154c181bdb72b1742170a4df",
    held: "dddfa399c33267ad6dcb67ff66d556017f03a16ddf330cd72f1bc9cb979d7666",
    mount: "fd9e3477764ca22ceb30d2b33a9580aaa89ffbd55a1c6317ade149a65790d072",
};
impl Guest {
    fn image(&self) -> PathBuf {
        Path::new(self.state).join("private.ext4")
    }
    fn device(&self) -> String {
        format!("/dev/loop{}", self.loop_number)
    }
}
const BATCH: usize = 512;
const LAST: u32 = 1;
const UNWRITTEN: u32 = 0x800;
const BLOCK: u64 = 4096;

// Linux UAPI linux/fiemap.h and linux/loop.h; same layout and flag policy as
// jetstreamer-utils/src/allocation_tree_fixture_bin.rs.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct KernelExtent {
    logical: u64,
    physical: u64,
    length: u64,
    reserved64: [u64; 2],
    flags: u32,
    reserved: [u32; 3],
}
#[repr(C)]
struct Fiemap {
    start: u64,
    length: u64,
    flags: u32,
    mapped: u32,
    count: u32,
    reserved: u32,
    extents: [KernelExtent; BATCH],
}
#[repr(C)]
#[derive(Default)]
struct LoopInfo64 {
    device: u64,
    inode: u64,
    rdevice: u64,
    offset: u64,
    size_limit: u64,
    number: u32,
    encrypt_type: u32,
    encrypt_key_size: u32,
    flags: u32,
    // File name, crypt name, key and seed are irrelevant to the binding.
    opaque: [[u8; 16]; 10],
    init: [u64; 2],
}
const _: () = assert!(std::mem::size_of::<KernelExtent>() == 56);
const _: () = assert!(std::mem::offset_of!(Fiemap, extents) == 32);
const _: () = assert!(std::mem::size_of::<LoopInfo64>() == 232);

fn syscall(status: libc::c_int) -> std::io::Result<()> {
    if status == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn filesys(file: &File) -> Result<(u64, u64)> {
    let mut value = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // fstatvfs initializes all fields of value on success.
    syscall(unsafe { libc::fstatvfs(file.as_raw_fd(), value.as_mut_ptr()) })?;
    let value = unsafe { value.assume_init() };
    Ok((
        value.f_frsize,
        value
            .f_bavail
            .checked_mul(value.f_frsize)
            .context("free bytes overflow")?,
    ))
}

fn original(g: &Guest) -> Result<()> {
    let bound = |name: &str, sha: &str| Bound::new(Path::new(g.state).join(name), sha);
    let handoff = bound("handoff.json", g.handoff).sealed()?;
    let fit = bound("held-fit.json", g.held);
    let f = fit.sealed()?;
    ensure!(
        handoff["iid"] == g.iid
            && handoff["pid"] == g.pid
            && handoff["unit"] == g.unit
            && handoff["held_fit"] == json!(fit),
        "original handoff changed"
    );
    let m = bound("mount.json", g.mount).sealed()?;
    ensure!(
        m == json!({"backing":g.image(),"bytes":g.cap,"loop":g.device(),"root":g.guest,
            "root_device":libc::makedev(7,g.loop_number),"root_inode":2}),
        "mount receipt changed"
    );
    ensure!(
        f["winner"]["fits"] == true
            && f["winner"]["root"] == g.cap
            && num(&f, "protected_floor")?.checked_add(g.cap)
                == f["winner"]["required_free"].as_u64(),
        "gross guest reservation changed"
    );
    Ok(())
}

// Select the deepest enclosing mount. A stacked mount at that depth is ambiguous.
fn mount<'a>(path: &Path, info: &'a str) -> Result<(Vec<&'a str>, Vec<&'a str>)> {
    let mut selected = None;
    let mut depth = 0;
    let mut duplicate = false;
    for line in info.lines() {
        let (a, b) = line.split_once(" - ").context("mountinfo framing")?;
        let left: Vec<_> = a.split_whitespace().collect();
        let target = Path::new(*left.get(4).context("mount target")?);
        let n = target.components().count();
        if !path.starts_with(target) || n < depth {
            continue;
        }
        duplicate = n == depth;
        depth = n;
        let right: Vec<_> = b.split_whitespace().collect();
        ensure!(left.len() >= 6 && right.len() >= 3, "mountinfo fields");
        selected = Some((left, right));
    }
    ensure!(!duplicate, "ambiguous top mount");
    selected.context("missing original mount")
}
fn owner(profile: &Guest, image: &File, device: &File) -> Result<Value> {
    let host_dev = libc::makedev(259, 1);
    let loop_dev = libc::makedev(7, profile.loop_number);
    let backing = profile.image();
    let p = backing.as_path();
    let loop_name = profile.device();
    let st = image.metadata()?;
    let named = fs::symlink_metadata(p)?;
    trusted_parents(p)?;
    ensure!(
        p.canonicalize()? == p
            && st.is_file()
            && named.is_file()
            && (named.dev(), named.ino()) == (st.dev(), st.ino())
            && st.dev() == host_dev
            && st.ino() == profile.inode
            && st.mode() & 0o7777 == 0o600
            && st.nlink() == 1
            && st.uid() == 0
            && st.len() == profile.cap,
        "peer backing inode or capacity changed"
    );
    let dev = device.metadata()?;
    ensure!(
        dev.file_type().is_block_device() && dev.rdev() == loop_dev,
        "different kernel loop"
    );
    let mut status = LoopInfo64::default();
    let mut size = 0u64;
    // LOOP_GET_STATUS64 and BLKGETSIZE64 only copy a status struct or u64 to userspace.
    syscall(unsafe { libc::ioctl(device.as_raw_fd(), 0x4c05, &mut status) })?;
    syscall(unsafe { libc::ioctl(device.as_raw_fd(), 0x80081272_u64, &mut size) })?;
    let fields = [
        status.device,
        status.inode,
        status.rdevice,
        status.offset,
        status.size_limit,
        u64::from(status.number),
        u64::from(status.encrypt_type),
        u64::from(status.encrypt_key_size),
        u64::from(status.flags),
    ];
    ensure!(
        fields
            == [
                host_dev,
                st.ino(),
                0,
                0,
                0,
                u64::from(profile.loop_number),
                0,
                0,
                4
            ]
            && size == profile.cap
            && Path::new(
                fs::read_to_string(format!(
                    "/sys/block/loop{}/loop/backing_file",
                    profile.loop_number
                ))?
                .trim()
            ) == p,
        "peer loop rebound, resized or changed flags"
    );
    let guest = Path::new(profile.guest);
    let root = fs::metadata(guest)?;
    ensure!(
        guest.canonicalize()? == guest && (root.dev(), root.ino()) == (loop_dev, 2),
        "peer guest root changed"
    );
    let info = fs::read_to_string("/proc/self/mountinfo")?;
    let (h, hf) = mount(p, &info)?;
    let (g, gf) = mount(guest, &info)?;
    ensure!(
        (h[0], h[2], h[3], h[4], hf[0], hf[1])
            == ("47", "259:1", "/", "/", "ext4", "/dev/nvme0n1p1"),
        "peer backing filesystem changed"
    );
    ensure!(
        (g[0], g[3], g[4], gf[0], gf[1])
            == (
                profile.mount_id,
                "/",
                profile.guest,
                "ext4",
                loop_name.as_str()
            )
            && g[2] == format!("7:{}", profile.loop_number)
            && !g[5]
                .split(',')
                .chain(gf[2].split(','))
                .any(|s| s == "discard" || s.starts_with("discard=")),
        "peer guest mount or discard changed"
    );
    Ok(
        json!({"device":st.dev(),"inode":st.ino(),"uid":st.uid(),"nlink":st.nlink(),"size":st.len(),"host_mount":47,"guest_mount":profile.mount_id.parse::<u64>()?,"host_source":hf[1],"guest_source":gf[1],"loop_status":fields}),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Extent {
    start: u64,
    end: u64,
    physical: u64,
}
fn accept(k: KernelExtent, cursor: u64, cap: u64) -> Result<(u64, Option<Extent>)> {
    ensure!(
        k.logical >= cursor
            && k.logical < cap
            && k.length > 0
            && k.reserved64 == [0; 2]
            && k.reserved == [0; 3],
        "unordered or invalid FIEMAP extent"
    );
    let next = k
        .logical
        .checked_add(k.length)
        .context("logical extent wraps")?;
    if k.flags & !(LAST | UNWRITTEN) != 0 || k.physical == 0 {
        return Ok((next, None));
    }
    let end = cap.min(next);
    ensure!(
        k.logical.is_multiple_of(BLOCK)
            && end.is_multiple_of(BLOCK)
            && k.physical.is_multiple_of(BLOCK)
            && k.physical.checked_add(end - k.logical).is_some(),
        "invalid physical extent"
    );
    Ok((
        next,
        Some(Extent {
            start: k.logical,
            end,
            physical: k.physical,
        }),
    ))
}
fn scan(file: &File, cap: u64) -> Result<Vec<Extent>> {
    let mut rows = Vec::new();
    let start = Instant::now();
    let mut cursor = 0;
    let mut seen = 0usize;
    while cursor < cap {
        let mut m = Fiemap {
            start: cursor,
            length: cap - cursor,
            flags: 0,
            mapped: 0,
            count: BATCH as u32,
            reserved: 0,
            extents: [KernelExtent::default(); BATCH],
        };
        // No FIEMAP_FLAG_SYNC: measuring allocation must not flush a running producer.
        syscall(unsafe { libc::ioctl(file.as_raw_fd(), 0xc020660b_u64, &mut m) })?;
        ensure!(
            (m.start, m.length, m.flags, m.count, m.reserved)
                == (cursor, cap - cursor, 0, BATCH as u32, 0)
                && m.mapped <= m.count,
            "invalid FIEMAP response"
        );
        let n = m.mapped as usize;
        seen += n;
        ensure!(
            seen <= 262144 && start.elapsed() < Duration::from_secs(15),
            "FIEMAP sample exceeded its bound"
        );
        if n == 0 {
            break;
        }
        let mut last = false;
        for &k in &m.extents[..n] {
            ensure!(!last, "FIEMAP data after last extent");
            let (next, entry) = accept(k, cursor, cap)?;
            cursor = next;
            last = k.flags & LAST != 0;
            if let Some(x) = entry {
                rows.push(x)
            }
        }
        if last {
            break;
        }
    }
    Ok(rows)
}
fn exclusive(rows: &[Extent], cap: u64) -> Result<u64> {
    let mut physical: Vec<_> = rows.iter().map(|r| (r.physical, r.end - r.start)).collect();
    physical.sort_unstable();
    let mut last = 0;
    let mut total = 0u64;
    for (start, len) in physical {
        ensure!(start >= last && len > 0, "duplicate physical allocation");
        last = start.checked_add(len).context("extent end wraps")?;
        total = total.checked_add(len).context("extent sum wraps")?;
    }
    ensure!(total <= cap, "allocation exceeds charged image");
    Ok(total)
}
fn visit_retained(first: &[Extent], second: &[Extent], mut visit: impl FnMut(u64, u64)) {
    let (mut i, mut j) = (0, 0);
    while i < first.len() && j < second.len() {
        let (a, b) = (first[i], second[j]);
        let lo = a.start.max(b.start);
        let hi = a.end.min(b.end);
        // Both physical ranges were checked for overflow on ingestion.
        if hi > lo && a.physical + (lo - a.start) == b.physical + (lo - b.start) {
            visit(a.physical + (lo - a.start), hi - lo);
        }
        if a.end <= b.end {
            i += 1;
        }
        if b.end <= a.end {
            j += 1;
        }
    }
}
fn retained(first: &[Extent], second: &[Extent]) -> u64 {
    let mut bytes = 0;
    visit_retained(first, second, |_, length| bytes += length);
    bytes
}

/// Physical ranges are data only. Callers must bind the filesystem, file identity and
/// complete scope and reject duplicate allocation before applying any credit.
pub(crate) fn stable_file_ranges(file: &File) -> Result<Vec<(u64, u64)>> {
    let before = file.metadata()?;
    ensure!(before.is_file(), "physical range scan requires a regular file");
    let cap = before.len() / BLOCK * BLOCK;
    let first = scan(file, cap)?;
    let second = scan(file, cap)?;
    let after = file.metadata()?;
    if metadata_identity(&before) != metadata_identity(&after) || before.nlink() != after.nlink() {
        return Ok(Vec::new());
    }
    let allocated = after.blocks().checked_mul(512).context("allocation count wraps")?;
    ensure!(
        exclusive(&first, cap)? <= allocated && exclusive(&second, cap)? <= allocated,
        "extent map exceeds kernel allocation count"
    );
    let mut matched = Vec::new();
    visit_retained(&first, &second, |start, length| matched.push((start, length)));
    Ok(matched)
}
struct Sample {
    id: Value,
    rows: Vec<Extent>,
    before: u64,
    after: u64,
    available: u64,
    total: u64,
}
impl Sample {
    fn document(&self) -> Value {
        let mut digest = Sha256::new();
        for r in &self.rows {
            for n in [r.start, r.end, r.physical] {
                digest.update(n.to_le_bytes());
            }
        }
        json!({"identity":self.id,"blocks_before":self.before,"blocks_after":self.after,"extent_count":self.rows.len(),"exclusive_data_bytes":self.total,"map_sha256":format!("{:x}",digest.finalize()),"available":self.available})
    }
}
fn blocks(file: &File) -> Result<u64> {
    file.metadata()?
        .blocks()
        .checked_mul(512)
        .context("inode block count overflow")
}
fn sample(profile: &Guest, image: &File, device: &File) -> Result<Sample> {
    let id = owner(profile, image, device)?;
    let before = blocks(image)?;
    ensure!(filesys(image)?.0 == BLOCK, "different host block size");
    let rows = scan(image, profile.cap)?;
    let available = filesys(image)?.1;
    let after = blocks(image)?;
    let total = exclusive(&rows, profile.cap)?;
    ensure!(
        total <= after && before <= after && owner(profile, image, device)? == id,
        "228 backing shrink or rebind during sample"
    );
    Ok(Sample {
        id,
        rows,
        before,
        after,
        available,
        total,
    })
}
fn common_allocation(a: &Sample, b: &Sample) -> Result<u64> {
    let credit = retained(&a.rows, &b.rows);
    ensure!(
        a.id == b.id && a.after <= b.before && credit <= a.total && credit <= b.total,
        "guest allocation shrank or rebound during election"
    );
    Ok(credit)
}
fn compare(a: &Sample, b: &Sample) -> Result<u64> {
    let credit = common_allocation(a, b)?;
    ensure!(
        credit == a.total && credit > 0,
        "original 228 allocation remapped during election"
    );
    Ok(credit)
}
pub(super) struct Extents {
    profile: &'static Guest,
    image: File,
    device: File,
    first: Sample,
    started: Instant,
}
impl Extents {
    pub(super) fn open() -> Result<Self> {
        Self::for_guest(&E228)
    }
    pub(super) fn turnover266() -> Result<Self> {
        Self::for_guest(&E266)
    }
    fn for_guest(profile: &'static Guest) -> Result<Self> {
        original(profile)?;
        let open = |p: &Path| {
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(p)
        };
        let image = open(&profile.image())?;
        let device = open(Path::new(&profile.device()))?;
        let started = Instant::now();
        let first = sample(profile, &image, &device)?;
        Ok(Self {
            profile,
            image,
            device,
            first,
            started,
        })
    }
    pub(super) fn finish(self) -> Result<Value> {
        let next = sample(self.profile, &self.image, &self.device)?;
        let credit = if self.profile.epoch == 228 {
            compare(&self.first, &next)?
        } else {
            common_allocation(&self.first, &next)?
        };
        let lower = self
            .first
            .available
            .min(next.available)
            .min(filesys(&self.image)?.1);
        Ok(
            json!({"schema":format!("horizon{}-charged-ext4-allocation-witness-v1",self.profile.epoch),"first":self.first.document(),"second":next.document(),"credit":credit,"free_lower":lower,"bracket_ns":u64::try_from(self.started.elapsed().as_nanos())?,"source_handoff":self.profile.handoff,"source_held":self.profile.held,"source_mount":self.profile.mount,"charged_image_bytes":self.profile.cap,"remaining_image_growth":self.profile.cap-credit,"other_growth_released":0,"capacity_released":false,"admission_authorized":false}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const CAP: u64 = E228.cap;

    fn e(start: u64, end: u64, physical: u64) -> Extent {
        Extent {
            start: start * BLOCK,
            end: end * BLOCK,
            physical: physical * BLOCK,
        }
    }
    fn s(rows: Vec<Extent>) -> Sample {
        let total = exclusive(&rows, CAP).unwrap();
        Sample {
            id: json!({"inode":18_330_573}),
            rows,
            before: total,
            after: total,
            available: 10 * BLOCK,
            total,
        }
    }

    #[test]
    fn extent_growth_and_boundary_splits_preserve_only_original_allocation() {
        let a = s(vec![e(1, 4, 12), e(8, 9, 22)]);
        let b = s(vec![e(0, 2, 11), e(2, 5, 13), e(8, 10, 22)]);
        assert_eq!(compare(&a, &b).unwrap(), 4 * BLOCK);
        assert_eq!(b.total, 7 * BLOCK);
        assert!(compare(&b, &a).is_err());
    }
    #[test]
    fn remap_hole_alias_rebind_and_shrink_cannot_lower_the_228_charge() {
        let a = s(vec![e(1, 4, 10)]);
        for mut b in [
            s(vec![e(1, 4, 11)]),
            s(vec![e(1, 2, 10), e(3, 4, 12)]),
            s(vec![]),
        ] {
            b.before = a.total;
            b.after = a.total;
            assert!(compare(&a, &b).is_err());
        }
        assert!(exclusive(&[e(1, 4, 10), e(5, 8, 12)], CAP).is_err());
        let mut b = s(vec![e(1, 4, 10)]);
        b.id = json!({"inode":2});
        assert!(compare(&a, &b).is_err());
        b.id = a.id.clone();
        b.before -= 1;
        assert!(compare(&a, &b).is_err());
        assert!(compare(&s(vec![]), &s(vec![])).is_err());
    }
    #[test]
    fn live_266_credits_only_surviving_physical_ranges() {
        let a = s(vec![e(0, 3, 10), e(3, 5, 20)]);
        let b = s(vec![e(0, 2, 10), e(2, 3, 16), e(3, 5, 20), e(5, 7, 30)]);
        assert_eq!(common_allocation(&a, &b).unwrap(), 4 * BLOCK);
        assert!(compare(&a, &b).is_err());
        let mut changed = b;
        changed.id = json!({"inode":0});
        assert!(common_allocation(&a, &changed).is_err());
    }
    #[test]
    fn unknown_shared_delayed_or_unaligned_extents_never_contribute() {
        let input = KernelExtent {
            logical: BLOCK,
            physical: 8 * BLOCK,
            length: BLOCK,
            ..Default::default()
        };
        for flags in [2, 4, 0x2000, 0x10000] {
            assert!(
                accept(KernelExtent { flags, ..input }, 0, CAP)
                    .unwrap()
                    .1
                    .is_none()
            );
        }
        assert!(
            accept(
                KernelExtent {
                    physical: 0,
                    ..input
                },
                0,
                CAP
            )
            .unwrap()
            .1
            .is_none()
        );
        assert!(
            accept(
                KernelExtent {
                    physical: 1,
                    ..input
                },
                0,
                CAP
            )
            .is_err()
        );
        assert!(
            accept(
                KernelExtent {
                    length: u64::MAX,
                    ..input
                },
                0,
                CAP
            )
            .is_err()
        );
        assert!(accept(input, 2 * BLOCK, CAP).is_err());
        assert_eq!(
            accept(
                KernelExtent {
                    flags: LAST | UNWRITTEN,
                    ..input
                },
                0,
                CAP
            )
            .unwrap()
            .1,
            Some(e(1, 2, 8))
        );
    }
    #[test]
    fn selects_the_original_deepest_mount_and_rejects_stacking() {
        let a = "47 0 259:1 / / rw - ext4 /dev/nvme0n1p1 rw";
        let b = "1167 47 7:6 / /home/test rw - ext4 /dev/loop6 rw";
        let text = format!("{a}\n{b}\n");
        assert_eq!(
            mount(Path::new("/home/test/a"), &text).unwrap().0[0],
            "1167"
        );
        assert_eq!(mount(Path::new("/home/test2/a"), &text).unwrap().0[0], "47");
        assert!(mount(Path::new("/home/test"), &format!("{text}{b}")).is_err());
    }
}
