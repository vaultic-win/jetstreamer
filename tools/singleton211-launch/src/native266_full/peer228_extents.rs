//! Reprice only blocks already occupied by the original 228 loop6 image.
//! File descriptors pin the objects, while two FIEMAP samples establish which
//! logical bytes still map to the same exclusive physical blocks.
use super::*;
use std::os::{fd::AsRawFd, unix::fs::FileTypeExt};

const STATE: &str = "/var/lib/jetstreamer/horizon228-native-root-tail-v166-a1/pilot";
const IMAGE: &str = "/var/lib/jetstreamer/horizon228-native-root-tail-v166-a1/pilot/private.ext4";
const GUEST: &str = "/home/ubuntu/.jetstreamer-private/qualification-228-demotion-root-tail-v1";
const LOOP: &str = "/dev/loop6";
const CAP: u64 = 112 << 30;
const HAND: &str = "da3fdea0fa6f6682daa741e4c72d5f3a81d6bd420743d5df70c46d40b6319752";
const HELD: &str = "45e7ff78f1fae3b0075dc84a0e66add7fe6751a655260f7d1fcf93b7a8e50895";
const MOUNT: &str = "eb09b34163d040856017b3ccdd45295448922483836ac20d4498d1697aeb335b";
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

fn original() -> Result<()> {
    let bound = |name: &str, hash: &str| Bound::new(Path::new(STATE).join(name), hash);
    let h = bound("handoff.json", HAND).sealed()?;
    let fit = bound("held-fit.json", HELD);
    let f = fit.sealed()?;
    let m = bound("mount.json", MOUNT).sealed()?;
    ensure!(
        h["iid"] == "5566869f329b46309aa8a2ea8f46047a"
            && h["pid"] == 2819393
            && h["unit"] == "horizon-qualify-228-demotion-root-tail-16d4b158-v1.service"
            && h["held_fit"] == json!(fit),
        "228 original handoff"
    );
    ensure!(
        m == json!({"backing":IMAGE,"bytes":CAP,"loop":LOOP,"root":GUEST,"root_device":libc::makedev(7,6),"root_inode":2}),
        "228 mount receipt"
    );
    ensure!(
        f["winner"]["fits"] == true
            && f["winner"]["root"] == CAP
            && num(&f, "protected_floor")?.checked_add(CAP)
                == f["winner"]["required_free"].as_u64(),
        "228 gross reservation"
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
fn owner(image: &File, device: &File) -> Result<Value> {
    let host_dev = libc::makedev(259, 1);
    let loop_dev = libc::makedev(7, 6);
    let p = Path::new(IMAGE);
    let st = image.metadata()?;
    let named = fs::symlink_metadata(p)?;
    trusted_parents(p)?;
    ensure!(
        p.canonicalize()? == p
            && st.is_file()
            && named.is_file()
            && (named.dev(), named.ino()) == (st.dev(), st.ino())
            && st.dev() == host_dev
            && st.ino() == 18_330_573
            && st.mode() & 0o7777 == 0o600
            && st.nlink() == 1
            && st.uid() == 0
            && st.len() == CAP,
        "228 backing inode or capacity changed"
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
        fields == [host_dev, st.ino(), 0, 0, 0, 6, 0, 0, 4]
            && size == CAP
            && fs::read_to_string("/sys/block/loop6/loop/backing_file")?.trim() == IMAGE,
        "228 loop rebound, resized or changed flags"
    );
    let guest = Path::new(GUEST);
    let root = fs::metadata(guest)?;
    ensure!(
        guest.canonicalize()? == guest && (root.dev(), root.ino()) == (loop_dev, 2),
        "228 guest root changed"
    );
    let info = fs::read_to_string("/proc/self/mountinfo")?;
    let (h, hf) = mount(p, &info)?;
    let (g, gf) = mount(guest, &info)?;
    ensure!(
        (h[0], h[2], h[3], h[4], hf[0], hf[1])
            == ("47", "259:1", "/", "/", "ext4", "/dev/nvme0n1p1"),
        "228 backing filesystem changed"
    );
    ensure!(
        (g[0], g[2], g[3], g[4], gf[0], gf[1]) == ("1167", "7:6", "/", GUEST, "ext4", LOOP)
            && !g[5]
                .split(',')
                .chain(gf[2].split(','))
                .any(|s| s == "discard" || s.starts_with("discard=")),
        "228 guest mount or discard changed"
    );
    Ok(
        json!({"device":st.dev(),"inode":st.ino(),"uid":st.uid(),"nlink":st.nlink(),"size":st.len(),"host_mount":47,"guest_mount":1167,"host_source":hf[1],"guest_source":gf[1],"loop_status":fields}),
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
fn retained(first: &[Extent], second: &[Extent]) -> u64 {
    let (mut i, mut j, mut bytes) = (0, 0, 0);
    while i < first.len() && j < second.len() {
        let (a, b) = (first[i], second[j]);
        let lo = a.start.max(b.start);
        let hi = a.end.min(b.end);
        // Both physical ranges were checked for overflow on ingestion.
        if hi > lo && a.physical + (lo - a.start) == b.physical + (lo - b.start) {
            bytes += hi - lo;
        }
        if a.end <= b.end {
            i += 1;
        }
        if b.end <= a.end {
            j += 1;
        }
    }
    bytes
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
fn sample(image: &File, device: &File) -> Result<Sample> {
    let id = owner(image, device)?;
    let before = blocks(image)?;
    ensure!(filesys(image)?.0 == BLOCK, "different host block size");
    let rows = scan(image, CAP)?;
    let available = filesys(image)?.1;
    let after = blocks(image)?;
    let total = exclusive(&rows, CAP)?;
    ensure!(
        total <= after && before <= after && owner(image, device)? == id,
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
fn compare(a: &Sample, b: &Sample) -> Result<u64> {
    let credit = retained(&a.rows, &b.rows);
    ensure!(
        a.id == b.id && a.after <= b.before && credit == a.total && credit <= b.total && credit > 0,
        "228 allocation shrank, changed owner or remapped during election"
    );
    Ok(credit)
}
pub(super) struct Extents {
    image: File,
    device: File,
    first: Sample,
    started: Instant,
}
impl Extents {
    pub(super) fn open() -> Result<Self> {
        original()?;
        let open = |p: &str| {
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(p)
        };
        let image = open(IMAGE)?;
        let device = open(LOOP)?;
        let started = Instant::now();
        let first = sample(&image, &device)?;
        Ok(Self {
            image,
            device,
            first,
            started,
        })
    }
    pub(super) fn finish(self) -> Result<Value> {
        let next = sample(&self.image, &self.device)?;
        let credit = compare(&self.first, &next)?;
        let lower = self
            .first
            .available
            .min(next.available)
            .min(filesys(&self.image)?.1);
        Ok(
            json!({"schema":"horizon228-charged-ext4-allocation-witness-v1","first":self.first.document(),"second":next.document(),"credit":credit,"free_lower":lower,"bracket_ns":u64::try_from(self.started.elapsed().as_nanos())?,"source_handoff":HAND,"source_held":HELD,"source_mount":MOUNT,"charged_image_bytes":CAP,"remaining_image_growth":CAP-credit,"other_growth_released":0,"capacity_released":false,"admission_authorized":false}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
