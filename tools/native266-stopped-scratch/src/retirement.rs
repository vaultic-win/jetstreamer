use super::*;
use crate::{
    journal::Journal,
    retained::{Q, ROOT},
};
use std::ffi::CString;
use std::io::ErrorKind;
unsafe extern "C" {
    fn renameat2(old: i32, from: *const i8, new: i32, to: *const i8, flags: u32) -> i32;
    fn unlinkat(dir: i32, name: *const i8, flags: i32) -> i32;
    fn fchown(fd: i32, uid: u32, gid: u32) -> i32;
}
fn sys(rc: i32) -> io::Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
fn child(d: &File, n: &str) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", d.as_raw_fd())).join(n)
}
fn dirid(d: &File, n: &str) -> io::Result<Option<u64>> {
    match fs::symlink_metadata(child(d, n)) {
        Ok(m) => {
            need(
                m.is_dir() && m.dev() == d.metadata()?.dev(),
                "unexpected named tree",
            )?;
            Ok(Some(m.ino()))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
fn unlink(d: &File, name: &str, isdir: bool) -> io::Result<()> {
    let name = CString::new(name)?;
    sys(unsafe { unlinkat(d.as_raw_fd(), name.as_ptr(), if isdir { 0x200 } else { 0 }) })
}
pub(super) fn rename_exclusive(src: &File, name: &str, dest: &File, new: &str) -> io::Result<()> {
    let from = CString::new(name)?;
    let to = CString::new(new)?;
    sys(unsafe {
        renameat2(
            src.as_raw_fd(),
            from.as_ptr(),
            dest.as_raw_fd(),
            to.as_ptr(),
            1,
        )
    })?;
    src.sync_all()?;
    dest.sync_all()
}
pub trait Tree {
    fn names(&self) -> io::Result<(Option<u64>, Option<u64>)>;
    fn full(&self) -> io::Result<()>;
    fn move_tree(&self) -> io::Result<()>;
    fn fence(&self) -> io::Result<()>;
    fn drain(&self) -> io::Result<()>;
    fn empty(&self) -> io::Result<()>;
    fn remove_empty(&self) -> io::Result<()>;
}
pub struct Original {
    pub src: File,
    pub vault: File,
}
impl Original {
    pub fn open() -> io::Result<Self> {
        let p = retained::parent();
        need(p.canonicalize()? == p, "derived directory parent path")?;
        let src = open(&p, DIRECTORY)?;
        let root = open(Path::new(ROOT), DIRECTORY)?;
        let vault = open(&child(&root, "lost+found"), DIRECTORY)?;
        let vm = vault.metadata()?;
        let mi = fs::read_to_string(format!("/proc/self/fdinfo/{}", vault.as_raw_fd()))?;
        need(
            (vm.dev(), vm.ino(), vm.uid(), vm.gid(), vm.mode()) == (DEVICE, 11, 0, 0, 0o40700)
                && mi.lines().any(|l| {
                    l.strip_prefix("mnt_id:")
                        .is_some_and(|s| s.trim().parse::<u64>().ok() == Some(MOUNT))
                }),
            "original root-only quarantine parent",
        )?;
        need(
            check_fd(&src, true)?.ino() == PARENT_INODE && check_fd(&root, true)?.ino() == 2,
            "original directory identity",
        )?;
        Ok(Self { src, vault })
    }
    fn quarantined(&self) -> io::Result<File> {
        let f = open(&child(&self.vault, Q), DIRECTORY)?;
        let m = f.metadata()?;
        let info = fs::read_to_string(format!("/proc/self/fdinfo/{}", f.as_raw_fd()))?;
        need(
            m.is_dir()
                && m.ino() == CHILD_INODE
                && m.dev() == DEVICE
                && [(0, 0), (1000, 1000)].contains(&(m.uid(), m.gid()))
                && m.mode() & 0o7777 == 0o700
                && info.lines().any(|s| {
                    s.strip_prefix("mnt_id:")
                        .is_some_and(|id| id.trim().parse::<u64>().ok() == Some(MOUNT))
                }),
            "quarantine identity",
        )?;
        Ok(f)
    }
}
pub(super) fn erase(
    dir: &File,
    parts: &mut Vec<String>,
    used: &mut u64,
    until: Instant,
    validate: &impl Fn(&File, bool) -> io::Result<fs::Metadata>,
) -> io::Result<()> {
    loop {
        need(Instant::now() < until, "retirement deadline")?;
        let mut batch = 0;
        for row in fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))? {
            *used += 1;
            need(
                *used <= MAX_ENTRIES && Instant::now() < until,
                "retirement entry/deadline limit",
            )?;
            let name = row?
                .file_name()
                .into_string()
                .map_err(|_| io::Error::other("non-UTF8 leaf"))?;
            let p = child(dir, &name);
            let fd = open(&p, PATH_ONLY)?;
            let isdir = fd.metadata()?.is_dir();
            let m = validate(&fd, isdir)?;
            if isdir {
                parts.push(name.clone());
                need(
                    dir_name(&parts.iter().map(String::as_str).collect::<Vec<_>>()),
                    "unrecognized derived directory",
                )?;
                let d = open(&p, DIRECTORY)?;
                need(
                    validate(&d, true)?.ino() == m.ino(),
                    "directory substitution",
                )?;
                erase(&d, parts, used, until, validate)?;
                parts.pop();
            } else {
                need(
                    leaf_name(&parts.iter().map(String::as_str).collect::<Vec<_>>(), &name),
                    "unrecognized derived file",
                )?
            }
            let again = fs::symlink_metadata(&p)?;
            need(
                (again.dev(), again.ino(), again.mode()) == (m.dev(), m.ino(), m.mode())
                    && (isdir || again.nlink() == 1),
                "name changed during unlink",
            )?;
            unlink(dir, &name, isdir)?;
            batch += 1;
            if batch == 2048 {
                break;
            }
        }
        if batch == 0 {
            break;
        }
    }
    dir.sync_all()
}
impl Tree for Original {
    fn names(&self) -> io::Result<(Option<u64>, Option<u64>)> {
        Ok((dirid(&self.src, CHILD)?, dirid(&self.vault, Q)?))
    }
    fn full(&self) -> io::Result<()> {
        let f = open(&child(&self.src, CHILD), DIRECTORY)?;
        need(
            check_fd(&f, true)?.ino() == CHILD_INODE,
            "wrong original child",
        )?;
        let mut c = Counts::default();
        inspect(
            &f,
            Path::new(""),
            &mut c,
            Instant::now() + Duration::from_secs(240),
        )?;
        need(
            c == EXPECTED,
            "closed original differs from completed source check",
        )
    }
    fn move_tree(&self) -> io::Result<()> {
        let h = open(&child(&self.src, CHILD), DIRECTORY)?;
        need(
            check_fd(&h, true)?.ino() == CHILD_INODE,
            "wrong rename source",
        )?;
        rename_exclusive(&self.src, CHILD, &self.vault, Q)?;
        need(
            self.quarantined()?.metadata()?.ino() == h.metadata()?.ino(),
            "rename readback",
        )
    }
    fn fence(&self) -> io::Result<()> {
        let f = self.quarantined()?;
        if f.metadata()?.uid() != 0 {
            sys(unsafe { fchown(f.as_raw_fd(), 0, 0) })?
        };
        f.sync_all()?;
        need(
            self.quarantined()?.metadata()?.uid() == 0,
            "quarantine custody",
        )
    }
    fn drain(&self) -> io::Result<()> {
        let f = self.quarantined()?;
        need(f.metadata()?.uid() == 0, "quarantine ownership")?;
        let until = Instant::now() + Duration::from_secs(840);
        let mut c = Counts::default();
        inspect(&f, Path::new(""), &mut c, until)?;
        need(
            c.files <= EXPECTED.files
                && c.directories <= EXPECTED.directories
                && c.logical <= EXPECTED.logical
                && c.allocated_files <= EXPECTED.allocated_files,
            "unexpected residual inventory",
        )?;
        erase(&f, &mut Vec::new(), &mut 0, until, &check_fd)
    }
    fn empty(&self) -> io::Result<()> {
        let f = self.quarantined()?;
        need(
            f.metadata()?.uid() == 0
                && fs::read_dir(format!("/proc/self/fd/{}", f.as_raw_fd()))?
                    .next()
                    .is_none(),
            "quarantine is not empty",
        )?;
        f.sync_all()
    }
    fn remove_empty(&self) -> io::Result<()> {
        self.empty()?;
        need(
            self.names()? == (None, Some(CHILD_INODE)),
            "final quarantine changed",
        )?;
        unlink(&self.vault, Q, true)?;
        self.vault.sync_all()
    }
}
pub fn retire(
    t: &impl Tree,
    j: &Journal,
    binding: &str,
    original_alloc: u64,
    gate: &mut impl FnMut() -> io::Result<()>,
) -> io::Result<()> {
    let named = Some(CHILD_INODE);
    let intent = j.get("intent")?;
    let prior_intent = intent.is_some();
    let intent = if let Some(i) = intent {
        validate_intent(&i, binding)?;
        i
    } else {
        need(
            t.names()? == (named, None) && j.get("empty")?.is_none() && j.get("retired")?.is_none(),
            "initial ownership",
        )?;
        t.full()?;
        gate()?;
        let i = format!("{binding}image_allocated_before_retirement={original_alloc}\n");
        j.put("intent", &i)?;
        i
    };
    let empty = j.get("empty")?;
    let done = j.get("retired")?;
    for v in [&empty, &done].into_iter().flatten() {
        need(*v == intent, "retirement chain mismatch")?
    }
    if done.is_some() {
        return need(
            empty.is_some() && t.names()? == (None, None),
            "retirement completion state differs",
        );
    }
    if t.names()? == (named, None) {
        need(empty.is_none(), "original reappeared after drain")?;
        if prior_intent {
            t.full()?;
        }
        gate()?;
        t.move_tree()?;
    }
    if t.names()? == (None, named) {
        t.fence()?;
        gate()?;
        if empty.is_none() {
            t.drain()?;
            t.empty()?;
            j.put("empty", &intent)?;
        }
        t.empty()?;
        gate()?;
        t.remove_empty()?;
    }
    need(
        j.get("empty")?.as_deref() == Some(&intent) && t.names()? == (None, None),
        "missing bound empty-quarantine evidence",
    )?;
    gate()?;
    j.put("retired", &intent)
}
pub fn validate_intent(i: &str, b: &str) -> io::Result<u64> {
    let n = i
        .strip_prefix(b)
        .and_then(|s| s.strip_prefix("image_allocated_before_retirement="))
        .and_then(|s| s.strip_suffix('\n'))
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| io::Error::other("invalid intent binding"))?;
    need(
        n > 100 << 30 && n <= IMAGE_SIZE,
        "invalid original image allocation",
    )?;
    Ok(n)
}
