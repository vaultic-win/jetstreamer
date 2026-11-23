use super::*;
use super::{closure::Volume, journal::Journal, retirement::Tree};
use std::cell::{Cell, RefCell};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::time::{SystemTime, UNIX_EPOCH};
const B: &str = "fixture authority\n";
const ORIG: u64 = 125 << 30;
struct Sandbox {
    root: PathBuf,
    uid: u32,
}
impl Sandbox {
    fn new() -> io::Result<Self> {
        let root = std::env::temp_dir().join(format!(
            "h266-private-retry-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::DirBuilder::new().mode(0o700).create(&root)?;
        let uid = root.metadata()?.uid();
        fs::create_dir(root.join("receipts"))?;
        fs::set_permissions(root.join("receipts"), fs::Permissions::from_mode(0o700))?;
        fs::create_dir(root.join("original"))?;
        fs::write(root.join("original/appendvec"), b"derived disposable")?;
        fs::write(root.join("partial.jet"), b"unchanged reproduction")?;
        Ok(Self { root, uid })
    }
    fn journal(&self) -> io::Result<Journal> {
        Journal::new(&self.root.join("receipts"), self.uid)
    }
    fn retained(&self) -> io::Result<()> {
        need(
            fs::read(self.root.join("partial.jet"))? == b"unchanged reproduction",
            "retained archive changed",
        )
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap()
    }
}
struct RealTree<'a> {
    f: &'a Sandbox,
    fault: Cell<Option<&'static str>>,
}
impl RealTree<'_> {
    fn action(&self, s: &'static str) -> io::Result<()> {
        if self.fault.get() == Some(s) {
            self.fault.set(None);
            return Err(io::Error::other(s));
        };
        Ok(())
    }
    fn path(&self, n: &str) -> PathBuf {
        self.f.root.join(n)
    }
}
impl Tree for RealTree<'_> {
    fn names(&self) -> io::Result<(Option<u64>, Option<u64>)> {
        let at = |n: &str| -> io::Result<Option<u64>> {
            Ok(self
                .path(n)
                .try_exists()?
                .then_some(crate::profile::CHILD_INODE))
        };
        Ok((at("original")?, at("quarantine")?))
    }
    fn full(&self) -> io::Result<()> {
        need(
            fs::read(self.path("original/appendvec"))? == b"derived disposable",
            "fixture content",
        )
    }
    fn move_tree(&self) -> io::Result<()> {
        self.action("after-intent")?;
        let dir = open(&self.f.root, DIRECTORY)?;
        retirement::rename_exclusive(&dir, "original", &dir, "quarantine")?;
        self.action("after-rename")
    }
    fn fence(&self) -> io::Result<()> {
        self.action("fence")
    }
    fn drain(&self) -> io::Result<()> {
        let f = self.path("quarantine/appendvec");
        if f.try_exists()? {
            fs::remove_file(f)?;
        }
        self.action("after-leaf-unlink")
    }
    fn empty(&self) -> io::Result<()> {
        need(
            fs::read_dir(self.path("quarantine"))?.next().is_none(),
            "quarantine nonempty",
        )
    }
    fn remove_empty(&self) -> io::Result<()> {
        self.action("after-empty-receipt")?;
        fs::remove_dir(self.path("quarantine"))?;
        self.action("after-root-unlink")
    }
}
#[test]
fn every_retirement_boundary_resumes_from_durable_state() -> io::Result<()> {
    for f in [
        "after-intent",
        "after-rename",
        "fence",
        "after-leaf-unlink",
        "after-empty-receipt",
        "after-root-unlink",
    ] {
        let b = Sandbox::new()?;
        let t = RealTree {
            f: &b,
            fault: Cell::new(Some(f)),
        };
        assert!(
            retirement::retire(&t, &b.journal()?, B, ORIG, &mut || b.retained()).is_err(),
            "{f}"
        );
        retirement::retire(&t, &b.journal()?, B, 0, &mut || b.retained())?;
        retirement::retire(&t, &b.journal()?, B, 0, &mut || b.retained())?;
        assert_eq!(t.names()?, (None, None));
        b.retained()?;
    }
    Ok(())
}
#[test]
fn both_names_absent_requires_previously_fsynced_empty_receipt() -> io::Result<()> {
    let b = Sandbox::new()?;
    let t = RealTree {
        f: &b,
        fault: Cell::new(Some("after-rename")),
    };
    let j = b.journal()?;
    assert!(retirement::retire(&t, &j, B, ORIG, &mut || Ok(())).is_err());
    fs::remove_dir_all(t.path("quarantine"))?;
    assert!(retirement::retire(&t, &j, B, ORIG, &mut || Ok(())).is_err());
    assert!(j.get("retired")?.is_none());
    Ok(())
}
#[test]
fn conflicting_fixed_receipt_is_preserved() -> io::Result<()> {
    let b = Sandbox::new()?;
    let j = b.journal()?;
    j.put("intent", "first")?;
    assert!(j.put("intent", "different").is_err());
    assert_eq!(j.get("intent")?.as_deref(), Some("first"));
    Ok(())
}
struct Medium {
    state: Cell<(bool, bool)>,
    size: Cell<u64>,
    fault: Cell<Option<&'static str>>,
    calls: RefCell<Vec<&'static str>>,
}
impl Medium {
    fn action(&self, s: &'static str) -> io::Result<()> {
        self.calls.borrow_mut().push(s);
        if self.fault.get() == Some(s) {
            self.fault.set(None);
            return Err(io::Error::other(s));
        };
        Ok(())
    }
}
impl Volume for Medium {
    fn state(&self) -> io::Result<(bool, bool)> {
        Ok(self.state.get())
    }
    fn allocated(&self) -> io::Result<u64> {
        Ok(self.size.get())
    }
    fn trim(&self) -> io::Result<String> {
        need(
            self.state.get() == (false, false),
            "attempted trim after RO",
        )?;
        self.size.set(2 << 30);
        self.action("trim")?;
        Ok("fixture trimmed\n".to_string())
    }
    fn remount_ro(&self) -> io::Result<()> {
        need(self.state.get() == (false, false), "duplicate remount")?;
        self.state.set((true, false));
        self.action("remount")
    }
    fn block_ro(&self) -> io::Result<()> {
        need(self.state.get() == (true, false), "wrong loop transition")?;
        self.state.set((true, true));
        self.action("block")
    }
    fn verify(&self) -> io::Result<()> {
        need(
            self.state.get() == (true, true),
            "EROFS verification before RO",
        )?;
        self.action("verify")
    }
}
fn retired(b: &Sandbox) -> io::Result<Journal> {
    let j = b.journal()?;
    let t = RealTree {
        f: b,
        fault: Cell::new(None),
    };
    retirement::retire(&t, &j, B, ORIG, &mut || b.retained())?;
    Ok(j)
}
#[test]
fn interrupted_trim_remount_block_and_verification_recover_without_writable_reopen()
-> io::Result<()> {
    for fault in ["trim", "remount", "block", "verify"] {
        let s = Sandbox::new()?;
        let j = retired(&s)?;
        let m = Medium {
            state: Cell::new((false, false)),
            size: Cell::new(124 << 30),
            fault: Cell::new(Some(fault)),
            calls: RefCell::default(),
        };
        assert!(
            closure::close(&m, &j, B, &mut |_| s.retained()).is_err(),
            "{fault}"
        );
        closure::close(&m, &s.journal()?, B, &mut |_| s.retained())?;
        closure::close(&m, &s.journal()?, B, &mut |_| s.retained())?;
        assert_eq!(
            m.calls.borrow().iter().filter(|&&s| s == "trim").count(),
            if fault == "trim" { 2 } else { 1 }
        );
        for n in ["remount", "block"] {
            assert_eq!(m.calls.borrow().iter().filter(|&&s| s == n).count(), 1)
        }
        assert_eq!(m.state.get(), (true, true));
        assert!(
            j.get("closed")?
                .unwrap()
                .contains("pretrim=133143986176\nfstrim=fixture trimmed\nposttrim=2147483648")
        );
        s.retained()?;
    }
    Ok(())
}
#[test]
fn unexplained_readonly_state_does_not_grant_trim_credit() -> io::Result<()> {
    let b = Sandbox::new()?;
    let j = retired(&b)?;
    let m = Medium {
        state: Cell::new((true, false)),
        size: Cell::new(2 << 30),
        fault: Cell::new(None),
        calls: RefCell::default(),
    };
    assert!(closure::close(&m, &j, B, &mut |_| Ok(())).is_err());
    assert!(j.get("closed")?.is_none());
    Ok(())
}
#[test]
fn kernel_rename_refuses_preexisting_quarantine() -> io::Result<()> {
    let b = Sandbox::new()?;
    let d = open(&b.root, DIRECTORY)?;
    fs::create_dir(b.root.join("quarantine"))?;
    assert_eq!(
        retirement::rename_exclusive(&d, "original", &d, "quarantine")
            .unwrap_err()
            .raw_os_error(),
        Some(17)
    );
    assert!(b.root.join("original/appendvec").is_file());
    b.retained()
}
#[test]
fn actual_fd_unlink_preserves_external_file_and_refuses_links_and_foreign_names() -> io::Result<()>
{
    use std::os::unix::fs::symlink;
    for kind in ["good", "symlink", "hardlink", "unknown"] {
        let b = Sandbox::new()?;
        let q = b.root.join("tree");
        fs::create_dir(&q)?;
        let inner = q.join(RUNTIME).join("accounts-state/3");
        fs::create_dir_all(&inner)?;
        let leaf = inner.join("1.0");
        match kind {
            "good" => fs::write(&leaf, b"test")?,
            "symlink" => symlink(b.root.join("partial.jet"), &leaf)?,
            "hardlink" => fs::hard_link(b.root.join("partial.jet"), &leaf)?,
            "unknown" => fs::write(inner.join("foreign"), b"x")?,
            _ => unreachable!(),
        }
        let f = open(&q, DIRECTORY)?;
        let dev = f.metadata()?.dev();
        let check = |x: &File, dir: bool| {
            let m = x.metadata()?;
            need(
                m.dev() == dev
                    && (if dir {
                        m.is_dir()
                    } else {
                        m.is_file() && m.nlink() == 1
                    }),
                "foreign fixture inode",
            )?;
            Ok(m)
        };
        let r = retirement::erase(
            &f,
            &mut Vec::new(),
            &mut 0,
            Instant::now() + Duration::from_secs(5),
            &check,
        );
        assert_eq!(r.is_ok(), kind == "good");
        if kind == "good" {
            assert!(fs::read_dir(q)?.next().is_none())
        } else {
            assert!(fs::read_dir(inner)?.next().is_some())
        }
        b.retained()?;
    }
    Ok(())
}
