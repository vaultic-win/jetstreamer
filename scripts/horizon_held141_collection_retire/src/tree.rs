//! Retire one closed, identity-bound flat collection. No recursive removal.
//! The caller owns the campaign mutation lock and both private directory descriptors.
use crate::atomic_fs::{
    AnchoredParent, exists_at, open_at, private_child, publish, read_at, rename_no_replace,
    unlink_at,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
};

pub(crate) type Signature = [u64; 10];
pub(crate) type Table = BTreeMap<String, (Signature, String)>;
const SOURCE: &str = "retained";
const CAPTURE: &str = "captured-rocksdb";
const TOMB: &str = "captured-members";

pub(crate) fn signature(m: &Metadata) -> Result<Signature> {
    fn ns(sec: i64, nanos: i64) -> Result<u64> {
        Ok((i128::from(sec) * 1_000_000_000 + i128::from(nanos)).try_into()?)
    }
    Ok([
        m.dev(),
        m.ino(),
        m.len(),
        ns(m.mtime(), m.mtime_nsec())?,
        ns(m.ctime(), m.ctime_nsec())?,
        m.uid().into(),
        m.gid().into(),
        m.mode().into(),
        m.nlink(),
        m.blocks(),
    ])
}
pub(crate) fn allocation(table: &Table) -> Result<u64> {
    table.values().try_fold(0u64, |total, (row, _)| {
        total
            .checked_add(row[9].checked_mul(512).context("allocation overflow")?)
            .context("allocation sum overflow")
    })
}
fn names(dir: &File) -> Result<BTreeSet<String>> {
    fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))?
        .map(|e| {
            e?.file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("non-UTF8 member in captured collection"))
        })
        .collect()
}
fn check_dir(dir: &File, expected: &Signature, exact: bool) -> Result<()> {
    let actual = signature(&dir.metadata()?)?;
    if exact {
        ensure!(&actual == expected, "original directory metadata changed");
    }
    ensure!(
        [0, 1, 5, 6, 7, 8].iter().all(|&i| actual[i] == expected[i]),
        "wrong collection directory identity"
    );
    Ok(())
}
fn checked_member(dir: &File, name: &str, expected: &Signature, renamed: bool) -> Result<File> {
    let file = open_at(dir, name, libc::O_RDONLY | libc::O_NONBLOCK)?;
    let m = file.metadata()?;
    let actual = signature(&m)?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && actual
                .iter()
                .enumerate()
                .all(|(i, v)| (renamed && i == 4) || *v == expected[i]),
        "identity changed for {name}"
    );
    Ok(file)
}
pub(crate) fn census(dir: &File, table: &Table, full: bool) -> Result<BTreeSet<String>> {
    let seen = names(dir)?;
    ensure!(
        !full || seen.len() == table.len(),
        "incomplete collection before retirement"
    );
    for name in &seen {
        let expected = table.get(name).context("unlisted entry in collection")?;
        checked_member(dir, name, &expected.0, false)?;
    }
    Ok(seen)
}
fn private_receipt(dir: &File, name: &str, content: &Value) -> Result<()> {
    if exists_at(dir, name)? {
        ensure!(
            serde_json::from_slice::<Value>(&read_at(dir, name)?)? == *content,
            "different existing {name}"
        );
    } else {
        publish(dir, name, content)?;
    }
    Ok(())
}
fn rmdir(dir: &File, name: &str) -> Result<()> {
    let name = CString::new(name)?;
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(io::Error::last_os_error()).context("remove exact empty captured directory");
    }
    dir.sync_all()?;
    Ok(())
}
fn free_bytes(dir: &File) -> Result<u64> {
    let mut st = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::fstatvfs(dir.as_raw_fd(), st.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let st = unsafe { st.assume_init() };
    st.f_bavail
        .checked_mul(st.f_frsize)
        .context("available bytes overflow")
}
fn file_digest(mut f: &File) -> Result<String> {
    let mut h = Sha256::new();
    io::copy(&mut f, &mut h)?;
    Ok(format!("{:x}", h.finalize()))
}
fn remove_captured(tomb: &File, name: &str, row: &(Signature, String)) -> Result<()> {
    let f = checked_member(tomb, name, &row.0, true)?;
    unlink_at(tomb, name)?;
    ensure!(
        f.metadata()?.nlink() == 0,
        "captured descriptor still linked: {name}"
    );
    tomb.sync_all()?;
    Ok(())
}

// One durable byte per confirmed no-clobber capture, in the signed table's lexical
// order. A crash can leave that exact file in the tomb on either side of this
// append. Missing files with no corresponding custody record are never credited.
struct CaptureJournal {
    file: File,
    count: usize,
}
impl CaptureJournal {
    fn open(state: &File, limit: usize) -> Result<Self> {
        let path = format!("/proc/self/fd/{}/captured-prefix", state.as_raw_fd());
        let mut options = OpenOptions::new();
        options
            .read(true)
            .append(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        let mut file = if exists_at(state, "captured-prefix")? {
            options.open(path)?
        } else {
            let f = options.create_new(true).mode(0o600).open(path)?;
            f.sync_all()?;
            state.sync_all()?;
            f
        };
        let m = file.metadata()?;
        ensure!(
            m.is_file()
                && m.nlink() == 1
                && m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o7777 == 0o600
                && m.dev() == state.metadata()?.dev()
                && m.len() <= limit as u64,
            "invalid capture journal"
        );
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() == m.len() as usize
                && bytes.iter().enumerate().all(|(i, b)| *b == Self::marker(i)),
            "corrupt capture journal"
        );
        Ok(Self {
            file,
            count: bytes.len(),
        })
    }
    fn marker(i: usize) -> u8 {
        (i % 251 + 1) as u8
    }
    fn confirm(&mut self) -> Result<()> {
        self.file.write_all(&[Self::marker(self.count)])?;
        self.file.sync_data()?;
        self.count += 1;
        Ok(())
    }
}

pub(crate) struct Transaction<'a> {
    pub parent: &'a AnchoredParent,
    pub state: &'a AnchoredParent,
    pub table: &'a Table,
    pub dir_id: &'a Signature,
    pub admission: &'a str,
    pub table_sha: &'a str,
}

impl Transaction<'_> {
    fn recheck(&self) -> Result<()> {
        self.parent.recheck()?;
        self.state.recheck()?;
        Ok(())
    }
    /// The gate is re-run under the same lock, including after atomic capture on retries.
    pub fn retire(&self, gate: impl Fn(&str) -> Result<()>) -> Result<Value> {
        let root = &self.parent.directory;
        let state = &self.state.directory;
        let table = self.table;
        let contract = json!({"admission":self.admission,"member_table_sha256":self.table_sha,"directory":self.dir_id,"members":table.len()});
        self.recheck()?;
        let baseline_name = "original-free.json";
        let intent = exists_at(state, "intent.json")?;
        let captured = exists_at(state, CAPTURE)?;
        let original = exists_at(root, SOURCE)?;
        let committed = exists_at(state, "unlink-authority.json")?;
        let emptied = exists_at(state, "empty.json")?;
        if exists_at(state, "complete.json")? {
            ensure!(
                !original && !captured && emptied && committed,
                "retired collection reappeared"
            );
            private_receipt(state, "empty.json", &contract)?;
            let result: Value = serde_json::from_slice(&read_at(state, "complete.json")?)?;
            ensure!(
                result["contract"] == contract,
                "completion concerns another collection"
            );
            return Ok(result);
        }
        if emptied {
            ensure!(
                intent && committed && !original,
                "inconsistent completed removal"
            );
            private_receipt(state, "empty.json", &contract)?;
        } else {
            ensure!(
                original != captured,
                "source and capture must be mutually exclusive"
            );
            ensure!(!captured || intent, "capture exists without intent");
            ensure!(
                !committed || captured,
                "unlink authority without captured tree"
            );
        }
        if original {
            let dir = open_at(root, SOURCE, libc::O_RDONLY | libc::O_DIRECTORY)?;
            check_dir(&dir, self.dir_id, true)?;
            census(&dir, table, true)?;
            drop(dir);
            if !exists_at(state, baseline_name)? {
                publish(
                    state,
                    baseline_name,
                    &json!({"available_bytes":free_bytes(root)?,"contract":contract}),
                )?;
            }
            private_receipt(state, "intent.json", &contract)?;
            gate("before-capture")?;
            self.recheck()?;
            check_dir(
                &open_at(root, SOURCE, libc::O_RDONLY | libc::O_DIRECTORY)?,
                self.dir_id,
                true,
            )?;
            rename_no_replace(root, SOURCE, state, CAPTURE)?;
            root.sync_all()?;
            state.sync_all()?;
        }
        private_receipt(state, "intent.json", &contract)?;
        let before: Value = serde_json::from_slice(&read_at(state, baseline_name)?)?;
        ensure!(
            before["contract"] == contract,
            "free-space baseline belongs to another run"
        );
        if !emptied {
            // While the entire closed tree is in the root-only operation directory, the
            // public name is absent. Keep the exact captured inode on failure for recovery.
            gate("after-capture")?;
            self.recheck()?;
            ensure!(
                !exists_at(root, SOURCE)?,
                "original collection path was recreated"
            );
            let dir = open_at(state, CAPTURE, libc::O_RDONLY | libc::O_DIRECTORY)?;
            check_dir(&dir, self.dir_id, false)?;
            let present = census(&dir, table, !committed)?;
            let tomb = private_child(state, TOMB)?;
            let interrupted = names(&tomb)?;
            ensure!(
                interrupted.len() <= 1 && (committed || interrupted.is_empty()),
                "invalid capture transaction state"
            );
            let mut journal = CaptureJournal::open(state, table.len())?;
            let ordered: Vec<_> = table.keys().collect();
            let index = journal.count;
            let pending = interrupted.first();
            let journaled_pending =
                pending.is_some() && index > 0 && pending == Some(ordered[index - 1]);
            if let Some(name) = pending {
                ensure!(
                    journaled_pending || Some(&name) == ordered.get(index),
                    "unexpected in-flight member"
                );
            }
            let new_pending = pending.is_some() && !journaled_pending;
            let expected_present: BTreeSet<_> = ordered
                .iter()
                .skip(index + usize::from(new_pending))
                .map(|s| (*s).clone())
                .collect();
            ensure!(
                present == expected_present,
                "remaining members disagree with durable capture journal"
            );
            ensure!(
                committed || (index == 0 && pending.is_none()),
                "missing authority for capture journal"
            );
            private_receipt(state, "unlink-authority.json", &contract)?;
            if let Some(name) = pending {
                let row = &table[name];
                let file = checked_member(&tomb, name, &row.0, true)?;
                ensure!(
                    file_digest(&file)? == row.1,
                    "interrupted capture digest differs: {name}"
                );
                if new_pending {
                    journal.confirm()?;
                }
                remove_captured(&tomb, name, row)?;
            }
            for name in present {
                let row = &table[&name];
                let original = checked_member(&dir, &name, &row.0, false)?;
                rename_no_replace(&dir, &name, &tomb, &name)?;
                dir.sync_all()?;
                tomb.sync_all()?;
                let taken = checked_member(&tomb, &name, &row.0, true)?;
                ensure!(
                    taken.metadata()?.ino() == original.metadata()?.ino(),
                    "capture switched inode"
                );
                journal.confirm()?;
                remove_captured(&tomb, &name, row)?;
            }
            ensure!(journal.count == table.len(), "incomplete capture journal");
            ensure!(
                names(&dir)?.is_empty() && names(&tomb)?.is_empty(),
                "nonempty capture after retirement"
            );
            private_receipt(state, "empty.json", &contract)?;
        }
        self.recheck()?;
        ensure!(
            !exists_at(root, SOURCE)?,
            "retired source name was recreated"
        );
        if exists_at(state, CAPTURE)? {
            let dir = open_at(state, CAPTURE, libc::O_RDONLY | libc::O_DIRECTORY)?;
            check_dir(&dir, self.dir_id, false)?;
            ensure!(names(&dir)?.is_empty(), "unapproved remaining files");
            rmdir(state, CAPTURE)?;
        }
        if exists_at(state, TOMB)? {
            rmdir(state, TOMB)?;
        }
        let available = free_bytes(root)?;
        let result = json!({"contract":contract,"removed_members":table.len(),"member_allocation_unlinked_bytes":allocation(table)?,"logical_bytes_unlinked":table.values().map(|(r,_)|r[2]).sum::<u64>(),"available_bytes_before":before["available_bytes"],"available_bytes_after":available,"r2_mutations":false,"reservation_ending_bytes":0});
        publish(state, "complete.json", &result)?;
        Ok(result)
    }
}
