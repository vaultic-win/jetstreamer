use super::*;
use crate::journal::Journal;
pub trait Volume {
    fn state(&self) -> io::Result<(bool, bool)>;
    fn allocated(&self) -> io::Result<u64>;
    fn trim(&self) -> io::Result<String>;
    fn remount_ro(&self) -> io::Result<()>;
    fn block_ro(&self) -> io::Result<()>;
    fn verify(&self) -> io::Result<()>;
}
pub struct Original;
impl Volume for Original {
    fn state(&self) -> io::Result<(bool, bool)> {
        let m = fs::read_to_string("/proc/self/mountinfo")?;
        let rows: Vec<_> = m
            .lines()
            .filter_map(|l| {
                let x: Vec<_> = l.split_whitespace().collect();
                (x.get(4) == Some(&retained::ROOT)).then_some(x)
            })
            .collect();
        need(rows.len() == 1, "ambiguous mount")?;
        let r = &rows[0];
        need(
            r[0].parse::<u64>().ok() == Some(MOUNT)
                && r[2] == format!("7:{}", DEVICE & 255)
                && r[3] == "/"
                && r[r.len() - 3] == "ext4"
                && r[r.len() - 2] == retained::LOOP,
            "wrong host mount",
        )?;
        let mro = r[5].split(',').any(|s| s == "ro");
        need(
            mro == r.last().unwrap().split(',').any(|s| s == "ro"),
            "vfs/superblock read-only disagreement",
        )?;
        let block = fs::read_to_string(format!("/sys/block/loop{}/ro", DEVICE & 255))?;
        need(matches!(block.trim(), "0" | "1"), "loop RO state")?;
        Ok((mro, block.trim() == "1"))
    }
    fn allocated(&self) -> io::Result<u64> {
        let m = fs::symlink_metadata(retained::IMAGE)?;
        need(
            m.dev() == 66305
                && m.ino() == IMAGE_INODE
                && m.len() == IMAGE_SIZE
                && m.is_file()
                && m.nlink() == 1
                && m.uid() == 0
                && m.mode() & 0o077 == 0
                && fs::read_to_string(format!(
                    "/sys/block/loop{}/loop/backing_file",
                    DEVICE & 255
                ))?
                .trim()
                    == retained::IMAGE,
            "backing identity",
        )?;
        Ok(m.blocks() * 512)
    }
    fn trim(&self) -> io::Result<String> {
        controller::command("/usr/sbin/fstrim", &["--verbose", "--", retained::ROOT])
    }
    fn remount_ro(&self) -> io::Result<()> {
        controller::command(
            "/usr/bin/mount",
            &["-o", "remount,ro,nosuid,nodev", retained::ROOT],
        )
        .map(|_| ())
    }
    fn block_ro(&self) -> io::Result<()> {
        controller::command("/usr/sbin/blockdev", &["--setro", retained::LOOP]).map(|_| ())
    }
    fn verify(&self) -> io::Result<()> {
        let p = Path::new(preservation::RUN).join("archives/epoch-266.jet");
        match OpenOptions::new()
            .write(true)
            .custom_flags(NOFOLLOW)
            .open(p)
        {
            Err(e) if e.raw_os_error() == Some(30) => (),
            _ => {
                return Err(io::Error::other(
                    "partial archive accepted write-open or wrong errno",
                ));
            }
        };
        retained::manifest()?;
        preservation::originals()?;
        Ok(())
    }
}
fn record(
    j: &Journal,
    name: &str,
    previous: &str,
    field: &str,
    actual: u64,
) -> io::Result<(String, u64)> {
    let v = j
        .get(name)?
        .unwrap_or_else(|| format!("{previous}{field}={actual}\n"));
    let n = v
        .strip_prefix(previous)
        .and_then(|s| s.strip_prefix(field))
        .and_then(|s| s.strip_prefix('='))
        .and_then(|s| s.strip_suffix('\n'))
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| io::Error::other("invalid closure chain"))?;
    need(n <= IMAGE_SIZE, "bad backing allocation")?;
    j.put(name, &v)?;
    Ok((v, n))
}
pub fn close(
    v: &impl Volume,
    j: &Journal,
    b: &str,
    gate: &mut impl FnMut(bool) -> io::Result<()>,
) -> io::Result<()> {
    let i = j
        .get("retired")?
        .ok_or_else(|| io::Error::other("missing retirement receipt"))?;
    let start = retirement::validate_intent(&i, b)?;
    need(
        j.get("intent")?.as_deref() == Some(&i) && j.get("empty")?.as_deref() == Some(&i),
        "original intent/empty missing",
    )?;
    gate(false)?;
    let (m, blk) = v.state()?;
    need(m || !blk, "block RO with a writable mount")?;
    let before_old = j.get("trim-baseline")?;
    let trimmed = j.get("trimmed")?;
    if m {
        need(
            trimmed.is_some() && before_old.is_some(),
            "unexplained prior readonly closure",
        )?;
    }
    need(
        trimmed.is_none() || before_old.is_some(),
        "trim receipt missing original baseline",
    )?;
    let (before, baseline) = record(j, "trim-baseline", &i, "pretrim", v.allocated()?)?;
    if trimmed.is_none() {
        need(!m && !blk, "cannot trim readonly volume")?;
        gate(false)?;
        if j.get("trim-output")?.is_none() {
            let out = v.trim()?;
            need(!out.is_empty() && out.len() < 4096, "trim output bound")?;
            let allocation = v.allocated()?;
            need(
                allocation < start && allocation <= baseline,
                "trim did not yield measurable backing recovery",
            )?;
            j.put("trim-output", &format!("{before}fstrim={out}"))?;
        }
    }
    let output = j
        .get("trim-output")?
        .ok_or_else(|| io::Error::other("missing filesystem trim receipt"))?;
    need(
        output.starts_with(&format!("{before}fstrim=")),
        "inconsistent filesystem trim receipt",
    )?;
    let current = v.allocated()?;
    if trimmed.is_none() {
        need(
            current < start && current <= baseline,
            "invalid post-trim allocation",
        )?;
    }
    let (after, measured) = record(j, "trimmed", &output, "posttrim", current)?;
    need(
        measured < start && measured <= baseline,
        "no demonstrated physical reclamation",
    )?;
    gate(false)?;
    if !m {
        v.remount_ro()?;
    }
    let (m, blk) = v.state()?;
    need(m, "mount still writable")?;
    if !blk {
        v.block_ro()?;
    }
    need(v.state()? == (true, true), "failed mount/block closure")?;
    gate(true)?;
    v.verify()?;
    let a = v.allocated()?;
    need(a < start && a <= IMAGE_SIZE, "final allocation")?;
    let (receipt, final_bytes) = record(j, "closed", &after, "final", a)?;
    need(final_bytes == a, "backing changed since closure")?;
    println!(
        "{receipt}measured_reclaimed={}\ncapacity_credit=0",
        start - final_bytes
    );
    Ok(())
}
