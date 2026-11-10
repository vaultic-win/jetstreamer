#![recursion_limit = "512"]
//! Metadata-only Root review; never native Frame, full Reader, admission or release authority.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
type R<T> = Result<T, Box<dyn std::error::Error>>;
const IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-fulfilled-owned-disk-tools-20261110-v3/check";
const NOFOLLOW: i32 = 0x20000;
const CLOEXEC: i32 = 0x80000;
const FIELDS: &str = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Result,ExecMainStatus,ControlGroup,Type,Job,MemoryMax,MemorySwapMax,MemoryAccounting,Restart,Delegate,KillMode";
fn need(ok: bool, why: &str) -> R<()> {
    if ok { Ok(()) } else { Err(why.into()) }
}
fn s<'a>(v: &'a Value, k: &str) -> R<&'a str> {
    v[k].as_str()
        .ok_or_else(|| format!("missing string {k}").into())
}
fn n(v: &Value, k: &str) -> R<u64> {
    v[k].as_u64()
        .ok_or_else(|| format!("missing integer {k}").into())
}
fn sha(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
fn now() -> R<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn ident(m: &fs::Metadata) -> Value {
    json!([
        m.dev(),
        m.ino(),
        m.mode(),
        m.uid(),
        m.gid(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec()
    ])
}
fn raw(path: &Path) -> R<Vec<u8>> {
    need(
        path.is_absolute() && path.canonicalize()? == path,
        "canonical metadata path required",
    )?;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(NOFOLLOW | CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    need(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.len() <= 32 << 20,
        "unsafe Root metadata",
    )?;
    let mut b = Vec::new();
    Read::by_ref(&mut f)
        .take((32 << 20) + 1)
        .read_to_end(&mut b)?;
    need(
        b.len() as u64 == m.len()
            && ident(&m) == ident(&f.metadata()?)
            && ident(&m) == ident(&fs::symlink_metadata(path)?),
        "metadata changed",
    )?;
    Ok(b)
}
fn bound(b: &Value) -> R<Value> {
    let bytes = raw(Path::new(s(b, "path")?))?;
    need(
        sha(&bytes) == s(b, "sha256")?,
        "bound metadata digest mismatch",
    )?;
    Ok(serde_json::from_slice(&bytes)?)
}
fn durable(path: &Path, value: &Value) -> R<()> {
    let parent = path.parent().ok_or("output parent")?;
    need(
        parent.is_absolute() && parent.canonicalize()? == parent,
        "canonical output parent required",
    )?;
    let m = fs::symlink_metadata(parent)?;
    need(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "private Root output parent required",
    )?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(NOFOLLOW | CLOEXEC)
        .open(path)?;
    serde_json::to_writer_pretty(&mut f, value)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn command(args: &[&str], cap: usize) -> R<String> {
    let out = Command::new("/usr/bin/systemctl")
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
        .env_remove("SYSTEMD_BUS_ADDRESS")
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env_remove("SYSTEMD_HOST")
        .args(args)
        .output()?;
    need(
        out.status.success() && out.stderr.is_empty() && out.stdout.len() <= cap,
        "systemd metadata capture failed",
    )?;
    Ok(String::from_utf8(out.stdout)?)
}
fn unit_name(name: &str) -> R<()> {
    need(
        !name.starts_with('-')
            && (name.ends_with(".service") || name.ends_with(".timer"))
            && name.bytes().all(|b| (33..127).contains(&b)),
        "invalid unit name",
    )
}
fn native(name: &str) -> R<Value> {
    unit_name(name)?;
    let text = command(&["show", name, "--no-pager", "-p", FIELDS], 65536)?;
    let mut v = serde_json::Map::new();
    for line in text.lines() {
        let (k, x) = line.split_once('=').ok_or("native delimiter")?;
        need(
            v.insert(k.into(), json!(x)).is_none(),
            "duplicate native property",
        )?;
    }
    for key in ["Id", "LoadState", "ActiveState", "SubState", "InvocationID"] {
        need(
            v.get(key).is_some_and(Value::is_string),
            "incomplete native metadata",
        )?;
    }
    Ok(Value::Object(v))
}

use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};
const ROOT_CAP: u64 = 309_237_645_312;
const DATA: u64 = 6_582_025_928_498;
const MEMORY: u64 = 759_789_531_136;
const MARGIN: u64 = 1 << 30;
fn dir(path: &Path) -> R<File> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(65536 | NOFOLLOW | CLOEXEC)
        .open(path)?)
}
fn debit(blocks: u64, links: u64, regular: bool) -> R<u64> {
    if regular && links == 1 {
        blocks
            .checked_mul(512)
            .ok_or_else(|| "physical block overflow".into())
    } else {
        Ok(0)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Fact {
    root: usize,
    blocks: u64,
    length: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
    birth: u128,
}
#[derive(Default)]
struct Seen {
    facts: BTreeMap<(u64, u64), Fact>,
    uncertain: BTreeSet<(u64, u64)>,
    current_root: usize,
}
impl Seen {
    fn record(&mut self, m: &fs::Metadata) -> R<bool> {
        let key = (m.dev(), m.ino());
        if self.facts.contains_key(&key) {
            self.uncertain.insert(key);
            return Ok(false);
        }
        if debit(m.blocks(), m.nlink(), m.is_file())? < 512 {
            return Ok(true);
        }
        let fact = Fact {
            root: self.current_root,
            blocks: m.blocks(),
            length: m.len(),
            mtime: m.mtime(),
            mtime_nsec: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_nsec: m.ctime_nsec(),
            birth: m.created()?.duration_since(UNIX_EPOCH)?.as_nanos(),
        };
        self.facts.insert(key, fact);
        need(
            self.facts.len() <= 4_000_000,
            "bounded stable-file fact table exceeded",
        )?;
        Ok(true)
    }
    fn digest(&self) -> String {
        let mut h = Sha256::new();
        for ((dev, ino), f) in &self.facts {
            for x in [
                *dev,
                *ino,
                f.root as u64,
                f.blocks,
                f.length,
                f.mtime as u64,
                f.mtime_nsec as u64,
                f.ctime as u64,
                f.ctime_nsec as u64,
            ] {
                h.update(x.to_le_bytes());
            }
            h.update(f.birth.to_le_bytes());
            h.update([u8::from(self.uncertain.contains(&(*dev, *ino)))]);
        }
        format!("{:x}", h.finalize())
    }
}
fn common_allocations(first: &Seen, second: &Seen, count: usize) -> R<Vec<u64>> {
    let mut sums = vec![0u64; count];
    for (key, a) in &first.facts {
        if first.uncertain.contains(key) || second.uncertain.contains(key) {
            continue;
        }
        if second.facts.get(key) == Some(a) {
            need(a.root < count, "stable root index mismatch")?;
            sums[a.root] = sums[a.root]
                .checked_add(a.blocks.checked_mul(512).ok_or("physical overflow")?)
                .ok_or("stable sum overflow")?;
        }
    }
    Ok(sums)
}
#[derive(Default)]
struct Scan {
    bytes: u64,
    entries: u64,
    excluded_multiple_links: u64,
    vanished: u64,
}
fn walk(
    fd: &File,
    dev: u64,
    seen: &mut Seen,
    depth: u32,
    out: &mut Scan,
    deadline: Instant,
) -> R<()> {
    need(
        depth <= 128 && Instant::now() < deadline,
        "physical scan depth/time bound exceeded",
    )?;
    let m = fd.metadata()?;
    need(m.is_dir() && m.dev() == dev, "directory device changed")?;
    let anchored = std::path::PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()));
    for item in fs::read_dir(&anchored)? {
        need(Instant::now() < deadline, "physical scan deadline expired")?;
        let path = item?.path();
        let m = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                out.vanished += 1;
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        need(
            m.dev() == dev && !m.file_type().is_symlink(),
            "foreign filesystem or symlink in owned root",
        )?;
        out.entries = out.entries.checked_add(1).ok_or("entries overflow")?;
        need(out.entries <= 8_000_000, "entry bound exceeded")?;
        if m.is_dir() {
            let child = match dir(&path) {
                Ok(f) => f,
                Err(e)
                    if e.downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
                {
                    out.vanished += 1;
                    continue;
                }
                Err(e) => return Err(e),
            };
            let cm = child.metadata()?;
            need(
                cm.dev() == m.dev() && cm.ino() == m.ino(),
                "child directory replaced",
            )?;
            walk(&child, dev, seen, depth + 1, out, deadline)?;
        } else {
            need(m.is_file(), "nonregular owned entry")?;
            if m.nlink() != 1 {
                out.excluded_multiple_links += 1;
                continue;
            }
            if seen.record(&m)? {
                out.bytes = out
                    .bytes
                    .checked_add(debit(m.blocks(), m.nlink(), m.is_file())?)
                    .ok_or("physical sum overflow")?;
            }
        }
    }
    Ok(())
}
fn scan(root: &Path, seen: &mut Seen, deadline: Instant) -> R<Value> {
    need(
        root.is_absolute() && root.canonicalize()? == root,
        "canonical owned root required",
    )?;
    let fd = dir(root)?;
    let m = fd.metadata()?;
    let mut out = Scan::default();
    walk(&fd, m.dev(), seen, 0, &mut out, deadline)?;
    let after = fs::symlink_metadata(root)?;
    need(
        after.is_dir()
            && after.dev() == m.dev()
            && after.ino() == m.ino()
            && root.canonicalize()? == root,
        "owned root replaced",
    )?;
    Ok(
        json!({"regular_unique_physical_bytes":out.bytes,"entries":out.entries,"excluded_multiple_link_entries":out.excluded_multiple_links,"vanished_entries":out.vanished,"device":m.dev(),"inode":m.ino()}),
    )
}
fn fulfilled(a: u64, b: u64) -> R<u64> {
    need(
        a <= ROOT_CAP && b <= ROOT_CAP,
        "observed owned allocation exceeds unchanged root cap",
    )?;
    Ok(a.min(b).saturating_sub(MARGIN))
}
fn remaining(data: u64, consumed: u64, candidate: u64) -> R<u64> {
    need(
        data == DATA && candidate == ROOT_CAP + (8 << 30),
        "exact full retained DATA and candidate envelope required",
    )?;
    data.checked_sub(consumed)
        .and_then(|n| n.checked_add(candidate))
        .ok_or_else(|| "remaining DATA arithmetic overflow".into())
}
fn fs_free(program: &Value) -> R<Value> {
    let path = Path::new(s(program, "path")?);
    need(
        path == Path::new("/usr/bin/stat") && sha(&raw(path)?) == s(program, "sha256")?,
        "exact stat filesystem reader required",
    )?;
    let out = Command::new(path)
        .args(["--file-system", "--format=%a %S %t", "--", "/home/sol"])
        .output()?;
    need(
        out.status.success() && out.stderr.is_empty() && out.stdout.len() < 1024,
        "filesystem stat failed",
    )?;
    let line = String::from_utf8(out.stdout)?;
    let v = line.split_whitespace().collect::<Vec<_>>();
    need(
        v.len() == 3 && v[2] == "ef53",
        "only ext filesystem without shared reflink extents is qualified",
    )?;
    let available = v[0]
        .parse::<u64>()?
        .checked_mul(v[1].parse::<u64>()?)
        .ok_or("filesystem free overflow")?;
    Ok(
        json!({"available_bytes":available,"filesystem_magic":v[2],"raw_sha256":sha(line.as_bytes())}),
    )
}
fn owner(actual: &Value, expected: &Value) -> R<()> {
    for key in ["Id", "InvocationID", "MainPID"] {
        need(
            actual[key] == expected[key],
            "owned producer identity changed",
        )?;
    }
    need(
        actual["ActiveState"] == "active"
            && actual["SubState"] == "running"
            && actual["NRestarts"] == "0"
            && actual["Restart"] == "no"
            && actual["MemoryMax"] == "73014444032"
            && actual["MemorySwapMax"] == "0",
        "owned producer is not original guarded68GiB actor",
    )
}
fn run() -> R<()> {
    let a = std::env::args().collect::<Vec<_>>();
    need(
        a.len() == 6 && a[2] == "--plan-sha256" && a[4] == "--self-sha256",
        "exact argv required",
    )?;
    let image = fs::read_link("/proc/self/exe")?;
    need(
        image == Path::new(IMAGE) && sha(&raw(&image)?) == a[5],
        "normally sealed own image required",
    )?;
    let plan = bound(&json!({"path":a[1],"sha256":a[3]}))?;
    need(
        plan["schema"] == "horizon-fulfilled-owned-disk-plan-v1"
            && plan["owner"] == "/root"
            && plan["primary_thread"] == "01a1af2a-9ce8-76a2-8939-b2112bd38f53",
        "exclusive Root plan required",
    )?;
    let head = bound(&plan["current_complete_authority"])?;
    need(
        head["schema"] == "horizon-Root-conservative-duplicate722-addback-current-authority-v1"
            && head["complete_DATA_bytes"] == DATA
            && head["complete_projected_memory_bytes"] == MEMORY
            && head["restored_conservative_actor48_bytes"] == 48u64 << 30
            && head["restored_conservative_future_DATA_bytes"] == 480_969_228_288u64
            && head["new_memory_or_DATA_credit_bytes"] == 0,
        "exact corrected conservative authority required",
    )?;
    let fleet = bound(&plan["current_fleet"])?;
    need(
        fleet["complete_DATA_authority"] == plan["current_complete_authority"]
            && fleet["live_replay_count"] == 7
            && fleet["proven_replay_count"] == 7,
        "complete seven-owner corrected fleet required",
    )?;
    let handoffs = bound(&plan["all_corrected_guard_handoffs"])?;
    need(
        handoffs["all_seven_original_producers_preserved"] == true
            && handoffs["no_guard_gap"] == true
            && handoffs["temporary_extra_guard_bytes"] == 0,
        "genuine continuous corrected seven-guard handoff required",
    )?;
    let mine = native("horizon-fulfilled-owned-disk-qualification-20261110-v3.service")?;
    need(
        mine["InvocationID"] == std::env::var("INVOCATION_ID")?
            && s(&mine, "MainPID")?.parse::<u32>()? == std::process::id()
            && mine["MemoryMax"] == "1073741824"
            && mine["MemorySwapMax"] == "0"
            && mine["NRestarts"] == "0"
            && mine["Restart"] == "no",
        "funded1GiB native identity required",
    )?;
    let rows = fleet["actual_executing_replays"]
        .as_array()
        .ok_or("seven actor rows")?;
    need(rows.len() == 7, "exact seven actors required")?;
    let mut epochs = BTreeSet::new();
    let mut roots = BTreeSet::new();
    let mut actors = BTreeMap::new();
    let mut declarations = Vec::new();
    for row in rows {
        let e = n(row, "epoch")?;
        need(
            (166..=172).contains(&e) && epochs.insert(e),
            "wrong/duplicate epoch",
        )?;
        let name = s(&row["unit"], "Id")?;
        let actual = native(name)?;
        owner(&actual, &row["unit"])?;
        actors.insert(name.to_owned(), actual);
        let h = handoffs["handoffs"]
            .as_array()
            .ok_or("handoff rows")?
            .iter()
            .map(bound)
            .collect::<R<Vec<_>>>()?
            .into_iter()
            .find(|h| h["epoch"] == e)
            .ok_or("missing exact actor guard handoff")?;
        let policy = bound(&h["new_plan"])?;
        let date = if e < 171 { "20261109" } else { "20261110" };
        let root = format!("/home/sol/.jetstreamer-private/epoch{e}-standard-lane-{date}-v1");
        need(
            policy["unit"] == name
                && policy["invocation_id"] == row["unit"]["InvocationID"]
                && policy["worker_root"] == root
                && policy["maximum_root_physical_bytes"] == ROOT_CAP
                && policy["minimum_free_bytes"] == 6_264_131_239_730u64
                && roots.insert(root.clone()),
            "exact disjoint existing guarded root budget required",
        )?;
        declarations.push((e, name.to_owned(), root));
    }
    let started = Instant::now();
    let deadline = started + Duration::from_secs(180);
    let target_dev = fs::metadata("/home/sol")?.dev();
    let before_fs = fs_free(&plan["filesystem_reader"])?;
    let mut first = Vec::new();
    let mut seen = Seen::default();
    let mut last_log = Instant::now();
    for (e, _, root) in &declarations {
        seen.current_root = first.len();
        let value = scan(Path::new(root), &mut seen, deadline)?;
        need(
            value["device"] == target_dev,
            "owned root is on a different filesystem",
        )?;
        first.push(value);
        if last_log.elapsed().as_secs() >= 30 {
            eprintln!(
                "first physical pass epoch{e} complete after{}s; prior guards preserved",
                started.elapsed().as_secs()
            );
            last_log = Instant::now();
        }
    }
    let midpoint_fs = fs_free(&plan["filesystem_reader"])?;
    let mut second_seen = Seen::default();
    let mut second = Vec::new();
    for (e, _, root) in &declarations {
        second_seen.current_root = second.len();
        let value = scan(Path::new(root), &mut second_seen, deadline)?;
        need(
            value["device"] == target_dev,
            "owned root filesystem changed",
        )?;
        second.push(value);
        if last_log.elapsed().as_secs() >= 30 {
            eprintln!(
                "second physical pass epoch{e} complete after{}s; no floor mutation",
                started.elapsed().as_secs()
            );
            last_log = Instant::now();
        }
    }
    let common = common_allocations(&seen, &second_seen, declarations.len())?;
    let after_fs = fs_free(&plan["filesystem_reader"])?;
    let mut total = 0u64;
    let mut owners_after = BTreeMap::new();
    let mut amounts = Vec::new();
    for (i, (e, name, root)) in declarations.iter().enumerate() {
        let after = native(name)?;
        owner(&after, &actors[name])?;
        let value = fulfilled(common[i], common[i])?;
        total = total.checked_add(value).ok_or("sum overflow")?;
        owners_after.insert(name.clone(), after);
        amounts.push(json!({"epoch":e,"root":root,"full_unchanged_root_cap_bytes":ROOT_CAP,"first":first[i],"second":second[i],"unchanged_files_present_across_midpoint_bytes":common[i],"already_allocated_unique_physical_bytes_after_margin":value,"additional_margin_bytes":MARGIN}));
    }
    need(
        bound(&plan["current_complete_authority"])? == head
            && bound(&plan["current_fleet"])? == fleet
            && started.elapsed().as_secs() <= 180,
        "authority changed or finite sample expired",
    )?;
    let free = n(&before_fs, "available_bytes")?
        .min(n(&midpoint_fs, "available_bytes")?)
        .min(n(&after_fs, "available_bytes")?);
    let required = remaining(DATA, total, ROOT_CAP + (8 << 30))?;
    let out = json!({"schema":"horizon-fulfilled-owned-disk-native-check-v1","owner":"/root","primary_thread":plan["primary_thread"],"plan":plan,"recorded_unix_seconds":now()?,"planning_sample_expires_unix_seconds":now()?.checked_add(300).ok_or("expiry overflow")?,"native_self":mine,"producer_before":actors,"producer_after":owners_after,"filesystem_before":before_fs,"filesystem_midpoint":midpoint_fs,"filesystem_after":after_fs,"first_fact_sha256":seen.digest(),"second_fact_sha256":second_seen.digest(),"first_eligible_file_count":seen.facts.len(),"second_eligible_file_count":second_seen.facts.len(),"first_uncertain_inode_count":seen.uncertain.len(),"second_uncertain_inode_count":second_seen.uncertain.len(),"fulfillment_basis":"Only singly linked ext files with allocated512-byte blocks with identical device/inode, root, size, allocated blocks, birthtime, ctime and mtime in both passes; uncertain repeated inodes are excluded. Free space captured at their common between-pass midpoint; no descriptors retained and no reservation ended.","owned_root_allocations":amounts,"complete_unchanged_DATA_promises_bytes":DATA,"candidate_additive_root_and_guard_metadata_bytes":ROOT_CAP+(8<<30),"already_allocated_bytes_inside_those_unchanged_caps":total,"required_free_for_remaining_promises_and_candidate_bytes":required,"conservative_available_bytes":free,"candidate_disk_fits_this_native_sample":free>=required,"physical_bytes_retired_or_offloaded":0,"DATA_promises_ended_bytes":0,"new_resource_credit_bytes":0,"memory_fit_not_checked":true,"producer_guard_timer_mutations":false,"remote_mutations":false,"new_resource_observations":true,"observation_reason":"admission-qualification","routine_cadence_reset":false,"replay_admission_authorized":false,"next_gate":"Fresh admission must recheck this complete owned-root accounting plus memory and current inputs, then qualify any actual continuous guard-floor handoff. This finite disk result does not lower a guard or select an ending."});
    durable(Path::new(s(&plan, "output")?), &out)?;
    println!(
        "{}",
        json!({"output":plan["output"],"already_allocated_inside_unchanged_caps_bytes":total,"required_free_bytes":required,"available_bytes":free,"disk_fits":free>=required,"replay_admission_authorized":false})
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Temp(std::path::PathBuf);
    impl Temp {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "owned-disk-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            ));
            fs::create_dir(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    #[test]
    fn multiply_linked_file_is_never_consumed_twice() {
        assert_eq!(debit(16, 2, true).unwrap(), 0);
        assert_eq!(debit(16, 1, true).unwrap(), 8192);
        assert_eq!(debit(16, 1, false).unwrap(), 0);
    }
    #[test]
    fn physical_arithmetic_overflow_rejected() {
        assert!(debit(u64::MAX, 1, true).is_err());
    }
    #[test]
    fn zero_and_margin_have_no_credit() {
        assert_eq!(fulfilled(0, 1 << 30).unwrap(), 0);
        assert_eq!(fulfilled(1 << 30, 2 << 30).unwrap(), 0);
    }
    #[test]
    fn smaller_endpoint_and_margin_used() {
        assert_eq!(fulfilled(5 << 30, 4 << 30).unwrap(), 3 << 30);
    }
    #[test]
    fn cap_excess_is_failed_gate() {
        assert!(fulfilled(ROOT_CAP + 1, 1).is_err());
    }
    #[test]
    fn exact_candidate_and_full_promises_preserved() {
        assert_eq!(
            remaining(DATA, 500 << 30, ROOT_CAP + (8 << 30)).unwrap(),
            DATA - (500 << 30) + ROOT_CAP + (8 << 30)
        );
        assert!(remaining(DATA - 1, 0, ROOT_CAP + (8 << 30)).is_err());
    }
    #[test]
    fn crossed_candidate_and_consumed_overflow_rejected() {
        assert!(remaining(DATA, 0, ROOT_CAP).is_err());
        assert!(remaining(DATA, DATA + 1, ROOT_CAP + (8 << 30)).is_err());
    }
    #[test]
    fn hardlink_is_excluded_and_sparse_apparent_length_not_counted() {
        let t = Temp::new();
        let f = t.0.join("file");
        fs::write(&f, vec![7u8; 16384]).unwrap();
        fs::hard_link(&f, t.0.join("other")).unwrap();
        let sparse = File::create(t.0.join("sparse")).unwrap();
        sparse.set_len(1 << 40).unwrap();
        let s = scan(
            &t.0,
            &mut Seen::default(),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(s["excluded_multiple_link_entries"], 2);
        assert!(n(&s, "regular_unique_physical_bytes").unwrap() < 1 << 20);
    }
    #[test]
    fn small_stable_allocation_is_counted_and_sparse_length_is_not() {
        let t = Temp::new();
        fs::write(t.0.join("small"), vec![9u8; 4096]).unwrap();
        File::create(t.0.join("sparse"))
            .unwrap()
            .set_len(1 << 40)
            .unwrap();
        let mut a = Seen::default();
        let mut b = Seen::default();
        scan(&t.0, &mut a, Instant::now() + Duration::from_secs(5)).unwrap();
        scan(&t.0, &mut b, Instant::now() + Duration::from_secs(5)).unwrap();
        let total = common_allocations(&a, &b, 1).unwrap()[0];
        assert!(total >= 4096 && total < 1 << 20);
    }
    #[test]
    fn stable_file_is_present_across_both_passes() {
        let t = Temp::new();
        fs::write(t.0.join("file"), vec![1u8; 2 << 20]).unwrap();
        let mut a = Seen::default();
        let mut b = Seen::default();
        scan(&t.0, &mut a, Instant::now() + Duration::from_secs(5)).unwrap();
        scan(&t.0, &mut b, Instant::now() + Duration::from_secs(5)).unwrap();
        assert!(common_allocations(&a, &b, 1).unwrap()[0] >= 2 << 20);
    }
    #[test]
    fn cross_root_inode_move_is_never_credited() {
        let a = Temp::new();
        let b = Temp::new();
        fs::write(a.0.join("file"), vec![1u8; 2 << 20]).unwrap();
        let mut first = Seen::default();
        scan(&a.0, &mut first, Instant::now() + Duration::from_secs(5)).unwrap();
        fs::rename(a.0.join("file"), b.0.join("moved")).unwrap();
        let mut second = Seen {
            current_root: 1,
            ..Seen::default()
        };
        scan(&b.0, &mut second, Instant::now() + Duration::from_secs(5)).unwrap();
        assert_eq!(common_allocations(&first, &second, 2).unwrap(), vec![0, 0]);
    }
    #[test]
    fn rewritten_same_size_file_has_no_stable_credit() {
        let t = Temp::new();
        let p = t.0.join("file");
        fs::write(&p, vec![1u8; 2 << 20]).unwrap();
        let mut a = Seen::default();
        scan(&t.0, &mut a, Instant::now() + Duration::from_secs(5)).unwrap();
        std::thread::sleep(Duration::from_millis(2));
        fs::write(&p, vec![2u8; 2 << 20]).unwrap();
        let mut b = Seen::default();
        scan(&t.0, &mut b, Instant::now() + Duration::from_secs(5)).unwrap();
        assert_eq!(common_allocations(&a, &b, 1).unwrap()[0], 0);
    }
    #[test]
    fn duplicated_inode_in_either_pass_is_excluded() {
        let t = Temp::new();
        fs::write(t.0.join("file"), vec![1u8; 2 << 20]).unwrap();
        let mut a = Seen::default();
        scan(&t.0, &mut a, Instant::now() + Duration::from_secs(5)).unwrap();
        scan(&t.0, &mut a, Instant::now() + Duration::from_secs(5)).unwrap();
        let mut b = Seen::default();
        scan(&t.0, &mut b, Instant::now() + Duration::from_secs(5)).unwrap();
        assert_eq!(common_allocations(&a, &b, 1).unwrap()[0], 0);
        assert_eq!(common_allocations(&b, &a, 1).unwrap()[0], 0);
    }
    #[test]
    fn symlinks_are_rejected_without_following() {
        use std::os::unix::fs::symlink;
        let t = Temp::new();
        symlink("/", t.0.join("outside")).unwrap();
        assert!(
            scan(
                &t.0,
                &mut Seen::default(),
                Instant::now() + Duration::from_secs(5)
            )
            .is_err()
        );
    }
    #[test]
    fn expired_deadline_rejects_instead_of_partial_sum() {
        let t = Temp::new();
        assert!(
            scan(
                &t.0,
                &mut Seen::default(),
                Instant::now() - Duration::from_secs(1)
            )
            .is_err()
        );
    }
    #[test]
    fn identity_change_is_not_fulfillment() {
        let a = json!({"Id":"x.service","InvocationID":"a","MainPID":"7","ActiveState":"active","SubState":"running","NRestarts":"0","Restart":"no","MemoryMax":"73014444032","MemorySwapMax":"0"});
        assert!(owner(&a, &a).is_ok());
        let mut b = a.clone();
        b["InvocationID"] = json!("b");
        assert!(owner(&b, &a).is_err());
    }
}
