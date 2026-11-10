//! Read-only auxiliary view of an already recorded retirement; never a fresh Frame.
use anyhow::{Context, Result, ensure};
use horizon_original199_parent_memory::{held_future_data_census, model::Bound};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
const IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-original199-future-DATA-tools-20261110-v1/check";
const OWN: &str = "horizon-original199-future-DATA-check-20261110-v1.service";
const PRIMARY: &str = "01a1af2a-9ce8-76a2-8939-b2112bd38f53";
const BEFORE: u64 = 645_972_897_792;
const REDUCTION: u64 = 320 << 30;
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("missing {k}"))
}
fn identity(m: &fs::Metadata) -> Value {
    json!([
        m.dev(),
        m.ino(),
        m.mode(),
        m.uid(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec()
    ])
}
fn raw(p: &Path) -> Result<Vec<u8>> {
    ensure!(
        p.is_absolute() && p.canonicalize()? == p,
        "canonical input required"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.len() <= 32 << 20,
        "metadata custody/size differs"
    );
    let mut b = Vec::new();
    Read::by_ref(&mut f)
        .take((32 << 20) + 1)
        .read_to_end(&mut b)?;
    ensure!(
        b.len() as u64 == m.len()
            && identity(&m) == identity(&f.metadata()?)
            && identity(&m) == identity(&fs::symlink_metadata(p)?),
        "metadata identity changed"
    );
    Ok(b)
}
fn bound(b: &Value) -> Result<Value> {
    let bytes = raw(Path::new(text(b, "path")?))?;
    ensure!(sha(&bytes) == text(b, "sha256")?, "bound digest differs");
    Ok(serde_json::from_slice(&bytes)?)
}
fn native(name: &str) -> Result<Value> {
    ensure!(
        !name.starts_with('-')
            && name.ends_with(".service")
            && name.bytes().all(|b| (33..127).contains(&b)),
        "invalid service name"
    );
    let o=Command::new("/usr/bin/systemctl").env_remove("DBUS_SYSTEM_BUS_ADDRESS").env_remove("SYSTEMD_BUS_ADDRESS").env_remove("DBUS_SESSION_BUS_ADDRESS").env_remove("SYSTEMD_HOST").args(["show",name,"--no-pager","-pId,InvocationID,ActiveState,SubState,MainPID,ControlPID,NRestarts,Job,MemoryMax,MemorySwapMax,Restart"]).output()?;
    ensure!(
        o.status.success() && o.stderr.is_empty() && o.stdout.len() < 65536,
        "native query failed"
    );
    let mut m = serde_json::Map::new();
    for line in std::str::from_utf8(&o.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("native delimiter")?;
        ensure!(
            m.insert(k.into(), json!(v)).is_none(),
            "duplicate native field"
        );
    }
    Ok(Value::Object(m))
}
fn matches(actual: &Value, expected: &Value) -> Result<()> {
    ensure!(
        actual["ActiveState"] == "active"
            && actual["SubState"] == "running"
            && actual["ControlPID"] == "0"
            && actual["NRestarts"] == "0"
            && actual["MainPID"]
                .as_str()
                .is_some_and(|v| v.parse::<u64>().is_ok_and(|p| p > 0)),
        "owner not stable/running"
    );
    for k in ["Id", "InvocationID", "MainPID"] {
        ensure!(actual[k] == expected[k], "live owner identity changed: {k}");
    }
    Ok(())
}
fn owners(fleet: &Value) -> Result<Value> {
    let rows = fleet["actual_executing_replays"]
        .as_array()
        .context("five replay census")?;
    ensure!(rows.len() == 5, "exact five-replay context required");
    let mut m = serde_json::Map::new();
    let stable = fleet["stable_non_replay_owners"]
        .as_object()
        .context("stable background owners")?;
    ensure!(
        stable.len() == 2
            && stable.contains_key(
                "horizon-r2-progressive-epochs101-200-v21-rust-authenticated.service"
            )
            && stable
                .contains_key("jetstreamer-epoch199-backfill-20261102-controller-v1-r2.service"),
        "exact stable background owners required"
    );
    for expected in rows.iter().map(|row| &row["unit"]).chain(stable.values()) {
        let name = text(expected, "Id")?;
        let value = native(name)?;
        matches(&value, expected)?;
        ensure!(
            m.insert(name.into(), value).is_none(),
            "duplicate current owner"
        );
    }
    ensure!(m.len() == 7, "complete protected owner census required");
    Ok(Value::Object(m))
}
fn authority(a: &Value) -> Result<u64> {
    ensure!(
        a["owner"] == "/root"
            && a["primary_thread"] == PRIMARY
            && a["complete_projected_memory_bytes"] == BEFORE
            && a["complete_DATA_bytes"] == 6_633_229_991_730u64,
        "exact current Root authority required"
    );
    ensure!(
        a["schema"]
            == "horizon-Root-existing-native16-serial-original199-auxiliary512-suballocation-v1"
            && a.get("original199_future_DATA_selection").is_none(),
        "already selected or foreign original199 authority"
    );
    Ok(6_633_229_991_730u64 - REDUCTION)
}
const TREE: &str =
    "/home/sol/.jetstreamer-private/epoch199-private-tail-20261017-v1/lane-a/private";
#[derive(Default)]
struct Scan {
    apparent: u64,
    physical: u64,
    entries: u64,
    digest: Sha256,
}
fn tree_identity(m: &fs::Metadata) -> Value {
    json!([identity(m), m.gid(), m.blocks()])
}
fn walk(
    path: &Path,
    root: &Path,
    device: u64,
    depth: usize,
    scan: &mut Scan,
    start: std::time::Instant,
) -> Result<()> {
    ensure!(
        depth <= 64 && start.elapsed().as_secs() < 60 && scan.entries < 4_000_000,
        "bounded retained tree census exceeded"
    );
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.dev() == device
            && !m.file_type().is_symlink()
            && ((m.uid() == 1001 && m.gid() == 1003) || (m.uid() == 0 && m.gid() == 0))
            && m.mode() & 0o022 == 0
            && (m.is_dir() || (m.is_file() && m.nlink() == 1)),
        "retained mount/type/owner/mode/link differs"
    );
    ensure!(path.canonicalize()? == path, "tree namespace changed");
    let held = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    ensure!(
        tree_identity(&m) == tree_identity(&held.metadata()?),
        "tree entry changed on open"
    );
    scan.entries = scan.entries.checked_add(1).context("entries overflow")?;
    scan.apparent = scan
        .apparent
        .checked_add(m.len())
        .context("apparent overflow")?;
    scan.physical = scan
        .physical
        .checked_add(m.blocks().checked_mul(512).context("blocks overflow")?)
        .context("physical overflow")?;
    scan.digest.update(serde_json::to_vec(&json!([
        path.strip_prefix(root)?.as_os_str().as_encoded_bytes(),
        tree_identity(&m)
    ]))?);
    if m.is_dir() {
        let mut entries = Vec::new();
        for e in fs::read_dir(path)? {
            ensure!(
                entries.len() < 100000,
                "one retained directory exceeds bound"
            );
            entries.push(e?.path());
        }
        entries.sort();
        for child in entries {
            walk(&child, root, device, depth + 1, scan, start)?;
        }
    }
    ensure!(
        tree_identity(&m) == tree_identity(&held.metadata()?)
            && tree_identity(&m) == tree_identity(&fs::symlink_metadata(path)?),
        "retained entry changed during census"
    );
    Ok(())
}
fn scan(root: &Path) -> Result<Value> {
    let m = fs::symlink_metadata(root)?;
    ensure!(m.is_dir(), "retained root must be a directory");
    let mut v = Scan::default();
    walk(root, root, m.dev(), 0, &mut v, std::time::Instant::now())?;
    Ok(
        json!({"root_identity":tree_identity(&m),"apparent_bytes":v.apparent,"physical_bytes":v.physical,"entries":v.entries,"metadata_digest":format!("{:x}",v.digest.finalize())}),
    )
}
fn caps(v: &Value) -> Result<()> {
    ensure!(
        v["apparent_bytes"]
            .as_u64()
            .is_some_and(|b| b <= 440u64 << 30)
            && v["physical_bytes"]
                .as_u64()
                .is_some_and(|b| b <= 440u64 << 30),
        "retained tree exceeds proposed440GiB payload cap"
    );
    Ok(())
}
fn run(plan: &Value) -> Result<Value> {
    ensure!(
        plan["schema"] == "horizon-original199-future-DATA-check-plan-v1"
            && plan["owner"] == "/root"
            && plan["primary_thread"] == PRIMARY,
        "exclusive Root plan required"
    );
    let parent = bound(&plan["current_complete_authority"])?;
    let projected = authority(&parent)?;
    let selected = bound(&parent["previous_complete_authority"])?;
    ensure!(
        selected["schema"]
            == "horizon-Root-once-only-held136-effective-memory-selection-authority-v1"
            && selected["complete_projected_memory_bytes"] == BEFORE
            && selected["current_complete_fleet"] == plan["current_fleet"],
        "qualified held136 authority or fleet crossed"
    );
    let fleet = bound(&plan["current_fleet"])?;
    let observer = bound(&fleet["observer"])?;
    ensure!(
        fleet["schema"] == "horizon-Root-complete-fleet-operational-review-v1"
            && fleet["live_replay_count"] == 5
            && fleet["proven_replay_count"] == 5
            && fleet["complete_projected_memory_bytes"] == 718987341824u64,
        "fresh complete fleet/authority crossed"
    );
    ensure!(
        fleet["sampled_at_utc"] == "2026-11-10T00:00:22Z"
            && observer["recorded_at_utc"] == fleet["sampled_at_utc"]
            && observer["cadence"]["routine_minimum_interval_enforced"] == true
            && now()?.checked_sub(1_794_268_822).is_some_and(|s| s <= 1800),
        "exact midnight sample required"
    );
    let own = native(OWN)?;
    ensure!(
        own["Id"] == OWN
            && own["InvocationID"] == std::env::var("INVOCATION_ID")?
            && text(&own, "MainPID")?.parse::<u32>()? == std::process::id()
            && own["MemoryMax"] == "536870912"
            && own["MemorySwapMax"] == "0"
            && own["Restart"] == "no"
            && own["NRestarts"] == "0",
        "exact auxiliary512 native invocation required"
    );
    ensure!(
        fs::read_to_string("/proc/self/cgroup")?.trim() == format!("0::/system.slice/{OWN}"),
        "own cgroup differs"
    );
    let before = owners(&fleet)?;
    let held: Bound = serde_json::from_value(plan["held_parent_selection"].clone())?;
    let raw: Bound = serde_json::from_value(plan["held_raw_accounting"].clone())?;
    let before_census = held_future_data_census(&held, &raw)?;
    eprintln!(
        "{} original199 scoped census-before passed; retained tree census starts",
        now()?
    );
    let tree_before = scan(Path::new(TREE))?;
    let tree_after = scan(Path::new(TREE))?;
    ensure!(
        tree_before == tree_after,
        "retained closed tree changed across censuses"
    );
    caps(&tree_after)?;
    eprintln!(
        "{} original199 tree census passed; scoped census-after starts",
        now()?
    );
    let after_census = held_future_data_census(&held, &raw)?;
    let after = owners(&fleet)?;
    ensure!(
        before == after,
        "protected owners changed during original199 qualification"
    );
    ensure!(
        bound(&plan["current_complete_authority"])? == parent,
        "manual authority changed"
    );
    Ok(
        json!({"schema":"horizon-original199-future-DATA-original-native-check-v1","owner":"/root","primary_thread":PRIMARY,"recorded_unix_seconds":now()?,"plan":plan,"native_self":own,"protected_owners_before":before,"protected_owners_after":after,"original199_census_before":before_census,"original199_census_after":after_census,"retained_tree_before":tree_before,"retained_tree_after":tree_after,"proposed_current_DATA_before_bytes":6633229991730u64,"proposed_current_DATA_after_bytes":projected,"original_DATA_promise_bytes":768u64<<30,"proposed_retained_DATA_bytes":448u64<<30,"proposed_payload_DATA_cap_bytes":440u64<<30,"proposed_retained_external_metadata_and_guard_DATA_bytes":8u64<<30,"proposed_ended_unused_future_DATA_bytes":REDUCTION,"complete_projected_memory_bytes":BEFORE,"actual_native_qualification_passed":true,"future_DATA_ending_recorded":false,"resource_credit_applied_bytes":0,"DATA_credit_bytes":0,"physical_credit_bytes":0,"all_DATA_and_raw_history_retained":true,"native_Frame_or_full_Reader_authority":false,"replay_admission_authorized":false,"producer_mutations":false,"remote_mutations":false}),
    )
}
fn main() -> Result<()> {
    let a = std::env::args().collect::<Vec<_>>();
    ensure!(
        a.len() == 6 && a[2] == "--plan-sha256" && a[4] == "--self-sha256",
        "exact argv required"
    );
    let image = fs::read_link("/proc/self/exe")?;
    ensure!(
        image == Path::new(IMAGE) && sha(&raw(&image)?) == a[5],
        "normally sealed self image required"
    );
    let plan = bound(&json!({"path":a[1],"sha256":a[3]}))?;
    let report = run(&plan)?;
    let p = Path::new(text(&plan, "output")?);
    let parent = p.parent().context("output parent")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent && m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "private output required"
    );
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?;
    serde_json::to_writer_pretty(&mut f, &report)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(parent)?.sync_all()?;
    println!(
        "{}",
        json!({"output":p,"native_qualification_passed":true,"resource_credit_applied_bytes":0})
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn parent() -> Value {
        json!({"schema":"horizon-Root-existing-native16-serial-original199-auxiliary512-suballocation-v1","owner":"/root","primary_thread":PRIMARY,"complete_projected_memory_bytes":BEFORE,"complete_DATA_bytes":6633229991730u64})
    }
    #[test]
    fn exact_unreduced_data_projects_once_without_memory_change() {
        assert_eq!(authority(&parent()).unwrap(), 6289632608050);
    }
    #[test]
    fn preselected_or_foreign_authority_rejects() {
        let mut v = parent();
        v["original199_future_DATA_selection"] = json!({});
        assert!(authority(&v).is_err());
        for k in [
            "owner",
            "primary_thread",
            "complete_projected_memory_bytes",
            "complete_DATA_bytes",
        ] {
            let mut v = parent();
            v[k] = json!("changed");
            assert!(authority(&v).is_err());
        }
    }
    #[test]
    fn retained_cap_checks_both_apparent_and_physical() {
        assert!(caps(&json!({"apparent_bytes":440u64<<30,"physical_bytes":0})).is_ok());
        assert!(caps(&json!({"apparent_bytes":0,"physical_bytes":(440u64<<30)+1})).is_err());
        assert!(caps(&json!({"physical_bytes":0})).is_err());
    }
    #[test]
    fn scanner_rejects_symlinks_and_hardlinks() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("payload");
        fs::write(&p, b"retained").unwrap();
        assert!(scan(d.path()).is_ok());
        let l = d.path().join("link");
        std::os::unix::fs::symlink(&p, &l).unwrap();
        assert!(scan(d.path()).is_err());
        fs::remove_file(l).unwrap();
        fs::hard_link(p, d.path().join("hard")).unwrap();
        assert!(scan(d.path()).is_err());
    }
    #[test]
    fn changed_tree_cannot_reuse_old_metadata_digest() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("payload");
        fs::write(&p, b"a").unwrap();
        let old = scan(d.path()).unwrap();
        fs::write(p, b"changed").unwrap();
        assert_ne!(old, scan(d.path()).unwrap());
    }
}
