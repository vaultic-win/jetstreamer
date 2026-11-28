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
    "/usr/local/lib/jetstreamer/horizon-original199-retained128-tools-20261110-v1/check-end";
const CHECK: &str = "horizon-original199-retained128-check-20261110-v1.service";
const END: &str = "horizon-original199-retained128-end-20261110-v1.service";
const OUTPUT_CHECK: &str = "/var/lib/jetstreamer/held136-baseline-view-qualification-20261109-v1/ROOT_ACTUAL_ORIGINAL199_RETAINED128_NATIVE_CHECK.json";
const OUTPUT_END: &str = "/var/lib/jetstreamer/held136-baseline-view-qualification-20261109-v1/ROOT_ORIGINAL199_SECOND320_FUTURE_DATA_ENDED_ONCE.json";
const INTENT: &str = "/var/lib/jetstreamer/held136-baseline-view-qualification-20261109-v1/ORIGINAL199_RETAINED128_SECOND320_ONCE_INTENT.json";
const FIRST_SELECTION: &str = "/var/lib/jetstreamer/held136-baseline-view-qualification-20261109-v1/ROOT_ONCE_ONLY_ORIGINAL199_FUTURE_DATA_SELECTED_CURRENT_AUTHORITY.json";
const FIRST_SHA: &str = "ebf7f27984954b9ff91db3b3b25ef58bd801c6d58fb49f5b647741c40e3b7188";
const BEFORE_DATA: u64 = 6_607_527_296_818;
const AFTER_DATA: u64 = BEFORE_DATA - REDUCTION;
const PRIMARY: &str = "01a1af2a-9ce8-76a2-8939-b2112bd38f53";
const BEFORE: u64 = 720_061_083_648;
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
    let o=Command::new("/usr/bin/systemctl").env_remove("DBUS_SYSTEM_BUS_ADDRESS").env_remove("SYSTEMD_BUS_ADDRESS").env_remove("DBUS_SESSION_BUS_ADDRESS").env_remove("SYSTEMD_HOST").args(["show",name,"--no-pager","-pId,InvocationID,ActiveState,SubState,MainPID,ControlPID,NRestarts,Job,MemoryMax,MemorySwapMax,Restart,Result,ExecMainStatus"]).output()?;
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
        .context("six replay census")?;
    ensure!(rows.len() == 6, "exact six-replay context required");
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
    ensure!(m.len() == 8, "complete protected owner census required");
    Ok(Value::Object(m))
}
fn authority(a: &Value) -> Result<u64> {
    ensure!(
        a["owner"] == "/root"
            && a["primary_thread"] == PRIMARY
            && a["schema"] == "horizon-fresh-standard171-resource-admission-v1"
            && a["complete_projected_memory_bytes"] == BEFORE
            && a["complete_DATA_bytes"] == BEFORE_DATA
            && a.get("original199_second_future_DATA_selection").is_none(),
        "exact unreselected six-owner resource authority required"
    );
    Ok(AFTER_DATA)
}
fn first_ending(plan: &Value, parent: &Value) -> Result<Value> {
    let selected_binding = json!({"path":FIRST_SELECTION,"sha256":FIRST_SHA});
    ensure!(
        plan["first_selected_ending"] == selected_binding,
        "exact first selection binding required"
    );
    let selected = bound(&selected_binding)?;
    ensure!(
        selected["once_only_ended_unused_future_DATA_bytes"] == REDUCTION
            && selected["all_raw_original199_DATA_bytes_retained"] == 768u64 << 30
            && selected["effective_retained_original199_DATA_bytes"] == 448u64 << 30
            && selected["physical_retirement_bytes"] == 0,
        "first320 ending must already be selected exactly once"
    );
    let first = bound(&selected["original199_future_DATA_selection"])?;
    ensure!(
        first["future_DATA_ending_recorded"] == true
            && first["actual_native_qualification_passed"] == true
            && first["unused_future_DATA_ended_bytes"] == REDUCTION
            && first["original_controller_and_FD9_preserved"] == true
            && first["original_producer_must_never_be_restarted"] == true,
        "genuine completed first ending required"
    );
    let mut ancestor = parent.clone();
    let mut found = false;
    for _ in 0..16 {
        let binding = &ancestor["previous_complete_authority"];
        if binding == &selected_binding {
            found = true;
            break;
        }
        if !binding.is_object() {
            break;
        }
        ancestor = bound(binding)?;
    }
    ensure!(
        found,
        "current complete authority must descend from the selected first ending"
    );
    Ok(selected)
}
fn prior_check(prior: &Value, plan: &Value, t: u64) -> Result<()> {
    ensure!(
        prior["schema"] == "horizon-original199-retained128-native-v1"
            && prior["actual_native_qualification_passed"] == true
            && prior["future_DATA_ending_recorded"] == false
            && prior["plan"]["purpose"] == "check"
            && prior["plan"]["current_complete_authority"] == plan["current_complete_authority"]
            && prior["plan"]["current_fleet"] == plan["current_fleet"]
            && prior["first_selected_ending"] == plan["first_selected_ending"],
        "genuine same-authority retained128 check required"
    );
    let started = prior["recorded_unix_seconds"]
        .as_u64()
        .context("original check clock")?;
    ensure!(
        t.checked_sub(started).is_some_and(|age| age <= 900),
        "original900s check clock expired or future"
    );
    Ok(())
}
fn completed_check(actual: &Value, prior: &Value) -> Result<()> {
    ensure!(
        actual["Id"] == CHECK
            && actual["InvocationID"] == prior["native_self"]["InvocationID"]
            && text(actual, "InvocationID")?.len() == 32
            && actual["ActiveState"] == "active"
            && actual["SubState"] == "exited"
            && actual["MainPID"] == "0"
            && actual["ControlPID"] == "0"
            && actual["NRestarts"] == "0"
            && actual["Restart"] == "no"
            && actual["Job"] == ""
            && actual["Result"] == "success"
            && actual["ExecMainStatus"] == "0",
        "original retained completed check must remain installed, successful and drained"
    );
    Ok(())
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
            .is_some_and(|b| b <= 120u64 << 30)
            && v["physical_bytes"]
                .as_u64()
                .is_some_and(|b| b <= 120u64 << 30),
        "retained tree exceeds proposed120GiB payload cap"
    );
    Ok(())
}
fn run(plan: &Value, ending: bool) -> Result<Value> {
    let own_name = if ending { END } else { CHECK };
    ensure!(
        plan["purpose"] == if ending { "end" } else { "check" }
            && plan["output"] == if ending { OUTPUT_END } else { OUTPUT_CHECK },
        "exact purpose/output required"
    );
    ensure!(
        !Path::new(INTENT).try_exists()? && !Path::new(OUTPUT_END).try_exists()?,
        "second ending intent/output already exists; manual reconciliation required"
    );
    ensure!(
        plan["schema"] == "horizon-original199-retained128-plan-v1"
            && plan["owner"] == "/root"
            && plan["primary_thread"] == PRIMARY,
        "exclusive Root plan required"
    );
    let parent = bound(&plan["current_complete_authority"])?;
    let projected = authority(&parent)?;
    let first_selected = first_ending(plan, &parent)?;
    let fleet = bound(&plan["current_fleet"])?;
    let observer = bound(&fleet["observer"])?;
    ensure!(
        fleet["schema"] == "horizon-Root-complete-fleet-operational-review-v1"
            && fleet["live_replay_count"] == 6
            && fleet["proven_replay_count"] == 5
            && fleet["complete_projected_memory_bytes"] == BEFORE
            && fleet["complete_DATA_authority"] == plan["current_complete_authority"]
            && fleet["complete_DATA_bytes"] == BEFORE_DATA,
        "fresh complete fleet/authority crossed"
    );
    ensure!(
        fleet["sampled_at_utc"] == "2026-11-10T01:30:22Z"
            && observer["recorded_at_utc"] == fleet["sampled_at_utc"]
            && observer["cadence"]["routine_minimum_interval_enforced"] == true
            && now()?.checked_sub(1_794_274_222).is_some_and(|s| s <= 1800),
        "exact fresh0130 six-owner sample required"
    );
    let own = native(own_name)?;
    ensure!(
        own["Id"] == own_name
            && own["InvocationID"] == std::env::var("INVOCATION_ID")?
            && text(&own, "MainPID")?.parse::<u32>()? == std::process::id()
            && own["MemoryMax"] == "536870912"
            && own["MemorySwapMax"] == "0"
            && own["Restart"] == "no"
            && own["NRestarts"] == "0",
        "exact auxiliary512 native invocation required"
    );
    ensure!(
        fs::read_to_string("/proc/self/cgroup")?.trim() == format!("0::/system.slice/{own_name}"),
        "own cgroup differs"
    );
    let prior = if ending {
        ensure!(
            plan["prior_native_check"]["path"] == OUTPUT_CHECK,
            "exact prior check namespace required"
        );
        let prior = bound(&plan["prior_native_check"])?;
        prior_check(&prior, plan, now()?)?;
        completed_check(&native(CHECK)?, &prior)?;
        ensure!(
            fs::read_to_string(format!("/sys/fs/cgroup/system.slice/{CHECK}/cgroup.procs"))?
                .trim()
                .is_empty(),
            "prior check cgroup not drained"
        );
        Some(prior)
    } else {
        ensure!(
            plan.get("prior_native_check").is_none(),
            "check cannot borrow prior authority"
        );
        None
    };
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
    if let Some(prior) = &prior {
        ensure!(
            tree_after == prior["retained_tree_after"],
            "retained tree changed since original check"
        );
        prior_check(prior, plan, now()?)?;
        completed_check(&native(CHECK)?, prior)?;
        let mut intent = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(INTENT)?;
        serde_json::to_writer_pretty(
            &mut intent,
            &json!({"schema":"original199-second320-retained128-ending-intent-v1","claim_key":"original199/2a1c51f557a64cd1ad691281cbb77c94/second-unused320-retain128","plan":plan,"first_selected_ending":plan["first_selected_ending"],"native_self":own,"additional_ended_unused_future_DATA_bytes":REDUCTION,"physical_retirement_bytes":0,"raw_history_rewritten":false}),
        )?;
        intent.write_all(b"\n")?;
        intent.sync_all()?;
        File::open(Path::new(INTENT).parent().context("intent parent")?)?.sync_all()?;
    }
    Ok(
        json!({"schema":"horizon-original199-retained128-native-v1","owner":"/root","primary_thread":PRIMARY,"recorded_unix_seconds":now()?,"plan":plan,"native_self":own,"protected_owners_before":before,"protected_owners_after":after,"original199_census_before":before_census,"original199_census_after":after_census,"retained_tree_before":tree_before,"retained_tree_after":tree_after,"first_selected_ending":plan["first_selected_ending"],"first_selected_ending_document":first_selected,"proposed_current_DATA_before_bytes":BEFORE_DATA,"proposed_current_DATA_after_bytes":projected,"original_DATA_promise_bytes":768u64<<30,"current_retained_DATA_before_bytes":448u64<<30,"proposed_retained_DATA_bytes":128u64<<30,"proposed_payload_DATA_cap_bytes":120u64<<30,"proposed_retained_external_metadata_and_guard_DATA_bytes":8u64<<30,"proposed_ended_unused_future_DATA_bytes":REDUCTION,"complete_projected_memory_bytes":BEFORE,"actual_native_qualification_passed":true,"future_DATA_ending_recorded":ending,"additional_unused_future_DATA_ended_bytes":if ending{REDUCTION}else{0},"prior_ended_future_DATA_bytes":REDUCTION,"cumulative_ended_future_DATA_bytes_if_selected":640u64<<30,"current_manual_authority_updated":false,"original_controller_and_FD9_preserved":true,"original_producer_must_never_be_restarted":true,"physical_retirement_bytes":0,"resource_credit_applied_bytes":0,"DATA_credit_bytes":0,"physical_credit_bytes":0,"all_DATA_and_raw_history_retained":true,"native_Frame_or_full_Reader_authority":false,"replay_admission_authorized":false,"producer_mutations":false,"remote_mutations":false}),
    )
}
fn main() -> Result<()> {
    let a = std::env::args().collect::<Vec<_>>();
    ensure!(
        a.len() == 7
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256"
            && ["--check", "--end"].contains(&a[6].as_str()),
        "exact argv required"
    );
    let image = fs::read_link("/proc/self/exe")?;
    ensure!(
        image == Path::new(IMAGE) && sha(&raw(&image)?) == a[5],
        "normally sealed self image required"
    );
    let plan = bound(&json!({"path":a[1],"sha256":a[3]}))?;
    let report = run(&plan, a[6] == "--end")?;
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
        json!({"schema":"horizon-fresh-standard171-resource-admission-v1","owner":"/root","primary_thread":PRIMARY,"complete_projected_memory_bytes":BEFORE,"complete_DATA_bytes":BEFORE_DATA})
    }
    #[test]
    fn second_ending_starts_at448_and_retains128_without_reapplying_first320() {
        assert_eq!(authority(&parent()).unwrap(), 6_263_929_913_138);
        assert_eq!((768u64 << 30) - (640u64 << 30), 128u64 << 30);
    }
    #[test]
    fn crossed_or_reselected_authority_denies() {
        for k in [
            "schema",
            "owner",
            "primary_thread",
            "complete_projected_memory_bytes",
            "complete_DATA_bytes",
        ] {
            let mut v = parent();
            v[k] = json!("changed");
            assert!(authority(&v).is_err());
        }
        let mut v = parent();
        v["original199_second_future_DATA_selection"] = json!({});
        assert!(authority(&v).is_err());
    }
    fn prior_fixture() -> (Value, Value) {
        let plan = json!({"current_complete_authority":{"path":"current"},"current_fleet":{"path":"fleet"},"first_selected_ending":{"path":FIRST_SELECTION,"sha256":FIRST_SHA}});
        let mut check_plan = plan.clone();
        check_plan["purpose"] = json!("check");
        let p = json!({"schema":"horizon-original199-retained128-native-v1","actual_native_qualification_passed":true,"future_DATA_ending_recorded":false,"plan":check_plan,"first_selected_ending":plan["first_selected_ending"],"recorded_unix_seconds":100,"native_self":{"InvocationID":"12345678901234567890123456789012"}});
        (p, plan)
    }
    #[test]
    fn original_check_clock_cannot_be_relabelled() {
        let (p, plan) = prior_fixture();
        assert!(prior_check(&p, &plan, 1000).is_ok());
        assert!(prior_check(&p, &plan, 1001).is_err());
        assert!(prior_check(&p, &plan, 99).is_err());
    }
    #[test]
    fn failed_completed_or_foreign_check_denies() {
        let (p, plan) = prior_fixture();
        for k in [
            "actual_native_qualification_passed",
            "future_DATA_ending_recorded",
            "first_selected_ending",
        ] {
            let mut b = p.clone();
            b[k] = json!("changed");
            assert!(prior_check(&b, &plan, 200).is_err());
        }
        let mut b = plan;
        b["current_complete_authority"] = json!({"path":"new"});
        assert!(prior_check(&p, &b, 200).is_err());
    }
    #[test]
    fn completed_check_requires_exact_original_success_and_no_live_pid() {
        let (p, _) = prior_fixture();
        let v = json!({"Id":CHECK,"InvocationID":p["native_self"]["InvocationID"],"ActiveState":"active","SubState":"exited","MainPID":"0","ControlPID":"0","NRestarts":"0","Restart":"no","Job":"","Result":"success","ExecMainStatus":"0"});
        assert!(completed_check(&v, &p).is_ok());
        for (k, x) in [
            ("InvocationID", "reused"),
            ("MainPID", "12"),
            ("ControlPID", "12"),
            ("NRestarts", "1"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "1"),
            ("Job", "1/start"),
            ("SubState", "running"),
        ] {
            let mut b = v.clone();
            b[k] = json!(x);
            assert!(completed_check(&b, &p).is_err());
        }
    }
    #[test]
    fn retained_cap_checks_both_apparent_and_physical() {
        assert!(caps(&json!({"apparent_bytes":120u64<<30,"physical_bytes":0})).is_ok());
        assert!(caps(&json!({"apparent_bytes":0,"physical_bytes":(120u64<<30)+1})).is_err());
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
